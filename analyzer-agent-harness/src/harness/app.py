"""HTTP app: MCP at /mcp, plus /health and the upload route."""

import asyncio
import contextlib
import functools
import logging
import sys
from typing import Any

from mcp.server.mcpserver import Context, MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Mount

from harness import auth, config, logs, uploads
from harness.db import DB
from harness.llm import LLM
from harness.scans import ScanManager
from harness.service import Service, UserError

log = logging.getLogger(__name__)

CLEANUP_INTERVAL_SECONDS = 300
MAX_REQUEST_BYTES = 64 * 1024 * 1024


def build_service(cfg, llm_completion=None, sonar_client=None):
    db = DB(cfg.db_path)
    llm = LLM(cfg, llm_completion)
    scans = ScanManager(cfg, db, llm, sonar_client)
    from harness import github
    return Service(cfg, db, scans, llm, sonar_client, github.GitHub(cfg, db))


def build_app(cfg, service=None):
    service = service or build_service(cfg)
    mcp = MCPServer(name="vuln-scanner-harness")

    def user_id(ctx):
        uid = auth.lookup(cfg.tokens_file, auth.bearer(ctx.headers or {}))
        if uid is None:
            raise ToolError("unauthorized")
        return uid

    def tool(fn):
        """Register a tool; show UserError text as-is and hide anything unexpected."""
        @functools.wraps(fn)
        async def wrapper(*args, **kwargs):
            logs.bind(session=kwargs.get("session_id"), scan=kwargs.get("scan_id"))
            try:
                result = fn(*args, **kwargs)
                return await result if asyncio.iscoroutine(result) else result
            except ToolError:
                raise
            except UserError as e:
                raise ToolError(str(e)) from e
            except Exception as e:
                log.exception("tool %s failed", fn.__name__)
                raise ToolError("internal error, see the server log") from e
        return mcp.tool()(wrapper)

    @mcp.custom_route("/health", methods=["GET"])
    async def health(request):
        return JSONResponse({"status": "ok"})

    @mcp.custom_route("/uploads/{upload_id}", methods=["PUT"])
    async def upload(request):
        return await uploads.receive(request, cfg, service.db)

    @tool
    def create_session(ctx: Context, target_type: str = "workspace", name: str | None = None,
                       repo_url: str | None = None) -> dict:
        """Create a scan session for the open workspace or a GitHub repo."""
        return service.create_session(user_id(ctx), name, target_type, repo_url)

    @tool
    def list_sessions(ctx: Context) -> dict:
        """List your sessions."""
        return service.list_sessions(user_id(ctx))

    @tool
    def get_session(ctx: Context, session_id: str, message_limit: int = 50) -> dict:
        """Get a session with its chat history."""
        return service.get_session(user_id(ctx), session_id, message_limit)

    @tool
    def rename_session(ctx: Context, session_id: str, name: str) -> dict:
        """Rename a session."""
        return service.rename_session(user_id(ctx), session_id, name)

    @tool
    async def delete_session(ctx: Context, session_id: str) -> dict:
        """Delete a session, its files, findings and history."""
        return await service.delete_session(user_id(ctx), session_id)

    @tool
    def sync_files(ctx: Context, session_id: str, manifest: list[dict[str, Any]]) -> dict:
        """Compare a workspace manifest with the stored one. Returns the paths to upload and delete."""
        return service.sync_files(user_id(ctx), session_id, manifest)

    @tool
    def request_upload(ctx: Context, session_id: str, size_bytes: int, sha256: str) -> dict:
        """Get a one-time URL for uploading a tar.gz of the needed files."""
        return service.request_upload(user_id(ctx), session_id, size_bytes, sha256)

    @tool
    async def start_scan(ctx: Context, session_id: str, upload_id: str | None = None,
                         deleted_paths: list[str] | None = None, full: bool = False) -> dict:
        """Start a scan. Returns at once with the scan id."""
        return await service.start_scan(user_id(ctx), session_id, upload_id, deleted_paths, full)

    @tool
    async def watch_scan(ctx: Context, scan_id: str) -> dict:
        """Send progress notifications until the scan ends, then return the scan summary."""
        async def report(percent, message):
            await ctx.report_progress(percent, 100, message)
        return await service.watch_scan(user_id(ctx), scan_id, report)

    @tool
    def get_scan_status(ctx: Context, scan_id: str) -> dict:
        """Get the scan summary."""
        return service.get_scan_status(user_id(ctx), scan_id)

    @tool
    async def cancel_scan(ctx: Context, scan_id: str) -> dict:
        """Cancel a running scan."""
        return await service.cancel_scan(user_id(ctx), scan_id)

    @tool
    def get_findings(ctx: Context, session_id: str, scan_id: str | None = None, severity: list[str] | None = None,
                     tool: list[str] | None = None, path: str | None = None, limit: int = 200,
                     offset: int = 0) -> dict:
        """Get findings for a session (latest scan by default), with filters and paging."""
        return service.get_findings(user_id(ctx), session_id, scan_id, severity, tool, path, limit, offset)

    @tool
    async def chat(ctx: Context, session_id: str, message: str) -> dict:
        """Ask the agent about the code and the findings."""
        return await service.chat(user_id(ctx), session_id, message)

    # Large manifests (up to 200,000 files) do not fit the SDK's 4 MB default.
    inner = mcp.streamable_http_app(host=cfg.host, max_request_body_size=MAX_REQUEST_BYTES)

    @contextlib.asynccontextmanager
    async def lifespan(app):
        service.scans.recover()

        async def cleanup_loop():
            while True:
                try:
                    await asyncio.to_thread(uploads.cleanup, service.db)
                except Exception:
                    log.exception("upload cleanup failed")
                await asyncio.sleep(CLEANUP_INTERVAL_SECONDS)

        task = asyncio.create_task(cleanup_loop())
        try:
            async with inner.router.lifespan_context(inner):
                yield
        finally:
            task.cancel()

    return Starlette(routes=[Mount("/", app=auth.BearerAuthMiddleware(inner, cfg.tokens_file))],
                     lifespan=lifespan)


def main():
    logs.setup()
    try:
        cfg = config.load()
    except config.ConfigError as e:
        log.error("%s", e)
        sys.exit(2)
    import uvicorn
    tls = {}
    if cfg.tls_cert:
        tls = {"ssl_certfile": str(cfg.tls_cert), "ssl_keyfile": str(cfg.tls_key)}
        log.info("serving HTTPS")
    # log_config=None: uvicorn's loggers use our handler, which redacts upload signatures.
    uvicorn.run(build_app(cfg), host=cfg.host, port=cfg.port, log_config=None, **tls)
