"""Helpers that act like the VS Code extension: manifest, archive, upload."""

import hashlib
import io
import tarfile

import httpx

from mcp_client import call


def manifest(folder):
    out = []
    for p in sorted(folder.rglob("*")):
        if p.is_file():
            data = p.read_bytes()
            out.append({"path": p.relative_to(folder).as_posix(),
                        "sha256": hashlib.sha256(data).hexdigest(), "size": len(data)})
    return out


def archive(folder, paths):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for p in paths:
            tar.add(folder / p, arcname=p)
    return buf.getvalue()


def sha(data):
    return hashlib.sha256(data).hexdigest()


async def upload(client, session_id, data):
    up = await call(client, "request_upload", {"session_id": session_id, "size_bytes": len(data), "sha256": sha(data)})
    r = httpx.put(up["upload_url"], content=data, headers={"content-type": "application/gzip"})
    return up, r


async def sync_upload_scan(client, session_id, folder, full=False):
    """The contract's upload flow. Returns (sync result, scan summary, progress events)."""
    s = await call(client, "sync_files", {"session_id": session_id, "manifest": manifest(folder)})
    args = {"session_id": session_id, "deleted_paths": s["delete"], "full": full}
    if s["need"]:
        up, r = await upload(client, session_id, archive(folder, s["need"]))
        assert r.status_code == 201, r.text
        args["upload_id"] = up["upload_id"]
    scan = await call(client, "start_scan", args)
    events = []

    async def on_progress(progress, total, message):
        events.append((progress, total, message))

    summary = await call(client, "watch_scan", {"scan_id": scan["scan_id"]}, progress_callback=on_progress)
    return s, summary, events
