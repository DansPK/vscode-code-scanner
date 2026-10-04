import os
import shutil
import socket
import threading
import time
from pathlib import Path

import httpx
import pytest
import uvicorn

from harness import auth, config

ROOT = Path(__file__).resolve().parent.parent
BIN = ROOT / ".bin"
FIXTURE = Path(__file__).parent / "fixtures" / "vulnerable_app"
if BIN.is_dir():
    os.environ["PATH"] = f"{BIN}{os.pathsep}{os.environ['PATH']}"
RULES = ",".join(str(p) for p in sorted((BIN / "rules").glob("*.yml"))) or "/opt/semgrep-rules"

needs_scanners = pytest.mark.skipif(
    not (shutil.which("semgrep") and shutil.which("gitleaks")), reason="semgrep/gitleaks not installed")


@pytest.fixture
def vuln_app(tmp_path):
    """A copy of the fixture project (Semgrep skips paths under tests/ otherwise)."""
    dest = tmp_path / "code"
    shutil.copytree(FIXTURE, dest)
    return dest


@pytest.fixture
def cfg(tmp_path):
    env = {
        "HARNESS_PUBLIC_URL": "http://127.0.0.1:0",
        "HARNESS_TOKENS_FILE": str(tmp_path / "tokens.json"),
        "HARNESS_SIGNING_SECRET": "test-secret",
        "HARNESS_DATA_DIR": str(tmp_path / "data"),
        "LLM_BASE_URL": "http://llm.invalid",
        "LLM_API_KEY": "k",
        "LLM_MODEL": "openai/fake",
        "SONAR_HOST_URL": "http://sonar.invalid",
        "SONAR_TOKEN": "t",
        "SEMGREP_CONFIGS": RULES,
        "UPLOAD_MAX_MB": "1",
    }
    return config.load(env)


@pytest.fixture
def tokens(cfg):
    return {"alice": auth.add_user(cfg.tokens_file, "alice", "Alice"),
            "bob": auth.add_user(cfg.tokens_file, "bob", "Bob")}


def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class FakeSonar:
    """SonarQube is not available in tests: the scanner CLI is missing, so the SonarQube
    step fails (and the other tools carry on). Project deletes are recorded."""

    def __init__(self):
        self.deleted = []

    async def get(self, path, **params):
        return {}

    async def delete_project(self, key):
        self.deleted.append(key)


class Server:
    """The real app in a background thread, with a fake LLM and SonarQube."""

    def __init__(self, cfg, llm=None, tls=None):
        from dataclasses import replace
        from fakes import FakeLLMCompletion
        from harness.app import build_app, build_service
        port = _free_port()
        self.url = f"{'https' if tls else 'http'}://127.0.0.1:{port}"
        self.cfg = replace(cfg, public_url=self.url)
        self.llm = llm or FakeLLMCompletion()
        self.sonar = FakeSonar()
        self.service = build_service(self.cfg, self.llm, self.sonar)
        app = build_app(self.cfg, self.service)
        ssl = {"ssl_certfile": str(tls[0]), "ssl_keyfile": str(tls[1])} if tls else {}
        self.srv = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning", **ssl))
        self.thread = threading.Thread(target=self.srv.run, daemon=True)
        self.thread.start()
        for _ in range(200):
            try:
                if httpx.get(self.url + "/health", verify=str(tls[0]) if tls else True).status_code == 200:
                    return
            except httpx.HTTPError:
                time.sleep(0.05)
        raise RuntimeError("server did not start")

    def stop(self):
        self.srv.should_exit = True
        self.thread.join(10)


@pytest.fixture
def harness_server(cfg, tokens):
    s = Server(cfg)
    yield s
    s.stop()


@pytest.fixture
def server(harness_server):
    return harness_server.url
