import shutil
import ssl
import subprocess

import httpx
import pytest

from conftest import Server
from harness import config
from mcp_client import call, connect

pytestmark = pytest.mark.skipif(not shutil.which("openssl"), reason="openssl not installed")


@pytest.fixture
def dev_cert(tmp_path):
    root = tmp_path / "repo"
    (root / "scripts").mkdir(parents=True)
    script = config.Path(__file__).parent.parent / "scripts" / "make_dev_cert.sh"
    shutil.copy(script, root / "scripts" / "make_dev_cert.sh")
    subprocess.run(["sh", str(root / "scripts" / "make_dev_cert.sh")], check=True, capture_output=True)
    return root / "certs" / "dev-cert.pem", root / "certs" / "dev-key.pem"


async def test_https_with_dev_certificate(cfg, tokens, dev_cert):
    s = Server(cfg, tls=dev_cert)
    try:
        assert s.url.startswith("https://")
        assert httpx.get(s.url + "/health", verify=str(dev_cert[0])).json() == {"status": "ok"}
        with pytest.raises(httpx.ConnectError):  # not trusted without the certificate
            httpx.get(s.url + "/health")
        ctx = ssl.create_default_context(cafile=str(dev_cert[0]))
        async with connect(s.url, tokens["alice"], verify=ctx) as c:
            assert (await call(c, "list_sessions"))["sessions"] == []
            up = await call(c, "request_upload", {"session_id": (await call(c, "create_session", {}))["session_id"],
                                                   "size_bytes": 10, "sha256": "a" * 64})
            assert up["upload_url"].startswith("https://")
    finally:
        s.stop()


def test_tls_config(cfg, dev_cert):
    base = {"HARNESS_PUBLIC_URL": "https://x", "HARNESS_TOKENS_FILE": "t", "HARNESS_SIGNING_SECRET": "s",
            "LLM_BASE_URL": "x", "LLM_API_KEY": "x", "LLM_MODEL": "x", "SONAR_HOST_URL": "x", "SONAR_TOKEN": "x"}
    c = config.load({**base, "HARNESS_TLS_CERT": str(dev_cert[0]), "HARNESS_TLS_KEY": str(dev_cert[1])})
    assert c.tls_cert == dev_cert[0]
    assert config.load(base).tls_cert is None
    with pytest.raises(config.ConfigError, match="both"):
        config.load({**base, "HARNESS_TLS_CERT": str(dev_cert[0])})
    with pytest.raises(config.ConfigError, match="not found"):
        config.load({**base, "HARNESS_TLS_CERT": "/nope.pem", "HARNESS_TLS_KEY": str(dev_cert[1])})
