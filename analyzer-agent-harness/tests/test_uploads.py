import io
import tarfile
import time
from dataclasses import replace

import httpx
import pytest

from flow import archive, manifest, sha, upload
from harness import uploads
from mcp_client import call, connect


async def _session_with_pending(c, folder):
    sid = (await call(c, "create_session", {}))["session_id"]
    s = await call(c, "sync_files", {"session_id": sid, "manifest": manifest(folder)})
    return sid, archive(folder, s["need"])


async def test_upload_status_codes(harness_server, tokens, vuln_app):
    async with connect(harness_server.url, tokens["alice"]) as c:
        sid, data = await _session_with_pending(c, vuln_app)
        # wrong hash -> 400
        up = await call(c, "request_upload", {"session_id": sid, "size_bytes": len(data), "sha256": "a" * 64})
        assert httpx.put(up["upload_url"], content=data).status_code == 400
        # good -> 201, reuse -> 409
        up, r = await upload(c, sid, data)
        assert r.status_code == 201
        assert httpx.put(up["upload_url"], content=data).status_code == 409
        # bad signature -> 403
        up = await call(c, "request_upload", {"session_id": sid, "size_bytes": len(data), "sha256": sha(data)})
        assert httpx.put(up["upload_url"].replace("sig=", "sig=0"), content=data).status_code == 403
        assert httpx.put(up["upload_url"].split("?")[0], content=data).status_code == 403
        # declared too big -> refused at request_upload
        with pytest.raises(RuntimeError, match="larger than the server limit"):
            await call(c, "request_upload", {"session_id": sid, "size_bytes": 10**12, "sha256": "a" * 64})


async def test_upload_expired_403(harness_server, tokens, vuln_app):
    db = harness_server.service.db
    async with connect(harness_server.url, tokens["alice"]) as c:
        sid, data = await _session_with_pending(c, vuln_app)
        cfg = replace(harness_server.cfg, upload_url_ttl_seconds=-5)
        _, url, _ = uploads.create(cfg, db, sid, len(data), sha(data))
        assert httpx.put(url, content=data).status_code == 403


async def test_upload_over_limit_413(harness_server, tokens, vuln_app):
    db = harness_server.service.db
    async with connect(harness_server.url, tokens["alice"]) as c:
        sid, _ = await _session_with_pending(c, vuln_app)
    big = b"x" * (harness_server.cfg.upload_max_mb * 1024 * 1024 + 10)
    # Declare a small size, then send more than the limit (no content-length: streamed).
    _, url, _ = uploads.create(harness_server.cfg, db, sid, 100, "a" * 64)

    def gen():
        for i in range(0, len(big), 1 << 20):
            yield big[i:i + (1 << 20)]
    assert httpx.put(url, content=gen()).status_code == 413
    _, url, _ = uploads.create(harness_server.cfg, db, sid, 100, "a" * 64)
    assert httpx.put(url, content=big).status_code == 413  # with content-length


def _evil(kind):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        if kind == "symlink":
            info = tarfile.TarInfo("db.py")
            info.type = tarfile.SYMTYPE
            info.linkname = "/etc/passwd"
            tar.addfile(info)
        elif kind == "hardlink":
            info = tarfile.TarInfo("db.py")
            info.type = tarfile.LNKTYPE
            info.linkname = "/etc/passwd"
            tar.addfile(info)
        else:
            name = {"dotdot": "../evil", "absolute": "/etc/passwd", "nested": "a/../../evil"}[kind]
            data = b"evil"
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


@pytest.mark.parametrize("kind", ["dotdot", "absolute", "nested", "symlink", "hardlink"])
def test_unpack_refuses_evil_archives(tmp_path, kind):
    arc = tmp_path / "a.tar.gz"
    arc.write_bytes(_evil(kind))
    dest = tmp_path / "dest"
    dest.mkdir()
    with pytest.raises(uploads.UnpackError):
        uploads.unpack(arc, dest, {"db.py": "0" * 64, "evil": "0" * 64}, 10**9)
    assert list(dest.rglob("*")) == []
    assert not (tmp_path / "evil").exists()


def test_unpack_checks_manifest_hash_and_size(tmp_path, vuln_app):
    data = archive(vuln_app, ["db.py", "auth.py"])
    arc = tmp_path / "a.tar.gz"
    arc.write_bytes(data)
    good = {e["path"]: e["sha256"] for e in manifest(vuln_app)}
    with pytest.raises(uploads.UnpackError, match="not in the manifest"):
        uploads.unpack(arc, tmp_path / "d1", {"db.py": good["db.py"]}, 10**9)
    with pytest.raises(uploads.UnpackError, match="hash"):
        uploads.unpack(arc, tmp_path / "d2", {**good, "db.py": "0" * 64}, 10**9)
    with pytest.raises(uploads.UnpackError, match="too large"):
        uploads.unpack(arc, tmp_path / "d3", good, 10)
    assert sorted(uploads.unpack(arc, tmp_path / "d4", good, 10**9)) == ["auth.py", "db.py"]


async def test_evil_upload_through_start_scan_writes_nothing(harness_server, tokens, vuln_app):
    async with connect(harness_server.url, tokens["alice"]) as c:
        sid, _ = await _session_with_pending(c, vuln_app)
        data = _evil("dotdot")
        up, r = await upload(c, sid, data)
        assert r.status_code == 201
        with pytest.raises(RuntimeError, match="bad path"):
            await call(c, "start_scan", {"session_id": sid, "upload_id": up["upload_id"]})
        code = harness_server.cfg.sessions_dir / sid / "code"
        assert list(code.rglob("*")) == []
        assert not (harness_server.cfg.sessions_dir / sid / "evil").exists()


def test_cleanup_removes_old_uploads(cfg, tmp_path):
    from harness.db import DB
    db = DB(cfg.db_path)
    f = tmp_path / "x.tar.gz"
    f.write_bytes(b"x")
    db.run("INSERT INTO uploads (id, session_id, size, sha256, expires_at, path) VALUES (?,?,?,?,?,?)",
           ("u1", "s", 1, "a" * 64, time.time() - 2 * uploads.UPLOAD_GRACE_SECONDS, str(f)))
    assert uploads.cleanup(db) == 1 and not f.exists()
