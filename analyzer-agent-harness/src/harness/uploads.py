"""Presigned upload URLs, the PUT /uploads/<id> route, and safe unpacking."""

import errno
import hashlib
import hmac
import logging
import secrets
import shutil
import tarfile
import time
from pathlib import Path

from starlette.responses import JSONResponse

from harness.files import PathError, check_rel_path

log = logging.getLogger(__name__)

CHUNK = 1 << 16
UPLOAD_GRACE_SECONDS = 3600  # keep an uploaded archive this long after its URL expires


class UnpackError(Exception):
    pass


def sign(secret, upload_id, session_id, expires, size, sha256):
    msg = "\n".join([upload_id, session_id, str(int(expires)), str(size), sha256])
    return hmac.new(secret.encode(), msg.encode(), hashlib.sha256).hexdigest()


def create(cfg, db, session_id, size, sha256):
    upload_id = secrets.token_hex(16)
    expires = int(time.time()) + cfg.upload_url_ttl_seconds
    db.run("INSERT INTO uploads (id, session_id, size, sha256, expires_at) VALUES (?,?,?,?,?)",
           (upload_id, session_id, size, sha256, expires))
    sig = sign(cfg.signing_secret, upload_id, session_id, expires, size, sha256)
    url = f"{cfg.public_url}/uploads/{upload_id}?expires={expires}&sig={sig}"
    return upload_id, url, expires


def _err(status, message):
    return JSONResponse({"error": message}, status_code=status)


async def receive(request, cfg, db):
    """Handle PUT /uploads/<id>. No bearer token: the signature is the proof."""
    upload_id = request.path_params["upload_id"]
    row = db.one("SELECT * FROM uploads WHERE id=?", (upload_id,))
    try:
        expires = int(request.query_params.get("expires", ""))
    except ValueError:
        return _err(403, "bad signature")
    if row is None or expires != int(row["expires_at"]):
        return _err(403, "bad signature")
    good = sign(cfg.signing_secret, upload_id, row["session_id"], expires, row["size"], row["sha256"])
    if not hmac.compare_digest(good, request.query_params.get("sig", "")):
        return _err(403, "bad signature")
    if time.time() > expires:
        return _err(403, "upload URL has expired")
    # Claim the URL before reading the body, so two uploads cannot race.
    if db.run("UPDATE uploads SET used=1 WHERE id=? AND used=0", (upload_id,)) == 0:
        return _err(409, "upload URL was already used")

    limit = cfg.upload_max_mb * 1024 * 1024
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > limit:
        return _err(413, "archive is larger than the server limit")

    cfg.uploads_dir.mkdir(parents=True, exist_ok=True)
    dest = cfg.uploads_dir / f"{upload_id}.tar.gz"
    h, size = hashlib.sha256(), 0
    try:
        with open(dest, "wb") as out:
            async for chunk in request.stream():
                size += len(chunk)
                if size > limit:
                    raise OverflowError
                h.update(chunk)
                out.write(chunk)
    except OverflowError:
        dest.unlink(missing_ok=True)
        return _err(413, "archive is larger than the server limit")
    except OSError as e:
        dest.unlink(missing_ok=True)
        if e.errno == errno.ENOSPC:
            log.error("disk full while storing upload %s", upload_id)
            return _err(507, "the server disk is full")
        raise
    except Exception:
        dest.unlink(missing_ok=True)
        raise
    if size != row["size"] or h.hexdigest() != row["sha256"]:
        dest.unlink(missing_ok=True)
        return _err(400, "size or hash does not match what was declared")
    db.run("UPDATE uploads SET path=? WHERE id=?", (str(dest), upload_id))
    log.info("upload stored: %s (%d bytes)", upload_id, size)
    return JSONResponse({"ok": True}, status_code=201)


def take(db, upload_id, session_id):
    """Return the stored archive path for a finished upload of this session, or raise."""
    row = db.one("SELECT * FROM uploads WHERE id=? AND session_id=?", (upload_id, session_id))
    if row is None or not row["path"] or not Path(row["path"]).exists():
        raise UnpackError("upload not found, or the archive was not uploaded yet")
    return Path(row["path"])


def discard(db, upload_id):
    row = db.one("SELECT path FROM uploads WHERE id=?", (upload_id,))
    if row and row["path"]:
        Path(row["path"]).unlink(missing_ok=True)
    db.run("UPDATE uploads SET path=NULL WHERE id=?", (upload_id,))


def cleanup(db):
    """Delete archives and rows whose URL expired a while ago."""
    cutoff = time.time() - UPLOAD_GRACE_SECONDS
    for row in db.all("SELECT id, path FROM uploads WHERE expires_at < ?", (cutoff,)):
        if row["path"]:
            Path(row["path"]).unlink(missing_ok=True)
    return db.run("DELETE FROM uploads WHERE expires_at < ?", (cutoff,))


def unpack(archive, dest, expected, max_bytes):
    """Unpack a tar.gz into `dest` (a new, empty folder). Every file must be in `expected`
    ({path: sha256}) with a matching hash. Refuse the whole archive on any absolute path,
    '..', link, or device, or if it unpacks to more than `max_bytes`. Returns the paths written."""
    written, total = [], 0
    dest = Path(dest)
    try:
        with tarfile.open(archive, "r:gz") as tar:
            for m in tar:
                name = m.name.removeprefix("./").rstrip("/")
                if m.isdir():
                    if name and name != ".":
                        try:
                            check_rel_path(name)
                        except PathError as e:
                            raise UnpackError(f"archive has a bad path: {m.name!r}") from e
                    continue
                if not m.isreg():
                    raise UnpackError(f"archive has a link or special file: {m.name!r}")
                try:
                    check_rel_path(name)
                except PathError as e:
                    raise UnpackError(f"archive has a bad path: {m.name!r}") from e
                if name not in expected:
                    raise UnpackError(f"archive has a file that is not in the manifest: {name!r}")
                total += m.size
                if total > max_bytes:
                    raise UnpackError("archive is too large when unpacked")
                target = dest / name
                target.parent.mkdir(parents=True, exist_ok=True)
                h = hashlib.sha256()
                src = tar.extractfile(m)
                with open(target, "wb") as out:
                    for chunk in iter(lambda: src.read(CHUNK), b""):
                        h.update(chunk)
                        out.write(chunk)
                if h.hexdigest() != expected[name]:
                    raise UnpackError(f"hash does not match the manifest for {name!r}")
                written.append(name)
    except (tarfile.TarError, EOFError, OSError) as e:
        raise UnpackError(f"archive cannot be read: {type(e).__name__}") from e
    return written


def move_into(staging, code_dir, paths):
    """Move unpacked files from staging into the session's code folder."""
    for rel in paths:
        target = Path(code_dir) / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.is_symlink() or target.is_file():
            target.unlink()
        elif target.is_dir():
            shutil.rmtree(target)
        shutil.move(str(Path(staging) / rel), target)
