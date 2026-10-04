"""Bearer-token auth. The tokens file holds only SHA-256 hashes of tokens.

File format (JSON): {"users": [{"user_id": "...", "name": "...", "token_sha256": "..."}]}
"""

import argparse
import hashlib
import hmac
import json
import secrets
import sys
from pathlib import Path


def hash_token(token):
    return hashlib.sha256(token.encode()).hexdigest()


def _read(path):
    path = Path(path)
    if not path.exists():
        return {"users": []}
    return json.loads(path.read_text())


def lookup(tokens_file, token):
    """Return the user id for a plain token, or None."""
    if not token:
        return None
    digest = hash_token(token)
    found = None
    # Check every entry so timing does not depend on where the match is.
    for user in _read(tokens_file)["users"]:
        if hmac.compare_digest(user["token_sha256"], digest):
            found = user["user_id"]
    return found


def bearer(headers):
    """Extract the token from an Authorization header mapping, or None."""
    value = headers.get("authorization") or headers.get("Authorization") or ""
    scheme, _, token = value.partition(" ")
    return token.strip() if scheme.lower() == "bearer" else None


def add_user(tokens_file, user_id, name):
    """Create a new token for a user, store its hash, and return the plain token."""
    token = secrets.token_urlsafe(32)
    data = _read(tokens_file)
    data["users"] = [u for u in data["users"] if u["user_id"] != user_id]
    data["users"].append({"user_id": user_id, "name": name, "token_sha256": hash_token(token)})
    path = Path(tokens_file)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2))
    return token


class BearerAuthMiddleware:
    """Reject requests to /mcp without a known bearer token (HTTP 401)."""

    def __init__(self, app, tokens_file):
        self.app = app
        self.tokens_file = tokens_file

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http" and scope["path"].startswith("/mcp"):
            headers = {k.decode().lower(): v.decode() for k, v in scope["headers"]}
            if lookup(self.tokens_file, bearer(headers)) is None:
                await send({"type": "http.response.start", "status": 401,
                            "headers": [(b"content-type", b"application/json"),
                                        (b"www-authenticate", b"Bearer")]})
                await send({"type": "http.response.body", "body": b'{"error":"unauthorized"}'})
                return
        await self.app(scope, receive, send)


def cli(argv=None):
    p = argparse.ArgumentParser(description="Create a token for a user. The token is printed once.")
    p.add_argument("user_id")
    p.add_argument("--name", default="")
    p.add_argument("--file", help="tokens file (default: $HARNESS_TOKENS_FILE)")
    args = p.parse_args(argv)
    import os
    tokens_file = args.file or os.environ.get("HARNESS_TOKENS_FILE")
    if not tokens_file:
        p.error("set --file or HARNESS_TOKENS_FILE")
    token = add_user(tokens_file, args.user_id, args.name or args.user_id)
    sys.stdout.write(token + "\n")
