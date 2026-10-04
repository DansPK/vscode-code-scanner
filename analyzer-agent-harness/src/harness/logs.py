"""Logging setup: one line per record, tagged with the current session and scan ids."""

import contextvars
import logging
import re
import sys

context = contextvars.ContextVar("log_context", default={})


def bind(**ids):
    """Add ids (session, scan) to every log line in the current task from now on."""
    context.set({**context.get(), **{k: v for k, v in ids.items() if v}})


class ContextFilter(logging.Filter):
    def filter(self, record):
        ids = context.get()
        record.ctx = "".join(f" {k}={v}" for k, v in ids.items())
        return True


class RedactingFormatter(logging.Formatter):
    """Upload URLs carry a signature (for example in uvicorn's access log). Never print it."""

    SIG = re.compile(r"(sig=)[0-9a-fA-F]+")

    def format(self, record):
        return self.SIG.sub(r"\1***", super().format(record))


def setup(level=logging.INFO):
    handler = logging.StreamHandler(sys.stderr)
    handler.addFilter(ContextFilter())
    handler.setFormatter(RedactingFormatter("%(asctime)s %(levelname)s %(name)s%(ctx)s: %(message)s"))
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(level)
    # LiteLLM can log request bodies (code, keys) at debug level, and prints help banners.
    for noisy in ("LiteLLM", "litellm", "httpx", "httpcore"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
    import litellm
    litellm.suppress_debug_info = True
