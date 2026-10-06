"""All settings, read from environment variables in one place."""

import os
from dataclasses import dataclass
from pathlib import Path


class ConfigError(Exception):
    pass


def _req(env, name):
    value = env.get(name, "").strip()
    if not value:
        raise ConfigError(f"Missing required environment variable {name}")
    return value


def _bool(value):
    return value.strip().lower() in ("1", "true", "yes", "on")


@dataclass(frozen=True)
class Config:
    host: str
    port: int
    public_url: str
    tokens_file: Path
    signing_secret: str
    data_dir: Path
    upload_max_mb: int
    upload_max_unpacked_mb: int
    upload_url_ttl_seconds: int
    llm_base_url: str
    llm_api_key: str
    llm_model: str
    llm_context_tokens: int
    llm_timeout_seconds: int
    llm_max_parallel: int
    llm_tool_calling: bool
    semgrep_configs: list[str]
    sonar_host_url: str
    sonar_token: str
    sonar_issue_types: list[str]
    git_clone_timeout_seconds: int
    tls_cert: Path | None = None
    tls_key: Path | None = None
    web_search_url: str | None = None  # a SearXNG instance; None turns the agents' web tools off

    @property
    def db_path(self):
        return self.data_dir / "harness.db"

    @property
    def sessions_dir(self):
        return self.data_dir / "sessions"

    @property
    def uploads_dir(self):
        return self.data_dir / "uploads"


def _tls(env):
    cert, key = env.get("HARNESS_TLS_CERT", "").strip(), env.get("HARNESS_TLS_KEY", "").strip()
    if bool(cert) != bool(key):
        raise ConfigError("Set both HARNESS_TLS_CERT and HARNESS_TLS_KEY, or neither")
    for name, value in (("HARNESS_TLS_CERT", cert), ("HARNESS_TLS_KEY", key)):
        if value and not Path(value).is_file():
            raise ConfigError(f"{name} file not found: {value}")
    return (Path(cert), Path(key)) if cert else (None, None)


def load(env=None):
    env = os.environ if env is None else env
    tls_cert, tls_key = _tls(env)
    try:
        return Config(
            host=env.get("HARNESS_HOST", "0.0.0.0"),
            port=int(env.get("HARNESS_PORT", "8080")),
            public_url=_req(env, "HARNESS_PUBLIC_URL").rstrip("/"),
            tokens_file=Path(_req(env, "HARNESS_TOKENS_FILE")),
            signing_secret=_req(env, "HARNESS_SIGNING_SECRET"),
            data_dir=Path(env.get("HARNESS_DATA_DIR", "/data")),
            upload_max_mb=int(env.get("UPLOAD_MAX_MB", "200")),
            upload_max_unpacked_mb=int(env.get("UPLOAD_MAX_UNPACKED_MB", "1000")),
            upload_url_ttl_seconds=int(env.get("UPLOAD_URL_TTL_SECONDS", "600")),
            llm_base_url=_req(env, "LLM_BASE_URL"),
            llm_api_key=_req(env, "LLM_API_KEY"),
            llm_model=_req(env, "LLM_MODEL"),
            llm_context_tokens=int(env.get("LLM_CONTEXT_TOKENS", "32000")),
            llm_timeout_seconds=int(env.get("LLM_TIMEOUT_SECONDS", "120")),
            llm_max_parallel=int(env.get("LLM_MAX_PARALLEL", "2")),
            llm_tool_calling=_bool(env.get("LLM_TOOL_CALLING", "true")),
            semgrep_configs=env.get("SEMGREP_CONFIGS", "/opt/semgrep-rules").split(","),
            sonar_host_url=_req(env, "SONAR_HOST_URL").rstrip("/"),
            sonar_token=_req(env, "SONAR_TOKEN"),
            sonar_issue_types=env.get("SONAR_ISSUE_TYPES", "VULNERABILITY,BUG").split(","),
            git_clone_timeout_seconds=int(env.get("GIT_CLONE_TIMEOUT_SECONDS", "300")),
            tls_cert=tls_cert,
            tls_key=tls_key,
            web_search_url=env.get("WEB_SEARCH_URL", "").strip().rstrip("/") or None,
        )
    except ValueError as e:
        raise ConfigError(f"Bad number in environment: {e}") from e
