from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache
from urllib.parse import urlsplit

DEFAULT_PUBLIC_PATH_PATTERNS = (
    "/",
    "/assets/*",
    "/favicon.svg",
    "/healthz",
    "/api/public/*",
)


@dataclass(frozen=True, slots=True)
class Settings:
    app_name: str
    port: int
    challenge_ttl_seconds: int
    upstream_base_url: str | None
    aux_application_base_url: str | None
    aux_application_path_prefix: str | None
    openclaw_bootstrap_base_url: str | None
    upstream_origin: str | None
    upstream_timeout_seconds: float
    bootstrap_timeout_seconds: float
    public_path_patterns: tuple[str, ...]
    session_ttl_seconds: int
    session_cookie_name: str
    session_cookie_secure: bool
    session_cookie_samesite: str
    openclaw_workspace_path: str
    passkey_store_path: str
    passkey_rp_id: str | None
    passkey_rp_name: str


def build_settings(
    *,
    upstream_base_url: str | None,
    aux_application_base_url: str | None = None,
    aux_application_path_prefix: str | None = "/aux-application",
    openclaw_bootstrap_base_url: str | None = None,
    upstream_origin: str | None = None,
    port: int = 8080,
    app_name: str = "OpenClaw Auth Proxy",
    challenge_ttl_seconds: int = 60,
    upstream_timeout_seconds: float = 20.0,
    bootstrap_timeout_seconds: float = 90.0,
    public_path_patterns: tuple[str, ...] = DEFAULT_PUBLIC_PATH_PATTERNS,
    session_ttl_seconds: int = 60 * 60 * 12,
    session_cookie_name: str = "openclaw_passkey_session",
    session_cookie_secure: bool = False,
    session_cookie_samesite: str = "lax",
    openclaw_workspace_path: str = "/openclaw/",
    passkey_store_path: str = "/tmp/openclaw-passkeys.json",
    passkey_rp_id: str | None = None,
    passkey_rp_name: str | None = None,
) -> Settings:
    resolved_upstream_origin = upstream_origin
    if resolved_upstream_origin is None and upstream_base_url:
        parts = urlsplit(upstream_base_url)
        if parts.scheme and parts.netloc:
            resolved_upstream_origin = f"{parts.scheme}://{parts.netloc}"

    return Settings(
        app_name=app_name,
        port=port,
        challenge_ttl_seconds=challenge_ttl_seconds,
        upstream_base_url=upstream_base_url,
        aux_application_base_url=aux_application_base_url,
        aux_application_path_prefix=(aux_application_path_prefix.strip().rstrip("/") or "/aux-application")
        if aux_application_path_prefix
        else None,
        openclaw_bootstrap_base_url=openclaw_bootstrap_base_url,
        upstream_origin=resolved_upstream_origin,
        upstream_timeout_seconds=upstream_timeout_seconds,
        bootstrap_timeout_seconds=bootstrap_timeout_seconds,
        public_path_patterns=public_path_patterns,
        session_ttl_seconds=session_ttl_seconds,
        session_cookie_name=session_cookie_name,
        session_cookie_secure=session_cookie_secure,
        session_cookie_samesite=session_cookie_samesite,
        openclaw_workspace_path=openclaw_workspace_path,
        passkey_store_path=passkey_store_path,
        passkey_rp_id=passkey_rp_id.strip() or None if passkey_rp_id else None,
        passkey_rp_name=(passkey_rp_name or app_name).strip() or app_name,
    )


def _parse_bool(raw_value: str | None, default: bool) -> bool:
    if raw_value is None:
        return default
    return raw_value.strip().lower() in {"1", "true", "yes", "on"}


def _parse_patterns(raw_value: str | None) -> tuple[str, ...]:
    if not raw_value:
        return DEFAULT_PUBLIC_PATH_PATTERNS
    parts = []
    for chunk in raw_value.replace("\n", ",").split(","):
        value = chunk.strip()
        if value:
            parts.append(value)
    return tuple(parts) or DEFAULT_PUBLIC_PATH_PATTERNS


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    upstream_base_url = os.getenv("UPSTREAM_BASE_URL", "").strip()
    if not upstream_base_url:
        upstream_base_url = os.getenv("OPENCLAW_BASE_URL", "").strip()

    return build_settings(
        app_name=os.getenv("APP_NAME", "OpenClaw Auth Proxy"),
        port=int(os.getenv("PORT", "8080")),
        upstream_base_url=upstream_base_url or None,
        aux_application_base_url=os.getenv("AUX_APPLICATION_BASE_URL", "").strip() or None,
        aux_application_path_prefix=os.getenv("AUX_APPLICATION_PATH_PREFIX", "/aux-application").strip() or "/aux-application",
        openclaw_bootstrap_base_url=os.getenv("OPENCLAW_BOOTSTRAP_BASE_URL", "").strip() or None,
        upstream_origin=os.getenv("UPSTREAM_ORIGIN", "").strip() or None,
        challenge_ttl_seconds=int(os.getenv("CHALLENGE_TTL_SECONDS", "60")),
        upstream_timeout_seconds=float(os.getenv("UPSTREAM_TIMEOUT_SECONDS", "20")),
        bootstrap_timeout_seconds=float(os.getenv("BOOTSTRAP_TIMEOUT_SECONDS", "90")),
        public_path_patterns=_parse_patterns(os.getenv("PUBLIC_PATH_PATTERNS")),
        session_ttl_seconds=int(os.getenv("SESSION_TTL_SECONDS", str(60 * 60 * 12))),
        session_cookie_name=os.getenv("SESSION_COOKIE_NAME", "openclaw_passkey_session").strip(),
        session_cookie_secure=_parse_bool(os.getenv("SESSION_COOKIE_SECURE"), False),
        session_cookie_samesite=os.getenv("SESSION_COOKIE_SAMESITE", "lax").strip().lower(),
        openclaw_workspace_path=os.getenv("OPENCLAW_WORKSPACE_PATH", "/openclaw/").strip() or "/openclaw/",
        passkey_store_path=os.getenv("PASSKEY_STORE_PATH", "/tmp/openclaw-passkeys.json").strip()
        or "/tmp/openclaw-passkeys.json",
        passkey_rp_id=os.getenv("PASSKEY_RP_ID", "").strip() or None,
        passkey_rp_name=os.getenv("PASSKEY_RP_NAME", "").strip() or None,
    )
