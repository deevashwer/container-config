from __future__ import annotations

import json
import os
from dataclasses import dataclass
from functools import lru_cache
from typing import Any
from urllib.parse import urlsplit

from cryptography.hazmat.primitives.asymmetric import ec

from .security import key_id_from_public_jwk, public_key_from_jwk


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
    owner_public_key_jwk: dict[str, Any] | None
    owner_public_key: ec.EllipticCurvePublicKey | None
    owner_key_id: str | None
    challenge_ttl_seconds: int
    upstream_base_url: str | None
    upstream_origin: str | None
    upstream_timeout_seconds: float
    public_path_patterns: tuple[str, ...]
    session_ttl_seconds: int
    session_cookie_name: str
    session_cookie_secure: bool
    session_cookie_samesite: str
    openclaw_workspace_path: str


def build_settings(
    *,
    owner_public_key_jwk: dict[str, Any] | None,
    upstream_base_url: str | None,
    upstream_origin: str | None = None,
    port: int = 8080,
    app_name: str = "OpenClaw Auth Proxy",
    challenge_ttl_seconds: int = 60,
    upstream_timeout_seconds: float = 20.0,
    public_path_patterns: tuple[str, ...] = DEFAULT_PUBLIC_PATH_PATTERNS,
    session_ttl_seconds: int = 60 * 60 * 12,
    session_cookie_name: str = "openclaw_owner_session",
    session_cookie_secure: bool = False,
    session_cookie_samesite: str = "lax",
    openclaw_workspace_path: str = "/openclaw/",
) -> Settings:
    owner_public_key = None
    owner_key_id = None
    if owner_public_key_jwk is not None:
        owner_public_key = public_key_from_jwk(owner_public_key_jwk)
        owner_key_id = key_id_from_public_jwk(owner_public_key_jwk)

    resolved_upstream_origin = upstream_origin
    if resolved_upstream_origin is None and upstream_base_url:
        parts = urlsplit(upstream_base_url)
        if parts.scheme and parts.netloc:
            resolved_upstream_origin = f"{parts.scheme}://{parts.netloc}"

    return Settings(
        app_name=app_name,
        port=port,
        owner_public_key_jwk=owner_public_key_jwk,
        owner_public_key=owner_public_key,
        owner_key_id=owner_key_id,
        challenge_ttl_seconds=challenge_ttl_seconds,
        upstream_base_url=upstream_base_url,
        upstream_origin=resolved_upstream_origin,
        upstream_timeout_seconds=upstream_timeout_seconds,
        public_path_patterns=public_path_patterns,
        session_ttl_seconds=session_ttl_seconds,
        session_cookie_name=session_cookie_name,
        session_cookie_secure=session_cookie_secure,
        session_cookie_samesite=session_cookie_samesite,
        openclaw_workspace_path=openclaw_workspace_path,
    )


def _parse_optional_json(raw_value: str | None) -> dict[str, Any] | None:
    if not raw_value:
        return None
    return json.loads(raw_value)


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
        owner_public_key_jwk=_parse_optional_json(os.getenv("OWNER_PUBLIC_KEY_JWK")),
        upstream_base_url=upstream_base_url or None,
        upstream_origin=os.getenv("UPSTREAM_ORIGIN", "").strip() or None,
        challenge_ttl_seconds=int(os.getenv("CHALLENGE_TTL_SECONDS", "60")),
        upstream_timeout_seconds=float(os.getenv("UPSTREAM_TIMEOUT_SECONDS", "20")),
        public_path_patterns=_parse_patterns(os.getenv("PUBLIC_PATH_PATTERNS")),
        session_ttl_seconds=int(os.getenv("SESSION_TTL_SECONDS", str(60 * 60 * 12))),
        session_cookie_name=os.getenv("SESSION_COOKIE_NAME", "openclaw_owner_session").strip(),
        session_cookie_secure=_parse_bool(os.getenv("SESSION_COOKIE_SECURE"), False),
        session_cookie_samesite=os.getenv("SESSION_COOKIE_SAMESITE", "lax").strip().lower(),
        openclaw_workspace_path=os.getenv("OPENCLAW_WORKSPACE_PATH", "/openclaw/").strip() or "/openclaw/",
    )
