from __future__ import annotations

import json
import os
from dataclasses import dataclass
from functools import lru_cache
from typing import Any

from cryptography.hazmat.primitives.asymmetric import ec

from .security import key_id_from_public_jwk, public_key_from_jwk


@dataclass(frozen=True, slots=True)
class Settings:
    app_name: str
    port: int
    owner_public_key_jwk: dict[str, Any] | None
    owner_public_key: ec.EllipticCurvePublicKey | None
    owner_key_id: str | None
    challenge_ttl_seconds: int
    upstream_base_url: str | None
    upstream_timeout_seconds: float


def build_settings(
    *,
    owner_public_key_jwk: dict[str, Any] | None,
    upstream_base_url: str | None,
    port: int = 8080,
    app_name: str = "OpenClaw Auth Proxy",
    challenge_ttl_seconds: int = 60,
    upstream_timeout_seconds: float = 20.0,
) -> Settings:
    owner_public_key = None
    owner_key_id = None
    if owner_public_key_jwk is not None:
        owner_public_key = public_key_from_jwk(owner_public_key_jwk)
        owner_key_id = key_id_from_public_jwk(owner_public_key_jwk)

    return Settings(
        app_name=app_name,
        port=port,
        owner_public_key_jwk=owner_public_key_jwk,
        owner_public_key=owner_public_key,
        owner_key_id=owner_key_id,
        challenge_ttl_seconds=challenge_ttl_seconds,
        upstream_base_url=upstream_base_url,
        upstream_timeout_seconds=upstream_timeout_seconds,
    )


def _parse_optional_json(raw_value: str | None) -> dict[str, Any] | None:
    if not raw_value:
        return None
    return json.loads(raw_value)


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
        challenge_ttl_seconds=int(os.getenv("CHALLENGE_TTL_SECONDS", "60")),
        upstream_timeout_seconds=float(os.getenv("UPSTREAM_TIMEOUT_SECONDS", "20")),
    )
