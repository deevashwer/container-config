from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class PublicConfigResponse(BaseModel):
    app_name: str
    challenge_ttl_seconds: int
    owner_key_id: str | None
    owner_key_configured: bool
    public_path_patterns: list[str]
    session_cookie_name: str
    openclaw_workspace_path: str


class ChallengeRequest(BaseModel):
    method: str = Field(min_length=1, max_length=12)
    path: str = Field(min_length=1)
    body_sha256: str = Field(min_length=64, max_length=64)


class ChallengeResponse(BaseModel):
    challenge_id: str
    nonce: str
    expires_at: datetime
    key_id: str | None
    signing_payload: str
    version: str


class SessionResponse(BaseModel):
    authenticated: bool
    key_id: str | None
    auth_kind: str | None
    expires_at: datetime | None = None


class UpstreamBootstrapRequest(BaseModel):
    env: dict[str, str] = Field(default_factory=dict)


class SessionLoginRequest(BaseModel):
    bootstrap_env: dict[str, str] = Field(default_factory=dict)
