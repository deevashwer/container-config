from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class PublicConfigResponse(BaseModel):
    app_name: str
    challenge_ttl_seconds: int
    ownership_claimed: bool
    initialization_available: bool
    passkey_count: int
    public_path_patterns: list[str]
    session_cookie_name: str
    openclaw_workspace_path: str


class SessionResponse(BaseModel):
    authenticated: bool
    credential_id: str | None
    auth_kind: str | None
    expires_at: datetime | None = None


class UpstreamBootstrapRequest(BaseModel):
    env: dict[str, str] = Field(default_factory=dict)


class PasskeyAttestationResponse(BaseModel):
    clientDataJSON: str = Field(min_length=1)
    attestationObject: str = Field(min_length=1)


class PasskeyAssertionResponse(BaseModel):
    clientDataJSON: str = Field(min_length=1)
    authenticatorData: str = Field(min_length=1)
    signature: str = Field(min_length=1)
    userHandle: str | None = None


class PasskeyRegistrationCredential(BaseModel):
    id: str = Field(min_length=1)
    rawId: str = Field(min_length=1)
    type: str = Field(min_length=1)
    response: PasskeyAttestationResponse


class PasskeyAuthenticationCredential(BaseModel):
    id: str = Field(min_length=1)
    rawId: str = Field(min_length=1)
    type: str = Field(min_length=1)
    response: PasskeyAssertionResponse


class PasskeyInitializationFinishRequest(BaseModel):
    challenge_id: str = Field(min_length=1)
    credential: PasskeyRegistrationCredential
    bootstrap_env: dict[str, str] = Field(default_factory=dict)


class PasskeyAuthenticationFinishRequest(BaseModel):
    challenge_id: str = Field(min_length=1)
    credential: PasskeyAuthenticationCredential
    bootstrap_env: dict[str, str] = Field(default_factory=dict)
