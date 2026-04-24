from __future__ import annotations

import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass

import httpx
from fastapi import Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse

from .models import ChallengeRequest, ChallengeResponse, PublicConfigResponse
from .security import (
    AUTH_VERSION,
    ChallengeError,
    InMemoryChallengeStore,
    normalize_method,
    normalize_path,
    sha256_hex,
    verify_signature,
)
from .settings import Settings, get_settings


HOP_BY_HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
}
PROXY_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]


@dataclass(frozen=True, slots=True)
class VerifiedRequest:
    key_id: str
    challenge_id: str
    method: str
    path: str


def request_target(request: Request) -> str:
    query = request.url.query
    return f"{request.url.path}?{query}" if query else request.url.path


def filter_upstream_request_headers(request: Request) -> dict[str, str]:
    forwarded_headers: dict[str, str] = {}
    for name, value in request.headers.items():
        lower_name = name.lower()
        if lower_name in HOP_BY_HOP_HEADERS:
            continue
        if lower_name.startswith("x-auth-"):
            continue
        if lower_name == "host":
            continue
        forwarded_headers[name] = value
    return forwarded_headers


def filter_upstream_response_headers(headers: httpx.Headers) -> dict[str, str]:
    forwarded_headers: dict[str, str] = {}
    for name, value in headers.items():
        if name.lower() in HOP_BY_HOP_HEADERS:
            continue
        forwarded_headers[name] = value
    return forwarded_headers


def get_runtime_settings(request: Request) -> Settings:
    return request.app.state.settings


def get_challenge_store(request: Request) -> InMemoryChallengeStore:
    return request.app.state.challenge_store


async def require_owner_auth(request: Request) -> VerifiedRequest:
    settings = get_runtime_settings(request)
    if settings.owner_public_key is None or settings.owner_key_id is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="OWNER_PUBLIC_KEY_JWK is not configured",
        )

    challenge_id = request.headers.get("x-auth-challenge-id", "").strip()
    signature = request.headers.get("x-auth-signature", "").strip()
    key_id = request.headers.get("x-auth-key-id", "").strip()
    if not challenge_id or not signature or not key_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="missing auth headers",
        )
    if key_id != settings.owner_key_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="unknown owner key",
        )

    body = await request.body()
    method = normalize_method(request.method)
    path = normalize_path(request_target(request))
    body_sha256 = sha256_hex(body)

    challenge_store = get_challenge_store(request)
    try:
        challenge = await challenge_store.consume(challenge_id)
    except ChallengeError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
        ) from exc

    if challenge.method != method:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="challenge method mismatch",
        )
    if challenge.path != path:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="challenge path mismatch",
        )
    if challenge.body_sha256 != body_sha256:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="challenge body hash mismatch",
        )

    verified = verify_signature(
        public_key=settings.owner_public_key,
        signature_b64url=signature,
        signing_payload=challenge.signing_payload,
    )
    if not verified:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid signature",
        )

    return VerifiedRequest(
        key_id=key_id,
        challenge_id=challenge_id,
        method=method,
        path=path,
    )


def build_upstream_url(base_url: str, request: Request) -> str:
    path = request.url.path or "/"
    url = f"{base_url.rstrip('/')}{path}"
    if request.url.query:
        url = f"{url}?{request.url.query}"
    return url


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    yield


def create_app(settings: Settings | None = None) -> FastAPI:
    runtime_settings = settings or get_settings()

    app = FastAPI(title=runtime_settings.app_name, lifespan=lifespan)
    app.state.settings = runtime_settings
    app.state.challenge_store = InMemoryChallengeStore(runtime_settings.challenge_ttl_seconds)

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/api/public/config", response_model=PublicConfigResponse)
    async def public_config(runtime: Settings = Depends(get_runtime_settings)) -> PublicConfigResponse:
        return PublicConfigResponse(
            app_name=runtime.app_name,
            challenge_ttl_seconds=runtime.challenge_ttl_seconds,
            owner_key_id=runtime.owner_key_id,
            owner_key_configured=runtime.owner_public_key is not None,
        )

    @app.post("/api/public/challenge", response_model=ChallengeResponse)
    async def create_challenge(
        payload: ChallengeRequest,
        challenge_store: InMemoryChallengeStore = Depends(get_challenge_store),
        runtime: Settings = Depends(get_runtime_settings),
    ) -> ChallengeResponse:
        challenge = await challenge_store.issue(
            method=payload.method,
            path=payload.path,
            body_sha256=payload.body_sha256,
        )
        return ChallengeResponse(
            challenge_id=challenge.challenge_id,
            nonce=challenge.nonce,
            expires_at=challenge.expires_at,
            key_id=runtime.owner_key_id,
            signing_payload=challenge.signing_payload,
            version=AUTH_VERSION,
        )

    @app.api_route("/", methods=PROXY_METHODS, include_in_schema=False)
    @app.api_route("/{path:path}", methods=PROXY_METHODS, include_in_schema=False)
    async def proxy_everything(
        request: Request,
        path: str = "",
        verified: VerifiedRequest = Depends(require_owner_auth),
        runtime: Settings = Depends(get_runtime_settings),
    ) -> Response:
        del path
        del verified

        if not runtime.upstream_base_url:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="UPSTREAM_BASE_URL is not configured",
            )

        upstream_url = build_upstream_url(runtime.upstream_base_url, request)
        content = await request.body()
        headers = filter_upstream_request_headers(request)
        timeout = httpx.Timeout(runtime.upstream_timeout_seconds)

        async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client:
            upstream_response = await client.request(
                method=request.method,
                url=upstream_url,
                headers=headers,
                content=content,
            )

        response_headers = filter_upstream_response_headers(upstream_response.headers)
        media_type = upstream_response.headers.get("content-type")
        return Response(
            content=upstream_response.content,
            status_code=upstream_response.status_code,
            headers=response_headers,
            media_type=media_type,
        )

    @app.exception_handler(HTTPException)
    async def http_error_handler(
        request: Request,
        exc: HTTPException,
    ) -> JSONResponse:
        del request
        return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)

    return app


app = create_app()


if __name__ == "__main__":
    import uvicorn

    port = int(os.getenv("PORT", "8080"))
    uvicorn.run("app.main:app", host="0.0.0.0", port=port, reload=False)
