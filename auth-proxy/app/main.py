from __future__ import annotations

import asyncio
import fnmatch
import json
import logging
import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import SplitResult, urlsplit, urlunsplit

import httpx
from fastapi import Depends, FastAPI, HTTPException, Request, Response, WebSocket, status
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

try:
    import websockets
    from websockets.exceptions import ConnectionClosed, InvalidStatus
except ImportError:  # pragma: no cover - exercised only in minimal local test envs
    websockets = SimpleNamespace(connect=None)

    class ConnectionClosed(Exception):
        pass

    class InvalidStatus(Exception):
        response = None

from .models import (
    ChallengeRequest,
    ChallengeResponse,
    PublicConfigResponse,
    SessionLoginRequest,
    SessionResponse,
    UpstreamBootstrapRequest,
)
from .security import (
    AUTH_VERSION,
    ChallengeError,
    InMemoryChallengeStore,
    normalize_method,
    normalize_path,
    sha256_hex,
    verify_signature,
)
from .sessions import InMemorySessionStore, SessionError, StoredSession
from .settings import Settings, get_settings


STATIC_DIR = Path(__file__).resolve().parent / "static"
LOGGER = logging.getLogger("openclaw_auth_proxy")
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
WEBSOCKET_CLOSE_UNAUTHORIZED = 4401
PROXY_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]


@dataclass(frozen=True, slots=True)
class VerifiedRequest:
    key_id: str
    auth_kind: str
    challenge_id: str | None = None
    expires_at: datetime | None = None


def request_target(request: Request) -> str:
    query = request.url.query
    return f"{request.url.path}?{query}" if query else request.url.path


def normalize_forwarded_proto(scheme: str) -> str:
    if scheme == "ws":
        return "http"
    if scheme == "wss":
        return "https"
    return scheme


def forwarded_port_from_host(host: str | None, *, scheme: str) -> str:
    if host:
        if host.startswith("[") and "]:" in host:
            return host.rsplit("]:", 1)[1]
        if host.count(":") == 1:
            return host.rsplit(":", 1)[1]
    normalized_scheme = normalize_forwarded_proto(scheme)
    if normalized_scheme == "https":
        return "443"
    if normalized_scheme == "http":
        return "80"
    return ""


def add_forwarded_proxy_headers(
    headers: dict[str, str],
    *,
    scheme: str,
    host: str | None,
    client_host: str | None,
) -> None:
    forwarded_proto = normalize_forwarded_proto(scheme)
    headers["X-Forwarded-Proto"] = forwarded_proto
    if host:
        headers["X-Forwarded-Host"] = host
        port = forwarded_port_from_host(host, scheme=scheme)
        if port:
            headers["X-Forwarded-Port"] = port
    if client_host:
        headers["X-Forwarded-For"] = client_host
        headers["X-Real-IP"] = client_host


def filter_upstream_request_headers(request: Request, *, upstream_origin: str | None) -> dict[str, str]:
    forwarded_headers: dict[str, str] = {}
    for name, value in request.headers.items():
        lower_name = name.lower()
        if lower_name in HOP_BY_HOP_HEADERS:
            continue
        if lower_name.startswith("x-auth-"):
            continue
        if lower_name == "host":
            continue
        if lower_name == "cookie":
            continue
        if lower_name in {"forwarded", "origin", "x-forwarded-for", "x-forwarded-host", "x-forwarded-port", "x-forwarded-proto", "x-real-ip"}:
            continue
        forwarded_headers[name] = value
    request_origin = request.headers.get("origin")
    if request_origin:
        forwarded_headers["Origin"] = request_origin
    elif upstream_origin:
        forwarded_headers["Origin"] = upstream_origin
    add_forwarded_proxy_headers(
        forwarded_headers,
        scheme=request.url.scheme,
        host=request.headers.get("host"),
        client_host=request.client.host if request.client else None,
    )
    return forwarded_headers


def filter_upstream_response_headers(headers: httpx.Headers) -> dict[str, str]:
    forwarded_headers: dict[str, str] = {}
    for name, value in headers.items():
        if name.lower() in HOP_BY_HOP_HEADERS:
            continue
        forwarded_headers[name] = value
    return forwarded_headers


def filter_upstream_websocket_headers(websocket: WebSocket) -> dict[str, str]:
    forwarded_headers: dict[str, str] = {}
    for name, value in websocket.headers.items():
        lower_name = name.lower()
        if lower_name in HOP_BY_HOP_HEADERS:
            continue
        if lower_name.startswith("sec-websocket-"):
            continue
        if lower_name.startswith("x-auth-"):
            continue
        if lower_name == "host":
            continue
        if lower_name == "cookie":
            continue
        if lower_name in {"forwarded", "origin", "x-forwarded-for", "x-forwarded-host", "x-forwarded-port", "x-forwarded-proto", "x-real-ip"}:
            continue
        forwarded_headers[name] = value
    add_forwarded_proxy_headers(
        forwarded_headers,
        scheme=websocket.url.scheme,
        host=websocket.headers.get("host"),
        client_host=websocket.client.host if websocket.client else None,
    )
    return forwarded_headers


def split_websocket_subprotocols(websocket: WebSocket) -> list[str]:
    raw_value = websocket.headers.get("sec-websocket-protocol", "")
    return [item.strip() for item in raw_value.split(",") if item.strip()]


def build_upstream_url(base_url: str, *, path: str, query: str = "", websocket: bool = False) -> str:
    parts = urlsplit(base_url)
    if websocket:
        scheme = "wss" if parts.scheme == "https" else "ws"
    else:
        scheme = parts.scheme
    normalized_path = path if path.startswith("/") else f"/{path}"
    upstream_parts = SplitResult(
        scheme=scheme,
        netloc=parts.netloc,
        path=f"{parts.path.rstrip('/')}{normalized_path}",
        query=query,
        fragment="",
    )
    return urlunsplit(upstream_parts)


def resolve_upstream_target(
    settings: Settings,
    *,
    path: str,
    query: str = "",
    websocket: bool = False,
) -> tuple[str, str]:
    aux_prefix = settings.aux_application_path_prefix
    if aux_prefix and settings.aux_application_base_url:
        if path == aux_prefix or path.startswith(f"{aux_prefix}/"):
            stripped_path = path[len(aux_prefix) :] or "/"
            if not stripped_path.startswith("/"):
                stripped_path = f"/{stripped_path}"
            return (
                build_upstream_url(
                    settings.aux_application_base_url,
                    path=stripped_path,
                    query=query,
                    websocket=websocket,
                ),
                settings.aux_application_base_url,
            )

    if not settings.upstream_base_url:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="UPSTREAM_BASE_URL is not configured",
        )
    return (
        build_upstream_url(
            settings.upstream_base_url,
            path=path,
            query=query,
            websocket=websocket,
        ),
        settings.upstream_base_url,
    )


def get_runtime_settings(request: Request) -> Settings:
    return request.app.state.settings


def get_challenge_store(request: Request) -> InMemoryChallengeStore:
    return request.app.state.challenge_store


def get_session_store(request: Request) -> InMemorySessionStore:
    return request.app.state.session_store


def sanitize_client_bootstrap_env(raw_env: dict[str, str] | None) -> dict[str, str]:
    if not raw_env:
        return {}
    allowed_keys = {"ANTHROPIC_API_KEY"}
    sanitized: dict[str, str] = {}
    for key, value in raw_env.items():
        if key not in allowed_keys:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"unsupported bootstrap env key: {key}",
            )
        normalized_value = str(value).strip()
        if normalized_value:
            sanitized[key] = normalized_value
    return sanitized


async def ensure_upstream_bootstrapped(app: FastAPI, bootstrap_env: dict[str, str] | None = None) -> None:
    settings: Settings = app.state.settings
    if not settings.openclaw_bootstrap_base_url:
        return
    if app.state.upstream_bootstrap_complete:
        return
    if not bootstrap_env:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="upstream bootstrap env is required before OpenClaw can start",
        )

    async with app.state.upstream_bootstrap_lock:
        if app.state.upstream_bootstrap_complete:
            return

        bootstrap_url = f"{settings.openclaw_bootstrap_base_url.rstrip('/')}/api/bootstrap/config"
        payload = UpstreamBootstrapRequest(env=bootstrap_env).model_dump(mode="json")
        timeout = httpx.Timeout(settings.bootstrap_timeout_seconds)
        try:
            async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client:
                response = await client.request(
                    method="POST",
                    url=bootstrap_url,
                    headers={"content-type": "application/json"},
                    content=json.dumps(payload, separators=(",", ":")).encode("utf-8"),
                )
        except httpx.TimeoutException as exc:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=(
                    "timed out waiting for upstream bootstrap to finish "
                    f"after {settings.bootstrap_timeout_seconds:.0f}s"
                ),
            ) from exc

        if response.status_code >= 400:
            detail = response.text or f"bootstrap request failed with status {response.status_code}"
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"failed to bootstrap upstream: {detail}",
            )

        app.state.upstream_bootstrap_complete = True


def path_matches_pattern(path: str, pattern: str) -> bool:
    normalized_pattern = pattern.strip()
    if not normalized_pattern:
        return False
    if normalized_pattern.endswith("/*"):
        prefix = normalized_pattern[:-2]
        return path == prefix or path.startswith(f"{prefix}/")
    return fnmatch.fnmatch(path, normalized_pattern)


def is_public_path(path: str, settings: Settings) -> bool:
    return any(path_matches_pattern(path, pattern) for pattern in settings.public_path_patterns)


async def require_owner_auth_headers(request: Request) -> VerifiedRequest:
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
        auth_kind="headers",
        challenge_id=challenge_id,
    )


async def try_session_auth(request: Request) -> VerifiedRequest | None:
    settings = get_runtime_settings(request)
    session_id = request.cookies.get(settings.session_cookie_name, "").strip()
    if not session_id:
        return None

    session_store = get_session_store(request)
    try:
        session = await session_store.get(session_id)
    except SessionError:
        return None

    return VerifiedRequest(
        key_id=session.key_id,
        auth_kind="session",
        expires_at=session.expires_at,
    )


async def require_authenticated_request(request: Request) -> VerifiedRequest:
    verified = await try_session_auth(request)
    if verified is not None:
        return verified
    return await require_owner_auth_headers(request)


async def require_websocket_session(websocket: WebSocket) -> StoredSession:
    settings: Settings = websocket.app.state.settings
    session_id = websocket.cookies.get(settings.session_cookie_name, "").strip()
    if not session_id:
        await websocket.close(code=WEBSOCKET_CLOSE_UNAUTHORIZED, reason="missing session cookie")
        raise RuntimeError("missing session cookie")

    session_store: InMemorySessionStore = websocket.app.state.session_store
    try:
        return await session_store.get(session_id)
    except SessionError as exc:
        await websocket.close(code=WEBSOCKET_CLOSE_UNAUTHORIZED, reason=str(exc))
        raise RuntimeError(str(exc)) from exc


def set_session_cookie(response: Response, *, settings: Settings, session: StoredSession) -> None:
    response.set_cookie(
        key=settings.session_cookie_name,
        value=session.session_id,
        max_age=settings.session_ttl_seconds,
        expires=session.expires_at,
        httponly=True,
        secure=settings.session_cookie_secure,
        samesite=settings.session_cookie_samesite,
        path="/",
    )


def clear_session_cookie(response: Response, *, settings: Settings) -> None:
    response.delete_cookie(
        key=settings.session_cookie_name,
        httponly=True,
        secure=settings.session_cookie_secure,
        samesite=settings.session_cookie_samesite,
        path="/",
    )


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    yield


def create_app(settings: Settings | None = None) -> FastAPI:
    runtime_settings = settings or get_settings()

    app = FastAPI(title=runtime_settings.app_name, lifespan=lifespan)
    app.state.settings = runtime_settings
    app.state.challenge_store = InMemoryChallengeStore(runtime_settings.challenge_ttl_seconds)
    app.state.session_store = InMemorySessionStore(runtime_settings.session_ttl_seconds)
    app.state.upstream_bootstrap_lock = asyncio.Lock()
    app.state.upstream_bootstrap_complete = False
    app.mount("/assets", StaticFiles(directory=STATIC_DIR / "assets"), name="assets")

    @app.get("/", include_in_schema=False)
    async def dashboard() -> FileResponse:
        return FileResponse(STATIC_DIR / "index.html")

    @app.get("/favicon.svg", include_in_schema=False)
    async def favicon() -> FileResponse:
        return FileResponse(STATIC_DIR / "favicon.svg", media_type="image/svg+xml")

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
            public_path_patterns=list(runtime.public_path_patterns),
            session_cookie_name=runtime.session_cookie_name,
            openclaw_workspace_path=runtime.openclaw_workspace_path,
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

    @app.post("/api/private/session/login", response_model=SessionResponse)
    async def login_session(
        payload: SessionLoginRequest,
        verified: VerifiedRequest = Depends(require_owner_auth_headers),
        runtime: Settings = Depends(get_runtime_settings),
        session_store: InMemorySessionStore = Depends(get_session_store),
    ) -> Response:
        await ensure_upstream_bootstrapped(app, sanitize_client_bootstrap_env(payload.bootstrap_env))
        session = await session_store.issue(key_id=verified.key_id)
        response_payload = SessionResponse(
            authenticated=True,
            key_id=session.key_id,
            auth_kind="session",
            expires_at=session.expires_at,
        )
        response = JSONResponse(response_payload.model_dump(mode="json"))
        set_session_cookie(response, settings=runtime, session=session)
        return response

    @app.post("/api/private/bootstrap")
    async def bootstrap_upstream(
        payload: UpstreamBootstrapRequest,
        verified: VerifiedRequest = Depends(require_authenticated_request),
    ) -> dict[str, object]:
        del verified
        sanitized_env = sanitize_client_bootstrap_env(payload.env)
        await ensure_upstream_bootstrapped(app, sanitized_env)
        return {
            "bootstrapped": True,
            "env_keys": sorted(sanitized_env.keys()),
        }

    @app.get("/api/private/session", response_model=SessionResponse)
    async def session_status(request: Request) -> SessionResponse:
        verified = await require_authenticated_request(request)
        return SessionResponse(
            authenticated=True,
            key_id=verified.key_id,
            auth_kind=verified.auth_kind,
            expires_at=verified.expires_at,
        )

    @app.post("/api/private/session/logout", response_model=SessionResponse)
    async def logout_session(
        request: Request,
        runtime: Settings = Depends(get_runtime_settings),
        session_store: InMemorySessionStore = Depends(get_session_store),
    ) -> Response:
        session_id = request.cookies.get(runtime.session_cookie_name, "").strip()
        if session_id:
            await session_store.revoke(session_id)
        response = JSONResponse(
            SessionResponse(
                authenticated=False,
                key_id=None,
                auth_kind=None,
                expires_at=None,
            ).model_dump(mode="json")
        )
        clear_session_cookie(response, settings=runtime)
        return response

    @app.api_route("/{path:path}", methods=PROXY_METHODS, include_in_schema=False)
    async def proxy_http(
        request: Request,
        path: str,
        runtime: Settings = Depends(get_runtime_settings),
    ) -> Response:
        del path

        if not is_public_path(request.url.path, runtime):
            await require_authenticated_request(request)
            if runtime.openclaw_bootstrap_base_url and not app.state.upstream_bootstrap_complete:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="upstream bootstrap has not completed; initialize the session first",
                )

        upstream_url, upstream_origin_base = resolve_upstream_target(
            runtime,
            path=request.url.path or "/",
            query=request.url.query,
        )
        content = await request.body()
        upstream_origin = runtime.upstream_origin
        if runtime.aux_application_base_url and upstream_origin_base == runtime.aux_application_base_url:
            upstream_origin = None
        headers = filter_upstream_request_headers(request, upstream_origin=upstream_origin)
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

    @app.websocket("/{path:path}")
    async def proxy_websocket(websocket: WebSocket, path: str) -> None:
        del path

        runtime: Settings = websocket.app.state.settings
        browser_origin = websocket.headers.get("origin")
        browser_host = websocket.headers.get("host")
        client_host = websocket.client.host if websocket.client else None
        if websockets.connect is None:
            await websocket.close(code=status.WS_1011_INTERNAL_ERROR, reason="websockets dependency is not installed")
            return

        if not is_public_path(websocket.url.path, runtime):
            try:
                await require_websocket_session(websocket)
                if runtime.openclaw_bootstrap_base_url and not websocket.app.state.upstream_bootstrap_complete:
                    await websocket.close(
                        code=status.WS_1011_INTERNAL_ERROR,
                        reason="upstream bootstrap has not completed",
                    )
                    return
            except RuntimeError as exc:
                LOGGER.warning(
                    "rejecting websocket before upstream connect path=%s client=%s host=%s origin=%s reason=%s",
                    websocket.url.path,
                    client_host or "n/a",
                    browser_host or "n/a",
                    browser_origin or "n/a",
                    str(exc),
                )
                return
        try:
            upstream_url, upstream_origin_base = resolve_upstream_target(
                runtime,
                path=websocket.url.path or "/",
                query=websocket.url.query,
                websocket=True,
            )
        except HTTPException as exc:
            await websocket.close(code=status.WS_1011_INTERNAL_ERROR, reason=str(exc.detail))
            return
        forwarded_headers = filter_upstream_websocket_headers(websocket)
        subprotocols = split_websocket_subprotocols(websocket)
        upstream_origin = browser_origin or runtime.upstream_origin
        if runtime.aux_application_base_url and upstream_origin_base == runtime.aux_application_base_url:
            upstream_origin = browser_origin or None

        try:
            async with websockets.connect(
                upstream_url,
                additional_headers=forwarded_headers,
                subprotocols=subprotocols or None,
                open_timeout=runtime.upstream_timeout_seconds,
                max_size=None,
                origin=upstream_origin,
            ) as upstream:
                await websocket.accept(subprotocol=upstream.subprotocol)

                async def browser_to_upstream() -> None:
                    while True:
                        message = await websocket.receive()
                        message_type = message["type"]
                        if message_type == "websocket.disconnect":
                            break
                        if message_type != "websocket.receive":
                            continue
                        if message.get("text") is not None:
                            await upstream.send(message["text"])
                        elif message.get("bytes") is not None:
                            await upstream.send(message["bytes"])

                async def upstream_to_browser() -> None:
                    async for message in upstream:
                        if isinstance(message, str):
                            await websocket.send_text(message)
                        else:
                            await websocket.send_bytes(message)

                tasks = {
                    asyncio.create_task(browser_to_upstream()),
                    asyncio.create_task(upstream_to_browser()),
                }
                done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
                for task in pending:
                    task.cancel()
                for task in done:
                    task.result()
        except InvalidStatus as exc:
            status_code = getattr(getattr(exc, "response", None), "status_code", "n/a")
            reason = getattr(getattr(exc, "response", None), "reason_phrase", "n/a")
            LOGGER.warning(
                "upstream websocket handshake rejected path=%s client=%s host=%s origin=%s upstream=%s status=%s reason=%s",
                websocket.url.path,
                client_host or "n/a",
                browser_host or "n/a",
                browser_origin or "n/a",
                upstream_url,
                status_code,
                reason,
            )
            if websocket.client_state.name != "CONNECTED":
                await websocket.close(code=status.WS_1011_INTERNAL_ERROR, reason="upstream websocket handshake rejected")
            else:
                await websocket.close(code=status.WS_1011_INTERNAL_ERROR, reason="upstream websocket handshake rejected")
        except ConnectionClosed:
            if websocket.client_state.name == "CONNECTED":
                await websocket.close()
        except Exception:
            LOGGER.exception(
                "upstream websocket proxy error path=%s client=%s host=%s origin=%s upstream=%s",
                websocket.url.path,
                client_host or "n/a",
                browser_host or "n/a",
                browser_origin or "n/a",
                upstream_url,
            )
            if websocket.client_state.name != "CONNECTED":
                await websocket.close(code=status.WS_1011_INTERNAL_ERROR)
            else:
                await websocket.close(code=status.WS_1011_INTERNAL_ERROR, reason="upstream websocket error")

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
