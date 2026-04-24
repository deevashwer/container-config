from __future__ import annotations

import asyncio
import threading
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from types import SimpleNamespace
from typing import TYPE_CHECKING
from urllib.parse import SplitResult, urlsplit, urlunsplit

import httpx
from fastapi import FastAPI, HTTPException, Request, Response, WebSocket, status
from fastapi.responses import JSONResponse, RedirectResponse

try:
    import websockets
    from websockets.exceptions import ConnectionClosed
except ImportError:  # pragma: no cover - exercised only when the local env lacks websocket support
    websockets = SimpleNamespace(connect=None)

    class ConnectionClosed(Exception):
        pass

if TYPE_CHECKING:
    try:
        from python_client.owner_auth_chat import BaseTransport, OwnerAuthProxyClient
    except ModuleNotFoundError:  # pragma: no cover - only used when running as a plain script
        from owner_auth_chat import BaseTransport, OwnerAuthProxyClient


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


def request_target(request: Request) -> str:
    query = request.url.query
    return f"{request.url.path}?{query}" if query else request.url.path


def build_upstream_url(base_url: str, *, path: str, query: str = "", websocket: bool = False) -> str:
    parts = urlsplit(base_url)
    scheme = parts.scheme
    if websocket:
        scheme = "wss" if scheme == "https" else "ws"
    normalized_path = path if path.startswith("/") else f"/{path}"
    upstream_parts = SplitResult(
        scheme=scheme,
        netloc=parts.netloc,
        path=f"{parts.path.rstrip('/')}{normalized_path}",
        query=query,
        fragment="",
    )
    return urlunsplit(upstream_parts)


def split_websocket_subprotocols(websocket: WebSocket) -> list[str]:
    raw_value = websocket.headers.get("sec-websocket-protocol", "")
    return [item.strip() for item in raw_value.split(",") if item.strip()]


def filter_upstream_request_headers(request: Request) -> dict[str, str]:
    forwarded_headers: dict[str, str] = {}
    for name, value in request.headers.items():
        lower_name = name.lower()
        if lower_name in HOP_BY_HOP_HEADERS:
            continue
        if lower_name == "host":
            continue
        if lower_name == "cookie":
            continue
        if lower_name == "origin":
            continue
        forwarded_headers[name] = value
    return forwarded_headers


def filter_upstream_response_headers(headers: httpx.Headers, *, remote_base_url: str) -> dict[str, str]:
    forwarded_headers: dict[str, str] = {}
    for name, value in headers.items():
        lower_name = name.lower()
        if lower_name in HOP_BY_HOP_HEADERS:
            continue
        if lower_name == "set-cookie":
            continue
        if lower_name == "location" and value.startswith(remote_base_url):
            value = value[len(remote_base_url) :] or "/"
        forwarded_headers[name] = value
    return forwarded_headers


def filter_upstream_websocket_headers(websocket: WebSocket, *, cookie_header: str | None) -> dict[str, str]:
    forwarded_headers: dict[str, str] = {}
    for name, value in websocket.headers.items():
        lower_name = name.lower()
        if lower_name in HOP_BY_HOP_HEADERS:
            continue
        if lower_name.startswith("sec-websocket-"):
            continue
        if lower_name == "host":
            continue
        if lower_name == "cookie":
            continue
        if lower_name == "origin":
            continue
        forwarded_headers[name] = value
    if cookie_header:
        forwarded_headers["Cookie"] = cookie_header
    return forwarded_headers


@dataclass(slots=True)
class RemoteGatewayStatus:
    transport: str
    workspace_path: str
    public_config: dict[str, object]
    verification_document: object | None


class AuthenticatedRemoteSession:
    """Keeps the owner key and remote auth session entirely in local Python."""

    def __init__(self, *, transport: BaseTransport, owner_client: OwnerAuthProxyClient) -> None:
        self.transport = transport
        self.owner_client = owner_client
        self._lock = threading.Lock()
        self.public_config: dict[str, object] = {}
        self.workspace_path = "/openclaw/"
        self.remote_base_url = getattr(transport, "base_url", "").rstrip("/")
        self._bootstrapped = False

    def bootstrap(self) -> RemoteGatewayStatus:
        with self._lock:
            if self._bootstrapped:
                return self.status()
            self.public_config = self.owner_client.load_public_config()
            self.owner_client.ensure_owner_key_matches()
            self.workspace_path = str(self.public_config.get("openclaw_workspace_path") or "/openclaw/")
            self.login()
            self._bootstrapped = True
            return self.status()

    def status(self) -> RemoteGatewayStatus:
        return RemoteGatewayStatus(
            transport=self.transport.describe(),
            workspace_path=self.workspace_path,
            public_config=self.public_config,
            verification_document=self.transport.get_verification_document(),
        )

    def login(self) -> None:
        response = self.owner_client.authenticated_request("POST", "/api/private/session/login")
        response.raise_for_status()

    def cookie_header(self) -> str:
        client = getattr(self.transport, "client", None)
        if client is None:
            return ""
        cookie_pairs = [f"{cookie.name}={cookie.value}" for cookie in client.cookies.jar]
        return "; ".join(cookie_pairs)

    def request(
        self,
        method: str,
        path: str,
        *,
        headers: dict[str, str] | None = None,
        content: bytes | None = None,
        retry_on_401: bool = True,
    ) -> httpx.Response:
        response = self.transport.request(method, path, headers=headers, content=content)
        if response.status_code == 401 and retry_on_401:
            with self._lock:
                self.login()
            response = self.transport.request(method, path, headers=headers, content=content)
        return response

    async def ensure_login(self) -> None:
        await asyncio.to_thread(self.login)

    def close(self) -> None:
        self.transport.close()


def create_browser_gateway_app(session: AuthenticatedRemoteSession) -> FastAPI:
    if not session.remote_base_url:
        raise ValueError("transport does not expose a remote base URL")

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        try:
            app.state.remote_status = await asyncio.to_thread(session.bootstrap)
            yield
        finally:
            session.close()

    app = FastAPI(title="OpenClaw Local Browser Gateway", lifespan=lifespan)
    app.state.remote_session = session

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/api/local/status")
    async def local_status() -> JSONResponse:
        status_payload = session.status()
        return JSONResponse(
            {
                "transport": status_payload.transport,
                "workspace_path": status_payload.workspace_path,
                "public_config": status_payload.public_config,
                "verification_document": status_payload.verification_document,
            }
        )

    @app.get("/", include_in_schema=False)
    async def root_redirect() -> RedirectResponse:
        return RedirectResponse(url=session.workspace_path, status_code=status.HTTP_307_TEMPORARY_REDIRECT)

    @app.api_route("/{path:path}", methods=PROXY_METHODS, include_in_schema=False)
    async def proxy_http(request: Request, path: str) -> Response:
        del path
        forwarded_headers = filter_upstream_request_headers(request)
        content = await request.body()
        upstream_response = await asyncio.to_thread(
            session.request,
            request.method,
            request_target(request),
            headers=forwarded_headers,
            content=content or None,
        )
        response_headers = filter_upstream_response_headers(
            upstream_response.headers,
            remote_base_url=session.remote_base_url,
        )
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

        if websockets.connect is None:
            await websocket.close(code=status.WS_1011_INTERNAL_ERROR, reason="websockets dependency is not installed")
            return

        await session.ensure_login()
        upstream_url = build_upstream_url(
            session.remote_base_url,
            path=websocket.url.path or "/",
            query=websocket.url.query,
            websocket=True,
        )
        additional_headers = filter_upstream_websocket_headers(
            websocket,
            cookie_header=session.cookie_header(),
        )
        subprotocols = split_websocket_subprotocols(websocket)
        remote_origin = session.remote_base_url

        try:
            async with websockets.connect(
                upstream_url,
                additional_headers=additional_headers,
                subprotocols=subprotocols or None,
                open_timeout=20,
                max_size=None,
                origin=remote_origin,
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
        except ConnectionClosed:
            if websocket.client_state.name == "CONNECTED":
                await websocket.close()
        except Exception as exc:
            if websocket.client_state.name != "CONNECTED":
                await websocket.close(code=status.WS_1011_INTERNAL_ERROR)
            else:
                await websocket.close(code=status.WS_1011_INTERNAL_ERROR, reason=str(exc))

    @app.exception_handler(HTTPException)
    async def http_error_handler(request: Request, exc: HTTPException) -> JSONResponse:
        del request
        return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)

    return app
