from __future__ import annotations

import asyncio
import html
import json
import threading
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import asdict, dataclass, is_dataclass
from enum import Enum
from types import SimpleNamespace
from typing import TYPE_CHECKING
from urllib.parse import SplitResult, urlsplit, urlunsplit

import httpx
from fastapi import FastAPI, HTTPException, Request, Response, WebSocket, status
from fastapi.responses import HTMLResponse, JSONResponse

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
    remote_base_url: str
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
            remote_base_url=self.remote_base_url,
            public_config=self.public_config,
            verification_document=self.transport.get_verification_document(),
        )

    def login(self) -> None:
        self.owner_client.login_session()

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

    def jsonable(value: object) -> object:
        if is_dataclass(value):
            return {key: jsonable(item) for key, item in asdict(value).items()}
        if isinstance(value, Enum):
            return value.value
        if isinstance(value, dict):
            return {str(key): jsonable(item) for key, item in value.items()}
        if isinstance(value, (list, tuple)):
            return [jsonable(item) for item in value]
        return value

    def render_dashboard(status_payload: RemoteGatewayStatus) -> str:
        verification = jsonable(status_payload.verification_document) if status_payload.verification_document is not None else None
        security_verified = bool(getattr(status_payload.verification_document, "security_verified", False))
        if isinstance(verification, dict):
            security_verified = bool(verification.get("security_verified", security_verified))

        remote_host = status_payload.remote_base_url or "remote enclave"
        workspace_path = status_payload.workspace_path or "/openclaw/"
        pretty_verification = json.dumps(verification or {"security_verified": False}, indent=2)
        verification_state = "Verified" if security_verified else "Unverified"
        verification_color = "#2d6a4f" if security_verified else "#9a3412"
        verification_bg = "#e8f5e9" if security_verified else "#fff7ed"
        verification_copy = (
            "The local Python gateway verified the remote enclave attestation and pinned the attested TLS key "
            "before minting the upstream session."
            if security_verified
            else "This local gateway is running, but the upstream attestation is not marked verified."
        )
        escaped_remote_host = html.escape(remote_host)
        escaped_workspace_path = html.escape(workspace_path)
        escaped_transport = html.escape(status_payload.transport)
        escaped_verification_copy = html.escape(verification_copy)
        escaped_pretty_verification = html.escape(pretty_verification)

        return f"""<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>OpenClaw Verified Local Gateway</title>
    <style>
      :root {{
        color-scheme: light;
        --bg: #f5f1e8;
        --card: #fffdf8;
        --ink: #1f2933;
        --muted: #52606d;
        --border: #d9cbb5;
        --accent: #0f766e;
      }}
      * {{ box-sizing: border-box; }}
      body {{
        margin: 0;
        font-family: "Iowan Old Style", "Palatino Linotype", "Book Antiqua", serif;
        background:
          radial-gradient(circle at top left, rgba(15, 118, 110, 0.12), transparent 32rem),
          linear-gradient(180deg, #f7f2e9 0%, var(--bg) 100%);
        color: var(--ink);
      }}
      main {{
        max-width: 980px;
        margin: 0 auto;
        padding: 48px 20px 64px;
      }}
      .hero {{
        display: grid;
        gap: 18px;
        margin-bottom: 28px;
      }}
      .eyebrow {{
        font: 600 0.84rem/1.2 ui-monospace, "SFMono-Regular", "SF Mono", Consolas, monospace;
        letter-spacing: 0.08em;
        text-transform: uppercase;
        color: var(--accent);
      }}
      h1 {{
        margin: 0;
        font-size: clamp(2.2rem, 6vw, 4rem);
        line-height: 0.96;
      }}
      .lede {{
        max-width: 52rem;
        font-size: 1.06rem;
        line-height: 1.6;
        color: var(--muted);
      }}
      .grid {{
        display: grid;
        gap: 16px;
        grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
        margin-bottom: 24px;
      }}
      .card {{
        background: var(--card);
        border: 1px solid var(--border);
        border-radius: 18px;
        padding: 18px;
        box-shadow: 0 10px 24px rgba(31, 41, 51, 0.05);
      }}
      .status-card {{
        background: {verification_bg};
        border-color: rgba(31, 41, 51, 0.08);
      }}
      .label {{
        font: 600 0.78rem/1.2 ui-monospace, "SFMono-Regular", "SF Mono", Consolas, monospace;
        letter-spacing: 0.08em;
        text-transform: uppercase;
        color: var(--muted);
        margin-bottom: 8px;
      }}
      .value {{
        font-size: 1.15rem;
        line-height: 1.35;
        word-break: break-word;
      }}
      .pill {{
        display: inline-flex;
        align-items: center;
        gap: 0.5rem;
        padding: 0.42rem 0.75rem;
        border-radius: 999px;
        font: 700 0.85rem/1 ui-monospace, "SFMono-Regular", "SF Mono", Consolas, monospace;
        background: rgba(255,255,255,0.72);
        color: {verification_color};
        border: 1px solid rgba(31,41,51,0.08);
      }}
      .actions {{
        display: flex;
        flex-wrap: wrap;
        gap: 12px;
        margin: 24px 0 8px;
      }}
      .button {{
        display: inline-flex;
        align-items: center;
        justify-content: center;
        min-height: 48px;
        padding: 0 20px;
        border-radius: 999px;
        text-decoration: none;
        font-weight: 700;
        border: 1px solid transparent;
      }}
      .button-primary {{
        background: var(--accent);
        color: #f8fffd;
      }}
      .button-secondary {{
        background: rgba(255,255,255,0.72);
        color: var(--ink);
        border-color: var(--border);
      }}
      pre {{
        margin: 0;
        padding: 18px;
        overflow-x: auto;
        border-radius: 18px;
        border: 1px solid #1f29331a;
        background: #102a43;
        color: #d9e2ec;
        font: 500 0.85rem/1.55 ui-monospace, "SFMono-Regular", "SF Mono", Consolas, monospace;
      }}
      .footer-note {{
        margin-top: 14px;
        color: var(--muted);
        line-height: 1.6;
      }}
    </style>
  </head>
  <body>
    <main>
      <section class="hero">
        <div class="eyebrow">Verified Local Gateway</div>
        <h1>Attestation checked locally before the browser session begins.</h1>
        <div class="lede">
          <p>{escaped_verification_copy}</p>
          <p>
            Your browser is connected to this local gateway, not directly to <code>{escaped_remote_host}</code>.
            The local gateway holds the owner state and upstream session cookie, then proxies your
            OpenClaw traffic onward. The remote TLS connection terminates inside the enclave on the
            gateway’s verified upstream side.
          </p>
        </div>
      </section>

      <section class="grid">
        <article class="card status-card">
          <div class="label">Verification</div>
          <div class="pill">{verification_state}</div>
          <p class="footer-note">All remote browser requests continue through this local proxy to preserve the verified path.</p>
        </article>
        <article class="card">
          <div class="label">Remote Enclave</div>
          <div class="value"><code>{escaped_remote_host}</code></div>
        </article>
        <article class="card">
          <div class="label">Workspace Path</div>
          <div class="value"><code>{escaped_workspace_path}</code></div>
        </article>
        <article class="card">
          <div class="label">Transport</div>
          <div class="value">{escaped_transport}</div>
        </article>
      </section>

      <div class="actions">
        <a class="button button-primary" href="{escaped_workspace_path}">Open OpenClaw</a>
        <a class="button button-secondary" href="/api/local/status">Raw Verification JSON</a>
      </div>

      <section class="card">
        <div class="label">Verification Document</div>
        <pre>{escaped_pretty_verification}</pre>
      </section>
    </main>
  </body>
</html>"""

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
                "remote_base_url": status_payload.remote_base_url,
                "public_config": status_payload.public_config,
                "verification_document": jsonable(status_payload.verification_document),
            }
        )

    @app.get("/", include_in_schema=False)
    async def landing_page() -> HTMLResponse:
        return HTMLResponse(render_dashboard(session.status()))

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
