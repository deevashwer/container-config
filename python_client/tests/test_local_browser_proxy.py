from __future__ import annotations

import asyncio
import sys
from dataclasses import dataclass
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import python_client.local_browser_proxy as gateway_module
from python_client.local_browser_proxy import AuthenticatedRemoteSession, RemoteGatewayStatus, create_browser_gateway_app


class FakeTransport:
    def __init__(self) -> None:
        self.base_url = "https://remote.example"
        self.client = httpx.Client(base_url=self.base_url)
        self.requests: list[tuple[str, str, dict[str, str] | None, bytes | None]] = []
        self.responses: list[httpx.Response] = []
        self.closed = False

    def request(
        self,
        method: str,
        path: str,
        *,
        headers: dict[str, str] | None = None,
        content: bytes | None = None,
    ) -> httpx.Response:
        self.requests.append((method, path, headers, content))
        if self.responses:
            return self.responses.pop(0)
        return httpx.Response(200, json={"ok": True}, request=httpx.Request(method, f"{self.base_url}{path}"))

    def get_verification_document(self) -> object:
        return {"security_verified": True}

    def describe(self) -> str:
        return "verified transport"

    def close(self) -> None:
        self.closed = True
        self.client.close()


class FakeOwnerClient:
    def __init__(self, transport: FakeTransport) -> None:
        self.transport = transport
        self.load_calls = 0
        self.ensure_calls = 0
        self.login_calls = 0

    def load_public_config(self) -> dict[str, object]:
        self.load_calls += 1
        return {
            "app_name": "OpenClaw Auth Proxy",
            "owner_key_id": "owner-key-1",
            "owner_key_configured": True,
            "openclaw_workspace_path": "/openclaw/",
            "public_path_patterns": ["/api/public/*"],
        }

    def ensure_owner_key_matches(self) -> None:
        self.ensure_calls += 1

    def login_session(self) -> dict[str, object]:
        self.login_calls += 1
        self.transport.client.cookies.set("openclaw_owner_session", "session-cookie")
        return {"authenticated": True}


@dataclass
class DummyUpstreamWebSocket:
    url: str
    additional_headers: dict[str, str] | None
    subprotocols: list[str] | None
    origin: str | None
    subprotocol: str | None = None
    sent_messages: list[str | bytes] | None = None
    _queue: asyncio.Queue[str | bytes | None] | None = None

    def __post_init__(self) -> None:
        self.subprotocol = self.subprotocols[0] if self.subprotocols else None
        self.sent_messages = []
        self._queue = asyncio.Queue()

    async def __aenter__(self) -> "DummyUpstreamWebSocket":
        return self

    async def __aexit__(self, exc_type, exc, tb) -> bool:
        return False

    async def send(self, message: str | bytes) -> None:
        assert self.sent_messages is not None
        assert self._queue is not None
        self.sent_messages.append(message)
        await self._queue.put(f"echo:{message}" if isinstance(message, str) else message)
        await self._queue.put(None)

    def __aiter__(self) -> "DummyUpstreamWebSocket":
        return self

    async def __anext__(self) -> str | bytes:
        assert self._queue is not None
        item = await self._queue.get()
        if item is None:
            raise StopAsyncIteration
        return item


class DummyWebSocketsModule:
    last_connection: DummyUpstreamWebSocket | None = None

    @classmethod
    def connect(
        cls,
        url: str,
        *,
        additional_headers: dict[str, str] | None = None,
        subprotocols: list[str] | None = None,
        open_timeout: float | None = None,
        max_size: int | None = None,
        origin: str | None = None,
    ) -> DummyUpstreamWebSocket:
        del open_timeout
        del max_size
        cls.last_connection = DummyUpstreamWebSocket(
            url=url,
            additional_headers=additional_headers,
            subprotocols=subprotocols,
            origin=origin,
        )
        return cls.last_connection


class FakeGatewaySession:
    def __init__(self) -> None:
        self.remote_base_url = "https://remote.example"
        self.workspace_path = "/openclaw/"
        self.public_config = {
            "app_name": "OpenClaw Auth Proxy",
            "openclaw_workspace_path": "/openclaw/",
            "public_path_patterns": ["/api/public/*"],
        }
        self.verification_document = {"security_verified": True}
        self.request_calls: list[tuple[str, str, dict[str, str] | None, bytes | None, bool]] = []
        self.login_calls = 0
        self.closed = False

    def bootstrap(self) -> RemoteGatewayStatus:
        return self.status()

    def status(self) -> RemoteGatewayStatus:
        return RemoteGatewayStatus(
            transport="verified transport",
            workspace_path=self.workspace_path,
            remote_base_url=self.remote_base_url,
            public_config=self.public_config,
            verification_document=self.verification_document,
        )

    def request(
        self,
        method: str,
        path: str,
        *,
        headers: dict[str, str] | None = None,
        content: bytes | None = None,
        retry_on_401: bool = True,
    ) -> httpx.Response:
        self.request_calls.append((method, path, headers, content, retry_on_401))
        return httpx.Response(
            200,
            json={"forwarded": True, "path": path},
            headers={"content-type": "application/json", "location": "https://remote.example/openclaw/"},
            request=httpx.Request(method, f"{self.remote_base_url}{path}"),
        )

    async def ensure_login(self) -> None:
        self.login_calls += 1

    def cookie_header(self) -> str:
        return "openclaw_owner_session=session-cookie"

    def close(self) -> None:
        self.closed = True


def test_remote_session_bootstrap_logs_in_and_exposes_status() -> None:
    transport = FakeTransport()
    owner_client = FakeOwnerClient(transport)
    session = AuthenticatedRemoteSession(transport=transport, owner_client=owner_client)

    status_payload = session.bootstrap()

    assert owner_client.load_calls == 1
    assert owner_client.ensure_calls == 1
    assert owner_client.login_calls == 1
    assert status_payload.workspace_path == "/openclaw/"
    assert status_payload.remote_base_url == "https://remote.example"
    assert status_payload.transport == "verified transport"
    assert session.cookie_header() == "openclaw_owner_session=session-cookie"


def test_remote_session_request_retries_after_401() -> None:
    transport = FakeTransport()
    owner_client = FakeOwnerClient(transport)
    session = AuthenticatedRemoteSession(transport=transport, owner_client=owner_client)
    session.bootstrap()
    transport.responses = [
        httpx.Response(401, request=httpx.Request("GET", "https://remote.example/openclaw/")),
        httpx.Response(200, json={"ok": True}, request=httpx.Request("GET", "https://remote.example/openclaw/")),
    ]

    response = session.request("GET", "/openclaw/")

    assert response.status_code == 200
    assert owner_client.login_calls == 2
    assert len(transport.requests) == 2


@pytest.fixture(autouse=True)
def patch_websockets(monkeypatch) -> None:
    DummyWebSocketsModule.last_connection = None
    monkeypatch.setattr(gateway_module.websockets, "connect", DummyWebSocketsModule.connect)


def test_browser_gateway_root_renders_verification_landing_page() -> None:
    app = create_browser_gateway_app(FakeGatewaySession())

    with TestClient(app) as client:
        response = client.get("/")

    assert response.status_code == 200
    assert "Attestation checked locally before the browser session begins." in response.text
    assert 'href="/openclaw/"' in response.text
    assert "https://remote.example" in response.text


def test_browser_gateway_reports_local_status() -> None:
    app = create_browser_gateway_app(FakeGatewaySession())

    with TestClient(app) as client:
        response = client.get("/api/local/status")

    assert response.status_code == 200
    body = response.json()
    assert body["transport"] == "verified transport"
    assert body["workspace_path"] == "/openclaw/"
    assert body["remote_base_url"] == "https://remote.example"
    assert body["verification_document"]["security_verified"] is True


def test_browser_gateway_proxies_http_requests() -> None:
    session = FakeGatewaySession()
    app = create_browser_gateway_app(session)

    with TestClient(app) as client:
        response = client.get("/openclaw/__openclaw/control-ui-config.json", headers={"origin": "http://127.0.0.1:8090"})

    assert response.status_code == 200
    assert response.json()["forwarded"] is True
    assert response.headers["location"] == "/openclaw/"
    assert session.request_calls[0][0] == "GET"
    assert session.request_calls[0][1] == "/openclaw/__openclaw/control-ui-config.json"
    assert "Origin" not in (session.request_calls[0][2] or {})


def test_browser_gateway_proxies_websockets() -> None:
    session = FakeGatewaySession()
    app = create_browser_gateway_app(session)

    with TestClient(app) as client:
        with client.websocket_connect("/openclaw/ws", subprotocols=["oc-protocol"]) as websocket:
            websocket.send_text("ping")
            assert websocket.receive_text() == "echo:ping"

    assert session.login_calls == 1
    assert DummyWebSocketsModule.last_connection is not None
    assert DummyWebSocketsModule.last_connection.url == "wss://remote.example/openclaw/ws"
    assert DummyWebSocketsModule.last_connection.origin == "https://remote.example"
    assert DummyWebSocketsModule.last_connection.additional_headers is not None
    assert "Origin" not in DummyWebSocketsModule.last_connection.additional_headers
    assert DummyWebSocketsModule.last_connection.additional_headers["Cookie"] == "openclaw_owner_session=session-cookie"
