from __future__ import annotations

import asyncio
import hashlib
import sys
from dataclasses import dataclass
from pathlib import Path

import httpx
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

APP_ROOT = Path(__file__).resolve().parents[1]
if str(APP_ROOT) not in sys.path:
    sys.path.insert(0, str(APP_ROOT))

import app.main as main_module
from app.main import WEBSOCKET_CLOSE_UNAUTHORIZED, create_app
from app.security import (
    base64url_encode,
    key_id_from_public_jwk,
    public_jwk_from_key,
)
from app.settings import build_settings


class DummyAsyncClient:
    last_request: dict[str, object] | None = None
    requests: list[dict[str, object]] = []

    def __init__(self, *args, **kwargs) -> None:
        self.args = args
        self.kwargs = kwargs

    async def __aenter__(self) -> "DummyAsyncClient":
        return self

    async def __aexit__(self, exc_type, exc, tb) -> bool:
        return False

    async def request(
        self,
        method: str,
        url: str,
        headers: dict[str, str] | None = None,
        content: bytes | None = None,
    ) -> httpx.Response:
        DummyAsyncClient.last_request = {
            "method": method,
            "url": url,
            "headers": headers or {},
            "content": content or b"",
        }
        DummyAsyncClient.requests.append(DummyAsyncClient.last_request)
        request = httpx.Request(method, url)
        if url == "http://bootstrap/api/bootstrap/config":
            return httpx.Response(
                200,
                json={"status": "ready", "ready": True},
                headers={"content-type": "application/json"},
                request=request,
            )
        return httpx.Response(
            200,
            json={"forwarded": True, "url": url},
            headers={"content-type": "application/json", "x-upstream": "ok"},
            request=request,
        )


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


def make_client(
    *,
    public_patterns: tuple[str, ...] = ("/", "/assets/*", "/favicon.svg", "/healthz", "/api/public/*"),
    aux_application_base_url: str | None = None,
    aux_application_path_prefix: str = "/aux-application",
) -> tuple[TestClient, ec.EllipticCurvePrivateKey]:
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_jwk = public_jwk_from_key(private_key.public_key())
    settings = build_settings(
        owner_public_key_jwk=public_jwk,
        upstream_base_url="http://example-upstream",
        aux_application_base_url=aux_application_base_url,
        aux_application_path_prefix=aux_application_path_prefix,
        challenge_ttl_seconds=60,
        session_ttl_seconds=300,
        session_cookie_name="proxy-session",
        public_path_patterns=public_patterns,
    )
    return TestClient(create_app(settings)), private_key


def sign_payload(private_key: ec.EllipticCurvePrivateKey, payload: str) -> str:
    signature = private_key.sign(payload.encode("utf-8"), ec.ECDSA(hashes.SHA256()))
    return base64url_encode(signature)


def sign_payload_raw_p1363(private_key: ec.EllipticCurvePrivateKey, payload: str) -> str:
    der_signature = private_key.sign(payload.encode("utf-8"), ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der_signature)
    raw_signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return base64url_encode(raw_signature)


def auth_headers(
    client: TestClient,
    private_key: ec.EllipticCurvePrivateKey,
    *,
    method: str,
    path: str,
    body: str = "",
    key_id: str | None = None,
    signing_key: ec.EllipticCurvePrivateKey | None = None,
) -> dict[str, str]:
    public_jwk = public_jwk_from_key(private_key.public_key())
    challenge = client.post(
        "/api/public/challenge",
        json={
            "method": method,
            "path": path,
            "body_sha256": hashlib.sha256(body.encode("utf-8")).hexdigest(),
        },
    )
    assert challenge.status_code == 200
    payload = challenge.json()
    return {
        "x-auth-challenge-id": payload["challenge_id"],
        "x-auth-key-id": key_id or key_id_from_public_jwk(public_jwk),
        "x-auth-signature": sign_payload(signing_key or private_key, payload["signing_payload"]),
    }


@pytest.fixture(autouse=True)
def patch_network_clients(monkeypatch) -> None:
    DummyAsyncClient.last_request = None
    DummyAsyncClient.requests = []
    DummyWebSocketsModule.last_connection = None
    monkeypatch.setattr(main_module.httpx, "AsyncClient", DummyAsyncClient)
    monkeypatch.setattr(main_module.websockets, "connect", DummyWebSocketsModule.connect)


def test_public_config_is_accessible_without_auth() -> None:
    client, private_key = make_client()
    del private_key

    response = client.get("/api/public/config")

    assert response.status_code == 200
    assert response.json()["session_cookie_name"] == "proxy-session"
    assert response.json()["owner_key_configured"] is True


def test_root_dashboard_is_public() -> None:
    client, private_key = make_client()
    del private_key

    response = client.get("/")

    assert response.status_code == 200
    assert "OpenClaw Secure Console" in response.text


def test_static_assets_are_public() -> None:
    client, private_key = make_client()
    del private_key

    response = client.get("/assets/app.js")

    assert response.status_code == 200
    assert "OwnerAuthBrowserClient" in response.text


def test_favicon_is_public() -> None:
    client, private_key = make_client()
    del private_key

    response = client.get("/favicon.svg")

    assert response.status_code == 200
    assert "<svg" in response.text


def test_proxy_forwards_authenticated_request() -> None:
    client, private_key = make_client()
    headers = auth_headers(
        client,
        private_key,
        method="GET",
        path="/openclaw/__openclaw/control-ui-config.json",
    )
    headers["origin"] = "http://127.0.0.1:8080"

    response = client.get("/openclaw/__openclaw/control-ui-config.json", headers=headers)

    assert response.status_code == 200
    assert response.json()["forwarded"] is True
    assert DummyAsyncClient.last_request is not None
    assert DummyAsyncClient.last_request["url"] == "http://example-upstream/openclaw/__openclaw/control-ui-config.json"
    assert "x-auth-signature" not in DummyAsyncClient.last_request["headers"]
    assert DummyAsyncClient.last_request["headers"]["Origin"] == "http://127.0.0.1:8080"
    assert DummyAsyncClient.last_request["headers"]["X-Forwarded-Proto"] == "http"
    assert DummyAsyncClient.last_request["headers"]["X-Forwarded-Host"] == "testserver"


def test_proxy_accepts_browser_style_raw_signature() -> None:
    client, private_key = make_client()
    public_jwk = public_jwk_from_key(private_key.public_key())
    challenge = client.post(
        "/api/public/challenge",
        json={
            "method": "GET",
            "path": "/openclaw/__openclaw/control-ui-config.json",
            "body_sha256": hashlib.sha256(b"").hexdigest(),
        },
    )
    assert challenge.status_code == 200
    payload = challenge.json()

    response = client.get(
        "/openclaw/__openclaw/control-ui-config.json",
        headers={
            "x-auth-challenge-id": payload["challenge_id"],
            "x-auth-key-id": key_id_from_public_jwk(public_jwk),
            "x-auth-signature": sign_payload_raw_p1363(private_key, payload["signing_payload"]),
        },
    )

    assert response.status_code == 200
    assert response.json()["forwarded"] is True


def test_proxy_rejects_missing_headers() -> None:
    client, private_key = make_client()
    del private_key

    response = client.get("/openclaw")

    assert response.status_code == 401
    assert response.json()["detail"] == "missing auth headers"


def test_proxy_rejects_replayed_challenge() -> None:
    client, private_key = make_client()
    headers = auth_headers(client, private_key, method="GET", path="/openclaw")

    first = client.get("/openclaw", headers=headers)
    second = client.get("/openclaw", headers=headers)

    assert first.status_code == 200
    assert second.status_code == 401
    assert second.json()["detail"] == "challenge already used"


def test_proxy_rejects_path_mismatch() -> None:
    client, private_key = make_client()
    headers = auth_headers(client, private_key, method="GET", path="/openclaw")

    response = client.get("/different-path", headers=headers)

    assert response.status_code == 401
    assert response.json()["detail"] == "challenge path mismatch"


def test_proxy_rejects_method_mismatch() -> None:
    client, private_key = make_client()
    headers = auth_headers(client, private_key, method="GET", path="/openclaw")

    response = client.post("/openclaw", headers=headers)

    assert response.status_code == 401
    assert response.json()["detail"] == "challenge method mismatch"


def test_proxy_rejects_body_hash_mismatch() -> None:
    client, private_key = make_client()
    headers = auth_headers(client, private_key, method="POST", path="/openclaw", body="")

    response = client.post("/openclaw", headers=headers, content=b'{"changed":true}')

    assert response.status_code == 401
    assert response.json()["detail"] == "challenge body hash mismatch"


def test_proxy_rejects_unknown_owner_key() -> None:
    client, private_key = make_client()
    other_private_key = ec.generate_private_key(ec.SECP256R1())
    other_public_jwk = public_jwk_from_key(other_private_key.public_key())
    headers = auth_headers(
        client,
        private_key,
        method="GET",
        path="/openclaw",
        key_id=key_id_from_public_jwk(other_public_jwk),
    )

    response = client.get("/openclaw", headers=headers)

    assert response.status_code == 401
    assert response.json()["detail"] == "unknown owner key"


def test_proxy_rejects_invalid_signature() -> None:
    client, private_key = make_client()
    wrong_private_key = ec.generate_private_key(ec.SECP256R1())
    headers = auth_headers(
        client,
        private_key,
        method="GET",
        path="/openclaw",
        signing_key=wrong_private_key,
    )

    response = client.get("/openclaw", headers=headers)

    assert response.status_code == 401
    assert response.json()["detail"] == "invalid signature"


def test_session_login_creates_cookie_and_allows_followup_requests() -> None:
    client, private_key = make_client()
    request_body = '{"bootstrap_env":{"ANTHROPIC_API_KEY":"x"}}'
    headers = auth_headers(
        client,
        private_key,
        method="POST",
        path="/api/private/session/login",
        body=request_body,
    )

    login = client.post(
        "/api/private/session/login",
        headers={**headers, "content-type": "application/json"},
        content=request_body,
    )
    follow_up = client.get("/openclaw")

    assert login.status_code == 200
    assert login.json()["authenticated"] is True
    assert "proxy-session" in client.cookies
    assert follow_up.status_code == 200
    assert DummyAsyncClient.last_request is not None
    assert "cookie" not in {key.lower() for key in DummyAsyncClient.last_request["headers"]}


def test_session_status_supports_header_and_cookie_auth() -> None:
    client, private_key = make_client()
    direct_headers = auth_headers(
        client,
        private_key,
        method="GET",
        path="/api/private/session",
    )

    direct = client.get("/api/private/session", headers=direct_headers)

    login_headers = auth_headers(
        client,
        private_key,
        method="POST",
        path="/api/private/session/login",
        body='{"bootstrap_env":{"ANTHROPIC_API_KEY":"x"}}',
    )
    login = client.post(
        "/api/private/session/login",
        headers={**login_headers, "content-type": "application/json"},
        content='{"bootstrap_env":{"ANTHROPIC_API_KEY":"x"}}',
    )
    via_cookie = client.get("/api/private/session")

    assert direct.status_code == 200
    assert direct.json()["auth_kind"] == "headers"
    assert login.status_code == 200
    assert via_cookie.status_code == 200
    assert via_cookie.json()["auth_kind"] == "session"
    assert via_cookie.json()["expires_at"] is not None


def test_session_logout_clears_cookie_and_relocks_private_routes() -> None:
    client, private_key = make_client()
    request_body = '{"bootstrap_env":{"ANTHROPIC_API_KEY":"x"}}'
    headers = auth_headers(
        client,
        private_key,
        method="POST",
        path="/api/private/session/login",
        body=request_body,
    )
    client.post(
        "/api/private/session/login",
        headers={**headers, "content-type": "application/json"},
        content=request_body,
    )

    logout = client.post("/api/private/session/logout")
    locked = client.get("/openclaw")

    assert logout.status_code == 200
    assert logout.json()["authenticated"] is False
    assert "proxy-session" not in client.cookies
    assert locked.status_code == 401
    assert locked.json()["detail"] == "missing auth headers"


def test_public_routes_bypass_auth() -> None:
    client, private_key = make_client(
        public_patterns=("/", "/assets/*", "/favicon.svg", "/healthz", "/api/public/*", "/webhooks/*")
    )
    del private_key

    response = client.post("/webhooks/telegram", json={"ok": True})

    assert response.status_code == 200
    assert response.json()["forwarded"] is True
    assert DummyAsyncClient.last_request is not None
    assert DummyAsyncClient.last_request["url"] == "http://example-upstream/webhooks/telegram"


def test_aux_application_prefix_routes_to_alternate_upstream() -> None:
    client, private_key = make_client(aux_application_base_url="http://127.0.0.1:3000")
    headers = auth_headers(
        client,
        private_key,
        method="GET",
        path="/aux-application/index.html",
    )

    response = client.get("/aux-application/index.html", headers=headers)

    assert response.status_code == 200
    assert response.json()["forwarded"] is True
    assert DummyAsyncClient.last_request is not None
    assert DummyAsyncClient.last_request["url"] == "http://127.0.0.1:3000/index.html"


def test_aux_application_websocket_routes_to_alternate_upstream() -> None:
    client, private_key = make_client(aux_application_base_url="http://127.0.0.1:3000")
    request_body = '{"bootstrap_env":{"ANTHROPIC_API_KEY":"x"}}'
    headers = auth_headers(
        client,
        private_key,
        method="POST",
        path="/api/private/session/login",
        body=request_body,
    )
    client.post(
        "/api/private/session/login",
        headers={**headers, "content-type": "application/json"},
        content=request_body,
    )

    with client.websocket_connect("/aux-application/ws") as websocket:
        websocket.send_text("hello")
        assert websocket.receive_text() == "echo:hello"

    assert DummyWebSocketsModule.last_connection is not None
    assert DummyWebSocketsModule.last_connection.url == "ws://127.0.0.1:3000/ws"


def test_protected_websocket_rejects_missing_session() -> None:
    client, private_key = make_client()
    del private_key

    with pytest.raises(WebSocketDisconnect) as excinfo:
        with client.websocket_connect("/openclaw/ws"):
            pass

    assert excinfo.value.code == WEBSOCKET_CLOSE_UNAUTHORIZED


def test_protected_websocket_forwards_after_session_login() -> None:
    client, private_key = make_client()
    request_body = '{"bootstrap_env":{"ANTHROPIC_API_KEY":"x"}}'
    headers = auth_headers(
        client,
        private_key,
        method="POST",
        path="/api/private/session/login",
        body=request_body,
    )
    client.post(
        "/api/private/session/login",
        headers={**headers, "content-type": "application/json"},
        content=request_body,
    )

    with client.websocket_connect(
        "/openclaw/ws",
        subprotocols=["oc-protocol"],
        headers={"origin": "http://127.0.0.1:8090"},
    ) as websocket:
        websocket.send_text("ping")
        assert websocket.receive_text() == "echo:ping"

    assert DummyWebSocketsModule.last_connection is not None
    assert DummyWebSocketsModule.last_connection.url == "ws://example-upstream/openclaw/ws"
    assert DummyWebSocketsModule.last_connection.origin == "http://127.0.0.1:8090"
    assert "Origin" not in (DummyWebSocketsModule.last_connection.additional_headers or {})
    assert DummyWebSocketsModule.last_connection.subprotocols == ["oc-protocol"]
    assert DummyWebSocketsModule.last_connection.sent_messages == ["ping"]
    assert DummyWebSocketsModule.last_connection.additional_headers is not None
    assert DummyWebSocketsModule.last_connection.additional_headers["X-Forwarded-Proto"] == "http"
    assert DummyWebSocketsModule.last_connection.additional_headers["X-Forwarded-Host"] == "testserver"


def test_session_login_bootstraps_upstream_with_fixed_anthropic_key() -> None:
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_jwk = public_jwk_from_key(private_key.public_key())
    settings = build_settings(
        owner_public_key_jwk=public_jwk,
        upstream_base_url="http://example-upstream",
        openclaw_bootstrap_base_url="http://bootstrap",
        challenge_ttl_seconds=60,
        session_ttl_seconds=300,
        session_cookie_name="proxy-session",
    )
    client = TestClient(create_app(settings))
    request_body = '{"bootstrap_env":{"ANTHROPIC_API_KEY":"test-anthropic-key"}}'
    headers = auth_headers(
        client,
        private_key,
        method="POST",
        path="/api/private/session/login",
        body=request_body,
    )

    response = client.post(
        "/api/private/session/login",
        headers={**headers, "content-type": "application/json"},
        content=request_body,
    )

    assert response.status_code == 200
    assert len(DummyAsyncClient.requests) == 1
    assert DummyAsyncClient.requests[0]["url"] == "http://bootstrap/api/bootstrap/config"
    assert DummyAsyncClient.requests[0]["content"] == b'{"env":{"ANTHROPIC_API_KEY":"test-anthropic-key"}}'


def test_authenticated_proxy_request_requires_bootstrap_first() -> None:
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_jwk = public_jwk_from_key(private_key.public_key())
    settings = build_settings(
        owner_public_key_jwk=public_jwk,
        upstream_base_url="http://example-upstream",
        openclaw_bootstrap_base_url="http://bootstrap",
        challenge_ttl_seconds=60,
        session_ttl_seconds=300,
        session_cookie_name="proxy-session",
    )
    client = TestClient(create_app(settings))
    headers = auth_headers(
        client,
        private_key,
        method="GET",
        path="/openclaw/__openclaw/control-ui-config.json",
    )

    response = client.get("/openclaw/__openclaw/control-ui-config.json", headers=headers)

    assert response.status_code == 409
    assert response.json()["detail"] == "upstream bootstrap has not completed; initialize the session first"


def test_private_bootstrap_endpoint_accepts_signed_client_env() -> None:
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_jwk = public_jwk_from_key(private_key.public_key())
    settings = build_settings(
        owner_public_key_jwk=public_jwk,
        upstream_base_url="http://example-upstream",
        openclaw_bootstrap_base_url="http://bootstrap",
        challenge_ttl_seconds=60,
        session_ttl_seconds=300,
        session_cookie_name="proxy-session",
    )
    client = TestClient(create_app(settings))
    request_body = '{"env":{"ANTHROPIC_API_KEY":"abc"}}'
    headers = auth_headers(
        client,
        private_key,
        method="POST",
        path="/api/private/bootstrap",
        body=request_body,
    )

    response = client.post("/api/private/bootstrap", headers=headers, content=request_body)

    assert response.status_code == 200
    assert response.json()["bootstrapped"] is True
    assert DummyAsyncClient.requests[0]["url"] == "http://bootstrap/api/bootstrap/config"
    assert DummyAsyncClient.requests[0]["content"] == b'{"env":{"ANTHROPIC_API_KEY":"abc"}}'


def test_public_websocket_bypasses_auth() -> None:
    client, private_key = make_client(
        public_patterns=("/", "/assets/*", "/favicon.svg", "/healthz", "/api/public/*", "/hooks/*")
    )
    del private_key

    with client.websocket_connect("/hooks/live") as websocket:
        websocket.send_text("hello")
        assert websocket.receive_text() == "echo:hello"

    assert DummyWebSocketsModule.last_connection is not None
    assert DummyWebSocketsModule.last_connection.url == "ws://example-upstream/hooks/live"
    assert DummyWebSocketsModule.last_connection.origin == "http://example-upstream"
    assert "Origin" not in (DummyWebSocketsModule.last_connection.additional_headers or {})
