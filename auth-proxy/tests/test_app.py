from __future__ import annotations

import asyncio
import hashlib
import json
import secrets
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

import httpx
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

APP_ROOT = Path(__file__).resolve().parents[1]
if str(APP_ROOT) not in sys.path:
    sys.path.insert(0, str(APP_ROOT))

import app.main as main_module
from app.main import WEBSOCKET_CLOSE_UNAUTHORIZED, create_app
from app.passkeys import base64url_encode
from app.settings import build_settings


TEST_ORIGIN = "http://testserver"
FLAG_USER_PRESENT = 0x01
FLAG_USER_VERIFIED = 0x04
FLAG_ATTESTED_CREDENTIAL_DATA = 0x40


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


def cbor_encode_length(major_type: int, value: int) -> bytes:
    if value < 24:
        return bytes([(major_type << 5) | value])
    if value < 256:
        return bytes([(major_type << 5) | 24, value])
    if value < 65536:
        return bytes([(major_type << 5) | 25]) + value.to_bytes(2, "big")
    return bytes([(major_type << 5) | 26]) + value.to_bytes(4, "big")


def cbor_encode(value) -> bytes:
    if isinstance(value, bool):
        return b"\xf5" if value else b"\xf4"
    if value is None:
        return b"\xf6"
    if isinstance(value, int):
        if value >= 0:
            return cbor_encode_length(0, value)
        return cbor_encode_length(1, -1 - value)
    if isinstance(value, bytes):
        return cbor_encode_length(2, len(value)) + value
    if isinstance(value, str):
        encoded = value.encode("utf-8")
        return cbor_encode_length(3, len(encoded)) + encoded
    if isinstance(value, list):
        return cbor_encode_length(4, len(value)) + b"".join(cbor_encode(item) for item in value)
    if isinstance(value, dict):
        chunks = []
        for key, item in value.items():
            chunks.append(cbor_encode(key))
            chunks.append(cbor_encode(item))
        return cbor_encode_length(5, len(value)) + b"".join(chunks)
    raise TypeError(f"unsupported CBOR type: {type(value)!r}")


@dataclass
class VirtualPasskey:
    private_key: ec.EllipticCurvePrivateKey = field(default_factory=lambda: ec.generate_private_key(ec.SECP256R1()))
    credential_id_bytes: bytes = field(default_factory=lambda: secrets.token_bytes(32))
    sign_count: int = 0

    @property
    def credential_id(self) -> str:
        return base64url_encode(self.credential_id_bytes)

    def _client_data(self, *, ceremony_type: str, challenge: str, origin: str) -> bytes:
        return json.dumps(
            {
                "type": ceremony_type,
                "challenge": challenge,
                "origin": origin,
            },
            separators=(",", ":"),
        ).encode("utf-8")

    def _cose_public_key(self) -> dict[int, object]:
        numbers = self.private_key.public_key().public_numbers()
        return {
            1: 2,
            3: -7,
            -1: 1,
            -2: numbers.x.to_bytes(32, "big"),
            -3: numbers.y.to_bytes(32, "big"),
        }

    def _registration_authenticator_data(self, rp_id: str) -> bytes:
        rp_hash = hashlib.sha256(rp_id.encode("utf-8")).digest()
        flags = FLAG_USER_PRESENT | FLAG_USER_VERIFIED | FLAG_ATTESTED_CREDENTIAL_DATA
        return (
            rp_hash
            + bytes([flags])
            + self.sign_count.to_bytes(4, "big")
            + (b"\x00" * 16)
            + len(self.credential_id_bytes).to_bytes(2, "big")
            + self.credential_id_bytes
            + cbor_encode(self._cose_public_key())
        )

    def _assertion_authenticator_data(self, rp_id: str) -> bytes:
        self.sign_count += 1
        rp_hash = hashlib.sha256(rp_id.encode("utf-8")).digest()
        flags = FLAG_USER_PRESENT | FLAG_USER_VERIFIED
        return rp_hash + bytes([flags]) + self.sign_count.to_bytes(4, "big")

    def build_registration_request(
        self,
        options: dict[str, object],
        *,
        origin: str = TEST_ORIGIN,
        bootstrap_env: dict[str, str] | None = None,
    ) -> dict[str, object]:
        public_key = options["public_key"]
        client_data = self._client_data(
            ceremony_type="webauthn.create",
            challenge=public_key["challenge"],
            origin=origin,
        )
        attestation_object = cbor_encode(
            {
                "fmt": "none",
                "attStmt": {},
                "authData": self._registration_authenticator_data(public_key["rp"]["id"]),
            }
        )
        return {
            "challenge_id": options["challenge_id"],
            "credential": {
                "id": self.credential_id,
                "rawId": self.credential_id,
                "type": "public-key",
                "response": {
                    "clientDataJSON": base64url_encode(client_data),
                    "attestationObject": base64url_encode(attestation_object),
                },
            },
            "bootstrap_env": bootstrap_env or {},
        }

    def build_authentication_request(
        self,
        options: dict[str, object],
        *,
        origin: str = TEST_ORIGIN,
        bootstrap_env: dict[str, str] | None = None,
    ) -> dict[str, object]:
        public_key = options["public_key"]
        client_data = self._client_data(
            ceremony_type="webauthn.get",
            challenge=public_key["challenge"],
            origin=origin,
        )
        authenticator_data = self._assertion_authenticator_data(public_key["rpId"])
        signature = self.private_key.sign(
            authenticator_data + hashlib.sha256(client_data).digest(),
            ec.ECDSA(hashes.SHA256()),
        )
        return {
            "challenge_id": options["challenge_id"],
            "credential": {
                "id": self.credential_id,
                "rawId": self.credential_id,
                "type": "public-key",
                "response": {
                    "clientDataJSON": base64url_encode(client_data),
                    "authenticatorData": base64url_encode(authenticator_data),
                    "signature": base64url_encode(signature),
                    "userHandle": None,
                },
            },
            "bootstrap_env": bootstrap_env or {},
        }


def make_client(
    *,
    public_patterns: tuple[str, ...] = ("/", "/assets/*", "/favicon.svg", "/healthz", "/api/public/*"),
    aux_application_base_url: str | None = None,
    aux_application_path_prefix: str = "/aux-application",
    openclaw_bootstrap_base_url: str | None = None,
) -> TestClient:
    passkey_store_path = str(Path(tempfile.mkdtemp()) / "passkeys.json")
    settings = build_settings(
        upstream_base_url="http://example-upstream",
        aux_application_base_url=aux_application_base_url,
        aux_application_path_prefix=aux_application_path_prefix,
        openclaw_bootstrap_base_url=openclaw_bootstrap_base_url,
        challenge_ttl_seconds=60,
        session_ttl_seconds=300,
        session_cookie_name="proxy-session",
        public_path_patterns=public_patterns,
        passkey_store_path=passkey_store_path,
    )
    return TestClient(create_app(settings))


def begin_initialization(client: TestClient) -> dict[str, object]:
    response = client.post("/api/public/init/options", headers={"origin": TEST_ORIGIN})
    assert response.status_code == 200
    return response.json()


def initialize_enclave(
    client: TestClient,
    passkey: VirtualPasskey,
    *,
    bootstrap_env: dict[str, str] | None = None,
) -> httpx.Response:
    options = begin_initialization(client)
    return client.post(
        "/api/public/init/finish",
        json=passkey.build_registration_request(options, bootstrap_env=bootstrap_env),
    )


def begin_authentication(client: TestClient) -> dict[str, object]:
    response = client.post("/api/public/passkeys/authenticate/options", headers={"origin": TEST_ORIGIN})
    assert response.status_code == 200
    return response.json()


def authenticate_passkey(
    client: TestClient,
    passkey: VirtualPasskey,
    *,
    bootstrap_env: dict[str, str] | None = None,
) -> httpx.Response:
    options = begin_authentication(client)
    return client.post(
        "/api/public/passkeys/authenticate/finish",
        json=passkey.build_authentication_request(options, bootstrap_env=bootstrap_env),
    )


@pytest.fixture(autouse=True)
def patch_network_clients(monkeypatch) -> None:
    DummyAsyncClient.last_request = None
    DummyAsyncClient.requests = []
    DummyWebSocketsModule.last_connection = None
    monkeypatch.setattr(main_module.httpx, "AsyncClient", DummyAsyncClient)
    monkeypatch.setattr(main_module.websockets, "connect", DummyWebSocketsModule.connect)


def test_public_config_is_accessible_without_auth() -> None:
    client = make_client()

    response = client.get("/api/public/config")

    assert response.status_code == 200
    assert response.json()["session_cookie_name"] == "proxy-session"
    assert response.json()["ownership_claimed"] is False
    assert response.json()["initialization_available"] is True


def test_root_dashboard_is_public() -> None:
    client = make_client()

    response = client.get("/")

    assert response.status_code == 200
    assert "OpenClaw Secure Console" in response.text


def test_static_assets_are_public() -> None:
    client = make_client()

    response = client.get("/assets/app.js")

    assert response.status_code == 200
    assert "PasskeyAuthBrowserClient" in response.text


def test_favicon_is_public() -> None:
    client = make_client()

    response = client.get("/favicon.svg")

    assert response.status_code == 200
    assert "<svg" in response.text


def test_proxy_rejects_missing_session_cookie() -> None:
    client = make_client()

    response = client.get("/openclaw")

    assert response.status_code == 401
    assert response.json()["detail"] == "missing session cookie"


def test_enclave_initialization_creates_cookie_and_allows_followup_requests() -> None:
    client = make_client()
    passkey = VirtualPasskey()

    registration = initialize_enclave(client, passkey)
    follow_up = client.get("/openclaw")

    assert registration.status_code == 200
    assert registration.json()["authenticated"] is True
    assert registration.json()["credential_id"] == passkey.credential_id
    assert "proxy-session" in client.cookies
    assert follow_up.status_code == 200
    assert DummyAsyncClient.last_request is not None
    assert DummyAsyncClient.last_request["url"] == "http://example-upstream/openclaw"
    assert "cookie" not in {key.lower() for key in DummyAsyncClient.last_request["headers"]}


def test_enclave_initialization_is_gone_after_first_claim() -> None:
    client = make_client()
    passkey = VirtualPasskey()

    first = initialize_enclave(client, passkey)
    second = client.post("/api/public/init/options", headers={"origin": TEST_ORIGIN})

    assert first.status_code == 200
    assert second.status_code == 410
    assert second.json()["detail"] == "this enclave has already been initialized"


def test_passkey_authentication_recreates_session_after_logout() -> None:
    client = make_client()
    passkey = VirtualPasskey()
    initialize_enclave(client, passkey)
    client.post("/api/private/session/logout")

    login = authenticate_passkey(client, passkey)
    follow_up = client.get("/openclaw")

    assert login.status_code == 200
    assert login.json()["authenticated"] is True
    assert follow_up.status_code == 200


def test_passkey_authentication_requires_registered_passkey() -> None:
    client = make_client()

    response = client.post("/api/public/passkeys/authenticate/options", headers={"origin": TEST_ORIGIN})

    assert response.status_code == 409
    assert response.json()["detail"] == "no passkey is registered for this gateway yet"


def test_session_status_and_logout_use_cookie_auth() -> None:
    client = make_client()
    passkey = VirtualPasskey()
    initialize_enclave(client, passkey)

    status_response = client.get("/api/private/session")
    logout = client.post("/api/private/session/logout")
    locked = client.get("/openclaw")

    assert status_response.status_code == 200
    assert status_response.json()["auth_kind"] == "session"
    assert status_response.json()["credential_id"] == passkey.credential_id
    assert logout.status_code == 200
    assert logout.json()["authenticated"] is False
    assert "proxy-session" not in client.cookies
    assert locked.status_code == 401
    assert locked.json()["detail"] == "missing session cookie"


def test_public_routes_bypass_auth() -> None:
    client = make_client(
        public_patterns=("/", "/assets/*", "/favicon.svg", "/healthz", "/api/public/*", "/webhooks/*")
    )

    response = client.post("/webhooks/telegram", json={"ok": True})

    assert response.status_code == 200
    assert response.json()["forwarded"] is True
    assert DummyAsyncClient.last_request is not None
    assert DummyAsyncClient.last_request["url"] == "http://example-upstream/webhooks/telegram"


def test_aux_application_prefix_routes_to_alternate_upstream() -> None:
    client = make_client(aux_application_base_url="http://127.0.0.1:3000")
    passkey = VirtualPasskey()
    initialize_enclave(client, passkey)

    response = client.get("/aux-application/index.html")

    assert response.status_code == 200
    assert response.json()["forwarded"] is True
    assert DummyAsyncClient.last_request is not None
    assert DummyAsyncClient.last_request["url"] == "http://127.0.0.1:3000/index.html"


def test_aux_application_websocket_routes_to_alternate_upstream() -> None:
    client = make_client(aux_application_base_url="http://127.0.0.1:3000")
    passkey = VirtualPasskey()
    initialize_enclave(client, passkey)

    with client.websocket_connect("/aux-application/ws") as websocket:
        websocket.send_text("hello")
        assert websocket.receive_text() == "echo:hello"

    assert DummyWebSocketsModule.last_connection is not None
    assert DummyWebSocketsModule.last_connection.url == "ws://127.0.0.1:3000/ws"


def test_protected_websocket_rejects_missing_session() -> None:
    client = make_client()

    with pytest.raises(WebSocketDisconnect) as excinfo:
        with client.websocket_connect("/openclaw/ws"):
            pass

    assert excinfo.value.code == WEBSOCKET_CLOSE_UNAUTHORIZED


def test_protected_websocket_forwards_after_passkey_login() -> None:
    client = make_client()
    passkey = VirtualPasskey()
    initialize_enclave(client, passkey)

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


def test_enclave_initialization_bootstraps_upstream_with_fixed_anthropic_key() -> None:
    client = make_client(openclaw_bootstrap_base_url="http://bootstrap")
    passkey = VirtualPasskey()

    response = initialize_enclave(client, passkey, bootstrap_env={"ANTHROPIC_API_KEY": "test-anthropic-key"})

    assert response.status_code == 200
    assert len(DummyAsyncClient.requests) == 1
    assert DummyAsyncClient.requests[0]["url"] == "http://bootstrap/api/bootstrap/config"
    assert DummyAsyncClient.requests[0]["content"] == b'{"env":{"ANTHROPIC_API_KEY":"test-anthropic-key"}}'


def test_initialization_requires_bootstrap_env_and_does_not_partially_claim_enclave() -> None:
    client = make_client(openclaw_bootstrap_base_url="http://bootstrap")
    passkey = VirtualPasskey()

    first = initialize_enclave(client, passkey)
    config = client.get("/api/public/config")
    login_options = client.post("/api/public/passkeys/authenticate/options", headers={"origin": TEST_ORIGIN})
    second = initialize_enclave(client, passkey, bootstrap_env={"ANTHROPIC_API_KEY": "x"})
    third = client.post("/api/public/init/options", headers={"origin": TEST_ORIGIN})

    assert first.status_code == 409
    assert first.json()["detail"] == "upstream bootstrap env is required before OpenClaw can start"
    assert config.status_code == 200
    assert config.json()["ownership_claimed"] is False
    assert config.json()["initialization_available"] is True
    assert login_options.status_code == 409
    assert login_options.json()["detail"] == "no passkey is registered for this gateway yet"
    assert second.status_code == 200
    assert third.status_code == 410
    assert third.json()["detail"] == "this enclave has already been initialized"
    assert DummyAsyncClient.requests[0]["url"] == "http://bootstrap/api/bootstrap/config"
    assert DummyAsyncClient.requests[0]["content"] == b'{"env":{"ANTHROPIC_API_KEY":"x"}}'


def test_private_bootstrap_endpoint_accepts_session_cookie() -> None:
    client = make_client(openclaw_bootstrap_base_url="http://bootstrap")
    passkey = VirtualPasskey()
    initialize_enclave(client, passkey, bootstrap_env={"ANTHROPIC_API_KEY": "abc"})
    DummyAsyncClient.requests = []

    response = client.post("/api/private/bootstrap", content='{"env":{"ANTHROPIC_API_KEY":"abc"}}')

    assert response.status_code == 200
    assert response.json()["bootstrapped"] is True
    assert response.json()["env_keys"] == ["ANTHROPIC_API_KEY"]
    assert DummyAsyncClient.requests == []
