from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path

from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from python_client.local_browser_proxy import RemoteGatewayStatus, VerifiedLaunchSession, create_browser_gateway_app


class FakeTransport:
    def __init__(self) -> None:
        self.base_url = "https://remote.example"
        self.closed = False

    def get_verification_document(self) -> object:
        return {
            "security_verified": True,
            "tls_public_key": "tls-key-123",
            "hpke_public_key": "hpke-key-456",
        }

    def describe(self) -> str:
        return "verified transport"

    def close(self) -> None:
        self.closed = True


class FakeGatewayClient:
    def __init__(self) -> None:
        self.load_calls = 0

    def load_public_config(self) -> dict[str, object]:
        self.load_calls += 1
        return {
            "app_name": "OpenClaw Auth Proxy",
            "ownership_claimed": True,
            "initialization_available": False,
            "passkey_count": 1,
            "openclaw_workspace_path": "/openclaw/",
            "public_path_patterns": ["/api/public/*"],
        }

    def unlock_url(self) -> str:
        return "https://remote.example/"


@dataclass
class FakeLaunchSession:
    remote_base_url: str = "https://remote.example"
    unlock_url: str = "https://remote.example/"
    workspace_path: str = "/openclaw/"
    public_config: dict[str, object] | None = None
    verification_document: object | None = None
    closed: bool = False

    def __post_init__(self) -> None:
        if self.public_config is None:
            self.public_config = {
                "app_name": "OpenClaw Auth Proxy",
                "ownership_claimed": True,
                "initialization_available": False,
                "passkey_count": 1,
                "openclaw_workspace_path": "/openclaw/",
                "public_path_patterns": ["/api/public/*"],
            }
        if self.verification_document is None:
            self.verification_document = {
                "security_verified": True,
                "tls_public_key": "tls-key-123",
                "hpke_public_key": "hpke-key-456",
            }

    def bootstrap(self) -> RemoteGatewayStatus:
        return self.status()

    def status(self) -> RemoteGatewayStatus:
        return RemoteGatewayStatus(
            transport="verified transport",
            unlock_url=self.unlock_url,
            workspace_path=self.workspace_path,
            remote_base_url=self.remote_base_url,
            public_config=self.public_config or {},
            verification_document=self.verification_document,
            expected_tls_public_key="tls-key-123",
            expected_hpke_public_key="hpke-key-456",
        )

    def close(self) -> None:
        self.closed = True


def test_launch_session_bootstrap_loads_public_config_once() -> None:
    transport = FakeTransport()
    gateway_client = FakeGatewayClient()
    session = VerifiedLaunchSession(transport=transport, gateway_client=gateway_client)

    first = session.bootstrap()
    second = session.bootstrap()

    assert gateway_client.load_calls == 1
    assert first.unlock_url == "https://remote.example/"
    assert second.workspace_path == "/openclaw/"
    assert first.transport == "verified transport"
    assert first.expected_tls_public_key == "tls-key-123"
    assert first.expected_hpke_public_key == "hpke-key-456"


def test_browser_gateway_root_renders_verification_landing_page() -> None:
    app = create_browser_gateway_app(FakeLaunchSession())

    with TestClient(app) as client:
        response = client.get("/")

    assert response.status_code == 200
    assert "Verify locally, then continue on the real enclave origin." in response.text
    assert 'href="/launch"' in response.text
    assert "https://remote.example/" in response.text


def test_browser_gateway_reports_local_status() -> None:
    app = create_browser_gateway_app(FakeLaunchSession())

    with TestClient(app) as client:
        response = client.get("/api/local/status")

    assert response.status_code == 200
    body = response.json()
    assert body["transport"] == "verified transport"
    assert body["workspace_path"] == "/openclaw/"
    assert body["unlock_url"] == "https://remote.example/"
    assert body["launch_url"].startswith("https://remote.example/?")
    assert body["remote_base_url"] == "https://remote.example"
    assert body["expected_tls_public_key"] == "tls-key-123"
    assert body["expected_hpke_public_key"] == "hpke-key-456"
    assert body["verification_document"]["security_verified"] is True


def test_browser_gateway_launch_redirects_to_remote_unlock_page() -> None:
    app = create_browser_gateway_app(FakeLaunchSession())

    with TestClient(app) as client:
        response = client.get("/launch", follow_redirects=False)

    assert response.status_code == 307
    assert response.headers["location"].startswith("https://remote.example/?")
    assert "local_verifier_gap=1" in response.headers["location"]
    assert "local_verified_tls_public_key=tls-key-123" in response.headers["location"]
    assert "local_verified_hpke_public_key=hpke-key-456" in response.headers["location"]
