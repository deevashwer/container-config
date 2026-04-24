from __future__ import annotations

import hashlib

import httpx
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient

import app.main as main_module
from app.main import create_app
from app.security import (
    base64url_encode,
    key_id_from_public_jwk,
    public_jwk_from_key,
)
from app.settings import build_settings


class DummyAsyncClient:
    last_request: dict[str, object] | None = None

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
        request = httpx.Request(method, url)
        return httpx.Response(
            200,
            json={"forwarded": True, "url": url},
            headers={"content-type": "application/json", "x-upstream": "ok"},
            request=request,
        )


def make_client() -> tuple[TestClient, ec.EllipticCurvePrivateKey]:
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_jwk = public_jwk_from_key(private_key.public_key())
    settings = build_settings(
        owner_public_key_jwk=public_jwk,
        upstream_base_url="http://example-upstream",
        challenge_ttl_seconds=60,
    )
    return TestClient(create_app(settings)), private_key


def sign_payload(private_key: ec.EllipticCurvePrivateKey, payload: str) -> str:
    signature = private_key.sign(payload.encode("utf-8"), ec.ECDSA(hashes.SHA256()))
    return base64url_encode(signature)


def auth_headers(
    client: TestClient,
    private_key: ec.EllipticCurvePrivateKey,
    *,
    method: str,
    path: str,
    body: str = "",
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
        "x-auth-key-id": key_id_from_public_jwk(public_jwk),
        "x-auth-signature": sign_payload(private_key, payload["signing_payload"]),
    }


def test_proxy_forwards_authenticated_request(monkeypatch) -> None:
    DummyAsyncClient.last_request = None
    monkeypatch.setattr(main_module.httpx, "AsyncClient", DummyAsyncClient)

    client, private_key = make_client()
    headers = auth_headers(
        client,
        private_key,
        method="GET",
        path="/openclaw/__openclaw/control-ui-config.json",
    )

    response = client.get("/openclaw/__openclaw/control-ui-config.json", headers=headers)

    assert response.status_code == 200
    assert response.json()["forwarded"] is True
    assert DummyAsyncClient.last_request is not None
    assert DummyAsyncClient.last_request["url"] == "http://example-upstream/openclaw/__openclaw/control-ui-config.json"
    assert "x-auth-signature" not in DummyAsyncClient.last_request["headers"]


def test_proxy_rejects_replayed_challenge(monkeypatch) -> None:
    monkeypatch.setattr(main_module.httpx, "AsyncClient", DummyAsyncClient)

    client, private_key = make_client()
    headers = auth_headers(client, private_key, method="GET", path="/openclaw")

    first = client.get("/openclaw", headers=headers)
    second = client.get("/openclaw", headers=headers)

    assert first.status_code == 200
    assert second.status_code == 401
    assert second.json()["detail"] == "challenge already used"


def test_proxy_rejects_path_mismatch(monkeypatch) -> None:
    monkeypatch.setattr(main_module.httpx, "AsyncClient", DummyAsyncClient)

    client, private_key = make_client()
    headers = auth_headers(client, private_key, method="GET", path="/openclaw")

    response = client.get("/different-path", headers=headers)

    assert response.status_code == 401
    assert response.json()["detail"] == "challenge path mismatch"


def test_proxy_rejects_missing_headers() -> None:
    client, _ = make_client()

    response = client.get("/openclaw")

    assert response.status_code == 401
    assert response.json()["detail"] == "missing auth headers"
