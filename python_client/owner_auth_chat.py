from __future__ import annotations

import argparse
import base64
import json
import sys
from dataclasses import asdict, dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any

import httpx
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec


DEFAULT_STATE_PATH = Path.home() / ".config" / "openclaw-owner-chat" / "state.json"


def eprint(message: str) -> None:
    print(message, file=sys.stderr)


# Keep the owner key in portable JWK form so the same state file can work for
# local HTTP now and a future passkey-backed flow later.
def base64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def base64url_decode(value: str) -> bytes:
    padding = "=" * ((4 - len(value) % 4) % 4)
    return base64.urlsafe_b64decode(value + padding)


def sha256_hex(value: bytes | str) -> str:
    if isinstance(value, str):
        value = value.encode("utf-8")
    return sha256(value).hexdigest()


def sanitize_public_jwk(jwk: dict[str, Any]) -> dict[str, str]:
    required_keys = {"crv", "kty", "x", "y"}
    missing = required_keys.difference(jwk)
    if missing:
        raise ValueError(f"missing public JWK fields: {sorted(missing)}")
    sanitized = {key: str(jwk[key]) for key in sorted(required_keys)}
    if sanitized["kty"] != "EC" or sanitized["crv"] != "P-256":
        raise ValueError("only EC P-256 JWK keys are supported")
    return sanitized


def sanitize_private_jwk(jwk: dict[str, Any]) -> dict[str, str]:
    sanitized = sanitize_public_jwk(jwk)
    if "d" not in jwk:
        raise ValueError("missing private JWK field: d")
    sanitized["d"] = str(jwk["d"])
    return sanitized


def canonical_public_jwk_json(jwk: dict[str, Any]) -> str:
    return json.dumps(sanitize_public_jwk(jwk), sort_keys=True, separators=(",", ":"))


def key_id_from_public_jwk(jwk: dict[str, Any]) -> str:
    return sha256_hex(canonical_public_jwk_json(jwk))


def public_jwk_from_key(public_key: ec.EllipticCurvePublicKey) -> dict[str, str]:
    numbers = public_key.public_numbers()
    x = numbers.x.to_bytes(32, "big")
    y = numbers.y.to_bytes(32, "big")
    return {
        "crv": "P-256",
        "kty": "EC",
        "x": base64url_encode(x),
        "y": base64url_encode(y),
    }


def private_jwk_from_key(private_key: ec.EllipticCurvePrivateKey) -> dict[str, str]:
    public_jwk = public_jwk_from_key(private_key.public_key())
    d = private_key.private_numbers().private_value.to_bytes(32, "big")
    return {
        **public_jwk,
        "d": base64url_encode(d),
    }


def private_key_from_jwk(jwk: dict[str, Any]) -> ec.EllipticCurvePrivateKey:
    sanitized = sanitize_private_jwk(jwk)
    d = int.from_bytes(base64url_decode(sanitized["d"]), "big")
    x = int.from_bytes(base64url_decode(sanitized["x"]), "big")
    y = int.from_bytes(base64url_decode(sanitized["y"]), "big")
    public_numbers = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1())
    private_numbers = ec.EllipticCurvePrivateNumbers(d, public_numbers)
    return private_numbers.private_key()


# The client re-derives the canonical payload locally before signing so it does
# not blindly trust the challenge response body from the proxy.
def build_signing_payload(
    *,
    challenge_id: str,
    nonce: str,
    method: str,
    path: str,
    body_sha256: str,
    expires_at: str,
) -> str:
    payload = {
        "body_sha256": body_sha256,
        "challenge_id": challenge_id,
        "expires_at": expires_at,
        "method": method.upper(),
        "nonce": nonce,
        "path": path,
        "version": "openclaw-owner-auth-v1",
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def sign_payload(private_jwk: dict[str, Any], payload: str) -> str:
    private_key = private_key_from_jwk(private_jwk)
    signature = private_key.sign(payload.encode("utf-8"), ec.ECDSA(hashes.SHA256()))
    return base64url_encode(signature)


# This is the whole local client state for now. `state_root` and
# `state_generation` are placeholders for the later persistence work.
@dataclass
class OwnerState:
    owner_private_jwk: dict[str, str]
    owner_public_jwk: dict[str, str]
    owner_key_id: str
    state_root: str | None = None
    state_generation: int = 0


class StateStore:
    def __init__(self, path: Path) -> None:
        self.path = path

    def exists(self) -> bool:
        return self.path.exists()

    def load(self) -> OwnerState:
        if not self.path.exists():
            raise FileNotFoundError(f"state file not found: {self.path}")
        data = json.loads(self.path.read_text())
        return OwnerState(
            owner_private_jwk=data["owner_private_jwk"],
            owner_public_jwk=data["owner_public_jwk"],
            owner_key_id=data["owner_key_id"],
            state_root=data.get("state_root"),
            state_generation=int(data.get("state_generation", 0)),
        )

    def save(self, state: OwnerState) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(asdict(state), indent=2) + "\n")

    def create(self, *, force: bool = False) -> OwnerState:
        if self.path.exists() and not force:
            raise FileExistsError(f"state file already exists: {self.path}")
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_jwk = public_jwk_from_key(private_key.public_key())
        private_jwk = private_jwk_from_key(private_key)
        state = OwnerState(
            owner_private_jwk=private_jwk,
            owner_public_jwk=public_jwk,
            owner_key_id=key_id_from_public_jwk(public_jwk),
        )
        self.save(state)
        return state


class TransportError(RuntimeError):
    pass


# Everything above the transport layer stays the same whether we are talking to
# localhost or to an attested Tinfoil hostname.
class BaseTransport:
    def request(
        self,
        method: str,
        path: str,
        *,
        headers: dict[str, str] | None = None,
        content: bytes | None = None,
    ) -> httpx.Response:
        raise NotImplementedError

    def get_verification_document(self) -> Any:
        return None

    def describe(self) -> str:
        raise NotImplementedError

    def close(self) -> None:
        return None


class LocalTransport(BaseTransport):
    def __init__(self, *, base_url: str) -> None:
        self.base_url = base_url.rstrip("/")
        self.client = httpx.Client(base_url=self.base_url, follow_redirects=True, timeout=20)

    def request(
        self,
        method: str,
        path: str,
        *,
        headers: dict[str, str] | None = None,
        content: bytes | None = None,
    ) -> httpx.Response:
        return self.client.request(method=method.upper(), url=path, headers=headers, content=content)

    def describe(self) -> str:
        return f"local transport -> {self.base_url}"

    def close(self) -> None:
        self.client.close()


class VerifiedTinfoilTransport(BaseTransport):
    def __init__(self, *, enclave: str, repo: str) -> None:
        try:
            from tinfoil import SecureClient as TinfoilSecureClient
        except ImportError as exc:
            raise TransportError(
                "tinfoil is not installed. Install python_client/requirements.txt to use verified mode."
            ) from exc

        self.enclave = enclave
        self.repo = repo
        self.secure_client = TinfoilSecureClient(enclave=enclave, repo=repo)
        self.client = self.secure_client.make_secure_http_client()
        self.base_url = f"https://{enclave}"

    def request(
        self,
        method: str,
        path: str,
        *,
        headers: dict[str, str] | None = None,
        content: bytes | None = None,
    ) -> httpx.Response:
        url = f"{self.base_url}{path}"
        return self.client.request(method=method.upper(), url=url, headers=headers, content=content)

    def get_verification_document(self) -> Any:
        return self.secure_client.get_verification_document()

    def describe(self) -> str:
        return f"verified Tinfoil transport -> https://{self.enclave}"

    def close(self) -> None:
        self.client.close()


# This is the only proxy-aware layer. It handles the public config + challenge
# handshake, then sends the real application request with auth headers attached.
class OwnerAuthProxyClient:
    def __init__(self, *, transport: BaseTransport, state: OwnerState) -> None:
        self.transport = transport
        self.state = state
        self.public_config: dict[str, Any] | None = None

    def load_public_config(self) -> dict[str, Any]:
        response = self.transport.request("GET", "/api/public/config")
        response.raise_for_status()
        config = response.json()
        self.public_config = config
        return config

    def ensure_owner_key_matches(self) -> None:
        config = self.public_config or self.load_public_config()
        if not config.get("owner_key_configured"):
            raise RuntimeError("server does not have OWNER_PUBLIC_KEY_JWK configured")
        if config.get("owner_key_id") != self.state.owner_key_id:
            raise RuntimeError(
                "local owner key does not match server owner key\n"
                f"local={self.state.owner_key_id}\n"
                f"server={config.get('owner_key_id')}"
            )

    def authenticated_request(
        self,
        method: str,
        path: str,
        *,
        json_body: dict[str, Any] | None = None,
        raw_body: bytes | None = None,
        extra_headers: dict[str, str] | None = None,
    ) -> httpx.Response:
        if json_body is not None and raw_body is not None:
            raise ValueError("provide either json_body or raw_body, not both")

        body = raw_body
        if json_body is not None:
            body = json.dumps(json_body, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        if body is None:
            body = b""

        # Ask the proxy for a one-time challenge tied to the exact request we
        # are about to send.
        challenge_body = {
            "method": method.upper(),
            "path": path,
            "body_sha256": sha256_hex(body),
        }
        challenge_response = self.transport.request(
            "POST",
            "/api/public/challenge",
            headers={"content-type": "application/json"},
            content=json.dumps(challenge_body, separators=(",", ":"), ensure_ascii=True).encode("utf-8"),
        )
        challenge_response.raise_for_status()
        challenge = challenge_response.json()

        # Recompute the expected payload locally before signing it. This keeps
        # the client in control of what it is actually authorizing.
        expected_payload = build_signing_payload(
            challenge_id=challenge["challenge_id"],
            nonce=challenge["nonce"],
            method=method.upper(),
            path=path,
            body_sha256=challenge_body["body_sha256"],
            expires_at=challenge["expires_at"],
        )
        if challenge["signing_payload"] != expected_payload:
            raise RuntimeError("server returned an unexpected signing payload")

        headers = {
            "x-auth-challenge-id": challenge["challenge_id"],
            "x-auth-key-id": self.state.owner_key_id,
            "x-auth-signature": sign_payload(self.state.owner_private_jwk, challenge["signing_payload"]),
        }
        if body:
            headers["content-type"] = "application/json"
        if extra_headers:
            headers.update(extra_headers)

        return self.transport.request(
            method,
            path,
            headers=headers,
            content=body or None,
        )

    def get_json(self, path: str) -> dict[str, Any]:
        response = self.authenticated_request("GET", path)
        response.raise_for_status()
        return response.json()

    def post_json(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        response = self.authenticated_request("POST", path, json_body=payload)
        response.raise_for_status()
        return response.json()


# The CLI stays thin on purpose: load state, choose transport, then delegate to
# the shared client so local and verified modes behave the same way.
def print_state_summary(state: OwnerState, state_path: Path) -> None:
    print(f"state_path={state_path}")
    print(f"owner_key_id={state.owner_key_id}")
    print("OWNER_PUBLIC_KEY_JWK=" + json.dumps(state.owner_public_jwk, separators=(",", ":")))


def render_verification_document(document: Any) -> str:
    if document is None:
        return "verification_document=<none>"
    if hasattr(document, "__dict__"):
        try:
            return json.dumps(asdict(document), indent=2, default=str)
        except TypeError:
            return json.dumps(document.__dict__, indent=2, default=str)
    return json.dumps(document, indent=2, default=str)


def build_transport(args: argparse.Namespace) -> BaseTransport:
    if args.mode == "local":
        return LocalTransport(base_url=args.base_url)
    if not args.enclave:
        raise SystemExit("--enclave is required in tinfoil mode")
    if not args.repo:
        raise SystemExit("--repo is required in tinfoil mode")
    return VerifiedTinfoilTransport(enclave=args.enclave, repo=args.repo)


def cmd_bootstrap(args: argparse.Namespace) -> int:
    state_path = Path(args.state_file).expanduser()
    store = StateStore(state_path)

    if store.exists() and not args.force:
        state = store.load()
        print_state_summary(state, state_path)
        return 0

    state = store.create(force=args.force)
    print_state_summary(state, state_path)
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    state_path = Path(args.state_file).expanduser()
    state = StateStore(state_path).load()
    transport = build_transport(args)
    try:
        client = OwnerAuthProxyClient(transport=transport, state=state)
        config = client.load_public_config()
        client.ensure_owner_key_matches()
        print(f"transport={transport.describe()}")
        print("public_config=" + json.dumps(config, indent=2))
        print(render_verification_document(transport.get_verification_document()))
        return 0
    finally:
        transport.close()


def cmd_request(args: argparse.Namespace) -> int:
    state_path = Path(args.state_file).expanduser()
    state = StateStore(state_path).load()
    transport = build_transport(args)
    try:
        client = OwnerAuthProxyClient(transport=transport, state=state)
        client.ensure_owner_key_matches()
        payload = None
        if args.json is not None:
            payload = json.loads(args.json)

        response = client.authenticated_request(args.method.upper(), args.path, json_body=payload)
        print(f"status={response.status_code}")
        content_type = response.headers.get("content-type", "")
        if "application/json" in content_type:
            print(json.dumps(response.json(), indent=2))
        else:
            print(response.text)
        return 0
    finally:
        transport.close()


def cmd_chat(args: argparse.Namespace) -> int:
    state_path = Path(args.state_file).expanduser()
    state = StateStore(state_path).load()
    transport = build_transport(args)
    try:
        client = OwnerAuthProxyClient(transport=transport, state=state)
        client.load_public_config()
        client.ensure_owner_key_matches()

        print(f"transport={transport.describe()}")
        if args.mode == "tinfoil":
            print(render_verification_document(transport.get_verification_document()))
        # Keep the interactive mode generic: it is just a small shell over the
        # same authenticated request primitive used by the one-shot command.
        print("type /quit to exit, /verify to print verification info, /request METHOD /path [json] to send a request")

        while True:
            line = input("> ").strip()
            if not line:
                continue
            if line in {"/quit", "/exit"}:
                return 0
            if line == "/verify":
                print(render_verification_document(transport.get_verification_document()))
                continue
            if line.startswith("/request "):
                parts = line.split(" ", 3)
                if len(parts) < 3:
                    eprint("usage: /request METHOD /path [json]")
                    continue
                method = parts[1]
                path = parts[2]
                payload = None
                if len(parts) == 4:
                    payload = json.loads(parts[3])
                response = client.authenticated_request(method, path, json_body=payload)
                print(f"status={response.status_code}")
                content_type = response.headers.get("content-type", "")
                if "application/json" in content_type:
                    print(json.dumps(response.json(), indent=2))
                else:
                    print(response.text)
                continue

            eprint("use /request METHOD /path [json]")
    finally:
        transport.close()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Local owner-auth client for the OpenClaw auth proxy.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    bootstrap = subparsers.add_parser("bootstrap", help="generate or print the local owner key state")
    bootstrap.add_argument("--state-file", default=str(DEFAULT_STATE_PATH))
    bootstrap.add_argument("--force", action="store_true")
    bootstrap.set_defaults(func=cmd_bootstrap)

    for name, help_text, handler in [
        ("verify", "verify server config and print attestation details when available", cmd_verify),
        ("request", "make one authenticated request through the proxy", cmd_request),
        ("chat", "run a simple interactive authenticated request shell", cmd_chat),
    ]:
        sub = subparsers.add_parser(name, help=help_text)
        sub.add_argument("--state-file", default=str(DEFAULT_STATE_PATH))
        sub.add_argument("--mode", choices=("local", "tinfoil"), default="local")
        sub.add_argument("--base-url", default="http://127.0.0.1:8080")
        sub.add_argument("--enclave", default="")
        sub.add_argument("--repo", default="tinfoilsh/confidential-model-router")
        if name == "request":
            sub.add_argument("method")
            sub.add_argument("path")
            sub.add_argument("--json")
        sub.set_defaults(func=handler)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
