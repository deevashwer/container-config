from __future__ import annotations

import argparse
import base64
import json
import os
import re
import ssl
import sys
from dataclasses import asdict, dataclass, is_dataclass
from enum import Enum
from hashlib import sha256
from pathlib import Path
from typing import Any

import httpx
import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


DEFAULT_STATE_PATH = Path.home() / ".config" / "openclaw-owner-chat" / "state.json"
GITHUB_PROXY = "https://github-proxy.tinfoil.sh"


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
    bootstrap_env: dict[str, str] | None = None
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
            bootstrap_env=data.get("bootstrap_env") or {},
            state_root=data.get("state_root"),
            state_generation=int(data.get("state_generation", 0)),
        )

    def save(self, state: OwnerState) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(asdict(state), indent=2) + "\n")

    def create(self, *, force: bool = False, bootstrap_env: dict[str, str] | None = None) -> OwnerState:
        if self.path.exists() and not force:
            raise FileExistsError(f"state file already exists: {self.path}")
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_jwk = public_jwk_from_key(private_key.public_key())
        private_jwk = private_jwk_from_key(private_key)
        state = OwnerState(
            owner_private_jwk=private_jwk,
            owner_public_jwk=public_jwk,
            owner_key_id=key_id_from_public_jwk(public_jwk),
            bootstrap_env=bootstrap_env or {},
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


# These helpers mirror the SDK's TLS pinning behavior so the manual verifier can
# still bind the HTTP client to the attested enclave certificate.
def verify_peer_public_key_fingerprint(cert_binary: bytes | None, expected_fp: str) -> None:
    if not cert_binary:
        raise ValueError("no TLS certificate found")
    cert = x509.load_der_x509_certificate(cert_binary)
    public_key_der = cert.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    actual_fp = sha256_hex(public_key_der)
    if actual_fp != expected_fp:
        raise ValueError(f"certificate fingerprint mismatch: expected {expected_fp}, got {actual_fp}")


def make_tls_pinned_client(expected_fp: str) -> httpx.Client:
    def wrap_socket(*args: Any, **kwargs: Any) -> ssl.SSLSocket:
        sock = ssl.create_default_context().wrap_socket(*args, **kwargs)
        verify_peer_public_key_fingerprint(sock.getpeercert(binary_form=True), expected_fp)
        return sock

    ctx = ssl.create_default_context()
    ctx.wrap_socket = wrap_socket
    return httpx.Client(verify=ctx, follow_redirects=True, timeout=20)


def coerce_predicate_type(value: Any) -> Any:
    from tinfoil.attestation.types import PredicateType

    if isinstance(value, PredicateType):
        return value

    text = str(value)
    if text in PredicateType._value2member_map_:
        return PredicateType(text)
    if text.startswith("PredicateType."):
        text = text.split(".", 1)[1]
    try:
        return PredicateType[text]
    except KeyError as exc:
        raise ValueError(f"unsupported predicate type: {value}") from exc


# Accept a few simple JSON shapes so the verification target can come either
# from a release predicate, a cached verification record, or a hand-written
# measurement file.
def measurement_from_payload(payload: Any) -> Any:
    from tinfoil.attestation.types import Measurement, PredicateType

    if not isinstance(payload, dict):
        raise ValueError("measurement payload must be a JSON object")

    if "code_measurement" in payload:
        return measurement_from_payload(payload["code_measurement"])
    if "measurement" in payload:
        return measurement_from_payload(payload["measurement"])
    if "predicate" in payload:
        predicate_type = payload.get("predicateType")
        return measurement_from_predicate(payload["predicate"], predicate_type=predicate_type)
    if "type" in payload and "registers" in payload:
        predicate_type = coerce_predicate_type(payload["type"])
        registers = [str(item) for item in payload["registers"]]
        return Measurement(type=predicate_type, registers=registers)
    if "snp_measurement" in payload or "tdx_measurement" in payload:
        return measurement_from_predicate(payload)
    raise ValueError("unsupported measurement JSON shape")


def measurement_from_predicate(predicate: Any, *, predicate_type: Any | None = None) -> Any:
    from tinfoil.attestation.types import Measurement, PredicateType

    if not isinstance(predicate, dict):
        raise ValueError("measurement predicate must be a JSON object")

    resolved_type = coerce_predicate_type(predicate_type) if predicate_type is not None else None

    if resolved_type == PredicateType.TDX_GUEST_V2 or (
        resolved_type is None and {"mrtd", "rtmr0", "rtmr1", "rtmr2", "rtmr3"}.issubset(predicate)
    ):
        registers = [str(predicate[key]) for key in ("mrtd", "rtmr0", "rtmr1", "rtmr2", "rtmr3")]
        return Measurement(type=PredicateType.TDX_GUEST_V2, registers=registers)

    if resolved_type == PredicateType.SEV_GUEST_V2 or (
        resolved_type is None and "snp_measurement" in predicate and "tdx_measurement" not in predicate
    ):
        snp_measurement = predicate.get("snp_measurement")
        if not snp_measurement:
            raise ValueError("missing snp_measurement")
        return Measurement(type=PredicateType.SEV_GUEST_V2, registers=[str(snp_measurement)])

    if resolved_type in {None, PredicateType.SNP_TDX_MULTIPLATFORM_v1}:
        snp_measurement = predicate.get("snp_measurement")
        tdx_measurement = predicate.get("tdx_measurement")
        if not snp_measurement or not isinstance(tdx_measurement, dict):
            raise ValueError("multiplatform measurements require snp_measurement and tdx_measurement")
        rtmr1 = tdx_measurement.get("rtmr1")
        rtmr2 = tdx_measurement.get("rtmr2")
        if not rtmr1 or not rtmr2:
            raise ValueError("multiplatform measurements require tdx_measurement.rtmr1 and tdx_measurement.rtmr2")
        return Measurement(
            type=PredicateType.SNP_TDX_MULTIPLATFORM_v1,
            registers=[str(snp_measurement), str(rtmr1), str(rtmr2)],
        )

    raise ValueError(f"unsupported predicate type for measurement payload: {resolved_type}")


def attach_verification_document(exc: Exception, document: Any) -> Exception:
    try:
        setattr(exc, "verification_document", document)
    except Exception:
        pass
    return exc


def extract_digest_from_release_body(body: str) -> str | None:
    for pattern in (
        re.compile(r"EIF hash: ([a-fA-F0-9]{64})"),
        re.compile(r"Digest: `([a-fA-F0-9]{64})`"),
    ):
        match = pattern.search(body)
        if match:
            return match.group(1)
    return None


def fetch_release_digest_for_tag(repo: str, release_tag: str) -> str:
    release_urls = [
        f"{GITHUB_PROXY}/repos/{repo}/releases/tags/{release_tag}",
        f"https://api.github.com/repos/{repo}/releases/tags/{release_tag}",
    ]
    last_error: Exception | None = None

    for release_url in release_urls:
        try:
            release_response = requests.get(release_url, timeout=15)
            release_response.raise_for_status()
            response_data = release_response.json()
            if not isinstance(response_data, dict):
                raise ValueError(f"unexpected release response for {repo}@{release_tag}")

            body = response_data.get("body") or ""
            digest = extract_digest_from_release_body(body)
            if digest:
                return digest
        except Exception as exc:
            last_error = exc

    for digest_url in (
        f"{GITHUB_PROXY}/{repo}/releases/download/{release_tag}/tinfoil.hash",
        f"https://github.com/{repo}/releases/download/{release_tag}/tinfoil.hash",
    ):
        try:
            digest_response = requests.get(digest_url, timeout=15)
            digest_response.raise_for_status()
            return digest_response.text.strip()
        except Exception as exc:
            last_error = exc

    if last_error is None:
        raise ValueError(f"could not resolve digest for {repo}@{release_tag}")
    raise last_error


class VerifiedTinfoilTransport(BaseTransport):
    def __init__(
        self,
        *,
        enclave: str,
        repo: str,
        release_tag: str = "",
        measurement_file: str = "",
    ) -> None:
        try:
            from tinfoil.attestation.attestation import fetch_attestation
            from tinfoil.attestation.attestation_tdx import verify_tdx_hardware
            from tinfoil.attestation.types import TDX_TYPES
            from tinfoil.client import VerificationDocument, VerificationStepState
            from tinfoil.github import fetch_attestation_bundle, fetch_latest_digest
            from tinfoil.sigstore import fetch_latest_hardware_measurements, verify_attestation
        except ImportError as exc:
            raise TransportError(
                "tinfoil is not installed. Install python_client/requirements.txt to use verified mode."
            ) from exc

        self.enclave = enclave
        self.repo = repo
        self.release_tag = release_tag
        self.measurement_file = measurement_file
        self.base_url = f"https://{enclave}"
        self._verification_document: Any = None

        doc = VerificationDocument(
            config_repo=repo,
            enclave_host=enclave,
            selected_router_endpoint=enclave,
        )
        self._verification_document = doc

        expected_measurement = None
        try:
            enclave_attestation = fetch_attestation(self.enclave)
            verification = enclave_attestation.verify()
            doc.enclave_measurement = verification
            doc.tls_public_key = verification.public_key_fp
            doc.hpke_public_key = verification.hpke_public_key or ""
            doc.enclave_fingerprint = verification.measurement.fingerprint()
            doc.steps["verify_enclave"] = VerificationStepState(status="success")

            if self.measurement_file:
                payload = json.loads(Path(self.measurement_file).expanduser().read_text())
                expected_measurement = measurement_from_payload(payload)
                doc.release_digest = "pinned_measurement_file"
                doc.code_measurement = expected_measurement
                doc.code_fingerprint = expected_measurement.fingerprint()
                doc.steps["fetch_digest"] = VerificationStepState(status="skipped")
                doc.steps["verify_code"] = VerificationStepState(status="skipped")
            else:
                if verification.measurement.type in TDX_TYPES:
                    doc.hardware_measurement = verify_tdx_hardware(
                        fetch_latest_hardware_measurements(),
                        verification.measurement,
                    )

                if self.release_tag:
                    digest = fetch_release_digest_for_tag(self.repo, self.release_tag)
                else:
                    digest = fetch_latest_digest(self.repo)
                doc.release_digest = digest
                doc.steps["fetch_digest"] = VerificationStepState(status="success")

                bundle = fetch_attestation_bundle(self.repo, digest)
                expected_measurement = verify_attestation(bundle, digest, self.repo)
                doc.code_measurement = expected_measurement
                doc.code_fingerprint = expected_measurement.fingerprint()
                doc.steps["verify_code"] = VerificationStepState(status="success")

            expected_measurement.assert_equal(verification.measurement)
            doc.steps["compare_measurements"] = VerificationStepState(status="success")
            doc.security_verified = True
            self.client = make_tls_pinned_client(verification.public_key_fp)
        except Exception as exc:
            if doc.steps["verify_enclave"].status == "pending":
                doc.steps["verify_enclave"] = VerificationStepState(status="failed", error=str(exc))
            elif doc.steps["fetch_digest"].status == "pending" and not self.measurement_file:
                doc.steps["fetch_digest"] = VerificationStepState(status="failed", error=str(exc))
            elif doc.steps["verify_code"].status == "pending" and not self.measurement_file:
                doc.steps["verify_code"] = VerificationStepState(status="failed", error=str(exc))
            else:
                doc.steps["compare_measurements"] = VerificationStepState(status="failed", error=str(exc))
            raise attach_verification_document(exc, doc)

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
        return self._verification_document

    def describe(self) -> str:
        if self.measurement_file:
            return f"verified Tinfoil transport -> https://{self.enclave} (measurement file)"
        if self.release_tag:
            return f"verified Tinfoil transport -> https://{self.enclave} ({self.repo}@{self.release_tag})"
        return f"verified Tinfoil transport -> https://{self.enclave} ({self.repo}@latest)"

    def close(self) -> None:
        self.client.close()


# This is the only proxy-aware layer. It handles the public config + challenge
# handshake, then sends the real application request with auth headers attached.
class OwnerAuthProxyClient:
    def __init__(self, *, transport: BaseTransport, state: OwnerState) -> None:
        self.transport = transport
        self.state = state
        self.public_config: dict[str, Any] | None = None
        self._upstream_bootstrapped = False

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
        if path not in {"/api/private/bootstrap", "/api/private/session/login"}:
            self.bootstrap_upstream()

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

    def bootstrap_upstream(self) -> dict[str, Any]:
        if self._upstream_bootstrapped:
            return {"bootstrapped": True, "env_keys": sorted((self.state.bootstrap_env or {}).keys())}
        response = self.authenticated_request(
            "POST",
            "/api/private/bootstrap",
            json_body={"env": self.state.bootstrap_env or {}},
        )
        response.raise_for_status()
        self._upstream_bootstrapped = True
        return response.json()

    def get_json(self, path: str) -> dict[str, Any]:
        response = self.authenticated_request("GET", path)
        response.raise_for_status()
        return response.json()

    def post_json(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        response = self.authenticated_request("POST", path, json_body=payload)
        response.raise_for_status()
        return response.json()

    def login_session(self) -> dict[str, Any]:
        response = self.authenticated_request(
            "POST",
            "/api/private/session/login",
            json_body={"bootstrap_env": self.state.bootstrap_env or {}},
        )
        response.raise_for_status()
        self._upstream_bootstrapped = True
        return response.json()


# The CLI stays thin on purpose: load state, choose transport, then delegate to
# the shared client so local and verified modes behave the same way.
def print_state_summary(state: OwnerState, state_path: Path) -> None:
    print(f"state_path={state_path}")
    print(f"owner_key_id={state.owner_key_id}")
    bootstrap_keys = sorted((state.bootstrap_env or {}).keys())
    print("bootstrap_env_keys=" + ",".join(bootstrap_keys or ["none"]))
    print("OWNER_PUBLIC_KEY_JWK=" + json.dumps(state.owner_public_jwk, separators=(",", ":")))


def resolve_bootstrap_env(args: argparse.Namespace) -> dict[str, str]:
    value = (args.anthropic_api_key or os.getenv("ANTHROPIC_API_KEY") or "").strip()
    if not value:
        return {}
    return {"ANTHROPIC_API_KEY": value}


def jsonable(value: Any) -> Any:
    if is_dataclass(value):
        return {
            field_name: jsonable(getattr(value, field_name))
            for field_name in value.__dataclass_fields__
        }
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, dict):
        return {str(key): jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [jsonable(item) for item in value]
    return value


def render_verification_document(document: Any) -> str:
    if document is None:
        return "verification_document=<none>"
    return json.dumps(jsonable(document), indent=2, default=str)


def report_command_error(exc: Exception) -> int:
    document = getattr(exc, "verification_document", None)
    if document is not None:
        eprint(render_verification_document(document))
    eprint(f"error: {exc}")
    return 1


def build_transport(args: argparse.Namespace) -> BaseTransport:
    if args.mode == "local":
        return LocalTransport(base_url=args.base_url)
    if not args.enclave:
        raise SystemExit("--enclave is required in tinfoil mode")
    if args.release_tag and not args.repo:
        raise SystemExit("--repo is required when --release-tag is set")
    if not args.repo and not args.measurement_file:
        raise SystemExit("--repo or --measurement-file is required in tinfoil mode")
    return VerifiedTinfoilTransport(
        enclave=args.enclave,
        repo=args.repo,
        release_tag=args.release_tag,
        measurement_file=args.measurement_file,
    )


def cmd_bootstrap(args: argparse.Namespace) -> int:
    state_path = Path(args.state_file).expanduser()
    store = StateStore(state_path)

    if store.exists() and not args.force:
        state = store.load()
        print_state_summary(state, state_path)
        return 0

    state = store.create(force=args.force, bootstrap_env=resolve_bootstrap_env(args))
    print_state_summary(state, state_path)
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    state_path = Path(args.state_file).expanduser()
    state = StateStore(state_path).load()
    transport: BaseTransport | None = None
    try:
        transport = build_transport(args)
        client = OwnerAuthProxyClient(transport=transport, state=state)
        config = client.load_public_config()
        client.ensure_owner_key_matches()
        print(f"transport={transport.describe()}")
        print("public_config=" + json.dumps(config, indent=2))
        print(render_verification_document(transport.get_verification_document()))
        return 0
    except Exception as exc:
        return report_command_error(exc)
    finally:
        if transport is not None:
            transport.close()


def cmd_request(args: argparse.Namespace) -> int:
    state_path = Path(args.state_file).expanduser()
    state = StateStore(state_path).load()
    transport: BaseTransport | None = None
    try:
        transport = build_transport(args)
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
    except Exception as exc:
        return report_command_error(exc)
    finally:
        if transport is not None:
            transport.close()


def cmd_chat(args: argparse.Namespace) -> int:
    state_path = Path(args.state_file).expanduser()
    state = StateStore(state_path).load()
    transport: BaseTransport | None = None
    try:
        transport = build_transport(args)
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
    except Exception as exc:
        return report_command_error(exc)
    finally:
        if transport is not None:
            transport.close()


def cmd_serve(args: argparse.Namespace) -> int:
    state_path = Path(args.state_file).expanduser()
    state = StateStore(state_path).load()
    transport: BaseTransport | None = None
    try:
        transport = build_transport(args)
        owner_client = OwnerAuthProxyClient(transport=transport, state=state)

        # The browser never touches the owner key directly in this mode. Python
        # verifies the remote target and mints the upstream session first.
        try:
            from python_client import local_browser_proxy as browser_proxy_module
            from python_client.local_browser_proxy import AuthenticatedRemoteSession, create_browser_gateway_app
        except ModuleNotFoundError:
            import local_browser_proxy as browser_proxy_module
            from local_browser_proxy import AuthenticatedRemoteSession, create_browser_gateway_app

        try:
            import uvicorn
        except ImportError as exc:
            raise TransportError(
                "uvicorn is not installed. Install python_client/requirements.txt to use serve mode."
            ) from exc
        if browser_proxy_module.websockets.connect is None:
            raise TransportError(
                "websockets is not installed. Install python_client/requirements.txt to use serve mode."
            )

        remote_session = AuthenticatedRemoteSession(transport=transport, owner_client=owner_client)
        status_payload = remote_session.bootstrap()
        print(f"transport={status_payload.transport}")
        print("public_config=" + json.dumps(status_payload.public_config, indent=2))
        if args.mode == "tinfoil":
            print(render_verification_document(status_payload.verification_document))
        local_url = f"http://{args.host}:{args.port}"
        print(f"local_browser_gateway={local_url}")
        print(f"workspace_url={local_url}{status_payload.workspace_path}")
        app = create_browser_gateway_app(remote_session)
        uvicorn.run(app, host=args.host, port=args.port, reload=False, log_level=args.log_level)
        return 0
    except Exception as exc:
        if transport is not None:
            transport.close()
        return report_command_error(exc)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Local owner-auth client for the OpenClaw auth proxy.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    bootstrap = subparsers.add_parser("bootstrap", help="generate or print the local owner key state")
    bootstrap.add_argument("--state-file", default=str(DEFAULT_STATE_PATH))
    bootstrap.add_argument("--force", action="store_true")
    bootstrap.add_argument("--anthropic-api-key", default="")
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
        sub.add_argument("--repo", default="")
        sub.add_argument("--release-tag", default="")
        sub.add_argument("--measurement-file", default="")
        if name == "request":
            sub.add_argument("method")
            sub.add_argument("path")
            sub.add_argument("--json")
        sub.set_defaults(func=handler)

    serve = subparsers.add_parser("serve", help="run a localhost browser gateway that proxies the real OpenClaw UI")
    serve.add_argument("--state-file", default=str(DEFAULT_STATE_PATH))
    serve.add_argument("--mode", choices=("local", "tinfoil"), default="local")
    serve.add_argument("--base-url", default="http://127.0.0.1:8080")
    serve.add_argument("--enclave", default="")
    serve.add_argument("--repo", default="")
    serve.add_argument("--release-tag", default="")
    serve.add_argument("--measurement-file", default="")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8090)
    serve.add_argument("--log-level", default="info")
    serve.set_defaults(func=cmd_serve)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
