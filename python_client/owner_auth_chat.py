from __future__ import annotations

import argparse
import json
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
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


LEGACY_STATE_PATH = Path.home() / ".config" / "openclaw-owner-chat" / "state.json"
GITHUB_PROXY = "https://github-proxy.tinfoil.sh"


def eprint(message: str) -> None:
    print(message, file=sys.stderr)


def sha256_hex(value: bytes | str) -> str:
    if isinstance(value, str):
        value = value.encode("utf-8")
    return sha256(value).hexdigest()


class TransportError(RuntimeError):
    pass


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


@dataclass(slots=True)
class StorageSummary:
    browser_vault_db: str
    browser_vault_store: str
    legacy_python_state_path: str
    legacy_python_state_present: bool
    python_client_secret_state: str
    server_side_passkey_store: str


class GatewayPublicClient:
    def __init__(self, *, transport: BaseTransport) -> None:
        self.transport = transport
        self.public_config: dict[str, Any] | None = None

    def load_public_config(self) -> dict[str, Any]:
        response = self.transport.request("GET", "/api/public/config")
        response.raise_for_status()
        config = response.json()
        self.public_config = config
        return config

    def unlock_url(self) -> str:
        base_url = getattr(self.transport, "base_url", "").rstrip("/")
        if not base_url:
            raise RuntimeError("transport does not expose a remote base URL")
        return f"{base_url}/"


def local_storage_summary(legacy_state_path: Path) -> StorageSummary:
    return StorageSummary(
        browser_vault_db="openclaw.auth-proxy.keystore.v2",
        browser_vault_store="vault",
        legacy_python_state_path=str(legacy_state_path),
        legacy_python_state_present=legacy_state_path.exists(),
        python_client_secret_state="none",
        server_side_passkey_store="PASSKEY_STORE_PATH",
    )


def print_storage_summary(summary: StorageSummary) -> None:
    print("browser_vault_db=" + summary.browser_vault_db)
    print("browser_vault_store=" + summary.browser_vault_store)
    print("legacy_python_state_path=" + summary.legacy_python_state_path)
    print("legacy_python_state_present=" + ("yes" if summary.legacy_python_state_present else "no"))
    print("python_client_secret_state=" + summary.python_client_secret_state)
    print("server_side_passkey_store=" + summary.server_side_passkey_store)


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
    legacy_state_path = Path(args.state_file).expanduser()
    summary = local_storage_summary(legacy_state_path)
    if args.purge_legacy_state and legacy_state_path.exists():
        legacy_state_path.unlink()
        summary = local_storage_summary(legacy_state_path)
        print("purged_legacy_state=yes")
    else:
        print("purged_legacy_state=no")
    print_storage_summary(summary)
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    transport: BaseTransport | None = None
    try:
        transport = build_transport(args)
        client = GatewayPublicClient(transport=transport)
        config = client.load_public_config()
        print(f"transport={transport.describe()}")
        print("unlock_url=" + client.unlock_url())
        print("public_config=" + json.dumps(config, indent=2))
        print(render_verification_document(transport.get_verification_document()))
        return 0
    except Exception as exc:
        return report_command_error(exc)
    finally:
        if transport is not None:
            transport.close()


def cmd_removed_direct_mode(args: argparse.Namespace) -> int:
    del args
    eprint(
        "error: direct authenticated request/chat mode was removed. "
        "Passkey authentication now happens in the browser on the enclave origin. "
        "Use `serve` to verify and launch the remote unlock page, then continue in the browser."
    )
    return 2


def cmd_serve(args: argparse.Namespace) -> int:
    transport: BaseTransport | None = None
    try:
        transport = build_transport(args)
        gateway_client = GatewayPublicClient(transport=transport)

        try:
            from python_client.local_browser_proxy import VerifiedLaunchSession, create_browser_gateway_app
        except ModuleNotFoundError:
            from local_browser_proxy import VerifiedLaunchSession, create_browser_gateway_app

        try:
            import uvicorn
        except ImportError as exc:
            raise TransportError(
                "uvicorn is not installed. Install python_client/requirements.txt to use serve mode."
            ) from exc

        launch_session = VerifiedLaunchSession(transport=transport, gateway_client=gateway_client)
        status_payload = launch_session.bootstrap()
        print(f"transport={status_payload.transport}")
        print("public_config=" + json.dumps(status_payload.public_config, indent=2))
        print("unlock_url=" + status_payload.unlock_url)
        if args.mode == "tinfoil":
            print(render_verification_document(status_payload.verification_document))
        local_url = f"http://{args.host}:{args.port}"
        print(f"local_verification_center={local_url}")
        if args.open_browser:
            import webbrowser

            webbrowser.open(local_url)
        app = create_browser_gateway_app(launch_session)
        uvicorn.run(app, host=args.host, port=args.port, reload=False, log_level=args.log_level)
        return 0
    except Exception as exc:
        if transport is not None:
            transport.close()
        return report_command_error(exc)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Passkey-aware verifier and launcher for the OpenClaw auth proxy.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    bootstrap = subparsers.add_parser(
        "bootstrap",
        help="show current secret-storage locations and optionally delete the old owner-key state file",
    )
    bootstrap.add_argument("--state-file", default=str(LEGACY_STATE_PATH))
    bootstrap.add_argument("--purge-legacy-state", action="store_true")
    bootstrap.set_defaults(func=cmd_bootstrap)

    verify = subparsers.add_parser(
        "verify",
        help="fetch public config and print attestation details when available",
    )
    verify.add_argument("--mode", choices=("local", "tinfoil"), default="local")
    verify.add_argument("--base-url", default="http://127.0.0.1:8080")
    verify.add_argument("--enclave", default="")
    verify.add_argument("--repo", default="")
    verify.add_argument("--release-tag", default="")
    verify.add_argument("--measurement-file", default="")
    verify.set_defaults(func=cmd_verify)

    for name, help_text in [
        ("request", "removed: direct authenticated requests are no longer available"),
        ("chat", "removed: interactive direct requests are no longer available"),
    ]:
        sub = subparsers.add_parser(name, help=help_text)
        sub.set_defaults(func=cmd_removed_direct_mode)

    serve = subparsers.add_parser(
        "serve",
        help="run a localhost verification center that launches the real remote passkey flow",
    )
    serve.add_argument("--mode", choices=("local", "tinfoil"), default="local")
    serve.add_argument("--base-url", default="http://127.0.0.1:8080")
    serve.add_argument("--enclave", default="")
    serve.add_argument("--repo", default="")
    serve.add_argument("--release-tag", default="")
    serve.add_argument("--measurement-file", default="")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8090)
    serve.add_argument("--log-level", default="info")
    serve.add_argument("--open-browser", action="store_true")
    serve.set_defaults(func=cmd_serve)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
