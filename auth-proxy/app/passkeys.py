from __future__ import annotations

import asyncio
import base64
import json
import secrets
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any, Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


FLAG_USER_PRESENT = 0x01
FLAG_USER_VERIFIED = 0x04
FLAG_ATTESTED_CREDENTIAL_DATA = 0x40


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def isoformat_z(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def parse_datetime(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def base64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def base64url_decode(value: str) -> bytes:
    padding = "=" * ((4 - len(value) % 4) % 4)
    return base64.urlsafe_b64decode(value + padding)


def random_b64url(length: int = 32) -> str:
    return base64url_encode(secrets.token_bytes(length))


def host_without_port(host: str) -> str:
    value = host.strip()
    if not value:
        return value
    if value.startswith("[") and "]" in value:
        closing = value.find("]")
        return value[1:closing]
    if value.count(":") == 1:
        return value.rsplit(":", 1)[0]
    return value


class PasskeyError(ValueError):
    """Raised when a WebAuthn request cannot be validated."""


@dataclass(slots=True)
class PendingPasskeyCeremony:
    ceremony_id: str
    purpose: Literal["initialize", "authenticate"]
    challenge: str
    rp_id: str
    origin: str
    issued_at: datetime
    expires_at: datetime
    allowed_credential_ids: tuple[str, ...] = ()


class InMemoryPasskeyCeremonyStore:
    def __init__(self, ttl_seconds: int) -> None:
        self._ttl_seconds = ttl_seconds
        self._lock = asyncio.Lock()
        self._items: dict[str, PendingPasskeyCeremony] = {}

    async def issue(
        self,
        *,
        purpose: Literal["initialize", "authenticate"],
        rp_id: str,
        origin: str,
        allowed_credential_ids: tuple[str, ...] = (),
    ) -> PendingPasskeyCeremony:
        now = utc_now()
        item = PendingPasskeyCeremony(
            ceremony_id=secrets.token_urlsafe(18),
            purpose=purpose,
            challenge=random_b64url(32),
            rp_id=rp_id,
            origin=origin.rstrip("/"),
            issued_at=now,
            expires_at=now + timedelta(seconds=self._ttl_seconds),
            allowed_credential_ids=allowed_credential_ids,
        )
        async with self._lock:
            self._prune_locked(now)
            self._items[item.ceremony_id] = item
        return item

    async def consume(
        self,
        ceremony_id: str,
        *,
        purpose: Literal["initialize", "authenticate"],
    ) -> PendingPasskeyCeremony:
        now = utc_now()
        async with self._lock:
            self._prune_locked(now)
            item = self._items.pop(ceremony_id, None)
            if item is None:
                raise PasskeyError("unknown or expired passkey challenge")
            if item.purpose != purpose:
                raise PasskeyError("passkey challenge purpose mismatch")
            if item.expires_at <= now:
                raise PasskeyError("passkey challenge expired")
            return item

    def _prune_locked(self, now: datetime) -> None:
        expired_ids = [
            ceremony_id
            for ceremony_id, item in self._items.items()
            if item.expires_at <= now
        ]
        for ceremony_id in expired_ids:
            del self._items[ceremony_id]


@dataclass(slots=True)
class StoredPasskeyCredential:
    credential_id: str
    public_key_pem: str
    sign_count: int
    created_at: str
    last_used_at: str | None = None


@dataclass(slots=True)
class VerifiedPasskeyRegistration:
    credential_id: str
    public_key_pem: str
    sign_count: int


@dataclass(slots=True)
class VerifiedPasskeyAssertion:
    credential_id: str
    next_sign_count: int


@dataclass(slots=True)
class ParsedAuthenticatorData:
    rp_id_hash: bytes
    flags: int
    sign_count: int
    credential_id: str | None
    public_key: ec.EllipticCurvePublicKey | None


class FileBackedPasskeyStore:
    def __init__(self, path: str | Path | None) -> None:
        self._path = Path(path).expanduser() if path else None
        self._lock = asyncio.Lock()
        self._credentials: dict[str, StoredPasskeyCredential] | None = None

    async def count(self) -> int:
        async with self._lock:
            await self._ensure_loaded_locked()
            assert self._credentials is not None
            return len(self._credentials)

    async def registration_open(self) -> bool:
        return await self.count() == 0

    async def descriptors(self) -> list[dict[str, str]]:
        async with self._lock:
            await self._ensure_loaded_locked()
            assert self._credentials is not None
            return [{"id": credential_id, "type": "public-key"} for credential_id in self._credentials]

    async def get(self, credential_id: str) -> StoredPasskeyCredential | None:
        async with self._lock:
            await self._ensure_loaded_locked()
            assert self._credentials is not None
            return self._credentials.get(credential_id)

    async def add(self, credential: StoredPasskeyCredential) -> StoredPasskeyCredential:
        async with self._lock:
            await self._ensure_loaded_locked()
            assert self._credentials is not None
            if self._credentials:
                raise PasskeyError("this enclave has already been initialized")
            if credential.credential_id in self._credentials:
                raise PasskeyError("that passkey is already registered")
            self._credentials[credential.credential_id] = credential
            await self._persist_locked()
            return credential

    async def update_usage(self, credential_id: str, *, sign_count: int) -> StoredPasskeyCredential:
        async with self._lock:
            await self._ensure_loaded_locked()
            assert self._credentials is not None
            credential = self._credentials.get(credential_id)
            if credential is None:
                raise PasskeyError("unknown passkey credential")
            credential.sign_count = sign_count
            credential.last_used_at = isoformat_z(utc_now())
            await self._persist_locked()
            return credential

    async def _ensure_loaded_locked(self) -> None:
        if self._credentials is not None:
            return
        self._credentials = {}
        if not self._path or not self._path.exists():
            return
        raw = json.loads(self._path.read_text(encoding="utf-8"))
        for item in raw.get("credentials", []):
            credential = StoredPasskeyCredential(
                credential_id=str(item["credential_id"]),
                public_key_pem=str(item["public_key_pem"]),
                sign_count=int(item.get("sign_count", 0)),
                created_at=str(item["created_at"]),
                last_used_at=str(item["last_used_at"]) if item.get("last_used_at") else None,
            )
            self._credentials[credential.credential_id] = credential

    async def _persist_locked(self) -> None:
        if self._path is None:
            return
        assert self._credentials is not None
        self._path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "version": 1,
            "credentials": [asdict(item) for item in self._credentials.values()],
        }
        temp_path = self._path.with_suffix(f"{self._path.suffix}.tmp")
        temp_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        temp_path.replace(self._path)


class CborDecodeError(PasskeyError):
    """Raised when CBOR input cannot be parsed."""


def _decode_cbor_length(data: bytes, offset: int, additional_info: int) -> tuple[int, int]:
    if additional_info < 24:
        return additional_info, offset
    if additional_info == 24:
        return data[offset], offset + 1
    if additional_info == 25:
        return int.from_bytes(data[offset : offset + 2], "big"), offset + 2
    if additional_info == 26:
        return int.from_bytes(data[offset : offset + 4], "big"), offset + 4
    if additional_info == 27:
        return int.from_bytes(data[offset : offset + 8], "big"), offset + 8
    raise CborDecodeError("unsupported CBOR length encoding")


def cbor_decode_first(data: bytes, offset: int = 0) -> tuple[Any, int]:
    if offset >= len(data):
        raise CborDecodeError("unexpected end of CBOR input")
    initial_byte = data[offset]
    offset += 1
    major_type = initial_byte >> 5
    additional_info = initial_byte & 0x1F
    length, offset = _decode_cbor_length(data, offset, additional_info)

    if major_type == 0:
        return length, offset
    if major_type == 1:
        return -1 - length, offset
    if major_type == 2:
        end = offset + length
        return data[offset:end], end
    if major_type == 3:
        end = offset + length
        return data[offset:end].decode("utf-8"), end
    if major_type == 4:
        items = []
        for _ in range(length):
            item, offset = cbor_decode_first(data, offset)
            items.append(item)
        return items, offset
    if major_type == 5:
        value: dict[Any, Any] = {}
        for _ in range(length):
            key, offset = cbor_decode_first(data, offset)
            item, offset = cbor_decode_first(data, offset)
            value[key] = item
        return value, offset
    if major_type == 6:
        return cbor_decode_first(data, offset)
    if major_type == 7:
        if additional_info == 20:
            return False, offset
        if additional_info == 21:
            return True, offset
        if additional_info == 22:
            return None, offset
    raise CborDecodeError("unsupported CBOR type")


def cbor_decode(data: bytes) -> Any:
    value, offset = cbor_decode_first(data, 0)
    if offset != len(data):
        raise CborDecodeError("unexpected trailing CBOR data")
    return value


def parse_client_data_json(
    value: str,
    *,
    expected_type: str,
    expected_challenge: str,
    expected_origin: str,
) -> bytes:
    try:
        raw = base64url_decode(value)
        payload = json.loads(raw.decode("utf-8"))
    except (ValueError, json.JSONDecodeError) as exc:
        raise PasskeyError("invalid client data JSON") from exc
    if payload.get("type") != expected_type:
        raise PasskeyError("unexpected WebAuthn ceremony type")
    if payload.get("challenge") != expected_challenge:
        raise PasskeyError("passkey challenge mismatch")
    if str(payload.get("origin", "")).rstrip("/") != expected_origin.rstrip("/"):
        raise PasskeyError("passkey origin mismatch")
    return raw


def _load_ec_public_key_from_cose(cose_key: dict[Any, Any]) -> ec.EllipticCurvePublicKey:
    if cose_key.get(1) != 2:
        raise PasskeyError("unsupported COSE key type")
    if cose_key.get(3) != -7:
        raise PasskeyError("unsupported passkey algorithm")
    if cose_key.get(-1) != 1:
        raise PasskeyError("unsupported elliptic curve")
    x = cose_key.get(-2)
    y = cose_key.get(-3)
    if not isinstance(x, bytes) or not isinstance(y, bytes):
        raise PasskeyError("invalid passkey public key encoding")
    numbers = ec.EllipticCurvePublicNumbers(
        int.from_bytes(x, "big"),
        int.from_bytes(y, "big"),
        ec.SECP256R1(),
    )
    return numbers.public_key()


def serialize_public_key(public_key: ec.EllipticCurvePublicKey) -> str:
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")


def load_public_key(pem: str) -> ec.EllipticCurvePublicKey:
    public_key = serialization.load_pem_public_key(pem.encode("ascii"))
    if not isinstance(public_key, ec.EllipticCurvePublicKey):
        raise PasskeyError("stored passkey is not an EC public key")
    return public_key


def parse_authenticator_data(authenticator_data: bytes) -> ParsedAuthenticatorData:
    if len(authenticator_data) < 37:
        raise PasskeyError("authenticator data is too short")
    rp_id_hash = authenticator_data[:32]
    flags = authenticator_data[32]
    sign_count = int.from_bytes(authenticator_data[33:37], "big")
    credential_id = None
    public_key = None
    offset = 37

    if flags & FLAG_ATTESTED_CREDENTIAL_DATA:
        if len(authenticator_data) < offset + 18:
            raise PasskeyError("attested credential data is truncated")
        offset += 16  # AAGUID
        credential_length = int.from_bytes(authenticator_data[offset : offset + 2], "big")
        offset += 2
        credential_bytes = authenticator_data[offset : offset + credential_length]
        if len(credential_bytes) != credential_length:
            raise PasskeyError("credential id is truncated")
        credential_id = base64url_encode(credential_bytes)
        offset += credential_length
        cose_key, _ = cbor_decode_first(authenticator_data, offset)
        if not isinstance(cose_key, dict):
            raise PasskeyError("credential public key is not a COSE map")
        public_key = _load_ec_public_key_from_cose(cose_key)

    return ParsedAuthenticatorData(
        rp_id_hash=rp_id_hash,
        flags=flags,
        sign_count=sign_count,
        credential_id=credential_id,
        public_key=public_key,
    )


def _require_authenticator_flags(parsed: ParsedAuthenticatorData) -> None:
    if not (parsed.flags & FLAG_USER_PRESENT):
        raise PasskeyError("passkey user presence is required")
    if not (parsed.flags & FLAG_USER_VERIFIED):
        raise PasskeyError("passkey user verification is required")


def _require_rp_id(parsed: ParsedAuthenticatorData, rp_id: str) -> None:
    expected = sha256(rp_id.encode("utf-8")).digest()
    if parsed.rp_id_hash != expected:
        raise PasskeyError("passkey RP ID hash mismatch")


def verify_registration_response(
    *,
    credential: dict[str, Any],
    pending: PendingPasskeyCeremony,
) -> VerifiedPasskeyRegistration:
    if credential.get("type") != "public-key":
        raise PasskeyError("unexpected passkey credential type")
    raw_client_data = parse_client_data_json(
        str(credential["response"]["clientDataJSON"]),
        expected_type="webauthn.create",
        expected_challenge=pending.challenge,
        expected_origin=pending.origin,
    )
    del raw_client_data
    try:
        attestation_object = cbor_decode(base64url_decode(str(credential["response"]["attestationObject"])))
    except KeyError as exc:
        raise PasskeyError("passkey attestation response is incomplete") from exc
    if not isinstance(attestation_object, dict):
        raise PasskeyError("invalid passkey attestation object")
    if attestation_object.get("fmt") != "none":
        raise PasskeyError("only attestation=none is supported")
    authenticator_data = attestation_object.get("authData")
    if not isinstance(authenticator_data, bytes):
        raise PasskeyError("invalid authenticator data in attestation")
    parsed = parse_authenticator_data(authenticator_data)
    _require_rp_id(parsed, pending.rp_id)
    _require_authenticator_flags(parsed)
    if parsed.credential_id is None or parsed.public_key is None:
        raise PasskeyError("passkey registration did not include a credential public key")
    try:
        raw_id = base64url_encode(base64url_decode(str(credential["rawId"])))
    except ValueError as exc:
        raise PasskeyError("invalid passkey rawId encoding") from exc
    if raw_id != parsed.credential_id:
        raise PasskeyError("credential id mismatch in passkey registration")
    return VerifiedPasskeyRegistration(
        credential_id=parsed.credential_id,
        public_key_pem=serialize_public_key(parsed.public_key),
        sign_count=parsed.sign_count,
    )


def verify_authentication_response(
    *,
    credential: dict[str, Any],
    pending: PendingPasskeyCeremony,
    stored: StoredPasskeyCredential,
) -> VerifiedPasskeyAssertion:
    if credential.get("type") != "public-key":
        raise PasskeyError("unexpected passkey credential type")
    try:
        raw_id = base64url_encode(base64url_decode(str(credential["rawId"])))
    except ValueError as exc:
        raise PasskeyError("invalid passkey rawId encoding") from exc
    if raw_id != stored.credential_id:
        raise PasskeyError("unexpected passkey credential")
    if pending.allowed_credential_ids and raw_id not in pending.allowed_credential_ids:
        raise PasskeyError("passkey credential was not requested by the server")
    raw_client_data = parse_client_data_json(
        str(credential["response"]["clientDataJSON"]),
        expected_type="webauthn.get",
        expected_challenge=pending.challenge,
        expected_origin=pending.origin,
    )
    try:
        authenticator_data = base64url_decode(str(credential["response"]["authenticatorData"]))
        signature = base64url_decode(str(credential["response"]["signature"]))
    except KeyError as exc:
        raise PasskeyError("passkey assertion response is incomplete") from exc
    parsed = parse_authenticator_data(authenticator_data)
    _require_rp_id(parsed, pending.rp_id)
    _require_authenticator_flags(parsed)

    client_data_hash = sha256(raw_client_data).digest()
    public_key = load_public_key(stored.public_key_pem)
    try:
        public_key.verify(
            signature,
            authenticator_data + client_data_hash,
            ec.ECDSA(hashes.SHA256()),
        )
    except InvalidSignature as exc:
        raise PasskeyError("invalid passkey assertion signature") from exc

    if stored.sign_count and parsed.sign_count and parsed.sign_count <= stored.sign_count:
        raise PasskeyError("passkey sign counter did not advance")

    return VerifiedPasskeyAssertion(
        credential_id=stored.credential_id,
        next_sign_count=max(stored.sign_count, parsed.sign_count),
    )
