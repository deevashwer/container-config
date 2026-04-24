from __future__ import annotations

import asyncio
import base64
import json
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec


AUTH_VERSION = "openclaw-owner-auth-v1"


class ChallengeError(ValueError):
    """Raised when a challenge cannot be used."""


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def isoformat_z(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def base64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def base64url_decode(value: str) -> bytes:
    padding = "=" * ((4 - len(value) % 4) % 4)
    return base64.urlsafe_b64decode(value + padding)


def sha256_hex(value: bytes) -> str:
    return sha256(value).hexdigest()


def normalize_method(method: str) -> str:
    return method.upper()


def normalize_path(path: str) -> str:
    if not path.startswith("/"):
        raise ValueError("signed paths must start with '/'")
    return path


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
    return sha256_hex(canonical_public_jwk_json(jwk).encode("utf-8"))


def public_key_from_jwk(jwk: dict[str, Any]) -> ec.EllipticCurvePublicKey:
    sanitized = sanitize_public_jwk(jwk)
    x = int.from_bytes(base64url_decode(sanitized["x"]), "big")
    y = int.from_bytes(base64url_decode(sanitized["y"]), "big")
    numbers = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1())
    return numbers.public_key()


def private_key_from_jwk(jwk: dict[str, Any]) -> ec.EllipticCurvePrivateKey:
    sanitized = sanitize_private_jwk(jwk)
    d = int.from_bytes(base64url_decode(sanitized["d"]), "big")
    public_numbers = public_key_from_jwk(sanitized).public_numbers()
    private_numbers = ec.EllipticCurvePrivateNumbers(d, public_numbers)
    return private_numbers.private_key()


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


def build_signing_payload(
    *,
    challenge_id: str,
    nonce: str,
    method: str,
    path: str,
    body_sha256: str,
    expires_at: datetime,
) -> str:
    payload = {
        "body_sha256": body_sha256,
        "challenge_id": challenge_id,
        "expires_at": isoformat_z(expires_at),
        "method": normalize_method(method),
        "nonce": nonce,
        "path": normalize_path(path),
        "version": AUTH_VERSION,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def verify_signature(
    *,
    public_key: ec.EllipticCurvePublicKey,
    signature_b64url: str,
    signing_payload: str,
) -> bool:
    try:
        signature = base64url_decode(signature_b64url)
        public_key.verify(
            signature,
            signing_payload.encode("utf-8"),
            ec.ECDSA(hashes.SHA256()),
        )
        return True
    except (InvalidSignature, ValueError):
        return False


@dataclass(slots=True)
class StoredChallenge:
    challenge_id: str
    nonce: str
    method: str
    path: str
    body_sha256: str
    expires_at: datetime
    issued_at: datetime
    used: bool = False

    @property
    def signing_payload(self) -> str:
        return build_signing_payload(
            challenge_id=self.challenge_id,
            nonce=self.nonce,
            method=self.method,
            path=self.path,
            body_sha256=self.body_sha256,
            expires_at=self.expires_at,
        )


class InMemoryChallengeStore:
    def __init__(self, ttl_seconds: int) -> None:
        self._ttl_seconds = ttl_seconds
        self._lock = asyncio.Lock()
        self._challenges: dict[str, StoredChallenge] = {}

    async def issue(self, *, method: str, path: str, body_sha256: str) -> StoredChallenge:
        now = utc_now()
        challenge = StoredChallenge(
            challenge_id=secrets.token_urlsafe(18),
            nonce=secrets.token_urlsafe(32),
            method=normalize_method(method),
            path=normalize_path(path),
            body_sha256=body_sha256,
            expires_at=now + timedelta(seconds=self._ttl_seconds),
            issued_at=now,
        )
        async with self._lock:
            self._prune_locked(now)
            self._challenges[challenge.challenge_id] = challenge
        return challenge

    async def consume(self, challenge_id: str) -> StoredChallenge:
        now = utc_now()
        async with self._lock:
            self._prune_locked(now)
            challenge = self._challenges.get(challenge_id)
            if challenge is None:
                raise ChallengeError("unknown challenge")
            if challenge.used:
                raise ChallengeError("challenge already used")
            if challenge.expires_at <= now:
                del self._challenges[challenge_id]
                raise ChallengeError("challenge expired")
            challenge.used = True
            return challenge

    def _prune_locked(self, now: datetime) -> None:
        expired_ids = [
            challenge_id
            for challenge_id, challenge in self._challenges.items()
            if challenge.expires_at <= now
        ]
        for challenge_id in expired_ids:
            del self._challenges[challenge_id]
