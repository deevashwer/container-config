from __future__ import annotations

import asyncio
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class SessionError(ValueError):
    """Raised when a browser session cannot be used."""


@dataclass(slots=True)
class StoredSession:
    session_id: str
    key_id: str
    issued_at: datetime
    expires_at: datetime


class InMemorySessionStore:
    def __init__(self, ttl_seconds: int) -> None:
        self._ttl_seconds = ttl_seconds
        self._lock = asyncio.Lock()
        self._sessions: dict[str, StoredSession] = {}

    async def issue(self, *, key_id: str) -> StoredSession:
        now = utc_now()
        session = StoredSession(
            session_id=secrets.token_urlsafe(32),
            key_id=key_id,
            issued_at=now,
            expires_at=now + timedelta(seconds=self._ttl_seconds),
        )
        async with self._lock:
            self._prune_locked(now)
            self._sessions[session.session_id] = session
        return session

    async def get(self, session_id: str) -> StoredSession:
        now = utc_now()
        async with self._lock:
            self._prune_locked(now)
            session = self._sessions.get(session_id)
            if session is None:
                raise SessionError("unknown session")
            if session.expires_at <= now:
                del self._sessions[session_id]
                raise SessionError("session expired")
            return session

    async def revoke(self, session_id: str) -> None:
        async with self._lock:
            self._sessions.pop(session_id, None)

    def _prune_locked(self, now: datetime) -> None:
        expired_ids = [
            session_id
            for session_id, session in self._sessions.items()
            if session.expires_at <= now
        ]
        for session_id in expired_ids:
            del self._sessions[session_id]
