"""Verifiable local credentials: issue and authenticate bearer tokens.

Tokens are HMAC-SHA256 signed locally (no external IdP, no real secrets).
The wire format is ``b64url(payload_json).b64url(hmac)``.

Authorization-relevant identity (caller id and scopes) lives *inside* the
signed payload, so a caller cannot self-declare a role: any tampering breaks
the signature and is rejected as ``forged_credential``.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from dataclasses import replace

from app.errors import (
    ExpiredCredentialError,
    ForgedCredentialError,
    MissingCredentialError,
)
from app.models import Clock, Identity


def _b64encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64decode(text: str) -> bytes:
    padding = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + padding)


class TokenIssuer:
    def __init__(self, key: bytes = b"bootstrap-local-key") -> None:
        self._key = key

    def _sign(self, payload_b64: str) -> str:
        mac = hmac.new(self._key, payload_b64.encode("ascii"), hashlib.sha256)
        return _b64encode(mac.digest())

    def issue(
        self,
        caller_id: str,
        scopes: frozenset[str] | set[str] | tuple[str, ...],
        ttl_seconds: int,
        clock: Clock,
    ) -> str:
        now = clock.now()
        from datetime import timedelta

        payload = {
            "sub": caller_id,
            "scp": sorted(scopes),
            "iat": now.isoformat(),
            "exp": (now + timedelta(seconds=ttl_seconds)).isoformat(),
        }
        payload_b64 = _b64encode(json.dumps(payload, separators=(",", ":")).encode())
        return f"{payload_b64}.{self._sign(payload_b64)}"

    def authenticate(self, token: str | None, clock: Clock) -> Identity:
        if not token:
            raise MissingCredentialError("no bearer token provided")

        parts = token.split(".")
        if len(parts) != 2 or not parts[0] or not parts[1]:
            raise ForgedCredentialError("malformed token")
        payload_b64, signature = parts

        expected = self._sign(payload_b64)
        if not hmac.compare_digest(signature, expected):
            raise ForgedCredentialError("signature verification failed")

        try:
            payload = json.loads(_b64decode(payload_b64))
            caller_id = payload["sub"]
            scopes = payload["scp"]
            exp = payload["exp"]
        except Exception as exc:  # malformed payload => treated as forged
            raise ForgedCredentialError("unreadable token payload") from exc

        if not isinstance(caller_id, str) or not isinstance(scopes, list):
            raise ForgedCredentialError("invalid token claims")

        from datetime import datetime

        try:
            expires_at = datetime.fromisoformat(exp)
        except Exception as exc:
            raise ForgedCredentialError("invalid expiry claim") from exc

        now = clock.now()
        if now >= expires_at:
            raise ExpiredCredentialError(
                f"credential expired at {expires_at.isoformat()}",
                detail={"expired_at": expires_at.isoformat(), "now": now.isoformat()},
            )

        return Identity(
            caller_id=caller_id,
            scopes=frozenset(s for s in scopes if isinstance(s, str)),
            expires_at=expires_at,
        )
