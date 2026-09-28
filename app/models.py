"""Domain model definitions (types only; behavior lives in other modules)."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Protocol


class Clock(Protocol):
    """Time source, so tests can run deterministically."""

    def now(self) -> datetime: ...


class LeaseStatus(str, Enum):
    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"
    VERSION_MISMATCH = "version_mismatch"


class DenialReason(str, Enum):
    """Distinguishable, explainable failure reasons."""

    MISSING_CREDENTIAL = "missing_credential"
    FORGED_CREDENTIAL = "forged_credential"
    EXPIRED_CREDENTIAL = "expired_credential"
    UNAUTHORIZED_SCOPE = "unauthorized_scope"
    LEASE_EXPIRED = "lease_expired"
    LEASE_REVOKED = "lease_revoked"
    LEASE_VERSION_MISMATCH = "lease_version_mismatch"
    LEASE_NOT_FOUND = "lease_not_found"
    CONFLICT = "conflict"


@dataclass(frozen=True, slots=True)
class Identity:
    """An authenticated caller."""

    caller_id: str
    scopes: frozenset[str] = field(default_factory=frozenset)
    expires_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class SecretVersion:
    """One immutable version of a secret."""

    secret_name: str
    version: int
    value: str
    created_at: datetime


@dataclass(frozen=True, slots=True)
class SecretRecord:
    """A secret with its full version history."""

    name: str
    versions: tuple[SecretVersion, ...]
    overlap_window_seconds: int
    current_version: int


@dataclass(slots=True)
class Lease:
    """A short-lived, revocable lease bound to one secret version."""

    lease_id: str
    caller_id: str
    secret_name: str
    version: int
    issued_at: datetime
    expires_at: datetime
    revoked: bool = False


@dataclass(frozen=True, slots=True)
class AccessResult:
    """Outcome of an issue / renew / access decision.

    ``value`` is only populated by an actual secret read; issue and renew
    return lease metadata without materializing the secret value.
    ``basis`` is a human-readable explanation of why this decision was made.
    """

    lease_id: str
    secret_name: str
    version: int
    expires_at: datetime
    status: LeaseStatus
    value: str | None = None
    basis: str = ""
