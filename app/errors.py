"""Domain errors.

Every denial is raised as a subclass carrying a stable, machine-readable
``DenialReason``. The HTTP layer maps reasons to distinct status codes and
an ``error.reason`` field, so callers (and tests) can distinguish:

missing credential / forged credential / expired credential /
unauthorized scope / lease expired / lease revoked /
lease version mismatch / lease not found.
"""

from __future__ import annotations

from app.models import DenialReason


class BrokerError(Exception):
    """Base error with a stable machine-readable reason."""

    reason: DenialReason = DenialReason.CONFLICT

    def __init__(self, message: str = "", *, detail: dict | None = None) -> None:
        super().__init__(message or self.reason.value)
        self.message = message or self.reason.value
        self.detail: dict = detail or {}


class MissingCredentialError(BrokerError):
    reason = DenialReason.MISSING_CREDENTIAL


class ForgedCredentialError(BrokerError):
    reason = DenialReason.FORGED_CREDENTIAL


class ExpiredCredentialError(BrokerError):
    reason = DenialReason.EXPIRED_CREDENTIAL


class UnauthorizedScopeError(BrokerError):
    reason = DenialReason.UNAUTHORIZED_SCOPE


class LeaseExpiredError(BrokerError):
    reason = DenialReason.LEASE_EXPIRED


class LeaseRevokedError(BrokerError):
    reason = DenialReason.LEASE_REVOKED


class LeaseVersionMismatchError(BrokerError):
    reason = DenialReason.LEASE_VERSION_MISMATCH


class LeaseNotFoundError(BrokerError):
    reason = DenialReason.LEASE_NOT_FOUND
