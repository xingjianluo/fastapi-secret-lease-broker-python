"""Core lease broker: issue / renew / revoke / access decisions.

All four operations take the store's single lock for their whole
"authenticate -> authorize -> check -> mutate" sequence, so concurrent calls
are serialized into a total order and every decision is consistent with the
state observed inside that critical section:

* concurrent renew of one lease never creates a second lease (the lease id is
  stable and expiry is updated in place);
* a revoke cannot be lost against a renew;
* a request still in flight after a revoke cannot succeed, because it too
  re-checks ``revoked`` inside the same lock before returning a value.

Version binding: a lease is bound to exactly one secret version at issue time.
After rotation the lease keeps returning the *old* version's value during the
overlap window. Once the window closes the old version is retired and the
lease fails with ``lease_version_mismatch`` — it is never silently redirected
to the new value and never silently allowed.
"""

from __future__ import annotations

import logging
import uuid
from datetime import timedelta

from app.auth import TokenIssuer
from app.authz import Authorizer
from app.errors import (
    LeaseExpiredError,
    LeaseRevokedError,
    LeaseVersionMismatchError,
    UnauthorizedScopeError,
)
from app.models import AccessResult, Clock, Lease, LeaseStatus, SecretRecord
from app.store import MemoryStore

logger = logging.getLogger("lease_broker.audit")


def _valid_ttl(ttl_seconds: int) -> int:
    if not isinstance(ttl_seconds, int) or ttl_seconds <= 0:
        raise ValueError("ttl_seconds must be a positive integer")
    return ttl_seconds


class LeaseBroker:
    def __init__(
        self,
        store: MemoryStore,
        issuer: TokenIssuer,
        authorizer: Authorizer,
        clock: Clock,
    ) -> None:
        self._store = store
        self._issuer = issuer
        self._authz = authorizer
        self._clock = clock

    # ----- secrets / rotation (fixture + admin helpers) ------------------

    def add_secret(self, record: SecretRecord) -> None:
        self._store.put_secret(record)

    def rotate_secret(self, name: str, value: str, overlap_window_seconds: int | None = None) -> SecretRecord:
        return self._store.rotate_secret(name, value, self._clock, overlap_window_seconds)

    # ----- audit ----------------------------------------------------------

    def _audit(self, action: str, token: str | None, detail: str, allowed: bool) -> None:
        caller = "?"
        if token:
            try:
                caller = self._issuer.authenticate(token, self._clock).caller_id
            except Exception:
                caller = "<unauthenticated>"
        logger.info(
            "action=%s caller=%s allowed=%s | %s", action, caller, allowed, detail
        )

    # ----- issue ----------------------------------------------------------

    def issue_lease(self, token: str | None, secret_name: str, ttl_seconds: int) -> AccessResult:
        ttl = _valid_ttl(ttl_seconds)
        with self._store.lock():
            identity = self._issuer.authenticate(token, self._clock)  # raises auth errors
            if not self._authz.can_read_secret(identity, secret_name):
                self._audit(
                    "issue", token,
                    f"deny unauthorized: caller={identity.caller_id} secret={secret_name}",
                    False,
                )
                raise UnauthorizedScopeError(
                    f"caller '{identity.caller_id}' has no read scope for secret '{secret_name}'",
                    detail={"caller": identity.caller_id, "secret": secret_name},
                )

            record = self._store.get_secret(secret_name)
            if record is None:
                # Default-deny: a secret that does not exist is not an open door.
                raise UnauthorizedScopeError(
                    f"unknown secret '{secret_name}'",
                    detail={"caller": identity.caller_id, "secret": secret_name},
                )

            now = self._clock.now()
            lease = Lease(
                lease_id=uuid.uuid4().hex,
                caller_id=identity.caller_id,
                secret_name=secret_name,
                version=record.current_version,
                issued_at=now,
                expires_at=now + timedelta(seconds=ttl),
            )
            self._store.put_lease(lease)
            self._audit(
                "issue", token,
                f"allow lease={lease.lease_id} secret={secret_name} "
                f"version={lease.version} expires_at={lease.expires_at.isoformat()}",
                True,
            )
            return AccessResult(
                lease_id=lease.lease_id,
                secret_name=secret_name,
                version=lease.version,
                expires_at=lease.expires_at,
                status=LeaseStatus.ACTIVE,
                basis=(
                    f"authenticated caller '{identity.caller_id}' holds read scope; "
                    f"new lease bound to current version {lease.version}, "
                    f"expires at {lease.expires_at.isoformat()}"
                ),
            )

    # ----- renew ----------------------------------------------------------

    def renew_lease(self, token: str | None, lease_id: str, ttl_seconds: int) -> AccessResult:
        ttl = _valid_ttl(ttl_seconds)
        with self._store.lock():
            identity = self._issuer.authenticate(token, self._clock)
            lease = self._store.require_lease(lease_id)

            if not self._authz.can_manage_lease(identity, lease):
                raise UnauthorizedScopeError(
                    f"caller '{identity.caller_id}' may not renew lease '{lease_id}'",
                    detail={"caller": identity.caller_id, "lease": lease_id},
                )

            # Revocation wins over expiry: a revoked lease is never renewed.
            self._ensure_live(lease)

            now = self._clock.now()
            # Version binding is preserved: renewal extends the *same* lease,
            # it never rebinds it to a newer secret version and never makes a
            # new lease id (so concurrent renewals cannot duplicate a lease).
            lease.expires_at = now + timedelta(seconds=ttl)
            self._store.put_lease(lease)
            self._audit(
                "renew", token,
                f"allow lease={lease_id} version={lease.version} "
                f"new_expiry={lease.expires_at.isoformat()}",
                True,
            )
            return AccessResult(
                lease_id=lease.lease_id,
                secret_name=lease.secret_name,
                version=lease.version,
                expires_at=lease.expires_at,
                status=LeaseStatus.ACTIVE,
                basis=(
                    f"renewed existing lease in place (id unchanged), still bound to "
                    f"version {lease.version}; new expiry {lease.expires_at.isoformat()}"
                ),
            )

    # ----- revoke ---------------------------------------------------------

    def revoke_lease(self, token: str | None, lease_id: str) -> dict:
        with self._store.lock():
            identity = self._issuer.authenticate(token, self._clock)
            lease = self._store.require_lease(lease_id)

            if not self._authz.can_manage_lease(identity, lease):
                raise UnauthorizedScopeError(
                    f"caller '{identity.caller_id}' may not revoke lease '{lease_id}'",
                    detail={"caller": identity.caller_id, "lease": lease_id},
                )

            already = lease.revoked
            lease.revoked = True
            self._store.put_lease(lease)
            self._audit(
                "revoke", token,
                f"{'already-revoked' if already else 'revoked'} lease={lease_id} "
                f"secret={lease.secret_name} version={lease.version}",
                True,
            )
            return {
                "lease_id": lease_id,
                "revoked": True,
                "already_revoked": already,
                "basis": (
                    f"lease marked revoked; any subsequent renew/access is denied "
                    f"with reason '{LeaseStatus.REVOKED.value}'"
                ),
            }

    # ----- access (read secret value through a lease) ---------------------

    def access_secret(self, token: str | None, lease_id: str) -> AccessResult:
        with self._store.lock():
            identity = self._issuer.authenticate(token, self._clock)
            lease = self._store.require_lease(lease_id)

            if identity.caller_id != lease.caller_id and not self._authz.can_revoke_any(identity):
                # Only the lease owner (or break-glass ops) may read through it.
                raise UnauthorizedScopeError(
                    f"caller '{identity.caller_id}' does not own lease '{lease_id}'",
                    detail={"caller": identity.caller_id, "lease": lease_id, "owner": lease.caller_id},
                )

            # Fixed, documented evaluation order => distinguishable outcomes.
            # 1. revoked beats everything; 2. expiry; 3. version retirement.
            if lease.revoked:
                self._audit("access", token, f"deny lease={lease_id} revoked", False)
                raise LeaseRevokedError(
                    f"lease '{lease_id}' was revoked",
                    detail={"lease": lease_id, "secret": lease.secret_name, "version": lease.version},
                )

            now = self._clock.now()
            if now >= lease.expires_at:
                self._audit(
                    "access", token,
                    f"deny lease={lease_id} expired expires_at={lease.expires_at.isoformat()} now={now.isoformat()}",
                    False,
                )
                raise LeaseExpiredError(
                    f"lease '{lease_id}' expired at {lease.expires_at.isoformat()}",
                    detail={
                        "lease": lease_id,
                        "expires_at": lease.expires_at.isoformat(),
                        "now": now.isoformat(),
                    },
                )

            secret_version = self._store.secret_version(lease.secret_name, lease.version)
            if secret_version is None:
                self._audit(
                    "access", token,
                    f"deny lease={lease_id} version={lease.version} retired/missing",
                    False,
                )
                raise LeaseVersionMismatchError(
                    f"bound version {lease.version} no longer available for secret '{lease.secret_name}'",
                    detail={"lease": lease_id, "secret": lease.secret_name, "bound_version": lease.version},
                )

            record = self._store.get_secret(lease.secret_name)
            current = record.current_version if record else None
            window_closed = self._old_version_window_closed(lease.version, record, now)
            if window_closed:
                self._audit(
                    "access", token,
                    f"deny lease={lease_id} old_version={lease.version} "
                    f"current={current} overlap window closed",
                    False,
                )
                raise LeaseVersionMismatchError(
                    f"overlap window for version {lease.version} of "
                    f"'{lease.secret_name}' has closed; current version is {current}",
                    detail={
                        "lease": lease_id,
                        "secret": lease.secret_name,
                        "bound_version": lease.version,
                        "current_version": current,
                    },
                )

            self._audit(
                "access", token,
                f"allow lease={lease_id} secret={lease.secret_name} version={lease.version} "
                f"current={current} expires_at={lease.expires_at.isoformat()}",
                True,
            )
            note = (
                "overlap window still open; serving bound old version"
                if current != lease.version
                else "serving current version"
            )
            return AccessResult(
                lease_id=lease.lease_id,
                secret_name=lease.secret_name,
                version=lease.version,
                value=secret_version.value,
                expires_at=lease.expires_at,
                status=LeaseStatus.ACTIVE,
                basis=(
                    f"lease active and owned by caller; {note} {lease.version} "
                    f"(current={current}); value never promoted across versions"
                ),
            )

    # ----- internals ------------------------------------------------------

    def _ensure_live(self, lease: Lease) -> None:
        """Revocation first, then expiry (used by renew)."""
        if lease.revoked:
            raise LeaseRevokedError(
                f"lease '{lease.lease_id}' was revoked and cannot be renewed",
                detail={"lease": lease.lease_id},
            )
        if self._clock.now() >= lease.expires_at:
            raise LeaseExpiredError(
                f"lease '{lease.lease_id}' expired at {lease.expires_at.isoformat()}",
                detail={"lease": lease.lease_id, "expires_at": lease.expires_at.isoformat()},
            )

    def _old_version_window_closed(self, bound_version: int, record: SecretRecord | None, now) -> bool:
        """An old version is readable only until ``overlap_window_seconds``
        after the version that superseded it was created."""
        if record is None:
            return True
        if bound_version == record.current_version:
            return False
        newer = next((v for v in record.versions if v.version == bound_version + 1), None)
        if newer is None:  # version was pruned away entirely
            return True
        return now >= newer.created_at + timedelta(seconds=record.overlap_window_seconds)
