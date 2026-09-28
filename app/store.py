"""In-memory, thread-safe storage for secrets and leases.

A single reentrant lock guards every state transition. The broker performs
authenticate -> authorize -> check -> mutate while holding ``lock()`` so
that concurrent renew/revoke/access are serialized and can never observe a
half-applied decision (no duplicate leases, no revoke lost, no request
succeeding after the revoke it raced with).
"""

from __future__ import annotations

from contextlib import contextmanager
from threading import RLock
from collections.abc import Iterator

from app.errors import LeaseNotFoundError
from app.models import Clock, Lease, SecretRecord, SecretVersion


class MemoryStore:
    def __init__(self) -> None:
        self._lock = RLock()
        self._secrets: dict[str, SecretRecord] = {}
        self._leases: dict[str, Lease] = {}

    @contextmanager
    def lock(self) -> Iterator[None]:
        with self._lock:
            yield

    # ----- secrets -------------------------------------------------------

    def put_secret(self, record: SecretRecord) -> None:
        with self._lock:
            self._secrets[record.name] = record

    def get_secret(self, name: str) -> SecretRecord | None:
        with self._lock:
            return self._secrets.get(name)

    def rotate_secret(
        self, name: str, value: str, clock: Clock, overlap_window_seconds: int | None = None
    ) -> SecretRecord:
        """Append a new immutable version and mark it current.

        Old versions are retained so leases bound to them keep reading the
        old value during the overlap window. They never expose the new value.
        """
        with self._lock:
            current = self._secrets.get(name)
            if current is None:
                raise KeyError(name)
            next_version = current.current_version + 1
            record = SecretRecord(
                name=name,
                versions=current.versions
                + (
                    SecretVersion(
                        secret_name=name,
                        version=next_version,
                        value=value,
                        created_at=clock.now(),
                    ),
                ),
                overlap_window_seconds=(
                    current.overlap_window_seconds
                    if overlap_window_seconds is None
                    else overlap_window_seconds
                ),
                current_version=next_version,
            )
            self._secrets[name] = record
            return record

    def secret_version(self, name: str, version: int) -> SecretVersion | None:
        with self._lock:
            record = self._secrets.get(name)
            if record is None:
                return None
            return next((v for v in record.versions if v.version == version), None)

    # ----- leases --------------------------------------------------------

    def put_lease(self, lease: Lease) -> None:
        with self._lock:
            self._leases[lease.lease_id] = lease

    def get_lease(self, lease_id: str) -> Lease | None:
        with self._lock:
            return self._leases.get(lease_id)

    def require_lease(self, lease_id: str) -> Lease:
        lease = self.get_lease(lease_id)
        if lease is None:
            raise LeaseNotFoundError(f"unknown lease {lease_id}")
        return lease

    def all_leases(self) -> list[Lease]:
        with self._lock:
            return list(self._leases.values())
