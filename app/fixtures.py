"""Reproducible local fixture: seed secrets, identities and tokens.

Everything here is fake local data — no external services and no real
credentials. The same seed always yields the same identities/scopes.
"""

from __future__ import annotations

from app.auth import TokenIssuer
from app.authz import Authorizer, read_scope
from app.broker import LeaseBroker
from app.models import Clock, SecretRecord, SecretVersion
from app.store import MemoryStore

# caller_id -> scopes
SEED_CALLERS: dict[str, frozenset[str]] = {
    "alice": frozenset({read_scope("db/password")}),
    "bob": frozenset({read_scope("api/key")}),
    "ops": frozenset({"lease:revoke"}),
    "glass": frozenset({"secret:*:read"}),
}

SEED_SECRETS: tuple[tuple[str, str, int], ...] = (
    # (name, initial value, overlap window seconds)
    ("db/password", "db-password-v1", 30),
    ("api/key", "api-key-v1", 15),
)


def build_broker(clock: Clock, key: bytes = b"bootstrap-local-key") -> tuple[LeaseBroker, TokenIssuer, MemoryStore]:
    store = MemoryStore()
    issuer = TokenIssuer(key)
    broker = LeaseBroker(store, issuer, Authorizer(), clock)
    now = clock.now()
    for name, value, window in SEED_SECRETS:
        store.put_secret(
            SecretRecord(
                name=name,
                versions=(SecretVersion(name, 1, value, now),),
                overlap_window_seconds=window,
                current_version=1,
            )
        )
    return broker, issuer, store


def seed_tokens(issuer: TokenIssuer, clock: Clock, ttl_seconds: int = 3600) -> dict[str, str]:
    """Mint one bearer token per seeded caller for local/manual testing."""
    return {
        caller: issuer.issue(caller, scopes, ttl_seconds, clock)
        for caller, scopes in SEED_CALLERS.items()
    }
