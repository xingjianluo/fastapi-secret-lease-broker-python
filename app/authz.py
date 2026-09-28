"""Authorization: a small default-deny scope policy.

The decision only ever consults scopes carried inside the *verified* token
identity — never a role claimed in the request body, so self-declaring a role
cannot widen access.

Scope grammar:

* ``secret:<name>:read``  — may obtain/use a read lease for that secret
* ``secret:*:read``       — may read any secret (break-glass identity only)
* ``lease:revoke``        — may revoke any lease (operations identity)

Leases can also always be managed (renewed/revoked) by their owning caller.
Anything not explicitly granted is denied.
"""

from __future__ import annotations

from app.models import Identity, Lease

WILDCARD_SCOPE = "secret:*:read"
REVOKE_SCOPE = "lease:revoke"


def read_scope(secret_name: str) -> str:
    return f"secret:{secret_name}:read"


class Authorizer:
    def can_read_secret(self, identity: Identity, secret_name: str) -> bool:
        scopes = identity.scopes
        return read_scope(secret_name) in scopes or WILDCARD_SCOPE in scopes

    def can_revoke_any(self, identity: Identity) -> bool:
        return REVOKE_SCOPE in scopes_safe(identity)

    def can_manage_lease(self, identity: Identity, lease: Lease) -> bool:
        """Owner or holder of the explicit revoke scope."""
        return identity.caller_id == lease.caller_id or self.can_revoke_any(identity)


def scopes_safe(identity: Identity) -> frozenset[str]:
    return identity.scopes
