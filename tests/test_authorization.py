"""Authorization: default-deny and least-privilege scope separation.

Authentication is necessary but not sufficient — the authenticated identity
must also hold the exact read scope for the requested secret, and leases may
only be used by their owner.
"""

from __future__ import annotations

from tests.conftest import access, issue, reason, renew, revoke


def _grant(env, caller: str, secret: str = "db/password", ttl: int = 60):
    return issue(env.client, env.tokens[caller], secret, ttl)


def test_authorized_caller_gets_lease_with_expiry_and_basis(env):
    resp = _grant(env, "alice")
    assert resp.status_code == 201
    body = resp.json()
    assert body["version"] == 1
    assert body["status"] == "active"
    assert body["expires_at"]
    assert "scope" in body["basis"]


def test_callers_are_isolated_by_secret_scope(env):
    # bob is only scoped to api/key, not db/password
    resp = _grant(env, "bob", "db/password")
    assert resp.status_code == 403
    assert reason(resp) == "unauthorized_scope"


def test_unknown_secret_is_default_denied(env):
    resp = _grant(env, "alice", "does/not-exist")
    assert resp.status_code == 403
    assert reason(resp) == "unauthorized_scope"


def test_caller_cannot_use_another_callers_lease(env):
    lease = _grant(env, "alice").json()["lease_id"]
    resp = access(env.client, env.tokens["bob"], lease)
    assert resp.status_code == 403
    assert reason(resp) == "unauthorized_scope"
    assert resp.json()["error"]["detail"]["owner"] == "alice"


def test_caller_cannot_renew_another_callers_lease(env):
    lease = _grant(env, "alice").json()["lease_id"]
    resp = renew(env.client, env.tokens["bob"], lease)
    assert reason(resp) == "unauthorized_scope"


def test_non_ops_caller_cannot_revoke(env):
    lease = _grant(env, "alice").json()["lease_id"]
    resp = revoke(env.client, env.tokens["bob"], lease)
    assert reason(resp) == "unauthorized_scope"


def test_wildcard_break_glass_identity_can_read_any_secret(env):
    resp = _grant(env, "glass", "db/password")
    assert resp.status_code == 201
    assert resp.json()["version"] == 1


def test_ops_revoke_scope_does_not_grant_secret_reads(env):
    # ops can revoke but must not be able to mint a read lease itself.
    resp = _grant(env, "ops", "db/password")
    assert resp.status_code == 403
    assert reason(resp) == "unauthorized_scope"
