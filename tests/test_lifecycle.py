"""Lease lifecycle: expiry, revocation, rotation overlap, version binding."""

from __future__ import annotations

from tests.conftest import access, issue, reason, renew, revoke


def _lease(env, caller="alice", secret="db/password", ttl=60):
    return issue(env.client, env.tokens[caller], secret, ttl).json()["lease_id"]


def test_access_returns_secret_value_while_active(env):
    lid = _lease(env)
    resp = access(env.client, env.tokens["alice"], lid)
    assert resp.status_code == 200
    body = resp.json()
    assert body["value"] == "db-password-v1"
    assert body["version"] == 1


def test_expired_lease_is_denied_with_expired_reason(env):
    lid = _lease(env, ttl=60)
    env.clock.advance(61)
    resp = access(env.client, env.tokens["alice"], lid)
    assert resp.status_code == 410
    assert reason(resp) == "lease_expired"
    assert resp.json()["error"]["detail"]["expires_at"]


def test_expired_lease_cannot_be_renewed(env):
    lid = _lease(env, ttl=60)
    env.clock.advance(61)
    resp = renew(env.client, env.tokens["alice"], lid, 60)
    assert reason(resp) == "lease_expired"


def test_revoked_lease_is_denied_with_revoked_reason(env):
    lid = _lease(env)
    r = revoke(env.client, env.tokens["ops"], lid)
    assert r.status_code == 200 and r.json()["revoked"] is True
    resp = access(env.client, env.tokens["alice"], lid)
    assert resp.status_code == 410
    assert reason(resp) == "lease_revoked"
    assert reason(resp) != "lease_expired"  # reasons stay distinguishable


def test_owner_can_revoke_own_lease_and_it_takes_effect_immediately(env):
    lid = _lease(env)
    assert revoke(env.client, env.tokens["alice"], lid).status_code == 200
    assert reason(access(env.client, env.tokens["alice"], lid)) == "lease_revoked"


def test_revoke_is_idempotent_but_reports_already_revoked(env):
    lid = _lease(env)
    first = revoke(env.client, env.tokens["ops"], lid).json()
    second = revoke(env.client, env.tokens["ops"], lid).json()
    assert first["already_revoked"] is False
    assert second["already_revoked"] is True


def test_revocation_beats_expiry_when_both_apply(env):
    # Documented, predictable precedence: revoked > expired.
    lid = _lease(env, ttl=60)
    revoke(env.client, env.tokens["ops"], lid)
    env.clock.advance(120)
    assert reason(access(env.client, env.tokens["alice"], lid)) == "lease_revoked"


# ----- rotation & overlap window -------------------------------------------

def test_old_lease_reads_old_version_during_overlap_window(env):
    lid = _lease(env)
    env.broker.rotate_secret("db/password", "db-password-v2", overlap_window_seconds=30)
    resp = access(env.client, env.tokens["alice"], lid)
    assert resp.status_code == 200
    body = resp.json()
    assert body["version"] == 1
    assert body["value"] == "db-password-v1"  # never the new value
    assert "old version" in body["basis"]


def test_new_lease_after_rotation_binds_current_version(env):
    _old = _lease(env)
    env.broker.rotate_secret("db/password", "db-password-v2", overlap_window_seconds=30)
    lid2 = _lease(env)
    body = access(env.client, env.tokens["alice"], lid2).json()
    assert body["version"] == 2 and body["value"] == "db-password-v2"


def test_old_lease_fails_immediately_after_overlap_window_closes(env):
    lid = _lease(env)
    env.broker.rotate_secret("db/password", "db-password-v2", overlap_window_seconds=30)
    # still open at the exact boundary - 1
    env.clock.advance(29)
    assert access(env.client, env.tokens["alice"], lid).status_code == 200
    env.clock.advance(1)  # t == window end -> closed
    resp = access(env.client, env.tokens["alice"], lid)
    assert resp.status_code == 409
    assert reason(resp) == "lease_version_mismatch"
    assert resp.json()["error"]["detail"]["current_version"] == 2
    assert resp.json()["error"]["detail"]["bound_version"] == 1


def test_window_closed_lease_is_never_silently_promoted(env):
    lid = _lease(env)
    env.broker.rotate_secret("db/password", "db-password-v2", overlap_window_seconds=30)
    env.clock.advance(31)
    resp = access(env.client, env.tokens["alice"], lid)
    assert reason(resp) == "lease_version_mismatch"
    assert "v2" not in resp.text  # new value must never leak through the old lease


def test_unknown_lease_id_returns_not_found(env):
    resp = access(env.client, env.tokens["alice"], "deadbeef" * 4)
    assert resp.status_code == 404
    assert reason(resp) == "lease_not_found"
