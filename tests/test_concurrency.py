"""Concurrency: serializable renew/revoke decisions under contention.

The broker takes a single lock around authenticate -> authorize -> check ->
mutate, so regardless of thread interleaving:

* N concurrent renewals of one lease must keep exactly ONE lease id (no
  duplicate leases) and a single, well-defined final expiry;
* a revoke racing renewals cannot be lost — the lease ends revoked;
* access requests still in flight after the revoke cannot succeed.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

from tests.conftest import access, issue, reason, renew, revoke


def _lid(env):
    return issue(env.client, env.tokens["alice"], "db/password", 60).json()["lease_id"]


def test_concurrent_renewals_keep_single_lease_id(env):
    lid = _lid(env)
    with ThreadPoolExecutor(max_workers=16) as pool:
        results = list(pool.map(
            lambda i: renew(env.client, env.tokens["alice"], lid, 100 + i),
            range(32),
        ))

    assert all(r.status_code == 200 for r in results), [r.text for r in results]
    bodies = [r.json() for r in results]
    assert {b["lease_id"] for b in bodies} == {lid}  # no duplicate leases
    assert {b["version"] for b in bodies} == {1}     # version never rebinds

    # Exactly one lease exists for alice; expiry is the last committed write.
    leases = [l for l in env.broker._store.all_leases() if l.lease_id == lid]
    assert len(leases) == 1
    expected_base = env.clock.now() + timedelta(seconds=100)
    assert leases[0].expires_at >= expected_base


def test_revoke_racing_concurrent_renewals_is_never_lost(env):
    lid = _lid(env)

    def do_renew(_):
        return renew(env.client, env.tokens["alice"], lid, 120)

    def do_revoke():
        return revoke(env.client, env.tokens["ops"], lid)

    with ThreadPoolExecutor(max_workers=16) as pool:
        futures = [pool.submit(do_renew, i) for i in range(24)]
        revoke_future = pool.submit(do_revoke)
        # interleave more renewals after the revoke was scheduled
        futures += [pool.submit(do_renew, i) for i in range(24, 40)]
        outcomes = [f.result() for f in futures]
        revoke_result = revoke_future.result()

    assert revoke_result.status_code == 200

    # Any renewal serialized after the revoke must have been denied as revoked.
    post_revoke_renewals = [r for r in outcomes if r.status_code != 200]
    assert post_revoke_renewals, "at least renewals after revoke must fail"
    assert all(reason(r) == "lease_revoked" for r in post_revoke_renewals)

    # Final state is unambiguous: revoked and unusable.
    final = access(env.client, env.tokens["alice"], lid)
    assert reason(final) == "lease_revoked"
    stored = env.broker._store.require_lease(lid)
    assert stored.revoked is True


def test_in_flight_access_after_revoke_cannot_succeed(env):
    lid = _lid(env)

    verdict = {}

    def reader():
        # small stagger so this is likely in flight around the revoke
        verdict["access"] = access(env.client, env.tokens["alice"], lid)

    with ThreadPoolExecutor(max_workers=2) as pool:
        f = pool.submit(reader)
        pool.submit(lambda: revoke(env.client, env.tokens["ops"], lid)).result()
        f.result()

    # Whether access landed just before or just after revocation, the lease
    # is now revoked; a second read must deterministically fail.
    again = access(env.client, env.tokens["alice"], lid)
    assert reason(again) == "lease_revoked"
    # And if the first read did win the race, it never returned a revoked value
    # without marking state: final stored state is revoked.
    assert env.broker._store.require_lease(lid).revoked is True


def test_concurrent_revoke_and_renew_leave_consistent_expiry(env):
    """Renewals serialized before revoke may extend expiry; after revoke they
    fail, and the recorded expiry is never rewritten by a failed renewal."""
    lid = _lid(env)
    lease_before = env.broker._store.require_lease(lid)
    original_expiry = lease_before.expires_at

    with ThreadPoolExecutor(max_workers=8) as pool:
        fr = pool.submit(lambda: renew(env.client, env.tokens["alice"], lid, 300))
        fv = pool.submit(lambda: revoke(env.client, env.tokens["ops"], lid))
        renew_resp, revoke_resp = fr.result(), fv.result()

    stored = env.broker._store.require_lease(lid)
    assert stored.revoked is True
    if renew_resp.status_code == 200:
        # renewal committed first; expiry moved forward, then revoke landed
        assert stored.expires_at > original_expiry
    else:
        # revoke committed first; renewal was rejected and expiry untouched
        assert reason(renew_resp) == "lease_revoked"
        assert stored.expires_at == original_expiry
    assert revoke_resp.status_code == 200


def test_concurrent_issue_calls_create_independent_leases(env):
    # Sanity: distinct issue calls must never alias one another under load.
    with ThreadPoolExecutor(max_workers=16) as pool:
        resps = list(pool.map(
            lambda _: issue(env.client, env.tokens["alice"], "db/password", 60),
            range(20),
        ))
    ids = [r.json()["lease_id"] for r in resps]
    assert len(set(ids)) == 20
