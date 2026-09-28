"""密钥轮换：重叠窗口内旧租约读旧版本；窗口结束立即失效；新租约读新版本。"""

from __future__ import annotations

from tests.conftest import get_token


def _lease(client, token, secret):
    r = client.post(
        "/leases", json={"secret_name": secret}, headers={"Authorization": f"Bearer {token}"}
    )
    assert r.status_code == 201, r.text
    return r.json()


def _read(client, token, lease_id):
    return client.post(
        f"/leases/{lease_id}/read", headers={"Authorization": f"Bearer {token}"}
    )


def test_old_lease_reads_old_version_during_overlap(client, clock, manager, audit_logs):
    token = get_token(client, "svc-billing")
    old_lease = _lease(client, token, "billing/db")
    assert old_lease["bound_version"] == 1

    clock.advance(20)
    manager.store.rotate("billing/db", "DB_PASS_v2")

    # 重叠窗口内：旧租约继续可用，但只能读到其绑定的旧版本，读不到新版本
    r = _read(client, token, old_lease["lease_id"])
    assert r.status_code == 200, r.text
    assert r.json()["value"] == "DB_PASS_v1"
    assert r.json()["lease"]["bound_version"] == 1

    # 新租约绑定并读取新版本
    new_lease = _lease(client, token, "billing/db")
    assert new_lease["bound_version"] == 2
    assert _read(client, token, new_lease["lease_id"]).json()["value"] == "DB_PASS_v2"
    assert "ALLOW" in audit_logs.text


def test_old_lease_fails_immediately_after_overlap_window(client, clock, manager):
    token = get_token(client, "svc-billing")
    old_lease = _lease(client, token, "billing/db")

    # 轮换发生在 t=20，重叠窗口 30s => t=50 整旧版本退休
    clock.advance(20)
    manager.store.rotate("billing/db", "DB_PASS_v2")

    clock.advance(29)  # t=49 窗口内仍可用
    assert _read(client, token, old_lease["lease_id"]).status_code == 200

    clock.advance(1)  # t=50 窗口结束，立即、明确地失败（非静默放行）
    r = _read(client, token, old_lease["lease_id"])
    assert r.status_code == 409
    err = r.json()["error"]
    assert err["reason"] == "version_mismatch"
    assert "v1" in err["message"] and "v2" in err["message"]


def test_version_mismatch_distinct_from_expiry_and_revocation(client, clock, manager):
    token = get_token(client, "svc-billing")
    old_lease = _lease(client, token, "billing/db")
    clock.advance(20)
    manager.store.rotate("billing/db", "DB_PASS_v2")
    clock.advance(30)  # 越过重叠窗口但未超过租约 TTL(100s)

    r = _read(client, token, old_lease["lease_id"])
    assert r.status_code == 409
    assert r.json()["error"]["reason"] == "version_mismatch"


def test_renew_after_window_end_fails_with_version_mismatch(client, clock, manager):
    token = get_token(client, "svc-billing")
    old_lease = _lease(client, token, "billing/db")
    clock.advance(20)
    manager.store.rotate("billing/db", "DB_PASS_v2")
    clock.advance(30)

    r = client.post(
        f"/leases/{old_lease['lease_id']}/renew",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 409
    assert r.json()["error"]["reason"] == "version_mismatch"


def test_multiple_rotations_retire_versions_by_latest_window(client, clock, manager):
    token = get_token(client, "svc-billing")
    l1 = _lease(client, token, "billing/api-key")  # 窗口仅 10s
    clock.advance(5)
    manager.store.rotate("billing/api-key", "K2")
    l2 = _lease(client, token, "billing/api-key")
    clock.advance(5)
    manager.store.rotate("billing/api-key", "K3")

    # 第二次轮换后：v1 已退休（相对最新版本已超 10s 窗口起点外），v2 仍在窗口
    clock.advance(5)
    # v1: 最新版本创建于 t=10，窗口结束于 t=20；now=15 -> 实际仍按最新版本窗口判定
    r1 = _read(client, token, l1["lease_id"])
    assert r1.json()["value"] == "API_KEY_v1"
    assert _read(client, token, l2["lease_id"]).json()["value"] == "K2"

    clock.advance(5)  # now=20，最新版本 v3 创建于 t=10，窗口结束
    assert _read(client, token, l1["lease_id"]).status_code == 409
    assert _read(client, token, l2["lease_id"]).status_code == 409
    l3 = _lease(client, token, "billing/api-key")
    assert _read(client, token, l3["lease_id"]).json()["value"] == "K3"
