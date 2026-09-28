"""并发一致性：续期串行化、吊销不漏、吊销后仍在处理的请求不得成功。"""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

from broker.errors import BrokerError, ErrorReason


def test_concurrent_renewals_keep_single_lease(client, clock, audit_logs):
    from tests.conftest import get_token

    token = get_token(client, "svc-billing")
    r = client.post(
        "/leases", json={"secret_name": "billing/db"},
        headers={"Authorization": f"Bearer {token}"},
    )
    lease_id = r.json()["lease_id"]
    clock.advance(50)

    barrier = threading.Barrier(8)

    def renew():
        barrier.wait()
        return client.post(
            f"/leases/{lease_id}/renew", headers={"Authorization": f"Bearer {token}"}
        )

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = [f.result() for f in as_completed([pool.submit(renew) for _ in range(8)])]

    # 全部成功，且全部就地更新同一条租约：无重复租约、无 409
    assert {resp.status_code for resp in results} == {200}
    assert {resp.json()["lease_id"] for resp in results} == {lease_id}
    assert len(manager_state(client)) == 1
    assert "DENY" not in audit_logs.text


def test_concurrent_revocation_survives_renewal_race(client):
    from tests.conftest import get_token

    token = get_token(client, "svc-billing")
    r = client.post(
        "/leases", json={"secret_name": "billing/db"},
        headers={"Authorization": f"Bearer {token}"},
    )
    lease_id = r.json()["lease_id"]

    barrier = threading.Barrier(2)
    outcomes: list[str] = []

    def renew():
        barrier.wait()
        resp = client.post(
            f"/leases/{lease_id}/renew", headers={"Authorization": f"Bearer {token}"}
        )
        outcomes.append(f"renew:{resp.status_code}")

    def revoke():
        barrier.wait()
        resp = client.post(
            f"/leases/{lease_id}/revoke", headers={"Authorization": f"Bearer {token}"}
        )
        outcomes.append(f"revoke:{resp.status_code}")

    with ThreadPoolExecutor(max_workers=2) as pool:
        f1 = pool.submit(renew)
        f2 = pool.submit(revoke)
        f1.result(); f2.result()

    # 无论谁先，最终状态必须一致：租约已吊销，且吊销不“漏掉”
    final = client.post(
        f"/leases/{lease_id}/read", headers={"Authorization": f"Bearer {token}"}
    )
    assert final.status_code == 403
    assert final.json()["error"]["reason"] == ErrorReason.LEASE_REVOKED.value
    assert "revoke:204" in outcomes


def test_inflight_read_after_revoke_cannot_succeed(client, manager):
    """直接在管理器层模拟“请求校验进行中时租约被吊销”：

    多个线程同时对同一租约发起 read/revoke；
    任何 read 成功都必须发生在吊销标记落盘之前，
    吊销完成之后不允许再出现成功读取。
    """
    from tests.conftest import get_token

    token = get_token(client, "svc-billing")
    lease = manager.request_lease(token, "billing/db")

    order: list[str] = []
    lock = threading.Lock()
    barrier = threading.Barrier(6)

    def do_read():
        barrier.wait()
        try:
            manager.read_secret(token, lease.lease_id)
            with lock:
                order.append("read-ok")
        except BrokerError as exc:
            assert exc.reason in (ErrorReason.LEASE_REVOKED, ErrorReason.LEASE_EXPIRED)
            with lock:
                order.append(f"read-deny:{exc.reason.value}")

    def do_revoke():
        barrier.wait()
        manager.revoke_lease(token, lease.lease_id)
        with lock:
            order.append("revoked")

    threads = [threading.Thread(target=do_read) for _ in range(5)]
    threads.append(threading.Thread(target=do_revoke))
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    revoke_idx = order.index("revoked")
    # 吊销之后的所有读取结果都必须是拒绝
    later = order[revoke_idx + 1:]
    assert all(item.startswith("read-deny") for item in later), later
    # 且最终一次读取必然被拒
    try:
        manager.read_secret(token, lease.lease_id)
        raise AssertionError("吊销后读取不应成功")
    except BrokerError as exc:
        assert exc.reason == ErrorReason.LEASE_REVOKED


def test_concurrent_leases_are_independent(client):
    from tests.conftest import get_token

    token = get_token(client, "svc-billing")
    barrier = threading.Barrier(4)

    def request_one():
        barrier.wait()
        return client.post(
            "/leases", json={"secret_name": "billing/db"},
            headers={"Authorization": f"Bearer {token}"},
        )

    with ThreadPoolExecutor(max_workers=4) as pool:
        resps = [f.result() for f in as_completed([pool.submit(request_one) for _ in range(4)])]
    ids = {r.json()["lease_id"] for r in resps}
    assert len(ids) == 4  # 不同申请产生各自独立租约
    assert len(manager_state(client)) == 4


# ---- helpers ----


def manager_state(client):
    return client.app.state.manager._leases
