"""租约生命周期：到期、吊销、租约归属、授权被即时收回。"""

from __future__ import annotations

from tests.conftest import get_token


def _lease(client, token, secret="billing/db"):
    r = client.post(
        "/leases", json={"secret_name": secret}, headers={"Authorization": f"Bearer {token}"}
    )
    assert r.status_code == 201, r.text
    return r.json()


def _read(client, token, lease_id):
    return client.post(
        f"/leases/{lease_id}/read", headers={"Authorization": f"Bearer {token}"}
    )


def test_lease_grants_then_expires(client, clock, audit_logs):
    token = get_token(client, "svc-billing")
    lease = _lease(client, token)

    # 输入：窗口内读取 -> 放行，响应携带明确到期时间与绑定版本
    r = _read(client, token, lease["lease_id"])
    assert r.status_code == 200
    body = r.json()
    assert body["value"] == "DB_PASS_v1"
    assert body["lease"]["expires_at"] == lease["issued_at"] + 100
    assert "ALLOW" in audit_logs.text and "decision" in audit_logs.text

    # 输入：时间推进到到期瞬间 -> 明确拒绝，原因为 lease_expired
    clock.advance(100)
    r = _read(client, token, lease["lease_id"])
    assert r.status_code == 403
    assert r.json()["error"]["reason"] == "lease_expired"
    assert "DENY:lease_expired" in audit_logs.text


def test_revoked_lease_denied_and_revocation_idempotent(client, audit_logs):
    token = get_token(client, "svc-billing")
    lease = _lease(client, token)

    r = client.post(
        f"/leases/{lease['lease_id']}/revoke", headers={"Authorization": f"Bearer {token}"}
    )
    assert r.status_code == 204

    # 吊销后读取被拒，原因与“过期”可区分
    r = _read(client, token, lease["lease_id"])
    assert r.status_code == 403
    assert r.json()["error"]["reason"] == "lease_revoked"
    assert "DENY:lease_revoked" in audit_logs.text

    # 重复吊销保持幂等成功
    r = client.post(
        f"/leases/{lease['lease_id']}/revoke", headers={"Authorization": f"Bearer {token}"}
    )
    assert r.status_code == 204


def test_renew_extends_same_lease(client, clock):
    token = get_token(client, "svc-billing")
    lease = _lease(client, token)

    clock.advance(90)
    r = client.post(
        f"/leases/{lease['lease_id']}/renew", headers={"Authorization": f"Bearer {token}"}
    )
    assert r.status_code == 200
    renewed = r.json()
    # 仍是同一条租约，没有产生新 id
    assert renewed["lease_id"] == lease["lease_id"]
    assert renewed["expires_at"] == clock() + 100

    # 续期后旧到期时间不再生效
    clock.advance(95)
    assert _read(client, token, lease["lease_id"]).status_code == 200


def test_cannot_renew_expired_or_revoked(client, clock):
    token = get_token(client, "svc-billing")
    lease = _lease(client, token)
    clock.advance(101)
    r = client.post(
        f"/leases/{lease['lease_id']}/renew", headers={"Authorization": f"Bearer {token}"}
    )
    assert r.status_code == 403
    assert r.json()["error"]["reason"] == "lease_expired"

    lease2 = _lease(client, token)
    client.post(f"/leases/{lease2['lease_id']}/revoke",
                headers={"Authorization": f"Bearer {token}"})
    r = client.post(
        f"/leases/{lease2['lease_id']}/renew", headers={"Authorization": f"Bearer {token}"}
    )
    assert r.status_code == 403
    assert r.json()["error"]["reason"] == "lease_revoked"


def test_other_principal_cannot_access_lease(client):
    # 租约归属：svc-reporting 对 db 同样有权限，也不能读他人租约
    t1 = get_token(client, "svc-billing")
    t2 = get_token(client, "svc-reporting")
    lease = _lease(client, t1)

    for path in ("read", "renew", "revoke"):
        r = client.post(
            f"/leases/{lease['lease_id']}/{path}", headers={"Authorization": f"Bearer {t2}"}
        ) if path != "read" else _read(client, t2, lease["lease_id"])
        assert r.status_code == 403, (path, r.text)
        assert r.json()["error"]["reason"] == "access_denied", path


def test_unknown_lease_returns_not_found(client):
    token = get_token(client, "svc-billing")
    r = _read(client, token, "deadbeef")
    assert r.status_code == 404
    assert r.json()["error"]["reason"] == "lease_not_found"


def test_policy_revocation_takes_effect_immediately(client, manager):
    # 服务端策略收回（区别于租约吊销）：已签发租约在下一次操作时即失效
    token = get_token(client, "svc-reporting")
    lease = _lease(client, token)
    assert _read(client, token, lease["lease_id"]).status_code == 200

    manager.policy._grants["svc-reporting"].discard("secret:billing/db")
    r = _read(client, token, lease["lease_id"])
    assert r.status_code == 403
    assert r.json()["error"]["reason"] == "access_denied"
