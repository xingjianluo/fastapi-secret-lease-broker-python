"""凭证与授权：无凭证、格式非法、伪造、过期凭证、越权与默认拒绝。"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _forge_token(payload: dict, signing_key: str) -> str:
    body = _b64(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode())
    sig = _b64(hmac.new(signing_key.encode(), body.encode(), hashlib.sha256).digest())
    return f"{body}.{sig}"


def test_missing_credential_denied(client, audit_logs):
    # 输入：无 Authorization 头申请租约
    r = client.post("/leases", json={"secret_name": "billing/db"})
    body = r.json()["error"]
    assert r.status_code == 401
    assert body["reason"] == "missing_credential"
    assert "decision=DENY:missing_credential" in audit_logs.text


def test_malformed_credential_denied(client, audit_logs):
    # 输入：结构损坏的令牌
    r = client.post(
        "/leases",
        json={"secret_name": "billing/db"},
        headers={"Authorization": "Bearer not-a-jwt"},
    )
    body = r.json()["error"]
    assert r.status_code == 401
    assert body["reason"] == "malformed_credential"
    assert "DENY:malformed_credential" in audit_logs.text


def test_forged_credential_denied(client, clock, audit_logs):
    # 输入：用攻击者自己的密钥签名的令牌，sub 自称为高权限调用方
    forged = _forge_token(
        {"sub": "svc-billing", "iat": clock(), "exp": clock() + 999, "jti": "x"},
        signing_key="attacker-secret",
    )
    r = client.post(
        "/leases",
        json={"secret_name": "billing/api-key"},
        headers={"Authorization": f"Bearer {forged}"},
    )
    body = r.json()["error"]
    assert r.status_code == 401
    assert body["reason"] == "forged_credential"
    # 自行声明身份/角色不能绕过：请求在签名校验阶段即被拒
    assert "DENY:forged_credential" in audit_logs.text


def test_tampered_payload_denied(client, clock):
    good = _forge_token(
        {"sub": "svc-anon", "iat": clock(), "exp": clock() + 999, "jti": "y"},
        signing_key="test-signing-key",
    )
    body_b64 = _b64(json.dumps(
        {"sub": "svc-billing", "iat": clock(), "exp": clock() + 999, "jti": "y"},
        separators=(",", ":"), sort_keys=True,
    ).encode())
    tampered = f"{body_b64}.{good.split('.')[1]}"
    r = client.post(
        "/leases",
        json={"secret_name": "billing/api-key"},
        headers={"Authorization": f"Bearer {tampered}"},
    )
    assert r.status_code == 401
    assert r.json()["error"]["reason"] == "forged_credential"


def test_expired_credential_denied(client, clock):
    # 输入：合法签名但已过期的凭证
    expired = _forge_token(
        {"sub": "svc-billing", "iat": clock() - 2000, "exp": clock() - 1000, "jti": "z"},
        signing_key="test-signing-key",
    )
    r = client.post(
        "/leases",
        json={"secret_name": "billing/db"},
        headers={"Authorization": f"Bearer {expired}"},
    )
    assert r.status_code == 401
    assert r.json()["error"]["reason"] == "expired_credential"


def test_out_of_scope_secret_default_deny(client, audit_logs):
    # svc-reporting 只有 db 权限，请求 api-key 必须被默认拒绝
    from tests.conftest import get_token

    token = get_token(client, "svc-reporting")
    r = client.post(
        "/leases",
        json={"secret_name": "billing/api-key"},
        headers={"Authorization": f"Bearer {token}"},
    )
    body = r.json()["error"]
    assert r.status_code == 403
    assert body["reason"] == "access_denied"
    assert "DENY:access_denied" in audit_logs.text


def test_unknown_secret_denied_without_disclosure(client):
    # 未授权的密钥名与“不存在”不可区分：统一 access_denied，不泄露存在性
    from tests.conftest import get_token

    token = get_token(client, "svc-billing")
    r = client.post(
        "/leases",
        json={"secret_name": "does/not-exist"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 403
    assert r.json()["error"]["reason"] == "access_denied"


def test_registered_but_no_grants_default_deny(client):
    # svc-anon 已登记（能拿到合法身份凭证），但策略表无任何授权
    from tests.conftest import get_token

    token = get_token(client, "svc-anon")
    r = client.post(
        "/leases",
        json={"secret_name": "billing/db"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 403
    assert r.json()["error"]["reason"] == "access_denied"


def test_provisioning_key_required(client):
    r = client.post("/credentials", json={"principal": "svc-billing"})
    assert r.status_code == 403
    assert r.json()["error"]["reason"] == "access_denied"


def test_unregistered_principal_cannot_get_credential(client):
    r = client.post(
        "/credentials",
        json={"principal": "svc-evil"},
        headers={"X-Provisioning-Key": "test-provisioning-key"},
    )
    assert r.status_code == 403
    assert r.json()["error"]["reason"] == "access_denied"
