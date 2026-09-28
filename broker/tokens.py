"""本地 HMAC 身份凭证：签名防伪造、带过期时间。

令牌格式: base64url(payload_json) + "." + base64url(hmac_sha256(payload))

注意：凭证只承载“身份”，不承载角色/权限。
授权一律由服务端策略表裁决，调用方无法在凭证里自行声明角色。
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import uuid
from typing import Any

from broker.errors import BrokerError, ErrorReason


def _b64encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def _sign(payload_b64: str, secret_key: str) -> str:
    mac = hmac.new(secret_key.encode("utf-8"), payload_b64.encode("ascii"), hashlib.sha256)
    return _b64encode(mac.digest())


def issue_token(principal: str, ttl: float, secret_key: str, now: float) -> str:
    payload: dict[str, Any] = {
        "sub": principal,
        "iat": now,
        "exp": now + ttl,
        "jti": uuid.uuid4().hex,
    }
    payload_b64 = _b64encode(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    return f"{payload_b64}.{_sign(payload_b64, secret_key)}"


def verify_token(token: str, secret_key: str, now: float) -> dict[str, Any]:
    """校验结构、签名、有效期；失败抛 BrokerError，原因可区分。"""
    if not isinstance(token, str) or token.count(".") != 1 or not token.strip():
        raise BrokerError(
            ErrorReason.MALFORMED_CREDENTIAL,
            "凭证格式非法：期望 '<payload>.<signature>'",
            http_status=401,
        )
    payload_b64, sig_b64 = token.split(".")
    try:
        payload = json.loads(_b64decode(payload_b64).decode("utf-8"))
        _b64decode(sig_b64)
    except Exception as exc:  # base64 / json 解码失败
        raise BrokerError(
            ErrorReason.MALFORMED_CREDENTIAL,
            f"凭证内容无法解析: {exc}",
            http_status=401,
        ) from exc

    expected = _sign(payload_b64, secret_key)
    if not hmac.compare_digest(sig_b64, expected):
        raise BrokerError(
            ErrorReason.FORGED_CREDENTIAL,
            "凭证签名校验失败，疑似伪造或密钥不匹配",
            http_status=401,
        )

    if not isinstance(payload, dict) or "sub" not in payload or "exp" not in payload:
        raise BrokerError(
            ErrorReason.MALFORMED_CREDENTIAL,
            "凭证缺少必要字段 sub/exp",
            http_status=401,
        )

    if now >= float(payload["exp"]):
        raise BrokerError(
            ErrorReason.EXPIRED_CREDENTIAL,
            f"凭证已于 {payload['exp']} 过期",
            http_status=401,
        )
    return payload
