"""可区分的失败原因定义。

所有鉴权 / 授权 / 租约校验失败都通过 BrokerError 抛出，
reason 为机器可读的稳定字符串，便于调用方区分处理。
"""

from __future__ import annotations

from enum import Enum


class ErrorReason(str, Enum):
    MISSING_CREDENTIAL = "missing_credential"
    MALFORMED_CREDENTIAL = "malformed_credential"
    FORGED_CREDENTIAL = "forged_credential"
    EXPIRED_CREDENTIAL = "expired_credential"
    ACCESS_DENIED = "access_denied"
    LEASE_EXPIRED = "lease_expired"
    LEASE_REVOKED = "lease_revoked"
    LEASE_NOT_FOUND = "lease_not_found"
    VERSION_MISMATCH = "version_mismatch"


class BrokerError(Exception):
    """业务失败基类，携带稳定 reason 与可解释 message。"""

    def __init__(self, reason: ErrorReason, message: str, http_status: int = 403) -> None:
        super().__init__(message)
        self.reason = reason
        self.message = message
        self.http_status = http_status
