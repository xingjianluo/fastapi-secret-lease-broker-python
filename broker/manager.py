"""租约管理器：签发 / 读取校验 / 续期 / 吊销，带并发保护。

判定顺序（每个操作都在同一把 RLock 内完成“校验 + 状态变更”）：
    1. 凭证验证（缺失/伪造/过期由 tokens 层抛出）
    2. 租约归属 + 服务端策略复核（授权失败）
    3. 吊销标记（已吊销）
    4. TTL（已过期）
    5. 轮换重叠窗口（版本不匹配：绑定版本已退休）

因此并发续期不会产生重复租约，并发吊销不会漏掉，
且“吊销后仍在处理的请求”会在锁内看到吊销标记而失败。
"""

from __future__ import annotations

import threading
import uuid

from broker.clock import Clock, system_clock
from broker.errors import BrokerError, ErrorReason
from broker.models import Lease
from broker.policy import Policy
from broker.store import SecretStore
from broker.tokens import issue_token, verify_token


def scope_of(secret_name: str) -> str:
    return f"secret:{secret_name}"


class LeaseManager:
    def __init__(
        self,
        store: SecretStore,
        policy: Policy,
        token_secret: str,
        token_ttl: float = 3600,
        lease_ttl: float = 300,
        clock: Clock = system_clock,
    ) -> None:
        self.store = store
        self.policy = policy
        self.token_secret = token_secret
        self.token_ttl = token_ttl
        self.lease_ttl = lease_ttl
        self.clock = clock
        self._leases: dict[str, Lease] = {}
        self._principals: set[str] = set()
        self._lock = threading.RLock()

    # ---- 调用方登记与身份凭证签发（开通面，不属于数据面） ----

    def register_principal(self, principal: str) -> None:
        with self._lock:
            self._principals.add(principal)

    def issue_credential(self, principal: str) -> str:
        """仅为已登记调用方签发凭证；凭证只证明身份，不携带角色。"""
        with self._lock:
            if principal not in self._principals:
                raise BrokerError(
                    ErrorReason.ACCESS_DENIED,
                    f"调用方 '{principal}' 未登记，不能签发凭证",
                    http_status=403,
                )
            return issue_token(principal, self.token_ttl, self.token_secret, self.clock())

    # ---- 内部校验辅助 ----

    def _authenticate(self, token: str | None) -> str:
        if not token:
            raise BrokerError(
                ErrorReason.MISSING_CREDENTIAL,
                "缺少身份凭证，请在 Authorization: Bearer <token> 中提供",
                http_status=401,
            )
        payload = verify_token(token, self.token_secret, self.clock())
        return str(payload["sub"])

    def _load_owned_lease(self, principal: str, lease_id: str):
        lease = self._leases.get(lease_id)
        if lease is None:
            raise BrokerError(
                ErrorReason.LEASE_NOT_FOUND,
                f"租约 '{lease_id}' 不存在",
                http_status=404,
            )
        if lease.principal != principal:
            # 不泄露租约存在性，统一按授权失败处理
            raise BrokerError(
                ErrorReason.ACCESS_DENIED,
                "租约不属于当前调用方，禁止访问",
                http_status=403,
            )
        # 每次操作都复核服务端策略：授权被收回后即时生效
        if not self.policy.authorize(principal, scope_of(lease.secret_name)):
            raise BrokerError(
                ErrorReason.ACCESS_DENIED,
                f"调用方 '{principal}' 对 scope '{scope_of(lease.secret_name)}' 不再具有访问权限",
                http_status=403,
            )
        return lease

    @staticmethod
    def _check_live(lease: Lease, secret, now: float) -> None:
        """吊销 -> 过期 -> 版本退休，顺序固定，失败原因可区分。"""
        if lease.revoked:
            raise BrokerError(
                ErrorReason.LEASE_REVOKED,
                f"租约 '{lease.lease_id}' 已被吊销",
                http_status=403,
            )
        if lease.is_expired(now):
            raise BrokerError(
                ErrorReason.LEASE_EXPIRED,
                f"租约 '{lease.lease_id}' 已于 {lease.expires_at} 过期",
                http_status=403,
            )
        if secret.version_is_retired(lease.bound_version, now):
            raise BrokerError(
                ErrorReason.VERSION_MISMATCH,
                (
                    f"租约 '{lease.lease_id}' 绑定的是 {lease.secret_name} v{lease.bound_version}，"
                    f"该版本已随轮换重叠窗口结束而退休（当前版本 v{secret.current_version}），"
                    "请重新申请租约"
                ),
                http_status=409,
            )

    # ---- 数据面 ----

    def request_lease(self, token: str | None, secret_name: str) -> Lease:
        principal = self._authenticate(token)
        scope = scope_of(secret_name)
        with self._lock:
            if not self.policy.authorize(principal, scope):
                raise BrokerError(
                    ErrorReason.ACCESS_DENIED,
                    f"调用方 '{principal}' 未被授予 scope '{scope}'，默认拒绝",
                    http_status=403,
                )
            secret = self.store.get(secret_name)  # 不存在同样按授权失败处理
            now = self.clock()
            lease = Lease(
                lease_id=uuid.uuid4().hex,
                principal=principal,
                scope=scope,
                secret_name=secret_name,
                bound_version=secret.current_version,
                issued_at=now,
                expires_at=now + self.lease_ttl,
            )
            self._leases[lease.lease_id] = lease
            return lease

    def read_secret(self, token: str | None, lease_id: str) -> tuple[Lease, str]:
        principal = self._authenticate(token)
        with self._lock:
            lease = self._load_owned_lease(principal, lease_id)
            secret = self.store.get(lease.secret_name)
            now = self.clock()
            self._check_live(lease, secret, now)
            # 永远只返回租约绑定的版本，密钥轮换后也读不到新版本
            version = secret.get_version(lease.bound_version)
            return lease, version.value

    def renew_lease(self, token: str | None, lease_id: str) -> Lease:
        principal = self._authenticate(token)
        with self._lock:
            lease = self._load_owned_lease(principal, lease_id)
            secret = self.store.get(lease.secret_name)
            now = self.clock()
            self._check_live(lease, secret, now)
            # 就地延长同一条租约记录，不生成新 id / 新对象
            lease.expires_at = now + self.lease_ttl
            return lease

    def revoke_lease(self, token: str | None, lease_id: str) -> None:
        principal = self._authenticate(token)
        with self._lock:
            lease = self._load_owned_lease(principal, lease_id)
            lease.revoked = True  # 幂等：重复吊销保持已吊销
