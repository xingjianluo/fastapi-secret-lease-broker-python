"""密钥存储：维护带版本与轮换重叠窗口的本地密钥。

轮换规则：
- rotate 后 current_version 指向新版本；
- 旧版本租约在 overlap_window 内仍可读取其绑定的旧版本值；
- 窗口结束瞬间旧版本立即退休（retired），读取被明确拒绝而非静默放行。
"""

from __future__ import annotations

from broker.clock import Clock, system_clock
from broker.errors import BrokerError, ErrorReason
from broker.models import Secret, SecretVersion


class SecretStore:
    def __init__(self, clock: Clock = system_clock) -> None:
        self.clock = clock
        self._secrets: dict[str, Secret] = {}

    def add_secret(self, name: str, value: str, overlap_window: float) -> Secret:
        if name in self._secrets:
            raise ValueError(f"密钥已存在: {name}")
        secret = Secret(name=name, overlap_window=overlap_window)
        sv = SecretVersion(version=1, value=value, created_at=self.clock())
        secret.versions[1] = sv
        secret.current_version = 1
        self._secrets[name] = secret
        return secret

    def get(self, name: str) -> Secret:
        secret = self._secrets.get(name)
        if secret is None:
            raise BrokerError(
                ErrorReason.ACCESS_DENIED,
                f"请求的密钥 '{name}' 不存在或不在授权范围内",
                http_status=404,
            )
        return secret

    def rotate(self, name: str, new_value: str) -> Secret:
        secret = self.get(name)
        secret.rotate(new_value, self.clock())
        return secret
