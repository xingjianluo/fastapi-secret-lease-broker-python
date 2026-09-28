"""核心数据类型：密钥版本、密钥、租约。"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class SecretVersion:
    """密钥的一个不可变版本。"""

    version: int
    value: str
    created_at: float


@dataclass
class Secret:
    """一个具名密钥，保留历史版本以支持轮换重叠窗口。"""

    name: str
    overlap_window: float  # 轮换后旧版本租约仍可用的秒数
    versions: dict[int, SecretVersion] = field(default_factory=dict)
    current_version: int = 0

    def get_version(self, version: int) -> SecretVersion | None:
        return self.versions.get(version)

    def latest(self) -> SecretVersion:
        return self.versions[self.current_version]

    def rotate(self, value: str, now: float) -> SecretVersion:
        new_version = self.current_version + 1
        sv = SecretVersion(version=new_version, value=value, created_at=now)
        self.versions[new_version] = sv
        self.current_version = new_version
        return sv

    def version_is_retired(self, version: int, now: float) -> bool:
        """旧版本是否已越过轮换重叠窗口（窗口结束必须立即失效）。"""
        if version == self.current_version:
            return False
        sv = self.versions.get(version)
        if sv is None:
            return True
        return now >= self.latest().created_at + self.overlap_window


@dataclass
class Lease:
    """一段绑定到密钥具体版本的短期访问租约。"""

    lease_id: str
    principal: str
    scope: str
    secret_name: str
    bound_version: int
    issued_at: float
    expires_at: float
    revoked: bool = False

    def is_expired(self, now: float) -> bool:
        return now >= self.expires_at
