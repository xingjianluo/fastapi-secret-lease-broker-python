"""服务端授权策略：principal -> 允许访问的 scope 集合，默认拒绝。

角色/权限绝不取自凭证内容，只来自此服务端策略表，
因此调用方无法通过自行声明角色绕过授权。
"""

from __future__ import annotations


class Policy:
    def __init__(self, grants: dict[str, set[str]] | None = None) -> None:
        # 拷贝一份，避免外部变更
        self._grants: dict[str, set[str]] = {p: set(s) for p, s in (grants or {}).items()}

    def grant(self, principal: str, *scopes: str) -> None:
        self._grants.setdefault(principal, set()).update(scopes)

    def scopes_of(self, principal: str) -> frozenset[str]:
        return frozenset(self._grants.get(principal, set()))

    def authorize(self, principal: str, scope: str) -> bool:
        """仅当策略表显式授予该 principal 对该 scope 的访问时允许，否则默认拒绝。"""
        return scope in self._grants.get(principal, set())
