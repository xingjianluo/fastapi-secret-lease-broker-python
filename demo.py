"""本地端到端演示：无需启动服务器、无外部服务，直接跑通并打印全部关键场景。

    uv run python demo.py

演示内容：
  1. 无凭证 / 伪造凭证 / 过期凭证被拒绝且原因可区分
  2. 越权请求默认拒绝
  3. 租约签发、读取、过期、吊销
  4. 密钥轮换重叠窗口：旧租约读旧版本，窗口结束立即版本不匹配
  5. 并发续期（单条租约）与并发吊销（不漏吊销）
"""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor

from broker.errors import BrokerError
from broker.manager import LeaseManager
from broker.policy import Policy
from broker.store import SecretStore


class Clock:
    def __init__(self) -> None:
        self.t = 1_000_000.0

    def __call__(self) -> float:
        return self.t

    def sleep(self, s: float) -> None:
        self.t += s
        print(f"  ⏩ 时间推进 {s}s -> now={self.t}")


def show(title: str) -> None:
    print(f"\n=== {title} ===")


def attempt(title: str, fn) -> None:
    try:
        result = fn()
        print(f"  ✅ {title}: 允许 -> {result}")
    except BrokerError as e:
        print(f"  ❌ {title}: 拒绝 reason={e.reason.value} | {e.message}")


def main() -> None:
    clk = Clock()
    mgr = LeaseManager(
        store=SecretStore(clk),
        policy=Policy(
            {
                "svc-billing": {"secret:billing/db", "secret:billing/api-key"},
                "svc-reporting": {"secret:billing/db"},
            }
        ),
        token_secret="demo-key",
        token_ttl=1000,
        lease_ttl=100,
        clock=clk,
    )
    mgr.register_principal("svc-billing")
    mgr.register_principal("svc-reporting")
    mgr.store.add_secret("billing/db", "DB_PASS_v1", overlap_window=30)
    billing = mgr.issue_credential("svc-billing")
    reporting = mgr.issue_credential("svc-reporting")

    show("1. 凭证攻击：缺失 / 伪造 / 过期")
    from broker.tokens import issue_token

    attempt("无凭证申请租约", lambda: mgr.request_lease(None, "billing/db"))
    forged = issue_token("svc-billing", 1000, "attacker-own-key", clk())
    attempt("伪造签名凭证（结构合法但签名密钥错误）",
            lambda: mgr.request_lease(forged, "billing/db"))
    expired = issue_token("svc-billing", 10, "demo-key", clk() - 100)
    attempt("过期凭证", lambda: mgr.request_lease(expired, "billing/db"))

    show("2. 越权：reporting 无权访问 api-key")
    attempt("越权请求 api-key", lambda: mgr.request_lease(reporting, "billing/api-key"))

    show("3. 正常租约 / 过期 / 吊销")
    lease = mgr.request_lease(billing, "billing/db")
    print(f"  📄 租约 {lease.lease_id[:8]} 绑定 v{lease.bound_version} 到期 {lease.expires_at}")
    attempt("读取密钥", lambda: mgr.read_secret(billing, lease.lease_id)[1])
    clk.sleep(100)
    attempt("到期后读取", lambda: mgr.read_secret(billing, lease.lease_id)[1])

    lease2 = mgr.request_lease(billing, "billing/db")
    mgr.revoke_lease(billing, lease2.lease_id)
    attempt("吊销后读取", lambda: mgr.read_secret(billing, lease2.lease_id)[1])

    show("4. 轮换重叠窗口（30s）")
    old = mgr.request_lease(billing, "billing/db")
    clk.sleep(20)
    mgr.store.rotate("billing/db", "DB_PASS_v2")
    print("  🔁 密钥已轮换到 v2（旧版本在 30s 重叠窗口内仍可用）")
    attempt("旧租约窗口内读取（只能读到 v1）",
            lambda: mgr.read_secret(billing, old.lease_id)[1])
    new = mgr.request_lease(billing, "billing/db")
    attempt("新租约读取（读到 v2）", lambda: mgr.read_secret(billing, new.lease_id)[1])
    clk.sleep(10)
    attempt("再推进 10s（旧版本仍在窗口内）",
            lambda: mgr.read_secret(billing, old.lease_id)[1])
    clk.sleep(20)
    attempt("窗口结束瞬间旧租约（version_mismatch）",
            lambda: mgr.read_secret(billing, old.lease_id)[1])

    show("5. 并发续期与并发吊销")
    l = mgr.request_lease(billing, "billing/db")
    barrier = threading.Barrier(8)

    def renew() -> str:
        barrier.wait()
        renewed = mgr.renew_lease(billing, l.lease_id)
        return renewed.lease_id

    with ThreadPoolExecutor(max_workers=8) as pool:
        ids = list(pool.map(lambda _: renew(), range(8)))
    assert len(set(ids)) == 1
    print(f"  ✅ 8 个并发续期只作用于同一条租约 {ids[0][:8]}，无重复租约")

    barrier2 = threading.Barrier(2)

    def race_renew():
        barrier2.wait()
        try:
            mgr.renew_lease(billing, l.lease_id)
            return "renew-ok"
        except BrokerError as e:
            return f"renew-{e.reason.value}"

    def race_revoke():
        barrier2.wait()
        mgr.revoke_lease(billing, l.lease_id)
        return "revoked"

    with ThreadPoolExecutor(max_workers=2) as pool:
        r1 = pool.submit(race_renew)
        r2 = pool.submit(race_revoke)
        print(f"  并发结果: {r1.result()} / {r2.result()}")
    attempt("最终读取（必然 lease_revoked）", lambda: mgr.read_secret(billing, l.lease_id)[1])
    print("\n演示完成。")


if __name__ == "__main__":
    main()
