"""本地启动入口：装配种子调用方、策略与密钥，全部进程内、无外部依赖。

运行: uv run uvicorn main:app --reload
种子数据见 build_demo_manager()，也可供测试与脚本复用。
"""

from __future__ import annotations

import os

import uvicorn
from fastapi import FastAPI

from broker.api import create_app
from broker.clock import system_clock
from broker.manager import LeaseManager
from broker.policy import Policy
from broker.store import SecretStore

PROVISIONING_KEY = os.environ.get("BROKER_PROVISIONING_KEY", "local-provisioning-key")
TOKEN_SECRET = os.environ.get("BROKER_TOKEN_SECRET", "local-demo-signing-key")


def build_demo_manager() -> LeaseManager:
    manager = LeaseManager(
        store=SecretStore(clk := system_clock),
        policy=Policy(
            {
                "svc-billing": {"secret:billing/db", "secret:billing/api-key"},
                "svc-reporting": {"secret:billing/db"},  # 只读库密码，不含 api-key
                "svc-anon": set(),  # 已登记但无任何授权，用于演示默认拒绝
            }
        ),
        token_secret=TOKEN_SECRET,
        token_ttl=3600,
        lease_ttl=120,
        clock=clk,
    )
    for principal in ("svc-billing", "svc-reporting", "svc-anon"):
        manager.register_principal(principal)

    # 密钥名, 初始值, 轮换重叠窗口（秒）
    manager.store.add_secret("billing/db", "DB_PASS_v1", overlap_window=30)
    manager.store.add_secret("billing/api-key", "API_KEY_v1", overlap_window=10)
    return manager


manager = build_demo_manager()
app: FastAPI = create_app(manager, provisioning_key=PROVISIONING_KEY)


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)
