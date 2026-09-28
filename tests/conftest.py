"""测试夹具：虚拟时钟驱动的 broker + FastAPI TestClient。

所有测试通过 caplog 打开 broker.audit 日志，
单测日志会打印“请求输入”与“最终判定依据”。
"""

from __future__ import annotations

import logging

import pytest
from fastapi.testclient import TestClient

from broker.api import create_app
from broker.manager import LeaseManager
from broker.policy import Policy
from broker.store import SecretStore

PROVISIONING_KEY = "test-provisioning-key"
TOKEN_SECRET = "test-signing-key"


class VirtualClock:
    def __init__(self, start: float = 1_000_000.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@pytest.fixture
def clock() -> VirtualClock:
    return VirtualClock()


@pytest.fixture
def manager(clock: VirtualClock) -> LeaseManager:
    mgr = LeaseManager(
        store=SecretStore(clock),
        policy=Policy(
            {
                "svc-billing": {"secret:billing/db", "secret:billing/api-key"},
                "svc-reporting": {"secret:billing/db"},
                "svc-anon": set(),
            }
        ),
        token_secret=TOKEN_SECRET,
        token_ttl=1000,
        lease_ttl=100,
        clock=clock,
    )
    for p in ("svc-billing", "svc-reporting", "svc-anon"):
        mgr.register_principal(p)
    mgr.store.add_secret("billing/db", "DB_PASS_v1", overlap_window=30)
    mgr.store.add_secret("billing/api-key", "API_KEY_v1", overlap_window=10)
    return mgr


@pytest.fixture
def client(manager: LeaseManager):
    app = create_app(manager, provisioning_key=PROVISIONING_KEY)
    app.state.manager = manager
    return TestClient(app)


@pytest.fixture
def audit_logs(caplog):
    caplog.set_level(logging.INFO, logger="broker.audit")
    return caplog


def get_token(client: TestClient, principal: str) -> str:
    r = client.post(
        "/credentials",
        json={"principal": principal},
        headers={"X-Provisioning-Key": PROVISIONING_KEY},
    )
    assert r.status_code == 200, r.text
    return r.json()["token"]
