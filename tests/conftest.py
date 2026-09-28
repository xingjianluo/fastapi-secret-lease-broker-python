"""Shared pytest fixtures and logging capture.

Every test logs the *request inputs* and the *final decision basis* via the
``decision`` log line emitted by the helper client, so a failure is
explainable from the unit-test log alone.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from app.app import create_app
from app.authz import read_scope
from app.clock import ManualClock

FIXED_NOW = datetime(2026, 9, 29, 12, 0, 0, tzinfo=timezone.utc)


def _install_clock(app, clock: ManualClock) -> None:
    """Replace the running app's system clock with a controllable one."""
    app.state.clock = clock
    # broker captured the clock object reference? It got a separate SystemClock;
    # rebuild broker against our clock through the fixture helper instead.
    from app.fixtures import build_broker, seed_tokens

    broker, issuer, store = build_broker(clock)
    app.state.broker = broker
    app.state.issuer = issuer
    app.state.tokens = seed_tokens(issuer, clock)


@pytest.fixture
def clock() -> ManualClock:
    return ManualClock(FIXED_NOW)


@pytest.fixture
def env(clock):
    """A fully wired app with a controllable clock and seeded tokens."""
    app = create_app()
    _install_clock(app, clock)

    @dataclass
    class Env:
        client: TestClient
        clock: ManualClock
        tokens: dict
        broker: object

    return Env(
        client=TestClient(app),
        clock=clock,
        tokens=app.state.tokens,
        broker=app.state.broker,
    )


test_log = logging.getLogger("lease_broker.test")


@pytest.fixture(autouse=True)
def decision_logger(caplog):
    """Surface request inputs and decision bases per test (see -s / log_cli)."""
    caplog.set_level(logging.INFO, logger="lease_broker")
    yield
    for record in caplog.records:
        if record.name.startswith("lease_broker"):
            test_log.info(record.getMessage())


def issue(client: TestClient, token: str | None, secret_name: str, ttl: int = 60,
          raw_header: str | None = None):
    headers = {"Authorization": raw_header} if raw_header is not None else (
        {"Authorization": f"Bearer {token}"} if token else {}
    )
    resp = client.post("/api/v1/leases", json={"secret_name": secret_name, "ttl_seconds": ttl},
                       headers=headers)
    test_log.info(f"[REQUEST] POST /leases secret={secret_name} ttl={ttl} "
          f"auth={'bearer' if (token or raw_header) else 'none'} -> {resp.status_code}")
    return resp


def access(client: TestClient, token: str | None, lease_id: str, raw_header: str | None = None):
    headers = {"Authorization": raw_header} if raw_header is not None else (
        {"Authorization": f"Bearer {token}"} if token else {}
    )
    resp = client.get(f"/api/v1/leases/{lease_id}/secret", headers=headers)
    test_log.info(f"[REQUEST] GET /leases/{lease_id[:8]}/secret -> {resp.status_code}")
    return resp


def renew(client: TestClient, token: str | None, lease_id: str, ttl: int = 60, raw_header=None):
    headers = {"Authorization": raw_header} if raw_header is not None else (
        {"Authorization": f"Bearer {token}"} if token else {}
    )
    resp = client.post(f"/api/v1/leases/{lease_id}/renew", json={"ttl_seconds": ttl},
                       headers=headers)
    test_log.info(f"[REQUEST] POST /leases/{lease_id[:8]}/renew ttl={ttl} -> {resp.status_code}")
    return resp


def revoke(client: TestClient, token: str | None, lease_id: str, raw_header=None):
    headers = {"Authorization": raw_header} if raw_header is not None else (
        {"Authorization": f"Bearer {token}"} if token else {}
    )
    resp = client.post(f"/api/v1/leases/{lease_id}/revoke", headers=headers)
    test_log.info(f"[REQUEST] POST /leases/{lease_id[:8]}/revoke -> {resp.status_code}")
    return resp


def reason(resp) -> str:
    return resp.json()["error"]["reason"]
