"""FastAPI application wiring with a reproducible local fixture.

Run locally with::

    uvicorn app.app:app --reload

The broker uses the real system clock and seeds fake secrets/callers on
startup. ``GET /api/v1/local/tokens`` lists minted bearer tokens purely to
make local experimentation reproducible — it is fixture data, not a real IdP.
"""

from __future__ import annotations

from fastapi import FastAPI

from app.api import router
from app.clock import SystemClock
from app.fixtures import build_broker, seed_tokens


def create_app() -> FastAPI:
    app = FastAPI(
        title="local-secret-lease-broker",
        version="0.1.0",
        description="Short-lived, revocable, version-bound secret access leases.",
    )
    clock = SystemClock()
    broker, issuer, _store = build_broker(clock)
    app.state.broker = broker
    app.state.clock = clock
    app.state.issuer = issuer
    app.state.tokens = seed_tokens(issuer, clock)
    app.include_router(router)

    @app.get("/health", tags=["meta"])
    def health() -> dict:
        return {"status": "ok"}

    @app.get("/api/v1/local/tokens", tags=["local-fixture"])
    def local_tokens() -> dict:
        """Local-only helper: seeded caller tokens for manual verification."""
        return {"tokens": app.state.tokens}

    return app


app = create_app()
