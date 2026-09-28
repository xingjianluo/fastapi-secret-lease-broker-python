"""Module-level sanity: the app wires together and token round-trips."""

from __future__ import annotations

from datetime import datetime, timezone

from app.app import create_app
from app.auth import TokenIssuer
from app.authz import read_scope
from app.clock import ManualClock
from app.models import DenialReason  # re-export sanity
from app.errors import MissingCredentialError


def test_app_and_denial_reasons_present() -> None:
    app = create_app()
    assert app.title == "local-secret-lease-broker"
    assert DenialReason.MISSING_CREDENTIAL.value == "missing_credential"


def test_identity_scopes_come_from_signed_token_only() -> None:
    clk = ManualClock(datetime(2026, 1, 1, tzinfo=timezone.utc))
    issuer = TokenIssuer()
    ident = issuer.authenticate(
        issuer.issue("alice", {read_scope("db/password")}, 60, clk), clk
    )
    assert ident.caller_id == "alice"
    assert read_scope("db/password") in ident.scopes

    try:
        issuer.authenticate(None, clk)
        raise AssertionError("missing token must raise")
    except MissingCredentialError:
        pass
