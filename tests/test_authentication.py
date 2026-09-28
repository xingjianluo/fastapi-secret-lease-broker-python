"""Credential verification: missing / forged / tampered / expired tokens.

A caller must never gain access by self-declaring identity; only a valid
HMAC-signed token whose scopes live inside the signed payload is accepted.
"""

from __future__ import annotations

from tests.conftest import issue, reason


def test_missing_credential_is_denied_with_distinct_reason(env):
    resp = issue(env.client, None, "db/password")
    assert resp.status_code == 401
    assert reason(resp) == "missing_credential"
    assert "allowed" in resp.json() and resp.json()["allowed"] is False


def test_garbage_token_is_forged_not_missing(env):
    # A present-but-nonsensical credential is a forgery attempt.
    resp = issue(env.client, "x", "db/password", raw_header="Bearer definitely-not-a-jwt")
    assert resp.status_code == 401
    assert reason(resp) == "forged_credential"


def test_signature_tampering_is_forged(env):
    token = env.tokens["alice"]
    head, sig = token.split(".")
    # flip a couple of chars in the signature
    forged_sig = ("aa" if sig[:2] != "aa" else "bb") + sig[2:]
    resp = issue(env.client, "x", "db/password", raw_header=f"Bearer {head}.{forged_sig}")
    assert reason(resp) == "forged_credential"


def test_payload_tampering_to_add_scope_is_forged(env):
    """The core anti-escalation case: editing scopes into the payload breaks
    the HMAC, so a caller cannot self-declare a broader role."""
    import base64
    import json

    token = env.tokens["bob"]  # bob has no db/password scope
    head, sig = token.split(".")
    pad = "=" * (-len(head) % 4)
    payload = json.loads(base64.urlsafe_b64decode(head + pad))
    payload["scp"] = ["secret:db/password:read"]  # attempt privilege escalation
    new_head = base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode()
                                        ).decode().rstrip("=")
    # Keep the ORIGINAL signature -> mismatch guaranteed.
    resp = issue(env.client, "x", "db/password", raw_header=f"Bearer {new_head}.{sig}")
    assert resp.status_code == 401
    assert reason(resp) == "forged_credential"


def test_token_signed_with_other_key_is_forged(env):
    from app.auth import TokenIssuer

    attacker = TokenIssuer(b"attacker-secret-key")
    fake = attacker.issue("alice", {"secret:db/password:read"}, 3600, env.clock)
    resp = issue(env.client, "x", "db/password", raw_header=f"Bearer {fake}")
    assert reason(resp) == "forged_credential"


def test_expired_credential_is_distinct_from_forgery(env):
    from app.auth import TokenIssuer
    from app.authz import read_scope

    stale = TokenIssuer().issue("alice", {read_scope("db/password")}, 10, env.clock)
    env.clock.advance(11)
    resp = issue(env.client, "x", "db/password", raw_header=f"Bearer {stale}")
    assert resp.status_code == 401
    assert reason(resp) == "expired_credential"
    assert resp.json()["error"]["detail"]["expired_at"]


def test_malformed_authorization_scheme_is_forged(env):
    token = env.tokens["alice"]
    resp = issue(env.client, "x", "db/password", raw_header=f"Token {token}")
    assert reason(resp) == "forged_credential"
