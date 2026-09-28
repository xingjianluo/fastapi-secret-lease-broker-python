"""HTTP layer: schemas, bearer-token dependency, error mapping, routes."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from app.broker import LeaseBroker
from app.errors import BrokerError
from app.models import DenialReason

logger = logging.getLogger("lease_broker.http")

router = APIRouter(prefix="/api/v1", tags=["leases"])

# Distinguishable HTTP status per denial reason.
_STATUS_BY_REASON: dict[DenialReason, int] = {
    DenialReason.MISSING_CREDENTIAL: 401,
    DenialReason.FORGED_CREDENTIAL: 401,
    DenialReason.EXPIRED_CREDENTIAL: 401,
    DenialReason.UNAUTHORIZED_SCOPE: 403,
    DenialReason.LEASE_NOT_FOUND: 404,
    DenialReason.LEASE_EXPIRED: 410,
    DenialReason.LEASE_REVOKED: 410,
    DenialReason.LEASE_VERSION_MISMATCH: 409,
    DenialReason.CONFLICT: 409,
}


# ----- schemas -------------------------------------------------------------

class IssueRequest(BaseModel):
    secret_name: str = Field(min_length=1)
    ttl_seconds: int = Field(gt=0, le=3600)


class RenewRequest(BaseModel):
    ttl_seconds: int = Field(gt=0, le=3600)


class LeaseOut(BaseModel):
    lease_id: str
    secret_name: str
    version: int
    expires_at: str
    status: str
    basis: str


class AccessOut(LeaseOut):
    value: str | None = None


# ----- helpers -------------------------------------------------------------

def get_broker(request: Request) -> LeaseBroker:
    return request.app.state.broker


def _bearer(request: Request) -> str | None:
    auth = request.headers.get("authorization")
    if not auth:
        return None
    scheme, _, token = auth.partition(" ")
    if scheme.lower() != "bearer" or not token:
        # Present but malformed header -> keep token as-is so the broker can
        # reject it as a forged credential rather than "missing".
        return auth
    return token


def _lease_payload(result: Any) -> dict:
    return {
        "lease_id": result.lease_id,
        "secret_name": result.secret_name,
        "version": result.version,
        "expires_at": result.expires_at.isoformat(),
        "status": result.status.value,
        "basis": result.basis,
    }


def _denial_response(err: BrokerError) -> JSONResponse:
    status = _STATUS_BY_REASON.get(err.reason, 409)
    body = {
        "allowed": False,
        "error": {"reason": err.reason.value, "message": err.message, "detail": err.detail},
    }
    return JSONResponse(status_code=status, content=body)


# ----- routes --------------------------------------------------------------

@router.post("/leases", response_model=LeaseOut, status_code=201)
def issue_lease(payload: IssueRequest, request: Request, broker: LeaseBroker = Depends(get_broker)):
    token = _bearer(request)
    logger.info(
        "REQUEST issue: secret_name=%s ttl_seconds=%s auth=%s",
        payload.secret_name, payload.ttl_seconds, "present" if token else "absent",
    )
    try:
        result = broker.issue_lease(token, payload.secret_name, payload.ttl_seconds)
    except BrokerError as err:
        logger.info("DENIED issue: reason=%s detail=%s", err.reason.value, err.detail)
        return _denial_response(err)
    logger.info("GRANTED issue: lease_id=%s basis=%s", result.lease_id, result.basis)
    return _lease_payload(result)


@router.post("/leases/{lease_id}/renew", response_model=LeaseOut)
def renew_lease(lease_id: str, payload: RenewRequest, request: Request,
                broker: LeaseBroker = Depends(get_broker)):
    token = _bearer(request)
    logger.info("REQUEST renew: lease_id=%s ttl_seconds=%s", lease_id, payload.ttl_seconds)
    try:
        result = broker.renew_lease(token, lease_id, payload.ttl_seconds)
    except BrokerError as err:
        logger.info("DENIED renew lease=%s: reason=%s detail=%s", lease_id, err.reason.value, err.detail)
        return _denial_response(err)
    logger.info("GRANTED renew lease=%s basis=%s", lease_id, result.basis)
    return _lease_payload(result)


@router.post("/leases/{lease_id}/revoke")
def revoke_lease(lease_id: str, request: Request, broker: LeaseBroker = Depends(get_broker)):
    token = _bearer(request)
    logger.info("REQUEST revoke: lease_id=%s", lease_id)
    try:
        result = broker.revoke_lease(token, lease_id)
    except BrokerError as err:
        logger.info("DENIED revoke lease=%s: reason=%s detail=%s", lease_id, err.reason.value, err.detail)
        return _denial_response(err)
    logger.info("GRANTED revoke lease=%s already=%s", lease_id, result["already_revoked"])
    return {"allowed": True, **result}


@router.get("/leases/{lease_id}/secret", response_model=AccessOut)
def access_secret(lease_id: str, request: Request, broker: LeaseBroker = Depends(get_broker)):
    token = _bearer(request)
    logger.info("REQUEST access: lease_id=%s auth=%s", lease_id, "present" if token else "absent")
    try:
        result = broker.access_secret(token, lease_id)
    except BrokerError as err:
        logger.info("DENIED access lease=%s: reason=%s detail=%s", lease_id, err.reason.value, err.detail)
        return _denial_response(err)
    logger.info(
        "GRANTED access lease=%s secret=%s version=%s basis=%s",
        lease_id, result.secret_name, result.version, result.basis,
    )
    out = _lease_payload(result)
    out["value"] = result.value
    return out
