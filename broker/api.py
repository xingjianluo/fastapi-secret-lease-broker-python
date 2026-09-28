"""FastAPI 路由：凭证签发 -> 租约申请 -> 读取 / 续期 / 吊销。

所有 BrokerError 统一转为：
    {"error": {"reason": "<稳定原因码>", "message": "<可解释说明>"}}
每个数据面请求都会记录“请求输入 + 最终判定依据”，便于本地审计与测试排查。
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import FastAPI, Header, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from broker.errors import BrokerError, ErrorReason
from broker.manager import LeaseManager

logger = logging.getLogger("broker.audit")


class CredentialRequest(BaseModel):
    principal: str = Field(..., description="已登记的调用方身份标识")


class CredentialResponse(BaseModel):
    token: str
    expires_at: float


class LeaseRequest(BaseModel):
    secret_name: str


class LeaseView(BaseModel):
    lease_id: str
    principal: str
    scope: str
    secret_name: str
    bound_version: int
    issued_at: float
    expires_at: float
    revoked: bool


class ReadResponse(BaseModel):
    lease: LeaseView
    value: str
    decision_basis: str = Field(..., description="本次读取被放行的依据")


def create_app(manager: LeaseManager, provisioning_key: str = "local-provisioning-key") -> FastAPI:
    app = FastAPI(title="Secret Lease Broker", version="0.1.0")

    def view(lease) -> LeaseView:
        return LeaseView(
            lease_id=lease.lease_id,
            principal=lease.principal,
            scope=lease.scope,
            secret_name=lease.secret_name,
            bound_version=lease.bound_version,
            issued_at=lease.issued_at,
            expires_at=lease.expires_at,
            revoked=lease.revoked,
        )

    def bearer(request: Request) -> str | None:
        auth = request.headers.get("authorization")
        if not auth:
            return None
        parts = auth.split(" ", 1)
        if len(parts) == 2 and parts[0].lower() == "bearer":
            return parts[1].strip()
        return auth.strip()

    def audit(action: str, request_input: dict[str, Any], decision: str) -> None:
        logger.info("action=%s input=%s decision=%s", action, request_input, decision)

    @app.exception_handler(BrokerError)
    async def broker_error_handler(request: Request, exc: BrokerError) -> JSONResponse:
        action = getattr(request.state, "action", "unknown")
        request_input = getattr(request.state, "input", {})
        audit(action, request_input, f"DENY:{exc.reason.value} detail={exc.message}")
        return JSONResponse(
            status_code=exc.http_status,
            content={"error": {"reason": exc.reason.value, "message": exc.message}},
        )

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/credentials", response_model=CredentialResponse)
    def create_credential(
        request: Request,
        body: CredentialRequest,
        x_provisioning_key: str | None = Header(default=None),
    ) -> CredentialResponse:
        request.state.action = "issue_credential"
        request.state.input = body.model_dump()
        # 开通面：本地用共享 provisioning key 保护，不属于数据面授权
        if x_provisioning_key != provisioning_key:
            raise BrokerError(
                ErrorReason.ACCESS_DENIED,
                "开通密钥 X-Provisioning-Key 缺失或错误，拒绝签发凭证",
                http_status=403,
            )
        token = manager.issue_credential(body.principal)
        audit("issue_credential", body.model_dump(), "ALLOW")
        return CredentialResponse(token=token, expires_at=manager.clock() + manager.token_ttl)

    @app.post("/leases", response_model=LeaseView, status_code=201)
    def create_lease(body: LeaseRequest, request: Request) -> LeaseView:
        request.state.action = "request_lease"
        request.state.input = body.model_dump()
        lease = manager.request_lease(bearer(request), body.secret_name)
        audit(
            "request_lease",
            body.model_dump(),
            f"ALLOW lease_id={lease.lease_id} bound_version=v{lease.bound_version} "
            f"expires_at={lease.expires_at}",
        )
        return view(lease)

    @app.post("/leases/{lease_id}/read", response_model=ReadResponse)
    def read(lease_id: str, request: Request) -> ReadResponse:
        request.state.action = "read_secret"
        request.state.input = {"lease_id": lease_id}
        lease, value = manager.read_secret(bearer(request), lease_id)
        basis = (
            f"principal={lease.principal} 持有未吊销且未过期的租约 {lease.lease_id}，"
            f"绑定 {lease.secret_name} v{lease.bound_version}（版本未退休），"
            f"now={manager.clock()} < expires_at={lease.expires_at}"
        )
        audit("read_secret", {"lease_id": lease_id}, f"ALLOW {basis}")
        return ReadResponse(lease=view(lease), value=value, decision_basis=basis)

    @app.post("/leases/{lease_id}/renew", response_model=LeaseView)
    def renew(lease_id: str, request: Request) -> LeaseView:
        request.state.action = "renew_lease"
        request.state.input = {"lease_id": lease_id}
        lease = manager.renew_lease(bearer(request), lease_id)
        audit("renew_lease", {"lease_id": lease_id}, f"ALLOW 就地续期 expires_at={lease.expires_at}")
        return view(lease)

    @app.post("/leases/{lease_id}/revoke", status_code=204)
    def revoke(lease_id: str, request: Request) -> None:
        request.state.action = "revoke_lease"
        request.state.input = {"lease_id": lease_id}
        manager.revoke_lease(bearer(request), lease_id)
        audit("revoke_lease", {"lease_id": lease_id}, "ALLOW 租约已标记吊销")

    return app
