# Secret Lease Broker（本地密钥访问租约代理）

一个完全本地可运行的 FastAPI 服务：不同调用方凭**可验证身份凭证**，按**最小权限**获得指向某个密钥**具体版本**的**短期、可撤销**访问租约。越权、过期、吊销、轮换重叠窗口结束等情况都会返回**稳定且可区分的失败原因**，不存在静默放行。

- 无外部服务、无真实凭据：身份凭证用进程内 HMAC 密钥签名，密钥与租约保存在内存中。
- 并发安全：租约的校验与状态变更在同一把锁内完成。

## 1. 快速开始

```bash
uv sync                       # 安装依赖（含 pytest / httpx）
uv run python demo.py         # 不启服务，脚本化复现全部场景并打印判定
uv run pytest -s              # 运行 26 个单测（-s 可看到请求输入与判定日志）
uv run uvicorn main:app --reload   # 启动 HTTP 服务，默认 127.0.0.1:8000
```

种子数据（见 `main.py`）：

| principal      | 授权 scope                         |
|----------------|------------------------------------|
| `svc-billing`  | `secret:billing/db`、`secret:billing/api-key` |
| `svc-reporting`| `secret:billing/db`（只读库密码）  |
| `svc-anon`     | 无（已登记但零授权，演示默认拒绝） |

密钥 `billing/db`（轮换重叠窗口 30s）、`billing/api-key`（窗口 10s）。
开通密钥默认 `local-provisioning-key`，签名密钥默认 `local-demo-signing-key`，可用环境变量 `BROKER_PROVISIONING_KEY` / `BROKER_TOKEN_SECRET` 覆盖。

## 2. HTTP 接口

所有数据面接口用 `Authorization: Bearer <token>` 携带身份凭证。
错误响应统一为 `{"error": {"reason": "<稳定原因码>", "message": "<可解释说明>"}}`。

| 方法 & 路径 | 说明 |
|---|---|
| `POST /credentials` | 开通面：需头 `X-Provisioning-Key`，为**已登记** principal 签发身份凭证 |
| `POST /leases` | 申请租约，body `{"secret_name": "billing/db"}`；返回租约（含 `bound_version`、`expires_at`） |
| `POST /leases/{id}/read` | 凭租约读取密钥；返回绑定版本的值与本次放行依据 `decision_basis` |
| `POST /leases/{id}/renew` | 就地续期同一租约（同一 `lease_id`，延长 `expires_at`） |
| `POST /leases/{id}/revoke` | 吊销租约（幂等） |
| `GET /health` | 健康检查 |

```bash
KEY=local-provisioning-key
TOK=$(curl -s -X POST localhost:8000/credentials \
  -H "X-Provisioning-Key: $KEY" -H 'Content-Type: application/json' \
  -d '{"principal":"svc-billing"}' | python -c 'import sys,json;print(json.load(sys.stdin)["token"])')

LID=$(curl -s -X POST localhost:8000/leases \
  -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' \
  -d '{"secret_name":"billing/db"}' | python -c 'import sys,json;print(json.load(sys.stdin)["lease_id"])')

curl -s -X POST localhost:8000/leases/$LID/read -H "Authorization: Bearer $TOK"
```

## 3. 授权模型（默认拒绝，角色不可自证）

1. **凭证只证明身份，不携带角色/权限。** 令牌载荷只有 `sub / iat / exp / jti`，并用服务端 HMAC 密钥签名（`broker/tokens.py`）。
2. **授权只来自服务端策略表** `principal -> 允许的 scope 集合`（`broker/policy.py`）。没有任何显式授权记录即拒绝，因此在令牌里改写 `sub` 或自行声明角色无法提权——篡改会导致签名校验失败，合法身份但无授权则 `access_denied`。
3. **每次操作都复核策略与租约归属**：策略被收回（如从授权集合中删除 scope）在下一次 read/renew 时立即生效；租约只允许其属主访问，他人访问统一 `access_denied`，不泄露租约存在性。

## 4. 租约生命周期

```
登记 principal ──POST /credentials──▶ 身份凭证（HMAC，有 exp）
申请租约  ──POST /leases──▶ Lease{lease_id, bound_version, issued_at, expires_at}
   │
   ├─ read：校验 身份 → 归属/策略 → 吊销 → TTL → 版本退休，全部通过才返回绑定版本的值
   ├─ renew：就地延长同一条租约（不新建租约、不换 id）；已过期/已吊销/版本退休不得续期
   └─ revoke：置 revoked=true（幂等），此后 read/renew 立即失败
```

- 租约 TTL 默认 120s（测试夹具 100s），`expires_at` 在签发与续期响应中明确返回。
- 判定顺序固定为 **吊销 → 过期 → 版本退休**，因此四类失败互不混淆（见第 6 节）。

## 5. 密钥轮换与重叠窗口规则

每个密钥保留全部历史版本（`broker/models.py`）。轮换 `rotate()` 会新增一个**不可变版本**并把 `current_version` 指向它：

- 租约在签发时**绑定一个具体版本**，之后 read 永远只返回该版本的值——密钥更新后旧租约**读不到新版本**。
- 轮换后设置 `overlap_window` 秒的**重叠窗口**：窗口内旧租约可继续读取其绑定的旧版本（平滑轮换）。
- 窗口结束的瞬间（`now >= 新版本创建时间 + overlap_window`）旧版本立即退休，旧租约再访问得到 **409 `version_mismatch`**，消息中指明绑定版本与当前版本，而**不是静默放行也不是读到新值**。
- 想要新版本值：重新 `POST /leases`，新租约绑定当前版本。
- 多次连续轮换时，退休判定以“最新版本创建时间 + 窗口”为准。

## 6. 可区分的失败原因

| reason | HTTP | 触发条件 |
|---|---|---|
| `missing_credential` | 401 | 未提供凭证 |
| `malformed_credential` | 401 | 凭证结构/编码非法或缺少必要字段 |
| `forged_credential` | 401 | HMAC 签名不匹配（伪造、篡改 payload、签名密钥错误） |
| `expired_credential` | 401 | 凭证自身 `exp` 已过 |
| `access_denied` | 403 | 策略未授权 / 租约不属于该调用方 / 开通密钥错误 / principal 未登记 |
| `lease_not_found` | 404 | 租约 id 不存在 |
| `lease_expired` | 403 | 租约 `expires_at` 已到且未被吊销 |
| `lease_revoked` | 403 | 租约已被吊销 |
| `version_mismatch` | 409 | 绑定版本已随轮换重叠窗口结束而退休 |

## 7. 并发一致性

`LeaseManager` 用单把 `RLock` 保护租约表，所有操作都在锁内完成“校验 + 状态变更”：

- **并发续期**：多个续期请求串行执行，均就地更新同一条租约记录，不产生重复 `lease_id`，也不会新建租约。
- **并发吊销 vs 续期/读取**：谁先拿到锁谁先生效，但最终状态收敛且一致——一旦吊销落盘，之后的任何 read/renew 必然 `lease_revoked`，吊销不会被漏掉或被续期“救活”。
- 并发的新租约申请相互独立，各自得到不同 `lease_id`。

测试 `tests/test_concurrency.py` 用线程屏障制造竞态，断言：8 路并发续期只保留一条租约；续期/吊销并发后最终读必然是 `lease_revoked`；吊销之后的在途读取不允许成功。

## 8. 可观测性：审计日志

logger `broker.audit` 对每个请求记录一行，包含**请求输入**与**最终判定依据**，例如：

```
action=request_lease input={'secret_name': 'billing/db'} decision=DENY:missing_credential detail=缺少身份凭证...
action=read_secret input={'lease_id': '5270...'} decision=ALLOW principal=svc-billing 持有未吊销且未过期的租约 ...，绑定 billing/db v1 ...，now=... < expires_at=...
action=read_secret input={'lease_id': '5270...'} decision=DENY:version_mismatch detail=租约绑定 v1，该版本已随轮换重叠窗口结束而退休（当前版本 v2）
```

`uv run pytest -s --log-cli-level=INFO` 可在单测日志中查看这些行。

## 9. 测试覆盖（26 个）

| 文件 | 覆盖场景 |
|---|---|
| `tests/test_auth.py` | 无凭证、格式非法、伪造签名、篡改 payload、过期凭证、越权 scope、不存在密钥、零授权 principal、开通密钥保护、未登记 principal |
| `tests/test_lease_lifecycle.py` | 租约到期、吊销与幂等吊销、续期延长同一租约、过期/吊销后不可续期、跨 principal 访问、租约不存在、策略即时收回 |
| `tests/test_rotation.py` | 窗口内旧租约读旧版本、新租约读新版本、窗口结束瞬间 409、版本不匹配与过期/吊销可区分、窗口后不可续期、多次轮换 |
| `tests/test_concurrency.py` | 8 路并发续期单租约、续期/吊销竞态收敛、在途读取遇吊销、并发新租约独立 |

## 10. 代码结构

```
broker/
  errors.py    # BrokerError + 稳定 reason 枚举
  clock.py     # 可注入时钟（测试用虚拟时钟）
  models.py    # SecretVersion / Secret（版本+重叠窗口）/ Lease（绑定版本+TTL+吊销）
  tokens.py    # HMAC 身份凭证签发与验证
  policy.py    # 服务端授权策略表（默认拒绝）
  store.py     # 密钥存储与轮换
  manager.py   # 租约签发/读取/续期/吊销（锁内校验+变更）
  api.py       # FastAPI 路由、统一错误响应、审计日志
main.py        # 种子数据与启动入口
demo.py        # 本地端到端场景演示
tests/         # conftest（虚拟时钟+TestClient）与 4 组测试
```
