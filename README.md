# 本地密钥访问租约代理（Local Secret Lease Broker）

一个完全本地可运行的 FastAPI 服务：调用方持**可验证身份凭证**，按**最小权限**获得针对某个密钥**某一版本**的**短期、可撤销访问租约（lease）**。
对越权、过期、吊销、轮换重叠窗口等情况，系统给出**可区分、可解释**的失败原因，不依赖任何外部服务或真实凭据。

- 运行时：Python ≥ 3.14，FastAPI + Uvicorn（内存存储，零外部依赖）
- 凭证：本地 HMAC-SHA256 签名的 bearer token（自包含 payload），无真实 IdP
- 数据：进程内存 + 单把锁，重启即重置；种子数据全部是假数据

---

## 1. 快速开始

```bash
# 安装依赖（项目已配置 uv；也可用任意 venv + pip）
uv sync

# 方式 A：直接运行
python main.py                 # http://127.0.0.1:8000

# 方式 B：uvicorn
uv run uvicorn app.app:app --reload --port 8000

# 方式 C：真实服务器冒烟脚本（线程内启动 uvicorn 并打 HTTP 请求）
python smoke_test.py

# 运行全部单测（实时打印每个请求输入与最终判定依据）
uv run pytest                  # 或 python -m pytest
```

打开交互式文档：<http://127.0.0.1:8000/docs>

### 1.1 种子调用方（仅本地夹具，非真实身份系统）

`GET /api/v1/local/tokens` 返回预置调用方的 bearer token：

| caller | 持有的 scope | 含义 |
|---|---|---|
| `alice` | `secret:db/password:read` | 只能读 `db/password` |
| `bob`   | `secret:api/key:read`      | 只能读 `api/key`（与 alice 隔离） |
| `ops`   | `lease:revoke`             | 只能吊销/管理租约，**不能**读取密钥 |
| `glass` | `secret:*:read`            | 破玻璃（break-glass）：可读任意密钥 |

种子密钥：`db/password`（轮换重叠窗口 30s）、`api/key`（15s）。

### 1.2 curl 走读

```bash
BASE=http://127.0.0.1:8000
ALICE=$(curl -s $BASE/api/v1/local/tokens | python -c "import sys,json;print(json.load(sys.stdin)['tokens']['alice'])")

# 无凭证 -> 401 missing_credential
curl -s -X POST $BASE/api/v1/leases -H 'Content-Type: application/json' \
  -d '{"secret_name":"db/password","ttl_seconds":60}'

# 签发租约 -> 201，带 expires_at 与判定依据 basis
curl -s -X POST $BASE/api/v1/leases -H "Authorization: Bearer $ALICE" \
  -H 'Content-Type: application/json' -d '{"secret_name":"db/password","ttl_seconds":60}'

# 凭租约读取密钥值
curl -s $BASE/api/v1/leases/<lease_id>/secret -H "Authorization: Bearer $ALICE"

# 续期（租约 id 不变）/ 吊销
curl -s -X POST $BASE/api/v1/leases/<lease_id>/renew  -H "Authorization: Bearer $ALICE" \
  -H 'Content-Type: application/json' -d '{"ttl_seconds":120}'
curl -s -X POST $BASE/api/v1/leases/<lease_id>/revoke -H "Authorization: Bearer $ALICE"
```

---

## 2. 授权模型（默认拒绝，身份不可自声明）

1. **认证先于授权。** 请求需携带 `Authorization: Bearer <token>`。token 形如
   `b64url(payload).b64url(hmac_sha256(payload))`，payload 内含 `sub`（调用方）、
   `scp`（scope 列表）、`iat`、`exp`。
2. 服务端用本地密钥验签并检查 `exp`。**调用方身份与 scope 只来自已签名 payload，
   永不读取请求体里自报的角色**——篡改 payload 立刻破坏签名，无法提权。
3. 授权是**默认拒绝**的白名单：
   - `secret:<name>:read`：可对该密钥签发/使用只读租约；
   - `secret:*:read`：可对任意密钥签发（仅 `glass`）；
   - `lease:revoke`：可吊销任意租约（仅 `ops`），但不授予读密钥能力；
   - 租约的**属主**可续期/吊销/读取自己的租约；其他人一律拒绝；
   - 未列出的情况（含请求不存在的密钥）全部拒绝。

### 失败原因（可区分，HTTP 状态码稳定）

所有拒绝都返回 `{"allowed": false, "error": {"reason", "message", "detail"}}`：

| reason | HTTP | 触发条件 |
|---|---|---|
| `missing_credential` | 401 | 没带 `Authorization` 头 |
| `forged_credential` | 401 | token 格式坏、签名不匹配、payload 被篡改、用别的密钥签发 |
| `expired_credential` | 401 | token 已过 `exp`（与伪造明确区分，`detail` 给出 expired_at） |
| `unauthorized_scope` | 403 | 已认证但无对应 scope / 非租约属主 / 密钥不存在（默认拒绝） |
| `lease_not_found` | 404 | 租约 id 不存在 |
| `lease_expired` | 410 | 租约已过 `expires_at` |
| `lease_revoked` | 410 | 租约已被吊销 |
| `lease_version_mismatch` | 409 | 绑定的旧版本重叠窗口已结束 |

认证类失败与授权类失败分开（401 vs 403）；过期、吊销、版本不匹配也各自独立。

---

## 3. 租约生命周期

```
            issue(认证+scope 检查)
   (无) ───────────────────────────────► ACTIVE ──now>=expires_at──► EXPIRED（终态，不可续）
                                            │
                                            │ revoke（属主或 lease:revoke）
                                            ▼
                                         REVOKED（终态，幂等，不可续，不可读）
```

- **签发 `POST /api/v1/leases`**：认证 + scope 校验通过后，生成随机 `lease_id`，
  **绑定密钥当前最新版本**，记录 `issued_at / expires_at`。响应含明确 `expires_at`
  和人类可读 `basis`（判定依据）。签发结果不返回密钥值，需再用租约读取。
- **读取 `GET /api/v1/leases/{id}/secret`**：仅租约属主（或 `lease:revoke` 管理者）
  可用。服务端按**固定顺序**评估并返回可区分结果：
  1. 已吊销 → `lease_revoked`（吊销优先于过期，二者同时成立也报吊销）；
  2. 已过期 → `lease_expired`（`detail` 含 expires_at / now）；
  3. 绑定版本不可用或轮换重叠窗口已结束 → `lease_version_mismatch`
     （`detail` 含 bound_version / current_version）；
  4. 全部通过才返回值。
- **续期 `POST /api/v1/leases/{id}/renew`**：**就地延长同一租约**——`lease_id` 不变、
  **绑定版本不变**（绝不会因为密钥轮换而“顺手”升到新版本）。已吊销/已过期不可续。
- **吊销 `POST /api/v1/leases/{id}/revoke`**：幂等，重复吊销返回 `already_revoked: true`。
  吊销立即生效；之后任何续期/读取都失败。属主可吊销自己的租约，`ops` 可吊销任意租约。

---

## 4. 密钥轮换与重叠窗口（旧租约不读到新值）

- 每个密钥保存**不可变的版本序列**（`v1, v2, …`），轮换只会追加新版本并把
  `current_version` 前移；旧版本被保留，供绑定它的租约在窗口内继续读。
- 租约在签发时**绑定且只绑定一个版本**：
  - 轮换后、**重叠窗口内**：旧租约继续返回**旧版本的值**（`basis` 会说明
    “overlap window still open; serving bound old version”），绝不会返回新版本；
  - **窗口结束的瞬间**（`now >= 新版本创建时间 + overlap_window_seconds`）：
    旧租约立即失败为 `lease_version_mismatch`，**不会被静默放行，也不会被静默升级**
    到新版本（测试 `test_window_closed_lease_is_never_silently_promoted` 断言新值绝不泄漏）；
  - 轮换后**新签发**的租约绑定当前新版本。
- 轮换通过本地管理接口/夹具触发，示例见
  `tests/test_lifecycle.py`（测试用可控时钟 `ManualClock` 精确验证边界 t-1 / t）。

---

## 5. 并发一致性

broker 对每次 **认证 → 授权 → 状态检查 → 写入** 的全过程持有存储层的同一把
可重入锁（`MemoryStore.lock()`），使并发操作被串行化为某个确定的全序，因此：

- **并发续期不产生重复租约**：续期是原地改 `expires_at`，`lease_id` 恒定
  （`test_concurrent_renewals_keep_single_lease_id`，32 路并发）；
- **吊销不会漏掉**：与续期并发时，排在吊销之后的续期一律 `lease_revoked`，
  终态恒为已吊销（`test_revoke_racing_concurrent_renewals_is_never_lost`）；
- **吊销之后仍在处理的请求不会成功**：访问同样在锁内复查 `revoked`
  （`test_in_flight_access_after_revoke_cannot_succeed`）；
- 失败原因仍可区分：过期 / 已吊销 / 版本不匹配 / 授权失败分别报不同的 `reason`。

---

## 6. 测试与可解释日志

```bash
python -m pytest                      # 实时日志：请求输入 + 最终判定依据
python -m pytest tests/test_lifecycle.py -q
```

- `tests/test_authentication.py`：无凭证、坏格式、签名篡改、payload 加 scope 提权、
  异钥伪造、过期凭证；
- `tests/test_authorization.py`：scope 隔离、默认拒绝、跨属主、`ops` 不能读、
  break-glass 通配；
- `tests/test_lifecycle.py`：过期、吊销（幂等/优先于过期）、轮换重叠窗口边界、
  旧租约版本绑定与窗口结束即失败、未知租约；
- `tests/test_concurrency.py`：并发续期不重复、续期与吊销竞争、吊销后在途请求、
  并发签发相互独立。

每条请求都会通过 `lease_broker.http` / `lease_broker.audit` logger 记录**请求输入**
（方法、路径、密钥名、TTL、是否带凭证）与**最终判定依据**（GRANTED 的 `basis`，
或 DENIED 的 `reason + detail`）。pytest 已开启 `log_cli`，可在单测日志中直接看到，例如：

```
lease_broker.http  | REQUEST access: lease_id=8e0c28... auth=present
lease_broker.audit | action=access caller=alice allowed=False | deny lease=... old_version=1 current=2 overlap window closed
lease_broker.http  | DENIED access lease=...: reason=lease_version_mismatch detail={'bound_version': 1, 'current_version': 2}
```

---

## 7. 代码结构

```
app/
  models.py    # Identity / SecretVersion / SecretRecord / Lease / AccessResult / DenialReason
  errors.py    # 每种 reason 对应的异常类型
  clock.py     # SystemClock（生产）/ ManualClock（确定性测试）
  auth.py      # HMAC token 签发与认证（伪造/过期可区分，角色不可自声明）
  authz.py     # 默认拒绝的 scope 策略
  store.py     # 线程安全内存存储（密钥版本 + 租约 + 全局锁）
  broker.py    # 核心：签发/续期/吊销/访问 的加锁决策与审计日志
  fixtures.py  # 本地种子密钥与调用方
  api.py       # FastAPI 路由、schema、reason -> HTTP 状态码映射
  app.py       # 应用装配 + /health + /api/v1/local/tokens
tests/         # 认证/授权/生命周期/并发 四组共 30+ 用例，conftest 提供可控时钟与日志
main.py        # python main.py 启动入口
smoke_test.py  # 真实 uvicorn HTTP 冒烟脚本
```

## 8. 设计边界（明确不做的事）

- 纯本地教学/演示实现：token 签名密钥写在 `TokenIssuer` 默认参数里，不是真实密钥管理；
- 无刷新令牌/无鉴权审计持久化：所有状态在内存，重启即清空；
- 重叠窗口按“后继版本创建时间 + 窗口秒数”计算；窗口结束即拒绝，不做宽限期；
- 租约不可转赠，非属主持有读 scope 也不能通过他人租约取值。
