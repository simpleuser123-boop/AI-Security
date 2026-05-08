# AI-Security-Guardian 首批客户私有化 Beta 试点运行手册

适用版本：单企业私有化 Beta  
适用对象：交付团队、客户运维、客户安全运营、客户管理员、DBA、网络/安全团队  
默认安全边界：`DRY_RUN=true`，不执行真实封禁、云安全组变更或 EDR 主机隔离  
默认部署口径：Linux 服务器 + Docker Compose + PostgreSQL + Redis + Nginx/TLS

本文档用于试点运行期的日常检查、巡检、告警处置、审计、备份、队列、模型、通知、dry-run 响应和问题升级。部署前准入请先执行 `docs/private-beta-preflight-checklist.md`，客户交付包请参考 `docs/single-enterprise-private-beta-customer-delivery-package.md`。

## 1. 运行原则

- 首批 Beta 默认且必须保持 `DRY_RUN=true`。如客户要求真实封禁，必须另行通过 `python scripts/check_production_readiness.py --gate real-enforcement`，并具备客户书面授权、业务白名单、审批、回滚、解封和复盘证据。
- `/healthz` 只代表 Web 进程存活；运行放行以 `/readyz`、Redis、PostgreSQL、模型、审计和 Stream 状态为准。
- 任何检查输出不得包含 `.env` 明文、数据库密码、Redis 密码、管理员密码哈希、JWT、API Key 或第三方凭据。
- P0/P1 事件先止血恢复，再做根因分析；涉及疑似误封时第一动作是切回或确认 `DRY_RUN=true`。
- 所有异常、处置、变更和客户确认必须留痕，优先使用 `templates/customer-beta-issue-report.md` 和 `templates/customer-beta-ops-checklog.md`。

## 2. 角色和职责

| 角色 | 职责 |
|---|---|
| 交付团队 | 版本确认、部署支持、readiness、演练、问题定位、修复建议、周报汇总 |
| 客户运维 | 容器、主机、磁盘、证书、Nginx/LB、Redis、备份任务和日志归档 |
| 客户安全运营 | 告警研判、告警状态流转、规则/IOC 调整建议、dry-run 响应复核 |
| 客户管理员 | 登录账号、角色权限、Settings、通知通道测试、客户侧审批和签收 |
| 客户 DBA | PostgreSQL 连通、迁移版本、备份、恢复演练和数据库性能排查 |
| 客户网络/安全 | 域名、TLS、ACL、防火墙、安全组、抓包授权、业务白名单 |

## 3. 常用变量和命令约定

默认在项目根目录执行：

```bash
cd /opt/ai-security-guardian
```

建议运行前确认：

```bash
docker compose ps
git rev-parse HEAD 2>/dev/null || true
docker image ls ai-security-guardian
```

如需从 `.env` 加载变量，必须在客户批准的受控终端执行，不要把输出粘贴到文档或聊天：

```bash
set -a
. ./.env
set +a
```

常用健康入口：

```bash
curl -fsS http://127.0.0.1:5000/api/health
curl -fsS http://127.0.0.1:5000/healthz
curl -fsS http://127.0.0.1:5000/readyz
curl -fsS http://127.0.0.1:5000/metrics
```

## 4. 每日健康检查

频率：每日 1 次；部署、配置变更、模型更新、Redis/DB 重启后立即补做一次。  
记录：填写 `templates/customer-beta-ops-checklog.md`。

| 编号 | 检查项 | 命令 / 方式 | 正常标准 | 异常动作 |
|---|---|---|---|---|
| D-01 | 容器状态 | `docker compose ps` | `app`、`redis` 为 running/healthy；启用 full-chain 时 `guardian` 正常 | 查看 `docker compose logs --tail=200 <service>` |
| D-02 | Web 存活 | `curl -fsS http://127.0.0.1:5000/healthz` | HTTP 200，`status=live` | 重启 app 前先保留日志 |
| D-03 | 依赖就绪 | `curl -fsS http://127.0.0.1:5000/readyz` | HTTP 200，`status=ready` 或明确可接受的 degraded | 见第 5 节 |
| D-04 | API 健康 | `curl -fsS http://127.0.0.1:5000/api/health` | `status=healthy` | 定位 degraded 项 |
| D-05 | Redis 认证 | `docker compose exec redis sh -lc 'redis-cli -a "$REDIS_PASSWORD" ping'` | `PONG` | 检查密码、端口、容器和 ACL |
| D-06 | Redis Stream | `python scripts/redis_stream_status.py --json` | Redis available；`xpending` 和 lag 不持续增长 | 见第 9 节 |
| D-07 | 模型状态 | `python scripts/bootstrap_models.py --check`、`/readyz`、`/metrics` | 四类模型 READY；`guardian_model_ready=1` 或 `/readyz` 模型检查通过 | 见第 10 节 |
| D-08 | 审计完整性 | 见第 8 节 `/metrics` 命令 | `audit_integrity_valid 1`，巡检失败计数不增长 | 见第 8 节 |
| D-09 | 通知失败 | DB 查询或告警详情检查 | 无新增 `notify_failed`、`notify_retry_failed` 或失败任务 | 见第 11 节 |
| D-10 | DRY_RUN | `grep '^DRY_RUN=' .env`、readiness、响应动作抽查 | `DRY_RUN=true`；响应状态为 `dry_run_simulated` | 见第 12 节 |
| D-11 | 日志异常 | `docker compose logs --tail=200 app` | 无持续 Traceback、DB/Redis/auth 错误 | 建问题单，附脱敏日志 |
| D-12 | 磁盘空间 | `df -h` | 数据、日志、备份分区不接近客户阈值；建议可用空间 > 20% | 清理已归档日志或扩容 |
| D-13 | 证书和入口 | `curl -Ik https://<domain>/api/health` | HTTPS 正常，证书未临期，WSS 无异常 | 联系网络/安全团队 |

每日检查结论分三类：

| 结论 | 定义 | 动作 |
|---|---|---|
| 正常 | 所有关键项通过，无新增 P1/P0 | 记录检查表 |
| 观察 | 有 WARN、短时 lag、非阻塞通知失败或单项 P2 | 记录问题和观察窗口 |
| 异常 | `/readyz` 失败、DB/Redis 不可用、Stream 持续堆积、审计失败、疑似误封 | 建立问题单并升级 |

## 5. `/readyz` 异常处置

`/readyz` 返回 503 或 `status=unready` 时，按 `fatal` 和 `checks` 字段定位。

```bash
curl -sS http://127.0.0.1:5000/readyz | tee /tmp/guardian-readyz.json
docker compose logs --tail=200 app
```

常见分支：

| 异常项 | 可能原因 | 处置 |
|---|---|---|
| `database` | PostgreSQL 不可达、账号过期、ACL 阻断、迁移异常 | DBA 执行 `SELECT 1`；确认 `DATABASE_URL`；检查 `alembic_version` |
| `redis` | Redis 容器停止、密码错误、端口阻断 | `redis-cli -a "$REDIS_PASSWORD" ping`；检查 Redis 日志 |
| `config` | 生产密钥、管理员哈希、Redis 密码等缺失 | 执行 `python scripts/check_production_readiness.py --gate private-beta` |
| `models` | 模型目录为空、模型不可读、guardian 模型心跳异常 | 执行 `python scripts/bootstrap_models.py --check`；核对 SHA256 |

恢复后必须复验：

```bash
curl -fsS http://127.0.0.1:5000/readyz
python scripts/check_production_readiness.py --gate private-beta
```

## 6. 每周巡检

频率：每周 1 次，建议在试点周会前完成。  
记录：作为试点周报附件。

| 编号 | 巡检项 | 检查方式 | 通过标准 |
|---|---|---|---|
| W-01 | 版本和发布包 | `git rev-parse HEAD`、镜像 tag、`docs/private-beta-release-manifest.md` | 版本可追溯，不使用未确认临时包 |
| W-02 | Readiness gate | `python scripts/check_production_readiness.py --gate private-beta` | 无 `[FAIL]`；`DRY_RUN=true` |
| W-03 | 数据库迁移 | `flask --app web.migration_app:create_migration_app db current` | 与 release manifest 最新 revision 一致；当前清单为 `20260507_0005` |
| W-04 | Redis Stream 趋势 | 每日 `xlen`、`xpending`、lag 对比 | 无持续上升；无长期 pending |
| W-05 | 模型完整性 | 见第 10 节 SHA256 命令 | 与交付 manifest 或客户制品记录一致 |
| W-06 | 审计完整性 | `/metrics`、审计巡检输出、抽查审计事件 | 哈希链有效，关键操作可追溯 |
| W-07 | 备份可用性 | 备份文件、SHA256、恢复演练记录 | 最近备份存在且校验通过 |
| W-08 | 通知链路 | 邮件/Webhook 测试、失败任务查询 | 通道可用或客户明确不启用；无失败堆积 |
| W-09 | 告警闭环 | 抽查 open/investigating/resolved/ignored | 高危告警有处置记录；状态流转有审计 |
| W-10 | 性能和容量 | `/metrics`、`df -h`、必要时 benchmark | 无容量风险；关键接口无持续超时 |
| W-11 | 账号和权限 | 管理员账号、离职/变更人员、API Key | 无无人负责账号；权限符合客户要求 |
| W-12 | 遗留问题 | 问题单、P0/P1/P2 状态 | P0/P1 已关闭或有客户认可规避方案 |

可选周度 E2E 演练：

```bash
python scripts/private_beta_e2e_drill.py \
  --base-url http://127.0.0.1:5000 \
  --json-output reports/private_beta_e2e_drill_$(date +%Y%m%d).json
```

通过标准：演练步骤全部 PASS；响应验证为 `dry_run_simulated` 且 `provider_called=false`。

## 7. 告警处置流程

### 7.1 分级

| 级别 | 定义 | 目标动作 |
|---|---|---|
| Critical | 审计完整性失败、疑似真实业务阻断、凭据泄漏、关键资产高置信攻击 | 立即升级 P0/P1，先止血 |
| High | 高置信攻击、客户核心资产相关、重复触发、可能需要响应动作 | 当日研判，必要时创建 dry-run 响应 |
| Medium | 可疑行为、需结合上下文确认 | 1 到 2 个工作日内研判 |
| Low | 演练、噪声、低置信异常 | 汇总观察或调参 |

### 7.2 标准处置步骤

1. 安全运营在控制台 `Alerts` 查看告警详情、来源 IP、threat type、level、summary、raw payload 和时间线。
2. 判断是否为演练流量、已知业务、扫描器、监控系统或真实攻击。
3. 将告警状态更新为 `investigating`，备注研判人、证据和初步结论。
4. 如需响应，只能在 `DRY_RUN=true` 下创建和审批响应动作；不得绕过客户审批执行真实封禁。
5. 验证 dry-run 响应动作记录、审计事件和计划解封/重试任务。
6. 结论明确后更新为 `resolved` 或 `ignored`，备注根因、影响、是否需要规则/白名单调整。
7. 高危或客户关注事件纳入周报。

### 7.3 数据库辅助查询

仅在客户授权的运维终端执行，输出需脱敏：

```bash
psql "$DATABASE_URL" -c "
SELECT id, timestamp, source_ip, threat_type, level, status, summary
FROM alerts
ORDER BY timestamp DESC
LIMIT 20;"
```

告警状态历史：

```bash
psql "$DATABASE_URL" -c "
SELECT alert_id, from_status, to_status, operator, note, created_at
FROM alert_histories
ORDER BY created_at DESC
LIMIT 50;"
```

响应动作：

```bash
psql "$DATABASE_URL" -c "
SELECT id, alert_id, action_type, target, status, dry_run, reason, created_at, updated_at
FROM response_actions
ORDER BY created_at DESC
LIMIT 30;"
```

### 7.4 告警关闭标准

| 场景 | 关闭条件 |
|---|---|
| 真实攻击 | 客户确认影响范围、处置建议、后续动作；dry-run 响应记录完整 |
| 误报 | 有证据证明为业务/演练/扫描器；规则或白名单建议已记录 |
| 重复告警 | 已关联主事件；重复项备注主事件编号 |
| 审计或系统告警 | 根因已处理，健康检查和审计复验通过 |

## 8. 审计巡检

审计巡检关注两类证据：哈希链完整性和关键操作留痕。

### 8.1 每日检查

```bash
curl -fsS http://127.0.0.1:5000/metrics | grep -E 'audit_integrity_valid|audit_integrity_patrol'
```

正常标准：

- `audit_integrity_valid 1`
- `audit_integrity_patrol_runs_total{result="failed"}` 不持续增长
- `audit_integrity_last_success_timestamp_seconds` 在巡检周期内更新

### 8.2 手工执行一次审计完整性校验

如需手工复核，可在应用环境执行：

```bash
python - <<'PY'
from src.audit.security_logger import SecurityLogger
from src.audit.log_paths import resolve_audit_log_dir

sl = SecurityLogger(log_dir=resolve_audit_log_dir(), enable_integrity=True)
try:
    print(sl.verify_integrity())
finally:
    sl.close()
PY
```

通过标准：输出中 `valid=True`。如失败：

1. 立即按 P1 或 P0 建单，保留 `logs/` 目录现场。
2. 暂停非必要变更，防止覆盖证据。
3. 检查是否有人手工编辑、截断、替换或回滚审计日志。
4. 导出最近关键操作审计和容器日志。
5. 复验修复后更新问题单和周报。

### 8.3 关键审计抽查

每周至少抽查以下操作是否可追溯：

| 操作 | 期望 |
|---|---|
| 登录失败 / 登录成功 | 有 actor、时间、来源、结果 |
| 告警状态流转 | 有 alert id、from/to status、operator、note |
| 设置变更 | 有字段、操作者、时间，不泄露敏感值 |
| 通知测试 | 有 notification 测试审计 |
| 响应创建、审批、执行、回滚 | 有 response action id、dry-run 状态、审批人和结果 |
| 审计完整性失败 | 自动产生 critical 告警和审计记录 |

## 9. Redis Stream 堆积检查

默认 Stream：`guardian:alerts`  
默认 consumer group：`guardian:web`

### 9.1 推荐检查命令

```bash
python scripts/redis_stream_status.py --json
```

也可用 `redis-cli`：

```bash
docker compose exec redis sh -lc 'redis-cli -a "$REDIS_PASSWORD" XLEN guardian:alerts'
docker compose exec redis sh -lc 'redis-cli -a "$REDIS_PASSWORD" XPENDING guardian:alerts guardian:web'
docker compose exec redis sh -lc 'redis-cli -a "$REDIS_PASSWORD" XINFO GROUPS guardian:alerts'
```

### 9.2 正常标准

| 指标 | 正常标准 |
|---|---|
| Redis available | `true` |
| `XLEN` | 可有保留长度，但不随时间无限增长 |
| `XPENDING` | 短时可 > 0，但应回落 |
| group lag | 不持续增长；消费者恢复后应下降 |
| consumer failures | `/metrics` 中 `guardian_alert_stream_consume_failures_total` 不持续增长 |

### 9.3 异常处理

| 现象 | 处置 |
|---|---|
| Redis unavailable | 检查 Redis 容器、密码、端口、内网 ACL；复验 `/readyz` |
| `XINFO GROUPS` 无 `guardian:web` | 重启 app 或确认 consumer 启动配置；检查 app 日志 |
| pending 持续增长 | 查看 `docker compose logs --tail=300 app` 中 persist/ack 错误；检查 DB 连通 |
| lag 持续增长但 app 正常 | 检查 consumer 是否卡住、Web 进程数、DB 写入延迟；必要时重启 app |
| consume failures 增长 | 建 P1/P2 问题单，附 Redis 状态、app 日志、DB 状态 |

恢复后复验：

```bash
python scripts/redis_stream_status.py --json
curl -fsS http://127.0.0.1:5000/metrics | grep -E 'redis_stream|guardian_alert_stream'
```

## 10. 模型就绪检查

### 10.1 必需模型文件

当前 Beta 需要以下关键文件存在且可读：

- `ddos_rf_v1.pkl`
- `ddos_rf_v1.model_manifest.json`
- `intrusion_rf_v1.pkl`
- `intrusion_rf_v1.model_manifest.json`
- `intrusion_scaler_v1.pkl`
- `intrusion_label_encoder_v1.pkl`
- `intrusion_feature_cols_v1.pkl`
- `web_attack_nb_v1.pkl`
- `web_attack_nb_v1.model_manifest.json`
- `anomaly_if_v1.pkl`
- `anomaly_if_v1.model_manifest.json`

### 10.2 检查命令

```bash
python scripts/bootstrap_models.py --check
find models/saved -maxdepth 1 -type f -exec sha256sum {} \; | sort
curl -fsS http://127.0.0.1:5000/readyz
curl -fsS http://127.0.0.1:5000/metrics | grep -E 'guardian_model_ready|guardian_model_expected|guardian_model_loaded|guardian_model_missing|guardian_model_state'
```

正常标准：

- `scripts/bootstrap_models.py --check` 退出码为 0。
- `/readyz` 的 `models` 检查通过。
- full-chain 启用时，`guardian_model_ready 1`，`guardian_model_missing 0`。
- 模型 SHA256 与 `docs/private-beta-release-manifest.md` 或客户模型制品记录一致。

### 10.3 异常处理

| 现象 | 处置 |
|---|---|
| 模型文件缺失 | 从交付制品恢复 `models/saved`；复验 SHA256 |
| manifest JSON 解析失败 | 重新交付模型 manifest；禁止手工修改运行中模型 |
| 容器内不可读 | 检查 volume 挂载和文件权限；`models/saved` 应只读挂载给 app |
| `/readyz` 模型失败 | 同时检查 app 日志和 guardian 模型心跳；必要时重启 guardian/app |
| 模型 SHA256 不一致 | 暂停模型相关验收，确认是否误替换或交付版本不一致 |

## 11. 通知失败检查

通知通道包括 SMTP、Webhook 和企业通知占位。未配置通道时系统可返回 `no_channels_configured`，这不等同于发送失败，但必须在试点边界中说明“客户未启用外部通知”。

### 11.1 每日失败检查

查询响应动作和调度任务：

```bash
psql "$DATABASE_URL" -c "
SELECT id, action_type, status, reason, error, created_at, updated_at
FROM response_actions
WHERE action_type IN ('notify', 'notify_retry')
  AND (status = 'failed' OR reason ILIKE '%notify%failed%' OR error IS NOT NULL)
ORDER BY created_at DESC
LIMIT 30;"
```

```bash
psql "$DATABASE_URL" -c "
SELECT id, task_type, status, attempt_count, max_attempts, run_at, last_error, created_at, updated_at
FROM response_schedule_tasks
WHERE task_type = 'notify_retry'
ORDER BY updated_at DESC
LIMIT 30;"
```

日志辅助：

```bash
docker compose logs --tail=300 app | egrep -i 'notify|smtp|webhook|notification|mail|retry|url_error|smtp_error|http_error' || true
```

### 11.2 通道测试

客户管理员可在控制台 Settings 测试邮件或 Webhook。也可通过 API 测试，需使用已登录 token：

```bash
curl -fsS -X POST http://127.0.0.1:5000/api/settings/test_email \
  -H "Authorization: Bearer <JWT>" \
  -H "Content-Type: application/json" \
  -d '{"email":"soc@example.com"}'
```

```bash
curl -fsS -X POST http://127.0.0.1:5000/api/settings/test_webhook \
  -H "Authorization: Bearer <JWT>" \
  -H "Content-Type: application/json" \
  -d '{"url":"https://hooks.example.com/guardian"}'
```

### 11.3 失败处理

| 失败类型 | 处置 |
|---|---|
| `smtp_not_configured` | 确认客户是否启用邮件；未启用则记录边界 |
| `smtp_error:*` | 检查 SMTP 主机、端口、TLS、账号、ACL，不记录密码 |
| `ssrf_blocked:*` | Webhook URL 被安全校验拒绝；更换为客户批准的公网/内网 HTTPS endpoint |
| `http_error:*` / `url_error:*` | 检查 Webhook 服务状态、DNS、证书、网络出口 |
| `notify_retry` pending 堆积 | 检查 scheduler 是否运行、失败次数、`last_error`；复验通道后等待重试 |
| all channels failed | P2；如影响客户安全运营通知则升级 P1 |

## 12. `DRY_RUN` 响应检查

### 12.1 环境检查

```bash
grep '^DRY_RUN=' .env
python scripts/check_production_readiness.py --gate private-beta
```

正常标准：

- `DRY_RUN=true`
- readiness 中 `DRY_RUN: true; private Beta runs in non-enforcing mode`
- 不存在启用真实封禁所需的未审批变更窗口

### 12.2 响应动作抽查

```bash
psql "$DATABASE_URL" -c "
SELECT id, alert_id, action_type, target_type, target, status, dry_run, reason, created_at
FROM response_actions
ORDER BY created_at DESC
LIMIT 30;"
```

正常标准：

- Beta 试点响应动作为 `dry_run=true`。
- 执行结果为 `dry_run_simulated` 或其他非真实 provider 执行状态。
- API 执行响应中 `provider_called=false`。
- 不应出现未审批的真实 `executed` 封禁。

### 12.3 演练验证

```bash
python scripts/private_beta_e2e_drill.py \
  --base-url http://127.0.0.1:5000 \
  --json-output reports/private_beta_e2e_drill_$(date +%Y%m%d%H%M%S).json
```

通过标准：

- “响应审批测试” PASS。
- “DRY_RUN 响应验证” PASS。
- JSON 证据中响应状态为 `dry_run_simulated`。

### 12.4 发现 `DRY_RUN=false` 的处置

如首批 Beta 未经批准发现 `DRY_RUN=false`：

1. 立即按 P0/P1 升级。
2. 暂停新增响应动作。
3. 将 `.env` 改回 `DRY_RUN=true`，清空或撤销 `REAL_ENFORCEMENT_GATE`。
4. 重启 app 和 guardian：

```bash
docker compose up -d app guardian
```

5. 检查最近响应动作是否真实执行，必要时按 `templates/misblock-recovery-sop.md` 做误封恢复。
6. 执行 `python scripts/check_production_readiness.py --gate private-beta` 复验。

## 13. 备份检查

### 13.1 每日备份检查

```bash
find backups -maxdepth 2 -type f -mtime -2 -ls | head -50
find backups -name '*.sha256' -mtime -7 -print
```

正常标准：

- 最近 24 小时或客户备份策略窗口内存在 PostgreSQL 备份。
- 模型、日志、`.env` SHA256、Compose 配置或等效证据齐全。
- 备份目录权限符合客户要求，建议 `700`。
- 普通证据包不复制 `.env` 明文，只保存 SHA256。

### 13.2 备份范围

| 对象 | 方式 | 频率 |
|---|---|---|
| PostgreSQL | `pg_dump "$DATABASE_URL" -Fc` 或客户 DBA 平台 | 每日；变更前必须 |
| `.env` / 密钥系统版本 | 保存 SHA256 或客户密钥系统版本号 | 变更前后 |
| `models/saved` | tar 包 + SHA256 或制品仓库版本 | 模型变更前后 |
| `logs/` | 日志归档 + SHA256 | 每日或客户日志策略 |
| 镜像和 Compose | 镜像 tag/ID、`docker compose config` | 发布和变更时 |

### 13.3 备份命令模板

```bash
export TS=$(date +%Y%m%d%H%M%S)
mkdir -p "backups/$TS"
chmod 700 "backups/$TS"

sha256sum .env > "backups/$TS/env.sha256"

pg_dump "$DATABASE_URL" -Fc -f "backups/$TS/guardian_prod.dump"
sha256sum "backups/$TS/guardian_prod.dump" > "backups/$TS/guardian_prod.dump.sha256"

tar -czf "backups/$TS/models-saved.tar.gz" models/saved
sha256sum "backups/$TS/models-saved.tar.gz" > "backups/$TS/models-saved.tar.gz.sha256"
find models/saved -maxdepth 1 -type f -exec sha256sum {} \; | sort > "backups/$TS/models-saved.sha256"

tar -czf "backups/$TS/logs.tar.gz" logs
sha256sum "backups/$TS/logs.tar.gz" > "backups/$TS/logs.tar.gz.sha256"

docker compose ps > "backups/$TS/compose-ps.txt"
docker image ls ai-security-guardian > "backups/$TS/images.txt"
docker compose config > "backups/$TS/compose-config.yml"
```

### 13.4 每周恢复抽检

恢复抽检必须在隔离库执行：

```bash
export BACKUP_TS=<BACKUP_TIMESTAMP>
sha256sum -c "backups/$BACKUP_TS/guardian_prod.dump.sha256"

createdb guardian_restore_drill
pg_restore -d guardian_restore_drill "backups/$BACKUP_TS/guardian_prod.dump"
psql guardian_restore_drill -c 'SELECT version_num FROM alembic_version;'
psql guardian_restore_drill -c '\dt'
```

通过标准：

- SHA256 校验通过。
- `pg_restore` 成功。
- `alembic_version.version_num` 与当前发布清单一致。
- 核心表可查询：`alerts`、`audit_events`、`response_actions`、`response_schedule_tasks`。

## 14. 问题升级路径

### 14.1 优先级

| 级别 | 定义 | 首要动作 | 响应目标 |
|---|---|---|---|
| P0 | 控制台完全不可用且影响验收、疑似真实误封影响生产、数据不可恢复、凭据泄漏、审计链被破坏 | 立即止血、切回安全状态、保全证据 | 立即响应 |
| P1 | `/readyz` 持续失败、DB/Redis 不可用、告警无法入库、Stream 持续堆积、关键通知不可用 | 恢复核心链路，建立问题单 | 当日响应 |
| P2 | 单功能异常、通知偶发失败、规则误报偏高、性能波动、非核心页面异常 | 定位和规避，纳入周报 | 2 个工作日 |
| P3 | 文档、体验、非阻塞优化 | 周会评审 | 后续迭代 |

### 14.2 升级链路

1. 一线运维或安全运营发现异常，先采集最小证据。
2. 客户管理员确认影响范围、业务影响和是否涉及误封/凭据/数据。
3. P0/P1 同步客户项目负责人、客户运维负责人、客户安全负责人、DBA 或网络负责人。
4. 交付团队接手产品和代码层定位。
5. 如需要客户侧变更，进入客户变更流程。
6. 关闭前必须复验并补齐问题单。

### 14.3 最小证据包

```bash
docker compose ps
curl -sS http://127.0.0.1:5000/api/health
curl -sS http://127.0.0.1:5000/healthz
curl -sS http://127.0.0.1:5000/readyz
python scripts/redis_stream_status.py --json
docker compose logs --tail=300 app
docker compose logs --tail=200 redis
```

涉及模型：

```bash
python scripts/bootstrap_models.py --check
find models/saved -maxdepth 1 -type f -exec sha256sum {} \; | sort
```

涉及审计：

```bash
curl -fsS http://127.0.0.1:5000/metrics | grep -E 'audit_integrity|guardian_response_actions|redis_stream'
```

涉及误封：

- 当前 `DRY_RUN` 状态。
- 被影响 IP/CIDR。
- 响应动作 ID。
- Provider 类型：iptables、云安全组、EDR 或其他。
- 是否已恢复业务。
- 关联变更单。

## 15. 试点周报模板

建议每周由交付团队和客户项目负责人共同确认。可直接复制以下模板。

```markdown
# AI-Security-Guardian 私有化 Beta 试点周报

客户名称：
环境名称：
试点周次：
统计周期：
当前版本 / 镜像 tag：
Git commit / 发布包编号：
当前 DRY_RUN：true / false
周报负责人：

## 1. 本周总体结论

- 运行状态：正常 / 观察 / 异常
- 是否满足继续试点条件：是 / 否
- 是否建议扩大试点：是 / 否 / 暂缓
- 是否允许进入真实响应评估：否（默认）/ 是（需另附 real-enforcement 证据）

## 2. 健康检查摘要

| 日期 | /healthz | /readyz | Redis | Stream pending/lag | 模型 | 审计 | 备份 | 结论 |
|---|---|---|---|---|---|---|---|---|
| 周一 |  |  |  |  |  |  |  |  |
| 周二 |  |  |  |  |  |  |  |  |
| 周三 |  |  |  |  |  |  |  |  |
| 周四 |  |  |  |  |  |  |  |  |
| 周五 |  |  |  |  |  |  |  |  |

## 3. 告警运营摘要

| 指标 | 数量 | 说明 |
|---|---:|---|
| 新增告警 |  |  |
| Critical |  |  |
| High |  |  |
| Medium |  |  |
| Low |  |  |
| 已关闭 |  |  |
| 研判中 |  |  |
| 误报 / 演练 |  |  |
| dry-run 响应动作 |  |  |

## 4. 重点事件

| 时间 | 告警 / 问题编号 | 级别 | 影响 | 处置 | 当前状态 | 责任人 |
|---|---|---|---|---|---|---|
|  |  |  |  |  |  |  |

## 5. Redis Stream 和消费状态

- 本周最大 XLEN：
- 本周最大 XPENDING：
- 本周最大 lag：
- 是否出现持续堆积：是 / 否
- 处置记录：

## 6. 模型和检测状态

- 模型完整性：通过 / 不通过
- 模型 SHA256 是否一致：是 / 否
- `guardian_model_ready`：1 / 0 / 未启用 full-chain
- 本周误报观察：
- 本周漏报或客户反馈：

## 7. 通知状态

- 邮件通道：启用 / 未启用 / 异常
- Webhook 通道：启用 / 未启用 / 异常
- 通知失败次数：
- notify retry 未完成数：
- 需客户处理事项：

## 8. 审计和备份

- 审计完整性：通过 / 不通过
- 审计异常：
- 最近一次 PostgreSQL 备份时间：
- 最近一次备份 SHA256 校验：通过 / 不通过
- 最近一次恢复抽检：通过 / 未执行 / 不通过
- RTO/RPO 观察：

## 9. 问题清单

| 编号 | 优先级 | 描述 | 根因分类 | 规避方案 | 修复计划 | 状态 | 责任人 |
|---|---|---|---|---|---|---|---|
|  |  |  |  |  |  |  |  |

## 10. 下周计划

- 运行和巡检：
- 告警运营：
- 规则 / IOC / 白名单：
- 通知和集成：
- 备份恢复：
- 客户待办：
- 交付团队待办：

## 11. 风险和决策请求

| 风险 / 决策 | 影响 | 建议 | 需要谁确认 | 目标日期 |
|---|---|---|---|---|
|  |  |  |  |  |
```

## 16. 运行期交付物

试点运行期建议持续归档以下材料：

- 每日 `customer-beta-ops-checklog.md`
- 每周周报
- P0/P1/P2 问题单和关闭确认
- readiness 输出
- Redis Stream 状态
- 模型 SHA256
- 审计完整性结果
- 备份 SHA256 和恢复抽检记录
- dry-run 响应演练 JSON
- 客户确认的变更单、审批单和会议纪要

试点结束时，上述材料应汇总到 `templates/customer-beta-evidence-index.md`，并作为验收或扩大试点的依据。
