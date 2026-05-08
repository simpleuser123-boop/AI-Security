# 单企业私有化 Beta 全流程演练报告

演练日期：2026-05-07  
项目目录：`C:\Users\yyl\Desktop\ai安全\ai-security-guardian`  
演练目标：验证 ai-security-guardian 在单企业私有化 Beta 交付前的部署、迁移、依赖、模型、健康检查、验收、压测、备份恢复、审计完整性和误封恢复闭环。

## 1. 演练范围与环境

本次演练采用“当前机器可执行项 + 既有隔离演练证据复核”的方式：

- Web/API 本地演练进程：`python -m web.app`，监听 `http://127.0.0.1:5057`。
- 数据库：隔离 PostgreSQL 容器 `guardian-task4-postgres`，库 `guardian`，恢复演练库 `guardian_restore_drill_20260506`。
- Redis：Docker Compose 服务 `ai-security-guardian-redis`，仅绑定 `127.0.0.1:6379`。
- 模型目录：`models/saved`。
- 审计日志：`logs/production/security.log` 与 legacy `logs/security.log` 校验。
- 搜索与文档读取已避开 `.venv`、`.tmp`、`node_modules`、`.git` 等目录；`rg` 在当前桌面环境被拒绝访问后，改用 PowerShell 文件搜索。

本次未修改业务代码；仅生成本报告和临时压测报告。

## 2. 执行摘要

总体结论：Beta 演练“有条件通过”。核心功能、迁移、模型、健康检查、验收脚本、HTTP 健康端点压测、备份恢复、审计哈希链、误封恢复单测均具备可交付基础；当前 `.env` 仍不满足真实私有化 Beta 配置门禁，Redis Stream consumer 对空流阻塞超时的处理会影响共享 Redis 客户端 readiness，需要在交付前整改。

关键结果：

- `scripts/check_production_readiness.py`：失败，3 个 failure、1 个 warning。
- PostgreSQL 迁移版本：`20260506_0001`，表数量 11。
- Redis 进程级带密码检查：可用，`xlen=0`，`xpending=0`，`lag=0`。
- 模型就绪：必需模型缺失列表为空，manifest 数量 4。
- `/healthz`：HTTP 200。
- `/readyz`：HTTP 200，`database/redis/config/models` 均 ok（关闭 consumer 自动启动后）。
- `/metrics`：HTTP 200，包含 `guardian_model_ready`、`redis_stream_*`、`audit_integrity_valid`。
- `verify_v1.py`：场景 1-9 全部 PASS。
- 场景 10：`python -m pytest -m e2e tests\e2e\test_v1_acceptance.py::test_10_web_restart_alerts -q` PASS。
- `benchmark_http.py`：40 请求、4 worker，整体 P95 `59.55ms`，错误率 `0.00%`，核心 API 目标 PASS。
- 审计哈希链：当前 legacy 日志校验 `valid=True`，6 行；生产日志当前为空基线，`valid=True`。
- 误封恢复相关测试：5 项 PASS。

## 3. 通过项

### 3.1 数据库迁移

复核对象：隔离 PostgreSQL 容器 `guardian-task4-postgres`。

执行结果：

```text
version_num = 20260506_0001
public_table_count = 11
```

恢复演练库 `guardian_restore_drill_20260506` 表清单：

```text
alembic_version
alert_histories
alerts
audit_events
banned_ips
iocs
model_versions
response_actions
response_schedule_tasks
rules
settings
```

结论：迁移和恢复库 schema 校验通过。

### 3.2 Redis 检查

Docker 状态：

```text
ai-security-guardian-redis   redis:7-alpine   Up 45 hours (healthy)   127.0.0.1:6379->6379/tcp
```

项目脚本在显式注入 `.env` Redis 密码后输出：

```json
{
  "available": true,
  "mode": "redis",
  "host": "127.0.0.1",
  "port": 6379,
  "xlen": 0,
  "xpending": 0,
  "lag": 0
}
```

结论：Redis 服务和密码认证可用；无堆积。

### 3.3 模型就绪检查

执行最小模型检查：

```text
MODEL_DIR= models/saved
missing= []
manifest_count= 4
```

结论：关键模型文件和 manifest 已就绪。

### 3.4 Web/API 启动与健康检查

本地 Beta 演练进程使用 PostgreSQL、Redis、`DRY_RUN=true`、正式格式 HTTPS Origin 和必需 runtime guard 启动。

初次启动使用错误 DB 密码时，`/readyz` 正确返回 unready；修正 DB 连接后，关闭 `ALERT_STREAM_CONSUMER_AUTOSTART` 再启动，结果：

```json
{
  "status": "ready",
  "checks": {
    "config": {"ok": true, "detail": "ok"},
    "database": {"ok": true, "detail": "ok"},
    "redis": {"ok": true, "detail": "ok", "mode": "redis"},
    "models": {"ok": true, "detail": "model_dir_nonempty_no_guardian_heartbeat"}
  },
  "degraded": []
}
```

`/healthz` 返回：

```json
{"component":"ai-security-guardian-web","status":"live"}
```

`/metrics` 返回 HTTP 200，关键指标：

```text
guardian_model_ready 0
redis_stream_pending 0
redis_stream_length 0
redis_stream_group_lag 0
audit_integrity_valid 1
```

结论：Web/API 健康端点可用；metrics 格式可被 Prometheus 采集。

### 3.5 verify_v1.py 与 E2E 场景 10

`python scripts\verify_v1.py`：

```text
[PASS] 1 正常 Web /api/items?id=1 无误报
[PASS] 2 SQL 注入 -> web_attack high
[PASS] 3 双层编码 XSS -> web_attack high
[PASS] 4 命令注入 -> web_attack high
[PASS] 5 IOC 黑名单 -> threat_intel 语义
[PASS] 6 SYN 突增 -> anomaly/(或 ddos)
[PASS] 8 Redis 中断 -> 客户端降级 memory
[PASS] 7 模型缺失：其余引擎继续
[PASS] 9 审计篡改 -> 完整性失败
```

场景 10：

```text
python -m pytest -m e2e tests\e2e\test_v1_acceptance.py::test_10_web_restart_alerts -q
. [100%]
```

结论：v1 验收场景通过。场景 10 需要显式 `-m e2e`，否则会被默认 pytest marker 过滤。

### 3.6 benchmark_http.py

命令：

```powershell
python scripts\benchmark_http.py `
  --base-url http://127.0.0.1:5057 `
  --endpoints /api/health,/healthz,/readyz,/metrics `
  --no-auth `
  --requests 40 `
  --workers 4 `
  --warmup-requests 4 `
  --detect-iters 50 `
  --output-dir tmp\beta-drill-benchmarks `
  --report-prefix beta-drill-http
```

结果：

```text
HTTP overall: requests=40 avg=31.93ms p50=29.63ms p95=59.55ms p99=68.24ms error_rate=0.00% status={'200': 40}
Detection segment: p95=0.010ms target<100ms PASS
Production target: core_api_p95<300ms PASS
```

报告文件：

- `tmp\beta-drill-benchmarks\beta-drill-http-20260507-131716.json`
- `tmp\beta-drill-benchmarks\beta-drill-http-20260507-131716.md`

结论：匿名健康与观测端点性能通过；因当前环境未提供明文管理员密码或 JWT，本次未覆盖需要认证的业务 API 压测。

### 3.7 备份恢复

复核历史 PostgreSQL dump：

```text
backup = backups\20260506-task4-db-drill\guardian-task4-20260506.dump
sha256 = 626FB8059F442D06220FA8A6BEF4415DAB202C28A2DB44FFC0D93DDFA0541D99
```

`Get-FileHash` 与 `.sha256` 文件一致。恢复库 `guardian_restore_drill_20260506` 已存在并可查询，迁移版本和表清单正确。

结论：数据库备份文件可校验、可恢复、可读 schema。

### 3.8 审计哈希链校验

手工校验 legacy 日志：

```text
{'valid': True, 'total_lines': 6, 'invalid_lines': []}
```

`/metrics` 中：

```text
audit_integrity_valid 1
```

结论：当前审计哈希链校验通过。归档与基线重建流程已在 `docs/audit-log-baseline.md` 描述。

### 3.9 误封恢复流程

执行测试：

```powershell
python -m pytest `
  tests\test_responder.py::TestUnban `
  tests\test_responder.py::TestApprovalFlow::test_manual_unblock_requires_executed_then_records_order `
  tests\test_responder.py::TestWebAttackResponseActions::test_business_whitelist_protects_from_auto_ban `
  -q
```

结果：

```text
..... [100%]
```

覆盖内容：

- 已封禁 IP 可解封。
- 误封回滚记录 operator 与 reason。
- 手工解封必须在已执行封禁后形成正确状态链。
- 业务白名单可阻止自动封禁。

结论：误封恢复的核心逻辑有测试覆盖；生产真实 iptables 或云安全组解封需在客户授权主机另行实操。

## 4. 失败项

### 4.1 Private Beta readiness 当前失败

命令：

```powershell
python scripts\check_production_readiness.py
```

结果：

```text
Result: FAIL (3 failure(s), 1 warning(s))
```

失败原因：

- `DATABASE_URL` 仍包含示例、开发、测试或占位数据库配置。
- `ALLOWED_ORIGINS` 仍是占位域名：`https://REPLACE_WITH_PRIVATE_BETA_FQDN`。
- `DB_CONNECTIVITY` 失败：PostgreSQL `SELECT 1` 不可达。
- `DRY_RUN=false` 在 private-beta gate 下为 warning，提示真实封禁需要单独审批。

结论：当前 `.env` 不能直接作为单企业私有化 Beta 交付配置。

### 4.2 Web Stream consumer 会导致 Redis readiness 失败

使用默认 `ALERT_STREAM_CONSUMER_AUTOSTART=true` 启动 Web/API 后，日志出现：

```text
[RedisClient] xreadgroup 失败降级: Timeout reading from socket
[RedisClient] 切换为内存降级模式
```

随后 `/readyz` 返回 503，fatal 包含：

```text
database
redis
```

修正数据库密码后，DB 可通过；但 Redis 仍会因 consumer 对空流的阻塞读超时而把共享客户端降级为 memory，影响 `/readyz`。关闭 consumer 自动启动后 `/readyz` 通过。

结论：这是本次演练发现的真实缺陷或配置风险。生产不应让消费者的空流长轮询超时污染健康检查使用的 Redis 客户端。

### 4.3 Docker app 镜像未在本次重新构建

历史演练 `docs/deployment-drill-20260505.md` 记录：Docker Hub OAuth token 请求超时，无法拉取 `python:3.10-slim` 元数据，导致 app 镜像构建失败。本次未重新构建 app 镜像，仅复核 Docker、Redis、PostgreSQL 容器状态并用本地进程覆盖 Web/API。

结论：空环境部署的 Docker app 构建仍需在可访问镜像源或企业内网 registry 环境中重新演练。

## 5. 风险项

1. 当前 `.env` 存在占位 PostgreSQL host、占位 CORS 域名和 `DRY_RUN=false`，有误上线风险。
2. Compose 解析 `ADMIN_PASSWORD_HASH` 中 `$` 时持续出现变量插值 warning，可能导致合成配置中的哈希被截断。
3. `/metrics` 中 `guardian_model_ready 0`，模型目录虽非空，但没有 Guardian heartbeat；如果启用完整 Guardian 链路，应看到模型 ready 信号大于 0。
4. 本次 HTTP 压测只覆盖匿名健康端点，没有覆盖登录后核心业务 API。
5. `python -m web.app` 是开发启动方式；生产容器需使用 Dockerfile 中的 gunicorn 路径再验证。
6. 真实抓包、真实封禁、iptables 解封、Nginx TLS/WSS 未在当前 Windows 本机执行，只能作为客户授权环境演练步骤。
7. Redis Stream consumer 有共享客户端降级风险，可能造成健康检查误报 unready，也可能影响 Web 告警入库实时性。

## 6. 整改建议

1. 交付前生成客户专用 `.env`：替换正式 PostgreSQL、正式 HTTPS Origin、强密钥、Redis 密码；将 `DRY_RUN=true` 作为 Beta 默认值。
2. 修复或规避 Redis Stream consumer 降级问题：consumer 使用独立 RedisClient；空流 `XREADGROUP BLOCK` 超时不应调用 `_degrade()`；或将 `REDIS_SOCKET_TIMEOUT_SEC` 大于 consumer block 时间。
3. 修复 Compose 哈希插值：对 `.env` 中 `ADMIN_PASSWORD_HASH` 的 `$` 做 Compose 兼容转义，或避免在 Compose `environment` 中重复展开该变量。
4. 在企业内网 registry 或 Docker mirror 可用后，重新执行空环境 Docker app 构建、`docker compose up -d app guardian` 和容器内 `/readyz`。
5. 为 `benchmark_http.py` 准备一次性测试账号密码或 JWT，补跑认证 API：`/api/alerts`、`/api/stats`、`/api/rules`、`/api/settings`。
6. 启动 `guardian` full-chain profile 后复核 `/metrics` 中 `guardian_model_ready > 0`，并验证 Redis Stream `XLEN/XPENDING/XINFO GROUPS` 在流量下不持续增长。
7. 真实封禁上线前保持单独 gate：执行 `python scripts/check_production_readiness.py --gate real-enforcement`，并补齐审批、白名单、审计、回滚、解封和复盘证据。
8. 将备份恢复纳入发布清单：每次上线前保留 DB dump、`.env` SHA256、模型 SHA256、审计日志归档校验、镜像 tag 和回滚指令。

## 7. Beta 演练判定

有条件通过。

可进入单企业私有化 Beta 的前提：

- 客户环境 `.env` readiness 无 failure。
- Redis Stream consumer 降级问题完成修复或以独立客户端/超时配置规避，并在默认 autostart 下 `/readyz` 通过。
- Docker app 镜像在目标环境完成空环境部署演练。
- Beta 阶段保持 `DRY_RUN=true`，真实封禁不随 Beta 默认开放。

在上述整改完成前，不建议将当前仓库根目录 `.env` 直接作为客户 Beta 发布配置。
