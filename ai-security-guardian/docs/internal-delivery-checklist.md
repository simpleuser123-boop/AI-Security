# 内部交付清单：无需客户资料即可完成

本文档只覆盖内部可在本地或隔离环境完成的交付验收准备。客户正式域名、客户数据库、客户 Redis、客户网卡/抓包授权、客户业务 IP 白名单、客户证书、客户真实流量和客户部署窗口不写入内部完成项。

所有命令默认在项目根目录执行：

```powershell
cd C:\Users\yyl\.codex\worktrees\89f2\ai安全\ai-security-guardian
```

## 当前项目状态

| 项目 | 当前状态 | 明确证据 |
|---|---|---|
| 配置模板 | 已存在 `.env.host-nondegraded.example` 和 `.env.prod-drill.example`，分别用于宿主机非降级测试与 Compose prod-drill | `Test-Path .env.host-nondegraded.example; Test-Path .env.prod-drill.example` |
| 模型制品 | `models/saved` 已包含 4 个模型、4 个 manifest 和 3 个入侵检测辅助文件 | `Get-ChildItem models\saved | Select-Object Name,Length` |
| 数据库 | 已有 Alembic 迁移入口和本地 PostgreSQL 依赖栈 | `Test-Path migrations\versions\20260506_0001_initial_schema.py; Test-Path docker-compose.local-deps.yml` |
| Redis | 已有本地 Redis 依赖栈、Stream 状态脚本和真实 Redis 集成测试 | `Test-Path scripts\redis_stream_status.py; Test-Path tests\test_alert_stream_redis.py` |
| Docker | 已有 `Dockerfile`、`docker-compose.yml`、`docker-compose.prod-drill.yml` | `Test-Path Dockerfile; Test-Path docker-compose.yml; Test-Path docker-compose.prod-drill.yml` |
| 压测 | 已有进程内 P95 和 HTTP/API 压测脚本，已有 `reports/benchmarks/` 产物 | `Test-Path scripts\benchmark_p95.py; Test-Path scripts\benchmark_http.py; Get-ChildItem reports\benchmarks -ErrorAction SilentlyContinue` |
| 回滚/解封 SOP | 已有客户部署手册中的回滚与误封恢复章节；本清单下方提供内部 SOP 模板验收 | `Select-String -Path docs\deployment.md -Pattern "应用镜像回滚","防火墙误封恢复"` |

## 内部任务项与验收

> 当前状态只按已有测试/报告记录填写。命令存在、脚本可运行或 readiness 单项 PASS，不等于生产验收已完成；若真实结果出现 schema 缺失、429/500、Redis memory fallback 或 env 口径混用，本清单必须记录为失败或待修复。

### 1. 配置基线

| 任务项 | 验收命令 | 真实验收口径 | 当前状态 | 责任边界 |
|---|---|---|---|---|
| 检查本地依赖环境配置不引用客户资料 | `Select-String -Path .env.host-nondegraded.example,.env.prod-drill.example -Pattern "customer|客户|example.com|REPLACE_ME|127.0.0.1|guardian.localtest|postgres|redis"` | 输出只允许出现本地地址、`guardian.localtest`、Compose 服务名或注释说明；不得出现客户域名、客户 IP、客户库名、客户密钥 | 待复核 | 内部可完成 |
| 渲染本地生产演练 Compose | `docker compose --env-file .env.prod-drill.example -f docker-compose.yml -f docker-compose.prod-drill.yml config > tmp\internal-prod-drill-compose.yml` | 命令退出码为 `0`；`tmp\internal-prod-drill-compose.yml` 存在；容器内 `DATABASE_URL` 使用 `postgres`，`REDIS_HOST` 使用 `redis`；`app` 端口只绑定 `127.0.0.1:5000:5000` | 待复核 | 内部可完成 |
| 校验生产式配置 gate | `docker compose --env-file .env.prod-drill.example -f docker-compose.yml -f docker-compose.prod-drill.yml run --rm app python scripts/check_production_readiness.py --skip-env-file` | readiness 输出无 `[FAIL]` 只代表配置/依赖探针通过；不得打印明文密码、密钥、管理员哈希；不得把该项单独写成 schema 验收通过 | 待复核 | 内部可完成 |
| 数据库 schema readiness | `docker compose --env-file .env.prod-drill.example -f docker-compose.yml -f docker-compose.prod-drill.yml exec -T app python web/init_db.py --check`；必要时补充 `docker compose --env-file .env.prod-drill.example -f docker-compose.yml -f docker-compose.prod-drill.yml run --rm app flask --app web.migration_app:create_migration_app db current` | 必须证明业务表/列和 Alembic revision 已存在且在 head；若 `/readyz` 或 readiness PASS 但该命令发现 schema 缺失，数据库 schema 验收仍为失败 | 失败/待修复：已有测试结论指出 readiness PASS 不能覆盖 schema 缺失 | 内部可完成 |
| 客户正式配置准入 | 不作为内部完成项 | 客户提供正式域名、生产 PostgreSQL、Redis 密码、管理员哈希后，另行执行 `python scripts/check_production_readiness.py --env-file <客户环境文件>` 且无 `[FAIL]`，并单独完成 schema readiness | 待客户资料 | 需要客户资料 |

### 2. 模型制品

| 任务项 | 验收命令 | 通过标准 | 责任边界 |
|---|---|---|---|
| 检查必需模型文件完整 | `python -c "import os,sys; d='models/saved'; req=['intrusion_rf_v1.pkl','ddos_rf_v1.pkl','web_attack_nb_v1.pkl','anomaly_if_v1.pkl','intrusion_feature_cols_v1.pkl','intrusion_label_encoder_v1.pkl','intrusion_scaler_v1.pkl','intrusion_rf_v1.model_manifest.json','ddos_rf_v1.model_manifest.json','web_attack_nb_v1.model_manifest.json','anomaly_if_v1.model_manifest.json']; miss=[x for x in req if not os.path.isfile(os.path.join(d,x))]; print('missing=',miss); sys.exit(1 if miss else 0)"` | `missing=[]`，退出码为 `0` | 内部可完成 |
| 生成模型 SHA256 清单 | `New-Item -ItemType Directory -Force tmp | Out-Null; Get-FileHash models\saved\* | Sort-Object Path | Format-Table -AutoSize | Out-File tmp\model-sha256-internal.txt` | `tmp\model-sha256-internal.txt` 存在且包含 `models\saved` 下全部文件 | 内部可完成 |
| 校验 manifest/registry | `python -m pytest tests\test_schema_manifest.py tests\test_model_registry.py -q` | pytest 退出码为 `0` | 内部可完成 |
| 重新训练模型 | 不作为内部交付清单任务 | 当前任务禁止跑模型训练；如未来需要重新训练，应单独立项并记录数据来源、训练命令、指标和制品 SHA256 | 当前阻塞，另行立项 |

### 3. 数据库

| 任务项 | 验收命令 | 真实验收口径 | 当前状态 | 责任边界 |
|---|---|---|---|---|
| 启动本地 PostgreSQL/Redis 依赖栈 | `python scripts\start_local_deps.py --env-file .env.host-nondegraded.example` | 端口空闲时启动并等待 healthy；端口已被健康依赖占用时明确复用；端口冲突且不可复用时明确失败并清理本项目 Created 容器 | 待复核 | 内部可完成 |
| 校验应用连接真实 PostgreSQL 和真实 Redis | `python scripts\verify_local_deps.py .env.host-nondegraded.example` | 输出包含 `PostgreSQL connected`、`Redis AUTH PING: PONG`、`Application DATABASE_URL backend: postgresql`、`RedisClient mode: redis`，退出码为 `0`；若使用 `--port-strategy alternate`，必须改用 `tmp\local-deps.env`；若误用 `.env.prod-drill.example`，脚本必须提示需要 `127.0.0.1` | 待复核 | 内部可完成 |
| 宿主机 env 与 Compose env 隔离 | `python scripts\verify_local_deps.py .env.host-nondegraded.example`；`docker compose --env-file .env.prod-drill.example -f docker-compose.yml -f docker-compose.prod-drill.yml config` | 宿主机测试只用 `127.0.0.1` 端口；Compose prod-drill 只用服务名 `postgres`/`redis`；不得交叉复用 env 文件或把一种口径的 PASS 写成另一种口径通过 | 待复核 | 内部可完成 |
| 校验迁移可重复执行 | `$env:DATABASE_URL="postgresql+psycopg2://guardian:guardian-local-postgres-pass@127.0.0.1:55432/guardian_local_test"; python -m pytest tests\test_database_migrations.py -q` | pytest 退出码为 `0`；测试证明 `flask db upgrade` 可重复执行且不破坏探针数据 | 待复核 | 内部可完成 |
| PostgreSQL 非降级测试无 Redis fallback 残留 | `python scripts\run_non_degraded_tests.py` | 测试必须同时使用真实 PostgreSQL 和真实 Redis；`RedisClient mode` 必须为 `redis`；不得设置 `GUARDIAN_REDIS_DISABLE_CONNECT=true`；不得出现 Redis memory fallback 或 skip 后仍记为通过 | 失败/待修复：已有结论指出 PostgreSQL 测试仍有 Redis 降级残留，不能列为通过 | 内部可完成 |
| 客户生产库初始化/迁移 | 不作为内部完成项 | 需客户提供 PostgreSQL 地址、账号、网络访问和变更窗口后执行迁移；内部只提供命令模板 | 待客户资料 | 需要客户资料 |

### 4. Redis 与告警流

| 任务项 | 验收命令 | 通过标准 | 责任边界 |
|---|---|---|---|
| 校验本地 Redis 密码访问 | `$env:REDIS_HOST="127.0.0.1"; $env:REDIS_PORT="56379"; $env:REDIS_DB="0"; $env:REDIS_PASSWORD="guardian-local-redis-pass"; python scripts\redis_stream_status.py --json` | 命令退出码为 `0`；输出为 JSON；不得使用 memory fallback 作为通过标准 | 内部可完成 |
| 校验 Redis Stream consumer 入库、ACK、Socket.IO | `$env:REDIS_HOST="127.0.0.1"; $env:REDIS_PORT="56379"; $env:REDIS_TEST_DB="15"; $env:REDIS_PASSWORD="guardian-local-redis-pass"; $env:REQUIRE_REDIS_AVAILABLE="true"; $env:GUARDIAN_REDIS_DISABLE_CONNECT="false"; python -m pytest -m integration tests\test_alert_stream_redis.py -q -rA` | pytest 退出码为 `0`；输出不得全部 skip；通过项包含持久化、重复消息幂等、Web 重启可查、Socket.IO 收到告警 | 内部可完成 |
| 校验 staged drill 闭环 | `$env:REDIS_HOST="127.0.0.1"; $env:REDIS_PORT="56379"; $env:REDIS_PASSWORD="guardian-local-redis-pass"; python scripts\staging_drill.py --cleanup` | 输出包含 `Guardian wrote Redis Stream`、`Web consumer persisted alert`、`Web consumer acked message`、`Socket.IO alert event observed`、`Web restart history query returned the alert`、`XPENDING=0` | 内部可完成 |
| 客户 Redis 暴露面、ACL、运维监控 | 不作为内部完成项 | 需客户提供 Redis 部署方式、网络边界、密码/ACL、监控平台后验收 | 需要客户资料 |

### 5. 测试

| 任务项 | 验收命令 | 真实验收口径 | 当前状态 | 责任边界 |
|---|---|---|---|---|
| 默认离线回归 | `python -m pytest -q` | pytest 退出码为 `0`；该项只证明离线逻辑回归，不作为数据库/Redis/模型真实依赖通过标准 | 待复核 | 内部可完成 |
| 关键安全硬化 | `python -m pytest tests\test_production_hardening.py tests\test_responder.py tests\test_response_r4.py -q` | pytest 退出码为 `0` | 待复核 | 内部可完成 |
| E2E 非降级生产验收 | `python -m pytest -m production_e2e -q` | pytest 退出码为 `0`；模型制品完整；不得设置 `GUARDIAN_REDIS_DISABLE_CONNECT=true`；不得使用 Redis memory fallback；不得包含模型缺失或 Redis 中断降级场景 | 待复核 | 内部可完成 |
| E2E 降级容灾验证 | `python -m pytest -m degradation_e2e -q` | pytest 退出码为 `0` 只证明模型缺失、Redis 中断等容灾路径有效；不得列入生产验收通过标准 | 待复核，不计入生产通过 | 内部说明 |
| 现有降级脚本使用边界 | `python scripts\verify_v1.py` | 该命令包含模型缺失和 Redis memory fallback 场景；即使整体 PASS，也不能作为本清单生产验收通过标准 | 不作为生产验收 | 内部说明 |
| 客户现场 E2E | 不作为内部完成项 | 需客户环境、域名、账号、TLS/WSS、真实数据库/Redis 后执行 | 待客户资料 | 需要客户资料 |

### 6. 压测

| 任务项 | 验收命令 | 真实验收口径 | 当前状态 | 责任边界 |
|---|---|---|---|---|
| 检测段进程内 P95 | `python scripts\benchmark_p95.py --detect-iters 400 --requests 1 --workers 1` | 输出检测段 `P95 < 100 ms`；HTTP 部分如服务未启动可不作为本项通过标准 | 通过：既有报告显示 detection segment P95 < 100ms | 内部可完成 |
| HTTP/API 压测准备 | `docker compose --env-file .env.prod-drill.example -f docker-compose.yml -f docker-compose.prod-drill.yml up -d --wait` | `db-migrate` 已成功退出；`app`、`redis`、`postgres` 健康检查通过；`docker compose --env-file .env.prod-drill.example -f docker-compose.yml -f docker-compose.prod-drill.yml exec -T app python web/init_db.py --check` 退出码为 `0`；不得只用 `/readyz` PASS 代替 schema 检查 | 失败/待修复：schema 缺失问题未关闭 | 内部可完成 |
| HTTP/API P95，1000 请求/32 workers | `$jwt = docker compose --env-file .env.prod-drill.example -f docker-compose.yml -f docker-compose.prod-drill.yml exec -T app python -c "from web.app import create_app; from flask_jwt_extended import create_access_token; app,_=create_app(); ctx=app.app_context(); ctx.push(); print(create_access_token(identity='benchmark', additional_claims={'role':'admin'})); ctx.pop()"; python scripts\benchmark_http.py --base-url http://127.0.0.1:5000 --jwt-token $jwt --requests 1000 --workers 32 --warmup-requests 100` | 必须无 429/5xx，错误率 0，核心 API P95 < 300ms，且生成 JSON/Markdown 报告 | 失败：`reports/benchmarks/http-benchmark-20260508-210101.md` 记录 `429=78`、`500=631`、错误率 70.90%，不能写成已通过 |
| HTTP/API 受限样本，200 请求/8 workers/8 RPS | `BENCHMARK_USERNAME=<USER> BENCHMARK_PASSWORD='<PASSWORD>' python scripts\benchmark_http.py --scenario performance --base-url http://127.0.0.1:5000 --requests 200 --workers 8 --target-rps 8 --warmup-requests 0 --report-prefix http-benchmark-performance` | 只证明该受限负载样本无 429/5xx 且 P95 达标；不得外推为 1000/32 或客户容量通过 | 通过：`reports/benchmarks/http-benchmark-performance-20260508-224357.md` 显示 200 全部 200、无 429/5xx、P95 达标 |
| 限流验证 | `BENCHMARK_USERNAME=<USER> BENCHMARK_PASSWORD='<PASSWORD>' python scripts\benchmark_http.py --scenario rate-limit --base-url http://127.0.0.1:5000 --endpoints /api/stats --requests 6 --workers 3 --warmup-requests 0 --report-prefix http-benchmark-ratelimit` | 429 出现只证明限流生效；不得作为性能压测通过条件 | 通过但不计入性能验收：`reports/benchmarks/http-benchmark-ratelimit-20260508-224534.md` 记录 `429=4` |
| 客户真实流量容量基线 | 不作为内部完成项 | 需客户流量模型、并发量、部署规格和压测窗口后执行 | 待客户资料 | 需要客户资料 |

### 7. Docker

| 任务项 | 验收命令 | 通过标准 | 责任边界 |
|---|---|---|---|
| 构建镜像 | `docker compose --env-file .env.prod-drill.example -f docker-compose.yml -f docker-compose.prod-drill.yml build app` | 命令退出码为 `0`；`docker image inspect ai-security-guardian:latest --format "{{.Id}}"` 能输出镜像 ID | 内部可完成 |
| 生产式本地启动 | `docker compose --env-file .env.prod-drill.example -f docker-compose.yml -f docker-compose.prod-drill.yml down -v; docker compose --env-file .env.prod-drill.example -f docker-compose.yml -f docker-compose.prod-drill.yml up -d --wait` | 从空 PostgreSQL volume 启动；`db-migrate` 先完成 Alembic upgrade 与 `web/init_db.py --check`；`curl.exe -fsS http://127.0.0.1:5000/readyz` 退出码为 `0` | 内部可完成 |
| Compose 证据归档 | `New-Item -ItemType Directory -Force tmp | Out-Null; docker compose --env-file .env.prod-drill.example -f docker-compose.yml -f docker-compose.prod-drill.yml ps > tmp\compose-ps-internal.txt; docker image inspect ai-security-guardian:latest --format "{{.Id}}" > tmp\image-id-internal.txt` | `tmp\compose-ps-internal.txt` 和 `tmp\image-id-internal.txt` 存在且非空 | 内部可完成 |
| 客户部署 | 不作为内部完成项 | 需客户主机、镜像仓库策略、TLS 入口、端口策略、部署窗口 | 需要客户资料 |

### 8. 回滚 SOP 模板

| 任务项 | 验收命令 | 通过标准 | 责任边界 |
|---|---|---|---|
| 生成内部回滚证据目录模板 | `New-Item -ItemType Directory -Force tmp\rollback-template | Out-Null; docker compose --env-file .env.prod-drill.example -f docker-compose.yml -f docker-compose.prod-drill.yml ps > tmp\rollback-template\compose-ps.txt; docker image inspect ai-security-guardian:latest --format "{{.Id}}" > tmp\rollback-template\image-id.txt; Get-FileHash .env.prod-drill.example > tmp\rollback-template\env-prod-drill.sha256; Get-FileHash models\saved\* | Sort-Object Path > tmp\rollback-template\models.sha256` | 目录 `tmp\rollback-template` 下 4 个证据文件存在且非空 | 内部可完成 |
| 验证应用镜像回滚模板命令可执行 | `docker image inspect ai-security-guardian:latest --format "{{.RepoTags}} {{.Id}}"` | 输出包含 `ai-security-guardian:latest` 和镜像 ID；实际旧 tag 回滚需发布时提供旧 tag | 内部可完成模板 |
| 验证模型回滚模板证据 | `Get-FileHash models\saved\* | Sort-Object Path | Out-File tmp\rollback-template\models.before.sha256` | `tmp\rollback-template\models.before.sha256` 存在且包含所有模型与 manifest | 内部可完成模板 |
| 客户生产回滚执行 | 不作为内部完成项 | 需客户发布版本、生产备份点、数据库恢复权限、变更窗口 | 需要客户资料 |

### 9. 解封 SOP 模板

| 任务项 | 验收命令 | 通过标准 | 责任边界 |
|---|---|---|---|
| 静态校验解封相关代码和测试存在 | `Test-Path src\response\firewall.py; Test-Path src\response\ip_policy.py; Test-Path tests\test_responder.py; Test-Path tests\test_response_r4.py` | 四个输出均为 `True` | 内部可完成 |
| 校验响应与 IP 策略测试 | `python -m pytest tests\test_responder.py tests\test_response_r4.py -q` | pytest 退出码为 `0` | 内部可完成 |
| 生成解封 SOP 模板证据 | `New-Item -ItemType Directory -Force tmp\unblock-template | Out-Null; Select-String -Path docs\deployment.md -Pattern "防火墙误封恢复","DRY_RUN=true","iptables -D","RESPONSE_BUSINESS_IP_WHITELIST" | Out-File tmp\unblock-template\unblock-sop-source.txt` | `tmp\unblock-template\unblock-sop-source.txt` 存在且包含止血、删除规则、白名单、复验四类关键字 | 内部可完成模板 |
| 客户真实解封演练 | 不作为内部完成项 | 需客户业务 IP 白名单、真实封禁后端、运维权限、审批记录；不得用降级测试代替 | 需要客户资料 |

## 当前阻塞项

| 阻塞项 | 阻塞范围 | 解除条件 | 内部可先完成的证据 |
|---|---|---|---|
| 本任务未执行完整验收命令 | 仅阻塞“已验收通过”结论，不阻塞清单交付 | 后续按本文命令逐项执行并保存输出 | 本文档本身、命令清单、边界说明 |
| readiness PASS 但 schema 缺失 | 阻塞数据库 schema、Docker 启动和 HTTP/API 压测通过结论 | `web/init_db.py --check` 和 Alembic revision 检查均通过后，才能把 schema readiness 写为通过 | readiness 输出、schema 检查命令和失败记录 |
| 1000/32 HTTP 压测出现 429/500 | 阻塞容量与性能验收通过结论 | 压测报告必须无 429/5xx、错误率 0 且 P95 达标 | `reports/benchmarks/http-benchmark-20260508-210101.md` 失败证据 |
| E2E 与降级场景边界需保持分离 | 阻塞把 `verify_v1.py` 或 `degradation_e2e` 写成生产验收通过 | 生产验收只引用 `production_e2e`；降级场景单列为容灾验证 | `tests/e2e/test_v1_acceptance.py` marker 分组 |
| 宿主机 env 与 Compose env 不得混用 | 阻塞本地真实依赖和 Compose prod-drill 交叉验收结论 | 宿主机命令使用 `.env.host-nondegraded.example` 或 `tmp/local-deps.env`；Compose 命令使用 `.env.prod-drill.example` | `docs/local-real-dependencies.md`、本文命令 |
| PostgreSQL 测试仍有 Redis 降级残留 | 阻塞非降级数据库/Redis 集成验收通过结论 | `python scripts\run_non_degraded_tests.py` 证明 Redis 为真实连接、无 memory fallback、无 skip | 非降级测试输出 |
| 客户正式域名和证书未提供 | 阻塞客户 `ALLOWED_ORIGINS`、TLS/WSS、Nginx 证据 | 客户提供正式 HTTPS Origin、证书和入口策略 | `.env.prod-drill.example` 与本地 `guardian.localtest` 配置证据 |
| 客户 PostgreSQL/Redis 信息未提供 | 阻塞客户数据库/Redis 联通与生产 readiness | 客户提供连接串、账号、密码/ACL、网络放通 | `docker-compose.local-deps.yml`、`.env.host-nondegraded.example` 和 `.env.prod-drill.example` 本地真实依赖证据 |
| 客户抓包授权和网卡范围未提供 | 阻塞 `guardian` full-chain 真实流量检测验收 | 客户提供授权、网卡、主机权限、流量镜像方案 | 本地 Docker profile 和代码路径静态证据 |
| 客户业务 IP 白名单和审批未提供 | 阻塞真实封禁、解封演练和 `--gate real-enforcement` | 客户提供白名单、审批、回滚/解封责任人 | 响应/解封测试和 SOP 模板证据 |
| 客户容量目标未提供 | 阻塞客户容量结论和 SLA 口径 | 客户提供 QPS、并发、数据量、部署规格、压测窗口 | 本地 `benchmark_http.py` 报告与 P95 目标证据 |

## 不作为通过标准的项目

| 项目 | 原因 | 可接受用途 |
|---|---|---|
| Redis memory fallback / Redis 降级测试 | 约束要求不允许把降级测试列为通过标准 | 仅用于研发了解异常路径，不用于本清单验收 |
| 模型缺失后其他引擎继续工作 | 约束要求不允许把降级测试列为通过标准 | 仅用于研发回归，不用于模型交付验收 |
| `python scripts\verify_v1.py` 的整体 PASS | 该脚本当前包含降级场景 7/8 | 可作为补充回归；正式验收使用 `python -m pytest -m production_e2e -q` |
| 客户生产 `.env` 占位值通过 | 会把需要客户资料的信息混入内部完成项 | 内部只验证 `.env.prod-drill.example` 或宿主机非降级依赖栈 |
