# 私有化 Beta 交付清单

本文档面向交付、实施、运维、研发和管理层，用于在客户侧部署一个单企业私有化 Beta 环境。它基于 `README.md`、`docs/deployment.md`、`docs/acceptance-checklist.md`、`docs/staging-drill.md`、`docs/audit-log-baseline.md`、`docker-compose.yml` 和 `.env.example` 汇总形成。

Beta 目标是交付一个可部署、可验收、可回滚、可审计的单企业私有化环境；不承诺多租户、大规模横向扩容、自动化运维平台和完整商业化 SLA。

## 1. 交付范围

### 1.1 Beta 必须交付

| 范围 | Beta 要求 | 交付边界 |
|------|-----------|----------|
| 部署形态 | 单企业、单套私有化环境 | Docker Compose 部署；默认 `app` + `redis`，按授权启用 `guardian` full-chain |
| Web/API 控制台 | 登录、Dashboard、Alerts、Settings、核心 REST API | 生产入口建议经 Nginx TLS/WSS 转发 |
| 检测链路 | Web 攻击检测、IOC 命中、融合决策、模型检测基础链路 | 抓包能力依赖客户主机授权、网卡权限和 `NET_RAW` / `NET_ADMIN` |
| 告警闭环 | 告警入库、状态流转、Web 重启后历史告警可查 | Redis Stream 到 Web consumer 入库链路必须验证 |
| 响应动作 | `DRY_RUN=true` 演练必交付；真实封禁前必须完成误封恢复演练 | Beta 默认不建议首日开启真实封禁 |
| 管理员认证 | `ADMIN_PASSWORD_HASH`、JWT、基础 RBAC | 单管理员或少量角色，非完整 IAM/SSO |
| 审计 | 关键操作写入审计事件，`security.log` 哈希链完整性校验 | 审计归档、基线重建按维护窗口执行 |
| 数据库 | 生产使用 PostgreSQL，迁移由 Flask-Migrate/Alembic 管理 | SQLite 仅限开发、测试、演示 |
| Redis | 密码、内网访问、Stream 堆积观测 | Compose 默认仅宿主机 `127.0.0.1:6379` 发布 |
| 模型 | 关键模型文件、辅助文件、manifest 和 SHA256 清单 | 模型可由制品或受控目录交付，不强制随仓库 |
| 备份恢复 | 数据库、`.env`、模型、日志可备份并完成恢复演练 | 至少完成一次隔离环境恢复演练 |
| 回滚 | 应用镜像、环境变量、数据库、模型、误封恢复路径明确 | 生产变更前必须保留上一版本证据 |
| 验收证据 | 命令输出、截图、SHA256、演练记录、测试报告 | 证据不包含明文密钥、密码或管理员哈希 |

### 1.2 GA 后置能力

| 能力 | 后置原因 | GA 建议 |
|------|----------|---------|
| 多租户 / 多企业隔离 | Beta 目标是单企业私有化 | 引入 tenant 维度、权限边界、租户级审计与配额 |
| 企业 SSO / LDAP / OIDC | 当前为基础管理员认证和 RBAC | 接入企业身份源、组映射、会话治理 |
| 高可用集群 | 当前 Compose 更适合单机或小规模私有化 | PostgreSQL/Redis HA、Web 多实例、Socket.IO 消息队列和粘性会话 |
| 自动化安装器 / 运维控制台 | Beta 以手册和脚本交付为主 | 一键部署、升级、巡检、备份、恢复平台化 |
| 完整通知中心 | 当前通知通道为可选配置和基础重试 | 通知失败可视化、通道健康、企业微信/钉钉/邮件策略编排 |
| 模型运营闭环 | Beta 要求模型可用和版本可追溯 | 模型效果看板、漂移监控、灰度、回滚策略自动化 |
| 定时自动解封 | 验收清单已标注为路线图项 | 解封计划、审批、变更审计和冲突检测 |
| 报告导出增强 | 当前报告基于持久化数据 | 增加审计摘要、CSV/PDF、管理层周期报告 |
| 商业 SLA 与容量模型 | Beta 未覆盖大规模生产容量 | 明确容量分层、压测基线、SLO、应急值班机制 |

## 2. 部署前置条件

### 2.1 主机与网络

- 已安装 Docker Engine 和 Docker Compose Plugin。
- 入口域名、证书、Nginx 或内网负载均衡已准备。
- 对外只开放 `80/443`；`5000` 仅允许本机 Nginx 或内网 LB 访问。
- Redis `6379` 禁止公网访问；Compose 默认绑定 `127.0.0.1:6379`。
- 若启用 `guardian` 抓包，客户需书面授权抓包范围，并确认主机具备真实网卡访问能力。
- 若使用 PostgreSQL 托管库，发布机或容器网络必须能访问数据库地址。

### 2.2 目录规划

生产建议在项目根目录或安装目录下准备：

```bash
mkdir -p data logs models/saved backups release-env
chmod 750 data logs models models/saved backups release-env
chmod 700 backups
```

建议安装根目录：

```bash
/opt/ai-security-guardian
```

Beta 交付人员需确认：

- `data/` 可被 app 容器写入。
- `logs/` 可被 app 和 guardian 写入。
- `models/saved/` 对容器只读挂载，但宿主机可由受控发布人员更新。
- `backups/` 权限收敛，避免备份中的 `.env` 泄漏。

### 2.3 发布包

- 项目代码或镜像包。
- `docker-compose.yml`，必要时包含 `docker-compose.prod.yml` 覆盖端口绑定。
- `.env.example` 和客户环境专用 `.env`。
- 模型文件、manifest、SHA256 清单或制品下载说明。
- 本文档、`docs/deployment.md`、`docs/acceptance-checklist.md`、`docs/staging-drill.md`、`docs/audit-log-baseline.md`。

## 3. 环境变量清单

### 3.1 Beta 必填

| 变量 | Beta 要求 | 示例 / 说明 |
|------|-----------|-------------|
| `FLASK_ENV` | 必须为 `production` | 生产配置 gate 依赖此值 |
| `AUDIT_ENV` | 建议为 `production` | 审计日志进入 `logs/production` |
| `SECRET_KEY` | 必须替换，至少 32 字符 | `python -c "import secrets; print(secrets.token_hex(32))"` |
| `ADMIN_USERNAME` | 必填 | 默认可为 `admin` |
| `ADMIN_PASSWORD_HASH` | 生产必填 | 使用 `python scripts/generate_admin_password_hash.py` |
| `ADMIN_ROLE` | 必填 | `admin` / `analyst` / `viewer` |
| `DATABASE_URL` | 生产必须是可连接 PostgreSQL | `postgresql+psycopg2://...`；缺少真实连接信息时保留占位并让校验失败，禁止伪造通过 |
| `AUTO_CREATE_DB_TABLES` | 必须为 `false` | 生产通过迁移建表 |
| `REDIS_PASSWORD` | 必填，非弱密码 | 与 Redis `requirepass` 一致 |
| `REDIS_DB` | 必填 | 通常为 `0` |
| `ALLOWED_ORIGINS` | 必填，必须是正式 HTTPS Origin | 禁止 `*`、`http://`、localhost、127.0.0.1、占位域名；示例：`https://guardian-console.company.tld` |
| `LOG_INTEGRITY_ENABLED` | 建议 `true` | 审计日志哈希链 |
| `RUNTIME_GUARDS_ENABLED` | Beta 生产必须显式 `true` | runtime guards 总开关 |
| `REQUIRE_REDIS_AVAILABLE` | Beta 生产必须显式 `true` | Redis 不可用则启动失败 |
| `REQUIRE_MODELS_READY` | Beta 生产必须显式 `true` | 关键模型缺失则启动失败 |
| `MODEL_DIR` | Compose 内为 `/app/models/saved` | 宿主机为 `./models/saved` |
| `MODEL_DELIVERY_MODE` | `artifact` 或 `repository` | Beta 推荐 `artifact` |
| `DRY_RUN` | Beta 建议 `true`，且 `private-beta` readiness 允许 `true` | 真实封禁前另走 `real-enforcement` readiness |
| `REDIS_HOST_FOR_GUARDIAN` | 启用 full-chain 时必填 | host 网络下通常为 `127.0.0.1` |

### 3.2 Beta 可选

| 变量 | 用途 | Beta 处理建议 |
|------|------|---------------|
| `ABUSEIPDB_API_KEY` / `VIRUSTOTAL_API_KEY` | 外部威胁情报 | 无外网或无合同可留空，使用本地 IOC |
| `DEEPSEEK_API_BASE` / `DEEPSEEK_API_KEY` | LLM 能力 | 非 Beta 必须 |
| `ALERT_EMAIL` / `ALERT_WEBHOOK` / SMTP 变量 | 告警通知 | 客户需要时配置，先做失败演练 |
| `RESPONSE_FIREWALL_BACKEND` | 封禁后端 | 默认 `iptables`，Beta 首选 dry-run |
| `RESPONSE_BUSINESS_IP_WHITELIST` | 业务 IP 白名单 | 真实封禁前必填 |
| `ENABLE_PACKET_CAPTURE` | 抓包开关 | app 默认为 false，guardian 为 true |
| `PACKET_INTERFACE` | 指定网卡 | 留空自动选择；生产建议显式确认 |
| `ENABLE_WEB_LOG` / `WEB_LOG_PATH` | Web 访问日志采集 | 需要挂载 Nginx 日志时启用 |
| `PIP_INDEX_URL` / `APT_MIRROR` | 构建加速 | 国内网络按需配置 |

### 3.3 明确禁止

- 生产 `.env` 中保留示例 `SECRET_KEY`。
- 生产使用明文 `ADMIN_PASSWORD` 作为认证路径。
- 生产 `DATABASE_URL` 使用 SQLite、localhost、示例或占位连接串，或无法执行 `SELECT 1`。
- 生产 `ALLOWED_ORIGINS=*`、`http://`、localhost、127.0.0.1、占位域名或非 HTTPS Origin。
- Beta 默认关闭任何 dangerous bypass / disable-connect 类开关；`GUARDIAN_REDIS_DISABLE_CONNECT=true` 只能用于本地测试，不能用于 Beta 校验。
- 将 `.env`、数据库 dump、模型私有制品地址、管理员哈希提交到版本控制。

## 4. 数据库 / Redis / 模型 / 日志目录要求

### 4.1 数据库

Beta 生产必须使用 PostgreSQL。首次部署和后续升级使用迁移命令：

```bash
docker compose run --rm app flask --app web.migration_app:create_migration_app db upgrade
docker compose run --rm app python -m web.init_db --check
```

交付要求：

- `DATABASE_URL` 指向客户生产或 Beta 专用 PostgreSQL。
- DBA 已创建数据库、账号和网络访问控制。
- 上线前有 `pg_dump -Fc` 备份策略。
- 发布证据包含 `flask db current` 或迁移输出。
- `.env` 中 `AUTO_CREATE_DB_TABLES=false`。

### 4.2 Redis

交付要求：

- Redis 使用密码，`REDIS_PASSWORD` 非空。
- Redis 不监听公网。
- `app` 通过 Compose bridge 使用 `REDIS_HOST=redis`。
- `guardian` 使用 host 网络时通过 `REDIS_HOST_FOR_GUARDIAN=127.0.0.1` 访问 Redis。
- 验证 Stream 不持续堆积。

观测命令：

```bash
docker compose exec redis sh -lc 'redis-cli -a "$REDIS_PASSWORD" ping'
docker compose exec redis sh -lc 'redis-cli -a "$REDIS_PASSWORD" XLEN guardian:alerts'
docker compose exec redis sh -lc 'redis-cli -a "$REDIS_PASSWORD" XPENDING guardian:alerts guardian:web'
docker compose exec redis sh -lc 'redis-cli -a "$REDIS_PASSWORD" XINFO GROUPS guardian:alerts'
```

### 4.3 模型目录

`docker-compose.yml` 将宿主机 `./models/saved` 只读挂载到容器 `/app/models/saved`。

Beta 必须存在：

- `intrusion_rf_v1.pkl`
- `ddos_rf_v1.pkl`
- `web_attack_nb_v1.pkl`
- `anomaly_if_v1.pkl`
- 对应 `*.model_manifest.json`
- `intrusion_feature_cols_v1.pkl`
- `intrusion_label_encoder_v1.pkl`
- `intrusion_scaler_v1.pkl`

上线前生成校验清单：

```bash
find models/saved -maxdepth 1 -type f -exec sha256sum {} \; | sort > backups/model-sha256-$(date +%Y%m%d%H%M%S).txt
docker compose run --rm app sh -lc 'ls -l /app/models/saved && test -r /app/models/saved/intrusion_rf_v1.pkl'
```

### 4.4 日志与审计目录

审计日志默认按环境隔离：

- `logs/test/security.log`
- `logs/dev/security.log`
- `logs/staging/security.log`
- `logs/production/security.log`

Beta 生产要求：

- `AUDIT_ENV=production` 或显式设置 `AUDIT_LOG_DIR`。
- `LOG_INTEGRITY_ENABLED=true`。
- `logs/` 可写且纳入备份。
- 日志归档和基线重建按 `docs/audit-log-baseline.md` 执行。
- 生产归档文件同步到只读对象存储或客户指定 WORM 介质时，不得混入测试日志。

## 5. 上线步骤

### 5.1 准备发布目录

```bash
cd /opt/ai-security-guardian
mkdir -p data logs models/saved backups release-env
cp .env.example .env
chmod 600 .env
```

编辑 `.env`，至少完成：

- 生成并填写 `SECRET_KEY`。
- 生成并填写 `ADMIN_PASSWORD_HASH`，清空或忽略 `ADMIN_PASSWORD`。
- 填写 PostgreSQL `DATABASE_URL`。
- 填写 `REDIS_PASSWORD`。
- 填写真实 `ALLOWED_ORIGINS`。
- 设置 `FLASK_ENV=production`、`AUDIT_ENV=production`。
- 设置 `REQUIRE_REDIS_AVAILABLE=true`、`REQUIRE_MODELS_READY=true`。
- 首次上线保持 `DRY_RUN=true`。

### 5.2 准备模型

```bash
ls -l models/saved
find models/saved -maxdepth 1 -type f -exec sha256sum {} \; | sort > backups/model-sha256-prelaunch.txt
```

若 `MODEL_DELIVERY_MODE=artifact`，交付记录必须包含：

- 制品来源或内网共享路径。
- 下载人、下载时间。
- SHA256 校验结果。
- manifest 版本。

### 5.3 生产配置校验

```bash
python scripts/check_production_readiness.py
docker compose config
```

准入标准：

- `check_production_readiness.py` 默认执行 `private-beta` gate，允许 `DRY_RUN=true`，无 `[FAIL]` 即满足 Beta 配置准入。
- `docker compose config` 可正常渲染。
- 输出和截图不得包含明文密码。

若客户明确要求开启真实封禁，必须在 Beta 准入之外单独执行：

```bash
python scripts/check_production_readiness.py --gate real-enforcement
```

该 gate 要求 `DRY_RUN=false`，并检查业务白名单、审批、审计、回滚、解封和复盘门禁证据。未通过时只能以 `DRY_RUN=true` 交付 Beta。

### 5.4 启动 Redis 并初始化数据库

```bash
docker compose up -d redis
docker compose exec redis sh -lc 'redis-cli -a "$REDIS_PASSWORD" ping'
docker compose run --rm app flask --app web.migration_app:create_migration_app db upgrade
docker compose run --rm app python -m web.init_db --check
```

### 5.5 启动 Web/API

生产建议增加 `docker-compose.prod.yml`，限制 app 只监听本机：

```yaml
services:
  app:
    ports:
      - "127.0.0.1:5000:5000"
```

启动：

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d app
docker compose -f docker-compose.yml -f docker-compose.prod.yml ps
docker compose -f docker-compose.yml -f docker-compose.prod.yml logs --tail=100 app
```

健康检查：

```bash
curl -fsS http://127.0.0.1:5000/api/health
curl -fsS http://127.0.0.1:5000/healthz
curl -fsS http://127.0.0.1:5000/readyz
```

### 5.6 配置 Nginx TLS/WSS

使用 `docs/deployment.md` 中 Nginx 片段转发 HTTP 和 `/socket.io/`。应用侧必须设置：

```bash
ALLOWED_ORIGINS=https://console.example.com
```

验证：

```bash
sudo nginx -t
sudo systemctl reload nginx
curl -Ik https://console.example.com/api/health
```

浏览器登录 Dashboard，确认 `/socket.io/` 为 `101 Switching Protocols` 或轮询正常，无 CORS / Mixed Content 错误。

### 5.7 启用完整检测链路

仅在客户授权抓包并确认主机权限后启用：

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml --profile full-chain up -d guardian
docker compose -f docker-compose.yml -f docker-compose.prod.yml --profile full-chain ps
docker compose -f docker-compose.yml -f docker-compose.prod.yml logs --tail=100 guardian
```

若未授权抓包，Beta 可以只交付 Web/API + Redis + DB + 模型就绪 + 演练数据链路，但必须在交付边界中标注“真实流量检测未启用”。

## 6. 验收步骤

### 6.1 自动化验收

按客户环境能力执行：

```bash
python -m pytest -q
python scripts/check_production_readiness.py
python -m pytest -m production_e2e -q
python -m pytest -m degradation_e2e -q  # 容灾验证，不计入生产通过标准
python scripts/staging_drill.py --cleanup
python scripts/benchmark_p95.py
BENCHMARK_USERNAME=admin BENCHMARK_PASSWORD='REPLACE_ME' python scripts/benchmark_http.py --base-url http://127.0.0.1:5000 --requests 1000 --workers 32 --warmup-requests 100
```

最低 Beta 通过标准：

- 私有化 Beta 配置校验无 `[FAIL]`，且允许 `DRY_RUN=true`。
- `/api/health`、`/healthz`、`/readyz` 成功。
- `scripts/staging_drill.py --cleanup` 通过，证明 Redis -> Web consumer -> DB -> Socket.IO -> 历史查询链路闭环。
- `python -m pytest -m production_e2e -q` 通过；模型缺失和 Redis memory fallback 仅由 `python -m pytest -m degradation_e2e -q` 验证，不计入生产通过标准。
- HTTP 核心 API P95 目标参考 `< 300ms`，检测段 P95 目标参考 `< 100ms`。

### 6.2 手工验收

- 登录 `/login`。
- 打开 `/dashboard`，确认图表、实时连接状态和告警摘要。
- 打开 `/alerts`，确认告警列表、详情、状态流转。
- 打开 `/settings`，确认管理员可访问配置项。
- 匿名访问受保护 `/api/*` 返回 `401`。
- 使用错误 Origin 验证 CORS 不放行。
- 重启 Web 后历史告警仍可查询。

### 6.3 安全验收

- `.env` 权限为 `600`。
- `ADMIN_PASSWORD_HASH` 已配置，生产不依赖 `ADMIN_PASSWORD`。
- Redis 不公网监听，密码错误 `ping` 失败，带密码 `ping` 成功。
- Docker 日志不出现密钥、Redis 密码、管理员哈希明文。
- 审计哈希链校验 `valid=True`。
- `DRY_RUN=false` 前完成业务白名单、审批、审计、回滚、解封、复盘门禁确认，并通过 `--gate real-enforcement`。

### 6.4 管理层验收口径

Beta 交付通过不等于 GA。管理层验收应确认：

- 已交付单企业私有化闭环环境。
- 已明确真实抓包、真实封禁、通知外呼等高风险能力是否启用。
- 已获得上线证据、备份证据、回滚证据和未交付 GA 能力列表。
- 已形成研发缺口清单和下一阶段优先级。

## 7. 回滚步骤

### 7.1 回滚触发条件

- 发布后 `/readyz` 持续失败。
- 登录、告警查询、告警入库或 Socket.IO 主链路不可用。
- Redis Stream pending 持续增长且无法恢复。
- 模型缺失或误报异常升高。
- 数据库迁移导致核心表不可用。
- 真实响应动作影响客户业务。

### 7.2 现场保全

```bash
export INCIDENT_TS=$(date +%Y%m%d%H%M%S)
mkdir -p backups/incident-$INCIDENT_TS
docker compose ps > backups/incident-$INCIDENT_TS/compose-ps.txt
docker image ls ai-security-guardian > backups/incident-$INCIDENT_TS/images.txt
cp .env backups/incident-$INCIDENT_TS/env.current
find models/saved -maxdepth 1 -type f -exec sha256sum {} \; | sort > backups/incident-$INCIDENT_TS/models.current.sha256
docker compose logs --tail=500 app > backups/incident-$INCIDENT_TS/app.log
docker compose logs --tail=500 redis > backups/incident-$INCIDENT_TS/redis.log
```

若涉及响应动作，先切回：

```bash
# 编辑 .env
DRY_RUN=true
docker compose up -d app guardian
```

### 7.3 应用镜像回滚

```bash
docker image ls ai-security-guardian
docker tag ai-security-guardian:<OLD_TAG> ai-security-guardian:latest
docker compose up -d --no-build app
curl -fsS http://127.0.0.1:5000/readyz
```

启用完整链路时：

```bash
docker compose --profile full-chain up -d guardian
```

验收：

- 镜像 ID 与上一稳定版本一致。
- 健康检查通过。
- 登录、Dashboard、Alerts 正常。

### 7.4 环境变量回滚

```bash
cp release-env/env.production.<GOOD_TS> .env
chmod 600 .env
python scripts/check_production_readiness.py
docker compose up -d app
```

若 Redis 密码也回滚：

```bash
docker compose up -d redis
docker compose exec redis sh -lc 'redis-cli -a "$REDIS_PASSWORD" ping'
docker compose up -d app
```

### 7.5 数据库回滚

先停写：

```bash
docker compose stop app guardian || true
```

PostgreSQL 建议由 DBA 恢复到临时库并切换连接串，或在维护窗口恢复正式库：

```bash
createdb guardian_restore_tmp
pg_restore -d guardian_restore_tmp backups/<GOOD_TS>/guardian_prod.dump
```

恢复后：

```bash
docker compose up -d app
curl -fsS http://127.0.0.1:5000/readyz
docker compose run --rm app python -m web.init_db --check
```

### 7.6 模型回滚

```bash
docker compose stop app guardian || true
tar -xzf backups/<GOOD_TS>/models-saved.tar.gz -C /tmp
rsync -a --delete /tmp/models/saved/ models/saved/
chmod -R go-w models/saved
docker compose up -d app
curl -fsS http://127.0.0.1:5000/readyz
```

验收：

- SHA256 与旧模型清单一致。
- `/readyz` 通过。
- 误报或模型加载问题恢复到可接受状态。

## 8. 备份恢复步骤

### 8.1 备份范围

每次发布前必须备份：

- PostgreSQL 数据库。
- `.env` 或客户密钥系统中的同版本配置。
- `models/saved` 和 SHA256 清单。
- `logs/`，尤其是 `logs/production/security.log` 和归档目录。
- 镜像 tag、镜像 ID、`docker compose config` 输出。

### 8.2 备份命令

```bash
export TS=$(date +%Y%m%d%H%M%S)
mkdir -p backups/$TS
chmod 700 backups/$TS

cp .env backups/$TS/env.production
chmod 600 backups/$TS/env.production
sha256sum backups/$TS/env.production > backups/$TS/env.production.sha256

pg_dump "$DATABASE_URL" -Fc -f backups/$TS/guardian_prod.dump
sha256sum backups/$TS/guardian_prod.dump > backups/$TS/guardian_prod.dump.sha256

tar -czf backups/$TS/models-saved.tar.gz models/saved
find models/saved -maxdepth 1 -type f -exec sha256sum {} \; | sort > backups/$TS/models-saved.sha256

tar -czf backups/$TS/logs.tar.gz logs
sha256sum backups/$TS/logs.tar.gz > backups/$TS/logs.tar.gz.sha256

docker compose ps > backups/$TS/compose-ps.txt
docker image ls ai-security-guardian > backups/$TS/images.txt
docker compose config > backups/$TS/compose-config.yml
```

### 8.3 恢复演练

恢复演练必须在隔离环境执行：

```bash
export BACKUP_TS=<要演练的备份时间戳>
sha256sum -c backups/$BACKUP_TS/env.production.sha256
sha256sum -c backups/$BACKUP_TS/guardian_prod.dump.sha256
sha256sum -c backups/$BACKUP_TS/logs.tar.gz.sha256

createdb guardian_restore_drill
pg_restore -d guardian_restore_drill backups/$BACKUP_TS/guardian_prod.dump
psql guardian_restore_drill -c '\dt'
```

恢复模型：

```bash
rm -rf /tmp/guardian-model-restore
mkdir -p /tmp/guardian-model-restore
tar -xzf backups/$BACKUP_TS/models-saved.tar.gz -C /tmp/guardian-model-restore
find /tmp/guardian-model-restore -type f -exec sha256sum {} \; | sort
```

恢复后业务验收：

```bash
python scripts/check_production_readiness.py
docker compose up -d redis app
curl -fsS http://127.0.0.1:5000/api/health
curl -fsS http://127.0.0.1:5000/healthz
curl -fsS http://127.0.0.1:5000/readyz
python -m pytest -m production_e2e -q
python -m pytest -m degradation_e2e -q
```

恢复演练结论必须记录 RTO、RPO、问题项和整改人。

## 9. 误封恢复步骤

### 9.1 Beta 策略

- Beta 首次交付默认 `DRY_RUN=true`。
- `DRY_RUN=false` 只能在客户书面确认、业务白名单配置完成、误封恢复演练通过，并通过 `python scripts/check_production_readiness.py --gate real-enforcement` 后开启。
- 对办公出口、LB、监控探针、DNS、数据库、堡垒机、客户核心业务网段必须加入白名单或禁止响应动作。

### 9.2 定位误封

```bash
grep -E 'block|ban|firewall|iptables|response' logs/production/security.log | tail -n 100
docker compose logs --tail=200 app | egrep -i 'block|ban|iptables|firewall|response' || true
```

确认：

- 被封 IP。
- 封禁来源告警。
- 操作人或自动响应动作。
- 当前 `DRY_RUN` 状态。

### 9.3 立即止血

将 `.env` 改为：

```bash
DRY_RUN=true
```

重启相关服务：

```bash
docker compose up -d app guardian
```

### 9.4 删除封禁规则

iptables 示例：

```bash
sudo iptables -S | grep '<MISBLOCKED_IP>' || true
sudo iptables -D INPUT -s <MISBLOCKED_IP> -j DROP || true
sudo iptables -D OUTPUT -d <MISBLOCKED_IP> -j DROP || true
sudo iptables -S | grep '<MISBLOCKED_IP>' || true
```

云安全组场景：

- 按客户云厂商控制台或 CLI 删除对应 deny 规则。
- 保留变更单号、删除前后截图、操作人。

### 9.5 加入白名单并复验

编辑 `.env`：

```bash
RESPONSE_BUSINESS_IP_WHITELIST=<MISBLOCKED_IP>
```

执行：

```bash
python scripts/check_production_readiness.py
docker compose up -d app guardian
curl -fsS http://127.0.0.1:5000/readyz
```

验收：

- 被误封来源恢复访问。
- 防火墙或云安全组中无对应 deny 规则。
- 审计日志和数据库响应动作保留误封、解封、白名单变更证据。
- 复盘前保持 `DRY_RUN=true`。

## 10. 交付证据清单

### 10.1 管理层交付证据

- Beta 交付范围确认单。
- GA 后置能力列表和原因。
- 部署拓扑图或文字说明。
- 是否启用真实抓包、真实封禁、外部通知的边界说明。
- 上线结论：通过 / 有条件通过 / 不通过。

### 10.2 技术上线证据

- 镜像 tag、镜像 ID、构建日志。
- `docker compose config` 输出。
- `.env` SHA256，不包含明文内容。
- `scripts/check_production_readiness.py` 输出。
- 数据库迁移输出、`web.init_db --check` 输出。
- PostgreSQL 备份文件名和 SHA256。
- 模型 manifest、模型 SHA256 清单。
- Redis 密码验证、`XLEN`、`XPENDING`、`XINFO GROUPS` 输出。
- `/api/health`、`/healthz`、`/readyz` 输出。
- Nginx `nginx -t` 和 TLS 访问验证。

### 10.3 功能验收证据

- 登录、Dashboard、Alerts、Settings 截图。
- Socket.IO / WSS 连接成功截图。
- `python scripts/staging_drill.py --cleanup` 输出。
- `python -m pytest -m production_e2e -q` 输出。
- `python -m pytest -m degradation_e2e -q` 输出，作为容灾验证证据，不作为生产通过标准。
- `python -m pytest -q` 输出。
- HTTP benchmark 报告，若执行 `scripts/benchmark_http.py`，保留 `reports/benchmarks/` 产物。
- 告警状态流转和审计记录截图或导出。

### 10.4 安全与运维证据

- Redis 未公网监听的 `ss -lntp` 或等效证据。
- 防火墙规则导出。
- `.env` 权限检查。
- 审计日志完整性校验结果。
- 审计归档和基线重建记录，若本次执行。
- 备份目录清单、SHA256 校验结果。
- 恢复演练记录和 RTO/RPO 结论。
- 回滚演练记录。
- 误封恢复演练记录。

## 11. 研发缺口清单

| 缺口 | 对 Beta 的影响 | 建议优先级 |
|------|----------------|------------|
| 定时自动解封仍为路线图项 | Beta 可通过手工解封交付，但真实封禁风险较高 | P1 |
| 多实例 WebSocket 扩容未默认支持 | Beta 单实例可用，GA 高可用受限 | P1 |
| 通知失败可视化不足 | Beta 可用日志排查，运维体验有限 | P2 |
| 模型效果线上指标不足 | Beta 可做离线和脚本验收，长期运营不足 | P1 |
| 采集丢包率和真实抓包容量基线不足 | 客户真实流量环境需要补压测 | P1 |
| 报告导出审计摘要和 CSV 增强未完成 | 管理层周期汇报能力不足 | P2 |
| 企业 SSO / 统一身份未接入 | Beta 可用管理员账号，企业推广受限 | P2 |
| 自动化安装、升级、巡检工具不足 | 交付依赖人工手册，规模化效率受限 | P1 |

## 12. Beta 放行结论模板

交付负责人在最终交付时填写：

| 项目 | 结论 |
|------|------|
| 客户名称 |  |
| 环境名称 | 私有化 Beta |
| 部署日期 |  |
| 应用版本 / 镜像 tag |  |
| 数据库类型 | PostgreSQL |
| Redis 是否加密访问 | 是 / 否 |
| 模型版本 |  |
| 是否启用 guardian full-chain | 是 / 否 |
| 是否启用真实封禁 | 是 / 否，Beta 默认否 |
| 验收结论 | 通过 / 有条件通过 / 不通过 |
| 遗留问题 |  |
| GA 后置项确认 | 已确认 / 未确认 |
| 客户代表 |  |
| 交付负责人 |  |
| 研发负责人 |  |
