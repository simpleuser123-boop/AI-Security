# 生产部署、回滚与备份恢复手册（v1.0）

本文档面向 AI-Security-Guardian 企业级上线、变更、回滚与灾备演练。内容与 `Dockerfile`、`docker-compose.yml`、`.env.example`、`README.md` 保持一致，默认部署形态为：

SaaS Beta 运维 SLO、Prometheus 告警、Grafana Dashboard、值班升级和 HA 方案见 `docs/phase-c5-saas-operations-reliability.md`。生产上线时，本手册负责部署和恢复动作，Phase C5 手册负责运行期健康判断和告警响应。

- `app`：Flask Web/API/Socket.IO，容器内监听 `5000`，非 root 用户 `guardian` 运行。
- `redis`：Redis 7，Compose 中仅绑定宿主机 `127.0.0.1:6379`，生产必须配置 `REDIS_PASSWORD`。
- `guardian`：完整检测链路，可选 `full-chain` profile，使用 `network_mode: host` 并需要 `NET_ADMIN` / `NET_RAW`。
- `models/saved`：只读挂载到 `/app/models/saved`，生产模型通过制品或受控目录交付。
- `data` / `logs`：分别挂载数据库文件或运行数据、应用日志。

所有命令默认在项目根目录执行。

```bash
cd /opt/ai-security-guardian
```

## 1. 上线前置条件

### 1.1 主机与端口

检查项：

- Docker Engine 与 Docker Compose Plugin 已安装。
- 生产入口只开放 `80/443` 给用户访问；`5000` 只允许本机 Nginx 或内网 LB 访问。
- Redis 只允许本机或业务内网访问，禁止公网访问 `6379`。
- 若启用 `guardian` 抓包，运行节点必须经过授权，并具备真实网卡访问能力。

命令：

```bash
docker version
docker compose version
ss -lntp | egrep ':80|:443|:5000|:6379' || true
```

Linux 防火墙参考：

```bash
# 仅示例：按企业标准替换 TRUSTED_ADMIN_CIDR / NGINX_LB_CIDR
sudo ufw default deny incoming
sudo ufw allow 22/tcp
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw deny 6379/tcp
sudo ufw deny 5000/tcp
sudo ufw status verbose
```

验收证据：

- `docker version`、`docker compose version` 输出。
- `ss -lntp` 截图或日志，证明 Redis 未监听公网地址。
- 防火墙规则导出。

### 1.2 目录规划

生产建议目录：

```bash
sudo mkdir -p /opt/ai-security-guardian/{data,logs,models/saved,backups,release-env}
sudo chown -R "$USER":"$USER" /opt/ai-security-guardian
chmod 750 /opt/ai-security-guardian
chmod 750 /opt/ai-security-guardian/{data,logs,models,models/saved,backups,release-env}
```

检查：

```bash
test -d data && test -d logs && test -d models/saved && test -d backups && echo OK
find models/saved -maxdepth 1 -type f | sort
```

## 2. 环境变量

完整模板见 `.env.example`。生产环境必须显式确认以下变量：

| 变量 | 生产要求 |
|------|----------|
| `FLASK_ENV` | 必须为 `production` |
| `SECRET_KEY` | 至少 32 字符，禁止使用示例值或开发默认值 |
| `ADMIN_USERNAME` / `ADMIN_PASSWORD_HASH` | 必须使用哈希；禁止生产使用明文 `ADMIN_PASSWORD` |
| `DATABASE_URL` | Private Beta / production 必须指向客户真实可连接 PostgreSQL；SQLite、localhost、`db.prod.company.tld`、`postgres.example.com`、示例/占位连接串仅允许开发/测试 |
| `AUTO_CREATE_DB_TABLES` | 生产保持 `false`，首次上线和后续升级使用 Flask-Migrate/Alembic |
| `REDIS_HOST` / `REDIS_PORT` / `REDIS_DB` / `REDIS_PASSWORD` | `REDIS_PASSWORD` 必填，必须与 Redis `requirepass` 一致，且不能是默认弱口令或 `REPLACE_WITH...` 占位值 |
| `REDIS_CONNECT_TIMEOUT_SEC` / `REDIS_SOCKET_TIMEOUT_SEC` | Redis 客户端连接/读写超时，默认 `0.5` / `2.0` 秒，避免健康检查长时间阻塞 |
| `ALLOWED_ORIGINS` | 填正式 HTTPS Origin，例如 `https://guardian-console.company.tld`；禁止 `*`、`http://`、localhost、127.0.0.1、占位域名 |
| `DRY_RUN` | 私有化 Beta 必须为 `true`；真实封禁 readiness 才允许改为 `false` |
| `REAL_ENFORCEMENT_GATE` | 默认留空；只有完成 `--gate real-enforcement` 验收后，才允许显式设为 `real-enforcement` |
| `REAL_ENFORCEMENT_APPROVAL_REQUIRED` | 仅真实封禁 gate 使用；必须确认审批门禁已启用 |
| `REAL_ENFORCEMENT_AUDIT_VERIFIED` | 仅真实封禁 gate 使用；必须确认审计和哈希链证据已验证 |
| `REAL_ENFORCEMENT_ROLLBACK_READY` | 仅真实封禁 gate 使用；必须确认回滚/止血路径已演练 |
| `REAL_ENFORCEMENT_UNBLOCK_READY` | 仅真实封禁 gate 使用；必须确认手工解封或等效恢复已演练 |
| `REAL_ENFORCEMENT_REVIEW_REQUIRED` | 仅真实封禁 gate 使用；必须确认响应后复盘要求 |
| `RESPONSE_BUSINESS_IP_WHITELIST` | 真实封禁 gate 要求非空；若留空，必须已在 `response_whitelist_entries` 上传 active IP/CIDR 白名单 |
| `RUNTIME_GUARDS_ENABLED` | Private Beta / production 必须显式为 `true`，作为运行期保护已开启的总开关 |
| `REQUIRE_REDIS_AVAILABLE` | Private Beta / production 必须显式为 `true`，Redis 不可用时启动失败 |
| `REQUIRE_MODELS_READY` | Private Beta / production 必须显式为 `true`，关键模型缺失时启动失败 |
| `LOG_INTEGRITY_ENABLED` | 生产建议 `true` |
| `MODEL_DIR` | Compose 内为 `/app/models/saved`，宿主机挂载为 `./models/saved` |
| `REDIS_HOST_FOR_GUARDIAN` | 启用 `full-chain` 时通常为 `127.0.0.1` |

生成密钥与管理员密码哈希：

```bash
python -c "import secrets; print(secrets.token_hex(32))"
python scripts/generate_admin_password_hash.py
```

创建生产 `.env`：

```bash
cp .env.example .env
chmod 600 .env
vi .env
```

私有化 Beta 配置校验：

```bash
python scripts/check_production_readiness.py
```

或使用外部环境文件：

```bash
python scripts/check_production_readiness.py --env-file /etc/guardian/production.env
```

默认脚本执行 `private-beta` gate，允许 `DRY_RUN=true`，用于证明客户侧私有化环境可部署、可审计、可回滚、可验收。它不代表真实封禁能力已经放行。该 gate 包括：

- `SECRET_KEY` 强度、默认值与弱 token 检查。
- `ADMIN_PASSWORD_HASH` 存在性、Werkzeug 哈希格式、是否匹配默认密码检查；生产禁止明文 `ADMIN_PASSWORD`。
- `DATABASE_URL` 必须是非示例、非本地、非占位的客户 PostgreSQL，并执行 `SELECT 1` 连通性检查；静态配置仍是占位时，`DB_CONNECTIVITY` 会先提示替换真实连接串。
- `REDIS_PASSWORD` 必填且非弱密码，并执行带密码 `PING` 连通性检查。
- `ALLOWED_ORIGINS` 禁止 `*`、localhost、127.0.0.1、`http://`、占位域名和非正式域名；Private Beta 也必须使用客户正式 HTTPS 域名。
- `DRY_RUN=true` 通过；若为 `false`，输出 `[FAIL]`。私有化 Beta 有条件放行不允许真实封禁。
- `RUNTIME_GUARDS_ENABLED` / `REQUIRE_REDIS_AVAILABLE` / `REQUIRE_MODELS_READY` 必须显式为 `true`；不符合时输出 `[FAIL]`。
- `MODEL_DIR` 与关键模型/manifest 文件存在且可读。
- `LOG_INTEGRITY_ENABLED=true`，审计日志目录存在且可写。

真实封禁上线前必须单独执行更高风险 gate：

```bash
python scripts/check_production_readiness.py --gate real-enforcement
```

该 gate 必须满足 `DRY_RUN=false`，并显式检查业务白名单、审批门禁、审计证据、回滚路径、解封路径和响应后复盘要求。它还会只读查询数据库，确认已存在 active DB 白名单（当 `RESPONSE_BUSINESS_IP_WHITELIST` 为空时）、至少一个 active 且 `last_validation_result.ok=true` 的 provider 配置，以及至少一条 `passed` 的恢复/回滚/误封演练记录。通过后在同一变更单中设置 `REAL_ENFORCEMENT_GATE=real-enforcement`；运行时若 `DRY_RUN=false` 但缺少该 gate，真实封禁会被拒绝并写入响应审计。真实 `ban_ip` 执行成功必须同时写入未来时间的 `scheduled_unblock_at` 并创建 `scheduled_unblock` 任务；如果任务创建失败，系统必须立即走回滚解封并写审计，不允许留下没有 TTL 的真实封禁。不要把私有化 Beta readiness 通过解读为真实封禁已可上线；私有化 Beta 的放行条件之一是 `DRY_RUN=true`。

验收证据：

- 私有化 Beta：`scripts/check_production_readiness.py` 输出无 `[FAIL]`，允许 `DRY_RUN=true`。
- 真实封禁：`scripts/check_production_readiness.py --gate real-enforcement` 输出无 `[FAIL]`，且 `DRY_RUN=false`、`REAL_ENFORCEMENT_GATE=real-enforcement`、审批/审计/回滚/解封/复盘门禁、白名单、provider 测试和恢复演练证据齐备。
- `.env` 权限为 `600`。
- `ALLOWED_ORIGINS` 与正式域名一致。
- `ADMIN_PASSWORD` 在生产环境为空或未设置。

## 3. 数据库初始化与迁移

生产禁止依赖应用启动自动建表。`AUTO_CREATE_DB_TABLES=false` 必须保持为上线基线；它只保留给开发/应急演示，不作为正式生产发布方案。正式 schema 版本由 Flask-Migrate（Alembic）管理，迁移命令使用轻量 app：`web.migration_app:create_migration_app`。

### 3.1 开发/测试 SQLite

SQLite 仅用于开发、测试、演示或临时 POC。`FLASK_ENV=production` 下应用会拒绝 SQLite `DATABASE_URL`，避免把单机文件库误用为正式数据库。

推荐按迁移初始化：

```bash
export FLASK_ENV=development
export DATABASE_URL=sqlite:///data/security.db
flask --app web.migration_app:create_migration_app db upgrade
```

轻量空库初始化入口仍保留给本地快速验证：

```bash
python -m web.init_db
python -m web.init_db --check
```

### 3.2 生产 PostgreSQL 首次建表与升级

先由 DBA 创建空库、账号和网络访问控制，再执行初始化。生产账号建议只授予应用需要的 DML 权限；首次建表或结构升级可使用受控发布账号执行 DDL。

```bash
# PostgreSQL 示例
createdb guardian_prod
psql guardian_prod -c "CREATE USER guardian WITH PASSWORD 'REPLACE_WITH_STRONG_PASSWORD';"
psql guardian_prod -c "GRANT CONNECT ON DATABASE guardian_prod TO guardian;"
```

初始化或升级应用表：

```bash
export FLASK_ENV=production
export DATABASE_URL=postgresql+psycopg2://guardian:REPLACE_WITH_STRONG_PASSWORD@postgres.example.com:5432/guardian_prod
docker compose run --rm app flask --app web.migration_app:create_migration_app db upgrade
docker compose run --rm app python -m web.init_db --check
```

检查：

```bash
docker compose run --rm app python - <<'PY'
import os
from sqlalchemy import create_engine, inspect
engine = create_engine(os.environ["DATABASE_URL"])
print(sorted(inspect(engine).get_table_names()))
PY
```

`python -m web.init_db --check` 只验证 ORM 期望表是否存在；`python -m web.init_db` 保留为空库快速初始化或开发/测试用途。生产后续结构变更必须通过迁移 revision 发布，不再用 `create_all()` 作为升级机制。

### 3.3 迁移发布策略

常用命令：

```bash
# 查看当前数据库版本
flask --app web.migration_app:create_migration_app db current

# 升级到最新版本；重复执行应保持幂等，不破坏数据
flask --app web.migration_app:create_migration_app db upgrade

# ORM 变更后生成迁移草稿，提交前必须人工审阅 revision 内容
flask --app web.migration_app:create_migration_app db migrate -m "describe schema change"
```

发布规则：

- 每次 ORM schema 变更必须提交对应 `migrations/versions/*.py`。
- 发布前在暂存 PostgreSQL 上执行 `flask db upgrade`，再跑 `python -m web.init_db --check` 和回归测试。
- 生产升级前执行 `pg_dump -Fc` 备份，并记录当前 `flask db current` 输出、应用镜像 tag、`.env` SHA256、迁移 revision。
- 已经用旧版 `python -m web.init_db`/`create_all()` 建出的存量库，先备份并确认表结构与初始迁移一致，再执行 `flask --app web.migration_app:create_migration_app db stamp head` 写入版本标记；后续升级再走 `db upgrade`。

回滚注意：

- DDL 发布前必须执行 `pg_dump -Fc` 备份，并记录应用镜像 tag、`.env` SHA256、迁移脚本版本。
- 可逆变更必须提供 downgrade SQL；不可逆变更必须在变更单中明确恢复方式，只能通过备份恢复或补偿脚本回滚。
- 回滚应用镜像前确认数据库结构兼容旧版本；若不兼容，先执行 downgrade SQL 或切换到恢复库。

验收证据：

- 初始化命令退出码为 `0`。
- `flask --app web.migration_app:create_migration_app db current` 显示目标 revision。
- `python -m web.init_db --check` 通过。
- 表清单截图或日志。
- DBA 备份策略确认记录。
- 证明 `.env` 中 `AUTO_CREATE_DB_TABLES=false`。

## 4. Redis 密码与内网访问

Compose 中 `redis` 服务默认：

- 使用 `redis:7-alpine`。
- 设置 `REDIS_PASSWORD` 后以 `--requirepass` 启动。
- 仅发布 `127.0.0.1:6379:6379`，不绑定 `0.0.0.0`。
- `app` 在 Compose bridge 网络中通过 `redis:6379` 访问。
- `guardian` 使用 host 网络时通过 `REDIS_HOST_FOR_GUARDIAN=127.0.0.1` 访问宿主机 Redis。

启动前检查 `.env`：

```bash
grep -E '^(REDIS_PASSWORD|REDIS_HOST|REDIS_PORT|REDIS_DB|REDIS_HOST_FOR_GUARDIAN)=' .env
```

启动 Redis 并检查密码：

```bash
docker compose up -d redis
docker compose ps redis
docker compose exec redis sh -lc 'redis-cli ping || true'
docker compose exec redis sh -lc 'redis-cli -a "$REDIS_PASSWORD" ping'
```

宿主机监听检查：

```bash
ss -lntp | grep ':6379'
# 期望看到 127.0.0.1:6379，而不是 0.0.0.0:6379
```

Stream 堆积观测：

```bash
docker compose exec redis sh -lc 'redis-cli -a "$REDIS_PASSWORD" XLEN guardian:alerts'
docker compose exec redis sh -lc 'redis-cli -a "$REDIS_PASSWORD" XPENDING guardian:alerts guardian:web'
docker compose exec redis sh -lc 'redis-cli -a "$REDIS_PASSWORD" XINFO GROUPS guardian:alerts'
docker compose exec redis sh -lc 'redis-cli -a "$REDIS_PASSWORD" XINFO STREAM guardian:alerts'
```

若本机没有 `redis-cli`，使用项目内 Python fallback（从 `REDIS_HOST` / `REDIS_PORT` / `REDIS_DB` / `REDIS_PASSWORD` 读取配置，不打印密码）：

```bash
python scripts/redis_stream_status.py
python scripts/redis_stream_status.py --json
```

生产检查项：

- `REDIS_PASSWORD` 非空且未提交到版本控制。
- 非本机无法访问 `6379`。
- Redis 密码错误时 `redis-cli ping` 失败，带 `-a` 成功。
- `REQUIRE_REDIS_AVAILABLE=true` 时 Redis 不可用会阻止应用启动。
- Web、后台 Stream consumer、Guardian 均从 `REDIS_HOST` / `REDIS_PORT` / `REDIS_DB` / `REDIS_PASSWORD` 构造 Redis 客户端；Compose 中 `guardian` 因 `network_mode: host` 可用 `REDIS_HOST_FOR_GUARDIAN` 映射到进程内 `REDIS_HOST`，其余端口、DB、密码保持同一组变量。
- `/api/health`、`/readyz` 与 `/metrics` 复用 Web 进程内 Redis 客户端；Redis 密码错误或网络异常时按 `REDIS_CONNECT_TIMEOUT_SEC` / `REDIS_SOCKET_TIMEOUT_SEC` 快速失败并降级，不应让接口长时间阻塞。

Redis Stream 生产验收指标：

- `XLEN guardian:alerts` 在正常流量下稳定 bounded，不持续线性增长；当前实现写入时使用 `MAXLEN ~ 10000` 软修剪。
- `XPENDING guardian:alerts guardian:web` 不持续增长；短时非 0 可以接受，但应随 consumer 恢复后回落。
- `XINFO GROUPS guardian:alerts` 中 `guardian:web` 的 `pending` 不持续增长，`consumers` 大于 0，`lag` 在稳定流量下可回落或保持在业务阈值内。
- Web consumer 日志应出现正常启动记录，数据库告警入库后执行 `XACK`，`/metrics` 中 `redis_stream_pending`、`redis_stream_length`、`redis_stream_group_lag` 可被 Prometheus 抓取。

## 5. 模型目录与交付

Compose 将宿主机 `./models/saved` 只读挂载到容器 `/app/models/saved`。上线前必须确认关键模型存在：

- `intrusion_rf_v1.pkl`
- `ddos_rf_v1.pkl`
- `web_attack_nb_v1.pkl`
- `anomaly_if_v1.pkl`
- 对应 `*.model_manifest.json`
- 入侵检测辅助文件：`intrusion_feature_cols_v1.pkl`、`intrusion_label_encoder_v1.pkl`、`intrusion_scaler_v1.pkl`

检查命令：

```bash
python - <<'PY'
import os, sys, json
d = os.getenv("MODEL_DIR", "models/saved")
required = [
    "intrusion_rf_v1.pkl",
    "ddos_rf_v1.pkl",
    "web_attack_nb_v1.pkl",
    "anomaly_if_v1.pkl",
    "intrusion_feature_cols_v1.pkl",
    "intrusion_label_encoder_v1.pkl",
    "intrusion_scaler_v1.pkl",
]
missing = [name for name in required if not os.path.exists(os.path.join(d, name))]
print("MODEL_DIR=", d)
print("missing=", missing)
sys.exit(1 if missing else 0)
PY
```

容器内检查：

```bash
docker compose run --rm app sh -lc 'ls -l /app/models/saved && test -r /app/models/saved/intrusion_rf_v1.pkl'
```

模型目录权限：

```bash
chmod -R go-w models/saved
find models/saved -maxdepth 1 -type f -exec sha256sum {} \; | sort > backups/model-sha256-$(date +%Y%m%d%H%M%S).txt
```

验收证据：

- 模型文件清单与 SHA256。
- manifest 版本记录。
- 容器内只读挂载验证。
- 若 `MODEL_DELIVERY_MODE=artifact`，保留制品 URI、下载记录和校验值。

## 6. Docker Compose 部署流程

### 6.1 空环境最小复演

```bash
cp .env.example .env
python -c "import secrets; print(secrets.token_hex(32))"
python scripts/generate_admin_password_hash.py
```

编辑 `.env`，至少替换并确认：

- `FLASK_ENV=production`
- `SECRET_KEY=<上一步生成的 64 位 hex>`
- `ADMIN_PASSWORD_HASH='<Werkzeug 哈希值>'`
- `DATABASE_URL=postgresql+psycopg2://<user>:<password>@<postgres-host>:5432/<database>`
- `REDIS_PASSWORD=<至少 12 字符强密码>`
- `ALLOWED_ORIGINS=https://<正式控制台域名>`
- `AUTO_CREATE_DB_TABLES=false`
- `RUNTIME_GUARDS_ENABLED=true`
- `REQUIRE_REDIS_AVAILABLE=true`
- `REQUIRE_MODELS_READY=true`

`.env` 中任何包含 `$` 的值必须使用单引号包住，尤其是 `ADMIN_PASSWORD_HASH`。否则 `docker compose config --quiet` 会把 `$...` 误判为 Compose 变量并输出未设置变量告警。

检查配置、构建镜像、执行迁移并启动 Web/API：

```bash
docker compose config --quiet
docker compose build app
docker compose up -d redis
docker compose run --rm app flask --app web.migration_app:create_migration_app db upgrade
docker compose run --rm app python -m web.init_db --check
docker compose up -d app
docker compose ps
```

检查健康、就绪和 Prometheus 指标：

```bash
curl -fsS http://127.0.0.1:5000/healthz
curl -fsS http://127.0.0.1:5000/readyz
curl -fsS http://127.0.0.1:5000/metrics | head
```

国内网络可在 `.env` 中设置：

```bash
PYTHON_BASE_IMAGE=public.ecr.aws/docker/library/python:3.11-slim
PIP_INDEX_URL=https://pypi.tuna.tsinghua.edu.cn/simple
APT_MIRROR=mirrors.ustc.edu.cn
```

### 6.2 本机端口限制

生产建议使用 override 将 `app` 端口限制在本机，避免绕过 Nginx TLS 直接访问 `5000`。仓库内置 `docker-compose.prod-drill.yml` 已只覆盖端口绑定：

```bash
docker compose -f docker-compose.yml -f docker-compose.prod-drill.yml config --quiet
docker compose -f docker-compose.yml -f docker-compose.prod-drill.yml up -d redis
docker compose -f docker-compose.yml -f docker-compose.prod-drill.yml run --rm app flask --app web.migration_app:create_migration_app db upgrade
docker compose -f docker-compose.yml -f docker-compose.prod-drill.yml run --rm app python -m web.init_db --check
docker compose -f docker-compose.yml -f docker-compose.prod-drill.yml up -d app
```

### 6.3 Web/API 生产启动方式

`python -m web.app` 只作为本地开发入口保留。它通过 `socketio.run()` 启动，便于调试、热重载和 Windows 本机联调；生产容器不再依赖 Werkzeug development server。

生产镜像默认启动命令为：

```bash
gunicorn \
  --bind 0.0.0.0:${PORT:-5000} \
  --worker-class gthread \
  --workers ${WEB_CONCURRENCY:-1} \
  --threads ${GUNICORN_THREADS:-100} \
  --timeout ${GUNICORN_TIMEOUT:-120} \
  --graceful-timeout ${GUNICORN_GRACEFUL_TIMEOUT:-30} \
  --keep-alive ${GUNICORN_KEEPALIVE:-5} \
  --access-logfile - \
  --error-logfile - \
  --log-level ${GUNICORN_LOG_LEVEL:-info} \
  web.wsgi:app
```

选型说明：

- Linux 容器优先使用 `gunicorn` + `gthread`。项目当前 `Flask-SocketIO` 明确配置为 `async_mode="threading"`，且已依赖 `simple-websocket`，因此该组合可以承载 Socket.IO WebSocket，不需要引入 eventlet/gevent monkey patch 风险。
- `WEB_CONCURRENCY` 默认保持 `1`。Flask-SocketIO 在单个 Gunicorn master 下不建议直接开启多个 worker；Gunicorn 的连接分发不保证 Socket.IO 会话稳定落到同一 worker。需要扩容时，运行多个 `WEB_CONCURRENCY=1` 的 app 实例，由 Nginx/LB 做粘性会话，并为 Socket.IO 配置共享消息队列后再放开多实例广播。
- `GUNICORN_THREADS` 默认 `100`，适合 Web/API + Socket.IO 长连接的轻中等并发。CPU 密集型模型推理不应放在 Web 请求线程里长时间执行；应由检测链路或后台任务处理。
- `GUNICORN_TIMEOUT` 默认 `120` 秒，避免慢启动、模型/数据库首次连接和少量慢请求被过早杀死。反向代理 `proxy_read_timeout` 对 `/socket.io/` 应大于 `ping_interval + ping_timeout`，本文 Nginx 示例使用 `300s`。
- 日志统一写到 stdout/stderr：`--access-logfile -`、`--error-logfile -`，由 Docker logging driver、journald 或集中式日志系统采集。应用审计日志继续写入挂载的 `./logs:/app/logs`。

eventlet/gevent 评估：

- `gunicorn -k eventlet` 或 `gunicorn -k gevent` 适合高并发长连接，但需要安装对应依赖、尽早 monkey patch，并把 Socket.IO async mode 切换到对应模式。本项目当前没有这类补丁入口；为避免影响数据库、Redis、Scapy、TensorFlow/scikit-learn 等依赖，本版本不默认引入。
- ASGI 不是当前推荐路径。应用是 Flask + Flask-SocketIO 的 WSGI 架构，切到 ASGI 需要额外适配或框架迁移，不符合本次“不重构应用工厂”的约束。

Windows 本机替代：

```powershell
# 完整本地联调，保留现有开发入口
$env:FLASK_ENV="development"
$env:DISABLE_RELOADER="true"
python -m web.app

# 仅 HTTP/API 的 WSGI 生产替代；Waitress 不承载 Socket.IO WebSocket 升级
waitress-serve --listen=0.0.0.0:5000 web.wsgi:app
```

Waitress 可作为 Windows 本机 HTTP/API 部署替代，但它不是完整 WebSocket 服务器。若生产必须使用 Dashboard 的 Socket.IO 实时能力，推荐使用 Linux 容器方案，或在 Windows 仅作为开发/演示运行。

### 6.4 启用完整检测链路

仅在需要真实抓包和主机授权后启用：

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml --profile full-chain up -d guardian
docker compose -f docker-compose.yml -f docker-compose.prod.yml --profile full-chain ps
docker compose -f docker-compose.yml -f docker-compose.prod.yml logs --tail=100 guardian
```

检查：

```bash
docker compose exec redis sh -lc 'redis-cli -a "$REDIS_PASSWORD" XLEN guardian:alerts'
docker inspect ai-security-guardian-main --format '{{json .HostConfig.CapAdd}}'
```

上线验收：

- `app` 和 `redis` 状态为 healthy。
- `/api/health`、`/healthz`、`/readyz` 返回成功。
- `guardian` profile 启用时进程存在，日志无权限错误。
- `docker compose logs` 中没有密钥、密码明文泄漏。

## 7. Nginx TLS 与 WSS

Nginx 在宿主机或前置代理上终止 TLS，将 HTTP 与 WebSocket 转发到 `127.0.0.1:5000`。

```nginx
map $http_upgrade $connection_upgrade {
    default upgrade;
    '' close;
}

upstream guardian_app {
    server 127.0.0.1:5000;
    keepalive 32;
}

server {
    listen 80;
    server_name console.example.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name console.example.com;

    ssl_certificate     /etc/nginx/ssl/fullchain.pem;
    ssl_certificate_key /etc/nginx/ssl/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_session_timeout 1d;

    client_max_body_size 20m;

    location / {
        proxy_pass http://guardian_app;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_connect_timeout 5s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }

    location /socket.io/ {
        proxy_pass http://guardian_app;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $connection_upgrade;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 300s;
        proxy_send_timeout 300s;
    }
}
```

应用侧必须设置：

```bash
ALLOWED_ORIGINS=https://console.example.com
```

发布 Nginx：

```bash
sudo nginx -t
sudo systemctl reload nginx
curl -Ik https://console.example.com/api/health
```

WSS 验证：

```bash
# 使用浏览器访问 https://console.example.com/dashboard
# 打开开发者工具，确认 /socket.io/ 请求状态为 101 Switching Protocols 或轮询正常，无 Mixed Content / CORS 错误。
```

验收证据：

- `nginx -t` 成功输出。
- `curl -Ik` 返回 `HTTP/2 200` 或健康接口可用。
- 浏览器网络面板中 Socket.IO/WSS 连接成功。
- 证书链与域名匹配截图。

## 8. API、CORS 与真实响应演练

- 除 `/api/health`、`/healthz`、`/readyz`、`/metrics`、`/api/auth/login` 及静态页面外，REST API 需要有效 JWT。
- CORS 只允许 `ALLOWED_ORIGINS`，生产禁止 `*`。
- `DRY_RUN=true` 时封禁/解封只记录审计，不执行真实 iptables 或云 API。
- `DRY_RUN=false` 前必须完成误封恢复演练并设置业务白名单。

演练命令：

```bash
python scripts/staging_drill.py --cleanup
python scripts/verify_v1.py
python scripts/benchmark_p95.py
BENCHMARK_USERNAME=admin BENCHMARK_PASSWORD='REPLACE_ME' \
  python scripts/benchmark_http.py --base-url http://127.0.0.1:5000 --requests 1000 --workers 32 --warmup-requests 100
```

检查审计：

```bash
tail -n 100 logs/security.log
docker compose logs --tail=100 app
```

## 9. 备份策略

备份至少覆盖四类对象：

- 数据库：业务表、告警、响应动作、用户配置。
- 环境变量：`.env` 或外部密钥系统中的版本化配置，必须加密保存。
- 模型目录：`models/saved` 及 SHA256 清单。
- 审计日志：`logs/security.log`、归档日志和哈希链基线。

建议保留策略：

- 每日全量数据库备份，关键变更前手工备份。
- 每次发布前备份 `.env` 到 `release-env`，文件权限 `600`。
- 每次模型变更前记录模型 SHA256 和 manifest。
- 每季度至少一次恢复演练。

### 9.1 备份命令

Private Deployment GA 建议优先用自动化证据包脚本生成备份恢复证据骨架。脚本只写 `.env` SHA256，不复制 `.env` 内容；无真实 PostgreSQL 访问时只生成 `pg_dump` 与恢复演练命令模板，并在 `customer-actions.md` 标记待客户环境执行，不伪造通过结果。

```bash
python scripts/generate_private_deployment_evidence.py \
  --audit-env production \
  --audit-log-dir logs/production \
  --output-dir reports/private-deployment-evidence/$TS
```

如客户环境已提供真实 PostgreSQL dump：

```bash
python scripts/generate_private_deployment_evidence.py \
  --db-dump backups/$TS/guardian_prod.dump \
  --base-url http://127.0.0.1:5000 \
  --output-dir reports/private-deployment-evidence/$TS
```

生成的 `database/migration-version.json` 会区分三类版本：`local_latest_revision` 是交付包内最新迁移脚本版本，`source_database_current_revision` 是可连接源库的 `alembic_version`，`restore_drill_current_revision` 必须来自隔离恢复库。只有 dump 文件或只有源库版本时，恢复演练仍应标记为待客户环境执行。

创建备份目录：

```bash
export TS=$(date +%Y%m%d%H%M%S)
mkdir -p backups/$TS
chmod 700 backups/$TS
```

备份环境变量：

```bash
cp .env backups/$TS/env.production
chmod 600 backups/$TS/env.production
sha256sum backups/$TS/env.production > backups/$TS/env.production.sha256
```

备份 SQLite：

```bash
docker compose stop app guardian || true
cp data/security.db backups/$TS/security.db
sha256sum backups/$TS/security.db > backups/$TS/security.db.sha256
docker compose up -d app
```

备份 PostgreSQL：

```bash
pg_dump "$DATABASE_URL" -Fc -f backups/$TS/guardian_prod.dump
sha256sum backups/$TS/guardian_prod.dump > backups/$TS/guardian_prod.dump.sha256
```

备份模型：

```bash
tar -czf backups/$TS/models-saved.tar.gz models/saved
find models/saved -maxdepth 1 -type f -exec sha256sum {} \; | sort > backups/$TS/models-saved.sha256
```

备份日志：

```bash
tar -czf backups/$TS/logs.tar.gz logs
python scripts/archive_security_audit_log.py --help >/dev/null 2>&1 || true
sha256sum backups/$TS/logs.tar.gz > backups/$TS/logs.tar.gz.sha256
```

生成备份索引：

```bash
{
  echo "backup_ts=$TS"
  docker compose ps
  docker image ls ai-security-guardian
} > backups/$TS/manifest.txt
```

### 9.2 备份检查项

- 备份文件存在且大小非 0。
- SHA256 文件已生成。
- `.env` 备份权限为 `600`，备份目录权限为 `700`；交付证据包只保存 `.env` SHA256，不保存明文。
- 数据库备份可在临时库恢复。
- 模型备份清单与上线前 SHA256 一致。
- `audit/hash-chain-verification.json` 中 `valid=true`；失败时先保全日志并走事件响应。
- `health/health-summary.json` 覆盖 `/api/health`、`/healthz`、`/readyz`、`/metrics` 摘要；无法访问客户服务时保留 `health/health-check-commands.md` 待客户执行。
- `manifest.json` 与 `customer-actions.md` 中不得出现数据库密码、Redis 密码、管理员密码哈希、API Token 或 `.env` 明文。

## 10. 恢复演练

恢复演练必须在临时环境或隔离主机执行，禁止直接在生产库上试错。目标是证明备份可用、步骤可重复、验收证据可追溯。

### 10.1 演练准备

```bash
export DRILL_TS=$(date +%Y%m%d%H%M%S)
export BACKUP_TS=<要演练的备份时间戳>
mkdir -p /tmp/guardian-restore-$DRILL_TS
cp -a backups/$BACKUP_TS /tmp/guardian-restore-$DRILL_TS/
cd /tmp/guardian-restore-$DRILL_TS
```

记录演练对象：

```bash
find backups/$BACKUP_TS -maxdepth 1 -type f -ls
sha256sum -c backups/$BACKUP_TS/*.sha256
```

### 10.2 环境变量恢复

```bash
cp backups/$BACKUP_TS/env.production /opt/ai-security-guardian/.env
chmod 600 /opt/ai-security-guardian/.env
cd /opt/ai-security-guardian
python scripts/check_production_readiness.py
```

验收：

- 校验脚本通过。
- `ALLOWED_ORIGINS`、`DATABASE_URL`、`REDIS_PASSWORD` 与目标环境一致。
- 不出现明文 `ADMIN_PASSWORD` 生产回退。

### 10.3 数据库恢复

SQLite：

```bash
cd /opt/ai-security-guardian
docker compose stop app guardian || true
cp backups/$BACKUP_TS/security.db data/security.db
chmod 640 data/security.db
docker compose up -d app
docker compose run --rm app python - <<'PY'
from web.app import create_app
from web.database import db
app = create_app()
with app.app_context():
    print("tables:", sorted(db.metadata.tables.keys()))
PY
```

PostgreSQL：

```bash
createdb guardian_restore_drill
pg_restore -d guardian_restore_drill backups/$BACKUP_TS/guardian_prod.dump
psql guardian_restore_drill -c '\dt'
```

验收：

- 表结构可读。
- 核心业务表记录数符合备份时间点预期。
- Web 重启后历史告警可查询。

### 10.4 模型恢复

```bash
cd /opt/ai-security-guardian
docker compose stop app guardian || true
rm -rf models/saved.restore
mkdir -p models/saved.restore
tar -xzf backups/$BACKUP_TS/models-saved.tar.gz -C models/saved.restore --strip-components=2
find models/saved.restore -maxdepth 1 -type f -exec sha256sum {} \; | sort > /tmp/models-restored.sha256
diff -u backups/$BACKUP_TS/models-saved.sha256 /tmp/models-restored.sha256
rsync -a --delete models/saved.restore/ models/saved/
chmod -R go-w models/saved
docker compose up -d app
```

容器内模型检查：

```bash
docker compose run --rm app sh -lc 'test -r /app/models/saved/intrusion_rf_v1.pkl && ls -l /app/models/saved'
curl -fsS http://127.0.0.1:5000/readyz
```

### 10.5 恢复后业务验收

```bash
docker compose ps
curl -fsS http://127.0.0.1:5000/api/health
curl -fsS http://127.0.0.1:5000/healthz
curl -fsS http://127.0.0.1:5000/readyz
python scripts/verify_v1.py
```

WSS 验收：

- 浏览器访问正式或演练域名。
- 登录后打开 Dashboard。
- 浏览器网络面板确认 `/socket.io/` 连接成功。

### 10.6 恢复演练证据清单

- 演练计划：时间、参与人、备份时间点、目标 RTO/RPO。
- `sha256sum -c` 输出。
- `.env` SHA256，不能包含 `.env` 明文。
- 数据库 dump SHA256、恢复命令输出、表清单和迁移版本。
- 模型文件 SHA256 与 manifest。
- 审计日志 hash-chain 校验结果。
- 应用健康检查输出：`/api/health`、`/healthz`、`/readyz`、`/metrics` 摘要。
- WSS 连接截图。
- 模型 SHA256 对比结果。
- Redis `XLEN` / `XINFO STREAM` 输出。
- `scripts/verify_v1.py` 输出。
- 演练结论：是否达成 RTO/RPO，问题项和整改人。

## 11. 回滚总原则

回滚前先止血，再恢复一致性：

1. 冻结变更窗口，记录当前版本、镜像 ID、`.env` SHA256、模型 SHA256、数据库备份点。
2. 判断是否需要先切回 `DRY_RUN=true`，避免响应动作继续扩大影响。
3. 优先回滚应用镜像和环境变量；若涉及数据写坏，再恢复数据库。
4. 模型回滚必须与 manifest/SHA256 一起回滚。
5. 防火墙误封必须先恢复业务访问，再保留审计证据。

通用现场记录：

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

## 12. 应用镜像回滚

前提：保留上一版本镜像 tag，例如 `ai-security-guardian:v1.0.0-20260505120000`。

```bash
docker image ls ai-security-guardian
docker image inspect ai-security-guardian:<OLD_TAG> --format '{{.Id}}'
```

回滚方法 A：临时改 Compose 镜像 tag 后启动：

```bash
cp docker-compose.yml backups/incident-$INCIDENT_TS/docker-compose.yml.current
perl -0pi -e 's/image: ai-security-guardian:[^\n]+/image: ai-security-guardian:<OLD_TAG>/' docker-compose.yml
docker compose up -d app
docker compose ps app
curl -fsS http://127.0.0.1:5000/api/health
```

回滚方法 B：重新打 `latest` 指向旧镜像：

```bash
docker tag ai-security-guardian:<OLD_TAG> ai-security-guardian:latest
docker compose up -d --no-build app
docker compose ps app
curl -fsS http://127.0.0.1:5000/readyz
```

若启用了完整链路：

```bash
docker compose --profile full-chain up -d guardian
docker compose --profile full-chain ps
```

验收：

- 镜像 ID 与旧版本一致。
- 健康检查通过。
- 登录、告警列表、Dashboard 正常。
- 日志中无迁移失败、模型加载失败、Redis 认证失败。

## 13. 环境变量回滚

`.env` 每次发布前必须备份到 `release-env` 或密钥系统。回滚：

```bash
export ENV_BACKUP=release-env/env.production.<GOOD_TS>
sha256sum "$ENV_BACKUP"
cp .env backups/incident-$INCIDENT_TS/env.before-env-rollback
cp "$ENV_BACKUP" .env
chmod 600 .env
python scripts/check_production_readiness.py
docker compose up -d app
```

涉及 Redis 密码变更时，必须同时重启 Redis 与应用：

```bash
docker compose up -d redis
docker compose exec redis sh -lc 'redis-cli -a "$REDIS_PASSWORD" ping'
docker compose up -d app
```

验收：

- 生产配置校验通过。
- Redis 带密码 ping 成功。
- `ALLOWED_ORIGINS` 与当前域名匹配。
- `DRY_RUN` 状态符合变更单要求。

## 14. 数据库恢复回滚

适用场景：

- 发布后写入坏数据。
- 初始化或迁移误操作。
- 需要回到某个备份时间点。

恢复前必须停写：

```bash
docker compose stop app guardian || true
```

SQLite：

```bash
cp data/security.db backups/incident-$INCIDENT_TS/security.db.before-restore
cp backups/<GOOD_TS>/security.db data/security.db
chmod 640 data/security.db
docker compose up -d app
curl -fsS http://127.0.0.1:5000/readyz
```

PostgreSQL：

```bash
createdb guardian_restore_tmp
pg_restore -d guardian_restore_tmp backups/<GOOD_TS>/guardian_prod.dump
# DBA 确认后切换连接串，或在维护窗口内恢复到正式库
```

验收：

- 核心表记录数与备份点一致。
- Web 能查询历史告警。
- `response_actions` 与 `security.log` 保留恢复审计。

## 15. 模型回滚

适用场景：

- 新模型误报/漏报显著升高。
- 模型文件缺失或 manifest 错误。
- `REQUIRE_MODELS_READY=true` 导致服务启动失败。

回滚：

```bash
docker compose stop app guardian || true
cp -a models/saved backups/incident-$INCIDENT_TS/models.saved.before-rollback
rm -rf models/saved.rollback
mkdir -p models/saved.rollback
tar -xzf backups/<GOOD_TS>/models-saved.tar.gz -C models/saved.rollback --strip-components=2
find models/saved.rollback -maxdepth 1 -type f -exec sha256sum {} \; | sort > /tmp/models.rollback.sha256
diff -u backups/<GOOD_TS>/models-saved.sha256 /tmp/models.rollback.sha256
rsync -a --delete models/saved.rollback/ models/saved/
chmod -R go-w models/saved
docker compose up -d app
```

检查：

```bash
docker compose run --rm app sh -lc 'ls -l /app/models/saved && test -r /app/models/saved/ddos_rf_v1.pkl'
curl -fsS http://127.0.0.1:5000/readyz
python scripts/verify_v1.py
```

验收：

- SHA256 与旧模型清单一致。
- `/readyz` 通过。
- 验证脚本通过或误报指标恢复到回滚前基线。

## 16. 防火墙误封恢复

适用场景：

- `DRY_RUN=false` 后误封业务 IP、办公出口 IP、LB、监控探针。
- iptables 或云安全组规则导致控制台不可达。

详细 SOP 见 `templates/misblock-recovery-sop.md`。实操顺序必须按“止血、解封、加白、审计、复盘”执行：

1. 止血：立即把应用切回 `DRY_RUN=true`，并移除或置空 `REAL_ENFORCEMENT_GATE`，防止新的真实封禁继续下发。
2. 解封：从 iptables、云安全组或等效防火墙中删除误封 IP 的 deny/drop 规则，先恢复业务访问。
3. 加白：把误封来源加入 `RESPONSE_BUSINESS_IP_WHITELIST` 或对应客户侧白名单，重新执行 readiness 校验。
4. 审计：保留 `logs/security.log`、`response_actions`、`audit_events`、变更单和防火墙规则变更证据。
5. 复盘：确认触发规则、审批记录、检测样本和恢复耗时；复盘完成前不得重新设置 `DRY_RUN=false` 和 `REAL_ENFORCEMENT_GATE=real-enforcement`。

先定位误封 IP：

```bash
grep -E 'block|ban|firewall|iptables|response' logs/security.log | tail -n 100
docker compose logs --tail=200 app | egrep -i 'block|ban|iptables|firewall|response' || true
```

立即切回演练模式，避免继续封禁：

```bash
cp .env backups/incident-$INCIDENT_TS/env.before-dry-run
perl -0pi -e 's/^DRY_RUN=.*/DRY_RUN=true/m' .env
perl -0pi -e 's/^REAL_ENFORCEMENT_GATE=.*/REAL_ENFORCEMENT_GATE=/' .env
docker compose up -d app guardian
```

iptables 后端恢复示例：

```bash
sudo iptables -S | grep '<MISBLOCKED_IP>' || true
sudo iptables -D INPUT -s <MISBLOCKED_IP> -j DROP
sudo iptables -D OUTPUT -d <MISBLOCKED_IP> -j DROP || true
sudo iptables -S | grep '<MISBLOCKED_IP>' || true
```

若使用云安全组：

```bash
# 按云厂商控制台或 CLI 删除 <MISBLOCKED_IP> 的 deny 规则，并保存变更单号。
```

加入业务白名单后再恢复：

```bash
perl -0pi -e 's/^RESPONSE_BUSINESS_IP_WHITELIST=.*/RESPONSE_BUSINESS_IP_WHITELIST=<MISBLOCKED_IP>/' .env
python scripts/check_production_readiness.py
docker compose up -d app guardian
```

验收：

- 被误封来源可以访问控制台或业务探针恢复。
- `iptables -S` 或云安全组中无对应 deny 规则。
- `logs/security.log` 和 `response_actions` 保留误封、解封、白名单变更证据。
- `manual_unban_ip` / `rollback_ban` 写入 `audit_events`；若解封任务已经到期但 provider 规则不存在，`scheduled_unblock` 记录为 `skipped`，不反复失败。
- 解封失败的 `response_schedule_tasks.last_error` 有错误信息，`attempt_count` 递增，并按退避策略重试。
- 复盘后再决定是否将 `DRY_RUN=false`。

## 17. 上线前自检命令

```bash
python -m pytest -q
python scripts/check_production_readiness.py
python scripts/verify_v1.py
python scripts/benchmark_p95.py
BENCHMARK_USERNAME=admin BENCHMARK_PASSWORD='REPLACE_ME' python scripts/benchmark_http.py --base-url http://127.0.0.1:5000 --requests 1000 --workers 32 --warmup-requests 100
python scripts/staging_drill.py --cleanup
docker compose config --quiet
docker compose up -d redis
docker compose run --rm app flask --app web.migration_app:create_migration_app db upgrade
docker compose run --rm app python -m web.init_db --check
docker compose up -d app
docker compose ps
curl -fsS http://127.0.0.1:5000/healthz
curl -fsS http://127.0.0.1:5000/readyz
curl -fsS http://127.0.0.1:5000/metrics | head
```

生产首次启动前建议在临时环境验证：`FLASK_ENV=production` 且故意省略 `SECRET_KEY` 或 `ADMIN_PASSWORD_HASH` 时进程应立即失败。

## 18. 最终验收证据清单

上线包：

- 镜像 tag、镜像 ID、构建日志。
- `docker compose config --quiet` 通过记录；如需保存完整 config，必须先脱敏环境变量。
- `.env` SHA256，不包含明文内容。
- 模型 manifest 与 SHA256。
- 数据库迁移输出和 `flask db current` 版本。

安全：

- Redis 密码验证输出。
- `ss -lntp` 证明 Redis 未公网监听。
- 防火墙规则导出。
- `ALLOWED_ORIGINS` 检查记录。
- Nginx `nginx -t` 与 TLS 证书检查。

功能：

- `/api/health`、`/healthz`、`/readyz` 输出。
- 登录、Dashboard、Alerts、Settings 页面截图。
- WSS/Socket.IO 连接成功截图。
- `scripts/verify_v1.py` 和 `scripts/staging_drill.py --cleanup` 输出。

备份恢复：

- 发布前备份目录清单。
- `.env` SHA256，不包含明文内容。
- 数据库 dump SHA256；无真实 PostgreSQL 时必须列入客户环境待执行项。
- 模型文件 SHA256 与 manifest。
- 审计日志 hash-chain 校验结果。
- 迁移版本：本地最新 revision 与恢复库 `alembic_version`。
- `/api/health`、`/healthz`、`/readyz`、`/metrics` 摘要。
- 恢复演练记录与 RTO/RPO 结论。

回滚：

- 上一版本镜像 tag 可用证明。
- 上一版本 `.env` 备份位置和 SHA256。
- 数据库可恢复备份点。
- 模型可恢复备份点。
- 防火墙误封恢复演练记录。

## 19. 当前机器无法执行真实能力时的替代验证

| 能力 | 替代方式 |
|------|----------|
| 真实 SYN 洪泛 / 网卡抓包 | 使用 `scripts/benchmark_p95.py` 与单元/E2E 中高 `syn_count` 流特征验证；全链路在具备 `NET_RAW` 的环境运行 `main.py` |
| 在线 Redis 压测 | 验证 Redis 密码、`XLEN` / `XINFO STREAM`；连接失败降级只允许在非生产测试 |
| TLS/WSS | 本地自签证书 + §7 Nginx 片段；最终验收必须在目标域名验证 |
| 外部数据库恢复 | 在临时库恢复 dump，记录表清单和核心记录数 |
