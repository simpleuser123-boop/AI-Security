# 单企业私有化 Beta 客户专用 `.env` 模板与 readiness 清单

本文档用于交付团队在客户环境生成正式 `.env`。不要把真实 `.env`、真实密钥、数据库密码、Redis 密码或管理员密码提交到仓库、工单附件或聊天记录。本文只提供占位模板和验收方法。

私有化 Beta 有条件放行的硬边界：

- 必须使用真实 PostgreSQL，且 `python scripts/check_production_readiness.py` 能执行 `SELECT 1`。
- 必须使用客户正式 HTTPS Origin，禁止 `*`、`http://`、localhost、127.0.0.1、示例域名和占位域名。
- 必须设置真实 Redis 密码，禁止空值、默认弱口令和 `REPLACE_WITH...` 占位值。
- 必须设置 `DRY_RUN=true`。Beta 阶段只允许演练响应动作，不允许真实封禁。
- 必须开启运行期保护：`RUNTIME_GUARDS_ENABLED=true`、`REQUIRE_REDIS_AVAILABLE=true`、`REQUIRE_MODELS_READY=true`。
- 必须无占位值、无默认弱口令、无明文 `ADMIN_PASSWORD`。

## 1. 客户 `.env` 模板

将以下内容复制为客户环境的 `.env` 或受控密钥系统条目后，由客户/DBA/运维填入真实值。占位符必须全部替换；不要在本文档中回填真实值。

```dotenv
# ===== Runtime =====
FLASK_ENV=production
AUDIT_ENV=production
LOG_LEVEL=INFO

# ===== Secrets: 只填入客户环境，不提交仓库 =====
# 至少 32 字符，建议使用:
# python -c "import secrets; print(secrets.token_hex(32))"
SECRET_KEY=<CLIENT_GENERATED_RANDOM_SECRET_KEY>

ADMIN_USERNAME=admin
ADMIN_ROLE=admin
# 使用 python scripts/generate_admin_password_hash.py 生成。
# 生产环境禁止设置 ADMIN_PASSWORD。
ADMIN_PASSWORD_HASH=<WERKZEUG_PASSWORD_HASH>
ADMIN_PASSWORD=

# ===== PostgreSQL: 必须是真实可连接的客户数据库 =====
# 示例格式，仅表示结构；不要使用示例主机、示例库名或占位密码。
DATABASE_URL=postgresql+psycopg2://<DB_USER>:<DB_PASSWORD>@<POSTGRES_FQDN_OR_PRIVATE_IP>:5432/<DB_NAME>
DB_CONNECT_TIMEOUT_SEC=3
AUTO_CREATE_DB_TABLES=false

# ===== Redis: 密码必须与 Redis requirepass 一致 =====
REDIS_HOST=<REDIS_HOST>
REDIS_PORT=6379
REDIS_DB=0
REDIS_PASSWORD=<CLIENT_REDIS_PASSWORD>
REDIS_CONNECT_TIMEOUT_SEC=0.5
REDIS_SOCKET_TIMEOUT_SEC=2.0

# ===== Web / CORS =====
# 必须是客户正式 HTTPS Origin，含协议和主机，不含 path/query。
# 多个 Origin 用英文逗号分隔。
ALLOWED_ORIGINS=https://<GUARDIAN_CONSOLE_CUSTOMER_DOMAIN>
JWT_TOKEN_EXPIRES=3600
JWT_REFRESH_TOKEN_EXPIRES=86400
API_RATE_LIMIT=100 per minute

# ===== Private Beta safety gates =====
# Beta 放行硬条件：必须为 true。false 代表真实封禁，不能走 private-beta gate。
DRY_RUN=true
RUNTIME_GUARDS_ENABLED=true
REQUIRE_REDIS_AVAILABLE=true
REQUIRE_MODELS_READY=true
LOG_INTEGRITY_ENABLED=true

# ===== Models =====
# Docker Compose 中容器内目录为 /app/models/saved；宿主机为 ./models/saved。
MODEL_DIR=models/saved
# repository: 模型随仓库/工作区交付
# artifact: 模型通过制品库、对象存储或共享盘交付
MODEL_DELIVERY_MODE=artifact
# artifact 模式必须记录客户可审计的制品地址、包名、版本或交付单号。
MODEL_ARTIFACT_URI=<CLIENT_MODEL_ARTIFACT_URI_OR_DELIVERY_RECORD>

# ===== Optional external integrations =====
ABUSEIPDB_API_KEY=
VIRUSTOTAL_API_KEY=
DEEPSEEK_API_BASE=
DEEPSEEK_API_KEY=
ALERT_EMAIL=
ALERT_WEBHOOK=
ALERT_SMTP_HOST=
ALERT_SMTP_PORT=587
ALERT_SMTP_USER=
ALERT_SMTP_PASSWORD=
ALERT_SMTP_FROM=
ALERT_SMTP_USE_TLS=true
ALERT_NOTIFY_MAX_RETRIES=3
ALERT_ENTERPRISE_CHANNEL_ENABLED=false

# ===== Response backend remains non-enforcing in Beta =====
RESPONSE_FIREWALL_BACKEND=iptables
RESPONSE_HOST_ISOLATION=none
RESPONSE_BUSINESS_IP_WHITELIST=
RESPONSE_PRIVATE_IP_WHITELIST=
RESPONSE_ALLOW_PRIVATE_BAN=false
REAL_ENFORCEMENT_APPROVAL_REQUIRED=false
REAL_ENFORCEMENT_AUDIT_VERIFIED=false
REAL_ENFORCEMENT_ROLLBACK_READY=false
REAL_ENFORCEMENT_UNBLOCK_READY=false
REAL_ENFORCEMENT_REVIEW_REQUIRED=false
```

## 2. 当前 readiness 失败项含义

`DATABASE_URL` 失败表示当前环境仍在使用 SQLite、localhost、`db.prod.company.tld`、`postgres.example.com`、示例/占位连接串、非 PostgreSQL 后端，或缺少数据库名。客户环境必须填真实 PostgreSQL URL，并由 DBA 确认可从应用主机或容器网络访问。

`ALLOWED_ORIGINS` 失败表示 CORS Origin 不是正式 HTTPS 域名，常见原因是填了 `*`、`http://localhost:5000`、`http://127.0.0.1`、`https://example.com`、`https://REPLACE_WITH...`，或带了路径。客户环境应填写控制台正式访问入口，例如 `https://guardian-console.customer.tld`。

`DB_CONNECTIVITY` 失败表示 URL 格式可能通过了静态检查，但实际 `SELECT 1` 连不上。常见原因是数据库未创建、账号密码错误、网络 ACL/安全组未放通、DNS 解析失败、端口不通、PostgreSQL 驱动缺失或连接超时。readiness 只输出异常类型，不打印密码。

如果 `DRY_RUN` 失败，表示 Beta 环境没有显式设置 `DRY_RUN=true`。这是私有化 Beta 有条件放行的硬条件，不能用 `DRY_RUN=false` 通过 Beta readiness。

`REDIS_PASSWORD` 失败表示 Redis 密码为空、过短、使用默认弱口令，或仍是 `REPLACE_WITH...` / placeholder / example 占位值。客户环境必须填真实运行密码，并保证应用配置与 Redis `requirepass` 一致。

`RUNTIME_GUARDS` 失败表示运行期保护没有完整开启。Private Beta 必须显式设置 `RUNTIME_GUARDS_ENABLED=true`、`REQUIRE_REDIS_AVAILABLE=true`、`REQUIRE_MODELS_READY=true`，避免 Redis 或模型缺失时静默降级。

## 3. 客户环境填写要求

`SECRET_KEY` 由客户环境生成并保管，不能沿用 `.env.example` 的 `REPLACE_ME_WITH_64_HEX_CHARS`，不能包含 `secret`、`password`、`changeme` 等弱 token。

`ADMIN_PASSWORD_HASH` 必须是 `scripts/generate_admin_password_hash.py` 生成的 Werkzeug 哈希。生产 `.env` 中 `ADMIN_PASSWORD` 必须为空或不存在。

`DATABASE_URL` 必须指向客户真实 PostgreSQL。建议使用应用专用账号，首次迁移可使用受控发布账号执行 DDL，运行期账号按客户权限规范收敛。

`AUTO_CREATE_DB_TABLES=false` 必须保持不变。首次建表和后续升级使用 Flask-Migrate/Alembic，不依赖应用启动自动建表。

`REDIS_PASSWORD` 必须为客户生成的强密码，并与 Redis `requirepass` 一致。`REQUIRE_REDIS_AVAILABLE=true` 表示 Redis 不可用时不允许应用静默降级。

`MODEL_DIR` 必须指向已交付并可读的模型目录。`MODEL_DELIVERY_MODE=artifact` 时，`MODEL_ARTIFACT_URI` 应填写制品库 URI、对象存储地址、共享盘路径或交付单号，并保留 SHA256/manifest 证据。

## 4. 如何验证

准备目录和权限：

```bash
mkdir -p data logs models/saved
chmod 600 .env
chmod 750 data logs models models/saved
```

运行私有化 Beta readiness：

```bash
python scripts/check_production_readiness.py --env-file .env
```

期望结果：

- 输出无 `[FAIL]`。
- `DRY_RUN` 显示 `true; private Beta runs in non-enforcing mode`。
- `DATABASE_URL` 显示 PostgreSQL production URL configured。
- `DB_CONNECTIVITY` 显示 database `SELECT 1` succeeded。
- `ALLOWED_ORIGINS` 显示正式 HTTPS Origin 数量。
- `REDIS_CONNECTIVITY` 显示 Redis ping succeeded。
- `MODEL_FILES` 显示 required artifacts present。

数据库迁移与表检查：

```bash
flask --app web.migration_app:create_migration_app db upgrade
python -m web.init_db --check
```

容器部署前配置检查：

```bash
docker compose config
docker compose up -d redis
docker compose run --rm app flask --app web.migration_app:create_migration_app db upgrade
docker compose run --rm app python -m web.init_db --check
docker compose up -d app
curl -fsS http://127.0.0.1:5000/healthz
curl -fsS http://127.0.0.1:5000/readyz
```

## 5. 交付前 readiness 命令清单

```bash
python scripts/check_production_readiness.py --env-file .env
flask --app web.migration_app:create_migration_app db upgrade
python -m web.init_db --check
docker compose config
docker compose up -d redis
docker compose exec redis sh -lc 'redis-cli -a "$REDIS_PASSWORD" ping'
docker compose run --rm app python -m web.init_db --check
docker compose up -d app
docker compose ps
curl -fsS http://127.0.0.1:5000/api/health
curl -fsS http://127.0.0.1:5000/healthz
curl -fsS http://127.0.0.1:5000/readyz
```

交付证据只保存命令输出、`.env` 文件 SHA256、模型 SHA256、数据库迁移版本、TLS/WSS 截图和运维确认记录；不要保存或传播 `.env` 明文。
