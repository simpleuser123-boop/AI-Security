# 目标环境私有化 Beta 复验执行清单

本文档用于交付团队在客户目标环境重新演练 AI-Security-Guardian 私有化 Beta 的 Docker、PostgreSQL、Redis、模型、迁移、健康检查、E2E、压测和日志安全。它补齐“商业化 Beta 总验收报告”中的目标环境复验要求：当前仓库允许进入首批单企业私有化 Beta，但必须在客户目标环境完成本清单后才可放行。

执行目录默认是目标环境项目根目录：

```bash
cd /opt/ai-security-guardian
```

Beta 硬边界：

- 私有化 Beta 默认且必须保持 `DRY_RUN=true`；真实封禁不随 Beta 默认开放。
- 任一标记为“阻断 Beta 放行”的步骤失败，均不得放行。
- 所有证据只保存命令输出、截图、SHA256、报告文件、变更单号或工单号；不得保存或传播 `.env` 明文、数据库密码、Redis 密码、管理员密码或管理员哈希。

## 1. 复验信息登记

执行前填写：

| 项目 | 内容 |
|------|------|
| 客户名称 |  |
| 环境名称 | 私有化 Beta 目标环境 |
| 执行日期 |  |
| 执行人 |  |
| 应用版本 / Git commit / 镜像 tag |  |
| 数据库地址标识 | 仅记录主机别名或工单号，不记录密码 |
| Redis 地址标识 | 仅记录主机别名或服务名 |
| 控制台正式 Origin | `https://...` |
| 是否启用 `guardian` full-chain | 是 / 否 |
| 是否启用真实封禁 | Beta 默认否 |

创建证据目录：

```bash
export DRILL_TS=$(date +%Y%m%d%H%M%S)
mkdir -p backups/target-drill-$DRILL_TS
chmod 700 backups/target-drill-$DRILL_TS
```

通过标准：

- 证据目录存在且权限为 `700`。
- 后续所有命令输出、截图、报告和 SHA256 清单均归档到该目录或客户指定证据库。

失败排查：

- 权限不足：确认执行用户拥有项目目录写权限。
- 磁盘不足：清理旧构建缓存或切换到客户指定证据目录。

交付证据：

- `ls -ld backups/target-drill-$DRILL_TS` 输出。

阻断 Beta 放行：否；但无证据目录时不得开始正式复验。

## 2. Docker / Compose 版本检查

命令：

```bash
docker version
docker compose version
docker info --format '{{.ServerVersion}}'
docker compose config > backups/target-drill-$DRILL_TS/compose-config.yml
```

通过标准：

- Docker Engine 可用，客户端可连接 daemon。
- Docker Compose Plugin 可用，能成功渲染 `docker compose config`。
- `compose-config.yml` 中 `app`、`redis` 服务存在，`models/saved` 以只读方式挂载到 `/app/models/saved`。
- `redis` 端口绑定不是 `0.0.0.0:6379`；默认应为 `127.0.0.1:6379:6379` 或仅内网访问。

失败排查：

- `Cannot connect to Docker daemon`：启动 Docker 服务，确认当前用户在 `docker` 组或使用客户规定的 sudo 流程。
- `docker compose` 不存在：安装 Docker Compose Plugin，不使用旧版 `docker-compose` 作为正式复验口径。
- `DATABASE_URL` 或 `ALLOWED_ORIGINS` 导致 config 渲染失败：先补齐客户 `.env` 中必填项，再重试。
- Redis 端口暴露到公网：增加生产 override，限制为 `127.0.0.1:6379:6379` 或移除宿主机端口发布。

交付证据：

- `docker version` 输出。
- `docker compose version` 输出。
- `backups/target-drill-$DRILL_TS/compose-config.yml`。
- Redis 端口绑定截图或 `compose-config.yml` 片段。

阻断 Beta 放行：是。Docker/Compose 不可用、Compose 无法渲染、Redis 公网暴露均阻断放行。

## 3. 客户 `.env` 与 Beta readiness

命令：

```bash
chmod 600 .env
python scripts/check_production_readiness.py --env-file .env | tee backups/target-drill-$DRILL_TS/readiness.txt
sha256sum .env > backups/target-drill-$DRILL_TS/env.sha256
```

通过标准：

- `readiness.txt` 无 `[FAIL]`。
- `FLASK_ENV=production`。
- `DATABASE_URL` 是可连接 PostgreSQL。
- `ALLOWED_ORIGINS` 是客户正式 HTTPS Origin，禁止 `*`、`http://`、localhost、127.0.0.1、示例域名和占位域名。
- `DRY_RUN=true`。
- `RUNTIME_GUARDS_ENABLED=true`、`REQUIRE_REDIS_AVAILABLE=true`、`REQUIRE_MODELS_READY=true`。
- `.env` 权限为 `600`，证据只保存 SHA256，不保存明文。

失败排查：

- `DATABASE_URL` 失败：联系 DBA 确认库名、账号、密码、DNS、端口和网络 ACL；禁止用 SQLite 或 localhost 伪造通过。
- `DB_CONNECTIVITY` 失败：从目标主机执行 PostgreSQL `SELECT 1` 连通性检查，确认安全组和防火墙。
- `ALLOWED_ORIGINS` 失败：替换为客户正式控制台域名，例如 `https://guardian-console.customer.tld`。
- `DRY_RUN` 失败：Beta 改回 `DRY_RUN=true`；真实封禁需另走 `--gate real-enforcement`。
- Redis 或模型失败：按本文第 5、6 节分别排查。

交付证据：

- `backups/target-drill-$DRILL_TS/readiness.txt`。
- `backups/target-drill-$DRILL_TS/env.sha256`。
- `.env` 权限检查输出：`ls -l .env`。

阻断 Beta 放行：是。任何 `[FAIL]`、`DRY_RUN=false`、正式 Origin 缺失、生产密钥默认值、`.env` 明文泄露风险均阻断放行。

## 4. PostgreSQL 连通性

命令：

```bash
docker compose run --rm app python - <<'PY' | tee backups/target-drill-$DRILL_TS/postgres-connectivity.txt
import os
from sqlalchemy import create_engine, text

engine = create_engine(os.environ["DATABASE_URL"], pool_pre_ping=True)
with engine.connect() as conn:
    print("select_1=", conn.execute(text("SELECT 1")).scalar())
    print("database=", conn.execute(text("SELECT current_database()")).scalar())
    print("server_version=", conn.execute(text("SHOW server_version")).scalar())
PY
```

通过标准：

- 命令退出码为 `0`。
- `select_1= 1`。
- 输出能显示目标数据库名和 PostgreSQL 版本。
- 输出中不出现数据库密码。

失败排查：

- 容器内 DNS 解析失败：确认 `DATABASE_URL` 主机名可从 Compose 网络解析，或使用客户内网地址。
- 认证失败：由 DBA 重置应用账号密码并更新 `.env`。
- 超时：检查安全组、PostgreSQL `pg_hba.conf`、防火墙、VPN 或堡垒访问策略。
- SSL 要求不匹配：按客户数据库策略在 `DATABASE_URL` 增加 `sslmode=require` 等参数。

交付证据：

- `backups/target-drill-$DRILL_TS/postgres-connectivity.txt`。
- DBA 连通性确认记录或变更单号。

阻断 Beta 放行：是。PostgreSQL 不可连接阻断放行。

## 5. Redis 密码和内网访问检查

先启动 Redis：

```bash
docker compose up -d redis
docker compose ps redis | tee backups/target-drill-$DRILL_TS/redis-ps.txt
```

密码检查：

```bash
docker compose exec redis sh -lc 'redis-cli ping || true' | tee backups/target-drill-$DRILL_TS/redis-ping-without-password.txt
docker compose exec redis sh -lc 'redis-cli -a "$REDIS_PASSWORD" ping' | tee backups/target-drill-$DRILL_TS/redis-ping-with-password.txt
```

内网监听检查：

```bash
ss -lntp | grep ':6379' | tee backups/target-drill-$DRILL_TS/redis-listen.txt
docker compose port redis 6379 | tee backups/target-drill-$DRILL_TS/redis-compose-port.txt
```

Stream 观测：

```bash
docker compose exec redis sh -lc 'redis-cli -a "$REDIS_PASSWORD" XLEN guardian:alerts' | tee backups/target-drill-$DRILL_TS/redis-xlen.txt
docker compose exec redis sh -lc 'redis-cli -a "$REDIS_PASSWORD" XPENDING guardian:alerts guardian:web' | tee backups/target-drill-$DRILL_TS/redis-xpending.txt
docker compose exec redis sh -lc 'redis-cli -a "$REDIS_PASSWORD" XINFO GROUPS guardian:alerts' | tee backups/target-drill-$DRILL_TS/redis-xinfo-groups.txt
```

通过标准：

- Redis 容器状态为 running/healthy。
- 未带密码 `redis-cli ping` 失败或返回需要认证；带密码返回 `PONG`。
- `ss` 或 `docker compose port` 证明 Redis 未绑定公网地址；默认应为 `127.0.0.1:6379` 或客户内网地址。
- `XPENDING guardian:alerts guardian:web` 不持续增长；正常演练后应可回到 `0`。

失败排查：

- 未带密码也能 `PONG`：确认 `REDIS_PASSWORD` 非空并重启 Redis，检查 Compose command 是否启用 `--requirepass`。
- 带密码失败：确认 `.env` 中 `REDIS_PASSWORD` 与 Redis 实际 `requirepass` 一致。
- `0.0.0.0:6379`：修改 Compose/防火墙，禁止公网访问 Redis。
- `XPENDING` 持续增长：检查 `app` consumer 日志、数据库连接、Redis Stream group 和 Web 进程是否运行。
- `XINFO GROUPS` 报 stream 不存在：新环境无告警时可接受；执行第 11 节 E2E 后应重新观测。

交付证据：

- `redis-ps.txt`、`redis-ping-without-password.txt`、`redis-ping-with-password.txt`。
- `redis-listen.txt` 或客户防火墙规则导出。
- `redis-xlen.txt`、`redis-xpending.txt`、`redis-xinfo-groups.txt`。

阻断 Beta 放行：是。Redis 无密码、密码不匹配、公网暴露、`REQUIRE_REDIS_AVAILABLE=true` 下不可用均阻断放行。短时无 Stream group 可在 E2E 前接受，但 E2E 后仍无法消费告警则阻断放行。

## 6. 模型目录和 manifest 检查

宿主机检查：

```bash
python - <<'PY' | tee backups/target-drill-$DRILL_TS/model-host-check.txt
import json
import os
import sys

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
manifests = sorted(name for name in os.listdir(d) if name.endswith(".model_manifest.json")) if os.path.isdir(d) else []
print("MODEL_DIR=", d)
print("missing=", missing)
print("manifest_count=", len(manifests))
print("manifests=", manifests)
sys.exit(1 if missing or len(manifests) < 4 else 0)
PY
```

manifest JSON 检查：

```bash
python - <<'PY' | tee backups/target-drill-$DRILL_TS/model-manifest-check.txt
import glob
import json
import os
import sys

d = os.getenv("MODEL_DIR", "models/saved")
failed = []
for path in sorted(glob.glob(os.path.join(d, "*.model_manifest.json"))):
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        print(os.path.basename(path), "ok", sorted(data.keys()))
    except Exception as exc:
        failed.append((path, type(exc).__name__))
print("failed=", failed)
sys.exit(1 if failed else 0)
PY
```

容器内只读挂载与 SHA256：

```bash
find models/saved -maxdepth 1 -type f -exec sha256sum {} \; | sort > backups/target-drill-$DRILL_TS/model-sha256.txt
docker compose run --rm app sh -lc 'ls -l /app/models/saved && test -r /app/models/saved/intrusion_rf_v1.pkl && test ! -w /app/models/saved' | tee backups/target-drill-$DRILL_TS/model-container-check.txt
```

通过标准：

- 关键模型、辅助文件和至少 4 个 `*.model_manifest.json` 存在。
- manifest 为合法 JSON。
- 容器内 `/app/models/saved` 可读且不可写。
- `model-sha256.txt` 已归档。

失败排查：

- 文件缺失：从客户制品库、对象存储或受控共享盘重新交付模型包。
- manifest JSON 错误：回退到上一版模型制品，或重新生成 manifest。
- 容器内不可读：检查宿主机权限、SELinux/AppArmor、挂载路径是否正确。
- 容器内可写：检查 `docker-compose.yml` 是否保留 `./models/saved:/app/models/saved:ro`。

交付证据：

- `model-host-check.txt`。
- `model-manifest-check.txt`。
- `model-container-check.txt`。
- `model-sha256.txt`。
- 模型制品 URI、版本号或交付单号。

阻断 Beta 放行：是。关键模型/manifest 缺失、manifest 无法解析、容器内模型目录不可读或可写均阻断放行。

## 7. `flask db upgrade/current`

执行迁移：

```bash
docker compose run --rm app flask --app web.migration_app:create_migration_app db upgrade | tee backups/target-drill-$DRILL_TS/flask-db-upgrade.txt
docker compose run --rm app flask --app web.migration_app:create_migration_app db current | tee backups/target-drill-$DRILL_TS/flask-db-current.txt
```

表清单：

```bash
docker compose run --rm app python - <<'PY' | tee backups/target-drill-$DRILL_TS/db-tables.txt
import os
from sqlalchemy import create_engine, inspect

engine = create_engine(os.environ["DATABASE_URL"])
with engine.connect() as conn:
    tables = sorted(inspect(conn).get_table_names())
print("tables=", tables)
PY
```

通过标准：

- `db upgrade` 退出码为 `0`。
- `db current` 显示目标 revision。
- 表清单包含 `alembic_version`、`alerts`、`alert_histories`、`audit_events`、`response_actions` 等核心表。
- 重复执行 `db upgrade` 保持幂等，不破坏数据。

失败排查：

- migration 找不到：确认 `migrations/` 目录随发布包交付。
- DDL 权限不足：由 DBA 授予发布账号临时 DDL 权限，运行期账号按客户策略收敛。
- 表已存在但未纳入 Alembic：先备份，确认结构匹配后按 `docs/deployment.md` 执行 `db stamp head`。
- migration 中断：停止上线，保全数据库状态，由研发/DBA 判断回滚或补偿迁移。

交付证据：

- `flask-db-upgrade.txt`。
- `flask-db-current.txt`。
- `db-tables.txt`。
- 发布前 PostgreSQL 备份文件名和 SHA256。

阻断 Beta 放行：是。迁移失败、版本未知、核心表缺失均阻断放行。

## 8. `web.init_db --check`

命令：

```bash
docker compose run --rm app python -m web.init_db --check | tee backups/target-drill-$DRILL_TS/init-db-check.txt
```

通过标准：

- 命令退出码为 `0`。
- ORM 期望表均存在。
- `.env` 中 `AUTO_CREATE_DB_TABLES=false` 保持不变。

失败排查：

- 表缺失：回到第 7 节重新执行迁移。
- 连接错误：回到第 4 节排查 PostgreSQL 连通性。
- 误开 `AUTO_CREATE_DB_TABLES=true`：改回 `false`，生产结构升级只走迁移。

交付证据：

- `init-db-check.txt`。
- `.env` SHA256 和 `AUTO_CREATE_DB_TABLES=false` 的配置审查记录，不保存 `.env` 明文。

阻断 Beta 放行：是。`web.init_db --check` 失败阻断放行。

## 9. `docker compose build app`

命令：

```bash
docker compose build app 2>&1 | tee backups/target-drill-$DRILL_TS/docker-build-app.txt
docker image inspect ai-security-guardian:latest --format '{{.Id}} {{.Created}}' | tee backups/target-drill-$DRILL_TS/docker-image-inspect.txt
```

如客户环境无法访问 Docker Hub，可先配置企业镜像源或内网 registry，再重试：

```bash
PIP_INDEX_URL=https://pypi.tuna.tsinghua.edu.cn/simple APT_MIRROR=mirrors.tuna.tsinghua.edu.cn docker compose build app
```

通过标准：

- app 镜像构建成功。
- 镜像 ID 可记录。
- 构建日志中不出现 `.env` 明文、数据库密码、Redis 密码、管理员密码或管理员哈希。
- Dockerfile 默认以非 root 用户 `guardian` 运行，并使用 Gunicorn 启动 Web/API。

失败排查：

- 基础镜像拉取失败：使用客户企业 registry、Docker mirror 或离线镜像包。
- Python 依赖下载失败：配置 `PIP_INDEX_URL` 或离线 wheelhouse。
- apt 源失败：配置 `APT_MIRROR` 或客户内网 apt 源。
- 权限错误：确认构建上下文文件权限，避免不可读制品进入镜像构建。

交付证据：

- `docker-build-app.txt`。
- `docker-image-inspect.txt`。
- 镜像 tag、镜像 ID、镜像来源说明。

阻断 Beta 放行：是。目标环境无法构建或无法使用客户批准镜像启动 app 时阻断放行。

## 10. `docker compose up app/redis`

建议生产增加端口覆盖，只允许本机或内网代理访问 app：

```bash
cat > docker-compose.prod.yml <<'YAML'
services:
  app:
    ports:
      - "127.0.0.1:5000:5000"
YAML
```

启动：

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d redis
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d app
docker compose -f docker-compose.yml -f docker-compose.prod.yml ps | tee backups/target-drill-$DRILL_TS/compose-ps-app-redis.txt
docker compose -f docker-compose.yml -f docker-compose.prod.yml logs --tail=200 app > backups/target-drill-$DRILL_TS/app-startup.log
docker compose -f docker-compose.yml -f docker-compose.prod.yml logs --tail=200 redis > backups/target-drill-$DRILL_TS/redis-startup.log
```

通过标准：

- `app` 和 `redis` 均 running/healthy。
- app 日志无数据库迁移失败、Redis 认证失败、模型加载失败、密钥配置失败。
- app 端口不直接暴露公网。
- Redis 仍只允许本机或客户内网访问。

失败排查：

- `app` 反复重启：查看 `app-startup.log`，优先排查 `.env`、DB、Redis、模型和端口占用。
- `redis` unhealthy：确认密码、端口、volume 权限。
- `depends_on` 等待失败：先单独确认 Redis healthy，再启动 app。
- 端口冲突：调整 `docker-compose.prod.yml` 端口或客户反向代理配置。

交付证据：

- `compose-ps-app-redis.txt`。
- `app-startup.log`。
- `redis-startup.log`。
- 端口监听输出：`ss -lntp | egrep ':5000|:6379'`。

阻断 Beta 放行：是。app/redis 不能稳定启动、端口公网暴露、启动日志出现关键依赖失败均阻断放行。

## 11. `/healthz`、`/readyz`、`/metrics`

本机探针：

```bash
curl -fsS http://127.0.0.1:5000/healthz | tee backups/target-drill-$DRILL_TS/healthz.json
curl -fsS http://127.0.0.1:5000/readyz | tee backups/target-drill-$DRILL_TS/readyz.json
curl -fsS http://127.0.0.1:5000/metrics | tee backups/target-drill-$DRILL_TS/metrics.txt
```

若通过正式域名访问：

```bash
curl -Ik https://<GUARDIAN_CONSOLE_CUSTOMER_DOMAIN>/healthz | tee backups/target-drill-$DRILL_TS/healthz-tls.txt
curl -Ik https://<GUARDIAN_CONSOLE_CUSTOMER_DOMAIN>/readyz | tee backups/target-drill-$DRILL_TS/readyz-tls.txt
```

通过标准：

- `/healthz` HTTP 200，表示进程存活。
- `/readyz` HTTP 200，JSON 中 `database`、`redis`、`config`、`models` 均 ok，不存在 fatal degraded。
- `/metrics` HTTP 200，包含 `guardian_model_ready`、`redis_stream_pending`、`redis_stream_length`、`redis_stream_group_lag`、`audit_integrity_valid` 等指标。
- 输出中不包含密钥或密码。

失败排查：

- `/healthz` 失败：app 进程未启动或端口/代理异常。
- `/readyz` 503：根据 JSON 的 `checks` 定位 DB、Redis、config 或 models；分别回到第 3-8 节排查。
- `/metrics` 失败：查看 app 日志，确认监控路由未被认证或代理规则误拦截。
- 正式域名失败：检查 Nginx/LB、TLS 证书、`ALLOWED_ORIGINS` 和上游 `127.0.0.1:5000`。

交付证据：

- `healthz.json`。
- `readyz.json`。
- `metrics.txt`。
- 如有正式域名：`healthz-tls.txt`、`readyz-tls.txt`、TLS 证书截图或 `curl -Ik` 输出。

阻断 Beta 放行：是。`/readyz` 不通过或 `/metrics` 不可采集均阻断放行；仅 `/healthz` 通过不足以放行。

## 12. E2E 验收

自动化场景：

```bash
python scripts/verify_v1.py | tee backups/target-drill-$DRILL_TS/verify-v1.txt
python scripts/staging_drill.py --cleanup | tee backups/target-drill-$DRILL_TS/staging-drill.txt
python -m pytest -m e2e tests/e2e/test_v1_acceptance.py -q | tee backups/target-drill-$DRILL_TS/e2e-pytest.txt
```

Redis Stream 复验：

```bash
docker compose exec redis sh -lc 'redis-cli -a "$REDIS_PASSWORD" XLEN guardian:alerts' | tee backups/target-drill-$DRILL_TS/e2e-redis-xlen.txt
docker compose exec redis sh -lc 'redis-cli -a "$REDIS_PASSWORD" XPENDING guardian:alerts guardian:web' | tee backups/target-drill-$DRILL_TS/e2e-redis-xpending.txt
docker compose exec redis sh -lc 'redis-cli -a "$REDIS_PASSWORD" XINFO GROUPS guardian:alerts' | tee backups/target-drill-$DRILL_TS/e2e-redis-xinfo-groups.txt
```

手工验收：

- 登录 `/login`。
- 打开 `/dashboard`，确认图表、实时连接和告警摘要。
- 打开 `/alerts`，确认告警列表、详情和状态流转。
- 打开 `/settings`，确认管理员可访问设置。
- 浏览器网络面板确认 `/socket.io/` 为 `101 Switching Protocols` 或轮询正常，无 CORS / Mixed Content 错误。
- 匿名访问受保护 `/api/*` 返回 `401`。

通过标准：

- `verify_v1.py` 场景通过。
- `staging_drill.py --cleanup` 通过，证明 Guardian -> Redis Stream -> Web consumer -> DB -> Socket.IO -> 历史查询闭环。
- E2E pytest 通过，尤其 Web 重启后历史告警可查询。
- Redis `XPENDING` 不持续增长，正常消费后回到 `0` 或客户约定阈值内。
- 手工页面和 WSS/Socket.IO 验收通过。

失败排查：

- E2E 场景失败：先确认 app 使用目标 DB/Redis，而不是本地 fallback。
- `staging_drill` pending 不归零：检查 Web consumer、数据库写入、Redis group 和 app 日志。
- 登录失败：确认 `ADMIN_USERNAME` 和 `ADMIN_PASSWORD_HASH`，不要在日志或证据中记录明文密码。
- WSS 失败：检查 Nginx `/socket.io/` Upgrade 头、TLS、CORS 和代理超时。

交付证据：

- `verify-v1.txt`。
- `staging-drill.txt`。
- `e2e-pytest.txt`。
- `e2e-redis-xlen.txt`、`e2e-redis-xpending.txt`、`e2e-redis-xinfo-groups.txt`。
- 登录、Dashboard、Alerts、Settings、WSS 网络面板截图。

阻断 Beta 放行：是。主链路 E2E、staging drill、Web 重启历史查询、WSS/Socket.IO 目标环境验证失败均阻断放行。若客户明确不启用 WebSocket 展示能力，需在交付边界中书面记录替代方式和影响。

## 13. HTTP 认证 API 压测

准备一次性压测账号或由客户临时提供管理员密码；不要把密码写入命令历史或证据文件。推荐用环境变量注入：

```bash
read -s BENCHMARK_PASSWORD
export BENCHMARK_USERNAME=admin
export BENCHMARK_PASSWORD
```

执行认证 API 压测：

```bash
python scripts/benchmark_http.py \
  --base-url http://127.0.0.1:5000 \
  --requests 1000 \
  --workers 32 \
  --warmup-requests 100 \
  --output-dir backups/target-drill-$DRILL_TS/benchmarks \
  --report-prefix target-auth-api
```

如需通过正式域名压测：

```bash
python scripts/benchmark_http.py \
  --base-url https://<GUARDIAN_CONSOLE_CUSTOMER_DOMAIN> \
  --requests 1000 \
  --workers 32 \
  --warmup-requests 100 \
  --output-dir backups/target-drill-$DRILL_TS/benchmarks \
  --report-prefix target-auth-api-tls
```

通过标准：

- 脚本能自动登录获取 JWT。
- 错误率为 `0.00%` 或在客户书面认可阈值内。
- 核心 API P95 目标参考 `< 300ms`。
- 报告产物生成 JSON 和 Markdown。
- 报告中不包含管理员密码、JWT、Redis 密码或数据库密码。

失败排查：

- 登录失败：确认压测账号、角色、密码哈希和 API 认证配置。
- 401/403 增多：确认 JWT 过期时间、RBAC 角色、压测 endpoints 是否需要 admin。
- P95 超标：检查数据库慢查询、容器 CPU/内存限制、Gunicorn threads、Nginx/LB、目标机器负载。
- 5xx：查看 app 日志和 `/readyz`，确认 DB/Redis/模型无故障。

交付证据：

- `backups/target-drill-$DRILL_TS/benchmarks/*.json`。
- `backups/target-drill-$DRILL_TS/benchmarks/*.md`。
- 压测时间窗口、并发、请求数和目标 URL 记录。

阻断 Beta 放行：是。认证 API 无法登录、核心 API 大量 4xx/5xx、错误率不可接受、P95 明显超出目标且无客户豁免，均阻断放行。

## 14. 日志中不得出现密钥

采集启动和演练日志：

```bash
docker compose logs --tail=1000 app > backups/target-drill-$DRILL_TS/app-logs-tail.txt
docker compose logs --tail=1000 redis > backups/target-drill-$DRILL_TS/redis-logs-tail.txt
test -f logs/production/security.log && tail -n 1000 logs/production/security.log > backups/target-drill-$DRILL_TS/security-log-tail.txt || true
```

敏感模式扫描：

```bash
{ grep -RInE 'SECRET_KEY|ADMIN_PASSWORD|ADMIN_PASSWORD_HASH|REDIS_PASSWORD|DATABASE_URL|postgresql://|postgresql\\+psycopg2://|BEGIN PRIVATE KEY|api[_-]?key|token=' backups/target-drill-$DRILL_TS/*.txt backups/target-drill-$DRILL_TS/*.log || true; } | tee backups/target-drill-$DRILL_TS/secret-scan.txt
```

如客户安全规范允许，可额外扫描最近 Docker 日志和应用日志目录：

```bash
grep -RInE 'SECRET_KEY|ADMIN_PASSWORD|ADMIN_PASSWORD_HASH|REDIS_PASSWORD|DATABASE_URL|postgresql://|postgresql\\+psycopg2://|BEGIN PRIVATE KEY|api[_-]?key|token=' logs docker-compose*.yml README.md docs/*.md || true
```

通过标准：

- app、redis、security 日志中不出现明文密钥、密码、管理员哈希、JWT、数据库连接串密码或私钥。
- 允许出现变量名本身，但不得出现真实值。
- `secret-scan.txt` 中如有命中，必须逐条确认是占位符、文档变量名或无敏感值。

失败排查：

- 真实密钥进入日志：立即停止传播证据包，按客户流程轮换对应密钥/密码，清理日志暴露面并重新演练。
- `DATABASE_URL` 带密码出现：修正日志打印逻辑或启动脚本，改为脱敏输出。
- JWT 或 API key 出现：缩短 token 生命周期并轮换，修正异常日志或调试日志级别。

交付证据：

- `app-logs-tail.txt`、`redis-logs-tail.txt`、`security-log-tail.txt`。
- `secret-scan.txt`。
- 若有命中：敏感性判定表、整改记录、轮换记录。

阻断 Beta 放行：是。任何真实密钥、密码、管理员哈希、JWT、数据库完整连接串或私钥进入日志或证据包，均阻断放行，完成轮换和复验后才可继续。

## 15. 可选：完整检测链路 `guardian` 复验

仅在客户书面授权抓包范围且主机具备 `NET_RAW` / `NET_ADMIN` 时执行：

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml --profile full-chain up -d guardian
docker compose -f docker-compose.yml -f docker-compose.prod.yml --profile full-chain ps | tee backups/target-drill-$DRILL_TS/guardian-ps.txt
docker compose -f docker-compose.yml -f docker-compose.prod.yml --profile full-chain logs --tail=200 guardian > backups/target-drill-$DRILL_TS/guardian-startup.log
curl -fsS http://127.0.0.1:5000/metrics | tee backups/target-drill-$DRILL_TS/metrics-after-guardian.txt
```

通过标准：

- `guardian` 进程运行。
- 日志无抓包权限错误、模型加载失败或 Redis 认证失败。
- 触发演练流量后 Redis Stream 有写入，Web 可消费入库。
- `/metrics` 中模型和 Redis Stream 指标符合客户验收口径。

失败排查：

- 权限错误：确认容器 `cap_add`、host network、客户授权和运行主机能力。
- 看不到流量：确认 `PACKET_INTERFACE`、镜像网络、主机网卡和镜像流量策略。
- Redis 写入失败：确认 `REDIS_HOST_FOR_GUARDIAN=127.0.0.1` 或客户 host 网络 Redis 地址。

交付证据：

- `guardian-ps.txt`。
- `guardian-startup.log`。
- `metrics-after-guardian.txt`。
- 客户抓包授权记录。

阻断 Beta 放行：视交付范围而定。若合同/交付边界要求启用 full-chain，则失败阻断放行；若 Beta 明确只交付 Web/API + Redis + DB + 模型就绪，则需记录“真实抓包未启用”的边界和原因。

## 16. Beta 放行阻断项汇总

以下失败必须阻断 Beta 放行：

| 类别 | 阻断条件 |
|------|----------|
| Docker/Compose | Docker daemon 不可用；Compose Plugin 不可用；`docker compose config` 失败；Redis 或 app 端口公网暴露 |
| Beta readiness | `scripts/check_production_readiness.py --env-file .env` 任一 `[FAIL]`；`DRY_RUN=false`；默认密钥/弱口令/明文生产密码 |
| PostgreSQL | `SELECT 1` 不通；迁移失败；`db current` 无目标 revision；核心表缺失 |
| Redis | 无密码；密码错误；公网暴露；`REQUIRE_REDIS_AVAILABLE=true` 下不可用；E2E 后 Stream 无法消费或 pending 持续增长 |
| 模型 | 关键模型/辅助文件缺失；manifest 缺失或非法；容器内模型不可读；模型目录不是只读挂载 |
| 初始化 | `python -m web.init_db --check` 失败；生产误用 `AUTO_CREATE_DB_TABLES=true` |
| 构建部署 | `docker compose build app` 失败且无客户批准的等价镜像；`app` / `redis` 不能稳定启动 |
| 健康检查 | `/readyz` 非 200；`/metrics` 不可采集；正式域名健康检查失败且无客户豁免 |
| E2E | `verify_v1.py`、`staging_drill.py --cleanup`、E2E pytest 或 Web 重启历史查询失败 |
| 压测 | 认证 API 无法登录；核心 API 大量 4xx/5xx；P95 明显超标且无客户书面豁免 |
| 日志安全 | 日志或证据包出现真实密钥、密码、管理员哈希、JWT、数据库完整连接串或私钥 |
| 真实封禁 | 若客户要求 `DRY_RUN=false`，但 `check_production_readiness.py --gate real-enforcement` 未通过，或审批、白名单、审计、回滚、解封、复盘证据不齐 |

## 17. 最终交付证据包

交付团队至少提交：

- `readiness.txt` 和 `env.sha256`。
- Docker/Compose 版本、`compose-config.yml`、镜像 ID、构建日志。
- PostgreSQL 连通性、迁移、`db current`、表清单、`web.init_db --check`。
- Redis 密码验证、内网监听、`XLEN`、`XPENDING`、`XINFO GROUPS`。
- 模型 manifest、模型 SHA256、容器内只读挂载检查。
- `app` / `redis` 启动状态和日志尾部。
- `/healthz`、`/readyz`、`/metrics` 输出。
- E2E、staging drill、认证 API 压测报告。
- 日志敏感信息扫描结果。
- 登录、Dashboard、Alerts、Settings、WSS/Socket.IO 截图。
- 若启用 full-chain：Guardian 启动、抓包授权、Redis Stream 入库证据。

最终结论填写：

| 项目 | 结论 |
|------|------|
| 目标环境复验结论 | 通过 / 有条件通过 / 不通过 |
| 阻断项是否清零 | 是 / 否 |
| 是否允许进入首批单企业私有化 Beta | 是 / 否 |
| 遗留问题 |  |
| 客户代表 |  |
| 交付负责人 |  |
| 研发负责人 |  |
