# 本地生产部署演练记录（2026-05-05）

项目目录：`C:\Users\yyl\Desktop\ai安全\ai-security-guardian`

参考文档：`docs/deployment.md`

## 结论

- Redis、数据库初始化、健康检查、备份、数据库回滚、模型恢复校验均已完成。
- Docker Compose 的 `redis` 服务已启动并处于 healthy。
- Docker Compose 的 `app` 镜像构建未完成，原因是 Docker Hub OAuth token 请求超时，无法拉取 `python:3.10-slim` 元数据。因此 `app` 容器启动、容器内 `python -m web.init_db`、容器内 `/readyz` 未能真实执行。
- 为覆盖流程，使用同一代码、同一 Redis、生产变量约束、本地 SQLite 演练库执行了等价的数据库初始化与健康检查。
- 发现一个配置风险：`.env` 中 `ADMIN_PASSWORD_HASH` 包含 `$`，`docker compose config` 将哈希片段识别为 Compose 变量，导致合成配置里的哈希被截断并持续打印 warning。

## 1. 前置检查

命令：

```powershell
docker version
docker compose version
python scripts/check_production_readiness.py
```

结果：

- Docker Client/Server：`29.4.1`
- Docker Desktop：`4.71.0`
- Docker Compose：`v5.1.3`
- `scripts/check_production_readiness.py`：`Result: PASS`
- 模型目录 `models/saved` 存在，关键模型文件和 manifest 均存在。

备注：

- 当前 `.env` 中 `DATABASE_URL=postgresql://guardian:CHANGE_ME_STRONG_PASSWORD@localhost:5432/guardian`。
- 当前 `.env` 中 `AUTO_CREATE_DB_TABLES=true`，与部署文档要求的生产基线 `false` 不一致。
- 当前 `.env` 中 `DRY_RUN=false`。演练时通过命令级环境变量覆盖为 `DRY_RUN=true`，避免真实响应动作。

## 2. Docker Compose 启动

新增本地演练 override：

```yaml
services:
  app:
    ports: !override
      - "127.0.0.1:5000:5000"
```

文件：`docker-compose.prod-drill.yml`

Redis 启动命令：

```powershell
docker compose -f docker-compose.yml -f docker-compose.prod-drill.yml up -d redis
docker compose -f docker-compose.yml -f docker-compose.prod-drill.yml ps
```

结果：

- `ai-security-guardian-redis` 已运行。
- 状态：`Up ... (healthy)`
- 端口：`127.0.0.1:6379->6379/tcp`

App 构建命令：

```powershell
docker compose -f docker-compose.yml -f docker-compose.prod-drill.yml build app
```

结果：

- 失败。
- 失败点：拉取 `python:3.10-slim` 元数据。
- 错误摘要：`failed to fetch oauth token ... https://auth.docker.io/token ... connectex ... did not properly respond`
- 本机无 `ai-security-guardian` 镜像可复用。

## 3. Redis 密码验证

命令：

```powershell
docker compose exec redis sh -lc 'redis-cli ping || true'
docker compose exec redis sh -lc 'redis-cli -a "$REDIS_PASSWORD" ping'
docker compose exec redis sh -lc 'redis-cli -a WRONG ping || true'
docker compose exec redis sh -lc 'redis-cli -a "$REDIS_PASSWORD" XLEN guardian:alerts'
```

结果：

- 无密码 `PING`：`NOAUTH Authentication required.`
- 正确密码 `PING`：`PONG`
- 错误密码：`AUTH failed: WRONGPASS invalid username-password pair or user is disabled.`
- `guardian:alerts` Stream 长度：`0`

结论：Redis requirepass 生效，密码验证通过。

## 4. 数据库初始化

由于 app 镜像构建失败，容器内初始化未执行。等价本地初始化使用：

```powershell
DATABASE_URL=sqlite:///C:/Users/yyl/Desktop/ai安全/ai-security-guardian/data/security-drill-local.db
AUTO_CREATE_DB_TABLES=false
DRY_RUN=true
python -m web.init_db
```

结果：

- 命令退出码：`0`
- 输出：`Database tables created successfully.`
- 表清单：
  - `alert_histories`
  - `alerts`
  - `audit_events`
  - `banned_ips`
  - `iocs`
  - `model_versions`
  - `response_actions`
  - `response_schedule_tasks`
  - `rules`
  - `settings`

备注：

- 首次初始化过程中，应用工厂会在建表前读取 `settings`、`banned_ips`、`iocs`，因此出现过 `no such table` warning。
- 建表最终成功，表清单验证通过。

## 5. 健康检查与 /readyz

由于 app 容器未能构建，使用本地进程启动 `python -m web.app`，并显式设置生产演练变量：

- `FLASK_ENV=production`
- `DATABASE_URL=sqlite:///C:/Users/yyl/Desktop/ai安全/ai-security-guardian/data/security-drill-local.db`
- `AUTO_CREATE_DB_TABLES=false`
- `DRY_RUN=true`
- `REDIS_HOST=127.0.0.1`
- `MODEL_DIR=models/saved`

结果：

- `GET http://127.0.0.1:5000/api/health`：HTTP 200
- `GET http://127.0.0.1:5000/healthz`：HTTP 200，`{"component":"ai-security-guardian-web","status":"live"}`
- `GET http://127.0.0.1:5000/readyz`：HTTP 200
- `/readyz` 检查项：`config/database/redis/models` 均为 ok。

备注：

- 本地 Flask 服务默认监听 `0.0.0.0:5000`，不同于 Docker 演练 override 的 `127.0.0.1:5000` 绑定策略。
- 健康检查后本地进程已停止。

## 6. 备份流程

备份目录：

```text
C:\Users\yyl\Desktop\ai安全\ai-security-guardian\backups\20260505190002
```

备份对象：

- `.env` -> `env.production`
- SQLite 演练库 -> `security-drill-local.db`
- 模型目录 -> `models-saved.tar.gz`
- 日志目录 -> `logs.tar.gz`
- Compose 状态 -> `compose-ps.txt`
- 镜像清单 -> `images.txt`
- 模型文件 SHA256 清单 -> `models-saved.sha256`

SHA256 校验结果：

- `env.production`：PASS
- `security-drill-local.db`：PASS
- `models-saved.tar.gz`：PASS
- `logs.tar.gz`：PASS

备份文件大小：

- `env.production`：850 bytes
- `security-drill-local.db`：143360 bytes
- `models-saved.tar.gz`：3133152 bytes
- `logs.tar.gz`：42668 bytes

## 7. 回滚与恢复演练

数据库回滚步骤：

1. 在 `audit_events` 插入演练标记 `rollback-drill-marker-20260505190002`。
2. 验证插入后标记计数为 `1`。
3. 使用备份 `security-drill-local.db` 覆盖恢复。
4. 验证恢复后标记计数为 `0`。
5. 验证表数量仍为 `10`。

结果：

- `before=0`
- `after_insert=1`
- `after_restore_marker_count=0`
- `table_count=10`

模型恢复校验：

1. 将 `models-saved.tar.gz` 解压到 `.tmp/models-restore-drill-20260505190002`。
2. 重新计算模型文件 SHA256。
3. 与备份目录中的 `models-saved.sha256` 对比。

结果：

- `MODEL_HASH_MATCH`
- 10 个模型/manifest/辅助文件均存在。

恢复后健康检查：

- 重新启动本地应用后访问 `/readyz`。
- 结果：HTTP 200。

## 8. 风险与整改项

1. Docker Hub 当前不可达导致 app 镜像无法构建。需要配置 Docker registry mirror，或预拉取/内部分发 `python:3.10-slim`。
2. `.env` 中 `ADMIN_PASSWORD_HASH` 的 `$` 会触发 Compose 插值 warning，并在 `docker compose config` 中显示为截断值。建议将该值移出 Compose 插值路径，例如使用 `env_file` 专用文件且避免在 `environment` 中重复展开，或按 Compose 规则转义 `$`。
3. `.env` 当前 `AUTO_CREATE_DB_TABLES=true`，不符合部署手册生产基线。生产应改为 `false`，首次上线显式执行 `python -m web.init_db`。
4. `.env` 当前 `DRY_RUN=false`，本地演练已覆盖为 `true`。生产关闭 DRY_RUN 前仍需完成误封恢复演练和业务白名单确认。
5. 当前 `.env` 的 PostgreSQL 连接串仍含 `CHANGE_ME_STRONG_PASSWORD`，本地演练未连接外部 PostgreSQL。
