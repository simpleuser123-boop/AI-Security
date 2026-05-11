# 宿主机非降级真实依赖环境

此环境只启动本机 PostgreSQL 与 Redis，用于宿主机非降级集成测试。它不启动应用容器，不连接客户数据库，不导入客户资料。应用从宿主机访问依赖时必须使用 `127.0.0.1` 发布端口，不能使用 Compose 内部服务名 `postgres` / `redis`。

## 启动

```powershell
python scripts/start_local_deps.py --env-file .env.host-nondegraded.example
```

启动脚本会先检查 `55432` / `56379`：

- 端口空闲：按 `.env.host-nondegraded.example` 启动本项目 PostgreSQL / Redis，并等待健康检查。
- 两个端口都已被健康依赖占用，且当前 env 可用同一组账号/密码连通：复用已有依赖，不创建新容器。
- 端口被其他进程或不匹配依赖占用：默认明确失败并提示占用方；不会强行停止非本项目容器。

如需使用备用端口，必须显式指定 `--port-strategy alternate`。脚本会把更新后的 `DATABASE_URL`、`LOCAL_POSTGRES_PORT`、`LOCAL_REDIS_PORT` 和 `REDIS_PORT` 写入 `tmp/local-deps.env`，后续验证也必须使用这个 env 文件：

```powershell
python scripts/start_local_deps.py --env-file .env.host-nondegraded.example --port-strategy alternate
python scripts/verify_local_deps.py tmp/local-deps.env
```

如需只检查冲突并失败，不复用也不换端口：

```powershell
python scripts/start_local_deps.py --env-file .env.host-nondegraded.example --port-strategy fail
```

## 验证

```powershell
python scripts/verify_local_deps.py .env.host-nondegraded.example
```

验证脚本会强制检查：

- PostgreSQL 可连接，且 `DATABASE_URL` backend 为 `postgresql`
- `DATABASE_URL` 主机必须为 `127.0.0.1`
- `DATABASE_URL` 端口必须等于 `LOCAL_POSTGRES_PORT`
- Redis 使用 `REDIS_PASSWORD` 完成 AUTH 后 `PING` 返回 `PONG`
- `REDIS_HOST` 必须为 `127.0.0.1`
- `REDIS_PORT` 必须等于 `LOCAL_REDIS_PORT`
- `config.config.get_config()` 解析出的 `SQLALCHEMY_DATABASE_URI` 等于本地 PostgreSQL `DATABASE_URL`
- `RedisClient.mode` 为 `redis`，不是 `memory`
- `GUARDIAN_REDIS_DISABLE_CONNECT` 不是 `true`
- `REQUIRE_REDIS_AVAILABLE` 是 `true`

## 非降级测试入口

```powershell
python scripts/run_non_degraded_tests.py
```

该入口会先加载 `.env.host-nondegraded.example`，再执行 `scripts/verify_local_deps.py`，最后运行脚本内的严格 pytest 探针。入口强制要求：

- `DATABASE_URL` 为 `127.0.0.1` 上的本地 PostgreSQL，禁止 SQLite、`localhost` 和 Compose 服务名
- Redis 使用真实连接和密码认证，`RedisClient.mode` 必须为 `redis`
- `REDIS_HOST` 必须为 `127.0.0.1`，禁止 `localhost` 和 Compose 服务名
- `GUARDIAN_REDIS_DISABLE_CONNECT` 不得为 `true`
- `REQUIRE_REDIS_AVAILABLE` 与 `REQUIRE_MODELS_READY` 必须为 `true`
- pytest 过程中出现 skip 会直接失败

## 停止

```powershell
docker compose -p ai-security-guardian-local-deps --env-file .env.host-nondegraded.example -f docker-compose.local-deps.yml down
```

如果使用了备用端口：

```powershell
docker compose -p ai-security-guardian-local-deps --env-file tmp/local-deps.env -f docker-compose.local-deps.yml down
```

如需清空本地测试卷：

```powershell
docker compose -p ai-security-guardian-local-deps --env-file .env.host-nondegraded.example -f docker-compose.local-deps.yml down -v
```
