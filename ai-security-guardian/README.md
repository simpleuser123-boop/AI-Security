# AI-Security-Guardian

基于 Python 的安全检测与响应示例系统，包含 Web 控制台、REST API、检测主循环和审计日志完整性保护。

## 模块结构

- `web/`：Flask 页面、API、WebSocket 与前端静态资源。
- `src/collectors/`：流量与日志采集、威胁情报查询。
- `src/features/`：特征提取。
- `src/detectors/`：DDoS/入侵/Web/异常检测引擎。
- `src/decision/`：融合决策。
- `src/response/`：响应动作（封禁/隔离等）。
- `src/audit/`：审计日志与哈希链完整性。
- `main.py`：完整检测链路入口（Phase 8）。

## 本地启动

1. 安装依赖：

```bash
python -m pip install -r requirements.txt
```

2. 配置环境：

```bash
cp .env.example .env
```

至少修改：`SECRET_KEY`、`ADMIN_PASSWORD_HASH`、`REDIS_PASSWORD`；生产环境详见 [docs/deployment.md](docs/deployment.md)（明文 `ADMIN_PASSWORD` 仅用于开发回退）。

生产配置上线前可执行一键校验：

```bash
python scripts/check_production_readiness.py
```

脚本只读取当前环境与 `.env`，不会自动修改 `.env`；任一关键项失败都会返回非 0 退出码。

3. 启动 Web/API（默认 5000）：

```bash
python -m web.app
```

4. 启动完整检测链路（主入口）：

```bash
python main.py
```

## Docker 启动

- 仅启动 Web/API（默认）：

```bash
docker compose up --build
```

- 启动完整链路（包含 `guardian` profile）：

```bash
docker compose --profile full-chain up --build
```

生产部署、Redis、TLS、演练与回滚见 **[docs/deployment.md](docs/deployment.md)**。  
v1.0 功能/安全/性能逐项勾选见 **[docs/acceptance-checklist.md](docs/acceptance-checklist.md)**。
审计日志归档、hash chain 基线重建与证据保存见 **[docs/audit-log-baseline.md](docs/audit-log-baseline.md)**。
CI/CD 与测试分组见 **[docs/ci-test-groups.md](docs/ci-test-groups.md)**。

## 关键环境变量

请参考 `.env.example`，常用项如下：

- `SECRET_KEY`：JWT 与 Flask 密钥，必须修改。
- `ADMIN_USERNAME` / `ADMIN_PASSWORD_HASH`：管理员认证，推荐只用哈希。
- `ADMIN_ROLE`：基础 RBAC 角色，支持 `viewer` / `analyst` / `admin`；默认 `admin`。
- `DATABASE_URL`：数据库连接。生产必须使用 PostgreSQL；SQLite 仅用于开发/测试。
- `REDIS_HOST` / `REDIS_PORT` / `REDIS_PASSWORD`：缓存与队列。
- `REQUIRE_REDIS_AVAILABLE`：设为 `true` 时，Redis 不可达将启动失败（生产建议开启）。
- `REQUIRE_MODELS_READY`：设为 `true` 时，关键模型缺失将启动失败（生产建议开启）。
- `LOG_INTEGRITY_ENABLED`：审计日志哈希链开关。
- `AUDIT_ENV` / `AUDIT_LOG_DIR`：审计日志环境与目录；默认按 `logs/test|dev|staging|production` 隔离。
- `MODEL_DIR`：模型目录，默认 `models/saved`。
- `MODEL_DELIVERY_MODE`：模型交付方式（`repository`/`artifact`）。
- `MODEL_ARTIFACT_URI`：模型不随仓库时的下载地址或制品说明。

## 模型交付策略与就绪校验

默认策略：模型文件**不强制随仓库提交**，可通过外部制品平台或内网共享目录分发。

- 若 `MODEL_DELIVERY_MODE=repository`：确认 `MODEL_DIR` 下存在已训练模型文件。
- 若 `MODEL_DELIVERY_MODE=artifact`：先按 `MODEL_ARTIFACT_URI` 拉取模型到 `MODEL_DIR`，再启动服务。

最小就绪检查（Windows PowerShell 示例）：

```powershell
python -c "import os,sys; d=os.getenv('MODEL_DIR','models/saved'); req=['intrusion_rf_v1.pkl','ddos_rf_v1.pkl','web_attack_nb_v1.pkl','anomaly_if_v1.pkl']; miss=[f for f in req if not os.path.exists(os.path.join(d,f))]; print('MODEL_DIR=',d); print('missing=',miss); sys.exit(1 if miss else 0)"
```

训练脚本位置（按需生成模型）：

- `models/train/train_intrusion.py`
- `models/train/train_ddos.py`
- `models/train/train_web_attack.py`
- `models/train/train_anomaly.py`

## 最小验证流程

```bash
python -m pytest -q
python scripts/check_production_readiness.py
python scripts/verify_v1.py
python scripts/benchmark_p95.py
python -m pytest tests/e2e/test_v1_acceptance.py -q
python -m tests._smoke_phase7
python -m tests._phase8_smoke
```

- **默认单元/离线测试**：`python -m pytest -q`。默认排除 `slow`、`integration`、`e2e`，并禁用真实 Redis 连接，使用内存降级路径，适合本地和 CI 快速验证。
- **慢测**：`python -m pytest -m slow -q`；包含有意等待外部超时/降级的测试。
- **集成测试**：`$env:GUARDIAN_REDIS_DISABLE_CONNECT="false"; python -m pytest -m integration -q`（PowerShell）。Redis Stream 集成测试需要可用 Redis；未连上时测试会跳过。
- **E2E 验收**：`python -m pytest -m e2e -q` 或直接运行 `python -m pytest tests/e2e/test_v1_acceptance.py -q`。
- **端到端验收**：`scripts/verify_v1.py`（场景 1～9）；场景 10（Web 重启后仍可查库内告警）由 `tests/e2e/test_v1_acceptance.py` 覆盖。  
- **压测与 P95**：`scripts/benchmark_p95.py`（检测链路与 HTTP 粗测；Redis Stream 观测命令见脚本输出）。  

手动检查流程：`/login` -> `/dashboard` -> `/alerts` -> `/settings`。

## 数据库初始化说明

- 开发/测试：默认使用 SQLite，应用启动会自动创建缺失表，便于本地快速验证。
- 生产：必须显式配置 PostgreSQL `DATABASE_URL`，应用启动不会自动建表，也不应依赖 `AUTO_CREATE_DB_TABLES=true`。
- 生产首次上线：在空库、账号和网络 ACL 准备完成后执行 `python -m web.init_db`，再执行 `python -m web.init_db --check` 验证表结构存在。
- 后续模型变更以外的数据库结构升级：当前项目尚未引入 Alembic/Flask-Migrate；生产变更应先在暂存库验证 SQL/脚本、备份生产库，再在维护窗口执行。详见 [docs/deployment.md](docs/deployment.md)。

## 企业控制面最小闭环

当前优先落地低风险、高价值的企业化能力：

1. 基础 RBAC：JWT 携带 `role`，`viewer` 仅读，`analyst` 可处置告警，`admin` 可改规则、IOC、封禁、设置并查询审计。
2. 操作审计查询：登录、告警处置、规则/IOC/封禁/设置/命令等关键写操作会写入 `audit_events` 表。
3. 审计 API：`GET /api/audit/events`，支持 `event_type`、`actor`、`resource_type`、`resource_id`、`ip_address`、`since`、`until`、`limit`、`offset` 查询，仅 `admin` 可访问。

建议后续顺序：告警误报反馈指标化 -> 企业通知失败重试可视化 -> 报告导出补审计摘要与 CSV。

## 常见故障排查

- Redis 连接失败：
  - 检查 `REDIS_HOST/REDIS_PORT/REDIS_PASSWORD`。
  - Docker 模式下 `app` 到 Redis 使用 `redis` 主机名。
- 模型缺失或未加载：
  - 执行上面的就绪检查命令，确认 `MODEL_DIR` 与文件名一致。
  - 查看 `main.py` 启动日志中的模型加载结果。
- 权限问题（抓包）：
  - `main.py` 抓包需要管理员权限或容器 `NET_RAW/NET_ADMIN` 能力。
  - 无权限时可加 `--no-packet-capture` 先降级运行。
- 健康检查失败：
  - `/healthz`：进程存活探针，只确认 Flask 进程能快速响应，不检查 Redis/DB/模型。
  - `/readyz`：生产就绪探针，带短超时检查 DB、Redis、配置和模型；依赖不可用时返回 503。
  - `/api/health`：前端/管理端展示接口，始终快速返回 JSON，依赖异常体现在 `checks`/`degraded`。
  - Docker 中可用 `docker compose ps` 与容器日志进一步定位。

