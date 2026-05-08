# AI-Security-Guardian 单企业私有化 Beta 客户试点交付包

版本：Beta 首批试点  
适用对象：单一企业客户私有化部署、试点验收和试运行  
默认安全模式：`DRY_RUN=true`

本文档面向客户项目负责人、安全运营团队、运维团队、DBA、网络/云平台管理员和变更审批人。文档中的命令以 Linux 服务器和 Docker Compose 部署为默认口径；如客户使用等效平台，可按客户标准替换命令，但验收证据和边界要求保持不变。

## 1. 试点目标和边界

### 1.1 试点目标

本次试点目标是在客户授权的单企业私有化环境中，完成 AI-Security-Guardian 的可部署、可观测、可审计、可备份、可恢复、可验收闭环，验证其对安全告警检测、告警持久化、控制台查看、状态流转和 dry-run 响应演练的适配效果。

试点期重点验证：

| 目标 | 验证方式 | 通过口径 |
|------|----------|----------|
| 私有化环境可部署 | Docker Compose、PostgreSQL、Redis、模型目录、Nginx/TLS | 服务可启动，`/readyz` 通过 |
| 安全配置可审计 | readiness 检查、`.env` SHA256、CORS、Redis 密码、审计日志 | 无默认密钥、无弱配置、证据可追溯 |
| 检测与告警闭环 | 演练流量、`verify_v1.py`、控制台告警列表 | 告警可生成、入库、查询、流转 |
| 运维可执行 | 健康检查、Redis Stream、日志、备份恢复 | 客户运维可按步骤检查和恢复 |
| 响应动作可演练 | `DRY_RUN=true` 响应记录、误封恢复演练 | 不执行真实封禁，审计记录完整 |

### 1.2 本次试点范围

| 范围 | 本次是否包含 | 说明 |
|------|--------------|------|
| 单企业私有化部署 | 包含 | 一套客户私有化环境，不承诺多企业共用 |
| Web/API 控制台 | 包含 | 登录、Dashboard、Alerts、Settings、核心 API |
| PostgreSQL 正式数据库 | 包含 | 生产/Beta 必须使用 PostgreSQL，SQLite 仅限开发测试 |
| Redis 队列与缓存 | 包含 | 必须启用密码和内网访问控制 |
| 模型文件与 manifest | 包含 | 按交付清单提供模型或制品地址及 SHA256 |
| 审计日志哈希链 | 包含 | 关键操作审计和完整性检查 |
| 告警状态流转 | 包含 | 确认、解决、忽略等基础流转 |
| dry-run 响应演练 | 包含 | 默认 `DRY_RUN=true`，只记录不封禁 |
| 真实抓包 | 有条件包含 | 需客户书面授权、网卡权限和部署节点满足要求 |
| 真实封禁 | 默认不包含 | 仅在单独审批和真实封禁 gate 通过后开启 |

### 1.3 本次试点不包含的能力

以下能力不在首批单企业私有化 Beta 默认交付范围内：

| 不包含能力 | 说明 |
|------------|------|
| 多租户 / 多企业隔离 | 本次为单企业私有化试点，不提供多客户共享 SaaS 隔离承诺 |
| 企业 SSO / LDAP / OIDC | 默认使用系统管理员账号和基础 RBAC |
| 高可用集群承诺 | 默认单套 Docker Compose 部署；客户可自行提供 PostgreSQL/Redis 高可用底座 |
| 商业化 SLA | Beta 试点不承诺正式商用 SLA、赔付条款或 7x24 托管运维 |
| 自动化安装器 | 以交付手册、脚本和模板为主 |
| 完整通知中心 | 邮件、Webhook 等外部通知为可选配置，需客户提供通道后单独验证 |
| 模型线上效果运营平台 | 本次提供模型就绪和基础检测验证，不提供完整漂移监控和模型灰度平台 |
| 自动化大规模响应编排 | 默认 dry-run，真实响应必须单独审批 |
| 客户网络整改 | 防火墙、证书、域名、数据库账号、Nginx 等由客户按自身标准提供 |

## 2. 客户环境前置条件

客户需在部署前准备以下条件，并在交付前置会上确认。

| 类别 | 前置条件 | 验证方式 |
|------|----------|----------|
| 主机 | Linux 服务器或等效容器运行环境，已安装 Docker Engine 和 Docker Compose Plugin | `docker version`、`docker compose version` |
| 目录 | 已准备 `data/`、`logs/`、`models/saved/`、`backups/`、`release-env/` | `ls -ld` 和权限截图 |
| 域名与证书 | 客户正式 HTTPS 控制台域名和证书 | `curl -Ik https://<domain>/api/health` |
| 网络 | 对外仅开放 `80/443`；`5000` 仅对本机 Nginx 或内网 LB；Redis 不公网开放 | `ss -lntp`、安全组/防火墙截图 |
| PostgreSQL | 客户提供可连接 PostgreSQL 数据库、账号和网络 ACL | `SELECT 1` 通过 |
| Redis | Redis 使用强密码，客户确认端口访问范围 | `redis-cli -a "$REDIS_PASSWORD" ping` |
| 模型目录 | 模型文件、辅助文件、manifest 已放入 `models/saved` | SHA256 清单 |
| 时间同步 | 服务器时间同步，推荐 NTP | `timedatectl` |
| 运维权限 | 客户指定可执行部署、重启、备份、恢复和日志查看的人员 | 负责人名单 |
| 抓包授权 | 若启用 guardian full-chain，需客户授权抓包范围和网卡 | 授权记录 |
| 变更窗口 | 客户确认部署、验收、回滚和问题响应窗口 | 变更单 |

## 3. 客户需要提供的信息

请客户填写 [客户环境信息收集表](../templates/customer-beta-environment-intake.md)，至少包含：

| 信息 | 用途 | 注意事项 |
|------|------|----------|
| 客户名称、环境名称、联系人 | 交付记录和问题升级 | 至少包含项目、安全、运维、DBA、网络负责人 |
| 控制台域名 | `ALLOWED_ORIGINS`、Nginx TLS | 必须是正式 HTTPS Origin |
| PostgreSQL 连接信息 | `DATABASE_URL` 和迁移 | 交付证据不得保存明文密码 |
| Redis 主机、端口、密码 | Redis 连接和健康检查 | 密码由客户保管 |
| 管理员账号策略 | 生成 `ADMIN_PASSWORD_HASH` | 生产禁止使用明文 `ADMIN_PASSWORD` |
| 模型交付方式 | `MODEL_DELIVERY_MODE`、`MODEL_ARTIFACT_URI` | 需保留 SHA256 和 manifest |
| 需要监控的流量范围 | guardian 抓包和告警验证 | 需客户授权 |
| 业务白名单 | 真实封禁前保护核心资产 | Beta dry-run 阶段也建议准备 |
| 备份介质和保留策略 | 数据库、日志、模型、配置备份 | 明确 RTO/RPO 目标 |
| 问题上报通道 | 试点期间支持流程 | 邮件、群组、工单或热线 |

## 4. 部署步骤

### 4.1 准备发布目录

```bash
cd /opt/ai-security-guardian
mkdir -p data logs models/saved backups release-env
chmod 750 data logs models models/saved release-env
chmod 700 backups
cp .env.example .env
chmod 600 .env
```

### 4.2 填写客户 `.env`

可参考 [单企业私有化 Beta 客户专用 `.env` 模板与 readiness 清单](private-beta-env-checklist.md)。关键要求：

| 变量 | Beta 要求 |
|------|-----------|
| `FLASK_ENV` | `production` |
| `AUDIT_ENV` | `production` |
| `SECRET_KEY` | 客户生成，至少 32 字符，不使用示例值 |
| `ADMIN_PASSWORD_HASH` | 使用脚本生成，生产禁止依赖明文 `ADMIN_PASSWORD` |
| `DATABASE_URL` | 指向客户真实 PostgreSQL |
| `AUTO_CREATE_DB_TABLES` | `false` |
| `REDIS_PASSWORD` | 客户强密码 |
| `ALLOWED_ORIGINS` | 客户正式 HTTPS Origin |
| `DRY_RUN` | Beta 默认且必须为 `true` |
| `RUNTIME_GUARDS_ENABLED` | `true` |
| `REQUIRE_REDIS_AVAILABLE` | `true` |
| `REQUIRE_MODELS_READY` | `true` |
| `LOG_INTEGRITY_ENABLED` | `true` |

生成密钥和管理员密码哈希：

```bash
python -c "import secrets; print(secrets.token_hex(32))"
python scripts/generate_admin_password_hash.py
```

### 4.3 放置模型文件

```bash
ls -l models/saved
find models/saved -maxdepth 1 -type f -exec sha256sum {} \; | sort > backups/model-sha256-prelaunch.txt
docker compose run --rm app sh -lc 'ls -l /app/models/saved && test -r /app/models/saved/intrusion_rf_v1.pkl'
```

### 4.4 配置预检查

```bash
python scripts/check_production_readiness.py
docker compose config
```

通过标准：

- `check_production_readiness.py` 无 `[FAIL]`。
- 默认 `private-beta` gate 允许且要求 `DRY_RUN=true`。
- `docker compose config` 可正常渲染。
- 输出证据不得包含密钥、密码、管理员哈希明文。

### 4.5 启动 Redis 和初始化数据库

```bash
docker compose up -d redis
docker compose exec redis sh -lc 'redis-cli -a "$REDIS_PASSWORD" ping'
docker compose run --rm app flask --app web.migration_app:create_migration_app db upgrade
docker compose run --rm app python -m web.init_db --check
```

### 4.6 启动 Web/API

生产建议通过 `docker-compose.prod.yml` 限制 app 仅监听本机：

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

### 4.7 配置 Nginx TLS/WSS

按 [生产部署、回滚与备份恢复手册](deployment.md) 配置 Nginx。验证：

```bash
sudo nginx -t
sudo systemctl reload nginx
curl -Ik https://<GUARDIAN_CONSOLE_DOMAIN>/api/health
```

浏览器登录控制台后，确认 `/socket.io/` 连接正常，无 CORS 或 Mixed Content 错误。

### 4.8 可选启用完整检测链路

仅当客户授权抓包并确认运行节点具备 `NET_ADMIN` / `NET_RAW` 能力时启用：

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml --profile full-chain up -d guardian
docker compose -f docker-compose.yml -f docker-compose.prod.yml --profile full-chain ps
docker compose -f docker-compose.yml -f docker-compose.prod.yml logs --tail=100 guardian
```

未启用 full-chain 时，试点结论中必须注明“真实流量抓包检测未启用，仅完成控制台、模型、数据库、队列和演练链路验证”。

## 5. 初始化步骤

完成部署后执行以下初始化。

| 步骤 | 操作 | 验收 |
|------|------|------|
| 管理员登录 | 使用客户指定管理员账号登录 `/login` | 可进入 Dashboard |
| 基础配置核对 | 检查 Settings、CORS、运行模式 | 确认为 `DRY_RUN=true` |
| 数据库检查 | 执行 `python -m web.init_db --check` | 表结构检查通过 |
| Redis Stream 检查 | 执行 `XLEN`、`XPENDING`、`XINFO GROUPS` | 无持续堆积 |
| 模型检查 | 执行模型文件和 manifest SHA256 对比 | 缺失列表为空 |
| 审计检查 | 执行审计日志完整性校验或查看 `/metrics` | `audit_integrity_valid` 为有效 |
| 演练 IOC/规则 | 按客户授权写入演练数据 | 操作有审计记录 |
| 试点白名单 | 录入或确认办公出口、LB、监控、DNS、数据库、堡垒机等资产 | 真实封禁前必须完成 |

推荐命令：

```bash
docker compose ps
docker compose exec redis sh -lc 'redis-cli -a "$REDIS_PASSWORD" XLEN guardian:alerts'
docker compose exec redis sh -lc 'redis-cli -a "$REDIS_PASSWORD" XPENDING guardian:alerts guardian:web'
curl -fsS http://127.0.0.1:5000/metrics | grep -E 'audit_integrity_valid|redis_stream|guardian_model_ready'
```

## 6. 验收步骤

### 6.1 自动化验收

```bash
python scripts/check_production_readiness.py
python scripts/verify_v1.py
python -m pytest -q
python scripts/staging_drill.py --cleanup
python scripts/benchmark_p95.py
```

如客户提供测试账号密码，可执行核心 API 压测：

```bash
BENCHMARK_USERNAME=<USER> BENCHMARK_PASSWORD='<PASSWORD>' \
python scripts/benchmark_http.py \
  --base-url http://127.0.0.1:5000 \
  --requests 1000 \
  --workers 32 \
  --warmup-requests 100
```

### 6.2 手工验收

| 验收项 | 操作 | 通过标准 |
|--------|------|----------|
| 登录 | 访问 `/login` | 正确账号可登录，错误账号失败 |
| Dashboard | 访问 `/dashboard` | 页面正常，实时连接正常 |
| Alerts | 访问 `/alerts` | 告警列表、详情、状态流转可用 |
| Settings | 访问 `/settings` | 管理员可查看和修改允许项 |
| API 认证 | 匿名访问受保护 `/api/*` | 返回 `401` |
| 健康检查 | 访问 `/api/health`、`/healthz`、`/readyz` | 均成功 |
| 历史查询 | 重启 Web 后查询历史告警 | 历史告警仍可查询 |
| 审计 | 执行一次配置或告警状态变更 | 审计事件可追溯 |

### 6.3 验收签收

客户和交付团队按 [试点验收签收表](../templates/customer-beta-acceptance-signoff.md) 签收。若存在遗留项，应明确是否“有条件通过”、整改责任人和计划日期。

## 7. 运维检查步骤

试点期间建议每日检查一次，变更后立即检查一次。

| 检查项 | 命令 / 方式 | 正常标准 |
|--------|-------------|----------|
| 容器状态 | `docker compose ps` | app、redis 为 healthy/running |
| 进程健康 | `curl -fsS http://127.0.0.1:5000/healthz` | 200 |
| 就绪状态 | `curl -fsS http://127.0.0.1:5000/readyz` | ready |
| Redis 密码 | `redis-cli -a "$REDIS_PASSWORD" ping` | PONG |
| Redis Stream | `XLEN`、`XPENDING`、`XINFO GROUPS` | 不持续增长 |
| 磁盘空间 | `df -h` | 日志、备份、数据盘空间充足 |
| 日志错误 | `docker compose logs --tail=200 app` | 无持续异常 |
| 审计完整性 | `/metrics` 或审计校验脚本 | 哈希链有效 |
| 模型状态 | `/readyz`、模型目录 SHA256 | 模型可读 |
| 证书有效期 | 客户证书平台或 `openssl` | 证书未临期 |

运维检查结果建议填写 [试点运维检查记录](../templates/customer-beta-ops-checklog.md)。

## 8. 备份恢复步骤

### 8.1 备份范围

每次发布、配置变更、模型更新和试点关键里程碑前，至少备份：

- PostgreSQL 数据库。
- `.env` 或客户密钥系统中的同版本配置。
- `models/saved` 模型目录和 SHA256 清单。
- `logs/` 审计日志和归档日志。
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
export BACKUP_TS=<BACKUP_TIMESTAMP>
sha256sum -c backups/$BACKUP_TS/env.production.sha256
sha256sum -c backups/$BACKUP_TS/guardian_prod.dump.sha256
sha256sum -c backups/$BACKUP_TS/logs.tar.gz.sha256

createdb guardian_restore_drill
pg_restore -d guardian_restore_drill backups/$BACKUP_TS/guardian_prod.dump
psql guardian_restore_drill -c '\dt'
```

恢复后检查：

```bash
python scripts/check_production_readiness.py
docker compose up -d redis app
curl -fsS http://127.0.0.1:5000/api/health
curl -fsS http://127.0.0.1:5000/healthz
curl -fsS http://127.0.0.1:5000/readyz
python scripts/verify_v1.py
```

恢复演练需记录 RTO、RPO、问题项和整改人，可使用 [备份恢复演练记录](../templates/customer-beta-backup-restore-record.md)。

## 9. 误封恢复步骤

### 9.1 Beta 默认策略

首批 Beta 默认 `DRY_RUN=true`，系统只记录拟执行响应动作，不执行真实封禁。因此试点期间若未单独开启真实封禁，不应发生系统造成的真实误封。

若客户已按审批开启 `DRY_RUN=false`，出现疑似误封时，第一动作是止血，而不是继续分析根因。

### 9.2 止血

立即将 `.env` 改为：

```bash
DRY_RUN=true
REAL_ENFORCEMENT_GATE=
```

重启相关服务：

```bash
docker compose up -d app guardian
```

### 9.3 定位和解封

```bash
grep -E 'block|ban|firewall|iptables|response' logs/production/security.log | tail -n 100
docker compose logs --tail=200 app | egrep -i 'block|ban|iptables|firewall|response' || true
```

iptables 示例：

```bash
sudo iptables -S | grep '<MISBLOCKED_IP>' || true
sudo iptables -D INPUT -s <MISBLOCKED_IP> -j DROP || true
sudo iptables -D OUTPUT -d <MISBLOCKED_IP> -j DROP || true
sudo iptables -S | grep '<MISBLOCKED_IP>' || true
```

云安全组场景：

- 按客户云厂商控制台或 CLI 删除对应 deny 规则。
- 保留变更单号、删除前后截图、操作人和时间。

### 9.4 加白和复盘

编辑 `.env` 或客户侧策略：

```bash
RESPONSE_BUSINESS_IP_WHITELIST=<MISBLOCKED_IP_OR_CIDR>
```

复验：

```bash
python scripts/check_production_readiness.py
docker compose up -d app guardian
curl -fsS http://127.0.0.1:5000/readyz
```

复盘完成前保持 `DRY_RUN=true`。误封恢复记录使用 [误封恢复演练模板](../templates/misblock-recovery-drill-template.md) 或客户变更系统。

## 10. `DRY_RUN=true` 试点限制说明

`DRY_RUN=true` 是首批 Beta 的默认安全边界。该模式下：

| 能力 | 行为 |
|------|------|
| 告警检测 | 正常执行 |
| 告警入库 | 正常执行 |
| 控制台展示 | 正常执行 |
| 审计记录 | 正常执行 |
| 拟响应动作 | 记录 action 和审计，不下发真实封禁 |
| iptables / 云安全组封禁 | 不执行 |
| 主机隔离 | 不执行 |
| 业务影响 | 不应产生系统封禁导致的流量阻断 |

限制条款：

- dry-run 结果只能证明“系统会建议或记录响应动作”，不能证明客户防火墙、云安全组或 EDR provider 已真实执行。
- dry-run 不等同于真实封禁验收通过。
- dry-run 期间的误报、规则触发和告警分级应用于调参和评估，不作为自动封禁依据。
- 如客户要求真实封禁，必须进入第 11 节流程。

## 11. 真实封禁开启条件

真实封禁不属于首批 Beta 默认交付项。客户如需开启，必须全部满足以下条件：

| 条件 | 必须证据 |
|------|----------|
| 客户书面授权 | 真实响应启用申请表、变更单 |
| 业务白名单完成 | 办公出口、LB、DNS、监控、数据库、堡垒机、核心业务网段 |
| Provider 权限最小化 | iptables 或云安全组/EDR 权限说明 |
| 误封恢复演练通过 | 解封步骤、恢复耗时、责任人 |
| 审批矩阵确认 | 客户安全、网络、业务、交付负责人签字 |
| 审计链路确认 | 响应动作、解封、白名单变更有审计 |
| 回滚路径确认 | 可切回 `DRY_RUN=true`，可撤销 `REAL_ENFORCEMENT_GATE` |
| readiness 通过 | `python scripts/check_production_readiness.py --gate real-enforcement` 无 `[FAIL]` |

开启窗口内 `.env` 目标状态：

```dotenv
DRY_RUN=false
REAL_ENFORCEMENT_GATE=real-enforcement
REAL_ENFORCEMENT_APPROVAL_REQUIRED=true
REAL_ENFORCEMENT_AUDIT_VERIFIED=true
REAL_ENFORCEMENT_ROLLBACK_READY=true
REAL_ENFORCEMENT_UNBLOCK_READY=true
REAL_ENFORCEMENT_REVIEW_REQUIRED=true
```

申请表使用 [真实响应启用申请表](../templates/real-response-enable-request.md)。未完成以上条件时，交付结论只能写“真实封禁未开启，试点运行于 `DRY_RUN=true`”。

## 12. 试点期间问题上报流程

问题上报使用 [试点问题上报单](../templates/customer-beta-issue-report.md)。

### 12.1 分级

| 级别 | 定义 | 响应目标 |
|------|------|----------|
| P0 | 控制台不可用、误封影响生产、数据不可恢复、安全凭据泄漏 | 立即响应，先止血 |
| P1 | `/readyz` 失败、告警入库中断、Redis/DB 不可用、核心验收阻塞 | 当日响应 |
| P2 | 单项功能异常、规则误报偏高、性能波动、通知失败 | 2 个工作日内响应 |
| P3 | 文档问题、体验建议、非阻塞优化 | 试点周会跟进 |

### 12.2 上报内容

问题单至少包含：

- 客户名称、环境、联系人。
- 发生时间和影响范围。
- 当前 `DRY_RUN` 状态。
- 复现步骤。
- 截图或命令输出。
- 最近变更记录。
- `docker compose ps`。
- `/api/health`、`/healthz`、`/readyz` 输出。
- `docker compose logs --tail=200 app`。
- Redis `XLEN`、`XPENDING`、`XINFO GROUPS`。
- 如涉及误封，必须包含被影响 IP、封禁 provider、恢复动作和变更单。

### 12.3 处理流程

1. 客户提交问题单或在约定通道上报。
2. 双方确认优先级、影响范围和临时止血动作。
3. P0/P1 先恢复服务或切回 `DRY_RUN=true`，再分析根因。
4. 交付团队给出处理结论、规避方案或修复版本。
5. 客户复验并关闭问题。
6. 重大问题进入试点复盘和成功标准评估。

## 13. 试点成功标准

试点周期建议为 2 到 4 周。满足以下条件可判定试点成功：

| 类别 | 成功标准 |
|------|----------|
| 部署 | 客户环境稳定运行，`/readyz` 连续 7 天无持续失败 |
| 安全 | 无默认密钥、无明文密码泄漏、Redis 不公网开放、审计链有效 |
| 检测 | 试点范围内演练场景能产生可解释告警 |
| 告警闭环 | 告警可入库、查询、状态流转、审计留痕 |
| 运维 | 客户运维可独立执行日常检查和基础故障定位 |
| 备份恢复 | 至少一次隔离恢复演练通过，RTO/RPO 有记录 |
| dry-run 响应 | 响应动作建议和审计记录完整，无真实业务阻断 |
| 问题处理 | P0/P1 问题已关闭或有双方认可的规避方案 |
| 边界确认 | 客户已确认 Beta 限制和不在试点范围能力 |
| 下一步 | 双方形成是否扩大试点、开启真实封禁或进入商用评估的结论 |

## 14. 试点退出机制

### 14.1 正常退出

试点达成成功标准后，双方签署验收结论，并选择：

- 结束试点并保留环境观察。
- 进入扩大试点。
- 进入真实封禁受控开放。
- 进入商用评估或采购流程。

正常退出需交付：

- 试点验收签收表。
- 交付证据清单。
- 问题关闭清单。
- Beta 限制和后续建议。

### 14.2 有条件退出

如核心能力可用但存在非阻塞问题，可有条件通过。必须明确：

- 遗留问题。
- 风险影响。
- 临时规避方案。
- 整改责任人。
- 目标完成日期。
- 未完成前不得开启的能力，例如 `DRY_RUN=false`。

### 14.3 异常退出

出现以下情况，可暂停或终止试点：

| 触发条件 | 处理方式 |
|----------|----------|
| 客户无法提供必要环境 | 暂停部署，补齐前置条件后恢复 |
| 安全门禁无法通过 | 不上线或仅保留离线演示 |
| P0 问题无法在约定窗口恢复 | 切回安全状态，暂停试点 |
| 客户要求停止 | 停止服务，按客户数据处理要求备份或清理 |
| 真实封禁造成不可接受风险 | 立即切回 `DRY_RUN=true`，关闭真实响应评估 |

异常退出前建议执行：

```bash
docker compose ps
docker compose logs --tail=500 app > backups/exit-app.log
docker compose logs --tail=500 redis > backups/exit-redis.log
pg_dump "$DATABASE_URL" -Fc -f backups/exit-guardian.dump
find models/saved -maxdepth 1 -type f -exec sha256sum {} \; | sort > backups/exit-models.sha256
```

## 15. 交付证据清单

交付证据建议统一登记在 [交付证据索引](../templates/customer-beta-evidence-index.md)。

| 证据类别 | 必需证据 |
|----------|----------|
| 基础信息 | 客户环境信息收集表、部署拓扑、联系人清单 |
| 配置安全 | `.env` SHA256、`check_production_readiness.py` 输出、`.env` 权限截图 |
| 镜像与部署 | 镜像 tag、镜像 ID、构建日志、`docker compose config`、`docker compose ps` |
| 数据库 | 迁移输出、`web.init_db --check`、PostgreSQL 备份文件名和 SHA256 |
| Redis | 带密码 `PING`、未公网监听证据、`XLEN`、`XPENDING`、`XINFO GROUPS` |
| 模型 | 模型文件清单、manifest、SHA256、制品交付记录 |
| 健康检查 | `/api/health`、`/healthz`、`/readyz` 输出 |
| 控制台 | 登录、Dashboard、Alerts、Settings 截图 |
| WebSocket | `/socket.io/` 成功连接截图 |
| 功能验收 | `verify_v1.py`、`staging_drill.py --cleanup`、pytest 输出 |
| 性能 | `benchmark_p95.py`、`benchmark_http.py` 报告 |
| 审计 | 审计日志完整性校验、关键操作审计记录 |
| 运维 | 试点运维检查记录 |
| 备份恢复 | 备份清单、SHA256、恢复演练记录、RTO/RPO |
| 误封恢复 | dry-run 说明、误封恢复演练、真实响应启用申请表（如适用） |
| 问题处理 | 问题上报单、处理记录、关闭确认 |
| 签收 | 试点验收签收表、退出或下一阶段结论 |

## 附录：客户交付模板

- [客户环境信息收集表](../templates/customer-beta-environment-intake.md)
- [试点验收签收表](../templates/customer-beta-acceptance-signoff.md)
- [试点问题上报单](../templates/customer-beta-issue-report.md)
- [试点运维检查记录](../templates/customer-beta-ops-checklog.md)
- [备份恢复演练记录](../templates/customer-beta-backup-restore-record.md)
- [交付证据索引](../templates/customer-beta-evidence-index.md)
- [真实响应启用申请表](../templates/real-response-enable-request.md)
- [误封恢复演练模板](../templates/misblock-recovery-drill-template.md)
