# 首批客户私有化 Beta 部署前 Preflight Checklist

适用对象：AI-Security-Guardian 首批单企业私有化 Beta 部署前检查。本文面向交付团队、客户 IT、DBA、网络/安全团队和客户项目负责人。

硬性准入原则：

- 任何检查项为 **FAIL**，均不得进入部署、迁移、启动或客户验收窗口。
- 不允许用口头承诺替代检查证据；缺少证据按 **FAIL** 处理。
- 首批私有化 Beta 默认且必须保持 `DRY_RUN=true`；真实封禁不属于默认部署范围。
- 如客户要求 `DRY_RUN=false`，必须在本清单全部通过后，额外通过 `python scripts/check_production_readiness.py --gate real-enforcement`，并具备审批、白名单、审计、回滚、解封、复盘证据。
- 检查输出和交付证据不得包含 `.env` 明文、数据库密码、Redis 密码、管理员密码哈希、JWT、API Key 或其他敏感凭据。

建议在项目根目录执行命令：

```bash
cd /opt/ai-security-guardian
```

## 1. 责任方说明

| 责任方 | 职责边界 |
|---|---|
| 交付团队 | 执行部署前检查、整理证据、推动问题关闭、确认是否允许进入部署窗口 |
| 客户 IT/运维 | 提供主机、Docker、目录、系统服务、备份介质和运行权限 |
| 客户网络/安全 | 提供域名、TLS、端口、ACL、防火墙、安全组、抓包授权和白名单 |
| 客户 DBA | 提供 PostgreSQL 数据库、账号、权限、备份恢复能力和迁移窗口 |
| 客户项目负责人 | 确认变更窗口、风险接受、联系人和最终放行结论 |

## 2. Preflight 总览

| 类别 | 检查方法 | 通过标准 | 失败影响 | 责任方 |
|---|---|---|---|---|
| 变更窗口 | 查看客户变更单、部署计划、联系人和值守安排 | 已批准部署窗口；交付、客户 IT、DBA、网络/安全均有联系人和值守方式 | 发生故障无法协调止血、回滚或恢复，部署不可控 | 客户项目负责人、交付团队 |
| 发布包版本 | `git rev-parse HEAD`、查看镜像 tag、核对 `docs/private-beta-release-manifest.md` | 代码版本、镜像 tag、迁移 head、模型清单均明确；不得使用未确认的临时包 | 无法追溯问题版本，回滚和证据链失效 | 交付团队 |
| Readiness gate | `python scripts/check_production_readiness.py --env-file .env` | 输出无 `[FAIL]`；`DRY_RUN=true`；DB、Redis、模型、CORS、密钥检查均通过 | 生产配置可能使用弱密钥、错误 DB、危险 CORS 或缺失依赖 | 交付团队、客户 IT |
| FAIL 处理 | 汇总所有 FAIL 项到问题清单 | 所有 FAIL 已关闭并复测通过，才允许继续部署 | 带病上线，后续部署失败或引发客户业务风险 | 交付团队、客户项目负责人 |

## 3. 主机与系统

| 检查项 | 检查方法 | 通过标准 | 失败影响 | 责任方 |
|---|---|---|---|---|
| 操作系统与架构 | `uname -a`、客户 CMDB 或主机交付记录 | Linux 或客户认可的等效容器运行环境；架构与镜像兼容 | 镜像无法运行或行为与交付脚本不一致 | 客户 IT |
| CPU/内存 | `nproc`、`free -h`、客户资源申请单 | 至少满足 `app` 2 CPU / 2GB、`redis` 1 CPU / 512MB；启用 `guardian` 时额外预留 2 CPU / 2GB | 容器频繁 OOM、健康检查失败、性能基线不可信 | 客户 IT |
| 磁盘空间 | `df -h`、确认数据盘挂载 | `data/`、`logs/`、`backups/` 所在分区空间满足客户保留策略；部署前不得接近满盘 | DB、日志、备份写入失败；审计证据丢失 | 客户 IT |
| 时间同步 | `timedatectl` 或客户 NTP 检查 | NTP/时间同步已启用；时区和客户运维标准一致 | JWT、日志、审计、备份和故障时间线不可信 | 客户 IT |
| 安装目录 | `ls -ld /opt/ai-security-guardian data logs models/saved backups release-env` | 目录存在；`backups` 建议 `700`；`.env` 所在目录不对无关用户开放 | 服务无法写日志/数据，或敏感配置泄露 | 客户 IT、交付团队 |
| 主机抓包授权 | 查看客户授权记录；启用 full-chain 时检查 `PACKET_INTERFACE` | 如启用 `guardian`，必须有书面授权、监控范围和网卡确认；未授权则明确不启用 full-chain | 未授权抓包导致合规风险；或 full-chain 启动后无真实流量 | 客户网络/安全、客户项目负责人 |

## 4. 网络与端口

| 检查项 | 检查方法 | 通过标准 | 失败影响 | 责任方 |
|---|---|---|---|---|
| 对外入口端口 | `ss -lntp`、安全组/防火墙规则截图 | 对外只开放客户批准的 `80/443`；管理端口遵循客户堡垒机规范 | 控制台不可访问或暴露非预期端口 | 客户网络/安全 |
| App 端口暴露 | `ss -lntp \| grep ':5000'`、`docker compose config` | `5000` 仅允许本机 Nginx 或内网 LB 访问；生产建议绑定 `127.0.0.1:5000` | 绕过 TLS/鉴权入口，直接暴露 Flask/Gunicorn 上游 | 客户网络/安全、交付团队 |
| Redis 端口暴露 | `ss -lntp \| grep ':6379'`、外部探测 | Redis 不公网开放；Compose 默认只绑定 `127.0.0.1:6379`；安全组禁止公网访问 | Redis 被未授权访问，告警队列和缓存泄露或被破坏 | 客户网络/安全、客户 IT |
| PostgreSQL 网络连通 | 从应用主机或容器执行 `SELECT 1`，或运行 readiness | 应用运行网络可访问客户 PostgreSQL；DNS、ACL、安全组均放通 | 迁移失败、服务 `/readyz` 失败、告警无法入库 | 客户 DBA、客户网络/安全 |
| 出站访问 | 根据客户是否使用外部威胁情报、模型制品、SMTP/Webhook 检查 ACL | 必需的制品下载、SMTP、Webhook 或威胁情报出口已批准；不需要的出口保持关闭 | 模型无法交付、通知失败，或外联策略违规 | 客户网络/安全、交付团队 |
| WebSocket/WSS | 浏览器或 `curl -Ik` 验证 TLS 入口；部署后在浏览器网络面板确认 `/socket.io/` | Nginx/LB 支持 Upgrade；无 CORS、Mixed Content 或超时问题 | Dashboard 实时告警不可用，客户误判系统无告警 | 客户网络/安全、交付团队 |

## 5. Docker 与 Compose

| 检查项 | 检查方法 | 通过标准 | 失败影响 | 责任方 |
|---|---|---|---|---|
| Docker Engine | `docker version` | Docker daemon 可用，版本符合客户安全基线 | 无法构建或运行容器 | 客户 IT |
| Compose Plugin | `docker compose version` | Compose v2 plugin 可用 | 编排命令不可执行，部署流程中断 | 客户 IT |
| Compose 配置渲染 | `docker compose config --quiet` | 配置可解析；不出现必填环境变量缺失；包含 `$` 的哈希已按 `.env` raw 格式正确处理 | 启动时变量被截断或服务配置错误 | 交付团队 |
| 镜像可用性 | `docker image ls ai-security-guardian` 或私有镜像仓库拉取记录 | 指定 tag 已存在或可拉取；不依赖未固定的临时镜像 | 部署时拉取失败，或版本不可追溯 | 交付团队、客户 IT |
| 容器权限 | 查看 `Dockerfile`、`docker-compose.yml` | `app` 非 root 运行；`guardian` 只有启用 full-chain 时才授予 `NET_ADMIN` / `NET_RAW` 和 host network | Web 容器权限过高，或抓包链路因权限不足失败 | 交付团队、客户 IT |
| 目录挂载 | `docker compose config`、`ls -ld data logs models/saved` | `models/saved` 对容器只读；`logs`、`data` 可写；路径指向客户批准目录 | 模型被运行时篡改，或日志/数据无法写入 | 客户 IT、交付团队 |
| 健康检查定义 | `docker compose config` 查看 healthcheck | `app` 包含 `/healthz` healthcheck；Redis 包含带密码 PING healthcheck | 容器状态无法反映关键存活情况 | 交付团队 |

## 6. PostgreSQL

| 检查项 | 检查方法 | 通过标准 | 失败影响 | 责任方 |
|---|---|---|---|---|
| 数据库类型 | 检查 `.env` 的 `DATABASE_URL`；运行 readiness | 必须为 `postgresql+psycopg2://...`；禁止 SQLite、localhost、示例或占位连接串 | 告警和审计数据落入错误数据库，或生产使用本地文件库 | 客户 DBA、交付团队 |
| 数据库连通 | `python scripts/check_production_readiness.py --env-file .env` 或 `psql` 执行 `SELECT 1` | `DB_CONNECTIVITY` 通过；连接超时、账号、DNS 和 ACL 均正常 | 迁移、启动和 `/readyz` 失败 | 客户 DBA、客户网络/安全 |
| 数据库权限 | DBA 确认账号权限；迁移前可用发布账号执行 DDL | 迁移账号可执行 Alembic DDL；运行账号满足应用 DML；权限符合客户最小权限规范 | 迁移失败，或运行期写入/查询失败 | 客户 DBA |
| 自动建表开关 | 检查 `.env`：`AUTO_CREATE_DB_TABLES=false` | 生产/Beta 不依赖应用启动自动建表，统一走 Flask-Migrate/Alembic | schema 不可控，升级和回滚风险增大 | 交付团队、客户 DBA |
| 迁移版本 | 部署前计划执行 `flask --app web.migration_app:create_migration_app db upgrade`；核对 manifest 最新 revision | 目标 revision 明确，当前发布包迁移链线性；部署窗口内可检查 `db current` | 表结构不匹配导致启动或功能异常 | 交付团队、客户 DBA |
| 发布前数据库备份 | `pg_dump "$DATABASE_URL" -Fc -f backups/$TS/guardian_prod.dump` 或 DBA 备份记录 | 备份可生成、大小非 0、SHA256 已记录；恢复责任人明确 | 迁移失败时无法恢复，可能造成数据丢失 | 客户 DBA、客户 IT |

## 7. Redis

| 检查项 | 检查方法 | 通过标准 | 失败影响 | 责任方 |
|---|---|---|---|---|
| Redis 密码 | 检查 `.env`，不展示明文；`redis-cli -a "$REDIS_PASSWORD" ping` | `REDIS_PASSWORD` 非空、非弱口令、非占位；带密码 PING 返回 PONG | 队列被未授权访问，或应用无法连接 Redis | 客户 IT、交付团队 |
| Redis 绑定范围 | `ss -lntp \| grep ':6379'`、安全组规则 | 不监听公网；Compose 场景为 `127.0.0.1:6379` 或客户批准的内网地址 | Redis 暴露导致安全风险 | 客户网络/安全、客户 IT |
| Redis 可用性强制 | 检查 `.env`：`REQUIRE_REDIS_AVAILABLE=true` | Private Beta / production 必须显式为 `true` | Redis 故障时系统静默降级，告警闭环不可验收 | 交付团队 |
| App 连接配置 | `docker compose config` | `app` 在 Compose bridge 中使用 `REDIS_HOST=redis`，端口/DB/密码一致 | Web consumer、健康检查或指标无法访问 Redis | 交付团队 |
| Guardian 连接配置 | 启用 full-chain 时检查 `REDIS_HOST_FOR_GUARDIAN` | host network 下通常为 `127.0.0.1`，并与 Redis 绑定范围一致 | Guardian 写 Stream 失败，告警无法进入 Web/DB | 交付团队、客户 IT |
| Stream 初始状态 | `XLEN guardian:alerts`、`XPENDING guardian:alerts guardian:web`、`XINFO GROUPS guardian:alerts` | 无异常堆积；consumer group 状态符合部署阶段预期 | 告警消费延迟或堆积，Beta 验收失败 | 交付团队、客户 IT |

## 8. TLS、域名与 CORS

| 检查项 | 检查方法 | 通过标准 | 失败影响 | 责任方 |
|---|---|---|---|---|
| 正式域名 | 客户 DNS 记录、`curl -Ik https://<domain>/api/health` | 使用客户正式 HTTPS 控制台域名；不使用示例、localhost 或临时 IP 作为 Beta Origin | CORS/readiness 失败，客户无法按正式入口验收 | 客户网络/安全 |
| TLS 证书 | `openssl s_client -connect <domain>:443 -servername <domain>` 或证书平台截图 | 证书链完整、域名匹配、未过期，协议符合客户安全基线 | 浏览器拒绝访问，WSS 失败，客户安全验收失败 | 客户网络/安全 |
| Nginx/LB 配置 | `nginx -t`、客户 LB 配置审核 | `/` 和 `/socket.io/` 均转发到 app；设置 `X-Forwarded-*` 和 Upgrade 头 | 健康检查可过但实时告警或登录态异常 | 客户网络/安全、交付团队 |
| CORS Origin | 检查 `.env`：`ALLOWED_ORIGINS=https://<正式域名>`；运行 readiness | 禁止 `*`、`http://`、localhost、127.0.0.1、占位域名和带 path 的 Origin | 跨域放行过宽或正式控制台无法访问 API | 交付团队、客户网络/安全 |
| HTTP 到 HTTPS 策略 | 客户 Nginx/LB 配置 | 对外访问强制 HTTPS 或符合客户内网安全策略 | 凭据可能经明文链路传输，或浏览器 Mixed Content | 客户网络/安全 |

## 9. 模型与制品

| 检查项 | 检查方法 | 通过标准 | 失败影响 | 责任方 |
|---|---|---|---|---|
| 模型目录 | `ls -l models/saved` | 目录存在，交付人员可更新，容器内只读挂载 | 模型缺失或被运行时改写 | 交付团队、客户 IT |
| 必需模型文件 | 检查 `intrusion_rf_v1.pkl`、`ddos_rf_v1.pkl`、`web_attack_nb_v1.pkl`、`anomaly_if_v1.pkl` 及辅助文件 | 关键模型、`*.model_manifest.json`、入侵辅助文件均存在且可读 | `/readyz` 失败，检测链路不可用 | 交付团队 |
| 模型 SHA256 | `find models/saved -maxdepth 1 -type f -exec sha256sum {} \; \| sort` | SHA256 与 release manifest 或制品记录一致 | 模型版本不可追溯，误报/漏报无法定位 | 交付团队 |
| 模型交付方式 | 检查 `MODEL_DELIVERY_MODE`、`MODEL_ARTIFACT_URI` 和制品下载记录 | `repository` 或 `artifact` 明确；artifact 模式有制品 URI/交付单和校验记录 | 部署现场无法获得模型，或交付证据不完整 | 交付团队、客户 IT |
| 模型强制就绪 | 检查 `.env`：`REQUIRE_MODELS_READY=true`；运行 readiness | Private Beta / production 必须显式为 `true`，模型缺失时启动失败 | 系统在无模型状态下静默运行，检测结果不可信 | 交付团队 |
| 模型回滚点 | 核对上一版模型压缩包、manifest 和 SHA256 | 部署前已有可恢复模型版本和回滚步骤 | 新模型异常时无法恢复到上一稳定版本 | 交付团队 |

## 10. 备份与恢复

| 检查项 | 检查方法 | 通过标准 | 失败影响 | 责任方 |
|---|---|---|---|---|
| 备份范围 | 检查备份计划 | 覆盖 PostgreSQL、`.env` 或密钥系统版本、`models/saved`、`logs`、镜像 tag/ID、Compose 配置 | 回滚和审计证据不完整 | 客户 IT、客户 DBA、交付团队 |
| 备份目录权限 | `ls -ld backups release-env` | `backups` 建议 `700`；`.env` 备份文件 `600`；证据包不包含 `.env` 明文 | 密钥、数据库 dump 或审计日志泄露 | 客户 IT |
| 数据库备份 | `pg_dump -Fc` 或 DBA 备份平台记录；生成 SHA256 | 备份文件存在、大小非 0、校验值已记录 | 迁移失败或数据错误时无法恢复 | 客户 DBA |
| 模型备份 | `tar -czf backups/$TS/models-saved.tar.gz models/saved`；生成 SHA256 | 模型包、manifest 和 SHA256 齐全 | 模型变更失败无法回滚 | 交付团队 |
| 日志备份 | `tar -czf backups/$TS/logs.tar.gz logs`；客户日志归档策略 | 审计日志、归档日志和 hash-chain 基线纳入保全 | 安全事件和客户验收证据丢失 | 客户 IT、交付团队 |
| 恢复演练计划 | 查看客户恢复演练记录或部署窗口计划 | 至少明确隔离恢复环境、RTO/RPO、执行人和验收命令 | 备份是否可用无法证明 | 客户 IT、客户 DBA、客户项目负责人 |

## 11. 日志、审计与观测

| 检查项 | 检查方法 | 通过标准 | 失败影响 | 责任方 |
|---|---|---|---|---|
| 审计环境 | 检查 `.env`：`AUDIT_ENV=production` 或 `AUDIT_LOG_DIR` | Beta 生产日志进入客户确认的生产审计目录 | 测试/生产日志混淆，审计链不可用 | 交付团队 |
| 日志完整性 | 检查 `.env`：`LOG_INTEGRITY_ENABLED=true`；运行 readiness | 哈希链保护已启用，日志目录可写 | 关键操作审计不可证明未被篡改 | 交付团队、客户 IT |
| 日志权限 | `ls -ld logs logs/production` | app/guardian 可写；无关用户不可写；纳入备份 | 服务报错无法排查，或审计日志被篡改 | 客户 IT |
| 敏感信息 | 抽查 `docker compose logs --tail=200 app` 和交付证据 | 日志和证据不出现密码、管理员哈希、JWT、API Key、`.env` 明文 | 凭据泄漏，必须暂停部署并轮换密钥 | 交付团队、客户 IT |
| 健康端点 | 部署前确认 Nginx/LB 允许内部探测；部署后执行 `/api/health`、`/healthz`、`/readyz`、`/metrics` | `/readyz` 作为就绪准入；`/healthz` 只代表进程存活 | 只看存活不看依赖，导致 DB/Redis/模型故障仍被放行 | 交付团队、客户 IT |
| 指标采集 | 客户监控方案或 `curl http://127.0.0.1:5000/metrics` | Prometheus 指标或等效采集路径已明确；至少覆盖 Redis Stream、模型、审计、HTTP | 试点期间无法发现堆积、模型缺失或审计异常 | 客户 IT、交付团队 |

## 12. 权限、密钥与账号

| 检查项 | 检查方法 | 通过标准 | 失败影响 | 责任方 |
|---|---|---|---|---|
| `.env` 权限 | `ls -l .env` | `.env` 权限为 `600` 或客户密钥系统等效控制 | 密钥泄露，必须暂停部署并轮换 | 客户 IT、交付团队 |
| `SECRET_KEY` | 运行 readiness；客户确认生成方式 | 至少 32 字符，非示例、非默认、非弱 token | JWT/会话安全失效 | 交付团队、客户 IT |
| 管理员密码哈希 | `python scripts/generate_admin_password_hash.py` 生成；运行 readiness | `ADMIN_PASSWORD_HASH` 为 Werkzeug 哈希；生产不依赖明文 `ADMIN_PASSWORD` | 管理员账号弱认证或明文密码泄露 | 交付团队、客户项目负责人 |
| 管理员角色 | 检查 `ADMIN_USERNAME`、`ADMIN_ROLE`，确认客户账号策略 | 首批 Beta 管理员账号、角色、保管人和交接方式明确 | 无法登录或权限过宽无人负责 | 客户项目负责人、交付团队 |
| 数据库账号 | DBA 权限说明 | 使用客户批准账号；运行期权限最小化；迁移账号和运行账号边界明确 | 数据库权限过大或不足，影响安全和上线 | 客户 DBA |
| Redis 密钥保管 | 客户密钥管理记录 | Redis 密码不写入文档、聊天、截图；只在 `.env` 或密钥系统保存 | Redis 凭据泄露，需要重置并重启依赖服务 | 客户 IT |
| 外部 API Key | 检查威胁情报、SMTP、Webhook、LLM 等变量 | 未使用则留空；使用时由客户授权并纳入密钥管理 | 外呼失败或第三方凭据泄露 | 客户网络/安全、客户 IT |
| 真实响应权限 | 检查 `DRY_RUN` 和 real-enforcement 相关变量 | 首批 Beta 为 `DRY_RUN=true`；真实响应权限、白名单和 provider 凭据不得提前放开 | 误封客户业务或触发未授权隔离/封禁 | 客户网络/安全、客户项目负责人 |

## 13. 账号与业务流程

| 检查项 | 检查方法 | 通过标准 | 失败影响 | 责任方 |
|---|---|---|---|---|
| 登录账号交接 | 客户账号交接记录 | 管理员账号、初始密码生成和重置流程明确；交付证据不记录明文密码 | 部署后无人可登录，或凭据暴露 | 客户项目负责人、交付团队 |
| 角色边界 | 核对 `viewer` / `analyst` / `admin` 使用计划 | 首批 Beta 最少账号可用，管理员权限受控；客户知道哪些操作会写审计 | 客户误操作配置、规则或响应动作 | 客户项目负责人 |
| 操作审批 | 客户变更流程和真实响应申请表 | 配置变更、规则变更、真实响应启用均有审批路径 | 高风险操作无审计审批，责任不清 | 客户项目负责人、客户网络/安全 |
| 业务白名单 | 检查 `RESPONSE_BUSINESS_IP_WHITELIST` 或客户白名单表 | 即使 Beta dry-run，也应收集办公出口、LB、DNS、监控、数据库、堡垒机、核心业务网段；真实封禁前必须完成 | 真实响应阶段误封核心资产 | 客户网络/安全、客户业务负责人 |
| 问题升级 | 查看客户问题上报通道和 P0/P1 联系人 | P0/P1 有电话、工单或群组升级路径；部署窗口内可立即响应 | 故障发生后无法止血或回滚 | 客户项目负责人、交付团队 |

## 14. 回滚与退出

| 检查项 | 检查方法 | 通过标准 | 失败影响 | 责任方 |
|---|---|---|---|---|
| 应用镜像回滚 | `docker image ls ai-security-guardian`；确认上一稳定 tag | 上一稳定镜像 tag/ID 可用，回滚命令和负责人明确 | 新版本失败后无法快速恢复服务 | 交付团队、客户 IT |
| `.env` 回滚 | 检查 `release-env` 或客户密钥系统版本 | 上一稳定 `.env` 或密钥版本可恢复；只保存 SHA256 到普通证据 | 配置错误无法恢复，或泄露敏感配置 | 客户 IT、交付团队 |
| 数据库回滚 | DBA 备份点、恢复库计划、迁移 downgrade/恢复策略 | 迁移前有备份；可在隔离库验证；不在生产库试错 | 迁移错误导致数据不可恢复 | 客户 DBA、客户项目负责人 |
| 模型回滚 | 检查上一版模型包、manifest、SHA256 | 可将 `models/saved` 恢复到上一稳定版本，并通过 `/readyz` | 新模型异常导致误报/漏报无法止血 | 交付团队 |
| Redis/队列恢复 | Redis 重启和 Stream 检查命令 | Redis 异常时有重启、认证、Stream 堆积检查步骤 | 告警堆积或丢失，Web 历史查询不完整 | 客户 IT、交付团队 |
| 误封恢复 | 检查 `templates/misblock-recovery-sop.md` 或客户等效 SOP | 即使首批 Beta dry-run，也已确认止血、解封、加白、审计、复盘流程；真实封禁前必须演练通过 | 真实响应误伤业务时无法快速恢复 | 客户网络/安全、客户项目负责人 |
| 退出条件 | 查看试点退出机制和客户签收要求 | 明确暂停、回滚、终止试点条件；P0/P1 先恢复服务再定位根因 | 试点风险不可控，双方验收口径冲突 | 客户项目负责人、交付团队 |

## 15. 最终放行签字

所有检查项必须填写结论。任一 `FAIL` 时，最终结论只能为“不放行”。

| 项目 | 结论 |
|---|---|
| 客户名称 |  |
| 环境名称 | 私有化 Beta |
| 目标部署时间 |  |
| 应用版本 / 镜像 tag |  |
| Git commit / 发布包编号 |  |
| PostgreSQL 是否通过 | PASS / FAIL |
| Redis 是否通过 | PASS / FAIL |
| TLS/CORS 是否通过 | PASS / FAIL |
| 模型是否通过 | PASS / FAIL |
| 备份恢复是否通过 | PASS / FAIL |
| Readiness gate 是否无 `[FAIL]` | PASS / FAIL |
| 是否保持 `DRY_RUN=true` | PASS / FAIL |
| 是否存在未关闭 FAIL | 是 / 否 |
| 最终结论 | 放行 / 不放行 |
| 客户项目负责人 |  |
| 客户 IT/运维负责人 |  |
| 客户 DBA |  |
| 客户网络/安全负责人 |  |
| 交付负责人 |  |
| 签字日期 |  |

结论规则：

- `最终结论=放行` 仅在所有关键检查均为 PASS，且不存在未关闭 FAIL 时可填写。
- 若客户选择带风险推进，但存在任何 FAIL，交付团队仍必须记录为“不放行”，并暂停部署动作。
- 本清单通过仅表示允许进入私有化 Beta 部署窗口，不代表 GA 商用放行，也不代表真实封禁能力已获准启用。
