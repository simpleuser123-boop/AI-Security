# 商业化 P0 研发执行看板

> 日期：2026-05-06  
> 范围：数据库迁移框架改造、私有化 Beta 交付清单、租户隔离数据模型设计、响应审批和误封恢复流程。  
> 原则：本看板只定义研发执行任务、依赖、交付物和验收标准，不实现代码。

## 依据文档

- `docs/AI安全守卫-v1.0-交付验收与路线图.md`
- `docs/AI安全守卫-v1.0-工程实施方案.md`
- `docs/AI安全守卫-v1.0-生产落地技术方案.md`
- `docs/implementation-task-board.md`
- `docs/acceptance-checklist.md`
- `docs/deployment.md`
- `docs/staging-drill.md`
- `docs/audit-log-baseline.md`
- `docs/private-beta-delivery-checklist.md`
- `commercialization-roadmap-docs/01-商业化落地路线图.md`
- `commercialization-roadmap-docs/02-商业化里程碑.md`
- `commercialization-roadmap-docs/03-商业化风险清单.md`
- `commercialization-roadmap-docs/04-下一步建议.md`

## 推荐执行顺序

1. **P0-COM-01 数据库迁移框架改造**：先固化 schema 版本、迁移发布、回滚和生产 gate。它是后续租户隔离、响应动作留痕、私有化升级交付的工程地基。
2. **P0-COM-02 私有化 Beta 交付清单** 与 **P0-COM-04 响应审批和误封恢复流程** 并行推进：交付清单负责客户侧部署和验收证据，响应流程负责真实封禁前的安全边界。
3. **P0-COM-03 租户隔离数据模型设计** 从第 1 天开始设计评审，但 tenant 相关 DDL 不应早于 P0-COM-01 的迁移基线和回滚策略完成后进入主干。
4. Beta 放行必须等待 P0-COM-01、P0-COM-02 达成准入；如本次启用真实封禁，则 P0-COM-04 必须作为更高风险门禁单独通过。P0-COM-03 至少完成架构设计和迁移影响评审，作为后续多租户 Alpha 的入口。

## 串并行关系

| 类型 | 任务关系 | 说明 |
|---|---|---|
| 必须串行 | P0-COM-01 -> 租户 `tenant_id` DDL 落地 | 没有正式迁移框架、初始 revision、备份和 downgrade 策略时，不允许大面积改核心表。 |
| 必须串行 | P0-COM-01 -> Beta 生产升级演练 | 私有化客户升级必须依赖 `flask db upgrade/current`、备份恢复和迁移回滚证据。 |
| 必须串行 | P0-COM-04 -> `DRY_RUN=false` | 真实封禁必须先有审批、白名单、手工解封、定时解封策略和误封演练记录。 |
| 可并行 | P0-COM-02 与 P0-COM-04 | 交付材料、部署证据模板、响应审批 SOP 可同时推进，并在 Beta 验收时汇合。 |
| 可并行 | P0-COM-03 设计 与 P0-COM-01 实施 | 租户 ERD、字段清单、上下文传递方案可先设计；实际 DDL 合入等 P0-COM-01 完成。 |
| 可并行 | P0-COM-02 文档固化 与测试脚本补齐 | 交付负责人可整理证据清单，研发/QA 同步补齐 readiness、staging drill、E2E 验证项。 |

## P0 看板

| 任务 ID | 任务名称 | 背景 | 涉及文件 | 负责人角色 | 优先级 | 前置依赖 | 交付物 | 验收标准 | 风险 |
|---|---|---|---|---|---|---|---|---|---|
| P0-COM-01 | 数据库迁移框架改造 | 路线图和风险清单均指出，生产不能依赖 `create_all()` 或手工建表；私有化客户后续升级、回滚、多租户改造都依赖正式 schema 版本治理。当前项目已出现 `migrations/`、`web/migration_app.py`、`web/models.py`、`tests/test_database_migrations.py`，需要把它们固化为发布基线。 | `migrations/`；`migrations/versions/20260506_0001_initial_schema.py`；`web/migration_app.py`；`web/models.py`；`web/database.py`；`web/init_db.py`；`config/config.py`；`.env.example`；`requirements.txt`；`docs/deployment.md`；`docs/acceptance-checklist.md`；`tests/test_database_migrations.py`；`tests/test_db_persistence.py` | 技术负责人；后端研发；DBA/平台工程；QA | P0 | 现有 ORM 表清单确认；当前生产数据模型冻结；PostgreSQL 测试库可用；迁移命令和生产环境变量口径统一 | 正式 Alembic/Flask-Migrate 迁移目录；初始 schema revision；迁移发布 SOP；`db upgrade/current/stamp` 操作说明；生产禁止 `AUTO_CREATE_DB_TABLES=true` 的 gate；迁移回滚和备份恢复说明；迁移测试集 | 全新 PostgreSQL 执行 `flask --app web.migration_app:create_migration_app db upgrade` 成功；重复 upgrade 幂等；`python -m web.init_db --check` 通过；`flask db current` 可追踪 revision；生产 readiness 检查拒绝 SQLite 和自动建表；迁移前备份、失败回滚、存量库 `stamp head` 方案均写入部署文档；相关测试通过 | 初始迁移与存量库不一致导致升级失败；不可逆 DDL 无 downgrade；生产账号权限过大；迁移脚本未经人工审阅；迁移和 ORM 漂移造成后续 tenant 改造返工 |
| P0-COM-02 | 私有化 Beta 交付清单 | 商业化 Phase A 目标是单企业私有化可部署、可验收、可回滚、可审计；Beta 不承诺多租户和 SaaS，但必须给客户一个边界清晰的交付包。当前已有 `docs/private-beta-delivery-checklist.md`，需要转成可执行交付门禁。 | `docs/private-beta-delivery-checklist.md`；`docs/deployment.md`；`docs/acceptance-checklist.md`；`docs/staging-drill.md`；`docs/audit-log-baseline.md`；`README.md`；`.env.example`；`docker-compose.yml`；`docker-compose.prod-drill.yml`；`Dockerfile`；`scripts/check_production_readiness.py`；`scripts/staging_drill.py`；`scripts/verify_v1.py`；`tests/e2e/test_v1_acceptance.py` | 产品负责人；交付负责人；运维/平台；后端研发；QA；合规/安全 | P0 | P0-COM-01 至少完成迁移命令和数据库初始化口径；生产环境变量模板可用；模型制品、Redis、Nginx/TLS、审计日志路径明确；响应策略默认 dry-run | Beta 交付范围和不交付范围；客户部署前置条件；环境变量必填/禁止项；数据库、Redis、模型、日志目录要求；上线步骤；验收步骤；回滚步骤；备份恢复步骤；误封恢复步骤；交付证据清单；Beta 放行结论模板 | 在全新客户环境可按文档完成 `redis -> db migration -> app -> health/readyz -> staging drill -> verify_v1`；交付证据不包含明文密钥；Web 重启后历史告警可查；Redis Stream 不持续堆积；Nginx TLS/WSS 可验证；备份恢复和回滚演练有记录；明确真实抓包、真实封禁、外部通知是否启用 | 交付范围过宽导致 Beta 被误认为 GA；客户网络/主机权限不足无法启用 Guardian 抓包；模型制品缺失或 manifest 不一致；手工部署步骤过多导致交付质量不稳定；证据材料泄露敏感配置 |
| P0-COM-03 | 租户隔离数据模型设计 | 商业化路线图将多租户列为 Phase B 阻塞项，风险清单指出核心模型缺 `tenant_id` 会导致后补成本高、越权风险大。虽然 Beta 是单企业，当前必须先完成数据模型和迁移影响设计，为多租户 Alpha 留出架构入口。 | `web/models.py`；`web/app.py`；`web/alert_stream_consumer.py`；`web/database.py`；`migrations/versions/`；`tests/test_enterprise_control_plane.py`；后续建议新增 `docs/tenant-isolation-data-model.md`；后续建议新增租户隔离测试集；`docs/audit-log-baseline.md`；`docs/private-beta-delivery-checklist.md` | 技术负责人；后端架构；安全工程；产品负责人；QA | P0 | P0-COM-01 的迁移基线和 review 机制；核心业务表清单；当前 RBAC 角色边界；Redis Stream message schema；审计和报表查询边界 | 租户 ERD；Tenant/Organization/User/Membership/Role/APIKey 设计；核心表 `tenant_id` 改造清单；租户上下文传递方案；Repository 强制过滤规范；Redis Stream `tenant_id` 规范；租户级审计、报表、规则、IOC、通知、响应配置边界；迁移分阶段方案；越权测试矩阵 | A/B 租户数据、规则、IOC、审计、报表、响应动作互不可见的验收用例已定义；任意 API 未带租户上下文时拒绝访问的规则明确；所有核心查询默认强制 `tenant_id` 过滤；Redis Stream 消息可按租户消费和追踪；单企业私有化可映射到默认 tenant，不破坏 Beta 交付；安全评审通过 | tenant 字段后补引发大面积迁移和历史数据归属问题；遗漏审计、报表、导出或响应动作造成侧漏；租户上下文只在 API 层过滤，后台 consumer/任务绕过；默认 tenant 设计不清导致私有化与 SaaS 分叉 |
| P0-COM-04 | 响应审批和误封恢复流程 | 路线图要求响应动作可审计、可回滚或可人工处置；商业化风险清单指出自动封禁误伤会直接影响客户业务。Beta 默认 `DRY_RUN=true`，真实封禁必须先产品化审批、白名单、解封和演练流程。 | `src/response/`；`web/models.py` 中 `ResponseAction`、`response_schedule_tasks` 相关模型；`web/app.py` 响应 API；`docs/deployment.md` §误封恢复；`docs/private-beta-delivery-checklist.md` §误封恢复；`docs/acceptance-checklist.md` F-07/F-08；`tests/test_response_r4.py`；`tests/test_responder.py`；后续建议新增 `docs/response-approval-and-misblock-recovery.md` | 安全工程；产品负责人；后端研发；交付负责人；运维/平台；客户成功 | P0 | P0-COM-01 中响应动作入库和审计表可用；业务白名单字段和配置入口明确；客户授权范围明确；高危响应等级和角色权限定义完成 | 响应审批状态机；`DRY_RUN -> 待审批 -> 执行 -> 到期解封/手工解封 -> 复盘` 流程；真实封禁前检查清单；业务 IP 白名单模板；误封定位和止血 SOP；iptables/云安全组恢复步骤；响应动作审计字段；客户确认模板；演练报告模板 | `DRY_RUN=false` 前必须有审批记录、白名单、回滚人和恢复窗口；high/critical 响应动作均写入 `ResponseAction` 和审计；手工解封路径可在演练环境验证；定时解封策略和失败重试策略明确；误封恢复演练通过并能证明被误封来源恢复访问；无审批时 critical 隔离降级为人工待办 | 自动响应越权或绕过审批；白名单漏配 LB/办公出口/监控探针；解封失败导致业务长时间中断；云安全组和本机 iptables 状态不一致；审计记录不足无法复盘；客户首日误开真实封禁 |

## Beta 放行门禁

- P0-COM-01：迁移初始化、升级、current、备份和回滚证据齐全。
- P0-COM-02：私有化部署包、验收脚本、交付证据清单和 Beta 边界均完成。
- P0-COM-04：默认 `DRY_RUN=true`；真实封禁不属于 Beta 默认放行范围，必须单独通过 `--gate real-enforcement`，并完成审批、审计、回滚、解封、复盘和误封恢复演练。
- P0-COM-03：完成设计评审，确认单企业默认 tenant 策略不阻塞 Beta，tenant DDL 可后续按迁移治理进入主干。

## 研发跟踪建议

- 每个任务在 issue 或迭代看板中使用上述任务 ID。
- P0-COM-01、P0-COM-04 涉及生产事故风险，必须有技术负责人和安全工程双人 review。
- P0-COM-03 不以“大表一次性加字段”为目标，先交付设计、测试矩阵和迁移拆分方案。
- P0-COM-02 的验收材料必须能被客户、交付、运维和管理层共同阅读，避免只服务研发自测。
