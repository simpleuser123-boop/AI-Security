# Tenant Isolation Data Model

本文档定义 AI Security Guardian 的租户隔离数据模型规范。本文只描述规则和验收口径，不代表已完成代码、迁移、配置或测试实现。

关键词含义：

- MUST：必须满足，未满足视为隔离缺陷。
- SHOULD：应当满足，除非有明确风险评估和替代控制。
- MUST NOT：禁止，违反即视为越权或数据隔离缺陷。

## 1. 默认 tenant 策略

### 1.1 tenant 解析优先级

所有访问租户数据的入口 MUST 在进入业务读写之前解析出唯一的 `tenant_id`。解析来源按入口类型区分：

| 入口 | `tenant_id` 来源 | 缺失时行为 |
| --- | --- | --- |
| Web/API | 认证 token、会话、API key 或组织成员关系中的租户声明；仅当租户声明与调用者授权范围匹配时有效 | MUST 拒绝请求。未认证返回 401，已认证但无租户或无权限返回 403，参数缺失可返回 400 |
| Redis Stream consumer | stream key 中的 tenant 段和 message body 中的 `tenant_id`，二者 MUST 一致 | MUST 拒绝处理该消息，写入租户保留的错误审计或 DLQ，不得写入业务表 |
| Celery/RQ/异步任务 | 任务参数、headers/meta 或调度记录中的 `tenant_id` | MUST 失败并记录隔离错误，不得访问租户表 |
| cron/manual job | CLI 参数 `--tenant-id`、明确的租户清单、或受控的管理员批处理计划 | MUST 退出并返回非 0，不得使用默认租户 |
| 测试环境 | fixture 明确创建的测试 tenant，例如 `tenant_a`、`tenant_b` | MUST 显式传入；测试可使用固定测试 tenant，但 MUST NOT 作为生产 fallback |

### 1.2 未显式传入 tenant_id 时的行为

- API 调用未显式传入 `tenant_id` 时，系统 SHOULD 从认证主体的唯一租户上下文派生 `tenant_id`。
- 如果认证主体属于多个 tenant，请求 MUST 显式选择 tenant，或通过当前会话中已绑定且可审计的 tenant 选择结果解析。
- 如果无法解析出唯一 tenant，系统 MUST fail closed。
- 系统 MUST NOT 因为 `tenant_id` 缺失而回退到任意历史 tenant、最近使用 tenant、`default` tenant、`system` tenant 或全表查询。

### 1.3 default/system tenant

- 生产环境 MUST NOT 允许隐式 `default` tenant。`default` 只能作为本地开发或测试 fixture 名称使用，且 MUST 通过测试配置显式启用。
- `system` MUST 仅表示 actor/service principal 或全局控制面身份，MUST NOT 作为租户业务数据的默认归属。
- 如确需系统级业务动作，例如模型发布、全局健康检查、租户注册，数据 MUST 写入明确标记为全局表的表，或写入带目标 `tenant_id` 的租户表。
- 任何 `actor = system` 的审计记录如果影响租户资源，MUST 同时记录目标 `tenant_id`。

### 1.4 禁止跨租户 fallback

- 租户表查询 MUST 始终包含 `tenant_id = current_tenant_id` 过滤条件，主键查询也不例外。
- 写入租户表时 `tenant_id` MUST 来自当前 tenant 上下文或经过授权的目标 tenant 参数，MUST NOT 从客户端 payload 盲目信任。
- 如果关联资源的 `tenant_id` 与当前上下文不一致，系统 MUST 拒绝操作。
- 查询未命中时 MUST 返回未找到或无权限，MUST NOT 再尝试不带 tenant 过滤的查询。
- 缓存、Redis key、后台任务参数、审计 payload 和导出文件名 SHOULD 带 tenant 维度，避免跨租户复用。

## 2. 核心表 tenant_id 清单

当前核心业务表来源于 `ai-security-guardian/web/models.py` 与初始迁移。多租户目标模型下，除明确标为全局表的表外，所有业务表 MUST 包含 `tenant_id`。

通用列规则：

- `tenant_id` 类型 SHOULD 与租户注册表主键一致，建议为 `String(64)` 或 UUID。
- 租户表的 `tenant_id` MUST NOT 为空，MUST 外键引用全局 `tenants.id` 或通过等价租户注册服务校验。
- 租户表所有常用查询索引 MUST 将 `tenant_id` 放在前缀位置。
- 租户内唯一键 MUST 将 `tenant_id` 纳入唯一约束。除全局表外，MUST NOT 使用跨租户唯一约束锁定业务值。
- 子表 SHOULD 冗余保存 `tenant_id`，并通过应用层、复合外键或迁移校验保证其与父表一致。

| 表 | 核心用途 | 是否必须包含 `tenant_id` | `tenant_id` 来源 | 约束、索引、唯一键策略 |
| --- | --- | --- | --- | --- |
| `alerts` | 告警主表 | MUST | API/collector/Redis 消息所属 tenant | `tenant_id` NOT NULL；索引 `tenant_id, status, timestamp`；`external_id` 唯一键 MUST 改为 `tenant_id, external_id` |
| `alert_histories` | 告警状态流转历史 | MUST | 从父级 `alerts.tenant_id` 继承 | `tenant_id` NOT NULL；索引 `tenant_id, alert_id, created_at`；`alert_id` 关联 MUST 校验同租户 |
| `response_actions` | 封禁、解封、演练等响应动作 | MUST | 当前 tenant 上下文；若关联告警则从 `alerts.tenant_id` 校验 | 索引 `tenant_id, alert_id`、`tenant_id, status, created_at`；关联 `alert_id` MUST 同租户 |
| `response_schedule_tasks` | 定时解封、通知重试、补偿任务 | MUST | 创建任务时的当前 tenant；关联告警时与 `alerts.tenant_id` 一致 | 索引 `tenant_id, status, run_at`；retry/compensation MUST 保持原 `tenant_id` |
| `rules` | 检测规则和响应规则 | MUST | 创建/导入规则时的目标 tenant | 索引 `tenant_id, enabled, priority`；规则名或规则 id 若需唯一，MUST 使用 `tenant_id, name` 或 `tenant_id, id` |
| `iocs` | 威胁情报 IOC 条目 | MUST | tenant 本地 IOC、同步任务目标 tenant 或 per-tenant feed | `tenant_id` NOT NULL；唯一键 MUST 为 `tenant_id, ioc_type, value`；索引 `tenant_id, value`、`tenant_id, expires_at` |
| `settings` | 租户配置、策略开关、阈值 | MUST | 当前 tenant 或管理员指定目标 tenant | 主键 SHOULD 为 `tenant_id, key`；MUST NOT 使用单列 `key` 表示所有 tenant 共享设置 |
| `banned_ips` | 手工/API 封禁 IP 列表 | MUST | 当前 tenant；响应动作或管理员操作的目标 tenant | 主键或唯一键 MUST 为 `tenant_id, ip`；索引 `tenant_id, updated_at` |
| `audit_events` | 安全审计事件 | MUST 条件性 | 涉及租户资源时来自当前 tenant；纯全局事件可为空但 MUST 标记 scope | 租户事件索引 `tenant_id, created_at`、`tenant_id, event_type`；payload 中资源 tenant MUST 与列一致 |
| `model_versions` | 已登记/部署模型版本元数据 | MUST NOT，作为全局表 | 不适用 | 全局唯一 `version` 可保留；该表只保存模型工件元数据，不保存租户告警、策略或客户数据 |

### 2.1 全局表规则

允许没有 `tenant_id` 的全局表 MUST 满足以下条件：

- 表内容不包含租户专属业务数据、客户标识、告警、响应动作、封禁对象、规则配置或租户私有 IOC。
- 访问全局表的 API MUST 经过管理员或系统服务授权。
- 全局表被租户业务引用时，引用方 MUST 保留自身 `tenant_id`，不能因引用全局对象而变成全局数据。
- 全局默认规则、全局 IOC feed、全局设置模板 SHOULD 使用单独的全局模板表；落到租户运行态时 MUST materialize 为带 `tenant_id` 的租户记录，或在查询层显式区分 `scope = global` 与 `scope = tenant` 且禁止无序 fallback。

明确可作为全局表的示例：

| 表 | 为什么可以没有 `tenant_id` | 边界 |
| --- | --- | --- |
| `model_versions` | 只描述模型 artifact、checksum、版本号和部署元数据，可被多个 tenant 共享 | 模型对某 tenant 的启用状态、阈值和回滚策略 MUST 存在租户表中 |
| `tenants` 或外部租户注册表 | 控制面租户目录，本身用于解析租户 | 租户配额、策略和运行数据 SHOULD 放入租户表或带 tenant 的扩展表 |
| `alembic_version` | 数据库迁移元数据，不是业务表 | 不得存放业务状态 |

## 3. Redis Stream tenant schema

### 3.1 Stream key

租户相关 stream key MUST 包含 tenant。推荐格式：

```text
guardian:{tenant_id}:alerts
guardian:{tenant_id}:alerts:retry
guardian:{tenant_id}:alerts:dlq
guardian:{tenant_id}:response:schedule
```

规则：

- 多租户生产环境 MUST NOT 使用单一共享 `guardian:alerts` 承载所有 tenant 告警。
- 单租户 legacy key `guardian:alerts` 只能用于本地开发、单租户部署或迁移窗口，并 MUST 被标记为非多租户合规。
- 如果 Redis Cluster 需要 hash tag，SHOULD 使用稳定格式，例如 `guardian:{tenant:<tenant_id>}:alerts`。

### 3.2 Message body

每条租户消息 body MUST 包含：

| 字段 | 要求 |
| --- | --- |
| `tenant_id` | MUST 存在，MUST 与 stream key 中 tenant 一致 |
| `event_id` 或 `alert_id` | MUST 存在，用于幂等入库 |
| `schema_version` | SHOULD 存在，便于演进和兼容 |
| `trace_id` / `correlation_id` | SHOULD 存在，便于跨 API、任务、审计追踪 |
| `producer` | SHOULD 存在，标识 collector、detector、manual job 或 system service |

consumer MUST 在入库前校验 `tenant_id`。校验失败 MUST NOT 写入 `alerts`、`alert_histories`、`response_actions` 等租户表。

### 3.3 Consumer group 隔离

- 使用 per-tenant stream 时，consumer group SHOULD 使用 `guardian:web`、`guardian:response` 等功能名，隔离由 stream key 提供。
- 如果因迁移期必须共享 stream，consumer group MUST 包含 tenant，例如 `guardian:web:{tenant_id}`，且 consumer MUST 按 body `tenant_id` 过滤和校验。
- consumer name SHOULD 包含进程或实例 ID，MUST NOT 被用作授权边界。
- PEL、claim、autoclaim 处理 MUST 限定在同一 tenant stream 和 group 内。

### 3.4 DLQ、retry、scheduled message

- DLQ、retry、scheduled message MUST 保留原始 `tenant_id`、原始 stream id、原始 event id、错误原因和重试次数。
- retry 后重新投递 MUST 投回同一 tenant 的 stream 或同一 tenant 的 retry stream。
- scheduled message MUST 将 `tenant_id` 作为调度 key 的一部分，也 MUST 在 message body 中保留 `tenant_id`。
- DLQ 查看、重放和删除操作 MUST 校验操作者对目标 tenant 的权限。

## 4. 后台任务隔离

### 4.1 任务传递 tenant_id

所有后台执行器，包括 Celery、RQ、cron、后台线程、manual job、CLI drill 和补偿脚本，MUST 将 `tenant_id` 作为显式输入之一：

| 执行器 | 传递方式 | 隔离要求 |
| --- | --- | --- |
| Celery | task kwargs 或 headers 中的 `tenant_id` | worker 进入任务第一步 MUST 绑定 tenant context |
| RQ | job meta 或 kwargs 中的 `tenant_id` | 执行前 MUST 校验 job meta 与参数一致 |
| cron | 每次执行传入 `--tenant-id` 或受控 tenant 清单 | 批处理 MUST 逐 tenant 循环，不能共享 ORM session |
| manual job/CLI | 必填参数 `--tenant-id`，批量任务使用 `--tenant-id` 多值或 manifest | 缺失 MUST 退出，不得读取生产默认值 |
| 后台线程 | 创建线程时复制当前 tenant context 或从调度表读取 | 线程池复用时 MUST 清理旧 tenant context |

### 4.2 无 tenant 上下文访问租户数据

- 后台任务在无 tenant 上下文时 MUST NOT 查询、写入、缓存或发布租户数据。
- 任务代码 MUST 在数据库访问前检查 tenant context。检查失败 MUST 抛出隔离错误，并记录全局安全审计。
- 全局任务，例如模型 artifact 校验或健康检查，MUST 明确声明只访问全局表；一旦触达租户表，MUST 切换到目标 tenant。

### 4.3 重试、补偿、批处理和管理员任务

- 重试 MUST 使用原任务的 `tenant_id`，MUST NOT 使用当前 worker 默认值或重试发起人的 tenant。
- 补偿任务 MUST 记录目标 `tenant_id`、原操作 ID、原 actor 和补偿原因。
- 批处理管理员任务 MUST 接受明确 tenant allowlist。`all tenants` 操作 SHOULD 分解为每个 tenant 一条子任务，并记录每个 tenant 的独立结果。
- 管理员跨租户查询 MUST 默认返回按 tenant 分组的汇总，MUST NOT 混合返回可操作的租户资源 ID，除非请求显式选择 tenant 并完成授权校验。
- 任务使用缓存、锁或去重 key 时，key MUST 包含 `tenant_id`，例如 `tenant:{tenant_id}:job:{job_id}`。

## 5. 越权测试矩阵

每个多租户发布门禁 MUST 覆盖以下测试矩阵。测试至少使用两个 tenant：`tenant_a` 和 `tenant_b`，并为每个 tenant 创建同名、同 external id、同 IP 或同 IOC value 的样本，以验证唯一键和过滤条件。

| 类别 | 测试目标 | 场景 | 预期 |
| --- | --- | --- | --- |
| API 读跨租户 | 查询隔离 | `tenant_a` token 查询 `tenant_b` 的 alert id、rule id、IOC value、banned ip | MUST 返回 404 或 403，MUST NOT 返回 `tenant_b` 数据 |
| API 写跨租户 | 写入归属 | `tenant_a` token 在 payload 中伪造 `tenant_id = tenant_b` | MUST 拒绝或覆盖为 `tenant_a`，MUST NOT 写入 `tenant_b` |
| API 更新/删除 | 关联资源校验 | `tenant_a` 更新 `tenant_b` alert 的状态、封禁、解封或设置 | MUST 拒绝，审计 MUST 记录越权尝试 |
| 后台任务跨租户 | 任务参数隔离 | 创建 `tenant_a` 任务但 payload 指向 `tenant_b` alert | MUST 失败，不得修改 `tenant_b` |
| 后台重试 | tenant 保持 | retry worker 在无上下文或错误上下文中重试 `tenant_a` 任务 | MUST 使用原 `tenant_id = tenant_a` 或失败，MUST NOT 漂移 |
| Redis Stream key/body | schema 校验 | key 为 `guardian:tenant_a:alerts`，body 为 `tenant_id = tenant_b` | MUST 拒绝处理并进入同 tenant DLQ 或隔离错误路径 |
| Redis consumer group | 消费隔离 | `tenant_a` consumer 尝试读取 `tenant_b` stream/group | MUST 无数据或权限拒绝 |
| Redis DLQ/replay | 重放隔离 | 管理员重放 `tenant_b` DLQ 到 `tenant_a` stream | MUST 拒绝，除非执行显式迁移工具且双 tenant 授权 |
| 审批流跨租户 | 待审批归属 | `tenant_a` 审批人审批 `tenant_b` 的 ban approval | MUST 拒绝，approval、response action、audit tenant MUST 一致 |
| 审批流回放 | 审批 token/id 猜测 | 使用 `tenant_a` 会话提交 `tenant_b` approval id | MUST 返回 404 或 403，不得泄露目标存在性细节 |
| 唯一键 | 租户内唯一 | `tenant_a` 与 `tenant_b` 使用相同 `external_id`、`ioc_type/value`、`settings.key`、`banned_ips.ip` | MUST 均可创建；同 tenant 重复 MUST 触发唯一冲突 |
| 查询过滤遗漏 | ORM 主键查询 | 使用全局唯一外观的 id 调用 get/update/delete | MUST 自动加 tenant 过滤或校验实体 tenant |
| 管理员边界 | 管理员 tenant scope | tenant 管理员访问其他 tenant；平台管理员未指定 tenant 执行业务写入 | tenant 管理员 MUST 拒绝；平台管理员业务写入 MUST 指定目标 tenant |
| system tenant 边界 | system actor | system job 无目标 tenant 写入 alert/response/banned ip | MUST 失败；只允许写全局表或带目标 tenant 的租户表 |
| 全局表引用 | 全局模型引用 | `tenant_a` 启用全局 `model_versions.version` | 启用状态 MUST 写入租户表，MUST NOT 修改 `model_versions` 表来表达 tenant 状态 |

### 5.1 最低验收要求

- 测试 MUST 同时覆盖 REST/API、后台任务、Redis Stream、审批流、数据库唯一键和管理员边界。
- 测试 MUST 包含正向同租户成功路径和反向跨租户拒绝路径。
- 测试 MUST 对数据库最终状态做断言，而不仅检查 HTTP 状态码。
- 测试 SHOULD 检查审计事件中 `tenant_id`、`actor`、`resource_type`、`resource_id` 一致。
- 发布前 SHOULD 增加静态扫描或 ORM helper 约束，发现租户表查询缺少 `tenant_id` 时失败。
