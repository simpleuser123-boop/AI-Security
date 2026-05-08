# Phase C6: 真实响应受控开放方案

## 背景

AI-Security-Guardian 当前响应链路已经具备分级响应、审计记录、审批状态、定时解封任务和 provider 抽象雏形：

- `src/response/responder.py` 中 `SecurityResponder` 默认 `dry_run=True`，并要求 `REAL_ENFORCEMENT_GATE=real-enforcement` 才允许真实封禁路径继续执行。
- `src/response/firewall.py` 中 iptables provider 在非 dry-run 时还要求 `approved_response_execution()` 上下文，未审批调用会返回 `approval_required`。
- `src/response/ip_policy.py` 已提供业务白名单、私网白名单、保留地址和私网地址保护，默认拒绝 RFC1918/CGNAT 私网真实封禁。
- `src/response/scheduler.py` 与 `web.models.ResponseScheduleTask` 已提供定时解封、通知重试等可恢复任务基础。
- `web.app` 当前手工封禁入口先创建 `pending_approval` 的 `ResponseAction`，不直接落真实封禁。
- `docs/deployment.md` 已明确私有化 Beta 必须保持 `DRY_RUN=true`，真实封禁必须单独通过 `--gate real-enforcement`。

因此 Phase C6 的目标不是把真实封禁默认打开，而是在客户强要求时，设计一套可以审计、可回滚、可恢复、可交付验收的受控开放机制。

## 目标

1. 保持 Beta 默认安全策略：`DRY_RUN=true` 是私有化 Beta 默认值和验收基线。
2. 明确真实响应启用条件：`DRY_RUN=false` 只能在 `real-enforcement` gate 通过后启用。
3. 引入产品、技术、安全、交付四类 gate，任何一类不通过都不得启用真实响应。
4. 支持私有化场景先行：以客户内网、客户云账号、客户 EDR 租户为执行边界。
5. 明确 SaaS 后置能力：SaaS 多租户真实响应暂不作为 C6 默认交付能力。
6. 给出 API、数据模型、provider、演练模板和测试清单，后续可以拆分为工程任务。
7. 严格拆分 readiness gate：`private-beta` 只证明可部署、可审计、可演练，且必须保持 `DRY_RUN=true`；`real-enforcement` 才允许 `DRY_RUN=false`。

## 非目标

- 不改变当前 Beta 默认 `DRY_RUN=true` 策略。
- 不在 Beta 默认部署中开启真实封禁、真实云安全组变更或真实 EDR 隔离。
- 不把 `cloud_sg_placeholder`、`LoggingHostIsolationProvider` 直接视为生产 provider。
- 不承诺 SaaS 多租户真实响应在 C6 交付。
- 不支持无审批、无白名单、无定时解封、无恢复演练的自动封禁。
- 不把检测模型置信度直接等价为可执行封禁授权。

## 默认安全策略

### 强制默认值

- 私有化 Beta 和 SaaS Beta 默认必须为 `DRY_RUN=true`。
- `DRY_RUN=false` 不得出现在默认 `.env.example`、演示部署、试用部署或客户未验收环境中。
- `REAL_ENFORCEMENT_GATE` 默认留空。
- `RESPONSE_FIREWALL_BACKEND` 默认可为 `iptables`，但在 `DRY_RUN=true` 下只记录意图，不执行真实命令。
- `RESPONSE_HOST_ISOLATION` 默认必须为 `none`。

### 启用真实响应的硬条件

只有同时满足以下条件，才允许设置：

```bash
DRY_RUN=false
REAL_ENFORCEMENT_GATE=real-enforcement
```

硬条件：

- `python scripts/check_production_readiness.py --gate real-enforcement` 通过。
- `REAL_ENFORCEMENT_GATE=real-enforcement`。
- `REAL_ENFORCEMENT_APPROVAL_REQUIRED=true`。
- `REAL_ENFORCEMENT_AUDIT_VERIFIED=true`。
- `REAL_ENFORCEMENT_ROLLBACK_READY=true`。
- `REAL_ENFORCEMENT_UNBLOCK_READY=true`。
- `REAL_ENFORCEMENT_REVIEW_REQUIRED=true`。
- 产品、技术、安全、交付四类 gate 全部签署通过。
- 响应审批工作流已启用，真实动作必须关联审批单。
- 业务白名单和私网资产白名单已配置并经客户确认；`RESPONSE_BUSINESS_IP_WHITELIST` 非空，或 `response_whitelist_entries` 已上传 active IP/CIDR 白名单。
- provider 配置已测试通过：`response_provider_configs.status='active'`、`last_validated_at` 非空、`last_validation_result.ok=true`。
- 恢复演练记录存在：`response_drills.status='passed'`，类型为 `real_ban_unblock`、`provider_rollback` 或 `misblock_recovery`，并已记录 `ended_at`。
- 每次封禁必须有 `scheduled_unblock_at` 或同等 TTL。
- 客户侧完成误封恢复演练，保存演练证据。
- 审计链路可用：`response_actions`、`response_schedule_tasks`、`audit_events`、`logs/security.log` 可查询和归档。

### 运行期保护

- 若 `DRY_RUN=false` 但 `REAL_ENFORCEMENT_GATE != real-enforcement`，响应层必须拒绝真实封禁并记录 `real_enforcement_gate_required`。
- provider 层必须拒绝未处在 `approved_response_execution()` 上下文中的真实执行。
- 白名单、保留地址、本机地址、客户私网保护命中时必须跳过封禁。
- 私网地址默认不得封禁；`RESPONSE_ALLOW_PRIVATE_BAN=true` 只能用于受控实验，不进入 C6 生产交付基线。

## 完整 Gate

### 产品 Gate

通过标准：

- 客户已书面确认真实响应范围、风险和责任边界。
- 明确启用对象：仅 IP 临时封禁、云安全组 deny、EDR 主机隔离中的哪些动作。
- 明确不启用对象：生产核心业务网段、办公出口、VPN、LB、DNS、监控探针、堡垒机、EDR 管控节点等。
- 明确响应等级：建议仅 `critical` 或人工审批后的 `high` 可进入真实动作。
- 明确 TTL：默认 high 1 小时、critical 24 小时；客户可配置更短 TTL，不允许无限期自动封禁。
- 明确人工审批 SLA、响应后复盘 SLA、误封恢复 SLA。
- 客户接受 Beta 真实响应为受控开放能力，不属于默认功能。

产物：

- 《真实响应启用申请表》
- 《客户风险确认书》
- 《响应范围与非范围清单》
- 《误封责任与恢复 SLA 确认》

### 技术 Gate

通过标准：

- `DRY_RUN=true` 环境已稳定运行并完成至少一次全链路演练。
- 数据库为生产级 PostgreSQL，迁移版本可追踪。
- Redis、模型、审计日志、调度任务均通过 readiness。
- `response_actions`、`response_schedule_tasks`、`audit_events` 已具备租户字段和查询索引。
- provider 使用客户授权凭证，凭证由客户密钥系统或受控环境变量提供。
- provider 支持幂等创建、幂等删除、超时、重试、错误码归一化。
- 定时解封 worker 已部署，重启后可恢复 pending 任务。
- 真实封禁执行前后能拉取 provider 侧状态证明。

产物：

- `check_production_readiness.py --gate real-enforcement` 输出
- provider 连通性测试记录
- 定时解封恢复测试记录
- 数据库迁移和回滚记录

### 安全 Gate

通过标准：

- 业务白名单、私网白名单、管理网段白名单经客户安全团队确认。
- 所有真实动作必须经过审批流，不允许检测直接执行。
- 审批至少包含申请人、审批人、原因、证据、TTL、目标、provider、回滚方式。
- 审批人与申请人原则上不得为同一人；紧急模式必须事后复核。
- 所有 provider 凭证最小权限，仅允许目标安全组或目标 EDR tenant 内动作。
- 审计日志不可静默关闭，日志归档和哈希校验通过。
- SSRF、命令注入、IP 格式、租户越权、重复封禁、越权解封测试通过。
- 完成误封恢复演练并证明 RTO 达标。

产物：

- 《业务白名单确认表》
- 《安全审批矩阵》
- 《最小权限凭证证明》
- 《审计完整性验证记录》
- 《误封恢复演练报告》

### 交付 Gate

通过标准：

- 客户现场已完成 dry-run 演示、审批演示、真实小流量演示、恢复演示。
- 交付工程师、客户安全团队、客户网络/云团队、客户 EDR 管理员均在演练记录中签字。
- 已交付客户侧操作手册，包括一键切回 `DRY_RUN=true`、解封、provider 回滚。
- 已建立值班升级路径和联系人。
- 已约定真实响应灰度窗口，首次启用不得在业务高峰。
- 已确认 SaaS 能力限制：C6 真实响应仅私有化受控开放。

产物：

- 《上线变更单》
- 《灰度计划》
- 《回滚预案》
- 《值班联系人表》
- 《交付验收单》

## 审批工作流

### 状态机

建议在现有 `ResponseAction.status` 基础上扩展：

- `pending_approval`：已创建审批请求，未授权执行。
- `approved`：审批通过，但尚未执行 provider。
- `rejected`：审批拒绝或 gate 不通过。
- `executing`：provider 调用中。
- `executed`：真实动作已生效。
- `dry_run_simulated`：dry-run 演练动作。
- `scheduled_unblocked`：定时解封完成。
- `manual_unblocked`：人工解封完成。
- `failed`：执行失败，需要人工处理。
- `reviewed`：响应后复盘完成。

### 审批角色

- 申请人：安全运营人员或检测系统。
- 产品审批：确认客户授权、功能范围和风险告知。
- 技术审批：确认环境、provider、调度、回滚路径可用。
- 安全审批：确认目标、白名单、证据和最小权限。
- 交付审批：确认客户窗口、联系人和恢复演练。
- 执行人：系统账号或交付授权账号。
- 复核人：响应后复盘负责人。

### 执行规则

- 检测链路只能创建 `pending_approval`，不得直接执行真实封禁。
- `DRY_RUN=true` 时允许 dry-run 自动审批用于演练，但必须标记 `dry_run_only=true`。
- `DRY_RUN=false` 时必须存在已通过的审批记录，且审批记录必须引用当前 `real-enforcement` gate。
- 每个真实动作必须写入 `ResponseAction`，并在 `meta` 中保存 `approval_id`、`gate_id`、`provider`、`ttl_seconds`、`rollback_plan_id`。
- 审批通过后由服务端重新计算白名单与 gate，不信任客户端提交结果。
- 审批只授权一次动作，不得作为永久自动封禁开关。

## 白名单策略

### 白名单类型

- 业务白名单：客户核心业务出口、支付、登录、API 网关、LB、办公出口。
- 管理白名单：堡垒机、VPN、运维跳板机、监控探针、CI/CD、备份系统。
- 私网白名单：客户内网服务网段、云 VPC 网段、Kubernetes 节点和 Pod CIDR。
- Provider 保护白名单：云安全组管理源、EDR 管控平台、日志采集器。
- 临时白名单：重大活动、发布窗口、演练窗口的短期保护对象。

### 配置建议

短期可复用环境变量：

```bash
RESPONSE_BUSINESS_IP_WHITELIST=203.0.113.10,203.0.113.11
RESPONSE_PRIVATE_IP_WHITELIST=10.10.1.10,10.10.1.11
RESPONSE_ALLOW_PRIVATE_BAN=false
```

C6 工程化后建议落库：

- 支持 CIDR，不仅是单 IP。
- 支持 `scope`：global、tenant、provider、environment。
- 支持 `expires_at`：临时白名单自动过期。
- 支持审批变更和审计。

### 判定顺序

1. IP 格式校验。
2. 回环、链路本地、组播、保留地址拒绝。
3. 业务白名单命中拒绝。
4. 私网白名单命中拒绝。
5. RFC1918/CGNAT 默认拒绝。
6. provider-specific 保护列表命中拒绝。
7. 审批、TTL、gate 校验。
8. provider 执行。

## 定时解封

### 基线要求

- 所有真实封禁必须带 TTL。
- high 默认 TTL 1 小时，critical 默认 TTL 24 小时。
- 真实 `ban_ip` provider 执行成功后必须创建 `scheduled_unblock` 任务，并保留 `related_response_action_id`。
- 持久化层拒绝没有未来 `scheduled_unblock_at` 的真实 `ban_ip executed` 记录。
- TTL 到期必须执行 `scheduled_unblock` 任务；worker 重启后从 `response_schedule_tasks` 恢复 pending 任务。
- 定时解封失败必须重试，写入 `last_error` 和 `attempt_count`，达到最大次数后升级为人工待办。
- 定时解封必须幂等：如果 provider 规则已经不存在，记录 `unban_ip skipped` / `scheduled_unblock_rule_absent`，任务完成，不得无限失败。
- 系统切回 `DRY_RUN=true` 不应删除已有解封任务；但再次执行时应按任务记录的 `dry_run` 和 provider 状态处理。

### 当前基础

现有 `ResponseScheduler.schedule_unblock()` 已可创建 `TASK_SCHEDULED_UNBLOCK`；`ResponseScheduleTask` 已包含 `run_at`、`status`、`attempt_count`、`max_attempts`、`related_response_action_id`。

### C6 增强

- 在 `ResponseAction` 中强制 `scheduled_unblock_at` 非空，除非动作类型不是封禁。
- 定时解封任务 payload 增加 `provider`、`provider_rule_id`、`approval_id`、`gate_id`。
- 解封前查询 provider 状态，确认规则仍由 Guardian 创建。
- 解封只删除 Guardian 创建的规则，不删除客户手工规则。
- 解封完成后写入 provider 侧证据：规则不存在、主机恢复、时间戳。
- 如果封禁成功但解封任务创建失败，立即执行回滚解封并写入 `response.ban_ip.schedule_unblock_failed` 审计事件。

## 云安全组 Provider

### Provider 范围

C6 私有化优先支持云安全组 provider。初期建议按客户实际云厂商选择一个落地，不在同一阶段铺开所有云。

候选：

- AWS Security Group / Network ACL
- Azure NSG
- Google Cloud Firewall
- 阿里云安全组
- 腾讯云安全组
- 华为云安全组

### 接口草案

```python
class CloudSecurityGroupProvider:
    def validate_config(self) -> ProviderCheckResult: ...
    def dry_run_block_ip(self, ip: str, *, ttl_seconds: int, context: dict) -> ProviderResult: ...
    def block_ip(self, ip: str, *, ttl_seconds: int, context: dict) -> ProviderResult: ...
    def unblock_ip(self, rule_id: str, *, context: dict) -> ProviderResult: ...
    def get_rule(self, rule_id: str) -> ProviderRuleState: ...
```

### C6 Provider Schema（当前实现）

当前代码先落地统一 provider 抽象、placeholder、配置 schema 和测试桩；真实云 SDK 默认不启用。

`RESPONSE_FIREWALL_BACKEND` 可选：

- `iptables`：默认值，保持原行为。
- `cloud_sg_placeholder`：云安全组占位，不调用云 API。
- `aliyun_security_group`
- `tencent_security_group`
- `aws_security_group`
- `huawei_security_group`

云安全组 provider 配置只保存非敏感元数据：

```bash
RESPONSE_FIREWALL_BACKEND=aws_security_group
RESPONSE_CLOUD_SG_TENANT_ID=tenant-a
RESPONSE_CLOUD_SG_REGION=ap-southeast-1
RESPONSE_CLOUD_SG_ALLOWED_IDS=sg-allowed-1,sg-allowed-2
RESPONSE_CLOUD_SG_TARGET_IDS=sg-allowed-1
RESPONSE_CLOUD_SG_CREDENTIAL_REF=secret://customer-vault/cloud-sg/tenant-a
RESPONSE_CLOUD_SG_RESPONSE_ACTION_ID=ra-123
```

约束：

- `RESPONSE_CLOUD_SG_CREDENTIAL_REF` 只能是凭证引用，不能是 access key、secret key 或 token 明文。
- `RESPONSE_CLOUD_SG_TARGET_IDS` 必须完全属于 `RESPONSE_CLOUD_SG_ALLOWED_IDS`，否则拒绝执行。
- `dry_run=true` 只返回包含安全组、CIDR、动作和 `guardian:<tenant_id>:<response_action_id>` 标识的 plan。
- 非 dry-run 必须同时通过 responder 的 approval、real-enforcement gate，以及 provider 层的 `approved_response_execution()`。
- 当前真实 SDK client 未绑定时，非 dry-run 返回 `provider_sdk_not_configured`，不会伪装为成功。

### 执行原则

- 只操作客户指定的安全组或防火墙策略。
- 每条规则必须打 tag/description：`created_by=ai-security-guardian`、`approval_id`、`expires_at`。
- 创建前检查重复规则，避免无限叠加。
- 删除时只删除带 Guardian 标识的规则。
- provider API 超时必须短，失败后不得无限重试。
- provider 结果必须写入 `ResponseAction.meta.provider_result`。

### 最小权限

凭证只允许：

- 查询目标安全组规则。
- 添加 deny/drop 规则到指定安全组。
- 删除带 Guardian 标识的规则。

禁止：

- 修改非目标安全组。
- 修改入站放行规则。
- 修改路由表、IAM、实例生命周期。

## EDR Provider

### Provider 范围

C6 可设计 EDR/主机隔离 provider，但默认不交付 SaaS 真实隔离。私有化客户如强要求，应按客户 EDR 产品单独适配。

候选：

- Microsoft Defender for Endpoint
- CrowdStrike Falcon
- SentinelOne
- Carbon Black
- 深信服、奇安信、天擎等本地 EDR

### 接口草案

```python
class EdrIsolationProvider:
    def validate_config(self) -> ProviderCheckResult: ...
    def dry_run_isolate_host(self, host_id: str, *, context: dict) -> ProviderResult: ...
    def isolate_host(self, host_id: str, *, context: dict) -> ProviderResult: ...
    def release_host(self, isolation_id: str, *, context: dict) -> ProviderResult: ...
    def get_host_state(self, host_id: str) -> HostIsolationState: ...
```

### 执行原则

- IP 不能直接等价为主机，必须解析到客户确认的 `host_id`。
- 主机隔离必须比 IP 封禁更高审批等级：仅 `critical`，并且必须满足双人审批或交付确认、恢复演练通过、provider test 通过。
- 隔离前必须确认目标不是 EDR 管控节点、域控、堡垒机、日志平台、备份节点。
- 隔离必须带自动释放时间或人工释放工单。
- 释放失败必须升级到客户 EDR 管理员。
- `DRY_RUN=true` 时 provider 只能返回隔离计划，不得调用真实 EDR API。
- 审计必须保留发起人、审批人、目标、provider、恢复建议和 provider 返回证据。

### 当前代码映射

当前 `src/response/host_isolation.py` 已落地 provider 抽象和受控占位实现。默认 `RESPONSE_HOST_ISOLATION=none`，critical 告警只会写入 `isolation_manual_pending`，不会失败扩散或调用 EDR。

`RESPONSE_HOST_ISOLATION` 可选：

- `none`：默认值，降级为人工待办。
- `logging` / `placeholder`：只记录计划，用于联调、演练和审计验证，不视为生产 EDR。
- `edr_custom_webhook`
- `edr_crowdstrike`
- `edr_defender`
- `edr_sentinelone`

EDR provider 配置只保存非敏感元数据：

```bash
RESPONSE_HOST_ISOLATION=edr_defender
RESPONSE_HOST_ISOLATION_TENANT_ID=tenant-a
RESPONSE_HOST_ISOLATION_CREDENTIAL_REF=secret://customer-vault/edr/tenant-a
RESPONSE_HOST_ISOLATION_ENDPOINT=https://customer-edr.example/api/isolate
RESPONSE_HOST_ISOLATION_PROVIDER_TEST_PASSED=true
RESPONSE_HOST_ISOLATION_RECOVERY_DRILL_PASSED=true
```

真实主机隔离运行期必须同时满足：

- `DRY_RUN=false`
- `REAL_ENFORCEMENT_GATE=real-enforcement`
- 已执行 `execute_approved_host_isolation()` 或等价审批执行入口
- 发起人与审批人不同，或交付确认 `delivery_confirmed=true`
- `recovery_drill_passed=true`
- `provider_test_passed=true`

provider 层仍会二次保护：非 dry-run 且不在 `approved_response_execution()` 上下文中会返回 `approval_required`；SDK/client 未绑定时返回 `provider_sdk_not_configured`，不会伪装为成功。恢复路径先以 `unisolate_host` / `recover_host_isolation()` 草案保留，审计中必须写入 `recovery_hint`。

## 客户恢复演练

### 演练目标

证明客户在真实响应误伤时，可以在约定 RTO 内恢复业务访问，并保留完整审计证据。

### 演练环境

- 首选客户预生产或隔离演练环境。
- 使用客户批准的测试 IP、测试安全组、测试主机。
- 不得选择真实业务核心网段做首次演练。

### 演练步骤

1. 确认 `DRY_RUN=true`，执行 dry-run 封禁，检查审批和审计。
2. 通过四类 gate，临时设置 `DRY_RUN=false` 与 `REAL_ENFORCEMENT_GATE=real-enforcement`。
3. 对测试 IP 或测试主机执行一次真实响应。
4. 验证 provider 侧规则或隔离状态已生效。
5. 验证 `ResponseAction`、`AuditEvent`、provider 证据完整。
6. 执行定时解封或人工解封。
7. 验证业务恢复。
8. 立即切回 `DRY_RUN=true`，清空或撤销 `REAL_ENFORCEMENT_GATE`。
9. 复盘耗时、失败点、审批记录和日志。

### 误封应急 Runbook

1. 止血：将 `.env` 或密钥配置切回 `DRY_RUN=true`，移除 `REAL_ENFORCEMENT_GATE`。
2. 暂停：暂停响应 worker 或 provider 执行队列。
3. 定位：按 `response_action_id`、IP、provider rule id 查询动作。
4. 恢复：删除云安全组 deny 规则，或 EDR release host。
5. 加白：将误封对象加入业务白名单或私网白名单。
6. 验证：业务探针、用户访问、监控恢复。
7. 审计：归档 `response_actions`、`audit_events`、provider 操作日志。
8. 复盘：未完成前不得再次启用 `DRY_RUN=false`。

详细恢复 SOP 交付件：`templates/misblock-recovery-sop.md`。误封现场第一步必须先切回 `DRY_RUN=true` 并移除 `REAL_ENFORCEMENT_GATE`，再执行回滚或人工解封。

## 私有化 / SaaS 分界

### C6 支持：私有化受控开放

私有化可以先支持真实响应，因为执行边界清晰：

- 客户提供云账号或 EDR tenant。
- 系统部署在客户网络或客户云 VPC 内。
- 客户自行确认业务白名单和恢复窗口。
- provider 只影响客户授权资源。
- 审批和演练证据可随交付包归档。

### C6 不默认支持：SaaS 真实响应

SaaS 真实响应后置，原因：

- 多租户 provider 凭证隔离复杂。
- SaaS 平台误操作可能跨客户产生高风险。
- 客户云 API 回调、网络连通、EDR tenant 授权差异大。
- 需要更完整的租户级 kill switch、provider sandbox、审批委托和跨租户审计。

### SaaS 后置能力清单

后续 SaaS 若开放，至少需要：

- 租户级 `real_enforcement_enabled` 开关，默认 false。
- 租户级 provider 凭证保险箱和最小权限校验。
- 租户级白名单、审批策略、TTL 策略。
- 平台级 kill switch，可一键切断所有真实 provider。
- 租户级执行队列隔离和速率限制。
- 跨租户审计证明和客户自助导出。
- SaaS 合同条款和责任边界更新。

## API 草案

以下 API 均要求 JWT 或租户 API Key，且需要 admin/security-admin 级权限。真实执行类 API 还必须通过服务端 gate 校验。

### Gate

```http
GET /api/response/real-enforcement/gate
POST /api/response/real-enforcement/gate/check
POST /api/response/real-enforcement/gate/activate
POST /api/response/real-enforcement/gate/deactivate
```

说明：

- `check` 只校验，不启用。
- `activate` 仅私有化可用，要求四类 gate 证据 id。
- `deactivate` 立即切回受控状态，建议同时提示运维设置 `DRY_RUN=true`。

### 审批

```http
POST /api/response/approvals
GET /api/response/approvals
GET /api/response/approvals/{approval_id}
POST /api/response/approvals/{approval_id}/approve
POST /api/response/approvals/{approval_id}/reject
POST /api/response/approvals/{approval_id}/execute
POST /api/response/approvals/{approval_id}/review
```

创建请求体草案：

```json
{
  "action_type": "ban_ip",
  "target": "198.51.100.23",
  "provider": "cloud_security_group",
  "ttl_seconds": 3600,
  "reason": "critical alert confirmed by analyst",
  "alert_id": "alert_123",
  "evidence": {
    "confidence": 0.98,
    "rule_id": "critical-ddos"
  }
}
```

### 白名单

```http
GET /api/response/whitelists
POST /api/response/whitelists
PATCH /api/response/whitelists/{id}
DELETE /api/response/whitelists/{id}
POST /api/response/whitelists/check
```

### Provider

```http
GET /api/response/providers
POST /api/response/providers/{provider_id}/validate
POST /api/response/providers/{provider_id}/dry-run
GET /api/response/providers/{provider_id}/actions/{provider_action_id}
```

### 定时解封与恢复

```http
GET /api/response/schedule-tasks
POST /api/response/actions/{response_action_id}/unblock-now
POST /api/response/actions/{response_action_id}/rollback
POST /api/response/recovery-drills
GET /api/response/recovery-drills/{drill_id}
```

## 数据模型草案

### 复用现有表

`response_actions` 增强使用：

- `action_type`：`ban_ip`、`unban_ip`、`isolate_host`、`release_host`、`response_review`。
- `status`：采用审批状态机。
- `dry_run`：真实动作必须为 false，演练必须为 true。
- `scheduled_unblock_at`：真实封禁必填。
- `meta`：保存审批、gate、provider、TTL、证据和回滚信息。

`response_schedule_tasks` 增强使用：

- `task_type`：`scheduled_unblock`、`scheduled_release_host`、`notify_retry`。
- `payload`：保存 tenant、provider、rule_id、host_id、approval_id。
- `related_response_action_id`：关联原始封禁动作。

`audit_events` 增强使用：

- `event_type` 建议：`response.approval.created`、`response.approval.approved`、`response.action.executed`、`response.action.rollback`、`response.gate.activated`。

### 新增表建议

`response_real_enforcement_gates`

- `id`
- `tenant_id`
- `environment`
- `status`: pending、active、revoked、expired
- `product_gate_status`
- `technical_gate_status`
- `security_gate_status`
- `delivery_gate_status`
- `activated_by`
- `activated_at`
- `expires_at`
- `evidence`

`response_approvals`

- `id`
- `tenant_id`
- `alert_id`
- `action_type`
- `target_type`: ip、host、security_group_rule
- `target`
- `provider`
- `ttl_seconds`
- `status`
- `requested_by`
- `approved_by`
- `rejected_by`
- `executed_by`
- `reviewed_by`
- `gate_id`
- `response_action_id`
- `evidence`
- `created_at`
- `updated_at`

`response_whitelist_entries`

- `id`
- `tenant_id`
- `scope`: business、management、private、provider、temporary
- `value`: IP 或 CIDR
- `value_type`: ip、cidr
- `reason`
- `owner`
- `expires_at`
- `status`
- `created_by`
- `approved_by`

`response_provider_configs`

- `id`
- `tenant_id`
- `provider_type`: iptables、cloud_security_group、edr
- `provider_name`
- `environment`
- `status`
- `config_ref`
- `last_validated_at`
- `last_validation_result`

`response_provider_actions`

- `id`
- `tenant_id`
- `response_action_id`
- `provider_config_id`
- `operation`
- `provider_rule_id`
- `provider_host_id`
- `request_hash`
- `result`
- `created_at`

`response_recovery_drills`

- `id`
- `tenant_id`
- `environment`
- `drill_type`
- `target`
- `started_at`
- `ended_at`
- `rto_seconds`
- `result`
- `evidence`
- `participants`

## 测试清单

### 单元测试

- `SecurityResponder()` 默认 `dry_run=True`。
- `DRY_RUN=false` 且缺少 `REAL_ENFORCEMENT_GATE=real-enforcement` 时拒绝真实封禁。
- provider 非 dry-run 且无 `approved_response_execution()` 时返回 `approval_required`。
- 白名单命中时 `status=skipped`，provider 不被调用。
- 私网地址默认拒绝真实封禁。
- invalid IP、localhost、link-local、multicast 均拒绝。
- `approve_and_ban_ip()` 在 dry-run 下只产生演练动作。
- 定时解封只对已执行动作生效。

### 集成测试

- Web `/api/banned_ips` POST 返回 `202 pending_approval`，不直接写 `banned_ips` 真实封禁。
- 审批 API 全状态流转测试。
- gate 未通过时 execute API 返回 403。
- gate 通过但白名单命中时 execute API 返回 skipped。
- provider dry-run 返回预期计划，不产生外部变更。
- provider block 后写入 `ResponseAction`、`ProviderAction`、`AuditEvent`。
- scheduler 重启后能继续执行到期解封。
- quota、RBAC、租户隔离均生效。

### E2E 演练测试

- 私有化 dry-run 全链路：告警 -> 审批 -> dry-run 封禁 -> dry-run 解封 -> 复盘。
- 私有化真实小流量：测试 IP -> 云安全组 deny -> 自动解封 -> 状态验证。
- EDR 测试主机：隔离 -> 验证 -> 释放。
- 误封恢复：切回 `DRY_RUN=true` -> 手工解封 -> 加白 -> 复盘。
- provider API 超时：动作 failed，生成待办，不重复创建规则。

### 安全测试

- 越权租户不能读取或执行其他租户审批。
- API Key 作用域不足不能执行真实响应。
- 审批人与申请人为同一人时按策略拒绝或要求二次审批。
- 伪造客户端 gate 字段无效，服务端重新校验。
- CIDR 白名单边界测试。
- provider 凭证泄漏扫描，日志不得输出 secret。
- Webhook SSRF 保护不被真实响应通知绕过。

### 运维测试

- `check_production_readiness.py` 默认 gate 要求 `DRY_RUN=true`。
- `check_production_readiness.py --gate real-enforcement` 要求 `DRY_RUN=false` 和 gate 证据。
- `DRY_RUN=false` 但缺少 `REAL_ENFORCEMENT_GATE=real-enforcement`、审批、审计、回滚、解封、复盘、白名单、provider 测试或恢复演练任一项时必须 FAIL。
- 应用重启后 pending schedule task 不丢失。
- 数据库备份恢复后响应历史和待解封任务可查询。
- 一键停用真实响应流程可在约定 RTO 内完成。

### Readiness Gate 测试用例

| 用例 | 前置条件 | 操作 | 期望 |
|------|----------|------|------|
| dry-run beta gate | `DRY_RUN=true`，生产基础项齐备 | `python scripts/check_production_readiness.py` | PASS；输出说明 private Beta 为非执行模式 |
| beta 不放行真实封禁 | `DRY_RUN=false`，其余基础项齐备 | `python scripts/check_production_readiness.py` | FAIL；提示 private-beta 必须 `DRY_RUN=true` |
| real gate 拒绝 dry-run | `DRY_RUN=true` | `python scripts/check_production_readiness.py --gate real-enforcement` | FAIL；真实执行 gate 要求 `DRY_RUN=false` |
| 审批缺失 | `DRY_RUN=false`，未设置 `REAL_ENFORCEMENT_APPROVAL_REQUIRED=true` | 执行 real-enforcement gate | FAIL；命中审批门禁 |
| 白名单缺失 | `RESPONSE_BUSINESS_IP_WHITELIST` 为空，DB 无 active IP/CIDR 白名单 | 执行 real-enforcement gate | FAIL；要求 env 白名单或 DB 白名单 |
| DB 白名单放行 | env 白名单为空，DB 有 active `business/private/control_plane/office/monitoring` IP/CIDR | 执行 real-enforcement gate | 白名单检查 PASS |
| provider 未测试 | 无 active provider，或 `last_validation_result.ok` 非 true | 执行 real-enforcement gate | FAIL；不得调用真实 provider，仅检查配置记录 |
| provider dry-run | 配置真实 provider 客户端桩，`dry_run=True` 调用 provider dry-run | 执行 provider 单元测试 | 返回 plan；外部 API 调用计数为 0 |
| 定时解封 | 真实执行动作带未来 `scheduled_unblock_at` | 执行 scheduler tick 或重启恢复测试 | 到期解封完成；规则不存在时记录 skipped，不重复失败 |
| 回滚 | 已执行封禁动作 | 调用 `rollback_ban` / `manual_unban_ip` | 写入审计，provider 解封一次，业务恢复 |
| 复盘 | 已执行或已解封响应动作 | 调用 review API 或 `mark_response_reviewed` | 状态进入 reviewed；复盘不授予新的执行权限 |
| 恢复演练缺失 | DB 无 `passed` 的 `real_ban_unblock`、`provider_rollback`、`misblock_recovery` 记录 | 执行 real-enforcement gate | FAIL；要求恢复演练记录存在 |

## 交付模板清单

- `templates/real-response-enable-request.md`：真实响应启用申请表。
- `templates/real-response-risk-acceptance.md`：客户风险确认书。
- `templates/real-response-gate-checklist.md`：四类 gate 检查表。
- `templates/response-business-whitelist.xlsx`：业务白名单和私网白名单模板。
- `templates/provider-config-cloud-sg.md`：云安全组 provider 配置模板。
- `templates/provider-config-edr.md`：EDR provider 配置模板。
- `templates/real-response-approval-sop.md`：审批 SOP。
- `templates/misblock-recovery-runbook.md`：误封恢复 Runbook。
- `templates/recovery-drill-report.md`：客户恢复演练报告。
- `templates/go-live-change-ticket.md`：上线变更单。
- `templates/rollback-plan.md`：回滚预案。
- `templates/post-response-review.md`：响应后复盘模板。

## 分阶段落地建议

### C6.1 文档和 readiness 固化

- 完成本文档和交付模板。
- 强化 `check_production_readiness.py --gate real-enforcement` 输出四类 gate 缺失项。
- 在部署文档中引用本文档。

### C6.2 审批和白名单落库

- 新增 `response_approvals`、`response_whitelist_entries`、`response_real_enforcement_gates`。
- Web/API 从环境变量白名单过渡到租户级白名单。
- 所有真实响应执行从 `response_approvals/{id}/execute` 进入。

### C6.3 Provider 生产化

- 选择一个云安全组 provider 做私有化首发。
- provider 实现幂等、tag、状态查询、删除校验。
- EDR provider 保持设计态或按客户项目单独适配。

### C6.4 恢复演练和灰度

- 完成客户恢复演练模板。
- 支持演练报告在系统中归档。
- 首批客户仅支持私有化、小范围、短 TTL、人工审批。

## 最终准入结论

Phase C6 的默认结论是：真实响应可以设计为受控开放能力，但不得成为 Beta 默认能力。

硬性规则：

- `DRY_RUN=true` 是 Beta 默认策略。
- `DRY_RUN=false` 只能在 `real-enforcement` gate 通过后启用。
- `REAL_ENFORCEMENT_GATE=real-enforcement` 不是单一开关，而是产品、技术、安全、交付四类 gate 全部通过后的运行期证明。
- 私有化可在客户强要求、客户签署风险、恢复演练通过后受控开放。
- SaaS 真实响应后置，C6 只定义边界和后续能力要求。
