# AI-Security-Guardian GA 前路线图收敛方案

日期：2026-05-08  
范围：基于当前 `ai-security-guardian` 项目、单企业私有化 Beta RC 演练结果、SaaS Beta RC 能力验收与商业化路线图，收敛到 GA 前必须完成的产品、工程、交付和合同准入项。

## 1. 管理层摘要

当前项目已经从 Demo 进入 Beta RC 状态：数据库迁移、多租户基础模型、租户级核心表、License/套餐/配额/用量计量 MVP、审计哈希链、Redis Stream 消费、备份恢复演练、响应审批/白名单/provider/drill 模型、SaaS 控制面基础 API 和 SLO 文档均已具备雏形。

但 GA 不能直接从当前 RC 放行。建议拆成两条线：

- **Private Deployment GA**：优先成为可签首批单企业私有化商业合同的版本。目标是“可部署、可恢复、可审计、可运维、责任边界清晰”。真实响应只允许在客户书面授权、恢复演练和 `real-enforcement` gate 全部通过后受控开放。
- **SaaS GA**：不建议与 Private Deployment GA 同步承诺正式商用。SaaS 当前具备 Beta 商业化骨架，但仍缺正式 SLA 运营闭环、数据生命周期证明、跨租户静态扫描清零、状态页/值班/灰度/HA 实操证据、自动化合规证据中心和正式计费对账。

商业合同前的硬性结论：

| 能力 | Private Deployment GA 合同前 | SaaS GA 合同前 |
|---|---|---|
| SLA | 必须具备私有化运维 SLA、升级/故障响应口径；不承诺平台托管可用性赔付，除非另签托管服务 | 必须具备正式 SLA/SLO、状态页、值班、错误预算、赔付或免责口径 |
| 备份恢复 | 必须完成客户环境至少一次隔离恢复演练，记录 RTO/RPO | 必须完成平台级定期备份、恢复演练、租户级恢复影响边界和季度演练机制 |
| 审计证据 | 必须提供客户级证据包：部署、配置、迁移、审计哈希链、响应、备份恢复 | 必须支持按租户、时间、事件类型导出合规证据，平台管理员操作强审计 |
| 真实响应责任边界 | 必须写入合同/启用申请：默认 `DRY_RUN=true`；真实响应需客户授权、白名单、审批、TTL、回滚、复盘 | GA 默认不开放 SaaS 真实响应；如开放，必须有租户级 kill switch、provider 凭证隔离、审批委托和合同责任条款 |
| 数据保留和删除 | 必须明确客户本地数据保留、备份保留、日志归档和退出清理流程 | 必须实现租户级保留、归档、删除、导出、删除证明和备份残留说明 |
| License/计费策略 | 必须具备离线 License 或合同期授权、节点/用户/保留期/响应能力边界 | 必须具备 Plan/Subscription/Quota/UsageMeter、账单对账、套餐变更生效、超额策略和退款/停用规则 |

推荐排期：

- Private Deployment GA：**4-6 周**，以当前 Beta RC 有条件通过结果为基础做收敛。
- SaaS GA：**8-12 周**，在多租户隔离清零、SaaS 运维和数据生命周期完成后再进入正式商用。

## 2. 当前 RC 验收结论归纳

### 2.1 单企业私有化 Beta RC

结论：**有条件通过**。

已通过项：

- PostgreSQL 迁移与恢复库 schema 校验通过。
- Redis 服务、密码认证、Stream 状态检查可用。
- 模型目录和 manifest 就绪。
- `/healthz`、`/readyz`、`/metrics` 可用，Prometheus 风格指标存在。
- `verify_v1.py` 场景 1-9 PASS，E2E 场景 10 PASS。
- HTTP 健康端点压测 P95 约 59.55ms，错误率 0。
- PostgreSQL dump SHA256 校验和恢复库查询通过。
- 审计哈希链校验有效。
- 误封恢复相关测试通过。

阻塞/整改项：

- 当前 `.env` 仍有占位 PostgreSQL、占位 HTTPS Origin、DB 连接失败等 readiness failure，不能作为客户发布配置。
- Redis Stream consumer 的空流阻塞超时会污染共享 Redis client，导致 `/readyz` 在默认 autostart 下失败；生产必须修复或独立 client 隔离。
- Docker app 镜像未在目标空环境重新构建通过，需在企业 registry/mirror 可用环境复演。
- 压测只覆盖匿名健康与观测端点，缺认证业务 API 压测。
- `guardian_model_ready` 仍为 0，full-chain Guardian heartbeat 需复核。
- 真实抓包、真实封禁、iptables/云安全组解封、Nginx TLS/WSS 仍需客户授权环境实操。

### 2.2 SaaS Beta RC

结论：**Beta 骨架通过，GA 未就绪**。

已具备项：

- 多租户基础模型：Tenant、Organization、User、Membership、Role、APIKey。
- 核心业务表已引入 `tenant_id`，并有租户级查询 helper、租户 Stream key 和隔离测试。
- SaaS 控制面：租户创建/暂停、套餐、订阅、配额、License、用量查询、商业状态查询。
- 商业计量 MVP：Plan、Subscription、LicenseKey、Quota、UsageMeter；支持配额拒绝、告警、降级、只读策略。
- 运维可靠性文档：SLO、Prometheus 告警、Grafana Dashboard、值班手册和 HA 建议。
- 真实响应受控开放模型：审批、白名单、provider 配置、恢复演练、TTL guard 的数据模型和测试基础。
- 回归结果：`test_tenant_isolation_c1.py`、`test_commercial_metering_mvp.py`、`test_response_r4.py`、`test_response_approval_web.py`、`test_production_hardening.py` 共 73 项通过；`test_saas_control_plane.py`、`test_enterprise_control_plane.py`、`test_audit_log_baseline.py`、`test_observability_r5.py` 共 36 项通过。

GA 阻塞项：

- `scripts/tenant_query_scan.py web tests scripts` 仍发现真实业务代码中的租户直接访问风险：`web/app.py` 存在 `ResponseAction` direct `session.get`。测试和脚本中也存在多处未显式 tenant predicate，需要分类清理或标注豁免。
- SaaS SLO 还是 Beta 文档口径，缺真实多实例、HA、状态页、值班演练和错误预算执行记录。
- 数据保留/删除/导出尚未形成可验证的租户生命周期闭环。
- License/计费当前是 MVP，不等于正式账单、对账、支付、退款、停用和发票系统。
- SaaS 真实响应明确应后置，不能作为 SaaS GA 默认能力。

## 3. Private Deployment GA 路线

### 3.1 必须完成项

| 编号 | 必须完成项 | GA 口径 |
|---|---|---|
| PD-GA-01 | 客户化发布配置门禁 | 客户 `.env` 无占位值，`check_production_readiness.py` private-beta/GA gate 无 FAIL；`DRY_RUN=true` 为默认 |
| PD-GA-02 | Redis consumer readiness 修复 | consumer 使用独立 Redis client，空流长轮询超时不触发全局降级；默认 autostart 下 `/readyz` 通过 |
| PD-GA-03 | Docker 空环境部署复演 | 在目标 OS/registry/mirror 下完成 build、compose up、db upgrade、health/readyz/metrics |
| PD-GA-04 | 认证业务 API 压测 | 覆盖 `/api/alerts`、`/api/stats`、`/api/rules`、`/api/settings`、`/api/reports/export`，P95 和错误率达标 |
| PD-GA-05 | 备份恢复正式演练 | 客户环境完成 DB dump、配置、模型、审计日志备份，隔离恢复通过，记录 RTO/RPO |
| PD-GA-06 | 审计证据包 | 哈希链巡检有效，关键操作写入 `audit_events`，交付证据索引完整 |
| PD-GA-07 | 运维手册和 SLA | 明确 P0/P1/P2 响应目标、升级路径、维护窗口、版本升级、回滚和客户/厂商责任分工 |
| PD-GA-08 | 真实响应边界 | 默认不开放真实封禁；如开启，`--gate real-enforcement` 必须通过，审批/白名单/TTL/回滚/解封/复盘证据齐备 |
| PD-GA-09 | License 策略 | 支持私有化离线 License 或合同期授权：有效期、节点/用户/规则/保留期/真实响应能力开关 |
| PD-GA-10 | 客户退出与数据处理 | 明确停用、备份交付、日志归档、数据清理和删除证明流程 |

### 3.2 可后置项

- 企业 SSO/LDAP/OIDC：可作为首批 GA 后增购或企业增强包。
- 多节点 HA 私有化：可作为高级部署形态，首批 GA 可承诺单套部署加客户底座 HA。
- 多云 provider 全覆盖：首批只支持一个经客户验证的 provider；其他云厂商项目化适配。
- 模型漂移运营平台：保留模型 manifest 和版本审计，完整漂移看板后置。
- 自动化安装器：首批可以用标准化部署包、脚本和交付手册，后续再产品化安装器。

### 3.3 风险项

| 风险 | 影响 | 收敛动作 |
|---|---|---|
| 客户环境差异大 | 部署周期不可控 | 固化环境 intake、precheck、registry/mirror 要求和远程预检 |
| Redis consumer readiness 污染 | 服务被 LB 摘除或误判不可用 | 作为 GA 阻塞修复并加入回归 |
| 真实响应误封 | 客户生产事故 | 默认 `DRY_RUN=true`；真实响应作为单独启用包和合同附件 |
| 备份可用但恢复不可用 | 灾难恢复失败 | 每个客户至少一次隔离恢复演练，记录 RTO/RPO |
| 审计证据不完整 | 采购/复盘失败 | 交付证据索引强制化，审计导出和哈希校验纳入验收 |
| License 离线校验不清 | 商业授权失控 | LicenseKey 不保存明文，只保存 hash/prefix，授权范围写入合同 |

### 3.4 验收标准

Private Deployment GA 必须同时满足：

- `check_production_readiness.py` 对客户生产配置无 FAIL。
- Docker 空环境部署成功，`/healthz`、`/readyz`、`/metrics` 连续 7 天无持续失败。
- 全链路演练：Guardian/演练流量 -> Redis Stream -> Web consumer -> DB -> WebSocket -> 查询 -> 报表。
- Web 重启后历史告警、规则、IOC、响应记录、审计记录不丢失。
- 认证 API 压测：核心 API P95 < 300ms，错误率 < 1%；健康/观测端点 P95 < 300ms。
- 备份恢复：隔离恢复成功，RTO/RPO 被客户签收。
- 审计：哈希链有效，审计事件可按时间和事件类型导出。
- 真实响应如未开启：验收单明确“未开启真实封禁，仅 dry-run”。如开启：`real-enforcement` gate 通过且演练记录齐全。
- 签署交付边界、SLA、数据处理和 License 附件。

### 3.5 建议周期

建议 **4-6 周**：

- 第 1 周：修复 GA 阻塞、客户化 env 模板、Docker 空环境复演。
- 第 2 周：认证 API 压测、Redis/full-chain/metrics 回归、交付包冻结。
- 第 3-4 周：首个客户环境试运行、备份恢复、审计证据和运维演练。
- 第 5-6 周：遗留问题关闭、合同附件定稿、GA tag 和发布说明。

## 4. SaaS GA 路线

### 4.1 必须完成项

| 编号 | 必须完成项 | GA 口径 |
|---|---|---|
| SAAS-GA-01 | 租户隔离清零 | 业务代码通过 tenant 静态扫描；直接 `session.get` 必须替换为 tenant helper 或有严格豁免 |
| SAAS-GA-02 | SaaS HA 实操 | 至少 2 个 Web/API 实例、LB `/readyz` 摘除、Redis/PostgreSQL HA、Socket.IO 跨实例策略验证 |
| SAAS-GA-03 | 正式 SLO/SLA | 99.5% 或更高月可用目标、API P95、Stream lag、审计巡检、通知失败率、错误预算和状态页 |
| SAAS-GA-04 | 值班与事故流程 | SEV1/SEV2 演练，15/30 分钟响应目标，复盘模板和客户通知流程 |
| SAAS-GA-05 | 数据生命周期 | 租户级数据保留、归档、导出、删除、删除证明；备份残留和法定保留说明 |
| SAAS-GA-06 | 合规证据中心 | 按租户、时间、事件类型导出审计、配置、响应、登录、管理员操作证据 |
| SAAS-GA-07 | License/计费生产化 | Plan/Subscription/Quota/UsageMeter 与账单/对账/停用/超额/套餐变更联动 |
| SAAS-GA-08 | 平台管理员边界 | 平台管理员所有跨租户操作强审计；业务写入必须显式目标 tenant |
| SAAS-GA-09 | 租户级安全控制 | API Key scope、MFA/SSO 至少一个企业级登录方案、租户暂停/只读/删除状态机 |
| SAAS-GA-10 | SaaS 真实响应默认关闭 | GA 合同和产品 UI 明确默认不提供真实封禁；后续单租户白名单灰度另签 |

### 4.2 可后置项

- 在线支付、发票、税务系统：可先采用销售合同 + 手工对账 + License/Subscription 后台绑定。
- 自助注册全自动 KYC：可先销售创建租户，后续开放自助开通。
- 多区域容灾：SaaS GA 可先单区域 HA + 备份恢复，跨区域 DR 作为企业版增强。
- 租户级模型定制训练：先共享模型版本 + 租户阈值，定制模型后置。
- SaaS 真实响应：默认后置到单独 RC，不进入 GA 主线。

### 4.3 风险项

| 风险 | 影响 | 收敛动作 |
|---|---|---|
| 租户隔离遗漏 | SaaS 重大安全事故 | 静态扫描清零、越权测试矩阵、业务代码 review gate |
| 数据删除不可证明 | 合规和采购风险 | 建数据生命周期任务、删除证明和备份残留说明 |
| 计费只是 MVP | 收入确认和客户争议 | 与合同 SKU、账单周期、超额策略、停用策略对齐 |
| SLA 无实操证据 | 合同承诺无法兑现 | 值班演练、状态页、错误预算、HA 和恢复演练先行 |
| 平台管理员越权 | 内部操作事故 | 平台管理员操作强审计、双人审批或 break-glass 流程 |
| SaaS 真实响应误操作 | 跨租户高危事故 | 默认关闭，租户级 kill switch 和 provider vault 后置 |

### 4.4 验收标准

SaaS GA 必须同时满足：

- 静态租户扫描对生产代码无未豁免 finding。
- A/B 租户数据、规则、IOC、审计、报表、响应动作互不可见。
- SaaS 控制面可创建、暂停、恢复租户；套餐/配额/License 变更即时生效。
- 用量可按租户、指标、周期查询和导出，并能对账。
- 核心 SLO 可观测：可用性、API P95、Stream lag、通知失败率、响应失败率、审计巡检。
- 至少完成一次 SEV1 演练、一次备份恢复演练、一次租户数据导出/删除演练。
- 合规证据可按租户和时间范围导出。
- 数据保留/删除策略在产品、合同和后台任务中一致。
- SaaS 合同明确责任边界、数据处理协议、SLA、计费、停用、删除和真实响应限制。

### 4.5 建议周期

建议 **8-12 周**：

- 第 1-2 周：租户隔离清零、静态扫描 gate、越权测试扩充。
- 第 3-4 周：SaaS HA、状态页、SLO Dashboard、告警和值班演练。
- 第 5-6 周：数据生命周期、证据导出、删除证明和备份恢复演练。
- 第 7-8 周：计费/License 合同口径、对账导出、超额和停用状态机。
- 第 9-12 周：安全评审、客户 Beta 扩大试运行、合同附件定稿、GA 发布。

## 5. 商业合同前必须具备能力定义

### 5.1 SLA

Private Deployment GA：

- 合同中写明客户负责底层主机、网络、数据库、Redis、域名证书和防火墙；厂商负责应用配置、升级指导、缺陷修复和约定支持响应。
- 给出 P0/P1/P2 响应目标、升级联系人、维护窗口和免责项。

SaaS GA：

- 提供平台可用性 SLA、API 延迟 SLO、状态页、故障通知、赔付或服务抵扣规则。
- 错误预算触发发布冻结和稳定性优先级调整。

### 5.2 备份恢复

Private Deployment GA：

- 每次上线前备份 DB、`.env` SHA256、模型 SHA256、审计日志、镜像 tag、compose config。
- 客户环境至少一次隔离恢复演练通过。

SaaS GA：

- 平台级自动备份、恢复演练、租户数据恢复边界、备份保留周期、加密和访问审计。
- 说明删除后备份残留的最长清除周期。

### 5.3 审计证据

Private Deployment GA：

- 交付证据索引必须包含配置安全、迁移、健康检查、模型、Redis、备份恢复、审计哈希链、响应演练。

SaaS GA：

- 租户级证据中心，支持导出登录、API Key、管理员操作、配置变更、告警状态、响应动作、License/计费变更。

### 5.4 真实响应责任边界

Private Deployment GA：

- 默认 `DRY_RUN=true`。
- `DRY_RUN=false` 只允许在客户签署真实响应启用申请、白名单确认、最小权限 provider、恢复演练和 `real-enforcement` gate 全部通过后开启。
- 合同写明系统建议、客户授权、provider 执行、误封恢复责任和 SLA。

SaaS GA：

- 默认不承诺真实封禁/EDR 隔离。
- 若销售必须承诺，应拆成单独受控开放附件，不进入 SaaS GA 默认合同。

### 5.5 数据保留和删除

Private Deployment GA：

- 由客户持有环境时，合同需写明本地 DB、日志、备份、模型、配置的保留和退出清理责任。
- 厂商若接触交付证据，需要脱敏和归档周期。

SaaS GA：

- 产品实现租户级 retention policy、归档、删除 job、删除审计、导出和删除证明。
- 与套餐中的 `retention_days` 一致，不能只存在于配额字段。

### 5.6 License/计费策略

Private Deployment GA：

- 采用离线 LicenseKey 或销售合同授权，至少限制：有效期、用户数、规则数、IOC 数、数据保留期、响应能力、节点/环境。
- License 状态变更写审计。

SaaS GA：

- Plan/Subscription/Quota/UsageMeter 与商业 SKU 对齐。
- 用量按周期结算，可导出对账；超额策略明确为拒绝、只读、降级或告警。
- 套餐升级/降级即时影响权限和配额，历史账单可追溯。

## 6. 研发任务清单

### 6.1 P0：GA 阻塞

| 任务 | 归属线 | 说明 |
|---|---|---|
| 修复 Redis consumer readiness 污染 | Private/SaaS | 独立 Redis client 或超时不降级；默认 autostart `/readyz` 通过 |
| 清理生产代码租户扫描 finding | SaaS | 替换 `web/app.py` 中 tenant-scoped `session.get`；测试/脚本分类豁免 |
| 增加 SaaS GA 静态扫描 CI gate | SaaS | 对 `web/`、`src/`、`scripts/` 生产路径启用 fail-on-finding |
| 认证业务 API 压测脚本和报告 | Private/SaaS | 支持测试账号/JWT，输出 P95、P99、错误率、慢接口 |
| 数据生命周期任务 | SaaS | retention_days 真正驱动归档/删除/导出/删除证明 |
| 合规证据导出 API | Private/SaaS | 审计、配置、响应、备份恢复、License/计费变更按范围导出 |
| 备份恢复自动化脚本 | Private/SaaS | dump、SHA256、restore、schema check、RTO/RPO 报告 |
| License GA 策略 | Private/SaaS | License 生效、失效、续期、覆盖 plan、审计和合同 SKU 映射 |
| SLA/SLO Dashboard 实装 | SaaS | Grafana JSON、Prometheus rules、blackbox probe、状态页 |

### 6.2 P1：GA 质量

| 任务 | 归属线 | 说明 |
|---|---|---|
| Docker 空环境和企业 registry 复演 | Private | 固化镜像源、构建日志和离线交付证据 |
| full-chain Guardian heartbeat 修复/确认 | Private/SaaS | `guardian_model_ready >= 1` 和 metrics heartbeat 在真实链路更新 |
| Nginx TLS/WSS 客户环境验收 | Private | TLS、CORS、Socket.IO、反代头、安全 header |
| 多实例 Socket.IO 策略 | SaaS | Redis message queue 或粘性会话边界明确 |
| 平台管理员 break-glass 审计 | SaaS | 跨租户操作审批、原因、时限、复盘 |
| 真实响应 provider 首个生产实现 | Private | 选择一个云安全组或 iptables 路径，幂等、tag、查询、删除校验 |

### 6.3 P2：可后置增强

| 任务 | 归属线 | 说明 |
|---|---|---|
| SSO/OIDC/MFA | SaaS/Private | 企业增强能力 |
| 自动化安装器 | Private | 替代手工部署文档 |
| 多区域 DR | SaaS | 跨区域恢复和演练 |
| 模型质量运营看板 | SaaS/Private | 漂移、误报率、回滚 |
| 自助注册和在线支付 | SaaS | 销售合同阶段后置 |

## 7. GA 放行建议

1. 先放行 **Private Deployment GA**，但只面向明确接受边界的首批客户；默认 dry-run，真实响应单独签署和验收。
2. SaaS 继续作为 **Beta RC 扩大试运行**，不得承诺正式 SaaS SLA、默认真实响应或完整数据删除证明。
3. SaaS GA 的红线是：租户隔离扫描清零、数据生命周期可证明、SLO/值班/HA 有实操证据、License/计费可对账。
4. 所有商业合同附件必须先由产品、研发、安全、交付、法务共同确认，避免销售承诺超过当前技术和运维边界。

