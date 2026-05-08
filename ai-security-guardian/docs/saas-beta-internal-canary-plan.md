# AI-Security-Guardian SaaS Beta 内部灰度计划

适用范围：SaaS Beta 内部灰度，不面向真实客户  
适用环境：内部 SaaS staging / canary 环境，使用模拟租户、模拟组织、模拟用户、模拟 License 和 dry-run 响应  
默认安全边界：不接入真实客户资产，不导入真实客户日志，不执行真实封禁、云安全组变更或 EDR 主机隔离  
关联能力：多租户隔离、套餐配额、License、用量计量、SaaS 控制面、审计证据、运维 SLO

## 1. 目标与非目标

本次内部灰度目标是在进入真实客户 SaaS Beta 之前，用内部模拟租户验证 AI-Security-Guardian 的 SaaS 基础能力是否形成最小闭环：租户创建、租户状态、套餐订阅、License 覆盖、配额生效、用量计量、越权防护、审计留痕、运维观测和失败退出。

本次灰度不验证商业付费闭环，不承诺正式 SLA，不引入真实客户数据，不验证公网规模化多区域部署，不验证真实响应动作执行。所有告警、IOC、规则、API Key、License、组织和用户均使用内部模拟数据。

## 2. 当前项目能力基线

灰度设计基于当前项目中已经出现的 SaaS 能力：

| 能力 | 当前项目依据 | 灰度验证重点 |
|---|---|---|
| 租户目录 | `Tenant`、`Organization`、`User`、`Membership`、`Role`、`APIKey` | 租户生命周期、成员授权、API Key 访问边界 |
| 多租户数据 | `alerts`、`rules`、`iocs`、`settings`、`banned_ips`、`audit_events` 等表已带 `tenant_id` | A/B/C 租户读写隔离、主键猜测、payload 伪造 |
| 套餐与配额 | `Plan`、`Subscription`、`Quota`、`web/billing.py` 默认指标 | 用户、告警、规则、IOC、API 调用、通知、响应动作、保留期限制 |
| License | `LicenseKey` 可覆盖订阅限制 | License 创建、启用、禁用、续期、过期和覆盖优先级 |
| 用量计量 | `UsageMeter`，支持 `current` 和 `YYYY-MM` bucket | 写操作计数、API 调用计数、跨周期查询和超额策略 |
| SaaS 控制面 | `/api/admin/saas/*` 与 `saas_admin` 页面 | 平台管理员管理租户、配额、License、用量，租户管理员不可访问 |
| 审计 | `audit_events`、审计哈希链、审计巡检指标 | SaaS 操作、用量告警、越权尝试和响应动作证据 |
| 运维 SLO | `/healthz`、`/readyz`、`/metrics`、Phase C5 SLO | API P95、5xx、Stream lag、审计巡检、模型就绪 |

## 3. 灰度原则

- 只使用内部模拟租户，租户命名必须带 `sim_` 或 `internal_` 前缀。
- 不允许导入真实客户日志、IP、域名、账号、邮件、License 合同号或截图。
- 所有响应动作保持 `DRY_RUN=true`；如环境中存在真实 provider 配置，灰度前必须禁用。
- 平台管理员和租户管理员分离；租户管理员不得访问 `/api/admin/saas/*`。
- 所有灰度操作必须保留审计证据，证据包不得包含明文密码、JWT、API Key、数据库连接串、Redis 密码或 License 明文。
- 任何跨租户泄露、未授权真实响应、审计完整性失败都按退出条件处理，不做继续观察。

## 4. 灰度周期

建议周期为 14 个自然日，分四个阶段执行。

| 阶段 | 时间 | 目标 | 退出口径 |
|---|---:|---|---|
| P0 准备 | D-2 到 D0 | 环境、数据、账号、套餐、License、监控和证据模板准备 | readiness 无 fatal，模拟租户可创建，基线测试通过 |
| P1 小流量灰度 | D1 到 D3 | 2 个模拟租户，低频 API 与控制台操作 | 无 P0/P1，隔离和计量主路径通过 |
| P2 扩大灰度 | D4 到 D10 | 4 到 5 个模拟租户，覆盖套餐差异、超额策略和后台任务 | 连续 5 天 SLO 达标，无跨租户问题 |
| P3 收口评审 | D11 到 D14 | 故障演练、证据归档、缺陷收敛和放行决策 | 输出通过、有条件通过或不通过结论 |

若 P1 发生阻断问题，灰度回退到 P0，修复后重新开始 D1 计数。若 P2 发生 P1 级问题但不涉及隔离、安全和审计，可暂停扩大、保留已接入租户继续观察。

## 5. 测试租户设计

内部灰度至少创建 5 个模拟租户，每个租户覆盖不同商业和运维状态。

| 租户 ID | 模拟类型 | 套餐 / License | 配额特征 | 场景重点 |
|---|---|---|---|---|
| `sim_free_a` | 免费/试用小租户 | `mvp-default` 或低配计划 | 低规则、低 IOC、低 API 调用 | 配额临界、超额拒绝、只读降级 |
| `sim_team_b` | 中型团队租户 | 标准计划 | 中等规则、告警、通知 | 正常运营路径、用量增长、审计查询 |
| `sim_enterprise_c` | 企业租户 | 高配计划 + active License | License 覆盖配额 | License 启用、续期、禁用后回落 |
| `sim_suspended_d` | 暂停租户 | 任意计划，tenant status = suspended | 不允许业务访问 | JWT/API Key 访问拒绝和审计 |
| `sim_overage_e` | 超额租户 | 自定义 Quota | `alert`、`read_only`、`degrade`、`reject` 策略 | 超额策略、告警事件、写入阻断 |

每个租户至少准备：

- 1 个组织、2 个用户、1 个 tenant admin、1 个 viewer 或 analyst。
- 1 个 API Key，过期 API Key 另建一条负向样本。
- 3 条规则、3 条 IOC、5 条模拟告警。
- 至少 1 条设置项、1 条 dry-run 响应动作、1 条审计事件查询样本。

## 6. 灰度场景

### 6.1 多租户隔离

| 场景 | 操作 | 通过标准 |
|---|---|---|
| 同租户正向访问 | `sim_team_b` 用户查询本租户 alerts/rules/iocs/settings | 返回本租户数据，审计 tenant 一致 |
| 跨租户读 | `sim_free_a` token 查询 `sim_team_b` alert/rule/ioc id | 返回 403 或 404，不泄露目标内容 |
| 跨租户写 | payload 中伪造 `tenant_id=sim_enterprise_c` 创建规则或 IOC | 拒绝或覆盖为当前 tenant，不写入目标租户 |
| 主键猜测 | 使用其他租户已有资源 id 执行 update/delete/resolve | 拒绝，数据库最终状态不变 |
| API Key 隔离 | `sim_team_b` API Key 访问 `sim_enterprise_c` 资源 | 拒绝并记录访问失败审计 |
| 暂停租户 | `sim_suspended_d` 的 JWT/API Key 访问 `/api/stats` 等业务 API | 返回 `tenant_inactive`，写入 `tenant.access_denied` |
| 后台任务 | 手工构造 tenant 不一致的告警/响应任务 | 不入库或进入隔离错误路径，不污染其他租户 |
| Redis Stream | key 与 body 的 `tenant_id` 不一致 | 拒绝处理，保留错误证据 |

最低验收：所有负向场景必须断言 HTTP 状态、审计事件和数据库最终状态，不能只看接口返回。

### 6.2 套餐配额

覆盖指标：`users`、`alerts`、`rules`、`iocs`、`api_calls`、`notifications`、`response_actions`、`retention_days`。

| 场景 | 操作 | 通过标准 |
|---|---|---|
| 默认套餐 | 新建租户不指定 License | 生效 `mvp-default` 默认限制 |
| 手工覆盖 | 平台管理员修改单租户 `rules` 配额 | 只影响目标租户，写入 `saas.quota.updated` |
| 配额边界 | 创建资源到 limit 正好等于上限 | 上限内允许，下一次写入触发超额策略 |
| warning 阈值 | 设置 80% 或自定义阈值后增长用量 | 写入 `usage_quota.warning` 审计 |
| reject | 超额后继续写入 | 返回 `quota_exceeded`，业务数据不新增 |
| read_only | API 调用超额后读请求继续、写请求阻断 | 读成功，写返回 403 |
| degrade | 通知或响应动作超额 | 返回降级决策，不执行高成本动作 |
| alert | 超额后允许继续 | 业务允许，写入 `usage_quota.overage` |

### 6.3 License

| 场景 | 操作 | 通过标准 |
|---|---|---|
| 创建 License | 给 `sim_enterprise_c` 创建 active License，limits 覆盖 `rules`/`api_calls` | 返回 License 前缀，明文只展示一次，审计已写入 |
| 覆盖优先级 | License limits 高于套餐 limits | `effective_limits` 使用 License 覆盖值 |
| 禁用 License | 将 License status 改为 disabled | 配额回落到套餐或手工 Quota，审计已写入 |
| 续期 License | 更新 `expires_at` 到未来日期 | 状态 active，过期时间可查询 |
| 过期 License | 构造过期 License | 不再覆盖配额 |
| 错租户 License | 尝试用 A 租户 License 影响 B 租户 | 拒绝或无效，不能跨租户生效 |

### 6.4 用量计量

| 场景 | 操作 | 通过标准 |
|---|---|---|
| API 调用计量 | 调用 `/api/stats`、列表查询、控制面查询 | `api_calls` 计数递增，period 包含 `current` 和当月 bucket |
| 资源写入计量 | 创建 rule、IOC、alert、response action | 对应 metric 递增一次，失败写入不计成功用量 |
| 用量查询 | `/api/admin/saas/tenants/{tenant_id}/usage?metric=rules&period=YYYY-MM` | 只返回目标租户目标周期数据 |
| 跨租户隔离 | `sim_free_a` 与 `sim_team_b` 使用同名 rule/IOC | 用量分别计入各自 tenant |
| 计量审计 | 用量变化和超额事件 | 有 `usage_meter.changed`、warning、overage 等审计 |

### 6.5 SaaS 控制面

| 场景 | 操作 | 通过标准 |
|---|---|---|
| 平台管理员创建租户 | POST `/api/admin/saas/tenants` | 201，创建 tenant、默认组织/订阅/配额快照 |
| 平台管理员暂停租户 | PATCH tenant status = suspended | 业务访问被拒，审计已写 |
| 平台管理员管理配额 | PUT tenant quota | 只影响目标租户 |
| 平台管理员管理 License | create/update/status | 全操作审计可查 |
| 租户管理员访问控制面 | tenant admin 请求 `/api/admin/saas/tenants` | 403 |
| 控制台页面 | `saas_admin.html` 列表、详情、用量、License | 数据不串租户，错误态清晰 |

### 6.6 审计证据

灰度证据必须覆盖以下事件：

- `saas.tenant.created`、`saas.tenant.updated`
- `saas.quota.updated`
- `saas.license.created`、`saas.license.updated`、`saas.license.status_updated`
- `usage_meter.changed`
- `usage_quota.warning`、`usage_quota.overage`
- `tenant.access_denied`
- 告警状态流转、规则/IOC 变更、dry-run 响应动作
- 审计哈希链巡检结果

证据包建议目录：

```text
reports/saas-beta-internal-canary/YYYYMMDD/
  00-summary.md
  01-readiness/
  02-tenants/
  03-quota-license-usage/
  04-isolation-negative-tests/
  05-audit/
  06-slo/
  07-incidents/
```

证据脱敏要求：不保存明文 JWT、API Key、License 全量 key、数据库 URL、Redis 密码、管理员密码哈希和 `.env` 原文。

### 6.7 运维 SLO

内部灰度使用 Beta SLO，不承诺正式 SLA。默认目标：

| 指标 | 目标 | 失败口径 |
|---|---|---|
| Web/API 可用性 | 灰度期可用性 >= 99.5% | 任意连续 30 分钟不可用进入 P1 |
| API P95 | `/api/*` P95 < 300ms | 连续 10 分钟超标进入 P2，伴随 5xx 进入 P1 |
| API 5xx | 5 分钟窗口 < 2% | 连续 5 分钟 >= 2% 进入 P1 |
| 告警消费延迟 | P95 < 5s，Max < 30s | Max > 30s 持续 5 分钟进入 P2 |
| Redis Stream lag | lag < 1000，pending < 100 | 持续 10 分钟超标进入 P2 |
| 审计完整性 | `audit_integrity_valid == 1`，24h 内无失败巡检 | 任意失败进入 P0 |
| 模型就绪 | `guardian_model_ready >= 1` | 连续 3 分钟不 ready 进入 P1 |
| 控制面错误 | SaaS admin 关键操作成功率 >= 99% | 创建/暂停/配额/License 任一主路径失败进入 P1 |

## 7. 指标与看板

灰度期间每天固定输出一次日报，包含：

| 类别 | 指标 |
|---|---|
| 租户 | active/suspended 租户数、租户创建/暂停次数、租户访问拒绝次数 |
| 隔离 | 跨租户负向用例通过率、越权审计数、数据库最终状态异常数 |
| 商业化 | 各 tenant 套餐、License 状态、配额使用率、warning/overage 次数 |
| 计量 | `api_calls`、`rules`、`iocs`、`alerts`、`notifications`、`response_actions` 当日增量 |
| 控制面 | `/api/admin/saas/*` 成功率、P95、5xx、403/404 分布 |
| 运维 | `/healthz`、`/readyz`、`/metrics`、API P95、5xx、Redis lag、模型 ready |
| 审计 | 审计事件数、审计巡检结果、敏感信息扫描结果 |
| 缺陷 | P0/P1/P2 数量、打开时长、规避方案、是否阻断扩大 |

## 8. 失败退出条件

### 8.1 必须立即停止灰度

出现以下任一情况，立即暂停所有新增租户和新增流量，保全证据并进入复盘：

- 任何接口、任务、报表、导出或控制台页面出现跨租户数据泄露。
- 租户 A 的操作修改了租户 B 的数据、配额、License、审计、响应动作或设置。
- 未经批准执行真实封禁、云安全组变更、EDR 隔离或外部通知。
- 审计哈希链失败、关键 SaaS 操作无审计，或审计日志出现不可解释缺口。
- 证据包、日志或页面泄露明文凭据、JWT、API Key、License 全量 key、数据库 URL 或 Redis 密码。
- 数据库迁移、回滚或备份恢复失败导致 SaaS 控制面不可恢复。

### 8.2 必须回退到上一阶段

出现以下任一情况，停止扩大灰度，回退到上一阶段观察：

- `/api/admin/saas/*` 主路径失败率 >= 1%，且 1 个工作日内未修复。
- `/readyz` 连续失败超过 10 分钟，但未造成数据或审计风险。
- Redis lag/pending 持续增长，影响告警展示但可通过重启或扩容恢复。
- API P95 连续 2 个观察窗口超标，且无法确认是压测行为导致。
- License 覆盖、Quota materialize 或 UsageMeter 计量存在非安全类一致性问题。

### 8.3 判定灰度不通过

14 天结束时满足以下任一条件，结论为不通过：

- P0 未关闭。
- P1 未关闭且无明确规避方案。
- 多租户隔离负向测试通过率低于 100%。
- 套餐配额、License、用量计量任一主路径不可用。
- SaaS 控制面无法完成租户创建、暂停、配额修改、License 管理和用量查询。
- 审计证据不完整，无法复盘关键操作。
- 运维 SLO 连续 5 天未达标，且没有容量或架构改进计划。

## 9. 放行标准

灰度结论分三类：

| 结论 | 标准 | 后续动作 |
|---|---|---|
| 通过 | P0/P1 全关闭；隔离负向 100% 通过；商业化主路径通过；SLO 连续 5 天达标；证据完整 | 可进入更大内部 Beta 或真实客户前安全评审 |
| 有条件通过 | 无 P0；P1 有已验证规避；P2/P3 有排期；核心链路可用 | 限定能力进入下一阶段，冻结未达标能力 |
| 不通过 | 存在隔离、安全、审计或控制面阻断问题 | 暂停 SaaS Beta，对应模块整改后重新灰度 |

## 10. 每日执行清单

每天固定执行：

1. 检查 `/healthz`、`/readyz`、`/metrics`。
2. 查询 SaaS 控制面租户列表、目标租户用量和 License 状态。
3. 执行 1 组跨租户读写负向用例。
4. 检查 `UsageMeter` 当日增量和 Quota warning/overage 审计。
5. 检查 Redis Stream lag/pending 和告警消费延迟。
6. 检查审计完整性巡检结果。
7. 扫描当日证据包是否包含敏感信息。
8. 更新缺陷列表和是否允许继续扩大灰度的结论。

## 11. 灰度结束交付物

- `00-summary.md`：灰度结论、范围、周期、租户、关键指标、阻断项。
- 租户清单：模拟租户、套餐、License、状态、配额。
- 场景执行记录：多租户隔离、套餐配额、License、用量计量、控制面、审计、SLO。
- 指标报告：API P95、5xx、Redis lag、审计巡检、模型 ready、控制面成功率。
- 缺陷清单：P0/P1/P2/P3、根因、修复状态、规避方案。
- 退出或放行建议：是否进入真实客户前安全评审，哪些能力必须冻结。

