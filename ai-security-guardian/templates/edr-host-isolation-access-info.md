# EDR/主机隔离接入信息收集表

适用范围：收集客户 EDR/主机隔离 provider 接入信息和恢复责任边界。C6 默认不启用 SaaS 真实主机隔离，私有化客户强要求时按本表受控开放。

## 强制前置声明

- 默认运行基线必须为 `DRY_RUN=true`，`RESPONSE_HOST_ISOLATION` 默认必须为 `none`。
- EDR 真实隔离需要单独审批，且审批等级高于 IP 封禁。
- 未完成主机释放/恢复演练不得启用真实隔离。
- 出现误隔离时，优先切回 `DRY_RUN=true` 并撤销 `REAL_ENFORCEMENT_GATE`，再由客户 EDR 管理员释放主机。

## 基础信息

| 项目 | 内容 |
|------|------|
| 客户名称 |  |
| EDR 产品 | Microsoft Defender / CrowdStrike / SentinelOne / Carbon Black / 其他 |
| Tenant / 管理域 |  |
| API Endpoint |  |
| 凭证引用 | `secret://...`，禁止填写明文 token |
| 环境 | 生产 / 预生产 / 演练 |
| 客户 EDR 管理员 |  |
| 客户安全负责人 |  |

## Provider 配置

| 配置项 | 值 | 备注 |
|--------|----|------|
| `RESPONSE_HOST_ISOLATION` |  | `none` / `edr_defender` / `edr_crowdstrike` / `edr_sentinelone` / 其他 |
| `RESPONSE_HOST_ISOLATION_TENANT_ID` |  |  |
| `RESPONSE_HOST_ISOLATION_CREDENTIAL_REF` |  | 只填凭证引用 |
| `RESPONSE_HOST_ISOLATION_ENDPOINT` |  |  |
| `RESPONSE_HOST_ISOLATION_PROVIDER_TEST_PASSED` |  | `true` 前必须有证据 |
| `RESPONSE_HOST_ISOLATION_RECOVERY_DRILL_PASSED` |  | `true` 前必须有演练报告 |

## 允许与禁止主机范围

| 主机组/资产组 | Host ID 来源 | 是否允许隔离 | 业务用途 | 负责人 | 备注 |
|---------------|--------------|--------------|----------|--------|------|
|  |  | 是 / 否 |  |  |  |

禁止隔离对象确认：

| 对象 | 已确认保护 | 说明 |
|------|------------|------|
| EDR 管控节点 | 是 / 否 |  |
| 域控 / 身份系统 | 是 / 否 |  |
| 堡垒机 / 跳板机 | 是 / 否 |  |
| 日志平台 / SIEM | 是 / 否 |  |
| 备份节点 | 是 / 否 |  |
| 生产核心数据库 | 是 / 否 |  |

## 审批与恢复要求

- 主机隔离仅允许 `critical` 且完成双人审批或交付确认。
- IP 不得直接等价为主机，必须解析到客户确认的 `host_id`。
- 隔离动作必须有自动释放时间或人工释放工单。
- 释放失败必须升级到客户 EDR 管理员和值班负责人。

| 验证项 | 期望结果 | 实际结果 | 证据 |
|--------|----------|----------|------|
| dry-run 隔离计划 | 不调用真实 EDR API |  |  |
| provider validate | provider test passed |  |  |
| 测试主机隔离 | 仅在演练窗口执行 |  |  |
| 测试主机释放 | 主机网络和 EDR 状态恢复 |  |  |
| 审计完整性 | 记录申请、审批、目标、TTL、释放证据 |  |  |

## 签署

| 角色 | 姓名 | 结论 | 签名 | 时间 |
|------|------|------|------|------|
| 客户 EDR 管理员 |  | 同意 / 不同意 |  |  |
| 客户安全负责人 |  | 同意 / 不同意 |  |  |
| 客户业务负责人 |  | 同意 / 不同意 |  |  |
| 交付负责人 |  | 同意 / 不同意 |  |  |

