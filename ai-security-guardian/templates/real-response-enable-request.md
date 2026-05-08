# 真实响应启用申请表

适用范围：AI-Security-Guardian Phase C6 私有化客户侧真实响应受控开放。该申请表仅用于申请启用真实响应能力，不代表审批通过。

## 强制前置声明

- 默认运行基线必须为 `DRY_RUN=true`。
- 真实响应必须单独审批，且审批只授权本次申请范围内的动作。
- 未完成并通过恢复演练，不得启用 `DRY_RUN=false`。
- 出现误封时，第一处置动作是切回 `DRY_RUN=true`，并撤销或置空 `REAL_ENFORCEMENT_GATE`。

## 申请信息

| 项目 | 内容 |
|------|------|
| 客户名称 |  |
| 环境 | 生产 / 预生产 / 演练 |
| 申请单号 |  |
| 申请人 |  |
| 申请时间 |  |
| 计划启用窗口 |  |
| 计划关闭或复核时间 |  |
| 交付负责人 |  |
| 客户安全负责人 |  |
| 客户网络/云负责人 |  |
| 客户 EDR 负责人 |  |

## 启用范围

| 响应动作 | 是否申请 | Provider | 目标范围 | 默认 TTL | 最大 TTL | 备注 |
|----------|----------|----------|----------|----------|----------|------|
| IP 临时封禁 |  | iptables / 云安全组 |  | high 1 小时，critical 24 小时 |  |  |
| 云安全组 deny |  | AWS / 阿里云 / 腾讯云 / 华为云 / 其他 |  |  |  |  |
| EDR 主机隔离 |  | Defender / CrowdStrike / SentinelOne / 其他 |  | 必填释放时间 |  | 仅 critical 和双人审批 |

## 明确不启用范围

| 资产或网段 | 类型 | 不启用原因 | 保护方式 |
|------------|------|------------|----------|
|  | 核心业务网段 / 办公出口 / VPN / LB / DNS / 监控 / 堡垒机 / EDR 管控节点 |  | 白名单 / provider 保护 |

## Gate 确认

| Gate | 必填证据 | 状态 | 签署人 | 时间 |
|------|----------|------|--------|------|
| 产品 Gate | 风险与责任边界、响应范围、TTL、SLA | 未通过 / 通过 |  |  |
| 技术 Gate | `check_production_readiness.py --gate real-enforcement` 输出、provider 测试、调度测试 | 未通过 / 通过 |  |  |
| 安全 Gate | 白名单、审批矩阵、最小权限凭证、审计验证、误封恢复演练 | 未通过 / 通过 |  |  |
| 交付 Gate | dry-run 演示、真实小流量演示、恢复演示、值班联系人 | 未通过 / 通过 |  |  |

## Real-Enforcement 准入证据清单

`DRY_RUN=false` 只允许在以下全部通过后于启用窗口内设置。任一项缺失时保持 `DRY_RUN=true`。

| 类别 | 必须满足 | 证据位置 |
|------|----------|----------|
| Runtime marker | `REAL_ENFORCEMENT_GATE=real-enforcement` | 环境变量变更单 |
| 人工审批 | `REAL_ENFORCEMENT_APPROVAL_REQUIRED=true` | 审批矩阵、双人审批记录 |
| 审计验证 | `REAL_ENFORCEMENT_AUDIT_VERIFIED=true` | `audit_events`、安全日志、哈希链抽检记录 |
| 回滚就绪 | `REAL_ENFORCEMENT_ROLLBACK_READY=true` | 回滚演练截图或命令记录 |
| 解封就绪 | `REAL_ENFORCEMENT_UNBLOCK_READY=true` | 手动解封和定时解封验收记录 |
| 复盘要求 | `REAL_ENFORCEMENT_REVIEW_REQUIRED=true` | post-response review 模板和责任人 |
| 业务白名单 | `RESPONSE_BUSINESS_IP_WHITELIST` 含有效 IPv4/CIDR，或 `response_whitelist_entries` 有 active 的 business/private/control_plane/office/monitoring 记录 | 环境变量或 DB 截图 |
| Provider 验证 | `response_provider_configs` 有 active provider，且 `last_validated_at` 非空、`last_validation_result.ok=true` | provider test 输出和 DB 记录 |
| 恢复演练 | `response_drills` 有 passed 的 `real_ban_unblock`、`provider_rollback` 或 `misblock_recovery`，且 `ended_at` 非空 | 演练报告和 DB 记录 |

## 环境变量目标状态

| 变量 | 当前值 | 申请启用窗口目标值 | 回退值 | 备注 |
|------|--------|--------------------|--------|------|
| `DRY_RUN` | `true` | `false` | `true` | 非启用窗口必须保持 `true` |
| `REAL_ENFORCEMENT_GATE` | 空 | `real-enforcement` | 空 | 误封时立即撤销 |
| `REAL_ENFORCEMENT_APPROVAL_REQUIRED` |  | `true` |  |  |
| `REAL_ENFORCEMENT_AUDIT_VERIFIED` |  | `true` |  |  |
| `REAL_ENFORCEMENT_ROLLBACK_READY` |  | `true` |  |  |
| `REAL_ENFORCEMENT_UNBLOCK_READY` |  | `true` |  |  |
| `REAL_ENFORCEMENT_REVIEW_REQUIRED` |  | `true` |  |  |

## 审批记录

| 角色 | 审批结论 | 审批意见 | 签名 | 时间 |
|------|----------|----------|------|------|
| 产品负责人 | 同意 / 不同意 |  |  |  |
| 技术负责人 | 同意 / 不同意 |  |  |  |
| 安全负责人 | 同意 / 不同意 |  |  |  |
| 交付负责人 | 同意 / 不同意 |  |  |  |
| 客户授权代表 | 同意 / 不同意 |  |  |  |

## 启用结论

- 是否允许设置 `DRY_RUN=false`：是 / 否
- 是否允许设置 `REAL_ENFORCEMENT_GATE=real-enforcement`：是 / 否
- 生效开始时间：
- 生效结束或复核时间：
- 关联变更单：
- 关联恢复演练报告：
