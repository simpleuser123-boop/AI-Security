# 云安全组接入信息收集表

适用范围：收集客户云安全组 provider 接入所需的非敏感元数据和验收证据。禁止在本文档中填写明文密钥。

## 强制前置声明

- 默认运行基线必须为 `DRY_RUN=true`。
- 云安全组接入完成不代表真实响应启用，真实响应需要单独审批。
- 未完成误封恢复演练不得启用真实响应。
- 出现误封时，优先切回 `DRY_RUN=true` 并撤销 `REAL_ENFORCEMENT_GATE`，再删除 Guardian 创建的 deny/drop 规则。

## 基础信息

| 项目 | 内容 |
|------|------|
| 客户名称 |  |
| 云厂商 | AWS / Azure / GCP / 阿里云 / 腾讯云 / 华为云 / 其他 |
| 账号/订阅/项目 ID |  |
| Region |  |
| VPC/VNet ID |  |
| 环境 | 生产 / 预生产 / 演练 |
| 客户云负责人 |  |
| 客户安全负责人 |  |

## Provider 配置

| 配置项 | 值 | 备注 |
|--------|----|------|
| `RESPONSE_FIREWALL_BACKEND` |  | 例如 `aws_security_group` |
| `RESPONSE_CLOUD_SG_TENANT_ID` |  |  |
| `RESPONSE_CLOUD_SG_REGION` |  |  |
| `RESPONSE_CLOUD_SG_ALLOWED_IDS` |  | 允许操作的安全组全集 |
| `RESPONSE_CLOUD_SG_TARGET_IDS` |  | 必须完全属于 allowed ids |
| `RESPONSE_CLOUD_SG_CREDENTIAL_REF` |  | 只填凭证引用，如 `secret://...` |

## 安全组范围

| 安全组 ID | 名称 | 业务用途 | 是否允许 Guardian 操作 | 允许动作 | 禁止动作 | 负责人 |
|-----------|------|----------|------------------------|----------|----------|--------|
|  |  |  | 是 / 否 | 查询 / 添加 deny / 删除 Guardian deny | 放行规则 / 非 Guardian 规则 |  |

## 规则标识要求

所有 Guardian 创建的规则必须带可追溯标识：

- `created_by=ai-security-guardian`
- `approval_id=<审批单号>`
- `response_action_id=<动作 ID>`
- `expires_at=<到期时间>`
- `tenant_id=<客户或租户 ID>`

## 接入验证

| 验证项 | 期望结果 | 实际结果 | 证据 |
|--------|----------|----------|------|
| dry-run 计划 | 返回安全组、CIDR、动作、TTL，不调用云 API |  |  |
| provider validate | active 且 `last_validation_result.ok=true` |  |  |
| 目标安全组边界 | `TARGET_IDS` 超出 `ALLOWED_IDS` 时拒绝 |  |  |
| 真实测试 IP 封禁 | 仅在审批和演练窗口内执行，且带 TTL |  |  |
| 定时解封 | TTL 到期后规则删除或 skipped |  |  |
| 误封回滚 | 手工删除 Guardian 规则并恢复访问 |  |  |

## 签署

| 角色 | 姓名 | 结论 | 签名 | 时间 |
|------|------|------|------|------|
| 客户云负责人 |  | 同意 / 不同意 |  |  |
| 客户安全负责人 |  | 同意 / 不同意 |  |  |
| 交付负责人 |  | 同意 / 不同意 |  |  |

