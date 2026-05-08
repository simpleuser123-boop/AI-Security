# 定时解封验收模板

适用范围：验证真实封禁必须带 TTL，且定时解封任务可持久化、可恢复、可重试、可审计。

## 强制前置声明

- 默认运行基线必须为 `DRY_RUN=true`。
- 定时解封验收不代表真实响应启用，真实响应仍需单独审批。
- 未完成定时解封和误封恢复演练不得启用真实响应。
- 出现误封或解封失败时，优先切回 `DRY_RUN=true` 并撤销 `REAL_ENFORCEMENT_GATE`。

## 验收信息

| 项目 | 内容 |
|------|------|
| 验收编号 |  |
| 客户名称 |  |
| 环境 | 预生产 / 演练 / 生产小流量 |
| Provider | iptables / 云安全组 / EDR |
| 测试目标 |  |
| TTL |  |
| 审批单号 |  |
| 变更单号 |  |
| 验收窗口 |  |

## 前置检查

| 检查项 | 期望 | 实际 | 证据 |
|--------|------|------|------|
| `DRY_RUN` 初始状态 | `true` |  |  |
| `REAL_ENFORCEMENT_GATE` 初始状态 | 空 |  |  |
| 审批记录 | 已通过，含 TTL 和回滚方式 |  |  |
| 白名单 | 测试目标不命中保护白名单，业务保护对象已加白 |  |  |
| provider validate | active 且 ok |  |  |
| scheduler/worker | 已部署，可访问数据库 |  |  |

## 验收步骤

| 步骤 | 操作 | 预期结果 | 实际结果 | 证据 |
|------|------|----------|----------|------|
| 1 | 临时启用 `DRY_RUN=false` 与 `REAL_ENFORCEMENT_GATE=real-enforcement` | real gate 生效 |  |  |
| 2 | 执行测试封禁 | `ResponseAction.status=executed`，`scheduled_unblock_at` 为未来时间 |  |  |
| 3 | 查询 `response_schedule_tasks` | 生成 `scheduled_unblock` pending 任务 |  |  |
| 4 | 查询 provider 状态 | Guardian 标识规则存在，包含 TTL/审批标识 |  |  |
| 5 | 等待 TTL 或触发 scheduler tick | 到期自动解封 |  |  |
| 6 | 再次查询 provider 状态 | 规则不存在或记录为 skipped |  |  |
| 7 | 验证任务状态 | completed / skipped，失败时有 `last_error` 和 `attempt_count` |  |  |
| 8 | 重启 worker 后复测 pending 任务 | pending 任务不丢失，可继续执行 |  |  |
| 9 | 切回 `DRY_RUN=true` 并撤销 gate | 真实响应关闭 |  |  |

## 验收标准

- 真实封禁记录不得缺少未来时间的 `scheduled_unblock_at`。
- 解封任务创建失败时，系统必须立即执行回滚解封并写入审计。
- 解封必须幂等，provider 规则已不存在时应记录 skipped，不得无限失败。
- 切回 `DRY_RUN=true` 不得删除既有解封任务。
- 审计中必须能关联审批、封禁、定时解封、provider 证据和操作人。

## 验收结论

| 项目 | 结论 |
|------|------|
| 定时解封是否通过 | 通过 / 不通过 |
| 是否允许进入真实响应启用审批 | 是 / 否 |
| 遗留问题 |  |
| 整改负责人 |  |
| 复测时间 |  |

## 签署

| 角色 | 签名 | 时间 |
|------|------|------|
| 客户安全负责人 |  |  |
| 客户网络/云负责人 |  |  |
| 交付负责人 |  |  |

