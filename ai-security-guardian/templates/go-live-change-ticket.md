# 上线变更单模板

适用范围：Phase C6 真实响应受控开放的上线、灰度、回退和验收记录。

## 强制前置声明

- 默认运行基线必须为 `DRY_RUN=true`。
- 真实响应上线必须单独审批，不得复用私有化 Beta readiness 作为上线授权。
- 未完成恢复演练不得启用 `DRY_RUN=false`。
- 出现误封时，优先切回 `DRY_RUN=true` 并撤销 `REAL_ENFORCEMENT_GATE`。

## 变更基本信息

| 项目 | 内容 |
|------|------|
| 变更单号 |  |
| 客户名称 |  |
| 变更标题 | Phase C6 真实响应受控开放 |
| 变更类型 | 标准 / 普通 / 紧急 |
| 环境 | 生产 / 预生产 |
| 计划开始时间 |  |
| 计划结束时间 |  |
| 低峰窗口确认 | 是 / 否 |
| 影响范围 |  |
| 回退触发条件 |  |

## 变更内容

| 内容 | 当前状态 | 目标状态 | 回退状态 |
|------|----------|----------|----------|
| `DRY_RUN` | `true` | `false` | `true` |
| `REAL_ENFORCEMENT_GATE` | 空 | `real-enforcement` | 空 |
| Provider |  |  | 禁用或 dry-run |
| 白名单 |  | 已确认 | 恢复上一个版本 |
| Scheduler |  | 已启用 | 保留 pending 解封任务 |

## 前置条件

| 条件 | 状态 | 证据 |
|------|------|------|
| 私有化 Beta readiness 通过且 `DRY_RUN=true` | 未通过 / 通过 |  |
| `real-enforcement` gate 通过 | 未通过 / 通过 |  |
| 四类 gate 签署完成 | 未通过 / 通过 |  |
| 业务白名单确认完成 | 未通过 / 通过 |  |
| Provider 最小权限验证完成 | 未通过 / 通过 |  |
| 定时解封验收完成 | 未通过 / 通过 |  |
| 误封恢复演练通过 | 未通过 / 通过 |  |
| 上线后 24 小时观察人已排班 | 未通过 / 通过 |  |

## 实施步骤

| 步骤 | 操作 | 操作人 | 计划时间 | 结果 | 证据 |
|------|------|--------|----------|------|------|
| 1 | 备份 `.env`、数据库、模型清单、审计日志 |  |  |  |  |
| 2 | 执行 `python scripts/check_production_readiness.py`，确认 private-beta gate |  |  |  |  |
| 3 | 执行 `python scripts/check_production_readiness.py --gate real-enforcement` |  |  |  |  |
| 4 | 在变更窗口设置 `DRY_RUN=false` |  |  |  |  |
| 5 | 设置 `REAL_ENFORCEMENT_GATE=real-enforcement` |  |  |  |  |
| 6 | 重启读取配置的 app/worker/guardian |  |  |  |  |
| 7 | 执行测试目标小流量真实响应 |  |  |  |  |
| 8 | 验证 provider 状态和定时解封任务 |  |  |  |  |
| 9 | 验证审计日志、response action 和 schedule task |  |  |  |  |
| 10 | 进入 24 小时观察 |  |  |  |  |

## 回退步骤

| 步骤 | 操作 | 操作人 | 结果 | 证据 |
|------|------|--------|------|------|
| 1 | 设置 `DRY_RUN=true` |  |  |  |
| 2 | 撤销或置空 `REAL_ENFORCEMENT_GATE` |  |  |  |
| 3 | 暂停响应 worker 或 provider 执行队列，如需要 |  |  |  |
| 4 | 对已执行动作执行 manual unban / rollback / EDR release |  |  |  |
| 5 | 验证业务恢复和 provider 状态 |  |  |  |
| 6 | 归档审计并启动复盘 |  |  |  |

## 审批

| 角色 | 结论 | 签名 | 时间 |
|------|------|------|------|
| 客户业务负责人 | 同意 / 不同意 |  |  |
| 客户安全负责人 | 同意 / 不同意 |  |  |
| 客户网络/云负责人 | 同意 / 不同意 |  |  |
| 客户 EDR 管理员 | 同意 / 不同意 / 不适用 |  |  |
| 交付负责人 | 同意 / 不同意 |  |  |

