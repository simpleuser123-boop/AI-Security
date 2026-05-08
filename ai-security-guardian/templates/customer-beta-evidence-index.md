# 单企业私有化 / Private Deployment GA 交付证据索引

填写说明：本索引用于登记交付证据位置和验收状态。请不要上传或记录 `.env` 明文、数据库密码、Redis 密码、管理员密码哈希、API Token。`.env` 只登记 SHA256；PostgreSQL 无真实客户环境时不得填写“通过”，只能登记待客户环境执行项。

## 1. 基本信息

| 项目 | 内容 |
|------|------|
| 客户名称 |  |
| 环境 |  |
| 交付日期 |  |
| 交付负责人 |  |
| 客户验收负责人 |  |
| 证据存放位置 |  |
| 证据包生成命令 | `python scripts/generate_private_deployment_evidence.py ...` |
| 证据包 manifest | `manifest.json` |

## 2. 证据索引

| 编号 | 证据类别 | 证据名称 | 文件 / 链接 / 截图位置 | 状态 | 备注 |
|------|----------|----------|------------------------|------|------|
| E-01 | 基础信息 | 客户环境信息收集表 |  | 已收集 / 缺失 / 不适用 |  |
| E-02 | 配置安全 | `.env` SHA256 |  | 已收集 / 缺失 / 不适用 | 不保存明文 |
| E-03 | 配置安全 | readiness 输出 |  | 已收集 / 缺失 / 不适用 |  |
| E-04 | 部署 | 镜像 tag、镜像 ID |  | 已收集 / 缺失 / 不适用 |  |
| E-05 | 部署 | `docker compose config` |  | 已收集 / 缺失 / 不适用 |  |
| E-06 | 部署 | `docker compose ps` |  | 已收集 / 缺失 / 不适用 |  |
| E-07 | 数据库 | 迁移输出 |  | 已收集 / 缺失 / 不适用 |  |
| E-08 | 数据库 | `web.init_db --check` |  | 已收集 / 缺失 / 不适用 |  |
| E-09 | 数据库 | PostgreSQL dump SHA256 | `database/db-dump.sha256` | 已收集 / 待客户环境执行 / 缺失 / 不适用 | 不记录连接串明文 |
| E-09A | 数据库 | 源库迁移版本 | `database/migration-version.json` | 已收集 / 待客户环境执行 / 缺失 / 不适用 | `source_database_current_revision`，连接串已脱敏 |
| E-09B | 数据库 | 恢复库迁移版本 | `database/migration-version.json` | 已收集 / 待客户环境执行 / 缺失 / 不适用 | `restore_drill_current_revision`；无隔离恢复库不得标记通过 |
| E-10 | Redis | 密码 `PING` 输出 |  | 已收集 / 缺失 / 不适用 | 脱敏 |
| E-11 | Redis | 未公网监听证据 |  | 已收集 / 缺失 / 不适用 |  |
| E-12 | Redis | Stream `XLEN/XPENDING/XINFO` |  | 已收集 / 缺失 / 不适用 |  |
| E-13 | 模型 | 模型文件清单 |  | 已收集 / 缺失 / 不适用 |  |
| E-14 | 模型 | manifest 与 SHA256 | `models/model-sha256.txt` / `models/model-manifests.json` | 已收集 / 缺失 / 不适用 |  |
| E-15 | 健康检查 | `/api/health` 输出 | `health/health-summary.json` | 已收集 / 待客户环境执行 / 缺失 / 不适用 |  |
| E-16 | 健康检查 | `/healthz` 输出 |  | 已收集 / 缺失 / 不适用 |  |
| E-17 | 健康检查 | `/readyz` 输出 |  | 已收集 / 缺失 / 不适用 |  |
| E-17A | 健康检查 | `/metrics` 摘要 | `health/health-summary.json` | 已收集 / 待客户环境执行 / 缺失 / 不适用 |  |
| E-18 | 控制台 | 登录截图 |  | 已收集 / 缺失 / 不适用 |  |
| E-19 | 控制台 | Dashboard 截图 |  | 已收集 / 缺失 / 不适用 |  |
| E-20 | 控制台 | Alerts 截图 |  | 已收集 / 缺失 / 不适用 |  |
| E-21 | 控制台 | Settings 截图 |  | 已收集 / 缺失 / 不适用 |  |
| E-22 | WebSocket | `/socket.io/` 成功连接 |  | 已收集 / 缺失 / 不适用 |  |
| E-23 | 验收 | `verify_v1.py` 输出 |  | 已收集 / 缺失 / 不适用 |  |
| E-24 | 验收 | `staging_drill.py --cleanup` 输出 |  | 已收集 / 缺失 / 不适用 |  |
| E-25 | 验收 | pytest 输出 |  | 已收集 / 缺失 / 不适用 |  |
| E-26 | 性能 | benchmark 报告 |  | 已收集 / 缺失 / 不适用 |  |
| E-27 | 审计 | 审计 hash-chain 完整性校验 | `audit/hash-chain-verification.json` | 已收集 / 缺失 / 不适用 |  |
| E-28 | 运维 | 运维检查记录 |  | 已收集 / 缺失 / 不适用 |  |
| E-29 | 备份恢复 | 备份清单和 SHA256 |  | 已收集 / 缺失 / 不适用 |  |
| E-30 | 备份恢复 | 恢复演练记录 |  | 已收集 / 缺失 / 不适用 |  |
| E-31 | 误封恢复 | 误封恢复演练记录 |  | 已收集 / 缺失 / 不适用 |  |
| E-32 | 真实响应 | 真实响应启用申请表 |  | 已收集 / 缺失 / 不适用 | 默认不适用 |
| E-33 | 问题处理 | 问题单和关闭记录 |  | 已收集 / 缺失 / 不适用 |  |
| E-34 | 签收 | 试点验收签收表 |  | 已收集 / 缺失 / 不适用 |  |

## 2.1 自动化证据包目录结构

建议用以下目录作为交付证据包最小结构：

```text
private-deployment-evidence/<UTC timestamp>/
  README.md
  manifest.json
  customer-actions.md
  config/
    env.sha256
  database/
    db-dump.sha256
    migration-version.json
    postgresql-restore-drill-command.txt
  models/
    model-sha256.txt
    model-manifests.json
  audit/
    hash-chain-verification.json
  health/
    health-summary.json 或 health-check-commands.md
  templates/
    customer-beta-evidence-index.md
    customer-beta-backup-restore-record.md
```

## 3. 缺失证据说明

| 编号 | 缺失原因 | 是否影响验收 | 补充计划 |
|------|----------|--------------|----------|
|  |  | 是 / 否 |  |

## 4. 证据确认

| 角色 | 姓名 | 结论 | 签名 | 日期 |
|------|------|------|------|------|
| 客户验收负责人 |  | 完整 / 有缺失 / 不通过 |  |  |
| 交付负责人 |  | 完整 / 有缺失 / 不通过 |  |  |
