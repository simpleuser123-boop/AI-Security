# 审计日志基线重建流程

AI-Security-Guardian 的 `security.log` 使用 SHA-256 hash chain 防篡改。归档和重建基线只能在维护窗口、部署切换、发现历史链已损坏并完成取证、或日志体积需要周期轮转时执行。

## 目录隔离

默认审计目录按环境分离：

- `logs/test/security.log`
- `logs/dev/security.log`
- `logs/staging/security.log`
- `logs/production/security.log`

环境识别优先级为 `AUDIT_ENV`、`APP_ENV`、`FLASK_ENV`、`ENVIRONMENT`。可用 `AUDIT_LOG_DIR` 或 `GUARDIAN_LOG_DIR` 显式指定目录。测试必须使用 `test` 目录或临时目录，不能写入 `logs/production`。

旧版本可能留下根目录形式的 `logs/security.log`。归档脚本在未显式传入 `--log-dir`、且目标环境日志为空时，会把该 legacy 文件复制到目标环境的 `archive/` 目录并在目标环境目录创建新基线；legacy 原文件保留不动，用于取证追溯。

## 归档与基线重建

归档不会删除历史日志。脚本会先校验当前 `security.log`，再复制到同环境目录下的 `archive/`，写入一份 JSON 元数据，然后清空活动日志并写入一条新的系统基线事件，使新 hash chain 从 `genesis` 开始。生产执行前应停止写入审计日志的进程，避免归档过程中仍有新事件追加。

```bash
python scripts/archive_security_audit_log.py --env production --reason "monthly-rotation" --operator "secops" --ticket "CHG-20260505-01"
```

也可以显式指定目录：

```bash
python scripts/archive_security_audit_log.py --log-dir logs/staging --env staging --reason "pre-release-baseline"
```

脚本输出中的关键字段：

- `source_log`：被归档的原始日志；可能是 legacy `logs/security.log`。
- `archived_log`：归档副本，不得修改。
- `metadata_file`：归档清单，包含操作原因、环境、工单、行数、归档前校验结果和 SHA-256 摘要。
- `baseline_integrity`：新活动日志的完整性校验结果。
- `legacy_source`：是否从旧根目录日志迁移。

## 校验

运行时巡检调用 `SecurityLogger.verify_integrity()`。手工校验示例：

```bash
python - <<'PY'
from src.audit.security_logger import SecurityLogger
sl = SecurityLogger(log_dir="logs/production", enable_integrity=True)
print(sl.verify_integrity())
PY
```

校验通过时 `valid=True`。失败时应立即停止归档轮转，保存当前 `security.log`、对应 `archive/` 文件、数据库告警记录、系统时间源信息和操作人记录，再按事件响应流程处理。

归档后应分别校验归档文件和新基线：

```bash
python - <<'PY'
from src.audit.security_logger import SecurityLogger
sl = SecurityLogger(log_dir="logs/production", enable_integrity=True)
print("baseline:", sl.verify_integrity("logs/production/security.log"))
print("archive:", sl.verify_integrity("logs/production/archive/security-YYYYMMDDTHHMMSSZ.log"))
PY
```

## 审计证据保存

每次归档至少保留：

- `archive/security-<UTC时间>.log`
- `archive/security-<UTC时间>.json`
- 本次归档命令、操作人、审批单或变更单编号
- 重建后 `security.log` 首条基线事件及其完整性校验结果
- 外部记录的归档文件 SHA-256 摘要，和脚本元数据中的 `archive_sha256` 交叉核对

生产证据建议同步到只读对象存储或 WORM 介质，并记录外部 SHA-256 摘要。不要把生产归档拷入测试目录，也不要用测试日志覆盖生产基线。
