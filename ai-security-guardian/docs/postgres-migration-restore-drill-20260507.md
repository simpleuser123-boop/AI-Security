# PostgreSQL 商业化迁移备份恢复演练方案（20260507_0002/0003）

本文档用于 AI-Security-Guardian 商业化迁移 `20260507_0002` / `20260507_0003` 在 PostgreSQL 环境的发布前演练与客户交付证据归档。目标是证明：迁移前可备份、迁移后可校验、异常时可 downgrade 或从 `pg_dump` 恢复，并且备份可恢复到临时库验证。

所有命令默认在项目根目录执行，生产执行前由 DBA 按客户环境替换连接串、库名、账号和备份目录。

## 1. 迁移内容与影响范围

目标迁移链：

- `20260506_0001`：初始业务表。
- `20260507_0002`：Phase B1 多租户数据模型。
- `20260507_0003`：商业化计量 MVP。

`20260507_0002` 新增表：

- `tenants`
- `organizations`
- `users`
- `roles`
- `memberships`
- `api_keys`

`20260507_0002` 修改既有业务表：

- 为 `alerts`、`alert_histories`、`response_actions`、`response_schedule_tasks`、`rules`、`iocs`、`settings`、`banned_ips`、`audit_events`、`model_versions` 增加 `tenant_id`，默认回填为 `tenant_default`。
- 新增租户维度索引：例如 `ix_alerts_tenant_status_ts`、`ix_rules_tenant_enabled_priority`、`ix_iocs_tenant_type_value`、`ix_audit_tenant_created` 等。
- 初始化默认租户、默认组织、系统用户、owner 角色与默认 membership。

`20260507_0003` 新增表：

- `plans`
- `license_keys`
- `subscriptions`
- `quotas`
- `usage_meters`

`20260507_0003` 初始化数据：

- `plan_default_mvp`
- `sub_default_mvp`
- 默认租户 `tenant_default` 的商业化配额：`users`、`alerts`、`rules`、`iocs`、`api_calls`、`notifications`、`response_actions`、`retention_days`。

## 2. 风险说明与回滚原则

当前两个迁移 revision 均提供 `downgrade()`，但生产回滚必须按风险分级执行：

- `20260507_0003` downgrade 会删除 `usage_meters`、`quotas`、`subscriptions`、`license_keys`、`plans`，会丢失迁移后写入的套餐、License、订阅、配额和用量数据。
- `20260507_0002` downgrade 会删除多租户基础表，并从既有业务表删除 `tenant_id`，会丢失迁移后的租户隔离信息。
- 因此，生产首选恢复策略是：发布前执行 `pg_dump -Fc`，异常时优先切换到恢复库或从备份恢复；仅在确认迁移后未产生需要保留的新商业数据时，才考虑 Alembic downgrade。
- downgrade 前必须停止应用写入，记录当前 `flask db current`、应用镜像 tag、`.env` SHA256、备份 SHA256 和操作人。

## 3. 演练前准备

设置变量：

```bash
export TS=$(date +%Y%m%d%H%M%S)
export APP_DB_URL='postgresql+psycopg2://guardian:REPLACE_WITH_PASSWORD@postgres.example.com:5432/guardian_prod'
export APP_DB_NAME='guardian_prod'
export RESTORE_DB_NAME="guardian_restore_${TS}"
export BACKUP_DIR="backups/postgres-migration-${TS}"
mkdir -p "$BACKUP_DIR"
chmod 700 "$BACKUP_DIR"

export FLASK_ENV=production
export DATABASE_URL="$APP_DB_URL"
export SECRET_KEY='REPLACE_WITH_PRODUCTION_SECRET_OR_USE_EXISTING_ENV'
```

记录基线：

```bash
flask --app web.migration_app:create_migration_app db current | tee "$BACKUP_DIR/flask-db-current.before.txt"
git rev-parse HEAD | tee "$BACKUP_DIR/git-revision.txt"
docker image ls ai-security-guardian | tee "$BACKUP_DIR/docker-images.before.txt"
sha256sum .env > "$BACKUP_DIR/env.sha256" 2>/dev/null || true
```

## 4. 演练前备份 pg_dump

执行 PostgreSQL 自定义格式备份：

```bash
pg_dump "$APP_DB_URL" -Fc -f "$BACKUP_DIR/${APP_DB_NAME}.before-20260507-commercial.dump"
sha256sum "$BACKUP_DIR/${APP_DB_NAME}.before-20260507-commercial.dump" \
  > "$BACKUP_DIR/${APP_DB_NAME}.before-20260507-commercial.dump.sha256"
ls -lh "$BACKUP_DIR" | tee "$BACKUP_DIR/backup-files.txt"
sha256sum -c "$BACKUP_DIR/${APP_DB_NAME}.before-20260507-commercial.dump.sha256" \
  | tee "$BACKUP_DIR/backup-sha256-check.txt"
```

验收点：

- dump 文件存在且大小非 0。
- SHA256 校验通过。
- 备份目录权限为 `700`。

## 5. 执行 flask db upgrade

在暂存 PostgreSQL 或维护窗口内执行：

```bash
flask --app web.migration_app:create_migration_app db upgrade \
  2>&1 | tee "$BACKUP_DIR/flask-db-upgrade.txt"
```

若通过 Docker Compose 执行：

```bash
docker compose run --rm app \
  flask --app web.migration_app:create_migration_app db upgrade \
  2>&1 | tee "$BACKUP_DIR/flask-db-upgrade.txt"
```

验收点：

- 命令退出码为 `0`。
- 输出包含升级到 `20260507_0002`、`20260507_0003` 的记录。
- 无 `ERROR`、`Traceback` 或锁等待超时。

## 6. 执行 flask db current

```bash
flask --app web.migration_app:create_migration_app db current \
  2>&1 | tee "$BACKUP_DIR/flask-db-current.after.txt"
```

期望结果：

```text
20260507_0003 (head)
```

验收点：

- 当前 revision 为 `20260507_0003`。
- 若输出不是 `head`，停止发布并检查 Alembic 版本链。

## 7. 表结构校验

使用 `psql` 校验新增表、关键列、索引和默认数据：

```bash
psql "$APP_DB_URL" -v ON_ERROR_STOP=1 <<'SQL' | tee "$BACKUP_DIR/schema-check.txt"
SELECT version_num FROM alembic_version;

SELECT table_name
FROM information_schema.tables
WHERE table_schema = 'public'
  AND table_name IN (
    'tenants','organizations','users','roles','memberships','api_keys',
    'plans','license_keys','subscriptions','quotas','usage_meters'
  )
ORDER BY table_name;

SELECT table_name, column_name, data_type, is_nullable
FROM information_schema.columns
WHERE table_schema = 'public'
  AND column_name = 'tenant_id'
  AND table_name IN (
    'alerts','alert_histories','response_actions','response_schedule_tasks',
    'rules','iocs','settings','banned_ips','audit_events','model_versions'
  )
ORDER BY table_name;

SELECT tablename, indexname
FROM pg_indexes
WHERE schemaname = 'public'
  AND indexname IN (
    'ix_alerts_tenant_status_ts',
    'ix_response_schedule_tenant_run',
    'ix_rules_tenant_enabled_priority',
    'ix_iocs_tenant_type_value',
    'ix_audit_tenant_created',
    'ix_model_versions_tenant_created',
    'ix_plans_status',
    'ix_license_keys_tenant_status',
    'ix_subscriptions_tenant_status',
    'ix_quotas_tenant_metric',
    'ix_usage_tenant_metric'
  )
ORDER BY tablename, indexname;

SELECT id, slug, status, plan FROM tenants WHERE id = 'tenant_default';
SELECT id, tenant_id, status FROM subscriptions WHERE id = 'sub_default_mvp';
SELECT tenant_id, metric, "limit", source FROM quotas WHERE tenant_id = 'tenant_default' ORDER BY metric;
SQL
```

验收点：

- `alembic_version.version_num = 20260507_0003`。
- 10 张新增表全部存在。
- 10 张既有业务表均存在 `tenant_id`。
- 商业化索引存在。
- 默认租户、默认订阅和默认配额存在。

## 8. 核心数据写入/读取校验

在演练库写入最小业务闭环数据，验证多租户、商业化计量和核心业务表可读写：

```bash
psql "$APP_DB_URL" -v ON_ERROR_STOP=1 <<'SQL' | tee "$BACKUP_DIR/read-write-check.txt"
BEGIN;

INSERT INTO tenants (id, name, slug, status, plan, created_at, updated_at)
VALUES ('tenant_drill_20260507', 'Drill Tenant 20260507', 'drill-20260507', 'active', 'mvp-default', NOW(), NOW());

INSERT INTO organizations (id, tenant_id, name, slug, status, created_at, updated_at)
VALUES ('org_drill_20260507', 'tenant_drill_20260507', 'Drill Org', 'default', 'active', NOW(), NOW());

INSERT INTO plans (id, code, name, status, limits, created_at, updated_at)
VALUES (
  'plan_drill_20260507',
  'drill-20260507',
  'Drill Plan',
  'active',
  '{"rules": 3, "api_calls": 100, "retention_days": 30}'::jsonb,
  NOW(),
  NOW()
);

INSERT INTO subscriptions (id, tenant_id, plan_id, status, starts_at, created_at, updated_at)
VALUES ('sub_drill_20260507', 'tenant_drill_20260507', 'plan_drill_20260507', 'active', NOW(), NOW(), NOW());

INSERT INTO quotas (tenant_id, metric, "limit", source, created_at, updated_at)
VALUES ('tenant_drill_20260507', 'rules', 3, 'drill', NOW(), NOW());

INSERT INTO usage_meters (tenant_id, metric, period, used, created_at, updated_at)
VALUES ('tenant_drill_20260507', 'rules', 'current', 1, NOW(), NOW());

INSERT INTO alerts (
  id, tenant_id, timestamp, source_ip, threat_type, level, status, created_at, updated_at
) VALUES (
  'alert_drill_20260507', 'tenant_drill_20260507', NOW(), '198.51.100.10', 'drill', 'low', 'open', NOW(), NOW()
);

SELECT t.id AS tenant_id, s.id AS subscription_id, q.metric, q."limit", u.used, a.id AS alert_id
FROM tenants t
JOIN subscriptions s ON s.tenant_id = t.id
JOIN quotas q ON q.tenant_id = t.id AND q.metric = 'rules'
JOIN usage_meters u ON u.tenant_id = t.id AND u.metric = 'rules'
JOIN alerts a ON a.tenant_id = t.id
WHERE t.id = 'tenant_drill_20260507';

ROLLBACK;
SQL
```

验收点：

- 写入事务成功。
- 查询返回 `tenant_drill_20260507`、`sub_drill_20260507`、`rules`、`limit=3`、`used=1`、`alert_drill_20260507`。
- 最后 `ROLLBACK`，不污染生产数据；如客户要求保留演练记录，可改为 `COMMIT` 并记录清理 SQL。

## 9. downgrade 或恢复策略

### 9.1 Alembic downgrade 路径

仅在暂存环境或确认无迁移后新增商业化数据时使用：

```bash
flask --app web.migration_app:create_migration_app db downgrade 20260507_0002 \
  2>&1 | tee "$BACKUP_DIR/flask-db-downgrade-to-0002.txt"
flask --app web.migration_app:create_migration_app db current \
  2>&1 | tee "$BACKUP_DIR/flask-db-current.after-downgrade-0002.txt"
```

继续回退到初始 schema：

```bash
flask --app web.migration_app:create_migration_app db downgrade 20260506_0001 \
  2>&1 | tee "$BACKUP_DIR/flask-db-downgrade-to-0001.txt"
```

风险确认：

- 回退到 `20260507_0002` 会删除 0003 商业化表及数据。
- 回退到 `20260506_0001` 会删除多租户基础表和既有业务表中的 `tenant_id`。
- downgrade 后如要重新发布，必须再次执行 `flask db upgrade` 并重复结构/读写校验。

### 9.2 首选恢复路径

生产异常首选从备份恢复到临时库，验证无误后切换应用连接串或由 DBA 在维护窗口恢复正式库：

```bash
createdb "$RESTORE_DB_NAME"
pg_restore -d "$RESTORE_DB_NAME" "$BACKUP_DIR/${APP_DB_NAME}.before-20260507-commercial.dump" \
  2>&1 | tee "$BACKUP_DIR/pg-restore-to-temp.txt"
```

临时库验证通过后，恢复策略二选一：

- 切换应用 `DATABASE_URL` 指向已验证的恢复库，重启应用。
- 停写正式库，备份事故现场，再由 DBA 将 dump 恢复回正式库。

正式库覆盖恢复必须先停写：

```bash
docker compose stop app guardian || true
pg_dump "$APP_DB_URL" -Fc -f "$BACKUP_DIR/${APP_DB_NAME}.incident-before-restore.dump"
# DBA 在维护窗口内执行 drop/create 或 pg_restore --clean --if-exists，按客户变更规范审批。
```

## 10. 从备份恢复到临时库验证

创建临时恢复连接串：

```bash
export RESTORE_DB_URL="postgresql+psycopg2://guardian:REPLACE_WITH_PASSWORD@postgres.example.com:5432/${RESTORE_DB_NAME}"
```

验证备份恢复后的版本和表数据：

```bash
psql "$RESTORE_DB_URL" -v ON_ERROR_STOP=1 <<'SQL' | tee "$BACKUP_DIR/restore-db-check.txt"
SELECT version_num FROM alembic_version;

SELECT table_name
FROM information_schema.tables
WHERE table_schema = 'public'
ORDER BY table_name;

SELECT COUNT(*) AS alerts_count FROM alerts;
SELECT COUNT(*) AS rules_count FROM rules;
SELECT COUNT(*) AS iocs_count FROM iocs;
SELECT COUNT(*) AS audit_events_count FROM audit_events;
SQL
```

如备份点已经在 `20260506_0001`，可在临时库继续演练升级：

```bash
DATABASE_URL="$RESTORE_DB_URL" \
  flask --app web.migration_app:create_migration_app db upgrade \
  2>&1 | tee "$BACKUP_DIR/restore-db-upgrade.txt"

DATABASE_URL="$RESTORE_DB_URL" \
  flask --app web.migration_app:create_migration_app db current \
  2>&1 | tee "$BACKUP_DIR/restore-db-current.after-upgrade.txt"
```

验收点：

- `pg_restore` 退出码为 `0`。
- 临时库可查询 `alembic_version` 和核心业务表。
- 临时库升级到 `20260507_0003` 成功。
- 临时库表结构校验和核心读写校验均通过。

## 11. 证据清单

演练完成后，将以下文件归档到客户交付包：

- `flask-db-current.before.txt`
- `git-revision.txt`
- `docker-images.before.txt`
- `env.sha256`
- `${APP_DB_NAME}.before-20260507-commercial.dump`
- `${APP_DB_NAME}.before-20260507-commercial.dump.sha256`
- `backup-sha256-check.txt`
- `flask-db-upgrade.txt`
- `flask-db-current.after.txt`
- `schema-check.txt`
- `read-write-check.txt`
- `pg-restore-to-temp.txt`
- `restore-db-check.txt`
- `restore-db-upgrade.txt`（如执行）
- `restore-db-current.after-upgrade.txt`（如执行）
- downgrade 输出文件（如执行）
- 应用健康检查输出：`/api/health`、`/healthz`、`/readyz`
- 参与人、演练时间、RTO/RPO、问题项和整改结论

## 12. 演练结论模板

```text
演练日期：
客户环境：
数据库版本：
应用镜像 tag / Git revision：
迁移前 revision：
迁移后 revision：
备份文件：
备份 SHA256：
临时恢复库：
RTO 目标 / 实际：
RPO 目标 / 实际：

结论：
[ ] pg_dump 备份可用
[ ] flask db upgrade 成功
[ ] flask db current 为 20260507_0003
[ ] 表结构校验通过
[ ] 核心数据写入/读取校验通过
[ ] downgrade 风险已确认
[ ] 临时库 pg_restore 验证通过
[ ] 恢复库可再次升级到 20260507_0003

遗留问题：
整改责任人：
客户确认人：
```
