# Database Migration and Backup Restore Evidence - 2026-05-06

Scope: Task 4 only. Evidence was collected against a real PostgreSQL staging database, not SQLite.

## Source Review

Reviewed before execution:

- `README.md`: database initialization section requires `flask --app web.migration_app:create_migration_app db upgrade`; `python -m web.init_db --check` is retained as a table-existence check.
- `docs/deployment.md`: PostgreSQL upgrade/check/backup/restore commands and evidence expectations.
- `migrations/alembic.ini`: Alembic script location is `migrations`.
- `migrations/env.py`: Flask-Migrate obtains the URL from the configured Flask app engine.
- `web/migration_app.py`: lightweight migration app uses `get_config()` and registers ORM metadata.
- `web/init_db.py`: `--check` inspects existing tables and exits without creating missing tables.

## Connection Target

Configured `.env` target, sanitized:

```text
DATABASE_URL=postgresql://guardian:***@localhost:5432/guardian
backend=postgresql
```

The configured `localhost:5432` was not initially listening. To avoid modifying current Beta environment configuration, an isolated local PostgreSQL staging container was started for this task:

```text
container=guardian-task4-postgres
image=pgvector/pgvector:0.8.0-pg15
listen=127.0.0.1:5432
database=guardian
user=guardian
```

Runtime verification:

```text
target_sanitized= postgresql://guardian:***@localhost:5432/guardian
backend= postgresql
current_database= guardian
current_user= guardian
server_version= 15.14 (Debian 15.14-1.pgdg12+1)
table_count= 11
```

For migration commands only, `ALLOWED_ORIGINS` was overridden in the process environment as `https://staging.local.example` so `FLASK_ENV=production` config validation could load without editing `.env`.

## DB Upgrade

Command:

```powershell
$env:ALLOWED_ORIGINS='https://staging.local.example'
python -m flask --app web.migration_app:create_migration_app db upgrade
```

Output:

```text
INFO  [alembic.runtime.migration] Context impl PostgresqlImpl.
INFO  [alembic.runtime.migration] Will assume transactional DDL.
INFO  [alembic.runtime.migration] Running upgrade  -> 20260506_0001, Initial schema for existing ORM models.
```

Result: passed.

## DB Current

Command:

```powershell
$env:ALLOWED_ORIGINS='https://staging.local.example'
python -m flask --app web.migration_app:create_migration_app db current
```

Output:

```text
20260506_0001 (head)
INFO  [alembic.runtime.migration] Context impl PostgresqlImpl.
INFO  [alembic.runtime.migration] Will assume transactional DDL.
```

Result: passed.

## Init DB Check

Command:

```powershell
$env:ALLOWED_ORIGINS='https://staging.local.example'
python -m web.init_db --check
```

Output:

```text
Existing tables: alembic_version, alert_histories, alerts, audit_events, banned_ips, iocs, model_versions, response_actions, response_schedule_tasks, rules, settings
Database schema check passed.
```

Result: passed.

## Backup

Commands:

```powershell
$ts='20260506-task4-db-drill'
$backupDir="backups\$ts"
New-Item -ItemType Directory -Force -Path $backupDir | Out-Null
docker exec guardian-task4-postgres pg_dump -U guardian -d guardian -Fc -f /tmp/guardian-task4-20260506.dump
docker cp guardian-task4-postgres:/tmp/guardian-task4-20260506.dump backups\20260506-task4-db-drill\guardian-task4-20260506.dump
Get-FileHash -Algorithm SHA256 backups\20260506-task4-db-drill\guardian-task4-20260506.dump
```

Backup file:

```text
path=backups/20260506-task4-db-drill/guardian-task4-20260506.dump
size_bytes=26034
sha256=626FB8059F442D06220FA8A6BEF4415DAB202C28A2DB44FFC0D93DDFA0541D99
```

Result: passed.

## Restore Drill

Restore target:

```text
database=guardian_restore_drill_20260506
target_sanitized=postgresql://guardian:***@localhost:5432/guardian_restore_drill_20260506
```

Commands:

```powershell
docker exec guardian-task4-postgres dropdb -U guardian --if-exists guardian_restore_drill_20260506
docker exec guardian-task4-postgres createdb -U guardian guardian_restore_drill_20260506
docker exec guardian-task4-postgres pg_restore -U guardian -d guardian_restore_drill_20260506 /tmp/guardian-task4-20260506.dump
docker exec guardian-task4-postgres psql -U guardian -d guardian_restore_drill_20260506 -v ON_ERROR_STOP=1 -c "SELECT version_num FROM alembic_version;"
docker exec guardian-task4-postgres psql -U guardian -d guardian_restore_drill_20260506 -v ON_ERROR_STOP=1 -c "SELECT table_name FROM information_schema.tables WHERE table_schema='public' ORDER BY table_name;"
```

Restore output:

```text
version_num
---------------
20260506_0001
(1 row)

table_name
-------------------------
alembic_version
alert_histories
alerts
audit_events
banned_ips
iocs
model_versions
response_actions
response_schedule_tasks
rules
settings
(11 rows)

table_name  | count
--------------+-------
alerts       |     0
audit_events |     0
settings     |     0
(3 rows)
```

Restore schema check command:

```powershell
# DATABASE_URL was overridden in-process to point at guardian_restore_drill_20260506.
python -m web.init_db --check
```

Restore schema check output:

```text
restore_target_sanitized= postgresql://guardian:***@localhost:5432/guardian_restore_drill_20260506
Existing tables: alembic_version, alert_histories, alerts, audit_events, banned_ips, iocs, model_versions, response_actions, response_schedule_tasks, rules, settings
Database schema check passed.
```

Result: passed.

## Conclusion

Overall result: passed.

No SQLite fallback was used. No production database was modified. Destructive commands were limited to the isolated restore target database `guardian_restore_drill_20260506`.
