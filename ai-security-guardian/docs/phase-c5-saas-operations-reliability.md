# Phase C5：SaaS 运维与可靠性硬化

本文定义 AI-Security-Guardian SaaS Beta 的 SLO、Prometheus 告警、Grafana Dashboard、值班手册与 HA 方案。目标是让运维团队可以用 `/healthz`、`/readyz`、`/metrics` 快速判断系统是否健康，并在风险扩大前收到告警。

## 1. SaaS Beta SLO

| 能力 | Beta SLO | 统计窗口 | 口径 / PromQL |
|------|----------|----------|---------------|
| Web/API 可用性 | 99.5% 月可用 | 30 天 | `sum(rate(guardian_http_requests_total{status_class!~"5xx"}[5m])) / sum(rate(guardian_http_requests_total[5m]))`；同时外部黑盒探针对 `/api/health` 和 `/readyz` 成功 |
| API P95 | P95 < 300 ms | 5 分钟滚动，月度 95% 窗口达标 | `histogram_quantile(0.95, sum by (le) (rate(guardian_http_request_duration_seconds_bucket{route=~"/api/.*"}[5m])))` |
| 告警消费延迟 | P95 < 5s；Max < 30s | 5 分钟滚动 | 当前代码输出 sum/count/max：`rate(guardian_alert_consume_latency_ms_sum[5m]) / rate(guardian_alert_consume_latency_ms_count[5m])` 和 `guardian_alert_consume_latency_ms_max`；P95 需后续改为 histogram |
| Redis Stream lag | `redis_stream_group_lag < 1000` 且 `redis_stream_pending < 100` | 10 分钟 | `/metrics` 的 `redis_stream_group_lag`、`redis_stream_pending` |
| 通知失败率 | < 2% | 30 分钟 | `delta(guardian_response_actions_total{action_type="notify",status="failed"}[30m]) / delta(guardian_response_actions_total{action_type="notify"}[30m])`；当前为 DB gauge，Prometheus 可用 `delta` 近似，建议后续改为原生 counter |
| 响应动作失败率 | < 1%，真实封禁失败 0 容忍 | 30 分钟 | `guardian_response_actions_total{status=~"failed|rejected"}`，排除 `pending_approval`、`approved`、`skipped`、`dry_run` 正常状态 |
| 审计巡检成功率 | 100% | 24 小时 | `audit_integrity_valid == 1` 且 `increase(audit_integrity_patrol_runs_total{result="failed"}[24h]) == 0` |

错误预算建议：Beta 阶段以月为单位复盘，Web/API 99.5% 约等于每月 3.6 小时不可用预算。若 7 天内消耗超过 50%，冻结非紧急发布并优先处理稳定性债务。

## 2. /metrics 覆盖情况

已覆盖：

- Web/API 请求数与 latency histogram：`guardian_http_requests_total`、`guardian_http_request_duration_seconds_*`。
- Guardian 检测链路：`guardian_packets_total`、`guardian_packets_dropped_total`、`guardian_detection_latency_ms_*`、`guardian_alerts_total`、`guardian_model_ready`。
- Guardian heartbeat：`guardian_metrics_snapshot_updated_timestamp_seconds`、`guardian_last_detection_timestamp_seconds`。
- Redis Stream 写入与消费：`guardian_redis_stream_writes_total`、`redis_stream_pending`、`redis_stream_length`、`redis_stream_group_lag`、`guardian_alert_stream_consumed_total`、`guardian_alert_stream_consume_failures_total`、`guardian_alert_consume_latency_ms_*`。
- 通知与响应动作状态：`guardian_response_actions_total{action_type,status}`。
- 审计巡检：`audit_integrity_valid`、`audit_integrity_patrol_runs_total`、`audit_integrity_last_*_timestamp_seconds`。

仍建议补强：

- 将 `guardian_alert_consume_latency_ms_*` 升级为 histogram，以支持真实 P95。
- 将通知与响应动作结果从 DB gauge 改为写入时 counter，避免 DB 行修改导致 `increase()` 口径不完美。
- 增加进程级指标：CPU、内存、FD、Gunicorn worker 存活，建议用 node_exporter / cAdvisor / process-exporter。
- 增加外部黑盒探针：从客户访问路径探测 TLS、Nginx、登录页、`/api/health`。

## 3. Prometheus 告警规则建议

```yaml
groups:
  - name: guardian-saas-beta
    rules:
      - alert: GuardianWebApiDown
        expr: up{job="ai-security-guardian"} == 0
        for: 2m
        labels: {severity: critical}
        annotations:
          summary: "Guardian /metrics scrape failed"
          runbook: "docs/phase-c5-saas-operations-reliability.md#7-值班与故障升级手册"

      - alert: GuardianReadinessFailing
        expr: probe_success{job="guardian-readyz"} == 0
        for: 3m
        labels: {severity: critical}
        annotations:
          summary: "/readyz is failing from blackbox probe"

      - alert: GuardianApiP95High
        expr: histogram_quantile(0.95, sum by (le) (rate(guardian_http_request_duration_seconds_bucket{route=~"/api/.*"}[5m]))) > 0.3
        for: 10m
        labels: {severity: warning}
        annotations:
          summary: "API P95 latency is above 300ms"

      - alert: GuardianApi5xxHigh
        expr: sum(rate(guardian_http_requests_total{status_class="5xx"}[5m])) / clamp_min(sum(rate(guardian_http_requests_total[5m])), 0.001) > 0.02
        for: 5m
        labels: {severity: critical}
        annotations:
          summary: "API 5xx ratio above 2%"

      - alert: GuardianMetricsHeartbeatStale
        expr: time() - guardian_metrics_snapshot_updated_timestamp_seconds > 300
        for: 5m
        labels: {severity: warning}
        annotations:
          summary: "Guardian detection metrics heartbeat is stale"

      - alert: GuardianModelNotReady
        expr: guardian_model_ready < 1
        for: 3m
        labels: {severity: critical}
        annotations:
          summary: "No Guardian detection engine reports ready"

      - alert: GuardianRedisStreamLagHigh
        expr: redis_stream_group_lag > 1000 or redis_stream_pending > 100
        for: 10m
        labels: {severity: warning}
        annotations:
          summary: "Redis alert stream lag or pending backlog is high"

      - alert: GuardianAlertConsumerStalled
        expr: increase(guardian_redis_stream_writes_total{result="ok"}[10m]) > 0 and increase(guardian_alert_stream_consumed_total[10m]) == 0
        for: 10m
        labels: {severity: critical}
        annotations:
          summary: "Alerts are written to Redis but Web consumer is not acking"

      - alert: GuardianAlertConsumeLatencyHigh
        expr: guardian_alert_consume_latency_ms_max > 30000
        for: 5m
        labels: {severity: warning}
        annotations:
          summary: "Alert consume latency max is above 30s"

      - alert: GuardianRedisStreamWriteFailures
        expr: increase(guardian_redis_stream_writes_total{result="failed"}[5m]) > 0
        for: 1m
        labels: {severity: critical}
        annotations:
          summary: "Guardian failed to write alerts to Redis Stream"

      - alert: GuardianNotificationFailuresHigh
        expr: delta(guardian_response_actions_total{action_type="notify",status="failed"}[30m]) > 3
        for: 5m
        labels: {severity: warning}
        annotations:
          summary: "Notification failures are increasing"

      - alert: GuardianResponseActionFailures
        expr: delta(guardian_response_actions_total{status=~"failed|rejected"}[30m]) > 0
        for: 5m
        labels: {severity: critical}
        annotations:
          summary: "Response action failed or was rejected"

      - alert: GuardianAuditIntegrityFailed
        expr: audit_integrity_valid == 0
        for: 1m
        labels: {severity: critical}
        annotations:
          summary: "Security audit hash-chain integrity check failed"

      - alert: GuardianAuditPatrolStale
        expr: time() - audit_integrity_last_run_timestamp_seconds > 180
        for: 5m
        labels: {severity: warning}
        annotations:
          summary: "Audit integrity patrol has not run recently"
```

## 4. Grafana Dashboard 设计

Dashboard：`AI Security Guardian / SaaS Beta Operations`

| Row | Panel | Query / 指标 | 判断方式 |
|-----|-------|--------------|----------|
| Overview | Availability | API success ratio、blackbox `/readyz` | 绿色：>99.5%；红色：5xx 或 readyz fail |
| Overview | API P95 | `histogram_quantile(0.95, sum by (le)(rate(guardian_http_request_duration_seconds_bucket{route=~"/api/.*"}[5m])))` | 目标线 300ms |
| Overview | Open Incidents Signals | active critical alerts count | 汇总 critical 告警 |
| Web/API | Request Rate by Route | `sum by(route,status_class)(rate(guardian_http_requests_total[5m]))` | 找到慢/错接口 |
| Web/API | 5xx Ratio | 5xx / total | >2% 红色 |
| Detection | Packets and Alerts | `rate(guardian_packets_total[5m])`、`rate(guardian_alerts_total[5m])` | 检测链路是否有流量 |
| Detection | Detection Latency | `rate(guardian_detection_latency_ms_sum[5m]) / rate(guardian_detection_latency_ms_count[5m])` | 作为平均延迟 |
| Detection | Model Ready | `guardian_model_ready` | `<1` 红色 |
| Stream | Stream Lag | `redis_stream_group_lag`、`redis_stream_pending`、`redis_stream_length` | 持续增长需处理 |
| Stream | Consume Throughput | `rate(guardian_alert_stream_consumed_total[5m])` | 写入有量但消费为 0 是故障 |
| Stream | Consume Latency | `guardian_alert_consume_latency_ms_max`、平均消费延迟 | Max > 30s 预警 |
| Response | Notifications | `guardian_response_actions_total{action_type="notify"}` by status | failed 增长预警 |
| Response | Response Actions | `guardian_response_actions_total` by action/status | failed/rejected 红色 |
| Audit | Audit Integrity | `audit_integrity_valid`、`audit_integrity_patrol_runs_total` | 必须 1 且失败 0 |
| Infra | Redis/Web Process | node_exporter/cAdvisor/process-exporter | CPU、内存、重启、磁盘 |

建议变量：`env`、`tenant_id`（当前 `/metrics` 尚未按 tenant 暴露，后续可加）、`route`、`status_class`。

## 5. 健康判断标准

健康：

- `/healthz` 200，进程存活。
- `/readyz` 200 且 `status=ready`；短时 `degraded` 需要看 degraded 项。
- `/api/health` 200 且 `status=healthy`。
- API P95 < 300ms，5xx ratio < 2%。
- `guardian_model_ready >= 1`，metrics heartbeat 5 分钟内更新。
- `redis_stream_group_lag` 和 `redis_stream_pending` 不持续增长。
- `audit_integrity_valid == 1`，巡检在 3 分钟内运行过。

不健康：

- `/readyz` 503：数据库、Redis、模型或配置 fatal。
- `guardian_alert_stream_consumed_total` 不增长但 Stream writes 在增长。
- 审计完整性失败。
- 响应动作 `failed/rejected` 增长，尤其 `DRY_RUN=false` 时。

## 6. HA 方案

Beta 推荐架构：

- Nginx / LB 层：至少 2 个 Web/API 实例，使用健康检查 `/readyz` 摘除不健康实例。
- Web/API：每个实例 `WEB_CONCURRENCY=1`，横向多实例扩容；Socket.IO 需要粘性会话。若要跨实例广播，后续接入 Flask-SocketIO message queue。
- Redis：生产使用托管 Redis 或 Redis Sentinel/Cluster；启用持久化、内网访问、密码和监控。Stream `MAXLEN ~ 10000` 已保护内存，但仍需监控 lag。
- PostgreSQL：托管 HA PostgreSQL 或主从架构；发布前备份，定期恢复演练。
- Guardian 检测链路：抓包节点与 Web/API 分离。至少 2 个授权采集节点时，按网络分区或镜像端口分摊，避免重复封禁策略冲突。
- 模型交付：只读挂载，多实例使用同一版本制品；manifest/SHA256 纳入发布记录。
- 审计日志：本地写入同时建议采集到集中日志系统，防止单机磁盘丢失。

故障降级原则：

- Web/API 可读优先，真实响应动作默认继续由 `DRY_RUN=true` 保护。
- Redis 故障时生产应 fail closed：`REQUIRE_REDIS_AVAILABLE=true` 防止误以为 Stream 正常。
- 模型不 ready 时 `/readyz` fatal，LB 不应继续分流。

## 7. 值班与故障升级手册

### 7.1 分级

| 等级 | 触发 | 响应目标 |
|------|------|----------|
| SEV1 | 控制台/API 大面积不可用、审计完整性失败、真实响应动作失败、Redis Stream 完全停滞 | 15 分钟内响应，30 分钟内止血 |
| SEV2 | API P95 持续 >300ms、Stream lag 高、通知失败增长、模型 heartbeat stale | 30 分钟内响应，2 小时内恢复或给出缓解 |
| SEV3 | 单租户问题、非关键 Dashboard 面板异常、巡检偶发失败后恢复 | 1 个工作日内处理 |

### 7.2 首轮排查

```bash
curl -fsS http://127.0.0.1:5000/healthz
curl -fsS http://127.0.0.1:5000/readyz
curl -fsS http://127.0.0.1:5000/api/health
curl -fsS http://127.0.0.1:5000/metrics | head -n 80
docker compose ps
docker compose logs --tail=200 app
docker compose logs --tail=200 redis
python scripts/redis_stream_status.py --json
```

判断顺序：

1. `/healthz` 失败：进程或 LB 到实例路径故障，先重启/扩容 Web 实例。
2. `/readyz` fatal database：检查 `DATABASE_URL`、PostgreSQL 连接、迁移状态和连接池。
3. `/readyz` fatal redis：检查 Redis 密码、网络、内存、连接数；生产不要静默降级。
4. `/readyz` fatal models：检查模型目录、只读挂载、manifest 和权限。
5. `/metrics` stale：检查 Guardian 检测进程是否运行、Redis snapshot 是否可写。

### 7.3 Redis Stream lag

现象：`redis_stream_group_lag` 或 `redis_stream_pending` 持续增长。

处理：

```bash
python scripts/redis_stream_status.py --json
docker compose logs --tail=300 app | grep -i AlertConsumer
docker compose restart app
```

若重启后 pending 不回落，检查数据库写入是否失败。若 backlog 接近 Redis 内存上限，先扩容 Web consumer 实例或临时提高 Redis 内存，再定位慢 DB/慢 API。

升级：10 分钟无法回落升 SEV1。

### 7.4 API 延迟或 5xx

处理：

- 看 Grafana route 维度，确认是全局还是单接口。
- 检查 DB 慢查询、Redis 超时、通知 webhook 阻塞、CPU/内存。
- 先扩容 Web/API 或摘除异常实例，再定位代码路径。

升级：5xx > 2% 持续 5 分钟升 SEV1；P95 > 300ms 持续 10 分钟升 SEV2。

### 7.5 通知失败

处理：

- 查看 `guardian_response_actions_total{action_type="notify",status="failed"}`。
- 检查 SMTP/Webhook 配置、DNS、目标平台状态和 SSRF 安全拦截原因。
- 对客户侧 webhook 故障，通知客户切换备用通道。

升级：critical 告警通知连续失败升 SEV2；所有通道失败且存在真实攻击告警升 SEV1。

### 7.6 响应动作失败或误封

处理：

1. 立即确认 `.env` 中 `DRY_RUN` 与 `REAL_ENFORCEMENT_GATE`。
2. 若存在误封风险，先切回 `DRY_RUN=true` 并重启响应进程。
3. 按 `docs/deployment.md` 的防火墙误封恢复流程解封和加白。
4. 保留 `response_actions`、`audit_events`、`logs/security.log`、防火墙规则和变更单。

升级：真实封禁失败、误封业务 IP、无法解封均为 SEV1。

### 7.7 审计完整性失败

处理：

- 立即冻结日志清理、发布和手工改文件操作。
- 备份 `logs/security.log`、数据库 `audit_events`、容器日志。
- 执行 `run_audit_integrity_patrol_once` 或相关校验脚本确认 invalid lines。
- 安全负责人参与判断是否为篡改、磁盘损坏或日志轮转问题。

升级：始终 SEV1。

### 7.8 复盘

每个 SEV1/SEV2 需要记录：

- 起止时间、影响租户、影响接口、错误预算消耗。
- 首个告警、首个响应动作、止血动作、恢复动作。
- 根因、遗漏的监控、是否需要调整 SLO/告警阈值。
- 后续任务负责人和完成日期。

## 8. Phase C5 后续任务清单

- 将告警消费延迟改为 Prometheus histogram，支持真实 P95。
- 通知和响应动作增加写入时 counter，保留 DB gauge 作为对账指标。
- 增加 `/metrics` tenant label 的安全设计，避免高基数与租户信息泄漏。
- 添加 blackbox exporter 配置样例和 Grafana JSON dashboard。
- 接入 process-exporter/cAdvisor/node_exporter，补齐进程和容器级 SLI。
- 多 Web 实例 Socket.IO 广播使用 Redis message queue，消除单实例广播限制。
