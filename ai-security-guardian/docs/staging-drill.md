# Redis / Guardian / Web / DB 全链路预发演练

本文档用于验证告警从 Guardian 写入 Redis Stream，到 Web consumer 消费、入库、ack、WebSocket 推送，再到 Web 重启后历史可查的完整链路。默认单元测试不依赖真实 Redis；真实 Redis 演练通过脚本或 `integration` 测试显式执行。

## 前置条件

1. 启动 Redis 与 Web 依赖：

   ```bash
   docker compose up -d redis
   ```

2. 若 Redis 设置密码，确认环境变量与 `redis-cli -a` 一致：

   ```bash
   $env:REDIS_HOST="127.0.0.1"
   $env:REDIS_PORT="6379"
   $env:REDIS_PASSWORD="<your-password>"
   ```

3. 生产或预发使用文件数据库，避免重启后历史只存在内存中：

   ```bash
   $env:DATABASE_URL="sqlite:///data/staging-drill.db"
   $env:AUTO_CREATE_DB_TABLES="true"
   ```

## 一键演练

脚本默认使用隔离 Stream，避免污染正式 `guardian:alerts`：

```bash
python scripts/staging_drill.py --cleanup
```

如需演练实际默认 Stream：

```bash
python scripts/staging_drill.py --stream guardian:alerts --group guardian:web
```

脚本会完成以下断言：

- `SecurityGuardian._on_threat()` 写入 Redis Stream。
- `GuardianAlertStreamConsumer` 读取 Stream，写入 `alerts` / `alert_histories`，成功后 `XACK`。
- Socket.IO 收到 `alert` 事件。
- 重复投递同一 `alert_id` 不产生重复告警行。
- 重新创建 Web app 后，同一数据库仍能通过 `/api/alerts` 查到历史告警。
- `XPENDING` 归零，说明没有持续未 ack 堆积。

## redis-cli 观测命令

无密码：

```bash
redis-cli XLEN guardian:alerts
redis-cli XINFO STREAM guardian:alerts
redis-cli XINFO GROUPS guardian:alerts
redis-cli XPENDING guardian:alerts guardian:web
redis-cli XPENDING guardian:alerts guardian:web - + 20
redis-cli XINFO CONSUMERS guardian:alerts guardian:web
```

有密码：

```bash
redis-cli -a "$REDIS_PASSWORD" XLEN guardian:alerts
redis-cli -a "$REDIS_PASSWORD" XPENDING guardian:alerts guardian:web
redis-cli -a "$REDIS_PASSWORD" XINFO GROUPS guardian:alerts
```

判定标准：

- `XLEN` 可以存在历史值，但应受 Guardian `MAXLEN` 控制，不应持续单调暴涨。
- `XPENDING guardian:alerts guardian:web` 的第一列应在消费完成后回到 `0`。
- 若 `XPENDING` 长时间大于 `0`，检查 Web consumer 日志、数据库连接、以及是否有旧 consumer 崩溃后留下 PEL；Web consumer 会读取自身 pending，并通过 `XAUTOCLAIM` 回收空闲 pending。

## 集成测试

默认测试不需要真实 Redis：

```bash
python -m pytest tests/test_alert_stream_consumer_smoke.py
```

真实 Redis 集成测试需显式打开 `integration`：

```bash
$env:GUARDIAN_REDIS_DISABLE_CONNECT="false"
$env:REDIS_TEST_DB="15"
python -m pytest tests/test_alert_stream_redis.py -m integration
```

这些测试覆盖 Web consumer 入库/ack、重复消息幂等、Web app 重建后历史查询、Socket.IO 推送。Redis 不可达时会跳过，不会污染默认单元测试。

## 手工故障演练

1. 暂停 Web consumer 或停止 Web。
2. 触发 Guardian 告警。
3. 观测：

   ```bash
   redis-cli XPENDING guardian:alerts guardian:web
   ```

4. 恢复 Web，确认 `XPENDING` 回到 `0`，`/api/alerts` 可查到告警。

重复消费风险的验收点是：同一 `alert_id` 对应 `alerts.id` / `alerts.external_id` 唯一，重复 Stream 消息只更新同一行，不新增多行。
