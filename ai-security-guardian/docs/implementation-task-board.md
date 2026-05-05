# AI-Security-Guardian v0.8 → v1.0 实施看板

> 基线梳理日期：2026-04-28  
> 依据：《AI安全守卫-v1.0-交付验收与路线图.md》《AI安全守卫-v1.0-工程实施方案.md》《AI安全守卫-v1.0-生产落地技术方案.md》与当前仓库代码阅读结论。  
> 用途：指导后续分阶段改造，**不将未实现能力标为已完成**。

---

## 当前系统入口与运行方式

| 入口 | 命令 / 方式 | 说明 |
|------|-------------|------|
| Web / API / Socket.IO | `python -m web.app`（默认 `PORT=5000`） | Flask 工厂 `web/app.py::create_app`；JWT/CORS/限流；业务状态为进程内 `_ServerState`，**非数据库**。 |
| 完整检测链路（Guardian） | `python main.py` | `main.py::SecurityGuardian`：采集 → 威胁情报前置 → 特征 →（部分）检测 → 融合 → 响应 → 审计 → Redis Stream `guardian:alerts`。需抓包时用管理员权限或 `--no-packet-capture`。 |
| Docker（仅 Web） | `docker compose up --build` | 默认构建 `Dockerfile`，`CMD` 为 `python -m web.app`；依赖 healthy 的 `redis`。 |
| Docker（Web + Guardian） | `docker compose --profile full-chain up --build` | `guardian` 服务 `network_mode: host`、`python main.py`；`ENABLE_FLASK=false`，告警依赖 Redis Stream（**Web 侧当前未消费该流**，见下文）。 |

**关键环境变量（节选）**：`SECRET_KEY`、`ADMIN_PASSWORD_HASH`、`REDIS_*`、`DRY_RUN`、`MODEL_DIR`、`LOG_INTEGRITY_ENABLED`、`DATABASE_URL`（配置类已定义，**Web 尚未接 ORM 持久化**）。

---

## 代码事实差异（方案/文档 vs 当前代码）

以下为**仓库现状**，用于避免按文档误判“已交付”：

| 差异点 | 文档或 README 表述 | 代码事实 |
|--------|-------------------|----------|
| Web `src_ip` 透传 | 工程方案要求 Web 特征保留/透传 `src_ip`，告警可封禁来源 IP | `WebFeatureExtractor.extract()` **未写入** `src_ip`；`WebAttackDetector` 从 `features.get("src_ip","")` 读取，故在线 Web 路径上 **`source_ip` 常为空**（除非上游另行注入）。 |
| Redis Stream 消费 | 交付路线图：Guardian 写 Stream，Web 消费；工程方案目标链路入库 | Guardian `main.py` 调用 `redis.stream_add("guardian:alerts", …)`；**`web/app.py` 无任何 `stream_read_group`/后台 consumer**。跨进程告警依赖文档描述的 Stream **未在 Web 侧闭环**。 |
| 数据库持久化 | README/`Config` 出现 `DATABASE_URL`、交付要求告警/规则等入库 | `config/config.py` 定义 `SQLALCHEMY_DATABASE_URI`，**`create_app` 未初始化 Flask-SQLAlchemy 模型或迁移**；告警/规则/IOC 均在 `_ServerState` 内存中。 |
| R1 路线图归类 | 《生产落地技术方案》§9 将「Redis Stream 消费」写在 R1 一行 | 《工程实施方案》将 Stream consumer 纳入 **R2**。本看板按工程实施方案 **将 Stream 消费归入 R2**，并在「差异」中注明两文档归类不一致。 |
| docker-compose 注释 | guardian 通过 Redis 把告警给 app | 与代码一致方向（Guardian 写 Stream），但 **app 进程不读 Stream**，除非单独实现 consumer；仅靠同进程 `push_alert` 才能实时出现 Guardian 告警到 UI。 |
| 模型热更新 | 设置项 `model_hot_reload` / 文档热更新 | `main.py` **仅在启动时** `load_models()`；设置中的热更新 **未连接到检测进程**。 |
| 响应「定时解封」 | 文档：封禁时长与调度 | `SecurityResponder._ban_ip` 记录 `_banned_ips` 截止时间，**无后台调度**调用 `unban_ip`；iptables 层面未自动到期解封。 |

---

## v0.8 已实现能力（基线，便于对照差距）

- **采集**：`PacketCollector`、`LogCollector`（Web 日志）、`ThreatIntelCollector`（本地黑名单 + AbuseIPDB/VirusTotal/mock）。
- **特征**：`FlowFeatureExtractor`（五元组批量内聚合，≥2 包成流）、`WebFeatureExtractor`（多层解码与规则友好特征）、`FeaturePipeline`。
- **检测**：`DDoSDetector` / `IntrusionDetector` / `WebAttackDetector` / `AnomalyDetector`；单模型失败可跳过。
- **决策**：`FusionEngine`（加权 + 多引擎等级升级）。
- **响应**：`SecurityResponder` — `dry_run`、日志模拟告警、iptables 列表调用、`validate_ip`；**真实 SMTP/Webhook/隔离 API 未接**。
- **审计**：`SecurityLogger` JSON Lines + 哈希链 + 缓冲降级；完整性校验 API 存在。
- **Web**：JWT、CORS 白名单、限流、REST、Socket.IO 广播（**数据源为内存**）；Webhook 测试 URL 含 SSRF 基础过滤。
- **Redis**：`RedisClient` 含 Stream 读写与内存降级；**消费者仅在测试/smoke 中演练**。
- **部署**：`Dockerfile` 非 root、`docker-compose` 含 Redis healthcheck、Guardian profile。

---

## 明显风险点（合并三份文档与代码）

| 风险 | 说明 | 关联路线 |
|------|------|----------|
| 实时流特征不可用 / 不可靠 | `process_packet` 每包调用 `flow_extractor.extract([pkt])`，单包无法形成 ≥2 包的流；且 `extract` 末尾 `_flows.clear()`，**无法跨 tick 累积五元组**。网络检测链路与训练 NSL-KDD 41 维 **大量缺省填 0**。 | R1、R3 |
| Web 攻击告警缺乏来源 IP | 见「代码事实差异」，影响 F-02/F-07 与封禁有效性。 | R1 |
| 运营数据全内存 | 重启丢告警/规则/IOC/设置；与「持久化验收」冲突。 | R2 |
| 告警未经 DB 治理 | 无版本、无状态与历史表；报告为 `state` 聚合。 | R2、R5 |
| 响应误伤与高权限 | iptables 真实执行依赖 `DRY_RUN=false`；无审批链、无云防火墙抽象。 | R4 |
| 运维指标缺失 | 无 Prometheus 风格指标；Guardian 无 HTTP 健康详情。 | R5 |

---

## 优先级说明（P0 / P1 / P2）

- **P0**：不满足则无法满足 v1.0「检测可信 / 状态可恢复 / 核心验收」。
- **P1**：生产闭环与情报/模型运维主体能力。
- **P2**：规模化运维、CI/CD、压测与文档硬化。

---

## R1 检测链路可信任务清单

| ID | 任务 | 优先级 | 涉及文件（预期） | 验收标准 | 测试建议 |
|----|------|--------|------------------|----------|----------|
| R1-01 | 实现跨 tick 的流窗口聚合（批量/滑动窗口），替代「单包 extract + 立刻 clear」 | P0 | `main.py`，新建 `src/features/flow_window.py`（建议），`src/collectors/packet_collector.py`（队列背压可选） | 同一五元组跨多个 tick 输入后能输出 **至少 1 条**流特征；主循环按 `MAX_PACKETS_PER_TICK` 批处理 | 单元测试：3 包跨 2 tick；属性测试过期流策略；日志/计数器可查队列丢弃 |
| R1-02 | 定义并实现 `network_flow_v1` 字段（duration、速率、窗口内统计等），与 detectors 输入契约对齐 | P0 | `src/features/flow_features.py`，`src/detectors/ddos_detector.py`，`src/detectors/intrusion_detector.py`，`src/detectors/anomaly_detector.py` | 文档化 schema；缺字段时 **明确降级/错误**，禁止静默全 0 冒充生产可信 | 契约测试：特征列顺序与 manifest（配合 R3）一致 |
| R1-03 | Web 特征补齐 `src_ip`（及必要上下文字段）并与 `WebAttackDetector` 输入一致 | P0 | `src/features/web_features.py`，`main.py::process_web_log`，`src/collectors/log_collector.py`（字段映射） | 规则/ML 检出 Web 攻击时 `DetectionResult.source_ip` **非空**（日志含 IP 场景） | 集成：构造 access.log 行含攻击 payload + 客户端 IP |
| R1-04 | 检测主循环隔离延迟指标（每阶段耗时）与异常计数 | P1 | `main.py`，可选 `src/utils/metrics.py` | 日志或指标中可区分采集/特征/推理/响应耗时；单引擎异常不退出进程（保持现状并量化） | 压测脚本 + 断言日志字段或使用后续 R5 指标 |

---

## R2 状态持久化任务清单

| ID | 任务 | 优先级 | 涉及文件（预期） | 验收标准 | 测试建议 |
|----|------|--------|------------------|----------|----------|
| R2-01 | 引入数据库层：SQLAlchemy 模型与迁移（Alert、AlertHistory、Rule、IOC、Setting、ResponseAction、AuditEvent 等） | P0 | 新建 `src/models/` 或 `web/models.py`，`migrations/`，`config/config.py`，`requirements.txt` | `DATABASE_URL` 可指向 MySQL/SQLite；`flask db upgrade` 或等价迁移可重复执行 | 迁移集成测试；CI 使用临时 SQLite |
| R2-02 | Web 后台线程：Redis Stream consumer（`guardian:alerts`），入库成功后 **XACK** | P0 | `web/app.py` 或新建 `web/stream_consumer.py`，`src/utils/redis_client.py` | Guardian 写入 1 条 → Web 消费 → DB 可见 → pending 不堆积（正常负载） | 集成测试 Mock Redis 或内存模式 `RedisClient`；`_phase8_smoke` 扩展 |
| R2-03 | REST API 由 DB 查询；`_ServerState` 仅开发缓存或移除 | P0 | `web/app.py`（各 `/api/*`），repository 层 | **重启 Web 后**历史告警、规则、IOC、设置仍存在 | 重启容器/进程前后查询同一 `alert_id` |
| R2-04 | 告警状态流转写入 `AlertHistory` | P1 | 同上 + 模型 | `/api/alerts/<id>/status` 写入历史表可追溯 | API 测试 PUT status → DB 行数与内容 |
| R2-05 | 报告 `/api/reports/summary` 基于 DB 聚合，而非仅内存 deque | P1 | `web/app.py::_build_report_summary` 重构 | 大面积告警后重启进程，报告数字与 DB 一致 | 对比重启前后 summary |

---

## R3 模型治理任务清单

| ID | 任务 | 优先级 | 涉及文件（预期） | 验收标准 | 测试建议 |
|----|------|--------|------------------|----------|----------|
| R3-01 | 每模型 `manifest.json`（版本、schema、特征列、指标、训练来源） | P0 | `models/saved/**`，各 `src/detectors/*.py`，训练脚本 `models/train/*.py` | 加载时校验 manifest 与特征维度；**不匹配则拒绝上线该版本** | 伪造错误 manifest 应加载失败并保留旧模型 |
| R3-02 | `ModelRegistry`：当前指针、原子切换、失败回滚 | P0 | 新建 `src/models/registry.py`（命名勿与 DB models 冲突时可改为 `model_registry` 包） | 新文件损坏时旧模型继续服务；审计日志记录版本切换 | 集成测试替换 `model.pkl` 场景 |
| R3-03 | 推理记录 `model_version` / `schema_version` / `latency_ms`（入审计或 DB） | P1 | `main.py::_on_threat`，`src/detectors/base.py` | 任一模型告警可在日志或 DB 中追溯到版本 | 抽查 `security.log` 或 Alert 表字段 |
| R3-04 | 训练管线输出与在线 `network_flow_v1` / `web_request_v1` 一致 | P0 | `models/train/*`，特征模块 | 与 R1-02 联调通过 | 离线对比训练矩阵列与在线 dict keys |
| R3-05 | （可选）热更新：检测进程监听或周期校验 manifest + 原子切换 | P2 | `main.py`，信号或轮询 | 与设置 `model_hot_reload` 联动且不重复加载 | 长运行进程替换模型文件观测行为 |

---

## R4 响应闭环任务清单

| ID | 任务 | 优先级 | 涉及文件（预期） | 验收标准 | 测试建议 |
|----|------|--------|------------------|----------|----------|
| R4-01 | 真实通知：`AlertNotifier`（SMTP + Webhook），配置来自环境变量 | P1 | 新建 `src/response/notifier.py`，`src/response/responder.py`，`config/config.py` | medium+ 告警产生可验证外发记录（日志/测试桩） | Mock SMTP/Webhook；双因素：失败重试次数与审计 |
| R4-02 | `FirewallManager` 抽象：iptables / 未来云 API | P1 | `src/response/responder.py`，新建 `firewall/` | 响应动作可单测 mock，不全网依赖 iptables | 接口级单元测试 |
| R4-03 | 定时解封调度器（与 `_banned_ips` 到期时间一致） | P1 | 新建 `src/response/scheduler.py`，`main.py` 或独立线程 | high/critical 封禁到期自动 `unban` 或可配置 | 虚拟时间或短 TTL 集成测试 |
| R4-04 | `HostIsolationProvider` 接口 + critical 路径降级为人工待办 | P2 | `src/response/responder.py` | 未配置 provider 时不抛异常，有审计 | 无 provider 集成测试 |
| R4-05 | 响应动作入库 `ResponseAction` + 全链路审计 | P1 | DB 模型， `src/audit/security_logger.py` | 每条封禁/解封/通知可查 | 与 R2 联调 |

---

## R5 运维可观测任务清单

| ID | 任务 | 优先级 | 涉及文件（预期） | 验收标准 | 测试建议 |
|----|------|--------|------------------|----------|----------|
| R5-01 | Prometheus 兼容 `/metrics` 或独立 exporter | P1 | 新建 `web/metrics.py` 或 Guardian 侧 HTTP 可选 | 至少覆盖：`guardian_packets_total`、`guardian_detection_latency_ms`、`guardian_model_ready`、`redis_stream_pending`（定义见工程方案 §10.2） | curl `/metrics` 或抓取测试 |
| R5-02 | 审计哈希链定时巡检任务 + 失败告警通路 | P1 | `src/audit/security_logger.py`，计划任务（Celery/APScheduler/系统 cron） | `audit_integrity_valid` 可查询；异常产生 **可观测** 告警 | 篡改 `security.log` 一行后巡检失败 |
| R5-03 | CI/CD：pytest、smoke、安全用例（JWT/CORS/SSRF） | P2 | `.github/workflows/` 或等价 | PR 必须通过 P0/P1 相关测试 | 流水线绿建 |
| R5-04 | Guardian 健康信号（队列长度、最近检测时间） | P2 | `main.py`，可选小型 HTTP admin port | full-chain 部署可判断 Guardian 存活与积压 | compose healthcheck 扩展或 sidecar |
| R5-05 | 情报 IOC 定时同步、TTL、多源合并（生产化） | P1 | `src/collectors/threat_intel.py`，DB，`cron`/worker | 过期 IOC 不命中；外部 API 超时 **不阻塞**主链路 | Mock 超时与 TTL 单元测试 |

---

## 文档与配置待对齐（非业务代码，后续可做）

- 统一 README 与《生产落地技术方案》中对 **R1 是否包含 Redis 消费** 的表述，避免团队分工歧义。
- `.env.example` 与实现同步列出 DB、通知、隔离 provider 等新变量（待 R2/R4 落地时更新）。

---

## 建议实施顺序（与工程实施方案 §11 对齐）

1. **R1**：流窗口 + Web `src_ip` + schema 契约雏形。  
2. **R2**：DB + Redis Stream consumer + API 切换。  
3. **R3**：manifest + ModelRegistry + 训练/在线一致。  
4. **R4**：通知、防火墙抽象、定时解封、响应入库。  
5. **R5**：指标、巡检、CI/CD、情报同步硬化。

---

**本看板跟踪方式建议**：在 issue 或 Cursor 会话中引用任务 ID（如 `R2-02`），完成后更新本文档状态列（若团队采用勾选清单，可增加「状态」列自行维护）。
