# AI安全守卫 v1.0 工程实施方案

> 版本：v1.0  
> 日期：2026-04-27  
> 定位：面向工程团队的生产化改造实施文档  
> 原则：基于当前代码渐进改造，不推倒重来；未实现能力以路线图形式落地。

---

## 1. 实施目标

本方案将当前 `ai-security-guardian` 原型改造为生产 v1.0 防护系统。工程实施重点是：

1. 让实时检测链路真正闭环。
2. 让训练、特征、推理 schema 一致。
3. 让 Web 控制台从内存态迁移到数据库持久化。
4. 让响应动作具备通知、回滚、审计和安全边界。
5. 让部署、监控、测试满足生产准入。

## 2. 当前代码基础

| 子系统 | 当前基础 | 工程判断 |
|---|---|---|
| `main.py` | 串联采集、特征、检测、融合、响应、审计、Redis Streams | 主控骨架可保留，但实时流处理方式需改造 |
| `src/collectors` | 抓包、日志、威胁情报查询 | 需要补批量窗口、系统日志业务化、情报同步 |
| `src/features` | Flow/Web 特征和通用 FeaturePipeline | 需要定义生产 schema 和适配模型输入 |
| `src/detectors` | 四类检测器 | 需要模型注册、热更新、schema 校验 |
| `src/decision` | 融合决策 | 需要配置化策略和资产上下文 |
| `src/response` | dry-run、iptables 封禁/解封、日志告警 | 需要真实通知、限速、隔离、调度器 |
| `src/audit` | JSON Lines、哈希链、缓冲 | 需要入库、巡检任务、报表数据源 |
| `web/app.py` | Flask 控制台、JWT、API、Socket.IO | 需要拆分业务层、数据库模型和 Redis 告警消费 |
| Docker | Web/API、Redis、Guardian profile | 需要生产环境变量校验、数据库、监控与健康检查 |

## 3. P0：实时检测链路改造

### 3.1 问题

当前 `main.py` 中 `process_packet()` 对单个包调用 `FlowFeatureExtractor.extract([pkt])`。但 `FlowFeatureExtractor` 只输出包数不少于 2 的流，并在每次 `extract()` 后清空内部状态，导致实时单包入口很难生成有效流特征。

### 3.2 改造目标

将逐包推理改为批量/滑动窗口推理：

```text
PacketCollector queue
  -> packet batch
  -> FlowWindowAggregator
  -> network_flow_v1 feature list
  -> DDoS / Intrusion / Anomaly detectors
  -> FusionEngine
```

### 3.3 实施要求

- 新增流窗口聚合器，维护五元组状态，按时间窗口或最小包数输出流特征。
- `main.py` 主循环每 tick 从队列读取最多 `MAX_PACKETS_PER_TICK` 个包后统一处理。
- `FlowFeatureExtractor` 不再在单包场景下清空跨 tick 状态，或新增专用窗口聚合类避免改变现有单元测试语义。
- 输出 `flow_duration`、`flow_pkt_rate`、`flow_byte_rate`、`window_unique_dst_ip`、`window_unique_dst_port`、`window_protocol_dist`。
- 对过期流、单包流、畸形时间戳做可控降级。

### 3.4 测试重点

- 3 个包同一五元组跨 tick 输入时能输出 1 条流特征。
- 单包流在超时前保留，超时后按策略丢弃或输出低置信特征。
- 高吞吐下队列满时记录丢包计数，不阻断主循环。

## 4. P0：特征与模型 schema 一致性

### 4.1 问题

DDoS 和入侵检测器当前按 NSL-KDD 41 维或训练保存的 `feature_columns` 取值，在线流特征缺失大量字段时会被填 0，模型结果不可信。

### 4.2 改造目标

建立生产 schema 契约：

| Schema | 生产用途 |
|---|---|
| `network_flow_v1` | DDoS、入侵、异常检测 |
| `web_request_v1` | Web 攻击检测 |
| `system_behavior_v1` | 系统/用户行为异常 |
| `ioc_match_v1` | 情报命中 |

### 4.3 实施要求

- 为每个模型保存 `model_manifest.json`，包含模型名、版本、schema、特征列、训练数据、指标、创建时间。
- 检测器加载模型时同时加载 manifest，并校验在线特征是否满足 schema。
- 训练脚本统一使用生产 schema 生成训练矩阵。
- 若继续使用 NSL-KDD 模型，则新增 `NSLKDDAdapter`，明确哪些字段可从在线流计算，哪些字段不可用；不可用字段不得静默填 0 后宣称生产可用。
- Web 特征保留 `src_ip`，确保响应层可封禁来源 IP。

### 4.4 测试重点

- schema 缺字段时检测器返回明确错误或降级结果。
- 训练保存的 feature columns 与在线推理输入顺序一致。
- Web 攻击命中后 `DetectionResult.source_ip` 非空。

## 5. P0：Redis 告警消费与 Web 持久化

### 5.1 问题

Guardian 已向 Redis Streams 写入告警，但 Web 侧主要使用进程内 `_ServerState`，告警、规则、IOC、设置、报告重启丢失。

### 5.2 改造目标

```text
Guardian -> Redis Stream guardian:alerts -> Web Consumer -> DB -> Socket.IO -> UI
```

### 5.3 实施要求

- 新增数据库模型：Alert、AlertHistory、Rule、IOC、Setting、ResponseAction、AuditEvent、ModelVersion。
- Web 启动后台 consumer，读取 `guardian:alerts`，入库成功后 ack。
- Socket.IO 只广播入库后的规范化告警。
- REST API 从数据库查询，不再依赖进程内 `_ServerState` 作为唯一数据源。
- `_ServerState` 可保留为开发模式缓存，但生产模式禁用或只做读缓存。

### 5.4 测试重点

- Redis Stream 中 1 条告警被 Web 消费后入库并 ack。
- Web 重启后历史告警仍可查询。
- 告警状态流转写入 AlertHistory。

## 6. P1：响应闭环

### 6.1 当前能力

当前响应层支持：

- low/medium/high/critical 分级处理。
- dry-run 模式。
- iptables 封禁和解封。
- IP 输入严格校验，避免命令注入。

### 6.2 生产改造

- 新增 `AlertNotifier`，支持 SMTP、Webhook、企业通知通道。
- 新增 `ResponseScheduler`，负责定时解封和响应重试。
- 新增 `FirewallManager` 抽象层，封装 iptables、Windows 防火墙、云安全组。
- 新增 `HostIsolationProvider`，对接 EDR Agent 或云主机隔离。
- 所有响应动作写入 `ResponseAction` 表和审计日志。

### 6.3 响应策略

| level | 自动动作 | 人工动作 |
|---|---|---|
| low | 记录 | 无 |
| medium | 通知 | 确认/忽略 |
| high | 通知、临时封禁、限速 | 解封/升级 |
| critical | 通知、封禁、隔离建议 | 隔离审批/应急处置 |

### 6.4 测试重点

- Webhook 失败有重试和失败审计。
- high 级别封禁后产生定时解封任务。
- critical 隔离未配置 provider 时降级为人工待办。

## 7. P1：威胁情报生产化

### 7.1 当前能力

当前已支持本地 IP/域名黑名单、AbuseIPDB 查询、VirusTotal IP/域名详细查询、mock 查询。

### 7.2 生产改造

- 引入 IOC 数据模型：type、value、source、score、ttl、first_seen、last_seen、expires_at。
- 支持 AbuseIPDB、VirusTotal、Spamhaus、PhishTank、OpenPhish、NVD、CNVD。
- 支持 IP、域名、URL、文件哈希、CVE 五类 IOC。
- 定时同步任务写入数据库，查询时先查本地库再远端查询。
- 与检测链路前置过滤集成，命中 IOC 直接生成高置信告警。

### 7.3 测试重点

- IOC 过期后不再命中。
- 多来源同一 IOC 合并 sources 和最高分。
- 外部 API 超时不会阻断检测链路。

## 8. P1：模型生命周期

### 8.1 改造目标

生产模型必须可追踪、可热更新、可回滚、可评估。

### 8.2 实施要求

- 模型目录结构：

```text
models/saved/
  ddos/
    v1/
      model.pkl
      manifest.json
      pipeline.pkl
    current -> v1
```

- `ModelRegistry` 负责加载当前版本、校验 manifest、切换版本。
- 热更新采用“先加载新版本，成功后原子切换”策略。
- 模型推理记录 engine、model_version、schema_version、confidence、latency_ms。
- 人工处置结果回流到模型评估表。

### 8.3 测试重点

- 新模型加载失败时旧模型继续服务。
- 回滚后推理结果记录旧版本号。
- manifest schema 不匹配时拒绝上线。

## 9. P1：审计与报告

### 9.1 当前能力

当前已有安全日志、响应日志、系统日志、哈希链完整性校验。

### 9.2 生产改造

- 审计事件同步入库，文件日志作为防篡改链路。
- 报告从数据库聚合生成，不使用内存态即席统计。
- 报告导出：`GET /api/reports/export?period=day|week|month&format=json|html`（JWT）；HTML 可在浏览器中打印为 PDF。服务端 PDF（WeasyPrint / headless Chromium 等）列为后续增强，依赖缺失时不阻塞上线。
- 增加完整性巡检任务，巡检失败生成 critical 告警。

### 9.3 报告内容

- 监控周期概览。
- 告警数量、等级分布、类型分布。
- 攻击来源 Top10。
- 响应动作和封禁列表。
- 模型版本与检测质量。
- 未处理风险与加固建议。

## 10. P2：运维与部署

### 10.1 部署改造

- docker-compose 增加数据库服务或外部数据库连接说明。
- Web/API 与 Guardian 服务拆分健康检查。
- Guardian 暴露内部健康指标：采集状态、模型状态、队列长度、最近检测时间。
- Nginx 统一 TLS、WSS、反向代理和访问控制。

### 10.2 监控指标

| 指标 | 说明 |
|---|---|
| `guardian_packets_total` | 采集包数 |
| `guardian_packets_dropped_total` | 丢包数 |
| `guardian_detection_latency_ms` | 检测延迟 |
| `guardian_alerts_total` | 告警数 |
| `guardian_model_ready` | 模型就绪状态 |
| `redis_stream_pending` | 未 ack 消息 |
| `audit_integrity_valid` | 审计完整性状态 |

### 10.3 CI/CD

- 单元测试：采集、特征、检测器、响应、审计。
- 集成测试：Redis Stream、数据库、Web API、主链路 smoke。
- 安全测试：命令注入、JWT 保护、CORS、SSRF、默认密码。
- 文档检查：README、部署说明、环境变量说明同步。

## 11. 推荐实施顺序

| 顺序 | 阶段 | 交付 |
|---|---|---|
| 1 | 实时链路修复 | 批量流聚合、Web `src_ip` 透传 |
| 2 | Redis + DB 持久化 | 告警入库、Web 查询改造 |
| 3 | schema 与模型治理 | manifest、模型注册、热更新 |
| 4 | 响应闭环 | 通知、限速、定时解封、隔离 provider |
| 5 | 情报生产化 | IOC 持久化、定时同步、多源情报 |
| 6 | 报告与监控 | 数据库报表、指标、巡检 |
| 7 | 上线硬化 | Nginx/TLS、CI/CD、压测、准入验收 |

## 12. 工程验收标准

- `python -m pytest -q` 在可写临时目录下通过。
- Guardian 可处理连续包流并生成网络流特征。
- Web 攻击告警包含来源 IP。
- Redis Stream 告警可被 Web 消费、入库、ack、推送。
- Web 重启后告警、规则、IOC、设置不丢失。
- 模型加载失败不会导致进程退出。
- 生产环境缺少关键密钥时启动失败。
- 所有响应动作均可审计、可回滚或可人工处置。
