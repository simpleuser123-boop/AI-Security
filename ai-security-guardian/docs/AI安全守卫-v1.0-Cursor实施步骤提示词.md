# AI安全守卫 v1.0 Cursor 实施步骤提示词

> 版本：v1.0  
> 日期：2026-04-27  
> 来源：基于《AI安全守卫 v1.0 交付验收与路线图》《AI安全守卫 v1.0 工程实施方案》《AI安全守卫 v1.0 生产落地技术方案》整理。  
> 用途：将生产化路线图拆成可复制到 Cursor 的分阶段实施提示词，便于按 R1-R5 顺序推进开发、测试和验收。

---

## 使用说明

1. 建议从“提示词 00”开始，让 Cursor 先建立基线认知和任务清单。
2. 每次只复制一个提示词到 Cursor，完成、测试、提交后再进入下一步。
3. 如果 Cursor 发现现有实现与提示词假设不一致，应优先以代码事实为准，并更新实现计划。
4. 每个提示词都要求 Cursor 先阅读相关文件，再做最小必要改动，避免推倒重来。
5. 每阶段完成后至少运行 `python -m pytest -q`；涉及 Web/API、Redis、数据库、Docker 的阶段需补充集成验证。

---

## 提示词 00：建立生产化改造基线与任务看板

```text
你现在负责把 ai-security-guardian 从 v0.8 原型渐进改造为生产 v1.0。请先不要大规模改代码，先完成代码基线梳理、风险确认和任务拆分。

背景文档：
- docs/AI安全守卫-v1.0-交付验收与路线图.md
- docs/AI安全守卫-v1.0-工程实施方案.md
- docs/AI安全守卫-v1.0-生产落地技术方案.md

目标：
1. 阅读 README、main.py、web/app.py、src/collectors、src/features、src/detectors、src/decision、src/response、src/audit、docker-compose.yml、Dockerfile、requirements.txt。
2. 对照三份方案文档，确认当前代码中 R1-R5 的已实现能力、未实现能力、明显风险点。
3. 生成 docs/implementation-task-board.md，作为后续开发看板。

输出要求：
1. 文档必须包含这些栏目：
   - 当前系统入口与运行方式
   - R1 检测链路可信任务清单
   - R2 状态持久化任务清单
   - R3 模型治理任务清单
   - R4 响应闭环任务清单
   - R5 运维可观测任务清单
   - P0/P1/P2 优先级
   - 每项任务的涉及文件、验收标准、测试建议
2. 不要把未实现功能写成已完成。
3. 如果发现方案文档与代码不一致，请在“代码事实差异”小节列出。
4. 不要修改业务代码，除非是修正明显文档路径或拼写错误。

验收：
- docs/implementation-task-board.md 已生成。
- 文档能指导后续 Cursor 分阶段实施。
- 不引入业务代码变更。
```

---

## 提示词 01：R1 网络流量检测链路批量/滑动窗口改造

```text
请实施 R1 的核心任务：让实时网络包从“逐包直接推理”改为“批量/滑动窗口聚合后推理”，确保连续 TCP/UDP/ICMP 流可以形成稳定 flow 特征并进入检测器。

请先阅读：
- main.py
- src/collectors/*
- src/features/*
- src/detectors/*
- tests/*
- docs/AI安全守卫-v1.0-工程实施方案.md 中 “P0：实时检测链路改造”

问题背景：
当前 main.py 可能对单个 packet 调用 FlowFeatureExtractor.extract([pkt])。如果 FlowFeatureExtractor 只输出包数不少于 2 的流，并且 extract 后清空状态，实时单包入口会导致有效流特征很难生成。

实施目标：
1. 新增或改造 FlowWindowAggregator，维护五元组状态。
2. main.py 主循环每个 tick 从采集队列读取最多 MAX_PACKETS_PER_TICK 个包，批量送入聚合器。
3. 聚合器按最小包数、窗口时间、流超时输出 network_flow_v1 特征。
4. 输出特征至少包含：
   - src_ip、dst_ip、src_port、dst_port、protocol
   - packet_count、byte_count
   - flow_duration
   - flow_pkt_rate
   - flow_byte_rate
   - window_unique_dst_ip
   - window_unique_dst_port
   - window_protocol_dist
5. 单包流在超时前保留；超时后按配置丢弃或输出低置信特征，但行为必须有测试覆盖。
6. 主循环中单个包、单个流、单个检测器异常不能拖垮整体循环，需要记录错误并继续。

约束：
1. 优先保持现有 FlowFeatureExtractor 单元测试语义。如果直接修改会破坏大量测试，请新增专用聚合类。
2. 不要改变检测器对 DetectionResult 的公开契约，除非同步更新所有调用方和测试。
3. 增加配置项时优先放在现有配置体系或环境变量读取位置，不要散落硬编码。

测试要求：
1. 增加单元测试：同一五元组 3 个包跨 tick 输入后能输出 1 条 flow 特征。
2. 增加单元测试：单包流超时前不输出或按策略输出，行为确定。
3. 增加单元测试：高吞吐队列满或批量读取异常时记录丢包/错误计数，不阻断主循环。
4. 运行 python -m pytest -q。

完成后请总结：
- 新增/修改的文件
- 实时链路的新数据流
- 已通过的测试
- 尚未覆盖的风险
```

---

## 提示词 02：R1 Web 日志特征保留 src_ip 并打通响应来源

```text
请实施 R1 的 Web 检测链路补齐：确保 Web 攻击检测告警包含来源 IP，并能被融合、响应、审计链路使用。

请先阅读：
- src/collectors 中 Web/access log 解析相关代码
- src/features 中 WebFeatureExtractor 或 Web 特征相关代码
- src/detectors 中 WebAttackDetector
- src/decision
- src/response
- web/app.py 中告警展示和 API 相关逻辑
- docs/AI安全守卫-v1.0-交付验收与路线图.md 中 F-02、F-07、验收测试场景

实施目标：
1. Web 日志采集事件必须保留 src_ip、url、method、status_code、response_size、user_agent、timestamp。
2. WebFeatureExtractor 输出 web_request_v1 特征时必须保留 src_ip，不得在特征转换中丢失。
3. WebAttackDetector 命中 SQLi、XSS、命令注入、路径遍历时，DetectionResult.source_ip 必须非空。
4. FusionEngine 合并结果后仍保留 source_ip。
5. 响应层处理 high/critical Web 攻击时能读取 source_ip，生成可审计的封禁或 dry-run 记录。
6. Web 控制台/API 返回告警时包含来源 IP 字段。

安全要求：
1. source_ip 必须做 IP 格式校验；无效 IP 不得进入真实封禁命令。
2. 不允许 subprocess 使用 shell=True。
3. 如果来源 IP 缺失，需要生成降级告警并说明无法自动响应的原因。

测试要求：
1. 增加 Web access.log 解析测试：解析后 src_ip 正确。
2. 增加 WebFeatureExtractor 测试：src_ip 在特征中保留。
3. 增加 WebAttackDetector 测试：SQLi、双层编码 XSS、命令注入、路径遍历均产生 high 告警，source_ip 非空。
4. 增加响应 dry-run 测试：high Web 告警会生成包含 source_ip 的响应动作记录。
5. 运行 python -m pytest -q。

完成后请给出验收映射：
- F-02 Web 攻击检测
- F-07 响应动作
- S-05 命令注入防护
```

---

## 提示词 03：R2 数据库模型与迁移基础

```text
请实施 R2 的数据库持久化基础：为 Web 控制台引入生产 v1.0 所需的数据模型和初始化机制，但先不要一次性重写所有 API。

请先阅读：
- web/app.py
- 当前是否已有 db、models、migrations、SQLAlchemy 相关实现
- requirements.txt
- docker-compose.yml
- docs/AI安全守卫-v1.0-工程实施方案.md 中 “P0：Redis 告警消费与 Web 持久化”
- docs/AI安全守卫-v1.0-生产落地技术方案.md 中 “状态持久”“安全审计层”“可视化与交互层”

实施目标：
1. 引入数据库配置，支持 SQLite 开发模式和生产数据库 URL。
2. 新增数据模型：
   - Alert
   - AlertHistory
   - Rule
   - IOC
   - Setting
   - ResponseAction
   - AuditEvent
   - ModelVersion
3. 为 Alert 设计字段：
   - id、external_id、timestamp、source_ip、target_ip、threat_type、level、confidence、engine、status、summary、raw_payload、model_version、created_at、updated_at
4. 为 AlertHistory 设计字段：
   - alert_id、from_status、to_status、operator、note、created_at
5. 为 ResponseAction 设计字段：
   - alert_id、action_type、target、status、dry_run、error、scheduled_unblock_at、created_at、updated_at
6. 增加数据库初始化命令或启动初始化逻辑，确保开发环境可一键创建表。
7. 更新 .env.example，加入 DATABASE_URL 等必要变量。

约束：
1. 现有内存态 _ServerState 可以暂时保留，但必须明确它只是开发缓存或兼容层。
2. 不要破坏现有登录、健康检查、静态页面路由。
3. 生产环境关键配置缺失时应该显式失败或给出清晰错误。

测试要求：
1. 增加模型创建测试：所有表能创建成功。
2. 增加 Alert 写入与查询测试。
3. 增加 AlertHistory 状态流转写入测试。
4. 运行 python -m pytest -q。

完成后请说明：
- 使用的 ORM/迁移方式
- 开发环境如何初始化数据库
- 哪些 API 仍未迁移到数据库
```

---

## 提示词 04：R2 Redis Stream Consumer、告警入库与 Socket.IO 推送

```text
请实施 R2 的告警持久化链路：Guardian 写 Redis Stream 后，Web 侧消费、入库、ack，并推送到 Socket.IO。

请先阅读：
- main.py 中 Redis Stream 写入逻辑
- web/app.py 中 Socket.IO、告警 API、_ServerState
- Redis 相关配置
- tests 中已有 Redis 或 Web 测试
- docs/AI安全守卫-v1.0-工程实施方案.md 中 5.2 链路图

目标链路：
Guardian -> Redis Stream guardian:alerts -> Web Consumer -> DB -> Socket.IO -> UI

实施要求：
1. Web 启动后台 consumer，支持 consumer group。
2. 读取 guardian:alerts 后，先规范化 payload，再写入 Alert 表。
3. 入库成功后 ack；入库失败不得 ack，需要记录错误并可重试。
4. Socket.IO 只广播已入库的规范化告警。
5. REST API 查询告警时优先查数据库，不再依赖 _ServerState 作为唯一数据源。
6. 增加 pending/retry 处理，避免 Redis Stream 消费失败后永久丢失。
7. Web 关闭或测试环境下，后台线程/任务应可干净停止，避免测试挂起。

幂等要求：
1. 如果 Redis 消息包含唯一告警 ID，Alert.external_id 应做唯一约束或幂等处理。
2. 重复消费同一消息不得生成重复告警。

测试要求：
1. 增加 Redis Stream 消费集成测试：写入 1 条 guardian:alerts，Web consumer 入库并 ack。
2. 增加重复消息测试：不会重复入库。
3. 增加 Web 重启模拟测试：历史告警仍可通过 API 查询。
4. 增加 Socket.IO 推送可以用 mock 或测试客户端验证。
5. 运行 python -m pytest -q。

完成后请总结：
- consumer 启停方式
- ack 与失败重试策略
- API 从内存态迁移到数据库的范围
```

---

## 提示词 05：R3 特征 Schema 契约与模型 Manifest

```text
请实施 R3 的第一步：建立特征 schema 契约和模型 manifest 校验，让训练、在线特征、推理输入可追踪且一致。

请先阅读：
- src/features/*
- src/detectors/*
- models 或模型保存目录
- 训练脚本，如 scripts/train*、src 中训练相关文件
- docs/AI安全守卫-v1.0-工程实施方案.md 中 “P0：特征与模型 schema 一致性”
- docs/AI安全守卫-v1.0-生产落地技术方案.md 中 “特征工程层”“威胁检测层”

实施目标：
1. 定义并版本化 schema：
   - network_flow_v1
   - web_request_v1
   - system_behavior_v1
   - ioc_match_v1
2. 每个 schema 明确 required fields、optional fields、类型、默认策略、禁止静默填充字段。
3. 新增 model_manifest.json 规范，至少包含：
   - model_name
   - version
   - schema_name
   - schema_version
   - feature_columns
   - training_dataset
   - metrics
   - created_at
   - artifact_files
4. 检测器加载模型时必须加载 manifest，并校验在线输入字段与 feature_columns。
5. schema 不匹配时，检测器应返回明确降级结果或拒绝加载模型，不得静默填 0 后宣称生产可用。
6. 如果继续兼容 NSL-KDD 模型，请新增 NSLKDDAdapter，明确可映射字段与不可映射字段。

约束：
1. 不要求一次性重训所有模型，但必须让模型可信边界清晰。
2. 规则型 WebAttackDetector 应继续可用。
3. 任何降级都要进入日志或审计，便于验收。

测试要求：
1. schema 缺 required field 时校验失败。
2. feature_columns 顺序与在线推理矩阵顺序一致。
3. manifest 缺失或 schema 不匹配时，模型拒绝上线或降级到规则模式。
4. Web 告警仍包含 source_ip。
5. 运行 python -m pytest -q。

完成后请输出：
- schema 文件位置
- manifest 示例
- 当前哪些模型是生产可信，哪些仅原型可用
```

---

## 提示词 06：R3 ModelRegistry、热更新、回滚与推理指标

```text
请实施 R3 的第二步：新增 ModelRegistry，支持模型版本加载、热更新、失败保留旧版本、回滚和推理指标记录。

请先阅读：
- src/detectors/*
- 模型加载相关代码
- docs/AI安全守卫-v1.0-工程实施方案.md 中 “P1：模型生命周期”
- docs/AI安全守卫-v1.0-交付验收与路线图.md 中 R3 验收项

目标目录结构：
models/saved/
  ddos/
    v1/
      model.pkl
      manifest.json
      pipeline.pkl
    current -> v1

实施要求：
1. 新增 ModelRegistry，负责：
   - 发现模型版本
   - 加载 manifest
   - 校验 schema
   - 加载 artifact
   - 获取 current 版本
   - 原子切换版本
   - 回滚到上一可用版本
2. 检测器通过 ModelRegistry 获取模型，不再各自散落加载逻辑。
3. 新模型加载失败时，旧模型继续服务，并记录错误。
4. 每条模型检测结果记录：
   - engine
   - model_version
   - schema_version
   - confidence
   - latency_ms
5. 模型切换、回滚、加载失败进入 AuditEvent 或审计日志。

约束：
1. current 在 Windows 上如果不能使用 symlink，应支持 current.txt 或配置文件方式。
2. 不要让模型加载失败导致整个 Guardian 或 Web 进程退出。
3. 保留规则引擎兜底能力。

测试要求：
1. 新模型加载成功后切换到新版本。
2. 新模型加载失败时旧版本继续服务。
3. 回滚后推理结果记录回滚后的版本号。
4. manifest schema 不匹配时拒绝上线。
5. 运行 python -m pytest -q。

完成后请说明：
- ModelRegistry API
- 当前接入了哪些检测器
- 仍需重训或补齐 manifest 的模型
```

---

## 提示词 07：R4 响应闭环：通知、FirewallManager、定时解封与审计

```text
请实施 R4 响应闭环第一阶段：让 high/critical 告警产生可审计、可回滚、可降级的响应动作。

请先阅读：
- src/response/*
- src/audit/*
- web/app.py 中告警状态和操作 API
- docs/AI安全守卫-v1.0-工程实施方案.md 中 “P1：响应闭环”
- docs/AI安全守卫-v1.0-生产落地技术方案.md 中 “防护响应层”

实施目标：
1. 新增 AlertNotifier，支持：
   - SMTP
   - Webhook
   - 企业通知通道占位 provider
2. 新增 FirewallManager 抽象，封装：
   - iptables
   - Windows 防火墙占位实现
   - 云安全组占位 provider
3. 新增 ResponseScheduler，支持：
   - 定时解封
   - 响应失败重试
   - 任务状态持久化或可恢复
4. high 告警默认策略：
   - 通知
   - 临时封禁或 dry-run
   - 创建 scheduled_unblock_at
5. critical 告警默认策略：
   - 通知
   - 封禁
   - 如果 HostIsolationProvider 未配置，则创建人工审批/待办记录
6. 所有响应动作写入 ResponseAction 表和审计日志。

安全要求：
1. 生产真实封禁必须校验 IP，拒绝 localhost、私网白名单、业务白名单和非法 IP。
2. Webhook URL 必须防 SSRF，禁止 localhost、127.0.0.0/8、169.254.169.254、内网元数据地址。
3. subprocess 不得使用 shell=True。
4. dry-run 模式必须清晰标记，不得伪装为真实执行成功。

测试要求：
1. Webhook 失败有重试和失败审计。
2. high 级别封禁后产生定时解封任务。
3. 到期后解封动作执行并写入 ResponseAction。
4. critical 隔离 provider 未配置时降级为人工待办。
5. SSRF URL 被拒绝。
6. 运行 python -m pytest -q。

完成后请给出：
- 响应策略表
- 新增 provider 配置说明
- dry-run 与真实执行的区别
```

---

## 提示词 08：R4/R5 威胁情报生产化与 IOC 持久化

```text
请实施威胁情报生产化：把本地黑名单和外部情报查询升级为可持久化、可同步、可过期、可前置过滤的 IOC 能力。

请先阅读：
- src/collectors 中威胁情报相关代码
- src/detectors 或主链路中情报命中逻辑
- 数据库模型中的 IOC
- docs/AI安全守卫-v1.0-工程实施方案.md 中 “P1：威胁情报生产化”

实施目标：
1. IOC 模型支持：
   - type：ip、domain、url、file_hash、cve
   - value
   - source
   - score
   - ttl
   - first_seen
   - last_seen
   - expires_at
   - metadata
2. 支持本地 IOC 查询优先，外部 API 查询兜底。
3. 支持 AbuseIPDB、VirusTotal 已有能力的生产化封装。
4. 为 Spamhaus、PhishTank、OpenPhish、NVD、CNVD 预留 provider 接口，可以先实现配置占位和清晰的 not configured 降级。
5. 多来源同一 IOC 合并 sources，并保留最高 score 和更新时间。
6. IOC 命中时可跳过模型推理，直接生成高置信 threat_intel 告警。
7. IOC 过期后不再命中。

约束：
1. 外部 API 超时不能阻断检测链路。
2. API key 不得进入日志。
3. mock 模式应保留，便于测试和离线演示。

测试要求：
1. IOC 过期后不命中。
2. 多来源同一 IOC 合并正确。
3. 外部 API 超时后返回降级结果，主链路继续。
4. 本地 IOC 命中生成 high 告警，并包含 source_ip 或 IOC value。
5. 运行 python -m pytest -q。

完成后请说明：
- IOC provider 接口
- 同步任务入口
- 哪些来源已真实接入，哪些是占位降级
```

---

## 提示词 09：R5 监控指标、健康检查与审计巡检

```text
请实施 R5 运维可观测第一阶段：暴露关键指标、健康检查和审计完整性巡检，让系统满足生产运行的基本可观测要求。

请先阅读：
- main.py
- web/app.py
- src/audit/*
- docker-compose.yml
- docs/AI安全守卫-v1.0-工程实施方案.md 中 “P2：运维与部署”
- docs/AI安全守卫-v1.0-交付验收与路线图.md 中 4.2 性能验收、S-07、上线准入清单

实施目标：
1. Web/API 提供健康检查：
   - /healthz：进程存活
   - /readyz：数据库、Redis、关键配置、模型可用性
2. Guardian 提供内部健康指标或状态输出：
   - 采集状态
   - 模型状态
   - 队列长度
   - 最近检测时间
   - Redis 写入状态
3. 暴露 Prometheus 或兼容文本指标：
   - guardian_packets_total
   - guardian_packets_dropped_total
   - guardian_detection_latency_ms
   - guardian_alerts_total
   - guardian_model_ready
   - redis_stream_pending
   - audit_integrity_valid
4. 增加审计完整性巡检任务，校验哈希链。
5. 巡检失败时生成 critical 告警，并写入审计。

约束：
1. 指标接口不得泄露 API key、密码、JWT、管理员信息。
2. 健康检查要区分 live 和 ready，不要因为下游短暂异常直接杀死进程。
3. 指标采集失败不能影响检测主链路。

测试要求：
1. /healthz 正常返回。
2. /readyz 在数据库或 Redis 不可用时返回明确 degraded/unready。
3. /metrics 包含上述关键指标。
4. 修改 security.log 后，完整性巡检失败并产生告警。
5. 运行 python -m pytest -q。

完成后请提供：
- 指标列表
- 健康检查语义
- 运维告警建议
```

---

## 提示词 10：生产安全硬化与上线准入检查

```text
请实施生产安全硬化与上线准入检查，确保 v1.0 不使用默认密钥、默认密码、危险 CORS、危险 Redis 暴露或不安全响应命令。

请先阅读：
- web/app.py
- .env.example
- docker-compose.yml
- Dockerfile
- src/response/*
- 所有配置读取代码
- docs/AI安全守卫-v1.0-交付验收与路线图.md 中 “安全验收”“上线准入清单”

实施目标：
1. API 认证：
   - 除健康检查、ready 检查、登录页/登录接口外，API 默认需要 JWT。
2. 默认密钥：
   - 生产环境缺少 SECRET_KEY 时启动失败。
   - 禁止使用默认 SECRET_KEY。
3. 管理员密码：
   - 生产环境必须使用 ADMIN_PASSWORD_HASH。
   - 禁止默认明文密码。
4. CORS：
   - 生产环境仅允许白名单 Origin。
5. Redis：
   - 支持 REDIS_PASSWORD。
   - docker-compose 不把 Redis 暴露到公网默认端口，或明确仅开发模式暴露。
6. 响应命令：
   - IP 参数严格校验。
   - subprocess 不使用 shell=True。
7. Webhook SSRF：
   - 禁止 localhost、回环地址、链路本地地址、云元数据地址、内网敏感段。
8. 敏感信息：
   - API Key、密码、JWT 不进入日志。
9. 容器权限：
   - Web/API 非 root 运行。
   - Guardian 高权限最小化，并在文档中说明。

测试要求：
1. 生产环境缺 SECRET_KEY 启动失败。
2. 默认管理员密码在生产环境不可用。
3. 未带 JWT 的受保护 API 返回 401。
4. 非白名单 Origin 被拒绝。
5. SSRF Webhook URL 被拒绝。
6. Redis 密码配置可用。
7. 运行 python -m pytest -q。

完成后请更新：
- .env.example
- README 或 docs/deployment.md
- 上线准入检查清单
```

---

## 提示词 11：报告生成、状态流转与运营 API 收口

```text
请把 Web 控制台的运营能力从内存态收口到数据库：告警状态流转、报告生成、规则/IOC/设置查询都应基于持久化数据。

请先阅读：
- web/app.py
- 前面新增的 models/db/consumer 相关代码
- 前端页面或模板
- docs/AI安全守卫-v1.0-交付验收与路线图.md 中 F-05、F-06、F-09
- docs/AI安全守卫-v1.0-工程实施方案.md 中 “P1：审计与报告”

实施目标：
1. 告警状态支持：
   - open
   - acknowledged
   - resolved
   - ignored
2. 状态变更必须写 AlertHistory，包含操作人、时间、备注。
3. 告警列表、详情、统计 API 从数据库读取。
4. 规则、IOC、设置 API 从数据库读取和写入。
5. 报告基于数据库聚合生成，不使用进程内即时统计。
6. 报告至少包含：
   - 周期概览
   - 告警等级分布
   - 告警类型分布
   - 攻击来源 Top10
   - 响应动作和封禁列表
   - 模型版本与检测质量
   - 未处理风险与加固建议
7. 支持 HTML 导出；PDF 可作为后续增强，如果当前依赖不足请保留接口和文档说明。

约束：
1. 保持现有 UI 基本可用。
2. API 返回结构尽量兼容现有前端。
3. _ServerState 如果继续存在，只能作为缓存，不得作为生产唯一数据源。

测试要求：
1. 告警状态流转写入 AlertHistory。
2. Web 重启后告警仍可查询。
3. 报告统计来自数据库，数据正确。
4. 规则/IOC/设置写入后可查询。
5. 运行 python -m pytest -q。

完成后请说明：
- 已迁移到数据库的 API
- 仍保留的兼容层
- 报告导出方式
```

---

## 提示词 12：端到端验收测试、压测与交付文档收尾

```text
请完成 v1.0 端到端验收测试、压测脚本和交付文档收尾。目标是让项目达到“可运行、可审计、可回滚、可验收”。

请先阅读：
- docs/AI安全守卫-v1.0-交付验收与路线图.md 中 4、7、8、9 节
- docs/AI安全守卫-v1.0-工程实施方案.md 中 12 节
- README.md
- docker-compose.yml
- tests/*

验收场景必须覆盖：
1. 正常 Web 请求：/api/items?id=1 不产生攻击告警。
2. SQL 注入：/login?u=admin' OR 1=1-- 产生 web_attack high 告警。
3. 双层编码 XSS：%253Cscript%253Ealert(1) 产生 web_attack high 告警。
4. 命令注入：/ping?host=127.0.0.1;cat /etc/passwd 产生 web_attack high 告警。
5. IOC 命中：本地黑名单 IP 访问产生 threat_intel high 告警。
6. 流量异常：SYN 包突增产生 ddos 或 anomaly 告警。
7. 模型缺失：删除或隐藏某模型文件后，该引擎降级，其余继续工作。
8. Redis 中断：停止 Redis 后本地降级并记录告警。
9. 审计篡改：修改 security.log 后完整性校验失败。
10. Web 重启：产生告警后重启，历史告警仍可查询。

实施要求：
1. 增加或完善端到端测试脚本，可放在 tests/e2e 或 scripts/verify_v1.py。
2. 增加基本压测脚本或说明，验证：
   - 端到端检测延迟 P95 < 100ms 的采集方式
   - Web API P95 < 300ms 的采集方式
   - Redis Stream 无持续堆积的观测方式
3. 增加 docs/deployment.md，包含：
   - 环境变量说明
   - 数据库初始化
   - Redis 密码与内网访问
   - Nginx TLS/WSS 样例
   - dry-run 与真实响应演练
   - 回滚方案
4. 增加 docs/acceptance-checklist.md，逐项映射 F-01 到 F-10、S-01 到 S-10、性能指标、模型指标、上线准入。
5. 更新 README.md，指向新增文档。

测试要求：
1. python -m pytest -q
2. 运行端到端验收脚本。
3. 如果某些压测或系统级能力在当前机器无法执行，请在文档中标注前置条件和替代验证方式。

完成后请输出：
- 通过的测试命令和结果摘要
- 未完成项和原因
- 是否达到生产 v1.0 上线准入
```

---

## 推荐执行顺序

| 顺序 | 提示词 | 阶段 | 主要交付 |
|---|---|---|---|
| 1 | 提示词 00 | 基线 | 任务看板与差异清单 |
| 2 | 提示词 01 | R1 | 网络流量窗口聚合 |
| 3 | 提示词 02 | R1 | Web 来源 IP 透传 |
| 4 | 提示词 03 | R2 | 数据库模型与初始化 |
| 5 | 提示词 04 | R2 | Redis 消费、入库、推送 |
| 6 | 提示词 05 | R3 | Schema 与 Manifest |
| 7 | 提示词 06 | R3 | ModelRegistry 与热更新 |
| 8 | 提示词 07 | R4 | 响应闭环 |
| 9 | 提示词 08 | R4/R5 | IOC 持久化与同步 |
| 10 | 提示词 09 | R5 | 指标、健康检查、巡检 |
| 11 | 提示词 10 | 安全硬化 | 上线准入安全项 |
| 12 | 提示词 11 | 运营收口 | 状态流转、报告、运营 API |
| 13 | 提示词 12 | 交付验收 | E2E、压测、交付文档 |

---

## Cursor 通用约束模板

下面这段可以附加到任意提示词末尾，作为通用工程约束：

```text
通用工程约束：
1. 先阅读相关代码和测试，再制定简短实施计划。
2. 以当前代码结构为准，优先复用已有模块和风格，不推倒重来。
3. 每次改动保持范围可控，不做无关重构。
4. 对安全相关逻辑补测试，尤其是认证、命令执行、SSRF、默认密钥、审计。
5. 所有新增配置同步更新 .env.example 和文档。
6. 如果发现脏工作区或用户已有修改，不要覆盖，先说明冲突并绕开。
7. 完成后运行 python -m pytest -q；无法运行时说明原因。
8. 最终回复必须列出修改文件、验证结果、剩余风险。
```

