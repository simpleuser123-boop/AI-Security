# v1.0 验收清单（可打印）

与 `docs/AI安全守卫-v1.0-交付验收与路线图.md` §4、§7、§8 及 `docs/AI安全守卫-v1.0-工程实施方案.md` §12 对照使用。完整场景脚本：`python scripts/verify_v1.py` + `python -m pytest tests/e2e/test_v1_acceptance.py -q`。

## 功能验收（F-01～F-10）

| 编号 | 验收项 | 通过标准 | 验证方式 / 证据 |
|------|--------|----------|-------------------|
| F-01 | 网络流量检测 | 连续流可形成 flow 特征并进入检测器 | `python -m pytest tests/test_flow_window_aggregator.py -q`；全链路需 Guardian + 抓包环境 |
| F-02 | Web 攻击检测 | SQLi、XSS、命令注入、路径遍历可触发告警且含源 IP | E2E 场景 1～4；`tests/e2e/verify_scenarios.py` |
| F-03 | 威胁情报前置过滤 | 本地 IOC 命中高置信告警 | E2E 场景 5；`ThreatIntelCollector.add_ip_to_blacklist` |
| F-04 | 融合决策 | 多引擎可融合、等级升级稳定 | `python -m pytest tests/test_detectors.py::TestFusionEngine -q` |
| F-05 | 告警持久化 | Web 重启后历史告警可查询 | E2E 场景 10；`tests/e2e/test_v1_acceptance.py::test_10_web_restart_alerts` |
| F-06 | 状态流转 | 告警可确认/解决/忽略并留痕 | `tests/test_db_persistence.py::test_alert_history_status_transition` |
| F-07 | 响应动作 | high/critical 产生封禁或隔离动作记录 | `DRY_RUN=true` 下审计与 DB；`tests/test_response_r4.py` |
| F-08 | 解封回滚 | 可手工解封；定时解封为路线图项 | API 解封 + `docs/deployment.md` §8 |
| F-09 | 报告生成 | 日/周/月报告基于持久化数据 | `tests/test_db_persistence.py::test_report_summary_from_db` |
| F-10 | 审计巡检 | 哈希链校验可运行并输出 valid | E2E 场景 9；`/readyz`、巡检任务（若启用） |

## 安全验收（S-01～S-10）

| 编号 | 验收项 | 通过标准 | 验证方式 |
|------|--------|----------|----------|
| S-01 | API 认证 | 除豁免路由外需 JWT | `tests/test_production_hardening.py`；匿名访问 `/api/*` 401 |
| S-02 | 默认密钥 | 生产无默认 `SECRET_KEY` | 生产启动校验 |
| S-03 | 管理员密码 | `ADMIN_PASSWORD_HASH`；无明文默认 | `verify_admin_credentials` 测试 |
| S-04 | CORS | 仅白名单 Origin | 配置审查 + 集成测试 |
| S-05 | 命令注入防护 | IP 校验、`subprocess` 无 `shell=True` | `tests/test_responder.py` 等 |
| S-06 | SSRF | Webhook 禁 localhost/元数据 | `tests/test_production_hardening.py` |
| S-07 | 日志完整性 | 哈希链可校验 | E2E 场景 9 |
| S-08 | 敏感信息 | 密钥不进日志 | 代码审计 + 通知失败测试 |
| S-09 | Redis 暴露 | 内网 + 密码 | `docs/deployment.md` §3、`docker-compose.yml` |
| S-10 | 容器权限 | Web 非 root；Guardian 最小权限 | `Dockerfile`、`deployment.md` |

## 性能指标（§4.2）

| 指标 | 目标 | 采集方式 |
|------|------|----------|
| 端到端检测延迟 | P95 < 100 ms | `scripts/benchmark_p95.py`（进程内 detect）；全链路用 Guardian metrics |
| Web API | P95 < 300 ms | 同脚本 HTTP 段；或 `hey`/`wrk` 对 `/api/alerts` |
| Redis Stream 堆积 | 无持续增长 | `redis-cli XLEN guardian:alerts`、`XPENDING`；见 `benchmark_p95.py` 尾部说明 |
| 模型推理失败率 | < 1% | 运行时指标 / 日志抽样（路线图增强） |
| 采集丢包率 | 可观测 | 抓包环境 `tcpdump`/Guardian 日志（路线图增强） |

## 模型指标（§4.3）

| 指标 | 目标 | 备注 |
|------|------|------|
| Accuracy / Precision / Recall / F1 / FPR / FNR | 文档阈值 | 以各 `models/train/*.py` 评估与离线报告为准 |
| 模型版本与 manifest | 每个上线模型有 manifest | `tests/test_schema_manifest.py`、`ModelRegistry` |
| schema 一致性 | 训练与推理列一致 | manifest + schema 测试 |

## 上线准入（§7 摘要）

> 私有化 Beta readiness 与真实封禁 readiness 分开判断。默认 `python scripts/check_production_readiness.py` 是 `private-beta` gate，允许 `DRY_RUN=true`；真实封禁上线必须额外通过 `python scripts/check_production_readiness.py --gate real-enforcement`。

- [ ] `.env` 生产配置完成；无默认密钥/默认密码  
- [ ] 数据库迁移/初始化完成；备份策略可用  
- [ ] Redis `requirepass`；Compose 绑定策略符合 `deployment.md`  
- [ ] `/readyz`、健康检查通过  
- [ ] `python -m pytest -q` 全绿  
- [ ] `python scripts/verify_v1.py` 通过；场景 10 pytest 通过  
- [ ] 私有化 Beta 保持或允许 `DRY_RUN=true`，dry-run 响应记录可审计  
- [ ] 真实封禁仅在 `--gate real-enforcement` 无 `[FAIL]` 后启用，且审批、审计、回滚、解封、复盘证据齐备  
- [ ] 审计完整性抽检通过  
- [ ] Nginx TLS + WSS 验证（若对外 WebSocket）  
- [ ] 回滚方案演练  

## SaaS Beta 运维验收（Phase C5）

运维设计详见 `docs/phase-c5-saas-operations-reliability.md`。

- [ ] SaaS Beta SLO 已确认：Web/API 可用性、API P95、告警消费延迟、Redis Stream lag、通知失败率、响应动作失败率、审计巡检成功率。
- [ ] Prometheus 已抓取 `/metrics`，包含 `guardian_http_request_duration_seconds_*`、`redis_stream_group_lag`、`guardian_alert_stream_consumed_total`、`guardian_response_actions_total`、`audit_integrity_valid`。
- [ ] Prometheus 告警规则已按 Phase C5 手册配置并完成 firing 测试。
- [ ] Grafana Dashboard 已覆盖 Overview、Web/API、Detection、Stream、Response、Audit、Infra。
- [ ] 值班手册已发给运维团队，SEV1/SEV2 升级联系人和响应目标已确认。
- [ ] HA 方案已确认：Web/API 多实例、Redis/PostgreSQL 高可用、LB `/readyz` 摘除、备份恢复演练。

## 映射：路线图 §8 十大场景

| 场景 | 脚本/测试 |
|------|-----------|
| 正常 `/api/items?id=1` | `check_01` |
| SQL 注入 | `check_02` |
| 双层 XSS | `check_03` |
| 命令注入 | `check_04` |
| IOC 黑名单 | `check_05` |
| SYN/流量异常 | `check_06`（真实模型或合成 anomaly） |
| 模型缺失降级 | `check_07` |
| Redis 降级 | `check_08` |
| 审计篡改 | `check_09` |
| Web 重启查告警 | `test_10_web_restart_alerts` |
