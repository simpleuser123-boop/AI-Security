# 项目代码类型说明

本文档按代码类型解释 AI-Security-Guardian 项目中各部分在做什么，并列出对应文件。

## 总体架构

项目是一个 Python/Flask 安全检测与响应系统：前端页面负责展示告警、规则、报表和设置；Flask 路由/API 负责认证、数据查询和操作入口；后端检测链路负责采集流量与日志、提取特征、执行模型/规则检测、融合风险结果并触发响应；审计、指标、Redis、数据库和脚本支撑生产运行。

## 类型分组

### Web 后端支撑

数据库连接、ORM 模型、告警流消费者、审计巡检和 Web 应用初始化辅助逻辑。

涉及文件：

- `web/__init__.py`
- `web/alert_stream_consumer.py`
- `web/audit_integrity_patrol.py`
- `web/database.py`
- `web/init_db.py`
- `web/models.py`

### 其他

未落入主要分组但仍属于项目自有文件的内容。

涉及文件：

- `src/__init__.py`

### 决策融合

把多个检测器的结果进行加权、投票或归一化，形成最终风险判断。

涉及文件：

- `src/decision/__init__.py`
- `src/decision/fusion_engine.py`

### 前端静态资源

浏览器端 JavaScript 与 CSS，负责页面交互、API 调用、图表/列表渲染、状态提示和视觉样式。

涉及文件：

- `web/static/css/components.css`
- `web/static/css/reports.css`
- `web/static/css/theme.css`
- `web/static/js/alerts.js`
- `web/static/js/app.js`
- `web/static/js/dashboard.js`
- `web/static/js/reports.js`
- `web/static/js/rules.js`
- `web/static/js/settings.js`
- `web/static/js/threat_intel.js`
- `web/static/js/utils.js`

### 前端页面模板

Jinja HTML 模板，由 Flask 在服务端渲染为页面骨架，再由静态 JS 填充动态数据。

涉及文件：

- `web/templates/alerts.html`
- `web/templates/base.html`
- `web/templates/command.html`
- `web/templates/dashboard.html`
- `web/templates/login.html`
- `web/templates/report_export.html`
- `web/templates/reports.html`
- `web/templates/rules.html`
- `web/templates/settings.html`
- `web/templates/threat_intel.html`

### 可观测性

采集系统指标、检测延迟、吞吐、健康状态和 Prometheus 指标。

涉及文件：

- `src/observability/__init__.py`
- `src/observability/guardian_metrics.py`

### 后端主入口

完整检测链路入口，串联采集、威胁情报、特征提取、检测、融合、响应和审计。

涉及文件：

- `main.py`

### 后端采集

从网络包、Web 日志、IOC/威胁情报源中收集原始安全信号。

涉及文件：

- `src/collectors/__init__.py`
- `src/collectors/ioc_providers.py`
- `src/collectors/ioc_repository.py`
- `src/collectors/ioc_sync.py`
- `src/collectors/log_collector.py`
- `src/collectors/packet_collector.py`
- `src/collectors/threat_intel.py`

### 审计日志

记录安全关键事件，并通过哈希链等方式保护日志完整性。

涉及文件：

- `src/audit/__init__.py`
- `src/audit/security_logger.py`

### 数据结构/Schema

定义网络流、Web 请求、IOC 匹配、系统行为等标准数据结构与校验。

涉及文件：

- `src/schema/__init__.py`
- `src/schema/feature_schemas.py`
- `src/schema/inference_guard.py`
- `src/schema/json/ioc_match_v1.json`
- `src/schema/json/network_flow_v1.json`
- `src/schema/json/system_behavior_v1.json`
- `src/schema/json/web_request_v1.json`
- `src/schema/manifest.py`
- `src/schema/nsl_kdd_adapter.py`
- `src/schema/persist.py`

### 检测模型/规则

DDoS、入侵、Web 攻击、异常检测等检测器，输出统一的检测结果。

涉及文件：

- `src/detectors/__init__.py`
- `src/detectors/anomaly_detector.py`
- `src/detectors/base.py`
- `src/detectors/ddos_detector.py`
- `src/detectors/inference_meta.py`
- `src/detectors/intrusion_detector.py`
- `src/detectors/web_detector.py`

### 模型注册

管理模型版本、元数据、激活状态与模型文件加载。

涉及文件：

- `src/registry/__init__.py`
- `src/registry/model_registry.py`

### 测试

单元测试、集成测试、冒烟测试和端到端验收，覆盖采集、检测、响应、持久化和 Web 行为。

涉及文件：

- `tests/_phase8_smoke.py`
- `tests/_smoke_phase7.py`
- `tests/_verify_ws_events.py`
- `tests/conftest.py`
- `tests/e2e/__init__.py`
- `tests/e2e/test_v1_acceptance.py`
- `tests/e2e/verify_scenarios.py`
- `tests/test_alert_stream_redis.py`
- `tests/test_collectors.py`
- `tests/test_db_persistence.py`
- `tests/test_detectors.py`
- `tests/test_features.py`
- `tests/test_flow_window_aggregator.py`
- `tests/test_ioc_production.py`
- `tests/test_model_registry.py`
- `tests/test_observability_r5.py`
- `tests/test_production_hardening.py`
- `tests/test_responder.py`
- `tests/test_response_r4.py`
- `tests/test_schema_manifest.py`

### 特征工程

把原始流量、日志或窗口聚合数据转换为模型和规则可消费的结构化特征。

涉及文件：

- `src/features/__init__.py`
- `src/features/flow_features.py`
- `src/features/flow_window_aggregator.py`
- `src/features/pipeline.py`
- `src/features/web_features.py`

### 自动响应

根据告警和策略执行封禁、隔离、通知、持久化、调度与安全校验。

涉及文件：

- `src/response/__init__.py`
- `src/response/firewall.py`
- `src/response/host_isolation.py`
- `src/response/ip_policy.py`
- `src/response/ip_validate.py`
- `src/response/notifier.py`
- `src/response/persistence.py`
- `src/response/responder.py`
- `src/response/scheduler.py`
- `src/response/webhook_url.py`

### 路由与 API

Flask 页面路由、REST API、认证、限流、WebSocket 和健康检查，是前后端通信的核心入口。

涉及文件：

- `web/app.py`
- `web/observability_routes.py`

### 运维/训练脚本

用于模型训练、数据集下载、密码哈希生成、生产就绪检查、压测和验收验证。

涉及文件：

- `scripts/benchmark_p95.py`
- `scripts/bootstrap_models.py`
- `scripts/check_production_readiness.py`
- `scripts/download_datasets.py`
- `scripts/generate_admin_password_hash.py`
- `scripts/train_all.py`
- `scripts/verify_v1.py`

### 通用工具

认证、环境变量加载、Redis 客户端与通用基础能力。

涉及文件：

- `src/utils/__init__.py`
- `src/utils/auth.py`
- `src/utils/env_loader.py`
- `src/utils/redis_client.py`

### 部署与依赖

容器镜像、Compose 编排和 Python 依赖清单。

涉及文件：

- `Dockerfile`
- `docker-compose.yml`
- `requirements.txt`

### 配置

集中读取运行参数、密钥位置、数据库、Redis、限流、CORS 和生产开关。

涉及文件：

- `.env.example`
- `config/config.py`

## 主要调用链

1. 用户访问 `web/templates/*.html` 页面，浏览器加载 `web/static/js/*.js` 与 `web/static/css/*.css`。
2. 前端脚本调用 `web/app.py` 中的 `/api/*` 接口，JWT、限流、CORS 和错误处理在 Flask 层统一执行。
3. 完整检测链路由 `main.py` 启动，先初始化日志、Redis、采集器、威胁情报、特征提取、检测器、融合引擎和响应器。
4. 采集模块把网络包和 Web 日志变成原始事件，特征模块转换成标准特征，检测模块输出风险结果。
5. 决策融合模块汇总多个检测器输出，响应模块执行封禁、通知、持久化和调度，审计模块记录关键动作。
6. Web 层通过数据库、Redis Stream 或内存状态读取告警和指标，再推送到页面或 WebSocket 客户端。

## 路由与 API 概览

以下路由从源码自动提取，便于定位接口入口。

| 文件 | 行号 | 路由声明 | 处理函数 |
|---|---:|---|---|
| `web/app.py` | 1212 | `@app.route("/")` | `index` |
| `web/app.py` | 1216 | `@app.route("/login")` | `page_login` |
| `web/app.py` | 1235 | `@app.route("/api/health")` | `health_check` |
| `web/app.py` | 1252 | `@app.route("/api/auth/login", methods=["POST"])` | `auth_login` |
| `web/app.py` | 1299 | `@app.route("/api/auth/refresh", methods=["POST"])` | `auth_refresh` |
| `web/app.py` | 1305 | `@app.route("/api/auth/me")` | `auth_me` |
| `web/app.py` | 1311 | `@app.route("/api/stats")` | `api_stats` |
| `web/app.py` | 1325 | `@app.route("/api/alerts")` | `api_alerts` |
| `web/app.py` | 1381 | `@app.route("/api/alerts/types")` | `api_alert_types` |
| `web/app.py` | 1388 | `@app.route("/api/alerts/<alert_id>")` | `api_alert_detail` |
| `web/app.py` | 1404 | `@app.route("/api/alerts/<alert_id>/status", methods=["POST"])` | `api_alert_update_status` |
| `web/app.py` | 1443 | `@app.route("/api/alerts/_seed", methods=["POST"])` | `api_alerts_seed` |
| `web/app.py` | 1468 | `@app.route("/api/metrics/traffic")` | `api_metrics_traffic` |
| `web/app.py` | 1533 | `@app.route("/api/metrics/attack_types")` | `api_metrics_attack_types` |
| `web/app.py` | 1547 | `@app.route("/api/metrics/top_attackers")` | `api_metrics_top_attackers` |
| `web/app.py` | 1561 | `@app.route("/api/banned_ips", methods=["GET", "POST"])` | `api_banned_ips` |
| `web/app.py` | 1589 | `@app.route("/api/banned_ips/<ip>", methods=["DELETE"])` | `api_banned_ip_delete` |
| `web/app.py` | 1601 | `@app.route("/api/command", methods=["POST"])` | `api_command` |
| `web/app.py` | 1610 | `@app.route("/api/rules", methods=["GET", "POST"])` | `api_rules` |
| `web/app.py` | 1640 | `@app.route("/api/rules/<rule_id>", methods=["GET", "PUT", "DELETE"])` | `api_rule_detail` |
| `web/app.py` | 1678 | `@app.route("/api/rules/<rule_id>/toggle", methods=["PATCH"])` | `api_rule_toggle` |
| `web/app.py` | 1694 | `@app.route("/api/rules/test", methods=["POST"])` | `api_rule_test` |
| `web/app.py` | 1739 | `@app.route("/api/rules/_seed", methods=["POST"])` | `api_rules_seed` |
| `web/app.py` | 1752 | `@app.route("/api/threat_intel", methods=["GET"])` | `api_threat_intel` |
| `web/app.py` | 1799 | `@app.route("/api/threat_intel/providers", methods=["GET"])` | `api_threat_intel_providers` |
| `web/app.py` | 1842 | `@app.route("/api/threat_intel/iocs", methods=["POST"])` | `api_threat_intel_add_ioc` |
| `web/app.py` | 1869 | `@app.route(` | `api_threat_intel_remove_ioc` |
| `web/app.py` | 1905 | `@app.route("/api/threat_intel/query", methods=["POST"])` | `api_threat_intel_query` |
| `web/app.py` | 1972 | `@app.route("/api/threat_intel/_seed", methods=["POST"])` | `api_threat_intel_seed` |
| `web/app.py` | 1984 | `@app.route("/api/reports", methods=["GET"])` | `api_reports` |
| `web/app.py` | 1998 | `@app.route("/api/reports/summary", methods=["GET"])` | `api_reports_summary` |
| `web/app.py` | 2014 | `@app.route("/api/reports/export", methods=["GET"])` | `api_reports_export` |
| `web/app.py` | 2048 | `@app.route("/api/settings", methods=["GET", "PUT"])` | `api_settings` |
| `web/app.py` | 2082 | `@app.route("/api/settings/test_webhook", methods=["POST"])` | `api_settings_test_webhook` |
| `web/app.py` | 2131 | `@app.route("/api/settings/test_email", methods=["POST"])` | `api_settings_test_email` |
| `web/observability_routes.py` | 94 | `@app.route("/healthz")` | `healthz` |
| `web/observability_routes.py` | 99 | `@app.route("/readyz")` | `readyz` |
| `web/observability_routes.py` | 148 | `@app.route("/metrics")` | `metrics` |

## 阅读建议

- 想看页面怎么工作：先读 `web/templates/base.html`，再读对应页面模板和 `web/static/js/*.js`。
- 想看 API 怎么工作：重点读 `web/app.py` 的 `_register_api_routes`。
- 想看检测链路：从 `main.py` 的 `SecurityGuardian` 开始，再进入 `src/collectors`、`src/features`、`src/detectors`、`src/decision`、`src/response`。
- 想看生产配置：读 `config/config.py`、`.env.example`、`Dockerfile` 和 `docker-compose.yml`。
