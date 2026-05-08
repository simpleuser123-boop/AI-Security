# AI-Security-Guardian 单企业私有化 Beta Release Freeze Manifest

生成时间：2026-05-08 17:26:30 CST  
目标版本：单企业私有化 Beta Release Freeze 候选  
结论：当前代码和交付材料已具备冻结清单基础，但不建议直接放行；必须先清理工作树并替换客户环境占位配置。

## 1. 代码版本

| 项 | 值 |
|---|---|
| Git root | `C:/Users/yyl/Desktop/ai安全` |
| 仓库子目录 | `ai-security-guardian` |
| 分支 | `main` |
| HEAD commit | `ccd7b1b55c7e30921b020a3a3d459e615c1a49ca` |
| 描述版本 | `ccd7b1b-dirty` |
| 工作树状态 | 未冻结：存在 65 个已修改或未跟踪条目 |

冻结前要求：

- Review 并提交当前 `ai-security-guardian/` 下的所有发布候选变更。
- 确认 `reports/` 是否作为发布证据交付；若只是本地生成物，应从代码发布包排除。
- 不在本次检查中创建 git tag。建议先形成 release commit，再按下方 tag 建议创建标签。

## 2. 迁移版本

当前迁移链线性，无分叉：

| 文件 | revision | down_revision |
|---|---|---|
| `migrations/versions/20260506_0001_initial_schema.py` | `20260506_0001` | `None` |
| `migrations/versions/20260507_0002_phase_b1_multitenancy.py` | `20260507_0002` | `20260506_0001` |
| `migrations/versions/20260507_0003_commercial_metering_mvp.py` | `20260507_0003` | `20260507_0002` |
| `migrations/versions/20260507_0004_phase_c6_real_response_controls.py` | `20260507_0004` | `20260507_0003` |
| `migrations/versions/20260507_0005_real_ban_ttl_guard.py` | `20260507_0005` | `20260507_0004` |

发布包最新迁移 revision：`20260507_0005`。

客户环境上线前必须执行：

```bash
flask --app web.migration_app:create_migration_app db upgrade
flask --app web.migration_app:create_migration_app db current
```

验收口径：客户 PostgreSQL 或恢复演练库的 `alembic_version.version_num` 必须等于 `20260507_0005`。

## 3. Docker 镜像 tag 建议

当前 `docker-compose.yml` 仍使用：

```yaml
image: ai-security-guardian:latest
```

冻结发布不建议使用 `latest`。建议在 release commit 形成后使用以下 tag 之一：

- 内部候选：`ai-security-guardian:private-beta-20260508-ccd7b1b`
- 客户交付：`ai-security-guardian:1.0.0-private-beta.20260508.ccd7b1b`

若当前 dirty 工作树被提交到新 commit，应把 tag 中的 `ccd7b1b` 替换为最终 release commit 的短 SHA。

Docker 检查摘要：

| 文件 | SHA256 |
|---|---|
| `Dockerfile` | `3deec64e1d8c45041e639e7180527c3f1a852e7f0b9cba652c94c438a21a33ae` |
| `docker-compose.yml` | `cfc016ecb5b56af3da09fbe3cb4a9254d5c471bbee168f548e789b5634bac3a3` |

检查结果：

- `Dockerfile` 使用 `public.ecr.aws/docker/library/python:3.11-slim`，非 root 用户 `guardian`，Gunicorn gthread 默认启动，包含 `/healthz` healthcheck。
- `docker-compose.yml` 包含 `app`、`redis` 和可选 `guardian` full-chain profile，模型目录只读挂载，Redis 仅绑定 `127.0.0.1:6379`。
- 使用 `.env.example` 执行 `docker compose --env-file .env.example config --quiet` 失败，原因是示例文件故意留空 `ADMIN_PASSWORD_HASH` 等生产必填项。
- 使用当前 `.env` 执行 `docker compose config --quiet` 退出码为 0，但出现 `$` 插值 warning。发布前应确认 `ADMIN_PASSWORD_HASH` 等包含 `$` 的值已按 Compose 规则加引号或转义，避免 hash 被截断。

## 4. 模型文件和 SHA256

模型目录：`models/saved`

| 文件 | SHA256 |
|---|---|
| `anomaly_if_v1.model_manifest.json` | `3830de211867672cf9d24885400dd0f4cbe6c6a926baca3a83dabbcefa4f4844` |
| `anomaly_if_v1.pkl` | `31cd3d4e7fba2ffac374908e0628a0118a76aeff5bf8ca974aff34cfe4559d03` |
| `ddos_rf_v1.model_manifest.json` | `53025fb515c2623042cf0e365218c0e9c0b231c5509d661e63047327d3eaab3b` |
| `ddos_rf_v1.pkl` | `b84db0d74fa5fb09c88e995ac838e9d86fc61b7ca7f6d0fb2bdf4bb6094afcfd` |
| `intrusion_feature_cols_v1.pkl` | `68a19fdf0f99bbd63be43ba6abf3e1e04a55e4d28ad20b9d8a1d6a22975c3272` |
| `intrusion_label_encoder_v1.pkl` | `47191dfc90b3eaf00a52eaf8bd2ff8629ebbd2e31982d002b8f97e2154501390` |
| `intrusion_rf_v1.model_manifest.json` | `39afb2cbb9bdeeaa988cd38fa8447ee1153bc01114df5dc1f6e7cd1e9587cff0` |
| `intrusion_rf_v1.pkl` | `47761641e2f424347f86974a34a20087f2312e2fabf3787795b6e4e13675d6e6` |
| `intrusion_scaler_v1.pkl` | `6073f49a81a1c6919c47f854ceda329de446006904f35d6f69be7f8811afd5e8` |
| `web_attack_nb_v1.model_manifest.json` | `fc58be171b5af2b459553b5d65e221ce1edc3b70b94897aa6e2df72afd83eb2c` |
| `web_attack_nb_v1.pkl` | `203b54b186d087e85fdf162c1a74cab66c581ff425980aa926b05ecf6372b0f8` |

模型 manifest 摘要：

| 模型 | version | schema | trust_tier | 说明 |
|---|---|---|---|---|
| `anomaly_if_v1` | `1.0.0` | `network_flow_v1:1` | `production` | synthetic normal-only Isolation Forest |
| `ddos_rf_v1` | `1.0.0` | `network_flow_v1:1` | `prototype_nsl_kdd` | NSL-KDD benchmark，不代表生产流量效果 |
| `intrusion_rf_v1` | `1.0.0` | `network_flow_v1:1` | `prototype_nsl_kdd` | NSL-KDD benchmark，不代表生产流量效果 |
| `web_attack_nb_v1` | `1.0.0` | `web_request_v1:1` | `production` | built-in web attack samples |

## 5. 关键脚本版本

项目关键脚本未声明独立语义版本，本次以文件 SHA256 固化版本：

| 脚本 | SHA256 | 发布用途 |
|---|---|---|
| `scripts/check_production_readiness.py` | `db2b90d2cf73a4339c01d4296910a4f1ded251c2f66957bc024871d1aca7f968` | 私有化 Beta / real-enforcement readiness gate |
| `scripts/private_beta_e2e_drill.py` | `bf94e548d7cb70585eb14c96406d473492248bf4acb3893a64155052e7be4dc6` | 私有化端到端演练 |
| `scripts/generate_private_deployment_evidence.py` | `677427e02cbecfd6d89e6421e5af4aa4fd7730199fda0a28fdffe81942ffd772` | 私有化交付证据采集 |
| `scripts/staging_drill.py` | `5c5617639f1f9c3b908a96ccbc900efbbdd6e1b41d9176e9239806e4ab39e3e5` | staging 演练 |
| `scripts/verify_v1.py` | `be8bff798740b17b9ba3ec86a7645aab73dcc386f308f579364cbeceff2ffe51` | v1 验收验证 |
| `scripts/bootstrap_models.py` | `395493148df1f5a80c9e875a1b4b9064e9a585be2276d46c131db8abb10c4544` | 模型文件检查/准备 |
| `scripts/tenant_query_scan.py` | `b679e0d7fe3e11c70b8311213d3592fa147eb5121db3ab09dd0ea3ab403d79e3` | 租户查询隔离扫描 |

## 6. 交付文档清单

Beta 发布核心文档：

- `README.md`
- `docs/deployment.md`
- `docs/private-beta-delivery-checklist.md`
- `docs/private-beta-env-checklist.md`
- `docs/single-enterprise-private-beta-customer-delivery-package.md`
- `docs/private-beta-target-drill.md`
- `docs/private-beta-drill-20260507.md`
- `docs/postgres-migration-restore-drill-20260507.md`
- `docs/acceptance-checklist.md`
- `docs/audit-log-baseline.md`
- `docs/staging-drill.md`
- `docs/ci-test-groups.md`
- `docs/phase-c6-real-response-controlled-release.md`
- `docs/phase-c5-saas-operations-reliability.md`
- `docs/ga-roadmap-convergence-plan.md`

客户交付模板：

- `templates/customer-beta-environment-intake.md`
- `templates/customer-beta-evidence-index.md`
- `templates/customer-beta-ops-checklog.md`
- `templates/customer-beta-issue-report.md`
- `templates/customer-beta-backup-restore-record.md`
- `templates/customer-beta-acceptance-signoff.md`
- `templates/go-live-change-ticket.md`
- `templates/real-response-enable-request.md`
- `templates/response-business-whitelist-confirmation.md`
- `templates/provider-minimum-privilege-authorization.md`
- `templates/cloud-security-group-access-info.md`
- `templates/edr-host-isolation-access-info.md`
- `templates/misblock-recovery-sop.md`
- `templates/misblock-recovery-drill-template.md`
- `templates/post-response-review-template.md`
- `templates/post-go-live-24h-observation-checklist.md`
- `templates/scheduled-unblock-acceptance-template.md`

## 7. 检查结果

已执行：

```bash
git status --short --branch
git rev-parse HEAD
git describe --tags --always --dirty
Get-FileHash -Algorithm SHA256 models/saved/*
python -m pytest tests/test_schema_manifest.py tests/test_model_registry.py tests/test_database_migrations.py -q
docker compose --env-file .env.example config --quiet
docker compose config --quiet
python scripts/check_production_readiness.py --gate private-beta
```

结果：

| 检查 | 结果 |
|---|---|
| Git 状态 | FAIL：当前为 `ccd7b1b-dirty`，存在未提交发布候选变更 |
| 迁移链 | PASS：最新 head `20260507_0005`，线性迁移 |
| 模型文件存在性 | PASS：11 个必要模型/manifest 文件存在 |
| 模型/迁移测试 | PASS：`17 passed` |
| Dockerfile | PASS：可用于构建运行镜像 |
| Compose 示例配置 | EXPECTED FAIL：`.env.example` 保持生产必填项为空，不能直接发布运行 |
| Compose 当前配置 | WARN：可解析，但当前 `.env` 出现 `$` 插值 warning |
| Private Beta readiness | FAIL：`DATABASE_URL`、`ALLOWED_ORIGINS`、`DRY_RUN`、`DB_CONNECTIVITY` 未通过 |

Private Beta readiness 当前失败详情：

- `DATABASE_URL` 仍像示例、开发、测试或占位连接串，必须替换为客户正式 PostgreSQL。
- `ALLOWED_ORIGINS=https://REPLACE_WITH_PRIVATE_BETA_FQDN` 仍是占位域名，必须替换为客户正式 HTTPS Origin。
- `DRY_RUN` 当前不符合 private-beta gate；首批私有化 Beta 必须保持 `DRY_RUN=true`。
- DB 连通性因 `DATABASE_URL` 未就绪而跳过。

## 8. 已知限制

- 当前工作树未提交，不能作为不可变 release baseline；必须先形成 release commit。
- 首批单企业私有化 Beta 默认只承诺单套客户私有化部署，不承诺多客户共享 SaaS 隔离能力。
- Beta 默认 `DRY_RUN=true`，真实封禁、云安全组变更、EDR 主机隔离不属于默认交付；开启前必须另走 `real-enforcement` gate、客户书面授权、业务白名单、审批、TTL、回滚、解封和复盘证据。
- NSL-KDD 相关模型属于 benchmark/prototype evidence，不代表客户生产流量效果；需要在客户环境持续收集误报、漏报和漂移指标。
- 高可用、多 Web 实例 Socket.IO、正式 SLA、自动化安装器、模型运营闭环、企业 SSO/OIDC/MFA 仍属于 GA 前或企业增强项。
- 真实抓包依赖客户授权、宿主机网卡权限和 `guardian` full-chain profile；未授权时只能交付 Web/API、Redis、DB、模型就绪和演练数据链路。
- 当前 `.env` 不是可交付配置，且不得提交真实密钥。客户配置应通过安全渠道交付，并用 readiness gate 在客户环境重新验证。

## 9. 冻结前阻塞项

1. 将客户环境配置替换为真实 PostgreSQL、正式 HTTPS Origin，并确认 `DRY_RUN=true`。
2. 修正 `.env` 中包含 `$` 的 hash 在 Docker Compose 插值阶段的 warning。
3. 在客户或等价目标环境执行 `python scripts/check_production_readiness.py --gate private-beta`，要求无 `[FAIL]`。
4. 执行数据库迁移并确认 `alembic_version.version_num = 20260507_0005`。
5. 确认模型文件按本 manifest 的 SHA256 完整交付。
6. Review 当前 65 个工作树变更，移除不应进入发布包的本地报告或临时文件。
7. 创建 release commit 后再创建 tag；本次检查不创建 git tag。

