# CI/CD 与测试分组

本项目使用 GitHub Actions 作为基础 CI。默认质量门禁在每次 `push` / `pull_request` 上运行，目标是快速发现单元、核心安全、schema/manifest 和 production-e2e 验收问题；慢测、`scripts/verify_v1.py` 和降级 E2E 不放进默认生产放行口径，避免把模型缺失、Redis memory fallback 等降级场景误写成生产验收通过。

## 当前口径修正

| 项目 | 真实验收命令 | 当前状态 |
|---|---|---|
| production-e2e 非降级验收 | `python -m pytest -m production_e2e -q` | 待复核；只覆盖非降级场景 |
| degradation-e2e 容灾验证 | `python -m pytest -m degradation_e2e -q` | 不计入生产通过 |
| 旧 v1 脚本 | `python scripts/verify_v1.py` | 不作为生产验收；该脚本混有模型缺失和 Redis fallback 场景 |
| PostgreSQL/Redis 非降级依赖 | `python scripts/run_non_degraded_tests.py` | 失败/待修复：若仍出现 Redis memory fallback，不得写为非降级通过 |

## 默认质量门禁

工作流文件：`.github/workflows/ci.yml`

CI 使用 Python 3.10，和 `Dockerfile` 中的 `python:3.10-slim` 运行基线保持一致。

默认 `Quality Gate` 包含：

1. **依赖安装**
   - `python -m pip install -r requirements.txt`
   - `python -m pip install pytest`
   - `python -m pip check`

2. **单元与离线快测**
   - `python -m pytest -q --tb=short --maxfail=1 -m "not integration and not e2e and not production_e2e and not degradation_e2e and not slow"`
   - 对齐 `pytest.ini` 的默认策略，排除需要外部服务或明显耗时的测试。

3. **关键安全硬化测试**
   - `python -m pytest tests/test_production_hardening.py -q --tb=short --maxfail=1`
   - 覆盖生产密钥、管理员口令策略、JWT 保护、CORS、Webhook SSRF 与 Redis 密码等关键硬化行为。

4. **SaaS 租户隔离静态扫描**
   - `python scripts/tenant_query_scan.py`
   - 阻断生产路径中未豁免的 tenant-scoped ORM 直读；输出包含文件、行号、模型、访问类型、分类和建议修复方式。测试专用直读必须用 `tenant-scan: allow ...` 标注原因，生产脚本直读必须修复或明确标注业务原因。

5. **schema/manifest 测试**
   - `python -m pytest tests/test_schema_manifest.py tests/test_model_registry.py -q --tb=short --maxfail=1`
   - 覆盖特征 schema、模型 manifest、模型治理字段、版本切换和上线策略。

6. **production-e2e 非降级生产验收**
   - `python -m pytest -m production_e2e -q`
   - 覆盖场景 1～6、9、10：正常 Web、SQLi、双层 XSS、命令注入、IOC、SYN/异常、审计篡改、Web 重启后历史告警可查。
   - 该分组要求模型制品完整，且不得设置 `GUARDIAN_REDIS_DISABLE_CONNECT=true`；模型缺失和 Redis memory fallback 不计入生产通过标准。

`scripts/verify_v1.py` 仍可作为研发补充回归手工运行，但它混有降级场景，不属于默认生产质量门禁，也不得作为生产验收通过证据。

## 可选分组

可在 GitHub Actions 页面手动触发 `workflow_dispatch`，通过 `optional_group` 选择：

- `slow`：运行 `python -m pytest -q --tb=short --maxfail=1 -m slow`
- `production-e2e`：运行 `python -m pytest -m production_e2e -q`
- `degradation-e2e`：运行 `python -m pytest -m degradation_e2e -q`
- `none`：只运行默认质量门禁

## 环境与密钥策略

CI 只使用 dummy 环境变量，例如 `SECRET_KEY` 与 `ADMIN_PASSWORD_HASH` 均为 CI 专用占位值。非降级验收测试通过测试认证夹具生成哈希并清除明文 `ADMIN_PASSWORD`，登录成功/失败仍走 `/api/auth/login`。不要在 workflow 中写入真实生产密钥；如后续需要访问制品仓库、私有镜像或部署环境，应使用 GitHub Environments / Actions Secrets 注入，并限制到部署 job。

默认 CI 设置 `GUARDIAN_REDIS_DISABLE_CONNECT=true`，避免普通单元测试依赖外部 Redis；production-e2e step 会显式覆盖为 `false`。集成测试如需真实 Redis，应新增独立 job 或服务容器，并保持它不阻塞默认质量门禁。

## 失败定位

CI 将不同风险面拆成独立 step：

- 依赖安装失败：先看 `Install dependencies` 或 `Dependency sanity check`。
- 普通逻辑回归：看 `Unit and offline tests`。
- 安全配置回归：看 `Critical security hardening tests`。
- SaaS 租户隔离回归：看 `SaaS tenant isolation static scan` 输出的 `ERROR ... suggestion=...` 行。
- schema 或模型治理回归：看 `Schema and manifest tests`。
- production-e2e 回归：看 `production-e2e 非降级生产验收` 输出的失败测试名。
- degradation-e2e 回归：只看手动触发的 `degradation-e2e` 分组；该分组不作为生产放行标准。
