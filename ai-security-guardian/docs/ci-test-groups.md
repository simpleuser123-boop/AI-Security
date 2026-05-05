# CI/CD 与测试分组

本项目使用 GitHub Actions 作为基础 CI。默认质量门禁在每次 `push` / `pull_request` 上运行，目标是快速发现单元、核心安全、schema/manifest 和 v1 验收问题；慢测与完整 E2E 不放进默认必跑链路，避免 CI 被外部等待或端到端流程拖慢。

## 默认质量门禁

工作流文件：`.github/workflows/ci.yml`

CI 使用 Python 3.10，和 `Dockerfile` 中的 `python:3.10-slim` 运行基线保持一致。

默认 `Quality Gate` 包含：

1. **依赖安装**
   - `python -m pip install -r requirements.txt`
   - `python -m pip install pytest`
   - `python -m pip check`

2. **单元与离线快测**
   - `python -m pytest -q --tb=short --maxfail=1 -m "not integration and not e2e and not slow"`
   - 对齐 `pytest.ini` 的默认策略，排除需要外部服务或明显耗时的测试。

3. **关键安全硬化测试**
   - `python -m pytest tests/test_production_hardening.py -q --tb=short --maxfail=1`
   - 覆盖生产密钥、管理员口令策略、JWT 保护、CORS、Webhook SSRF 与 Redis 密码等关键硬化行为。

4. **schema/manifest 测试**
   - `python -m pytest tests/test_schema_manifest.py tests/test_model_registry.py -q --tb=short --maxfail=1`
   - 覆盖特征 schema、模型 manifest、模型治理字段、版本切换和上线策略。

5. **v1 验收脚本**
   - `python scripts/verify_v1.py`
   - 覆盖 v1 场景 1 到 9。场景 10 由 E2E 分组覆盖。

## 可选分组

可在 GitHub Actions 页面手动触发 `workflow_dispatch`，通过 `optional_group` 选择：

- `slow`：运行 `python -m pytest -q --tb=short --maxfail=1 -m slow`
- `e2e`：运行 `python -m pytest -q --tb=short --maxfail=1 -m e2e`
- `none`：只运行默认质量门禁

## 环境与密钥策略

CI 只使用 dummy 环境变量，例如 `SECRET_KEY` 与 `ADMIN_PASSWORD` 均为 CI 专用占位值。不要在 workflow 中写入真实生产密钥；如后续需要访问制品仓库、私有镜像或部署环境，应使用 GitHub Environments / Actions Secrets 注入，并限制到部署 job。

默认 CI 设置 `GUARDIAN_REDIS_DISABLE_CONNECT=true`，避免依赖外部 Redis；集成测试如需真实 Redis，应新增独立 job 或服务容器，并保持它不阻塞默认质量门禁。

## 失败定位

CI 将不同风险面拆成独立 step：

- 依赖安装失败：先看 `Install dependencies` 或 `Dependency sanity check`。
- 普通逻辑回归：看 `Unit and offline tests`。
- 安全配置回归：看 `Critical security hardening tests`。
- schema 或模型治理回归：看 `Schema and manifest tests`。
- v1 场景回归：看 `v1 acceptance scenarios` 输出的具体 `[PASS]` / 失败场景。
