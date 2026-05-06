# AI-Security-Guardian Dockerfile（Phase 8：集成与部署）
# 对应架构文档 §11 + Phase 8 提示词 B 节
#
# 构建：
#   docker build -t ai-security-guardian:latest .
#
# 在 Docker Hub 不可达（如国内网络）的环境下，可通过 build-arg 切换 pip 镜像：
#   docker build \
#     --build-arg PIP_INDEX_URL=https://pypi.tuna.tsinghua.edu.cn/simple \
#     --build-arg APT_MIRROR=mirrors.tuna.tsinghua.edu.cn \
#     -t ai-security-guardian:latest .
#
# 如宿主机无法拉取 python:3.10-slim，可在 Docker Desktop → Settings → Docker Engine
# 的 daemon.json 中配置 registry-mirrors，例：
#   { "registry-mirrors": ["https://docker.mirrors.ustc.edu.cn"] }
# 配置后重启 Docker Desktop 再执行构建。
#
# 选型说明（按 Phase 8 提示词要求明确）：
#   - 基础镜像: python:3.10-slim
#   - 系统依赖: libpcap-dev（供 Scapy 在需要抓包时使用；Web/API 容器不会真正抓包，
#               但安装它以便同一镜像可兼做完整检测链路入口）
#   - 非 root 用户: guardian（降低容器逃逸风险）
#   - 默认启动: Gunicorn gthread worker（Web/API 层，无需管理员权限）
#   - 开发启动: `python -m web.app` 保留给本地调试
#
# 注意：故意不使用 `# syntax=docker/dockerfile:1.6`，避免 buildx 在首次构建时
# 额外拉取 `docker/dockerfile:1.6` 前端镜像（这是部分网络下构建失败的主因）。
FROM python:3.10-slim AS base

# ---- 构建参数（全部可通过 --build-arg 覆盖）-------------------------
ARG PIP_INDEX_URL=https://pypi.org/simple
ARG PIP_EXTRA_INDEX_URL=
ARG APT_MIRROR=

# ---- 运行期环境变量 -------------------------------------------------
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    TZ=Asia/Shanghai \
    PORT=5000 \
    WEB_CONCURRENCY=1 \
    GUNICORN_THREADS=100 \
    GUNICORN_TIMEOUT=120 \
    GUNICORN_GRACEFUL_TIMEOUT=30 \
    GUNICORN_KEEPALIVE=5

WORKDIR /app

# ---- 系统依赖（可选切换 apt 源；仅保留运行必需项，减少攻击面）------
# 传入 APT_MIRROR=mirrors.tuna.tsinghua.edu.cn 即可加速国内构建。
RUN set -eux; \
    if [ -n "${APT_MIRROR}" ]; then \
        sed -i "s@deb.debian.org@${APT_MIRROR}@g" /etc/apt/sources.list.d/debian.sources 2>/dev/null || true; \
        sed -i "s@deb.debian.org@${APT_MIRROR}@g" /etc/apt/sources.list 2>/dev/null || true; \
    fi; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        libpcap-dev \
        ca-certificates \
        curl \
        tini; \
    rm -rf /var/lib/apt/lists/*

# ---- Python 依赖（利用层缓存；requirements 先复制，后复制代码）-----
COPY requirements.txt ./
RUN set -eux; \
    EXTRA=""; \
    if [ -n "${PIP_EXTRA_INDEX_URL}" ]; then EXTRA="--extra-index-url ${PIP_EXTRA_INDEX_URL}"; fi; \
    pip install --no-cache-dir -i "${PIP_INDEX_URL}" ${EXTRA} -r requirements.txt

# ---- 创建非 root 用户并切换 ----------------------------------------
RUN groupadd --system guardian \
 && useradd --system --gid guardian --home-dir /app --shell /sbin/nologin guardian

# ---- 复制应用代码 --------------------------------------------------
COPY . .

# ---- 必要目录权限（logs / models/saved）---------------------------
RUN mkdir -p /app/logs /app/models/saved \
 && chown -R guardian:guardian /app

USER guardian

# ---- 暴露端口（Flask/Socket.IO）-----------------------------------
EXPOSE 5000

# ---- 健康检查 ------------------------------------------------------
# 容器启动后 30s 开始探活，失败超 3 次视为不健康；/healthz 只检查进程存活
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD python -c "import sys, urllib.request; \
sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:5000/healthz', timeout=1).status == 200 else 1)" \
    || exit 1

# ---- 入口 ----------------------------------------------------------
# 使用 tini 作为 PID 1，正确处理 SIGTERM / SIGINT，保证容器优雅停止
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["sh", "-c", "exec gunicorn --bind 0.0.0.0:${PORT:-5000} --worker-class gthread --workers ${WEB_CONCURRENCY:-1} --threads ${GUNICORN_THREADS:-100} --timeout ${GUNICORN_TIMEOUT:-120} --graceful-timeout ${GUNICORN_GRACEFUL_TIMEOUT:-30} --keep-alive ${GUNICORN_KEEPALIVE:-5} --access-logfile - --error-logfile - --log-level ${GUNICORN_LOG_LEVEL:-info} web.wsgi:app"]
