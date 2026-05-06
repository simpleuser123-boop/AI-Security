"""
应用配置模块。

安全要求：
- 禁止硬编码生产密钥，SECRET_KEY 必须通过环境变量提供。
- 区分开发、生产、测试三套配置。
- 生产环境（FLASK_ENV=production）在 ``get_config()`` 中执行额外硬化校验。
"""
from __future__ import annotations

import os
import re
from typing import List, Type
from urllib.parse import urlparse

from sqlalchemy.engine import make_url

from src.audit.log_paths import resolve_audit_log_dir
from src.utils.env_loader import load_dotenv_file

load_dotenv_file()

#: 禁止在生产环境使用的 SECRET_KEY 取值（含示例与开发默认值）
_FORBIDDEN_PRODUCTION_SECRET_KEYS: frozenset[str] = frozenset(
    {
        "",
        "dev-only-insecure-key-never-use-in-production",
        "test-only-secret-key",
        "changeme",
        "secret",
        "REPLACE_ME_WITH_64_HEX_CHARS",
        "your-secret-key",
        "please-change-me",
    }
)

_FORBIDDEN_PRODUCTION_PASSWORD_VALUES: frozenset[str] = frozenset(
    {
        "admin",
        "guardian",
        "changeme",
        "password",
        "password123",
        "secret",
        "123456",
        "admin123",
    }
)

_FORBIDDEN_PRODUCTION_ORIGINS: frozenset[str] = frozenset(
    {
        "http://localhost",
        "http://localhost:5000",
        "http://127.0.0.1",
        "http://127.0.0.1:5000",
        "http://0.0.0.0",
        "http://0.0.0.0:5000",
    }
)

_FORBIDDEN_PRODUCTION_ORIGIN_HOSTS: frozenset[str] = frozenset(
    {"localhost", "127.0.0.1", "0.0.0.0", "::1"}
)

_FORBIDDEN_PRODUCTION_ORIGIN_TOKENS: frozenset[str] = frozenset(
    {"example", "replace", "replace_with", "change_me", "changeme", "placeholder"}
)


def _require_env(key: str) -> str:
    """强制从环境变量获取配置，缺失则抛出异常。"""
    value = os.environ.get(key)
    if value is None or value == "":
        raise RuntimeError(
            f"环境变量 {key} 未设置。请参考 .env.example 配置环境变量。"
        )
    return value


def _resolve_secret_key() -> str:
    """按环境解析 SECRET_KEY。开发/测试允许不安全默认值；生产必须显式设置。"""
    key = os.environ.get("SECRET_KEY")
    if key:
        return key

    env = os.environ.get("FLASK_ENV", "development")
    if env == "development":
        return "dev-only-insecure-key-never-use-in-production"
    if env == "testing":
        return "test-only-secret-key"

    return _require_env("SECRET_KEY")


def _parse_allowed_origins(raw: str) -> List[str]:
    """逗号分隔 Origin 列表，去空白、去空项；禁止裸 ``*`` 作为条目。"""
    parts = [x.strip() for x in (raw or "").split(",")]
    return [p for p in parts if p and p != "*"]


def _validate_production_hardening(cfg: Type["Config"]) -> None:
    """生产环境启动前强制项：密钥、管理员哈希、Redis 密码、CORS 白名单。"""
    sk = (os.environ.get("SECRET_KEY") or "").strip()
    if not sk:
        raise RuntimeError("生产环境必须设置非空 SECRET_KEY。")
    if sk in _FORBIDDEN_PRODUCTION_SECRET_KEYS:
        raise RuntimeError(
            "生产环境禁止使用默认或示例 SECRET_KEY，请使用高强度随机值生成新的密钥。"
        )
    if len(sk) < 32:
        raise RuntimeError("生产环境 SECRET_KEY 长度建议至少 32 字符。")

    admin_hash = (os.environ.get("ADMIN_PASSWORD_HASH") or "").strip()
    if not admin_hash:
        raise RuntimeError(
            "生产环境必须设置 ADMIN_PASSWORD_HASH（禁止仅依赖明文 ADMIN_PASSWORD）。"
            " 使用: python scripts/generate_admin_password_hash.py"
        )
    if admin_hash.lower() in _FORBIDDEN_PRODUCTION_PASSWORD_VALUES:
        raise RuntimeError("生产环境 ADMIN_PASSWORD_HASH 不能是默认明文密码。")
    if not (
        admin_hash.startswith("pbkdf2:") or admin_hash.startswith("scrypt:")
    ) or "$" not in admin_hash:
        raise RuntimeError(
            "生产环境 ADMIN_PASSWORD_HASH 必须是 Werkzeug 密码哈希，"
            "请使用 scripts/generate_admin_password_hash.py 生成。"
        )

    if (os.environ.get("ADMIN_PASSWORD") or "").strip():
        raise RuntimeError("生产环境禁止设置明文 ADMIN_PASSWORD。")

    redis_pwd = (os.environ.get("REDIS_PASSWORD") or "").strip()
    if not redis_pwd:
        raise RuntimeError(
            "生产环境必须设置 REDIS_PASSWORD，避免 Redis 无鉴权暴露。"
        )
    if (
        redis_pwd.lower() in _FORBIDDEN_PRODUCTION_PASSWORD_VALUES
        or len(redis_pwd) < 12
    ):
        raise RuntimeError(
            "生产环境 REDIS_PASSWORD 不能使用默认/弱密码，且长度至少 12 字符。"
        )

    raw_origins = os.environ.get("ALLOWED_ORIGINS", "") or ""
    for token in raw_origins.split(","):
        if token.strip() == "*":
            raise RuntimeError("生产环境 CORS 禁止使用通配符 *。")

    origins = list(getattr(cfg, "ALLOWED_ORIGINS", []) or [])
    if not origins:
        raise RuntimeError(
            "生产环境 ALLOWED_ORIGINS 不能为空；请配置逗号分隔的 https 站点 Origin。"
        )
    for o in origins:
        origin = o.strip()
        if origin == "*":
            raise RuntimeError("生产环境 CORS 禁止使用通配符 *。")
        lo = origin.lower().rstrip("/")
        parsed = urlparse(origin)
        host = (parsed.hostname or "").strip().lower()
        if not parsed.scheme or not host:
            raise RuntimeError(f"生产环境 CORS Origin 格式无效: {origin!r}")
        if parsed.path not in {"", "/"} or parsed.params or parsed.query or parsed.fragment:
            raise RuntimeError(f"生产环境 CORS Origin 不能包含 path/query/fragment: {origin!r}")
        if lo in _FORBIDDEN_PRODUCTION_ORIGINS or host in _FORBIDDEN_PRODUCTION_ORIGIN_HOSTS:
            raise RuntimeError(f"生产环境 CORS Origin 禁止使用本地/示例地址: {origin!r}")
        if not lo.startswith("https://"):
            raise RuntimeError(f"生产环境 CORS Origin 必须使用 https://: {origin!r}")
        if "*" in host:
            raise RuntimeError(f"生产环境 CORS Origin 禁止使用通配符域名: {origin!r}")
        if "." not in host:
            raise RuntimeError(f"生产环境 CORS Origin 必须使用正式域名: {origin!r}")
        host_tokens = {token for token in re.split(r"[^a-z0-9_]+", host) if token}
        if host_tokens & _FORBIDDEN_PRODUCTION_ORIGIN_TOKENS:
            raise RuntimeError(f"生产环境 CORS Origin 不能使用示例或占位域名: {origin!r}")


def _validate_production_database_url(database_url: str) -> None:
    """生产数据库要求：PostgreSQL 为正式路径，SQLite 仅用于开发/测试。"""
    try:
        url = make_url(database_url)
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError(f"生产环境 DATABASE_URL 无法解析: {exc}") from exc

    driver = url.get_backend_name()
    if driver == "sqlite":
        raise RuntimeError(
            "生产环境禁止使用 SQLite DATABASE_URL；SQLite 仅用于开发/测试。"
            "请改用 PostgreSQL，例如 postgresql+psycopg2://user:pass@host:5432/dbname。"
        )
    if driver != "postgresql":
        raise RuntimeError(
            "生产环境推荐且当前支持的正式数据库为 PostgreSQL；"
            f"当前 DATABASE_URL backend={driver!r}。"
        )


class Config:
    """基础配置。"""

    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL", "sqlite:///security.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    REDIS_HOST = os.environ.get("REDIS_HOST", "localhost")
    REDIS_PORT = int(os.environ.get("REDIS_PORT", "6379"))
    REDIS_DB = int(os.environ.get("REDIS_DB", "0"))
    REDIS_PASSWORD = os.environ.get("REDIS_PASSWORD", "")
    REDIS_CONNECT_TIMEOUT_SEC = float(os.environ.get("REDIS_CONNECT_TIMEOUT_SEC", "0.2"))
    REDIS_SOCKET_TIMEOUT_SEC = float(os.environ.get("REDIS_SOCKET_TIMEOUT_SEC", "0.3"))
    HEALTHCHECK_DEPENDENCY_TIMEOUT_SEC = float(
        os.environ.get("HEALTHCHECK_DEPENDENCY_TIMEOUT_SEC", "0.3")
    )
    # 生产落地保护：关键依赖是否必须可用（不可用时启动失败）
    REQUIRE_REDIS_AVAILABLE = (
        os.environ.get("REQUIRE_REDIS_AVAILABLE", "false").lower() == "true"
    )
    REQUIRE_MODELS_READY = (
        os.environ.get("REQUIRE_MODELS_READY", "false").lower() == "true"
    )

    GUARDIAN_ALERT_STREAM = os.environ.get("GUARDIAN_ALERT_STREAM", "guardian:alerts")
    GUARDIAN_ALERT_STREAM_GROUP = os.environ.get("GUARDIAN_ALERT_STREAM_GROUP", "guardian:web")
    ALERT_STREAM_CONSUMER_AUTOSTART = os.environ.get(
        "ALERT_STREAM_CONSUMER_AUTOSTART", "true"
    ).lower() == "true"

    LOG_DIR = resolve_audit_log_dir()
    LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")
    MODEL_DIR = "models/saved"

    ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY", "")
    VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")
    # 威胁情报：单次 HTTP 超时（秒）、并行外部查询总等待上限（秒，超时则降级不判恶意）
    THREAT_INTEL_HTTP_TIMEOUT = float(os.environ.get("THREAT_INTEL_HTTP_TIMEOUT", "5"))
    THREAT_INTEL_EXTERNAL_WAIT_SEC = float(os.environ.get("THREAT_INTEL_EXTERNAL_WAIT_SEC", "0.45"))
    # DeepSeek/OpenAI-compatible endpoint config
    DEEPSEEK_API_BASE = os.environ.get("DEEPSEEK_API_BASE", "")
    DEEPSEEK_API_KEY = os.environ.get("DEEPSEEK_API_KEY", "")

    SECRET_KEY = _resolve_secret_key()
    JWT_TOKEN_EXPIRES = int(os.environ.get("JWT_TOKEN_EXPIRES", "3600"))
    JWT_REFRESH_TOKEN_EXPIRES = int(os.environ.get("JWT_REFRESH_TOKEN_EXPIRES", "86400"))

    API_RATE_LIMIT = os.environ.get("API_RATE_LIMIT", "100 per minute")
    ALLOWED_ORIGINS = _parse_allowed_origins(
        os.environ.get("ALLOWED_ORIGINS", "http://localhost:5000")
    )

    ALERT_EMAIL = os.environ.get("ALERT_EMAIL", "")
    ALERT_WEBHOOK = os.environ.get("ALERT_WEBHOOK", "")
    ALERT_SMTP_HOST = os.environ.get("ALERT_SMTP_HOST", "")
    ALERT_SMTP_PORT = int(os.environ.get("ALERT_SMTP_PORT", "587"))
    ALERT_SMTP_USER = os.environ.get("ALERT_SMTP_USER", "")
    ALERT_SMTP_PASSWORD = os.environ.get("ALERT_SMTP_PASSWORD", "")
    ALERT_SMTP_FROM = os.environ.get("ALERT_SMTP_FROM", "")
    ALERT_SMTP_USE_TLS = os.environ.get("ALERT_SMTP_USE_TLS", "true").lower() == "true"
    ALERT_NOTIFY_MAX_RETRIES = int(os.environ.get("ALERT_NOTIFY_MAX_RETRIES", "3"))
    ALERT_ENTERPRISE_CHANNEL_ENABLED = (
        os.environ.get("ALERT_ENTERPRISE_CHANNEL_ENABLED", "").lower() == "true"
    )

    RESPONSE_FIREWALL_BACKEND = os.environ.get("RESPONSE_FIREWALL_BACKEND", "iptables")
    RESPONSE_HOST_ISOLATION = os.environ.get("RESPONSE_HOST_ISOLATION", "none")
    RESPONSE_BUSINESS_IP_WHITELIST = os.environ.get("RESPONSE_BUSINESS_IP_WHITELIST", "")
    RESPONSE_PRIVATE_IP_WHITELIST = os.environ.get("RESPONSE_PRIVATE_IP_WHITELIST", "")

    LOG_INTEGRITY_ENABLED = os.environ.get("LOG_INTEGRITY_ENABLED", "true").lower() == "true"
    LOG_INTEGRITY_ALGORITHM = "sha256"


class DevelopmentConfig(Config):
    """开发环境配置。"""

    DEBUG = True
    LOG_DIR = resolve_audit_log_dir(env="dev")
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-only-insecure-key-never-use-in-production")
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL", "sqlite:///data/security.db")


class ProductionConfig(Config):
    """生产环境配置。"""

    DEBUG = False
    LOG_DIR = resolve_audit_log_dir(env="production")
    LOG_INTEGRITY_ENABLED = True


class TestingConfig(Config):
    """测试环境配置。"""

    TESTING = True
    LOG_DIR = resolve_audit_log_dir(env="test")
    # 默认内存库；若运行时设置了 ``DATABASE_URL``（如 pytest 临时文件），由 ``get_config()`` 覆盖。
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    SECRET_KEY = os.environ.get("SECRET_KEY", "test-only-secret-key")
    # 避免 pytest 挂起：默认不拉起后台 consumer，需要时用环境变量显式开启
    ALERT_STREAM_CONSUMER_AUTOSTART = (
        os.environ.get("ALERT_STREAM_CONSUMER_AUTOSTART", "").lower() == "true"
    )


config_map: dict[str, Type[Config]] = {
    "development": DevelopmentConfig,
    "production": ProductionConfig,
    "testing": TestingConfig,
}


def get_config() -> Type[Config]:
    """根据 FLASK_ENV 环境变量返回对应配置类，并执行生产环境校验。"""
    env = os.environ.get("FLASK_ENV", "development")
    cfg = config_map.get(env, DevelopmentConfig)

    # TestingConfig 类属性在 import 时固定为内存库；每次按当前环境变量解析，避免类属性泄漏。
    if env == "testing":
        cfg.SQLALCHEMY_DATABASE_URI = os.environ.get(
            "DATABASE_URL", "sqlite:///:memory:"
        )

    if env == "production":
        _require_env("DATABASE_URL")
        _require_env("SECRET_KEY")
        cfg.SQLALCHEMY_DATABASE_URI = os.environ["DATABASE_URL"]
        cfg.SECRET_KEY = os.environ["SECRET_KEY"]
        cfg.REQUIRE_REDIS_AVAILABLE = (
            os.environ.get("REQUIRE_REDIS_AVAILABLE", "true").lower() == "true"
        )
        cfg.REQUIRE_MODELS_READY = (
            os.environ.get("REQUIRE_MODELS_READY", "true").lower() == "true"
        )
        cfg.ALLOWED_ORIGINS = _parse_allowed_origins(
            os.environ.get("ALLOWED_ORIGINS", "")
        )
        _validate_production_hardening(cfg)
        _validate_production_database_url(cfg.SQLALCHEMY_DATABASE_URI)

    return cfg
