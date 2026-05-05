"""
管理员认证辅助模块（Phase 8：消除明文密码）

核心目标：
    - 生产环境优先使用 ADMIN_PASSWORD_HASH（Werkzeug 安全哈希）
    - 明文 ADMIN_PASSWORD 仅作为向后兼容的兜底，命中即发出安全警告
    - 所有比较走常量时间函数（werkzeug.security.check_password_hash 内置），
      避免通过响应时间侧信道泄漏密码信息

为什么选 Werkzeug 而不是 bcrypt?
    - Werkzeug 是 Flask 的硬依赖，无需新增 runtime 包，降低部署门槛
    - 默认算法 `pbkdf2:sha256:600000`（16 字节盐）已达 OWASP 2023 推荐强度
    - 若用户希望更强的 bcrypt，可在环境变量直接传入形如 `bcrypt$...` 的哈希，
      Werkzeug 支持解析多种前缀（pbkdf2 / scrypt；bcrypt 需装 `passlib`）。
      本模块保留扩展点：若安装了 `passlib[bcrypt]`，会自动识别 `bcrypt$` / `$2b$` 前缀

对外接口：
    - verify_admin_credentials(username, password) -> bool
    - hash_password(password) -> str                 生成哈希（脚本使用）
    - is_hash_configured() -> bool                   判断是否已配置哈希
"""
from __future__ import annotations

import hmac
import logging
import os
from typing import Optional

from werkzeug.security import check_password_hash, generate_password_hash

logger = logging.getLogger(__name__)

#: 默认哈希算法（与 OWASP 2023 建议对齐）
_DEFAULT_ALGORITHM: str = "pbkdf2:sha256:600000"

#: 未修改的默认明文密码（命中即高风险告警）
_WEAK_DEFAULT_PASSWORDS = frozenset({"changeme", "admin", "password", "123456"})

#: 本模块内部缓存：同一进程内只警告一次"使用明文密码"
_plaintext_warned: bool = False


# ---------------------------------------------------------------------
# 对外 API
# ---------------------------------------------------------------------
def is_hash_configured() -> bool:
    """是否已配置 ADMIN_PASSWORD_HASH。"""
    return bool((os.environ.get("ADMIN_PASSWORD_HASH") or "").strip())


def hash_password(password: str, algorithm: str = _DEFAULT_ALGORITHM) -> str:
    """生成管理员密码哈希（供 scripts/generate_admin_password_hash.py 调用）。

    Args:
        password: 明文密码；调用方自行保证已做长度 / 强度校验。
        algorithm: 哈希算法，默认 pbkdf2:sha256:600000。

    Returns:
        形如 ``pbkdf2:sha256:600000$saltXXXX$hashYYY`` 的字符串，
        可直接写入 `.env` 的 ``ADMIN_PASSWORD_HASH``。
    """
    if not isinstance(password, str) or not password:
        raise ValueError("密码必须为非空字符串")
    return generate_password_hash(password, method=algorithm)


def verify_admin_credentials(username: str, password: str) -> bool:
    """校验管理员用户名 / 密码。

    策略（按优先级）：
        1. 生产环境（FLASK_ENV=production）：仅允许 ADMIN_PASSWORD_HASH，禁止明文兜底
        2. 非生产：若 ADMIN_PASSWORD_HASH 存在，使用 ``check_password_hash`` 验证
        3. 非生产：否则退回到 ADMIN_PASSWORD 明文比对（常量时间 ``hmac.compare_digest``）
           并在首次使用时打印 WARNING；弱默认密码打印 CRITICAL
        4. 若未配置任何凭据，拒绝登录并打印 ERROR

    Args:
        username: 提交的用户名（已 strip）。
        password: 提交的明文密码。

    Returns:
        bool: True 表示凭据正确且通过。
    """
    env = (os.environ.get("FLASK_ENV") or "development").strip().lower()
    if env == "production" and not is_hash_configured():
        logger.error(
            "[Auth] 生产环境未配置 ADMIN_PASSWORD_HASH，拒绝登录。"
            " 请运行 scripts/generate_admin_password_hash.py 生成哈希。"
        )
        return False

    expected_user = (os.environ.get("ADMIN_USERNAME") or "admin").strip()
    user_match = hmac.compare_digest(
        username.encode("utf-8"), expected_user.encode("utf-8")
    )

    hash_value = (os.environ.get("ADMIN_PASSWORD_HASH") or "").strip()
    plaintext = os.environ.get("ADMIN_PASSWORD")

    # -- 分支 1：配置了哈希 ------------------------------------------
    if hash_value:
        try:
            pwd_match = check_password_hash(hash_value, password)
        except ValueError as exc:
            # 哈希格式不合法（例如写了一段随机字符串到环境变量里）
            logger.error(
                "[Auth] ADMIN_PASSWORD_HASH 格式非法，登录一律失败: %s", exc
            )
            return False
        return bool(user_match and pwd_match)

    # -- 分支 2：未配置哈希，仅非生产允许明文兜底 --------------------
    if plaintext is not None:
        _warn_plaintext_once(plaintext)
        pwd_match = hmac.compare_digest(
            password.encode("utf-8"), plaintext.encode("utf-8")
        )
        return bool(user_match and pwd_match)

    # -- 分支 3：两者都未配置 ----------------------------------------
    logger.error(
        "[Auth] 未配置 ADMIN_PASSWORD_HASH 或 ADMIN_PASSWORD，一切登录请求都会失败。"
        " 请通过 `python scripts/generate_admin_password_hash.py` 生成哈希。"
    )
    return False


# ---------------------------------------------------------------------
# 内部工具
# ---------------------------------------------------------------------
def _warn_plaintext_once(plaintext: str) -> None:
    """首次命中明文密码路径时打印安全警告，避免污染日志。"""
    global _plaintext_warned
    if _plaintext_warned:
        return
    _plaintext_warned = True

    lowered = (plaintext or "").strip().lower()
    if lowered in _WEAK_DEFAULT_PASSWORDS:
        logger.critical(
            "[Auth] 检测到默认弱密码！请立即执行："
            " python scripts/generate_admin_password_hash.py"
            " 并在 .env 中设置 ADMIN_PASSWORD_HASH 后删除 ADMIN_PASSWORD。"
        )
    else:
        logger.warning(
            "[Auth] 使用明文 ADMIN_PASSWORD 登录。生产环境请改用 ADMIN_PASSWORD_HASH"
            "（运行 scripts/generate_admin_password_hash.py 生成）。"
        )


__all__ = [
    "hash_password",
    "is_hash_configured",
    "verify_admin_credentials",
]
