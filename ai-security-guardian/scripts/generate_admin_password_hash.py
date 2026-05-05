"""生成管理员密码的 Werkzeug 安全哈希（Phase 8）。

使用：
    python scripts/generate_admin_password_hash.py            交互式输入
    python scripts/generate_admin_password_hash.py -p secret  命令行传入（不推荐，会进 shell history）
    echo -n 'secret' | python scripts/generate_admin_password_hash.py --stdin

输出形如：
    pbkdf2:sha256:600000$SALT$HASH

将结果写入 `.env`：
    ADMIN_PASSWORD_HASH=pbkdf2:sha256:600000$SALT$HASH
并删除旧的 `ADMIN_PASSWORD` 明文配置。

安全注意事项：
    - 不要把明文密码写入 git / 聊天记录 / Prompt
    - 建议使用至少 12 位、含大小写 + 数字 + 符号的强密码
    - 部署后强烈建议立即撤销本次生成哈希时所使用的 shell 历史（history -c 或清理 pwsh 历史）
"""
from __future__ import annotations

import argparse
import getpass
import os
import sys


MIN_PASSWORD_LENGTH = 12


def _check_strength(password: str) -> list[str]:
    """返回一组弱点提示；空列表表示满足推荐强度。"""
    issues: list[str] = []
    if len(password) < MIN_PASSWORD_LENGTH:
        issues.append(f"长度应不少于 {MIN_PASSWORD_LENGTH} 位")
    if password.lower() == password:
        issues.append("缺少大写字母")
    if password.upper() == password:
        issues.append("缺少小写字母")
    if not any(c.isdigit() for c in password):
        issues.append("缺少数字")
    if password.isalnum():
        issues.append("缺少符号（如 !@#$）")
    return issues


def _read_password(args: argparse.Namespace) -> str:
    if args.stdin:
        data = sys.stdin.read()
        # 允许末尾换行但保留中间字符
        return data.rstrip("\r\n")
    if args.password is not None:
        return args.password

    # 交互式输入 + 二次确认
    pwd1 = getpass.getpass("请输入管理员密码: ")
    pwd2 = getpass.getpass("请再次输入确认: ")
    if pwd1 != pwd2:
        print("两次输入不一致。", file=sys.stderr)
        sys.exit(2)
    return pwd1


def main() -> int:
    parser = argparse.ArgumentParser(
        description="生成管理员密码的 Werkzeug 安全哈希"
    )
    parser.add_argument(
        "-p", "--password",
        help="命令行直接传入密码（会进 shell history，仅自动化场景使用）",
    )
    parser.add_argument(
        "--stdin", action="store_true",
        help="从标准输入读取密码（推荐配合 echo -n 或管道使用）",
    )
    parser.add_argument(
        "--algorithm",
        default="pbkdf2:sha256:600000",
        help="哈希算法，默认 pbkdf2:sha256:600000",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="允许弱密码（仅开发环境使用；默认拒绝）",
    )
    args = parser.parse_args()

    # 保证可以 from src.utils.auth import hash_password
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
    from src.utils.auth import hash_password  # noqa: WPS433

    password = _read_password(args)
    if not password:
        print("密码不能为空。", file=sys.stderr)
        return 2

    issues = _check_strength(password)
    if issues and not args.force:
        print("密码强度不足：", file=sys.stderr)
        for item in issues:
            print(f"  - {item}", file=sys.stderr)
        print(
            "\n如确认要使用弱密码（仅限开发环境），追加 --force 重新运行。",
            file=sys.stderr,
        )
        return 3

    digest = hash_password(password, algorithm=args.algorithm)
    print("\n请将以下一行写入 .env 文件 (并删除旧的 ADMIN_PASSWORD)：\n")
    print(f"ADMIN_PASSWORD_HASH={digest}")
    print("\n提示：该哈希无法从输出反推原始密码；同一密码每次生成的哈希都不同。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
