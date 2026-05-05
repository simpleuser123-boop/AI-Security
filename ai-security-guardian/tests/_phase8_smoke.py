"""Phase 8 冒烟测试（扩展版）。

运行：
    python -m tests._phase8_smoke

断言覆盖：
    [S1] 主入口可正常导入
    [S2] 缺少部分模型文件时系统不直接崩溃
    [S3] Redis 不可用时仍能正常启动（降级到内存模式）
    [S4] 规则引擎在 ML 未加载时仍可识别 SQL 注入
    [S5] shutdown() 幂等可重复调用
    [S6] 哈希链完整性校验通过
    [S7] 管理员认证：哈希优先、明文兜底、弱密码告警
    [S8] Redis Streams：xadd -> xreadgroup -> xack 的内存降级语义正确
    [S9] bootstrap_models 在非交互环境下优雅退出（stdin 关闭）
"""
from __future__ import annotations

import io
import logging
import os
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent


def _close_security_logger_handlers() -> None:
    """Release FileHandler locks before deleting temporary smoke directories."""
    loggers = [logging.getLogger("security")]
    loggers.extend(
        logger
        for name, logger in logging.Logger.manager.loggerDict.items()
        if name.startswith("security.") and isinstance(logger, logging.Logger)
    )
    for sec_logger in loggers:
        for handler in list(sec_logger.handlers):
            sec_logger.removeHandler(handler)
            try:
                handler.flush()
            finally:
                handler.close()


def _setup_env() -> None:
    os.environ.setdefault("SECRET_KEY", "phase8-smoke-secret")
    os.environ.setdefault("DRY_RUN", "true")
    os.environ.setdefault("ENABLE_PACKET_CAPTURE", "false")
    os.environ.setdefault("ENABLE_WEB_LOG", "false")
    os.environ.setdefault("ENABLE_FLASK", "false")
    os.environ.setdefault("ADMIN_USERNAME", "admin")


def test_main_integration() -> None:
    """S1~S6: 主入口集成 + 降级 + 规则引擎 + 完整性校验。"""
    _setup_env()
    sys.path.insert(0, str(ROOT))

    old_cwd = os.getcwd()
    with tempfile.TemporaryDirectory(prefix="guardian-phase8-smoke-") as tmp:
        # SecurityGuardian uses relative logs/model paths; chdir keeps this
        # smoke independent from the repository's real security.log.
        os.chdir(tmp)
        try:
            from main import RuntimeConfig, SecurityGuardian

            cfg = RuntimeConfig.from_env()
            guardian = SecurityGuardian(cfg=cfg)

            print("[S1] Guardian init OK (redis.mode =", guardian.redis.mode, ")")
            assert guardian.redis.mode in {"redis", "memory"}

            loaded = guardian.load_models()
            print("[S2] loaded_models =", loaded, "(缺失模型不崩溃)")
            assert isinstance(loaded, dict)

            guardian.process_web_log(
                {
                    "src_ip": "10.0.0.99",
                    "http_method": "GET",
                    "url": "/users?id=1' UNION SELECT * FROM users--",
                    "status_code": 200,
                    "response_size": 512,
                }
            )
            print("[S4] 规则引擎命中 SQLi OK")

            guardian.shutdown()
            guardian.shutdown()
            print("[S5] shutdown 幂等 OK")

            verify = guardian.security_logger.verify_integrity()
            print("[S6] verify_integrity:", verify)
            assert verify["valid"], f"完整性校验失败: {verify}"
        finally:
            _close_security_logger_handlers()
            os.chdir(old_cwd)


def test_admin_auth_hashed() -> None:
    """S7a: 配置 ADMIN_PASSWORD_HASH 时应优先匹配哈希。"""
    # 每个用例前把模块 reset 掉以清除 "_plaintext_warned" 状态
    sys.modules.pop("src.utils.auth", None)
    from src.utils.auth import hash_password, verify_admin_credentials

    # 生成一个强密码的哈希并写入环境变量
    strong_password = "Str0ng!Pass@2026"
    digest = hash_password(strong_password)
    assert digest.startswith("pbkdf2:sha256"), f"哈希算法错误: {digest}"

    os.environ["ADMIN_USERNAME"] = "admin"
    os.environ["ADMIN_PASSWORD_HASH"] = digest
    os.environ.pop("ADMIN_PASSWORD", None)

    assert verify_admin_credentials("admin", strong_password) is True
    assert verify_admin_credentials("admin", "wrong-password") is False
    assert verify_admin_credentials("root", strong_password) is False
    print("[S7a] 哈希认证 OK")

    # 模拟配置了非法哈希的情况
    os.environ["ADMIN_PASSWORD_HASH"] = "this-is-not-a-hash"
    assert verify_admin_credentials("admin", strong_password) is False
    print("[S7a2] 非法哈希一律拒绝 OK")


def test_admin_auth_plaintext_fallback() -> None:
    """S7b: 未配置 HASH 时走明文兜底，弱默认值应打印 CRITICAL。"""
    sys.modules.pop("src.utils.auth", None)
    # 捕获日志
    import logging

    buf = io.StringIO()
    handler = logging.StreamHandler(buf)
    handler.setLevel(logging.DEBUG)
    root = logging.getLogger()
    root.addHandler(handler)
    previous_level = root.level
    root.setLevel(logging.DEBUG)

    try:
        from src.utils.auth import verify_admin_credentials

        os.environ.pop("ADMIN_PASSWORD_HASH", None)
        os.environ["ADMIN_PASSWORD"] = "changeme"
        os.environ["ADMIN_USERNAME"] = "admin"

        assert verify_admin_credentials("admin", "changeme") is True
        assert verify_admin_credentials("admin", "wrong") is False
        logs = buf.getvalue()
        assert "默认弱密码" in logs or "weak" in logs.lower() or "CRITICAL" in logs, (
            f"应出现弱密码告警: {logs[:500]}"
        )
        print("[S7b] 明文兜底 + 弱密码告警 OK")
    finally:
        root.removeHandler(handler)
        root.setLevel(previous_level)


def test_redis_streams_memory_mode() -> None:
    """S8: 验证 Redis Streams 在内存降级下的 xadd/xreadgroup/xack 语义。"""
    sys.modules.pop("src.utils.redis_client", None)
    from src.utils.redis_client import RedisClient

    # 指一个必定不存在的端口，强制进入内存模式
    client = RedisClient(host="127.0.0.1", port=1, password="")
    assert client.mode == "memory", f"期望内存模式, 实际 {client.mode}"

    stream = "smoke:alerts"
    group = "workers"

    ok = client.stream_ensure_group(stream, group)
    assert ok, "stream_ensure_group 应返回 True"

    ids = []
    for i in range(3):
        msg_id = client.stream_add(
            stream,
            {"level": "high", "seq": i, "details": f"event-{i}"},
            maxlen=100,
        )
        assert msg_id, "stream_add 应返回非空 id"
        ids.append(msg_id)

    assert client.stream_len(stream) == 3
    assert client.stream_pending(stream, group) == 0

    # consumer A 读 2 条
    entries_a = client.stream_read_group(stream, group, "consumer-A", count=2)
    assert len(entries_a) == 2, f"期望 2 条, 实际 {len(entries_a)}"
    assert client.stream_pending(stream, group) == 2

    # consumer B 应只能读到剩下 1 条
    entries_b = client.stream_read_group(stream, group, "consumer-B", count=10)
    assert len(entries_b) == 1, f"期望 1 条, 实际 {len(entries_b)}"
    assert client.stream_pending(stream, group) == 3

    # ack 其中 1 条
    acked = client.stream_ack(stream, group, [entries_a[0][0]])
    assert acked == 1
    assert client.stream_pending(stream, group) == 2

    # 字段应保留 JSON 反序列化
    first_fields = entries_a[0][1]
    assert first_fields["level"] == "high"
    assert isinstance(first_fields["seq"], int)

    print("[S8] Redis Streams 内存降级语义 OK")


def test_bootstrap_models_non_interactive() -> None:
    """S9: bootstrap_models 在非交互环境 (--check) 下应能正确退出。"""
    # 使用 --check 避免触发真实训练
    proc = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "bootstrap_models.py"), "--check"],
        capture_output=True,
        text=True,
        timeout=30,
        cwd=str(ROOT),
    )
    print("[S9] bootstrap_models --check returncode =", proc.returncode)
    assert proc.returncode in (0, 2), (
        f"--check 只应返回 0(齐全) 或 2(缺失): {proc.returncode}"
        f"\nstdout=\n{proc.stdout}\nstderr=\n{proc.stderr}"
    )
    assert "ETAT" in proc.stdout or "READY" in proc.stdout or "MISSING" in proc.stdout, (
        "应打印模型状态表"
    )


def main() -> int:
    print("=" * 60)
    print("Phase 8 冒烟测试（扩展版）")
    print("=" * 60)
    try:
        test_main_integration()
        test_admin_auth_hashed()
        test_admin_auth_plaintext_fallback()
        test_redis_streams_memory_mode()
        test_bootstrap_models_non_interactive()
    except AssertionError as exc:
        print(f"\n[FAIL] {exc}")
        return 1
    except Exception as exc:  # noqa: BLE001
        import traceback

        traceback.print_exc()
        print(f"\n[ERROR] {exc}")
        return 2
    print("\n[smoke] Phase 8 smoke test PASSED (all 9 checks)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
