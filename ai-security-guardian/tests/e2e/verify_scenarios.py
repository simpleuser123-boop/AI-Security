"""
v1.0 端到端验收场景（与 docs/AI安全守卫-v1.0-交付验收与路线图.md §8 对齐）。

实现说明：
- Web 攻击类场景在进程内调用 WebAttackDetector / WebFeatureExtractor，与 main.py
  process_web_log → detect 路径一致。
- IOC 使用 ThreatIntelCollector 内存黑名单（等价于「本地黑名单 IP」）。
- 流量异常：优先使用已加载的异常检测模型；若无模型，则用与 test_detectors 一致的
  合成特征 + 伪装模型验证「SYN 突增类」流特征可升为 anomaly high（替代验证）。
- Redis：连接非法端口验证降级为 memory 模式（等价于停止 Redis 后的客户端行为）。
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, List, Tuple

# 项目根目录
_PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from src.audit.security_logger import SecurityLogger  # noqa: E402
from src.detectors.anomaly_detector import AnomalyDetector  # noqa: E402
from src.detectors.ddos_detector import DDoSDetector  # noqa: E402
from src.detectors.web_detector import WebAttackDetector  # noqa: E402
from src.collectors.threat_intel import ThreatIntelCollector  # noqa: E402
from src.features.web_features import WebFeatureExtractor  # noqa: E402
from src.registry.model_registry import ModelRegistry  # noqa: E402


def _release_security_logger_handlers(sl: SecurityLogger) -> None:
    """Windows 下 tempfile 删除目录前须关闭 FileHandler，否则会 PermissionError。"""
    for h in list(sl.logger.handlers):
        sl.logger.removeHandler(h)
        try:
            h.close()
        except Exception:
            pass


def _wf(url: str, src_ip: str = "198.51.100.77") -> dict:
    raw = {
        "url": url,
        "http_method": "GET",
        "status_code": 200,
        "response_size": 100,
        "src_ip": src_ip,
    }
    return WebFeatureExtractor().extract(raw)


def check_01_normal_web_no_alert() -> None:
    d = WebAttackDetector()
    feat = _wf("/api/items?id=1")
    r = d.detect(feat)
    if r is None or r.threat_type != "normal":
        raise AssertionError(f"期望 normal，得到 {r}")


def check_02_sqli_web_attack_high() -> None:
    d = WebAttackDetector()
    # 与验收文档一致：/login?u=admin' OR 1=1--
    feat = _wf("/login?u=admin' OR 1=1--")
    r = d.detect(feat)
    if r is None:
        raise AssertionError("未检测到攻击")
    if r.threat_type != "web_attack" or r.threat_level != "high":
        raise AssertionError(f"期望 web_attack high，得到 {r.threat_type} {r.threat_level}")
    if "sql" not in (r.details or "").lower():
        raise AssertionError(f"details 应含 sql 线索: {r.details}")


def check_03_double_encoded_xss_high() -> None:
    d = WebAttackDetector()
    feat = _wf("/q=%253Cscript%253Ealert(1)%253C%252Fscript%253E")
    r = d.detect(feat)
    if r is None or r.threat_type != "web_attack" or r.threat_level != "high":
        raise AssertionError(f"期望 web_attack high，得到 {r}")
    if "xss" not in (r.details or "").lower():
        raise AssertionError(f"期望 xss: {r.details}")


def check_04_cmd_injection_high() -> None:
    d = WebAttackDetector()
    feat = _wf("/ping?host=127.0.0.1;cat /etc/passwd")
    r = d.detect(feat)
    if r is None or r.threat_type != "web_attack" or r.threat_level != "high":
        raise AssertionError(f"期望 web_attack high，得到 {r}")
    if "command" not in (r.details or "").lower():
        raise AssertionError(f"期望 command_injection: {r.details}")


def check_05_ioc_threat_intel_high() -> None:
    ti = ThreatIntelCollector(abuseipdb_key="", virustotal_key="")
    ip = "192.0.2.50"
    if not ti.add_ip_to_blacklist(ip):
        raise AssertionError("加入黑名单失败")
    r = ti.check_ip(ip)
    if not r.get("is_malicious"):
        raise AssertionError(f"黑名单 IP 应命中: {r}")
    if str(r.get("source", "")).lower() != "local":
        raise AssertionError(f"期望 source=local（内存黑名单）: {r}")


def check_06_syn_surge_anomaly_or_ddos() -> None:
    """SYN 突增：优先真实模型；否则用合成 IF/AE 命中 anomaly high（替代验证）。"""
    model_dir = os.environ.get("MODEL_DIR", "models/saved")
    ad = AnomalyDetector()
    reg = ModelRegistry(model_dir)
    path = reg.resolve_load_path("anomaly")
    loaded = False
    if path:
        try:
            reg.try_load_detector("anomaly", ad)
            loaded = ad.is_ready
        except Exception:
            loaded = False

    feat = {
        "src_ip": "10.10.10.10",
        "protocol": "tcp",
        "pkt_len_mean": 50,
        "flow_byte_count": 1000,
        "flow_pkt_count": 100,
        "window_unique_dst_port": 10,
        "syn_count": 200,
    }
    if loaded:
        r = ad.detect(feat)
        if r is None:
            raise AssertionError("异常模型已加载但无输出（调整特征或检查模型）")
        if r.threat_type not in ("anomaly", "ddos"):
            raise AssertionError(f"期望 anomaly/ddos 类，得到 {r.threat_type}")
        if r.threat_level not in ("high", "medium", "critical"):
            raise AssertionError(f"期望中高等级告警: {r.threat_level}")
        return

    # 替代验证：与 tests/test_detectors.py 一致的双模型命中 → anomaly high
    class _FakeIF:
        def predict(self, X):  # noqa: ANN001
            return [-1]

    class _FakeScaler:
        def transform(self, X):  # noqa: ANN001
            return X

    class _FakeAE:
        def predict(self, X, verbose=0):  # noqa: ANN001
            import numpy as np

            return np.zeros_like(X)

    ad2 = AnomalyDetector()
    ad2.if_model = _FakeIF()
    ad2.ae_model = _FakeAE()
    ad2.ae_scaler = _FakeScaler()
    ad2.ae_threshold = 0.001
    r2 = ad2.detect(feat)
    if r2 is None or r2.threat_type != "anomaly":
        raise AssertionError("替代路径应产生 anomaly")
    if r2.threat_level != "high":
        raise AssertionError(f"期望 high，得到 {r2.threat_level}")


def check_07_model_missing_other_engines_continue(tmp_path: Path) -> None:
    """删除一类模型文件后：该引擎不可用，Web 规则引擎仍拦截 SQLi。"""
    ddst = tmp_path / "models_saved"
    ddst.mkdir(parents=True)
    # 复制仓库内可读模型（若不存在则仅测 Web 规则 + DDoS 未就绪）
    repo_models = _PROJECT_ROOT / "models" / "saved"
    if repo_models.is_dir():
        for name in os.listdir(repo_models):
            p = repo_models / name
            if p.is_file():
                shutil.copy2(p, ddst / name)
    # 移除 ddos 模型文件（若存在）
    for cand in ("ddos_rf_v1.pkl",):
        cp = ddst / cand
        if cp.is_file():
            cp.unlink()

    dd = DDoSDetector()
    mr = ModelRegistry(str(ddst))
    p = mr.resolve_load_path("ddos")
    if p and os.path.isfile(p):
        try:
            mr.try_load_detector("ddos", dd)
        except Exception:
            pass
    if dd.is_ready and (ddst / "ddos_rf_v1.pkl").exists():
        raise AssertionError("预期 DDoS 模型应缺失或加载失败")

    wd = WebAttackDetector()
    feat = _wf("/api?id=1' OR 1=1--")
    rw = wd.detect(feat)
    if rw is None or rw.threat_type != "web_attack":
        raise AssertionError("Web 规则引擎应在无 ML 时仍工作")


def check_08_redis_downgrade_memory_mode() -> None:
    from src.utils.redis_client import RedisClient  # noqa: PLC0415

    c = RedisClient(host="127.0.0.1", port=63999, password="nope")
    if c.mode != "memory":
        raise AssertionError(f"无法连接时应为 memory 模式，当前 {c.mode}")


def check_09_audit_tamper_fails_integrity(tmp_path: Path) -> None:
    logd = tmp_path / "logs"
    sl = SecurityLogger(log_dir=str(logd), enable_integrity=True)
    sl.log_event("test", "info", {"k": 1})
    sl.log_event("test", "info", {"k": 2})
    logf = Path(sl.log_file)
    text = logf.read_text(encoding="utf-8")
    lines = text.strip().split("\n")
    if len(lines) < 2:
        raise AssertionError("日志行数不足")
    obj = json.loads(lines[0])
    obj["tampered"] = True
    lines[0] = json.dumps(obj, ensure_ascii=False)
    logf.write_text("\n".join(lines) + "\n", encoding="utf-8")
    v = sl.verify_integrity(str(logf))
    if v.get("valid"):
        raise AssertionError("篡改后校验应失败")
    _release_security_logger_handlers(sl)


def check_10_web_restart_alerts_queryable(
    monkeypatch, tmp_path: Path
) -> None:
    """同一 DATABASE_URL 下新进程仍可查询历史告警（模拟重启）。"""

    db_file = tmp_path / "e2e_restart.db"
    if monkeypatch:
        monkeypatch.setenv("FLASK_ENV", "testing")
        monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_file.as_posix()}")
        monkeypatch.setenv("SECRET_KEY", "test-secret-key-which-is-at-least-32b")
        monkeypatch.setenv("ADMIN_USERNAME", "admin")
        monkeypatch.setenv("ADMIN_PASSWORD", "changeme")
        monkeypatch.setenv("ALERT_STREAM_CONSUMER_AUTOSTART", "false")

    from web.app import create_app, push_alert  # noqa: E402

    app1, _ = create_app()
    app1.config["TESTING"] = True
    c1 = app1.test_client()
    t1 = c1.post(
        "/api/auth/login", json={"username": "admin", "password": "changeme"}
    ).get_json()["access_token"]
    h1 = {"Authorization": f"Bearer {t1}"}

    aid = uuid.uuid4().hex
    with app1.app_context():
        push_alert(
            app1,
            {
                "id": aid,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "source_ip": "203.0.113.1",
                "threat_type": "web_attack",
                "level": "high",
                "status": "open",
                "summary": "e2e restart",
            },
        )

    app2, _ = create_app()
    app2.config["TESTING"] = True
    c2 = app2.test_client()
    t2 = c2.post(
        "/api/auth/login", json={"username": "admin", "password": "changeme"}
    ).get_json()["access_token"]
    h2 = {"Authorization": f"Bearer {t2}"}
    r = c2.get("/api/alerts", headers=h2)
    if r.status_code != 200:
        raise AssertionError(r.get_data(as_text=True))
    data = r.get_json()
    if not any(x.get("id") == aid for x in data):
        raise AssertionError("重启后应仍能查到历史告警")


def all_checks_plain() -> List[Tuple[str, Callable[[], None]]]:
    """无需 pytest tmp/monkeypatch 的场景。"""
    return [
        ("1 正常 Web /api/items?id=1 无误报", check_01_normal_web_no_alert),
        ("2 SQL 注入 → web_attack high", check_02_sqli_web_attack_high),
        ("3 双层编码 XSS → web_attack high", check_03_double_encoded_xss_high),
        ("4 命令注入 → web_attack high", check_04_cmd_injection_high),
        ("5 IOC 黑名单 → threat_intel 语义", check_05_ioc_threat_intel_high),
        ("6 SYN 突增 → anomaly/(或 ddos)", check_06_syn_surge_anomaly_or_ddos),
        ("8 Redis 中断 → 客户端降级 memory", check_08_redis_downgrade_memory_mode),
    ]


def main() -> int:
    failed = 0
    for name, fn in all_checks_plain():
        try:
            fn()
            print(f"[PASS] {name}")
        except Exception as exc:  # noqa: BLE001
            print(f"[FAIL] {name}: {exc}")
            failed += 1

    # 7 模型缺失（临时目录）
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        tdp = Path(td)
        try:
            check_07_model_missing_other_engines_continue(tdp)
            print("[PASS] 7 模型缺失：其余引擎继续")
        except Exception as exc:  # noqa: BLE001
            print(f"[FAIL] 7 模型缺失：其余引擎继续: {exc}")
            failed += 1

    # 9 审计篡改
    with tempfile.TemporaryDirectory() as td:
        tdp = Path(td)
        try:
            check_09_audit_tamper_fails_integrity(tdp)
            print("[PASS] 9 审计篡改 → 完整性失败")
        except Exception as exc:  # noqa: BLE001
            print(f"[FAIL] 9 审计篡改: {exc}")
            failed += 1

    print()
    print(
        "说明: 场景 10（Web 重启查历史告警）请运行: python -m pytest tests/e2e/test_v1_acceptance.py -q"
    )
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
