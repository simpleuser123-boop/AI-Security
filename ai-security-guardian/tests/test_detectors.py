"""
Phase 4 威胁检测层 - 单元测试
对应架构文档 §5 / Phase 4 提示词验收标准

运行方式：
    cd ai-security-guardian
    python -m pytest tests/test_detectors.py -v

测试覆盖：
    - DetectionResult 数据类
    - DDoSDetector（模型未加载时返回 None）
    - IntrusionDetector（双模式切换）
    - WebAttackDetector（规则命中、URL 多层解码防绕过、误报）
    - AnomalyDetector（双模型协同）
    - FusionEngine（正常、单引擎、多引擎联动升级）
"""
from __future__ import annotations

import os
import sys

import pytest

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from src.decision.fusion_engine import FusionEngine  # noqa: E402
from src.detectors.anomaly_detector import AnomalyDetector  # noqa: E402
from src.detectors.base import BaseDetector, DetectionResult  # noqa: E402
from src.detectors.ddos_detector import DDoSDetector  # noqa: E402
from src.detectors.intrusion_detector import IntrusionDetector  # noqa: E402
from src.detectors.web_detector import WebAttackDetector  # noqa: E402
from src.schema.nsl_kdd_adapter import NSL_KDD_FEATURE_COLUMNS  # noqa: E402


# =====================================================================
# 1. DetectionResult 数据类
# =====================================================================
class TestDetectionResult:
    def test_all_fields_initialized(self):
        result = DetectionResult(
            threat_type="ddos",
            threat_level="high",
            confidence=0.92,
            details="测试",
            source_ip="10.0.0.1",
            raw_data={"k": "v"},
        )
        assert result.threat_type == "ddos"
        assert result.threat_level == "high"
        assert result.confidence == pytest.approx(0.92)
        assert result.details == "测试"
        assert result.source_ip == "10.0.0.1"
        assert result.raw_data == {"k": "v"}

    def test_default_values(self):
        result = DetectionResult(
            threat_type="normal",
            threat_level="low",
            confidence=1.0,
            details="ok",
        )
        assert result.source_ip == ""
        assert result.raw_data == {}

    def test_default_factory_isolated(self):
        """默认 raw_data 必须是 dict 的独立实例（测试 field(default_factory=dict)）。"""
        r1 = DetectionResult("normal", "low", 1.0, "a")
        r2 = DetectionResult("normal", "low", 1.0, "b")
        r1.raw_data["x"] = 1
        assert "x" not in r2.raw_data


# =====================================================================
# 2. DDoSDetector
# =====================================================================
class TestDDoSDetector:
    def test_detect_without_model_returns_none(self):
        detector = DDoSDetector()
        assert detector.is_ready is False
        result = detector.detect({"duration": 0, "src_bytes": 100})
        assert result is None

    def test_is_instance_of_base(self):
        assert isinstance(DDoSDetector(), BaseDetector)

    def test_nsl_reference_column_count_is_41(self):
        assert len(NSL_KDD_FEATURE_COLUMNS) == 41

    def test_load_model_missing_file(self, tmp_path):
        detector = DDoSDetector()
        with pytest.raises(Exception):
            detector.load_model(str(tmp_path / "not_exist.pkl"))


# =====================================================================
# 3. IntrusionDetector
# =====================================================================
class TestIntrusionDetector:
    def test_default_mode_is_random_forest(self):
        detector = IntrusionDetector()
        assert detector.use_deep_learning is False
        assert detector.is_ready is False

    def test_deep_learning_mode_flag(self):
        detector = IntrusionDetector(use_deep_learning=True)
        assert detector.use_deep_learning is True

    def test_detect_without_model_returns_none(self):
        detector = IntrusionDetector()
        assert detector.detect({"duration": 0}) is None

    def test_is_instance_of_base(self):
        assert isinstance(IntrusionDetector(), BaseDetector)


# =====================================================================
# 4. WebAttackDetector
# =====================================================================
class TestWebAttackDetector:
    _SRC = "198.51.100.77"

    @pytest.fixture()
    def detector(self):
        return WebAttackDetector()

    def _feat(self, **kwargs):
        base = {
            "src_ip": self._SRC,
            "http_method": "GET",
            "method": "GET",
            "status_code": 200,
        }
        base.update(kwargs)
        return base

    # ---- 规则命中 ----
    def test_sql_injection_detected(self, detector):
        result = detector.detect(self._feat(url_raw="/api?id=1' OR 1=1--"))
        assert result is not None
        assert result.threat_type == "web_attack"
        assert result.threat_level == "high"
        assert result.confidence == pytest.approx(0.95)
        assert "sql_injection" in result.details
        assert result.source_ip == self._SRC

    def test_sql_union_select_detected(self, detector):
        result = detector.detect(
            self._feat(
                url_raw="/api?id=1 UNION SELECT username,password FROM users"
            )
        )
        assert result.threat_type == "web_attack"
        assert "sql_injection" in result.details
        assert result.source_ip == self._SRC

    def test_xss_detected(self, detector):
        result = detector.detect(
            self._feat(url_raw="/s?q=<script>alert(1)</script>")
        )
        assert result.threat_type == "web_attack"
        assert "xss" in result.details
        assert result.source_ip == self._SRC

    def test_xss_event_handler_detected(self, detector):
        result = detector.detect(
            self._feat(url_raw='/a?v=<img src=x onerror=alert(1)>')
        )
        assert result.threat_type == "web_attack"
        assert "xss" in result.details
        assert result.source_ip == self._SRC

    def test_command_injection_detected(self, detector):
        result = detector.detect(
            self._feat(url_raw="/run?cmd=;cat /etc/passwd")
        )
        assert result.threat_type == "web_attack"
        assert "command_injection" in result.details
        assert result.source_ip == self._SRC

    def test_path_traversal_detected(self, detector):
        result = detector.detect(
            self._feat(url_raw="/file?name=../../../etc/passwd")
        )
        assert result.threat_type == "web_attack"
        assert "path_traversal" in result.details
        assert result.source_ip == self._SRC

    # ---- 多层 URL 解码防绕过 ----
    def test_single_encoded_xss_bypass(self, detector):
        # %3Cscript%3Ealert(1)%3C/script%3E -> <script>alert(1)</script>
        result = detector.detect(
            self._feat(url_raw="/x?q=%3Cscript%3Ealert(1)%3C/script%3E")
        )
        assert result.threat_type == "web_attack"
        assert "xss" in result.details
        assert result.source_ip == self._SRC

    def test_double_encoded_xss_bypass(self, detector):
        # %253Cscript%253E -> %3Cscript%3E -> <script>
        result = detector.detect(
            self._feat(url_raw="/x?q=%253Cscript%253Ealert(1)%253C/script%253E")
        )
        assert result.threat_type == "web_attack"
        assert "xss" in result.details
        assert result.source_ip == self._SRC

    def test_double_encoded_path_traversal(self, detector):
        # %252e%252e%2f -> %2e%2e%2f -> ../
        result = detector.detect(
            self._feat(url_raw="/f?p=%252e%252e%252fetc%252fpasswd")
        )
        assert result.threat_type == "web_attack"
        assert "path_traversal" in result.details
        assert result.source_ip == self._SRC

    def test_source_ip_from_web_request_v1(self, detector):
        """仅提供 web_request_v1.src_ip 时也应进入 DetectionResult。"""
        result = detector.detect(
            {
                "url_raw": "/x?q=1' OR 1=1--",
                "web_request_v1": {"src_ip": "198.51.100.88", "schema": "web_request_v1"},
            }
        )
        assert result.threat_level == "high"
        assert result.source_ip == "198.51.100.88"

    def test_decode_url_stops_when_stable(self):
        """_decode_url 必须在解码结果稳定时停止，不能无限循环。"""
        assert WebAttackDetector._decode_url("hello") == "hello"
        assert WebAttackDetector._decode_url("a%20b") == "a b"

    def test_decode_url_handles_non_string(self):
        assert WebAttackDetector._decode_url(None) == ""  # type: ignore[arg-type]

    # ---- 正常请求不误报 ----
    def test_normal_url_no_false_positive(self, detector):
        for url in [
            "/api/users?page=1&limit=10",
            "/index.html",
            "/static/css/style.css",
            "/api/products/search?q=laptop",
            "/favicon.ico",
        ]:
            result = detector.detect(self._feat(url_raw=url))
            assert result.threat_type == "normal", f"误报: {url}"

    def test_missing_url_returns_normal(self, detector):
        result = detector.detect({})
        assert result.threat_type == "normal"

    def test_is_instance_of_base(self, detector):
        assert isinstance(detector, BaseDetector)


# =====================================================================
# 5. AnomalyDetector
# =====================================================================
class TestAnomalyDetector:
    def test_default_not_ready(self):
        detector = AnomalyDetector()
        assert detector.is_ready is False
        assert detector.detect({"pkt_len_mean": 100}) is None

    def test_manual_if_only_detects_anomaly(self):
        """模拟 Isolation Forest 加载成功，Autoencoder 未加载的场景。"""
        detector = AnomalyDetector()

        class _FakeIF:
            def predict(self, X):
                return [-1]  # 强制异常

        detector.if_model = _FakeIF()
        assert detector.is_ready is True

        result = detector.detect({"pkt_len_mean": 500, "src_ip": "1.2.3.4"})
        assert result is not None
        assert result.threat_type == "anomaly"
        assert result.threat_level == "medium"  # 单模型命中 score=0.5
        assert result.source_ip == "1.2.3.4"

    def test_both_models_hit_yields_high_level(self):
        """双模型同时命中时异常分数=1.0，等级升为 high。"""
        detector = AnomalyDetector()

        class _FakeIF:
            def predict(self, X):
                return [-1]

        class _FakeScaler:
            def transform(self, X):
                return X

        class _FakeAE:
            def predict(self, X, verbose=0):  # noqa: ARG002
                import numpy as np

                return np.zeros_like(X)  # 全 0 重建，mse 很大

        detector.if_model = _FakeIF()
        detector.ae_model = _FakeAE()
        detector.ae_scaler = _FakeScaler()
        detector.ae_threshold = 0.001

        result = detector.detect(
            {
                "pkt_len_mean": 50,
                "flow_byte_count": 1000,
                "flow_pkt_count": 100,
                "window_unique_dst_port": 10,
                "syn_count": 20,
            }
        )
        assert result.threat_type == "anomaly"
        assert result.threat_level == "high"
        assert result.confidence == pytest.approx(1.0)

    def test_normal_when_no_model_hits(self):
        detector = AnomalyDetector()

        class _FakeIF:
            def predict(self, X):
                return [1]  # 正常

        detector.if_model = _FakeIF()
        result = detector.detect({"pkt_len_mean": 60})
        assert result.threat_type == "normal"

    def test_is_instance_of_base(self):
        assert isinstance(AnomalyDetector(), BaseDetector)


# =====================================================================
# 6. FusionEngine
# =====================================================================
class TestFusionEngine:
    @pytest.fixture()
    def engine(self):
        return FusionEngine()

    def test_all_normal_returns_normal(self, engine):
        results = [
            DetectionResult("normal", "low", 1.0, "ok"),
            DetectionResult("normal", "low", 1.0, "ok"),
            None,
        ]
        fused = engine.fuse(results)
        assert fused.threat_type == "normal"
        assert fused.threat_level == "low"

    def test_single_engine_alert_no_upgrade(self, engine):
        results = [
            DetectionResult("ddos", "medium", 0.7, "ddos", source_ip="10.0.0.1"),
            DetectionResult("normal", "low", 1.0, "ok"),
            None,
        ]
        fused = engine.fuse(results)
        assert fused.threat_type == "ddos"
        assert fused.threat_level == "medium"  # 单引擎不升级

    def test_two_engines_alert_upgrade_to_critical(self, engine):
        """两个引擎同时命中 high，应升级为 critical。"""
        results = [
            DetectionResult("ddos", "high", 0.9, "ddos"),
            DetectionResult("anomaly", "high", 0.85, "anomaly"),
        ]
        fused = engine.fuse(results)
        assert fused.threat_level == "critical"
        assert "ddos" in fused.threat_type
        assert "anomaly" in fused.threat_type
        assert fused.raw_data["upgraded"] is True

    def test_two_engines_alert_low_upgrade_to_medium(self, engine):
        results = [
            DetectionResult("web_attack", "low", 0.3, "web low"),
            DetectionResult("anomaly", "low", 0.4, "anomaly low"),
        ]
        fused = engine.fuse(results)
        assert fused.threat_level == "medium"

    def test_mixed_levels_picks_highest(self, engine):
        results = [
            DetectionResult("ddos", "medium", 0.7, "ddos medium"),
            DetectionResult("intrusion", "high", 0.9, "intrusion high"),
        ]
        fused = engine.fuse(results)
        # 最高等级为 high，两个引擎联动升级 -> critical
        assert fused.threat_level == "critical"

    def test_weighted_confidence_in_range(self, engine):
        results = [
            DetectionResult("ddos", "high", 0.8, "ddos"),
            DetectionResult("anomaly", "medium", 0.6, "anomaly"),
        ]
        fused = engine.fuse(results)
        assert 0.0 <= fused.confidence <= 1.0

    def test_none_results_ignored(self, engine):
        fused = engine.fuse([None, None, None])
        assert fused.threat_type == "normal"

    def test_source_ip_propagated(self, engine):
        results = [
            DetectionResult("ddos", "high", 0.9, "ddos", source_ip="192.168.1.100"),
            DetectionResult("anomaly", "medium", 0.6, "anomaly"),
        ]
        fused = engine.fuse(results)
        assert fused.source_ip == "192.168.1.100"

    def test_sub_results_include_source_ip(self, engine):
        results = [
            DetectionResult("web_attack", "high", 0.95, "w", source_ip="10.0.0.5"),
            DetectionResult("intrusion", "medium", 0.7, "i", source_ip=""),
        ]
        fused = engine.fuse(results)
        subs = fused.raw_data.get("sub_results") or []
        assert len(subs) == 2
        assert subs[0]["source_ip"] == "10.0.0.5"
        assert subs[1]["source_ip"] == ""


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
