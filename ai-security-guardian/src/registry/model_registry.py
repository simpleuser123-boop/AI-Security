"""
ModelRegistry：版本发现、manifest 校验、原子切换 current、回滚与审计。

目录约定（磁盘 ``models/saved/`` 下）::

    <family>/v1/manifest.json
    <family>/v1/model.pkl
    <family>/current.txt   # 内容为 v1（Windows 无 symlink 时用）
    <family>/current       # 可选 symlink / junction -> v1

兼容旧式扁平 ``ddos_rf_v1.pkl`` + ``*.model_manifest.json``。
"""
from __future__ import annotations

import logging
import os
import tempfile
from typing import TYPE_CHECKING, Callable, Dict, List, Optional, Tuple

from src.schema.manifest import (
    ManifestLoadError,
    ModelManifest,
    load_manifest_from_version_dir,
)

if TYPE_CHECKING:
    from src.audit.security_logger import SecurityLogger
    from src.detectors.base import BaseDetector

logger = logging.getLogger(__name__)

# 无版本子目录时的主模型文件名（相对 model_dir）
LEGACY_PRIMARY_FILE: Dict[str, str] = {
    "ddos": "ddos_rf_v1.pkl",
    "intrusion": "intrusion_rf_v1.pkl",
    "web_attack": "web_attack_nb_v1.pkl",
    "anomaly": "anomaly_if_v1.pkl",
}

_EXPECTED: Dict[str, Tuple[str, str]] = {
    "ddos": ("network_flow_v1", "tabular"),
    "intrusion": ("network_flow_v1", "tabular"),
    "web_attack": ("web_request_v1", "text_sklearn_pipeline"),
    "anomaly": ("network_flow_v1", "tabular"),
}


def _audit(
    sink: Optional["SecurityLogger"],
    action: str,
    details: Optional[dict] = None,
) -> None:
    if sink is None:
        return
    try:
        sink.log_model_governance(action, details or {})
    except Exception as exc:  # noqa: BLE001
        logger.error("[ModelRegistry] 审计写入失败: %s", exc)


class ModelRegistry:
    """
    按家族管理模型路径解析、热加载、回滚与治理审计。

    ``try_load_detector`` / ``promote_version`` / ``rollback`` 在加载失败时
    尽量恢复检测器到先前可用权重。
    """

    def __init__(
        self,
        model_dir: str,
        *,
        audit_sink: Optional["SecurityLogger"] = None,
    ) -> None:
        self.model_dir = os.path.abspath(model_dir)
        self._audit_sink = audit_sink
        self._last_good_version: Dict[str, str] = {}
        self._reload_lock_callbacks: Dict[str, Callable[[], None]] = {}

    def register_reload_hook(self, family: str, fn: Callable[[], None]) -> None:
        self._reload_lock_callbacks[family] = fn

    def family_root(self, family: str) -> str:
        self._ensure_family(family)
        return os.path.join(self.model_dir, family)

    def list_versions(self, family: str) -> List[str]:
        root = self.family_root(family)
        if not os.path.isdir(root):
            return []
        out: List[str] = []
        for name in sorted(os.listdir(root)):
            if name == "current" or name.startswith("."):
                continue
            vd = os.path.join(root, name)
            if not os.path.isdir(vd):
                continue
            if os.path.isfile(os.path.join(vd, "manifest.json")):
                out.append(name)
        return out

    def get_current_version_id(self, family: str) -> Optional[str]:
        root = self.family_root(family)
        if not os.path.isdir(root):
            return None
        cur = self._read_current_marker(root)
        if cur and os.path.isdir(os.path.join(root, cur)):
            return cur
        return cur

    def resolve_load_path(self, family: str) -> Optional[str]:
        self._ensure_family(family)
        root = self.family_root(family)
        if os.path.isdir(root):
            vid = self._read_current_marker(root)
            if vid:
                vdir = os.path.join(root, vid)
                if self._is_valid_version_dir(vdir):
                    return os.path.abspath(vdir)
            vers = self.list_versions(family)
            if vers:
                fallback = os.path.join(root, vers[-1])
                logger.warning(
                    "[ModelRegistry] %s 未配置 current，回退到最新版本目录 %s",
                    family,
                    vers[-1],
                )
                return os.path.abspath(fallback)
            return None
        legacy = os.path.join(self.model_dir, LEGACY_PRIMARY_FILE[family])
        if os.path.isfile(legacy):
            return os.path.abspath(legacy)
        return None

    def validate_manifest_for_family(self, family: str, manifest: ModelManifest) -> None:
        self._ensure_family(family)
        expected_schema, expected_mode = _EXPECTED[family]
        if manifest.schema_name != expected_schema:
            raise ManifestLoadError(
                f"家族 {family} 需要 schema_name={expected_schema}，实际={manifest.schema_name}"
            )
        if manifest.model_input_mode != expected_mode:
            raise ManifestLoadError(
                f"家族 {family} 需要 model_input_mode={expected_mode}，实际={manifest.model_input_mode}"
            )

    def try_load_detector(self, family: str, detector: "BaseDetector") -> bool:
        path = self.resolve_load_path(family)
        if not path:
            _audit(
                self._audit_sink,
                "model_path_missing",
                {"family": family, "model_dir": self.model_dir},
            )
            return False
        return self._load_detector_at(family, detector, path, audit_key="initial_load")

    def promote_version(self, family: str, version_id: str, detector: "BaseDetector") -> bool:
        self._ensure_family(family)
        root = self.family_root(family)
        vdir = os.path.join(root, version_id)
        if not self._is_valid_version_dir(vdir):
            _audit(
                self._audit_sink,
                "promote_rejected",
                {
                    "family": family,
                    "version": version_id,
                    "reason": "invalid_version_dir_or_manifest",
                },
            )
            return False
        prev_marker = self._read_current_marker(root)
        try:
            mp, man = load_manifest_from_version_dir(vdir)
            self.validate_manifest_for_family(family, man)
            del mp
        except (ManifestLoadError, OSError, ValueError) as exc:
            _audit(
                self._audit_sink,
                "promote_manifest_rejected",
                {"family": family, "version": version_id, "error": str(exc)},
            )
            logger.error("[ModelRegistry] promote 校验 manifest 失败: %s", exc)
            return False

        try:
            detector.load_model(os.path.abspath(vdir))
        except Exception as exc:  # noqa: BLE001
            logger.error("[ModelRegistry] promote 加载权重失败: %s", exc)
            _audit(
                self._audit_sink,
                "model_load_failed",
                {
                    "family": family,
                    "version": version_id,
                    "phase": "promote",
                    "error": str(exc),
                },
            )
            self._recover_detector(family, detector, root, prev_marker)
            return False

        try:
            self._atomic_set_current(root, version_id)
        except OSError as exc:
            logger.error("[ModelRegistry] 写入 current 失败: %s", exc)
            _audit(
                self._audit_sink,
                "current_write_failed",
                {"family": family, "version": version_id, "error": str(exc)},
            )
            self._recover_detector(family, detector, root, prev_marker)
            return False

        if prev_marker and prev_marker != version_id:
            self._last_good_version[family] = prev_marker
        _audit(
            self._audit_sink,
            "model_version_promoted",
            {
                "family": family,
                "from_version": prev_marker,
                "to_version": version_id,
            },
        )
        cb = self._reload_lock_callbacks.get(family)
        if cb:
            try:
                cb()
            except Exception as exc:  # noqa: BLE001
                logger.debug("[ModelRegistry] reload hook: %s", exc)
        return True

    def rollback(self, family: str, detector: "BaseDetector") -> bool:
        self._ensure_family(family)
        target = self._last_good_version.get(family)
        if not target:
            _audit(
                self._audit_sink,
                "rollback_rejected",
                {"family": family, "reason": "no_previous_version_recorded"},
            )
            return False
        root = self.family_root(family)
        vdir = os.path.join(root, target)
        if not self._is_valid_version_dir(vdir):
            _audit(
                self._audit_sink,
                "rollback_rejected",
                {"family": family, "version": target, "reason": "version_dir_invalid"},
            )
            return False
        from_marker = self._read_current_marker(root)
        if not self._load_detector_at(
            family, detector, os.path.abspath(vdir), audit_key="rollback_load"
        ):
            return False
        try:
            self._atomic_set_current(root, target)
        except OSError as exc:
            logger.error("[ModelRegistry] rollback 写 current 失败: %s", exc)
            return False
        _audit(
            self._audit_sink,
            "model_version_rollback",
            {
                "family": family,
                "from_version": from_marker,
                "to_version": target,
            },
        )
        return True

    @staticmethod
    def _ensure_family(family: str) -> None:
        if family not in LEGACY_PRIMARY_FILE:
            raise ValueError(f"未知模型家族: {family}")

    @staticmethod
    def _is_valid_version_dir(vdir: str) -> bool:
        return os.path.isdir(vdir) and os.path.isfile(
            os.path.join(vdir, "manifest.json")
        )

    def _load_detector_at(
        self,
        family: str,
        detector: "BaseDetector",
        path: str,
        *,
        audit_key: str,
    ) -> bool:
        try:
            detector.load_model(path)
        except Exception as exc:  # noqa: BLE001
            logger.error(
                "[ModelRegistry] 加载失败 family=%s path=%s: %s", family, path, exc
            )
            _audit(
                self._audit_sink,
                "model_load_failed",
                {"family": family, "path": path, "phase": audit_key, "error": str(exc)},
            )
            try:
                detector.clear_ml_state()
            except Exception:  # noqa: BLE001
                pass
            return False
        try:
            if os.path.isdir(path) and os.path.isfile(os.path.join(path, "manifest.json")):
                _, man = load_manifest_from_version_dir(path)
                self.validate_manifest_for_family(family, man)
            elif os.path.isfile(path):
                from src.schema.manifest import load_manifest_for_model_path

                man = load_manifest_for_model_path(path)
                self.validate_manifest_for_family(family, man)
        except Exception as exc:  # noqa: BLE001
            logger.error("[ModelRegistry] 加载后家族校验失败: %s", exc)
            _audit(
                self._audit_sink,
                "model_family_mismatch",
                {"family": family, "path": path, "error": str(exc)},
            )
            try:
                detector.clear_ml_state()
            except Exception:  # noqa: BLE001
                pass
            return False

        _audit(
            self._audit_sink,
            "model_load_ok",
            {"family": family, "path": path, "phase": audit_key},
        )
        return True

    def _recover_detector(
        self,
        family: str,
        detector: "BaseDetector",
        root: str,
        prev_marker: Optional[str],
    ) -> None:
        if not prev_marker:
            legacy = os.path.join(self.model_dir, LEGACY_PRIMARY_FILE[family])
            if os.path.isfile(legacy):
                try:
                    detector.load_model(legacy)
                except Exception:
                    try:
                        detector.clear_ml_state()
                    except Exception:
                        pass
            else:
                try:
                    detector.clear_ml_state()
                except Exception:
                    pass
            return
        prev_dir = os.path.join(root, prev_marker)
        if self._is_valid_version_dir(prev_dir):
            try:
                detector.load_model(os.path.abspath(prev_dir))
            except Exception as exc:  # noqa: BLE001
                logger.error("[ModelRegistry] 恢复上一版本失败: %s", exc)
                try:
                    detector.clear_ml_state()
                except Exception:
                    pass

    @staticmethod
    def _read_current_marker(family_root: str) -> Optional[str]:
        cur = os.path.join(family_root, "current")
        if os.path.islink(cur):
            raw = os.readlink(cur)
            if os.path.isabs(raw):
                base = os.path.basename(os.path.normpath(raw))
            else:
                base = os.path.normpath(raw).replace("\\", "/").split("/")[-1]
            return base or None
        if os.path.isdir(cur):
            real = os.path.realpath(cur)
            parent = os.path.realpath(family_root)
            if real == parent:
                return None
            if os.path.dirname(real) == parent:
                return os.path.basename(real)
        if os.path.isfile(cur) and not os.path.islink(cur):
            try:
                with open(cur, encoding="utf-8") as fh:
                    line = fh.readline().strip()
                return line or None
            except OSError:
                return None
        cur_txt = os.path.join(family_root, "current.txt")
        if os.path.isfile(cur_txt):
            try:
                with open(cur_txt, encoding="utf-8") as fh:
                    line = fh.readline().strip()
                return line or None
            except OSError:
                return None
        return None

    @staticmethod
    def _atomic_set_current(family_root: str, version_id: str) -> None:
        os.makedirs(family_root, exist_ok=True)
        target_txt = os.path.join(family_root, "current.txt")
        fd, tmp = tempfile.mkstemp(
            prefix="current_", suffix=".txt", dir=family_root, text=True
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(version_id.strip() + "\n")
            os.replace(tmp, target_txt)
        except Exception:
            try:
                if os.path.exists(tmp):
                    os.remove(tmp)
            except OSError:
                pass
            raise
        if os.name != "nt":
            sym = os.path.join(family_root, "current")
            try:
                if os.path.islink(sym) or os.path.isfile(sym):
                    os.remove(sym)
                os.symlink(version_id, sym, target_is_directory=True)
            except OSError:
                pass
