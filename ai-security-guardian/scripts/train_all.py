"""
一键训练全部检测模型（Phase 8：首次部署引导）

功能：
    1. 检查数据集是否就位，缺失时提示并可选自动调用 download_datasets
    2. 按 DDoS → Intrusion → WebAttack → Anomaly 顺序训练 4 个模型
    3. 任一模型训练失败不会中断其他模型（`--strict` 可切换为失败即退出）
    4. 训练完成后打印 `models/saved/` 目录清单

使用：
    python scripts/train_all.py                # 自动下载缺失数据集
    python scripts/train_all.py --no-download  # 缺数据集直接跳过对应模型
    python scripts/train_all.py --only web,anomaly
    python scripts/train_all.py --strict

注意：
    - NSL-KDD 数据集需联网下载（raw.githubusercontent.com）
    - WebAttack 训练只依赖内置样本，零外部数据即可跑通
    - Anomaly 训练使用仿真数据，零外部数据即可跑通
"""
from __future__ import annotations

import argparse
import importlib
import os
import sys
import time
import traceback
from typing import Callable, Dict, List, Tuple

# 将项目根加入 sys.path（脚本可从任意目录调用）
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

DATASET_DIR = os.path.join(ROOT, "data", "datasets")
NSL_KDD_FILES = ("KDDTrain+.txt", "KDDTest+.txt")


def _nsl_kdd_ready() -> bool:
    """判断 NSL-KDD 数据集是否已就位。"""
    return all(
        os.path.exists(os.path.join(DATASET_DIR, f))
        and os.path.getsize(os.path.join(DATASET_DIR, f)) > 0
        for f in NSL_KDD_FILES
    )


def _ensure_nsl_kdd(auto_download: bool) -> bool:
    """若缺失且允许自动下载则触发 download_datasets；返回是否就绪。"""
    if _nsl_kdd_ready():
        return True
    if not auto_download:
        print("[train_all] NSL-KDD 数据集缺失，且 --no-download 生效，跳过相关模型")
        return False
    print("[train_all] NSL-KDD 数据集缺失，开始下载...")
    try:
        from scripts.download_datasets import download_nsl_kdd  # noqa: WPS433
        results = download_nsl_kdd()
        if not all(results.values()):
            print(f"[train_all] 部分数据集下载失败: {results}")
    except Exception as exc:  # noqa: BLE001
        print(f"[train_all] 数据集下载异常: {exc}")
    return _nsl_kdd_ready()


def _invoke(module_path: str, func_name: str) -> None:
    """动态导入模块并调用其入口函数。"""
    mod = importlib.import_module(module_path)
    fn: Callable[[], None] = getattr(mod, func_name)
    fn()


# (short_name, requires_nsl_kdd, human_name, invoke_tuple)
# invoke_tuple: (module_path, function_name)
TRAINERS: List[Tuple[str, bool, str, Tuple[str, str]]] = [
    ("ddos", True, "DDoS 检测（随机森林）", ("models.train.train_ddos", "train")),
    ("intrusion", True, "入侵检测（CNN+LSTM / RF 备选）",
        ("models.train.train_intrusion", "train_rf_fallback")),  # RF 备选更稳
    ("web", False, "Web 攻击检测（TF-IDF + NB）",
        ("models.train.train_web_attack", "train")),
    ("anomaly", False, "异常检测（Isolation Forest + Autoencoder）",
        ("models.train.train_anomaly", "train_isolation_forest")),
]


def _parse_only(value: str) -> List[str]:
    parts = [p.strip().lower() for p in value.split(",") if p.strip()]
    valid = {name for name, _, _, _ in TRAINERS}
    invalid = [p for p in parts if p not in valid]
    if invalid:
        raise SystemExit(f"--only 包含未知模型: {invalid}，支持项: {sorted(valid)}")
    return parts


def main() -> int:
    parser = argparse.ArgumentParser(description="一键训练 AI-Security-Guardian 全部检测模型")
    parser.add_argument("--no-download", action="store_true",
                        help="缺少数据集时不自动下载")
    parser.add_argument("--only", default="",
                        help="只训练指定模型，逗号分隔（ddos,intrusion,web,anomaly）")
    parser.add_argument("--strict", action="store_true",
                        help="任一模型失败即退出")
    args = parser.parse_args()

    only_set = set(_parse_only(args.only)) if args.only else None

    print("=" * 60)
    print("AI-Security-Guardian 一键模型训练 (Phase 8)")
    print("=" * 60)

    # 准备数据集（仅在需要时）
    need_nsl = any(
        req_nsl for name, req_nsl, _, _ in TRAINERS
        if only_set is None or name in only_set
    )
    nsl_ok = _ensure_nsl_kdd(auto_download=not args.no_download) if need_nsl else True

    # 确保模型输出目录存在
    os.makedirs(os.path.join(ROOT, "models", "saved"), exist_ok=True)

    results: Dict[str, Tuple[bool, float, str]] = {}

    for short, requires_nsl, human, (module_path, func) in TRAINERS:
        if only_set is not None and short not in only_set:
            continue

        if requires_nsl and not nsl_ok:
            print(f"\n--- [SKIP] {human}: 缺少 NSL-KDD ---")
            results[short] = (False, 0.0, "数据集缺失")
            continue

        print(f"\n--- [TRAIN] {human} ---")
        start = time.time()
        try:
            _invoke(module_path, func)
            elapsed = time.time() - start
            results[short] = (True, elapsed, "ok")
            print(f"--- [DONE ] {human}: 耗时 {elapsed:.1f}s ---")
        except Exception as exc:  # noqa: BLE001
            elapsed = time.time() - start
            print(f"--- [FAIL ] {human}: {exc} ---")
            traceback.print_exc()
            results[short] = (False, elapsed, str(exc))
            if args.strict:
                print("\n[train_all] --strict 生效，停止后续训练")
                break

    print("\n" + "=" * 60)
    print("训练汇总：")
    for name, (ok, elapsed, msg) in results.items():
        flag = "OK  " if ok else "FAIL"
        print(f"  [{flag}] {name:10s}  耗时 {elapsed:6.1f}s  {msg}")

    saved_dir = os.path.join(ROOT, "models", "saved")
    print(f"\nmodels/saved/ 目录内容：")
    if os.path.isdir(saved_dir):
        for entry in sorted(os.listdir(saved_dir)):
            full = os.path.join(saved_dir, entry)
            if os.path.isfile(full):
                size = os.path.getsize(full)
                print(f"  - {entry}  ({size} bytes)")
            else:
                print(f"  - {entry}/  (目录)")
    else:
        print("  (目录不存在)")

    ok_count = sum(1 for ok, _, _ in results.values() if ok)
    total = len(results)
    print(f"\n成功 {ok_count} / {total} 个模型。")
    return 0 if ok_count == total else (2 if args.strict else 0)


if __name__ == "__main__":
    sys.exit(main())
