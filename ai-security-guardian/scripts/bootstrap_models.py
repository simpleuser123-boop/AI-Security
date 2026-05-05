"""
首次部署引导脚本（Phase 8）

功能：
    - 检查 models/saved/ 是否为空
    - 若为空，引导用户执行 train_all.py（交互式或 `--auto` 直接跑）
    - 若已存在部分模型，仅打印清单并退出 0

使用：
    python scripts/bootstrap_models.py          交互式（默认）
    python scripts/bootstrap_models.py --auto   自动训练缺失的模型（CI/CD 友好）
    python scripts/bootstrap_models.py --check  仅检查，不训练（适合 Dockerfile 预检）

退出码：
    0 - 模型齐全或已成功训练
    1 - 用户拒绝训练（交互模式）
    2 - 训练失败
"""
from __future__ import annotations

import argparse
import os
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

SAVED_DIR = os.path.join(ROOT, "models", "saved")

# 期望的模型产物（用于完整性判断）
EXPECTED_ARTIFACTS = {
    "ddos": ("ddos_rf_v1.pkl", "ddos_rf_v1.model_manifest.json"),
    "intrusion": (
        "intrusion_rf_v1.pkl",
        "intrusion_rf_v1.model_manifest.json",
        "intrusion_scaler_v1.pkl",
        "intrusion_label_encoder_v1.pkl",
        "intrusion_feature_cols_v1.pkl",
    ),
    "web": ("web_attack_nb_v1.pkl", "web_attack_nb_v1.model_manifest.json"),
    "anomaly": ("anomaly_if_v1.pkl", "anomaly_if_v1.model_manifest.json"),
}


def _status() -> dict[str, bool]:
    """返回每个模型是否"齐全"（所有期望产物都存在且非空）。"""
    out: dict[str, bool] = {}
    for name, files in EXPECTED_ARTIFACTS.items():
        full_paths = [os.path.join(SAVED_DIR, f) for f in files]
        out[name] = all(
            os.path.exists(p) and os.path.getsize(p) > 0 for p in full_paths
        )
    return out


def _print_status(status: dict[str, bool]) -> None:
    print("\n模型状态：")
    for name, ready in status.items():
        flag = "READY  " if ready else "MISSING"
        expected = ", ".join(EXPECTED_ARTIFACTS[name])
        print(f"  [{flag}] {name:10s}  期望: {expected}")


def main() -> int:
    parser = argparse.ArgumentParser(description="首次部署模型引导")
    parser.add_argument("--auto", action="store_true", help="自动训练缺失的模型")
    parser.add_argument("--check", action="store_true", help="仅检查不训练")
    args = parser.parse_args()

    os.makedirs(SAVED_DIR, exist_ok=True)
    status = _status()
    _print_status(status)

    missing = [name for name, ok in status.items() if not ok]
    if not missing:
        print("\n所有模型已就位，无需额外操作。")
        return 0

    if args.check:
        print(f"\n缺失模型: {missing}（--check 不会触发训练）")
        return 2

    if not args.auto:
        try:
            answer = input(
                f"\n检测到 {len(missing)} 个模型缺失: {missing}。"
                "是否立即训练? [y/N]: "
            ).strip().lower()
        except EOFError:
            # 非交互式环境（无 stdin）直接退出，避免阻塞
            print("检测到非交互式环境，请使用 --auto 自动训练或手动运行 train_all.py")
            return 1
        if answer not in {"y", "yes"}:
            print("已取消。可稍后手动运行: python scripts/train_all.py")
            return 1

    # 调用 train_all
    print("\n开始一键训练...\n")
    from scripts import train_all  # noqa: WPS433
    only = ",".join(missing)
    sys.argv = ["train_all.py", "--only", only]
    ret = train_all.main()

    post_status = _status()
    _print_status(post_status)
    still_missing = [n for n, ok in post_status.items() if not ok and n in missing]
    if still_missing:
        print(f"\n部分模型训练未完成: {still_missing}")
        return 2
    print("\n所有目标模型已训练完毕。")
    return 0 if ret == 0 else 2


if __name__ == "__main__":
    sys.exit(main())
