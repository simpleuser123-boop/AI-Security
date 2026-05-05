"""
DDoS 检测模型训练脚本（Step 3.2）

对应架构文档：§5.4.1 DDoS 检测 - 随机森林（首选）
对应 Phase 3 提示词：Step 3.2

技术规范：
    - 算法：RandomForestClassifier(n_estimators=100, max_depth=20, n_jobs=-1, random_state=42)
    - 数据集：NSL-KDD（KDDTrain+.txt / KDDTest+.txt）
    - 标签策略：二分类 normal / attack
    - 特征处理：41 特征列，类别列使用 pd.factorize() 编码

输出：
    - models/saved/ddos_rf_v1.pkl

验收标准：
    - 测试集准确率 ≥ 0.80
"""
from __future__ import annotations

import os
from typing import List, Optional, Tuple

import joblib

ROOT_TRAIN = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if ROOT_TRAIN not in __import__("sys").path:
    __import__("sys").path.insert(0, ROOT_TRAIN)
from src.schema.persist import write_model_manifest
from src.schema.evaluation import build_evaluation_report, classification_metrics
from src.schema.nsl_kdd_adapter import NSL_KDD_FEATURE_COLUMNS
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
from sklearn.preprocessing import OrdinalEncoder

# ===== NSL-KDD 41 个特征列 + label + difficulty =====
COLUMNS: List[str] = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in",
    "num_compromised", "root_shell", "su_attempted", "num_root",
    "num_file_creations", "num_shells", "num_access_files", "num_outbound_cmds",
    "is_host_login", "is_guest_login", "count", "srv_count", "serror_rate",
    "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate",
    "diff_srv_rate", "srv_diff_host_rate", "dst_host_count",
    "dst_host_srv_count", "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate", "dst_host_srv_serror_rate",
    "dst_host_rerror_rate", "dst_host_srv_rerror_rate", "label", "difficulty",
]

# 类别列
CATEGORICAL_COLS: List[str] = ["protocol_type", "service", "flag"]

# NSL-KDD 中的 DoS/DDoS 家族；其他攻击类型作为非 DDoS 负样本处理。
DOS_ATTACK_LABELS: frozenset[str] = frozenset(
    {
        "back",
        "land",
        "neptune",
        "pod",
        "smurf",
        "teardrop",
        "apache2",
        "udpstorm",
        "processtable",
        "mailbomb",
    }
)

# 路径常量（使用 os.path.join 拼接）
TRAIN_PATH: str = os.path.join("data", "datasets", "KDDTrain+.txt")
TEST_PATH: str = os.path.join("data", "datasets", "KDDTest+.txt")
MODEL_DIR: str = os.path.join("models", "saved")
MODEL_FILE: str = "ddos_rf_v1.pkl"

# 最低验收标准
MIN_ACCURACY: float = 0.80


def load_data(path: str) -> pd.DataFrame:
    """
    加载 NSL-KDD 数据集。

    Args:
        path: NSL-KDD CSV 文件路径（无表头）

    Returns:
        pd.DataFrame: 含 43 列（41 特征 + label + difficulty）
    """
    if not os.path.isfile(path):
        raise FileNotFoundError(
            f"未找到数据集: {path}，请先运行 scripts/download_datasets.py"
        )
    df = pd.read_csv(path, header=None, names=COLUMNS)
    return df


def preprocess(
    df: pd.DataFrame,
    categorical_encoder: Optional[OrdinalEncoder] = None,
    *,
    fit_encoder: bool = False,
) -> Tuple[np.ndarray, np.ndarray, OrdinalEncoder]:
    """
    数据预处理。

    步骤：
        1. 将 label 简化为二分类: normal / ddos
        2. 对类别列（protocol_type, service, flag）使用训练集拟合的 OrdinalEncoder 编码
        3. 提取 41 维特征矩阵

    Args:
        df: 原始 NSL-KDD DataFrame

    Returns:
        (X, y, categorical_encoder): X 为特征矩阵, y 为标签数组，categorical_encoder 用于测试集同构编码
    """
    df = df.copy()

    df["target"] = df["label"].apply(
        lambda x: "ddos" if x in DOS_ATTACK_LABELS else "normal"
    )

    if categorical_encoder is None:
        categorical_encoder = OrdinalEncoder(
            handle_unknown="use_encoded_value",
            unknown_value=-1,
        )
        fit_encoder = True

    if fit_encoder:
        df[CATEGORICAL_COLS] = categorical_encoder.fit_transform(df[CATEGORICAL_COLS])
    else:
        df[CATEGORICAL_COLS] = categorical_encoder.transform(df[CATEGORICAL_COLS])

    feature_cols = [c for c in COLUMNS if c not in ("label", "difficulty")]
    X = df[feature_cols].to_numpy()
    y = df["target"].to_numpy()
    return X, y, categorical_encoder


def train() -> RandomForestClassifier:
    """
    训练 DDoS 检测模型主流程：加载 → 预处理 → 训练 → 评估 → 保存。

    Returns:
        已训练并保存的 RandomForestClassifier
    """
    print("=" * 50)
    print("DDoS 检测模型训练（RandomForestClassifier）")
    print("=" * 50)

    train_df = load_data(TRAIN_PATH)
    test_df = load_data(TEST_PATH)
    X_train, y_train, categorical_encoder = preprocess(train_df, fit_encoder=True)
    X_test, y_test, _ = preprocess(test_df, categorical_encoder)

    print(f"训练集: {X_train.shape}, 测试集: {X_test.shape}")
    print(f"正常/DDoS 分布(训练): "
          f"normal={np.sum(y_train == 'normal')}, ddos={np.sum(y_train == 'ddos')}")

    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=20,
        n_jobs=-1,
        random_state=42,
    )
    print("\n开始训练...")
    model.fit(X_train, y_train)
    print("训练完成。")

    y_pred = model.predict(X_test)
    eval_metrics = classification_metrics(
        y_test,
        y_pred,
        positive_label="ddos",
        average="binary",
    )
    acc = eval_metrics["accuracy"]
    print(f"\n测试集准确率: {acc:.4f}")
    print(
        "统一评估指标: "
        f"Precision={eval_metrics['precision']:.4f}, "
        f"Recall={eval_metrics['recall']:.4f}, "
        f"F1={eval_metrics['f1']:.4f}, "
        f"FPR={eval_metrics['fpr']:.4f}, "
        f"FNR={eval_metrics['fnr']:.4f}"
    )
    print("\n分类报告:")
    print(classification_report(y_test, y_pred, digits=4))

    if acc < MIN_ACCURACY:
        print(f"[警告] 准确率 {acc:.4f} 低于验收标准 {MIN_ACCURACY}")
    else:
        print(f"[通过] 准确率 ≥ {MIN_ACCURACY}")

    os.makedirs(MODEL_DIR, exist_ok=True)
    model_path = os.path.join(MODEL_DIR, MODEL_FILE)
    joblib.dump(model, model_path)
    print(f"\n模型已保存至: {model_path}")
    eval_report = build_evaluation_report(
        model_name="ddos_rf_v1",
        model_version="1.0.0",
        schema_name="network_flow_v1",
        schema_version="1",
        data_source="NSL-KDD KDDTrain+/KDDTest+",
        metrics=eval_metrics,
        training_data_description=(
            "NSL-KDD 41-feature benchmark. DoS/DDoS labels are positive; "
            "other NSL-KDD attacks are treated as non-DDoS negatives. "
            "This is prototype benchmark evidence, not production traffic performance."
        ),
        evaluation_data_description="NSL-KDD KDDTest+ split with the same binary label mapping.",
        notes="prototype_nsl_kdd requires nsl_kdd_v1 adapter before online inference.",
    )
    write_model_manifest(
        model_path,
        model_name="ddos_rf_v1",
        version="1.0.0",
        schema_name="network_flow_v1",
        schema_version="1",
        feature_columns=list(NSL_KDD_FEATURE_COLUMNS),
        training_dataset="NSL-KDD",
        training_data_description=eval_report["training_data_description"],
        metrics={**eval_metrics, "min_accuracy_gate": MIN_ACCURACY},
        evaluation_report=eval_report,
        artifact_files={"model": MODEL_FILE},
        trust_tier="prototype_nsl_kdd",
        adapter="nsl_kdd_v1",
        model_input_mode="tabular",
    )
    print(f"清单已写入: {os.path.splitext(model_path)[0]}.model_manifest.json")
    return model


if __name__ == "__main__":
    train()
