"""
异常行为检测模型训练脚本（Step 3.4）

对应架构文档：§5.4.4 异常行为检测 - Isolation Forest + Autoencoder 双模型
对应 Phase 3 提示词：Step 3.4

技术规范：
    模型一 Isolation Forest：
        - n_estimators=100, contamination=0.01, random_state=42, n_jobs=-1
        - 仅用正常数据训练
    模型二 Autoencoder：
        - 编码器: Dense(16,relu) → Dense(8,relu) → Dense(4,relu)
        - 解码器: Dense(8,relu) → Dense(16,relu) → Dense(input_dim,linear)
        - 优化器: adam, 损失: mse, epochs=50, batch_size=32, validation_split=0.1
        - 阈值: 正常数据重构误差的 99 分位数

输出：
    - models/saved/anomaly_if_v1.pkl
    - models/saved/anomaly_ae_v1/            （Keras 保存目录）
    - models/saved/anomaly_ae_scaler_v1.pkl
    - models/saved/anomaly_ae_threshold_v1.pkl

验收标准：
    - IF：正常识别率 ≥ 0.95，异常检测率 ≥ 0.90
    - AE：正常识别率 ≥ 0.95，异常检测率 ≥ 0.90
"""
from __future__ import annotations

import os
ROOT_TRAIN = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if ROOT_TRAIN not in __import__("sys").path:
    __import__("sys").path.insert(0, ROOT_TRAIN)
from src.schema.persist import write_model_manifest
from src.schema.evaluation import build_evaluation_report, classification_metrics

from typing import Tuple

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

# ===== 路径常量 =====
MODEL_DIR: str = os.path.join("models", "saved")
IF_MODEL_FILE: str = "anomaly_if_v1.pkl"
AE_MODEL_DIR_NAME: str = "anomaly_ae_v1"
AE_SCALER_FILE: str = "anomaly_ae_scaler_v1.pkl"
AE_THRESHOLD_FILE: str = "anomaly_ae_threshold_v1.pkl"

# 验收阈值
MIN_NORMAL_ACC: float = 0.95
MIN_ANOMALY_DR: float = 0.90

# 数据维度：平均包长、流字节数、流包数、不同目的端口数、SYN 比率
FEATURE_DIM: int = 5


def generate_normal_data(n_samples: int = 5000, seed: int = 42) -> np.ndarray:
    """
    生成模拟的正常网络行为数据。

    特征（5 维）：平均包长、流字节数、流包数、不同目的端口数、SYN 比率

    Args:
        n_samples: 样本数
        seed: 随机种子

    Returns:
        形状 (n_samples, 5) 的 float 数组
    """
    rng = np.random.default_rng(seed)
    data = np.column_stack([
        rng.normal(50, 10, n_samples),
        rng.normal(100, 30, n_samples),
        rng.normal(10, 3, n_samples),
        rng.normal(5, 2, n_samples),
        rng.normal(0.1, 0.05, n_samples),
    ])
    return data.astype(np.float32)


def generate_anomaly_data(n_samples: int = 200, seed: int = 123) -> np.ndarray:
    """
    生成模拟的异常网络行为数据（扫描/DDoS 特征夸张化）。

    Args:
        n_samples: 样本数
        seed: 随机种子

    Returns:
        形状 (n_samples, 5) 的 float 数组
    """
    rng = np.random.default_rng(seed)
    anomalies = np.column_stack([
        rng.uniform(200, 1500, n_samples),
        rng.uniform(5000, 50000, n_samples),
        rng.uniform(500, 5000, n_samples),
        rng.uniform(50, 500, n_samples),
        rng.uniform(0.5, 1.0, n_samples),
    ])
    return anomalies.astype(np.float32)


def _evaluate_if(model: IsolationForest) -> Tuple[float, float, dict]:
    """评估 Isolation Forest，并返回统一指标。"""
    X_test_normal = generate_normal_data(n_samples=500, seed=7)
    X_test_anomaly = generate_anomaly_data(n_samples=200, seed=8)
    y_true = ["normal"] * len(X_test_normal) + ["anomaly"] * len(X_test_anomaly)
    raw_pred = np.concatenate([model.predict(X_test_normal), model.predict(X_test_anomaly)])
    y_pred = ["normal" if int(x) == 1 else "anomaly" for x in raw_pred]
    normal_acc = float(np.mean([p == "normal" for p in y_pred[: len(X_test_normal)]]))
    anomaly_dr = float(np.mean([p == "anomaly" for p in y_pred[len(X_test_normal) :]]))
    metrics = classification_metrics(y_true, y_pred, positive_label="anomaly", average="binary")
    return normal_acc, anomaly_dr, metrics


def train_isolation_forest() -> IsolationForest:
    """
    训练 Isolation Forest 异常检测模型。

    Returns:
        已训练并保存的 IsolationForest
    """
    print("=" * 50)
    print("异常行为检测模型训练（Isolation Forest）")
    print("=" * 50)

    X_normal = generate_normal_data()
    print(f"训练数据（仅正常行为）: {X_normal.shape}")

    model = IsolationForest(
        n_estimators=100,
        contamination=0.01,
        random_state=42,
        n_jobs=-1,
    )
    model.fit(X_normal)

    normal_acc, anomaly_dr, eval_metrics = _evaluate_if(model)
    print(f"\n正常样本识别率: {normal_acc:.4f} (≥ {MIN_NORMAL_ACC})")
    print(f"异常样本检测率: {anomaly_dr:.4f} (≥ {MIN_ANOMALY_DR})")
    print(
        "统一评估指标: "
        f"Accuracy={eval_metrics['accuracy']:.4f}, "
        f"Precision={eval_metrics['precision']:.4f}, "
        f"Recall={eval_metrics['recall']:.4f}, "
        f"F1={eval_metrics['f1']:.4f}, "
        f"FPR={eval_metrics['fpr']:.4f}, "
        f"FNR={eval_metrics['fnr']:.4f}"
    )
    if normal_acc >= MIN_NORMAL_ACC and anomaly_dr >= MIN_ANOMALY_DR:
        print("[通过] Isolation Forest 指标达标")
    else:
        print("[警告] Isolation Forest 指标未达标")

    os.makedirs(MODEL_DIR, exist_ok=True)
    model_path = os.path.join(MODEL_DIR, IF_MODEL_FILE)
    joblib.dump(model, model_path)
    eval_report = build_evaluation_report(
        model_name="anomaly_if_v1",
        model_version="1.0.0",
        schema_name="network_flow_v1",
        schema_version="1",
        data_source="synthetic_normal_and_anomaly_samples",
        metrics=eval_metrics,
        training_data_description=(
            "Synthetic normal-only network behavior samples generated by train_anomaly.py. "
            "Metrics are synthetic benchmark checks and must not be read as production performance."
        ),
        evaluation_data_description="Synthetic normal and exaggerated anomaly samples generated with held-out seeds.",
        notes="Isolation Forest is trained only on synthetic normal behavior.",
    )
    write_model_manifest(
        model_path,
        model_name="anomaly_if_v1",
        version="1.0.0",
        schema_name="network_flow_v1",
        schema_version="1",
        feature_columns=['pkt_len_mean', 'flow_byte_count', 'flow_pkt_count', 'window_unique_dst_port', 'syn_count'],
        training_dataset="synthetic_normal_only",
        training_data_description=eval_report["training_data_description"],
        metrics={**eval_metrics, "if_normal_acc": normal_acc, "if_anomaly_dr": anomaly_dr},
        evaluation_report=eval_report,
        artifact_files={"isolation_forest": IF_MODEL_FILE},
        trust_tier="production",
        model_input_mode="tabular",
    )
    print(f"\n模型已保存至: {model_path}")
    return model


def train_autoencoder() -> None:
    """
    训练 Autoencoder 异常检测模型。

    依赖 TensorFlow；若环境未安装，本函数会打印提示并跳过。
    """
    print("\n" + "=" * 50)
    print("异常行为检测模型训练（Autoencoder）")
    print("=" * 50)

    try:
        import tensorflow as tf
        from tensorflow import keras
        from tensorflow.keras import layers
    except ImportError:
        print("[跳过] 未检测到 TensorFlow，Autoencoder 训练已跳过。")
        print("       安装后重跑: pip install tensorflow>=2.12.0")
        return

    tf.random.set_seed(42)

    X_normal = generate_normal_data(n_samples=5000)
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X_normal)
    input_dim = X_scaled.shape[1]

    autoencoder = keras.Sequential([
        layers.Input(shape=(input_dim,)),
        layers.Dense(16, activation="relu"),
        layers.Dense(8, activation="relu"),
        layers.Dense(4, activation="relu"),
        layers.Dense(8, activation="relu"),
        layers.Dense(16, activation="relu"),
        layers.Dense(input_dim, activation="linear"),
    ])
    autoencoder.compile(optimizer="adam", loss="mse")

    history = autoencoder.fit(
        X_scaled, X_scaled,
        epochs=50,
        batch_size=32,
        validation_split=0.1,
        verbose=0,
    )
    final_loss = float(history.history["loss"][-1])
    print(f"最终训练损失 (MSE): {final_loss:.6f}")

    reconstructions = autoencoder.predict(X_scaled, verbose=0)
    mse_train = np.mean(np.power(X_scaled - reconstructions, 2), axis=1)
    threshold = float(np.percentile(mse_train, 99))
    print(f"异常检测阈值（99 分位）: {threshold:.6f}")

    X_test_normal = scaler.transform(generate_normal_data(n_samples=500, seed=7))
    X_test_anomaly = scaler.transform(generate_anomaly_data(n_samples=200, seed=8))
    recon_normal = autoencoder.predict(X_test_normal, verbose=0)
    recon_anomaly = autoencoder.predict(X_test_anomaly, verbose=0)
    mse_normal = np.mean(np.power(X_test_normal - recon_normal, 2), axis=1)
    mse_anomaly = np.mean(np.power(X_test_anomaly - recon_anomaly, 2), axis=1)

    normal_acc = float((mse_normal <= threshold).mean())
    anomaly_dr = float((mse_anomaly > threshold).mean())
    y_true = ["normal"] * len(mse_normal) + ["anomaly"] * len(mse_anomaly)
    y_pred = (
        ["normal" if x <= threshold else "anomaly" for x in mse_normal]
        + ["normal" if x <= threshold else "anomaly" for x in mse_anomaly]
    )
    eval_metrics = classification_metrics(y_true, y_pred, positive_label="anomaly", average="binary")
    print(f"\n正常样本识别率: {normal_acc:.4f} (≥ {MIN_NORMAL_ACC})")
    print(f"异常样本检测率: {anomaly_dr:.4f} (≥ {MIN_ANOMALY_DR})")
    print(
        "统一评估指标: "
        f"Accuracy={eval_metrics['accuracy']:.4f}, "
        f"Precision={eval_metrics['precision']:.4f}, "
        f"Recall={eval_metrics['recall']:.4f}, "
        f"F1={eval_metrics['f1']:.4f}, "
        f"FPR={eval_metrics['fpr']:.4f}, "
        f"FNR={eval_metrics['fnr']:.4f}"
    )
    if normal_acc >= MIN_NORMAL_ACC and anomaly_dr >= MIN_ANOMALY_DR:
        print("[通过] Autoencoder 指标达标")
    else:
        print("[警告] Autoencoder 指标未达标")

    os.makedirs(MODEL_DIR, exist_ok=True)
    ae_dir = os.path.join(MODEL_DIR, AE_MODEL_DIR_NAME)
    autoencoder.save(ae_dir)
    joblib.dump(scaler, os.path.join(MODEL_DIR, AE_SCALER_FILE))
    joblib.dump(threshold, os.path.join(MODEL_DIR, AE_THRESHOLD_FILE))
    eval_report = build_evaluation_report(
        model_name="anomaly_ae_v1",
        model_version="1.0.0",
        schema_name="network_flow_v1",
        schema_version="1",
        data_source="synthetic_normal_and_anomaly_samples",
        metrics=eval_metrics,
        training_data_description=(
            "Synthetic normal-only network behavior samples generated by train_anomaly.py. "
            "Metrics are synthetic benchmark checks and must not be read as production performance."
        ),
        evaluation_data_description="Synthetic normal and exaggerated anomaly samples generated with held-out seeds.",
        notes="Autoencoder threshold is the 99th percentile of synthetic normal reconstruction error.",
    )
    write_model_manifest(
        ae_dir,
        model_name="anomaly_ae_v1",
        version="1.0.0",
        schema_name="network_flow_v1",
        schema_version="1",
        feature_columns=['pkt_len_mean', 'flow_byte_count', 'flow_pkt_count', 'window_unique_dst_port', 'syn_count'],
        training_dataset="synthetic_normal_only",
        training_data_description=eval_report["training_data_description"],
        metrics={**eval_metrics, "ae_normal_acc": normal_acc, "ae_anomaly_dr": anomaly_dr},
        evaluation_report=eval_report,
        artifact_files={
            "autoencoder": AE_MODEL_DIR_NAME,
            "scaler": AE_SCALER_FILE,
            "threshold": AE_THRESHOLD_FILE,
        },
        trust_tier="production",
        model_input_mode="tabular",
    )
    print(f"\nKeras 模型已保存至: {ae_dir}")
    print(f"标准化器已保存至  : {os.path.join(MODEL_DIR, AE_SCALER_FILE)}")
    print(f"检测阈值已保存至  : {os.path.join(MODEL_DIR, AE_THRESHOLD_FILE)}")


def train() -> None:
    """异常检测训练入口：依次训练 Isolation Forest 与 Autoencoder。"""
    train_isolation_forest()
    train_autoencoder()


if __name__ == "__main__":
    train()
