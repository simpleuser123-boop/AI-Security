"""
网络入侵检测模型训练脚本（Step 3.5）

对应架构文档：§5.4.2 网络入侵检测
    - 首选：CNN + LSTM 混合模型
    - 备选：随机森林（CPU 友好）
对应 Phase 3 提示词：Step 3.5

技术规范（CNN+LSTM）：
    - 网络结构：
        Conv1D(64, k=3, relu) → MaxPool(2) → Conv1D(128, k=3, relu) → MaxPool(2) → Dropout(0.3)
        LSTM(64, return_sequences=True) → Dropout(0.3) → LSTM(32)
        Dense(64, relu) → Dropout(0.3) → Dense(num_classes, softmax)
    - 优化器: adam, 损失: sparse_categorical_crossentropy
    - epochs=20, batch_size=128

技术规范（随机森林备选）：
    - RandomForestClassifier(n_estimators=100, max_depth=20, n_jobs=-1, random_state=42)

输出：
    - models/saved/intrusion_cnn_lstm_v1/         （Keras 模型）
    - models/saved/intrusion_scaler_v1.pkl
    - models/saved/intrusion_label_encoder_v1.pkl
    - models/saved/intrusion_feature_cols_v1.pkl
    - models/saved/intrusion_rf_v1.pkl

验收标准：
    - CNN+LSTM 整体准确率 ≥ 0.75
    - 随机森林备选整体准确率 ≥ 0.75

注：
    Phase 3 提示词给出的数据重塑形状为 (samples, 1, features)，
    但该形状下 Conv1D(kernel_size=3) 无法沿长度 1 的时间步滑动。
    本实现采用等价且可工作的形状 (samples, features, 1)，
    即把 41 个特征视作序列维度、每步 1 通道，仍符合 CNN+LSTM 的一维时序建模语义。
"""
from __future__ import annotations

import os
ROOT_TRAIN = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if ROOT_TRAIN not in __import__("sys").path:
    __import__("sys").path.insert(0, ROOT_TRAIN)
from src.schema.persist import write_model_manifest
from src.schema.evaluation import build_evaluation_report, classification_metrics

from typing import List, Tuple

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
from sklearn.preprocessing import LabelEncoder, OrdinalEncoder, StandardScaler

# ===== NSL-KDD 列名 =====
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

CATEGORICAL_COLS: List[str] = ["protocol_type", "service", "flag"]

# 攻击类别映射（5 分类：normal / dos / probe / r2l / u2r）
ATTACK_CATEGORY_MAP = {
    "normal": "normal",
    "back": "dos", "land": "dos", "neptune": "dos", "pod": "dos",
    "smurf": "dos", "teardrop": "dos", "apache2": "dos", "udpstorm": "dos",
    "processtable": "dos", "mailbomb": "dos",
    "ipsweep": "probe", "nmap": "probe", "portsweep": "probe", "satan": "probe",
    "mscan": "probe", "saint": "probe",
    "ftp_write": "r2l", "guess_passwd": "r2l", "imap": "r2l", "multihop": "r2l",
    "phf": "r2l", "spy": "r2l", "warezclient": "r2l", "warezmaster": "r2l",
    "sendmail": "r2l", "named": "r2l", "snmpgetattack": "r2l",
    "snmpguess": "r2l", "xlock": "r2l", "xsnoop": "r2l",
    "buffer_overflow": "u2r", "loadmodule": "u2r", "perl": "u2r", "rootkit": "u2r",
    "httptunnel": "u2r", "ps": "u2r", "sqlattack": "u2r", "xterm": "u2r",
}

# ===== 路径常量 =====
TRAIN_PATH: str = os.path.join("data", "datasets", "KDDTrain+.txt")
TEST_PATH: str = os.path.join("data", "datasets", "KDDTest+.txt")
MODEL_DIR: str = os.path.join("models", "saved")

CNN_LSTM_DIR: str = "intrusion_cnn_lstm_v1"
SCALER_FILE: str = "intrusion_scaler_v1.pkl"
LE_FILE: str = "intrusion_label_encoder_v1.pkl"
FEATURE_COLS_FILE: str = "intrusion_feature_cols_v1.pkl"
RF_MODEL_FILE: str = "intrusion_rf_v1.pkl"

MIN_ACCURACY: float = 0.75


def _check_dataset() -> None:
    """校验 NSL-KDD 数据集是否存在。"""
    for path in (TRAIN_PATH, TEST_PATH):
        if not os.path.isfile(path):
            raise FileNotFoundError(
                f"未找到数据集: {path}，请先运行 scripts/download_datasets.py"
            )


def load_data(path: str) -> pd.DataFrame:
    """加载 NSL-KDD CSV 数据集。"""
    return pd.read_csv(path, header=None, names=COLUMNS)


def preprocess(
    df: pd.DataFrame,
    categorical_encoder: OrdinalEncoder | None = None,
    *,
    fit_encoder: bool = False,
) -> Tuple[np.ndarray, np.ndarray, List[str], OrdinalEncoder]:
    """
    数据预处理：攻击类别映射 + 类别列同构编码 + 特征抽取。

    Returns:
        (X, y, feature_cols, categorical_encoder): X 为 float32 特征矩阵；y 为 5 类标签；
        feature_cols 为列名；categorical_encoder 用于测试集同构编码。
    """
    df = df.copy()
    df["category"] = df["label"].map(ATTACK_CATEGORY_MAP).fillna("unknown")

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

    feature_cols = [
        c for c in COLUMNS if c not in ("label", "difficulty")
    ]
    X = df[feature_cols].to_numpy(dtype=np.float32)
    y = df["category"].to_numpy()
    return X, y, feature_cols, categorical_encoder


def _prepare_common() -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray,
                                StandardScaler, LabelEncoder, List[str]]:
    """两个模型共用的数据准备流程。"""
    _check_dataset()
    train_df = load_data(TRAIN_PATH)
    test_df = load_data(TEST_PATH)
    X_train, y_train, feature_cols, categorical_encoder = preprocess(
        train_df, fit_encoder=True
    )
    X_test, y_test, _, _ = preprocess(test_df, categorical_encoder)

    # 丢弃测试集中 unknown 类别（训练集中未出现）
    mask = y_test != "unknown"
    X_test, y_test = X_test[mask], y_test[mask]

    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train).astype(np.float32)
    X_test = scaler.transform(X_test).astype(np.float32)

    label_encoder = LabelEncoder()
    y_train_enc = label_encoder.fit_transform(y_train)
    # 测试集可能缺少某些类别，但全部应出现在训练集中
    known = set(label_encoder.classes_)
    mask2 = np.array([c in known for c in y_test])
    X_test = X_test[mask2]
    y_test = y_test[mask2]
    y_test_enc = label_encoder.transform(y_test)

    return (
        X_train, y_train_enc, X_test, y_test_enc,
        scaler, label_encoder, feature_cols,
    )


def train_cnn_lstm() -> None:
    """
    训练 CNN + LSTM 混合入侵检测模型。

    依赖 TensorFlow；若环境未安装则跳过（走随机森林备选）。
    """
    print("=" * 50)
    print("入侵检测模型训练（CNN + LSTM）")
    print("=" * 50)

    try:
        import tensorflow as tf
        from tensorflow import keras
        from tensorflow.keras import layers
    except ImportError:
        print("[跳过] 未检测到 TensorFlow，CNN+LSTM 训练已跳过。")
        print("       安装后重跑: pip install tensorflow>=2.12.0")
        return

    tf.random.set_seed(42)
    np.random.seed(42)

    (X_train, y_train_enc, X_test, y_test_enc,
     scaler, label_encoder, feature_cols) = _prepare_common()
    num_classes = int(len(label_encoder.classes_))
    num_features = int(X_train.shape[1])

    print(f"训练集: {X_train.shape}, 测试集: {X_test.shape}")
    print(f"类别数: {num_classes} -> {list(label_encoder.classes_)}")

    # 重塑为一维时序输入: (samples, features, 1)
    # 将 41 个特征视为时间步，每步 1 通道，满足 Conv1D(kernel=3) 的长度要求
    X_train_seq = X_train.reshape(X_train.shape[0], num_features, 1)
    X_test_seq = X_test.reshape(X_test.shape[0], num_features, 1)

    model = keras.Sequential([
        layers.Input(shape=(num_features, 1)),
        # CNN 特征提取
        layers.Conv1D(64, kernel_size=3, activation="relu"),
        layers.MaxPooling1D(pool_size=2),
        layers.Conv1D(128, kernel_size=3, activation="relu"),
        layers.MaxPooling1D(pool_size=2),
        layers.Dropout(0.3),
        # LSTM 时序建模
        layers.LSTM(64, return_sequences=True),
        layers.Dropout(0.3),
        layers.LSTM(32),
        # 全连接分类
        layers.Dense(64, activation="relu"),
        layers.Dropout(0.3),
        layers.Dense(num_classes, activation="softmax"),
    ])
    model.compile(
        optimizer="adam",
        loss="sparse_categorical_crossentropy",
        metrics=["accuracy"],
    )
    model.summary()

    model.fit(
        X_train_seq, y_train_enc,
        epochs=20,
        batch_size=128,
        validation_data=(X_test_seq, y_test_enc),
        verbose=2,
    )

    y_pred_enc = np.argmax(model.predict(X_test_seq, verbose=0), axis=1)
    y_pred = label_encoder.inverse_transform(y_pred_enc)
    y_test_labels = label_encoder.inverse_transform(y_test_enc)
    eval_metrics = classification_metrics(y_test_labels, y_pred, average="weighted")
    acc = eval_metrics["accuracy"]
    print(f"\n整体准确率: {acc:.4f} (≥ {MIN_ACCURACY})")
    print(
        "统一评估指标: "
        f"Precision={eval_metrics['precision']:.4f}, "
        f"Recall={eval_metrics['recall']:.4f}, "
        f"F1={eval_metrics['f1']:.4f}, "
        f"FPR={eval_metrics['fpr']:.4f}, "
        f"FNR={eval_metrics['fnr']:.4f}"
    )
    print("\n分类报告:")
    print(classification_report(y_test_labels, y_pred, digits=4, zero_division=0))
    if acc >= MIN_ACCURACY:
        print("[通过] CNN+LSTM 准确率达标")
    else:
        print("[警告] CNN+LSTM 准确率未达标")

    os.makedirs(MODEL_DIR, exist_ok=True)
    model.save(os.path.join(MODEL_DIR, CNN_LSTM_DIR))
    joblib.dump(scaler, os.path.join(MODEL_DIR, SCALER_FILE))
    joblib.dump(label_encoder, os.path.join(MODEL_DIR, LE_FILE))
    joblib.dump(feature_cols, os.path.join(MODEL_DIR, FEATURE_COLS_FILE))
    print(f"\nKeras 模型已保存至: {os.path.join(MODEL_DIR, CNN_LSTM_DIR)}")
    print(f"标准化器已保存至  : {os.path.join(MODEL_DIR, SCALER_FILE)}")
    print(f"标签编码器已保存至: {os.path.join(MODEL_DIR, LE_FILE)}")
    print(f"特征列名已保存至  : {os.path.join(MODEL_DIR, FEATURE_COLS_FILE)}")
    cnn_manifest_path = os.path.join(MODEL_DIR, CNN_LSTM_DIR)
    eval_report = build_evaluation_report(
        model_name="intrusion_cnn_lstm_v1",
        model_version="1.0.0",
        schema_name="network_flow_v1",
        schema_version="1",
        data_source="NSL-KDD KDDTrain+/KDDTest+",
        metrics=eval_metrics,
        training_data_description=(
            "NSL-KDD 41-feature benchmark mapped to normal/dos/probe/r2l/u2r. "
            "This is prototype benchmark evidence, not production traffic performance."
        ),
        evaluation_data_description="NSL-KDD KDDTest+ after dropping unknown labels not present in training.",
        notes="CNN+LSTM artifact uses NSL-KDD adapter metadata for governance tracking.",
    )
    write_model_manifest(
        cnn_manifest_path,
        model_name="intrusion_cnn_lstm_v1",
        version="1.0.0",
        schema_name="network_flow_v1",
        schema_version="1",
        feature_columns=list(feature_cols),
        training_dataset="NSL-KDD",
        training_data_description=eval_report["training_data_description"],
        metrics={**eval_metrics, "min_accuracy_gate": MIN_ACCURACY},
        evaluation_report=eval_report,
        artifact_files={
            "model": CNN_LSTM_DIR,
            "scaler": SCALER_FILE,
            "label_encoder": LE_FILE,
            "feature_columns": FEATURE_COLS_FILE,
        },
        trust_tier="prototype_nsl_kdd",
        adapter="nsl_kdd_v1",
        model_input_mode="tabular",
    )


def train_rf_fallback() -> None:
    """
    训练随机森林备选入侵检测模型（CPU 友好）。
    """
    print("\n" + "=" * 50)
    print("入侵检测模型训练（RandomForest 备选）")
    print("=" * 50)

    (X_train, y_train_enc, X_test, y_test_enc,
     scaler, label_encoder, feature_cols) = _prepare_common()

    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=20,
        n_jobs=-1,
        random_state=42,
    )
    print("开始训练...")
    model.fit(X_train, y_train_enc)
    print("训练完成。")

    y_pred_enc = model.predict(X_test)
    y_pred = label_encoder.inverse_transform(y_pred_enc)
    y_test_labels = label_encoder.inverse_transform(y_test_enc)
    eval_metrics = classification_metrics(y_test_labels, y_pred, average="weighted")
    acc = eval_metrics["accuracy"]
    print(f"\n整体准确率: {acc:.4f} (≥ {MIN_ACCURACY})")
    print(
        "统一评估指标: "
        f"Precision={eval_metrics['precision']:.4f}, "
        f"Recall={eval_metrics['recall']:.4f}, "
        f"F1={eval_metrics['f1']:.4f}, "
        f"FPR={eval_metrics['fpr']:.4f}, "
        f"FNR={eval_metrics['fnr']:.4f}"
    )
    print("\n分类报告:")
    print(classification_report(y_test_labels, y_pred, digits=4, zero_division=0))
    if acc >= MIN_ACCURACY:
        print("[通过] 随机森林备选准确率达标")
    else:
        print("[警告] 随机森林备选准确率未达标")

    os.makedirs(MODEL_DIR, exist_ok=True)
    joblib.dump(model, os.path.join(MODEL_DIR, RF_MODEL_FILE))
    # 同步保存 scaler / label_encoder / feature_cols 以便推理时无 Keras 依赖
    joblib.dump(scaler, os.path.join(MODEL_DIR, SCALER_FILE))
    joblib.dump(label_encoder, os.path.join(MODEL_DIR, LE_FILE))
    joblib.dump(feature_cols, os.path.join(MODEL_DIR, FEATURE_COLS_FILE))
    rf_path = os.path.join(MODEL_DIR, RF_MODEL_FILE)
    eval_report = build_evaluation_report(
        model_name="intrusion_rf_v1",
        model_version="1.0.0",
        schema_name="network_flow_v1",
        schema_version="1",
        data_source="NSL-KDD KDDTrain+/KDDTest+",
        metrics=eval_metrics,
        training_data_description=(
            "NSL-KDD 41-feature benchmark mapped to normal/dos/probe/r2l/u2r. "
            "This is prototype benchmark evidence, not production traffic performance."
        ),
        evaluation_data_description="NSL-KDD KDDTest+ after dropping unknown labels not present in training.",
        notes="prototype_nsl_kdd requires nsl_kdd_v1 adapter before online inference.",
    )
    write_model_manifest(
        rf_path,
        model_name="intrusion_rf_v1",
        version="1.0.0",
        schema_name="network_flow_v1",
        schema_version="1",
        feature_columns=list(feature_cols),
        training_dataset="NSL-KDD",
        training_data_description=eval_report["training_data_description"],
        metrics={**eval_metrics, "min_accuracy_gate": MIN_ACCURACY},
        evaluation_report=eval_report,
        artifact_files={
            "model": RF_MODEL_FILE,
            "scaler": SCALER_FILE,
            "label_encoder": LE_FILE,
            "feature_columns": FEATURE_COLS_FILE,
        },
        trust_tier="prototype_nsl_kdd",
        adapter="nsl_kdd_v1",
        model_input_mode="tabular",
    )
    print(f"\nRF 模型已保存至: {rf_path}")


def train() -> None:
    """入侵检测训练入口：先 CNN+LSTM（若可用），再随机森林备选。"""
    train_cnn_lstm()
    train_rf_fallback()


if __name__ == "__main__":
    train()
