"""统一模型评估报告结构。"""
from __future__ import annotations

from typing import Any, Dict, Mapping, Sequence

import numpy as np
from sklearn.metrics import accuracy_score, confusion_matrix, precision_recall_fscore_support

REQUIRED_EVALUATION_METRICS: tuple[str, ...] = (
    "accuracy",
    "precision",
    "recall",
    "f1",
    "fpr",
    "fnr",
)


def _binary_fpr_fnr(y_true: Sequence[Any], y_pred: Sequence[Any], positive_label: Any) -> tuple[float, float]:
    labels = [x for x in sorted(set(y_true) | set(y_pred), key=str) if x != positive_label]
    labels.append(positive_label)
    cm = confusion_matrix(y_true, y_pred, labels=labels)
    if cm.shape != (2, 2):
        raise ValueError("binary evaluation requires exactly two labels")
    tn, fp, fn, tp = cm.ravel()
    fpr = float(fp / (fp + tn)) if (fp + tn) else 0.0
    fnr = float(fn / (fn + tp)) if (fn + tp) else 0.0
    return fpr, fnr


def _macro_ovr_fpr_fnr(y_true: Sequence[Any], y_pred: Sequence[Any]) -> tuple[float, float]:
    labels = sorted(set(y_true) | set(y_pred), key=str)
    cm = confusion_matrix(y_true, y_pred, labels=labels)
    total = cm.sum()
    fprs = []
    fnrs = []
    for idx in range(len(labels)):
        tp = cm[idx, idx]
        fp = cm[:, idx].sum() - tp
        fn = cm[idx, :].sum() - tp
        tn = total - tp - fp - fn
        fprs.append(float(fp / (fp + tn)) if (fp + tn) else 0.0)
        fnrs.append(float(fn / (fn + tp)) if (fn + tp) else 0.0)
    return float(np.mean(fprs)) if fprs else 0.0, float(np.mean(fnrs)) if fnrs else 0.0


def classification_metrics(
    y_true: Sequence[Any],
    y_pred: Sequence[Any],
    *,
    positive_label: Any | None = None,
    average: str = "weighted",
) -> Dict[str, float]:
    """生成包含 Accuracy/Precision/Recall/F1/FPR/FNR 的统一指标字典。"""
    precision, recall, f1, _support = precision_recall_fscore_support(
        y_true,
        y_pred,
        average=average,
        zero_division=0,
    )
    if positive_label is not None:
        fpr, fnr = _binary_fpr_fnr(y_true, y_pred, positive_label)
    else:
        fpr, fnr = _macro_ovr_fpr_fnr(y_true, y_pred)
    return {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision": float(precision),
        "recall": float(recall),
        "f1": float(f1),
        "fpr": float(fpr),
        "fnr": float(fnr),
    }


def build_evaluation_report(
    *,
    model_name: str,
    model_version: str,
    schema_name: str,
    schema_version: str,
    data_source: str,
    metrics: Mapping[str, Any],
    training_data_description: str,
    evaluation_data_description: str,
    notes: str = "",
) -> Dict[str, Any]:
    """生成可写入 manifest 的评估报告。"""
    return {
        "model_name": model_name,
        "model_version": model_version,
        "schema": {"name": schema_name, "version": schema_version},
        "data_source": data_source,
        "training_data_description": training_data_description,
        "evaluation_data_description": evaluation_data_description,
        "metrics": {k: float(metrics[k]) for k in REQUIRED_EVALUATION_METRICS},
        "notes": notes,
    }
