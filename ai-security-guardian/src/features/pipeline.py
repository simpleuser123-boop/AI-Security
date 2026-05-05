"""
特征处理流水线
对应架构文档 §4.3 特征处理流水线

将 FlowFeatureExtractor / WebFeatureExtractor 产出的「特征字典列表」
标准化为统一的 numpy 二维数组,供下游各机器学习模型直接使用。

工作流程:
    1. fit(train_features)       拟合 StandardScaler + 每列 LabelEncoder;
    2. transform(any_features)   转换为 (N, D) 的 numpy 数组;
    3. save(path) / load(path)   通过 joblib 持久化整个流水线。
"""
from __future__ import annotations

import logging
from typing import Dict, List

import joblib
import numpy as np
from sklearn.preprocessing import LabelEncoder, StandardScaler

logger = logging.getLogger(__name__)


class FeaturePipeline:
    """
    统一的特征标准化 + 类别编码流水线。

    设计要点:
        - 数值列自动识别(``select_dtypes(include=[np.number])``);
        - 类别列自动识别(``select_dtypes(include=['object'])``);
        - 【安全】transform 阶段未见过的类别编码为 -1,不抛异常,
          避免因单个异常类别导致整个在线检测流水线中断。
    """

    UNKNOWN_CATEGORY_CODE: int = -1

    def __init__(self) -> None:
        self.scaler: StandardScaler = StandardScaler()
        self.label_encoders: Dict[str, LabelEncoder] = {}
        self.numeric_columns: List[str] = []
        self.categorical_columns: List[str] = []
        self._fitted: bool = False

    # ---------- 内部辅助 ----------

    @staticmethod
    def _to_dataframe(features_list: List[dict]):
        """延迟导入 pandas,避免顶层依赖拖慢模块首次 import。"""
        import pandas as pd  # noqa: WPS433 - 本地延迟导入是故意为之

        return pd.DataFrame(features_list)

    # ---------- 核心 API ----------

    def fit(self, features_list: List[dict]) -> "FeaturePipeline":
        """
        从训练数据中拟合标准化参数和类别编码器。

        当输入由多个来源(流特征 + Web 特征)合并时,某些样本可能
        缺失另一来源的列,此处统一:数值列缺失填 0,类别列缺失填空串。

        Args:
            features_list: 特征字典列表。

        Returns:
            self,方便链式调用。
        """
        if not features_list:
            raise ValueError("features_list 不能为空")

        df = self._to_dataframe(features_list)

        self.numeric_columns = df.select_dtypes(include=[np.number]).columns.tolist()
        # pandas 3.x 中 object 不再隐式包含字符串列，显式包含 string 可避免迁移告警
        self.categorical_columns = df.select_dtypes(
            include=['object', 'string']
        ).columns.tolist()

        # 缺失值处理:数值填 0,类别填空串(在线推理鲁棒性)
        if self.numeric_columns:
            df[self.numeric_columns] = df[self.numeric_columns].fillna(0)
        if self.categorical_columns:
            df[self.categorical_columns] = df[self.categorical_columns].fillna('')

        # 拟合数值标准化
        if self.numeric_columns:
            self.scaler.fit(df[self.numeric_columns].values.astype(np.float64))

        # 拟合类别编码(每列一个独立 LabelEncoder)
        self.label_encoders = {}
        for col in self.categorical_columns:
            le = LabelEncoder()
            le.fit(df[col].astype(str).values)
            self.label_encoders[col] = le

        self._fitted = True
        logger.info(
            "[FeaturePipeline] fit 完成: 数值列=%d, 类别列=%d",
            len(self.numeric_columns), len(self.categorical_columns),
        )
        return self

    def transform(self, features_list: List[dict]) -> np.ndarray:
        """
        将特征字典列表转换为标准化后的二维 numpy 数组。

        列顺序为 ``[numeric_columns..., categorical_columns...]``。

        【安全】对于训练时未见过的类别,编码为
        ``UNKNOWN_CATEGORY_CODE (-1)`` 而非抛异常。

        Args:
            features_list: 特征字典列表,可含训练时未见过的类别值。

        Returns:
            shape = ``(len(features_list), len(numeric_columns) + len(categorical_columns))``。
        """
        if not self._fitted:
            raise RuntimeError("FeaturePipeline 尚未 fit,不能 transform")
        if not features_list:
            total_cols = len(self.numeric_columns) + len(self.categorical_columns)
            return np.empty((0, total_cols), dtype=np.float64)

        df = self._to_dataframe(features_list)
        n_rows = len(df)

        # ---- 数值列 ----
        if self.numeric_columns:
            # 缺失列用 0 填充,缺失单元格(NaN)同样填 0,保证在线推理鲁棒
            for col in self.numeric_columns:
                if col not in df.columns:
                    df[col] = 0
            df[self.numeric_columns] = df[self.numeric_columns].fillna(0)
            numeric_vals = self.scaler.transform(
                df[self.numeric_columns].values.astype(np.float64)
            )
        else:
            numeric_vals = np.empty((n_rows, 0), dtype=np.float64)

        # ---- 类别列 ----
        cat_cols_encoded: List[np.ndarray] = []
        for col in self.categorical_columns:
            le = self.label_encoders.get(col)
            if le is None:
                cat_cols_encoded.append(
                    np.full((n_rows, 1), self.UNKNOWN_CATEGORY_CODE, dtype=np.float64)
                )
                continue

            if col not in df.columns:
                cat_cols_encoded.append(
                    np.full((n_rows, 1), self.UNKNOWN_CATEGORY_CODE, dtype=np.float64)
                )
                continue

            known_classes = set(le.classes_.tolist())
            # NaN -> 空串,再统一转为字符串
            series = df[col].fillna('').astype(str)

            encoded = np.empty(n_rows, dtype=np.float64)
            for i, val in enumerate(series.values):
                if val in known_classes:
                    encoded[i] = int(le.transform([val])[0])
                else:
                    # 【安全】未见过的类别 -> -1,不抛异常
                    encoded[i] = self.UNKNOWN_CATEGORY_CODE
            cat_cols_encoded.append(encoded.reshape(-1, 1))

        # ---- 拼接 ----
        if cat_cols_encoded:
            cat_array = np.hstack(cat_cols_encoded)
            return np.hstack([numeric_vals, cat_array])
        return numeric_vals

    # ---------- 持久化 ----------

    def save(self, path: str) -> None:
        """用 joblib 将整个流水线对象保存到磁盘。"""
        joblib.dump(self, path)
        logger.info("[FeaturePipeline] 已保存至 %s", path)

    @staticmethod
    def load(path: str) -> "FeaturePipeline":
        """加载已保存的流水线对象。"""
        pipeline: FeaturePipeline = joblib.load(path)
        logger.info("[FeaturePipeline] 已从 %s 加载", path)
        return pipeline
