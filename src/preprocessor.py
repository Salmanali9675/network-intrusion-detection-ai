"""
preprocessor.py
Data preprocessing, feature encoding, scaling, and train-test splitting pipeline
for network intrusion telemetry.
"""

import os
from typing import Tuple, List, Dict
import pandas as pd
import numpy as np
import joblib
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.compose import ColumnTransformer


CATEGORICAL_FEATURES = ["protocol_type", "service", "flag"]
NUMERICAL_FEATURES = [
    "duration", "src_bytes", "dst_bytes", "wrong_fragment",
    "urgent", "hot", "num_failed_logins", "logged_in",
    "count", "srv_count", "serror_rate", "same_srv_rate",
    "diff_srv_rate", "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate"
]
TARGET_COL = "attack_type"


def build_pipeline() -> ColumnTransformer:
    """Creates a ColumnTransformer to scale numerics and one-hot encode categoricals."""
    preprocessor = ColumnTransformer(
        transformers=[
            ("num", StandardScaler(), NUMERICAL_FEATURES),
            ("cat", OneHotEncoder(handle_unknown="ignore", sparse_output=False), CATEGORICAL_FEATURES)
        ]
    )
    return preprocessor


def prepare_dataset(df: pd.DataFrame, test_size: float = 0.2, random_state: int = 42):
    """
    Splits features and targets, fits preprocessor on train, transforms test,
    and returns encoded arrays with feature names.
    """
    X = df[NUMERICAL_FEATURES + CATEGORICAL_FEATURES]
    y = df[TARGET_COL]

    X_train_raw, X_test_raw, y_train, y_test = train_test_split(
        X, y, test_size=test_size, random_state=random_state, stratify=y
    )

    preprocessor = build_pipeline()
    X_train = preprocessor.fit_transform(X_train_raw)
    X_test = preprocessor.transform(X_test_raw)

    # Extract transformed feature names
    cat_feature_names = preprocessor.named_transformers_["cat"].get_feature_names_out(CATEGORICAL_FEATURES)
    all_feature_names = NUMERICAL_FEATURES + list(cat_feature_names)

    return {
        "X_train": X_train,
        "X_test": X_test,
        "y_train": y_train,
        "y_test": y_test,
        "preprocessor": preprocessor,
        "feature_names": all_feature_names,
        "raw_train": X_train_raw,
        "raw_test": X_test_raw
    }


def save_preprocessor(preprocessor, output_path: str):
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    joblib.dump(preprocessor, output_path)
