"""
threat_detector.py
Model training, cross-model benchmarking, and real-time packet threat classification engine.
"""

import os
import joblib
import numpy as np
import pandas as pd
from typing import Dict, Any, List

from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier, IsolationForest
from sklearn.metrics import accuracy_score, precision_recall_fscore_support, classification_report, confusion_matrix


class ThreatClassifier:
    """
    Multi-model cybersecurity classifier comparing linear, tree, and ensemble architectures.
    """

    def __init__(self, random_state: int = 42):
        self.random_state = random_state
        self.models: Dict[str, Any] = {
            "Logistic Regression": LogisticRegression(max_iter=1000, random_state=random_state),
            "Decision Tree": DecisionTreeClassifier(max_depth=12, random_state=random_state),
            "Random Forest": RandomForestClassifier(n_estimators=100, max_depth=16, random_state=random_state, n_jobs=-1),
            "Gradient Boosting": GradientBoostingClassifier(n_estimators=80, max_depth=5, random_state=random_state)
        }
        self.trained_models: Dict[str, Any] = {}
        self.best_model_name: str = ""
        self.best_model: Any = None
        self.benchmark_df: pd.DataFrame = pd.DataFrame()

    def train_and_benchmark(self, X_train: np.ndarray, y_train: pd.Series, X_test: np.ndarray, y_test: pd.Series) -> pd.DataFrame:
        """Trains all classifiers and compiles accuracy, precision, recall, and F1."""
        records = []
        best_f1 = -1.0

        for name, clf in self.models.items():
            clf.fit(X_train, y_train)
            self.trained_models[name] = clf

            y_pred = clf.predict(X_test)
            acc = accuracy_score(y_test, y_pred)
            prec, rec, f1, _ = precision_recall_fscore_support(y_test, y_pred, average="weighted", zero_division=0)

            records.append({
                "Model": name,
                "Accuracy": round(acc, 4),
                "Precision": round(prec, 4),
                "Recall": round(rec, 4),
                "F1-Score": round(f1, 4)
            })

            if f1 > best_f1:
                best_f1 = f1
                self.best_model_name = name
                self.best_model = clf

        self.benchmark_df = pd.DataFrame(records).sort_values(by="F1-Score", ascending=False).reset_index(drop=True)
        return self.benchmark_df

    def train_anomaly_detector(self, X_train: np.ndarray, contamination: float = 0.45) -> IsolationForest:
        """
        Trains an unsupervised Isolation Forest for Zero-Day anomaly detection.
        Flags unusual network telemetry without relying on known attack labels.
        """
        iso = IsolationForest(contamination=contamination, random_state=self.random_state, n_jobs=-1)
        iso.fit(X_train)
        return iso

    def save_best_model(self, output_path: str):
        if not self.best_model:
            raise ValueError("No model trained yet. Run train_and_benchmark() first.")
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        joblib.dump({
            "model_name": self.best_model_name,
            "model": self.best_model
        }, output_path)

    @staticmethod
    def inspect_packet(packet_dict: Dict[str, Any], preprocessor, model) -> Dict[str, Any]:
        """
        Simulates an inline Network Security Monitoring (NSM) sensor inspecting
        an incoming network connection packet and determining threat severity.
        """
        df_packet = pd.DataFrame([packet_dict])
        X_encoded = preprocessor.transform(df_packet)
        prediction = model.predict(X_encoded)[0]

        # Calculate class probabilities if available
        confidence = 0.0
        if hasattr(model, "predict_proba"):
            probs = model.predict_proba(X_encoded)[0]
            confidence = float(np.max(probs))

        # Severity ranking
        severity_map = {
            "Normal": ("BENIGN", "#10b981", "Allow connection"),
            "Probe": ("MEDIUM", "#f59e0b", "Log port-scan attempt, alert SOC"),
            "DoS": ("HIGH", "#ef4444", "Drop packets, apply firewall rate-limiting"),
            "R2L": ("CRITICAL", "#dc2626", "Isolate host, lock user account, trigger MFA"),
            "U2R": ("CRITICAL", "#7f1d1d", "EMERGENCY: Terminate process, revoke root session")
        }

        severity, color, recommendation = severity_map.get(prediction, ("UNKNOWN", "gray", "Monitor"))

        return {
            "attack_type": prediction,
            "is_malicious": prediction != "Normal",
            "confidence": round(confidence * 100, 1),
            "severity": severity,
            "recommended_action": recommendation
        }
