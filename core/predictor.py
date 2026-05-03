import numpy as np
from pathlib import Path
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

from models.isolation_forest import IsolationForestModel
from models.one_class_svm import OneClassSVMModel
from models.autoencoder import AutoencoderModel
from models.random_forest import RandomForestModel
from core.preprocessor import capture_live_traffic, load_uploaded_csv

SAVED_MODELS_DIR = Path(__file__).parent.parent / "saved_models"

MODEL_MAP = {
    "Isolation Forest": IsolationForestModel,
    "One-Class SVM": OneClassSVMModel,
    "Autoencoder": AutoencoderModel,
    "Random Forest": RandomForestModel,
}


def load_test_data() -> tuple[np.ndarray, np.ndarray]:
    X_path = SAVED_MODELS_DIR / "X_test.npy"
    y_path = SAVED_MODELS_DIR / "y_test.npy"
    if not X_path.exists() or not y_path.exists():
        raise FileNotFoundError("Test data not found. Please run train.py first.")
    return np.load(X_path), np.load(y_path)


def _load_model(model_name: str):
    model = MODEL_MAP[model_name]()
    model.load()
    return model


def run_detection(model_name: str) -> dict:
    X, y_true = load_test_data()
    predictions = _load_model(model_name).predict(X)
    anomaly_count = int(np.sum(predictions == -1))
    total = len(predictions)
    return {
        "total_samples": total,
        "anomalies_detected": anomaly_count,
        "normal_count": total - anomaly_count,
        "predictions": predictions,
        "metrics": _compute_metrics(y_true, predictions),
    }


def run_csv_detection(model_name: str, df) -> dict:
    X = load_uploaded_csv(df)
    predictions = _load_model(model_name).predict(X)
    anomaly_count = int(np.sum(predictions == -1))
    total = len(predictions)
    return {
        "total_samples": total,
        "anomalies_detected": anomaly_count,
        "normal_count": total - anomaly_count,
        "predictions": predictions,
        "metrics": None,
    }


def run_live_detection(model_name: str, duration: int = 10, iface: str = None) -> dict:
    X = capture_live_traffic(duration=duration, iface=iface)
    predictions = _load_model(model_name).predict(X)
    anomaly_count = int(np.sum(predictions == -1))
    total = len(predictions)
    return {
        "total_samples": total,
        "anomalies_detected": anomaly_count,
        "normal_count": total - anomaly_count,
        "predictions": predictions,
        "metrics": None,
    }


def _compute_metrics(y_true: np.ndarray, y_pred: np.ndarray) -> dict:
    return {
        "accuracy": round(accuracy_score(y_true, y_pred), 4),
        "precision": round(precision_score(y_true, y_pred, pos_label=-1, zero_division=0), 4),
        "recall": round(recall_score(y_true, y_pred, pos_label=-1, zero_division=0), 4),
        "f1_score": round(f1_score(y_true, y_pred, pos_label=-1, zero_division=0), 4),
    }
