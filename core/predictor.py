import time
import numpy as np
from pathlib import Path
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

from models.isolation_forest import IsolationForestModel
from models.one_class_svm import OneClassSVMModel
from models.random_forest import RandomForestModel, RandomForestMulticlassModel
from core.preprocessor import capture_live_traffic, load_uploaded_csv

SAVED_MODELS_DIR = Path(__file__).parent.parent / "saved_models"

MODEL_MAP = {
    "Isolation Forest": IsolationForestModel,
    "One-Class SVM":    OneClassSVMModel,
    "Random Forest":    RandomForestModel,
}

# Note: Autoencoder requires TensorFlow which doesn't support Python 3.15 yet
# To use Autoencoder, downgrade to Python 3.11 or 3.12


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


def _build_result(model, X, predictions, y_true, inference_time) -> dict:
    anomaly_count = int(np.sum(predictions == -1))
    total         = len(predictions)
    scores        = model.anomaly_scores(X)
    return {
        "total_samples":    total,
        "anomalies_detected": anomaly_count,
        "normal_count":     total - anomaly_count,
        "predictions":      predictions,
        "anomaly_scores":   scores,
        "y_true":           y_true,
        "inference_time":   inference_time,
        "metrics":          _compute_metrics(y_true, predictions) if y_true is not None else None,
    }


def run_detection(model_name: str) -> dict:
    X, y_true = load_test_data()
    model     = _load_model(model_name)
    t0        = time.perf_counter()
    predictions = model.predict(X)
    inference_time = time.perf_counter() - t0
    return _build_result(model, X, predictions, y_true, inference_time)


def run_csv_detection(model_name: str, df) -> dict:
    X     = load_uploaded_csv(df)
    model = _load_model(model_name)
    t0    = time.perf_counter()
    predictions = model.predict(X)
    inference_time = time.perf_counter() - t0
    result = _build_result(model, X, predictions, None, inference_time)
    result["df"] = df
    return result


def run_live_detection(model_name: str, duration: int = 10, iface: str = None) -> dict:
    X     = capture_live_traffic(duration=duration, iface=iface)
    model = _load_model(model_name)
    t0    = time.perf_counter()
    predictions = model.predict(X)
    inference_time = time.perf_counter() - t0
    return _build_result(model, X, predictions, None, inference_time)


def run_multiclass_detection() -> dict:
    X_path = SAVED_MODELS_DIR / "X_test_multiclass.npy"
    y_path = SAVED_MODELS_DIR / "y_test_multiclass.npy"
    if not X_path.exists():
        raise FileNotFoundError("Multiclass test data not found. Please run train.py first.")
    X      = np.load(X_path)
    y_true = np.load(y_path, allow_pickle=True)

    model = RandomForestMulticlassModel()
    model.load()

    t0          = time.perf_counter()
    predictions = model.predict(X)
    inf_time    = time.perf_counter() - t0

    classes, counts = np.unique(predictions, return_counts=True)
    attack_counts   = {cls: int(cnt) for cls, cnt in zip(classes, counts)}
    anomaly_count   = int(sum(v for k, v in attack_counts.items() if k != "normal"))

    return {
        "total_samples":     len(predictions),
        "anomalies_detected": anomaly_count,
        "normal_count":      attack_counts.get("normal", 0),
        "attack_counts":     attack_counts,
        "predictions":       predictions,
        "y_true":            y_true,
        "inference_time":    inf_time,
    }


def run_live_window(model, iface: str = None, window: int = 5) -> dict:
    """Capture one window of live traffic and return anomaly rate. Model is pre-loaded."""
    X           = capture_live_traffic(duration=window, iface=iface)
    t0          = time.perf_counter()
    predictions = model.predict(X)
    inf_time    = time.perf_counter() - t0
    result      = _build_result(model, X, predictions, None, inf_time)
    result["X_raw"] = X
    return result


def _compute_metrics(y_true: np.ndarray, y_pred: np.ndarray) -> dict:
    return {
        "accuracy":  round(accuracy_score(y_true, y_pred), 4),
        "precision": round(precision_score(y_true, y_pred, pos_label=-1, zero_division=0), 4),
        "recall":    round(recall_score(y_true, y_pred, pos_label=-1, zero_division=0), 4),
        "f1_score":  round(f1_score(y_true, y_pred, pos_label=-1, zero_division=0), 4),
    }
