"""
Training script for NetSafe.
Run from the netsafe/ directory:
    uv run python train.py
"""
import pickle
import numpy as np
from pathlib import Path
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.svm import OneClassSVM
from sklearn.model_selection import train_test_split

from core.preprocessor import load_combined, scale

SAVED_MODELS_DIR = Path(__file__).parent / "saved_models"
SAVED_MODELS_DIR.mkdir(exist_ok=True)


def train_isolation_forest(X_train: np.ndarray, y_train: np.ndarray):
    print("Training Isolation Forest...")
    model = IsolationForest(n_estimators=100, contamination=0.5, random_state=42, n_jobs=-1)
    model.fit(X_train[y_train == 1])
    with open(SAVED_MODELS_DIR / "isolation_forest.pkl", "wb") as f:
        pickle.dump(model, f)
    print("  Saved isolation_forest.pkl")


def train_one_class_svm(X_train: np.ndarray, y_train: np.ndarray):
    print("Training One-Class SVM...")
    X_normal = X_train[y_train == 1]
    sample_size = min(10_000, len(X_normal))
    idx = np.random.choice(len(X_normal), sample_size, replace=False)
    model = OneClassSVM(kernel="rbf", nu=0.1, gamma="scale")
    model.fit(X_normal[idx])
    with open(SAVED_MODELS_DIR / "one_class_svm.pkl", "wb") as f:
        pickle.dump(model, f)
    print("  Saved one_class_svm.pkl")


def train_random_forest(X_train: np.ndarray, y_train: np.ndarray):
    print("Training Random Forest...")
    sample_size = min(100_000, len(X_train))
    idx = np.random.choice(len(X_train), sample_size, replace=False)
    model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=2)
    model.fit(X_train[idx], y_train[idx])
    with open(SAVED_MODELS_DIR / "random_forest.pkl", "wb") as f:
        pickle.dump(model, f)
    print("  Saved random_forest.pkl")


def train_autoencoder(X_train: np.ndarray, y_train: np.ndarray):
    print("Training Autoencoder...")
    from tensorflow.keras.models import Model
    from tensorflow.keras.layers import Input, Dense
    from tensorflow.keras.callbacks import EarlyStopping

    input_dim = X_train.shape[1]
    encoding_dim = max(8, input_dim // 4)

    inputs = Input(shape=(input_dim,))
    encoded = Dense(encoding_dim * 2, activation="relu")(inputs)
    encoded = Dense(encoding_dim, activation="relu")(encoded)
    decoded = Dense(encoding_dim * 2, activation="relu")(encoded)
    outputs = Dense(input_dim, activation="linear")(decoded)

    autoencoder = Model(inputs, outputs)
    autoencoder.compile(optimizer="adam", loss="mse")

    # Train only on normal samples
    X_normal = X_train[y_train == 1]
    autoencoder.fit(
        X_normal, X_normal,
        epochs=30,
        batch_size=256,
        validation_split=0.1,
        callbacks=[EarlyStopping(patience=3, restore_best_weights=True)],
        verbose=1,
    )

    # Compute reconstruction error threshold (95th percentile on training data)
    reconstructions = autoencoder.predict(X_normal, verbose=0)
    mse = np.mean(np.power(X_normal - reconstructions, 2), axis=1)
    threshold = np.percentile(mse, 95)

    autoencoder.save(SAVED_MODELS_DIR / "autoencoder.h5")
    np.save(SAVED_MODELS_DIR / "autoencoder_threshold.npy", threshold)
    print(f"  Saved autoencoder.h5 (threshold={threshold:.6f})")


if __name__ == "__main__":
    print("Loading and combining datasets...")
    X, y = load_combined()
    print(f"  Total samples: {len(X)} | Features: {X.shape[1]}")
    print(f"  Normal: {np.sum(y == 1)} | Anomaly: {np.sum(y == -1)}")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    print("\nScaling features...")
    X_train_scaled, X_test_scaled, scaler = scale(X_train, X_test)

    # Save scaler for use during inference
    with open(SAVED_MODELS_DIR / "scaler.pkl", "wb") as f:
        pickle.dump(scaler, f)
    print("  Saved scaler.pkl")

    # Save test set for metrics display in the UI
    np.save(SAVED_MODELS_DIR / "X_test.npy", X_test_scaled)
    np.save(SAVED_MODELS_DIR / "y_test.npy", y_test)
    print("  Saved X_test.npy and y_test.npy")

    print()
    train_isolation_forest(X_train_scaled, y_train)
    train_one_class_svm(X_train_scaled, y_train)
    train_random_forest(X_train_scaled, y_train)
    train_autoencoder(X_train_scaled, y_train)

    print("\nAll models trained and saved successfully.")
