import numpy as np
from pathlib import Path

MODEL_PATH = Path(__file__).parent.parent / "saved_models" / "autoencoder.h5"
THRESHOLD_PATH = Path(__file__).parent.parent / "saved_models" / "autoencoder_threshold.npy"


class AutoencoderModel:
    def __init__(self):
        self.model = None
        self.threshold = None

    def load(self):
        if not MODEL_PATH.exists():
            raise FileNotFoundError(f"Trained model not found at {MODEL_PATH}. Please train the model first.")
        from tensorflow.keras.models import load_model
        self.model = load_model(MODEL_PATH, compile=False)
        self.threshold = float(np.load(THRESHOLD_PATH)) if THRESHOLD_PATH.exists() else 0.5

    def predict(self, X: np.ndarray) -> np.ndarray:
        reconstructions = self.model.predict(X, verbose=0)
        mse = np.mean(np.power(X - reconstructions, 2), axis=1)
        return np.where(mse > self.threshold, -1, 1)

    def anomaly_scores(self, X: np.ndarray) -> np.ndarray:
        reconstructions = self.model.predict(X, verbose=0)
        return np.mean(np.power(X - reconstructions, 2), axis=1)

    def save(self):
        self.model.save(MODEL_PATH)
