import pickle
import numpy as np
from pathlib import Path

MODEL_PATH = Path(__file__).parent.parent / "saved_models" / "random_forest.pkl"


class RandomForestModel:
    def __init__(self):
        self.model = None

    def load(self):
        if not MODEL_PATH.exists():
            raise FileNotFoundError(f"Trained model not found at {MODEL_PATH}. Please train the model first.")
        with open(MODEL_PATH, "rb") as f:
            self.model = pickle.load(f)

    def predict(self, X: np.ndarray) -> np.ndarray:
        # Returns 1 for normal, -1 for anomaly
        return self.model.predict(X)

    def save(self):
        with open(MODEL_PATH, "wb") as f:
            pickle.dump(self.model, f)
