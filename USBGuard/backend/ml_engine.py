"""
USB Guard - ML Classification Engine

"""

import os
import logging
import joblib
import numpy as np

logger = logging.getLogger(__name__)

THRESHOLD = 0.50
MODEL_DIR = os.path.join(os.path.dirname(__file__), "models")
RF_PATH   = os.path.join(MODEL_DIR, "rf_model_v1.pkl")
ISO_PATH  = os.path.join(MODEL_DIR, "iso_model_v1.pkl")


class MLEngine:

    def __init__(self):
        self.rf  = None
        self.iso = None
        self.load_models()

    def load_models(self):
        try:
            self.rf  = joblib.load(RF_PATH)
            self.iso = joblib.load(ISO_PATH)
            logger.info("ML models loaded successfully.")
        except FileNotFoundError as e:
            logger.error(f"Model not found: {e} — run training/train_model.py")
        except Exception as e:
            logger.error(f"Model load error: {e}")

    def reload_models(self):
        """Hot-swap: reload updated models without restarting."""
        logger.info("Hot-swapping ML models...")
        self.load_models()

    def classify(self, features: dict) -> dict:
        if self.rf is None or self.iso is None:
            logger.error("Models not loaded — defaulting to ALLOW (fail-safe).")
            return {"score": 0.0, "anomaly": False,
                    "decision": "ALLOW", "features": features}

        vector = np.array([[
            features.get("ikd_mean",      0.0),
            features.get("ikd_std",       0.0),
            features.get("keydown_dur",   0.0),
            features.get("burst_rate",    0),
            features.get("modifier_flag", 0),
            features.get("entropy",       0.0),
        ]])

        # Isolation Forest pre-filter (-1 = anomaly, 1 = normal)
        iso_pred   = self.iso.predict(vector)
        is_anomaly = bool(iso_pred[0] == -1)

        # Random Forest probability of malicious class
        score      = round(float(self.rf.predict_proba(vector)[0][1]), 4)
        decision   = "BLOCK" if score >= THRESHOLD else "ALLOW"

        result = {
            "score":    score,
            "anomaly":  is_anomaly,
            "decision": decision,
            "features": features,
        }
        logger.info(
            f"ML: score={score:.2f}  anomaly={is_anomaly}  "
            f"decision={decision}"
        )
        return result
