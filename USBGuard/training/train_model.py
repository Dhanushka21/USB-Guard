"""
USB Guard - ML Model Training Script
Run after setup_database.py to train and save Random Forest + Isolation Forest models.
"""
import json
import os
import numpy as np
from sklearn.ensemble        import RandomForestClassifier, IsolationForest
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics         import (accuracy_score, precision_score,
                                     recall_score, f1_score, confusion_matrix)
import joblib

BASE_DIR     = os.path.dirname(os.path.abspath(__file__))
DATASET_PATH = os.path.join(BASE_DIR, "..", "backend", "data", "dataset_v1.json")
MODEL_DIR    = os.path.join(BASE_DIR, "..", "backend", "models")
RF_OUT       = os.path.join(MODEL_DIR, "rf_model_v1.pkl")
ISO_OUT      = os.path.join(MODEL_DIR, "iso_model_v1.pkl")

os.makedirs(MODEL_DIR, exist_ok=True)


def load_dataset(path):
    with open(path) as f:
        data = json.load(f)
    X = np.array([[
        d["ikd_mean"], d["ikd_std"], d["keydown_dur"],
        d["burst_rate"], d["modifier_flag"], d["entropy"]
    ] for d in data])
    y = np.array([d["label"] for d in data])
    return X, y


def train():
    print("=" * 50)
    print("  USB Guard - Model Training")
    print("=" * 50)
    print()

    print("Loading dataset...")
    X, y = load_dataset(DATASET_PATH)
    attack = int(sum(y == 1))
    benign = int(sum(y == 0))
    print(f"Dataset: {len(y)} samples  ({attack} attack, {benign} benign)")
    print()

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=42
    )
    print(f"Train: {len(X_train)}  Test: {len(X_test)}")
    print()

    # ── Random Forest ──────────────────────────────────
    print("Training Random Forest (n_estimators=100)...")
    rf = RandomForestClassifier(
        n_estimators=100, max_depth=None,
        random_state=42, n_jobs=-1
    )
    rf.fit(X_train, y_train)

    cv = cross_val_score(rf, X_train, y_train, cv=5, scoring="accuracy")
    print(f"5-fold CV accuracy: {cv.mean():.3f} +/- {cv.std():.3f}")

    y_pred = rf.predict(X_test)
    tn, fp, fn, tp = confusion_matrix(y_test, y_pred).ravel()

    print()
    print("Test set results:")
    print(f"  Accuracy          : {accuracy_score(y_test, y_pred):.3f}")
    print(f"  Precision         : {precision_score(y_test, y_pred):.3f}")
    print(f"  Recall            : {recall_score(y_test, y_pred):.3f}")
    print(f"  F1 score          : {f1_score(y_test, y_pred):.3f}")
    print(f"  False positive rate: {fp / (fp + tn):.3f}")
    print(f"  True positives    : {tp}   False negatives: {fn}")
    print(f"  True negatives    : {tn}   False positives: {fp}")

    print()
    print("Feature importances:")
    features = ["ikd_mean","ikd_std","keydown_dur",
                "burst_rate","modifier_flag","entropy"]
    for name, imp in sorted(
        zip(features, rf.feature_importances_),
        key=lambda x: x[1], reverse=True
    ):
        bar = "#" * int(imp * 40)
        print(f"  {name:<15} {imp:.3f}  {bar}")

    # ── Isolation Forest ───────────────────────────────
    print()
    print("Training Isolation Forest (contamination=0.1)...")
    X_benign = X_train[y_train == 0]
    iso = IsolationForest(
        contamination=0.1, n_estimators=100,
        random_state=42, n_jobs=-1
    )
    iso.fit(X_benign)

    iso_preds    = iso.predict(X_test)
    caught       = sum(1 for p, l in zip(iso_preds, y_test)
                       if p == -1 and l == 1)
    false_alarms = sum(1 for p, l in zip(iso_preds, y_test)
                       if p == -1 and l == 0)
    attack_test  = int(sum(y_test == 1))
    print(f"  Attack samples caught as anomaly: {caught}/{attack_test}")
    print(f"  Benign samples flagged as anomaly: {false_alarms}")

    # ── Save models ────────────────────────────────────
    joblib.dump(rf,  RF_OUT)
    joblib.dump(iso, ISO_OUT)
    print()
    print("=" * 50)
    print("  Models saved:")
    print(f"  {RF_OUT}")
    print(f"  {ISO_OUT}")
    print()
    print("  Training complete. Run start.bat to launch USB Guard.")
    print("=" * 50)


if __name__ == "__main__":
    train()
