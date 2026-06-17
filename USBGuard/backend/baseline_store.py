"""
USB Guard - Per-Device Behavioral Baseline Store (Feature 3)
Maintains a rolling mean/variance of the 6 sandbox features per device
using Welford's online algorithm. Drift detection uses mean Z-score.
"""
import sqlite3
import json
import math
import os
import logging

logger = logging.getLogger(__name__)

DB_PATH      = os.path.join(os.path.dirname(__file__), "data", "baseline.db")
FEATURE_KEYS = ["ikd_mean", "ikd_std", "keydown_dur",
                "burst_rate", "modifier_flag", "entropy"]
MIN_SAMPLES  = 3   # minimum samples before drift comparison is meaningful


class BaselineStore:

    def __init__(self):
        self._init_db()

    def _init_db(self):
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS device_baselines (
                    device_hash  TEXT PRIMARY KEY,
                    sample_count INTEGER NOT NULL DEFAULT 0,
                    means_json   TEXT    NOT NULL DEFAULT '{}',
                    m2_json      TEXT    NOT NULL DEFAULT '{}'
                )
            """)

    def update_baseline(self, device_hash: str, features: dict):
        """Welford's online algorithm — incremental mean and variance update."""
        if not features or not any(features.values()):
            return
        with sqlite3.connect(DB_PATH) as conn:
            row = conn.execute(
                "SELECT sample_count, means_json, m2_json "
                "FROM device_baselines WHERE device_hash = ?",
                (device_hash,)
            ).fetchone()

            if row:
                n     = row[0]
                means = json.loads(row[1])
                m2s   = json.loads(row[2])
            else:
                n     = 0
                means = {k: 0.0 for k in FEATURE_KEYS}
                m2s   = {k: 0.0 for k in FEATURE_KEYS}

            n += 1
            for k in FEATURE_KEYS:
                x       = float(features.get(k, 0))
                delta   = x - means[k]
                means[k] += delta / n
                delta2   = x - means[k]
                m2s[k]  += delta * delta2

            conn.execute(
                "INSERT OR REPLACE INTO device_baselines "
                "(device_hash, sample_count, means_json, m2_json) "
                "VALUES (?,?,?,?)",
                (device_hash, n, json.dumps(means), json.dumps(m2s))
            )
        logger.debug(f"Baseline updated for {device_hash[:16]}… (n={n})")

    def compare_baseline(self, device_hash: str, features: dict) -> dict:
        """
        Compare features against stored baseline.
        Returns drift_score = mean absolute Z-score across features.
        Returns None if no baseline or insufficient samples (< MIN_SAMPLES).
        """
        with sqlite3.connect(DB_PATH) as conn:
            row = conn.execute(
                "SELECT sample_count, means_json, m2_json "
                "FROM device_baselines WHERE device_hash = ?",
                (device_hash,)
            ).fetchone()

        if not row or row[0] < MIN_SAMPLES:
            return {
                "drift_score":   None,
                "sample_count":  row[0] if row else 0,
                "status":        "insufficient_samples",
            }

        n     = row[0]
        means = json.loads(row[1])
        m2s   = json.loads(row[2])

        z_scores = []
        for k in FEATURE_KEYS:
            variance = m2s[k] / (n - 1) if n > 1 else 0.0
            if variance > 0:
                std = math.sqrt(variance)
                z   = abs(float(features.get(k, 0)) - means[k]) / std
                z_scores.append(z)

        drift = round(sum(z_scores) / len(z_scores), 3) if z_scores else 0.0
        return {
            "drift_score":    drift,
            "sample_count":   n,
            "baseline_means": means,
            "status":         "ok",
        }

    def get_status(self) -> list:
        with sqlite3.connect(DB_PATH) as conn:
            rows = conn.execute(
                "SELECT device_hash, sample_count FROM device_baselines"
            ).fetchall()
        return [{"hash": r[0][:16] + "…", "samples": r[1]} for r in rows]
