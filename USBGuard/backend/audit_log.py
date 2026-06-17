"""
USB Guard - Audit Logging Module

"""
import sqlite3
import hashlib
import json
import os
import csv
import logging
import threading
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

DB_PATH = os.path.join(os.path.dirname(__file__), "data", "audit_log.db")


class AuditLogger:

    def __init__(self):
        self._init_db()
        self._write_lock = threading.Lock()

    def _init_db(self):
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS audit_log (
                    id            INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp_utc TEXT    NOT NULL,
                    device_hash   TEXT    NOT NULL,
                    device_name   TEXT    NOT NULL,
                    vendor_id     TEXT    NOT NULL,
                    rf_score      REAL    NOT NULL,
                    iso_flag      INTEGER NOT NULL,
                    decision      TEXT    NOT NULL,
                    feature_json  TEXT    NOT NULL,
                    prev_hash     TEXT    NOT NULL,
                    entry_hash    TEXT    NOT NULL
                )
            """)

    def write(self, descriptor: dict, ml_result: dict):
        with self._write_lock:
            self._write_locked(descriptor, ml_result)

    def _write_locked(self, descriptor: dict, ml_result: dict):
        timestamp    = datetime.now(timezone.utc).isoformat()
        device_hash  = self._descriptor_hash(descriptor)
        prev_hash    = self._last_hash()
        feature_json = json.dumps(ml_result.get("features", {}))
        decision     = ml_result.get("decision", "UNKNOWN")
        score        = float(ml_result.get("score",   0.0))
        iso_flag     = int(ml_result.get("anomaly", False))
        name         = descriptor.get("iProduct",  "Unknown")
        vendor       = descriptor.get("idVendor",  "")

        entry_data = (timestamp + device_hash + str(score) +
                      str(iso_flag) + decision + feature_json + prev_hash)
        entry_hash = hashlib.sha256(entry_data.encode()).hexdigest()

        with sqlite3.connect(DB_PATH) as conn:
            conn.execute(
                "INSERT INTO audit_log "
                "(timestamp_utc, device_hash, device_name, vendor_id, "
                "rf_score, iso_flag, decision, feature_json, "
                "prev_hash, entry_hash) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (timestamp, device_hash, name, vendor,
                 score, iso_flag, decision, feature_json,
                 prev_hash, entry_hash)
            )
        logger.info(f"Audit: {decision}  score={score:.2f}  device={name}")

    def list_entries(self, limit: int = 200) -> list:
        with sqlite3.connect(DB_PATH) as conn:
            rows = conn.execute(
                "SELECT timestamp_utc, device_name, vendor_id, "
                "rf_score, decision, entry_hash "
                "FROM audit_log ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        return [
            {
                "timestamp": r[0][:19].replace("T", " "),
                "device":    f"{r[1]} · {r[2]}",
                "score":     f"{r[3]:.2f}" if r[3] > 0 else "—",
                "decision":  r[4],
                "hash":      r[5][:8] + "…"
            }
            for r in rows
        ]

    def verify_chain(self) -> bool:
        with sqlite3.connect(DB_PATH) as conn:
            rows = conn.execute(
                "SELECT timestamp_utc, device_hash, rf_score, iso_flag, "
                "decision, feature_json, prev_hash, entry_hash "
                "FROM audit_log ORDER BY id ASC"
            ).fetchall()
        if not rows:
            logger.info("Audit log empty — chain OK.")
            return True
        prev = "genesis"
        for r in rows:
            data     = r[0]+r[1]+str(r[2])+str(r[3])+r[4]+r[5]+r[6]
            expected = hashlib.sha256(data.encode()).hexdigest()
            if expected != r[7] or r[6] != prev:
                logger.critical("Audit log chain BROKEN — tampering detected!")
                return False
            prev = r[7]
        logger.info("Audit log chain verified — intact.")
        return True

    def export_csv(self, path: str):
        entries = self.list_entries(limit=10000)
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(
                f, fieldnames=["timestamp","device","score","decision","hash"]
            )
            writer.writeheader()
            writer.writerows(entries)
        logger.info(f"Audit log exported to CSV: {path}")

    def _descriptor_hash(self, d: dict) -> str:
        raw = (d.get("idVendor","") + d.get("idProduct","") +
               d.get("iManufacturer","") + d.get("iProduct",""))
        return hashlib.sha256(raw.encode()).hexdigest()

    def _last_hash(self) -> str:
        with sqlite3.connect(DB_PATH) as conn:
            row = conn.execute(
                "SELECT entry_hash FROM audit_log ORDER BY id DESC LIMIT 1"
            ).fetchone()
        return row[0] if row else "genesis"
