"""
USB Guard - Whitelist Integrity Auditor (Feature 2)
Periodically re-hashes the entire whitelist table and broadcasts
a 'whitelist_tampered' IPC event if external modification is detected.
"""
import sqlite3
import hashlib
import threading
import time
import logging
import os

logger = logging.getLogger(__name__)

DB_PATH            = os.path.join(os.path.dirname(__file__), "data", "whitelist.db")
AUDIT_INTERVAL_SEC = 60


class WhitelistAuditor:

    def __init__(self, ipc_server):
        self._ipc           = ipc_server
        self._baseline      = None
        self._lock          = threading.Lock()
        self._running       = False
        self._last_check_ts = None
        self._last_status   = "pending"

    def refresh_baseline(self):
        """Call after any add/remove so the baseline stays current."""
        with self._lock:
            self._baseline = self._table_hash()
            logger.debug(f"Whitelist baseline refreshed: {self._baseline[:16]}…")

    def start(self):
        self._baseline      = self._table_hash()
        self._running       = True
        self._last_check_ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        self._last_status   = "ok"
        t = threading.Thread(target=self._audit_loop, daemon=True)
        t.start()
        logger.info("Whitelist integrity auditor started (60s interval).")

    def stop(self):
        self._running = False

    def get_status(self) -> dict:
        current = self._table_hash()
        with self._lock:
            expected = self._baseline
        ok = (current == expected)
        return {
            "status":        "ok" if ok else "mismatch",
            "last_check":    self._last_check_ts,
            "baseline_hash": (expected[:16] + "…") if expected else None,
            "current_hash":  current[:16] + "…",
            "interval_sec":  AUDIT_INTERVAL_SEC,
        }

    def _audit_loop(self):
        while self._running:
            time.sleep(AUDIT_INTERVAL_SEC)
            if not self._running:
                break
            self._last_check_ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            current = self._table_hash()
            with self._lock:
                expected = self._baseline
            if current != expected:
                self._last_status = "mismatch"
                logger.warning(
                    "Whitelist integrity FAILED — "
                    f"expected {expected[:16]}… got {current[:16]}…"
                )
                self._ipc.send("whitelist_tampered", {
                    "message":       "Whitelist database was modified externally.",
                    "expected_hash": expected[:16] + "…",
                    "actual_hash":   current[:16]  + "…",
                    "timestamp":     self._last_check_ts,
                })
                # Accept new state to avoid re-firing for the same change
                with self._lock:
                    self._baseline = current
            else:
                self._last_status = "ok"
                logger.debug("Whitelist integrity OK.")

    def _table_hash(self) -> str:
        try:
            with sqlite3.connect(DB_PATH) as conn:
                rows = conn.execute(
                    "SELECT device_hash, device_name, vendor_id, "
                    "product_id, added_date "
                    "FROM whitelist ORDER BY device_hash"
                ).fetchall()
            content = "|".join(
                f"{r[0]},{r[1]},{r[2]},{r[3]},{r[4]}" for r in rows
            )
            return hashlib.sha256(content.encode()).hexdigest()
        except Exception as e:
            logger.error(f"Whitelist hash error: {e}")
            return "error"
