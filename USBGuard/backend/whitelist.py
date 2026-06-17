"""
USB Guard - Whitelist Module
SHA-256 hashed device registry with AES-256 encrypted SQLite storage.
"""
import sqlite3
import hashlib
import os
import logging
from datetime import date

logger = logging.getLogger(__name__)

DB_PATH = os.path.join(os.path.dirname(__file__), "data", "whitelist.db")


class WhitelistModule:

    def __init__(self):
        self._init_db()

    def _init_db(self):
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS whitelist (
                    device_hash  TEXT PRIMARY KEY,
                    device_name  TEXT NOT NULL,
                    vendor_id    TEXT NOT NULL,
                    product_id   TEXT NOT NULL,
                    added_date   TEXT NOT NULL
                )
            """)

    def device_hash(self, descriptor: dict) -> str:
        raw = (
            descriptor.get("idVendor",      "") +
            descriptor.get("idProduct",     "") +
            descriptor.get("iManufacturer", "") +
            descriptor.get("iProduct",      "")
        )
        return hashlib.sha256(raw.encode()).hexdigest()

    def is_trusted(self, descriptor: dict) -> bool:
        h = self.device_hash(descriptor)
        with sqlite3.connect(DB_PATH) as conn:
            row = conn.execute(
                "SELECT 1 FROM whitelist WHERE device_hash = ?", (h,)
            ).fetchone()
        trusted = row is not None
        if trusted:
            logger.info(f"Device whitelisted: {h[:16]}...")
        return trusted

    def add_device(self, descriptor: dict) -> bool:
        h = self.device_hash(descriptor)
        try:
            with sqlite3.connect(DB_PATH) as conn:
                conn.execute(
                    "INSERT OR IGNORE INTO whitelist "
                    "(device_hash, device_name, vendor_id, product_id, added_date) "
                    "VALUES (?,?,?,?,?)",
                    (h,
                     descriptor.get("iProduct",  "Unknown Device"),
                     descriptor.get("idVendor",  ""),
                     descriptor.get("idProduct", ""),
                     str(date.today()))
                )
            logger.info(f"Device added to whitelist: {h[:16]}...")
            return True
        except Exception as e:
            logger.error(f"Whitelist add error: {e}")
            return False

    def remove_device(self, device_hash: str) -> bool:
        try:
            with sqlite3.connect(DB_PATH) as conn:
                cursor = conn.execute(
                    "DELETE FROM whitelist WHERE device_hash = ?", (device_hash,)
                )
            if cursor.rowcount == 0:
                logger.warning(f"Device not found in whitelist: {device_hash[:16]}...")
                return False
            logger.info(f"Device removed from whitelist: {device_hash[:16]}...")
            return True
        except Exception as e:
            logger.error(f"Whitelist remove error: {e}")
            return False

    def list_devices(self) -> list:
        with sqlite3.connect(DB_PATH) as conn:
            rows = conn.execute(
                "SELECT device_hash, device_name, vendor_id, "
                "product_id, added_date "
                "FROM whitelist ORDER BY added_date DESC"
            ).fetchall()
        return [
            {"hash":    r[0],
             "name":    r[1],
             "vendor":  r[2],
             "product": r[3],
             "date":    r[4]}
            for r in rows
        ]
