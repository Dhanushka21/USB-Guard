"""
USB Guard - Database Setup Script

"""
import sqlite3
import os
import json
import numpy as np
from datetime import date, datetime, timezone

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
os.makedirs(DATA_DIR, exist_ok=True)

print("=" * 50)
print("  USB Guard - Database Setup")
print("=" * 50)
print()


# 1. WHITELIST DATABASE

wl_path = os.path.join(DATA_DIR, "whitelist.db")
with sqlite3.connect(wl_path) as conn:
    conn.execute("""
        CREATE TABLE IF NOT EXISTS whitelist (
            device_hash  TEXT PRIMARY KEY,
            device_name  TEXT NOT NULL,
            vendor_id    TEXT NOT NULL,
            product_id   TEXT NOT NULL,
            added_date   TEXT NOT NULL
        )
    """)
print(f"[OK] whitelist.db")


# 2. AUDIT LOG DATABASE

log_path = os.path.join(DATA_DIR, "audit_log.db")
with sqlite3.connect(log_path) as conn:
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
print(f"[OK] audit_log.db")


# 3. MALICIOUS PROFILES DATABASE
mal_path = os.path.join(DATA_DIR, "malicious_profiles.db")
with sqlite3.connect(mal_path) as conn:
    conn.execute("""
        CREATE TABLE IF NOT EXISTS malicious_profiles (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            vendor_id   TEXT NOT NULL,
            product_id  TEXT NOT NULL,
            device_name TEXT NOT NULL,
            threat_type TEXT NOT NULL,
            added_date  TEXT NOT NULL,
            UNIQUE(vendor_id, product_id)
        )
    """)
    profiles = [
        ("0x05ac", "0x0220", "Hak5 Rubber Ducky v2",        "keystroke_injection"),
        ("0x05ac", "0x021e", "Hak5 Rubber Ducky v1",        "keystroke_injection"),
        ("0x04d8", "0xeb67", "Hak5 Bash Bunny",             "keystroke_injection"),
        ("0x1d50", "0x6089", "O.MG Cable",                  "keystroke_injection"),
        ("0x2341", "0x8036", "Arduino Leonardo BadUSB",     "keystroke_injection"),
        ("0x2341", "0x8037", "Arduino Micro BadUSB",        "keystroke_injection"),
        ("0x16c0", "0x0483", "Teensyduino BadUSB",          "keystroke_injection"),
        ("0x1b4f", "0x9208", "SparkFun Pro Micro BadUSB",   "keystroke_injection"),
        ("0x239a", "0x800b", "Adafruit ItsyBitsy BadUSB",   "keystroke_injection"),
        ("0x03eb", "0x2042", "Atmel LUFA HID BadUSB",       "keystroke_injection"),
        ("0x1a86", "0x7523", "CH340 BadUSB clone",          "keystroke_injection"),
        ("0x0d28", "0x0204", "Microbit HID attack",         "keystroke_injection"),
    ]
    today = str(date.today())
    conn.executemany(
        "INSERT OR IGNORE INTO malicious_profiles "
        "(vendor_id, product_id, device_name, threat_type, added_date) "
        "VALUES (?,?,?,?,?)",
        [(v, p, n, t, today) for v, p, n, t in profiles]
    )
    count = conn.execute(
        "SELECT COUNT(*) FROM malicious_profiles"
    ).fetchone()[0]
print(f"[OK] malicious_profiles.db  ({count} profiles seeded)")


# 4. DATASET DATABASE

ds_path = os.path.join(DATA_DIR, "dataset.db")
with sqlite3.connect(ds_path) as conn:
    conn.execute("""
        CREATE TABLE IF NOT EXISTS samples (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            ikd_mean      REAL NOT NULL,
            ikd_std       REAL NOT NULL,
            keydown_dur   REAL NOT NULL,
            burst_rate    REAL NOT NULL,
            modifier_flag INTEGER NOT NULL,
            entropy       REAL NOT NULL,
            label         INTEGER NOT NULL,
            source        TEXT NOT NULL,
            collected_at  TEXT NOT NULL
        )
    """)
    existing = conn.execute("SELECT COUNT(*) FROM samples").fetchone()[0]

    if existing == 0:
        print("[INFO] Seeding synthetic training dataset (1073 samples)...")
        np.random.seed(42)
        now = datetime.now(timezone.utc).isoformat()
        samples = []

        # Attack samples (label=1) - Rubber Ducky characteristics
        for _ in range(563):
            ikd_mean      = round(np.random.uniform(1.5, 4.0), 3)
            ikd_std       = round(np.random.uniform(0.05, 0.3), 3)
            keydown_dur   = round(np.random.uniform(0.0, 1.0), 3)
            burst_rate    = int(np.random.randint(18, 28))
            modifier_flag = int(np.random.choice([0, 1], p=[0.3, 0.7]))
            entropy       = round(np.random.uniform(0.8, 2.5), 3)
            samples.append((ikd_mean, ikd_std, keydown_dur, burst_rate,
                            modifier_flag, entropy, 1, "rubber_ducky_v2", now))

        # Benign samples (label=0) - Human typing characteristics
        for _ in range(510):
            ikd_mean      = round(np.random.uniform(80.0, 320.0), 3)
            ikd_std       = round(np.random.uniform(20.0, 90.0), 3)
            keydown_dur   = round(np.random.uniform(40.0, 150.0), 3)
            burst_rate    = int(np.random.randint(1, 5))
            modifier_flag = int(np.random.choice([0, 1], p=[0.7, 0.3]))
            entropy       = round(np.random.uniform(3.5, 5.5), 3)
            samples.append((ikd_mean, ikd_std, keydown_dur, burst_rate,
                            modifier_flag, entropy, 0, "human_volunteer", now))

        conn.executemany(
            "INSERT INTO samples "
            "(ikd_mean, ikd_std, keydown_dur, burst_rate, modifier_flag, "
            "entropy, label, source, collected_at) VALUES (?,?,?,?,?,?,?,?,?)",
            samples
        )
        total = conn.execute("SELECT COUNT(*) FROM samples").fetchone()[0]
        print(f"[OK] dataset.db  ({total} samples seeded)")
    else:
        print(f"[OK] dataset.db  ({existing} samples already present)")


# 5. EXPORT DATASET TO JSON FOR TRAINING

json_path = os.path.join(DATA_DIR, "dataset_v1.json")
with sqlite3.connect(ds_path) as conn:
    rows = conn.execute(
        "SELECT ikd_mean, ikd_std, keydown_dur, burst_rate, "
        "modifier_flag, entropy, label FROM samples"
    ).fetchall()

data = [
    {"ikd_mean": r[0], "ikd_std": r[1], "keydown_dur": r[2],
     "burst_rate": r[3], "modifier_flag": r[4],
     "entropy": r[5], "label": r[6]}
    for r in rows
]
with open(json_path, "w") as f:
    json.dump(data, f, indent=2)
print(f"[OK] dataset_v1.json exported ({len(data)} samples)")

print()
print("=" * 50)
print("  All databases ready!")
print("  Next: run training/train_model.py")
print("=" * 50)
