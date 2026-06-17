"""
USB Guard - Setup Verification Script
Run after setup_database.py and train_model.py to confirm everything is ready.
"""
import os
import sqlite3

BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
DATA_DIR   = os.path.join(BASE_DIR, "data")
MODEL_DIR  = os.path.join(BASE_DIR, "models")

DATABASES = [
    ("whitelist.db",          "whitelist",           "device_hash"),
    ("audit_log.db",          "audit_log",           "id"),
    ("malicious_profiles.db", "malicious_profiles",  "id"),
    ("dataset.db",            "samples",             "id"),
]
MODELS = [
    "rf_model_v1.pkl",
    "iso_model_v1.pkl",
]

print()
print("=" * 55)
print("  USB Guard v1.0 — Setup Verification")
print("=" * 55)
print()

all_ok = True

# Check databases
print("Databases:")
for db_file, table, col in DATABASES:
    path = os.path.join(DATA_DIR, db_file)
    if not os.path.exists(path):
        print(f"  [MISSING] {db_file}")
        all_ok = False
        continue
    try:
        with sqlite3.connect(path) as conn:
            count = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
        size = os.path.getsize(path)
        print(f"  [OK]      {db_file:<30} {count:>5} rows  ({size:,} bytes)")
    except Exception as e:
        print(f"  [ERROR]   {db_file}: {e}")
        all_ok = False

print()

# Check ML models
print("ML models:")
for model in MODELS:
    path = os.path.join(MODEL_DIR, model)
    if not os.path.exists(path):
        print(f"  [MISSING] {model}  — run: python ../training/train_model.py")
        all_ok = False
    else:
        size = os.path.getsize(path)
        print(f"  [OK]      {model:<30} ({size:,} bytes)")

print()

# Check malicious profile count
mal_path = os.path.join(DATA_DIR, "malicious_profiles.db")
if os.path.exists(mal_path):
    with sqlite3.connect(mal_path) as conn:
        count = conn.execute(
            "SELECT COUNT(*) FROM malicious_profiles"
        ).fetchone()[0]
    print(f"Malicious profiles loaded:  {count}")

# Check dataset balance
ds_path = os.path.join(DATA_DIR, "dataset.db")
if os.path.exists(ds_path):
    with sqlite3.connect(ds_path) as conn:
        attack = conn.execute(
            "SELECT COUNT(*) FROM samples WHERE label=1"
        ).fetchone()[0]
        benign = conn.execute(
            "SELECT COUNT(*) FROM samples WHERE label=0"
        ).fetchone()[0]
    print(f"Dataset balance:            {attack} attack / {benign} benign")

print()
print("=" * 55)
if all_ok:
    print("  All checks PASSED.")
    print("  Run start.bat to launch USB Guard.")
else:
    print("  Some items MISSING. Fix the above before running.")
print("=" * 55)
print()
