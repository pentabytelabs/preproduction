# db_init.py
"""
Standalone DB initializer for the Flask Auth System.

Usage:
  python db_init.py           # creates auth.db if missing and ensures tables exist
  python db_init.py --recreate   # drops tables and recreates (use carefully)
"""

import sqlite3
import argparse
import os
from pathlib import Path

DB_PATH = Path("auth.db")

CREATE_USERS_TABLE = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    auth_key TEXT,
    customer_key TEXT,
    otp TEXT,
    otp_expiry TIMESTAMP
);
"""

def create_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute(CREATE_USERS_TABLE)
        conn.commit()
    print(f"[+] DB initialized at {DB_PATH.resolve()}")

def recreate_db():
    if DB_PATH.exists():
        backup = DB_PATH.with_suffix(".db.bak")
        os.replace(DB_PATH, backup)
        print(f"[!] Existing DB moved to {backup}")
    create_db()
    print("[!] Recreated DB (old DB backed up).")

def main():
    parser = argparse.ArgumentParser(description="Init or recreate the auth SQLite DB.")
    parser.add_argument("--recreate", action="store_true", help="Recreate DB (backups old DB)")
    args = parser.parse_args()

    if args.recreate:
        recreate_db()
    else:
        create_db()

if __name__ == "__main__":
    main()
