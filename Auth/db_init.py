import sqlite3

DB_PATH = "auth.db"

CREATE_USERS_TABLE = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    auth_key TEXT,
    customer_key TEXT,
    otp TEXT,
    otp_expiry TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT
);
"""

def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute(CREATE_USERS_TABLE)
        conn.commit()
    print("✅ Database initialized successfully at", DB_PATH)

if __name__ == "__main__":
    init_db()
