"""Minimal SQLite connection for NEOS Guard (WAL, 30s busy timeout)."""
import os, sqlite3
from pathlib import Path

DB_PATH = Path(os.getenv("NEOSGUARD_DB", Path(__file__).parent.parent / "data" / "neosguard.db"))


def get_conn():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=30000")
    return conn
