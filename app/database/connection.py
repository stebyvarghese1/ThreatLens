"""SQLite Connection Manager with WAL mode and resilience."""
import sqlite3
from pathlib import Path
from typing import Optional
from app.config import DB_PATH

SCHEMA_PATH = Path(__file__).resolve().parent / "schema.sql"

def get_db_connection(custom_path: Optional[Path] = None) -> sqlite3.Connection:
    """Create and return a configured SQLite connection.
    
    Enforces Write-Ahead Logging (WAL) and busy timeout to avoid concurrency lockups.
    """
    path = custom_path or DB_PATH
    conn = sqlite3.connect(str(path), timeout=10.0, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    
    # Configure SQLite for robust high-concurrency desktop operation
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA busy_timeout = 5000;")
    conn.execute("PRAGMA synchronous = NORMAL;")
    conn.execute("PRAGMA foreign_keys = ON;")
    
    return conn

def init_db(custom_path: Optional[Path] = None) -> None:
    """Initialize database tables and indexes from schema.sql."""
    conn = get_db_connection(custom_path)
    try:
        with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
            schema_script = f.read()
        conn.executescript(schema_script)
        conn.commit()
    finally:
        conn.close()

