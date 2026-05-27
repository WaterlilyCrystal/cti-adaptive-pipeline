"""
SQLite + ChromaDB handler.
Sinh viên A implement các hàm write.
Sinh viên B implement các hàm read/query.
"""
import sqlite3
import json
from datetime import datetime
from pathlib import Path

DB_PATH = "data/cti.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS intel_items (
    id              TEXT PRIMARY KEY,
    source          TEXT NOT NULL,
    source_type     TEXT NOT NULL,
    title           TEXT,
    url             TEXT UNIQUE,
    content         TEXT,
    lang            TEXT DEFAULT 'en',
    raw_iocs        TEXT DEFAULT '{}',
    ttp_mapping     TEXT DEFAULT '[]',
    confidence      REAL DEFAULT 0.0,
    relevance_score REAL DEFAULT 0.0,
    processed       INTEGER DEFAULT 0,
    report_done     INTEGER DEFAULT 0,
    collected_at    TEXT
);

CREATE TABLE IF NOT EXISTS sigma_rules (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    intel_id     TEXT,
    technique_id TEXT,
    rule_yaml    TEXT,
    created_at   TEXT,
    FOREIGN KEY (intel_id) REFERENCES intel_items(id)
);

CREATE TABLE IF NOT EXISTS feedback (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    intel_id      TEXT,
    original_ttp  TEXT,
    corrected_ttp TEXT,
    corrected_at  TEXT
);
"""


def init_db() -> sqlite3.Connection:
    Path("data").mkdir(exist_ok=True)
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.executescript(SCHEMA)
    conn.commit()
    return conn


def save_item(conn: sqlite3.Connection, item: dict) -> bool:
    """Sinh viên A implement: lưu IntelItem vào DB."""
    try:
        conn.execute("""
            INSERT OR IGNORE INTO intel_items
            (id, source, source_type, title, url, content,
             lang, confidence, collected_at)
            VALUES (?,?,?,?,?,?,?,?,?)
        """, (
            item["id"], item["source"], item["source_type"],
            item["title"], item["url"], item["content"],
            item.get("lang", "en"), item.get("confidence", 0.0),
            item.get("collected_at", datetime.utcnow().isoformat())
        ))
        conn.commit()
        return True
    except Exception as e:
        print(f"[db] save_item error: {e}")
        return False


def get_pending(conn: sqlite3.Connection) -> list[dict]:
    """Sinh viên B dùng: lấy các item chưa được phân tích."""
    rows = conn.execute(
        "SELECT * FROM intel_items WHERE processed=0 ORDER BY confidence DESC"
    ).fetchall()
    cols = [d[0] for d in conn.execute("SELECT * FROM intel_items LIMIT 0").description]
    return [dict(zip(cols, r)) for r in rows]


def mark_processed(conn: sqlite3.Connection, item_id: str):
    conn.execute("UPDATE intel_items SET processed=1 WHERE id=?", (item_id,))
    conn.commit()


def update_analysis(conn: sqlite3.Connection, item_id: str,
                    raw_iocs: dict, ttp_mapping: list, relevance: float):
    """Sinh viên B dùng: ghi kết quả phân tích trở lại DB."""
    conn.execute("""
        UPDATE intel_items
        SET raw_iocs=?, ttp_mapping=?, relevance_score=?, processed=1
        WHERE id=?
    """, (json.dumps(raw_iocs), json.dumps(ttp_mapping), relevance, item_id))
    conn.commit()