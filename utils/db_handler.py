"""
SQLite handler for CTI Adaptive Pipeline.
Student A: Implements write/batch operations.
Student B: Implements read/query and analysis updates.
"""
import sqlite3
import json
import logging
from datetime import datetime
from pathlib import Path

DB_PATH = "data/cti.db"

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

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
    """
    Initializes the SQLite database database directory and creates tables if they do not exist.
    """
    Path("data").mkdir(exist_ok=True)
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.executescript(SCHEMA)
    conn.commit()
    logging.info("Database initialized successfully.")
    return conn

def save_item(conn: sqlite3.Connection, item: dict) -> bool:
    """
    Student A: Saves a single IntelItem into the database.
    Fallback method for isolated or single stream entries.
    """
    try:
        conn.execute("""
            INSERT OR IGNORE INTO intel_items
            (id, source, source_type, title, url, content, lang, confidence, collected_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            item["id"], item["source"], item["source_type"],
            item.get("title"), item.get("url"), item.get("content"),
            item.get("lang", "en"), item.get("confidence", 0.0),
            item.get("collected_at", datetime.utcnow().isoformat())
        ))
        conn.commit()
        return True
    except Exception as e:
        logging.error(f"Error in save_item: {str(e)}")
        return False

def save_items_batch(conn: sqlite3.Connection, items: list[dict]) -> int:
    """
    Student A: Performance-optimized batch insertion using executemany.
    Reduces disk I/O bottlenecks during mass scraping.
    """
    if not items:
        return 0
        
    query = """
        INSERT OR IGNORE INTO intel_items
        (id, source, source_type, title, url, content, lang, confidence, collected_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """
    
    # Prepare data tuples matching the query parameters
    data_tuples = [
        (
            item["id"], item["source"], item["source_type"],
            item.get("title"), item.get("url"), item.get("content"),
            item.get("lang", "en"), item.get("confidence", 0.0),
            item.get("collected_at", datetime.utcnow().isoformat())
        )
        for item in items
    ]
    
    try:
        cursor = conn.cursor()
        cursor.executemany(query, data_tuples)
        conn.commit()
        inserted_count = cursor.rowcount
        logging.info(f"Batch insert completed. Added {inserted_count} new unique items.")
        return inserted_count
    except Exception as e:
        logging.error(f"Error in save_items_batch: {str(e)}")
        return 0

def get_pending(conn: sqlite3.Connection) -> list[dict]:
    """
    Student B: Fetches all raw threat intel items that have not been analyzed yet.
    Returns a list of dictionaries for easier integration with LLM prompts.
    """
    try:
        cursor = conn.execute(
            "SELECT * FROM intel_items WHERE processed=0 ORDER BY confidence DESC"
        )
        rows = cursor.fetchall()
        # Dynamically fetch column names from the query description
        cols = [description[0] for description in cursor.description]
        return [dict(zip(cols, row)) for row in rows]
    except Exception as e:
        logging.error(f"Error in get_pending: {str(e)}")
        return []

def update_analysis(conn: sqlite3.Connection, item_id: str,
                    raw_iocs: dict, ttp_mapping: list, relevance: float) -> bool:
    """
    Student B: Writes the AI and regex enrichment results back to the database.
    Marks the item as processed to clear it from the pipeline queue.
    """
    try:
        conn.execute("""
            UPDATE intel_items
            SET raw_iocs=?, ttp_mapping=?, relevance_score=?, processed=1
            WHERE id=?
        """, (json.dumps(raw_iocs), json.dumps(ttp_mapping), relevance, item_id))
        conn.commit()
        logging.info(f"Analysis updated successfully for item ID: {item_id}")
        return True
    except Exception as e:
        logging.error(f"Error in update_analysis for item {item_id}: {str(e)}")
        return False

def save_sigma_rule(conn: sqlite3.Connection, intel_id: str, technique_id: str, rule_yaml: str) -> bool:
    """
    Student B: Stores generated Sigma rule templates mapped to specific intelligence items.
    """
    try:
        conn.execute("""
            INSERT INTO sigma_rules (intel_id, technique_id, rule_yaml, created_at)
            VALUES (?, ?, ?, ?)
        """, (intel_id, technique_id, rule_yaml, datetime.utcnow().isoformat()))
        conn.commit()
        logging.info(f"Sigma rule saved for Intel ID: {intel_id} and Technique: {technique_id}")
        return True
    except Exception as e:
        logging.error(f"Error in save_sigma_rule: {str(e)}")
        return False