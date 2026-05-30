"""
SQLite handler for the CTI adaptive pipeline.
"""
from __future__ import annotations

import json
import logging
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List

from core.contextual import TECH_CATALOG, match_profile_to_content, normalize_tech_stack

DB_PATH = "data/cti.db"
DEFAULT_USER_ID = "default"

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("db_handler")

SCHEMA = """
CREATE TABLE IF NOT EXISTS intel_items (
    id                   TEXT PRIMARY KEY,
    source               TEXT NOT NULL,
    source_type          TEXT NOT NULL,
    title                TEXT,
    url                  TEXT UNIQUE,
    content              TEXT,
    lang                 TEXT DEFAULT 'en',
    raw_iocs             TEXT DEFAULT '{}',
    ttp_mapping          TEXT DEFAULT '[]',
    confidence           REAL DEFAULT 0.0,
    credibility_score    REAL DEFAULT 0.0,
    relevance_score      REAL DEFAULT 0.0,
    severity             TEXT DEFAULT 'low',
    processed            INTEGER DEFAULT 0,
    analyzed             INTEGER DEFAULT 0,
    report_done          INTEGER DEFAULT 0,
    triage_status        TEXT DEFAULT 'new',
    triage_priority      TEXT DEFAULT 'routine',
    impacted_assets      TEXT DEFAULT '[]',
    mitigation_script    TEXT DEFAULT '',
    notification_payload TEXT DEFAULT '',
    watch_until          TEXT DEFAULT '',
    resolution_status    TEXT DEFAULT '',
    resolution_note      TEXT DEFAULT '',
    resolution_by        TEXT DEFAULT '',
    resolution_at        TEXT DEFAULT '',
    executive_summary_en TEXT DEFAULT '',
    executive_summary_vi TEXT DEFAULT '',
    collected_at         TEXT
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

CREATE TABLE IF NOT EXISTS user_profiles (
    user_id              TEXT PRIMARY KEY,
    org_name             TEXT,
    industry             TEXT,
    public_domain        TEXT,
    preferred_language   TEXT DEFAULT 'en',
    preferred_languages  TEXT DEFAULT '["en"]',
    tech_stack_json      TEXT DEFAULT '{}',
    auto_discovered_json TEXT DEFAULT '[]',
    updated_at           TEXT
);

CREATE TABLE IF NOT EXISTS tech_stack_vulnerabilities (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id       TEXT,
    intel_id      TEXT,
    product_name  TEXT,
    matched_term  TEXT,
    source        TEXT,
    severity      TEXT,
    is_relevant   INTEGER DEFAULT 0,
    is_zero_day   INTEGER DEFAULT 0,
    confidence    REAL DEFAULT 0.0,
    created_at    TEXT
);

CREATE TABLE IF NOT EXISTS threat_notifications (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    intel_id     TEXT,
    channel      TEXT,
    destination  TEXT,
    payload      TEXT,
    status       TEXT,
    created_at   TEXT
);

CREATE TABLE IF NOT EXISTS scheduled_jobs (
    job_name       TEXT PRIMARY KEY,
    interval_hours INTEGER,
    enabled        INTEGER DEFAULT 1,
    last_run_at    TEXT DEFAULT '',
    next_run_hint  TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS collector_state (
    state_key   TEXT PRIMARY KEY,
    state_value TEXT DEFAULT '',
    updated_at  TEXT
);
"""


def _json_dump(value) -> str:
    return json.dumps(value, ensure_ascii=False)


def _json_load(value, default):
    if not value:
        return default
    try:
        return json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return default


def _ensure_column(conn: sqlite3.Connection, table: str, column: str, ddl: str) -> None:
    cursor = conn.execute(f"PRAGMA table_info({table})")
    columns = {row[1] for row in cursor.fetchall()}
    if column not in columns:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {ddl}")


def _default_profile_from_config(cfg: Dict | None = None) -> Dict:
    cfg = cfg or {}
    org_profile = cfg.get("org_profile", {})
    tech_stack = normalize_tech_stack({
        "operating_systems": list(org_profile.get("os", [])),
        "web_servers": list(org_profile.get("web", [])),
        "databases": list(org_profile.get("db", [])),
        "frameworks": list(org_profile.get("frameworks", [])),
        "cloud": list(org_profile.get("cloud", [])),
    })
    preferred_languages = org_profile.get("preferred_languages") or ["en"]
    return {
        "user_id": DEFAULT_USER_ID,
        "org_name": org_profile.get("name", "Default Organization"),
        "industry": org_profile.get("industry", "unknown"),
        "public_domain": org_profile.get("public_domain", ""),
        "preferred_language": org_profile.get("preferred_language", preferred_languages[0]),
        "preferred_languages": preferred_languages,
        "tech_stack": tech_stack,
        "auto_discovered": [],
    }


def init_db(cfg: Dict | None = None) -> sqlite3.Connection:
    Path("data").mkdir(exist_ok=True)
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)

    migrations = [
        ("intel_items", "analyzed", "analyzed INTEGER DEFAULT 0"),
        ("intel_items", "severity", "severity TEXT DEFAULT 'low'"),
        ("intel_items", "credibility_score", "credibility_score REAL DEFAULT 0.0"),
        ("intel_items", "triage_status", "triage_status TEXT DEFAULT 'new'"),
        ("intel_items", "triage_priority", "triage_priority TEXT DEFAULT 'routine'"),
        ("intel_items", "impacted_assets", "impacted_assets TEXT DEFAULT '[]'"),
        ("intel_items", "mitigation_script", "mitigation_script TEXT DEFAULT ''"),
        ("intel_items", "notification_payload", "notification_payload TEXT DEFAULT ''"),
        ("intel_items", "watch_until", "watch_until TEXT DEFAULT ''"),
        ("intel_items", "resolution_status", "resolution_status TEXT DEFAULT ''"),
        ("intel_items", "resolution_note", "resolution_note TEXT DEFAULT ''"),
        ("intel_items", "resolution_by", "resolution_by TEXT DEFAULT ''"),
        ("intel_items", "resolution_at", "resolution_at TEXT DEFAULT ''"),
        ("intel_items", "executive_summary_en", "executive_summary_en TEXT DEFAULT ''"),
        ("intel_items", "executive_summary_vi", "executive_summary_vi TEXT DEFAULT ''"),
    ]
    for table, column, ddl in migrations:
        _ensure_column(conn, table, column, ddl)

    ensure_default_profile(conn, _default_profile_from_config(cfg))
    _seed_scheduler_jobs(conn)
    conn.commit()
    logger.info("Database initialized successfully.")
    return conn


def _seed_scheduler_jobs(conn: sqlite3.Connection) -> None:
    jobs = {
        "social_ingestion": 2,
        "news_ingestion": 6,
        "vulnerability_sync": 24,
    }
    for job_name, interval in jobs.items():
        conn.execute(
            """
            INSERT OR IGNORE INTO scheduled_jobs (job_name, interval_hours, enabled)
            VALUES (?, ?, 1)
            """,
            (job_name, interval),
        )


def ensure_default_profile(conn: sqlite3.Connection, profile: Dict) -> None:
    existing = conn.execute(
        "SELECT COUNT(*) AS count FROM user_profiles WHERE user_id=?",
        (profile["user_id"],),
    ).fetchone()
    if existing and existing["count"]:
        return
    save_org_profile(conn, profile)


def save_org_profile(conn: sqlite3.Connection, profile: Dict) -> bool:
    normalized_stack = normalize_tech_stack(profile.get("tech_stack") or {})
    preferred_languages = profile.get("preferred_languages") or [profile.get("preferred_language", "en")]
    user_id = profile.get("user_id", DEFAULT_USER_ID)
    previous_row = conn.execute(
        "SELECT tech_stack_json FROM user_profiles WHERE user_id=?",
        (user_id,),
    ).fetchone()
    previous_stack = normalize_tech_stack(_json_load(previous_row["tech_stack_json"], {})) if previous_row else {}
    conn.execute(
        """
        INSERT INTO user_profiles (
            user_id, org_name, industry, public_domain, preferred_language,
            preferred_languages, tech_stack_json, auto_discovered_json, updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(user_id) DO UPDATE SET
            org_name=excluded.org_name,
            industry=excluded.industry,
            public_domain=excluded.public_domain,
            preferred_language=excluded.preferred_language,
            preferred_languages=excluded.preferred_languages,
            tech_stack_json=excluded.tech_stack_json,
            auto_discovered_json=excluded.auto_discovered_json,
            updated_at=excluded.updated_at
        """,
        (
            user_id,
            profile.get("org_name", "Default Organization"),
            profile.get("industry", "unknown"),
            profile.get("public_domain", ""),
            profile.get("preferred_language", "en"),
            _json_dump(preferred_languages),
            _json_dump(normalized_stack),
            _json_dump(profile.get("auto_discovered", [])),
            datetime.now(timezone.utc).isoformat(),
        ),
    )
    conn.commit()
    stack_changed = previous_stack != normalized_stack
    if stack_changed:
        rescan_profile_matches(conn, user_id=user_id)
    return stack_changed


def get_active_profile(conn: sqlite3.Connection, user_id: str = DEFAULT_USER_ID) -> Dict:
    row = conn.execute("SELECT * FROM user_profiles WHERE user_id=?", (user_id,)).fetchone()
    if not row:
        profile = _default_profile_from_config()
        save_org_profile(conn, profile)
        return profile
    return {
        "user_id": row["user_id"],
        "org_name": row["org_name"],
        "industry": row["industry"],
        "public_domain": row["public_domain"],
        "preferred_language": row["preferred_language"] or "en",
        "preferred_languages": _json_load(row["preferred_languages"], ["en"]),
        "tech_stack": normalize_tech_stack(_json_load(row["tech_stack_json"], {})),
        "auto_discovered": _json_load(row["auto_discovered_json"], []),
        "updated_at": row["updated_at"],
    }


def clear_profile_matches(conn: sqlite3.Connection, user_id: str = DEFAULT_USER_ID) -> None:
    conn.execute("DELETE FROM tech_stack_vulnerabilities WHERE user_id=?", (user_id,))
    conn.commit()


def record_profile_match(
    conn: sqlite3.Connection,
    intel_id: str,
    matched_terms: Iterable[str],
    source: str,
    severity: str,
    is_zero_day: bool,
    confidence: float,
    user_id: str = DEFAULT_USER_ID,
) -> None:
    rows = [
        (
            user_id,
            intel_id,
            term,
            term,
            source,
            severity,
            1,
            1 if is_zero_day else 0,
            confidence,
            datetime.now(timezone.utc).isoformat(),
        )
        for term in set(matched_terms)
    ]
    if not rows:
        return
    conn.executemany(
        """
        INSERT INTO tech_stack_vulnerabilities (
            user_id, intel_id, product_name, matched_term, source, severity,
            is_relevant, is_zero_day, confidence, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        rows,
    )
    conn.commit()


def rescan_profile_matches(conn: sqlite3.Connection, user_id: str = DEFAULT_USER_ID) -> int:
    profile = get_active_profile(conn, user_id=user_id)
    conn.execute("DELETE FROM tech_stack_vulnerabilities WHERE user_id=?", (user_id,))

    rows = conn.execute(
        """
        SELECT id, source, source_type, title, content, severity, confidence, credibility_score
        FROM intel_items
        """
    ).fetchall()

    match_rows = []
    impacted_updates = []
    now = datetime.now(timezone.utc).isoformat()

    for row in rows:
        item = dict(row)
        text = f"{item.get('title', '')}\n{item.get('content', '')}"
        matched_terms = match_profile_to_content(profile, text)
        impacted_updates.append((_json_dump(sorted(set(matched_terms))), item["id"]))
        if not matched_terms:
            continue
        confidence = float(item.get("credibility_score") or item.get("confidence") or 0.0)
        is_zero_day = 1 if "kev" in (item.get("source") or "").lower() else 0
        for term in sorted(set(matched_terms)):
            match_rows.append(
                (
                    user_id,
                    item["id"],
                    term,
                    term,
                    item.get("source", ""),
                    item.get("severity", "low"),
                    1,
                    is_zero_day,
                    confidence,
                    now,
                )
            )

    if impacted_updates:
        conn.executemany(
            "UPDATE intel_items SET impacted_assets=? WHERE id=?",
            impacted_updates,
        )
    if match_rows:
        conn.executemany(
            """
            INSERT INTO tech_stack_vulnerabilities (
                user_id, intel_id, product_name, matched_term, source, severity,
                is_relevant, is_zero_day, confidence, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            match_rows,
        )
    conn.commit()
    logger.info("Rescanned %s intel items against profile. Found %s tech stack matches.", len(rows), len(match_rows))
    return len(match_rows)


def save_item(conn: sqlite3.Connection, item: Dict) -> bool:
    return save_items_batch(conn, [item]) > 0


def save_items_batch(conn: sqlite3.Connection, items: List[Dict]) -> int:
    if not items:
        return 0
    query = """
        INSERT OR IGNORE INTO intel_items
        (id, source, source_type, title, url, content, lang, confidence, collected_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """
    data_tuples = [
        (
            item["id"],
            item["source"],
            item["source_type"],
            item.get("title"),
            item.get("url"),
            item.get("content"),
            item.get("lang", "en"),
            item.get("confidence", 0.0),
            item.get("collected_at", datetime.now(timezone.utc).isoformat()),
        )
        for item in items
    ]
    try:
        cursor = conn.cursor()
        before = conn.total_changes
        cursor.executemany(query, data_tuples)
        conn.commit()
        inserted_count = conn.total_changes - before
        logger.info("Batch insert completed. Added %s new unique items.", inserted_count)
        return inserted_count
    except Exception as exc:
        logger.error("Error in save_items_batch: %s", exc)
        return 0


def upsert_items_batch(conn: sqlite3.Connection, items: List[Dict]) -> int:
    if not items:
        return 0
    query = """
        INSERT INTO intel_items
        (id, source, source_type, title, url, content, lang, confidence, collected_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
            source=excluded.source,
            source_type=excluded.source_type,
            title=excluded.title,
            url=excluded.url,
            content=excluded.content,
            lang=excluded.lang,
            confidence=excluded.confidence,
            collected_at=excluded.collected_at,
            processed=0,
            analyzed=0,
            report_done=0,
            credibility_score=0.0,
            relevance_score=0.0,
            triage_status='new',
            triage_priority='routine',
            impacted_assets='[]',
            mitigation_script='',
            notification_payload='',
            watch_until='',
            executive_summary_en='',
            executive_summary_vi=''
    """
    data_tuples = [
        (
            item["id"],
            item["source"],
            item["source_type"],
            item.get("title"),
            item.get("url"),
            item.get("content"),
            item.get("lang", "en"),
            item.get("confidence", 0.0),
            item.get("collected_at", datetime.now(timezone.utc).isoformat()),
        )
        for item in items
    ]
    try:
        before = conn.total_changes
        conn.executemany(query, data_tuples)
        conn.commit()
        changed_count = conn.total_changes - before
        logger.info("Feed upsert completed. Inserted/updated %s records.", changed_count)
        rescan_profile_matches(conn)
        return changed_count
    except Exception as exc:
        logger.error("Error in upsert_items_batch: %s", exc)
        return 0


def get_pending(conn: sqlite3.Connection) -> List[Dict]:
    rows = conn.execute(
        """
        SELECT * FROM intel_items
        WHERE processed=1
          AND analyzed=0
          AND triage_status IN ('queued', 'critical')
        ORDER BY CASE triage_priority
            WHEN 'critical' THEN 3
            WHEN 'high' THEN 2
            ELSE 1
        END DESC, credibility_score DESC, confidence DESC
        """
    ).fetchall()
    return [dict(row) for row in rows]


def update_processing(
    conn: sqlite3.Connection,
    item_id: str,
    relevance: float,
    credibility_score: float = 0.0,
    triage_status: str = "queued",
    triage_priority: str = "routine",
    watch_until: str = "",
) -> bool:
    try:
        conn.execute(
            """
            UPDATE intel_items
            SET relevance_score=?, credibility_score=?, processed=1,
                triage_status=?, triage_priority=?, watch_until=?
            WHERE id=?
            """,
            (relevance, credibility_score, triage_status, triage_priority, watch_until, item_id),
        )
        conn.commit()
        return True
    except Exception as exc:
        logger.error("Error in update_processing for item %s: %s", item_id, exc)
        return False


def update_analysis(
    conn: sqlite3.Connection,
    item_id: str,
    raw_iocs: Dict,
    ttp_mapping: List[Dict],
    relevance: float,
    severity: str = "low",
    impacted_assets: List[str] | None = None,
    mitigation_script: str = "",
    notification_payload: Dict | None = None,
    triage_status: str = "archived",
    triage_priority: str = "routine",
    executive_summary_en: str = "",
    executive_summary_vi: str = "",
) -> bool:
    try:
        conn.execute(
            """
            UPDATE intel_items
            SET raw_iocs=?, ttp_mapping=?, relevance_score=?, analyzed=1, severity=?,
                impacted_assets=?, mitigation_script=?, notification_payload=?,
                triage_status=?, triage_priority=?, executive_summary_en=?,
                executive_summary_vi=?
            WHERE id=?
            """,
            (
                _json_dump(raw_iocs),
                _json_dump(ttp_mapping),
                relevance,
                severity,
                _json_dump(impacted_assets or []),
                mitigation_script,
                _json_dump(notification_payload or {}),
                triage_status,
                triage_priority,
                executive_summary_en,
                executive_summary_vi,
                item_id,
            ),
        )
        conn.commit()
        return True
    except Exception as exc:
        logger.error("Error in update_analysis for item %s: %s", item_id, exc)
        return False


def save_sigma_rule(conn: sqlite3.Connection, intel_id: str, technique_id: str, rule_yaml: str) -> bool:
    try:
        conn.execute(
            """
            INSERT INTO sigma_rules (intel_id, technique_id, rule_yaml, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (intel_id, technique_id, rule_yaml, datetime.now(timezone.utc).isoformat()),
        )
        conn.commit()
        return True
    except Exception as exc:
        logger.error("Error in save_sigma_rule: %s", exc)
        return False


def save_notification_event(
    conn: sqlite3.Connection,
    intel_id: str,
    channel: str,
    destination: str,
    payload: Dict,
    status: str,
) -> None:
    conn.execute(
        """
        INSERT INTO threat_notifications (intel_id, channel, destination, payload, status, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            intel_id,
            channel,
            destination,
            _json_dump(payload),
            status,
            datetime.now(timezone.utc).isoformat(),
        ),
    )
    conn.commit()


def get_dashboard_alerts(
    conn: sqlite3.Connection,
    severity: str = "all",
    source_type: str = "all",
) -> List[Dict]:
    query = """
        SELECT id, title, source, source_type, severity, credibility_score, triage_status,
               triage_priority, impacted_assets, mitigation_script, collected_at,
               resolution_status, notification_payload, url
        FROM intel_items
        WHERE analyzed=1
    """
    params: List[str] = []
    if severity != "all":
        query += " AND severity=?"
        params.append(severity)
    if source_type != "all":
        query += " AND source_type=?"
        params.append(source_type)
    query += " ORDER BY CASE triage_priority WHEN 'critical' THEN 3 WHEN 'high' THEN 2 ELSE 1 END DESC, collected_at DESC"
    rows = conn.execute(query, params).fetchall()
    results = []
    for row in rows:
        item = dict(row)
        item["impacted_assets"] = _json_load(item.get("impacted_assets"), [])
        item["notification_payload"] = _json_load(item.get("notification_payload"), {})
        results.append(item)
    return results


def get_heatmap_data(conn: sqlite3.Connection) -> List[Dict]:
    rows = conn.execute(
        """
        SELECT product_name, severity, COUNT(*) AS matches
        FROM tech_stack_vulnerabilities
        GROUP BY product_name, severity
        ORDER BY matches DESC, product_name ASC
        """
    ).fetchall()
    return [dict(row) for row in rows]


def set_remediation_status(
    conn: sqlite3.Connection,
    intel_id: str,
    status: str,
    acted_by: str,
    note: str = "",
) -> None:
    timestamp = datetime.now(timezone.utc).isoformat()
    conn.execute(
        """
        UPDATE intel_items
        SET resolution_status=?, resolution_by=?, resolution_at=?, resolution_note=?,
            triage_status=CASE
                WHEN ? IN ('mitigated', 'accepted_risk', 'not_applicable') THEN 'closed'
                ELSE triage_status
            END
        WHERE id=?
        """,
        (status, acted_by, timestamp, note, status, intel_id),
    )
    conn.commit()


def get_scheduler_jobs(conn: sqlite3.Connection) -> List[Dict]:
    rows = conn.execute("SELECT * FROM scheduled_jobs ORDER BY interval_hours ASC").fetchall()
    return [dict(row) for row in rows]


def get_collector_state(conn: sqlite3.Connection, state_key: str, default: str = "") -> str:
    row = conn.execute(
        "SELECT state_value FROM collector_state WHERE state_key=?",
        (state_key,),
    ).fetchone()
    return row["state_value"] if row and row["state_value"] is not None else default


def set_collector_state(conn: sqlite3.Connection, state_key: str, state_value: str) -> None:
    conn.execute(
        """
        INSERT INTO collector_state (state_key, state_value, updated_at)
        VALUES (?, ?, ?)
        ON CONFLICT(state_key) DO UPDATE SET
            state_value=excluded.state_value,
            updated_at=excluded.updated_at
        """,
        (state_key, state_value, datetime.now(timezone.utc).isoformat()),
    )
    conn.commit()


def touch_scheduler_job(conn: sqlite3.Connection, job_name: str, next_run_hint: str = "") -> None:
    conn.execute(
        """
        UPDATE scheduled_jobs
        SET last_run_at=?, next_run_hint=?
        WHERE job_name=?
        """,
        (datetime.now(timezone.utc).isoformat(), next_run_hint, job_name),
    )
    conn.commit()


def get_high_severity_items(conn: sqlite3.Connection, days: int = 30) -> List[Dict]:
    cutoff = datetime.now(timezone.utc).timestamp() - days * 86400
    rows = conn.execute(
        """
        SELECT * FROM intel_items
        WHERE analyzed=1 AND severity IN ('critical', 'high')
        ORDER BY collected_at DESC
        """
    ).fetchall()
    results = []
    for row in rows:
        item = dict(row)
        try:
            collected_at = datetime.fromisoformat(item["collected_at"]).timestamp()
        except Exception:
            collected_at = cutoff + 1
        if collected_at >= cutoff:
            results.append(item)
    return results
