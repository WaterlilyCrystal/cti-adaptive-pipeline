"""
CTI Adaptive Pipeline - Main Orchestrator
"""
from __future__ import annotations

import argparse
import json
import logging
from datetime import datetime, timezone

import yaml

import run_analysis
from analysis.ollama_client import OllamaServiceError, probe_service
from core.alienvault_collector import fetch_otx_pulses
from core.bluesky_collector import fetch_bluesky_infosec
from core.contextual import normalize_tech_stack
from core.cve_collector import fetch_cve_data
from core.mastodon_collector import fetch_mastodon_fosstodon
from core.reddit_collector import fetch_reddit_rss_feed
from core.rss_collector import fetch_rss_from_config
from core.telegram_collector import fetch_telegram_data
from utils.monitor import apply_runtime_profile
from utils import db_handler
from utils.db_handler import init_db, save_items_batch, upsert_items_batch

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")


def load_config(path: str = "config.yaml") -> dict:
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return apply_runtime_profile(yaml.safe_load(handle) or {})
    except UnicodeDecodeError:
        with open(path, "r", encoding="latin-1") as handle:
            return apply_runtime_profile(yaml.safe_load(handle) or {})


def sync_profile_from_config(cfg: dict, conn) -> None:
    org_cfg = cfg.get("org_profile", {})
    tech_stack = normalize_tech_stack(
        {
            "operating_systems": org_cfg.get("os", []),
            "web_servers": org_cfg.get("web", []),
            "databases": org_cfg.get("db", []),
            "frameworks": org_cfg.get("frameworks", []),
            "cloud": org_cfg.get("cloud", []),
        }
    )
    profile = {
        "user_id": db_handler.DEFAULT_USER_ID,
        "org_name": org_cfg.get("name", "Default Organization"),
        "industry": org_cfg.get("industry", "unknown"),
        "public_domain": org_cfg.get("public_domain", ""),
        "preferred_language": org_cfg.get("preferred_language", "en"),
        "preferred_languages": org_cfg.get("preferred_languages", ["en"]),
        "tech_stack": tech_stack,
        "auto_discovered": [],
    }
    db_handler.save_org_profile(conn, profile)


def phase_collect(cfg: dict, tiers: set[str] | None = None):
    timestamp = datetime.now(timezone.utc).isoformat()
    logging.info("[%s] === PHASE 1: COLLECTION ===", timestamp)
    db_conn = init_db(cfg)
    sync_profile_from_config(cfg, db_conn)

    tiers = tiers or {"social", "news", "vuln"}
    all_collected_items = []
    vuln_collected_items = []

    if "social" in tiers:
        for collector_name, collector in [
            ("Reddit", lambda: fetch_reddit_rss_feed(days_window=12 / 24)),
            ("Telegram", lambda: fetch_telegram_data(days_window=12 / 24)),
            ("Bluesky", lambda: fetch_bluesky_infosec(limit=200, days_back=1, keyword="ransomware OR malware OR exploit")),
            ("Mastodon", lambda: fetch_mastodon_fosstodon(limit=200, days_back=1, hashtag="cybersecurity")),
            ("AlienVault OTX", lambda: fetch_otx_pulses(limit=250, days_back=1)),
        ]:
            try:
                items = collector()
                logging.info("%s collection returned: %s items", collector_name, len(items))
                all_collected_items.extend(items)
            except Exception as exc:
                logging.error("%s collector failed: %s", collector_name, exc)

    if "news" in tiers:
        try:
            rss_items = fetch_rss_from_config(cfg, days_window=6 / 24)
            logging.info("RSS collection returned: %s items", len(rss_items))
            all_collected_items.extend(rss_items)
        except Exception as exc:
            logging.error("RSS collectors failed: %s", exc)

    if "vuln" in tiers:
        try:
            cve_items = fetch_cve_data(days_window=1, db_conn=db_conn)
            logging.info("Vulnerability sync returned: %s items", len(cve_items))
            vuln_collected_items.extend(cve_items)
        except Exception as exc:
            logging.error("CVE collectors failed: %s", exc)

    total_collected = len(all_collected_items) + len(vuln_collected_items)
    logging.info("Total raw items collected: %s", total_collected)
    if all_collected_items or vuln_collected_items:
        inserted = save_items_batch(db_conn, all_collected_items)
        upserted = upsert_items_batch(db_conn, vuln_collected_items)
        logging.info(
            "Phase 1 complete. Saved %s new social/news records and inserted/updated %s vulnerability records.",
            inserted,
            upserted,
        )
        try:
            with open("collect_test.txt", "w", encoding="utf-8") as handle:
                json.dump(all_collected_items + vuln_collected_items, handle, ensure_ascii=False, indent=2)
        except Exception as exc:
            logging.error("Failed to write collect_test.txt: %s", exc)
    else:
        logging.warning("No items collected from any source during this run.")

    db_conn.close()


def phase_process(cfg: dict):
    from core.processor import run_processing

    timestamp = datetime.now(timezone.utc).isoformat()
    logging.info("[%s] === PHASE 2: PROCESSING ===", timestamp)
    db_conn = init_db(cfg)
    try:
        processed_count = run_processing(db_conn, cfg, batch_size=cfg.get("pipeline", {}).get("batch_processing_size", 500))
        logging.info("Phase 2 complete. Processed %s items.", processed_count)
    finally:
        db_conn.close()


def phase_analyze(cfg: dict):
    timestamp = datetime.now(timezone.utc).isoformat()
    logging.info("[%s] === PHASE 3 & 4: ANALYSIS AND REPORTING ===", timestamp)
    db_conn = db_handler.init_db(cfg)
    consecutive_llm_failures = 0
    max_failures = max(1, int(cfg.get("pipeline", {}).get("phase3_stop_after_consecutive_llm_failures", 1)))
    try:
        try:
            probe_service(cfg)
        except OllamaServiceError as exc:
            logging.error("Phase 3 skipped because Ollama is unavailable: %s", exc)
            return
        pipeline_cfg = cfg.get("pipeline", {})
        max_items_per_run = max(1, int(pipeline_cfg.get("phase3_max_items", 20)))
        recent_days = max(1, int(pipeline_cfg.get("phase3_recent_days", 30)))
        relevant_only = bool(pipeline_cfg.get("phase3_relevant_only", True))
        items_to_process = db_handler.get_analysis_candidates(
            db_conn,
            limit=max_items_per_run,
            recent_days=recent_days,
            relevant_only=relevant_only,
        )
        if not items_to_process:
            logging.info(
                "No deterministic analysis candidates found. relevant_only=%s recent_days=%s max_items=%s",
                relevant_only,
                recent_days,
                max_items_per_run,
            )
            return
        logging.info(
            "Selected %s deterministic analysis candidate(s): %s",
            len(items_to_process),
            [item.get("title", item.get("id"))[:120] for item in items_to_process],
        )
        for item in items_to_process:
            try:
                run_analysis.process_single_item(item, cfg=cfg, db_conn=db_conn, is_mock=False)
                consecutive_llm_failures = 0
            except OllamaServiceError as exc:
                consecutive_llm_failures += 1
                logging.error(
                    "Ollama unavailable for item_id=%s title=%r: %s",
                    item.get("id"),
                    item.get("title", "")[:160],
                    exc,
                )
                if consecutive_llm_failures >= max_failures:
                    logging.error(
                        "Phase 3 stopped after %s consecutive Ollama failures. Pending items remain unanalyzed.",
                        consecutive_llm_failures,
                    )
                    break
            except Exception as exc:
                logging.error(
                    "LLM/Analysis error for item_id=%s title=%r source=%r",
                    item.get("id"),
                    item.get("title", "")[:160],
                    item.get("source"),
                    exc_info=True,
                )
    finally:
        db_conn.close()


def run_full(cfg: dict):
    phase_collect(cfg)
    phase_process(cfg)
    phase_analyze(cfg)
    logging.info("[%s] === PIPELINE RUN COMPLETED ===", datetime.now(timezone.utc).isoformat())


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CTI Adaptive Pipeline Orchestrator")
    parser.add_argument("--phase", choices=["collect", "process", "analyze", "all"], default="all")
    parser.add_argument(
        "--tier",
        choices=["all", "social", "news", "vuln"],
        default="all",
        help="For collection phase, limit execution to a specific ingestion tier.",
    )
    args = parser.parse_args()

    cfg = load_config()
    if args.phase == "collect":
        selected_tiers = {"social", "news", "vuln"} if args.tier == "all" else {args.tier}
        phase_collect(cfg, tiers=selected_tiers)
    elif args.phase == "process":
        phase_process(cfg)
    elif args.phase == "analyze":
        phase_analyze(cfg)
    else:
        run_full(cfg)
