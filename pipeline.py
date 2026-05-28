"""
CTI Adaptive Pipeline - Main Orchestrator
"""
import argparse
import yaml
import logging
import json
from datetime import datetime, timezone
from utils.db_handler import init_db, save_items_batch
from utils import db_handler
import run_analysis

from core.reddit_collector import fetch_reddit_rss_feed
from core.rss_collector import fetch_rss_from_config
from core.telegram_collector import fetch_telegram_data
from core.cve_collector import fetch_cve_data
from core.bluesky_collector import fetch_bluesky_infosec
from core.mastodon_collector import fetch_mastodon_fosstodon

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def load_config(path="config.yaml") -> dict:
    """Loads configuration and tech stack profiles from the YAML file."""
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return yaml.safe_load(f)
    except UnicodeDecodeError:
        # Fallback to latin-1 if file uses a different legacy encoding
        with open(path, 'r', encoding='latin-1') as f:
            return yaml.safe_load(f)
    except FileNotFoundError:
        logging.error(f"Configuration file not found: {path}")
        raise
    except Exception as e:
        logging.error(f"Failed to load configuration: {e}")
        raise

def phase_collect(cfg: dict):
    """
    Phase 1: Data Collection
    Fetches raw data from all open sources (Reddit RSS, News RSS, Telegram) 
    and saves them into SQLite with deduplication by URL.
    """
    timestamp = datetime.now(timezone.utc).isoformat()
    logging.info(f"[{timestamp}] === PHASE 1: COLLECTION ===")
    
    # Establish database connection
    db_conn = init_db()
    all_collected_items = []

    # Collection scheduling (standard CTI cadence)
    SOCIAL_HOURS = 2      # social sources polled every 2 hours
    NEWS_HOURS = 12       # news/RSS polled every 12 hours (instead of 6 for better coverage)
    CVE_DAYS = 1          # NVD/CISA incremental update daily

    # #1. Fetch from Reddit RSS (social cadence)
    # try:
    #     logging.info("Executing Reddit collector...")
    #     reddit_items = fetch_reddit_rss_feed(days_window=SOCIAL_HOURS / 24)
    #     logging.info(f"Reddit collection returned: {len(reddit_items)} items")
    #     all_collected_items.extend(reddit_items)
    # except Exception as e:
    #     logging.error(f"Reddit collector failed: {str(e)}")

    # 2. Fetch RSS news sources (configured in config.yaml)
    try:
        logging.info("Executing RSS collectors from config...")
        rss_items = fetch_rss_from_config(cfg, days_window=NEWS_HOURS / 24)
        logging.info(f"RSS collection returned: {len(rss_items)} items")
        all_collected_items.extend(rss_items)
    except Exception as e:
        logging.error(f"RSS collectors failed: {str(e)}")

    # # 3. Fetch Telegram public channel posts (social cadence)
    # try:
    #     logging.info("Executing Telegram collector...")
    #     telegram_items = fetch_telegram_data(days_window=SOCIAL_HOURS / 24)
    #     logging.info(f"Telegram collection returned: {len(telegram_items)} items")
    #     all_collected_items.extend(telegram_items)
    # except Exception as e:
    #     logging.error(f"Telegram collector failed: {str(e)}")

    # 3b. Fetch additional social sources: Bluesky
    try:
        logging.info("Executing Bluesky collector...")
        bluesky_items = fetch_bluesky_infosec(limit=200, days_back=1, keyword="ransomware OR malware OR exploit")
        logging.info(f"Bluesky collection returned: {len(bluesky_items)} items")
        all_collected_items.extend(bluesky_items)
    except Exception as e:
        logging.error(f"Bluesky collector failed: {str(e)}")

    # 3c. Fetch Mastodon (fosstodon.org) hashtag timelines
    try:
        logging.info("Executing Mastodon collector...")
        mastodon_items = fetch_mastodon_fosstodon(limit=200, days_back=1, hashtag="cybersecurity")
        logging.info(f"Mastodon collection returned: {len(mastodon_items)} items")
        all_collected_items.extend(mastodon_items)
    except Exception as e:
        logging.error(f"Mastodon collector failed: {str(e)}")

    # # 4. Fetch formal vulnerability feeds (CISA KEV + NVD + optional OTX)
    # try:
    #     logging.info("Executing CVE/KEV collectors (NVD + CISA KEV)...")
    #     cve_items = fetch_cve_data(days_window=CVE_DAYS)
    #     all_collected_items.extend(cve_items)
    # except Exception as e:
    #     logging.error(f"CVE collectors failed: {str(e)}")

    # Log collection statistics before deduplication
    logging.info(f"Total raw items collected: {len(all_collected_items)}")
    
    # 5. Save all collected items to SQLite in a high-performance batch
    if all_collected_items:
        logging.info(f"Sending {len(all_collected_items)} items to the database layer...")
        inserted = save_items_batch(db_conn, all_collected_items)
        logging.info(f"Phase 1 complete. Saved {inserted} new unique records to database.")
        
        # Write a test output file for quick local verification
        try:
            with open("collect_test.txt", "w", encoding="utf-8") as fh:
                json.dump(all_collected_items, fh, ensure_ascii=False, indent=2)
            logging.info("Wrote collected items to collect_test.txt for inspection.")
        except Exception as e:
            logging.error(f"Failed to write collect_test.txt: {e}")
            
        # Print summary statistics
        sources_count = {}
        for item in all_collected_items:
            source = item.get("source", "unknown")
            sources_count[source] = sources_count.get(source, 0) + 1
        logging.info("Collection breakdown by source:")
        for source, count in sorted(sources_count.items(), key=lambda x: x[1], reverse=True):
            logging.info(f"  - {source}: {count} items")
    else:
        logging.warning("No items collected from any source during this run.")

    # Always close the connection when the phase ends
    db_conn.close()
    logging.info("Phase 1 collection finished. Database connection closed.")

def phase_process(cfg: dict):
    """
    Phase 2: Data Pre-processing
    Cleans noise, de-duplicates items, normalizes text, handles translations, 
    and calculates relevance scores using the unified processing engine.
    """
    # Point directly to the unified module directory location
    from core.processor import run_processing
    
    timestamp = datetime.now(timezone.utc).isoformat()
    logging.info(f"[{timestamp}] === PHASE 2: PROCESSING ===")
    
    # Initialize database connection
    db_conn = init_db()
    
    try:
        # Run processing pipeline against the current database context
        processed_count = run_processing(db_conn, cfg)
        
        if processed_count > 0:
            logging.info(f"Phase 2 complete. Processed {processed_count} items.")
        else:
            logging.warning("Phase 2 returned 0 processed items. Staging area might be empty.")
            
    except Exception as e:
        logging.error(f"Phase 2 processing failed: {str(e)}")
        
    finally:
        db_conn.close()
        logging.info("Phase 2 processing finished. Database connection closed.")

def phase_analyze(cfg: dict):
    """
    Phase 3 & 4: Threat Analysis & Intelligence Enrichment
    [INTEGRATED] System automatically extracts IOCs, maps MITRE TTPs, 
    generates Sigma rules, and exports 3-tier reports using LLM (Qwen2.5).
    """
    timestamp = datetime.now(timezone.utc).isoformat()
    logging.info(f"[{timestamp}] === PHASE 3 & 4: ANALYSIS AND REPORTING ===")
    
    db_conn = db_handler.init_db()
    
    try:
        # Fetch articles cleaned by Phase 2 that haven't been analyzed yet
        all_pending_items = db_handler.get_pending(db_conn)
        
        # Limit to 5 feeds per run to prevent RAM/GPU overload on Local LLM
        items_to_process = all_pending_items[:5]
        
        if not items_to_process:
            logging.info("[-] No new feeds require AI analysis. System going to sleep.")
            return
            
        logging.info(f"[+] Found {len(all_pending_items)} pending feeds. Pushing {len(items_to_process)} feeds through the AI Pipeline...")
        
        # Run the analysis loop exactly as it operates standalone
        for item in items_to_process:
            try:
                run_analysis.process_single_item(item, db_conn=db_conn, is_mock=False)
            except Exception as e:
                logging.error(f"[-] LLM/Analysis error while processing feed '{item.get('title')}': {str(e)}")
                
        logging.info("[+] Phase 3 & 4 completed successfully!")
        
    except Exception as e:
        logging.error(f"[-] Critical error in Phase 3: {str(e)}")
    finally:
        db_conn.close()
        logging.info("Phase 3 disconnected from the Database.")
        

def run_full(cfg: dict):
    """Runs the entire end-to-end intelligence pipeline sequentially."""
    phase_collect(cfg)
    try:
        phase_process(cfg)
        phase_analyze(cfg)
    except NotImplementedError as e:
        logging.warning(f"Pipeline stopped early: {str(e)}")
    
    timestamp = datetime.now(timezone.utc).isoformat()
    logging.info(f"[{timestamp}] === PIPELINE RUN COMPLETED ===")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CTI Adaptive Pipeline Orchestrator")
    parser.add_argument(
        "--phase",
        choices=["collect", "process", "analyze", "all"],
        default="all",
        help="Execute a specific pipeline phase or run all phases sequentially"
    )
    args = parser.parse_args()
    
    # Load settings
    cfg = load_config()

    # Map command line arguments to functions
    phase_map = {
        "collect": phase_collect,
        "process": phase_process,
        "analyze": phase_analyze,
        "all": run_full,
    }
    
    # Execute selected phase
    phase_map[args.phase](cfg)