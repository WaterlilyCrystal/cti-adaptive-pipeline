#!/usr/bin/env python
"""
Quick debug script to check database state and processor
"""
import sqlite3
import logging
from pathlib import Path

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("debug")

DB_PATH = "data/cti.db"

def check_database():
    """Check database state"""
    logger.info("=" * 80)
    logger.info("PHASE 2 DEBUG - Database State Check")
    logger.info("=" * 80)
    
    if not Path(DB_PATH).exists():
        logger.error(f"Database file not found: {DB_PATH}")
        return
    
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    cursor = conn.cursor()
    
    # Check intel_items table
    try:
        cursor.execute("SELECT COUNT(*) FROM intel_items")
        total_items = cursor.fetchone()[0]
        logger.info(f"\n[DB] Total items in database: {total_items}")
        
        cursor.execute("SELECT COUNT(*) FROM intel_items WHERE processed=0")
        pending_items = cursor.fetchone()[0]
        logger.info(f"[DB] Pending items (processed=0): {pending_items}")
        
        cursor.execute("SELECT COUNT(*) FROM intel_items WHERE processed=1")
        processed_items = cursor.fetchone()[0]
        logger.info(f"[DB] Already processed items: {processed_items}")
        
        if pending_items > 0:
            logger.info(f"\n[DB] Showing first 5 pending items:")
            cursor.execute("""
                SELECT id, source, title, lang, confidence 
                FROM intel_items 
                WHERE processed=0 
                ORDER BY confidence DESC 
                LIMIT 5
            """)
            for row in cursor.fetchall():
                logger.info(f"  - ID: {row[0][:16]}... | Source: {row[1]} | Title: {row[2][:50]}... | Lang: {row[3]} | Conf: {row[4]}")
        else:
            logger.warning("[DB] No pending items found!")
            logger.info("\n[DB] Showing last 3 processed items:")
            cursor.execute("""
                SELECT id, source, title, lang, relevance_score 
                FROM intel_items 
                WHERE processed=1 
                ORDER BY collected_at DESC 
                LIMIT 3
            """)
            for row in cursor.fetchall():
                logger.info(f"  - ID: {row[0][:16]}... | Source: {row[1]} | Title: {row[2][:50]}... | Lang: {row[3]} | Score: {row[4]}")
        
        # Check sources distribution
        logger.info(f"\n[DB] Items by source:")
        cursor.execute("""
            SELECT source, COUNT(*) as count, SUM(CASE WHEN processed=0 THEN 1 ELSE 0 END) as pending
            FROM intel_items
            GROUP BY source
            ORDER BY count DESC
        """)
        for row in cursor.fetchall():
            logger.info(f"  - {row[0]}: {row[1]} total ({row[2]} pending)")
            
    except Exception as e:
        logger.error(f"Error checking database: {e}")
        import traceback
        logger.error(traceback.format_exc())
    
    finally:
        conn.close()
    
    logger.info("=" * 80)

if __name__ == "__main__":
    check_database()
