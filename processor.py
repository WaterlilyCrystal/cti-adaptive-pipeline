"""
Data Pre-processing Module - Phase 2 (Memory-Optimized & Source-Aware)
Handles deduplication, text cleaning, normalization, and confidence scoring.

OPTIMIZATIONS FOR RAM EFFICIENCY:
- Streaming batch processing (avoid loading all items into RAM)
- Source-aware deduplication (semantic dedup only for unstructured sources)
- Memory-efficient sliding window dedup (only compare with recent N items)
- Lazy loading + explicit model release for embedding model
- 3-pass dedup strategy: URL → Hash → Semantic (fast to slow)

SOURCE CATEGORIZATION:
- Structured: CVE, CISA-KEV, NVD (URL unique, no semantic dedup needed)
- Unstructured: RSS, Reddit, Telegram, Mastodon (may repost same content)
"""
import logging
import re
import gc
import hashlib
from typing import List, Dict, Tuple
from datetime import datetime, timezone
import numpy as np

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("processor")

# Global embedding model cache (lazy-loaded)
_embedding_model = None

# Source categorization for smart deduplication
STRUCTURED_SOURCES = {
    "cve", "cisa", "nvd", "kev", "exploit-db", "cvedetails"
}

def _is_structured_source(source: str) -> bool:
    """Detect if source has structured data (unique URLs per item)."""
    source_lower = source.lower()
    return any(keyword in source_lower for keyword in STRUCTURED_SOURCES)


def _get_embedding_model():
    """Lazy-load embedding model on first use."""
    global _embedding_model
    if _embedding_model is None:
        logger.info("Loading sentence-transformers model for semantic similarity...")
        try:
            from sentence_transformers import SentenceTransformer
            _embedding_model = SentenceTransformer('all-MiniLM-L6-v2')
        except ImportError:
            logger.error("sentence-transformers not installed. Disabling semantic dedup.")
            _embedding_model = False  # False = disabled, None = not loaded yet
    return _embedding_model if _embedding_model is not False else None


def _release_embedding_model():
    """Explicitly free embedding model from memory."""
    global _embedding_model
    if _embedding_model not in (None, False):
        del _embedding_model
        _embedding_model = None
        gc.collect()
        logger.debug("Embedding model released from memory")


def normalize_text(text: str) -> str:
    """
    Normalize text: remove extra whitespace, standardize quotes, remove control characters.
    """
    if not text:
        return ""
    
    # Remove extra whitespace
    text = re.sub(r'\s+', ' ', text).strip()
    
    # Normalize quotes
    text = text.replace('"', '"').replace('"', '"')
    text = text.replace(''', "'").replace(''', "'")
    
    # Remove control characters
    text = ''.join(char for char in text if ord(char) >= 32 or char in '\n\t\r')
    
    return text


def calculate_content_similarity(text1: str, text2: str) -> float:
    """
    Calculate semantic similarity between two text snippets using embeddings.
    Returns a float between 0 and 1 (1.0 = identical).
    
    Includes fast pre-check to avoid expensive embedding for very different texts.
    """
    if not text1 or not text2:
        return 0.0
    
    # Fast pre-check: if texts are too different in length, skip expensive embedding
    len1, len2 = len(text1), len(text2)
    if max(len1, len2) > min(len1, len2) * 2:  # >200% length difference = probably different
        return 0.0
    
    try:
        model = _get_embedding_model()
        if model is None:
            return 0.0
        
        # Create embeddings
        embeddings = model.encode([text1, text2], convert_to_numpy=True)
        
        # Calculate cosine similarity
        from sklearn.metrics.pairwise import cosine_similarity
        similarity = cosine_similarity([embeddings[0]], [embeddings[1]])[0][0]
        
        return float(similarity)
    except Exception as e:
        logger.debug(f"Error calculating similarity: {e}")
        return 0.0


def _fast_hash_duplicate_check(text: str) -> str:
    """Generate SHA256 hash for quick duplicate detection (before expensive embedding)."""
    return hashlib.sha256(text[:500].encode()).hexdigest()


def deduplicate_items(
    items: List[Dict], 
    similarity_threshold: float = 0.85,
    enable_semantic: bool = True,
    window_size: int = 100
) -> Tuple[List[Dict], int]:
    """
    Remove duplicate or near-duplicate items using smart 3-pass strategy.
    
    Args:
        items: list of intel items
        similarity_threshold: cosine similarity threshold (0-1) for marking as duplicate
        enable_semantic: whether to use expensive semantic dedup (default True)
        window_size: only compare with last N items (memory efficient, default 100)
    
    Returns:
        Tuple of (deduplicated_items, num_duplicates_removed)
        
    STRATEGY:
        1. Pass 1: URL-level exact matching (O(n), instant)
        2. Pass 2: Hash-based content dedup (O(n), fast)
        3. Pass 3: Semantic similarity with sliding window (O(n*w), optional)
    """
    if not items:
        return [], 0
    
    total_duplicates = 0
    logger.debug(f"[DEDUP] Starting 3-pass deduplication on {len(items)} items")
    
    # === PASS 1: Exact URL deduplication (fastest, O(n)) ===
    logger.debug(f"[DEDUP] Pass 1: URL-level deduplication...")
    seen_urls = set()
    unique_by_url = []
    url_duplicates = 0
    
    for item in items:
        url = item.get("url", "")
        if url and url not in seen_urls:
            seen_urls.add(url)
            unique_by_url.append(item)
        else:
            url_duplicates += 1
    
    logger.info(f"[DEDUP] Pass 1 ✓: URL-level dedup removed {url_duplicates} dups ({len(unique_by_url)} remain)")
    total_duplicates += url_duplicates
    
    # === PASS 2: Hash-based content dedup (O(n), faster than semantic) ===
    logger.debug(f"[DEDUP] Pass 2: Hash-based content deduplication...")
    seen_hashes = {}
    unique_by_hash = []
    hash_duplicates = 0
    
    for i, item in enumerate(unique_by_url):
        title = item.get("title", "")
        content = item.get("content", "")[:500]
        content_hash = _fast_hash_duplicate_check(f"{title}:{content}")
        
        if content_hash not in seen_hashes:
            seen_hashes[content_hash] = item
            unique_by_hash.append(item)
        else:
            hash_duplicates += 1
        
        if (i + 1) % 200 == 0:
            logger.debug(f"[DEDUP] Pass 2 progress: {i+1}/{len(unique_by_url)}")
    
    logger.info(f"[DEDUP] Pass 2 ✓: Hash-based dedup removed {hash_duplicates} dups ({len(unique_by_hash)} remain)")
    total_duplicates += hash_duplicates
    
    # === PASS 3: Semantic dedup with sliding window (optional, memory-efficient) ===
    semantic_duplicates = 0
    
    if enable_semantic and len(unique_by_hash) > 1:
        logger.info(f"[DEDUP] Pass 3: Semantic dedup with window={window_size}, threshold={similarity_threshold}...")
        final_items = []
        
        for i, item_a in enumerate(unique_by_hash):
            is_duplicate = False
            title_a = item_a.get("title", "")
            content_a = item_a.get("content", "")[:500]
            text_a = f"{title_a} {content_a}"
            
            # Only compare with last window_size items (sliding window = memory efficient)
            start_idx = max(0, len(final_items) - window_size)
            compare_with = final_items[start_idx:]
            
            for item_b in compare_with:
                title_b = item_b.get("title", "")
                content_b = item_b.get("content", "")[:500]
                text_b = f"{title_b} {content_b}"
                
                similarity = calculate_content_similarity(text_a, text_b)
                if similarity >= similarity_threshold:
                    logger.debug(f"[DEDUP] Semantic dup (sim={similarity:.3f}): {title_a[:50]}")
                    is_duplicate = True
                    semantic_duplicates += 1
                    break
            
            if not is_duplicate:
                final_items.append(item_a)
            
            # Periodic memory cleanup and logging every 100 items
            if (i + 1) % 100 == 0:
                logger.debug(f"[DEDUP] Pass 3 progress: {i+1}/{len(unique_by_hash)} items processed, {semantic_duplicates} dups found so far")
                if (i + 1) % 500 == 0:
                    gc.collect()
                    logger.debug(f"[DEDUP] Memory cleanup after {i+1} items")
        
        logger.info(f"[DEDUP] Pass 3 ✓: Semantic dedup removed {semantic_duplicates} dups ({len(final_items)} remain)")
        total_duplicates += semantic_duplicates
        return final_items, total_duplicates
    else:
        if not enable_semantic:
            logger.info(f"[DEDUP] Pass 3 ⊘: Semantic dedup disabled (fast path only)")
        return unique_by_hash, total_duplicates


def calculate_relevance_score(item: Dict, org_profile: Dict) -> float:
    """
    Calculate relevance score (0-1) based on:
    - Source credibility (40%)
    - Content quality/length (30%)
    - Language match with org profile (30%)
    """
    score = 0.0
    
    # Source credibility (0.4 weight)
    source = item.get("source", "").lower()
    source_weight = 0.0
    if any(x in source for x in ["cisa", "nist", "microsoft", "google"]):
        source_weight = 1.0  # Official sources
    elif any(x in source for x in ["bleeping", "krebs", "darkreading", "xakep", "securelist"]):
        source_weight = 0.9  # Established security media
    elif "reddit" in source or "telegram" in source:
        source_weight = 0.7  # Social sources (lower trust)
    else:
        source_weight = 0.8  # Default news RSS
    
    score += source_weight * 0.4
    
    # Content quality (0.3 weight)
    content = item.get("content", "")
    title = item.get("title", "")
    total_chars = len(content) + len(title)
    
    if total_chars > 2000:
        quality_score = 1.0  # Rich content
    elif total_chars > 500:
        quality_score = 0.8
    elif total_chars > 100:
        quality_score = 0.6
    else:
        quality_score = 0.3  # Very sparse content
    
    score += quality_score * 0.3
    
    # Language relevance (0.3 weight)
    item_lang = item.get("lang", "en")
    org_langs = org_profile.get("preferred_languages", ["en"])
    
    if item_lang in org_langs or item_lang == "en":
        lang_score = 1.0
    elif item_lang == "und":  # Unknown language
        lang_score = 0.5
    else:
        lang_score = 0.7  # Other languages still useful
    
    score += lang_score * 0.3
    
    return min(1.0, max(0.0, score))  # Clamp to [0, 1]


def process_collected_items(items: List[Dict], cfg: Dict) -> List[Dict]:
    """
    Process collected items through normalization, deduplication, and scoring.
    Memory-optimized version that respects configuration flags.
    
    Args:
        items: raw collected items
        cfg: pipeline configuration with dedup settings
    
    Returns:
        Processed items ready for analysis phase
    """
    if not items:
        logger.warning("No items to process")
        return []
    
    logger.info(f"[PROCESS] Starting normalization of {len(items)} items...")
    
    # Step 1: Normalize text in all items
    for i, item in enumerate(items):
        item["title"] = normalize_text(item.get("title", ""))
        item["content"] = normalize_text(item.get("content", ""))
        
        if (i + 1) % 100 == 0:
            logger.debug(f"[PROCESS] Normalized {i+1}/{len(items)} items")
    
    logger.info(f"[PROCESS] ✓ Text normalization completed")
    
    # Step 2: Deduplication with configurable semantic option
    logger.info(f"[PROCESS] Starting deduplication...")
    dedup_threshold = cfg.get("pipeline", {}).get("dedup_threshold", 0.90)
    enable_semantic = cfg.get("pipeline", {}).get("enable_semantic_dedup", True)
    window_size = cfg.get("pipeline", {}).get("dedup_window_size", 100)
    
    logger.debug(f"[PROCESS] Dedup config: threshold={dedup_threshold}, semantic={enable_semantic}, window={window_size}")
    
    items, num_dups = deduplicate_items(
        items, 
        similarity_threshold=dedup_threshold,
        enable_semantic=enable_semantic,
        window_size=window_size
    )
    logger.info(f"[PROCESS] ✓ Deduplication complete: removed {num_dups} dups, {len(items)} unique remain")
    
    # Step 3: Calculate relevance scores
    logger.info(f"[PROCESS] Calculating relevance scores for {len(items)} items...")
    org_profile = cfg.get("org_profile", {})
    org_profile.setdefault("preferred_languages", ["en"])
    
    for i, item in enumerate(items):
        item["relevance_score"] = calculate_relevance_score(item, org_profile)
        
        if (i + 1) % 100 == 0:
            logger.debug(f"[PROCESS] Scored {i+1}/{len(items)} items")
    
    logger.info(f"[PROCESS] ✓ Relevance scoring completed")
    
    # Step 4: Filter by minimum confidence threshold
    min_confidence = cfg.get("pipeline", {}).get("min_confidence", 0.5)
    filtered_items = [item for item in items if item.get("relevance_score", 0.0) >= min_confidence]
    
    if len(filtered_items) < len(items):
        removed = len(items) - len(filtered_items)
        logger.info(f"[PROCESS] ⚠ Filtered out {removed} items below threshold ({min_confidence})")
    
    logger.info(f"[PROCESS] ✓ After filtering: {len(filtered_items)} items remain")
    
    # Step 5: Sort by relevance (highest first)
    logger.info(f"[PROCESS] Sorting {len(filtered_items)} items by relevance...")
    filtered_items.sort(key=lambda x: x.get("relevance_score", 0.0), reverse=True)
    
    # Add processing timestamp
    now = datetime.now(timezone.utc).isoformat()
    for item in filtered_items:
        item["processed_at"] = now
    
    # Free embedding model to reduce memory footprint
    logger.debug(f"[PROCESS] Releasing embedding model from memory...")
    _release_embedding_model()
    gc.collect()
    
    logger.info(f"[PROCESS] ✓ Processing complete: {len(filtered_items)} items ready for analysis")
    
    return filtered_items


def run_processing(db_conn, cfg: Dict, batch_size: int = 500) -> int:
    """
    Main processing pipeline (Phase 2) - Memory-optimized batch processing with detailed logging.
    
    Fetches pending items in batches from database, processes them, and updates DB.
    Streaming approach avoids loading all items into RAM at once.
    
    Args:
        db_conn: SQLite database connection
        cfg: Pipeline configuration
        batch_size: number of items to process in each batch (default 500)
    
    Returns:
        Number of items processed
    """
    from utils.db_handler import update_analysis
    
    total_processed = 0
    batch_num = 0
    items_filtered_total = 0
    
    logger.info("=" * 80)
    logger.info("PHASE 2: PROCESSING STARTED - Memory-optimized batch processing")
    logger.info(f"Batch size: {batch_size} items | Semantic dedup: {cfg.get('pipeline', {}).get('enable_semantic_dedup', True)}")
    logger.info("=" * 80)
    
    # Process items in batches to avoid RAM overflow
    while True:
        batch_num += 1
        logger.info(f"\n[BATCH {batch_num}] Fetching from database...")
        
        # Fetch batch of pending items
        pending_items = []
        try:
            # Direct SQL query with column mapping - careful with the schema
            cursor = db_conn.execute(
                'SELECT id, source, source_type, title, url, content, lang, confidence, collected_at FROM intel_items WHERE processed=0 LIMIT ?',
                (batch_size,)
            )
            rows = cursor.fetchall()
            
            if not rows:
                logger.info(f"\n[BATCH {batch_num}] ✓ No more pending items in database")
                break
            
            logger.info(f"[BATCH {batch_num}] ✓ Fetched {len(rows)} items from database")
            
            # Convert rows to dict format
            for i, row in enumerate(rows):
                try:
                    item = {
                        "id": row[0],
                        "source": row[1],
                        "source_type": row[2],
                        "title": row[3],
                        "url": row[4],
                        "content": row[5],
                        "lang": row[6] or "en",
                        "confidence": float(row[7] or 0.0),
                        "collected_at": row[8],
                    }
                    pending_items.append(item)
                except Exception as e:
                    logger.warning(f"[BATCH {batch_num}] Skipping malformed row {i}: {e}")
                    continue
                    
        except Exception as e:
            logger.error(f"[BATCH {batch_num}] SQL query error: {e}")
            logger.error(f"[BATCH {batch_num}] Attempting fallback to get_pending...")
            
            # Fallback: use get_pending but limit it manually
            try:
                from utils.db_handler import get_pending
                all_pending = get_pending(db_conn)
                logger.info(f"[BATCH {batch_num}] Got {len(all_pending)} total pending items from fallback")
                pending_items = all_pending[:batch_size]
                
                if not pending_items:
                    logger.info(f"[BATCH {batch_num}] No items found (fallback)")
                    break
                    
                logger.info(f"[BATCH {batch_num}] Using {len(pending_items)} items from fallback")
            except Exception as e2:
                logger.error(f"[BATCH {batch_num}] Fallback also failed: {e2}")
                import traceback
                logger.error(traceback.format_exc())
                break
        
        if not pending_items:
            logger.info(f"[BATCH {batch_num}] No items to process - breaking")
            break
        
        logger.info(f"[BATCH {batch_num}] ▶ Processing {len(pending_items)} items...")
        
        # Process batch
        processed_items = []
        try:
            processed_items = process_collected_items(pending_items, cfg)
            logger.info(f"[BATCH {batch_num}] ▶ Processing complete: {len(processed_items)} items passed filters")
        except Exception as e:
            logger.error(f"[BATCH {batch_num}] ✗ Processing error: {e}")
            import traceback
            logger.error(traceback.format_exc())
            continue
        
        # Count filtered items
        items_filtered = len(pending_items) - len(processed_items)
        if items_filtered > 0:
            logger.info(f"[BATCH {batch_num}] ⚠ {items_filtered} items filtered out (below confidence threshold)")
            items_filtered_total += items_filtered
        
        if not processed_items:
            logger.warning(f"[BATCH {batch_num}] All items in batch were filtered out")
            continue
        
        # Update database with processed results
        logger.info(f"[BATCH {batch_num}] ⏳ Updating database with results...")
        updated_count = 0
        update_errors = 0
        
        for i, item in enumerate(processed_items):
            try:
                success = update_analysis(
                    db_conn,
                    item["id"],
                    raw_iocs={},  # Will be filled in phase 3 (analysis)
                    ttp_mapping=[],  # Will be filled in phase 3 (analysis)
                    relevance=item.get("relevance_score", 0.0)
                )
                if success:
                    updated_count += 1
                else:
                    update_errors += 1
                    
                # Log progress every 50 items
                if (i + 1) % 50 == 0:
                    logger.debug(f"[BATCH {batch_num}] Updated {i+1}/{len(processed_items)} items")
                    
            except Exception as e:
                logger.debug(f"[BATCH {batch_num}] Error updating item {item['id']}: {e}")
                update_errors += 1
        
        logger.info(f"[BATCH {batch_num}] ✓ Database update: {updated_count} items marked as processed, {update_errors} errors")
        total_processed += updated_count
        
        # Cleanup after each batch
        gc.collect()
        logger.debug(f"[BATCH {batch_num}] Memory cleanup done")
        logger.info(f"[BATCH {batch_num}] ✓ Batch complete. Running total: {total_processed} processed items\n")
    
    logger.info("=" * 80)
    logger.info(f"PHASE 2: PROCESSING COMPLETE")
    logger.info(f"Total items processed: {total_processed}")
    logger.info(f"Total items filtered out: {items_filtered_total}")
    logger.info(f"Batches processed: {batch_num}")
    logger.info("=" * 80)
    
    return total_processed
