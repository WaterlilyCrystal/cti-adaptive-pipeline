"""
Data Pre-processing Module - Phase 2
Handles deduplication, text cleaning, normalization, and confidence scoring.
"""
import logging
import re
from typing import List, Dict, Tuple
from datetime import datetime, timezone
from sentence_transformers import SentenceTransformer
import numpy as np

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("processor")

# Load embedding model for semantic similarity (lazy load on first use)
_embedding_model = None

def _get_embedding_model():
    """Lazy-load embedding model on first use."""
    global _embedding_model
    if _embedding_model is None:
        logger.info("Loading sentence-transformers model for semantic similarity...")
        _embedding_model = SentenceTransformer('all-MiniLM-L6-v2')
    return _embedding_model

def normalize_text(text: str) -> str:
    """
    Normalize text: remove extra whitespace, standardize quotes, etc.
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
    """
    if not text1 or not text2:
        return 0.0
    
    try:
        model = _get_embedding_model()
        
        # Create embeddings
        embeddings = model.encode([text1, text2])
        
        # Calculate cosine similarity
        from sklearn.metrics.pairwise import cosine_similarity
        similarity = cosine_similarity([embeddings[0]], [embeddings[1]])[0][0]
        
        return float(similarity)
    except Exception as e:
        logger.error(f"Error calculating similarity: {e}")
        return 0.0

def deduplicate_items(items: List[Dict], similarity_threshold: float = 0.85) -> Tuple[List[Dict], int]:
    """
    Remove duplicate or near-duplicate items based on URL and semantic similarity.
    
    Args:
        items: list of intel items
        similarity_threshold: cosine similarity threshold (0-1) for marking as duplicate
    
    Returns:
        Tuple of (deduplicated_items, num_duplicates_removed)
    """
    if not items:
        return [], 0
    
    # First pass: exact URL deduplication (fastest)
    seen_urls = set()
    unique_items = []
    url_duplicates = 0
    
    for item in items:
        url = item.get("url", "")
        if url not in seen_urls:
            seen_urls.add(url)
            unique_items.append(item)
        else:
            url_duplicates += 1
    
    logger.info(f"URL-level deduplication removed {url_duplicates} duplicates")
    
    # Second pass: semantic deduplication (slower, use only if enabled in config)
    semantic_duplicates = 0
    final_items = []
    
    for i, item_a in enumerate(unique_items):
        is_duplicate = False
        title_a = item_a.get("title", "")
        content_a = item_a.get("content", "")[:500]  # Use first 500 chars
        text_a = f"{title_a} {content_a}"
        
        # Compare with already-processed items
        for item_b in final_items:
            title_b = item_b.get("title", "")
            content_b = item_b.get("content", "")[:500]
            text_b = f"{title_b} {content_b}"
            
            similarity = calculate_content_similarity(text_a, text_b)
            if similarity >= similarity_threshold:
                logger.debug(f"Semantic duplicate detected (sim={similarity:.3f}): {title_a[:50]}")
                is_duplicate = True
                semantic_duplicates += 1
                break
        
        if not is_duplicate:
            final_items.append(item_a)
    
    logger.info(f"Semantic deduplication removed {semantic_duplicates} duplicates")
    total_duplicates = url_duplicates + semantic_duplicates
    
    return final_items, total_duplicates

def calculate_relevance_score(item: Dict, org_profile: Dict) -> float:
    """
    Calculate relevance score (0-1) based on:
    - Source credibility
    - Content length and quality
    - Language match with org profile
    """
    score = 0.0
    
    # Source credibility (0.4 weight)
    source = item.get("source", "").lower()
    source_weight = 0.0
    if any(x in source for x in ["cisa", "nist", "microsoft", "google"]):
        source_weight = 1.0  # Official sources
    elif any(x in source for x in ["bleeping", "krebs", "darkreading"]):
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
    
    Args:
        items: raw collected items
        cfg: pipeline configuration
    
    Returns:
        Processed items ready for analysis phase
    """
    if not items:
        logger.warning("No items to process")
        return []
    
    logger.info(f"Starting processing of {len(items)} items")
    
    # Step 1: Normalize text in all items
    for item in items:
        item["title"] = normalize_text(item.get("title", ""))
        item["content"] = normalize_text(item.get("content", ""))
    
    logger.info("Text normalization completed")
    
    # Step 2: Deduplication
    dedup_threshold = cfg.get("pipeline", {}).get("dedup_threshold", 0.90)
    items, num_dups = deduplicate_items(items, similarity_threshold=dedup_threshold)
    logger.info(f"Deduplication complete: removed {num_dups} duplicates, {len(items)} unique items remain")
    
    # Step 3: Calculate relevance scores
    org_profile = cfg.get("org_profile", {})
    org_profile.setdefault("preferred_languages", ["en"])
    
    for item in items:
        item["relevance_score"] = calculate_relevance_score(item, org_profile)
    
    logger.info("Relevance scoring completed")
    
    # Step 4: Filter by minimum confidence threshold
    min_confidence = cfg.get("pipeline", {}).get("min_confidence", 0.5)
    filtered_items = [item for item in items if item.get("relevance_score", 0.0) >= min_confidence]
    
    if len(filtered_items) < len(items):
        removed = len(items) - len(filtered_items)
        logger.info(f"Filtered out {removed} items below confidence threshold ({min_confidence})")
    
    # Step 5: Sort by relevance (highest first)
    filtered_items.sort(key=lambda x: x.get("relevance_score", 0.0), reverse=True)
    
    # Add processing timestamp
    now = datetime.now(timezone.utc).isoformat()
    for item in filtered_items:
        item["processed_at"] = now
    
    logger.info(f"Processing complete: {len(filtered_items)} items ready for analysis")
    
    return filtered_items

def run_processing(db_conn, cfg: Dict) -> int:
    """
    Main processing pipeline function (Phase 2).
    Fetches pending items from database, processes them, and updates database.
    
    Args:
        db_conn: SQLite database connection
        cfg: Pipeline configuration
    
    Returns:
        Number of items processed
    """
    from utils.db_handler import get_pending, update_analysis
    
    # Fetch all unprocessed items
    pending_items = get_pending(db_conn)
    logger.info(f"Found {len(pending_items)} pending items in database")
    
    if not pending_items:
        logger.warning("No pending items to process")
        return 0
    
    # Process items
    processed_items = process_collected_items(pending_items, cfg)
    
    if not processed_items:
        logger.warning("All items were filtered out during processing")
        return 0
    
    # Update database with processed results
    updated_count = 0
    for item in processed_items:
        success = update_analysis(
            db_conn,
            item["id"],
            raw_iocs={},  # Will be filled in phase 3 (analysis)
            ttp_mapping=[],  # Will be filled in phase 3 (analysis)
            relevance=item.get("relevance_score", 0.0)
        )
        if success:
            updated_count += 1
    
    logger.info(f"Processing phase complete: {updated_count}/{len(processed_items)} items updated in database")
    return updated_count
"""
Data Pre-processing Module - Phase 2 (Unified Engine)
Handles text cleaning, language detection, translation, semantic deduplication,
resource monitoring, and confidence/relevance scoring.
"""

import logging
import re
import os
import time
from typing import List, Dict, Tuple
from datetime import datetime, timezone
import numpy as np
from sentence_transformers import SentenceTransformer

# Try to load optional dependencies safely
try:
    from langdetect import detect
except ImportError:
    logging.warning("langdetect not installed. Defaulting to English detection.")
    def detect(text): return "en"

try:
    import psutil
except ImportError:
    psutil = None

# Configure logger
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("processor")

# Lazy-loaded semantic model
_embedding_model = None

def _get_embedding_model():
    """Lazy-load embedding model on first use to save memory during startup."""
    global _embedding_model
    if _embedding_model is None:
        logger.info("Loading sentence-transformers model (all-MiniLM-L6-v2)...")
        _embedding_model = SentenceTransformer('all-MiniLM-L6-v2')
    return _embedding_model

def _check_system_resources():
    """Throttles processing if system memory usage is dangerously high (> 85%)."""
    if psutil is not None:
        ram = psutil.virtual_memory()
        while ram.percent > 85.0:
            logger.warning(f"System RAM resource exhaustion detected ({ram.percent}%). Pausing for 30s...")
            time.sleep(30)
            ram = psutil.virtual_memory()

def _call_translation_llm(text: str) -> str:
    """Dispatches translation requests to the local Ollama daemon service layer."""
    import requests
    _check_system_resources()
    
    url = "http://localhost:11434/api/generate"
    payload = {
        "model": "qwen2.5:7b-instruct-q4_K_M",
        "prompt": f"Translate the following cyber security intelligence text to English. Output ONLY the translated text, do not add introductory phrases or commentary.\n\nText:\n{text}",
        "stream": False,
        "options": {"num_ctx": 4096, "temperature": 0.1}
    }
    try:
        response = requests.post(url, json=payload, timeout=60)
        if response.status_code == 200:
            return response.json().get("response", "").strip()
    except Exception as e:
        logger.error(f"Failed to connect to local Ollama translation daemon: {e}")
    return ""

def normalize_text(text: str) -> str:
    """Normalize text: remove extra whitespace, standardize quotes, and remove control characters."""
    if not text:
        return ""
    
    # Remove extra whitespace
    text = re.sub(r'\s+', ' ', text).strip()
    
    # Normalize quotes
    text = text.replace('"', '"').replace('"', '"')
    text = text.replace('\'', "'").replace('\'', "'")
    
    # Remove control characters
    text = ''.join(char for char in text if ord(char) >= 32 or char in '\n\t\r')
    
    return text

def translate_if_needed(item: Dict) -> Dict:
    """Detects foreign intelligence feeds and translates content to English."""
    content = item.get("content", "")
    if not content:
        return item

    try:
        detected_lang = detect(content[:500])
        item["lang"] = detected_lang
        
        # Monitor targets from foreign language hubs
        if detected_lang in ["ru", "zh-cn", "zh-tw", "uk", "fr", "es", "de", "ja", "ko"]:
            logger.info(f"Translating item [{item.get('id')[:8]}] from native language [{detected_lang}]...")
            translated = _call_translation_llm(content[:3000])
            if translated:
                item["content"] = translated
                item["title"] = _call_translation_llm(item.get("title", "")) or item.get("title")
    except Exception as e:
        logger.debug(f"Language processing layer bypassed: {e}")
    return item

def deduplicate_items(items: List[Dict], similarity_threshold: float = 0.85) -> Tuple[List[Dict], int]:
    """
    Remove duplicate or near-duplicate items using exact URL hashing and 
    high-performance vectorized semantic similarity matching.
    """
    if not items:
        return [], 0
    
    # Pass 1: Fast URL-level deduplication
    seen_urls = set()
    unique_items = []
    url_duplicates = 0
    
    for item in items:
        url = item.get("url", "")
        if not url or url not in seen_urls:
            if url:
                seen_urls.add(url)
            unique_items.append(item)
        else:
            url_duplicates += 1
    
    logger.info(f"URL-level deduplication removed {url_duplicates} duplicates.")
    
    # Pass 2: Vector-accelerated Semantic Deduplication
    semantic_duplicates = 0
    final_items = []
    cached_embeddings = []  # Stores vector states to avoid redundant encoding loops
    
    model = _get_embedding_model()
    
    for item_a in unique_items:
        title_a = item_a.get("title", "")
        content_a = item_a.get("content", "")[:500]
        text_a = f"{title_a} {content_a}"
        
        try:
            # Vectorize the current item once
            emb_a = model.encode([text_a], show_progress_bar=False)[0]
        except Exception as e:
            logger.error(f"Embedding encoding execution error: {e}")
            final_items.append(item_a)
            continue
            
        is_duplicate = False
        
        # Compare current vector with all verified cached item vectors
        if cached_embeddings:
            # Fast vectorized dot product computation
            norm_a = np.linalg.norm(emb_a)
            if norm_a > 0:
                for stored_emb in cached_embeddings:
                    norm_stored = np.linalg.norm(stored_emb)
                    if norm_stored == 0:
                        continue
                    similarity = np.dot(emb_a, stored_emb) / (norm_a * norm_stored)
                    
                    if similarity >= similarity_threshold:
                        logger.debug(f"Semantic duplicate detected (sim={similarity:.3f}): {title_a[:50]}")
                        is_duplicate = True
                        semantic_duplicates += 1
                        break
        
        if not is_duplicate:
            final_items.append(item_a)
            cached_embeddings.append(emb_a)
            
    logger.info(f"Semantic deduplication removed {semantic_duplicates} duplicates.")
    total_duplicates = url_duplicates + semantic_duplicates
    
    return final_items, total_duplicates

def calculate_relevance_score(item: Dict, org_profile: Dict) -> float:
    """Calculate contextual threat credibility score (0.0 to 1.0) inside the CTI pipeline."""
    score = 0.0
    
    # 1. Source Credibility Tier Matrix (0.4 weight)
    source = item.get("source", "").lower()
    source_weight = 0.8  # Default baseline score
    if any(x in source for x in ["cisa", "nist", "microsoft", "google"]):
        source_weight = 1.0
    elif any(x in source for x in ["bleeping", "krebs", "darkreading", "xakep", "securelist"]):
        source_weight = 0.9
    elif "reddit" in source or "telegram" in source:
        source_weight = 0.6
        
    score += source_weight * 0.4
    
    # 2. Content Payload Density Evaluation (0.3 weight)
    content_len = len(item.get("content", "")) + len(item.get("title", ""))
    if content_len > 2000:
        quality_score = 1.0
    elif content_len > 500:
        quality_score = 0.8
    elif content_len > 100:
        quality_score = 0.6
    else:
        quality_score = 0.3
        
    score += quality_score * 0.3
    
    # 3. Geo-Targeting & Language Alignment Matrix (0.3 weight)
    item_lang = item.get("lang", "en")
    org_langs = org_profile.get("preferred_languages", ["en"])
    
    if item_lang in org_langs or item_lang == "en":
        lang_score = 1.0
    elif item_lang == "und":
        lang_score = 0.5
    else:
        lang_score = 0.7
        
    score += lang_score * 0.3
    
    # Actionable Context Identification Bonus (Cap output values at 1.0)
    if "CVE-" in item.get("content", "").upper():
        score += 0.05

    return min(1.0, max(0.0, round(score, 2)))

def process_collected_items(items: List[Dict], cfg: Dict) -> List[Dict]:
    """Transformation pipeline layer running text stabilization, translation, dedup, and scoring."""
    if not items:
        logger.warning("No structural dictionary data found inside execution pool queue.")
        return []
        
    logger.info(f"Starting processing sequence of {len(items)} raw target intelligence segments.")
    
    # Step 1: Structural Clean & Normalize Text Elements
    for item in items:
        item["title"] = normalize_text(item.get("title", ""))
        item["content"] = normalize_text(item.get("content", ""))
        
    # Step 2: Language Extraction & Cross-Border LLM Translation Mapping
    translated_items = []
    for item in items:
        translated_items.append(translate_if_needed(item))
    
    # Step 3: Semantic Duplication Elimination
    dedup_threshold = cfg.get("pipeline", {}).get("dedup_threshold", 0.90)
    filtered_items, num_dups = deduplicate_items(translated_items, similarity_threshold=dedup_threshold)
    logger.info(f"Deduplication complete: {len(filtered_items)} items forward to scoring.")
    
    # Step 4: Analytical Matrix Evaluation (Relevance Scoring)
    org_profile = cfg.get("org_profile", {"preferred_languages": ["en"]})
    for item in filtered_items:
        item["relevance_score"] = calculate_relevance_score(item, org_profile)
        
    # Step 5: High-Pass Confidence Filter Validation
    min_confidence = cfg.get("pipeline", {}).get("min_confidence", 0.5)
    valid_items = [item for item in filtered_items if item.get("relevance_score", 0.0) >= min_confidence]
    
    removed_items_count = len(filtered_items) - len(valid_items)
    if removed_items_count > 0:
        logger.info(f"Dropped {removed_items_count} items scoring below production gate threshold ({min_confidence}).")
        
    # Step 6: Critical Triage Sorting
    valid_items.sort(key=lambda x: x.get("relevance_score", 0.0), reverse=True)
    
    processing_timestamp = datetime.now(timezone.utc).isoformat()
    for item in valid_items:
        item["processed_at"] = processing_timestamp
        
    return valid_items

def run_processing(db_conn, cfg: Dict) -> int:
    """Database interface runner executing continuous polling operations for Phase 2."""
    from utils.db_handler import get_pending, update_analysis
    
    pending_items = get_pending(db_conn)
    logger.info(f"Polled {len(pending_items)} unprocessed elements from the staging tables.")
    
    if not pending_items:
        return 0
        
    # Standardize DB row data factories to simple dictionaries for processing mutations
    items_to_process = [dict(row) if not isinstance(row, dict) else row for row in pending_items]
    processed_items = process_collected_items(items_to_process, cfg)
    
    if not processed_items:
        logger.warning("All fetched data entities dropped during pipeline normalization passes.")
        return 0
        
    updated_count = 0
    for item in processed_items:
        success = update_analysis(
            db_conn,
            item["id"],
            raw_iocs={},         # To be dynamically augmented by Student B inside Phase 3
            ttp_mapping=[],      # To be dynamically augmented by Student B inside Phase 3
            relevance=item.get("relevance_score", 0.0)
        )
        if success:
            updated_count += 1
            
    logger.info(f"Database sync phase completed: {updated_count}/{len(processed_items)} intelligence entries committed.")
    return updated_count