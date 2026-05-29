"""
Data pre-processing module for Phase 2.
Handles normalization, de-duplication, and credibility scoring.
"""
from __future__ import annotations

import gc
import hashlib
import logging
import re
from datetime import datetime, timezone
from typing import Dict, List, Tuple

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("processor")

_embedding_model = None

STRUCTURED_SOURCES = {"cve", "cisa", "nvd", "kev", "exploit-db", "cvedetails"}


def _is_structured_source(source: str) -> bool:
    source_lower = (source or "").lower()
    return any(keyword in source_lower for keyword in STRUCTURED_SOURCES)


def _get_embedding_model():
    global _embedding_model
    if _embedding_model is None:
        logger.info("Loading sentence-transformers model for semantic similarity...")
        try:
            from sentence_transformers import SentenceTransformer

            _embedding_model = SentenceTransformer("all-MiniLM-L6-v2")
        except ImportError:
            logger.error("sentence-transformers not installed. Disabling semantic dedup.")
            _embedding_model = False
    return _embedding_model if _embedding_model is not False else None


def _release_embedding_model():
    global _embedding_model
    if _embedding_model not in (None, False):
        del _embedding_model
        _embedding_model = None
        gc.collect()


def normalize_text(text: str) -> str:
    if not text:
        return ""
    text = re.sub(r"\s+", " ", text).strip()
    text = "".join(char for char in text if ord(char) >= 32 or char in "\n\t\r")
    return text


def calculate_content_similarity(text1: str, text2: str) -> float:
    if not text1 or not text2:
        return 0.0
    if max(len(text1), len(text2)) > min(len(text1), len(text2)) * 2:
        return 0.0
    model = _get_embedding_model()
    if model is None:
        return 0.0
    try:
        embeddings = model.encode([text1, text2], convert_to_numpy=True)
        from sklearn.metrics.pairwise import cosine_similarity

        return float(cosine_similarity([embeddings[0]], [embeddings[1]])[0][0])
    except Exception as exc:
        logger.debug("Error calculating similarity: %s", exc)
        return 0.0


def _fast_hash_duplicate_check(text: str) -> str:
    return hashlib.sha256(text[:500].encode()).hexdigest()


def deduplicate_items(
    items: List[Dict],
    similarity_threshold: float = 0.85,
    enable_semantic: bool = True,
    window_size: int = 100,
) -> Tuple[List[Dict], int]:
    if not items:
        return [], 0

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

    seen_hashes = {}
    unique_by_hash = []
    hash_duplicates = 0
    for item in unique_by_url:
        content_hash = _fast_hash_duplicate_check(f"{item.get('title', '')}:{item.get('content', '')[:500]}")
        if content_hash not in seen_hashes:
            seen_hashes[content_hash] = item
            unique_by_hash.append(item)
        else:
            hash_duplicates += 1

    total_duplicates = url_duplicates + hash_duplicates
    if not enable_semantic or len(unique_by_hash) <= 1:
        return unique_by_hash, total_duplicates

    final_items = []
    semantic_duplicates = 0
    for item_a in unique_by_hash:
        if _is_structured_source(item_a.get("source", "")):
            final_items.append(item_a)
            continue

        text_a = f"{item_a.get('title', '')} {item_a.get('content', '')[:500]}"
        start_idx = max(0, len(final_items) - window_size)
        compare_with = final_items[start_idx:]
        duplicate = False
        for item_b in compare_with:
            text_b = f"{item_b.get('title', '')} {item_b.get('content', '')[:500]}"
            if calculate_content_similarity(text_a, text_b) >= similarity_threshold:
                duplicate = True
                semantic_duplicates += 1
                break
        if not duplicate:
            final_items.append(item_a)

    total_duplicates += semantic_duplicates
    return final_items, total_duplicates


def calculate_credibility_score(item: Dict, org_profile: Dict, corpus: List[Dict]) -> float:
    source = item.get("source", "").lower()
    if any(x in source for x in ["cisa", "nist", "microsoft", "google", "kev"]):
        source_weight = 1.0
    elif any(x in source for x in ["bleeping", "krebs", "darkreading", "group-ib", "securelist"]):
        source_weight = 0.85
    elif any(x in source for x in ["reddit", "telegram", "bluesky", "mastodon", "alienvault"]):
        source_weight = 0.45
    else:
        source_weight = 0.7

    title = item.get("title", "")
    content = item.get("content", "")
    total_chars = len(title) + len(content)
    if total_chars > 2000:
        quality_score = 1.0
    elif total_chars > 500:
        quality_score = 0.8
    elif total_chars > 120:
        quality_score = 0.6
    else:
        quality_score = 0.3

    artifact_score = 0.0
    if re.search(r"\bCVE-\d{4}-\d+\b", content, re.IGNORECASE):
        artifact_score += 0.5
    if re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", content):
        artifact_score += 0.2
    if any(keyword in f"{title} {content}".lower() for keyword in ["rce", "exploit", "ioc", "mitigation", "patch", "waf"]):
        artifact_score += 0.3
    artifact_score = min(1.0, artifact_score)

    mentions = 0
    title_tokens = {token for token in re.findall(r"[a-z0-9]{4,}", title.lower())[:12]}
    cves = set(re.findall(r"\bCVE-\d{4}-\d+\b", content, re.IGNORECASE))
    for other in corpus:
        if other["id"] == item["id"]:
            continue
        other_text = f"{other.get('title', '')} {other.get('content', '')}".lower()
        if cves and any(cve.lower() in other_text for cve in cves):
            mentions += 1
            continue
        overlap = sum(1 for token in title_tokens if token in other_text)
        if overlap >= 3:
            mentions += 1
    mention_multiplier = min(1.0, mentions / 3)

    item_lang = item.get("lang", "en")
    org_langs = org_profile.get("preferred_languages", ["en"])
    if item_lang in org_langs or item_lang == "en":
        lang_score = 1.0
    elif item_lang == "und":
        lang_score = 0.5
    else:
        lang_score = 0.7

    score = (
        source_weight * 0.45
        + quality_score * 0.25
        + artifact_score * 0.15
        + mention_multiplier * 0.15
        + lang_score * 0.05
    )
    return min(1.0, max(0.0, score))


def qualifies_for_watch(item: Dict) -> bool:
    text = f"{item.get('title', '')} {item.get('content', '')}".lower()
    source = item.get("source", "").lower()
    is_social = any(name in source for name in ["reddit", "telegram", "bluesky", "mastodon", "alienvault"])
    has_unique_artifact = bool(
        re.search(r"\bCVE-\d{4}-\d+\b", text, re.IGNORECASE)
        or re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", text)
        or any(keyword in text for keyword in ["0day", "zero-day", "web shell", "ransomware", "apt"])
    )
    return is_social and has_unique_artifact


def process_collected_items(items: List[Dict], cfg: Dict) -> List[Dict]:
    if not items:
        return []

    max_content_chars = max(500, int(cfg.get("pipeline", {}).get("max_content_chars", 5000)))
    for item in items:
        item["title"] = normalize_text(item.get("title", ""))
        item["content"] = normalize_text(item.get("content", ""))[:max_content_chars]

    dedup_threshold = cfg.get("pipeline", {}).get("dedup_threshold", 0.90)
    enable_semantic = cfg.get("pipeline", {}).get("enable_semantic_dedup", True)
    window_size = max(10, min(int(cfg.get("pipeline", {}).get("dedup_window_size", 100)), 250))
    items, _ = deduplicate_items(
        items,
        similarity_threshold=dedup_threshold,
        enable_semantic=enable_semantic,
        window_size=window_size,
    )

    org_profile = cfg.get("org_profile", {"preferred_languages": ["en"]})
    min_confidence = cfg.get("pipeline", {}).get("min_confidence", 0.5)
    now = datetime.now(timezone.utc).isoformat()

    for item in items:
        credibility = calculate_credibility_score(item, org_profile, items)
        item["credibility_score"] = credibility
        item["relevance_score"] = credibility
        item["processed_at"] = now
        if credibility >= min_confidence:
            item["processing_status"] = "queued"
        elif qualifies_for_watch(item):
            item["processing_status"] = "watching"
        else:
            item["processing_status"] = "ignored"

    accepted_cves = set()
    for item in items:
        if item.get("processing_status") == "queued":
            accepted_cves.update(re.findall(r"\bCVE-\d{4}-\d+\b", item.get("content", ""), re.IGNORECASE))
    for item in items:
        if item.get("processing_status") != "watching":
            continue
        watch_cves = set(re.findall(r"\bCVE-\d{4}-\d+\b", item.get("content", ""), re.IGNORECASE))
        if accepted_cves.intersection(watch_cves):
            item["processing_status"] = "queued"
            item["credibility_score"] = max(item.get("credibility_score", 0.0), min_confidence)
            item["relevance_score"] = item["credibility_score"]

    items.sort(key=lambda entry: entry.get("credibility_score", 0.0), reverse=True)
    _release_embedding_model()
    gc.collect()
    return items


def run_processing(db_conn, cfg: Dict, batch_size: int = 500) -> int:
    from core.contextual import watch_window_expiry
    from utils.db_handler import update_processing

    batch_size = max(1, min(int(batch_size), 1000))
    total_processed = 0
    batch_num = 0
    items_filtered_total = 0

    logger.info("==========")
    logger.info("PHASE 2: PROCESSING STARTED")
    logger.info("==========")

    while True:
        batch_num += 1
        cursor = db_conn.execute(
            """
            SELECT id, source, source_type, title, url, content, lang, confidence, collected_at
            FROM intel_items
            WHERE processed=0
            LIMIT ?
            """,
            (batch_size,),
        )
        rows = cursor.fetchall()
        if not rows:
            logger.info("[BATCH %s] No more pending items in database.", batch_num)
            break

        pending_items = [
            {
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
            for row in rows
        ]
        logger.info("[BATCH %s] Processing %s items...", batch_num, len(pending_items))

        try:
            processed_items = process_collected_items(pending_items, cfg)
        except Exception as exc:
            _release_embedding_model()
            gc.collect()
            logger.error("[BATCH %s] Processing failed. Aborting phase 2 to avoid re-reading the same batch forever.", batch_num)
            logger.error("[BATCH %s] Batch item ids: %s", batch_num, [item["id"] for item in pending_items[:20]])
            logger.error("[BATCH %s] Exception detail", batch_num, exc_info=True)
            raise RuntimeError(f"Phase 2 aborted on batch {batch_num}") from exc

        updated_count = 0
        dropped_count = 0
        for item in processed_items:
            status = item.get("processing_status", "ignored")
            triage_status = "queued"
            triage_priority = "routine"
            watch_until = ""
            if status == "watching":
                triage_status = "watching"
                triage_priority = "low"
                watch_until = watch_window_expiry(hours=12)
            elif status == "ignored":
                triage_status = "ignored"
                triage_priority = "low"
                dropped_count += 1

            success = update_processing(
                db_conn,
                item["id"],
                relevance=item.get("relevance_score", 0.0),
                credibility_score=item.get("credibility_score", 0.0),
                triage_status=triage_status,
                triage_priority=triage_priority,
                watch_until=watch_until,
            )
            if success:
                updated_count += 1

        total_processed += updated_count
        items_filtered_total += dropped_count
        gc.collect()
        logger.info(
            "[BATCH %s] DB sync complete. %s items updated, %s dropped.",
            batch_num,
            updated_count,
            dropped_count,
        )

    logger.info(
        "PHASE 2 COMPLETE | Total Processed: %s | Total Filtered/Cleared: %s",
        total_processed,
        items_filtered_total,
    )
    return total_processed
