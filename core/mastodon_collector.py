import requests
import json
import re
import time
import logging
import hashlib
from datetime import datetime, timedelta, timezone
from langdetect import detect, LangDetectException

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("mastodon_collector")


def clean_html(raw_html: str) -> str:
    """
    Mastodon API returns content with HTML tags (<p>, <br>, <a>).
    This function removes those tags and returns clean, plain text for the AI.
    """
    clean_r = re.compile('<.*?>')
    clean_text = re.sub(clean_r, ' ', raw_html)
    return ' '.join(clean_text.split())

def fetch_mastodon_fosstodon(limit: int = 100, days_back: int = 3, hashtag: str = "cybersecurity") -> list[dict]:
    """
    Fetch the latest posts from the fosstodon.org community on Mastodon.
    Implements pagination to fetch up to a maximum limit within a specific time window.
    """
    # 1. CHANGED: URL now points to fosstodon.org
    url = f"https://fosstodon.org/api/v1/timelines/tag/{hashtag}"
    print(f"[*] Fetching Mastodon data (Server: fosstodon.org | Hashtag: #{hashtag})")
    print(f"[*] Target: Max {limit} posts from the last {days_back} days...")
    
    # Calculate the time threshold
    threshold_date = datetime.now(timezone.utc) - timedelta(days=days_back)

    normalized_data: list[dict] = []
    max_id = None  # Used for pagination (fetching older posts)

    try:
        while len(normalized_data) < limit:
            params = {"limit": 40}
            if max_id:
                params["max_id"] = max_id

            try:
                response = requests.get(url, params=params, timeout=15)
                response.raise_for_status()
            except requests.exceptions.RequestException as e:
                logger.error(f"Request error when calling Mastodon: {type(e).__name__}: {e}")
                break

            posts = response.json()
            if not posts:
                logger.debug("No posts returned from Mastodon timeline")
                break

            for post in posts:
                post_time_str = post.get("created_at", "").replace('Z', '+00:00')
                try:
                    post_date = datetime.fromisoformat(post_time_str).replace(tzinfo=timezone.utc)
                except ValueError:
                    logger.debug("Unable to parse Mastodon post timestamp, skipping")
                    continue

                if post_date < threshold_date:
                    logger.info(f"Reached {days_back}-day threshold for Mastodon, stopping pagination")
                    return normalized_data

                raw_content = post.get("content", "")
                clean_content = clean_html(raw_content)
                if not clean_content.strip():
                    continue

                account = post.get("account", {})
                username = account.get("username", "unknown_user")

                # Language detection
                lang = post.get("language") or "und"
                try:
                    if len(clean_content) > 10:
                        detected = detect(clean_content[:300])
                        lang = detected or lang
                except LangDetectException:
                    pass
                except Exception:
                    pass

                post_url = post.get("url", "")
                item_id = hashlib.md5(post_url.encode("utf-8")).hexdigest() if post_url else f"mastodon_{post.get('id')}"

                item = {
                    "id": item_id,
                    "source": f"Mastodon/@{username}",
                    "source_type": "social",
                    "title": clean_content.split("\n")[0][:200] if clean_content else f"Post by @{username}",
                    "url": post_url,
                    "content": clean_content,
                    "lang": lang,
                    "processed": 0,
                    "report_done": 0,
                    "collected_at": datetime.now(timezone.utc).isoformat(),
                }

                normalized_data.append(item)
                if len(normalized_data) >= limit:
                    logger.info(f"Reached limit of {limit} posts from Mastodon")
                    break

            max_id = posts[-1].get("id")
            time.sleep(1)

        logger.info(f"Mastodon collection finished: {len(normalized_data)} items")
        return normalized_data

    except Exception as e:
        logger.error(f"Error during Mastodon collection: {type(e).__name__}: {e}")
        return normalized_data

# ==========================================
# STANDALONE TEST BLOCK
# ==========================================
if __name__ == "__main__":
    print("=== TEST RUN: MASTODON COLLECTOR ===")
    data = fetch_mastodon_fosstodon(limit=50, days_back=3, hashtag="cybersecurity")
    if data:
        print(json.dumps(data[0], ensure_ascii=False, indent=2))
    else:
        print("No items collected. Check network connectivity and server URL")