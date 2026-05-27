import os
import json
import time
import logging
import hashlib
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv
from atproto import Client, exceptions
from langdetect import detect, LangDetectException




# Load environment variables from the .env file
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("bluesky_collector")


def fetch_bluesky_infosec(limit: int = 100, days_back: int = 3, keyword: str = "cybersecurity") -> list[dict]:
    """
    Fetch the latest posts from Bluesky based on a specific keyword.
    Uses the AT Protocol SDK and Cursor Pagination. Normalizes items to the
    `intel_items` schema used by the pipeline.
    """
    logger.info(f"Starting Bluesky collector (keyword='{keyword}', days_back={days_back})")

    handle = os.getenv("BLUESKY_HANDLE")
    app_password = os.getenv("BLUESKY_APP_PASSWORD")
    if not handle or not app_password:
        logger.error("Missing BLUESKY_HANDLE or BLUESKY_APP_PASSWORD in .env file")
        return []

    client = Client()
    try:
        client.login(handle, app_password)
        logger.info("Authenticated with Bluesky API")
    except exceptions.UnauthorizedError:
        logger.error("Invalid Bluesky credentials")
        return []
    except Exception as e:
        logger.error(f"Bluesky login error: {type(e).__name__}: {e}")
        return []

    threshold_date = datetime.now(timezone.utc) - timedelta(days=days_back)
    normalized_data: list[dict] = []
    cursor = None

    try:
        while len(normalized_data) < limit:
            response = client.app.bsky.feed.search_posts({
                "q": keyword,
                "limit": min(100, limit - len(normalized_data)),
                "cursor": cursor,
            })

            posts = getattr(response, "posts", []) or []
            if not posts:
                logger.debug("No more posts returned from Bluesky search")
                break

            for post in posts:
                # Timestamp extraction
                time_raw = getattr(post.record, "created_at", getattr(post, "indexed_at", None))
                if not time_raw:
                    continue
                post_time_str = time_raw.replace("Z", "+00:00")
                try:
                    if "." in post_time_str:
                        post_time_str = post_time_str.split(".")[0] + "+00:00"
                    post_date = datetime.fromisoformat(post_time_str).replace(tzinfo=timezone.utc)
                except Exception:
                    logger.debug(f"Unable to parse timestamp: {time_raw}")
                    continue

                if post_date < threshold_date:
                    continue

                raw_content = getattr(post.record, "text", "") or ""
                if not raw_content.strip():
                    continue

                username = getattr(post.author, "handle", "unknown")

                # Build URL and deterministic id
                rkey = str(getattr(post, "uri", "")).split("/")[-1]
                post_url = f"https://bsky.app/profile/{username}/post/{rkey}"
                item_id = hashlib.md5(post_url.encode("utf-8")).hexdigest()

                # Language detection
                lang = "und"
                try:
                    if len(raw_content) > 10:
                        detected = detect(raw_content[:300])
                        lang = detected or "und"
                except LangDetectException:
                    lang = "und"
                except Exception:
                    lang = "und"

                item = {
                    "id": item_id,
                    "source": f"Bluesky/@{username}",
                    "source_type": "social",
                    "title": (raw_content.split("\n")[0][:200]) if raw_content else f"Post by @{username}",
                    "url": post_url,
                    "content": raw_content,
                    "lang": lang,
                    "processed": 0,
                    "report_done": 0,
                    "collected_at": datetime.now(timezone.utc).isoformat(),
                }

                normalized_data.append(item)
                if len(normalized_data) >= limit:
                    break

            cursor = getattr(response, "cursor", None)
            if not cursor:
                break
            time.sleep(1)

        logger.info(f"Bluesky collection finished: {len(normalized_data)} items")
        return normalized_data

    except Exception as e:
        logger.error(f"Error during Bluesky collection: {type(e).__name__}: {e}")
        return normalized_data


if __name__ == "__main__":
    print("=== TEST RUN: BLUESKY COLLECTOR ===")
    data = fetch_bluesky_infosec(limit=50, days_back=3, keyword="ransomware OR malware")
    if data:
        print(json.dumps(data[0], ensure_ascii=False, indent=2))
    else:
        print("No items collected. Check credentials in .env")