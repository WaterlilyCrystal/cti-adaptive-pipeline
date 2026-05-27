import feedparser
import time
import logging
import hashlib
from datetime import datetime, timedelta, timezone
from langdetect import detect, LangDetectException

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Highly targeted cybersecurity subreddits (English + Chinese)
SUBREDDITS = [
    # === English ===
    "netsec", "blueteamsec", "threatintel", "malware", "ExploitDev", 
    "cybersecurity", "InfoSecNews", "APT", "reverseengineering", "PrivacyGuides",
    # === Chinese (Simplified & Traditional) ===
    "chinatech", "China_SW", "HongKong", "Taiwan",  # Regional tech communities
    "SecurityCommunity_CN",  # Chinese security
]

# Keywords used for preliminary noise filtering (multilingual)
RELEVANT_KEYWORDS = [
    # === English ===
    "cve", "exploit", "vulnerability", "apt", "malware", "zero-day", "0-day",
    "attack", "bypass", "leak", "ransomware", "poc", "rce", "threat", "campaign",
    "phishing", "spyware", "backdoor", "advisory", "infostealer", "breach",
    # === Chinese ===
    "漏洞", "exploit", "攻击", "恶意软件", "威胁", "勒索", "数据泄露",
    "安全", "检测", "防御", "CVE", "APT", "木马", "病毒",
    # === Russian (transliterated) ===
    "уязвимость", "malware", "атака", "exploit", "zero-day",
]

def is_relevant(title):
    """
    Checks if the post title contains any relevant cybersecurity keywords (multilingual).
    """
    title_lower = title.lower()
    return any(keyword.lower() in title_lower for keyword in RELEVANT_KEYWORDS)

def generate_md5_id(url):
    """
    Generates a deterministic string ID using the MD5 hash of the URL.
    Ensures a clean TEXT PRIMARY KEY for the SQLite schema.
    """
    return hashlib.md5(url.encode('utf-8')).hexdigest()

def fetch_reddit_rss_feed(days_window=3):
    """
    Fetches the newest posts within the specified days window from target subreddits.
    Filters by keywords and returns a structure matching the intel_items database schema.
    Supports multilingual subreddits (English, Chinese, Russian).
    """
    collected_data = []
    custom_user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) CTI-Adaptive-Pipeline/1.0"
    
    now = datetime.now(timezone.utc)
    time_limit = now - timedelta(days=days_window)

    logging.info(f"Starting Reddit /new/ RSS scraping (multilingual, Time window: last {days_window} days)...")

    for sub in SUBREDDITS:
        # Appending /new/ forces chronological order and bypasses pinned posts
        rss_url = f"https://www.reddit.com/r/{sub}/new/.rss"
        logging.info(f"Connecting to r/{sub} via RSS...")
        
        try:
            feed = feedparser.parse(rss_url, agent=custom_user_agent)
            if not feed.entries:
                logging.warning(f"No entries found or request blocked for r/{sub}/new/")
                continue
                
            count = 0
            for entry in feed.entries:
                # Parse publication time and convert to UTC timezone
                published_time = datetime.fromtimestamp(time.mktime(entry.published_parsed), timezone.utc)
                
                # Filter Condition 1: Time Window Validation
                if published_time < time_limit:
                    continue
                
                # Filter Condition 2: Content Relevance Validation
                if not is_relevant(entry.title):
                    continue

                post_url = entry.link if hasattr(entry, 'link') else ""
                if not post_url:
                    continue

                # Detect language from title + summary
                title_text = entry.title if hasattr(entry, 'title') else ""
                summary_text = entry.summary if hasattr(entry, 'summary') else ""
                full_text = f"{title_text} {summary_text}"
                
                lang = "en"
                try:
                    if full_text.strip() and len(full_text) > 10:
                        detected = detect(full_text[:300])
                        lang = detected if detected else "en"
                except LangDetectException:
                    lang = "en"
                except Exception:
                    lang = "en"

                # Mapping directly to the 'intel_items' database schema
                item = {
                    "id": generate_md5_id(post_url),
                    "source": f"Reddit/r/{sub}",
                    "source_type": "social",
                    "title": entry.title,
                    "url": post_url,
                    "content": entry.summary if hasattr(entry, 'summary') else "",
                    "lang": lang,                  # Auto-detected language
                    "processed": 0,                # 0 represents False/Pending in SQLite
                    "report_done": 0,              # 0 represents False/Pending in SQLite
                    "collected_at": now.isoformat()
                }
                collected_data.append(item)
                count += 1
                
            logging.info(f"Successfully collected {count} relevant items from r/{sub}")
            time.sleep(1.5)  # Built-in delay to prevent anti-scraping rate limits
            
        except Exception as e:
            logging.error(f"Error processing source r/{sub}: {str(e)}")
            continue

    logging.info(f"Scraping completed. Total items matching schema criteria: {len(collected_data)}")
    return collected_data

# Independent verification block for Student A
if __name__ == "__main__":
    print("=== TEST RUN: REDDIT RSS COLLECTOR (MULTILINGUAL) ===")
    results = fetch_reddit_rss_feed(days_window=3)
    
    if results:
        print("\n--- Sample Data Output Matching 'intel_items' Schema ---")
        import json
        print(json.dumps(results[0], indent=4, ensure_ascii=False))
    else:
        print("\nCollection failed. Verify network connectivity or check if the User-Agent was blocked.")