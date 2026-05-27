"""RSS feed collectors for CTI Adaptive Pipeline.

Provides functions to fetch and normalize RSS/Atom feed entries into the
`intel_items` schema used by the pipeline. Contains a built-in `SOURCES`
dictionary used when the pipeline config does not define RSS feeds.

Refactored for robust networking: uses `requests` to handle SSL failures,
Cloudflare/WAF anti-bot measures, and complex redirects common in RU/CN sources.
"""
from __future__ import annotations

import hashlib
import logging
import time
import socket
from datetime import datetime, timedelta, timezone
from typing import List, Dict

import requests
import urllib3
import feedparser
from langdetect import detect, LangDetectException

# Tắt cảnh báo InsecureRequestWarning khi request các trang có chứng chỉ SSL lỗi (rất phổ biến ở CTI feeds)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger("rss_collector")
if not logger.handlers:
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Fallback source list
# # === ENGLISH (Primary sources) ===
#   "CISA Advisories": "https://www.cisa.gov/uscert/ncas/current-activity.xml",
#   "SANS ISC Diary": "https://isc.sans.edu/rssfeed.xml",
#   "BleepingComputer": "https://www.bleepingcomputer.com/feed/",
#   "SecurityWeek": "https://feeds.feedburner.com/securityweek",
#   "The Record": "https://therecord.media/feed/",
#   "Microsoft Security Blog": "https://www.microsoft.com/en-us/security/blog/feed/",
#   "Google Security Blog": "https://security.googleblog.com/atom.xml",
#   "Krebs on Security": "https://krebsonsecurity.com/feed/",
#   "Hacker News (Security)": "https://feeds.hnrss.org/frontpage",
#   "Dark Reading": "https://www.darkreading.com/rss.xml",
SOURCES = {
  
  
  # === RUSSIAN (Cyberattacks, APTs, malware) ===
  "Xakep (Russian Security)": "https://xakep.ru/feed/",
  "Securelist (Russian)": "https://securelist.com/feed/",
  "Positive Technologies": "https://www.ptsecurity.com/rss/news.xml",
  "Group-IB": "https://www.group-ib.com/feed/blogfeed/", 
  
  # === CHINESE (Chinese malware, APTs, vulnerabilities) ===
  "Anquanke (Chinese APT/CVE)": "https://api.anquanke.com/data/v1/rss", 
  "Tencent Security": "https://s.tencent.com/rss",
  
  # === EUROPEAN & OTHERS ===
  "CERT-FR": "https://www.cert.ssi.gouv.fr/feed/",
  "ZDNet France Security": "https://www.zdnet.fr/feeds/rss/securite/",
  "CERT-Bund": "https://wid.cert-bund.de/portal/wid/securityadvisory?rss",
  "JPCERT/CC": "https://www.jpcert.or.jp/rss/jpcert.rdf",
  "AhnLab ASEC": "https://asec.ahnlab.com/en/feed/",
  "CERT.br": "https://www.cert.br/rss/certbr-rss.xml",
  "INCIBE-CERT": "https://www.incibe.es/incibe-cert/alerta-temprana/avisos/feed",
  "CERT Polska": "https://cert.pl/rss.xml",
  "iThome Security": "https://www.ithome.com.tw/rss/security",
  "NCSC-FI": "https://www.kyberturvallisuuskeskus.fi/en/rss.xml",
  
  # === ASIA-PACIFIC ===
  "Cyber Defense Magazine": "https://www.cyberdefensemagazine.com/rss/",
  "Help Net Security": "https://www.helpnetsecurity.com/feed/",
}


def _md5_for_url(url: str) -> str:
    return hashlib.md5(url.encode("utf-8")).hexdigest()


def _entry_published_time(entry) -> datetime | None:
    try:
        if hasattr(entry, "published_parsed") and entry.published_parsed:
            return datetime.fromtimestamp(time.mktime(entry.published_parsed), timezone.utc)
        if hasattr(entry, "updated_parsed") and entry.updated_parsed:
            return datetime.fromtimestamp(time.mktime(entry.updated_parsed), timezone.utc)
    except Exception:
        return None
    return None


def fetch_rss_feeds(feed_urls: List[str], days_window: int = 3, user_agent: str | None = None) -> List[Dict]:
    results: List[Dict] = []
    now = datetime.now(timezone.utc)
    time_limit = now - timedelta(days=days_window)

    # Sử dụng UA giống hệt trình duyệt thật để bypass WAF của các trang TQ/Nga
    ua = user_agent or "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    
    # Headers tiêu chuẩn để tránh lỗi 403 Forbidden hoặc Bot Challenge
    headers = {
        "User-Agent": ua,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9,ru;q=0.8,zh-CN;q=0.7",
        "Cache-Control": "max-age=0",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1"
    }

    # Dùng Session để tự động handle redirects tốt hơn
    session = requests.Session()
    session.headers.update(headers)

    for url in feed_urls:
        feed_name = url.split("//")[-1][:40]
        try:
            # Tăng timeout lên 30 giây (để chờ Freebuf/Aliyun)
            response = session.get(url, verify=False, timeout=30, allow_redirects=True)
            response.raise_for_status() 
            
            feed = feedparser.parse(response.content)
            
            if hasattr(feed, 'bozo') and feed.bozo:
                bozo_msg = str(feed.bozo_exception) if hasattr(feed, 'bozo_exception') else "Unknown issue"
                logger.debug(f"Feed {feed_name} parsing warning: {bozo_msg}")
                
        except requests.exceptions.HTTPError as e:
            # Bỏ qua nếu gặp 403, 404, 521 thay vì báo ERROR lớn
            logger.warning(f"Skipping {feed_name}: HTTP {e.response.status_code}")
            continue
        except (requests.exceptions.RequestException, TimeoutError, socket.timeout) as e:
            logger.warning(f"Network Timeout/Error for {feed_name}: {type(e).__name__}")
            continue
        except Exception as e:
            logger.error(f"Failed to fetch {feed_name}: {e}")
            continue

        feed_name = getattr(feed.feed, "title", feed_name)
        count = 0

        entries = getattr(feed, "entries", []) or []
        if not entries:
            logger.debug(f"No entries found in {feed_name} - feed may be empty or blocked by WAF")
            continue
        
        logger.info(f"Processing {feed_name}: found {len(entries)} entries")
            
        for entry in entries:
            try:
                published = _entry_published_time(entry)
                if published is None:
                    published = now
                    
                if published < time_limit:
                    continue

                title = getattr(entry, "title", "").strip() if hasattr(entry, "title") else ""
                
                if not title:
                    continue
                    
                content = ""
                if hasattr(entry, "summary") and entry.summary:
                    content = entry.summary[:5000]
                elif hasattr(entry, "description") and entry.description:
                    content = entry.description[:5000]
                elif hasattr(entry, "content") and entry.content:
                    try:
                        if isinstance(entry.content, (list, tuple)) and entry.content:
                            content = str(entry.content[0].get("value", ""))[:5000]
                    except Exception:
                        content = str(entry.content)[:5000]

                # Decode HTML entities
                try:
                    import html
                    title = html.unescape(title)
                    content = html.unescape(content)
                except Exception:
                    pass

                full_text = (title or "") + "\n" + (content or "")
                lang = "en"
                
                try:
                    if full_text.strip() and len(full_text) > 10:
                        detected = detect(full_text[:500])
                        lang = detected if detected else "und"
                    else:
                        lang = "und"
                except LangDetectException:
                    lang = "und"
                except Exception:
                    lang = "und"

                link = getattr(entry, "link", "").strip() if hasattr(entry, "link") else ""
                if not link:
                    link = entry.get("id", "").strip() if isinstance(entry, dict) else ""
                    if not link and hasattr(entry, "links") and entry.links:
                        try:
                            link = entry.links[0].get("href", "")
                        except Exception:
                            link = ""

                if not link:
                    continue

                item = {
                    "id": _md5_for_url(link),
                    "source": f"RSS/{feed_name}",
                    "source_type": "rss",
                    "title": title[:200],
                    "url": link,
                    "content": content,
                    "lang": lang,
                    "confidence": 0.0,
                    "processed": 0,
                    "report_done": 0,
                    "collected_at": now.isoformat(),
                }
                results.append(item)
                count += 1
            except Exception as e:
                logger.debug(f"Error processing single entry from {feed_name}: {type(e).__name__}: {e}")
                continue

        if count > 0:
            logger.info(f"Collected {count} items from {feed_name}")

    logger.info(f"RSS collection completed. Total items: {len(results)}")
    return results

def fetch_rss_from_config(cfg: dict, days_window: int = 3) -> List[Dict]:
    try:
        feed_urls = cfg.get("sources", {}).get("rss", [])
        if (not isinstance(feed_urls, list)) or (isinstance(feed_urls, list) and len(feed_urls) == 0):
            fallback = globals().get("SOURCES")
            if fallback and isinstance(fallback, dict):
                feed_urls = list(fallback.values())

        if not isinstance(feed_urls, list) or not feed_urls:
            return []

        seen = set()
        deduped = []
        for u in feed_urls:
            if not isinstance(u, str) or u in seen:
                continue
            seen.add(u)
            deduped.append(u)

        return fetch_rss_feeds(deduped, days_window=days_window)
    except Exception as e:
        logger.error(f"Error in fetch_rss_from_config: {e}")
        return []

if __name__ == "__main__":
    test_feeds = list(SOURCES.values())
    items = fetch_rss_feeds(test_feeds, days_window=3)
    print(f"Fetched {len(items)} RSS items")