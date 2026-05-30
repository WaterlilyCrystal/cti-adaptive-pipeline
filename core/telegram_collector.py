import os
import hashlib
import logging
import asyncio
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv
from telethon import TelegramClient
from telethon.errors import SessionPasswordNeededError
from langdetect import detect, LangDetectException

# Load environment variables from .env file
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Target public cybersecurity channels (multilingual: English, Russian, Chinese)
CHANNELS = [
    # === English ===
    "vxunderground",      # Largest English malware/APT channel
    "CyberKnow",          # Cyber knowledge sharing
    "intel471",           # Intelligence discussions
    "thecyberexpress",    # Cyber news
    "breachesandleaks",   # Data breach tracking
    "cveNotify",          # High-volume CVE alerts
    "malwr",              # Malware research and writeups
    "arpsyndicate",       # Vulnerability and exploit intelligence
    "exploitorg",         # Exploit and detection engineering research
    
    # === Russian ===
    "breakersgen",        # Russian hacker forum discussions
    "exploitdb_news",     # Exploit database updates
    "cybersecurity_russia", # Russian security community
    
    # === Chinese ===
    "feixuyun",           # Chinese security research
    "websec_feed",        # Web security updates
    "malwaresec",         # Malware analysis (multilingual)
]

async def scrape_telegram_channels(days_window=3):
    """
    Asynchronous internal function using Telethon User API to iterate through channel messages.
    Uses personal Telegram account credentials for authentication.
    Supports multilingual channels (English, Russian, Chinese).
    Filters content by date, structural validity, and extracts fields mapping to the schema.
    Auto-detects message language and includes it in the output.
    """
    # Retrieve User API credentials from environment
    api_id_raw = os.getenv("TELEGRAM_API_ID")
    api_hash = os.getenv("TELEGRAM_API_HASH")
    phone_number = os.getenv("TELEGRAM_PHONE_NUMBER")

    if not api_id_raw or not api_hash or not phone_number:
        logging.error("Telegram User API credentials missing in .env file.")
        logging.error("Required: TELEGRAM_API_ID, TELEGRAM_API_HASH, TELEGRAM_PHONE_NUMBER")
        return []

    try:
        api_id = int(api_id_raw)
    except ValueError:
        logging.error("TELEGRAM_API_ID must be a valid integer inside the .env file.")
        return []

    # Configure session file storage location within the data directory
    session_path = os.path.join("data", "cti_telegram_session")
    os.makedirs("data", exist_ok=True)
    
    collected_data = []
    now = datetime.now(timezone.utc)
    time_limit = now - timedelta(days=days_window)

    logging.info(f"Starting Telegram User API channel scraping (Time window: last {days_window} days)...")

    # Establish client connection context using User API with personal account
    async with TelegramClient(session_path, api_id, api_hash) as client:
        # Authenticate using personal Telegram account (User API)
        try:
            if not await client.is_user_authorized():
                logging.info("First-time authentication required. Sending code to your Telegram account...")
                await client.start(phone=phone_number)
                logging.info("User API authentication successful!")
            else:
                logging.info("Using existing authenticated User API session...")
                await client.start(phone=phone_number)
        except SessionPasswordNeededError:
            logging.error("Two-factor authentication enabled. Please disable or provide password.")
            return []
        except Exception as e:
            logging.error(f"Authentication failed: {str(e)}")
            return []
        
        # Iterate through target channels using authenticated User API session
        for channel in CHANNELS:
            logging.info(f"Connecting to Telegram channel: @{channel}...")
            try:
                count = 0
                # Fetch recent messages sequentially
                async for message in client.iter_messages(channel, limit=100):
                    # Skip messages with no text content (e.g., pure file uploads or media)
                    if not message.text:
                        continue
                        
                    # Message date object from Telethon is already timezone-aware (UTC)
                    if message.date < time_limit:
                        # Since messages are retrieved from newest to oldest, we break early
                        break

                    post_url = f"https://t.me/{channel}/{message.id}"
                    
                    # Generate unique string identifier via deterministic MD5 hash of the URL
                    item_id = hashlib.md5(post_url.encode('utf-8')).hexdigest()
                    
                    # Derive a scannable title string from the first line of text
                    first_line = message.text.split('\n')[0].strip()
                    title = first_line[:80] + "..." if len(first_line) > 80 else first_line
                    if not title:
                        title = f"Threat update from @{channel}"

                    # Auto-detect language from message content
                    lang = "en"
                    try:
                        if message.text and len(message.text) > 10:
                            detected = detect(message.text[:300])
                            lang = detected if detected else "en"
                    except LangDetectException:
                        lang = "en"
                    except Exception:
                        lang = "en"

                    # Construct exact dictionary matching the intel_items SQLite schema
                    item = {
                        "id": item_id,
                        "source": f"Telegram/@{channel}",
                        "source_type": "social",
                        "title": title,
                        "url": post_url,
                        "content": message.text,
                        "lang": lang,                    # Auto-detected language (en, ru, zh, etc.)
                        "processed": 0,
                        "report_done": 0,
                        "collected_at": now.isoformat()
                    }
                    collected_data.append(item)
                    count += 1
                    
                logging.info(f"Successfully processed {count} relevant items from @{channel}")
            except Exception as e:
                logging.error(f"Error processing channel @{channel}: {str(e)}")
                continue
                
    return collected_data

def fetch_telegram_data(days_window=3) -> list[dict]:
    """
    Synchronous wrapper function to execute the asynchronous Telethon User API loop safely.
    Uses personal Telegram account for authentication and data collection.
    Exposes a unified interface for pipeline.py execution.
    """
    try:
        return asyncio.run(scrape_telegram_channels(days_window))
    except Exception as e:
        logging.error(f"Telegram User API collection pipeline phase failed: {str(e)}")
        return []

# Isolated test run execution block
if __name__ == "__main__":
    print("=== TEST RUN: TELEGRAM USER API CHANNEL COLLECTOR ===")
    print("NOTE: On the very first run, you must:")
    print("  1. Check your terminal for a prompt requesting your phone number")
    print("  2. Enter your phone number with country code (e.g., +1234567890)")
    print("  3. Enter the verification code sent to your Telegram client")
    print("  4. The session will be saved and reused for future runs\n")
    
    results = fetch_telegram_data(days_window=3)
    print(f"\nExecution finished. Total items extracted: {len(results)}")
    
    if results:
        import json
        print("\n--- Sample Schema Dictionary Matching 'intel_items' ---")
        print(json.dumps(results[0], indent=4, ensure_ascii=False))
