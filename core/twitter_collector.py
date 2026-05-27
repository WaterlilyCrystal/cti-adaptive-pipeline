import os
import json
import requests
from datetime import datetime
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

def fetch_twitter_cve() -> list:
    """
    Fetch tweets related to CVE/ThreatIntel from X.
    Automatically fallback to Mock Data if using the Free API tier (GET requests blocked).
    """
    print(f"[*] Fetching data from X (Twitter)...")
    
    bearer_token = os.getenv("TWITTER_BEARER_TOKEN")
    print(f"[*] Debug Token: {bearer_token[:5] if bearer_token else 'Rỗng (None)'}...")
    if not bearer_token:
        print("[-] Error: TWITTER_BEARER_TOKEN not found in .env")
        return []

    url = "https://api.twitter.com/2/tweets/search/recent"
    headers = {"Authorization": f"Bearer {bearer_token}"}
    params = {
        "query": "#CVE OR #ThreatIntel -is:retweet",
        "tweet.fields": "created_at",
        "max_results": 10
    }

    tweets = []
    
    try:
        # Try calling the real X API
        response = requests.get(url, headers=headers, params=params, timeout=10)
        response.raise_for_status()
        tweets = response.json().get("data", [])
        print("[+] Successfully called X API!")
        
    except requests.exceptions.HTTPError as e:
        if response.status_code == 403:
            print("[-] X API returned 403 Forbidden (Free tier limitation).")
            print("[*] Automatically switching to Mock Data configuration for Demo purposes...")
            # Mock data executed immediately when API is blocked
            tweets = [
                {
                    "id": "1890123456789012345",
                    "text": "🚨 CRITICAL: Nginx zero-day vulnerability (CVE-2026-9999) actively exploited in the wild. Attackers are dropping web shells. Suspicious IP seen: 198.51.100.22. #ThreatIntel",
                    "created_at": datetime.utcnow().isoformat() + "Z"
                },
                {
                    "id": "1890123456789012346",
                    "text": "New ransomware strain targeting healthcare sector via exposed RDP ports. Be on the lookout for hash: a1b2c3d4e5f67890. #Ransomware",
                    "created_at": datetime.utcnow().isoformat() + "Z"
                }
            ]
        else:
            print(f"[-] HTTP Error connecting to X API: {e}")
            return []
    except Exception as e:
        print(f"[-] System error when calling X: {e}")
        return []

    # Normalize data into common format (Unified Data Bus)
    normalized_data = []
    for tweet in tweets:
        item = {
            "source": "Twitter",
            "source_id": f"tw_{tweet.get('id')}",
            "title": "Security Alert from X (Twitter)", 
            "content": tweet.get("text"),
            "url": f"https://x.com/i/web/status/{tweet.get('id')}",
            "published_at": tweet.get("created_at"),
            "raw_iocs": [] 
        }
        normalized_data.append(item)
        
    print(f"[+] Complete! Fetched {len(normalized_data)} items from X.")
    return normalized_data

# ==========================================
# STANDALONE TEST BLOCK
# ==========================================
if __name__ == "__main__":
    print("--- Running Standalone Test for twitter_collector.py ---")
    data = fetch_twitter_cve()
    
    print("\n--- Output Data ---")
    if data:
        # Print the data nicely with indentations
        print(json.dumps(data, indent=4, ensure_ascii=False))
    else:
        print("No data collected.")