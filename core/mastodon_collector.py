import requests
import json
import re
import time
from datetime import datetime, timedelta

def clean_html(raw_html: str) -> str:
    """
    Mastodon API returns content with HTML tags (<p>, <br>, <a>).
    This function removes those tags and returns clean, plain text for the AI.
    """
    clean_r = re.compile('<.*?>')
    clean_text = re.sub(clean_r, ' ', raw_html)
    return ' '.join(clean_text.split())

def fetch_mastodon_fosstodon(limit: int = 1000, days_back: int = 3, hashtag: str = "threatintel") -> list:
    """
    Fetch the latest posts from the fosstodon.org community on Mastodon.
    Implements pagination to fetch up to a maximum limit within a specific time window.
    """
    # 1. CHANGED: URL now points to fosstodon.org
    url = f"https://fosstodon.org/api/v1/timelines/tag/{hashtag}"
    print(f"[*] Fetching Mastodon data (Server: fosstodon.org | Hashtag: #{hashtag})")
    print(f"[*] Target: Max {limit} posts from the last {days_back} days...")
    
    # Calculate the time threshold
    threshold_date = datetime.utcnow() - timedelta(days=days_back)
    
    normalized_data = []
    max_id = None  # Used for pagination (fetching older posts)

    try:
        while len(normalized_data) < limit:
            # Mastodon API allows a maximum of 40 items per request
            params = {"limit": 40}
            if max_id:
                params["max_id"] = max_id

            response = requests.get(url, params=params, timeout=15)
            response.raise_for_status()
            
            posts = response.json()
            
            # Break the loop if there are no more posts returned
            if not posts:
                print("[*] Reached the end of the timeline.")
                break
                
            for post in posts:
                # Check the timestamp
                # Mastodon returns ISO format with 'Z' (e.g., 2026-05-27T10:00:00.000Z)
                post_time_str = post.get("created_at", "").replace('Z', '+00:00')
                try:
                    post_date = datetime.fromisoformat(post_time_str).replace(tzinfo=None)
                except ValueError:
                    continue # Skip if date parsing fails

                # If the post is older than our threshold, stop collecting entirely
                if post_date < threshold_date:
                    print(f"[+] Reached the {days_back}-day time limit. Stopping pagination.")
                    return normalized_data

                # Clean content
                raw_content = post.get("content", "")
                clean_content = clean_html(raw_content)
                
                # Skip empty posts (e.g., posts that only contain media)
                if not clean_content.strip():
                    continue
                    
                # Extract Author
                account = post.get("account", {})
                username = account.get("username", "unknown_user")
                
                # 2. CHANGED: Normalize EXACTLY to the Database Schema with new source
                item = {
                    "id": f"mastodon_{post.get('id')}",
                    "source": "Mastodon (fosstodon.org)",
                    "source_type": "Social Media",
                    "title": f"Alert from @{username}",
                    "url": post.get("url"),
                    "content": clean_content,
                    "lang": post.get("language", "en"),
                    "raw_iocs": "[]",     # To be extracted by AI in Phase 3
                    "ttp_mapping": "[]",  # To be extracted by AI in Phase 3
                    "confidence": 0.70,   # Social media gets a lower default confidence
                    "relevance_score": 0.0,
                    "processed": 0,
                    "report_done": 0,
                    "collected_at": datetime.utcnow().isoformat()
                }
                
                normalized_data.append(item)
                
                # Stop if we hit the requested limit
                if len(normalized_data) >= limit:
                    print(f"[+] Reached the maximum limit of {limit} posts.")
                    break
            
            # Update max_id for the next pagination request (use the ID of the last post in the current batch)
            max_id = posts[-1].get("id")
            
            # Sleep briefly to respect API rate limits
            time.sleep(1)
            
        print(f"[+] Successfully fetched and normalized {len(normalized_data)} social media records.")
        return normalized_data
        
    except requests.exceptions.RequestException as e:
        print(f"[-] Network connection error when calling Mastodon: {e}")
        return normalized_data # Return whatever we managed to collect before the error
    except Exception as e:
        print(f"[-] System error when processing Mastodon data: {e}")
        return normalized_data

# ==========================================
# STANDALONE TEST BLOCK
# ==========================================
if __name__ == "__main__":
    print("--- Running standalone test for the Mastodon module (Fosstodon) ---")
    
    # Test with a broader hashtag to ensure we get results quickly
    test_data = fetch_mastodon_fosstodon(limit=1000, days_back=3, hashtag="cybersecurity")
    
    if test_data:
        print(f"\n[+] Total records collected: {len(test_data)}")
        print("\n--- Data Structure Preview (First Record) ---")
        print(json.dumps(test_data[0], indent=4, ensure_ascii=False))