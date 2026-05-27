import os
import json
import time
from datetime import datetime, timedelta
from dotenv import load_dotenv
from atproto import Client, exceptions

# Load environment variables from the .env file
load_dotenv()

def fetch_bluesky_infosec(limit: int = 100, days_back: int = 3, keyword: str = "cybersecurity") -> list:
    """
    Fetch the latest posts from Bluesky based on a specific keyword.
    Uses the AT Protocol SDK and Cursor Pagination.
    """
    print(f"[*] Starting Bluesky Collector (Keyword: '{keyword}')...")
    
    handle = os.getenv("BLUESKY_HANDLE")
    app_password = os.getenv("BLUESKY_APP_PASSWORD")
    
    if not handle or not app_password:
        print("[-] ERROR: Missing BLUESKY_HANDLE or BLUESKY_APP_PASSWORD in the .env file")
        return []

    # 1. Initialize and Login Client
    client = Client()
    try:
        client.login(handle, app_password)
        print("[+] Successfully logged into Bluesky API!")
    except exceptions.UnauthorizedError:
        print("[-] ERROR: Invalid Bluesky Handle or App Password.")
        return []
    except Exception as e:
        print(f"[-] Network connection error: {e}")
        return []

    # 2. Set Time Threshold
    threshold_date = datetime.utcnow() - timedelta(days=days_back)
    normalized_data = []
    cursor = None # 'Cursor' used to turn pages on Bluesky

    try:
        # Pagination Loop
        while len(normalized_data) < limit:
            # 3. Call Search API
            # Max 100 posts per request. To search multiple keywords, use strings like 'ransomware OR malware'
            response = client.app.bsky.feed.search_posts({
                'q': keyword,
                'limit': min(100, limit - len(normalized_data)), # Only fetch the remaining required amount
                'cursor': cursor
            })
            
            posts = response.posts
            if not posts:
                print("[*] Exhausted search results on Bluesky.")
                break
                
            for post in posts:
                # --- Process Timestamp ---
                # Python SDK uses snake_case (created_at) or top-level indexed_at
                time_raw = getattr(post.record, 'created_at', getattr(post, 'indexed_at', None))
                
                if not time_raw:
                    continue # Bỏ qua nếu không tìm thấy thời gian
                    
                # Chuẩn hóa chuỗi thời gian (thay Z bằng +00:00 để datetime hiểu được)
                post_time_str = time_raw.replace('Z', '+00:00')
                
                try:
                    # Cắt bỏ phần thập phân của giây (nếu có) để tránh lỗi format
                    if '.' in post_time_str:
                        post_time_str = post_time_str.split('.')[0] + '+00:00'
                        
                    post_date = datetime.fromisoformat(post_time_str).replace(tzinfo=None)
                except ValueError as e:
                    print(f"[-] Lỗi parse thời gian: {time_raw} -> {e}")
                    continue

                # --- Process Content ---
                raw_content = post.record.text
                if not raw_content.strip():
                    continue
                    
                username = post.author.handle
                
                # --- Reconstruct Post URL ---
                # Bluesky URLs are not directly in the API, we construct them from the Handle and Record Key (rkey)
                rkey = post.uri.split('/')[-1]
                post_url = f"https://bsky.app/profile/{username}/post/{rkey}"
                
                # --- Normalize EXACTLY to your Database Schema ---
                item = {
                    "id": f"bsky_{rkey}",
                    "source": "Bluesky Social",
                    "source_type": "Social Media",
                    "title": f"Threat Intel by @{username}",
                    "url": post_url,
                    "content": raw_content,
                    "lang": "en",
                    "raw_iocs": "[]", # Will be extracted by LLM/AI later
                    "ttp_mapping": "[]",
                    "confidence": 0.75, # Default confidence score for Social Media
                    "relevance_score": 0.0,
                    "processed": 0,
                    "report_done": 0,
                    "collected_at": datetime.utcnow().isoformat()
                }
                
                normalized_data.append(item)
                
                # Check the limit after each post
                if len(normalized_data) >= limit:
                    break
            
            # 4. Get Cursor for the next page
            cursor = getattr(response, 'cursor', None)
            if not cursor:
                break
                
            # Sleep for 1 second to respect API Rate Limits
            time.sleep(1)
            
        print(f"[+] COMPLETED. Successfully collected {len(normalized_data)} CTI records from Bluesky.")
        return normalized_data
        
    except Exception as e:
        print(f"[-] System error during Bluesky pagination: {e}")
        return normalized_data

# ==========================================
# STANDALONE TEST BLOCK
# ==========================================
if __name__ == "__main__":
    print("--- Running standalone test for the Bluesky module ---")
    
    # Test searching for ransomware over the last 3 days
    test_data = fetch_bluesky_infosec(limit=50, days_back=3, keyword="ransomware")
    
    if test_data:
        print(f"\n[+] Total records collected: {len(test_data)}")
        print("\n--- Data Structure Preview (First Record) ---")
        print(json.dumps(test_data[0], indent=4, ensure_ascii=False))