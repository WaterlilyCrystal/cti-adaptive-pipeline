import json
from datetime import datetime
from ntscraper import Nitter

def test_nitter_scraper(keyword: str = "CVE", max_tweets: int = 5):
    """
    Test fetching tweets using ntscraper via public Nitter instances.
    No Twitter API keys or accounts required.
    """
    print(f"[*] Starting ntscraper test for keyword: {keyword}")
    
    # Initialize the Nitter scraper
    scraper = Nitter()
    
    # List of known public Nitter instances to try if the default one fails
    # As of 2026, X actively blocks these, so having backups is crucial
    custom_instances = [
        "https://nitter.privacydev.net",
        "https://nitter.net",
        "https://nitter.cz",
        "https://nitter.tokhmi.xyz"
    ]
    
    scraped_tweets = None
    
    # Try fetching using custom instances first
    for instance in custom_instances:
        try:
            print(f"[*] Attempting to fetch from instance: {instance}")
            scraped_tweets = scraper.get_tweets(
                keyword, 
                mode="term", # "term" for general search, "hashtag" for hashtags
                number=max_tweets,
                instance=instance
            )
            if scraped_tweets and scraped_tweets.get("tweets"):
                print(f"[+] Successfully connected to {instance}")
                break
        except Exception as e:
            print(f"[-] Instance {instance} failed or was blocked: {e}")
            continue

    # If all custom instances fail, try the library's default logic
    if not scraped_tweets:
        try:
            print("[*] Trying library default instance...")
            scraped_tweets = scraper.get_tweets(keyword, mode="term", number=max_tweets)
        except Exception as e:
            print(f"[-] Default instance failed: {e}")
            return []

    # Process and normalize the data if found
    normalized_data = []
    if scraped_tweets and "tweets" in scraped_tweets:
        for tweet in scraped_tweets["tweets"]:
            item = {
                "source": "X_Nitter",
                "source_id": f"nt_{tweet.get('id')}",
                "title": "Security Alert via Nitter",
                "content": tweet.get("text"),
                "url": tweet.get("link"),
                "published_at": tweet.get("date"),
                "raw_iocs": []
            }
            normalized_data.append(item)
            
    return normalized_data

# ==========================================
# STANDALONE RUN
# ==========================================
if __name__ == "__main__":
    print("--- Running Standalone Test for ntscraper ---")
    start_time = datetime.now()
    
    results = test_nitter_scraper(keyword="CVE", max_tweets=3)
    
    print("\n--- Scraped Output Data ---")
    if results:
        print(json.dumps(results, indent=4, ensure_ascii=False))
    else:
        print("[-] Failed to collect any data. All Nitter instances might be rate-limited or dead.")
        
    print(f"\n[*] Execution time: {datetime.now() - start_time}")