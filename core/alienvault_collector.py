import os
import json
import requests
from datetime import datetime, timedelta
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

def fetch_otx_pulses(limit: int = 1000, days_back: int = 3) -> list:
    """
    Fetch Pulses from AlienVault OTX updated within the last X days.
    """
    print(f"[*] Fetching data from AlienVault OTX (Limit: {limit}, Last {days_back} days)...")
    
    api_key = os.getenv("OTX_API_KEY")
    if not api_key:
        print("[-] Error: OTX_API_KEY not found in the .env file")
        return []

    # Calculate the timestamp for X days ago
    since_date = (datetime.utcnow() - timedelta(days=days_back)).isoformat()
    
    # URL for subscribed pulses with filtering
    # Note: OTX API uses 'modified_since' to get pulses updated after a specific time
    url = "https://otx.alienvault.com/api/v1/pulses/subscribed"
    headers = {"X-OTX-API-KEY": api_key}
    params = {
        "limit": limit,
        "modified_since": since_date 
    }

    normalized_data = []
    
    try:
        response = requests.get(url, headers=headers, params=params, timeout=15)
        response.raise_for_status()
        
        data = response.json()
        pulses = data.get("results", [])
        print(f"[+] OTX API call successful! Found {len(pulses)} pulses updated since {since_date}.")
        
        for pulse in pulses:
            # 1. Extract IOCs
            raw_iocs = []
            for indicator in pulse.get("indicators", []):
                ioc_type = indicator.get("type")
                ioc_value = indicator.get("indicator")
                if ioc_type in ["IPv4", "domain", "hostname", "FileHash-MD5", "FileHash-SHA256"]:
                    raw_iocs.append(f"{ioc_type}:{ioc_value}")
            
            # Calculate Base Confidence
            base_confidence = 0.85 if len(raw_iocs) > 0 else 0.70

            # 2. Normalize EXACTLY according to the Database Schema
            item = {
                "id": f"otx_{pulse.get('id')}",
                "source": "AlienVault OTX",
                "source_type": "Threat Feed",
                "title": pulse.get("name", "Untitled Pulse"),
                "url": f"https://otx.alienvault.com/pulse/{pulse.get('id')}",
                "content": pulse.get("description", ""),
                "lang": "en",
                "raw_iocs": json.dumps(raw_iocs),
                "ttp_mapping": "[]",
                "confidence": base_confidence,
                "relevance_score": 0.0,
                "processed": 0,
                "report_done": 0,
                "collected_at": datetime.utcnow().isoformat()
            }
            normalized_data.append(item)
            
        return normalized_data
            
    except requests.exceptions.RequestException as e:
        print(f"[-] Network connection error when calling OTX: {e}")
        return []
    except Exception as e:
        print(f"[-] System error when processing OTX data: {e}")
        return []

# ==========================================
# TEST BLOCK
# ==========================================
if __name__ == "__main__":
    print("--- Running standalone test for the OTX module (3 days, limit 1000) ---")
    
    test_data = fetch_otx_pulses(limit=1000, days_back=3)
    
    print(f"\n[+] Successfully fetched and normalized {len(test_data)} records.")
    if test_data:
        print("--- Preview of the first record's data ---")
        print(json.dumps(test_data[0], indent=4, ensure_ascii=False))