import os
import json
import requests
from datetime import datetime, timedelta
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

def fetch_nvd_cves_recent(limit: int = 1000, days: int = 3) -> list:
    """
    Fetch vulnerabilities updated in the last X days, capped at a specific limit.
    """
    print(f"[*] Fetching NVD data: Last {days} days, Limit {limit}...")
    
    api_key = os.getenv("NVD_API_KEY")
    headers = {"apiKey": api_key} if api_key else {}

    # Calculate time window
    now = datetime.utcnow()
    past = now - timedelta(days=days)
    nvd_date_format = "%Y-%m-%dT%H:%M:%S.000-00:00"
    
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        "resultsPerPage": limit,
        "startIndex": 0,
        "noRejected": "",
        "lastModStartDate": past.strftime(nvd_date_format),
        "lastModEndDate": now.strftime(nvd_date_format)
    }

    normalized_data = []
    
    try:
        response = requests.get(url, headers=headers, params=params, timeout=30)
        response.raise_for_status()
        
        data = response.json()
        vulnerabilities = data.get("vulnerabilities", [])
        print(f"[+] Successfully fetched {len(vulnerabilities)} CVEs.")
        
        for item in vulnerabilities:
            cve = item.get("cve", {})
            cve_id = cve.get("id", "Unknown")
            
            # Extract Description
            descriptions = cve.get("descriptions", [])
            en_desc = next((d['value'] for d in descriptions if d['lang'] == 'en'), "No description.")
            
            # Calculate Relevance Score
            metrics = cve.get("metrics", {})
            cvss_data = metrics.get("cvssMetricV31", metrics.get("cvssMetricV30", metrics.get("cvssMetricV2", {})))
            base_score = cvss_data[0].get("cvssData", {}).get("baseScore", 0.0) if cvss_data else 0.0
            relevance = base_score / 10.0

            # Extract CWE
            weaknesses = cve.get("weaknesses", [])
            raw_iocs = [f"CWE:{desc.get('value')}" for w in weaknesses for desc in w.get("description", []) if "CWE" in desc.get("value", "")]

            # Normalize to Schema
            norm_item = {
                "id": f"nvd_{cve_id.replace('-', '_')}",
                "source": "NVD",
                "source_type": "Vulnerability Database",
                "title": f"Vulnerability: {cve_id}",
                "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                "content": en_desc,
                "lang": "en",
                "raw_iocs": json.dumps(raw_iocs),
                "ttp_mapping": "[]",
                "confidence": 1.0,
                "relevance_score": float(relevance),
                "processed": 0,
                "report_done": 0,
                "collected_at": datetime.utcnow().isoformat()
            }
            normalized_data.append(norm_item)
            
        return normalized_data
            
    except Exception as e:
        print(f"[-] Error: {e}")
        return []

# ==========================================
# TEST
# ==========================================
if __name__ == "__main__":
    data = fetch_nvd_cves_recent(limit=1000, days=3)
    print(f"\n[+] Total records collected: {len(data)}")
    if data:
        print(json.dumps(data[0], indent=4, ensure_ascii=False))