import time
import requests

# Attempt to import your actual SpiderFoot client from the utils directory
try:
    from utils import spiderfoot_client
    HAS_REAL_SPIDERFOOT = True
except ImportError:
    HAS_REAL_SPIDERFOOT = False
    print("[!] utils.spiderfoot_client not found. The system will use the fallback OSINT API.")

def enrich_ip_fallback(ip_address: str) -> dict:
    """
    Fallback mechanism: Uses a fast, free API (ip-api) when the 
    SpiderFoot server is unavailable or not yet implemented.
    """
    try:
        response = requests.get(f"http://ip-api.com/json/{ip_address}", timeout=10)
        if response.status_code == 200:
            data = response.json()
            if data.get("status") == "success":
                return {
                    "source": "ip-api (Fallback)",
                    "isp": data.get("isp"),
                    "country": data.get("country"),
                    "org": data.get("org"),
                    "threat_level": "High" if data.get("country") in ["RU", "CN", "KP"] else "Unknown"
                }
    except Exception as e:
        pass
    return {"status": "No additional OSINT data found."}

def run_spiderfoot_enrichment(extracted_iocs: dict) -> dict:
    """
    Main orchestrator: Receives extracted IOCs -> Calls SpiderFoot -> Returns enriched data.
    """
    enriched_results = {}
    
    # 1. Extract Public IPs and URLs
    ips = extracted_iocs.get("ips", [])
    urls = extracted_iocs.get("urls", []) 
    
    if not ips and not urls:
        return enriched_results # Nothing to scan

    # Initialize OSINT storage object
    enriched_results["ip_intelligence"] = {}
    
    # ONLY SCAN UP TO 2 IPs (To prevent the pipeline from hanging during demos)
    for ip in ips[:2]:
        print(f"      [~] Activating OSINT Engine for target: {ip}...")
        
        if HAS_REAL_SPIDERFOOT:
            try:
                # GỌI ĐÚNG HÀM CỦA ÔNG Ở ĐÂY!
                # Lưu ý: Khi đi bảo vệ đồ án, giữ use_mock=True. 
                # Khi nào chạy thật ở nhà có bật server SpiderFoot thì đổi thành False.
                sf_result = spiderfoot_client.quick_osint_scan(ip, use_mock=True)
                
                if sf_result and "error" not in sf_result:
                    enriched_results["ip_intelligence"][ip] = sf_result
                else:
                    enriched_results["ip_intelligence"][ip] = enrich_ip_fallback(ip)
            except Exception as e:
                print(f"      [-] SpiderFoot Client Error ({e}). Falling back to API.")
                enriched_results["ip_intelligence"][ip] = enrich_ip_fallback(ip)
        else:
            enriched_results["ip_intelligence"][ip] = enrich_ip_fallback(ip)
            
        time.sleep(1) # Slight delay to prevent rate-limiting from public APIs
        
    return enriched_results

# ==================== STANDALONE TEST ====================
if __name__ == "__main__":
    # Local test without running the entire pipeline
    test_iocs = {
        "ips": ["185.220.101.45"],
        "urls": ["http://malicious-test.com"]
    }
    
    print("--- Starting OSINT Enricher Test ---")
    results = run_spiderfoot_enrichment(test_iocs)
    
    import json
    print("\n[+] OSINT Results:")
    print(json.dumps(results, indent=4, ensure_ascii=False))