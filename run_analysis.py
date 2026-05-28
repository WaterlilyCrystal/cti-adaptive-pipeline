import argparse
import json
import time

from utils import db_handler
from analysis import llm_caller, ttp_mapper, sigma_engine, ioc_extractor
from reporting import reporter

def process_single_item(item: dict, db_conn=None, is_mock: bool = False):
    """
    Linear processing function for a SINGLE threat intelligence feed.
    Executes the full pipeline from IOC extraction to report generation.
    """
    item_id = item.get('id', 'mock_id_123')
    title = item.get('title', 'Unknown Threat')
    content = item.get('content', '')
    
    print(f"\n{'='*60}")
    print(f"🚀 STARTING ANALYSIS: {title}")
    print(f"{'='*60}")
    
    # STEP 1: STATIC IOC EXTRACTION
    print("\n[Step 1] Extracting IOCs via Regex...")
    iocs = ioc_extractor.extract_all_iocs(content)
    print(f"   -> Found: {len(iocs.get('ips', []))} IPs, {len(iocs.get('urls', []))} URLs, {len(iocs.get('cves', []))} CVEs.")

    # STEP 2: SEMANTIC ANALYSIS VIA LLM (JSON)
    print("\n[Step 2] Activating Ollama for CTI semantic analysis...")
    cti_data = llm_caller.extract_cti_data(content)
    
    # STEP 3: MITRE ATT&CK VALIDATION AND ENRICHMENT
    print("\n[Step 3] Validating MITRE codes to prevent AI hallucination...")
    raw_ttps = cti_data.get('suggested_techniques', [])
    valid_ttps = ttp_mapper.validate_and_enrich_ttps(raw_ttps)
    
    # STEP 4: GENERATE REASONING AND DEFENSIVE RULES (SIGMA)
    print("\n[Step 4] Generating behavioral reasoning & Sigma rules...")
    for ttp in valid_ttps:
        tech_id = ttp['technique_id']
        tech_name = ttp.get('technique_name_official', 'Unknown')
        
        # Force AI to cite evidence from the article
        reasoning = llm_caller.generate_reasoning(content, tech_id, tech_name)
        ttp['reasoning'] = reasoning
        print(f"   -> Evidence for {tech_id}: {reasoning[:100]}...")
        
        # Generate Sigma rule if a matching template exists
        sigma_vars = {
            "threat_name": cti_data.get('threat_actors', ['Unknown Threat'])[0] if cti_data.get('threat_actors') else "Unknown Threat",
            "cve_id": iocs.get('cves', ['Unknown-CVE'])[0] if iocs.get('cves') else "Unknown-CVE",
            "ioc_indicator": iocs.get('ips', [''])[0] if iocs.get('ips') else (iocs.get('domains', [''])[0] if iocs.get('domains') else "suspicious_activity"),
            "source_url": item.get('source', 'Internal_CTI_System'),
            "severity": cti_data.get('severity', 'high')
        }
        
        sigma_yaml = sigma_engine.generate_sigma_rule(tech_id, sigma_vars)
        if sigma_yaml:
            safe_filename = f"detect_{tech_id}_{item_id[-6:]}.yml".lower()
            sigma_engine.validate_and_save_yaml(sigma_yaml, safe_filename)
            
            # --- TÍCH HỢP NATIVE DB: Lưu luật Sigma vào database ---
            if not is_mock and db_conn:
                db_handler.save_sigma_rule(db_conn, item_id, tech_id, sigma_yaml)

    # Update the original data with cleaned and evidenced TTPs
    cti_data['validated_ttps'] = valid_ttps

    # STEP 5: MULTI-TIER REPORT EXPORT
    print("\n[Step 5] Generating 3-tier reports (Executive, Technical, Operational)...")
    reporter.generate_multi_tier_reports(cti_data, iocs, title)

    # STEP 6: SAVE TO DATABASE (ONLY RUNS WHEN NOT IN MOCK MODE)
    if not is_mock and db_conn:
        print("\n[Step 6] Updating analysis results back to Database...")
        # Chuyển đổi severity thành điểm relevance giả định (cao = 0.9, thấp = 0.5)
        relevance_score = 0.9 if cti_data.get('severity', '').lower() in ['high', 'critical'] else 0.5
        
        # Gọi chính xác hàm update_analysis từ db_handler của nhóm
        success = db_handler.update_analysis(
            conn=db_conn,
            item_id=item_id,
            raw_iocs=iocs,
            ttp_mapping=valid_ttps,
            relevance=relevance_score
        )
        
        if success:
            print("   -> Database updated successfully (Processed flag set to 1).")
        else:
            print("   [-] Failed to update Database.")
    else:
        print("\n[Step 6] Mock Mode / No DB Connection: Skipping Database update.")

    print(f"\n✅ ANALYSIS COMPLETE: {title}")

def main():
    parser = argparse.ArgumentParser(description="Adaptive CTI Pipeline - Phase 3 & 4 Controller")
    parser.add_argument('--mock', action='store_true', help="Run using mock data (No Database needed)")
    args = parser.parse_args()

    if args.mock:
        print("[*] INITIALIZING MOCK DATA MODE (TESTING)")
        mock_item = {
            "id": "mock_sys_9999",
            "title": "Nginx Zero-Day RCE Exploit by APT29",
            "source": "https://cybersec.news/nginx-0day",
            "content": "We have observed the APT29 threat group utilizing a new unauthenticated RCE vulnerability (CVE-2026-9999) in Nginx 1.25.x. Attackers send a malformed HTTP/2 request to port 443. Once exploited, it drops a web shell payload named '/tmp/.nginx_update' to maintain persistence from IP 185.220.101.45. We highly recommend disabling HTTP/2 immediately.",
        }
        start_time = time.time()
        process_single_item(mock_item, db_conn=None, is_mock=True)
        print(f"\n⏱ Total execution time (Mock): {round(time.time() - start_time, 2)} seconds")
        
    else:
        print("[*] INITIALIZING PRODUCTION PIPELINE")
        
        # --- TÍCH HỢP NATIVE DB: Khởi tạo kết nối và gọi hàm get_pending ---
        conn = db_handler.init_db()
        all_pending_items = db_handler.get_pending(conn)
        
        # Chỉ lấy tối đa 5 bản tin để tránh quá tải LLM trong 1 lần chạy
        items = all_pending_items[:5] 
        
        if not items:
            print("[-] No new articles to analyze in the Database. System going to sleep.")
            conn.close()
            return

        print(f"[+] Found {len(all_pending_items)} pending items. Processing first {len(items)} items...")
        start_time = time.time()
        
        for item in items:
            process_single_item(item, db_conn=conn, is_mock=False)
            
        print(f"\n⏱ Total execution time for {len(items)} articles: {round(time.time() - start_time, 2)} seconds")
        conn.close()

if __name__ == "__main__":
    main()