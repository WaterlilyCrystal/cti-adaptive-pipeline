import argparse
import logging
import time

from analysis import ioc_extractor, llm_caller, osint_enricher, sigma_engine, ttp_mapper
from analysis.ollama_client import OllamaServiceError
from core.contextual import (
    build_mitigation_script,
    create_alert_payload,
    determine_zero_day,
    match_profile_to_content,
    notification_destinations,
    should_dispatch_immediately,
)
from reporting import reporter
from utils import db_handler
from utils.notifications import dispatch_alert

logger = logging.getLogger("run_analysis")


def process_single_item(item: dict, cfg: dict | None = None, db_conn=None, is_mock: bool = False):
    cfg = cfg or {}
    item_id = item.get("id", "mock_id_123")
    title = item.get("title", "Unknown Threat")
    content = item.get("content", "")
    max_content_chars = max(1000, int(cfg.get("pipeline", {}).get("max_content_chars", 5000)))

    print(f"\n{'=' * 60}")
    print(f"STARTING ANALYSIS: {title}")
    print(f"{'=' * 60}")

    print("\n[Step 1] Extracting IOCs via Regex...")
    iocs = ioc_extractor.extract_all_iocs(content)
    print(f"   -> Found: {len(iocs.get('ips', []))} IPs, {len(iocs.get('urls', []))} URLs, {len(iocs.get('cves', []))} CVEs.")

    print("\n[Step 1.5] Triggering OSINT Enrichment...")
    osint_data = osint_enricher.run_spiderfoot_enrichment(iocs)
    enriched_content = content[:max_content_chars]
    if osint_data:
        import json

        osint_blob = json.dumps(osint_data, ensure_ascii=False)[: max_content_chars // 2]
        enriched_content = f"{enriched_content}\n\n--- OSINT ENRICHMENT DATA ---\n{osint_blob}"[: max_content_chars + max_content_chars // 2]
        print("   -> Successfully enriched intelligence with OSINT data.")

    print("\n[Step 2] Activating Ollama for CTI semantic analysis...")
    cti_data = llm_caller.extract_cti_data(enriched_content, item_id=item_id, title=title, cfg=cfg)
    if cti_data.get("_analysis_failed"):
        raise OllamaServiceError(f"CTI extraction produced unusable output for item_id={item_id}")

    print("\n[Step 3] Validating MITRE codes...")
    raw_ttps = cti_data.get("suggested_techniques", [])
    valid_ttps = ttp_mapper.validate_and_enrich_ttps(raw_ttps, evidence_text=f"{title}\n{enriched_content}")

    print("\n[Step 4] Generating behavioral reasoning & Sigma rules...")
    for ttp in valid_ttps:
        tech_id = ttp["technique_id"]
        tech_name = ttp.get("technique_name_official", "Unknown")
        reasoning = ttp.get("evidence", "")
        if not reasoning:
            reasoning = llm_caller.generate_reasoning(enriched_content, tech_id, tech_name, cfg=cfg)
        ttp["reasoning"] = reasoning

        sigma_vars = {
            "threat_name": cti_data.get("threat_actors", ["Unknown Threat"])[0] if cti_data.get("threat_actors") else "Unknown Threat",
            "cve_id": iocs.get("cves", ["Unknown-CVE"])[0] if iocs.get("cves") else "Unknown-CVE",
            "ioc_indicator": iocs.get("ips", [""])[0] if iocs.get("ips") else (iocs.get("urls", [""])[0] if iocs.get("urls") else "suspicious_activity"),
            "source_url": item.get("source", "Internal_CTI_System"),
            "severity": cti_data.get("severity", "high"),
        }
        sigma_yaml = sigma_engine.generate_sigma_rule(tech_id, sigma_vars)
        if sigma_yaml:
            safe_filename = f"detect_{tech_id}_{item_id[-6:]}.yml".lower()
            sigma_engine.validate_and_save_yaml(sigma_yaml, safe_filename)
            if not is_mock and db_conn:
                db_handler.save_sigma_rule(db_conn, item_id, tech_id, sigma_yaml)

    cti_data["validated_ttps"] = valid_ttps

    profile = db_handler.get_active_profile(db_conn) if db_conn else {"preferred_language": "en", "tech_stack": {}}
    context_text = " ".join(
        [
            title,
            content,
            cti_data.get("summary_one_line", ""),
            cti_data.get("attack_vector", ""),
            " ".join(iocs.get("cves", [])),
        ]
    )
    matched_assets = match_profile_to_content(profile, context_text)
    is_zero_day = determine_zero_day(item, cti_data, iocs)
    severity = (cti_data.get("severity") or item.get("severity") or "low").lower()

    triage_priority = "routine"
    triage_status = "archived"
    if matched_assets:
        triage_priority = "critical" if is_zero_day or severity == "critical" else "high"
        triage_status = "critical" if triage_priority == "critical" else "matched"
    elif is_zero_day:
        triage_priority = "high"
        triage_status = "watching"

    mitigation_script = build_mitigation_script(iocs, matched_assets, title=title)
    preferred_language = profile.get("preferred_language", "en")
    notification_payload = create_alert_payload(item, cti_data, matched_assets, mitigation_script, language=preferred_language)

    print("\n[Step 5] Generating reports...")
    reports = reporter.generate_multi_tier_reports(cti_data, iocs, title, language=preferred_language, cfg=cfg)
    generate_secondary_summaries = bool((cfg.get("reporting") or {}).get("generate_secondary_language_summary", False))
    if reports["executive"] and generate_secondary_summaries:
        executive_vi = reports["executive"] if preferred_language == "vi" else reporter.generate_executive_summary(cti_data, iocs, language="vi", cfg=cfg)
        executive_en = reports["executive"] if preferred_language == "en" else reporter.generate_executive_summary(cti_data, iocs, language="en", cfg=cfg)
    else:
        executive_vi = reports["executive"] if preferred_language == "vi" else ""
        executive_en = reports["executive"] if preferred_language == "en" else ""

    if not is_mock and db_conn:
        print("\n[Step 6] Updating analysis results back to Database...")
        relevance_score = 0.95 if triage_priority == "critical" else (0.8 if matched_assets else 0.45)
        success = db_handler.update_analysis(
            conn=db_conn,
            item_id=item_id,
            raw_iocs=iocs,
            ttp_mapping=valid_ttps,
            relevance=relevance_score,
            severity=severity,
            impacted_assets=matched_assets,
            mitigation_script=mitigation_script,
            notification_payload=notification_payload,
            triage_status=triage_status,
            triage_priority=triage_priority,
            executive_summary_en=executive_en,
            executive_summary_vi=executive_vi,
        )
        if success and matched_assets:
            db_handler.record_profile_match(
                db_conn,
                intel_id=item_id,
                matched_terms=matched_assets,
                source=item.get("source", ""),
                severity=severity,
                is_zero_day=is_zero_day,
                confidence=float(item.get("credibility_score") or item.get("confidence") or relevance_score),
            )

        if success and should_dispatch_immediately(triage_priority):
            print("\n[Step 7] Dispatching notifications...")
            results = dispatch_alert(notification_payload, notification_destinations(cfg))
            for result in results:
                db_handler.save_notification_event(
                    db_conn,
                    intel_id=item_id,
                    channel=result["channel"],
                    destination=str(result["destination"]),
                    payload=notification_payload,
                    status=result["status"],
                )

    print(f"\nANALYSIS COMPLETE: {title}")


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(name)s - %(message)s")
    parser = argparse.ArgumentParser(description="Adaptive CTI Pipeline - Phase 3 & 4 Controller")
    parser.add_argument("--mock", action="store_true", help="Run using mock data (No Database needed)")
    args = parser.parse_args()

    if args.mock:
        print("[*] INITIALIZING MOCK DATA MODE")
        mock_item = {
            "id": "mock_sys_9999",
            "title": "Nginx Zero-Day RCE Exploit by APT29",
            "source": "https://cybersec.news/nginx-0day",
            "content": "We observed APT29 using CVE-2026-9999 in Nginx 1.25.x with malformed HTTP/2 requests on port 443 from 185.220.101.45. Disable HTTP/2 immediately.",
        }
        start_time = time.time()
        process_single_item(mock_item, cfg={}, db_conn=None, is_mock=True)
        print(f"\nTotal execution time (Mock): {round(time.time() - start_time, 2)} seconds")
        return

    print("[*] INITIALIZING PRODUCTION PIPELINE")
    conn = db_handler.init_db()
    all_pending_items = db_handler.get_pending(conn)
    items = all_pending_items[:5]
    if not items:
        print("[-] No new articles to analyze in the Database. System going to sleep.")
        conn.close()
        return

    start_time = time.time()
    for item in items:
        process_single_item(item, cfg={}, db_conn=conn, is_mock=False)
    print(f"\nTotal execution time for {len(items)} articles: {round(time.time() - start_time, 2)} seconds")
    conn.close()


if __name__ == "__main__":
    main()
