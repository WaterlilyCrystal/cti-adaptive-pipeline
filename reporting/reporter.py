import os
import json
import requests
from datetime import datetime

# Local Ollama API configuration
OLLAMA_API_URL = "http://localhost:11434/api/generate"
MODEL_NAME = "qwen2.5:7b-instruct-q4_K_M"

# ==============================================================================
# PROMPT TEMPLATES (TAILORED FOR EACH AUDIENCE)
# ==============================================================================

EXEC_SYSTEM = """You are a Chief Information Security Officer (CISO). 
Write a concise Executive Summary (max 3 short paragraphs) for the Board of Directors.
Focus on: Business Risk, Potential Impact (Financial/Reputational), and High-level recommendations.
Do NOT use technical jargon like CVEs or IP addresses. Use Markdown formatting.
End the report with a bold sentence starting with "Executive Action Required:"."""

TECH_SYSTEM = """You are a Senior Threat Intelligence Analyst.
Write a detailed Technical Report for the Security Operations Center (SOC) team.
Focus on: Attack Vectors, CVE details, MITRE ATT&CK techniques, and tactical behavior.
Format:
1. Threat Overview
2. Technical Breakdown
3. Analyzed TTPs
Use Markdown formatting with clear headings and bullet lists. Keep it strictly technical."""

OPS_SYSTEM = """You are a Security Operations Lead.
Write a strict, actionable Mitigation Plan for System Administrators and Network Engineers.
Focus ONLY on actionable items:
- IPs/Domains to block on Firewalls.
- Specific patching or configuration changes.
Keep it bulleted, direct, and instructional. Use Markdown formatting.
Do NOT include background fluff."""

def call_llm_for_report(system_prompt: str, data_context: str, max_tokens: int = 400) -> str:
    """
    Calls the LLM to generate a report.
    Temperature is slightly increased to 0.3 for a smoother writing style.
    num_predict limits the output length to avoid infinite generation loops.
    """
    payload = {
        "model": MODEL_NAME,
        "prompt": f"Based on the following Threat Intelligence data, generate the requested report:\n\n{data_context}",
        "system": system_prompt,
        "stream": False,
        "options": {
            "temperature": 0.3,
            "num_predict": max_tokens # Ngăn chặn AI viết quá dài gây treo máy
        }
    }
    
    try:
        response = requests.post(OLLAMA_API_URL, json=payload, timeout=120)
        response.raise_for_status()
        return response.json().get("response", "").strip()
    except Exception as e:
        return f"[-] LLM Generation Error: {e}"

def generate_multi_tier_reports(threat_data: dict, iocs: dict, report_title: str):
    """
    Receives analyzed data and outputs 3 Markdown (.md) report files.
    """
    print(f"[*] Initializing Multi-Tier Reports for: {report_title}...")
    
    # Combine data into a single JSON context string to feed the AI
    context_dict = {
        "threat_analysis": threat_data,
        "indicators_of_compromise": iocs,
        "report_date": datetime.now().strftime("%Y-%m-%d")
    }
    data_context = json.dumps(context_dict, indent=2)
    
    # Generate the 3 types of reports (with distinct length limits)
    print("      [1/3] Writing Executive Report...")
    exec_report = call_llm_for_report(EXEC_SYSTEM, data_context, max_tokens=300)
    
    print("      [2/3] Writing Technical Report...")
    tech_report = call_llm_for_report(TECH_SYSTEM, data_context, max_tokens=600)
    
    print("      [3/3] Writing Operational Directives...")
    ops_report = call_llm_for_report(OPS_SYSTEM, data_context, max_tokens=350)
    
    # Save files
    save_reports_to_disk(report_title, exec_report, tech_report, ops_report)

def save_reports_to_disk(base_name: str, exec_md: str, tech_md: str, ops_md: str):
    """Saves the 3 text outputs as .md files in the output/reports/ directory."""
    output_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "output", "reports")
    os.makedirs(output_dir, exist_ok=True)
    
    # Normalize filename (remove spaces, convert non-alphanumeric to underscores)
    safe_name = "".join([c if c.isalnum() else "_" for c in base_name]).lower()
    
    # Rút gọn tên file nếu nó quá dài (phòng trường hợp lỗi hệ điều hành)
    if len(safe_name) > 100:
        safe_name = safe_name[:90] + "_trim"
        
    files_to_save = {
        f"{safe_name}_01_executive.md": exec_md,
        f"{safe_name}_02_technical.md": tech_md,
        f"{safe_name}_03_operational.md": ops_md
    }
    
    for filename, content in files_to_save.items():
        file_path = os.path.join(output_dir, filename)
        try:
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(content)
        except Exception as e:
            print(f"      [-] Error saving {filename}: {e}")

# ==================== MOCK TEST (NO DATABASE NEEDED) ====================
if __name__ == "__main__":
    # Mock data simulating what was extracted from previous modules
    mock_threat_data = {
        "is_new_threat": True,
        "severity": "critical",
        "threat_actors": ["APT29"],
        "attack_vector": "Unauthenticated RCE via malformed HTTP/2 request to port 443.",
        "summary_one_line": "APT29 uses new unauthenticated RCE vulnerability in Nginx 1.25.x to drop web shell.",
        "validated_ttps": [
            {"technique_id": "T1505.003", "tactic": "persistence", "name": "Web Shell"}
        ]
    }
    
    mock_iocs = {
        "ips": ["185.220.101.45"],
        "cves": ["CVE-2026-9999"],
        "domains": ["malicious-c2-server.com"]
    }
    
    generate_multi_tier_reports(
        threat_data=mock_threat_data,
        iocs=mock_iocs,
        report_title="Nginx Zero-Day CVE-2026-9999"
    )