import json
import logging
import os
from datetime import datetime

from analysis.ollama_client import OllamaServiceError, generate_text

OLLAMA_API_URL = "http://localhost:11434/api/generate"
MODEL_NAME = "qwen2.5:3b-instruct-q4_K_M"
logger = logging.getLogger("reporter")
REPORT_KEYS = ("executive", "technical", "operational")

EXEC_SYSTEM = {
    "en": """You are a Chief Information Security Officer (CISO).
Write a concise executive summary in English for SME leadership.
Focus on business risk, operational impact, and the next action. Use Markdown.""",
    "vi": """Ban la co van an ninh cho doanh nghiep vua va nho.
Hay viet tom tat dieu hanh bang tieng Viet, de hieu cho lanh dao khong ky thuat.
Tap trung vao rui ro kinh doanh, anh huong van hanh, va hanh dong tiep theo. Dung Markdown.""",
}

TECH_SYSTEM = """You are a Senior Threat Intelligence Analyst.
Write a detailed Technical Report for the Security Operations Center.
Focus on attack vectors, CVE details, MITRE ATT&CK techniques, and tactical behavior.
Use Markdown with clear headings."""

OPS_SYSTEM = """You are a Security Operations Lead.
Write a strict, actionable mitigation plan for administrators.
Focus only on actionable items:
- IPs or domains to block
- Specific patching or configuration changes
Use Markdown bullets."""


def call_llm_for_report(system_prompt: str, data_context: str, max_tokens: int = 400, cfg: dict | None = None, label: str = "report") -> str:
    try:
        return generate_text(
            prompt=f"Based on the following threat intelligence data, generate the requested report:\n\n{data_context}",
            system=system_prompt,
            temperature=0.2,
            max_tokens=max_tokens,
            cfg=cfg,
            request_label=label,
        ).strip()
    except OllamaServiceError as exc:
        logger.error("Report generation failed: %s", exc, exc_info=True)
        return ""


def generate_executive_summary(threat_data: dict, iocs: dict, language: str = "en", cfg: dict | None = None) -> str:
    context_dict = {
        "threat_analysis": threat_data,
        "indicators_of_compromise": iocs,
        "report_date": datetime.now().strftime("%Y-%m-%d"),
    }
    return call_llm_for_report(
        EXEC_SYSTEM.get(language, EXEC_SYSTEM["en"]),
        json.dumps(context_dict, indent=2, ensure_ascii=False),
        max_tokens=260,
        cfg=cfg,
        label=f"executive-summary-{language}",
    )


def _fallback_report(threat_data: dict, iocs: dict, report_title: str) -> dict:
    severity = threat_data.get("severity", "low")
    summary = threat_data.get("summary_one_line") or report_title
    techniques = threat_data.get("validated_ttps", []) or []
    technique_lines = [
        f"- {ttp.get('technique_id', '')}: {ttp.get('technique_name_official', '')}".strip()
        for ttp in techniques
    ]
    ioc_lines = []
    for key in ["cves", "ips", "domains", "urls", "hashes"]:
        values = iocs.get(key, []) or []
        if values:
            ioc_lines.append(f"- {key}: {', '.join(values[:10])}")

    executive = f"## Executive Summary\n\nSeverity: **{severity}**\n\n{summary}\n"
    technical = "## Technical Report\n\n"
    technical += f"- Attack vector: {threat_data.get('attack_vector', 'Unknown') or 'Unknown'}\n"
    technical += "\n### MITRE ATT&CK\n"
    technical += "\n".join(technique_lines) if technique_lines else "- No validated technique mapped."
    technical += "\n\n### IOCs\n"
    technical += "\n".join(ioc_lines) if ioc_lines else "- No concrete IOCs extracted."
    operational = "## Operational Plan\n\n"
    operational += "- Review affected assets against the organization profile.\n"
    operational += "- Prioritize patching or exposure reduction for matched technologies.\n"
    operational += "- Monitor logs for the listed indicators and validated ATT&CK behavior.\n"
    return {
        "executive": executive,
        "technical": technical,
        "operational": operational,
    }


def _report_mode(cfg: dict | None) -> str:
    return str((cfg or {}).get("reporting", {}).get("mode", "fast")).lower()


def generate_multi_tier_reports(threat_data: dict, iocs: dict, report_title: str, language: str = "en", cfg: dict | None = None):
    print(f"[*] Initializing Multi-Tier Reports for: {report_title}...")
    fallback = _fallback_report(threat_data, iocs, report_title)
    mode = _report_mode(cfg)
    if mode in {"off", "template"}:
        save_reports_to_disk(report_title, fallback["executive"], fallback["technical"], fallback["operational"])
        return fallback

    context_dict = {
        "threat_analysis": threat_data,
        "indicators_of_compromise": iocs,
        "report_date": datetime.now().strftime("%Y-%m-%d"),
    }
    data_context = json.dumps(context_dict, indent=2, ensure_ascii=False)

    exec_report = call_llm_for_report(
        EXEC_SYSTEM.get(language, EXEC_SYSTEM["en"]),
        data_context,
        max_tokens=300,
        cfg=cfg,
        label=f"executive-report-{language}",
    )
    if not exec_report:
        save_reports_to_disk(report_title, fallback["executive"], fallback["technical"], fallback["operational"])
        return fallback

    if mode == "fast":
        reports = {
            "executive": exec_report,
            "technical": fallback["technical"],
            "operational": fallback["operational"],
        }
        save_reports_to_disk(report_title, reports["executive"], reports["technical"], reports["operational"])
        return reports

    tech_report = call_llm_for_report(TECH_SYSTEM, data_context, max_tokens=600, cfg=cfg, label="technical-report")
    ops_report = call_llm_for_report(OPS_SYSTEM, data_context, max_tokens=350, cfg=cfg, label="operational-report")
    tech_report = tech_report or fallback["technical"]
    ops_report = ops_report or fallback["operational"]
    save_reports_to_disk(report_title, exec_report, tech_report, ops_report)
    return {
        "executive": exec_report,
        "technical": tech_report,
        "operational": ops_report,
    }


def save_reports_to_disk(base_name: str, exec_md: str, tech_md: str, ops_md: str):
    output_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "output", "reports")
    os.makedirs(output_dir, exist_ok=True)
    safe_name = "".join([c if c.isalnum() else "_" for c in base_name]).lower()
    if len(safe_name) > 100:
        safe_name = safe_name[:90] + "_trim"

    files_to_save = {
        f"{safe_name}_01_executive.md": exec_md,
        f"{safe_name}_02_technical.md": tech_md,
        f"{safe_name}_03_operational.md": ops_md,
    }
    for filename, content in files_to_save.items():
        try:
            with open(os.path.join(output_dir, filename), "w", encoding="utf-8") as handle:
                handle.write(content)
        except Exception as exc:
            print(f"      [-] Error saving {filename}: {exc}")
