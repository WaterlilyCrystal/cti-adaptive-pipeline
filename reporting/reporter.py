import json
import logging
import os
from datetime import datetime

from analysis.ollama_client import OllamaServiceError, generate_text

logger = logging.getLogger("reporter")
REPORT_KEYS = ("executive", "technical", "operational")

REPORT_GUARDRAILS = {
    "en": """
You must write a grounded cyber threat report using only the facts explicitly present in the provided data.

Rules:
1. Do not invent CVEs, IOCs, vendors, products, versions, threat actors, exploitation status, mitigations, or impacted assets.
2. If evidence is missing or ambiguous, say "Not enough evidence in the provided data" instead of guessing.
3. Do not claim active exploitation unless the provided data explicitly supports it.
4. Do not recommend destructive or high-risk actions unless they are directly justified by the provided data.
5. Separate observed facts from analyst interpretation.
6. Be concise, professional, and operationally safe.
7. End the report with a short verification notice telling the reader to validate the information carefully before taking action.
""".strip(),
    "vi": """
Bạn phải viết báo cáo an ninh mạng bám sát dữ liệu được cung cấp.

Quy tắc:
1. Không được bịa CVE, IOC, nhà cung cấp, sản phẩm, phiên bản, nhóm đe doạ, tình trạng khai thác, biện pháp khắc phục, hoặc tài sản bị ảnh hưởng.
2. Nếu thiếu bằng chứng hoặc dữ liệu mơ hồ, phải ghi rõ "Chưa đủ bằng chứng trong dữ liệu được cung cấp" thay vì suy đoán.
3. Không được khẳng định đang bị khai thác thực tế nếu dữ liệu không nêu rõ.
4. Không được đưa ra khuyến nghị rủi ro cao hoặc có tính phá huỷ nếu dữ liệu không đủ cơ sở.
5. Phải tách bạch giữa dữ kiện quan sát được và nhận định phân tích.
6. Giọng văn phải chuyên nghiệp, ngắn gọn, an toàn khi vận hành.
7. Cuối báo cáo phải có lưu ý yêu cầu người đọc kiểm chứng và xác thực kỹ thông tin trước khi hành động.
""".strip(),
}

EXEC_SYSTEM = {
    "en": """
You are a Chief Information Security Officer (CISO) writing for SME leadership.
Write an executive summary in English using Markdown.

Required structure:
- Overview
- Business Risk
- Immediate Next Step
- Verification Notice

Keep it readable for non-technical decision makers.
""".strip(),
    "vi": """
Bạn là cố vấn an ninh thông tin viết cho lãnh đạo doanh nghiệp vừa và nhỏ.
Hãy viết tóm tắt điều hành bằng tiếng Việt có dấu, dùng Markdown.

Cấu trúc bắt buộc:
- Tổng quan
- Rủi ro kinh doanh
- Hành động tiếp theo ngay lúc này
- Lưu ý kiểm chứng

Văn phong phải dễ hiểu với người không chuyên sâu kỹ thuật.
""".strip(),
}

TECH_SYSTEM = {
    "en": """
You are a Senior Threat Intelligence Analyst writing a technical report in English for SOC analysts.
Use Markdown with clear headings.

Required structure:
- Confirmed Facts
- Technical Assessment
- Observed IOCs and Artifacts
- MITRE ATT&CK Mapping
- Assumptions and Gaps
- Verification Notice

Only list IOCs, techniques, and technical claims that are present in the provided data.
""".strip(),
    "vi": """
Bạn là chuyên gia phân tích tình báo đe doạ, viết báo cáo kỹ thuật bằng tiếng Việt có dấu cho SOC.
Hãy dùng Markdown với tiêu đề rõ ràng.

Cấu trúc bắt buộc:
- Dữ kiện đã xác nhận
- Đánh giá kỹ thuật
- IOC và tạo tác quan sát được
- Ánh xạ MITRE ATT&CK
- Giả định và khoảng trống thông tin
- Lưu ý kiểm chứng

Chỉ được nêu IOC, kỹ thuật và kết luận kỹ thuật có trong dữ liệu được cung cấp.
""".strip(),
}

OPS_SYSTEM = {
    "en": """
You are a Security Operations Lead writing an operational response plan in English.
Use Markdown bullets only.

Required structure:
- Safe Immediate Checks
- Containment or Mitigation Actions
- Monitoring Actions
- What Must Be Verified First
- Verification Notice

Only recommend actions that are justified by the provided data. If a recommendation depends on missing context, explicitly say it requires validation first.
""".strip(),
    "vi": """
Bạn là trưởng nhóm vận hành an ninh, viết kế hoạch ứng phó bằng tiếng Việt có dấu.
Chỉ dùng Markdown dạng bullet.

Cấu trúc bắt buộc:
- Kiểm tra an toàn cần làm ngay
- Hành động cô lập hoặc giảm thiểu
- Hành động giám sát
- Những gì phải xác thực trước
- Lưu ý kiểm chứng

Chỉ được khuyến nghị hành động khi dữ liệu có đủ cơ sở. Nếu còn thiếu ngữ cảnh, phải nói rõ cần xác thực trước khi thực hiện.
""".strip(),
}


def _compose_system_prompt(base_prompt: str, language: str) -> str:
    guardrails = REPORT_GUARDRAILS.get(language, REPORT_GUARDRAILS["en"])
    return f"{base_prompt}\n\n{guardrails}"


def _verification_notice(language: str, bullet: bool = False) -> str:
    if language == "vi":
        line = "Lưu ý kiểm chứng: Hãy xác thực kỹ nguồn, phạm vi ảnh hưởng, phiên bản bị tác động và điều kiện khai thác trước khi thực hiện bất kỳ hành động vận hành nào."
    else:
        line = "Verification Notice: Validate the source, affected scope, impacted versions, and exploitation conditions carefully before taking any operational action."
    return f"- {line}" if bullet else f"## {'Lưu ý kiểm chứng' if language == 'vi' else 'Verification Notice'}\n\n{line}\n"


def _report_title(language: str, kind: str) -> str:
    mapping = {
        "en": {
            "executive": "Executive Summary",
            "technical": "Technical Report",
            "operational": "Operational Plan",
            "facts": "Confirmed Facts",
            "assessment": "Technical Assessment",
            "iocs": "Observed IOCs and Artifacts",
            "mitre": "MITRE ATT&CK Mapping",
            "gaps": "Assumptions and Gaps",
        },
        "vi": {
            "executive": "Tóm tắt điều hành",
            "technical": "Báo cáo kỹ thuật",
            "operational": "Kế hoạch vận hành",
            "facts": "Dữ kiện đã xác nhận",
            "assessment": "Đánh giá kỹ thuật",
            "iocs": "IOC và tạo tác quan sát được",
            "mitre": "Ánh xạ MITRE ATT&CK",
            "gaps": "Giả định và khoảng trống thông tin",
        },
    }
    return mapping.get(language, mapping["en"]).get(kind, kind)


def _top_list(values, limit: int = 8) -> list:
    cleaned = []
    for value in values or []:
        text = str(value).strip()
        if text and text not in cleaned:
            cleaned.append(text)
        if len(cleaned) >= limit:
            break
    return cleaned


def _clip_text(value: str, limit: int = 280) -> str:
    text = str(value or "").strip()
    if len(text) <= limit:
        return text
    return text[: limit - 3].rstrip() + "..."


def _compact_ttps(threat_data: dict, limit: int = 8) -> list[dict]:
    results = []
    for ttp in threat_data.get("validated_ttps", []) or []:
        compact = {}
        if ttp.get("technique_id"):
            compact["technique_id"] = _clip_text(ttp["technique_id"], 32)
        if ttp.get("technique_name_official"):
            compact["technique_name"] = _clip_text(ttp["technique_name_official"], 96)
        if ttp.get("confidence"):
            compact["confidence"] = _clip_text(ttp["confidence"], 16)
        if compact:
            results.append(compact)
        if len(results) >= limit:
            break
    return results


def _build_report_context(threat_data: dict, iocs: dict, report_title: str) -> str:
    context_dict = {
        "title": report_title,
        "report_date": datetime.now().strftime("%Y-%m-%d"),
        "severity": _clip_text(threat_data.get("severity", ""), 16),
        "summary_one_line": _clip_text(threat_data.get("summary_one_line", ""), 280),
        "attack_vector": _clip_text(threat_data.get("attack_vector", ""), 280),
        "is_new_threat": threat_data.get("is_new_threat", ""),
        "threat_actors": [_clip_text(v, 64) for v in _top_list(threat_data.get("threat_actors", []), limit=5)],
        "malware_families": [_clip_text(v, 64) for v in _top_list(threat_data.get("malware_families", []), limit=5)],
        "validated_ttps": _compact_ttps(threat_data, limit=6),
        "iocs": {
            "cves": [_clip_text(v, 32) for v in _top_list(iocs.get("cves", []), limit=10)],
            "ips": [_clip_text(v, 64) for v in _top_list(iocs.get("ips", []), limit=10)],
            "domains": [_clip_text(v, 96) for v in _top_list(iocs.get("domains", []), limit=10)],
            "urls": [_clip_text(v, 160) for v in _top_list(iocs.get("urls", []), limit=8)],
            "hashes": [_clip_text(v, 96) for v in _top_list(iocs.get("hashes", []), limit=8)],
        },
    }
    payload = json.dumps(context_dict, indent=2, ensure_ascii=False)
    logger.info("Report context prepared for %r (%s chars).", report_title[:120], len(payload))
    return payload


def call_llm_for_report(
    system_prompt: str,
    data_context: str,
    max_tokens: int = 400,
    cfg: dict | None = None,
    label: str = "report",
    num_ctx_override: int = 2048,
    timeout_override: int = 45,
) -> str:
    try:
        return generate_text(
            prompt=(
                "Generate the requested report strictly from the following threat intelligence data. "
                "If the data is incomplete, explicitly state the limitation instead of guessing.\n\n"
                f"{data_context}"
            ),
            system=system_prompt,
            temperature=0.05,
            max_tokens=max_tokens,
            cfg=cfg,
            request_label=label,
            trigger_cooldown=False,
            num_ctx_override=num_ctx_override,
            timeout_override=timeout_override,
        ).strip()
    except OllamaServiceError as exc:
        logger.error("Report generation failed: %s", exc, exc_info=True)
        return ""


def generate_executive_summary(threat_data: dict, iocs: dict, language: str = "en", cfg: dict | None = None) -> str:
    fallback = _fallback_report(threat_data, iocs, threat_data.get("summary_one_line") or "Threat report", language)
    content = call_llm_for_report(
        _compose_system_prompt(EXEC_SYSTEM.get(language, EXEC_SYSTEM["en"]), language),
        _build_report_context(threat_data, iocs, threat_data.get("summary_one_line") or "Threat report"),
        max_tokens=220,
        cfg=cfg,
        label=f"executive-summary-{language}",
        num_ctx_override=1536,
        timeout_override=45,
    )
    return _sanitize_report_content(content, fallback["executive"], language, bullet=False)


def _fallback_report(threat_data: dict, iocs: dict, report_title: str, language: str = "en") -> dict:
    severity = threat_data.get("severity", "low")
    summary = threat_data.get("summary_one_line") or report_title
    attack_vector = threat_data.get("attack_vector", "")
    techniques = threat_data.get("validated_ttps", []) or []
    technique_lines = [
        f"- {ttp.get('technique_id', '')}: {ttp.get('technique_name_official', '')}".strip()
        for ttp in techniques
        if ttp.get("technique_id") or ttp.get("technique_name_official")
    ]
    ioc_lines = []
    for key in ["cves", "ips", "domains", "urls", "hashes"]:
        values = iocs.get(key, []) or []
        if values:
            ioc_lines.append(f"- {key}: {', '.join(values[:10])}")

    if language == "vi":
        executive = (
            f"## {_report_title(language, 'executive')}\n\n"
            f"**Mức độ nghiêm trọng:** {severity}\n\n"
            f"## Tổng quan\n\n{summary}\n\n"
            f"## Rủi ro kinh doanh\n\n"
            "Thông tin hiện có cho thấy đây là một mục cần được đối chiếu với tài sản thực tế trước khi ưu tiên xử lý.\n\n"
            f"## Hành động tiếp theo ngay lúc này\n\n"
            "- Kiểm tra xem công nghệ hoặc sản phẩm liên quan có tồn tại trong môi trường hay không.\n"
            "- Chỉ nâng mức ưu tiên sau khi xác thực phạm vi ảnh hưởng.\n\n"
            f"{_verification_notice(language, bullet=False)}"
        )
        technical = (
            f"## {_report_title(language, 'technical')}\n\n"
            f"### {_report_title(language, 'facts')}\n\n"
            f"- Mức độ nghiêm trọng được lưu: {severity}\n"
            f"- Attack vector: {attack_vector or 'Chưa đủ bằng chứng trong dữ liệu được cung cấp'}\n\n"
            f"### {_report_title(language, 'iocs')}\n\n"
            f"{chr(10).join(ioc_lines) if ioc_lines else '- Chưa có IOC cụ thể được trích xuất từ dữ liệu hiện có.'}\n\n"
            f"### {_report_title(language, 'mitre')}\n\n"
            f"{chr(10).join(technique_lines) if technique_lines else '- Chưa có kỹ thuật MITRE ATT&CK nào được xác nhận.'}\n\n"
            f"### {_report_title(language, 'gaps')}\n\n"
            "- Chưa đủ bằng chứng trong dữ liệu được cung cấp để kết luận thêm về điều kiện khai thác hoặc phạm vi ảnh hưởng.\n\n"
            f"{_verification_notice(language, bullet=False)}"
        )
        operational = (
            f"## {_report_title(language, 'operational')}\n\n"
            "- Kiểm tra tài sản và phiên bản liên quan trước khi thay đổi cấu hình hoặc vá lỗi.\n"
            "- Nếu có công nghệ trùng khớp, ưu tiên rà soát mức độ phơi bày và biện pháp giảm thiểu chính thức từ nhà cung cấp.\n"
            "- Theo dõi log và chỉ báo đã xác nhận; không triển khai chặn IOC không có trong dữ liệu.\n"
            f"{_verification_notice(language, bullet=True)}\n"
        )
    else:
        executive = (
            f"## {_report_title(language, 'executive')}\n\n"
            f"**Severity:** {severity}\n\n"
            f"## Overview\n\n{summary}\n\n"
            "## Business Risk\n\n"
            "The current record should be validated against the real environment before it is treated as an urgent exposure.\n\n"
            "## Immediate Next Step\n\n"
            "- Check whether the referenced product or technology exists in scope.\n"
            "- Raise priority only after validating actual exposure.\n\n"
            f"{_verification_notice(language, bullet=False)}"
        )
        technical = (
            f"## {_report_title(language, 'technical')}\n\n"
            f"### {_report_title(language, 'facts')}\n\n"
            f"- Stored severity: {severity}\n"
            f"- Attack vector: {attack_vector or 'Not enough evidence in the provided data'}\n\n"
            f"### {_report_title(language, 'iocs')}\n\n"
            f"{chr(10).join(ioc_lines) if ioc_lines else '- No concrete IOCs were extracted from the current data.'}\n\n"
            f"### {_report_title(language, 'mitre')}\n\n"
            f"{chr(10).join(technique_lines) if technique_lines else '- No MITRE ATT&CK technique has been validated.'}\n\n"
            f"### {_report_title(language, 'gaps')}\n\n"
            "- Not enough evidence in the provided data to make stronger claims about exploitation path or impact scope.\n\n"
            f"{_verification_notice(language, bullet=False)}"
        )
        operational = (
            f"## {_report_title(language, 'operational')}\n\n"
            "- Validate the affected asset and version before making configuration or patch changes.\n"
            "- If a matching technology is present, review exposure and official vendor guidance first.\n"
            "- Monitor confirmed indicators only; do not block or patch based on unverified assumptions.\n"
            f"{_verification_notice(language, bullet=True)}\n"
        )

    return {
        "executive": executive,
        "technical": technical,
        "operational": operational,
    }


def _sanitize_report_content(content: str, fallback: str, language: str, bullet: bool = False) -> str:
    text = (content or "").strip()
    if not text:
        return fallback
    lowered = text.lower()
    if "llm generation error:" in lowered:
        return fallback
    if lowered.startswith("500 server error:") or lowered.startswith("traceback"):
        return fallback
    verification_marker = "lưu ý kiểm chứng" if language == "vi" else "verification notice"
    if verification_marker not in lowered:
        text = f"{text}\n\n{_verification_notice(language, bullet=bullet)}"
    return text


def _report_mode(cfg: dict | None) -> str:
    return str((cfg or {}).get("reporting", {}).get("mode", "fast")).lower()


def generate_multi_tier_reports(threat_data: dict, iocs: dict, report_title: str, language: str = "en", cfg: dict | None = None):
    print(f"[*] Initializing Multi-Tier Reports for: {report_title}...")
    fallback = _fallback_report(threat_data, iocs, report_title, language)
    mode = _report_mode(cfg)
    if mode in {"off", "template"}:
        save_reports_to_disk(report_title, fallback["executive"], fallback["technical"], fallback["operational"])
        return fallback

    data_context = _build_report_context(threat_data, iocs, report_title)

    exec_report = call_llm_for_report(
        _compose_system_prompt(EXEC_SYSTEM.get(language, EXEC_SYSTEM["en"]), language),
        data_context,
        max_tokens=220,
        cfg=cfg,
        label=f"executive-report-{language}",
        num_ctx_override=1536,
        timeout_override=45,
    )
    exec_report = _sanitize_report_content(exec_report, fallback["executive"], language, bullet=False)

    if mode == "fast":
        reports = {
            "executive": exec_report,
            "technical": fallback["technical"],
            "operational": fallback["operational"],
        }
        save_reports_to_disk(report_title, reports["executive"], reports["technical"], reports["operational"])
        return reports

    tech_report = call_llm_for_report(
        _compose_system_prompt(TECH_SYSTEM.get(language, TECH_SYSTEM["en"]), language),
        data_context,
        max_tokens=420,
        cfg=cfg,
        label=f"technical-report-{language}",
        num_ctx_override=2048,
        timeout_override=50,
    )
    ops_report = call_llm_for_report(
        _compose_system_prompt(OPS_SYSTEM.get(language, OPS_SYSTEM["en"]), language),
        data_context,
        max_tokens=260,
        cfg=cfg,
        label=f"operational-report-{language}",
        num_ctx_override=1536,
        timeout_override=45,
    )
    tech_report = _sanitize_report_content(tech_report, fallback["technical"], language, bullet=False)
    ops_report = _sanitize_report_content(ops_report, fallback["operational"], language, bullet=True)
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
