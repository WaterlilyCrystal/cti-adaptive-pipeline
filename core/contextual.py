"""
Context-aware helpers for organization profile matching, passive discovery,
playbook generation, and alert packaging.
"""
from __future__ import annotations

import json
import os
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List
from urllib.parse import urlparse

import requests
from dotenv import load_dotenv

load_dotenv()


TECH_CATALOG = {
    "operating_systems": [
        "Ubuntu",
        "Windows Server",
        "Debian",
        "CentOS",
        "Red Hat",
        "Linux",
    ],
    "web_servers": [
        "Nginx",
        "Apache",
        "IIS",
        "Tomcat",
        "Caddy",
    ],
    "databases": [
        "MongoDB",
        "PostgreSQL",
        "MySQL",
        "MariaDB",
        "Redis",
        "Elasticsearch",
    ],
    "frameworks": [
        "NodeJS",
        "Express",
        "Django",
        "Flask",
        "Laravel",
        "Spring Boot",
        "React",
        "Vue",
        "WordPress",
        "PHP",
    ],
    "cloud": [
        "AWS",
        "Azure",
        "GCP",
        "Cloudflare",
        "Docker",
        "Kubernetes",
    ],
}

TECH_ALIASES = {
    "Ubuntu 22.04": "Ubuntu",
    "Ubuntu 24.04": "Ubuntu",
    "Windows Server 2019": "Windows Server",
    "Windows Server 2022": "Windows Server",
    "Red Hat Enterprise Linux": "Red Hat",
}


TECH_PATTERNS = {
    "Nginx": [r"\bnginx\b"],
    "Apache": [r"\bapache\b", r"\bhttpd\b"],
    "IIS": [r"\biis\b", r"\bmicrosoft-iis\b"],
    "Tomcat": [r"\btomcat\b"],
    "Caddy": [r"\bcaddy\b"],
    "Ubuntu": [r"\bubuntu\b"],
    "Windows Server": [r"\bwindows server\b"],
    "Debian": [r"\bdebian\b"],
    "CentOS": [r"\bcentos\b"],
    "Red Hat": [r"\bred hat\b", r"\brhel\b"],
    "Linux": [r"\blinux\b"],
    "MongoDB": [r"\bmongodb\b", r"\bmongo\b"],
    "PostgreSQL": [r"\bpostgresql\b", r"\bpostgres\b"],
    "MySQL": [r"\bmysql\b"],
    "MariaDB": [r"\bmariadb\b"],
    "Redis": [r"\bredis\b"],
    "Elasticsearch": [r"\belasticsearch\b"],
    "NodeJS": [r"\bnode\.?js\b", r"\bnodejs\b"],
    "Express": [r"\bexpress\b"],
    "Django": [r"\bdjango\b"],
    "Flask": [r"\bflask\b"],
    "Laravel": [r"\blaravel\b"],
    "Spring Boot": [r"\bspring boot\b"],
    "React": [r"\breact\b"],
    "Vue": [r"\bvue\b", r"\bvue\.js\b"],
    "WordPress": [r"\bwordpress\b", r"\bwp-content\b"],
    "PHP": [r"\bphp\b"],
    "AWS": [r"\baws\b", r"\bamazon web services\b"],
    "Azure": [r"\bazure\b"],
    "GCP": [r"\bgcp\b", r"\bgoogle cloud\b"],
    "Cloudflare": [r"\bcloudflare\b"],
    "Docker": [r"\bdocker\b", r"\bcontainer\b"],
    "Kubernetes": [r"\bkubernetes\b", r"\bk8s\b"],
}


LANG_LABELS = {
    "en": {
        "critical": "Critical",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
        "sleep_red": "Immediate action required",
        "sleep_yellow": "Review needed",
        "sleep_green": "No active matched threat",
    },
    "vi": {
        "critical": "Nghiem trong",
        "high": "Cao",
        "medium": "Trung binh",
        "low": "Thap",
        "sleep_red": "Can xu ly ngay",
        "sleep_yellow": "Can xem xet",
        "sleep_green": "Chua thay de doa phu hop dang mo",
    },
}


def canonicalize_technology_name(value: str) -> str:
    return TECH_ALIASES.get(value, value)


def normalize_tech_stack(tech_stack: Dict | None) -> Dict[str, List[str]]:
    tech_stack = tech_stack or {}
    normalized: Dict[str, List[str]] = {}
    for category, catalog in TECH_CATALOG.items():
        catalog_set = set(catalog)
        values = tech_stack.get(category, []) or []
        cleaned: List[str] = []
        for value in values:
            canonical = canonicalize_technology_name(value)
            if canonical in catalog_set and canonical not in cleaned:
                cleaned.append(canonical)
        normalized[category] = cleaned
    return normalized


def normalize_public_url(value: str) -> str:
    value = (value or "").strip()
    if not value:
        return ""
    if not value.startswith(("http://", "https://")):
        value = f"https://{value}"
    return value


def get_discovery_provider(config: Dict | None = None) -> str:
    config = config or {}
    return (config.get("provider") or os.getenv("TECH_DISCOVERY_PROVIDER") or "none").strip().lower()


def get_discovery_timeout(config: Dict | None = None) -> int:
    config = config or {}
    value = config.get("timeout", os.getenv("TECH_DISCOVERY_TIMEOUT", 10))
    try:
        return max(3, int(value))
    except (TypeError, ValueError):
        return 10


def get_discovery_live_mode(config: Dict | None = None) -> bool:
    config = config or {}
    value = config.get("live", os.getenv("TECH_DISCOVERY_LIVE", "false"))
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _iter_profile_terms(profile: Dict) -> List[str]:
    tech_stack = profile.get("tech_stack") or {}
    terms: List[str] = []
    for key in TECH_CATALOG:
        values = tech_stack.get(key) or profile.get(key) or []
        if isinstance(values, str):
            values = [values]
        for value in values:
            if value and value not in terms:
                terms.append(value)
    return terms


def infer_affected_technologies(text: str) -> List[str]:
    haystack = (text or "").lower()
    matches: List[str] = []
    for name, patterns in TECH_PATTERNS.items():
        if any(re.search(pattern, haystack) for pattern in patterns):
            matches.append(name)
    return matches


def match_profile_to_content(profile: Dict, text: str) -> List[str]:
    haystack = (text or "").lower()
    matched: List[str] = []
    for term in _iter_profile_terms(profile):
        patterns = TECH_PATTERNS.get(term, [rf"\b{re.escape(term.lower())}\b"])
        if any(re.search(pattern, haystack) for pattern in patterns):
            matched.append(term)
    return matched


def determine_zero_day(item: Dict, cti_data: Dict, iocs: Dict) -> bool:
    text = " ".join(
        [
            item.get("title", ""),
            item.get("content", ""),
            cti_data.get("summary_one_line", ""),
            cti_data.get("attack_vector", ""),
        ]
    ).lower()
    indicators = ["0day", "zero-day", "zero day", "actively exploited", "kev", "exploit in the wild"]
    has_hot_keyword = any(keyword in text for keyword in indicators)
    has_recent_cve = any(f"CVE-{datetime.now().year}" in cve for cve in iocs.get("cves", []))
    severity = (cti_data.get("severity") or item.get("severity") or "").lower()
    return severity in {"critical", "high"} and (has_hot_keyword or has_recent_cve)


def passive_discover_technologies(
    public_url: str,
    timeout: int = 10,
    provider: str = "none",
    prefer_live: bool = False,
    builtwith_api_key: str = "",
    wappalyzer_api_key: str = "",
) -> List[Dict]:
    target = normalize_public_url(public_url)
    if not target:
        return []

    discovered = _discover_passive_technologies(target, timeout=timeout)
    provider = (provider or "none").strip().lower()

    if provider == "builtwith":
        provider_items = _discover_with_builtwith(target, timeout=timeout, api_key=builtwith_api_key, prefer_live=prefer_live)
        return _merge_discoveries(discovered, provider_items)
    if provider == "wappalyzer":
        provider_items = _discover_with_wappalyzer(target, timeout=timeout, api_key=wappalyzer_api_key, prefer_live=prefer_live)
        return _merge_discoveries(discovered, provider_items)
    return discovered


def _discover_passive_technologies(public_url: str, timeout: int = 10) -> List[Dict]:
    target = normalize_public_url(public_url)
    if not target:
        return []

    discovered: List[Dict] = []
    try:
        response = requests.get(
            target,
            headers={"User-Agent": "Mozilla/5.0"},
            timeout=timeout,
            allow_redirects=True,
        )
    except requests.RequestException:
        return []

    server_headers = {
        "Server": response.headers.get("Server", ""),
        "X-Powered-By": response.headers.get("X-Powered-By", ""),
        "CF-Cache-Status": response.headers.get("CF-Cache-Status", ""),
    }
    html = response.text[:100000]

    def add(name: str, category: str, evidence: str) -> None:
        if any(item["name"] == name for item in discovered):
            return
        discovered.append({"name": name, "category": category, "evidence": evidence})

    header_blob = " ".join(server_headers.values()).lower()
    for name in TECH_PATTERNS:
        patterns = TECH_PATTERNS[name]
        if any(re.search(pattern, header_blob) for pattern in patterns):
            category = _find_category(name)
            add(name, category, "HTTP headers")

    html_checks = {
        "WordPress": "wp-content",
        "React": "__NEXT_DATA__",
        "Vue": "data-v-",
        "Cloudflare": "cloudflare",
        "PHP": "php",
    }
    html_lower = html.lower()
    for name, needle in html_checks.items():
        if needle.lower() in html_lower:
            add(name, _find_category(name), "HTML fingerprint")

    parsed = urlparse(response.url)
    if parsed.netloc and "cloudflare" in header_blob:
        add("Cloudflare", "cloud", parsed.netloc)

    return discovered


def _discover_with_builtwith(public_url: str, timeout: int, api_key: str = "", prefer_live: bool = False) -> List[Dict]:
    api_key = (api_key or os.getenv("BUILTWITH_API_KEY") or "").strip()
    if not api_key:
        return []

    try:
        response = requests.get(
            "https://api.builtwith.com/v22/api.json",
            params={"KEY": api_key, "LOOKUP": urlparse(public_url).netloc or public_url},
            timeout=timeout,
            headers={"User-Agent": "Mozilla/5.0"},
        )
        response.raise_for_status()
        return _extract_provider_technologies(response.json(), "BuiltWith API")
    except (requests.RequestException, ValueError):
        return []


def _discover_with_wappalyzer(public_url: str, timeout: int, api_key: str = "", prefer_live: bool = False) -> List[Dict]:
    api_key = (api_key or os.getenv("WAPPALYZER_API_KEY") or "").strip()
    if not api_key:
        return []

    try:
        response = requests.get(
            "https://api.wappalyzer.com/v2/lookup/",
            params={
                "urls": public_url,
                "recursive": "false",
                "live": "true" if prefer_live else "false",
            },
            timeout=min(timeout, 30),
            headers={"x-api-key": api_key, "User-Agent": "Mozilla/5.0"},
        )
        response.raise_for_status()
        return _extract_provider_technologies(response.json(), "Wappalyzer API")
    except (requests.RequestException, ValueError):
        return []


def _extract_provider_technologies(payload: Any, evidence: str) -> List[Dict]:
    discovered: List[Dict] = []
    corpus = " ".join(_collect_provider_strings(payload))

    for name in _collect_provider_names(payload):
        _append_discovery(discovered, name, evidence)

    for name in infer_affected_technologies(corpus):
        _append_discovery(discovered, name, evidence)

    return discovered


def _collect_provider_names(payload: Any) -> List[str]:
    names: List[str] = []

    def visit(node: Any) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                if key.lower() == "name" and isinstance(value, str):
                    names.append(value)
                visit(value)
        elif isinstance(node, list):
            for item in node:
                visit(item)

    visit(payload)
    return names


def _collect_provider_strings(payload: Any) -> List[str]:
    values: List[str] = []

    def visit(node: Any) -> None:
        if isinstance(node, dict):
            for value in node.values():
                visit(value)
        elif isinstance(node, list):
            for item in node:
                visit(item)
        elif isinstance(node, str):
            values.append(node)

    visit(payload)
    return values


def _append_discovery(discovered: List[Dict], name: str, evidence: str) -> None:
    canonical = canonicalize_technology_name(name)
    category = _find_category(canonical)
    if category == "other":
        return

    for item in discovered:
        if item["name"] == canonical:
            if evidence not in item["evidence"]:
                item["evidence"] = f"{item['evidence']}; {evidence}"
            return

    discovered.append({"name": canonical, "category": category, "evidence": evidence})


def _merge_discoveries(*groups: List[Dict]) -> List[Dict]:
    merged: List[Dict] = []
    for group in groups:
        for item in group:
            _append_discovery(merged, item["name"], item.get("evidence", "lookup"))
    return merged


def _find_category(name: str) -> str:
    for category, values in TECH_CATALOG.items():
        if name in values:
            return category
    return "other"


def build_mitigation_script(iocs: Dict, matched_assets: List[str], title: str = "") -> str:
    ips = sorted(set(iocs.get("ips", [])))
    domains = sorted(set(iocs.get("domains", []) + iocs.get("urls", [])))
    cves = sorted(set(iocs.get("cves", [])))

    lines = [f"# Mitigation playbook for: {title or 'Threat alert'}"]
    if matched_assets:
        lines.append(f"# Impacted stack: {', '.join(matched_assets)}")

    if ips:
        lines.append("")
        lines.append("# pfSense IP Alias")
        lines.extend(ips)
        lines.append("")
        lines.append("# iptables")
        lines.extend([f"iptables -A INPUT -s {ip} -j DROP" for ip in ips[:10]])

    if domains:
        clean_domains = [domain.replace("http://", "").replace("https://", "") for domain in domains]
        lines.append("")
        lines.append("# Cloudflare WAF expression")
        rules = [f'http.host eq "{domain.strip("/")}"' for domain in clean_domains[:10] if domain]
        if rules:
            lines.append(" or ".join(rules))

    if cves:
        lines.append("")
        lines.append("# Patch focus")
        lines.extend([f"- Validate exposure and patch for {cve}" for cve in cves[:10]])

    if len(lines) == 1:
        lines.append("No concrete IOCs extracted. Apply patch/config guidance from the technical report.")
    return "\n".join(lines)


def create_alert_payload(
    item: Dict,
    cti_data: Dict,
    matched_assets: List[str],
    mitigation_script: str,
    language: str = "en",
) -> Dict:
    labels = LANG_LABELS.get(language, LANG_LABELS["en"])
    severity = (cti_data.get("severity") or item.get("severity") or "low").lower()
    severity_label = labels.get(severity, severity.title())
    summary = cti_data.get("summary_one_line") or item.get("title") or "Threat detected"
    return {
        "title": item.get("title"),
        "severity": severity,
        "severity_label": severity_label,
        "impacted_assets": matched_assets,
        "summary": summary,
        "source": item.get("source"),
        "url": item.get("url"),
        "mitigation_script": mitigation_script,
        "html": (
            f"<h2>{item.get('title')}</h2>"
            f"<p><strong>Severity:</strong> {severity_label}</p>"
            f"<p><strong>Impacted assets:</strong> {', '.join(matched_assets) or 'Unknown'}</p>"
            f"<p>{summary}</p>"
            f"<pre>{mitigation_script}</pre>"
        ),
        "compact_text": f"[{severity_label}] {item.get('title')} | Assets: {', '.join(matched_assets) or 'Unknown'}",
    }


def notification_destinations(cfg: Dict) -> List[Dict]:
    channels = cfg.get("notifications", {})
    results: List[Dict] = []
    for channel in ("slack", "zalo", "email"):
        value = channels.get(channel)
        if not value:
            continue
        if isinstance(value, list):
            for item in value:
                results.append({"channel": channel, "destination": item})
        else:
            results.append({"channel": channel, "destination": value})
    return results


def should_dispatch_immediately(triage_priority: str) -> bool:
    return triage_priority in {"critical", "high"}


def sleep_well_indicator(active_alerts: List[Dict]) -> Dict:
    labels = LANG_LABELS["en"]
    if any(alert.get("triage_priority") == "critical" for alert in active_alerts):
        return {"color": "red", "label": labels["sleep_red"]}
    if active_alerts:
        return {"color": "yellow", "label": labels["sleep_yellow"]}
    return {"color": "green", "label": labels["sleep_green"]}


def watch_window_expiry(hours: int = 12) -> str:
    return (datetime.now(timezone.utc) + timedelta(hours=hours)).isoformat()


def serialize_json(data) -> str:
    return json.dumps(data, ensure_ascii=False)
