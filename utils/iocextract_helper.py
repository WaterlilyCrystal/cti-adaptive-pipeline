"""
IOC extraction wrapper.
Sinh viên B implement.
"""
import re
try:
    import iocextract
    HAS_IOCEXTRACT = True
except ImportError:
    HAS_IOCEXTRACT = False

PRIVATE_IP_PREFIXES = ("10.", "172.16.", "172.17.", "192.168.", "127.")


def extract_iocs(text: str) -> dict:
    """Bóc tách tất cả IOC từ text, defang tự động."""
    if not HAS_IOCEXTRACT:
        # Fallback regex nếu chưa cài iocextract
        return _regex_fallback(text)

    iocs = {
        "ips":     list(set(iocextract.extract_ips(text, refang=True))),
        "domains": list(set(iocextract.extract_urls(text, refang=True))),
        "md5s":    list(set(iocextract.extract_md5s(text))),
        "sha256s": list(set(iocextract.extract_sha256s(text))),
        "emails":  list(set(iocextract.extract_emails(text))),
        "cves":    list(set(re.findall(r"CVE-\d{4}-\d{4,7}", text))),
        "mitre":   list(set(re.findall(r"\bT\d{4}(?:\.\d{3})?\b", text))),
    }
    # Filter IP private
    iocs["ips"] = [ip for ip in iocs["ips"]
                   if not any(ip.startswith(p) for p in PRIVATE_IP_PREFIXES)]
    # Chỉ giữ key có giá trị
    return {k: v for k, v in iocs.items() if v}


def _regex_fallback(text: str) -> dict:
    """Fallback khi iocextract chưa được cài."""
    return {
        "cves":  list(set(re.findall(r"CVE-\d{4}-\d{4,7}", text))),
        "mitre": list(set(re.findall(r"\bT\d{4}(?:\.\d{3})?\b", text))),
    }