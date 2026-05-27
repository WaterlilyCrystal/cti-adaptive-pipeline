import iocextract
import re

def refang_text(text: str) -> str:
    """
    Hackers often obfuscate URLs/IPs (Defang) to evade scanning systems.
    This function restores (Refangs) them to their standard format before scanning.
    EX: hxxp:// -> http://, 192[.]168[.]1[.]1 -> 192.168.1.1
    """
    if not text:
        return ""
    
    # Replace variations of obfuscated dots
    text = re.sub(r'\[\.\]', '.', text)
    text = re.sub(r'\(\.\)', '.', text)
    text = re.sub(r'\{\.\}', '.', text)
    
    # Restore protocols
    text = re.sub(r'(?i)hxxp', 'http', text)
    text = re.sub(r'(?i)xxtp', 'http', text)
    text = re.sub(r'(?i)meow', 'http', text) # Some threat actors use 'meow' as a protocol
    
    return text

def is_public_ip(ip: str) -> bool:
    """
    Filter out internal network IP addresses (Private IPs), loopback IPs, or noise.
    Keep only true Public IPs exposed to the Internet.
    """
    private_prefixes = (
        "10.", "127.", "169.254.", "192.168.", 
        "172.16.", "172.17.", "172.18.", "172.19.", 
        "172.20.", "172.21.", "172.22.", "172.23.", 
        "172.24.", "172.25.", "172.26.", "172.27.", 
        "172.28.", "172.29.", "172.30.", "172.31."
    )
    return not ip.startswith(private_prefixes)

def extract_all_iocs(raw_content: str) -> dict:
    """
    Main function: Takes raw text -> Returns a Dictionary containing clean arrays of IOCs.
    """
    if not raw_content:
        return {}

    # Step 1: Refang the text
    clean_text = refang_text(raw_content)

    # Step 2: Use the iocextract library for extraction
    try:
        raw_ips = list(set(iocextract.extract_ips(clean_text)))
        domains = list(set(iocextract.extract_urls(clean_text)))
        
        # CHỖ ĐƯỢC FIX LÀ Ở ĐÂY: Dùng _hashes thay vì thêm chữ s
        md5s = list(set(iocextract.extract_md5_hashes(clean_text)))
        sha256s = list(set(iocextract.extract_sha256_hashes(clean_text)))
        
        emails = list(set(iocextract.extract_emails(clean_text)))
        
        # Use custom regex for CVEs as iocextract sometimes misses them
        cves = list(set(re.findall(r"(?i)CVE-\d{4}-\d{4,7}", clean_text)))
        cves = [cve.upper() for cve in cves]

        # Step 3: Filter for Public IPs
        public_ips = [ip for ip in raw_ips if is_public_ip(ip)]

        # Step 4: Group results (only keep populated lists)
        iocs = {
            "ips": public_ips,
            "domains": domains,
            "md5s": md5s,
            "sha256s": sha256s,
            "emails": emails,
            "cves": cves
        }
        
        # Remove empty keys to save DB space
        return {k: v for k, v in iocs.items() if v}
        
    except Exception as e:
        print(f"[-] IOC extraction error: {e}")
        return {}

# ==================== STANDALONE TEST ====================
if __name__ == "__main__":
    test_text = """
    Warning: Hackers are distributing malware from hxxps://malicious-site[.]com/payload.exe.
    The C2 server is located at IP 192[.]168[.]1[.]100 (LAN network) and 185.220.101.45 (public network).
    The infected file has an MD5 hash of 44d88612fea8a8f36de82e1278abb02f. 
    Exploiting vulnerability cve-2026-12345.
    """
    print("Extracting...")
    result = extract_all_iocs(test_text)
    import json
    print(json.dumps(result, indent=4))