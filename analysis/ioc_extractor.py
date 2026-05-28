import iocextract
import re
import ipaddress # Standard Python library for robust IP validation

def refang_text(text: str) -> str:
    """
    Hackers often obfuscate URLs/IPs/Emails (Defang) to evade scanning systems.
    This function restores (Refangs) them to their standard format before scanning.
    EX: hxxp:// -> http://, 192[.]168[.]1[.]1 -> 192.168.1.1
    """
    if not text:
        return ""
    
    # Replace variations of obfuscated dots
    text = re.sub(r'\[\.\]', '.', text)
    text = re.sub(r'\(\.\)', '.', text)
    text = re.sub(r'\{\.\}', '.', text)
    
    # Replace obfuscated @ symbols for emails
    text = re.sub(r'(?i)\[at\]', '@', text)
    text = re.sub(r'(?i)\(at\)', '@', text)
    
    # Restore protocols
    text = re.sub(r'(?i)hxxp', 'http', text)
    text = re.sub(r'(?i)xxtp', 'http', text)
    text = re.sub(r'(?i)meow', 'http', text) # Some threat actors use 'meow' as a protocol
    
    return text

def is_public_ip(ip_str: str) -> bool:
    """
    Uses the built-in ipaddress library to rigorously filter out Private, 
    Loopback, Multicast, and Carrier-Grade NAT IPs.
    Keeps only true Public (Global) IPs that are routable on the Internet.
    """
    try:
        ip = ipaddress.ip_address(ip_str)
        # is_global returns True if the IP is publicly routable (supports IPv4 and IPv6)
        return ip.is_global
    except ValueError:
        # If the string is not a valid IP format
        return False

def extract_all_iocs(raw_content: str) -> dict:
    """
    Main extraction pipeline: Takes raw threat intelligence text and 
    returns a Dictionary containing deduplicated arrays of standardized IOCs.
    """
    if not raw_content:
        return {}

    # Step 1: Refang the text to reverse obfuscation techniques
    clean_text = refang_text(raw_content)

    # Step 2: Use the iocextract library to locate potential indicators
    try:
        raw_ips = list(set(iocextract.extract_ips(clean_text)))
        urls = list(set(iocextract.extract_urls(clean_text))) # Renamed to 'urls' for accuracy
        
        md5s = list(set(iocextract.extract_md5_hashes(clean_text)))
        sha256s = list(set(iocextract.extract_sha256_hashes(clean_text)))
        
        emails = list(set(iocextract.extract_emails(clean_text)))
        
        # Use custom regex for CVEs as iocextract sometimes misses them
        cves = list(set(re.findall(r"(?i)CVE-\d{4}-\d{4,7}", clean_text)))
        cves = [cve.upper() for cve in cves]

        # Step 3: Strictly filter for Public IPs to reduce noise
        public_ips = [ip for ip in raw_ips if is_public_ip(ip)]

        # Step 4: Group results (only keep populated lists)
        iocs = {
            "ips": public_ips,
            "urls": urls,      # Now correctly labeled as urls
            "md5s": md5s,
            "sha256s": sha256s,
            "emails": emails,
            "cves": cves
        }
        
        # Remove empty keys to save Database space and clean up JSON output
        return {k: v for k, v in iocs.items() if v}
        
    except Exception as e:
        print(f"[-] IOC extraction error: {e}")
        return {}

# ==================== STANDALONE TEST ====================
if __name__ == "__main__":
    test_text = """
    Warning: Hackers are distributing malware from hxxps://malicious-site[.]com/payload.exe.
    Contact them at evil_hacker[at]protonmail.com.
    The C2 server is located at IP 192[.]168[.]1[.]100 (LAN network) and 185.220.101.45 (public network).
    The infected file has an MD5 hash of 44d88612fea8a8f36de82e1278abb02f. 
    Exploiting vulnerability cve-2026-12345.
    """
    print("[*] Initiating IOC Extraction Pipeline...")
    result = extract_all_iocs(test_text)
    
    import json
    print("\n[+] Extraction Complete. Results:")
    print(json.dumps(result, indent=4))