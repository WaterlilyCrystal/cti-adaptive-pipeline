import os
import yaml
import uuid
from datetime import datetime

# ==============================================================================
# SIGMA TEMPLATES (STRICT YAML FORMAT)
# ==============================================================================
# We define hardcoded templates to prevent LLM indentation errors.
SIGMA_TEMPLATES = {
    # Rule cho File đính kèm qua mail (T1566.001)
    "T1566.001": """title: Detect Spearphishing Attachment - {threat_name}
id: {rule_id}
status: experimental
description: Detects suspicious email attachments related to {threat_name} based on AI CTI analysis.
references:
    - {source_url}
author: Adaptive CTI Pipeline
date: {current_date}
tags:
    - attack.initial_access
    - attack.t1566.001
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        EventID: 4688
        ParentImage|endswith:
            - '\\outlook.exe'
        CommandLine|contains:
            - '{ioc_indicator}'
    condition: selection
falsepositives:
    - Legitimate user downloading unusual file types.
level: {severity}
""",

    # Rule TỔNG QUÁT cho Phishing Domain/URL (T1566) - Rất hợp với các bài báo Weebly
    "T1566": """title: Detect Phishing Domain Access - {threat_name}
id: {rule_id}
status: experimental
description: Detects network connections or web proxy requests to known phishing domains linked to {threat_name}.
references:
    - {source_url}
author: Adaptive CTI Pipeline
date: {current_date}
tags:
    - attack.initial_access
    - attack.t1566
logsource:
    category: proxy
detection:
    selection:
        c-uri|contains: '{ioc_indicator}'
    condition: selection
falsepositives:
    - Misclassified threat intelligence.
level: {severity}
""",

    "T1059.001": """title: Detect Malicious PowerShell Execution - {threat_name}
id: {rule_id}
status: experimental
description: Detects encoded or hidden PowerShell commands linked to {threat_name}.
references:
    - {source_url}
author: Adaptive CTI Pipeline
date: {current_date}
tags:
    - attack.execution
    - attack.t1059.001
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith: '\\powershell.exe'
        CommandLine|contains|all:
            - '-WindowStyle Hidden'
            - '{ioc_indicator}'
    condition: selection
falsepositives:
    - Admin scripts using hidden windows.
level: {severity}
""",

    "T1190": """title: Exploit Public-Facing Application - {threat_name}
id: {rule_id}
status: experimental
description: Detects exploitation attempts against public-facing apps targeting {cve_id}.
references:
    - {source_url}
author: Adaptive CTI Pipeline
date: {current_date}
tags:
    - attack.initial_access
    - attack.t1190
logsource:
    category: webserver
detection:
    selection:
        c-uri|contains: '{ioc_indicator}'
        sc-status: '200'
    condition: selection
falsepositives:
    - Vulnerability scanners (e.g., Nessus, Qualys).
level: {severity}
"""
}

def generate_sigma_rule(technique_id: str, variables: dict) -> str:
    """
    Fills the predefined Sigma YAML template with threat data.
    Returns the raw YAML string if the template exists, else None.
    """
    # 1. Tìm chính xác mã (VD: T1566.001)
    template = SIGMA_TEMPLATES.get(technique_id)
    
    # 2. CƠ CHẾ FALLBACK: Nếu không có mã con, tìm mã cha (VD: Từ T1566.002 lùi về T1566)
    if not template and "." in technique_id:
        parent_id = technique_id.split(".")[0]
        template = SIGMA_TEMPLATES.get(parent_id)
        if template:
            print(f"[*] Fallback: Dùng template của mã cha {parent_id} cho {technique_id}")

    if not template:
        print(f"[*] No predefined template for technique {technique_id}. Skipping Sigma generation.")
        return None

    # Inject auto-generated fields
    variables["rule_id"] = str(uuid.uuid4())
    variables["current_date"] = datetime.now().strftime("%Y/%m/%d")
    
    try:
        # Fill the template
        sigma_yaml = template.format(**variables)
        return sigma_yaml
    except KeyError as e:
        print(f"[-] Missing required variable for template {technique_id}: {e}")
        return None

def validate_and_save_yaml(yaml_content: str, filename: str) -> bool:
    """
    Validates the generated YAML string to ensure it won't crash the SIEM.
    If valid, saves it to the output directory.
    """
    try:
        # Test if the YAML is structurally sound
        yaml.safe_load(yaml_content)
    except yaml.YAMLError as exc:
        print(f"[-] YAML Validation Failed! Indentation or formatting error:\n{exc}")
        return False

    # Ensure output directory exists
    output_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "output", "sigma_rules")
    os.makedirs(output_dir, exist_ok=True)
    
    # Giới hạn độ dài tên file (tránh lỗi OS giống như bên report)
    if len(filename) > 100:
        name, ext = os.path.splitext(filename)
        filename = f"{name[:90]}_trim{ext}"
    
    file_path = os.path.join(output_dir, filename)
    try:
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(yaml_content)
        print(f"[+] Successfully generated and validated Sigma rule: {file_path}")
        return True
    except Exception as e:
        print(f"[-] Error saving file: {e}")
        return False

# ==================== MOCK TEST (NO DATABASE NEEDED) ====================
if __name__ == "__main__":
    print("--- Starting Sigma Template Engine Test ---")
    
    # Simulate data passed down from the IOC Extractor and MITRE Mapper
    mock_threat_data = {
        "threat_name": "Zero-Day Nginx RCE",
        "cve_id": "CVE-2026-9999",
        "ioc_indicator": "malicious-phishing-site.com", # Thử nghiệm với Domain
        "source_url": "https://twitter.com/security_researcher/status/123",
        "severity": "critical"
    }
    
    # Thử nghiệm với mã T1566.002 (Spearphishing Link) - sẽ tự fallback về T1566
    target_technique = "T1566.002"
    
    print(f"[*] Attempting to generate rule for {target_technique}...")
    
    generated_yaml = generate_sigma_rule(target_technique, mock_threat_data)
    
    if generated_yaml:
        # Validate and save
        safe_filename = f"detect_{mock_threat_data['cve_id'].lower().replace('-', '_')}.yml"
        validate_and_save_yaml(generated_yaml, safe_filename)
        
        print("\n--- Preview of Generated YAML ---")
        print(generated_yaml)