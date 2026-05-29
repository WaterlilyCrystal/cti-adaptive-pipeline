import json
import logging

from analysis.ollama_client import OllamaServiceError, generate_text

OLLAMA_API_URL = "http://localhost:11434/api/generate"
MODEL_NAME = "qwen2.5:3b-instruct-q4_K_M"
logger = logging.getLogger("llm_caller")

SYSTEM_PROMPT = """You are a senior Cyber Threat Intelligence (CTI) analyst.
Your task is to analyze threat intelligence reports and extract structured data.
You MUST respond ONLY with valid JSON. Do not include any introductory or concluding text (like "Here is the JSON").
Start your response with '{' and end with '}'."""

ANALYSIS_PROMPT = """Analyze the following threat intelligence content.

CRITICAL RULES FOR MITRE ATT&CK MAPPING:
1. You MUST ONLY extract real, officially documented MITRE ATT&CK technique IDs (e.g., T1566 for Phishing, T1190 for Exploit Public-Facing Application).
2. NEVER invent, guess, or use placeholder codes like 'T1234' or 'T0000'.
3. If you cannot confidently map a real technique, leave the "suggested_techniques" array EMPTY []. Do not hallucinate.

CONTENT:
{content}

Respond with this EXACT JSON structure. If a field is not found, use an empty list [] or empty string "".
{{
  "is_new_threat": true/false,
  "severity": "critical/high/medium/low",
  "threat_actors": ["name1", "name2"],
  "malware_families": ["name1"],
  "attack_vector": "brief description",
  "suggested_techniques": [
    {{
      "technique_id": "T1566",
      "confidence": "high/medium/low"
    }}
  ],
  "summary_one_line": "summary here"
}}"""

REASONING_PROMPT = """Given this threat content and the proposed MITRE ATT&CK technique:

Content: {content}
Technique: {technique_id} - {technique_name}

Explain in 1-2 sentences WHY this content maps to this technique.
You MUST quote the specific behavior from the content that matches.
Format exactly like this: "This maps to {technique_id} because [specific behavior] observed in '[exact quote from text]'."
"""

def extract_cti_data(content: str, item_id: str = "", title: str = "", cfg: dict | None = None) -> dict:
    print("[*] Sending content to LLM for JSON extraction...")
    formatted_prompt = ANALYSIS_PROMPT.format(content=content)
    raw_response = generate_text(
        prompt=formatted_prompt,
        system=SYSTEM_PROMPT,
        temperature=0.1,
        max_tokens=1024,
        cfg=cfg,
        request_label=f"cti extraction item_id={item_id}",
    )
    
    # Clean up the response just in case the LLM added markdown code blocks (```json ... ```)
    raw_response = raw_response.strip()
    if raw_response.startswith("```json"):
        raw_response = raw_response[7:]
    if raw_response.endswith("```"):
        raw_response = raw_response[:-3]
    raw_response = raw_response.strip()

    try:
        parsed_json = json.loads(raw_response)
        print("[+] Successfully parsed JSON from LLM.")
        return parsed_json
    except json.JSONDecodeError as e:
        logger.error(
            "LLM JSON parse error for item_id=%s title=%r: %s | raw_response=%r",
            item_id,
            title[:160],
            e,
            raw_response[:2000],
        )
        return {
            "is_new_threat": False,
            "severity": "low",
            "threat_actors": [],
            "malware_families": [],
            "attack_vector": "",
            "suggested_techniques": [],
            "summary_one_line": "",
            "_analysis_failed": True,
        }

def generate_reasoning(content: str, technique_id: str, technique_name: str, cfg: dict | None = None) -> str:
    print(f"[*] Generating evidentiary reasoning for {technique_id}...")
    formatted_prompt = REASONING_PROMPT.format(
        content=content[:2000],
        technique_id=technique_id,
        technique_name=technique_name
    )
    try:
        reasoning = generate_text(
            prompt=formatted_prompt,
            system="You are an analytical assistant.",
            temperature=0.2,
            max_tokens=220,
            cfg=cfg,
            request_label=f"reasoning {technique_id}",
        )
        return reasoning.strip()
    except OllamaServiceError as exc:
        logger.warning("Skipping reasoning for %s: %s", technique_id, exc)
        return ""

# ==================== MOCK TEST (NO DATABASE NEEDED) ====================
if __name__ == "__main__":
    # Ensure Ollama is running in the background before executing this!
    test_content = """
    🚨 NEW 0DAY ALERT: We have observed the APT29 threat group utilizing a new unauthenticated RCE vulnerability (CVE-2026-9999) in Nginx 1.25.x.
    The attackers send a malformed HTTP/2 request to port 443. 
    Once exploited, it drops a web shell payload named '/tmp/.nginx_update' to maintain persistence.
    We highly recommend disabling HTTP/2 immediately.
    """
    
    print("--- Testing CTI JSON Extraction ---")
    extracted_data = extract_cti_data(test_content)
    print(json.dumps(extracted_data, indent=4))
    
    print("\n--- Testing TTP Evidentiary Reasoning ---")
    # Pretend we validated T1505.003 (Web Shell) via the ttp_mapper.py
    reasoning_text = generate_reasoning(test_content, "T1505.003", "Web Shell")
    print(f"Reasoning:\n{reasoning_text}")
