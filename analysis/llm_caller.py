import json
import requests

# The default local API endpoint for Ollama
OLLAMA_API_URL = "http://localhost:11434/api/generate"
# The exact model name you pulled earlier
MODEL_NAME = "qwen2.5:7b-instruct-q4_K_M"

# ==============================================================================
# STRICT PROMPT TEMPLATES (TASK 2 & 4)
# ==============================================================================
SYSTEM_PROMPT = """You are a senior Cyber Threat Intelligence (CTI) analyst.
Your task is to analyze threat intelligence reports and extract structured data.
You MUST respond ONLY with valid JSON. Do not include any introductory or concluding text (like "Here is the JSON").
Start your response with '{' and end with '}'."""

ANALYSIS_PROMPT = """Analyze the following threat intelligence content.

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
      "technique_id": "T1234",
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

def call_ollama(prompt: str, system: str = "", temperature: float = 0.1) -> str:
    """
    Sends a prompt to the local Ollama API and returns the raw text response.
    Temperature is set very low (0.1) to prevent hallucinations and enforce formatting.
    """
    payload = {
        "model": MODEL_NAME,
        "prompt": prompt,
        "system": system,
        "stream": False,
        "options": {
            "temperature": temperature
        }
    }
    
    try:
        response = requests.post(OLLAMA_API_URL, json=payload, timeout=60)
        response.raise_for_status()
        return response.json().get("response", "")
    except requests.exceptions.RequestException as e:
        print(f"[-] Ollama connection error: {e}")
        return ""

def extract_cti_data(content: str) -> dict:
    """
    Forces the LLM to read the content and return a structured JSON dictionary.
    Includes a fallback mechanism if the JSON parsing fails.
    """
    print("[*] Sending content to LLM for JSON extraction...")
    formatted_prompt = ANALYSIS_PROMPT.format(content=content)
    
    raw_response = call_ollama(prompt=formatted_prompt, system=SYSTEM_PROMPT, temperature=0.1)
    
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
        print(f"[-] LLM JSON Format Error: {e}")
        print(f"Raw Output: {raw_response}")
        # Fallback template to prevent pipeline crash
        return {
            "is_new_threat": False,
            "severity": "low",
            "threat_actors": [],
            "malware_families": [],
            "attack_vector": "Failed to parse LLM output",
            "suggested_techniques": [],
            "summary_one_line": "Error during analysis."
        }

def generate_reasoning(content: str, technique_id: str, technique_name: str) -> str:
    """
    Forces the LLM to explain WHY it chose a specific MITRE technique by quoting the text.
    """
    print(f"[*] Generating evidentiary reasoning for {technique_id}...")
    formatted_prompt = REASONING_PROMPT.format(
        content=content[:2000], # Limit content size to save context window
        technique_id=technique_id,
        technique_name=technique_name
    )
    
    # We can use a slightly higher temperature (0.2) here since it's generating natural language
    reasoning = call_ollama(prompt=formatted_prompt, system="You are an analytical assistant.", temperature=0.2)
    return reasoning.strip()

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