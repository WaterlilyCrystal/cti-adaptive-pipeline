import os
from mitreattack.stix20 import MitreAttackData

# Path to the MITRE JSON file
MITRE_DATA_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "enterprise-attack.json")

print("[*] Loading MITRE ATT&CK dictionary into memory (This will take a few seconds)...")
try:
    mitre_attack_data = MitreAttackData(MITRE_DATA_PATH)
    print("[+] MITRE dictionary loaded successfully!")
except Exception as e:
    print(f"[-] ERROR: Cannot read the MITRE file. Please check the path {MITRE_DATA_PATH}. Details: {e}")
    mitre_attack_data = None

def validate_and_enrich_ttps(llm_suggested_ttps: list) -> list:
    """
    Receives a list of TTPs predicted by the AI.
    Looks up in the MITRE database to filter out fake IDs and fetch official names.
    """
    if not mitre_attack_data:
        return []

    validated_ttps = []
    
    for ttp in llm_suggested_ttps:
        tech_id = ttp.get("technique_id", "")
        
        try:
            # BUG FIX: Use the exact, correct method from mitreattack-python
            technique = mitre_attack_data.get_object_by_attack_id(tech_id, "attack-pattern")
            
            if technique:
                # In case the library returns a list for some IDs, grab the first object
                if isinstance(technique, list) and len(technique) > 0:
                    technique = technique[0]
                    
                # If the ID is real -> Enrich the data
                ttp["technique_name_official"] = technique.name
                
                # Get the tactic(s) containing this technique (Kill Chain Phases)
                tactics = []
                if hasattr(technique, 'kill_chain_phases'):
                    tactics = [phase.phase_name for phase in technique.kill_chain_phases]
                ttp["tactic"] = tactics
                
                ttp["is_valid"] = True
                validated_ttps.append(ttp)
            else:
                # Fake ID (Hallucination)
                print(f"[-] AI Hallucination: Rejected fake code {tech_id}")
                
        except Exception as e:
            # Print the actual system error instead of swallowing it
            print(f"[-] System error looking up {tech_id}: {e}")
            
    return validated_ttps

# ==================== MOCK TEST (NO DATABASE NEEDED) ====================
if __name__ == "__main__":
    # Simulate the LLM having just analyzed an article and returning this list
    mock_llm_output = [
        {"technique_id": "T1566.001", "confidence": "high"}, # Phishing (Real code)
        {"technique_id": "T1110", "confidence": "medium"},   # Brute Force (Real code)
        {"technique_id": "T9999", "confidence": "high"},     # LLM fabricated code (Fake code)
        {"technique_id": "T1234", "confidence": "low"}       # LLM fabricated code (Fake code)
    ]
    
    print("\n--- Starting MITRE validation ---")
    final_result = validate_and_enrich_ttps(mock_llm_output)
    
    import json
    print("\n[+] Results after filtering noise and enriching data:")
    print(json.dumps(final_result, indent=4, ensure_ascii=False))