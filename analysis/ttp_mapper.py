from __future__ import annotations

import json
import logging
import os
from typing import Dict, List

logger = logging.getLogger("ttp_mapper")

BASE_DIR = os.path.dirname(os.path.dirname(__file__))
MITRE_DATA_PATH = os.path.join(BASE_DIR, "data", "enterprise-attack.json")
MITRE_INDEX_PATH = os.path.join(BASE_DIR, "data", "enterprise-attack-index.json")
_mitre_index: Dict[str, Dict] | None = None


def _load_json(path: str) -> Dict:
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def _extract_attack_id(external_references: List[Dict]) -> str:
    for reference in external_references or []:
        external_id = reference.get("external_id", "")
        if isinstance(external_id, str) and external_id.startswith("T"):
            return external_id
    return ""


def _build_index_from_stix() -> Dict[str, Dict]:
    logger.info("Building MITRE ATT&CK index from %s", MITRE_DATA_PATH)
    bundle = _load_json(MITRE_DATA_PATH)
    index: Dict[str, Dict] = {}

    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue

        attack_id = _extract_attack_id(obj.get("external_references", []))
        if not attack_id:
            continue

        tactics = [
            phase.get("phase_name", "")
            for phase in obj.get("kill_chain_phases", [])
            if isinstance(phase, dict) and phase.get("phase_name")
        ]
        index[attack_id] = {
            "technique_name_official": obj.get("name", ""),
            "tactic": tactics,
        }

    payload = {
        "source_path": MITRE_DATA_PATH,
        "source_mtime": os.path.getmtime(MITRE_DATA_PATH),
        "index": index,
    }
    with open(MITRE_INDEX_PATH, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, ensure_ascii=False)
    logger.info("MITRE ATT&CK index cached: %s techniques", len(index))
    return index


def _load_cached_index() -> Dict[str, Dict] | None:
    if not os.path.exists(MITRE_INDEX_PATH):
        return None
    try:
        payload = _load_json(MITRE_INDEX_PATH)
        if payload.get("source_path") != MITRE_DATA_PATH:
            return None
        if float(payload.get("source_mtime", 0)) < os.path.getmtime(MITRE_DATA_PATH):
            return None
        index = payload.get("index", {})
        if isinstance(index, dict) and index:
            logger.info("Loaded MITRE ATT&CK index cache: %s techniques", len(index))
            return index
    except Exception as exc:
        logger.warning("Failed to read MITRE index cache: %s", exc)
    return None


def _get_mitre_index() -> Dict[str, Dict]:
    global _mitre_index
    if _mitre_index is not None:
        return _mitre_index

    cached = _load_cached_index()
    if cached is not None:
        _mitre_index = cached
        return _mitre_index

    try:
        _mitre_index = _build_index_from_stix()
    except Exception as exc:
        logger.error("Cannot build MITRE ATT&CK index from %s: %s", MITRE_DATA_PATH, exc)
        _mitre_index = {}
    return _mitre_index


def validate_and_enrich_ttps(llm_suggested_ttps: list) -> list:
    mitre_index = _get_mitre_index()
    if not mitre_index:
        return []

    validated_ttps = []
    for ttp in llm_suggested_ttps:
        tech_id = ttp.get("technique_id", "")
        metadata = mitre_index.get(tech_id)
        if not metadata:
            logger.info("Rejected unknown ATT&CK technique: %s", tech_id)
            continue

        enriched = dict(ttp)
        enriched["technique_name_official"] = metadata.get("technique_name_official", "")
        enriched["tactic"] = metadata.get("tactic", [])
        enriched["is_valid"] = True
        validated_ttps.append(enriched)

    return validated_ttps


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(name)s - %(message)s")
    sample = [
        {"technique_id": "T1566.001", "confidence": "high"},
        {"technique_id": "T1110", "confidence": "medium"},
        {"technique_id": "T9999", "confidence": "high"},
    ]
    print(json.dumps(validate_and_enrich_ttps(sample), indent=2, ensure_ascii=False))
