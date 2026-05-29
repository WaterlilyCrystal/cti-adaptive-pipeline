"""
Low-risk notification dispatch helpers.
Always persist alerts locally; webhook delivery is best-effort.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List

import requests


def dispatch_alert(payload: Dict, destinations: List[Dict]) -> List[Dict]:
    output_dir = Path("output") / "notifications"
    output_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    base_name = "".join(c if c.isalnum() else "_" for c in payload.get("title", "alert")).lower()[:60]
    json_path = output_dir / f"{timestamp}_{base_name}.json"
    html_path = output_dir / f"{timestamp}_{base_name}.html"
    json_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    html_path.write_text(payload.get("html", ""), encoding="utf-8")

    results = []
    for destination in destinations:
        channel = destination["channel"]
        target = destination["destination"]
        status = "spooled"
        if channel in {"slack", "zalo"} and isinstance(target, str) and target.startswith("http"):
            try:
                response = requests.post(target, json=payload, timeout=10)
                status = "sent" if response.ok else f"http_{response.status_code}"
            except requests.RequestException as exc:
                status = f"failed:{type(exc).__name__}"
        elif channel == "email":
            status = "spooled"
        results.append(
            {
                "channel": channel,
                "destination": target,
                "status": status,
                "json_path": str(json_path),
                "html_path": str(html_path),
            }
        )
    return results
