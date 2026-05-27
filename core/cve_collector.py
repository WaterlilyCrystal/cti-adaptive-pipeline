"""Collects formal vulnerability feeds (CISA KEV and NVD v2) for CTI pipeline.

Provides `fetch_cve_feeds(days_window=3)` which aggregates CISA KEV and NVD
vulnerabilities into the pipeline `intel_items` schema. Network calls are
defensive and will not raise to the caller; on error an empty list is returned
for that source.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
from datetime import datetime, timedelta, timezone
from typing import List, Dict

import requests
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger("cve_collector")
if not logger.handlers:
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def _md5_for_url(url: str) -> str:
    return hashlib.md5(url.encode("utf-8")).hexdigest()


def fetch_cisa_kev(days_window: int = 3) -> List[Dict]:
    """Fetch Known Exploited Vulnerabilities (CISA KEV) and map to schema.

    Returns list[dict] with `source_type` == "feed".
    """
    results: List[Dict] = []
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    try:
        resp = requests.get(url, timeout=20)
        resp.raise_for_status()
        data = resp.json()
        vulns = data.get("vulnerabilities") or []
        now = datetime.now(timezone.utc).isoformat()
        count = 0
        for v in vulns:
            try:
                cve_id = v.get("cveID") or v.get("cve") or v.get("CVE")
                if not cve_id:
                    continue

                # Construct a CISA reference URL (constructed reference acceptable)
                ref_url = f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog/{cve_id}"

                title_parts = [cve_id]
                if v.get("vulnerabilityName"):
                    title_parts.append(v.get("vulnerabilityName"))
                title = " - ".join(title_parts)

                content_lines = []
                if v.get("vendorProject"):
                    content_lines.append(f"Vendor: {v.get('vendorProject')}")
                if v.get("product"):
                    content_lines.append(f"Product: {v.get('product')}")
                if v.get("dateAdded"):
                    content_lines.append(f"DateAdded: {v.get('dateAdded')}")
                if v.get("dateUpdated"):
                    content_lines.append(f"DateUpdated: {v.get('dateUpdated')}")

                content = "\n".join(content_lines) or json.dumps(v)

                item = {
                    "id": _md5_for_url(ref_url),
                    "source": "CISA-KEV",
                    "source_type": "feed",
                    "title": title,
                    "url": ref_url,
                    "content": content,
                    "lang": "en",
                    "confidence": 1.0,
                    "processed": 0,
                    "report_done": 0,
                    "collected_at": now,
                }
                results.append(item)
                count += 1
            except Exception as e:
                logger.error(f"Error parsing CISA KEV entry: {e}")
                continue

        logger.info(f"Fetched {count} items from CISA KEV feed")
    except Exception as e:
        logger.error(f"Failed to retrieve CISA KEV feed: {e}")
    return results


def _format_iso_for_nvd(dt: datetime) -> str:
    # NVD expects ISO with milliseconds and timezone like: 2026-05-24T00:00:00.000+00:00
    return dt.replace(microsecond=0, tzinfo=timezone.utc).isoformat(timespec='milliseconds') + "+00:00"


def fetch_nvd_vulnerabilities(days_window: int = 3) -> List[Dict]:
    """Query NVD v2 API for CVEs published within the lookback window.

    Uses `pubStartDate` and `pubEndDate` to restrict results.
    """
    results: List[Dict] = []
    base = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    now = datetime.now(timezone.utc)
    start = now - timedelta(days=days_window)
    params = {
        "pubStartDate": _format_iso_for_nvd(start),
        "pubEndDate": _format_iso_for_nvd(now),
        # optionally reduce size per request; pagination not implemented here
    }
    headers = {"User-Agent": "CTI-Adaptive-Pipeline/1.0"}

    try:
        resp = requests.get(base, params=params, headers=headers, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        vulns = data.get("vulnerabilities") or []
        count = 0
        for v in vulns:
            try:
                cve = v.get("cve") or {}
                cve_id = cve.get("id")
                if not cve_id:
                    continue

                # Pick an English description if present
                desc = ""
                for d in cve.get("descriptions", []) or []:
                    if d.get("lang") == "en":
                        desc = d.get("value", "")
                        break
                if not desc:
                    # fallback to first description
                    if (cve.get("descriptions") or []):
                        desc = (cve.get("descriptions")[0].get("value", ""))

                nvd_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
                title = f"{cve_id}"
                content = desc or json.dumps(cve)

                item = {
                    "id": _md5_for_url(nvd_url),
                    "source": "NVD",
                    "source_type": "feed",
                    "title": title,
                    "url": nvd_url,
                    "content": content,
                    "lang": "en",
                    "confidence": 1.0,
                    "processed": 0,
                    "report_done": 0,
                    "collected_at": datetime.now(timezone.utc).isoformat(),
                }
                results.append(item)
                count += 1
            except Exception as e:
                logger.error(f"Error parsing NVD vulnerability entry: {e}")
                continue

        logger.info(f"Fetched {count} items from NVD between {params['pubStartDate']} and {params['pubEndDate']}")
    except Exception as e:
        logger.error(f"Failed to query NVD API: {e}")

    return results


def fetch_alienvault_otx(days_window: int = 3) -> List[Dict]:
    """Placeholder for AlienVault OTX pulls.

    This function is intentionally conservative: if an OTX API key is present
    it logs that OTX collection is not implemented and returns an empty list.
    The OTX API requires additional decisions (pulses, indicator types, rate
    limiting) which are outside the scope of this implemention.
    """
    api_key = os.getenv("X-OTX-API-KEY") or os.getenv("OTX_API_KEY")
    if api_key:
        logger.info("OTX API key found but OTX collection is not implemented in this module.")
    return []


def fetch_cve_feeds(days_window: int = 3) -> List[Dict]:
    """Aggregate CISA KEV and NVD feeds and return a combined list.
    """
    results: List[Dict] = []
    try:
        results.extend(fetch_cisa_kev(days_window=days_window))
    except Exception as e:
        logger.error(f"CISA KEV collection failed: {e}")

    try:
        results.extend(fetch_nvd_vulnerabilities(days_window=days_window))
    except Exception as e:
        logger.error(f"NVD collection failed: {e}")

    # Optional: include OTX pulses/indicators
    try:
        results.extend(fetch_alienvault_otx(days_window=days_window))
    except Exception:
        pass

    logger.info(f"Total CVE-like items collected: {len(results)}")
    return results


if __name__ == "__main__":
    items = fetch_cve_feeds(days_window=3)
    print(f"Fetched {len(items)} CVE items")


def fetch_cve_data(days_window: int = 3) -> List[Dict]:
    """Compatibility wrapper for legacy import name `fetch_cve_data` used by pipeline.

    Internally delegates to `fetch_cve_feeds` to keep the clearer function name
    while preserving backward compatibility with `pipeline.py`.
    """
    try:
        return fetch_cve_feeds(days_window=days_window)
    except Exception as e:
        logger.error(f"fetch_cve_data wrapper failed: {e}")
        return []
