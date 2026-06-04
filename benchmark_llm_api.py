from __future__ import annotations

import argparse
import copy
import json
import logging

from analysis.ollama_client import OllamaServiceError, probe_service
from core.processor import deduplicate_items
from pipeline import load_config
from reporting import reporter
from utils.benchmarking import timed_step, write_timing_summary


def apply_provider_override(cfg: dict, args: argparse.Namespace) -> dict:
    cfg = copy.deepcopy(cfg)
    llm_cfg = cfg.setdefault("llm", {})
    if args.runtime:
        llm_cfg["runtime"] = args.runtime
    if args.model:
        llm_cfg["model"] = args.model
    if args.api_base_url:
        llm_cfg["api_base_url"] = args.api_base_url
    if args.api_key_env:
        llm_cfg["api_key_env"] = args.api_key_env
    cfg.setdefault("reporting", {})["mode"] = args.report_mode
    cfg.setdefault("pipeline", {})["enable_llm_dedup"] = True
    cfg.setdefault("pipeline", {})["llm_dedup_max_pairs"] = args.max_dedup_pairs
    return cfg


def sample_items() -> list[dict]:
    return [
        {
            "id": "sample-1",
            "source": "sample",
            "title": "CVE-2026-9999 Nginx HTTP/2 RCE report",
            "url": "https://example.test/advisory-1",
            "content": "Researchers report CVE-2026-9999 affecting Nginx HTTP/2 handling. Exploitation may allow remote code execution on exposed servers.",
        },
        {
            "id": "sample-2",
            "source": "sample",
            "title": "Nginx HTTP/2 remote code execution vulnerability CVE-2026-9999",
            "url": "https://example.test/advisory-2",
            "content": "A separate advisory describes the same CVE-2026-9999 issue in Nginx HTTP/2 request handling with potential RCE impact.",
        },
        {
            "id": "sample-3",
            "source": "sample",
            "title": "Redis hardening guide",
            "url": "https://example.test/redis-hardening",
            "content": "This note discusses Redis configuration hardening and does not describe the Nginx vulnerability.",
        },
    ]


def run_benchmark(cfg: dict) -> dict:
    with timed_step("llm_api_benchmark", "provider_probe"):
        probe_service(cfg)

    items = sample_items()
    with timed_step("llm_api_benchmark", "llm_assisted_dedup", {"items": len(items)}):
        deduped, duplicates = deduplicate_items(
            items,
            similarity_threshold=0.90,
            enable_semantic=False,
            window_size=10,
            cfg=cfg,
        )

    threat_data = {
        "severity": "high",
        "summary_one_line": "Potential Nginx HTTP/2 RCE affecting internet-facing services.",
        "attack_vector": "Public-facing web service exploitation if the vulnerable component is exposed.",
        "validated_ttps": [{"technique_id": "T1190", "technique_name_official": "Exploit Public-Facing Application"}],
        "threat_actors": [],
        "malware_families": [],
    }
    iocs = {"cves": ["CVE-2026-9999"], "ips": [], "domains": [], "urls": [], "hashes": []}
    with timed_step("llm_api_benchmark", "report_generation"):
        reports = reporter.generate_multi_tier_reports(
            threat_data,
            iocs,
            "Benchmark - CVE-2026-9999 Nginx HTTP2 RCE",
            language="en",
            cfg=cfg,
        )

    summary = write_timing_summary()
    result = {
        "runtime": cfg.get("llm", {}).get("runtime"),
        "model": cfg.get("llm", {}).get("model"),
        "dedup_input_items": len(items),
        "dedup_output_items": len(deduped),
        "duplicates_removed": duplicates,
        "report_lengths": {key: len(value or "") for key, value in reports.items()},
        "timing_summary": summary,
    }
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return result


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(name)s - %(message)s")
    parser = argparse.ArgumentParser(description="Benchmark external/local LLM provider for dedup and report generation.")
    parser.add_argument("--runtime", default="", help="deepseek, openrouter, groq, openai_compatible, or ollama")
    parser.add_argument("--model", default="", help="Provider model name, e.g. deepseek-chat")
    parser.add_argument("--api-base-url", default="", help="OpenAI-compatible API base URL")
    parser.add_argument("--api-key-env", default="", help="Environment variable containing API key")
    parser.add_argument("--report-mode", default="fast", choices=["fast", "full", "template", "off"])
    parser.add_argument("--max-dedup-pairs", type=int, default=5)
    args = parser.parse_args()

    cfg = apply_provider_override(load_config(), args)
    try:
        run_benchmark(cfg)
    except OllamaServiceError as exc:
        raise SystemExit(f"LLM benchmark failed: {exc}") from exc


if __name__ == "__main__":
    main()
