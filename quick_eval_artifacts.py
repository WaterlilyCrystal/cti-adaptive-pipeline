import argparse
import csv
import json
import os
import re
import sqlite3
import statistics
import time
from pathlib import Path

from analysis import ioc_extractor, llm_caller
from core.contextual import match_profile_to_content
from core.processor import normalize_text
from reporting import reporter
from utils import db_handler


BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "data" / "cti.db"
REPORTS_DIR = BASE_DIR / "output" / "reports"
OUT_DIR = BASE_DIR / "output" / "eval"


def safe_report_name(title: str) -> str:
    safe_name = "".join([c if c.isalnum() else "_" for c in (title or "")]).lower()
    if len(safe_name) > 100:
        safe_name = safe_name[:90] + "_trim"
    return safe_name


def latex_escape(text: str) -> str:
    value = (text or "").replace("\\", "\\textbackslash{}")
    replacements = {
        "&": "\\&",
        "%": "\\%",
        "$": "\\$",
        "#": "\\#",
        "_": "\\_",
        "{": "\\{",
        "}": "\\}",
        "~": "\\textasciitilde{}",
        "^": "\\textasciicircum{}",
    }
    for old, new in replacements.items():
        value = value.replace(old, new)
    return value


def shorten(text: str, limit: int = 220) -> str:
    value = " ".join((text or "").split())
    if len(value) <= limit:
        return value
    return value[: limit - 3].rstrip() + "..."


def get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def fetch_recent_items(conn: sqlite3.Connection, limit: int) -> list[dict]:
    rows = conn.execute(
        """
        SELECT id, source, source_type, title, url, content, severity, analyzed, credibility_score
        FROM intel_items
        ORDER BY collected_at DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()
    return [dict(row) for row in rows]


def compute_cve_metrics(items: list[dict]) -> dict:
    benchmark = []
    for item in items:
        source = (item.get("source") or "").lower()
        if not any(marker in source for marker in ("nvd", "kev", "cve")):
            continue
        gold = set(re.findall(r"\bCVE-\d{4}-\d+\b", f"{item.get('title', '')} {item.get('url', '')}", re.IGNORECASE))
        if not gold:
            continue
        predicted = set(ioc_extractor.extract_all_iocs(f"{item.get('title', '')}\n{item.get('content', '')}\n{item.get('url', '')}").get("cves", []))
        benchmark.append((gold, predicted))

    tp = sum(len(gold & predicted) for gold, predicted in benchmark)
    fp = sum(len(predicted - gold) for gold, predicted in benchmark)
    fn = sum(len(gold - predicted) for gold, predicted in benchmark)
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    return {
        "sample_size": len(benchmark),
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": round(precision, 3),
        "recall": round(recall, 3),
        "f1": round(f1, 3),
    }


def compute_runtime_metrics(items: list[dict], profile: dict) -> dict:
    preprocess_ms = []
    report_template_ms = []
    for item in items[: min(len(items), 30)]:
        raw_text = f"{item.get('title', '')}\n{item.get('content', '')}"
        start = time.perf_counter()
        normalized = normalize_text(raw_text)
        iocs = ioc_extractor.extract_all_iocs(normalized)
        _ = match_profile_to_content(profile, normalized)
        preprocess_ms.append((time.perf_counter() - start) * 1000)

        start = time.perf_counter()
        reporter.generate_multi_tier_reports(
            {
                "severity": item.get("severity", "medium"),
                "summary_one_line": shorten(item.get("title", "")),
                "attack_vector": "",
                "validated_ttps": [],
                "threat_actors": [],
                "malware_families": [],
            },
            iocs,
            item.get("title", "Threat report"),
            language="en",
            cfg={"reporting": {"mode": "template"}},
        )
        report_template_ms.append((time.perf_counter() - start) * 1000)

    return {
        "median_preprocess_ms": round(statistics.median(preprocess_ms), 2) if preprocess_ms else 0.0,
        "median_template_report_ms": round(statistics.median(report_template_ms), 2) if report_template_ms else 0.0,
    }


def compute_report_hallucination_rate(items: list[dict]) -> dict:
    matched = 0
    flagged = 0
    for item in items:
        safe_name = safe_report_name(item.get("title", ""))
        report_paths = [
            REPORTS_DIR / f"{safe_name}_01_executive.md",
            REPORTS_DIR / f"{safe_name}_02_technical.md",
            REPORTS_DIR / f"{safe_name}_03_operational.md",
        ]
        if not all(path.exists() for path in report_paths):
            continue
        matched += 1
        report_text = "\n".join(path.read_text(encoding="utf-8", errors="ignore") for path in report_paths)
        source_text = f"{item.get('title', '')}\n{item.get('content', '')}\n{item.get('url', '')}"
        report_iocs = ioc_extractor.extract_all_iocs(report_text)
        source_iocs = ioc_extractor.extract_all_iocs(source_text)

        unsupported = False
        for key in ("cves", "ips", "domains", "urls"):
            report_set = set(report_iocs.get(key, []) or [])
            source_set = set(source_iocs.get(key, []) or [])
            if report_set - source_set:
                unsupported = True
                break
        if unsupported:
            flagged += 1

    rate = flagged / matched if matched else 0.0
    return {"matched_reports": matched, "flagged_reports": flagged, "rate": round(rate, 3)}


def compute_report_failure_rate() -> dict:
    files = list(REPORTS_DIR.glob("*.md"))
    if not files:
        return {"total": 0, "failed": 0, "rate": 0.0}
    failed = 0
    for path in files:
        text = path.read_text(encoding="utf-8", errors="ignore").strip().lower()
        if text.startswith("llm generation error:") or text.startswith("500 server error:") or text.startswith("traceback"):
            failed += 1
    return {"total": len(files), "failed": failed, "rate": round(failed / len(files), 3)}


def write_before_after(items: list[dict]) -> list[dict]:
    rows = []
    for item in items[:6]:
        raw_text = f"{item.get('title', '')}\n{item.get('content', '')}"
        rows.append(
            {
                "source": item.get("source", ""),
                "raw_text": shorten(raw_text, 280),
                "normalized_text": shorten(normalize_text(raw_text), 280),
            }
        )
    csv_path = OUT_DIR / "before_after_examples.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["source", "raw_text", "normalized_text"])
        writer.writeheader()
        writer.writerows(rows)
    return rows


def write_prompt_snippets() -> dict:
    snippets = {
        "llm_system_prompt": llm_caller.SYSTEM_PROMPT.strip(),
        "llm_analysis_prompt": llm_caller.ANALYSIS_PROMPT.strip(),
        "report_guardrails_en": reporter.REPORT_GUARDRAILS["en"].strip(),
        "executive_prompt_en": reporter.EXEC_SYSTEM["en"].strip(),
    }
    md_path = OUT_DIR / "prompt_snippets.md"
    with md_path.open("w", encoding="utf-8") as handle:
        for key, value in snippets.items():
            handle.write(f"## {key}\n\n```\n{value}\n```\n\n")
    return snippets


def write_case_study(items: list[dict]) -> dict:
    for item in items:
        safe_name = safe_report_name(item.get("title", ""))
        exec_path = REPORTS_DIR / f"{safe_name}_01_executive.md"
        tech_path = REPORTS_DIR / f"{safe_name}_02_technical.md"
        ops_path = REPORTS_DIR / f"{safe_name}_03_operational.md"
        if exec_path.exists() and tech_path.exists() and ops_path.exists():
            case = {
                "title": item.get("title", ""),
                "source": item.get("source", ""),
                "raw_excerpt": shorten(f"{item.get('title', '')}\n{item.get('content', '')}", 500),
                "executive": shorten(exec_path.read_text(encoding="utf-8", errors="ignore"), 900),
                "technical": shorten(tech_path.read_text(encoding="utf-8", errors="ignore"), 1100),
                "operational": shorten(ops_path.read_text(encoding="utf-8", errors="ignore"), 900),
            }
            (OUT_DIR / "case_study.json").write_text(json.dumps(case, indent=2, ensure_ascii=False), encoding="utf-8")
            return case
    return {}


def write_tex_bundle(metrics: dict, before_after_rows: list[dict], snippets: dict, case: dict) -> None:
    before_rows_tex = ""
    for row in before_after_rows[:3]:
        before_rows_tex += (
            f"\\textbf{{{latex_escape(row['source'])}}} & "
            f"{latex_escape(row['raw_text'])} & "
            f"{latex_escape(row['normalized_text'])} \\\\\n\\hline\n"
        )

    prompt_tex = latex_escape(snippets["llm_system_prompt"][:420])
    case_tex = ""
    if case:
        case_tex = f"""
\\paragraph{{Representative case study.}}
\\textbf{{Source item:}} {latex_escape(case['title'])}\\\\
\\textbf{{Raw input excerpt:}} {latex_escape(case['raw_excerpt'])}

\\paragraph{{Generated executive summary excerpt.}}
{latex_escape(case['executive'])}
"""

    tex = f"""
% Auto-generated by quick_eval_artifacts.py
\\subsection{{Quantitative Evaluation Summary}}
Table~\\ref{{tab:quant-results}} was updated from an executed sample of {metrics['eval_sample_size']} recent items.

\\begin{{table}}[h]
\\centering
\\caption{{Quantitative evaluation summary}}
\\label{{tab:quant-results}}
\\begin{{tabular}}{{|p{{6cm}}|p{{3.5cm}}|p{{5cm}}|}}
\\hline
\\textbf{{Metric}} & \\textbf{{Value}} & \\textbf{{Notes}} \\\\
\\hline
IOC precision (CVE benchmark) & {metrics['cve_precision']:.3f} & Structured-source CVE subset \\\\
\\hline
IOC recall (CVE benchmark) & {metrics['cve_recall']:.3f} & Structured-source CVE subset \\\\
\\hline
IOC F1 (CVE benchmark) & {metrics['cve_f1']:.3f} & Structured-source CVE subset \\\\
\\hline
LLM report hallucination rate & {metrics['hallucination_rate']:.3f} & Unsupported artifact mentions in saved reports \\\\
\\hline
Report timeout/failure rate & {metrics['report_failure_rate']:.3f} & Failed report files / total report files \\\\
\\hline
Median preprocessing runtime / item & {metrics['median_preprocess_ms']:.2f} ms & Normalize + IOC extraction + profile match \\\\
\\hline
Median template report runtime / item & {metrics['median_template_report_ms']:.2f} ms & Deterministic non-LLM reporting baseline \\\\
\\hline
\\end{{tabular}}
\\end{{table}}

\\subsection{{Before/After Cleaning Examples}}
\\begin{{table}}[h]
\\centering
\\caption{{Examples of raw versus normalized source text}}
\\begin{{tabular}}{{|p{{2.8cm}}|p{{5.3cm}}|p{{5.3cm}}|}}
\\hline
\\textbf{{Source}} & \\textbf{{Raw text}} & \\textbf{{Normalized text}} \\\\
\\hline
{before_rows_tex}\\end{{tabular}}
\\end{{table}}

\\subsection{{Prompt Engineering Evidence}}
\\paragraph{{System prompt excerpt for JSON extraction.}}
\\begin{{verbatim}}
{prompt_tex}
\\end{{verbatim}}

{case_tex}
"""
    (OUT_DIR / "eval_patch.tex").write_text(tex.strip() + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate quick evaluation artifacts from local CTI data.")
    parser.add_argument("--limit", type=int, default=80, help="Number of recent DB items to evaluate.")
    args = parser.parse_args()

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    conn = get_conn()
    try:
        items = fetch_recent_items(conn, args.limit)
        profile = db_handler.get_active_profile(conn)

        cve = compute_cve_metrics(items)
        runtime = compute_runtime_metrics(items, profile)
        halluc = compute_report_hallucination_rate(items)
        failures = compute_report_failure_rate()
        before_after_rows = write_before_after(items)
        snippets = write_prompt_snippets()
        case = write_case_study(items)

        metrics = {
            "eval_sample_size": len(items),
            "cve_precision": cve["precision"],
            "cve_recall": cve["recall"],
            "cve_f1": cve["f1"],
            "hallucination_rate": halluc["rate"],
            "report_failure_rate": failures["rate"],
            "median_preprocess_ms": runtime["median_preprocess_ms"],
            "median_template_report_ms": runtime["median_template_report_ms"],
        }
        (OUT_DIR / "quant_summary.json").write_text(json.dumps(metrics, indent=2), encoding="utf-8")
        write_tex_bundle(metrics, before_after_rows, snippets, case)
        print(json.dumps(metrics, indent=2))
        print(f"Wrote artifacts to: {OUT_DIR}")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
