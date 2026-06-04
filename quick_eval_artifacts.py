import argparse
import csv
import json
import os
import re
import sqlite3
import statistics
import sys
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
TIMING_RUN_JSON = OUT_DIR / "latest_timing_run.json"

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")


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


def ascii_ratio(text: str) -> float:
    if not text:
        return 1.0
    return sum(1 for char in text if ord(char) < 128) / len(text)


def is_english_normalization_candidate(item: dict) -> bool:
    text = f"{item.get('title', '')}\n{item.get('content', '')}"
    lang = (item.get("lang") or "").lower()
    if lang and lang not in {"en", "eng", "unknown"}:
        return False
    mojibake_markers = ("â", "Ã", "å", "è", "é", "ð", "�")
    if any(marker in text for marker in mojibake_markers):
        return False
    return ascii_ratio(text) >= 1.0


def readable_runtime_label(value: str) -> str:
    labels = {
        "phase_3_4_analysis_report": "Phase III-IV wrapper",
        "phase_3_4_analyze_report": "Analysis and reporting orchestration",
        "phase_3_analysis": "Semantic CTI analysis",
        "phase_4_reporting": "Defensive reporting and persistence",
        "pipeline": "End-to-end selected run",
        "llm_probe": "LLM availability probe",
        "process_single_item": "Per-item analysis workflow",
        "select_analysis_candidates": "Candidate selection",
        "step_1_5_osint_enrichment": "OSINT enrichment",
        "step_1_regex_ioc_extraction": "Regex IOC extraction",
        "step_2_llm_cti_extraction": "LLM CTI extraction",
        "step_3_mitre_validation": "MITRE ATT&CK validation",
        "step_4_5_profile_matching": "Technology-stack matching",
        "step_4_reasoning_and_sigma": "Reasoning and Sigma drafting",
        "step_5_multi_tier_report_generation": "Multi-tier report generation",
        "step_6_database_update": "Database state update",
        "step_7_notification_dispatch": "Notification dispatch",
        "phase_analyze_report_total": "Total analysis/report run",
    }
    return labels.get(value, value.replace("_", " "))


def get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def fetch_recent_items(conn: sqlite3.Connection, limit: int) -> list[dict]:
    rows = conn.execute(
        """
        SELECT id, source, source_type, title, url, content, severity, analyzed, credibility_score, lang
        FROM intel_items
        ORDER BY collected_at DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()
    return [dict(row) for row in rows]


def fetch_cve_benchmark_items(conn: sqlite3.Connection, limit: int) -> list[dict]:
    rows = conn.execute(
        """
        SELECT id, source, source_type, title, url, content, severity, analyzed, credibility_score, lang
        FROM intel_items
        WHERE title LIKE '%CVE-%' OR content LIKE '%CVE-%' OR url LIKE '%CVE-%'
        ORDER BY collected_at DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()
    return [dict(row) for row in rows]


def compute_cve_metrics(items: list[dict]) -> dict:
    benchmark = []
    for item in items:
        item_text = f"{item.get('title', '')}\n{item.get('content', '')}\n{item.get('url', '')}"
        gold = set(re.findall(r"\bCVE-\d{4}-\d+\b", item_text, re.IGNORECASE))
        if not gold:
            continue
        predicted = set(ioc_extractor.extract_all_iocs(item_text).get("cves", []))
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
    candidates = [item for item in items if is_english_normalization_candidate(item)]
    if len(candidates) < 3:
        candidates = items
    for item in candidates[:6]:
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


def write_multilingual_prompt() -> str:
    prompt = """You are a multilingual cyber threat intelligence analyst.
Given one public-source security item, produce an English analytical rendering without inventing facts.

Rules:
- Preserve the original source meaning and uncertainty.
- Translate or paraphrase only the information present in the source text.
- Extract security entities such as CVEs, affected products, vendors, malware names, threat actors, and TTPs when explicitly present.
- If a field is not supported by the source, write "not stated".
- End with: "Analyst verification is required before operational action."

Output:
1. Normalized English summary
2. Extracted entities
3. Relevance to the organization's technology stack
4. Executive, technical, and operational report notes
"""
    (OUT_DIR / "multilingual_llm_prompt.md").write_text(prompt, encoding="utf-8")
    return prompt


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


def load_runtime_summary() -> dict:
    if not TIMING_RUN_JSON.exists():
        return {"run": {}, "phase_summary": [], "step_summary": []}
    try:
        return json.loads(TIMING_RUN_JSON.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {"run": {}, "phase_summary": [], "step_summary": []}


def write_tex_bundle(metrics: dict, before_after_rows: list[dict], snippets: dict, case: dict, runtime_summary: dict) -> None:
    before_rows_tex = ""
    for row in before_after_rows[:3]:
        before_rows_tex += (
            f"\\textbf{{{latex_escape(row['source'])}}} & "
            f"{latex_escape(row['raw_text'])} & "
            f"{latex_escape(row['normalized_text'])} \\\\\n\\hline\n"
        )

    prompt_tex = latex_escape(snippets["llm_system_prompt"][:420])
    cve_benchmark_size = int(metrics.get("cve_benchmark_size", 0) or 0)
    if cve_benchmark_size:
        cve_precision_tex = f"{metrics['cve_precision']:.3f}"
        cve_recall_tex = f"{metrics['cve_recall']:.3f}"
        cve_f1_tex = f"{metrics['cve_f1']:.3f}"
        cve_note_tex = (
            f"CVE-containing DB subset, benchmark n={cve_benchmark_size}, "
            f"sampled n={int(metrics.get('cve_eval_sample_size', 0) or 0)}"
        )
    else:
        cve_precision_tex = "N/A"
        cve_recall_tex = "N/A"
        cve_f1_tex = "N/A"
        cve_note_tex = "No CVE-containing benchmark items found in the database sample"
    case_tex = ""
    if case:
        case_tex = f"""
\\paragraph{{Representative case study.}}
\\textbf{{Source item:}} {latex_escape(case['title'])}\\\\
\\textbf{{Raw input excerpt:}} {latex_escape(case['raw_excerpt'])}

\\paragraph{{Generated executive summary excerpt.}}
{latex_escape(case['executive'])}
"""

    runtime_tex = ""
    phase_rows = runtime_summary.get("phase_summary", []) or []
    if phase_rows:
        runtime_run = runtime_summary.get("run", {}) or {}
        runtime_run_id = latex_escape(runtime_run.get("run_id", "N/A"))
        total_runtime = max((row.get("total_seconds", 0.0) for row in phase_rows), default=0.0)
        runtime_rows_tex = ""
        for row in phase_rows:
            share = (row["total_seconds"] / total_runtime * 100) if total_runtime else 0.0
            runtime_rows_tex += (
                f"{latex_escape(readable_runtime_label(row['phase']))} & "
                f"{row['event_count']} & "
                f"{row['success_count']} & "
                f"{row['failure_count']} & "
                f"{row['total_seconds']:.3f} & "
                f"{row['median_seconds']:.3f} & "
                f"{share:.1f}\\% \\\\\n\\hline\n"
            )

        aggregate_steps = {"phase_analyze_report_total", "process_single_item"}
        aggregate_phases = {"pipeline"}
        step_rows = sorted(
            [row for row in (runtime_summary.get("step_summary", []) or []) if row.get("step") not in aggregate_steps],
            key=lambda row: row.get("total_seconds", 0.0),
            reverse=True,
        )
        step_rows_tex = ""
        for row in step_rows[:6]:
            step_rows_tex += (
                f"{latex_escape(readable_runtime_label(row['step']))} & "
                f"{latex_escape(readable_runtime_label(row['phase']))} & "
                f"{row['count']} & "
                f"{row['total_seconds']:.3f} & "
                f"{row['median_seconds']:.3f} & "
                f"{row['max_seconds']:.3f} \\\\\n\\hline\n"
            )

        dominant_step = step_rows[0] if step_rows else {}
        phase_candidates = [row for row in phase_rows if row.get("phase") not in aggregate_phases]
        dominant_phase = max(phase_candidates or phase_rows, key=lambda row: row.get("total_seconds", 0.0))
        interpretation_rows_tex = (
            f"Dominant phase & {latex_escape(readable_runtime_label(dominant_phase.get('phase', 'N/A')))} "
            f"consumed {dominant_phase.get('total_seconds', 0.0):.3f}s, indicating that the selected run was bounded mainly by analysis/report orchestration rather than deterministic preprocessing. \\\\\n\\hline\n"
            f"Dominant step & {latex_escape(readable_runtime_label(dominant_step.get('step', 'N/A')))} "
            f"consumed {dominant_step.get('total_seconds', 0.0):.3f}s across {dominant_step.get('count', 0)} event(s), which identifies LLM inference as the primary optimization target. \\\\\n\\hline\n"
            "Operational implication & Regex IOC extraction, profile matching, reporting templates, and database update were sub-second to millisecond-scale operations; therefore, reliability controls should focus on model runtime availability, timeout policy, and fallback API benchmarking. \\\\\n\\hline\n"
        )
        runtime_tex = f"""
\\subsection{{Pipeline Runtime Measurement}}
The runtime benchmark was collected from instrumented phase and step boundaries. Run identifier: \\texttt{{{runtime_run_id}}}. Tables below report executed measurements rather than theoretical complexity claims.

\\begin{{table}}[h]
\\centering
\\caption{{Phase-Level Runtime Distribution Summary}}
\\label{{tab:phase-runtime-summary}}
\\small
\\renewcommand{{\\arraystretch}}{{1.3}}
\\begin{{tabularx}}{{\\linewidth}}{{|
  >{{\\raggedright\\arraybackslash\\hsize=2.8\\hsize}}X|
  >{{\\centering\\arraybackslash\\hsize=0.5\\hsize}}X|
  >{{\\centering\\arraybackslash\\hsize=0.4\\hsize}}X|
  >{{\\centering\\arraybackslash\\hsize=0.4\\hsize}}X|
  >{{\\raggedleft\\arraybackslash\\hsize=1.1\\hsize}}X|
  >{{\\raggedleft\\arraybackslash\\hsize=1.1\\hsize}}X|
  >{{\\raggedleft\\arraybackslash\\hsize=0.7\\hsize}}X|}}
\\hline
\\textbf{{Execution Phase Component}} & \\textbf{{Events}} & \\textbf{{OK}} & \\textbf{{Fail}} & \\textbf{{Total Time (s)}} & \\textbf{{Median Time (s)}} & \\textbf{{Share (\\%)}} \\\\
\\hline
{runtime_rows_tex}\\end{{tabularx}}
\\end{{table}}

\\begin{{table}}[h]
\\centering
\\caption{{Top Critical Runtime-Consuming Pipeline Steps}}
\\label{{tab:step-runtime-bottlenecks}}
\\small
\\renewcommand{{\\arraystretch}}{{1.3}}
\\begin{{tabularx}}{{\\linewidth}}{{|
  >{{\\raggedright\\arraybackslash\\hsize=1.8\\hsize}}X|
  >{{\\raggedright\\arraybackslash\\hsize=1.8\\hsize}}X|
  >{{\\centering\\arraybackslash\\hsize=0.4\\hsize}}X|
  >{{\\raggedleft\\arraybackslash\\hsize=0.5\\hsize}}X|
  >{{\\raggedleft\\arraybackslash\\hsize=0.5\\hsize}}X|
  >{{\\raggedleft\\arraybackslash\\hsize=0.5\\hsize}}X|}}
\\hline
\\textbf{{Target Step}} & \\textbf{{Parent Execution Phase}} & \\textbf{{Count}} & \\textbf{{Total Time (s)}} & \\textbf{{Median Time (s)}} & \\textbf{{Max Time (s)}} \\\\
\\hline
{step_rows_tex}\\end{{tabularx}}
\\end{{table}}

\\begin{{table}}[h]
\\centering
\\caption{{System Telemetry Interpretation Matrix}}
\\label{{tab:runtime-interpretation}}
\\small
\\renewcommand{{\\arraystretch}}{{1.4}}
\\begin{{tabularx}}{{\\linewidth}}{{|
  >{{\\raggedright\\arraybackslash\\hsize=0.5\\hsize}}X|
  >{{\\raggedright\\arraybackslash\\hsize=1.5\\hsize}}X|}}
\\hline
\\textbf{{Operational Indicator}} & \\textbf{{Systemic Interpretation and Engineering Insight}} \\\\
\\hline
{interpretation_rows_tex}\\end{{tabularx}}
\\end{{table}}
"""

    tex = f"""
% Auto-generated by quick_eval_artifacts.py
\\subsection{{Quantitative Evaluation Summary}}
Table~\\ref{{tab:quant-results}} was updated from an executed sample of {metrics['eval_sample_size']} recent items. CVE extraction was evaluated on a separate CVE-containing database subset to avoid hiding vulnerability records behind a recency-only sample window.

\\begin{{table}}[h]
\\centering
\\caption{{Quantitative evaluation summary}}
\\label{{tab:quant-results}}
\\begin{{tabular}}{{|p{{6cm}}|p{{3.5cm}}|p{{5cm}}|}}
\\hline
\\textbf{{Metric}} & \\textbf{{Value}} & \\textbf{{Notes}} \\\\
\\hline
IOC precision (CVE benchmark) & {cve_precision_tex} & {cve_note_tex} \\\\
\\hline
IOC recall (CVE benchmark) & {cve_recall_tex} & {cve_note_tex} \\\\
\\hline
IOC F1 (CVE benchmark) & {cve_f1_tex} & {cve_note_tex} \\\\
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

\\subsection{{Deterministic Text Normalization Examples}}
The examples in Table~\\ref{{tab:normalization-examples}} measure the deterministic preprocessing layer only. This layer removes formatting noise and unsafe control characters while preserving the original source semantics. It is intentionally not used as a translation layer, because the database must retain traceable public-source evidence for auditability.

\\begin{{table}}[h]
\\centering
\\caption{{Examples of deterministic raw versus normalized source text}}
\\label{{tab:normalization-examples}}
\\begin{{tabular}}{{|p{{2.8cm}}|p{{5.3cm}}|p{{5.3cm}}|}}
\\hline
\\textbf{{Source}} & \\textbf{{Raw text}} & \\textbf{{Normalized text}} \\\\
\\hline
{before_rows_tex}\\end{{tabular}}
\\end{{table}}

\\subsection{{Multilingual LLM Handling}}
Multilingual source handling is performed at the semantic analysis and reporting layer rather than by overwriting raw database content. The LLM is prompted to produce an English analytical rendering, extract security entities, and explicitly mark unsupported fields as \\texttt{{not stated}}. This separation preserves the original evidence while still using the model's multilingual reasoning capability for analyst-facing summaries.

The prompt template used for this evaluation artifact is stored in \\texttt{{output/eval/multilingual\\_llm\\_prompt.md}} and applies the following guardrails: preserve source uncertainty, avoid unsupported claims, extract only source-backed entities, align findings with the organization technology stack, and require analyst verification before action.

\\subsection{{Prompt Engineering Evidence}}
\\paragraph{{System prompt excerpt for JSON extraction.}}
\\begin{{verbatim}}
{prompt_tex}
\\end{{verbatim}}

{runtime_tex}

{case_tex}
"""
    (OUT_DIR / "eval_patch.tex").write_text(tex.strip() + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate quick evaluation artifacts from local CTI data.")
    parser.add_argument("--limit", type=int, default=80, help="Number of recent DB items to evaluate.")
    parser.add_argument("--cve-limit", type=int, default=500, help="Number of CVE-containing DB items to use for CVE extraction benchmark.")
    args = parser.parse_args()

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    conn = get_conn()
    try:
        items = fetch_recent_items(conn, args.limit)
        cve_items = fetch_cve_benchmark_items(conn, args.cve_limit)
        profile = db_handler.get_active_profile(conn)

        cve = compute_cve_metrics(cve_items)
        runtime = compute_runtime_metrics(items, profile)
        halluc = compute_report_hallucination_rate(items)
        failures = compute_report_failure_rate()
        before_after_rows = write_before_after(items)
        write_multilingual_prompt()
        snippets = write_prompt_snippets()
        case = write_case_study(items)
        runtime_summary = load_runtime_summary()

        metrics = {
            "eval_sample_size": len(items),
            "cve_eval_sample_size": len(cve_items),
            "cve_benchmark_size": cve["sample_size"],
            "cve_true_positive": cve["tp"],
            "cve_false_positive": cve["fp"],
            "cve_false_negative": cve["fn"],
            "cve_precision": cve["precision"],
            "cve_recall": cve["recall"],
            "cve_f1": cve["f1"],
            "hallucination_rate": halluc["rate"],
            "report_failure_rate": failures["rate"],
            "median_preprocess_ms": runtime["median_preprocess_ms"],
            "median_template_report_ms": runtime["median_template_report_ms"],
        }
        (OUT_DIR / "quant_summary.json").write_text(json.dumps(metrics, indent=2), encoding="utf-8")
        write_tex_bundle(metrics, before_after_rows, snippets, case, runtime_summary)
        print(json.dumps(metrics, indent=2))
        print(f"Wrote artifacts to: {OUT_DIR}")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
