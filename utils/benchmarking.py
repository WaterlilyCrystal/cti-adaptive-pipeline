from __future__ import annotations

import csv
import json
import statistics
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator


RUN_ID = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "_" + uuid.uuid4().hex[:8]
OUT_DIR = Path("output") / "eval"
TIMING_JSONL = OUT_DIR / "phase_timings.jsonl"
TIMING_SUMMARY_JSON = OUT_DIR / "phase_timings_summary.json"
TIMING_SUMMARY_CSV = OUT_DIR / "phase_timings_summary.csv"
PHASE_SUMMARY_JSON = OUT_DIR / "phase_totals_summary.json"
PHASE_SUMMARY_CSV = OUT_DIR / "phase_totals_summary.csv"
TIMING_RUN_JSON = OUT_DIR / "latest_timing_run.json"
TIMING_LATEX = OUT_DIR / "phase_timings_patch.tex"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def record_timing(
    *,
    phase: str,
    step: str,
    duration_seconds: float,
    success: bool = True,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    record = {
        "run_id": RUN_ID,
        "timestamp": _now_iso(),
        "phase": phase,
        "step": step,
        "duration_seconds": round(float(duration_seconds), 6),
        "duration_ms": round(float(duration_seconds) * 1000, 3),
        "success": bool(success),
        "metadata": metadata or {},
    }
    with TIMING_JSONL.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, ensure_ascii=False) + "\n")
    return record


@contextmanager
def timed_step(phase: str, step: str, metadata: dict[str, Any] | None = None) -> Iterator[None]:
    start = time.perf_counter()
    success = True
    try:
        yield
    except Exception:
        success = False
        raise
    finally:
        record_timing(
            phase=phase,
            step=step,
            duration_seconds=time.perf_counter() - start,
            success=success,
            metadata=metadata,
        )


def write_timing_summary(run_id: str | None = None) -> list[dict[str, Any]]:
    if not TIMING_JSONL.exists():
        return []

    selected_run_id = run_id or RUN_ID
    records = []
    with TIMING_JSONL.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if record.get("run_id") == selected_run_id:
                records.append(record)

    grouped: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for record in records:
        grouped.setdefault((record["phase"], record["step"]), []).append(record)

    step_summary = []
    for (phase, step), group in sorted(grouped.items()):
        durations = [float(item["duration_seconds"]) for item in group]
        step_summary.append(
            {
                "run_id": selected_run_id,
                "phase": phase,
                "step": step,
                "count": len(group),
                "success_count": sum(1 for item in group if item.get("success")),
                "failure_count": sum(1 for item in group if not item.get("success")),
                "total_seconds": round(sum(durations), 6),
                "mean_seconds": round(statistics.mean(durations), 6),
                "median_seconds": round(statistics.median(durations), 6),
                "min_seconds": round(min(durations), 6),
                "max_seconds": round(max(durations), 6),
            }
        )

    phase_grouped: dict[str, list[dict[str, Any]]] = {}
    for record in records:
        phase_grouped.setdefault(record["phase"], []).append(record)

    phase_summary = []
    for phase, group in sorted(phase_grouped.items()):
        durations = [float(item["duration_seconds"]) for item in group]
        phase_summary.append(
            {
                "run_id": selected_run_id,
                "phase": phase,
                "event_count": len(group),
                "success_count": sum(1 for item in group if item.get("success")),
                "failure_count": sum(1 for item in group if not item.get("success")),
                "total_seconds": round(sum(durations), 6),
                "mean_seconds": round(statistics.mean(durations), 6),
                "median_seconds": round(statistics.median(durations), 6),
                "min_seconds": round(min(durations), 6),
                "max_seconds": round(max(durations), 6),
            }
        )

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    TIMING_SUMMARY_JSON.write_text(json.dumps(step_summary, indent=2, ensure_ascii=False), encoding="utf-8")
    with TIMING_SUMMARY_CSV.open("w", newline="", encoding="utf-8") as handle:
        fieldnames = [
            "run_id",
            "phase",
            "step",
            "count",
            "success_count",
            "failure_count",
            "total_seconds",
            "mean_seconds",
            "median_seconds",
            "min_seconds",
            "max_seconds",
        ]
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(step_summary)

    PHASE_SUMMARY_JSON.write_text(json.dumps(phase_summary, indent=2, ensure_ascii=False), encoding="utf-8")
    with PHASE_SUMMARY_CSV.open("w", newline="", encoding="utf-8") as handle:
        fieldnames = [
            "run_id",
            "phase",
            "event_count",
            "success_count",
            "failure_count",
            "total_seconds",
            "mean_seconds",
            "median_seconds",
            "min_seconds",
            "max_seconds",
        ]
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(phase_summary)

    run_metadata = {
        "run_id": selected_run_id,
        "started_at": min((item["timestamp"] for item in records), default=""),
        "ended_at": max((item["timestamp"] for item in records), default=""),
        "record_count": len(records),
        "step_summary_count": len(step_summary),
        "phase_summary_count": len(phase_summary),
    }
    TIMING_RUN_JSON.write_text(
        json.dumps(
            {
                "run": run_metadata,
                "phase_summary": phase_summary,
                "step_summary": step_summary,
            },
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    phase_rows_tex = ""
    for row in phase_summary:
        phase_rows_tex += (
            f"{row['phase']} & {row['event_count']} & {row['success_count']} & "
            f"{row['failure_count']} & {row['total_seconds']:.3f} & {row['median_seconds']:.3f} \\\\\n\\hline\n"
        )
    TIMING_LATEX.write_text(
        (
            "% Auto-generated by utils.benchmarking.write_timing_summary\n"
            "\\subsection{Phase Runtime Measurement}\n"
            "Runtime measurements were collected automatically during pipeline execution using internal timing hooks placed at phase and step boundaries. "
            f"The summarized run identifier was \\texttt{{{selected_run_id}}}.\n\n"
            "\\begin{table}[h]\n"
            "\\centering\n"
            "\\caption{Runtime summary by phase}\n"
            "\\begin{tabular}{|p{4.3cm}|p{1.4cm}|p{1.4cm}|p{1.4cm}|p{2cm}|p{2cm}|}\n"
            "\\hline\n"
            "\\textbf{Phase} & \\textbf{Events} & \\textbf{OK} & \\textbf{Fail} & \\textbf{Total (s)} & \\textbf{Median (s)} \\\\\n"
            "\\hline\n"
            f"{phase_rows_tex}"
            "\\end{tabular}\n"
            "\\end{table}\n"
        ),
        encoding="utf-8",
    )
    return step_summary
