# Adaptive Cyber Threat Intelligence Pipeline

Adaptive Cyber Threat Intelligence Pipeline is a local-first CTI workflow for collecting, processing, and analyzing public threat information from multiple sources. The project focuses on turning noisy external content into structured, reviewable intelligence with explicit analyst verification points.

## Project Scope

The system supports:

- Collection from selected public sources such as RSS feeds, Reddit, Telegram, OTX, and structured vulnerability sources
- Text normalization, filtering, and de-duplication
- Deterministic extraction of indicators such as CVEs, IPs, domains, URLs, and hashes
- LLM-assisted semantic analysis and multi-tier reporting
- Profile-aware matching against an organization's technology stack
- Streamlit-based dashboard review for analysts and project demonstration

The project is intended as an academic and engineering prototype. It is not a replacement for commercial CTI platforms or human-led security validation.

## Architecture Summary

The pipeline is organized into four stages:

1. `collect`: gather raw items from supported public sources
2. `process`: normalize, de-duplicate, and score collected items
3. `analyze`: extract IOCs, perform semantic CTI analysis, and generate reports
4. `all`: run the end-to-end workflow

Processed records are stored in SQLite and surfaced in the Streamlit dashboard.

## Technology Stack

- Python
- SQLite
- Streamlit
- Ollama
- Requests, Feedparser, Telethon, PRAW-compatible Reddit access patterns
- YAML and JSON
- Optional resource monitoring with `psutil`

## Repository Structure

```text
analysis/       LLM client, IOC extraction, ATT&CK mapping, Sigma generation
core/           Collectors, processing logic, contextual matching
data/           Local database and ATT&CK cache artifacts
output/         Generated reports, rules, notifications, and evaluation artifacts
reporting/      Multi-tier reporting logic
utils/          Database and notification helpers
app.py          Streamlit dashboard
pipeline.py     Main CLI orchestrator
```

## Prerequisites

- Python 3.10+
- Ollama installed locally
- A local Ollama model available, for example `qwen2.5:3b-instruct-q4_K_M`
- Telegram credentials if Telegram collection is enabled
- Optional API keys depending on enabled integrations

## Installation

1. Install Python dependencies:

```bash
pip install -r requirements.txt
```

2. Prepare the environment file:

```bash
copy .env.example .env
```

3. Update `.env` with the credentials you actually plan to use.

4. Review `config.yaml` and adjust:

- enabled data sources
- LLM runtime settings
- organization profile
- resource limits

5. Ensure Ollama is running locally and the configured model is available.

Example:

```bash
ollama pull qwen2.5:3b-instruct-q4_K_M
```

## Running the Pipeline

Run one stage at a time:

```bash
python pipeline.py --phase=collect
python pipeline.py --phase=process
python pipeline.py --phase=analyze
```

Run the full pipeline:

```bash
python pipeline.py --phase=all
```

## Launching the Dashboard

```bash
streamlit run app.py
```

The dashboard includes:

- Overview
- Threat Feed
- Organization Profile
- Reports
- Sigma

## Evaluation Artifacts

To regenerate the lightweight evaluation summary used in the report:

```bash
python quick_eval_artifacts.py --limit 80
```

This writes artifacts to `output/eval/`, including:

- `quant_summary.json`
- `before_after_examples.csv`
- `prompt_snippets.md`
- `case_study.json`
- `eval_patch.tex`

## Dashboard Notes

The dashboard prioritizes reviewability over perfect real-time visualization. When a specific visualization does not yet have enough live supporting data, the interface should explicitly indicate that the panel is illustrative rather than silently presenting it as measured output.

## Responsible AI and Verification

This project uses an LLM as an assistive analysis layer, not as an unquestionable authority.

Current safeguards include:

- deterministic extraction for structured indicators where possible
- grounded prompts for report generation
- explicit handling of missing evidence
- verification notices appended to generated reports
- fallback reporting when the LLM is unavailable or produces invalid output

All generated reports, mitigation suggestions, and prioritization results should be validated before operational action.

## Limitations

- Public-source collection quality varies significantly by platform
- Telegram collection requires authenticated account access
- Reddit and other social sources can be noisy and incomplete
- Local LLM inference can still be constrained by RAM, context size, and runtime stability
- ATT&CK mapping and report generation remain partially dependent on model quality
- Evaluation metrics currently emphasize reproducible local checks, not a large manually labeled benchmark

## Suggested Demo Workflow

For project presentation or report screenshots:

1. Run `collect`, `process`, and `analyze`
2. Launch `streamlit run app.py`
3. Capture:
   - Overview
   - one representative report event
   - one Sigma rule
   - one organization-profile matching example

## Academic Integrity Note

The repository should be presented as an engineering project that combines deterministic data handling with LLM-assisted interpretation. Any dashboard panel, evaluation metric, or generated report included in the final write-up should be traceable to either:

- a real collected sample,
- a clearly labeled illustrative example, or
- a documented fallback path.

Avoid claiming complete threat coverage, perfect extraction accuracy, or fully autonomous operational decision-making.
