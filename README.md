# Adaptive LLM-Based Threat Intelligence System

**Course:** Penetration Testing — Hanoi University of Science and Technology (SOICT)  
**Authors:** Nguyen Phuong Linh (20225547), Pham Nguyen Hai Nhi (20225549)  
**Lecturer:** Nguyen Quoc Khanh

An LLM-assisted Cyber Threat Intelligence (CTI) pipeline that collects, processes, and prioritizes public threat information for small and medium-sized organizations. The system integrates heterogeneous public sources into a unified workflow and uses a local Large Language Model to support semantic threat interpretation and multi-tier analyst reporting.

---

## Table of Contents

1. [System Design](#1-system-design)
2. [Performance & Output Results](#2-performance--output-results)
3. [Installation Guide](#3-installation-guide)
4. [Source Code & Sample Data](#4-source-code--sample-data)
5. [Running the Pipeline](#5-running-the-pipeline)
6. [Dashboard](#6-dashboard)
7. [Evaluation Scripts](#7-evaluation-scripts)
8. [Limitations](#8-limitations)

---

## 1. System Design

### 1.1 Architecture Overview

The pipeline is organized into four sequential phases, each independently executable:

```
┌─────────────────────────────────────────────────────────────────┐
│                     PUBLIC INTELLIGENCE SOURCES                  │
│  NVD/CVE  │  CISA KEV  │  OTX  │  RSS  │  Reddit  │  Telegram  │
└─────────────────────────┬───────────────────────────────────────┘
                          │  Phase I: Collection
                          ▼
┌─────────────────────────────────────────────────────────────────┐
│                     PHASE II: PROCESSING                         │
│  Text Normalization → De-duplication → Credibility Scoring       │
│  (URL-exact → content-hash → semantic → LLM pairwise)           │
└─────────────────────────┬───────────────────────────────────────┘
                          │  SQLite persistence (intel_items)
                          ▼
┌─────────────────────────────────────────────────────────────────┐
│                   PHASE III: ANALYSIS                            │
│  Deterministic IOC Extraction (regex + iocextract)              │
│  → LLM Semantic Extraction → MITRE ATT&CK Validation            │
│  → Sigma Rule Generation → Organization Profile Matching        │
└─────────────────────────┬───────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────────┐
│                   PHASE IV: REPORTING                            │
│  Multi-tier Reports (Executive / Technical / Operational)        │
│  → Triage Workflow → Streamlit Dashboard                        │
└─────────────────────────────────────────────────────────────────┘
```

### 1.2 Component Map

| Directory / File | Role |
|-----------------|------|
| `core/` | Collectors (RSS, Reddit, Telegram, OTX, NVD, CISA KEV), processing orchestration, profile-aware contextual matching |
| `analysis/` | LLM client wrapper, IOC extractor, ATT&CK TTP mapper, Sigma rule engine |
| `reporting/` | Multi-tier report generator (executive / technical / operational) |
| `utils/` | SQLite handler, notification helpers |
| `pipeline.py` | CLI entry point; orchestrates phases |
| `app.py` | Streamlit dashboard (5 panels) |
| `config.yaml` | Runtime configuration: sources, LLM provider, organization profile, resource limits |
| `data/cti.db` | SQLite database — all collected, processed, and analyzed items |

### 1.3 Data Model

Each collected item is stored as a single row in `intel_items` with JSON blobs for flexible fields:

```
id              TEXT PRIMARY KEY   -- MD5 of (source + URL) for dedup
source          TEXT               -- e.g. "NVD/CVE", "Telegram/@cveNotify"
source_type     TEXT               -- feed | social | rss | Threat Feed
title           TEXT
content         TEXT
lang            TEXT               -- ISO 639-1 language code (langdetect)
credibility_score REAL             -- weighted composite [0, 1]
triage_status   TEXT               -- queued | watching | matched | ignored | archived | closed
raw_iocs        TEXT               -- JSON: {ips, cves, urls, sha256s, md5s, emails}
ttp_mapping     TEXT               -- JSON: validated MITRE technique IDs
processed       INTEGER            -- 0/1 Phase II completion flag
analyzed        INTEGER            -- 0/1 Phase III completion flag
```

**Credibility score formula:**

```
score = (source_weight × 0.45) + (quality_score × 0.25)
      + (artifact_score × 0.15) + (mention_multiplier × 0.15)
      + (lang_score × 0.05)
```

Source weights by tier: CISA KEV (0.95) > NVD (0.90) > OTX (0.80) > Telegram channels (0.68–0.72) > Reddit (0.55–0.65) > RSS (0.55).

### 1.4 Record Lifecycle

```
collected → queued → [processing] → watching / matched / ignored
                                         ↓
                                     [analysis]
                                         ↓
                                   archived / closed
```

- **matched**: item affects at least one asset in the organization's technology profile
- **ignored**: suppressed by de-duplication or below credibility threshold
- **watching**: collected, not yet analyzed

### 1.5 De-duplication Strategy

The pipeline applies a four-level cascade to suppress noise before Phase III:

1. **URL-exact**: identical source URL → immediate drop
2. **Content-hash**: MD5 of normalized content → drop exact reposts
3. **Semantic similarity** (optional): cosine similarity on sentence embeddings via `sentence-transformers` + FAISS
4. **LLM pairwise** (benchmark only): prompted comparison for near-duplicate pairs (disabled by default due to API cost)

### 1.6 LLM Integration

The system uses a local Ollama model (`qwen2.5:3b-instruct-q4_K_M` by default) or any OpenAI-compatible external API. All LLM calls share a single `generate_text()` abstraction so the provider can be switched without changing pipeline logic.

Anti-hallucination safeguards:
- ATT&CK T-code validation layer rejects technique IDs not present in the official MITRE index
- Low-confidence LLM suggestions are filtered before storage (confidence ≠ "high" → rejected)
- Grounded prompts reference only extracted content; no fabricated evidence
- All generated reports carry a mandatory `ANALYST VERIFICATION REQUIRED` notice

---

## 2. Performance & Output Results

### 2.1 CVE Extraction (Primary IOC Type)

Evaluated on a benchmark of 496 NVD/CISA items (sample size 500):

| Metric | Value |
|--------|-------|
| Precision | **1.000** (0 false positives) |
| Recall | **0.960** (22 missed CVEs) |
| F1 Score | **0.980** |
| True Positives | 526 |
| False Positives | 0 |
| False Negatives | 22 |
| Hallucination Rate | **0.0%** |
| Report Failure Rate | 4.1% (LLM timeout / invalid JSON) |

CVE extraction is fully deterministic (regex-based); zero false positives is expected by design.

### 2.2 De-duplication Effectiveness

Evaluated across 4,533 collected items:

| Source Type | Total | Suppressed | Noise Rate |
|-------------|-------|-----------|------------|
| social (Reddit, Telegram, Mastodon) | 2,520 | 349 | **13.8%** |
| feed (NVD, CISA, OTX) | 1,608 | 0 | 0.0% |
| rss (BleepingComputer, etc.) | 355 | 17 | 4.8% |
| Threat Feed | 50 | 21 | **42.0%** |
| **Overall** | **4,533** | **387** | **8.5%** |

Social sources show the highest noise rate (13.8%) due to cross-platform CVE reposts. Structured feeds (NVD, CISA KEV) have no duplicates because each item has a unique, canonical URL.

### 2.3 Source Coverage & Credibility

| Source Type | Total | Analyzed | Matched | Avg Credibility |
|-------------|-------|---------|---------|----------------|
| feed | 1,608 | 16 | 3 | **0.783** |
| social | 2,520 | 8 | 0 | 0.534 |
| Threat Feed | 50 | 1 | 0 | 0.529 |
| rss | 355 | 0 | 0 | 0.035 |

Feed sources dominate analysis candidates due to higher credibility scores. Low RSS credibility (0.035) reflects the absence of authentication/API key collection and the presence of stub items without content.

### 2.4 MITRE ATT&CK Mapping

Evaluated on 25 analyzed items (incremental batch):

| Metric | Value |
|--------|-------|
| Items with valid TTP mapping | 16 / 25 (**64.0%**) |
| Items with empty mapping | 9 / 25 (36.0%) |
| Most frequent technique | T1566 — Phishing (×9) |
| Second most frequent | T1190 — Exploit Public-Facing Application (×7) |

The technique distribution is consistent with the corpus: vulnerability advisories map to T1190 (exploitation) and social reports of phishing campaigns map to T1566.

### 2.5 Pipeline Runtime

| Step | Median Latency |
|------|---------------|
| Phase II text preprocessing (per item) | 7.26 ms |
| Template report generation (per item) | 2.01 ms |
| LLM extraction call (local Ollama, per item) | ~90 s (3B model, CPU-only) |
| ATT&CK T-code validation (per item) | ~10–13 ms |
| IOC regex extraction (per item) | 3–8 ms |

Non-LLM processing is negligible (<10 ms per item). LLM inference on a CPU-only laptop is the primary bottleneck; switching to an external API (DeepSeek, Groq) reduces per-item time to ~2–5 s.

### 2.6 Multilingual Coverage

4,533 items across 12 detected languages:

| Language | Items | Share |
|----------|-------|-------|
| English (en) | 4,436 | 97.9% |
| German (de) | 23 | 0.5% |
| Italian (it) | 18 | 0.4% |
| Korean (ko) | 17 | 0.4% |
| Vietnamese (vi) | 8 | 0.2% |
| Russian (ru) | 6 | 0.1% |
| Others (7 languages) | 25 | 0.6% |

97 non-English items (2.1%) remain in `queued` status; candidate selection prioritizes credibility score, and English feed sources (avg 0.783) consistently outrank non-English social items (avg 0.534) within the current dataset.

---

## 3. Installation Guide

### 3.1 Prerequisites

| Requirement | Version | Notes |
|-------------|---------|-------|
| Python | 3.10+ | 3.11 recommended |
| pip | 23+ | |
| Ollama | latest | For local LLM inference |
| Git | any | |
| RAM | ≥ 8 GB | 16 GB recommended for local 3B model |

Optional (only if enabling those sources):
- Telegram account + API credentials
- Reddit API credentials (client_id, client_secret)
- AlienVault OTX API key
- External LLM API key (DeepSeek / OpenRouter / Groq)

### 3.2 Step-by-Step Installation

**Step 1 — Clone the repository**

```bash
git clone https://github.com/WaterlilyCrystal/cti-adaptive-pipeline.git
cd cti-adaptive-pipeline
```

**Step 2 — Create and activate a virtual environment**

```bash
# Windows
python -m venv .venv
.venv\Scripts\activate

# Linux / macOS
python -m venv .venv
source .venv/bin/activate
```

**Step 3 — Install Python dependencies**

```bash
pip install -r requirements.txt
```

> **Note:** `iocextract` requires `libmagic` on Linux. On Windows this is bundled with the package. If installation of `faiss-cpu` fails, install it separately: `pip install faiss-cpu --no-build-isolation`.

**Step 4 — Configure environment variables**

```bash
# Windows
copy .env.example .env

# Linux / macOS
cp .env.example .env
```

Edit `.env` and fill only the keys you plan to use:

```env
# For local Ollama: leave all API keys empty

# For external LLM (example: DeepSeek)
DEEPSEEK_API_KEY=sk-...

# For Telegram collection
TELEGRAM_API_ID=12345678
TELEGRAM_API_HASH=abcdef1234567890abcdef1234567890
TELEGRAM_PHONE_NUMBER=+84912345678

# For Reddit collection
REDDIT_CLIENT_ID=your_client_id
REDDIT_CLIENT_SECRET=your_client_secret

# For AlienVault OTX
OTX_API_KEY=your_otx_key
```

**Step 5 — Configure the pipeline**

Edit `config.yaml` to match your environment:

```yaml
# LLM runtime — choose one

# Option A: Local Ollama
llm:
  runtime: ollama
  model: qwen2.5:3b-instruct-q4_K_M

# Option B: External API (DeepSeek example)
llm:
  runtime: deepseek
  model: deepseek-chat
  api_base_url: https://api.deepseek.com
  api_key_env: DEEPSEEK_API_KEY

# Organization technology profile (for matched triage)
organization:
  technology_stack:
    - Nginx
    - PostgreSQL
    - AWS
    - Redis
    - Windows Server

# Enable/disable sources
sources:
  nvd: true
  cisa_kev: true
  otx: true            # requires OTX_API_KEY
  rss: true
  reddit: false        # requires REDDIT_CLIENT_ID / SECRET
  telegram: false      # requires TELEGRAM credentials
```

**Step 6 — Set up Ollama (local inference only)**

```bash
# Install Ollama from https://ollama.com
ollama pull qwen2.5:3b-instruct-q4_K_M
ollama serve   # keep running in a separate terminal
```

Verify Ollama is responding:

```bash
curl http://localhost:11434/api/tags
```

**Step 7 — Initialize the database**

The database is created automatically on first run. No manual migration is needed.

**Step 8 — Verify installation**

```bash
python pipeline.py --phase=collect --dry-run
```

This should complete without errors and report the number of items that would be collected.

### 3.3 Common Installation Issues

| Error | Cause | Fix |
|-------|-------|-----|
| `ModuleNotFoundError: iocextract` | pip install incomplete | `pip install iocextract` |
| `ollama: connection refused` | Ollama not running | Run `ollama serve` in a separate terminal |
| `sqlite3.OperationalError: no such table` | First run before DB init | Run `pipeline.py --phase=collect` first |
| `langdetect: No features in text` | Empty content field | Expected for stub items; not a fatal error |
| `faiss-cpu` build failure on Windows | Missing C++ build tools | `pip install faiss-cpu --no-build-isolation` or use pre-built wheel |
| Telegram `FloodWaitError` | Rate limit hit | Reduce collection frequency in `config.yaml` |

---

## 4. Source Code & Sample Data

### 4.1 Source Code Structure

```
cti-adaptive-pipeline/
├── pipeline.py              # CLI entry point (--phase collect|process|analyze|all)
├── app.py                   # Streamlit dashboard (5 panels)
├── config.yaml              # All runtime configuration
├── requirements.txt         # Python dependencies
├── .env.example             # Environment variable template
│
├── core/
│   ├── collectors/          # Per-source collection modules
│   │   ├── nvd_collector.py
│   │   ├── cisa_collector.py
│   │   ├── otx_collector.py
│   │   ├── rss_collector.py
│   │   ├── reddit_collector.py
│   │   └── telegram_collector.py
│   ├── processor.py         # Normalization, dedup, credibility scoring
│   └── contextual_matcher.py # Organization profile matching
│
├── analysis/
│   ├── llm_client.py        # LLM abstraction (Ollama / OpenAI-compatible)
│   ├── ioc_extractor.py     # Regex + iocextract IOC extraction
│   ├── ttp_mapper.py        # ATT&CK TTP mapping + MITRE validation
│   └── sigma_engine.py      # Sigma rule generation
│
├── reporting/
│   └── reporter.py          # Multi-tier report generator
│
├── utils/
│   ├── db_handler.py        # SQLite CRUD operations
│   └── notifier.py          # Alert/notification helpers
│
├── templates/               # Jinja2 report templates
├── data/                    # Runtime data (cti.db, ATT&CK cache)
├── output/                  # Generated reports, Sigma rules, eval artifacts
│   ├── reports/             # Per-item Markdown reports
│   ├── sigma/               # Generated .yml Sigma rules
│   └── eval/                # Evaluation JSON + LaTeX artifacts
│
└── sample_data/             # Representative demo data (see §4.2)
    ├── input/
    │   └── sample_collected_items.json
    └── output/
        ├── sample_ioc_extraction.json
        ├── sample_attck_mapping.json
        ├── reports/
        │   └── sample_report_nginx_ransomware.md
        └── sigma_rules/
            ├── detect_nginx_ransomware_T1190.yml
            └── detect_apt29_phishing_T1566.yml
```

### 4.2 Sample Data Walkthrough

The `sample_data/` directory contains a self-contained, runnable example of every pipeline output type. It does not require a live database or LLM to inspect.

#### Input: `sample_data/input/sample_collected_items.json`

8 realistic CTI items representing what Phase I collection produces. Each item shows the full database record schema after normalization and credibility scoring:

| Item | Source | `triage_status` | `credibility_score` | Key IOCs |
|------|--------|-----------------|---------------------|---------|
| CVE-2025-21298 Windows OLE RCE | NVD/CVE (feed) | `queued` | 0.90 | CVE-2025-21298 |
| CVE-2025-30065 Apache Parquet RCE | Telegram/@cveNotify | `matched` | 0.72 | CVE-2025-30065 |
| Nginx ransomware campaign | Mastodon/@vxunderground | `matched` | 0.68 | 2 IPs, 1 SHA256, CVE-2024-38473 |
| CVE-2025-0282 Ivanti KEV | CISA KEV (feed) | `queued` | 0.95 | CVE-2025-0282 |
| CVE-2025-1094 PostgreSQL auth bypass | Reddit/r/netsec | `matched` | 0.61 | CVE-2025-1094 |
| Lazarus LinkedIn campaign | BleepingComputer (rss) | `queued` | 0.55 | — |
| CVE-2025-21605 Redis RCE | Telegram/@vxunderground | `matched` | 0.70 | CVE-2025-21605 |
| APT29 phishing + AWS creds | AlienVault OTX (feed) | `matched` | 0.80 | 1 IP, 2 defanged URLs, 1 SHA256 |

Items with `"matched"` status have `"impacted_assets"` populated by the organization profile matcher (e.g., `["Nginx", "AWS"]`).

#### Output: `sample_data/output/sample_ioc_extraction.json`

IOC extraction results for 3 items (those with extractable network indicators):

```json
{
  "item_id": "c3d4e5f6...",
  "source": "Mastodon/@vxunderground",
  "extracted_iocs": {
    "ips":    ["185.220.101.45", "193.142.147.65"],
    "sha256s": ["e3b0c44298fc1c..."],
    "cves":   ["CVE-2024-38473"]
  },
  "extraction_method": "hybrid (regex + iocextract)",
  "extraction_time_ms": 6.4
}
```

Defanged URLs from OTX are refanged before storage: `hxxps://aws-secure-login[.]com` → stored as defanged to prevent accidental click-through.

#### Output: `sample_data/output/sample_attck_mapping.json`

ATT&CK mapping with validation for 2 items (APT29 phishing, Nginx ransomware):

- `T1566.002` (Spearphishing Link) and `T1078` (Valid Accounts) → **validated** (both in MITRE index, confidence "high")
- `T1556` → **rejected** (confidence "low" — filtered by guardrail)
- `T1190` (Exploit Public-Facing Application) and `T1486` (Data Encrypted for Impact) → **validated**

This demonstrates the validation layer: the LLM suggested 3 techniques for the APT29 item but only 2 passed the guardrail check.

#### Output: `sample_data/output/reports/sample_report_nginx_ransomware.md`

Full three-tier report for the Nginx ransomware campaign item:
- **Executive summary** — business impact, affected systems, recommended immediate action
- **Technical report** — CVEs, IOCs, MITRE techniques with evidence, Sigma rule reference
- **Operational report** — step-by-step containment and remediation checklist

All three tiers include: `⚠ ANALYST VERIFICATION REQUIRED — AI-generated content pending review`

#### Output: `sample_data/output/sigma_rules/`

Two auto-generated Sigma detection rules:

| File | Technique | Logic |
|------|-----------|-------|
| `detect_nginx_ransomware_T1190.yml` | T1190 | Web server path traversal patterns in HTTP logs |
| `detect_apt29_phishing_T1566.yml` | T1566.002 | Email gateway indicators: phishing domains, suspicious sender patterns |

Both rules include `falsepositives` guidance and are YAML-validated before saving.

---

## 5. Running the Pipeline

### 5.1 Individual Phases

```bash
# Phase I: Collect from all enabled sources
python pipeline.py --phase=collect

# Phase II: Normalize, deduplicate, score
python pipeline.py --phase=process

# Phase III: Extract IOCs, map ATT&CK, generate reports
python pipeline.py --phase=analyze

# Full end-to-end run
python pipeline.py --phase=all
```

### 5.2 Windows Auto-run

A convenience batch script runs all phases sequentially:

```bash
auto_run_windows.bat
```

### 5.3 Analyze a Specific Item

```bash
python run_analysis.py --item-id <id>
```

### 5.4 Benchmark an External LLM Provider

```bash
python benchmark_llm_api.py \
  --runtime deepseek \
  --model deepseek-chat \
  --api-base-url https://api.deepseek.com \
  --api-key-env DEEPSEEK_API_KEY
```

---

## 6. Dashboard

```bash
streamlit run app.py
```

Opens at `http://localhost:8501`. Five panels:

| Panel | Contents |
|-------|----------|
| **Overview** | Pipeline stats, triage distribution, credibility histogram |
| **Threat Feed** | Paginated feed of all collected items with triage controls |
| **Organization Profile** | Technology stack editor; triggers re-matching of existing items |
| **Reports** | Browse and download generated multi-tier Markdown reports |
| **Sigma** | View and download generated Sigma detection rules |

---

## 7. Evaluation Scripts

### Regenerate evaluation metrics

```bash
python quick_eval_artifacts.py --limit 80
```

Writes to `output/eval/`:
- `quant_summary.json` — CVE precision/recall/F1, hallucination rate, latency
- `before_after_examples.csv` — normalization before/after examples
- `prompt_snippets.md` — prompt engineering excerpts
- `eval_patch.tex` — LaTeX-ready evaluation section

### Extended evaluation (all metrics including dedup, ATT&CK, multilingual)

```bash
python eval_improvements.py
# or with a higher sample limit:
python eval_improvements.py --limit 500
```

Writes to `output/eval/`:
- `eval_improvements_data.json` — all metrics as structured JSON
- `eval_patch_v2.tex` — complete LaTeX evaluation section with all data filled

### Phase timing benchmarks

Every `pipeline.py` run writes timing data to:
- `output/eval/phase_timings.jsonl`
- `output/eval/phase_timings_summary.json`
- `output/eval/phase_timings_summary.csv`

---

## 8. Limitations

- Public-source collection quality varies significantly by platform; Telegram and Reddit content can be unverified and noisy
- Telegram collection requires an authenticated user account (not a bot token)
- Local LLM inference on CPU is slow (~90 s per item for a 3B-parameter model); external API reduces this to ~2–5 s but introduces dependency on provider availability and rate limits
- ATT&CK mapping quality depends on model capability; the 3B quantized model occasionally misses multi-step attack chains
- The current corpus is dominated by vulnerability advisories (NVD/CISA KEV), so IP and URL IOC extraction metrics are not representative of the extractor's capability on network-IOC-rich sources
- Evaluation sample size for LLM-dependent metrics (ATT&CK, semantic dedup) is small due to inference time constraints on local hardware
- No manually labeled ground-truth dataset for ATT&CK mapping; recall cannot be measured directly

## License

MIT — see [LICENSE](LICENSE).
