import glob
import os
import sqlite3
import textwrap

import pandas as pd
import streamlit as st
from streamlit_autorefresh import st_autorefresh
import yaml

from core.contextual import (
    TECH_CATALOG,
    canonicalize_technology_name,
    get_discovery_live_mode,
    get_discovery_provider,
    get_discovery_timeout,
    normalize_tech_stack,
    passive_discover_technologies,
    sleep_well_indicator,
)
from utils import db_handler

st_autorefresh(interval=60000, limit=None, key="soc_dashboard_refresh")

st.set_page_config(page_title="Adaptive CTI Dashboard", page_icon="shield", layout="wide", initial_sidebar_state="expanded")

BASE_DIR = os.path.dirname(__file__)
REPORTS_DIR = os.path.join(BASE_DIR, "output", "reports")
SIGMA_DIR = os.path.join(BASE_DIR, "output", "sigma_rules")
DB_PATH = os.path.join(BASE_DIR, "data", "cti.db")
CONFIG_PATH = os.path.join(BASE_DIR, "config.yaml")


def load_dashboard_config():
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as handle:
            return yaml.safe_load(handle) or {}
    except Exception:
        return {}


DASHBOARD_CONFIG = load_dashboard_config()
DISCOVERY_CONFIG = DASHBOARD_CONFIG.get("tech_discovery", {})


def inject_showcase_styles():
    st.markdown(
        """
        <style>
        @import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;700&family=IBM+Plex+Mono:wght@400;500&display=swap');

        html, body, [class*="css"] {
            font-family: 'Space Grotesk', sans-serif;
        }

        .showcase-shell {
            background:
                radial-gradient(circle at top left, rgba(255,91,114,0.12), transparent 24%),
                radial-gradient(circle at top right, rgba(71,189,255,0.14), transparent 28%),
                linear-gradient(145deg, #081321 0%, #0b1628 40%, #132338 100%);
            border: 1px solid rgba(148, 163, 184, 0.18);
            border-radius: 24px;
            padding: 26px 28px;
            box-shadow: 0 26px 60px rgba(2, 8, 23, 0.35);
            margin-bottom: 18px;
        }

        .showcase-hero {
            display: grid;
            grid-template-columns: 1.55fr 0.85fr;
            gap: 16px;
            margin-bottom: 16px;
        }

        .showcase-card {
            border-radius: 20px;
            border: 1px solid rgba(148, 163, 184, 0.14);
            background: linear-gradient(180deg, rgba(15,23,42,0.76), rgba(20,34,56,0.72));
            padding: 22px;
        }

        .showcase-eyebrow {
            display: inline-block;
            padding: 6px 12px;
            border-radius: 999px;
            background: rgba(255, 91, 114, 0.15);
            color: #ffd6de;
            border: 1px solid rgba(255, 91, 114, 0.25);
            font-size: 12px;
            font-weight: 700;
            letter-spacing: 0.7px;
            text-transform: uppercase;
            margin-bottom: 14px;
        }

        .showcase-title {
            color: #f8fbff;
            font-size: 38px;
            line-height: 1.04;
            font-weight: 700;
            margin: 0 0 12px 0;
        }

        .showcase-copy {
            color: #98adcb;
            font-size: 16px;
            line-height: 1.6;
        }

        .showcase-alert {
            background: linear-gradient(180deg, rgba(82, 17, 30, 0.88), rgba(51, 12, 21, 0.9));
            border: 1px solid rgba(255,91,114,0.22);
        }

        .showcase-alert-k {
            color: #ffc7d2;
            font-size: 12px;
            font-weight: 700;
            letter-spacing: 0.8px;
            text-transform: uppercase;
        }

        .showcase-alert-v {
            color: white;
            font-size: 70px;
            line-height: 1;
            font-weight: 700;
            margin: 10px 0 12px 0;
        }

        .showcase-alert-p {
            color: #ffd7de;
            font-size: 15px;
            line-height: 1.55;
        }

        .showcase-banner {
            display: grid;
            grid-template-columns: 150px 1fr;
            gap: 16px;
            align-items: center;
            margin-bottom: 16px;
            border-radius: 18px;
            border: 1px solid rgba(255,91,114,0.26);
            background: linear-gradient(90deg, rgba(127,29,29,0.95), rgba(91,22,36,0.92) 38%, rgba(54,16,27,0.92) 100%);
            padding: 16px 18px;
            box-shadow: 0 16px 36px rgba(69, 10, 10, 0.28);
        }

        .showcase-banner-left {
            color: white;
            font-size: 28px;
            font-weight: 700;
            line-height: 1;
        }

        .showcase-banner-right {
            color: #ffe1e7;
            font-size: 15px;
            line-height: 1.5;
        }

        .showcase-metrics {
            display: grid;
            grid-template-columns: repeat(4, minmax(0, 1fr));
            gap: 14px;
            margin-bottom: 16px;
        }

        .showcase-metric {
            border-radius: 18px;
            border: 1px solid rgba(148,163,184,0.12);
            background: rgba(15,23,42,0.62);
            padding: 16px 18px;
        }

        .showcase-metric-k {
            color: #8fa6c7;
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 0.7px;
        }

        .showcase-metric-v {
            color: #f8fbff;
            font-size: 32px;
            line-height: 1.1;
            font-weight: 700;
            margin-top: 6px;
        }

        .showcase-metric-p {
            color: #7dd3fc;
            font-size: 15px;
            margin-top: 7px;
            line-height: 1.45;
        }

        .showcase-grid {
            display: grid;
            grid-template-columns: 1.1fr 0.9fr 0.9fr;
            gap: 16px;
        }

        .showcase-panel-title {
            color: #f8fbff;
            font-size: 22px;
            font-weight: 700;
            margin-bottom: 14px;
        }

        .showcase-panel-note {
            color: #8fa6c7;
            font-size: 14px;
            line-height: 1.6;
            margin-bottom: 12px;
        }

        .heatmap-wrap {
            display: grid;
            gap: 9px;
        }

        .heatmap-head, .heatmap-row {
            display: grid;
            grid-template-columns: minmax(120px, 1.45fr) repeat(4, minmax(54px, 0.7fr));
            gap: 8px;
            align-items: center;
        }

        .heatmap-head {
            padding: 0 2px 2px 2px;
        }

        .heatmap-head div {
            color: #7e97b7;
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 0.7px;
            font-weight: 700;
        }

        .heatmap-row {
            border-radius: 14px;
            padding: 8px;
            background: linear-gradient(180deg, rgba(255,255,255,0.02), rgba(255,255,255,0.035));
            border: 1px solid rgba(148,163,184,0.10);
        }

        .heatmap-label {
            color: #f3f7fd;
            font-size: 13px;
            font-weight: 600;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
            padding-left: 2px;
        }

        .heatbox {
            min-width: 54px;
            text-align: center;
            padding: 9px 0;
            border-radius: 10px;
            border: 1px solid transparent;
            font-family: 'IBM Plex Mono', monospace;
            font-size: 13px;
            font-weight: 600;
        }

        .heat-low {
            background: rgba(51, 65, 85, 0.58);
            border-color: rgba(100, 116, 139, 0.28);
            color: #d9e6f7;
        }

        .heat-med {
            background: rgba(255, 193, 94, 0.16);
            border-color: rgba(255, 193, 94, 0.26);
            color: #ffe2a1;
        }

        .heat-high {
            background: rgba(255, 91, 114, 0.18);
            border-color: rgba(255, 91, 114, 0.26);
            color: #ffd2db;
        }

        .feature-item {
            border-radius: 15px;
            padding: 14px;
            margin-bottom: 12px;
            background: rgba(255,255,255,0.03);
            border: 1px solid rgba(148,163,184,0.12);
        }

        .feature-item:last-child {
            margin-bottom: 0;
        }

        .feature-k {
            color: #8fa6c7;
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 0.7px;
            margin-bottom: 6px;
        }

        .feature-v {
            color: #ffffff;
            font-size: 17px;
            font-weight: 700;
            margin-bottom: 4px;
        }

        .feature-p {
            color: #cedbeb;
            font-size: 14px;
            line-height: 1.6;
        }

        .flow-step {
            position: relative;
            display: grid;
            grid-template-columns: 38px 1fr;
            gap: 12px;
            align-items: start;
            margin-bottom: 12px;
            padding: 10px 12px 10px 10px;
            border-radius: 14px;
            background: rgba(255,255,255,0.03);
            border: 1px solid rgba(148,163,184,0.12);
        }

        .flow-step:last-child {
            margin-bottom: 0;
        }

        .flow-step:not(:last-child)::after {
            content: "";
            position: absolute;
            left: 25px;
            top: 38px;
            bottom: -14px;
            width: 1px;
            background: linear-gradient(180deg, rgba(71,189,255,0.30), rgba(71,189,255,0.02));
        }

        .flow-num {
            width: 32px;
            height: 32px;
            border-radius: 999px;
            display: flex;
            align-items: center;
            justify-content: center;
            background: rgba(71,189,255,0.14);
            border: 1px solid rgba(71,189,255,0.22);
            color: #d8f6ff;
            font-family: 'IBM Plex Mono', monospace;
            font-weight: 700;
        }

        .flow-title {
            color: white;
            font-size: 14px;
            font-weight: 700;
            margin-bottom: 3px;
        }

        .flow-copy {
            color: #bfd0e5;
            font-size: 14px;
            line-height: 1.6;
        }

        @media (max-width: 1100px) {
            .showcase-hero, .showcase-metrics, .showcase-grid {
                grid-template-columns: 1fr !important;
            }
        }

        .stTabs [data-baseweb="tab"] {
            min-height: 46px;
            padding: 8px 18px;
        }

        .stTabs [data-baseweb="tab"] p {
            font-size: 17px;
            font-weight: 700;
            letter-spacing: 0;
        }

        .stTabs [data-baseweb="tab-highlight"] {
            height: 3px;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


def read_file_content(filepath):
    try:
        with open(filepath, "r", encoding="utf-8") as handle:
            content = handle.read()
            lowered = content.strip().lower()
            if lowered.startswith("llm generation error:") or lowered.startswith("500 server error:") or lowered.startswith("traceback"):
                return (
                    "Report generation previously failed for this item.\n\n"
                    "The stored report file contained a runtime error instead of valid Markdown content."
                )
            return content
    except Exception as exc:
        return f"Error reading file: {exc}"


def get_files_in_dir(directory, extension="*"):
    if not os.path.exists(directory):
        return []
    return sorted(glob.glob(os.path.join(directory, f"*.{extension}")))


def open_connection():
    if not os.path.exists(DB_PATH):
        return db_handler.init_db()
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def save_profile_form(conn):
    profile = db_handler.get_active_profile(conn)
    profile_stack = normalize_tech_stack(profile.get("tech_stack", {}))
    st.subheader("Organization Profile")
    col1, col2, col3 = st.columns(3)
    org_name = col1.text_input("Organization", value=profile.get("org_name", ""))
    industry = col2.text_input("Industry", value=profile.get("industry", ""))
    preferred_language = col3.selectbox("Language", ["en", "vi"], index=0 if profile.get("preferred_language") != "vi" else 1)
    public_domain = st.text_input("Public domain", value=profile.get("public_domain", ""), placeholder="example.com")

    selected_stack = {}
    for category, catalog in TECH_CATALOG.items():
        default_values = [
            value for value in profile_stack.get(category, [])
            if value in catalog
        ]
        selected_stack[category] = st.multiselect(
            category.replace("_", " ").title(),
            catalog,
            default=default_values,
        )

    if st.button("Save Profile", type="primary"):
        stack_changed = db_handler.save_org_profile(
            conn,
            {
                "user_id": db_handler.DEFAULT_USER_ID,
                "org_name": org_name,
                "industry": industry,
                "public_domain": public_domain,
                "preferred_language": preferred_language,
                "preferred_languages": [preferred_language, "en"] if preferred_language != "en" else ["en"],
                "tech_stack": selected_stack,
                "auto_discovered": profile.get("auto_discovered", []),
            },
        )
        if stack_changed:
            st.success("Profile saved. Existing CVE/feed items were rescanned against the updated tech stack.")
        else:
            st.success("Profile saved. Tech stack did not change.")

    st.caption("Auto-discovery uses passive fingerprinting with optional provider enrichment.")
    if st.button("Auto-Discover Stack"):
        st.session_state["discovered_stack"] = passive_discover_technologies(
            public_domain,
            timeout=get_discovery_timeout(DISCOVERY_CONFIG),
            provider=get_discovery_provider(DISCOVERY_CONFIG),
            prefer_live=get_discovery_live_mode(DISCOVERY_CONFIG),
            builtwith_api_key=DASHBOARD_CONFIG.get("api_keys", {}).get("builtwith_api_key", ""),
            wappalyzer_api_key=DASHBOARD_CONFIG.get("api_keys", {}).get("wappalyzer_api_key", ""),
        )

    discovered = st.session_state.get("discovered_stack", [])
    if discovered:
        discovered_names = [item["name"] for item in discovered]
        st.dataframe(pd.DataFrame(discovered), width="stretch", hide_index=True)
        if st.button("Confirm and Merge Discovery"):
            merged_stack = normalize_tech_stack(profile.get("tech_stack", {}))
            for item in discovered:
                category = item["category"]
                merged_stack.setdefault(category, [])
                canonical_name = canonicalize_technology_name(item["name"])
                if canonical_name in TECH_CATALOG.get(category, []) and canonical_name not in merged_stack[category]:
                    merged_stack[category].append(canonical_name)
            db_handler.save_org_profile(
                conn,
                {
                    "user_id": db_handler.DEFAULT_USER_ID,
                    "org_name": org_name,
                    "industry": industry,
                    "public_domain": public_domain,
                    "preferred_language": preferred_language,
                    "preferred_languages": [preferred_language, "en"] if preferred_language != "en" else ["en"],
                    "tech_stack": merged_stack,
                    "auto_discovered": discovered_names,
                },
            )
            st.session_state["discovered_stack"] = []
            st.success("Discovered technologies merged and existing CVE/feed items rescanned.")


def render_overview(conn):
    alerts = db_handler.get_dashboard_alerts(conn)
    indicator = sleep_well_indicator([alert for alert in alerts if alert.get("resolution_status") not in {"mitigated", "accepted_risk", "not_applicable"}])
    open_alerts = [alert for alert in alerts if alert.get("triage_status") != "closed"]
    critical_open = sum(1 for alert in open_alerts if alert.get("severity") == "critical")
    high_open = sum(1 for alert in open_alerts if alert.get("severity") == "high")
    mitigated = sum(1 for alert in alerts if alert.get("resolution_status") == "mitigated")
    heatmap_rows = db_handler.get_heatmap_data(conn)
    heatmap_note = "Counts are derived from current matched-alert records in the database."
    if heatmap_rows:
        grouped = {}
        for row in heatmap_rows:
            name = row["product_name"]
            grouped.setdefault(name, {"critical": 0, "high": 0, "medium": 0, "low": 0})
            grouped[name][str(row["severity"]).lower()] = int(row["matches"] or 0)
        heatmap_view = [{"asset": name, **values} for name, values in list(grouped.items())[:6]]
    else:
        heatmap_note = (
            "No matched-alert heatmap data is available yet. The panel below uses illustrative placeholder values "
            "for presentation only and should not be interpreted as measured system output."
        )
        heatmap_view = [
            {"asset": "AWS", "critical": 1, "high": 1, "medium": 0, "low": 1},
            {"asset": "Nginx", "critical": 1, "high": 2, "medium": 1, "low": 0},
            {"asset": "NodeJS", "critical": 0, "high": 2, "medium": 1, "low": 0},
            {"asset": "React", "critical": 0, "high": 1, "medium": 1, "low": 0},
            {"asset": "Redis", "critical": 0, "high": 1, "medium": 0, "low": 1},
            {"asset": "Windows Server", "critical": 1, "high": 2, "medium": 0, "low": 0},
        ]

    heatmap_html = textwrap.dedent("""
    <div class="heatmap-wrap">
      <div class="heatmap-head">
        <div>Asset</div><div>Critical</div><div>High</div><div>Medium</div><div>Low</div>
      </div>
    """)
    for row in heatmap_view:
        def heat_class(value):
            if value >= 2:
                return "heat-high"
            if value == 1:
                return "heat-med"
            return "heat-low"

        heatmap_html += textwrap.dedent(f"""
        <div class="heatmap-row">
          <div class="heatmap-label">{row['asset']}</div>
          <div class="heatbox {heat_class(row['critical'])}">{row['critical']}</div>
          <div class="heatbox {heat_class(row['high'])}">{row['high']}</div>
          <div class="heatbox {heat_class(row['medium'])}">{row['medium']}</div>
          <div class="heatbox {heat_class(row['low'])}">{row['low']}</div>
        </div>
        """)
    heatmap_html += "</div>"

    html = textwrap.dedent(f"""
    <div class="showcase-shell">
      <div class="showcase-hero">
        <div class="showcase-card">
          <div class="showcase-eyebrow">Operational CTI Overview</div>
          <div class="showcase-title">Current Risk Posture</div>
          <div class="showcase-copy">
            Cross-source collection, profile-aware matching, IOC extraction, and analyst-oriented reporting
            are consolidated here into one review surface for triage and defensive follow-up.
          </div>
        </div>
        <div class="showcase-card showcase-alert">
          <div class="showcase-alert-k">Critical Cases</div>
          <div class="showcase-alert-v">{critical_open}</div>
          <div class="showcase-alert-p">
            Immediate review required for unresolved critical items across the current threat queue.
          </div>
        </div>
      </div>

      <div class="showcase-banner">
        <div class="showcase-banner-left">Immediate attention</div>
        <div class="showcase-banner-right">
          Review the highest-priority items, validate asset exposure, confirm exploitability conditions, and prepare mitigation or containment actions where evidence supports intervention.
        </div>
      </div>

      <div class="showcase-metrics">
        <div class="showcase-metric">
          <div class="showcase-metric-k">Sleep-Well Indicator</div>
          <div class="showcase-metric-v">{indicator['color'].upper()}</div>
          <div class="showcase-metric-p">{indicator['label']}</div>
        </div>
        <div class="showcase-metric">
          <div class="showcase-metric-k">Open Matched Alerts</div>
          <div class="showcase-metric-v">{len(open_alerts)}</div>
          <div class="showcase-metric-p">Threats relevant to defended assets</div>
        </div>
        <div class="showcase-metric">
          <div class="showcase-metric-k">High Severity</div>
          <div class="showcase-metric-v">{high_open}</div>
          <div class="showcase-metric-p">Escalation backlog under review</div>
        </div>
        <div class="showcase-metric">
          <div class="showcase-metric-k">Mitigated Alerts</div>
          <div class="showcase-metric-v">{mitigated}</div>
          <div class="showcase-metric-p">Closed with remediation action</div>
        </div>
      </div>

      <div class="showcase-grid">
        <div class="showcase-card">
          <div class="showcase-panel-title">Tech Stack Exposure Heatmap</div>
          <div class="showcase-panel-note">{heatmap_note}</div>
          {heatmap_html}
        </div>
        <div class="showcase-card">
          <div class="showcase-panel-title">System Capabilities</div>
          <div class="feature-item">
            <div class="feature-k">Cross-Source Collection</div>
            <div class="feature-v">RSS, Reddit, Telegram, CVE, KEV, OTX</div>
            <div class="feature-p">The pipeline merges structured and unstructured public intelligence into one normalized workflow.</div>
          </div>
          <div class="feature-item">
            <div class="feature-k">IOC and TTP Extraction</div>
            <div class="feature-v">Regex plus LLM-assisted CTI analysis</div>
            <div class="feature-p">Extracts CVEs, IPs, domains, attack vectors, and ATT&amp;CK context for triage.</div>
          </div>
          <div class="feature-item">
            <div class="feature-k">Profile-Aware Prioritization</div>
            <div class="feature-v">Environment-relevant threat matching</div>
            <div class="feature-p">Signals are rescored based on the organization's actual stack rather than generic threat volume alone.</div>
          </div>
        </div>
        <div class="showcase-card">
          <div class="showcase-panel-title">Pipeline Flow</div>
          <div class="flow-step">
            <div class="flow-num">1</div>
            <div><div class="flow-title">Collect</div><div class="flow-copy">Public feeds, social posts, and CVE streams are normalized into a shared intake layer.</div></div>
          </div>
          <div class="flow-step">
            <div class="flow-num">2</div>
            <div><div class="flow-title">Filter</div><div class="flow-copy">Duplicate and low-signal records are reduced before deeper analysis spends local compute.</div></div>
          </div>
          <div class="flow-step">
            <div class="flow-num">3</div>
            <div><div class="flow-title">Analyze</div><div class="flow-copy">IOC extraction, LLM reasoning, and ATT&amp;CK mapping turn raw text into reviewable CTI.</div></div>
          </div>
          <div class="flow-step">
            <div class="flow-num">4</div>
            <div><div class="flow-title">Report</div><div class="flow-copy">Executive, technical, and operational outputs support remediation, triage, and auditability.</div></div>
          </div>
        </div>
      </div>
    </div>
    """)
    # Streamlit Markdown can treat indented HTML after blank lines as code blocks.
    html = "\n".join(line.strip() for line in html.splitlines() if line.strip())
    st.markdown(html, unsafe_allow_html=True)


def render_feed(conn):
    st.header("Real-Time Threat Feed")
    col1, col2 = st.columns(2)
    severity = col1.selectbox("Severity", ["all", "critical", "high", "medium", "low"])
    source_type = col2.selectbox("Source Type", ["all", "rss", "Threat Feed", "reddit", "telegram"])
    alerts = db_handler.get_dashboard_alerts(conn, severity=severity, source_type=source_type)

    if not alerts:
        st.info("No analyzed alerts match the current filters.")
        return

    for alert in alerts[:50]:
        with st.container(border=True):
            st.subheader(alert["title"] or alert["id"])
            st.write(f"Severity: `{alert['severity']}` | Priority: `{alert['triage_priority']}` | Source: `{alert['source']}`")
            st.write(f"Impacted assets: {', '.join(alert.get('impacted_assets', [])) or 'None matched'}")
            summary = alert.get("notification_payload", {}).get("summary")
            if summary and summary.strip().lower() != "error during analysis.":
                st.write(summary)
            if alert.get("url"):
                st.markdown(f"[Source link]({alert['url']})")
            if alert.get("mitigation_script"):
                st.code(alert["mitigation_script"], language="bash")

            status_col, note_col = st.columns([1, 2])
            status = status_col.selectbox(
                "Resolution",
                ["open", "mitigated", "accepted_risk", "not_applicable"],
                index=0,
                key=f"status_{alert['id']}",
            )
            note = note_col.text_input("Note", key=f"note_{alert['id']}")
            if st.button("Apply Status", key=f"apply_{alert['id']}"):
                db_handler.set_remediation_status(conn, alert["id"], status=status, acted_by="streamlit_user", note=note)
                st.success("Threat workflow updated.")


def render_reports():
    st.header("Reports")
    report_files = get_files_in_dir(REPORTS_DIR, "md")
    if not report_files:
        st.warning(f"No reports found in {REPORTS_DIR}.")
        return

    report_groups = {}
    for path in report_files:
        filename = os.path.basename(path)
        base_group = filename.replace("_01_executive.md", "").replace("_02_technical.md", "").replace("_03_operational.md", "")
        report_groups.setdefault(base_group, {})
        if "executive" in filename:
            report_groups[base_group]["Executive"] = path
        elif "technical" in filename:
            report_groups[base_group]["Technical"] = path
        elif "operational" in filename:
            report_groups[base_group]["Operational"] = path

    selected_group = st.selectbox("Threat Event", list(report_groups.keys()))
    files_to_show = report_groups[selected_group]
    for label in ["Executive", "Technical", "Operational"]:
        if label in files_to_show:
            st.subheader(label)
            st.markdown(read_file_content(files_to_show[label]))


def render_sigma():
    st.header("Automated Defense Rules")
    sigma_files = get_files_in_dir(SIGMA_DIR, "yml")
    if not sigma_files:
        st.warning(f"No Sigma rules found in {SIGMA_DIR}.")
        return
    selected_sigma = st.selectbox("Sigma Rule", [os.path.basename(path) for path in sigma_files])
    full_path = os.path.join(SIGMA_DIR, selected_sigma)
    yaml_content = read_file_content(full_path)
    st.code(yaml_content, language="yaml")
    st.download_button("Download rule", data=yaml_content, file_name=selected_sigma, mime="text/yaml")


inject_showcase_styles()
st.title("Adaptive Cyber Threat Intelligence")
st.caption("Profile-driven CTI for SMEs: filter noise, escalate only relevant threats, track remediation.")

conn = db_handler.init_db()

tab_overview, tab_feed, tab_profile, tab_reports, tab_sigma = st.tabs(
    ["Overview", "Threat Feed", "Organization Profile", "Reports", "Sigma"]
)

with tab_overview:
    render_overview(conn)

with tab_feed:
    render_feed(conn)

with tab_profile:
    save_profile_form(conn)

with tab_reports:
    render_reports()

with tab_sigma:
    render_sigma()

conn.close()
