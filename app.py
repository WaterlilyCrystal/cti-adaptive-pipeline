import glob
import os
import sqlite3

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


def read_file_content(filepath):
    try:
        with open(filepath, "r", encoding="utf-8") as handle:
            return handle.read()
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
        db_handler.save_org_profile(
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
        db_handler.clear_profile_matches(conn)
        st.success("Profile saved. New threat matches will be recalculated on the next analysis run.")

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
            st.success("Discovered technologies merged into the saved profile.")


def render_overview(conn):
    alerts = db_handler.get_dashboard_alerts(conn)
    indicator = sleep_well_indicator([alert for alert in alerts if alert.get("resolution_status") not in {"mitigated", "accepted_risk", "not_applicable"}])

    st.header("Current Risk Posture")
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Sleep-Well Indicator", indicator["color"].upper())
    col2.metric("Indicator Detail", indicator["label"])
    col3.metric("Open Matched Alerts", sum(1 for alert in alerts if alert.get("triage_status") != "closed"))
    col4.metric("Mitigated Alerts", sum(1 for alert in alerts if alert.get("resolution_status") == "mitigated"))

    heatmap_rows = db_handler.get_heatmap_data(conn)
    st.subheader("Tech Stack Coverage Heatmap")
    if heatmap_rows:
        heatmap_df = pd.DataFrame(heatmap_rows)
        pivot = heatmap_df.pivot_table(index="product_name", columns="severity", values="matches", fill_value=0)
        st.dataframe(pivot, width="stretch")
    else:
        st.info("No matched tech stack vulnerabilities yet.")


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
