import streamlit as st
import os
import glob
import pandas as pd
import sqlite3
import json
from streamlit_autorefresh import st_autorefresh

st_autorefresh(interval=60000, limit=None, key="soc_dashboard_refresh")

# ==============================================================================
# PAGE CONFIGURATION
# ==============================================================================
st.set_page_config(
    page_title="Adaptive CTI Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ==============================================================================
# DIRECTORY PATHS
# ==============================================================================
BASE_DIR = os.path.dirname(__file__)
REPORTS_DIR = os.path.join(BASE_DIR, "output", "reports")
SIGMA_DIR = os.path.join(BASE_DIR, "output", "sigma_rules")
DB_PATH = os.path.join(BASE_DIR, "data", "cti.db")

# ==============================================================================
# UTILITIES & DATABASE FUNCTIONS
# ==============================================================================
def read_file_content(filepath):
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            return f.read()
    except Exception as e:
        return f"Error reading file: {e}"

def get_files_in_dir(directory, extension="*"):
    if not os.path.exists(directory):
        return []
    return sorted(glob.glob(os.path.join(directory, f"*.{extension}")))

def fetch_live_metrics():
    """Truy vấn Database thật để lấy số liệu thống kê cho Dashboard"""
    if not os.path.exists(DB_PATH):
        return 0, 0, pd.DataFrame()
        
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    try:
        # 1. Đếm tổng số bài đã phân tích
        cursor.execute("SELECT count(*) FROM intel_items WHERE processed=1")
        total_processed = cursor.fetchone()[0]
        
        # 2. Đếm tổng số rule Sigma
        cursor.execute("SELECT count(*) FROM sigma_rules")
        total_sigma = cursor.fetchone()[0]
        
        # 3. Gom nhóm và đếm các mã MITRE ATT&CK đã phát hiện
        cursor.execute("SELECT ttp_mapping FROM intel_items WHERE processed=1 AND ttp_mapping != '[]'")
        rows = cursor.fetchall()
        
        technique_counts = {}
        for row in rows:
            try:
                ttps = json.loads(row[0])
                for ttp in ttps:
                    tech_id = ttp.get("technique_id", "Unknown")
                    tech_name = ttp.get("technique_name_official", "Unknown")
                    label = f"{tech_id} - {tech_name}"
                    technique_counts[label] = technique_counts.get(label, 0) + 1
            except:
                pass
                
        if technique_counts:
            df_matrix = pd.DataFrame({
                "MITRE Technique": list(technique_counts.keys()),
                "Detection Count": list(technique_counts.values())
            }).sort_values(by="Detection Count", ascending=False)
        else:
            df_matrix = pd.DataFrame({"MITRE Technique": ["No Threat Detected"], "Detection Count": [0]})
            
    except Exception as e:
        st.error(f"Database Error: {e}")
        total_processed, total_sigma, df_matrix = 0, 0, pd.DataFrame()
    finally:
        conn.close()
        
    return total_processed, total_sigma, df_matrix

# ==============================================================================
# MAIN INTERFACE
# ==============================================================================
st.title("🛡️ Adaptive Cyber Threat Intelligence (CTI)")
st.markdown("*Automated semantic analysis, MITRE ATT&CK validation, and defense rule generation system.*")

tab_overview, tab_reports, tab_sigma = st.tabs([
    "📊 System Overview", 
    "📄 3-Tier Reports", 
    "🚨 Automated Defense (Sigma)"
])

# ------------------------------------------------------------------------------
# TAB 1: OVERVIEW (LIVE DATABASE METRICS)
# ------------------------------------------------------------------------------
with tab_overview:
    st.header("Pipeline Status (Live Production Data)")
    
    # Fetch real data from SQLite
    total_processed, total_sigma, df_matrix = fetch_live_metrics()
    
    # Display Live KPIs
    col1, col2, col3, col4 = st.columns(4)
    col1.metric(label="Processed Threat Feeds", value=total_processed, delta="Synced to DB")
    col2.metric(label="System Status", value="Active", delta="No Bottlenecks")
    col3.metric(label="Unique MITRE Tactics", value=len(df_matrix) if total_processed > 0 else 0)
    col4.metric(label="Generated Sigma Rules", value=total_sigma, delta="Ready for SIEM")

    st.divider()
    
    st.subheader("Live MITRE ATT&CK Detection Matrix")
    if total_processed > 0:
        st.dataframe(df_matrix, width="stretch", hide_index=True)
    else:
        st.info("No threats analyzed yet. Run the pipeline to populate this matrix.")

# ------------------------------------------------------------------------------
# TAB 2: MULTI-TIER REPORTS
# ------------------------------------------------------------------------------
with tab_reports:
    st.header("Multi-Audience Reporting System")
    st.info("The system automatically uses AI (Qwen2.5) to compile raw data into 3 specialized reporting tiers.")
    
    report_files = get_files_in_dir(REPORTS_DIR, "md")
    
    if not report_files:
        st.warning(f"No reports found in {REPORTS_DIR}. Please run the pipeline first.")
    else:
        report_groups = {}
        for fpath in report_files:
            fname = os.path.basename(fpath)
            base_group = fname.replace("_01_executive.md", "").replace("_02_technical.md", "").replace("_03_operational.md", "")
            if base_group not in report_groups:
                report_groups[base_group] = {}
            
            if "executive" in fname:
                report_groups[base_group]["CISO (Executive)"] = fpath
            elif "technical" in fname:
                report_groups[base_group]["SOC (Technical)"] = fpath
            elif "operational" in fname:
                report_groups[base_group]["Sysadmin (Operational)"] = fpath

        selected_group = st.selectbox("Select Threat Event to view reports:", list(report_groups.keys()))
        
        if selected_group:
            files_to_show = report_groups[selected_group]
            r_col1, r_col2, r_col3 = st.columns(3)
            
            with r_col1:
                st.subheader("🏢 For CISO (Executive)")
                if "CISO (Executive)" in files_to_show:
                    st.markdown(read_file_content(files_to_show["CISO (Executive)"]))
                    
            with r_col2:
                st.subheader("🕵️ For SOC Analyst")
                if "SOC (Technical)" in files_to_show:
                    st.markdown(read_file_content(files_to_show["SOC (Technical)"]))
                    
            with r_col3:
                st.subheader("🛠️ For Network Engineer")
                if "Sysadmin (Operational)" in files_to_show:
                    st.markdown(read_file_content(files_to_show["Sysadmin (Operational)"]))

# ------------------------------------------------------------------------------
# TAB 3: SIGMA DEFENSE RULES
# ------------------------------------------------------------------------------
with tab_sigma:
    st.header("Auto-Generated Defense Rules (Sigma Engine)")
    st.info("These rules are auto-populated with IOCs and TTPs by AI, ready for export to SIEMs (Splunk, Elastic).")
    
    sigma_files = get_files_in_dir(SIGMA_DIR, "yml")
    
    if not sigma_files:
        st.warning(f"No Sigma rules found in {SIGMA_DIR}. Please run the pipeline first.")
    else:
        sigma_filenames = [os.path.basename(f) for f in sigma_files]
        selected_sigma = st.selectbox("Select a Sigma Rule to view/download:", sigma_filenames)
        
        if selected_sigma:
            full_path = os.path.join(SIGMA_DIR, selected_sigma)
            yaml_content = read_file_content(full_path)
            
            st.code(yaml_content, language="yaml")
            
            st.download_button(
                label="📥 Download .yml rule",
                data=yaml_content,
                file_name=selected_sigma,
                mime="text/yaml"
            )