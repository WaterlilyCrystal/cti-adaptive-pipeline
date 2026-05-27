import streamlit as st
import os
import glob
import pandas as pd

# ==============================================================================
# PAGE CONFIGURATION (Must be the first command)
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

# ==============================================================================
# FILE READING UTILITIES
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
    # Find all files with the specified extension
    return sorted(glob.glob(os.path.join(directory, f"*.{extension}")))

# ==============================================================================
# MAIN INTERFACE
# ==============================================================================
st.title("🛡️ Adaptive Cyber Threat Intelligence (CTI)")
st.markdown("*Automated semantic analysis, MITRE ATT&CK validation, and defense rule generation system.*")

# Create 3 main Tabs for the Dashboard
tab_overview, tab_reports, tab_sigma = st.tabs([
    "📊 System Overview", 
    "📄 3-Tier Reports", 
    "🚨 Automated Defense (Sigma)"
])

# ------------------------------------------------------------------------------
# TAB 1: OVERVIEW (METRICS & MOCK CHARTS)
# ------------------------------------------------------------------------------
with tab_overview:
    st.header("Pipeline Status (Mock Data)")
    
    # Display KPIs in columns
    col1, col2, col3, col4 = st.columns(4)
    col1.metric(label="Processed Feeds", value="1", delta="New")
    col2.metric(label="Extracted IOCs", value="1 CVE", delta="Clean")
    col3.metric(label="Mapped MITRE Codes", value="T1505.003", delta="Validated")
    col4.metric(label="Generated Sigma Rules", value="1", delta="Ready")

    st.divider()
    
    # Mock Tactics Matrix
    st.subheader("Tactics Matrix")
    mock_matrix_data = pd.DataFrame({
        "Tactic": ["Initial Access", "Execution", "Persistence", "Privilege Escalation", "Defense Evasion"],
        "Technique Count": [4, 2, 1, 0, 3],
        "Severity": ["High", "Medium", "Critical", "Low", "High"]
    })
    st.dataframe(mock_matrix_data, use_container_width=True, hide_index=True)

# ------------------------------------------------------------------------------
# TAB 2: MULTI-TIER REPORTS (READING MARKDOWN FILES)
# ------------------------------------------------------------------------------
with tab_reports:
    st.header("Multi-Audience Reporting System")
    st.info("The system automatically uses AI (Qwen2.5) to compile raw data into 3 specialized reporting tiers.")
    
    report_files = get_files_in_dir(REPORTS_DIR, "md")
    
    if not report_files:
        st.warning(f"No reports found in {REPORTS_DIR}. Please run run_analysis.py first.")
    else:
        # Group reports by their base name (removing _01_executive, _02_technical suffixes)
        report_groups = {}
        for fpath in report_files:
            fname = os.path.basename(fpath)
            # Extract base name (e.g., nginx_zero_day_rce...)
            base_group = fname.replace("_01_executive.md", "").replace("_02_technical.md", "").replace("_03_operational.md", "")
            if base_group not in report_groups:
                report_groups[base_group] = {}
            
            if "executive" in fname:
                report_groups[base_group]["CISO (Executive)"] = fpath
            elif "technical" in fname:
                report_groups[base_group]["SOC (Technical)"] = fpath
            elif "operational" in fname:
                report_groups[base_group]["Sysadmin (Operational)"] = fpath

        # Dropdown to select a threat event
        selected_group = st.selectbox("Select Threat Event:", list(report_groups.keys()))
        
        if selected_group:
            files_to_show = report_groups[selected_group]
            
            # Split into 3 columns to display reports side-by-side
            r_col1, r_col2, r_col3 = st.columns(3)
            
            with r_col1:
                st.subheader("🏢 For CISO (Executive)")
                if "CISO (Executive)" in files_to_show:
                    st.markdown(read_file_content(files_to_show["CISO (Executive)"]))
                    
            with r_col2:
                st.subheader("🕵️ For SOC Analyst (Technical)")
                if "SOC (Technical)" in files_to_show:
                    st.markdown(read_file_content(files_to_show["SOC (Technical)"]))
                    
            with r_col3:
                st.subheader("🛠️ For Network Engineer (Operational)")
                if "Sysadmin (Operational)" in files_to_show:
                    st.markdown(read_file_content(files_to_show["Sysadmin (Operational)"]))

# ------------------------------------------------------------------------------
# TAB 3: SIGMA DEFENSE RULES (READING YAML FILES)
# ------------------------------------------------------------------------------
with tab_sigma:
    st.header("Auto-Generated Defense Rules (Sigma Engine)")
    st.info("These rules are auto-populated with IOCs and TTPs by AI, ready for export to SIEMs (Splunk, Elastic) or Firewalls.")
    
    sigma_files = get_files_in_dir(SIGMA_DIR, "yml")
    
    if not sigma_files:
        st.warning(f"No Sigma rules found in {SIGMA_DIR}. Please run run_analysis.py first.")
    else:
        # Get list of filenames
        sigma_filenames = [os.path.basename(f) for f in sigma_files]
        selected_sigma = st.selectbox("Select a Sigma Rule to view details:", sigma_filenames)
        
        if selected_sigma:
            # Full file path
            full_path = os.path.join(SIGMA_DIR, selected_sigma)
            yaml_content = read_file_content(full_path)
            
            # Display code with YAML syntax highlighting
            st.code(yaml_content, language="yaml")
            
            # Download button
            st.download_button(
                label="📥 Download .yml file",
                data=yaml_content,
                file_name=selected_sigma,
                mime="text/yaml"
            )