import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from io import StringIO
import time

# Set page config
st.set_page_config(layout="wide", page_title="OT Cybersecurity Risk Dashboard")

st.title("OT Cybersecurity Risk Assessment Dashboard")
st.markdown("Upload your vulnerability, asset, and ICS advisory data to visualize and assess risk.")

# -----------------------------------------------------------------------------
# Helper functions for file loading
# -----------------------------------------------------------------------------
@st.cache_data
def load_csv_or_excel(file):
    if file.name.endswith('.csv'):
        return pd.read_csv(file)
    else:
        return pd.read_excel(file)

# -----------------------------------------------------------------------------
# File uploads
# -----------------------------------------------------------------------------
col1, col2, col3 = st.columns(3)
with col1:
    vuln_file = st.file_uploader("Upload Vulnerability Template (CSV/Excel)", type=["csv", "xlsx"])
with col2:
    asset_file = st.file_uploader("Upload Asset Template (CSV/Excel)", type=["csv", "xlsx"])
with col3:
    advisory_file = st.file_uploader("Upload ICS Advisory Excel (CSV/Excel)", type=["csv", "xlsx"])

if not (vuln_file and asset_file and advisory_file):
    st.info("Please upload all three files to continue.")
    st.stop()

# -----------------------------------------------------------------------------
# Load data
# -----------------------------------------------------------------------------
with st.spinner("Loading data..."):
    vuln_df = load_csv_or_excel(vuln_file)
    asset_df = load_csv_or_excel(asset_file)
    advisory_df = load_csv_or_excel(advisory_file)

# -----------------------------------------------------------------------------
# Data preprocessing
# -----------------------------------------------------------------------------
# Rename columns if needed (to match expected names)
# We'll assume column names are exactly as given, but we'll lowercase for safety.
vuln_df.columns = vuln_df.columns.str.strip().str.lower()
asset_df.columns = asset_df.columns.str.strip().str.lower()
advisory_df.columns = advisory_df.columns.str.strip().str.lower()

# Check critical columns exist
required_vuln = ['asset_id', 'cve_id', 'cvss_score', 'exploitability', 'patch_availability', 'severity']
required_asset = ['asset_id']  # asset_id is the key
required_advisory = ['cve_number']  # match cve_id

for col in required_vuln:
    if col not in vuln_df.columns:
        st.error(f"Vulnerability file missing required column: {col}")
        st.stop()
for col in required_asset:
    if col not in asset_df.columns:
        st.error(f"Asset file missing required column: {col}")
        st.stop()
for col in required_advisory:
    if col not in advisory_df.columns:
        st.error(f"Advisory file missing required column: {col}")
        st.stop()

# Ensure cvss_score is numeric
vuln_df['cvss_score'] = pd.to_numeric(vuln_df['cvss_score'], errors='coerce')

# Merge advisory CVE details into vulnerabilities (enrich with advisory fields)
# We'll use the advisory CVE number to match cve_id
advisory_cve_map = advisory_df.set_index('cve_number')[['ics-cert_advisory_title', 'cwe_number', 'critical_infrastructure_sector']].to_dict('index')
# Add columns to vuln_df from advisory if cve_id matches
def enrich_vuln(row):
    cve = row['cve_id']
    if cve in advisory_cve_map:
        row['advisory_title'] = advisory_cve_map[cve].get('ics-cert_advisory_title', '')
        row['cwe'] = advisory_cve_map[cve].get('cwe_number', '')
        row['infra_sector'] = advisory_cve_map[cve].get('critical_infrastructure_sector', '')
    else:
        row['advisory_title'] = ''
        row['cwe'] = ''
        row['infra_sector'] = ''
    return row

vuln_df = vuln_df.apply(enrich_vuln, axis=1)

# Merge vulnerabilities with assets
merged_df = vuln_df.merge(asset_df, on='asset_id', how='left')

# Add a computed risk score (example: CVSS * criticality factor)
# Map asset criticality to numeric factor (low=1, medium=2, high=3, critical=4)
crit_map = {'low':1, 'medium':2, 'high':3, 'critical':4}
merged_df['criticality_factor'] = merged_df['criticality'].str.lower().map(crit_map).fillna(1)

# Calculate risk score = cvss_score * criticality_factor
merged_df['risk_score'] = merged_df['cvss_score'] * merged_df['criticality_factor']

# -----------------------------------------------------------------------------
# Sidebar filters
# -----------------------------------------------------------------------------
st.sidebar.header("Filters")
# Filter by severity
severities = merged_df['severity'].dropna().unique()
selected_severities = st.sidebar.multiselect("Severity", options=severities, default=severities)
# Filter by criticality
criticalities = merged_df['criticality'].dropna().unique()
selected_criticalities = st.sidebar.multiselect("Asset Criticality", options=criticalities, default=criticalities)
# Filter by network zone
zones = merged_df['network_zone'].dropna().unique()
selected_zones = st.sidebar.multiselect("Network Zone", options=zones, default=zones)
# Filter by CVSS range
cvss_range = st.sidebar.slider("CVSS Score Range", 0.0, 10.0, (0.0, 10.0))

filtered_df = merged_df[
    (merged_df['severity'].isin(selected_severities)) &
    (merged_df['criticality'].isin(selected_criticalities)) &
    (merged_df['network_zone'].isin(selected_zones)) &
    (merged_df['cvss_score'].between(cvss_range[0], cvss_range[1]))
]

# -----------------------------------------------------------------------------
# KPIs
# -----------------------------------------------------------------------------
st.subheader("Key Risk Indicators")
kpi1, kpi2, kpi3, kpi4 = st.columns(4)
with kpi1:
    st.metric("Total CVEs", len(filtered_df['cve_id'].unique()))
with kpi2:
    st.metric("Total Assets with Vulnerabilities", filtered_df['asset_id'].nunique())
with kpi3:
    st.metric("Average CVSS Score", f"{filtered_df['cvss_score'].mean():.2f}")
with kpi4:
    st.metric("Avg Risk Score (CVSS * Criticality)", f"{filtered_df['risk_score'].mean():.2f}")

# -----------------------------------------------------------------------------
# Visualizations
# -----------------------------------------------------------------------------
st.subheader("Risk Visualizations")
col1, col2 = st.columns(2)
with col1:
    fig = px.histogram(filtered_df, x="cvss_score", nbins=20, title="CVSS Score Distribution")
    st.plotly_chart(fig, use_container_width=True)
with col2:
    severity_counts = filtered_df['severity'].value_counts().reset_index()
    severity_counts.columns = ['Severity', 'Count']
    fig = px.pie(severity_counts, values='Count', names='Severity', title="Vulnerability Severity")
    st.plotly_chart(fig, use_container_width=True)

col1, col2 = st.columns(2)
with col1:
    criticality_counts = filtered_df['criticality'].value_counts().reset_index()
    criticality_counts.columns = ['Criticality', 'Count']
    fig = px.bar(criticality_counts, x='Criticality', y='Count', title="Assets by Criticality")
    st.plotly_chart(fig, use_container_width=True)
with col2:
    # Top 10 vulnerabilities by risk score
    top_vulns = filtered_df.groupby('cve_id')['risk_score'].max().sort_values(ascending=False).head(10).reset_index()
    fig = px.bar(top_vulns, x='cve_id', y='risk_score', title="Top 10 CVEs by Risk Score")
    st.plotly_chart(fig, use_container_width=True)

# -----------------------------------------------------------------------------
# Asset Risk Heatmap (by asset type and criticality)
# -----------------------------------------------------------------------------
st.subheader("Asset Risk Heatmap")
heatmap_data = filtered_df.groupby(['asset_type', 'criticality'])['risk_score'].mean().reset_index()
if not heatmap_data.empty:
    fig = px.density_heatmap(heatmap_data, x='asset_type', y='criticality', z='risk_score',
                             title="Average Risk Score by Asset Type and Criticality",
                             color_continuous_scale="Reds")
    st.plotly_chart(fig, use_container_width=True)
else:
    st.write("No data for heatmap.")

# -----------------------------------------------------------------------------
# Data Tables
# -----------------------------------------------------------------------------
st.subheader("Detailed Vulnerability Data")
# Show a summarized view with key fields
table_cols = ['cve_id', 'cvss_score', 'severity', 'criticality', 'asset_type', 'network_zone', 'risk_score', 'advisory_title']
if all(c in filtered_df.columns for c in table_cols):
    st.dataframe(filtered_df[table_cols].drop_duplicates().sort_values('risk_score', ascending=False),
                 use_container_width=True)
else:
    st.dataframe(filtered_df, use_container_width=True)

# -----------------------------------------------------------------------------
# Download filtered data
# -----------------------------------------------------------------------------
csv = filtered_df.to_csv(index=False).encode('utf-8')
st.download_button(
    label="Download filtered data as CSV",
    data=csv,
    file_name="ot_risk_assessment.csv",
    mime="text/csv"
)

st.success("Dashboard ready. Use filters to explore risk.")