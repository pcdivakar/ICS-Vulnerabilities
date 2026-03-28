import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from io import StringIO
import time
import numpy as np

# Set page config
st.set_page_config(layout="wide", page_title="OT Cybersecurity Risk Dashboard")

st.title("🔒 OT Cybersecurity Risk Assessment Dashboard")
st.markdown("Upload your vulnerability, asset, and ICS advisory data to visualize and assess risk in OT environments.")

# -----------------------------------------------------------------------------
# Helper functions
# -----------------------------------------------------------------------------
@st.cache_data
def load_csv_or_excel(file):
    if file.name.endswith('.csv'):
        return pd.read_csv(file)
    else:
        return pd.read_excel(file)

def create_risk_score(row):
    """Calculate risk score based on CVSS and asset criticality."""
    crit_map = {'low':1, 'medium':2, 'high':3, 'critical':4}
    factor = crit_map.get(row['criticality'].lower(), 1)
    return row['cvss_score'] * factor

# -----------------------------------------------------------------------------
# File uploads
# -----------------------------------------------------------------------------
col1, col2, col3 = st.columns(3)
with col1:
    vuln_file = st.file_uploader("📁 Upload Vulnerability Template (CSV/Excel)", type=["csv", "xlsx"])
with col2:
    asset_file = st.file_uploader("🏭 Upload Asset Template (CSV/Excel)", type=["csv", "xlsx"])
with col3:
    advisory_file = st.file_uploader("📄 Upload ICS Advisory Excel (CSV/Excel)", type=["csv", "xlsx"])

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
# Normalize column names
vuln_df.columns = vuln_df.columns.str.strip().str.lower()
asset_df.columns = asset_df.columns.str.strip().str.lower()
advisory_df.columns = advisory_df.columns.str.strip().str.lower()

# Required columns
required_vuln = ['asset_id', 'cve_id', 'cvss_score', 'exploitability', 'patch_availability', 'severity']
required_asset = ['asset_id']
required_advisory = ['cve_number']

missing = []
for col in required_vuln:
    if col not in vuln_df.columns:
        missing.append(col)
if missing:
    st.error(f"Vulnerability file missing required columns: {', '.join(missing)}")
    st.stop()

if 'asset_id' not in asset_df.columns:
    st.error("Asset file missing required column: asset_id")
    st.stop()

if 'cve_number' not in advisory_df.columns:
    st.error("Advisory file missing required column: cve_number")
    st.stop()

# Convert CVSS to numeric
vuln_df['cvss_score'] = pd.to_numeric(vuln_df['cvss_score'], errors='coerce')
vuln_df.dropna(subset=['cvss_score'], inplace=True)

# Merge advisory details (handle duplicate CVEs)
advisory_unique = advisory_df.drop_duplicates(subset='cve_number', keep='first')
advisory_cve_map = (advisory_unique
                    .set_index('cve_number')[['ics-cert_advisory_title', 'cwe_number', 'critical_infrastructure_sector']]
                    .to_dict('index'))

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

# Merge with assets
merged_df = vuln_df.merge(asset_df, on='asset_id', how='left')
# Fill missing asset details with defaults if not present
for col in ['asset_type', 'criticality', 'network_zone']:
    if col not in merged_df.columns:
        merged_df[col] = 'Unknown'
    else:
        merged_df[col] = merged_df[col].fillna('Unknown')

# Compute risk score
merged_df['risk_score'] = merged_df.apply(create_risk_score, axis=1)

# -----------------------------------------------------------------------------
# Sidebar filters (enhanced)
# -----------------------------------------------------------------------------
st.sidebar.header("🔍 Filters")
with st.sidebar.expander("Severity", expanded=True):
    severities = merged_df['severity'].dropna().unique()
    selected_severities = st.multiselect("Severity", options=severities, default=severities, key="severity")
with st.sidebar.expander("Asset Criticality", expanded=True):
    criticalities = merged_df['criticality'].dropna().unique()
    selected_criticalities = st.multiselect("Asset Criticality", options=criticalities, default=criticalities, key="criticality")
with st.sidebar.expander("Network Zone", expanded=True):
    zones = merged_df['network_zone'].dropna().unique()
    selected_zones = st.multiselect("Network Zone", options=zones, default=zones, key="zone")
with st.sidebar.expander("Asset Type", expanded=True):
    asset_types = merged_df['asset_type'].dropna().unique()
    selected_asset_types = st.multiselect("Asset Type", options=asset_types, default=asset_types, key="asset_type")
with st.sidebar.expander("Exploitability", expanded=True):
    exploit = merged_df['exploitability'].dropna().unique()
    selected_exploit = st.multiselect("Exploitability", options=exploit, default=exploit, key="exploit")
with st.sidebar.expander("Patch Availability", expanded=True):
    patch = merged_df['patch_availability'].dropna().unique()
    selected_patch = st.multiselect("Patch Availability", options=patch, default=patch, key="patch")
with st.sidebar.expander("CWE (Common Weakness Enumeration)", expanded=True):
    cwes = merged_df['cwe'].dropna().unique()
    selected_cwes = st.multiselect("CWE", options=cwes, default=cwes, key="cwe")
with st.sidebar.expander("Infrastructure Sector", expanded=True):
    sectors = merged_df['infra_sector'].dropna().unique()
    selected_sectors = st.multiselect("Sector", options=sectors, default=sectors, key="sector")

cvss_range = st.sidebar.slider("CVSS Score Range", 0.0, 10.0, (0.0, 10.0))
risk_range = st.sidebar.slider("Risk Score Range", 0.0, 40.0, (0.0, 40.0))  # max CVSS*4

# Search for specific CVE or asset
search = st.sidebar.text_input("Search (CVE or Asset ID)", "")

# Apply filters
filtered_df = merged_df[
    (merged_df['severity'].isin(selected_severities)) &
    (merged_df['criticality'].isin(selected_criticalities)) &
    (merged_df['network_zone'].isin(selected_zones)) &
    (merged_df['asset_type'].isin(selected_asset_types)) &
    (merged_df['exploitability'].isin(selected_exploit)) &
    (merged_df['patch_availability'].isin(selected_patch)) &
    (merged_df['cwe'].isin(selected_cwes)) &
    (merged_df['infra_sector'].isin(selected_sectors)) &
    (merged_df['cvss_score'].between(cvss_range[0], cvss_range[1])) &
    (merged_df['risk_score'].between(risk_range[0], risk_range[1]))
]

if search:
    filtered_df = filtered_df[filtered_df['cve_id'].str.contains(search, case=False) |
                              filtered_df['asset_id'].str.contains(search, case=False)]

if filtered_df.empty:
    st.warning("No data matches the selected filters. Please adjust your filters.")
    st.stop()

# -----------------------------------------------------------------------------
# Main Dashboard Tabs
# -----------------------------------------------------------------------------
tab1, tab2, tab3, tab4 = st.tabs(["📊 Overview", "🏭 Asset Risk", "🛡️ Vulnerability Insights", "📄 Advisory & CWE"])

# ------------------------------ Tab 1: Overview ------------------------------
with tab1:
    st.subheader("Key Risk Indicators")
    col1, col2, col3, col4, col5 = st.columns(5)
    with col1:
        st.metric("Total CVEs", len(filtered_df['cve_id'].unique()))
    with col2:
        st.metric("Total Assets", filtered_df['asset_id'].nunique())
    with col3:
        st.metric("Total Vulnerabilities", len(filtered_df))
    with col4:
        st.metric("Avg CVSS Score", f"{filtered_df['cvss_score'].mean():.2f}")
    with col5:
        st.metric("Avg Risk Score", f"{filtered_df['risk_score'].mean():.2f}")

    # Row of charts
    col1, col2 = st.columns(2)
    with col1:
        # CVSS Distribution
        fig_cvss = px.histogram(filtered_df, x="cvss_score", nbins=20,
                                title="CVSS Score Distribution",
                                color_discrete_sequence=['#FF6B6B'])
        fig_cvss.update_layout(bargap=0.1)
        st.plotly_chart(fig_cvss, use_container_width=True)

        # Severity pie
        severity_counts = filtered_df['severity'].value_counts().reset_index()
        severity_counts.columns = ['Severity', 'Count']
        fig_sev = px.pie(severity_counts, values='Count', names='Severity',
                         title="Vulnerability Severity", hole=0.3)
        st.plotly_chart(fig_sev, use_container_width=True)

    with col2:
        # Risk Score Distribution
        fig_risk = px.histogram(filtered_df, x="risk_score", nbins=20,
                                title="Risk Score Distribution (CVSS × Criticality Factor)",
                                color_discrete_sequence=['#4ECDC4'])
        fig_risk.update_layout(bargap=0.1)
        st.plotly_chart(fig_risk, use_container_width=True)

        # Criticality distribution
        crit_counts = filtered_df['criticality'].value_counts().reset_index()
        crit_counts.columns = ['Criticality', 'Count']
        fig_crit = px.bar(crit_counts, x='Criticality', y='Count',
                          title="Assets by Criticality", color='Criticality',
                          color_discrete_sequence=px.colors.qualitative.Set2)
        st.plotly_chart(fig_crit, use_container_width=True)

    # Network zone risk
    zone_risk = filtered_df.groupby('network_zone')['risk_score'].mean().reset_index()
    if not zone_risk.empty:
        fig_zone = px.bar(zone_risk, x='network_zone', y='risk_score',
                          title="Average Risk Score by Network Zone",
                          color='risk_score', color_continuous_scale='Reds')
        st.plotly_chart(fig_zone, use_container_width=True)

    # Top 10 CVEs by risk score
    top_cves = filtered_df.groupby('cve_id')['risk_score'].max().sort_values(ascending=False).head(10).reset_index()
    fig_top_cves = px.bar(top_cves, x='cve_id', y='risk_score',
                          title="Top 10 CVEs by Risk Score",
                          color='risk_score', color_continuous_scale='Reds')
    fig_top_cves.update_xaxes(tickangle=45)
    st.plotly_chart(fig_top_cves, use_container_width=True)

# ------------------------------ Tab 2: Asset Risk ------------------------------
with tab2:
    st.subheader("Asset Vulnerability Details")
    st.markdown("Explore vulnerabilities per asset. Expand any asset to see all associated CVEs.")

    # Group by asset
    asset_groups = filtered_df.groupby('asset_id')
    for asset_id, group in asset_groups:
        with st.expander(f"🏭 Asset: {asset_id} | Type: {group['asset_type'].iloc[0]} | Criticality: {group['criticality'].iloc[0]} | Risk Score: {group['risk_score'].mean():.2f}"):
            # Asset summary
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Total Vulnerabilities", len(group))
            with col2:
                st.metric("Avg CVSS Score", f"{group['cvss_score'].mean():.2f}")
            with col3:
                st.metric("Max Risk Score", f"{group['risk_score'].max():.2f}")

            # Vulnerabilities table for this asset
            asset_vuln_table = group[['cve_id', 'cvss_score', 'severity', 'exploitability', 'patch_availability', 'risk_score', 'cwe']].sort_values('risk_score', ascending=False)
            st.dataframe(asset_vuln_table, use_container_width=True)

            # Optional: show mini charts for this asset
            fig_asset = px.bar(asset_vuln_table, x='cve_id', y='risk_score',
                               title=f"Risk Score per CVE on Asset {asset_id}",
                               color='severity')
            fig_asset.update_xaxes(tickangle=45)
            st.plotly_chart(fig_asset, use_container_width=True)

    # Additional asset-level visualizations
    st.subheader("Asset Risk Dashboard")
    # Top assets by risk
    asset_risk = filtered_df.groupby('asset_id').agg({
        'risk_score': 'mean',
        'asset_type': 'first',
        'criticality': 'first',
        'network_zone': 'first'
    }).reset_index().sort_values('risk_score', ascending=False).head(15)

    fig_asset_risk = px.bar(asset_risk, x='asset_id', y='risk_score',
                            color='criticality', title="Top 15 Assets by Average Risk Score",
                            hover_data=['asset_type', 'network_zone'])
    fig_asset_risk.update_xaxes(tickangle=45)
    st.plotly_chart(fig_asset_risk, use_container_width=True)

    # Heatmap: Asset Type vs CVE count
    asset_cve_matrix = filtered_df.groupby(['asset_type', 'cve_id']).size().reset_index(name='count')
    if len(asset_cve_matrix['asset_type'].unique()) > 1 and len(asset_cve_matrix['cve_id'].unique()) > 1:
        pivot = asset_cve_matrix.pivot(index='asset_type', columns='cve_id', values='count').fillna(0)
        fig_heat = px.imshow(pivot, text_auto=True, aspect="auto",
                             title="Vulnerability Count per Asset Type and CVE",
                             color_continuous_scale="Blues")
        st.plotly_chart(fig_heat, use_container_width=True)
    else:
        st.info("Not enough unique asset types and CVEs for a heatmap.")

    # Scatter: Asset Type vs CVSS Score
    fig_scatter = px.scatter(filtered_df, x='asset_type', y='cvss_score',
                             color='criticality', size='risk_score',
                             hover_data=['cve_id', 'asset_id'],
                             title="CVSS Score by Asset Type (size = risk score)")
    st.plotly_chart(fig_scatter, use_container_width=True)

# ------------------------------ Tab 3: Vulnerability Insights ------------------------------
with tab3:
    st.subheader("Vulnerability Analysis")

    col1, col2 = st.columns(2)
    with col1:
        # Exploitability distribution
        exp_counts = filtered_df['exploitability'].value_counts().reset_index()
        exp_counts.columns = ['Exploitability', 'Count']
        fig_exp = px.pie(exp_counts, values='Count', names='Exploitability',
                         title="Exploitability Distribution", hole=0.3)
        st.plotly_chart(fig_exp, use_container_width=True)

        # Patch availability
        patch_counts = filtered_df['patch_availability'].value_counts().reset_index()
        patch_counts.columns = ['Patch Availability', 'Count']
        fig_patch = px.bar(patch_counts, x='Patch Availability', y='Count',
                           title="Patch Availability", color='Patch Availability')
        st.plotly_chart(fig_patch, use_container_width=True)

    with col2:
        # Vulnerability by asset type
        asset_vuln_count = filtered_df.groupby('asset_type')['cve_id'].nunique().reset_index()
        asset_vuln_count.columns = ['Asset Type', 'Unique CVEs']
        fig_asset_vuln = px.bar(asset_vuln_count, x='Asset Type', y='Unique CVEs',
                                title="Unique CVEs per Asset Type", color='Unique CVEs')
        st.plotly_chart(fig_asset_vuln, use_container_width=True)

        # Vulnerability density (vulns per asset)
        density = filtered_df.groupby('asset_type').agg({
            'asset_id': 'nunique',
            'cve_id': 'count'
        }).reset_index()
        density['vulns_per_asset'] = density['cve_id'] / density['asset_id']
        fig_density = px.bar(density, x='asset_type', y='vulns_per_asset',
                             title="Average Vulnerabilities per Asset by Type")
        st.plotly_chart(fig_density, use_container_width=True)

    # CVSS vs Risk Score scatter
    fig_cvss_risk = px.scatter(filtered_df, x='cvss_score', y='risk_score',
                               color='severity', size='criticality_factor',
                               hover_data=['cve_id', 'asset_id'],
                               title="CVSS vs Risk Score (size = criticality factor)")
    st.plotly_chart(fig_cvss_risk, use_container_width=True)

    # Top CVEs with most affected assets
    cve_asset_count = filtered_df.groupby('cve_id')['asset_id'].nunique().reset_index().sort_values('asset_id', ascending=False).head(10)
    fig_cve_assets = px.bar(cve_asset_count, x='cve_id', y='asset_id',
                            title="Top 10 CVEs by Number of Affected Assets",
                            color='asset_id')
    fig_cve_assets.update_xaxes(tickangle=45)
    st.plotly_chart(fig_cve_assets, use_container_width=True)

    # Vulnerability timeline (if date columns exist)
    date_columns = [col for col in filtered_df.columns if 'date' in col.lower()]
    if date_columns:
        st.subheader("Vulnerability Timeline")
        date_col = date_columns[0]  # use first date column
        filtered_df['date'] = pd.to_datetime(filtered_df[date_col], errors='coerce')
        timeline = filtered_df.groupby(filtered_df['date'].dt.to_period('M')).size().reset_index(name='count')
        timeline['date'] = timeline['date'].astype(str)
        fig_timeline = px.line(timeline, x='date', y='count', title="Vulnerabilities Over Time")
        st.plotly_chart(fig_timeline, use_container_width=True)

# ------------------------------ Tab 4: Advisory & CWE ------------------------------
with tab4:
    st.subheader("Advisory & CWE Insights")

    col1, col2 = st.columns(2)
    with col1:
        # CWE distribution
        cwe_counts = filtered_df['cwe'].value_counts().reset_index().head(15)
        cwe_counts.columns = ['CWE', 'Count']
        fig_cwe = px.bar(cwe_counts, x='CWE', y='Count', title="Top 15 CWEs")
        fig_cwe.update_xaxes(tickangle=45)
        st.plotly_chart(fig_cwe, use_container_width=True)

        # CWE by severity
        cwe_severity = filtered_df.groupby(['cwe', 'severity']).size().reset_index(name='count')
        if not cwe_severity.empty:
            fig_cwe_sev = px.bar(cwe_severity, x='cwe', y='count', color='severity',
                                 title="CWE Distribution by Severity")
            fig_cwe_sev.update_xaxes(tickangle=45)
            st.plotly_chart(fig_cwe_sev, use_container_width=True)

    with col2:
        # Infrastructure sector distribution
        sector_counts = filtered_df['infra_sector'].value_counts().reset_index()
        sector_counts.columns = ['Sector', 'Count']
        fig_sector = px.pie(sector_counts, values='Count', names='Sector',
                            title="Critical Infrastructure Sectors")
        st.plotly_chart(fig_sector, use_container_width=True)

        # Advisory titles (top 10 by mention)
        adv_counts = filtered_df['advisory_title'].value_counts().reset_index().head(10)
        adv_counts.columns = ['Advisory Title', 'Count']
        fig_adv = px.bar(adv_counts, x='Advisory Title', y='Count',
                         title="Top 10 Advisory References")
        fig_adv.update_xaxes(tickangle=45)
        st.plotly_chart(fig_adv, use_container_width=True)

    # CVE to Advisory mapping table
    st.subheader("CVE to Advisory Mapping")
    advisory_table = filtered_df[['cve_id', 'advisory_title', 'cwe', 'infra_sector']].drop_duplicates().sort_values('cve_id')
    st.dataframe(advisory_table, use_container_width=True)

# -----------------------------------------------------------------------------
# Download filtered data (all tabs combined)
# -----------------------------------------------------------------------------
st.sidebar.markdown("---")
csv = filtered_df.to_csv(index=False).encode('utf-8')
st.sidebar.download_button(
    label="📥 Download filtered data as CSV",
    data=csv,
    file_name="ot_risk_assessment.csv",
    mime="text/csv"
)

st.sidebar.success("Dashboard ready. Use filters to explore risk.")
