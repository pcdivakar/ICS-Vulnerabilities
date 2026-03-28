import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import sqlite3
from datetime import datetime
import numpy as np

# -------------------------------
# Page configuration
st.set_page_config(page_title="OT Cybersecurity Dashboard", layout="wide")

# -------------------------------
# Helper functions for database (used by management pages)
def init_db():
    conn = sqlite3.connect('ot_cyber.db')
    c = conn.cursor()
    # Assets table
    c.execute('''CREATE TABLE IF NOT EXISTS assets
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  site TEXT,
                  asset_type TEXT,
                  vendor TEXT,
                  firmware TEXT,
                  network_zone TEXT,
                  criticality TEXT,
                  protocol TEXT,
                  ip_address TEXT,
                  mac_address TEXT,
                  location TEXT,
                  serial_number TEXT,
                  last_seen TEXT,
                  other_properties TEXT,
                  created_at TIMESTAMP)''')
    # Vulnerabilities table
    c.execute('''CREATE TABLE IF NOT EXISTS vulnerabilities
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  asset_id INTEGER,
                  cve_id TEXT,
                  cvss_score REAL,
                  exploitability TEXT,
                  patch_availability TEXT,
                  severity TEXT,
                  hostname TEXT,
                  port INTEGER,
                  protocol TEXT,
                  plugin_name TEXT,
                  vulnerability_title TEXT,
                  created_at TIMESTAMP,
                  FOREIGN KEY(asset_id) REFERENCES assets(id))''')
    # Advisory table (CVE mapping)
    c.execute('''CREATE TABLE IF NOT EXISTS advisory
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  cve_number TEXT UNIQUE,
                  ics_cert_advisory_title TEXT,
                  cwe_number TEXT,
                  critical_infrastructure_sector TEXT,
                  created_at TIMESTAMP)''')
    conn.commit()
    conn.close()

def load_assets():
    conn = sqlite3.connect('ot_cyber.db')
    df = pd.read_sql_query("SELECT * FROM assets", conn)
    conn.close()
    return df

def load_vulnerabilities():
    conn = sqlite3.connect('ot_cyber.db')
    df = pd.read_sql_query("SELECT * FROM vulnerabilities", conn)
    conn.close()
    return df

def load_advisory():
    conn = sqlite3.connect('ot_cyber.db')
    df = pd.read_sql_query("SELECT * FROM advisory", conn)
    conn.close()
    return df

def save_asset(site, asset_type, vendor, firmware, network_zone, criticality,
               protocol, ip_address, mac_address, location, serial_number, last_seen, other_properties):
    conn = sqlite3.connect('ot_cyber.db')
    c = conn.cursor()
    c.execute("""INSERT INTO assets 
                 (site, asset_type, vendor, firmware, network_zone, criticality,
                  protocol, ip_address, mac_address, location, serial_number, last_seen,
                  other_properties, created_at)
                 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
              (site, asset_type, vendor, firmware, network_zone, criticality,
               protocol, ip_address, mac_address, location, serial_number, last_seen,
               other_properties, datetime.now()))
    conn.commit()
    asset_id = c.lastrowid
    conn.close()
    return asset_id

def save_vulnerability(asset_id, cve_id, cvss_score, exploitability, patch_availability,
                       severity, hostname, port, protocol, plugin_name, vulnerability_title):
    conn = sqlite3.connect('ot_cyber.db')
    c = conn.cursor()
    c.execute("""INSERT INTO vulnerabilities 
                 (asset_id, cve_id, cvss_score, exploitability, patch_availability,
                  severity, hostname, port, protocol, plugin_name, vulnerability_title, created_at)
                 VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
              (asset_id, cve_id, cvss_score, exploitability, patch_availability,
               severity, hostname, port, protocol, plugin_name, vulnerability_title, datetime.now()))
    conn.commit()
    conn.close()

def save_advisory(cve_number, title, cwe, sector):
    conn = sqlite3.connect('ot_cyber.db')
    c = conn.cursor()
    c.execute("""INSERT OR REPLACE INTO advisory 
                 (cve_number, ics_cert_advisory_title, cwe_number, critical_infrastructure_sector, created_at)
                 VALUES (?,?,?,?,?)""",
              (cve_number, title, cwe, sector, datetime.now()))
    conn.commit()
    conn.close()

def delete_all_assets():
    conn = sqlite3.connect('ot_cyber.db')
    c = conn.cursor()
    c.execute("DELETE FROM assets")
    c.execute("DELETE FROM vulnerabilities")
    conn.commit()
    conn.close()

def delete_all_advisory():
    conn = sqlite3.connect('ot_cyber.db')
    c = conn.cursor()
    c.execute("DELETE FROM advisory")
    conn.commit()
    conn.close()

def calculate_risk_score(assets, vulns):
    """Calculate total risk score (sum of CVSS * criticality weight)."""
    if assets.empty or vulns.empty:
        return 0
    criticality_weights = {'Low': 1, 'Medium': 2, 'High': 3, 'Critical': 4}
    assets['weight'] = assets['criticality'].map(criticality_weights).fillna(1)
    merged = pd.merge(vulns, assets, left_on='asset_id', right_on='id', how='inner')
    if merged.empty:
        return 0
    merged['risk'] = merged['cvss_score'] * merged['weight']
    return merged['risk'].sum()

# Initialize database (for management pages)
init_db()

# -------------------------------
# Sidebar navigation
st.sidebar.title("Navigation")
page = st.sidebar.radio("Go to", ["Dashboard", "Assets Management", "Vulnerabilities Management", "Advisory Data", "Import Data", "Export Data"])

# -----------------------------------------------------------------------------
# DASHBOARD PAGE (File‑only, no database)
# -----------------------------------------------------------------------------
if page == "Dashboard":
    st.title("🔒 OT Cybersecurity Dashboard")
    st.markdown("Upload vulnerability, asset, and ICS advisory data to visualize risk.")

    # File uploaders
    col1, col2, col3 = st.columns(3)
    with col1:
        vuln_file = st.file_uploader("📁 Vulnerability File (CSV/Excel)", type=["csv", "xlsx"], key="dashboard_vuln")
    with col2:
        asset_file = st.file_uploader("🏭 Asset File (CSV/Excel)", type=["csv", "xlsx"], key="dashboard_asset")
    with col3:
        advisory_file = st.file_uploader("📄 Advisory File (CSV/Excel)", type=["csv", "xlsx"], key="dashboard_advisory")

    if not (vuln_file and asset_file and advisory_file):
        st.info("Please upload all three files to see the dashboard.")
        st.stop()

    # Load data
    @st.cache_data
    def load_csv_or_excel(file):
        if file.name.endswith('.csv'):
            return pd.read_csv(file)
        else:
            return pd.read_excel(file)

    with st.spinner("Loading data..."):
        vuln_df = load_csv_or_excel(vuln_file)
        asset_df = load_csv_or_excel(asset_file)
        advisory_df = load_csv_or_excel(advisory_file)

    # Preprocessing
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

    # Enrich with advisory data
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
    for col in ['asset_type', 'criticality', 'network_zone']:
        if col not in merged_df.columns:
            merged_df[col] = 'Unknown'
        else:
            merged_df[col] = merged_df[col].fillna('Unknown')

    # Compute risk score (CVSS * criticality factor)
    crit_map = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
    merged_df['criticality'] = merged_df['criticality'].astype(str).str.lower().fillna('unknown')
    merged_df['criticality_factor'] = merged_df['criticality'].map(crit_map).fillna(1)
    merged_df['risk_score'] = merged_df['cvss_score'] * merged_df['criticality_factor']

    # Ensure numeric
    merged_df['criticality_factor'] = pd.to_numeric(merged_df['criticality_factor'], errors='coerce').fillna(1)
    merged_df['risk_score'] = pd.to_numeric(merged_df['risk_score'], errors='coerce').fillna(0)

    # Sidebar filters
    st.sidebar.header("🔍 Filters")
    with st.sidebar.expander("Severity", expanded=True):
        severities = merged_df['severity'].dropna().unique()
        selected_severities = st.multiselect("Severity", options=severities, default=severities, key="filt_sev")
    with st.sidebar.expander("Asset Criticality", expanded=True):
        criticalities = merged_df['criticality'].dropna().unique()
        selected_criticalities = st.multiselect("Asset Criticality", options=criticalities, default=criticalities, key="filt_crit")
    with st.sidebar.expander("Network Zone", expanded=True):
        zones = merged_df['network_zone'].dropna().unique()
        selected_zones = st.multiselect("Network Zone", options=zones, default=zones, key="filt_zone")
    with st.sidebar.expander("Asset Type", expanded=True):
        asset_types = merged_df['asset_type'].dropna().unique()
        selected_asset_types = st.multiselect("Asset Type", options=asset_types, default=asset_types, key="filt_type")
    with st.sidebar.expander("Exploitability", expanded=True):
        exploit = merged_df['exploitability'].dropna().unique()
        selected_exploit = st.multiselect("Exploitability", options=exploit, default=exploit, key="filt_exp")
    with st.sidebar.expander("Patch Availability", expanded=True):
        patch = merged_df['patch_availability'].dropna().unique()
        selected_patch = st.multiselect("Patch Availability", options=patch, default=patch, key="filt_patch")
    with st.sidebar.expander("CWE", expanded=True):
        cwes = merged_df['cwe'].dropna().unique()
        selected_cwes = st.multiselect("CWE", options=cwes, default=cwes, key="filt_cwe")
    with st.sidebar.expander("Infrastructure Sector", expanded=True):
        sectors = merged_df['infra_sector'].dropna().unique()
        selected_sectors = st.multiselect("Sector", options=sectors, default=sectors, key="filt_sector")

    cvss_range = st.sidebar.slider("CVSS Score Range", 0.0, 10.0, (0.0, 10.0))
    risk_range = st.sidebar.slider("Risk Score Range", 0.0, 40.0, (0.0, 40.0))
    search = st.sidebar.text_input("Search (CVE or Asset ID)")

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
                                  filtered_df['asset_id'].astype(str).str.contains(search, case=False)]

    if filtered_df.empty:
        st.warning("No data matches the selected filters. Please adjust filters.")
        st.stop()

    # KPIs
    st.markdown("### Key Metrics")
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

    # Tabs
    tab_overview, tab_asset_risk, tab_vuln_insights, tab_advisory = st.tabs([
        "📊 Overview", "🏭 Asset Risk", "🛡️ Vulnerability Insights", "📄 Advisory & CWE"
    ])

    with tab_overview:
        col1, col2 = st.columns(2)
        with col1:
            fig_cvss = px.histogram(filtered_df, x="cvss_score", nbins=20, title="CVSS Score Distribution",
                                    color_discrete_sequence=['#FF6B6B'])
            fig_cvss.update_layout(bargap=0.1)
            st.plotly_chart(fig_cvss, use_container_width=True)

            severity_counts = filtered_df['severity'].value_counts().reset_index()
            severity_counts.columns = ['Severity', 'Count']
            fig_sev = px.pie(severity_counts, values='Count', names='Severity',
                             title="Vulnerability Severity", hole=0.3)
            st.plotly_chart(fig_sev, use_container_width=True)

        with col2:
            fig_risk = px.histogram(filtered_df, x="risk_score", nbins=20, title="Risk Score Distribution",
                                    color_discrete_sequence=['#4ECDC4'])
            fig_risk.update_layout(bargap=0.1)
            st.plotly_chart(fig_risk, use_container_width=True)

            crit_counts = filtered_df['criticality'].value_counts().reset_index()
            crit_counts.columns = ['Criticality', 'Count']
            fig_crit = px.bar(crit_counts, x='Criticality', y='Count', title="Assets by Criticality",
                              color='Criticality', color_discrete_sequence=px.colors.qualitative.Set2)
            st.plotly_chart(fig_crit, use_container_width=True)

        zone_risk = filtered_df.groupby('network_zone')['risk_score'].mean().reset_index()
        if not zone_risk.empty:
            fig_zone = px.bar(zone_risk, x='network_zone', y='risk_score',
                              title="Average Risk Score by Network Zone",
                              color='risk_score', color_continuous_scale='Reds')
            st.plotly_chart(fig_zone, use_container_width=True)

        top_cves = filtered_df.groupby('cve_id')['risk_score'].max().sort_values(ascending=False).head(10).reset_index()
        fig_top_cves = px.bar(top_cves, x='cve_id', y='risk_score', title="Top 10 CVEs by Risk Score",
                              color='risk_score', color_continuous_scale='Reds')
        fig_top_cves.update_xaxes(tickangle=45)
        st.plotly_chart(fig_top_cves, use_container_width=True)

    with tab_asset_risk:
        st.subheader("Asset Vulnerability Details")
        st.markdown("Expand any asset to see its vulnerabilities.")
        asset_groups = filtered_df.groupby('asset_id')
        for asset_id, group in asset_groups:
            asset_type = group['asset_type'].iloc[0]
            criticality = group['criticality'].iloc[0]
            avg_risk = group['risk_score'].mean()
            with st.expander(f"🏭 Asset ID: {asset_id} | Type: {asset_type} | Criticality: {criticality} | Avg Risk: {avg_risk:.2f}"):
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric("Total Vulnerabilities", len(group))
                with col2:
                    st.metric("Avg CVSS Score", f"{group['cvss_score'].mean():.2f}")
                with col3:
                    st.metric("Max Risk Score", f"{group['risk_score'].max():.2f}")

                asset_vuln_table = group[['cve_id', 'cvss_score', 'severity', 'exploitability', 'patch_availability', 'risk_score', 'cwe']].sort_values('risk_score', ascending=False)
                st.dataframe(asset_vuln_table, use_container_width=True)

                fig_asset = px.bar(asset_vuln_table, x='cve_id', y='risk_score',
                                   title=f"Risk Score per CVE on Asset {asset_id}", color='severity')
                fig_asset.update_xaxes(tickangle=45)
                st.plotly_chart(fig_asset, use_container_width=True)

        st.subheader("Asset Risk Dashboard")
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

        # Heatmap (asset type vs CVE)
        asset_cve_matrix = filtered_df.groupby(['asset_type', 'cve_id']).size().reset_index(name='count')
        if len(asset_cve_matrix['asset_type'].unique()) > 1 and len(asset_cve_matrix['cve_id'].unique()) > 1:
            pivot = asset_cve_matrix.pivot(index='asset_type', columns='cve_id', values='count').fillna(0)
            fig_heat = px.imshow(pivot, text_auto=True, aspect="auto",
                                 title="Vulnerability Count per Asset Type and CVE",
                                 color_continuous_scale="Blues")
            st.plotly_chart(fig_heat, use_container_width=True)
        else:
            st.info("Not enough unique asset types and CVEs for a heatmap.")

        fig_scatter = px.scatter(filtered_df, x='asset_type', y='cvss_score',
                                 color='criticality', size='risk_score',
                                 hover_data=['cve_id', 'asset_id'],
                                 title="CVSS Score by Asset Type (size = risk score)")
        st.plotly_chart(fig_scatter, use_container_width=True)

    with tab_vuln_insights:
        col1, col2 = st.columns(2)
        with col1:
            exp_counts = filtered_df['exploitability'].value_counts().reset_index()
            exp_counts.columns = ['Exploitability', 'Count']
            fig_exp = px.pie(exp_counts, values='Count', names='Exploitability',
                             title="Exploitability Distribution", hole=0.3)
            st.plotly_chart(fig_exp, use_container_width=True)

            patch_counts = filtered_df['patch_availability'].value_counts().reset_index()
            patch_counts.columns = ['Patch Availability', 'Count']
            fig_patch = px.bar(patch_counts, x='Patch Availability', y='Count',
                               title="Patch Availability", color='Patch Availability')
            st.plotly_chart(fig_patch, use_container_width=True)

        with col2:
            asset_vuln_count = filtered_df.groupby('asset_type')['cve_id'].nunique().reset_index()
            asset_vuln_count.columns = ['Asset Type', 'Unique CVEs']
            fig_asset_vuln = px.bar(asset_vuln_count, x='Asset Type', y='Unique CVEs',
                                    title="Unique CVEs per Asset Type", color='Unique CVEs')
            st.plotly_chart(fig_asset_vuln, use_container_width=True)

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

        cve_asset_count = filtered_df.groupby('cve_id')['asset_id'].nunique().reset_index().sort_values('asset_id', ascending=False).head(10)
        fig_cve_assets = px.bar(cve_asset_count, x='cve_id', y='asset_id',
                                title="Top 10 CVEs by Number of Affected Assets",
                                color='asset_id')
        fig_cve_assets.update_xaxes(tickangle=45)
        st.plotly_chart(fig_cve_assets, use_container_width=True)

    with tab_advisory:
        col1, col2 = st.columns(2)
        with col1:
            cwe_counts = filtered_df['cwe'].value_counts().reset_index().head(15)
            cwe_counts.columns = ['CWE', 'Count']
            fig_cwe = px.bar(cwe_counts, x='CWE', y='Count', title="Top 15 CWEs")
            fig_cwe.update_xaxes(tickangle=45)
            st.plotly_chart(fig_cwe, use_container_width=True)

            cwe_severity = filtered_df.groupby(['cwe', 'severity']).size().reset_index(name='count')
            if not cwe_severity.empty:
                fig_cwe_sev = px.bar(cwe_severity, x='cwe', y='count', color='severity',
                                     title="CWE Distribution by Severity")
                fig_cwe_sev.update_xaxes(tickangle=45)
                st.plotly_chart(fig_cwe_sev, use_container_width=True)

        with col2:
            sector_counts = filtered_df['infra_sector'].value_counts().reset_index()
            sector_counts.columns = ['Sector', 'Count']
            fig_sector = px.pie(sector_counts, values='Count', names='Sector',
                                title="Critical Infrastructure Sectors")
            st.plotly_chart(fig_sector, use_container_width=True)

            adv_counts = filtered_df['advisory_title'].value_counts().reset_index().head(10)
            adv_counts.columns = ['Advisory Title', 'Count']
            fig_adv = px.bar(adv_counts, x='Advisory Title', y='Count',
                             title="Top 10 Advisory References")
            fig_adv.update_xaxes(tickangle=45)
            st.plotly_chart(fig_adv, use_container_width=True)

        st.subheader("CVE to Advisory Mapping")
        advisory_table = filtered_df[['cve_id', 'advisory_title', 'cwe', 'infra_sector']].drop_duplicates().sort_values('cve_id')
        st.dataframe(advisory_table, use_container_width=True)

    # Download button
    csv = filtered_df.to_csv(index=False).encode('utf-8')
    st.sidebar.markdown("---")
    st.sidebar.download_button("📥 Download Filtered Data as CSV", data=csv,
                               file_name="ot_risk_assessment.csv", mime="text/csv")
    st.sidebar.success("Dashboard ready. Use filters to explore risk.")

# -----------------------------------------------------------------------------
# ASSETS MANAGEMENT (uses SQLite)
# -----------------------------------------------------------------------------
elif page == "Assets Management":
    st.title("Manage OT Assets")
    
    with st.expander("Add New Asset"):
        with st.form("add_asset_form"):
            col1, col2 = st.columns(2)
            with col1:
                site = st.text_input("Site *", help="Required")
                asset_type = st.text_input("Asset Type *", help="Required")
                vendor = st.text_input("Vendor *", help="Required")
                firmware = st.text_input("Firmware Version")
                network_zone = st.text_input("Network Zone")
                criticality = st.selectbox("Criticality", ["Low", "Medium", "High", "Critical"])
                protocol = st.text_input("Protocol *", help="Required")
            with col2:
                ip_address = st.text_input("IP Address")
                mac_address = st.text_input("MAC Address")
                location = st.text_input("Location")
                serial_number = st.text_input("Serial Number")
                last_seen = st.date_input("Last Seen", value=datetime.now().date())
            other_properties = st.text_area("Other Properties (JSON or text)")
            submitted = st.form_submit_button("Add Asset")
            if submitted:
                if site and asset_type and vendor and protocol:
                    asset_id = save_asset(site, asset_type, vendor, firmware, network_zone, criticality,
                                          protocol, ip_address, mac_address, location, serial_number,
                                          last_seen.strftime("%Y-%m-%d"), other_properties)
                    st.success(f"Asset added with ID {asset_id}")
                else:
                    st.error("Site, Asset Type, Vendor and Protocol are required.")
    
    st.subheader("Existing Assets")
    assets_df = load_assets()
    if not assets_df.empty:
        st.dataframe(assets_df)
        if st.button("Delete All Assets"):
            delete_all_assets()
            st.warning("All assets and related vulnerabilities deleted.")
            st.rerun()
    else:
        st.info("No assets found.")

# -----------------------------------------------------------------------------
# VULNERABILITIES MANAGEMENT (uses SQLite)
# -----------------------------------------------------------------------------
elif page == "Vulnerabilities Management":
    st.title("Manage Vulnerabilities")
    
    assets_df = load_assets()
    if assets_df.empty:
        st.warning("Please add assets before adding vulnerabilities.")
    else:
        with st.expander("Add New Vulnerability"):
            with st.form("add_vuln_form"):
                asset_id = st.selectbox("Select Asset", options=assets_df['id'].tolist(),
                                        format_func=lambda x: f"{x} - {assets_df[assets_df['id']==x]['site'].values[0]} - {assets_df[assets_df['id']==x]['asset_type'].values[0]}")
                cve_id = st.text_input("CVE ID *")
                cvss_score = st.number_input("CVSS Score", min_value=0.0, max_value=10.0, step=0.1)
                exploitability = st.selectbox("Exploitability", ["None", "Proof-of-Concept", "Functional", "High"])
                patch_availability = st.selectbox("Patch Availability", ["Available", "Not Available", "Workaround"])
                severity = st.selectbox("Severity", ["Info", "Low", "Medium", "High", "Critical"])
                hostname = st.text_input("Hostname / IP")
                port = st.number_input("Port", min_value=0, max_value=65535, step=1)
                protocol = st.text_input("Protocol")
                plugin_name = st.text_input("Plugin Name")
                vulnerability_title = st.text_input("Vulnerability Title")
                submitted = st.form_submit_button("Add Vulnerability")
                if submitted and cve_id:
                    save_vulnerability(asset_id, cve_id, cvss_score, exploitability, patch_availability,
                                      severity, hostname, port, protocol, plugin_name, vulnerability_title)
                    st.success("Vulnerability added.")
                elif not cve_id:
                    st.error("CVE ID is required.")
    
    st.subheader("Existing Vulnerabilities")
    vuln_df = load_vulnerabilities()
    if not vuln_df.empty:
        merged = pd.merge(vuln_df, assets_df, left_on='asset_id', right_on='id', how='left')
        st.dataframe(merged)
    else:
        st.info("No vulnerabilities found.")

# -----------------------------------------------------------------------------
# ADVISORY DATA (uses SQLite)
# -----------------------------------------------------------------------------
elif page == "Advisory Data":
    st.title("Manage Advisory Data (CVE Mappings)")
    st.markdown("Upload or manually add CVE advisory information (title, CWE, infrastructure sector).")

    with st.expander("Add/Update Advisory Entry"):
        with st.form("add_advisory_form"):
            cve_number = st.text_input("CVE Number *", help="e.g., CVE-2024-12345")
            title = st.text_input("ICS-CERT Advisory Title")
            cwe = st.text_input("CWE Number")
            sector = st.text_input("Critical Infrastructure Sector")
            submitted = st.form_submit_button("Save Advisory")
            if submitted and cve_number:
                save_advisory(cve_number, title, cwe, sector)
                st.success(f"Advisory for {cve_number} saved.")
            elif not cve_number:
                st.error("CVE Number is required.")

    st.subheader("Existing Advisory Data")
    advisory_df = load_advisory()
    if not advisory_df.empty:
        st.dataframe(advisory_df)
        if st.button("Delete All Advisory Data"):
            delete_all_advisory()
            st.warning("All advisory data deleted.")
            st.rerun()
    else:
        st.info("No advisory data found. You can import from CSV below or add manually.")

    st.markdown("---")
    st.subheader("Import Advisory Data from CSV/Excel")
    advisory_file = st.file_uploader("Upload Advisory CSV/Excel", type=["csv", "xlsx"])
    if advisory_file is not None:
        try:
            if advisory_file.name.endswith('.csv'):
                df_adv = pd.read_csv(advisory_file)
            else:
                df_adv = pd.read_excel(advisory_file)
            required_cols = ['cve_number']
            missing = [col for col in required_cols if col not in df_adv.columns]
            if missing:
                st.error(f"Missing required columns: {missing}")
            else:
                for _, row in df_adv.iterrows():
                    cve = row['cve_number']
                    title = row.get('ics-cert_advisory_title', '')
                    cwe = row.get('cwe_number', '')
                    sector = row.get('critical_infrastructure_sector', '')
                    save_advisory(cve, title, cwe, sector)
                st.success(f"Imported {len(df_adv)} advisory entries.")
                st.rerun()
        except Exception as e:
            st.error(f"Error reading file: {e}")

# -----------------------------------------------------------------------------
# IMPORT DATA (to SQLite)
# -----------------------------------------------------------------------------
elif page == "Import Data":
    st.title("Import Data from Files")
    st.markdown("Use the standard templates below to import assets, vulnerabilities, and advisory data into the database.")

    col1, col2, col3 = st.columns(3)
    with col1:
        st.subheader("Assets Template")
        asset_template = pd.DataFrame({
            "site": ["Refinery A", "Refinery A", "Power Plant B"],
            "asset_type": ["PLC", "RTU", "HMI"],
            "vendor": ["Siemens", "Rockwell", "Schneider"],
            "firmware": ["v4.2", "v2.0", "v3.1"],
            "network_zone": ["Level 1", "Level 2", "Level 0"],
            "criticality": ["Critical", "High", "Medium"],
            "protocol": ["Modbus/TCP", "DNP3", "OPC DA"],
            "ip_address": ["192.168.1.10", "10.0.0.5", "172.16.0.20"],
            "mac_address": ["00:1A:2B:3C:4D:5E", "AA:BB:CC:DD:EE:FF", "11:22:33:44:55:66"],
            "location": ["Main Control Room", "Field Station 3", "Control Room East"],
            "serial_number": ["SN-12345", "SN-67890", "SN-112233"],
            "last_seen": ["2025-03-27", "2025-03-26", "2025-03-27"],
            "other_properties": ["{\"protocol\": \"Modbus\"}", "{\"protocol\": \"DNP3\"}", "{\"touchscreen\": true}"]
        })
        st.dataframe(asset_template)
        csv_asset = asset_template.to_csv(index=False).encode('utf-8')
        st.download_button("Download Assets CSV", csv_asset, "assets_template.csv", "text/csv")

    with col2:
        st.subheader("Vulnerabilities Template")
        vuln_template = pd.DataFrame({
            "asset_id": [1, 1, 2, 3],
            "cve_id": ["CVE-2024-12345", "CVE-2024-67890", "CVE-2023-45678", "CVE-2025-0001"],
            "cvss_score": [7.5, 9.0, 4.3, 8.2],
            "exploitability": ["Functional", "High", "Proof-of-Concept", "Functional"],
            "patch_availability": ["Not Available", "Workaround", "Available", "Not Available"],
            "severity": ["High", "Critical", "Medium", "High"],
            "hostname": ["192.168.1.10", "192.168.1.10", "10.0.0.5", "172.16.0.20"],
            "port": [443, 22, 161, 80],
            "protocol": ["tcp", "tcp", "udp", "tcp"],
            "plugin_name": ["SSL/TLS RC4 Cipher Suites Supported", "SSH Weak Algorithms Supported", "SNMP Community String Default", "Open Port Scan"],
            "vulnerability_title": ["RC4 Weak Cipher Support", "SSH Weak Key Exchange", "Default SNMP String", "Port 80 Open"]
        })
        st.dataframe(vuln_template)
        csv_vuln = vuln_template.to_csv(index=False).encode('utf-8')
        st.download_button("Download Vulnerabilities CSV", csv_vuln, "vulnerabilities_template.csv", "text/csv")

    with col3:
        st.subheader("Advisory Template")
        adv_template = pd.DataFrame({
            "cve_number": ["CVE-2024-12345", "CVE-2024-67890", "CVE-2023-45678"],
            "ics-cert_advisory_title": ["ICS Advisory ICSA-24-123-01", "ICS Advisory ICSA-24-456-02", "ICS Advisory ICSA-23-789-03"],
            "cwe_number": ["CWE-798", "CWE-287", "CWE-200"],
            "critical_infrastructure_sector": ["Energy", "Water", "Transportation"]
        })
        st.dataframe(adv_template)
        csv_adv = adv_template.to_csv(index=False).encode('utf-8')
        st.download_button("Download Advisory CSV", csv_adv, "advisory_template.csv", "text/csv")

    st.markdown("---")
    st.subheader("Upload Files to Import into Database")

    asset_file = st.file_uploader("Assets CSV/Excel", type=["csv", "xlsx"], key="import_assets")
    if asset_file is not None:
        try:
            if asset_file.name.endswith('.csv'):
                df_asset = pd.read_csv(asset_file)
            else:
                df_asset = pd.read_excel(asset_file)
            required_asset_cols = ['site', 'asset_type', 'vendor', 'protocol']
            missing = [col for col in required_asset_cols if col not in df_asset.columns]
            if missing:
                st.error(f"Missing required columns: {missing}")
            else:
                for _, row in df_asset.iterrows():
                    save_asset(
                        row.get('site', ''),
                        row.get('asset_type', ''),
                        row.get('vendor', ''),
                        row.get('firmware', ''),
                        row.get('network_zone', ''),
                        row.get('criticality', 'Medium'),
                        row.get('protocol', ''),
                        row.get('ip_address', ''),
                        row.get('mac_address', ''),
                        row.get('location', ''),
                        row.get('serial_number', ''),
                        row.get('last_seen', datetime.now().strftime("%Y-%m-%d")),
                        row.get('other_properties', '')
                    )
                st.success(f"Imported {len(df_asset)} assets.")
                st.rerun()
        except Exception as e:
            st.error(f"Error reading asset file: {e}")

    vuln_file = st.file_uploader("Vulnerabilities CSV/Excel", type=["csv", "xlsx"], key="import_vulns")
    if vuln_file is not None:
        try:
            if vuln_file.name.endswith('.csv'):
                df_vuln = pd.read_csv(vuln_file)
            else:
                df_vuln = pd.read_excel(vuln_file)
            required_vuln_cols = ['asset_id', 'cve_id', 'cvss_score']
            missing = [col for col in required_vuln_cols if col not in df_vuln.columns]
            if missing:
                st.error(f"Missing required columns: {missing}")
            else:
                for _, row in df_vuln.iterrows():
                    asset_id = int(row.get('asset_id', 0))
                    if asset_id == 0:
                        st.warning("Skipping vulnerability with invalid asset_id")
                        continue
                    save_vulnerability(
                        asset_id,
                        row.get('cve_id', ''),
                        float(row.get('cvss_score', 0)),
                        row.get('exploitability', ''),
                        row.get('patch_availability', ''),
                        row.get('severity', ''),
                        row.get('hostname', ''),
                        row.get('port', None) if pd.notna(row.get('port', None)) else None,
                        row.get('protocol', ''),
                        row.get('plugin_name', ''),
                        row.get('vulnerability_title', '')
                    )
                st.success(f"Imported {len(df_vuln)} vulnerabilities.")
                st.rerun()
        except Exception as e:
            st.error(f"Error reading vulnerability file: {e}")

    adv_file = st.file_uploader("Advisory CSV/Excel", type=["csv", "xlsx"], key="import_advisory")
    if adv_file is not None:
        try:
            if adv_file.name.endswith('.csv'):
                df_adv = pd.read_csv(adv_file)
            else:
                df_adv = pd.read_excel(adv_file)
            required_adv_cols = ['cve_number']
            missing = [col for col in required_adv_cols if col not in df_adv.columns]
            if missing:
                st.error(f"Missing required columns: {missing}")
            else:
                for _, row in df_adv.iterrows():
                    save_advisory(
                        row['cve_number'],
                        row.get('ics-cert_advisory_title', ''),
                        row.get('cwe_number', ''),
                        row.get('critical_infrastructure_sector', '')
                    )
                st.success(f"Imported {len(df_adv)} advisory entries.")
                st.rerun()
        except Exception as e:
            st.error(f"Error reading advisory file: {e}")

# -----------------------------------------------------------------------------
# EXPORT DATA (from SQLite)
# -----------------------------------------------------------------------------
elif page == "Export Data":
    st.title("Export Data")

    assets_df = load_assets()
    vuln_df = load_vulnerabilities()
    advisory_df = load_advisory()

    if not assets_df.empty:
        csv_assets = assets_df.to_csv(index=False).encode('utf-8')
        st.download_button("Download Assets CSV", csv_assets, "assets_export.csv", "text/csv")
    else:
        st.info("No assets to export.")

    if not vuln_df.empty:
        csv_vuln = vuln_df.to_csv(index=False).encode('utf-8')
        st.download_button("Download Vulnerabilities CSV", csv_vuln, "vulnerabilities_export.csv", "text/csv")
    else:
        st.info("No vulnerabilities to export.")

    if not advisory_df.empty:
        csv_adv = advisory_df.to_csv(index=False).encode('utf-8')
        st.download_button("Download Advisory CSV", csv_adv, "advisory_export.csv", "text/csv")
    else:
        st.info("No advisory data to export.")
