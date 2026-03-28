import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import sqlite3
from datetime import datetime
import numpy as np
import networkx as nx
from plotly.subplots import make_subplots

# -------------------------------
# Page configuration
st.set_page_config(page_title="OT Cybersecurity Dashboard", layout="wide")

# -------------------------------
# Custom CSS for Deloitte dark theme with vibrant accents
st.markdown(
    """
    <style>
        /* Main background */
        .stApp {
            background-color: #0e1117;
            color: #e5e5e5;
        }
        /* Sidebar */
        .css-1d391kg, .css-163ttbj, .css-1avcm0n {
            background-color: #1e1e2f;
        }
        /* Metric cards */
        .stMetric {
            background-color: #2c2c3a;
            border-radius: 10px;
            padding: 10px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.2);
            border-left: 4px solid #00a1ab;
        }
        /* Buttons */
        .stButton button {
            background-color: #00a1ab;
            color: white;
            border: none;
            border-radius: 5px;
            transition: 0.2s;
        }
        .stButton button:hover {
            background-color: #00838f;
        }
        /* Headers */
        h1, h2, h3, h4, h5, h6 {
            color: #ffffff;
        }
        /* Expander */
        .streamlit-expanderHeader {
            background-color: #2c2c3a;
            color: #ffffff;
        }
        /* Dataframe tables */
        .dataframe {
            background-color: #2c2c3a;
            color: #e5e5e5;
        }
        /* Success and info messages */
        .stAlert {
            background-color: #2c2c3a;
            color: #e5e5e5;
        }
        /* Sidebar expander */
        .css-1aumxhk {
            background-color: #2c2c3a;
        }
        /* Tabs */
        .stTabs [data-baseweb="tab-list"] {
            gap: 24px;
        }
        .stTabs [data-baseweb="tab"] {
            background-color: #1e1e2f;
            border-radius: 5px 5px 0 0;
            padding: 10px 20px;
            font-weight: bold;
        }
        .stTabs [aria-selected="true"] {
            background-color: #00a1ab;
            color: white;
        }
    </style>
    """,
    unsafe_allow_html=True
)

# -------------------------------
# Helper functions for database (unchanged, but added derive_ip_type)
def init_db():
    conn = sqlite3.connect('ot_cyber.db')
    c = conn.cursor()
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
                  os TEXT,
                  ip_type TEXT,
                  created_at TIMESTAMP)''')
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
    c.execute('''CREATE TABLE IF NOT EXISTS advisory
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  cve_number TEXT UNIQUE,
                  ics_cert_advisory_title TEXT,
                  cwe_number TEXT,
                  critical_infrastructure_sector TEXT,
                  created_at TIMESTAMP)''')
    conn.commit()
    conn.close()

def clear_all_data():
    conn = sqlite3.connect('ot_cyber.db')
    c = conn.cursor()
    c.execute("DELETE FROM assets")
    c.execute("DELETE FROM vulnerabilities")
    c.execute("DELETE FROM advisory")
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
               protocol, ip_address, mac_address, location, serial_number, last_seen,
               other_properties, os='', ip_type=''):
    conn = sqlite3.connect('ot_cyber.db')
    c = conn.cursor()
    c.execute("""INSERT INTO assets 
                 (site, asset_type, vendor, firmware, network_zone, criticality,
                  protocol, ip_address, mac_address, location, serial_number, last_seen,
                  other_properties, os, ip_type, created_at)
                 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
              (site, asset_type, vendor, firmware, network_zone, criticality,
               protocol, ip_address, mac_address, location, serial_number, last_seen,
               other_properties, os, ip_type, datetime.now()))
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
    if assets.empty or vulns.empty:
        return 0
    criticality_weights = {'Low': 1, 'Medium': 2, 'High': 3, 'Critical': 4}
    assets['weight'] = assets['criticality'].map(criticality_weights).fillna(1)
    merged = pd.merge(vulns, assets, left_on='asset_id', right_on='id', how='inner')
    if merged.empty:
        return 0
    merged['risk'] = merged['cvss_score'] * merged['weight']
    return merged['risk'].sum()

def derive_ip_type(ip):
    if pd.isna(ip) or ip == '':
        return 'Unknown'
    ip = str(ip)
    if ':' in ip:
        return 'IPv6'
    else:
        return 'IPv4'

# Initialize database
init_db()

# -------------------------------
# Sidebar navigation
st.sidebar.title("Navigation")
page = st.sidebar.radio("Go to", ["Dashboard", "Assets Management", "Vulnerabilities Management", "Advisory Data", "Import Data", "Export Data"])

# -----------------------------------------------------------------------------
# DASHBOARD PAGE (with multiple tabs)
# -----------------------------------------------------------------------------
if page == "Dashboard":
    # Deloitte header
    col_logo, col_title = st.columns([1, 3])
    with col_logo:
        st.image("https://upload.wikimedia.org/wikipedia/commons/thumb/5/5c/Deloitte.svg/1200px-Deloitte.svg.png", width=80)
    with col_title:
        st.markdown(
            """
            <div style="background-color: #0e1117; padding: 10px;">
            <h1 style="color: #ffffff; margin:0;">OT Cybersecurity Risk Assessment Dashboard</h1>
            <p style="color: #cccccc;">Powered by Deloitte – Advanced Risk Analytics</p>
            </div>
            """,
            unsafe_allow_html=True
        )
    st.markdown("---")

    st.markdown("Upload your data files to populate the dashboard.")

    # File uploaders (advisory optional)
    col1, col2, col3 = st.columns(3)
    with col1:
        vuln_file = st.file_uploader("📁 Vulnerability File (CSV/Excel)", type=["csv", "xlsx"], key="dashboard_vuln")
    with col2:
        asset_file = st.file_uploader("🏭 Asset File (CSV/Excel)", type=["csv", "xlsx"], key="dashboard_asset")
    with col3:
        advisory_file = st.file_uploader("📄 Advisory File (CSV/Excel) - Optional", type=["csv", "xlsx"], key="dashboard_advisory")

    # Load files into database (only require asset and vulnerability)
    if vuln_file and asset_file:
        if st.button("Load Files into Database (replaces existing data)"):
            with st.spinner("Loading and importing data..."):
                clear_all_data()

                def load_file(file):
                    if file.name.endswith('.csv'):
                        return pd.read_csv(file)
                    else:
                        return pd.read_excel(file)

                # Load assets
                asset_df = load_file(asset_file)
                asset_df.columns = asset_df.columns.str.strip().str.lower()
                required_asset = ['asset_id', 'asset_type', 'criticality', 'network_zone', 'site', 'vendor', 'protocol']
                for col in required_asset:
                    if col not in asset_df.columns:
                        st.error(f"Asset file missing required column: {col}")
                        st.stop()
                for _, row in asset_df.iterrows():
                    ip_address = row.get('ip_address', '')
                    if 'ip_type' in row and pd.notna(row['ip_type']) and row['ip_type'] != '':
                        ip_type = row['ip_type']
                    else:
                        ip_type = derive_ip_type(ip_address)
                    save_asset(
                        site=row.get('site', ''),
                        asset_type=row.get('asset_type', ''),
                        vendor=row.get('vendor', ''),
                        firmware=row.get('firmware', ''),
                        network_zone=row.get('network_zone', ''),
                        criticality=row.get('criticality', 'Medium'),
                        protocol=row.get('protocol', ''),
                        ip_address=ip_address,
                        mac_address=row.get('mac_address', ''),
                        location=row.get('location', ''),
                        serial_number=row.get('serial_number', ''),
                        last_seen=row.get('last_seen', datetime.now().strftime("%Y-%m-%d")),
                        other_properties=row.get('other_properties', ''),
                        os=row.get('os', ''),
                        ip_type=ip_type
                    )

                # Load vulnerabilities
                vuln_df = load_file(vuln_file)
                vuln_df.columns = vuln_df.columns.str.strip().str.lower()
                required_vuln = ['asset_id', 'cve_id', 'cvss_score', 'exploitability', 'patch_availability', 'severity']
                for col in required_vuln:
                    if col not in vuln_df.columns:
                        st.error(f"Vulnerability file missing required column: {col}")
                        st.stop()
                vuln_df['cvss_score'] = pd.to_numeric(vuln_df['cvss_score'], errors='coerce')
                vuln_df.dropna(subset=['cvss_score'], inplace=True)
                for _, row in vuln_df.iterrows():
                    save_vulnerability(
                        asset_id=int(row['asset_id']),
                        cve_id=row['cve_id'],
                        cvss_score=float(row['cvss_score']),
                        exploitability=row.get('exploitability', ''),
                        patch_availability=row.get('patch_availability', ''),
                        severity=row.get('severity', ''),
                        hostname=row.get('hostname', ''),
                        port=row.get('port', None),
                        protocol=row.get('protocol', ''),
                        plugin_name=row.get('plugin_name', ''),
                        vulnerability_title=row.get('vulnerability_title', '')
                    )

                # Load advisory if provided
                if advisory_file is not None:
                    adv_df = load_file(advisory_file)
                    adv_df.columns = adv_df.columns.str.strip().str.lower()
                    if 'cve_number' in adv_df.columns:
                        for _, row in adv_df.iterrows():
                            save_advisory(
                                cve_number=row['cve_number'],
                                title=row.get('ics-cert_advisory_title', ''),
                                cwe=row.get('cwe_number', ''),
                                sector=row.get('critical_infrastructure_sector', '')
                            )
                    else:
                        st.warning("Advisory file missing 'cve_number' column – skipping advisory import.")

                st.success("Data imported successfully! The dashboard and management pages now show the uploaded data.")
                st.rerun()
    else:
        st.info("Please upload at least the Asset and Vulnerability files and click 'Load Files' to populate the dashboard.")

    # Load data from database
    assets_df = load_assets()
    vuln_df = load_vulnerabilities()
    advisory_df = load_advisory()

    if assets_df.empty or vuln_df.empty:
        st.warning("No data in the database. Please upload the required files above.")
        st.stop()

    # Enrich vulnerabilities with advisory data (if available)
    if not advisory_df.empty:
        advisory_map = advisory_df.set_index('cve_number').to_dict('index')
        def enrich_vuln(row):
            cve = row['cve_id']
            if cve in advisory_map:
                row['advisory_title'] = advisory_map[cve].get('ics_cert_advisory_title', '')
                row['cwe'] = advisory_map[cve].get('cwe_number', '')
                row['infra_sector'] = advisory_map[cve].get('critical_infrastructure_sector', '')
            else:
                row['advisory_title'] = ''
                row['cwe'] = ''
                row['infra_sector'] = ''
            return row
        vuln_df = vuln_df.apply(enrich_vuln, axis=1)
    else:
        vuln_df['advisory_title'] = ''
        vuln_df['cwe'] = ''
        vuln_df['infra_sector'] = ''

    # Merge vulnerabilities with assets
    merged_df = pd.merge(vuln_df, assets_df, left_on='asset_id', right_on='id', how='left')
    for col in ['asset_type', 'criticality', 'network_zone']:
        if col not in merged_df.columns:
            merged_df[col] = 'Unknown'
        else:
            merged_df[col] = merged_df[col].fillna('Unknown')

    # Compute risk score
    crit_map = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
    merged_df['criticality'] = merged_df['criticality'].astype(str).str.lower().fillna('unknown')
    merged_df['criticality_factor'] = merged_df['criticality'].map(crit_map).fillna(1)
    merged_df['risk_score'] = merged_df['cvss_score'] * merged_df['criticality_factor']
    merged_df['criticality_factor'] = pd.to_numeric(merged_df['criticality_factor'], errors='coerce').fillna(1)
    merged_df['risk_score'] = pd.to_numeric(merged_df['risk_score'], errors='coerce').fillna(0)

    # Branding info (Data Source, Captured Date, Site Name)
    st.markdown(
        f"""
        <div style="background-color:#1e1e2f; padding:10px; border-radius:5px; margin-bottom:20px;">
        <b>Data Source:</b> Asset & Vulnerability Files (Advisory optional)<br>
        <b>Captured Date:</b> {datetime.now().strftime("%Y-%m-%d %H:%M")}<br>
        <b>Site Name:</b> {assets_df['site'].iloc[0] if not assets_df.empty else 'N/A'}
        </div>
        """,
        unsafe_allow_html=True
    )

    # -------------------------------------------------------------------------
    # TABS: Overview, Asset Analytics, Vulnerability Analytics, Network Map
    # -------------------------------------------------------------------------
    tab1, tab2, tab3, tab4 = st.tabs(["📊 Overview", "🏭 Asset Analytics", "🛡️ Vulnerability Analytics", "🌐 Network Map"])

    # ---------------------- TAB 1: OVERVIEW ----------------------
    with tab1:
        # Row 1: KPIs
        col1, col2, col3, col4, col5 = st.columns(5)
        with col1:
            st.metric("Total Assets", len(assets_df))
        with col2:
            st.metric("Total Vulnerabilities", len(vuln_df))
        with col3:
            st.metric("Unique CVEs", vuln_df['cve_id'].nunique())
        with col4:
            st.metric("Avg CVSS Score", f"{vuln_df['cvss_score'].mean():.2f}")
        with col5:
            st.metric("Total Risk Score", f"{calculate_risk_score(assets_df, vuln_df):.0f}")

        # Row 2: Asset criticality pie + Vulnerability severity pie
        col1, col2 = st.columns(2)
        with col1:
            st.subheader("Asset Criticality")
            crit_counts = assets_df['criticality'].value_counts().reset_index()
            crit_counts.columns = ['Criticality', 'Count']
            fig_crit = px.pie(crit_counts, values='Count', names='Criticality', hole=0.3,
                              color_discrete_sequence=px.colors.sequential.RdBu)
            st.plotly_chart(fig_crit, use_container_width=True)
        with col2:
            st.subheader("Vulnerability Severity")
            sev_counts = vuln_df['severity'].value_counts().reset_index()
            sev_counts.columns = ['Severity', 'Count']
            fig_sev = px.pie(sev_counts, values='Count', names='Severity', hole=0.3,
                             color_discrete_sequence=px.colors.sequential.Plasma)
            st.plotly_chart(fig_sev, use_container_width=True)

        # Row 3: Top 10 CVEs by risk score (horizontal bar)
        st.subheader("Top 10 CVEs by Risk Score")
        top_cves = merged_df.groupby('cve_id')['risk_score'].max().sort_values(ascending=False).head(10).reset_index()
        fig_top = px.bar(top_cves, x='risk_score', y='cve_id', orientation='h',
                         title="Highest Risk CVEs", color='risk_score',
                         color_continuous_scale='Reds')
        st.plotly_chart(fig_top, use_container_width=True)

        # Row 4: Network zone risk (bar)
        st.subheader("Average Risk Score by Network Zone")
        zone_risk = merged_df.groupby('network_zone')['risk_score'].mean().reset_index()
        if not zone_risk.empty:
            fig_zone = px.bar(zone_risk, x='network_zone', y='risk_score',
                              title="Average Risk per Zone", color='risk_score',
                              color_continuous_scale='Viridis')
            st.plotly_chart(fig_zone, use_container_width=True)

        # Row 5: Asset type vs vulnerability count (heatmap)
        st.subheader("Vulnerability Count by Asset Type and Criticality")
        if not merged_df.empty:
            heat_data = merged_df.groupby(['asset_type', 'criticality']).size().reset_index(name='count')
            pivot = heat_data.pivot(index='asset_type', columns='criticality', values='count').fillna(0)
            fig_heat = px.imshow(pivot, text_auto=True, aspect="auto",
                                 title="Vulnerabilities per Asset Type & Criticality",
                                 color_continuous_scale="Blues")
            st.plotly_chart(fig_heat, use_container_width=True)

        # Row 6: Timeline (if date column present)
        if 'created_at' in vuln_df.columns:
            st.subheader("Vulnerability Trend Over Time")
            vuln_df['date'] = pd.to_datetime(vuln_df['created_at']).dt.date
            timeline = vuln_df.groupby('date').size().reset_index(name='count')
            fig_timeline = px.line(timeline, x='date', y='count', markers=True,
                                   title="Vulnerabilities Added Over Time")
            st.plotly_chart(fig_timeline, use_container_width=True)

    # ---------------------- TAB 2: ASSET ANALYTICS ----------------------
    with tab2:
        st.header("Asset Analytics")
        # Filters
        col1, col2, col3 = st.columns(3)
        with col1:
            asset_types = assets_df['asset_type'].unique()
            selected_types = st.multiselect("Asset Type", asset_types, default=asset_types)
        with col2:
            vendors = assets_df['vendor'].unique()
            selected_vendors = st.multiselect("Vendor", vendors, default=vendors)
        with col3:
            criticalities = assets_df['criticality'].unique()
            selected_criticalities = st.multiselect("Criticality", criticalities, default=criticalities)

        filtered_assets = assets_df[
            assets_df['asset_type'].isin(selected_types) &
            assets_df['vendor'].isin(selected_vendors) &
            assets_df['criticality'].isin(selected_criticalities)
        ]

        # KPI row
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Filtered Assets", len(filtered_assets))
        with col2:
            st.metric("Unique Vendors", filtered_assets['vendor'].nunique())
        with col3:
            st.metric("Unique Protocols", filtered_assets['protocol'].nunique())
        with col4:
            st.metric("Unique OS", filtered_assets['os'].nunique() if 'os' in filtered_assets else 0)

        # Row 1: Asset type distribution, Vendor distribution, Protocol distribution
        col1, col2, col3 = st.columns(3)
        with col1:
            st.subheader("Asset Types")
            fig = px.bar(filtered_assets['asset_type'].value_counts().reset_index(),
                         x='asset_type', y='count', title="Asset Type Distribution",
                         color='count', color_continuous_scale='Teal')
            st.plotly_chart(fig, use_container_width=True)
        with col2:
            st.subheader("Top Vendors")
            top_vendors = filtered_assets['vendor'].value_counts().head(10).reset_index()
            fig = px.bar(top_vendors, x='vendor', y='count', title="Top 10 Vendors",
                         color='count', color_continuous_scale='Viridis')
            fig.update_xaxes(tickangle=45)
            st.plotly_chart(fig, use_container_width=True)
        with col3:
            st.subheader("Communication Protocols")
            fig = px.bar(filtered_assets['protocol'].value_counts().reset_index(),
                         x='protocol', y='count', title="Protocols Used",
                         color='count', color_continuous_scale='Plasma')
            fig.update_xaxes(tickangle=45)
            st.plotly_chart(fig, use_container_width=True)

        # Row 2: OS distribution (if exists) and IP type distribution
        col1, col2 = st.columns(2)
        with col1:
            st.subheader("Operating Systems")
            if 'os' in filtered_assets and not filtered_assets['os'].isna().all():
                os_counts = filtered_assets['os'].value_counts().reset_index()
                fig = px.pie(os_counts, values='count', names='os', hole=0.3,
                             title="OS Distribution", color_discrete_sequence=px.colors.qualitative.Set3)
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("No OS data available")
        with col2:
            st.subheader("IP Type Distribution")
            if 'ip_type' in filtered_assets and not filtered_assets['ip_type'].isna().all():
                ip_counts = filtered_assets['ip_type'].value_counts().reset_index()
                fig = px.bar(ip_counts, x='ip_type', y='count', title="IP Types",
                             color='count', color_continuous_scale='Mint')
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("No IP type data available")

        # Row 3: Asset table with details
        st.subheader("Asset Details")
        st.dataframe(filtered_assets, use_container_width=True)

        # Row 4: Risk heatmap per asset type and criticality (using vulnerabilities)
        if not merged_df.empty:
            st.subheader("Risk Heatmap (Asset Type vs Criticality)")
            risk_heat = merged_df.groupby(['asset_type', 'criticality'])['risk_score'].mean().reset_index()
            pivot_risk = risk_heat.pivot(index='asset_type', columns='criticality', values='risk_score').fillna(0)
            fig_risk = px.imshow(pivot_risk, text_auto=True, aspect="auto",
                                 title="Average Risk Score by Asset Type & Criticality",
                                 color_continuous_scale="Reds")
            st.plotly_chart(fig_risk, use_container_width=True)

    # ---------------------- TAB 3: VULNERABILITY ANALYTICS ----------------------
    with tab3:
        st.header("Vulnerability Analytics")
        # Filters
        col1, col2, col3 = st.columns(3)
        with col1:
            severities = vuln_df['severity'].unique()
            selected_sev = st.multiselect("Severity", severities, default=severities)
        with col2:
            exploit = vuln_df['exploitability'].unique()
            selected_exp = st.multiselect("Exploitability", exploit, default=exploit)
        with col3:
            patch = vuln_df['patch_availability'].unique()
            selected_patch = st.multiselect("Patch Availability", patch, default=patch)

        filtered_vulns = vuln_df[
            vuln_df['severity'].isin(selected_sev) &
            vuln_df['exploitability'].isin(selected_exp) &
            vuln_df['patch_availability'].isin(selected_patch)
        ]

        # KPI row
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Filtered Vulnerabilities", len(filtered_vulns))
        with col2:
            st.metric("Avg CVSS Score", f"{filtered_vulns['cvss_score'].mean():.2f}")
        with col3:
            st.metric("Unique CVEs", filtered_vulns['cve_id'].nunique())

        # Row 1: CVSS distribution, Exploitability pie, Patch availability pie
        col1, col2, col3 = st.columns(3)
        with col1:
            st.subheader("CVSS Score Distribution")
            fig = px.histogram(filtered_vulns, x='cvss_score', nbins=20,
                               title="CVSS Distribution", color_discrete_sequence=['#FF6B6B'])
            st.plotly_chart(fig, use_container_width=True)
        with col2:
            st.subheader("Exploitability")
            exp_counts = filtered_vulns['exploitability'].value_counts().reset_index()
            fig = px.pie(exp_counts, values='count', names='exploitability', hole=0.3,
                         title="Exploitability Levels", color_discrete_sequence=px.colors.sequential.Viridis)
            st.plotly_chart(fig, use_container_width=True)
        with col3:
            st.subheader("Patch Availability")
            patch_counts = filtered_vulns['patch_availability'].value_counts().reset_index()
            fig = px.pie(patch_counts, values='count', names='patch_availability', hole=0.3,
                         title="Patch Status", color_discrete_sequence=px.colors.sequential.Plasma)
            st.plotly_chart(fig, use_container_width=True)

        # Row 2: Top CVEs by asset count, top CVEs by risk score
        col1, col2 = st.columns(2)
        with col1:
            st.subheader("Top CVEs by Affected Assets")
            cve_asset_count = filtered_vulns.groupby('cve_id')['asset_id'].nunique().sort_values(ascending=False).head(10).reset_index()
            cve_asset_count.columns = ['CVE', 'Asset Count']
            fig = px.bar(cve_asset_count, x='CVE', y='Asset Count', title="Most Widespread CVEs",
                         color='Asset Count', color_continuous_scale='Sunset')
            fig.update_xaxes(tickangle=45)
            st.plotly_chart(fig, use_container_width=True)
        with col2:
            st.subheader("Top CVEs by Risk Score")
            cve_risk = filtered_vulns.groupby('cve_id')['risk_score'].mean().sort_values(ascending=False).head(10).reset_index()
            cve_risk.columns = ['CVE', 'Avg Risk Score']
            fig = px.bar(cve_risk, x='CVE', y='Avg Risk Score', title="Highest Risk CVEs",
                         color='Avg Risk Score', color_continuous_scale='Reds')
            fig.update_xaxes(tickangle=45)
            st.plotly_chart(fig, use_container_width=True)

        # Row 3: CWE distribution (if available)
        if 'cwe' in filtered_vulns.columns and not filtered_vulns['cwe'].isna().all():
            st.subheader("Top CWEs")
            cwe_counts = filtered_vulns['cwe'].value_counts().head(15).reset_index()
            cwe_counts.columns = ['CWE', 'Count']
            fig = px.bar(cwe_counts, x='CWE', y='Count', title="Most Common CWEs",
                         color='Count', color_continuous_scale='Tealgrn')
            fig.update_xaxes(tickangle=45)
            st.plotly_chart(fig, use_container_width=True)

        # Row 4: Vulnerability details table
        st.subheader("Vulnerability Details")
        st.dataframe(filtered_vulns[['cve_id', 'cvss_score', 'severity', 'exploitability', 'patch_availability', 'asset_id', 'hostname']],
                     use_container_width=True)

    # ---------------------- TAB 4: NETWORK MAP ----------------------
    with tab4:
        st.header("Network Map")
        st.markdown("Drag nodes to rearrange. Use the sidebar to add assets to groups and define VLANs.")

        # Create a list of assets with IP addresses
        assets_with_ip = assets_df[assets_df['ip_address'].notna() & (assets_df['ip_address'] != '')].copy()
        if assets_with_ip.empty:
            st.warning("No assets with IP addresses found. Please upload asset data containing IP addresses.")
        else:
            # Build a graph from IP relationships (simple: connect assets if they share same VLAN)
            # We'll allow user to group assets manually in sidebar, but also auto-group by network zone.
            # Let's create an interactive network graph using Plotly's scatter plot with annotations (nodes)
            # and edges. We'll use networkx to compute positions and then plot.

            # For simplicity, we'll create a graph where each asset is a node, and edges represent "connected" if they are in the same network zone.
            # Users can also add custom connections via a form.

            # Let's load current groups/VLANs from session state
            if 'groups' not in st.session_state:
                st.session_state.groups = {}
            if 'connections' not in st.session_state:
                st.session_state.connections = []  # list of (source, target)

            # Sidebar for grouping and connections
            with st.sidebar.expander("Network Map Controls", expanded=True):
                st.subheader("Group Assets by VLAN")
                # List unique network zones
                zones = assets_with_ip['network_zone'].unique()
                selected_zone = st.selectbox("Select Network Zone to group", zones)
                if st.button(f"Group assets in {selected_zone}"):
                    for _, row in assets_with_ip[assets_with_ip['network_zone'] == selected_zone].iterrows():
                        st.session_state.groups[row['id']] = selected_zone
                    st.success(f"Added {len(assets_with_ip[assets_with_ip['network_zone'] == selected_zone])} assets to group {selected_zone}")
                st.markdown("---")
                st.subheader("Manual Connections")
                asset_names = assets_with_ip.apply(lambda x: f"{x['id']} - {x['asset_type']} ({x['ip_address']})", axis=1).tolist()
                src = st.selectbox("Source Asset", asset_names)
                tgt = st.selectbox("Target Asset", asset_names, index=1 if len(asset_names) > 1 else 0)
                if st.button("Add Connection"):
                    src_id = int(src.split(' - ')[0])
                    tgt_id = int(tgt.split(' - ')[0])
                    if src_id != tgt_id:
                        st.session_state.connections.append((src_id, tgt_id))
                        st.success(f"Connection added between {src_id} and {tgt_id}")
                    else:
                        st.error("Cannot connect an asset to itself")
                if st.button("Clear All Connections"):
                    st.session_state.connections = []
                    st.success("All connections cleared")
                if st.button("Reset All Groups"):
                    st.session_state.groups = {}
                    st.success("All groups cleared")

            # Build graph
            G = nx.Graph()
            for _, row in assets_with_ip.iterrows():
                node_id = row['id']
                label = f"{row['asset_type']}\n{row['ip_address']}"
                group = st.session_state.groups.get(node_id, row['network_zone'])
                G.add_node(node_id, label=label, group=group, criticality=row['criticality'])

            for src, tgt in st.session_state.connections:
                G.add_edge(src, tgt)

            # Also auto-connect assets that share the same network zone (optional)
            # To avoid too many edges, we'll add edges only between assets in the same zone
            for zone in zones:
                zone_assets = assets_with_ip[assets_with_ip['network_zone'] == zone]['id'].tolist()
                for i in range(len(zone_assets)):
                    for j in range(i+1, len(zone_assets)):
                        G.add_edge(zone_assets[i], zone_assets[j])

            # Generate positions (spring layout)
            pos = nx.spring_layout(G, seed=42, k=2, iterations=50)

            # Create Plotly figure
            edge_trace = []
            for edge in G.edges():
                x0, y0 = pos[edge[0]]
                x1, y1 = pos[edge[1]]
                edge_trace.append(go.Scatter(
                    x=[x0, x1, None], y=[y0, y1, None],
                    mode='lines', line=dict(width=1, color='#888'),
                    hoverinfo='none', showlegend=False
                ))

            node_x = []
            node_y = []
            node_text = []
            node_color = []
            for node in G.nodes():
                x, y = pos[node]
                node_x.append(x)
                node_y.append(y)
                node_text.append(G.nodes[node]['label'])
                # Color by criticality
                crit = G.nodes[node]['criticality']
                if crit == 'Critical':
                    node_color.append('#e74c3c')
                elif crit == 'High':
                    node_color.append('#e67e22')
                elif crit == 'Medium':
                    node_color.append('#f1c40f')
                else:
                    node_color.append('#2ecc71')

            node_trace = go.Scatter(
                x=node_x, y=node_y,
                mode='markers+text',
                text=node_text,
                textposition="top center",
                hoverinfo='text',
                marker=dict(size=20, color=node_color, line=dict(width=2, color='white')),
                showlegend=False
            )

            fig = go.Figure(data=edge_trace + [node_trace],
                            layout=go.Layout(
                                title="Network Map (Draggable Nodes)",
                                titlefont_size=16,
                                showlegend=False,
                                hovermode='closest',
                                margin=dict(b=20, l=5, r=5, t=40),
                                xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                                yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                                plot_bgcolor='#1e1e2f',
                                paper_bgcolor='#1e1e2f',
                                font=dict(color='white')
                            ))
            st.plotly_chart(fig, use_container_width=True)

            # Display current groups
            st.subheader("Current Groups (VLANs)")
            groups_df = pd.DataFrame([(k, v) for k, v in st.session_state.groups.items()], columns=['Asset ID', 'Group'])
            if not groups_df.empty:
                st.dataframe(groups_df)
            else:
                st.info("No groups defined yet. Use the sidebar to create VLAN groups.")

# -----------------------------------------------------------------------------
# The remaining pages (Assets Management, Vulnerabilities Management, Advisory Data, Import Data, Export Data) are unchanged.
# They are included below for completeness but not shown here for brevity.
# Please refer to the previous version for their implementation.
# -----------------------------------------------------------------------------
