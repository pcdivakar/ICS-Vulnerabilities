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
# Helper functions for database
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
                  os TEXT,
                  ip_type TEXT,
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
    """Return a simple classification: IPv4 or IPv6. Could be extended."""
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
# DASHBOARD PAGE (File import + enhanced visuals)
# -----------------------------------------------------------------------------
if page == "Dashboard":
    st.title("🔒 OT Cybersecurity Dashboard")
    st.markdown("Upload your data files to populate the dashboard and management pages.")

    # File uploaders
    col1, col2, col3 = st.columns(3)
    with col1:
        vuln_file = st.file_uploader("📁 Vulnerability File (CSV/Excel)", type=["csv", "xlsx"], key="dashboard_vuln")
    with col2:
        asset_file = st.file_uploader("🏭 Asset File (CSV/Excel)", type=["csv", "xlsx"], key="dashboard_asset")
    with col3:
        advisory_file = st.file_uploader("📄 Advisory File (CSV/Excel)", type=["csv", "xlsx"], key="dashboard_advisory")

    # When all files are uploaded, import them into the database
    if vuln_file and asset_file and advisory_file:
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
                    # Determine ip_type: if column exists, use it; else derive
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

                # Load advisory
                adv_df = load_file(advisory_file)
                adv_df.columns = adv_df.columns.str.strip().str.lower()
                if 'cve_number' not in adv_df.columns:
                    st.error("Advisory file missing required column: cve_number")
                    st.stop()
                for _, row in adv_df.iterrows():
                    save_advisory(
                        cve_number=row['cve_number'],
                        title=row.get('ics-cert_advisory_title', ''),
                        cwe=row.get('cwe_number', ''),
                        sector=row.get('critical_infrastructure_sector', '')
                    )

                st.success("Data imported successfully! The dashboard and management pages now show the uploaded data.")
                st.rerun()
    else:
        st.info("Please upload all three files and click 'Load Files' to populate the dashboard.")

    # Load data from database for display (if any)
    assets_df = load_assets()
    vuln_df = load_vulnerabilities()
    advisory_df = load_advisory()

    # If database is empty, show a message and stop
    if assets_df.empty or vuln_df.empty:
        st.warning("No data in the database. Please upload the three files above.")
        st.stop()

    # Merge vulnerabilities with advisory data (CVE mapping)
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

    # -------------------------------------------------------------------------
    # Branding and metric blocks
    # -------------------------------------------------------------------------
    # Header with logo and info (use local logo or URL)
    col_logo, col_info = st.columns([1, 3])
    with col_logo:
        try:
            st.image("logo.png", width=100)   # Place a logo.png in your repo or use a URL
        except:
            st.markdown("**LOGO**")
    with col_info:
        st.markdown(
            """
            <div style="background-color:black; padding:10px; border-radius:5px; color:white;">
            <b>Data Source:</b> Asset, Vulnerability & Advisory Files<br>
            <b>Captured Date:</b> {}<br>
            <b>Site Name:</b> {}<br>
            </div>
            """.format(
                datetime.now().strftime("%Y-%m-%d %H:%M"),
                assets_df['site'].iloc[0] if not assets_df.empty else "N/A"
            ), unsafe_allow_html=True
        )

    st.markdown("---")
    # Metrics (stacked rectangular blocks)
    col1, col2, col3, col4, col5, col6, col7 = st.columns(7)
    with col1:
        ot_assets = assets_df[assets_df['asset_type'].str.lower().str.contains('ot', na=False)].shape[0]
        st.metric("OT Assets", ot_assets)
    with col2:
        it_assets = assets_df[assets_df['asset_type'].str.lower().str.contains('it', na=False)].shape[0]
        st.metric("IT Assets", it_assets)
    with col3:
        iot_assets = assets_df[assets_df['asset_type'].str.lower().str.contains('iot', na=False)].shape[0]
        st.metric("IoT Assets", iot_assets)
    with col4:
        distinct_protocols = assets_df['protocol'].nunique()
        st.metric("Distinct Protocols", distinct_protocols)
    with col5:
        num_vendors = assets_df['vendor'].nunique()
        st.metric("Vendors", num_vendors)
    with col6:
        unique_asset_types = assets_df['asset_type'].nunique()
        st.metric("Unique Asset Types", unique_asset_types)
    with col7:
        non_networking = assets_df[assets_df['ip_address'].isna() | (assets_df['ip_address'] == '')].shape[0]
        st.metric("Non-Networking Assets", non_networking)

    st.markdown("---")

    # -------------------------------------------------------------------------
    # First row of charts: OS pie, IP by protocol bar, criticality pie
    # -------------------------------------------------------------------------
    col1, col2, col3 = st.columns(3)
    with col1:
        st.subheader("OS Distribution")
        if 'os' in assets_df.columns and not assets_df['os'].isna().all():
            os_counts = assets_df['os'].value_counts().reset_index()
            os_counts.columns = ['OS', 'Count']
            fig_os = px.pie(os_counts, values='Count', names='OS', title="Operating Systems", hole=0.3)
            st.plotly_chart(fig_os, use_container_width=True)
        else:
            st.info("No OS data available")

    with col2:
        st.subheader("IP Addresses by Protocol")
        if 'ip_address' in assets_df.columns and 'protocol' in assets_df.columns:
            ip_by_protocol = assets_df.groupby('protocol')['ip_address'].nunique().reset_index()
            ip_by_protocol.columns = ['Protocol', 'Unique IPs']
            fig_prot = px.bar(ip_by_protocol, x='Protocol', y='Unique IPs', title="Unique IPs per Protocol")
            st.plotly_chart(fig_prot, use_container_width=True)
        else:
            st.info("No IP or protocol data available")

    with col3:
        st.subheader("Asset Criticality")
        crit_counts = assets_df['criticality'].value_counts().reset_index()
        crit_counts.columns = ['Criticality', 'Count']
        fig_crit = px.pie(crit_counts, values='Count', names='Criticality', title="Asset Criticality", hole=0.3)
        st.plotly_chart(fig_crit, use_container_width=True)

    # -------------------------------------------------------------------------
    # Second row: IP count by vendor (bar) + IP type horizontal bar
    # -------------------------------------------------------------------------
    col1, col2 = st.columns(2)
    with col1:
        st.subheader("IP Address Count by Vendor")
        if 'vendor' in assets_df.columns and 'ip_address' in assets_df.columns:
            vendor_ip_count = assets_df.groupby('vendor')['ip_address'].nunique().reset_index()
            vendor_ip_count.columns = ['Vendor', 'Unique IPs']
            fig_vendor = px.bar(vendor_ip_count, x='Vendor', y='Unique IPs', 
                                title="Unique IPs per Vendor", color='Unique IPs',
                                color_continuous_scale='Viridis')
            fig_vendor.update_xaxes(tickangle=45)
            st.plotly_chart(fig_vendor, use_container_width=True)
        else:
            st.info("No vendor or IP data")

    with col2:
        st.subheader("IP Addresses by IP Type")
        if 'ip_type' in assets_df.columns and not assets_df['ip_type'].isna().all():
            ip_type_counts = assets_df['ip_type'].value_counts().reset_index()
            ip_type_counts.columns = ['IP Type', 'Count']
            fig_ip_type = px.bar(ip_type_counts, x='IP Type', y='Count', orientation='h', 
                                 title="IP Type Distribution")
            st.plotly_chart(fig_ip_type, use_container_width=True)
        else:
            st.info("No IP type data available")

    # -------------------------------------------------------------------------
    # CVE section
    # -------------------------------------------------------------------------
    st.markdown("---")
    st.header("Vulnerability Insights")

    col1, col2, col3 = st.columns(3)
    with col1:
        total_cves = len(vuln_df['cve_id'].unique())
        st.metric("Total CVEs", total_cves)
    with col2:
        unique_cves = len(vuln_df['cve_id'].unique())
        st.metric("Unique CVEs", unique_cves)
    with col3:
        avg_cvss = vuln_df['cvss_score'].mean()
        st.metric("Average CVSS Score", f"{avg_cvss:.2f}")

    st.subheader("CVE Details")
    cve_details = vuln_df[['cve_id', 'cvss_score', 'severity']].drop_duplicates().sort_values('cvss_score', ascending=False).head(20)
    st.dataframe(cve_details, use_container_width=True)

    st.subheader("CVE Count by Vendor")
    if 'vendor' in merged_df.columns:
        cve_by_vendor = merged_df.groupby('vendor')['cve_id'].nunique().reset_index()
        cve_by_vendor.columns = ['Vendor', 'CVE Count']
        fig_vendor_cve = px.bar(cve_by_vendor, x='Vendor', y='CVE Count', title="CVEs per Vendor", color='CVE Count')
        fig_vendor_cve.update_xaxes(tickangle=45)
        st.plotly_chart(fig_vendor_cve, use_container_width=True)
    else:
        st.info("No vendor data available")

    st.subheader("CVE Criticality")
    def cvss_to_criticality(score):
        if score >= 9.0:
            return 'Critical'
        elif score >= 7.0:
            return 'High'
        elif score >= 4.0:
            return 'Medium'
        else:
            return 'Low'
    vuln_df['cve_criticality'] = vuln_df['cvss_score'].apply(cvss_to_criticality)
    crit_counts_cve = vuln_df['cve_criticality'].value_counts().reset_index()
    crit_counts_cve.columns = ['Criticality', 'Count']
    fig_cve_crit = px.pie(crit_counts_cve, values='Count', names='Criticality', title="CVE Criticality (CVSS based)", hole=0.3)
    st.plotly_chart(fig_cve_crit, use_container_width=True)

    st.subheader("Risk Heatmap (Asset Criticality vs CVE Criticality)")
    if 'criticality' in merged_df.columns and 'cve_criticality' in merged_df.columns:
        heatmap_data = merged_df.groupby(['criticality', 'cve_criticality']).size().reset_index(name='count')
        pivot = heatmap_data.pivot(index='criticality', columns='cve_criticality', values='count').fillna(0)
        fig_heat = px.imshow(pivot, text_auto=True, aspect="auto", title="Number of Vulnerabilities",
                             color_continuous_scale="Reds")
        st.plotly_chart(fig_heat, use_container_width=True)
    else:
        st.info("Insufficient data for risk heatmap")

    st.subheader("CVE Distribution by IP and Severity Range")
    if 'ip_address' in merged_df.columns and 'severity' in merged_df.columns:
        ip_severity = merged_df.groupby(['ip_address', 'severity']).size().reset_index(name='count')
        fig_ip_sev = px.bar(ip_severity, x='ip_address', y='count', color='severity',
                            title="CVE Count per IP by Severity", barmode='group')
        fig_ip_sev.update_xaxes(tickangle=45)
        st.plotly_chart(fig_ip_sev, use_container_width=True)
    else:
        st.info("No IP or severity data available")

    st.subheader("CVE Distribution by IP (Horizontal)")
    if 'ip_address' in merged_df.columns:
        cve_by_ip = merged_df.groupby('ip_address')['cve_id'].nunique().reset_index().sort_values('cve_id', ascending=True)
        cve_by_ip.columns = ['IP Address', 'CVE Count']
        fig_ip_cve = px.bar(cve_by_ip, x='CVE Count', y='IP Address', orientation='h',
                            title="CVE Count per IP", color='CVE Count')
        st.plotly_chart(fig_ip_cve, use_container_width=True)
    else:
        st.info("No IP data available")

    # Download button (optional)
    st.sidebar.markdown("---")
    csv = merged_df.to_csv(index=False).encode('utf-8')
    st.sidebar.download_button("📥 Download Data as CSV", data=csv,
                               file_name="ot_risk_assessment.csv", mime="text/csv")
    st.sidebar.success("Dashboard ready.")

# -----------------------------------------------------------------------------
# ASSETS MANAGEMENT (updated with OS and IP Type fields)
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
                os = st.text_input("Operating System")
            with col2:
                ip_address = st.text_input("IP Address")
                ip_type = st.selectbox("IP Type", ["", "IPv4", "IPv6", "Private", "Public"], help="Optional: select or leave empty to auto‑detect")
                mac_address = st.text_input("MAC Address")
                location = st.text_input("Location")
                serial_number = st.text_input("Serial Number")
                last_seen = st.date_input("Last Seen", value=datetime.now().date())
            other_properties = st.text_area("Other Properties (JSON or text)")
            submitted = st.form_submit_button("Add Asset")
            if submitted:
                if site and asset_type and vendor and protocol:
                    # If ip_type not provided, derive
                    final_ip_type = ip_type if ip_type else derive_ip_type(ip_address)
                    asset_id = save_asset(site, asset_type, vendor, firmware, network_zone, criticality,
                                          protocol, ip_address, mac_address, location, serial_number,
                                          last_seen.strftime("%Y-%m-%d"), other_properties,
                                          os=os, ip_type=final_ip_type)
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
# VULNERABILITIES MANAGEMENT (unchanged)
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
# ADVISORY DATA (unchanged)
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
# IMPORT DATA (updated to include os and ip_type)
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
            "other_properties": ["{\"protocol\": \"Modbus\"}", "{\"protocol\": \"DNP3\"}", "{\"touchscreen\": true}"],
            "os": ["Windows 10", "Linux", "VxWorks"],
            "ip_type": ["IPv4", "IPv4", "IPv4"]
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
# EXPORT DATA (unchanged)
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
