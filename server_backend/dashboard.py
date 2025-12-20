# dashboard.py (Didi's Visualization - Day 4, 7, 8, 10 Logic)
import streamlit as st
import pandas as pd
from datetime import datetime, timedelta
import os
import requests
import time
# Import the Incident model and Session factory from the shared models file
from models import Incident, Session, PingMetrics, TrafficStats, SSHEvent
from alert_manager import AlertManager
from report_generator import ReportGenerator
from sqlalchemy.exc import OperationalError
from sqlalchemy import func
import subprocess
import signal
try:
    import psutil
except ImportError:
    psutil = None
from config_manager import ConfigManager

# Set page configuration for a better layout
st.set_page_config(layout="wide", page_title="Sentinel Security Dashboard")

# --- Day 10: System Status Helper ---
API_BASE_URL = "http://127.0.0.1:5000"

def get_system_status():
    """Day 10: Fetch system status from API."""
    try:
        response = requests.get(f"{API_BASE_URL}/api/status", timeout=2)
        if response.status_code == 200:
            return response.json()
        return None
    except Exception as e:
        return None

# --- Day 8: Severity Ranking System ---
def get_severity_rank(severity):
    """Day 8: Get numeric rank for severity (higher = more critical)."""
    severity_ranks = {
        'Critical': 4,
        'High': 3,
        'Medium': 2,
        'Low': 1
    }
    return severity_ranks.get(severity, 0)

def load_incidents(severity_filter=None, days_filter=None, ip_filter=None, target_filter=None, status_filter='Active'):
    """
    Connects to the database, fetches incidents, and applies filtering logic.
    """
    session = Session()
    # In SQLite, session.bind.url.database returns the path/filename part
    db_file_name = session.bind.url.database 
    
    try:
        # Check if the database file exists before querying
        if not os.path.exists(db_file_name):
            
            # --- CUSTOM WARNING BASED ON FILE STRUCTURE IMAGE ---
            st.error("DATABASE FILE NOT FOUND.")
            st.warning(f"""
                The database file ({db_file_name}) could not be located.
                
                **ACTION REQUIRED:**
                1. **Check 'models.py'**: Ensure the `DATABASE_URL` uses the correct file name: `database.db`.
                2. **Check Path**: If you are running `dashboard.py` from the project root (`IR-System`),
                   your `models.py` should look like this:
                   `DATABASE_URL = "sqlite:///server_backend/database.db"` 
                   
                If the file still isn't found, try changing `DATABASE_URL` to an absolute path for debugging.
            """)
            return pd.DataFrame()

        # Day 8: Support filtering by status (not just Active)
        query = session.query(Incident)
        if status_filter:
            query = query.filter(Incident.status == status_filter)
        
        # Apply severity filter
        if severity_filter and severity_filter != "All":
            query = query.filter(Incident.severity == severity_filter)
            
        # Day 8: Apply IP filter
        if ip_filter and ip_filter.strip():
            query = query.filter(Incident.ip.like(f"%{ip_filter}%"))
        
        # Day 8: Apply Target filter
        if target_filter and target_filter.strip():
            query = query.filter(Incident.target.like(f"%{target_filter}%"))
            
        # Apply date filter (for incidents within the last 'days_filter' days)
        if days_filter and days_filter > 0:
            # Use UTC now for consistency with the database timestamp
            cutoff_date = datetime.utcnow() - timedelta(days=days_filter)
            query = query.filter(Incident.timestamp >= cutoff_date)

        incidents = query.order_by(Incident.timestamp.desc()).all()
        
        # Convert list of SQLAlchemy objects to a Pandas DataFrame
        data = [
            {
                "ID": inc.id,
                "Time (UTC)": inc.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                "Source IP": inc.ip,
                "Type": inc.type,
                "Severity": inc.severity,
                "Severity Rank": get_severity_rank(inc.severity),  # Day 8: Add rank for sorting
                "Rule Triggered": inc.rule,
                "Target": inc.target,
                "Status": inc.status,
                # Threat Intelligence fields
                "Country": inc.geo_country if inc.geo_country else "Unknown",
                "City": inc.geo_city if inc.geo_city else "Unknown",
                "ISP": inc.geo_isp if inc.geo_isp else "Unknown",
                "Risk Level": inc.threat_risk_level if inc.threat_risk_level else "Unknown",
                "Risk Score": inc.threat_risk_score if inc.threat_risk_score else 0,
                # Store raw incident for export
                "_raw": inc
            } for inc in incidents
        ]
        
        df = pd.DataFrame(data)
        
        # Ensure timestamp column is correctly formatted for sorting
        if not df.empty:
            df['Time (UTC)'] = pd.to_datetime(df['Time (UTC)'])
            # Day 8: Sort by severity rank (highest first), then by timestamp
            df = df.sort_values(['Severity Rank', 'Time (UTC)'], ascending=[False, False])
            
        return df

    except OperationalError as e:
        # If we reached here, the file exists but there's a problem (e.g., file lock, schema mismatch)
        st.error(f"Operational Error: Could not connect to or read the database ('{db_file_name}'). Ensure 'app.py' is not holding an exclusive lock and the database schema is correct.")
        return pd.DataFrame()
    except Exception as e:
        st.error(f"An unexpected error occurred during database query: {e}")
        return pd.DataFrame()
    finally:
        session.close()

# --- Day 7: Incident Resolution Helper ---
def resolve_incident_api(incident_id, status="Resolved"):
    """Day 7: Call API to resolve an incident."""
    try:
        response = requests.post(
            f"{API_BASE_URL}/api/incident/{incident_id}/resolve",
            json={"status": status},
            timeout=5
        )
        if response.status_code == 200:
            return True, response.json()
        return False, response.json() if response.text else {"message": "Unknown error"}
    except Exception as e:
        return False, {"message": str(e)}

# --- Day 11: Real-time Monitor Helpers ---

def get_ping_stats(limit=100):
    session = Session()
    try:
        metrics = session.query(PingMetrics).order_by(PingMetrics.timestamp.desc()).limit(limit).all()
        return [
            {
                "Target": m.target_ip,
                "Latency (ms)": m.latency_ms,
                "Status": m.status,
                "Time": m.timestamp
            } for m in metrics
        ]
    except Exception:
        return []
    finally:
        session.close()

def get_traffic_stats(limit=20):
    session = Session()
    try:
        stats = session.query(TrafficStats).order_by(TrafficStats.timestamp.desc()).limit(limit).all()
        return [
            {
                "Time": s.timestamp,
                "PPS In": s.packet_count_in,
                "PPS Out": s.packet_count_out,
                "CPU %": s.cpu_load,
                "DoS Score": s.dos_likelihood_score
            } for s in stats
        ]
    except Exception:
        return []
    finally:
        session.close()

def get_latest_ssh_events(limit=50):
    session = Session()
    try:
        events = session.query(SSHEvent).order_by(SSHEvent.timestamp.desc()).limit(limit).all()
        return [
            {
                "Time": e.timestamp,
                "Source IP": e.source_ip,
                "User": e.username,
                "Type": e.event_type,
                "Port": e.port
            } for e in events
        ]
    except Exception:
        return []
    finally:
        session.close()

def get_latest_incidents(limit=10):
    session = Session()
    try:
        incidents = session.query(Incident).order_by(Incident.timestamp.desc()).limit(limit).all()
        return [
            {
                "Time": i.timestamp,
                "Type": i.type,
                "Severity": i.severity,
                "Target": i.target,
                "IP": i.ip
            } for i in incidents
        ]
    except Exception:
        return []
    finally:
        session.close()




# --- Settings & Simulation Helpers ---

def is_simulation_running():
    """Check if simulate_data_stream.py is running."""
    if not psutil: return False
    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            if proc.info['cmdline'] and 'simulate_data_stream.py' in ' '.join(proc.info['cmdline']):
                return True
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    return False

def start_simulation():
    """Start the simulation script."""
    if is_simulation_running(): return
    cmd = ["python3", "../simulate_data_stream.py"]
    subprocess.Popen(cmd, cwd=os.path.dirname(__file__))

def stop_simulation():
    """Stop the simulation script."""
    if not psutil: return
    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            if proc.info['cmdline'] and 'simulate_data_stream.py' in ' '.join(proc.info['cmdline']):
                proc.terminate()
        except:
            pass

def settings_view():
    st.title("⚙️ System Settings")
    
    config_mgr = ConfigManager()
    current_config = config_mgr.get_all()
    
    # --- Tab 1: Network Configuration ---
    st.subheader("🌐 Network Monitoring Config")
    
    with st.form("network_config"):
        targets = st.text_area(
            "Ping Targets (One IP per line)", 
            value="\n".join(current_config.get('ping_targets', [])),
            height=100
        )
        
        st.markdown("### DoS Thresholds")
        cpu_thresh = st.slider("CPU Alert Threshold (%)", 0, 100, int(current_config.get('dos_thresholds', {}).get('cpu_percent', 80)))
        pps_in_thresh = st.number_input("PPS In Threshold", value=int(current_config.get('dos_thresholds', {}).get('pps_in', 1000)))
        
        if st.form_submit_button("Save Configuration"):
            new_targets = [t.strip() for t in targets.split('\n') if t.strip()]
            new_thresholds = current_config.get('dos_thresholds', {})
            new_thresholds['cpu_percent'] = cpu_thresh
            new_thresholds['pps_in'] = pps_in_thresh
            
            config_mgr.set('ping_targets', new_targets)
            config_mgr.set('dos_thresholds', new_thresholds)
            
            st.success("✅ Configuration saved! (Restart detection agent to apply changes)")

    # --- Tab 2: System Alerts ---
    st.markdown("---")
    st.subheader("🔔 System Alerts")
    st.info("System alerts are active. High severity incidents will trigger Desktop Notifications.")

    if st.button("🔔 Test Desktop Alert"):
        alert_mgr = AlertManager()
        success, msg = alert_mgr.send_test_email() # Reused method name, now does local only
        st.success(msg)

    # --- Tab 3: Alert Logs ---
    st.markdown("### 📜 Local Alert Log")
    st.caption("History of triggered alerts.")
    
    log_path = os.path.join(os.path.dirname(__file__), 'alerts.log')
    if os.path.exists(log_path):
        with open(log_path, 'r') as f:
            logs = f.readlines()
            if logs:
                st.code("".join(logs[-20:])) # Show last 20 lines
                if st.button("Clear Logs"):
                    open(log_path, 'w').close()
                    st.rerun()
            else:
                st.info("Log file is empty.")
    else:
        st.info("No local alert logs found.")

    # --- Tab 4: Automation Control ---
    st.markdown("---")
    st.subheader("🤖 Automation Policies")
    st.caption("Configure automated response actions per severity level")
    
    automation_config = current_config.get('automation_policies', {})
    
    # Global automation toggle
    col_auto1, col_auto2 = st.columns([1, 3])
    with col_auto1:
        automation_enabled = st.toggle(
            "Enable Automation",
            value=automation_config.get('enabled', True),
            help="Master switch for all automated containment actions"
        )
    
    with col_auto2:
        if automation_enabled:
            st.success("✅ Automation is ACTIVE - Actions will be taken automatically")
        else:
            st.warning("⚠️ Automation is DISABLED - Incidents will only be logged")
    
    # Per-severity configuration
    if automation_enabled:
        st.markdown("### Action Configuration by Severity")
        
        actions_config = automation_config.get('actions', {})
        
        # Create tabs for each severity
        sev_tabs = st.tabs(["🔴 Critical", "🟠 High", "🟡 Medium", "🟢 Low"])
        
        updated_actions = {}
        
        for idx, (severity, tab) in enumerate(zip(['Critical', 'High', 'Medium', 'Low'], sev_tabs)):
            with tab:
                severity_actions = actions_config.get(severity, {})
                
                col1, col2 = st.columns(2)
                
                with col1:
                    block_ip = st.checkbox(
                        "🚫 Block IP Address",
                        value=severity_actions.get('block_ip', False),
                        key=f"block_ip_{severity}",
                        help="Automatically block source IP using iptables"
                    )
                    
                    send_email = st.checkbox(
                        "📧 Send Email Alert",
                        value=severity_actions.get('send_email', False),
                        key=f"send_email_{severity}",
                        help="Send email notification to security team"
                    )
                
                with col2:
                    kill_process = st.checkbox(
                        "⚠️ Kill Process",
                        value=severity_actions.get('kill_process', False),
                        key=f"kill_process_{severity}",
                        help="Terminate suspicious process (use with caution)"
                    )
                    
                    send_desktop = st.checkbox(
                        "🔔 Desktop Notification",
                        value=severity_actions.get('send_desktop_alert', True),
                        key=f"send_desktop_{severity}",
                        help="Show desktop notification"
                    )
                
                updated_actions[severity] = {
                    'block_ip': block_ip,
                    'kill_process': kill_process,
                    'send_email': send_email,
                    'send_desktop_alert': send_desktop,
                    'auto_resolve': severity_actions.get('auto_resolve', False)
                }
        
        # Save button
        if st.button("💾 Save Automation Policies", type="primary"):
            new_automation_config = {
                'enabled': automation_enabled,
                'actions': updated_actions
            }
            config_mgr.set('automation_policies', new_automation_config)
            st.success("✅ Automation policies saved! Changes will apply to new incidents.")
            st.rerun()
    
    # Automation Statistics
    st.markdown("### 📊 Automation Statistics")
    
    # Read automation log if it exists
    automation_log_path = os.path.join(os.path.dirname(__file__), 'automation.log')
    if os.path.exists(automation_log_path):
        with open(automation_log_path, 'r') as f:
            log_lines = f.readlines()
        
        # Count actions
        total_actions = len(log_lines)
        successful_actions = sum(1 for line in log_lines if 'SUCCESS' in line)
        failed_actions = sum(1 for line in log_lines if 'FAILED' in line)
        ip_blocks = sum(1 for line in log_lines if 'BLOCK_IP' in line and 'SUCCESS' in line)
        
        stat_col1, stat_col2, stat_col3, stat_col4 = st.columns(4)
        with stat_col1:
            st.metric("Total Actions", total_actions)
        with stat_col2:
            st.metric("Successful", successful_actions)
        with stat_col3:
            st.metric("Failed", failed_actions)
        with stat_col4:
            st.metric("IPs Blocked", ip_blocks)
        
        # Show recent actions
        st.markdown("**Recent Automated Actions:**")
        if log_lines:
            recent_logs = log_lines[-10:]  # Last 10 actions
            st.code("".join(recent_logs), language="log")
            
            if st.button("Clear Automation Log"):
                open(automation_log_path, 'w').close()
                st.rerun()
        else:
            st.info("No automated actions logged yet.")
    else:
        st.info("No automation log found. Actions will be logged when automation is active.")

    # --- Tab 5: Simulation Control ---
    st.markdown("---")
    st.subheader("🧪 Data Simulation Control")
    
    sim_running = is_simulation_running()
    status_icon = "🟢" if sim_running else "🔴"
    status_text = "Running" if sim_running else "Stopped"
    
    st.metric("Simulation Status", f"{status_icon} {status_text}")
    
    col1, col2 = st.columns(2)
    with col1:
        if not sim_running:
            if st.button("▶️ Start Simulation", type="primary"):
                start_simulation()
                time.sleep(1)
                st.rerun()
        else:
            st.button("▶️ Start Simulation", disabled=True)
            
    with col2:
        if sim_running:
            if st.button("⏹️ Stop Simulation"):
                stop_simulation()
                time.sleep(1)
                st.rerun()
        else:
            st.button("⏹️ Stop Simulation", disabled=True)

# --- Main Dashboard LayoutFunctions ---

def main_dashboard_view():
    st.title("Sentinel Incident Response Console 🛡️")
    st.markdown("Real-time view of active security incidents across the network.")

    # --- Day 10: System Status Display ---
    with st.expander("🔍 System Status", expanded=False):
        status_data = get_system_status()
        if status_data:
            col1, col2, col3, col4 = st.columns(4)
            with col1:
                system_status = status_data.get('system', 'unknown')
                status_color = "🟢" if system_status == "operational" else "🟡" if system_status == "degraded" else "🔴"
                st.metric("System Status", f"{status_color} {system_status.title()}")
            
            with col2:
                db_status = status_data.get('components', {}).get('database', {}).get('status', 'unknown')
                st.metric("Database", "🟢 Healthy" if db_status == "healthy" else "🔴 Unhealthy")
            
            with col3:
                stats = status_data.get('statistics', {})
                st.metric("Total Incidents", stats.get('total_incidents', 0))
            
            with col4:
                st.metric("Active Incidents", stats.get('active_incidents', 0))
            
            # Show severity breakdown
            if 'severity_breakdown' in stats:
                st.write("**Severity Breakdown:**")
                severity_cols = st.columns(len(stats['severity_breakdown']))
                for idx, (severity, count) in enumerate(stats['severity_breakdown'].items()):
                    with severity_cols[idx]:
                        st.metric(severity, count)
        else:
            st.warning("⚠️ Could not fetch system status. Ensure Flask API is running.")
    
    # Use st.container to group UI elements and prevent layout shifts
    with st.container():
        col1, col2, col3, col4, col5 = st.columns([1, 1, 1, 1, 2])
        
        with col1:
            # Severity Filter
            severity_options = ["All", "Critical", "High", "Medium", "Low"]
            selected_severity = st.selectbox("Filter by Severity", severity_options)
    
        with col2:
            # Day 8: Source IP Filter
            ip_filter = st.text_input("Filter by Source IP", placeholder="e.g., 192.168.1")
    
        with col3:
            # Day 8: Target Filter
            target_filter = st.text_input("Filter by Target", placeholder="e.g., user_john")
    
        with col4:
            # Date Filter (Days)
            date_options = {
                "All Time": 0,
                "Last 24 Hours": 1,
                "Last 7 Days": 7,
                "Last 30 Days": 30
            }
            selected_date_label = st.selectbox("Filter by Timeframe", list(date_options.keys()))
            selected_days = date_options[selected_date_label]
    
        with col5:
            # Status filter (Day 7: Allow viewing resolved incidents)
            status_options = ["Active", "Resolved", "Closed", "All"]
            selected_status = st.selectbox("Filter by Status", status_options, index=0)
            # Refresh button
            if st.button("🔄 Refresh", key="refresh_button", help="Click to force a database refresh."):
                st.cache_data.clear()
                st.rerun()
            
    # --- Data Loading and Display ---
    
    # Use Streamlit's cache_data decorator for fast reloading, with a 5-second TTL
    @st.cache_data(ttl=5)
    def get_live_data(severity, days, ip_filter, target_filter, status_filter):
        return load_incidents(severity, days, ip_filter, target_filter, status_filter)
    
    # Fetch data using the cached function and filters
    status_filter_value = selected_status if selected_status != "All" else None
    incident_df = get_live_data(selected_severity, selected_days, ip_filter, target_filter, status_filter_value)
    
    # Display the main table
    st.subheader(f"{selected_status if selected_status != 'All' else 'All'} Incidents")
    
    if incident_df.empty:
        st.info("No incidents found matching the current filters.")
    else:
        # Day 8: Display metrics row
        metric_col1, metric_col2, metric_col3, metric_col4 = st.columns(4)
        with metric_col1:
            st.metric(label="Total Incidents", value=len(incident_df))
        with metric_col2:
            critical_count = len(incident_df[incident_df['Severity'] == 'Critical'])
            st.metric(label="Critical", value=critical_count)
        with metric_col3:
            high_count = len(incident_df[incident_df['Severity'] == 'High'])
            st.metric(label="High", value=high_count)
        with metric_col4:
            unique_ips = incident_df['Source IP'].nunique()
            st.metric(label="Unique IPs", value=unique_ips)
        
        # Export buttons
        st.markdown("---")
        export_col1, export_col2, export_col3 = st.columns([1, 1, 2])
        
        with export_col1:
            # CSV Export
            csv_data = incident_df.drop(columns=['_raw', 'Severity Rank'], errors='ignore').to_csv(index=False)
            st.download_button(
                label="📄 Export to CSV",
                data=csv_data,
                file_name=f"incidents_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv",
                help="Download incidents as CSV file"
            )
        
        with export_col2:
            # JSON Export
            import json
            json_data = incident_df.drop(columns=['_raw', 'Severity Rank'], errors='ignore').to_dict(orient='records')
            st.download_button(
                label="📋 Export to JSON",
                data=json.dumps(json_data, indent=2, default=str),
                file_name=f"incidents_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                mime="application/json",
                help="Download incidents as JSON file"
            )
        
        with export_col3:
            # Geographic summary
            if 'Country' in incident_df.columns:
                country_counts = incident_df[incident_df['Country'] != 'Unknown']['Country'].value_counts().head(5)
                if len(country_counts) > 0:
                    countries_str = ", ".join([f"{country} ({count})" for country, count in country_counts.items()])
                    st.info(f"🌍 **Top Origins:** {countries_str}")
        
        st.markdown("---")
        
        # Day 8: Charts Section
        chart_tab1, chart_tab2, chart_tab3 = st.tabs(["📊 By Target", "📈 By Severity", "🌐 By IP"])
        
        with chart_tab1:
            if not incident_df.empty and 'Target' in incident_df.columns:
                target_counts = incident_df['Target'].value_counts()
                st.bar_chart(target_counts)
                st.caption("Incidents by Target")
        
        with chart_tab2:
            if not incident_df.empty:
                severity_counts = incident_df['Severity'].value_counts()
                st.bar_chart(severity_counts)
                st.caption("Incidents by Severity")
        
        with chart_tab3:
            if not incident_df.empty:
                ip_counts = incident_df['Source IP'].value_counts().head(10)
                st.bar_chart(ip_counts)
                st.caption("Top 10 Source IPs by Incident Count")
        
        # Display the main table (hide Severity Rank and _raw columns)
        display_df = incident_df.drop(columns=['Severity Rank', '_raw'], errors='ignore')
        
        st.dataframe(
            display_df,
            width='stretch',
            hide_index=True,
            column_order=("ID", "Source IP", "Country", "City", "Type", "Severity", "Risk Level", "Time (UTC)", "Target", "Rule Triggered", "Status"),
            column_config={
                "Severity": st.column_config.TextColumn(
                    "Severity",
                    help="Incident impact level (Critical, High, Medium, Low)",
                    width="small"
                ),
                "Risk Level": st.column_config.TextColumn(
                    "Risk Level",
                    help="Threat intelligence risk assessment",
                    width="small"
                ),
                "Country": st.column_config.TextColumn(
                    "Country",
                    help="Geographic origin of the attack",
                    width="medium"
                ),
                "Time (UTC)": st.column_config.DatetimeColumn(
                    "Time (UTC)",
                    format="YYYY/MM/DD hh:mm:ss"
                )
            }
        )
        
        # Day 7: Incident Resolution Interface
        if selected_status == "Active" or selected_status == "All":
            st.subheader("🔧 Incident Management")
            selected_incident_for_action = st.selectbox(
                "Select Incident ID to Resolve/Triage",
                incident_df['ID'].tolist(),
                key="resolve_select"
            )
            
            action_col1, action_col2, action_col3 = st.columns(3)
            with action_col1:
                if st.button("✅ Resolve", key="resolve_btn", type="primary"):
                    success, result = resolve_incident_api(selected_incident_for_action, "Resolved")
                    if success:
                        st.success(f"✅ Incident {selected_incident_for_action} resolved successfully!")
                        st.cache_data.clear()
                        st.rerun()
                    else:
                        st.error(f"❌ Failed to resolve incident: {result.get('message', 'Unknown error')}")
            
            with action_col2:
                if st.button("🔒 Close", key="close_btn"):
                    success, result = resolve_incident_api(selected_incident_for_action, "Closed")
                    if success:
                        st.success(f"✅ Incident {selected_incident_for_action} closed successfully!")
                        st.cache_data.clear()
                        st.rerun()
                    else:
                        st.error(f"❌ Failed to close incident: {result.get('message', 'Unknown error')}")
            
            with action_col3:
                if st.button("🔄 Re-activate", key="reactivate_btn"):
                    success, result = resolve_incident_api(selected_incident_for_action, "Active")
                    if success:
                        st.success(f"✅ Incident {selected_incident_for_action} re-activated successfully!")
                        st.cache_data.clear()
                        st.rerun()
                    else:
                        st.error(f"❌ Failed to re-activate incident: {result.get('message', 'Unknown error')}")
    
    # Add a section for detailed incident logs
    if not incident_df.empty and st.toggle("Show Raw Log Details"):
        selected_incident_id = st.selectbox(
            "Select Incident ID for Log Details",
            incident_df['ID'].tolist()
        )
        
        if selected_incident_id:
            session = Session()
            try:
                raw_incident = session.query(Incident).filter(Incident.id == selected_incident_id).first()
                if raw_incident:
                    # Display incident details as a dictionary with all fields
                    details = {
                        "id": raw_incident.id,
                        "ip": raw_incident.ip,
                        "type": raw_incident.type,
                        "severity": raw_incident.severity,
                        "timestamp": str(raw_incident.timestamp),
                        "rule": raw_incident.rule,
                        "source_log": raw_incident.source_log,
                        "target": raw_incident.target,
                        "status": raw_incident.status,
                    }
                    
                    # Add extended fields if available
                    if raw_incident.target_ip:
                        details["target_ip"] = raw_incident.target_ip
                    if raw_incident.outcome:
                        details["outcome"] = raw_incident.outcome
                    if raw_incident.data_compromised_GB:
                        details["data_compromised_GB"] = raw_incident.data_compromised_GB
                    if raw_incident.attack_duration_min is not None:
                        details["attack_duration_min"] = raw_incident.attack_duration_min
                    if raw_incident.security_tools_used:
                        details["security_tools_used"] = raw_incident.security_tools_used
                    if raw_incident.user_role:
                        details["user_role"] = raw_incident.user_role
                    if raw_incident.location:
                        details["location"] = raw_incident.location
                    if raw_incident.attack_severity is not None:
                        details["attack_severity"] = raw_incident.attack_severity
                    if raw_incident.industry:
                        details["industry"] = raw_incident.industry
                    if raw_incident.response_time_min is not None:
                        details["response_time_min"] = raw_incident.response_time_min
                    if raw_incident.mitigation_method:
                        details["mitigation_method"] = raw_incident.mitigation_method
                    
                    st.json(details)
                    
                    # Report Generation Button
                    st.markdown("---")
                    if st.button("📄 Generate PDF Report"):
                        generator = ReportGenerator()
                        # Pass dictionary form of incident
                        pdf_path, pdf_filename = generator.generate_incident_report(details)
                        
                        with open(pdf_path, "rb") as pdf_file:
                             pdf_bytes = pdf_file.read()
                             
                        st.download_button(
                             label="⬇️ Download PDF",
                             data=pdf_bytes,
                             file_name=pdf_filename,
                             mime="application/pdf"
                        )
                        # Optional: clean up file after read (OS dependent regarding open handles, safest to keep or use tempfile)
                        # os.remove(pdf_path) 
                        
                else:
                    st.warning("Details not found for this ID.")
            finally:
                session.close()
    
def realtime_monitor_view():
    st.title("⚡ Real-time Network Monitor")
    
    # Auto-refresh
    # Auto-refresh mechanism - DISABLED due to causing crashes
    # if st.sidebar.checkbox("Enable Auto-refresh", value=False):
    #     st.rerun()
    
    if st.sidebar.button("🔄 Refresh Data"):
        st.rerun()

    # --- Section 1: Network Traffic & DoS ---
    st.subheader("📡 Network Traffic & DoS Analysis")
    traffic_stats = get_traffic_stats()
    if traffic_stats:
        df_traffic = pd.DataFrame(traffic_stats)
        
        col1, col2 = st.columns([3, 1])
        with col1:
            st.area_chart(df_traffic, x="Time", y=["PPS In", "PPS Out"])
        
        with col2:
            latest = df_traffic.iloc[0]
            dos_score = latest['DoS Score']
            st.metric("DoS Likelihood", f"{int(dos_score * 100)}%", delta=None)
            
            if dos_score > 0.7:
                st.error("Likelihood: CRITICAL")
            elif dos_score > 0.3:
                st.warning("Likelihood: SUSPICIOUS")
            else:
                st.success("Likelihood: LOW")
                
            st.metric("Current CPU", f"{latest['CPU %']}%")

    # --- Section 2: Ping Latency ---
    st.subheader("📶 Target Latency (Ping Streams)")
    ping_data = get_ping_stats()
    if ping_data:
        df_ping = pd.DataFrame(ping_data)
        # Reshape for multi-line chart (pivot)
        # We need a line for each target
        if not df_ping.empty:
            st.line_chart(df_ping, x="Time", y="Latency (ms)", color="Target")

    # --- Section 3: Live Feeds (Incidents & SSH) ---
    st.subheader("🚨 Live Event Feed")
    
    col_inc, col_ssh = st.columns(2)
    
    with col_inc:
        st.write("**Latest Incidents**")
        latest_incidents = get_latest_incidents()
        if latest_incidents:
            df_inc = pd.DataFrame(latest_incidents)
            st.dataframe(
                df_inc,
                column_config={
                    "Time": st.column_config.DatetimeColumn(format="HH:mm:ss"),
                },
                width='stretch',
                hide_index=True
            )
        else:
            st.info("No recent incidents.")

    with col_ssh:
        st.write("**Recent SSH Data**")
        ssh_events = get_latest_ssh_events()
        if ssh_events:
            df_ssh = pd.DataFrame(ssh_events)
            
            def highlight_type(val):
                color = 'green' if val == 'SUCCESS' else 'red'
                return f'color: {color}'

            st.dataframe(
                df_ssh.style.map(highlight_type, subset=['Type']),
                column_config={
                    "Time": st.column_config.DatetimeColumn(format="HH:mm:ss"),
                },
                width='stretch',
                hide_index=True
            )
        else:
            st.info("No recent SSH events.")

# --- App Entry Point ---

def main():
    # Sidebar Navigation
    st.sidebar.title("Navigation")
    view = st.sidebar.radio("Go to", ["Dashboard", "Real-time Monitor", "Settings"])

    if view == "Dashboard":
        main_dashboard_view()
    elif view == "Real-time Monitor":
        realtime_monitor_view()
    elif view == "Settings":
        settings_view()

if __name__ == "__main__":
    main()