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

def generate_incident_details(incident):
    """
    Generate context-specific details based on incident type.
    Returns a concise, human-readable summary.
    """
    incident_type = incident.type.lower() if incident.type else ""
    
    # Network/Authentication Incidents
    if any(word in incident_type for word in ['brute force', 'login', 'ssh', 'authentication']):
        attempts_info = f"from {incident.ip}" if incident.ip and incident.ip != "127.0.0.1" else ""
        return f"User: {incident.target} | {attempts_info}".strip(" |")
    
    # System Resource Incidents
    elif any(word in incident_type for word in ['disk', 'cpu', 'memory', 'resource']):
        source = incident.source_log.split('/')[-1] if incident.source_log else "system"
        return f"Source: {source} | Resource threshold exceeded"
    
    # Web Attacks
    elif any(word in incident_type for word in ['sql', 'xss', 'injection', 'web']):
        method = "Web Application Attack"
        source = f"from {incident.ip}" if incident.ip and incident.ip != "127.0.0.1" else ""
        return f"{method} {source}".strip()
    
    # Process/Service Incidents
    elif any(word in incident_type for word in ['process', 'service', 'sudo']):
        return f"Target: {incident.target} | Process/Service monitoring"
    
    # File Integrity
    elif any(word in incident_type for word in ['file', 'integrity', 'modification']):
        return f"File: {incident.target}"
    
    # User Enumeration
    elif 'enumeration' in incident_type:
        return f"Multiple user probes from {incident.ip}" if incident.ip else "User enumeration detected"
    
    # Default fallback
    else:
        log_name = incident.source_log.split('/')[-1] if incident.source_log else "N/A"
        return f"Source: {log_name}"

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
                "Type": inc.type,
                "Severity": inc.severity,
                "Severity Rank": get_severity_rank(inc.severity),
                # Smart Source field - shows IP for external, log for internal
                "Source": inc.ip if inc.ip and inc.ip not in ["127.0.0.1", "localhost", "::1"] else (inc.source_log.split('/')[-1] if inc.source_log else "System"),
                "Target": inc.target,
                "Source Log": inc.source_log.split('/')[-1] if inc.source_log else "N/A",
                "Details": generate_incident_details(inc),
                "Duration": f"{inc.attack_duration_min}m" if inc.attack_duration_min and inc.attack_duration_min > 0 else "N/A",
                "Outcome": inc.outcome if inc.outcome else "N/A",
                "Status": inc.status,
                "Rule": inc.rule,
                # Geographic info (only for external IPs)
                "Country": inc.geo_country if inc.geo_country else "N/A",
                "City": inc.geo_city if inc.geo_city else "N/A",
                "ISP": inc.geo_isp if inc.geo_isp else "N/A",
                "Risk Level": inc.threat_risk_level if inc.threat_risk_level else "Unknown",
                "Risk Score": inc.threat_risk_score if inc.threat_risk_score else 0,
                # Store full log path and raw incident for export
                "Source Log Path": inc.source_log if inc.source_log else "",
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

    # --- NEW: Clear Incidents Database ---
    st.markdown("---")
    st.subheader("🗑️ Clear Incidents Database")
    st.caption("Permanently delete incidents from the database. Use with caution!")
    
    with st.expander("⚠️ Clear Incidents Options", expanded=False):
        st.warning("**Warning:** This action cannot be undone. Incidents will be permanently deleted from the database.")
        
        col1, col2 = st.columns(2)
        
        with col1:
            clear_severity = st.selectbox(
                "Filter by Severity (Optional)",
                ["All", "Critical", "High", "Medium", "Low"],
                help="Select specific severity to clear, or 'All' to clear all severities"
            )
            
            clear_status = st.selectbox(
                "Filter by Status (Optional)",
                ["All", "Active", "Resolved", "Closed"],
                help="Select specific status to clear, or 'All' to clear all statuses"
            )
        
        with col2:
            clear_days = st.number_input(
                "Older than (days) - Optional",
                min_value=0,
                value=0,
                help="Only clear incidents older than specified days. Use 0 to ignore this filter."
            )
            
            # Show what will be cleared
            filter_desc = []
            if clear_severity != "All":
                filter_desc.append(f"Severity={clear_severity}")
            if clear_status != "All":
                filter_desc.append(f"Status={clear_status}")
            if clear_days > 0:
                filter_desc.append(f"Older than {clear_days} days")
            
            if filter_desc:
                st.info(f"**Will clear:** {', '.join(filter_desc)}")
            else:
                st.error("**Will clear:** ALL INCIDENTS")
        
        # Confirmation
        confirm_clear = st.checkbox("I understand this action cannot be undone", value=False)
        
        if st.button("🗑️ Clear Incidents", type="primary", disabled=not confirm_clear):
            try:
                # Build query parameters
                params = {}
                if clear_severity != "All":
                    params['severity'] = clear_severity
                if clear_status != "All":
                    params['status'] = clear_status
                if clear_days > 0:
                    params['days'] = clear_days
                
                # Call API
                response = requests.delete(
                    f"{API_BASE_URL}/api/incidents/clear",
                    params=params,
                    timeout=10
                )
                
                if response.status_code == 200:
                    result = response.json()
                    count = result.get('count', 0)
                    st.success(f"✅ Successfully cleared {count} incident(s)!")
                    st.cache_data.clear()
                    time.sleep(1)
                    st.rerun()
                else:
                    st.error(f"❌ Failed to clear incidents: {response.text}")
            except Exception as e:
                st.error(f"❌ Error: {e}")

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

    # --- Enhanced Statistics Dashboard ---
    st.subheader("📊 System Overview")
    
    # Get statistics
    status_data = get_system_status()
    session = Session()
    
    try:
        # Calculate metrics
        total_incidents = session.query(func.count(Incident.id)).scalar()
        active_incidents = session.query(func.count(Incident.id)).filter(Incident.status == 'Active').scalar()
        
        # Last 24 hours
        last_24h = datetime.utcnow() - timedelta(hours=24)
        incidents_24h = session.query(func.count(Incident.id)).filter(Incident.timestamp >= last_24h).scalar()
        
        # Last 7 days for trend
        last_7d = datetime.utcnow() - timedelta(days=7)
        incidents_7d = session.query(func.count(Incident.id)).filter(Incident.timestamp >= last_7d).scalar()
        
        # Top attacking IP
        top_ip_result = session.query(
            Incident.ip,
            func.count(Incident.id).label('count')
        ).group_by(Incident.ip).order_by(func.count(Incident.id).desc()).first()
        
        top_ip = f"{top_ip_result[0]} ({top_ip_result[1]})" if top_ip_result else "None"
        
        # Critical incidents
        critical_count = session.query(func.count(Incident.id)).filter(Incident.severity == 'Critical').scalar()
        
    except Exception as e:
        total_incidents = active_incidents = incidents_24h = critical_count = 0
        top_ip = "Error"
    finally:
        session.close()
    
    # Metrics row
    metric_col1, metric_col2, metric_col3, metric_col4, metric_col5 = st.columns(5)
    
    with metric_col1:
        st.metric(
            label="📈 Total Incidents",
            value=total_incidents,
            delta=f"+{incidents_24h} (24h)",
            delta_color="inverse"
        )
    
    with metric_col2:
        st.metric(
            label="🚨 Active",
            value=active_incidents,
            delta=f"{(active_incidents/total_incidents*100):.1f}%" if total_incidents > 0 else "0%",
            delta_color="inverse"
        )
    
    with metric_col3:
        st.metric(
            label="🔴 Critical",
            value=critical_count,
            delta="High Priority" if critical_count > 0 else "None",
            delta_color="inverse" if critical_count > 0 else "normal"
        )
    
    with metric_col4:
        st.metric(
            label="🎯 Top Attacker",
            value=top_ip,
            help="Most frequent attacking IP"
        )
    
    with metric_col5:
        # Agent status
        agent_status = "🟢 Online" if status_data and status_data.get('system') == 'operational' else "🔴 Offline"
        st.metric(
            label="🛡️ Agent Status",
            value=agent_status,
            help="Detection agent operational status"
        )
    
    # System Status expandable section
    with st.expander("🔍 Detailed System Status", expanded=False):
        if status_data:
            col1, col2, col3 = st.columns(3)
            with col1:
                db_status = status_data.get('components', {}).get('database', {}).get('status', 'unknown')
                st.metric("Database", "🟢 Healthy" if db_status == "healthy" else "🔴 Unhealthy")
            
            with col2:
                blacklist_status = status_data.get('components', {}).get('blacklist', {})
                ip_count = blacklist_status.get('ip_count', 0)
                st.metric("Blacklist IPs", ip_count)
            
            with col3:
                stats = status_data.get('statistics', {})
                resolved = stats.get('resolved_incidents', 0)
                st.metric("Resolved", resolved)
            
            # Severity breakdown
            if 'severity_breakdown' in stats and stats['severity_breakdown']:
                st.write("**Current Severity Distribution:**")
                severity_counts = stats['severity_breakdown']
                if len(severity_counts) > 0:
                    severity_cols = st.columns(len(severity_counts))
                    for idx, (severity, count) in enumerate(severity_counts.items()):
                        with severity_cols[idx]:
                            st.metric(severity, count)
                else:
                    st.info("No incidents to display severity distribution")
            else:
                st.info("Severity breakdown not available")
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
            unique_sources = incident_df['Source'].nunique()
            st.metric(label="Unique Sources", value=unique_sources)
        
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
                source_counts = incident_df['Source'].value_counts().head(10)
                st.bar_chart(source_counts)
                st.caption("Top 10 Sources by Incident Count")
        
        # Display the main table (hide internal columns)
        display_df = incident_df.drop(columns=['Severity Rank', '_raw', 'Source Log Path'], errors='ignore')
        
        # Dynamic column display based on incident types present
        incident_types = incident_df['Type'].str.lower() if not incident_df.empty else pd.Series()
        
        # Detect incident categories
        has_network = any(kw in ' '.join(incident_types) for kw in ['brute force', 'ssh', 'login', 'enumeration', 'ddos'])
        has_system = any(kw in ' '.join(incident_types) for kw in ['disk', 'cpu', 'memory', 'resource', 'process', 'service'])
        has_web = any(kw in ' '.join(incident_types) for kw in ['sql', 'xss', 'injection', 'web'])
        has_external_ips = not incident_df.empty and any(incident_df['Source'].str.contains(r'\d+\.\d+\.\d+\.\d+', na=False, regex=True))
        
        # Build dynamic column order
        base_columns = ["ID", "Time (UTC)", "Type", "Severity"]
        detail_columns = []
        context_columns = []
        
        # Always show Source and Target
        detail_columns.extend(["Source", "Target"])
        
        # Show Source Log for system incidents or when relevant
        if has_system or not has_network:
            detail_columns.append("Source Log")
        
        # Always show Details
        detail_columns.append("Details")
        
        # Show Duration and Outcome if any incidents have these populated
        if 'Duration' in display_df.columns and (display_df['Duration'] != 'N/A').any():
            detail_columns.append("Duration")
        if 'Outcome' in display_df.columns and (display_df['Outcome'] != 'N/A').any():
            detail_columns.append("Outcome")
        
        # Add Status and Rule
        detail_columns.extend(["Status", "Rule"])
        
        # Show geographic/threat intel for external IPs
        if has_external_ips and has_network:
            context_columns.extend(["Country", "Risk Level"])
        
        # Combine all columns
        dynamic_columns = tuple(base_columns + detail_columns + context_columns)
        
        st.dataframe(
            display_df,
            width='stretch',
            hide_index=True,
            column_order=dynamic_columns,
            column_config={
                "ID": st.column_config.NumberColumn(
                    "ID",
                    help="Incident ID",
                    width="small"
                ),
                "Time (UTC)": st.column_config.DatetimeColumn(
                    "Time (UTC)",
                    format="YYYY/MM/DD hh:mm:ss",
                    width="medium"
                ),
                "Type": st.column_config.TextColumn(
                    "Type",
                    help="Incident category (Network, System, Web, Database)",
                    width="medium"
                ),
                "Severity": st.column_config.TextColumn(
                    "Severity",
                    help="Impact level (Critical, High, Medium, Low)",
                    width="small"
                ),
                "Source": st.column_config.TextColumn(
                    "Source",
                    help="Attack source (IP for external, log file for internal)",
                    width="medium"
                ),
                "Target": st.column_config.TextColumn(
                    "Target",
                    help="Targeted user, system, or resource",
                    width="medium"
                ),
                "Source Log": st.column_config.TextColumn(
                    "Source Log",
                    help="Log file that detected this incident",
                    width="medium"
                ),
                "Details": st.column_config.TextColumn(
                    "Details",
                    help="Context-specific incident information",
                    width="large"
                ),
                "Duration": st.column_config.TextColumn(
                    "Duration",
                    help="Attack duration",
                    width="small"
                ),
                "Outcome": st.column_config.TextColumn(
                    "Outcome",
                    help="Result of the incident (Success/Failure)",
                    width="small"
                ),
                "Status": st.column_config.TextColumn(
                    "Status",
                    help="Current incident status",
                    width="small"
                ),
                "Country": st.column_config.TextColumn(
                    "Country",
                    help="Geographic origin (for external attacks)",
                    width="small"
                ),
                "Risk Level": st.column_config.TextColumn(
                    "Risk Level",
                    help="Threat intelligence risk assessment",
                    width="small"
                ),
                "Rule": st.column_config.TextColumn(
                    "Rule",
                    help="Detection rule that triggered this incident",
                    width="medium"
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
    if not incident_df.empty and st.toggle("Show Detailed Incident Information"):
        selected_incident_id = st.selectbox(
            "Select Incident ID for Full Details",
            incident_df['ID'].tolist()
        )
        
        if selected_incident_id:
            session = Session()
            try:
                raw_incident = session.query(Incident).filter(Incident.id == selected_incident_id).first()
                if raw_incident:
                    # Organize details by category
                    st.subheader(f"Incident #{raw_incident.id} - {raw_incident.type}")
                    
                    col1, col2 = st.columns(2)
                    
                    # Prepare a comprehensive dictionary for PDF generation
                    details_for_pdf = {
                        "id": raw_incident.id,
                        "ip": raw_incident.ip,
                        "type": raw_incident.type,
                        "severity": raw_incident.severity,
                        "timestamp": str(raw_incident.timestamp),
                        "rule": raw_incident.rule,
                        "source_log": raw_incident.source_log,
                        "target": raw_incident.target,
                        "status": raw_incident.status,
                        "target_ip": raw_incident.target_ip,
                        "outcome": raw_incident.outcome,
                        "data_compromised_GB": raw_incident.data_compromised_GB,
                        "attack_duration_min": raw_incident.attack_duration_min,
                        "security_tools_used": raw_incident.security_tools_used,
                        "user_role": raw_incident.user_role,
                        "location": raw_incident.location,
                        "attack_severity": raw_incident.attack_severity,
                        "industry": raw_incident.industry,
                        "response_time_min": raw_incident.response_time_min,
                        "mitigation_method": raw_incident.mitigation_method,
                        "geo_country": raw_incident.geo_country,
                        "geo_country_code": raw_incident.geo_country_code,
                        "geo_city": raw_incident.geo_city,
                        "geo_region": raw_incident.geo_region,
                        "geo_isp": raw_incident.geo_isp,
                        "geo_org": raw_incident.geo_org,
                        "threat_risk_level": raw_incident.threat_risk_level,
                        "threat_risk_score": raw_incident.threat_risk_score,
                        "abuse_confidence_score": raw_incident.abuse_confidence_score,
                        "abuse_total_reports": raw_incident.abuse_total_reports,
                    }

                    with col1:
                        st.markdown("### Core Information")
                        core_details = {
                            "ID": raw_incident.id,
                            "Type": raw_incident.type,
                            "Severity": raw_incident.severity,
                            "Status": raw_incident.status,
                            "Timestamp": str(raw_incident.timestamp),
                            "Rule": raw_incident.rule,
                            "Source Log": raw_incident.source_log,
                        }
                        for key, value in core_details.items():
                            if value is not None: # Check for None explicitly
                                st.text(f"{key}: {value}")
                        
                        st.markdown("### Attack Details")
                        attack_details = {}
                        if raw_incident.ip:
                            attack_details["Source IP"] = raw_incident.ip
                        if raw_incident.target:
                            attack_details["Target"] = raw_incident.target
                        if raw_incident.target_ip:
                            attack_details["Target IP"] = raw_incident.target_ip
                        if raw_incident.attack_duration_min is not None:
                            attack_details["Duration"] = f"{raw_incident.attack_duration_min} minutes"
                        if raw_incident.outcome:
                            attack_details["Outcome"] = raw_incident.outcome
                        if raw_incident.security_tools_used:
                            attack_details["Tools Used"] = raw_incident.security_tools_used
                        
                        for key, value in attack_details.items():
                            if value is not None:
                                st.text(f"{key}: {value}")
                    
                    with col2:
                        # Geographic/Threat Intelligence
                        if raw_incident.geo_country or raw_incident.threat_risk_level or raw_incident.abuse_confidence_score:
                            st.markdown("### Threat Intelligence")
                            threat_details = {}
                            if raw_incident.geo_country:
                                threat_details["Country"] = f"{raw_incident.geo_country} ({raw_incident.geo_country_code or 'N/A'})"
                            if raw_incident.geo_city:
                                threat_details["City"] = raw_incident.geo_city
                            if raw_incident.geo_region:
                                threat_details["Region"] = raw_incident.geo_region
                            if raw_incident.geo_isp:
                                threat_details["ISP"] = raw_incident.geo_isp
                            if raw_incident.geo_org:
                                threat_details["Organization"] = raw_incident.geo_org
                            if raw_incident.threat_risk_level:
                                threat_details["Risk Level"] = raw_incident.threat_risk_level
                            if raw_incident.threat_risk_score is not None:
                                threat_details["Risk Score"] = f"{raw_incident.threat_risk_score}/100"
                            if raw_incident.abuse_confidence_score is not None:
                                threat_details["Abuse Score"] = f"{raw_incident.abuse_confidence_score}%"
                            if raw_incident.abuse_total_reports is not None:
                                threat_details["Total Reports"] = raw_incident.abuse_total_reports
                            
                            for key, value in threat_details.items():
                                if value is not None:
                                    st.text(f"{key}: {value}")
                        
                        # Extended fields
                        extended_fields = {}
                        if raw_incident.user_role:
                            extended_fields["User Role"] = raw_incident.user_role
                        if raw_incident.location:
                            extended_fields["Location"] = raw_incident.location
                        if raw_incident.industry:
                            extended_fields["Industry"] = raw_incident.industry
                        if raw_incident.data_compromised_GB is not None:
                            extended_fields["Data Compromised"] = f"{raw_incident.data_compromised_GB} GB"
                        if raw_incident.response_time_min is not None:
                            extended_fields["Response Time"] = f"{raw_incident.response_time_min} minutes"
                        if raw_incident.mitigation_method:
                            extended_fields["Mitigation"] = raw_incident.mitigation_method
                        
                        if extended_fields:
                            st.markdown("### Additional Details")
                            for key, value in extended_fields.items():
                                if value is not None:
                                    st.text(f"{key}: {value}")
                    
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