# dashboard.py (Didi's Visualization - Day 4, 7, 8, 10 Logic)
import streamlit as st
import pandas as pd
from datetime import datetime, timedelta
import os
import requests
# Import the Incident model and Session factory from the shared models file
from models import Incident, Session
from sqlalchemy.exc import OperationalError
from sqlalchemy import func

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
                "Status": inc.status
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

# --- Main Dashboard Layout ---

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
    
    # Display the main table (hide Severity Rank column)
    display_df = incident_df.drop(columns=['Severity Rank'], errors='ignore')
    
    st.dataframe(
        display_df,
        width='stretch',
        hide_index=True,
        column_order=("ID", "Source IP", "Type", "Severity", "Time (UTC)", "Target", "Rule Triggered", "Status"),
        column_config={
            "Severity": st.column_config.TextColumn(
                "Severity",
                help="Incident impact level (Critical, High, Medium, Low)",
                width="small"
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
                # Display incident details as a dictionary
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
                st.json(details)
            else:
                st.warning("Details not found for this ID.")
        finally:
            session.close()