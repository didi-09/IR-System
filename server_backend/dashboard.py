# dashboard.py (Didi's Visualization - Day 4 Logic)
import streamlit as st
import pandas as pd
from datetime import datetime, timedelta
import os # <-- ADDED IMPORT FOR PATH CHECKING
# Import the Incident model and Session factory from the shared models file
from models import Incident, Session
from sqlalchemy.exc import OperationalError

# Set page configuration for a better layout
st.set_page_config(layout="wide", page_title="Sentinel Security Dashboard")

def load_incidents(severity_filter=None, days_filter=None):
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

        query = session.query(Incident).filter(Incident.status == 'Active')
        
        # Apply severity filter
        if severity_filter and severity_filter != "All":
            query = query.filter(Incident.severity == severity_filter)
            
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
                "Rule Triggered": inc.rule,
                "Target": inc.target,
                "Status": inc.status
            } for inc in incidents
        ]
        
        df = pd.DataFrame(data)
        
        # Ensure timestamp column is correctly formatted for sorting
        if not df.empty:
            df['Time (UTC)'] = pd.to_datetime(df['Time (UTC)'])
            
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

# --- Main Dashboard Layout ---

st.title("Sentinel Incident Response Console 🛡️")
st.markdown("Real-time view of active security incidents across the network.")

# Use st.container to group UI elements and prevent layout shifts
with st.container():
    col1, col2, col3 = st.columns([1, 1, 3])
    
    with col1:
        # Severity Filter
        severity_options = ["All", "Critical", "High", "Medium", "Low"]
        selected_severity = st.selectbox("Filter by Severity", severity_options)

    with col2:
        # Date Filter (Days)
        date_options = {
            "All Time": 0,
            "Last 24 Hours": 1,
            "Last 7 Days": 7,
            "Last 30 Days": 30
        }
        selected_date_label = st.selectbox("Filter by Timeframe", list(date_options.keys()))
        selected_days = date_options[selected_date_label]

    with col3:
        # Refresh button
        st.write("---")
        # Added a key to ensure Streamlit tracks this button's state
        if st.button("Refresh Data Manually", key="refresh_button", help="Click to force a database refresh."):
            st.cache_data.clear()
        
# --- Data Loading and Display ---

# Use Streamlit's cache_data decorator for fast reloading, with a 5-second TTL
@st.cache_data(ttl=5)
def get_live_data(severity, days):
    return load_incidents(severity, days)

# Fetch data using the cached function and filters
incident_df = get_live_data(selected_severity, selected_days)

# Display the main table
st.subheader("Active Incidents")

if incident_df.empty:
    st.info("No active incidents found matching the current filters.")
else:
    # Highlight high severity rows for better visibility
    st.dataframe(
        incident_df,
        use_container_width=True,
        hide_index=True,
        column_order=("ID", "Source IP", "Type", "Severity", "Time (UTC)", "Target", "Rule Triggered"),
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
    
    st.metric(label="Total Active Incidents", value=len(incident_df))

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