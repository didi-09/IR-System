# dashboard.py (Didi's Dashboard - Day 4 Logic: Visualization)
import streamlit as st
import pandas as pd
from sqlalchemy import create_engine
# We rely on 'models.py' being in the same directory to get the Incident table definition
from models import Incident 
import time

# --- Configuration (Matches models.py) ---
DATABASE_URL = "sqlite:///database.db"
engine = create_engine(DATABASE_URL)
# ----------------------------------------

# Function to fetch all incident data from the database
# Caching helps performance, and ttl=2 ensures it refreshes every 2 seconds
@st.cache_data(ttl=2) 
def fetch_incidents():
    """Fetches all records from the incidents table using pandas for efficiency."""
    try:
        # Use pandas to read data directly from the SQL table
        # We fetch the entire table to allow for in-memory filtering (Day 4 requirement)
        df = pd.read_sql_table(Incident.__tablename__, con=engine)
        
        # Convert timestamp column to datetime objects
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        
        # Sort by timestamp, newest first
        df = df.sort_values(by='timestamp', ascending=False)
        return df
    except Exception as e:
        st.error(f"Error fetching data from database: {e}")
        return pd.DataFrame()

# Streamlit App Layout
st.set_page_config(layout="wide", page_title="Didi's Incident Dashboard", initial_sidebar_state="expanded")

st.title("🛡️ Sentinel Incident Dashboard")
st.markdown("Monitor and triage active security alerts in real-time.")
st.markdown("---")

# Main container for the dashboard content
dashboard_container = st.container()

# Start the auto-refresh loop
with dashboard_container:
    col1, col2 = st.columns([1, 4])
    
    # --- Sidebar/Filter Column (Day 4 requirement) ---
    with col1:
        st.header("Filters & Metrics")
        
        # Fetch data first for filtering and metrics
        incident_data = fetch_incidents()
        
        # Filter for Status (e.g., Active only)
        status_options = incident_data['status'].unique().tolist() if not incident_data.empty else ["Active", "Closed"]
        selected_status = st.multiselect(
            "Filter by Status:",
            options=status_options,
            default=["Active"] # Default to showing only "Active" incidents for triage
        )

        # Filter for Severity (Day 4 requirement)
        severity_options = incident_data['severity'].unique().tolist() if not incident_data.empty else ["Low", "Medium", "High", "Critical"]
        selected_severity = st.multiselect(
            "Filter by Severity:",
            options=severity_options,
            default=severity_options # Show all by default
        )
        
        # Apply filtering
        if not incident_data.empty:
            filtered_data = incident_data[
                incident_data['status'].isin(selected_status) &
                incident_data['severity'].isin(selected_severity)
            ]
        else:
            filtered_data = incident_data
        
        # --- Metrics ---
        st.subheader("Metrics")
        st.metric("Total Incidents Logged", len(incident_data))
        st.metric("Active Incidents (Filtered)", len(filtered_data))
        
        # Highlight Critical Incidents
        critical_count = len(filtered_data[filtered_data['severity'] == 'Critical'])
        st.metric("Critical Alerts", critical_count, delta_color="inverse")

    # --- Main Dashboard Table Column (Day 4 requirement) ---
    with col2:
        st.header(f"Incident Queue ({len(filtered_data)} Alerts)")
        
        if filtered_data.empty:
            st.info("The incident queue is clear. No active alerts matching the criteria.")
        else:
            # Display the table with enhanced formatting
            st.dataframe(
                filtered_data, 
                # FIX: Replacing deprecated 'use_container_width=True' with 'width='stretch''
                width='stretch', 
                # Use Streamlit's powerful column configuration for better visualization
                column_config={
                    # FIX: Replaced unsupported BadgeColumn with TextColumn for compatibility
                    "severity": st.column_config.TextColumn( 
                        "Severity",
                        help="Risk level of the incident",
                        width="small",
                    ),
                    "timestamp": st.column_config.DatetimeColumn(
                        "Time",
                        format="YYYY-MM-DD HH:mm:ss",
                        width="medium"
                    ),
                    "ip": st.column_config.TextColumn("Source IP", width="small"),
                    "type": st.column_config.TextColumn("Incident Type", width="medium"),
                    "status": st.column_config.TextColumn("Status", width="small"),
                },
                # Select only the most relevant columns for the main view
                column_order=["id", "timestamp", "severity", "type", "ip", "target", "rule", "status"]
            )

# Re-run the script periodically to update the data automatically
# This creates a near real-time effect as data is saved and fetched
time.sleep(1) 
st.rerun()