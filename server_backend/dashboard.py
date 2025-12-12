# dashboard.py
import streamlit as st
import pandas as pd
from sqlalchemy import create_engine
from models import Incident # Import the table definition

# --- Configuration (Matches models.py) ---
DATABASE_URL = "sqlite:///database.db"
engine = create_engine(DATABASE_URL)
# ----------------------------------------

# Function to fetch all incident data from the database
def fetch_incidents():
    """Fetches all records from the incidents table."""
    try:
        # Use pandas to read data directly from the SQL table
        df = pd.read_sql_table(Incident.__tablename__, con=engine)
        return df
    except Exception as e:
        st.error(f"Error fetching data from database: {e}")
        return pd.DataFrame()

# Streamlit App Layout (Day 4 task)
st.set_page_config(layout="wide")

st.title("🛡️ Incident Management Dashboard")
st.markdown("---")

incident_data = fetch_incidents()

if incident_data.empty:
    st.info("No incidents found in the database. Run the backend script and wait for Bayoumy's alerts!")
else:
    st.header("Active Incidents")
    # Display the table (fulfills Day 4 requirement)
    st.dataframe(incident_data)
    
    # Simple count/status check
    st.sidebar.metric("Total Incidents", len(incident_data))
    
    # You will add filtering and more robust visualization here on Day 4 (Filters for Severity or Date [cite: 33])