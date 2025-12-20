# models.py
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Float
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime
import os

# Define the base class for declarative class definitions
Base = declarative_base()

# Define the table structure for Incidents
class Incident(Base):
    __tablename__ = 'incidents'
    
    # Primary Key
    id = Column(Integer, primary_key=True)
    
    # Core Fields (Required for application):
    ip = Column(String)      # Source IP of the incident (attacker_ip)
    type = Column(String)    # Incident Type (e.g., "Brute Force", "DDoS")
    severity = Column(String) # Severity Level (e.g., "Low", "Medium", "High", "Critical")
    timestamp = Column(DateTime, default=datetime.utcnow) # When the incident occurred
    source_log = Column(String) # The log file where the event occurred
    target = Column(String)     # The target user/system (target_system)
    
    # Required/Core Fields from Project Plan:
    rule = Column(String)  # The detection rule name
    status = Column(String, default="Active") # e.g., "Active", "Resolved", "Closed"
    
    # Extended Fields from SOC Dataset (Optional but preserved):
    target_ip = Column(String)  # Target IP address
    outcome = Column(String)    # Success or Failure
    data_compromised_GB = Column(String)  # Data compromised (stored as string for flexibility)
    attack_duration_min = Column(Integer)  # Attack duration in minutes
    security_tools_used = Column(String)  # Security tools that detected it
    user_role = Column(String)  # User role (Admin, Employee, External User)
    location = Column(String)   # Geographic location (country)
    attack_severity = Column(Integer)  # Numeric severity (1-10)
    industry = Column(String)  # Industry sector
    response_time_min = Column(Integer)  # Response time in minutes
    mitigation_method = Column(String)  # How it was mitigated
    
    # Threat Intelligence Fields (GeoIP + AbuseIPDB)
    geo_country = Column(String)  # Country name
    geo_country_code = Column(String)  # Country code (US, CN, etc.)
    geo_city = Column(String)  # City name
    geo_region = Column(String)  # Region/State
    geo_lat = Column(String)  # Latitude
    geo_lon = Column(String)  # Longitude
    geo_isp = Column(String)  # Internet Service Provider
    geo_org = Column(String)  # Organization
    is_proxy = Column(String)  # Is proxy/VPN (stored as string for flexibility)
    is_hosting = Column(String)  # Is hosting provider
    abuse_confidence_score = Column(Integer)  # AbuseIPDB confidence (0-100)
    abuse_total_reports = Column(Integer)  # Total abuse reports
    threat_risk_score = Column(Integer)  # Calculated risk score (0-100)
    threat_risk_level = Column(String)  # Risk level (Low, Medium, High, Critical)

    def __repr__(self):
        return f"<Incident(id='{self.id}', type='{self.type}', severity='{self.severity}')>"

class PingMetrics(Base):
    __tablename__ = 'ping_metrics'
    id = Column(Integer, primary_key=True)
    target_ip = Column(String)
    latency_ms = Column(Float)
    packet_loss_pct = Column(Float)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    status = Column(String)

class SSHEvent(Base):
    __tablename__ = 'ssh_events'
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    source_ip = Column(String)
    username = Column(String)
    event_type = Column(String) # SUCCESS, FAILURE, DISCONNECT
    auth_method = Column(String)
    port = Column(Integer, default=22)

class TrafficStats(Base):
    __tablename__ = 'traffic_stats'
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    packet_count_in = Column(Integer)
    packet_count_out = Column(Integer)
    byte_count_in = Column(Integer)
    byte_count_out = Column(Integer)
    cpu_load = Column(Float)
    dos_likelihood_score = Column(Float)


# Database Initialization
# Use absolute path to ensure consistency regardless of where the script is run from
# The database is located in IR-System/ (/home/kali/IR-Project/IR-System/database.db)
# models.py is in server_backend/, so we go up one level to reach IR-System/
_ir_system_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
_database_path = os.path.join(_ir_system_dir, 'database.db')
DATABASE_URL = f"sqlite:///{_database_path}"
engine = create_engine(DATABASE_URL)
Base.metadata.create_all(engine)

# Session setup for later use
Session = sessionmaker(bind=engine)

print("Database and Incidents table initialized successfully!")