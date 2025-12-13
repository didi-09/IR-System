# models.py
from sqlalchemy import create_engine, Column, Integer, String, DateTime
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
    
    # Agreed JSON Fields:
    ip = Column(String)      # Source IP of the incident
    type = Column(String)    # Incident Type (e.g., "Brute Force")
    severity = Column(String) # Severity Level (e.g., "High")
    timestamp = Column(DateTime, default=datetime.utcnow) # When the incident occurred
    
    # Required/Core Fields from Project Plan:
    rule = Column(String)  # The detection rule name
    status = Column(String, default="Active") # e.g., "Active", "Containment", "Closed"
    
    # Additional useful fields from the generated data structure:
    source_log = Column(String) # The log file where the event occurred
    target = Column(String)     # The target user/system

    def __repr__(self):
        return f"<Incident(id='{self.id}', type='{self.type}', severity='{self.severity}')>"

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