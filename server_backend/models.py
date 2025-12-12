# models.py
from sqlalchemy import create_engine, Column, Integer, String, DateTime
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime

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
DATABASE_URL = "sqlite:///database.db"
engine = create_engine(DATABASE_URL)
Base.metadata.create_all(engine)

# Session setup for later use
Session = sessionmaker(bind=engine)

print("Database and Incidents table initialized successfully!")