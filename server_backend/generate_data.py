import json
import random
from faker import Faker
from datetime import datetime, timedelta

# Initialize Faker for generating realistic-looking data
fake = Faker()

def generate_incident(incident_id, start_date):
    """
    Generates a single incident dictionary.
    """
    # Define realistic possible values
    incident_types = [
        "Brute Force",
        "SQL Injection Attempt",
        "Port Scan",
        "Malware Detected",
        "Unauthorized Access",
        "DDoS Attack",
        "Privilege Escalation"
    ]

    severity_levels = ["Low", "Medium", "High", "Critical"]

    # Generate a time close to the start_date for chronological order
    timestamp = start_date + timedelta(seconds=incident_id * random.randint(30, 180))

    # Simulate IP addresses, leaning towards private network ranges for realism
    ip_address = fake.ipv4_private()

    # Generate incident data
    incident = {
        "id": incident_id,
        # Use a realistic-looking IP, which can be an internal or external source
        "ip": ip_address,
        "type": random.choice(incident_types),
        "severity": random.choice(severity_levels),
        # Add a timestamp to simulate when the incident occurred
        "timestamp": timestamp.isoformat(),
        # Add a source log file for context (relevant to your Linux choice)
        "source_log": random.choice(["/var/log/auth.log", "/var/log/syslog", "/var/log/apache2/access.log"]),
        # Add a target user/system that was affected
        "target": random.choice(["root", "admin", "service_db", "web_server", "user_john"])
    }
    return incident

def generate_bulk_incidents(num_records, filename="incidents.json"):
    """
    Generates a list of incidents and writes them to a JSON file.
    """
    incidents_data = []
    
    # Start date for the first incident (e.g., a week ago)
    start_time = datetime.now() - timedelta(days=7)

    print(f"Generating {num_records} fake incidents...")
    
    for i in range(1, num_records + 1):
        incident = generate_incident(i, start_time)
        incidents_data.append(incident)
        
    print("Generation complete. Writing to file...")

    try:
        # Write the list of dictionaries to a JSON file
        with open(filename, 'w') as f:
            # Use 'indent=4' for a nicely formatted, readable JSON file
            json.dump(incidents_data, f, indent=4)
        
        print(f"Successfully created {filename} with {num_records} incident records.")
        print(f"Example record:\n{incidents_data[0]}")

    except Exception as e:
        print(f"An error occurred while writing the file: {e}")

# --- Configuration ---
# You can change the number of records you want to generate
NUM_RECORDS_TO_GENERATE = 5000 
# ---------------------

if __name__ == "__main__":
    # NOTE: You will need to install the 'faker' library first:
    # pip install Faker
    generate_bulk_incidents(NUM_RECORDS_TO_GENERATE)