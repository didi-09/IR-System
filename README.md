<<<<<<< HEAD
# 🛡️ Security Incident Detection & Response System  
## Project Documentation (Days 1 & 5)

---

# 📝 Day 1 – Setup & Architecture

This document summarizes the work completed for **Day 1** of the 7-day project plan, focusing on establishing the system architecture and defining the core data structures.
=======
# 📝 Project Documentation: Day 1 - Setup & Architecture

This document summarizes the work completed for **Day 1** of the 7-day project plan, focusing on establishing the architecture and defining the crucial data structure.
>>>>>>> f8a33625f4f67229b20ee867c83b0562101a2b13

---

## 📅 Day 1 Goal Achieved

<<<<<<< HEAD
**Goal:**  
Create the environment and agree on the data format.

**Result:**  
The core infrastructure decisions were finalized, and the SQLite database foundation was established to match the agreed-upon Incident JSON structure.
=======
**Goal:** Create the environment and agree on the data format.  
**Result:** The core infrastructure decisions were made, and the SQLite database foundation was set up to match the agreed-upon Incident JSON structure.
>>>>>>> f8a33625f4f67229b20ee867c83b0562101a2b13

---

## 📌 Crucial Architectural Decisions

<<<<<<< HEAD
| Decision Area | Choice | Rationale |
|---------------|--------|-----------|
| Work Split | **Parallel Tracks (Bayoumy & Didi)** | **Bayoumy (The Engine):** OS interaction, log parsing, detection, containment. <br> **Didi (The Brains):** Database, API, dashboard, alerts. |
| Database | **SQLite** | Lightweight, file-based database for rapid prototyping with SQLAlchemy integration. |
| OS for Agent | **Linux** | Direct access to system logs such as `/var/log/auth.log`. |
| Dashboard / UI | **Streamlit** | Chosen over Flask/HTML for rapid visualization and dashboard iteration. |
| API Backend | **Flask** | Lightweight REST API (`POST /api/alert`) to receive incidents from the detection engine. |
=======
### **Decision Area Overview**

| Decision Area | Choice | Rationale |
|---------------|--------|-----------|
| Work Split | **Parallel Tracks (Bayoumy & Didi)** | **Bayoumy (The Engine):** OS interaction, reading logs, detection, containment. <br> **Didi (The Brains):** Database, Dashboard, Alerts. |
| Database | **SQLite** | Simple, file-based DB for rapid prototyping and easy Python integration (SQLAlchemy). |
| OS for Agent | **Linux** | Provides clear access to log files such as `/var/log/auth.log` for authentication events. |
| Dashboard/UI | **Streamlit** | Replaces Flask/HTML for faster dashboard development and visualization. |
| API Backend | **Flask** | Used to create the endpoint `POST /api/alert` for sending incident data from the agent to the server. |
>>>>>>> f8a33625f4f67229b20ee867c83b0562101a2b13

---

## 📂 Incident JSON Structure (Alert Payload)

<<<<<<< HEAD
This JSON format is used by Bayoumy’s detection engine and ingested by Didi’s API.

| Key | Example Value | Description | Data Type |
|----|-------------|-------------|-----------|
| `id` | `1` | Unique incident identifier | Integer |
| `ip` | `"192.168.1.5"` | Source IP address | String |
| `type` | `"Brute Force"` | Incident category | String |
| `severity` | `"High"` | Risk level | String |
| `timestamp` | `"2025-12-12T10:30:00"` | Time of event (ISO 8601) | String |
| `source_log` | `"/var/log/auth.log"` | Origin log file | String |
| `target` | `"user_john"` | Targeted user or service | String |
| `rule` | `"Failed Login Count Exceeded"` | Triggered detection rule | String |
=======
This is the agreed JSON structure for alerts sent by Bayoumy’s detection agent and ingested by the Flask API.

| Key | Example Value | Description | Data Type |
|-----|---------------|-------------|-----------|
| `id` | `1` | Unique identifier for the incident. | Integer |
| `ip` | `"192.168.1.5"` | Source IP address that triggered the event. | String |
| `type` | `"Brute Force"` | High-level category of the threat. | String |
| `severity` | `"High"` | Level of risk associated with the incident. | String |
| `timestamp` | `"2025-12-12T10:30:00"` | Time the incident occurred (ISO 8601). | String |
| `source_log` | `"/var/log/auth.log"` | Log file where the event was detected. | String |
| `target` | `"user_john"` | Affected user or service. | String |
| `rule` | `"Failed Login Count Exceeded"` | Detection rule that was triggered. | String |
>>>>>>> f8a33625f4f67229b20ee867c83b0562101a2b13

---

## 💾 Database Schema Verification (`database.db`)

<<<<<<< HEAD
The SQLite database table `incidents` was created using **SQLAlchemy** (`models.py`) and maps directly to the JSON structure.

| Column Name | SQLAlchemy Type | JSON Field | Purpose |
|------------|----------------|------------|---------|
| `id` | Integer (PK) | `id` | Primary key |
| `ip` | String | `ip` | Source IP |
| `type` | String | `type` | Incident type |
| `severity` | String | `severity` | Severity level |
| `timestamp` | DateTime | `timestamp` | Incident time |
| `rule` | String | `rule` | Triggered rule |
| `status` | String | N/A | Incident state (Active / Closed) |
| `source_log` | String | `source_log` | Log source |
| `target` | String | `target` | Targeted entity |

---

## ✅ Day 1 Conclusion

The foundational architecture for **detection, ingestion, and persistence** is fully established.

---

# 🚨 Day 5 – Response & Notification

Day 5 focused on implementing **automated response and notification mechanisms**, completing the core response requirements for both system components.

---

## 1️⃣ Didi’s Backend – Alerting Implemented

The Flask backend (`app.py`) was enhanced to support automated notifications when high-risk incidents are ingested.

### Changes Summary

| File | Change | Description |
|----|------|------------|
| `app.py` | **New Function:** `send_notification(incident_details)` | Simulates sending external alerts (Slack / Email). Currently prints a high-priority alert to the server console. |
| `app.py` | **Integration in** `receive_alert()` | After saving an incident, the API checks severity. If severity is **High** or **Critical**, notification is triggered immediately. |

### Status  
✅ **COMPLETE**  
The backend now ingests incidents, stores them in the database, and triggers alerts for high-severity threats.

---

## 2️⃣ Bayoumy’s Engine – Containment Functions

The detection engine (`detection_script.py`) was extended with automated containment capabilities using Python’s `subprocess` module.

### Changes Summary

| File | Change | Description |
|----|------|------------|
| `detection_script.py` | **Function:** `block_ip(ip_address)` | Executes an `iptables` command to block malicious IPs (currently simulated). |
| `detection_script.py` | **Function:** `kill_process(pid)` | Executes `kill -9` to terminate suspicious processes (currently simulated). |

### Status  
✅ **COMPLETE**  
Containment mechanisms are implemented and tested in simulation mode, ready for integration with detection rules.

---

## 🔄 Next Step – Day 6: Integration (The “Merge”)

With detection, storage, alerting, and response mechanisms ready, the next phase is full system integration:

- Bayoumy will update `detection_script.py` to send incidents via **POST** to Didi’s API.
- An end-to-end test will be executed:
=======
The `incidents` table was created using **SQLAlchemy** inside `models.py`.  
Each field is mapped directly from the JSON structure.

| Column Name | SQLAlchemy Type | JSON Field | Description |
|-------------|-----------------|------------|-------------|
| `id` | Integer (Primary Key) | `id` | Unique incident ID. |
| `ip` | String | `ip` | Source IP of attack. |
| `type` | String | `type` | Threat category. |
| `severity` | String | `severity` | Incident severity level. |
| `timestamp` | DateTime | `timestamp` | Time of incident. |
| `rule` | String | `rule` | Triggered rule (required by plan). |
| `status` | String | N/A | Current incident status (Active, Closed). |
| `source_log` | String | `source_log` | Log file source. |
| `target` | String | `target` | Targeted user or system. |

---

## ✅ Conclusion

Day 1 is completed successfully.  
The foundation for **data persistence**, **alert ingestion**, and **overall architecture** has been established.

---

## ▶️ Next Step

### **Proceed to Day 3: Triage & Storage**
Implementing the `POST /api/alert` API endpoint in `app.py`.
>>>>>>> f8a33625f4f67229b20ee867c83b0562101a2b13

