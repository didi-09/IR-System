# 📝 Project Documentation: Day 1 - Setup & Architecture

This document summarizes the work completed for **Day 1** of the 7-day project plan, focusing on establishing the architecture and defining the crucial data structure.

---

## 📅 Day 1 Goal Achieved

**Goal:** Create the environment and agree on the data format.  
**Result:** The core infrastructure decisions were made, and the SQLite database foundation was set up to match the agreed-upon Incident JSON structure.

---

## 📌 Crucial Architectural Decisions

### **Decision Area Overview**

| Decision Area | Choice | Rationale |
|---------------|--------|-----------|
| Work Split | **Parallel Tracks (Bayoumy & Didi)** | **Bayoumy (The Engine):** OS interaction, reading logs, detection, containment. <br> **Didi (The Brains):** Database, Dashboard, Alerts. |
| Database | **SQLite** | Simple, file-based DB for rapid prototyping and easy Python integration (SQLAlchemy). |
| OS for Agent | **Linux** | Provides clear access to log files such as `/var/log/auth.log` for authentication events. |
| Dashboard/UI | **Streamlit** | Replaces Flask/HTML for faster dashboard development and visualization. |
| API Backend | **Flask** | Used to create the endpoint `POST /api/alert` for sending incident data from the agent to the server. |

---

## 📂 Incident JSON Structure (Alert Payload)

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

---

## 💾 Database Schema Verification (`database.db`)

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

