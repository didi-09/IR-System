# 🛡️ Security Incident Detection & Response System  
## Project Documentation (Days 1, 3, 4 & 5)

---

# 📝 Day 1 – Setup & Architecture

This document summarizes the work completed for **Day 1** of the 7-day project plan, focusing on establishing the system architecture and defining the core data structures.

---

## 📅 Day 1 Goal Achieved

**Goal:**  
Create the environment and agree on the data format.

**Result:**  
The core infrastructure decisions were finalized, and the SQLite database foundation was established to match the agreed-upon Incident JSON structure.

---

## 📌 Crucial Architectural Decisions

| Decision Area | Choice | Rationale |
|--------------|--------|-----------|
| Work Split | **Parallel Tracks (Bayoumy & Didi)** | **Bayoumy (Engine):** OS interaction, log parsing, detection, containment. <br> **Didi (Brains):** Database, API, dashboard, alerts. |
| Database | **SQLite** | Lightweight, file-based DB for rapid prototyping with SQLAlchemy. |
| OS for Agent | **Linux** | Direct access to system logs such as `/var/log/auth.log`. |
| Dashboard / UI | **Streamlit** | Faster visualization and triage compared to Flask/HTML. |
| API Backend | **Flask** | Lightweight REST API (`POST /api/alert`) for incident ingestion. |

---

## 📂 Incident JSON Structure (Alert Payload)

| Key | Example | Description |
|----|--------|------------|
| `id` | `1` | Unique incident ID |
| `ip` | `"192.168.1.5"` | Source IP |
| `type` | `"Brute Force"` | Incident category |
| `severity` | `"High"` | Risk level |
| `timestamp` | `"2025-12-12T10:30:00"` | ISO 8601 timestamp |
| `source_log` | `"/var/log/auth.log"` | Source log file |
| `target` | `"user_john"` | Targeted user/service |
| `rule` | `"Failed Login Count Exceeded"` | Triggered rule |

---

## 💾 Database Schema Verification (`database.db`)

| Column | Type | Purpose |
|------|-----|---------|
| `id` | Integer (PK) | Incident ID |
| `ip` | String | Source IP |
| `type` | String | Incident type |
| `severity` | String | Severity level |
| `timestamp` | DateTime | Time of incident |
| `rule` | String | Triggered rule |
| `status` | String | Active / Closed |
| `source_log` | String | Log source |
| `target` | String | Targeted entity |

---

## ✅ Day 1 Conclusion

The architectural foundation for detection, ingestion, and persistence is complete.

---

# 🧠 Day 3 – Triage & Database Finalization (Critical Setup)

This day focused on implementing the **intelligence layer** and finalizing the **core backend infrastructure**.

---

## 🔹 Team Contributions

| Team Member | Task | Description |
|------------|------|-------------|
| Bayoumy | Rule Implementation | Implemented the first core detection rule (e.g., **3 failed logins in 60 seconds**). |
| Bayoumy | Data Collection | Collected incident metadata (IP, timestamp, PID, target user). |
| Didi | API Endpoint | Implemented `/api/alert` ingestion endpoint in `app.py`. |
| Didi | DB Finalization | Finalized SQLAlchemy `Incident` model and session management. |

---

## ✅ Day 3 Status

- Detection logic operational  
- API ingestion active  
- Database persistence finalized  

---

# 📊 Day 4 – Visualization (Didi)

The visualization layer was implemented using **Streamlit** to enable real-time incident monitoring and triage.

---

## Dashboard Features (`dashboard.py`)

| Feature | Description |
|-------|------------|
| Incident Display | Fetches and displays **Active Incidents** from the database. |
| Filtering | Allows filtering by **Severity** and **Date Range**. |

---

## ✅ Day 4 Status

The dashboard provides a clear, interactive view of system security posture.

---

# 🚨 Day 5 – Alerting & Containment

Day 5 focused on **automated alerting** and **containment groundwork**, completing the response phase.

---

## 5.1 Didi’s Backend – Alerting Implemented

The Flask backend was enhanced to trigger notifications for high-risk incidents.

### Changes

| File | Change | Description |
|----|------|------------|
| `app.py` | `send_notification()` | Simulates external alerts (Slack / Email) via console output. |
| `app.py` | `receive_alert()` | Triggers notifications for **High** or **Critical** severity incidents after DB save. |

**Status:** ✅ COMPLETE

---

## 5.2 Bayoumy’s Engine – Containment Duties

Automated response foundations were added to the detection engine.

### Containment Actions

| Task | Description |
|----|------------|
| Action 1 | Subprocess function to block IPs using `iptables`. |
| Action 2 | Subprocess function to kill suspicious processes using `kill`. |

*(Currently implemented in simulation mode for safety.)*

**Status:** ✅ COMPLETE

---

# ▶️ How to Run & Test (Didi’s System)

Use **three terminal windows**.

---

## 6.1 Start Backend API

```bash
/bin/python /home/kali/IR-Project/IR-System/server_backend/app.py

```
**Verify:**  
`Starting Flask API server...`

---

## 6.2 Start Dashboard

```bash
streamlit run /path/to/dashboard.py
```
**Verify:**

`A web browser should open automatically, displaying the Streamlit dashboard interface with incident data.`

---
## 6.3 Test Alert Ingestion and Notification
```bash
/bin/python /home/kali/IR-Project/IR-System/server_backend/test_client.py
```

**Verify:**

The API terminal (Backend) prints "NOTIFICATION SENT" for incidents with High or Critical severity.

The Streamlit dashboard updates instantly to display the new incident entry.


---
