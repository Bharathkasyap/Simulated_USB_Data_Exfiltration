<details><summary><strong>🧠 Click here to Understand DLP vs. Sentinel Detection Rules</strong></summary>

### 🔍 Why This Section?
Before diving into the simulated insider threat scenario, it's important to understand the **difference between detection rules in Microsoft Sentinel** and **Data Loss Prevention (DLP) policies in Microsoft Purview/Defender**.

---

### 🧩 Key Differences:

| Feature                        | Microsoft Sentinel Detection Rules                  | Microsoft Purview DLP Rules                             |
|-------------------------------|------------------------------------------------------|---------------------------------------------------------|
| **Goal**                      | Detect malicious/suspicious activity via logs       | Prevent sensitive data from leaving organization        |
| **Based on**                  | KQL queries on ingested logs (Defender, Sysmon, etc.) | Predefined policies, content inspection (e.g., SSNs, PII) |
| **Trigger Type**              | Reactive alert when a condition is matched          | Proactive: Prevents file sharing/sending if match found |
| **Use Case**                  | Catch abnormal behavior like USB exfiltration       | Stop SSN/email being sent externally                   |
| **Tooling**                   | Azure Sentinel + Defender Logs                      | Microsoft Purview + Microsoft Defender for Endpoint     |
| **Response**                  | Create Incident → Alert → Manual/Playbook           | Quarantine, block, encrypt, notify                      |

---

### 🛠️ What You’ll Learn in the Simulation

- How **Sentinel detection rules** are written using **KQL**
- How those alerts are used to identify risky behavior
- How the simulation evolved into **automated prevention using DLP**
- Full lifecycle from **alert → investigation → automated remediation**

---

📎 **Click below to view our educational reference file:**

[➡️ Learn More: DLP vs Sentinel Rule Guide](https://github.com/YourRepoName/Email_Security_Simulation_Azure/blob/main/Education/DLP_vs_Sentinel_Reference.md)

</details>









# 🔐 Simulated USB Data Exfiltration using Sysmon + Sentinel

## 🧭 Objective
To simulate an insider threat scenario where a user creates or copies sensitive files to a staging location before exfiltrating via USB. Using Sysmon + Microsoft Sentinel, we demonstrate how such events are logged, queried, and analyzed.

---

## 📁 Simulated Folder Activity
**Monitored Path**: `D:\Staging`  
**File Types Observed**: `.docx`, `.pdf`  
**Example Filenames**: `finance_notes.pdf`, `backup_policy.docx`, `meeting_summary.pdf`

---

## 📊 Sysmon Configuration Used
Sysmon Rule: [sysmonconfig.xml](https://github.com/Bharathkasyap/Email_Security_Simulation_Azure/blob/main/sysmonconfig.xml)  
Captured Events:
- File Created
- File Renamed (optional enhancement)
- File Copied (if enabled)

---

## 📋 Example KQL Query Used in Sentinel
```kql
DeviceFileEvents
| where FolderPath startswith "D:\\Staging"
| where FileName has_any("finance", "summary", "backup", "project")
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, FolderPath, ActionType
| order by Timestamp desc
```

---

## 📸 Screenshot of Detection

![File Detection Screenshot](images/MDE_Sentinel_USB_Capture.png)

---

## 🧠 MITRE ATT&CK Mapping

- [T1052.001 – Exfiltration over Removable Media](https://attack.mitre.org/techniques/T1052/001/)
- [TA0010 – Exfiltration](https://attack.mitre.org/tactics/TA0010/)

---

## 🔍 Alerting Process

1. Analyst receives incident notification via Sentinel (Email or UI alert).
2. KQL detection fires upon file creation in target directory.
3. File names & paths reviewed in **DeviceFileEvents** logs.
4. SOC correlates with user identity & endpoint session history.
5. Escalation initiated if policy breached.

---

## ✅ Incident Response Flow

- **Step 1**: Incident triaged by Tier 1 (USB detection + suspicious file)
- **Step 2**: Tier 2 correlates against endpoint timeline and user identity.
- **Step 3**: Device isolated or user session terminated (if configured).
- **Step 4**: IOC (filename hash/path) sent to Defender or TI team.
- **Step 5**: Final review & documentation stored in case manager.

---

## 🧪 Sample Log Output

| Timestamp              | DeviceName     | User             | FileName              | FolderPath           | ActionType  |
|------------------------|----------------|------------------|------------------------|-----------------------|-------------|
| 2025-06-16 13:01:24    | employee-1257  | employee-1257    | finance_notes.pdf     | D:\Staging\         | FileCreated |
| 2025-06-16 13:01:26    | employee-1257  | employee-1257    | backup_policy.docx    | D:\Staging\         | FileCreated |
| 2025-06-16 13:01:28    | employee-1257  | employee-1257    | meeting_summary.pdf   | D:\Staging\         | FileCreated |

---

## 📘 README Tips

> “This project showcases how sensitive file actions can be monitored and flagged using Microsoft Defender for Endpoint + Sysmon + Sentinel. Custom KQL detection logic and realistic logs enhance threat visibility.”

---
_Last updated: 2025-06-16 18:12:55_  












**Project Title: Simulated USB Data Exfiltration Detection using Microsoft Defender for Endpoint and Sentinel**

---

### 🔍 Objective

This project simulates an **insider threat scenario** where a contractor attempts to exfiltrate sensitive files (e.g., SSNs, finance documents) via a USB drive. The goal is to:

* Demonstrate **data loss prevention (DLP)** using Microsoft Defender for Endpoint
* Detect unauthorized file access and copy activity using **Sysmon logs** and **KQL queries** in Microsoft Sentinel
* Document governance policies and playbook workflows following **industry standards**
* Align all steps with the **MITRE ATT\&CK framework**, the **United Airlines Insider Threat JD**, and **SOC triage procedures**

---

### 🏢 Scenario Summary

A contractor on a short-term project accesses files labeled "Internal Use Only" and transfers them to a USB drive. The files contain sensitive financial or personal information.

* Device: Windows 10 VM (Employee-1257)
* File Types: `.docx`, `.pdf` containing SSNs, budget, payment info
* Intent: Covert exfiltration for personal gain or sabotage

---

### 🏘️ Architecture & Tools Used

| Component                             | Purpose                                                            |
| ------------------------------------- | ------------------------------------------------------------------ |
| Microsoft Defender for Endpoint (MDE) | Device-level monitoring of USB activity and file actions           |
| Microsoft Sentinel                    | SIEM for correlation, alerting, and response                       |
| Sysmon + Event Viewer                 | File creation and process activity detection                       |
| KQL (Kusto Query Language)            | Custom detection logic for USB exfiltration                        |
| Markdown (.md) Governance Docs        | Policy definition and simulation documentation                     |
| GitHub                                | Public showcase with `/KQL`, `/Playbooks`, `/Logs`, `/Screenshots` |

---

### 🪡 MITRE ATT\&CK Mapping

| Tactic     | Technique                                                                                       | Description                                        |
| ---------- | ----------------------------------------------------------------------------------------------- | -------------------------------------------------- |
| **TA0010** | [T1052.001 - Exfiltration over Removable Media](https://attack.mitre.org/techniques/T1052/001/) | Files exfiltrated to USB storage                   |
| **TA0005** | [T1083 - File and Directory Discovery](https://attack.mitre.org/techniques/T1083/)              | Lists files before exfiltration                    |
| **TA0009** | [T1560.001 - Archive via Utility](https://attack.mitre.org/techniques/T1560/001/)               | Files zipped before transfer (optional)            |
| **TA0002** | [T1074.001 - Local Data Staging](https://attack.mitre.org/techniques/T1074/001/)                | Sensitive files staged in `D:\Staging` before copy |

---

### 🤦️ Step-by-Step Implementation

#### ✅ Step 1: Configure Sysmon with USB & File Monitoring

* Used `sysmonconfig.xml` from SwiftOnSecurity
* Installed Sysmon on the endpoint:

  ```powershell
  Sysmon64.exe -accepteula -i sysmonconfig.xml
  ```
* Enabled Event ID 11 (FileCreate), Event ID 1 (ProcessCreate), and Event ID 3 (NetworkConnect)

#### ✅ Step 2: Simulate USB File Copy

* Files like `Employee_SSN.docx`, `payment_notes.pdf`, `internal_budget.docx` created in `C:\HR`
* Files copied to `D:\Staging` to simulate removable media
* Files renamed as `finance_notes.pdf`, `meeting_summary.pdf`

#### ✅ Step 3: Use Event Viewer to Confirm Sysmon Logs

* Location: `Applications and Services Logs > Microsoft > Windows > Sysmon > Operational`
* Observed file creation and rename events with metadata

#### ✅ Step 4: Log Ingestion in Sentinel

* Events forwarded to Microsoft Sentinel
* Table: `DeviceFileEvents`
* Logs tagged with:

  * DeviceName: employee-1257
  * ActionType: FileCreated/FileRenamed

#### ✅ Step 5: KQL Detection Logic

```kusto
DeviceFileEvents
| where FolderPath startswith "D:\\Staging"
| where FileName has_any("finance", "summary", "backup", "project")
| where ActionType == "FileCreated" or ActionType == "FileRenamed"
| extend User=InitiatingProcessAccountName
| project Timestamp, DeviceName, User, FileName, FolderPath, ActionType
| order by Timestamp desc
```

---

### 🏋️️ SOC Analyst Role Mapping (Daily Operations)

| Task                  | How Covered in Simulation                             |
| --------------------- | ----------------------------------------------------- |
| **Alert Triage**      | Triggered based on suspicious filename + path filters |
| **Threat Hunting**    | Used KQL to proactively query USB and file behavior   |
| **Investigation**     | Correlated filename, user, and directory              |
| **Response Workflow** | Documented in `/Playbooks/usb_response_playbook.md`   |

---

### 🚒 Incident Response Steps

1. **Detection Triggered** via Sentinel custom rule
2. **Email/Portal Notification** received by analyst
3. **Playbook Run**: Triage + ticket generated
4. **Investigate Device Logs**: Search for matching filenames, users
5. **Alert Escalation**: Notify HR or Insider Threat Team
6. **Remediate**: Block USB access, isolate machine
7. **Document**: IOC report, user behavior, timeline

---

### 🔒 Prevention Governance Policies (Documented)

* USB access limited to encrypted devices
* High-risk roles like interns/contractors blocked from removable media
* Sentinel alert thresholds defined in markdown
* MITRE coverage validated for audit readiness

---

### 🕊️ Value to Recruiters & Job Relevance

| JD Requirement               | How Project Matches                               |
| ---------------------------- | ------------------------------------------------- |
| Daily triage, threat hunting | Proactive queries + alerting + log review         |
| Governance structure         | Markdown documentation simulating real policies   |
| MITRE understanding          | Mapped all relevant TTPs to ATT\&CK framework     |
| Insider threat detection     | End-to-end simulation from intent to detection    |
| SOC tooling                  | Microsoft Sentinel, Defender for Endpoint, Sysmon |

---

### 🌟 Summary

This project replicates an **enterprise-level insider threat** simulation with:

* Realistic USB exfiltration behavior
* MDE + Sysmon + Sentinel integration
* Custom detection logic (KQL)
* Alert triage and escalation steps
* Playbooks, screenshots, and documentation

> Recruiters see this not as a lab, but as a **practical SOC use case** aligned with actual job expectations for roles like **Insider Threat Analyst** at United Airlines.










## 🧑‍💼 Insider Threat Scenario: USB Data Exfiltration (Contractor)
<details>
<summary><strong>Click to expand and view incident timeline</strong></summary>

### 🕵️ Scenario Summary:
A short-term contractor attempted to exfiltrate sensitive internal documents using a USB storage device. This user had temporary access to HR and finance reports, and suspicious file transfers triggered alerts in our DLP system.

---

### 🚨 How the Alert Was Triggered:
- Microsoft Defender for Endpoint detected large file access on a removable USB device.
- Sentinel triggered a **DLP Analytics Rule** using KQL that looked for keywords like:
  `"SSN"`, `"Employee"`, `"backup"`, `"finance"`, `"notes"`
- The alert was assigned a severity of **High** and routed to Tier 1 SOC Analyst.

---

### 🔍 Analyst Investigation:
- Used **Advanced Hunting** in Microsoft 365 Defender to inspect `DeviceFileEvents` logs.
- Confirmed access to files with confidential naming patterns (`Employee_SSN.docx`, `finance_notes.pdf`).
- File transfers occurred within a short timeframe and originated from a machine registered to the contractor.
- **Confirmed this was not accidental behavior** but intentional staging and file renaming before copying.

---

### 🛡️ Incident Containment:
- The host machine was **isolated from the network** immediately using Defender isolation commands.
- SOC team blocked

