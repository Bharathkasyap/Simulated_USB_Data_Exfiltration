
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
