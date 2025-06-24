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

[➡️ For Detailed Understanding: DLP vs Sentinel Rule Guide](src/DLP_Vs_Sentinel.md)

</details>






## ✅ Insider Threat Scenario: USB Data Exfiltration by Contractor

### 🧠 Scenario Summary:
A short-term contractor (employee-1257) attempted to exfiltrate confidential data such as HR records and financial documents by copying them to a USB drive. Due to limited access, no real-time DLP prevention tools like Microsoft Purview were available. However, the attempt was successfully detected through custom KQL rules in Azure Sentinel, showcasing a strong understanding of detection methodologies and proactive security monitoring.

### 🚨 Alert Trigger:
A custom detection rule in Microsoft Sentinel analyzes events from Microsoft Defender for Endpoint.

### Alert triggered on:

- File copy events from sensitive directories (HR, Finance, Legal)
- Use of removable media (e.g., D:\Staging)
- Match with sensitive filename patterns (e.g., Employee_SSN.docx)

**Actor:** Known temp account with elevated file access

**[For Simulation Steps](src/simulation.md)**

### 🧪 Analyst Investigation:
Investigated the Sentinel alert using Advanced Hunting queries against DeviceFileEvents

${{\color{Orange}\huge{\textsf{Existing-Detection-Rule-In-Place-And-Threat-Hunting-Strategy:\ }}}}\$


<details> <summary><strong>Click here expand</strong></summary>

## 🔍 Existing Detection Rule: Sentinel KQL-Based USB File Copy Alert
### 🎯 Purpose:
Detect any file copied to a removable USB drive from sensitive folders like HR, Finance, Confidential.

---

### 🏢 Threat Summary

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


### 📄 Rule Location:
Microsoft Sentinel

**Analytics Rule Name:** USB_Sensitive_File_Copy_Detection

**Data Source Table:** DeviceFileEvents

### 🧠 KQL Detection Logic:

```kusto
DeviceFileEvents
| where ActionType == "FileCopied"
| where AdditionalFields contains "RemovableMedia"
| where FileName has_any ("SSN", "credit", "HR", "finance", "Confidential")
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, FolderPath, ActionType
```
---


### 📌 Explanation:

- ActionType == "FileCopied": Focuses only on actual data movement.
- RemovableMedia: Ensures USB is involved.
- Filename filter: Triggers only if files suggest sensitive content.
- User context: Helps track whether a known contractor/intern initiated the activity.

### 🚨 Triggered Alert Summary
**🕒 Alert Timestamp:** 2025-06-15 13:24:55 UTC

### 📢 Alert Generated:

- Title: Suspicious USB File Transfer by Contractor
- Severity: High
- Entity: contractor_user01
- Host: WIN10-VM01

### 📁 Involved File:
- C:\HR\Q2_Report.pdf
- FileType: .pdf
- Target: D:\Staging\Employee_SSN_Report.pdf

---

## 🧪 Sample Log Output

| Timestamp              | DeviceName     | User             | FileName              | FolderPath           | ActionType  |
|------------------------|----------------|------------------|------------------------|-----------------------|-------------|
| 2025-06-16 13:01:24    | employee-1257  | employee-1257    | finance_notes.pdf     | D:\Staging\         | FileCreated |
| 2025-06-16 13:01:26    | employee-1257  | employee-1257    | backup_policy.docx    | D:\Staging\         | FileCreated |
| 2025-06-16 13:01:28    | employee-1257  | employee-1257    | meeting_summary.pdf   | D:\Staging\         | FileCreated |

---

### 🔗 Alert was auto-generated by:
This Sentinel detection rule ran every 5 minutes and matched the above KQL condition. The match occurred once the file Q2_Report.pdf was copied to the USB.


### 🧠 How the Analyst Received the Alert

- Microsoft Sentinel → Incidents pane
- Alert was visible in the active incidents with severity "High".
- Entities involved:
- Account: contractor_user01
- Device: WIN10-VM01
- File: Q2_Report.pdf

---

### Alert Workflow (automated):

- Triggered a Sentinel analytics rule.
- Automatically created an incident.
- Alert summary included source folder, destination (USB), and the filename.
- Email/Teams notification was sent to SOC team (if SOAR playbook enabled).


```kusto
DeviceFileEvents
| where InitiatingProcessAccountName == "contractor_user01"
| where FolderPath has_any ("HR", "Finance", "Confidential")
| where AdditionalFields contains "RemovableMedia"
| project Timestamp, FileName, FolderPath, ActionType
```

### 🧠 Hypothesis

"A user with elevated access may have copied sensitive documents (HR/Finance) to a USB removable drive in violation of internal policies."

### 🛠️ Environment Prerequisites

- Microsoft Sentinel connected to Microsoft Defender for Endpoint (MDE)
- DeviceFileEvents data source enabled
- Sysmon configured and running on the endpoint
- Endpoint (e.g., Windows 10 VM) simulates internal user behavior

### 🔍 Step-by-Step Threat Hunt Process

### ✅ Step 1: Narrow Search to USB Write Events

We begin by looking for file copy actions to USB media.

```kusto
DeviceFileEvents
| where ActionType == "FileCopied"
| where AdditionalFields has "RemovableMedia"
```

### ✅ Step 2: Add Filters for File Sensitivity

Add filename filters to detect high-value data (HR, Finance, SSNs, etc.)

```kusto
| where FileName has_any("HR", "SSN", "Finance", "Employee", "Salary", "Report")
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, FolderPath, ActionType
```

### ✅ Step 3: Identify Risky User Accounts

Hone in on contractor or intern accounts.

```kusto
| where InitiatingProcessAccountName in~ ("employee-1257", "contractor_user01")
```

### ✅ Step 4: Observe File Destination Path

Check if copied files went to D: or other removable drive letters.

```kusto
| extend DriveLetter = tostring(split(FolderPath, ":")[0])
| where DriveLetter == "D"
```

### ✅ Step 5: Detect Obfuscation or Renaming

Check if sensitive file content was renamed with misleading names.

```kusto
| where FileName has_any("payment_details", "image", "backup", "info")
```

---

### 📌 Additional Techniques

- Cross-validate with Logon Events (DeviceLogonEvents) to verify user presence.
- Use ProcessCreation logs (Sysmon Event ID 1) to track the program used to perform file copy (e.g., Explorer.exe, cmd.exe).
- Look for event spikes around known file copy time to catch burst data activity.

---

### 📤 Output & Hunting Dashboard

- Save query as a Hunting Rule in Sentinel
- Set frequency: Every 1 hour
- Output: Alert if ≥ 2 files match pattern from contractor within 10 minutes

---

### 👁️‍🗨️ Initial Analyst Response (Tier 1/Tier 2)

- Opened alert → Clicked on “Investigate” tab.
- Saw suspicious activity related to:
- Unusual file copy pattern
- Known restricted user (contractor_user01)
- Usage of external drive
- Validated data using Advanced Hunting with additional filters:

---

### ✅ Final Goal of This Threat Hunt

- Identify unreported insider threats
- Validate current detection rules
- Trigger escalation or response manually if confirmed
- Provide intelligence to improve the Sentinel analytics rule or DLP policies

---

## ✅ Incident Response Flow

- **Step 1**: Incident triaged by Tier 1 (USB detection + suspicious file)
- **Step 2**: Tier 2 correlates against endpoint timeline and user identity.
- **Step 3**: Device isolated or user session terminated (if configured).
- **Step 4**: IOC (filename hash/path) sent to Defender or TI team.
- **Step 5**: Final review & documentation stored in case manager.

---


### 🪡 MITRE ATT\&CK Mapping

| Tactic     | Technique                                                                                       | Description                                        |
| ---------- | ----------------------------------------------------------------------------------------------- | -------------------------------------------------- |
| **TA0010** | [T1052.001 - Exfiltration over Removable Media](https://attack.mitre.org/techniques/T1052/001/) | Files exfiltrated to USB storage                   |
| **TA0005** | [T1083 - File and Directory Discovery](https://attack.mitre.org/techniques/T1083/)              | Lists files before exfiltration                    |
| **TA0009** | [T1560.001 - Archive via Utility](https://attack.mitre.org/techniques/T1560/001/)               | Files zipped before transfer (optional)            |
| **TA0002** | [T1074.001 - Local Data Staging](https://attack.mitre.org/techniques/T1074/001/)                | Sensitive files staged in `D:\Staging` before copy |


---

### 🏋️️ SOC Analyst Role Mapping (Daily Operations)

| Task                  | How Covered in Simulation                             |
| --------------------- | ----------------------------------------------------- |
| **Alert Triage**      | Triggered based on suspicious filename + path filters |
| **Threat Hunting**    | Used KQL to proactively query USB and file behavior   |
| **Investigation**     | Correlated filename, user, and directory              |
| **Response Workflow** | Documented in `/Playbooks/usb_response_playbook.md`   |

---

### 🔒 Prevention Governance Policies (Documented)

* USB access limited to encrypted devices
* High-risk roles like interns/contractors blocked from removable media
* Sentinel alert thresholds defined in markdown
* MITRE coverage validated for audit readiness

---

### 🕊️ Value to Reviewers & Job Relevance

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

---


## 📘 README Tips

> “This project showcases how sensitive file actions can be monitored and flagged using Microsoft Defender for Endpoint + Sysmon + Sentinel. Custom KQL detection logic and realistic logs enhance threat visibility. Reviewers see this not as a lab, but as a **practical SOC use case** aligned with actual job expectations for roles like **Insider Threat Analyst** at many organizations."



</details>

---

### Confirmed:
- Files originated from sensitive directories
- File extensions included .pdf, .docx, .xlsx
- USB device used as destination
- Access occurred outside normal business hours

### ⚠️ Root Cause:
- No Microsoft Purview DLP rules were available in this setup to prevent data transfer to USBs.
- Detection was post-event, highlighting a gap in proactive controls.
- Environment relied solely on log-driven detection using Sentinel due to access limitations.

### 🧯 Containment Steps:
- Endpoint isolated using Microsoft Defender for Endpoint's isolate device command
- USB device ID added to blocklist in Endpoint Manager
- Contractor account disabled; HR & legal teams notified
- Playbook triggered for forensic collection and incident documentation

### 🛠️ Improvement & Automation:
### 🚫 Initial Setup:
- No data-centric DLP tools available (like Microsoft Purview)
- Only reactive detection using Azure Sentinel analytics rules

### ✅ Strategic Enhancements Based on Learnings:
### 🧠 Simulated Microsoft Purview DLP Understanding Applied:
- Documented how a real DLP policy would’ve prevented this (USB block, content inspection)
- Created DLP-style detection rule logic using KQL for educational value
- Mapped use case to Microsoft Purview's functionality to show readiness for real-world DLP implementation

### 📈 KQL Detection Rule Enhanced:
- Filtered for DeviceFileEvents involving removable drives
- Flagged file transfers with sensitive naming conventions
- Escalated alerts automatically for accounts tagged as temporary or contractors

### ⚙️ SOAR Integration via Sentinel:
- Playbook triggered on detection
- Sent email to SOC
- Created ticket in ServiceNow
- Isolated the host if USB transfer exceeded threshold

### ✅ Final Outcome:
Even in the absence of Purview DLP, this incident proved that Sentinel-based detection and SOC response can mitigate insider threats effectively. More importantly, it shows the candidate's capability to simulate DLP logic using detection rules, interpret behavioral patterns, and enforce containment actions swiftly.

### Before:

- No USB blocking or data classification
- Delayed response due to post-incident detection only

### After:

- Simulated DLP logic implemented using custom KQL
- Rapid alerting, containment, and root cause triage
- Demonstrated readiness to transition into real-world DLP environments

### 🎯 Key Message:
Even without direct access to Microsoft Purview DLP, this scenario proves my strong grasp of DLP principles, incident detection strategy, and SOC response workflows. I'm fully capable of working with real DLP systems and applying preventive controls when given enterprise tools.

### Let's simulate the setup of the DLP tool Purview 

<details> <summary><strong>Click here expand</strong></summary>


### ✅ Microsoft Purview DLP Policy Simulation

### 🎯 Goal

Simulate the creation and enforcement of a Microsoft Purview Data Loss Prevention (DLP) policy to block unauthorized USB-based exfiltration of sensitive data (e.g., SSNs, credit card info, HR documents).

---

### 🛠️ Step-by-Step: Creating a DLP Policy

#### Step 1: Navigate to Microsoft Purview Compliance Portal

* Go to: [https://compliance.microsoft.com](https://compliance.microsoft.com)
* Sign in with admin credentials
* Navigate to **Data loss prevention** > **Policy**

#### Step 2: Click on **Create Policy**

* Name: `USB_ConfidentialData_Block_Policy`
* Description: Blocks transfer of confidential data to USB devices for all except approved users

#### Step 3: Select **Custom Policy** > **Devices** as location

* Target data in **Windows 10/11 endpoints**

<div align="center">
<img src =src/DLP_Policy.png width="300">
</div>
 </br>

#### Step 4: Define Conditions:

* **Content contains:**

  * U.S. Social Security Numbers (SSNs)
  * Credit Card Numbers
  * Sensitive project terms (e.g., "Internal Use Only")

#### Step 5: Define Actions:

* Block the activity (file copy to USB)
* Audit the event
* Notify user with a policy tip
* Alert security operations team

#### Step 6: Assign Policy Scope:

* Apply to:

  * All users except `Security_Admins`, `Approved_Contractors`

#### Step 7: Review & Publish

* Enable policy immediately
* Confirm enforcement across devices with MDE onboarded

---

### 🔔 Simulated DLP Alert Notification

<div align="center">
<img src =src/DLP_Notif.png width="300">
</div>
 </br>

> **Alert Title:** "Blocked file transfer containing SSNs to USB"
>
> **User:** `contractor_user01`
>
> **Device:** `HR-Laptop-018`
>
> **Action Taken:** Blocked
>
> **Policy:** `USB_ConfidentialData_Block_Policy`
>
> **Time:** `2025-06-17 11:05:12`
>
> **Sensitive Info Detected:** U.S. SSN, Keyword Match: "Internal Use Only"

---

### 📄 Dummy Log Sample

| Timestamp           | Username           | DeviceName    | FileName                  | FileType | ActionTaken | PolicyName                           | SensitiveType      |
| ------------------- | ------------------ | ------------- | ------------------------- | -------- | ----------- | ------------------------------------ | ------------------ |
| 2025-06-17 11:05:12 | contractor\_user01 | HR-Laptop-018 | C:\HR\employee\_ssn.docx  | .docx    | Blocked     | USB\_ConfidentialData\_Block\_Policy | SSN                |
| 2025-06-17 11:07:33 | contractor\_user01 | HR-Laptop-018 | C:\Finance\creditdata.pdf | .pdf     | Blocked     | USB\_ConfidentialData\_Block\_Policy | Credit Card Number |

---

### ✅ Outcome of Enforcement

* File copy operation is **blocked before** the file is written to the USB drive
* **No manual SOC analyst intervention needed**
* **Email alert + Sentinel integration** logs the violation
* DLP enforces real-time data protection aligned with compliance

---

### 📘 Summary

This simulation demonstrates:

* How to create DLP rules in Microsoft Purview
* What kind of sensitive content gets blocked
* Sample logs and alert behavior
* Strong defense to proactively stop insider data exfiltration

Use this as a dedicated `.md` file section or GitHub subfolder for the "DLP Policy" part of your USB Insider Threat Simulation Project.



</details>

---

