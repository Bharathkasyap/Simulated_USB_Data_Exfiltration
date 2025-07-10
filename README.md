
## ✅ Insider Threat Scenario: USB Data Exfiltration

A contractor attempts to copy confidential HR and finance files to a USB drive. Our Sentinel detection rules trigger alerts based on log behavior, identifying this as a policy violation. However, because detection occurs **after** the attempt, it creates a gap in prevention.

To solve this, we implemented a simulated DLP policy using Microsoft Purview to **block** such actions **before** data exfiltration occurs. This shows the practical value of combining Sentinel detection with Purview prevention in real environments.

<details><summary><strong>🧠 Click here to Understand DLP vs. Sentinel Detection Rules</strong></summary>

### 🔍 Why This Section?
Before we dive into the simulated USB data exfiltration case, it's important to highlight why relying only on **detection rules like those in Microsoft Sentinel** isn’t enough. **Detection identifies threats after the damage begins.** This is why we extended this project with a full simulation of Microsoft Purview DLP, a preventive tool that actively stops data loss before it happens.

---

### 🧩 Key Differences:

| Feature                        | Microsoft Sentinel Detection Rules                  | Microsoft Purview DLP Rules                             |
|-------------------------------|------------------------------------------------------|---------------------------------------------------------|
| **Goal**                      | Detect malicious/suspicious activity via logs       | Prevent sensitive data from leaving organization        |
| **Based on**                  | KQL queries on ingested logs (Defender, Sysmon, etc.) | Predefined policies, content inspection (e.g., SSNs, PII) |
| **Trigger Type**              | Reactive alert when a condition is matched          | Proactive: Prevents file sharing/sending if match found |
| **Use Case**                  | Catch abnormal behavior like USB exfiltration       | Block exfiltration before it leaves the system          |
| **Tooling**                   | Azure Sentinel + Defender Logs                      | Microsoft Purview + Microsoft Defender for Endpoint     |
| **Response**                  | Create Incident → Alert → Manual/Playbook           | Block, alert, quarantine, notify automatically          |

---

### 🛠️ What You’ll Learn in the Simulation

- Why reactive detection rules cannot fully protect sensitive data
- How proactive DLP controls in Microsoft Purview enforce data protection
- The full SOC lifecycle: Sentinel alerts leading to triage and escalation
- The upgraded approach: Applying Microsoft Purview policies to automatically block unauthorized data transfers
- Practical insights into combining Sentinel’s visibility with Purview’s enforcement

📎 **Click below to view our reference file:**

[➡️ DLP vs Sentinel Rule Guide](src/DLP_Vs_Sentinel.md)

</details>

**[Data Exfiltration Steps](src/USB_Data_Exfiltration_Steps.md)**

---

## 🧪 Detection Rule in Sentinel: USB File Copy Alert

### 🎯 Goal:
Detect potential data exfiltration by monitoring USB file copy events involving sensitive HR and finance documents.

### Tools Used:

| Component                             | Role                                                     |
| ------------------------------------- | -------------------------------------------------------- |
| Microsoft Sentinel                    | Alerting based on KQL rules                              |
| Microsoft Defender for Endpoint (MDE) | Provides DeviceFileEvents data                           |
| Sysmon + Event Viewer                 | Monitors file system activities                          |
| KQL                                   | Custom logic for identifying suspicious file transfers   |

### 🔍 KQL Detection Logic:

```kusto
DeviceFileEvents
| where ActionType == "FileCopied"
| where AdditionalFields contains "RemovableMedia"
| where FileName has_any("SSN", "Finance", "HR", "Confidential")
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, FolderPath
```

**Alert Triggered For:**
- User: `contractor_user01`
- Device: `employee-1257`
- File: `Q2_Report.pdf` copied to `D:\Staging`

**Outcome:**
Sentinel created a high-severity alert. Tier 1 SOC triaged the alert, and Tier 2 confirmed exfiltration indicators. However, no preventive action occurred until after the copy was complete.

---

## 🚫 Sentinel Limitation

Detection was accurate but **not preventive**. The file was already on the USB drive when the alert triggered. This revealed a gap in protection — exposing how Sentinel can only **see** the violation after it starts, not stop it.

---

## ✅ Microsoft Purview DLP Enforcement Simulation

To address this gap, we built and simulated a Microsoft Purview DLP policy to enforce **real-time protection**.

### Goal:
Block file transfers containing PII or financial data from being copied to removable media by unauthorized users (contractors, interns, etc.).

### Simulated DLP Policy Details:

| Policy Name                         | USB_ConfidentialData_Block_Policy              |
| ---------------------------------- | --------------------------------------------- |
| Target Devices                     | Windows 10/11 endpoints with Defender onboard  |
| Monitored Content                  | SSNs, credit card numbers, HR/Finance terms    |
| Action                             | Block file transfer, notify user and SOC       |
| Exceptions                         | Security_Admins, Whitelisted_Contractors       |

**Result:**
When the contractor attempted the same file copy under this policy:
- Transfer was blocked before writing to USB
- User received a warning with policy details
- SOC was alerted with policy match context
- No data left the device

---

### 🔐 Log Output (Simulated Reference)

| Timestamp           | User               | FileName                  | ActionTaken | Policy Match             |
|--------------------|--------------------|---------------------------|-------------|--------------------------|
| 2025-06-17 11:05:12 | contractor_user01  | employee_ssn.docx         | Blocked     | USB_ConfidentialData_Block_Policy |
| 2025-06-17 11:07:33 | contractor_user01  | creditdata.pdf            | Blocked     | USB_ConfidentialData_Block_Policy |

---

## 🔁 Comparison Table: Sentinel vs Purview Outcomes

| Action                     | Sentinel Only                            | Sentinel + Purview                          |
|---------------------------|------------------------------------------|---------------------------------------------|
| Detects USB copy          | ✅ Yes (KQL-based alert)                  | ✅ Yes (via logs + DLP policy audit)         |
| Prevents USB transfer     | ❌ No                                     | ✅ Yes, DLP blocks real-time                 |
| Alerts SOC                | ✅ Yes                                     | ✅ Yes with DLP context                      |
| Notifies end user         | ❌ No                                     | ✅ Yes (policy tips)                         |
| Isolates endpoint         | Manual if configured                     | Manual or automatic via SOAR                |

---

## 🎯 Final Outcome & Takeaway

This project demonstrates the **need to go beyond detection**. While Sentinel detection rules are powerful for visibility and triage, they cannot **prevent** a data breach alone.

By implementing Microsoft Purview’s DLP policies, we:
- Blocked sensitive data transfers at runtime
- Closed the prevention gap in our SOC strategy
- Delivered both reactive alerts and proactive enforcement

---

## 📘 Summary for Reviewers

This project proves:

- Deep understanding of KQL and threat detection in Microsoft Sentinel
- Strong DLP strategy through Microsoft Purview policy design
- Ability to combine reactive alerts with preventive controls
- Readiness to work on real DLP environments for insider threat protection











## 🧪 USB Data Exfiltration Steps: Technical Procedure Documentation

This file documents each step we followed during the simulation of a USB-based data exfiltration attempt by a short-term contractor. The purpose is to simulate an insider threat scenario, capture behavioral logs using Sysmon, and detect the activity using Microsoft Sentinel.

---

### ✅ Phase 1: Environment and Log Configuration

#### 1. Setup Microsoft Entra ID (formerly Azure AD)

* **Why**: Ensures identity is linked to endpoint behavior, particularly for temporary users or contractors.
* **Action**:
  * Create a new user (e.g., `employee-1257`) in Entra ID.
  * Assign it to the test VM where simulation will take place.

#### 2. Onboard Device into Microsoft Defender for Endpoint (MDE)

* **Why**: MDE enables collection of security events (e.g., file transfers, USB activity) and forwards them to Sentinel.
* **Action**:
  * Download onboarding package from Microsoft 365 Defender portal.
  * Install on the test Windows 10 VM.
  * Confirm device appears in Microsoft 365 Defender portal.

#### 3. Enable Sysmon for Detailed Endpoint Logging

* **Why**: Sysmon provides deep telemetry (process creation, file access, USB usage).
* **Action**:
  * Download Sysmon from Sysinternals.
  * Create a config file named `sysmonconfig.xml` (customized to capture file creation and removable drive access).
  * Run in elevated PowerShell:
    ```powershell
    cd C:\Downloads
    .\Sysmon64.exe -accepteula -i sysmonconfig.xml
    ```
  * Confirm Sysmon service is running using `Get-Service sysmon64`

#### 4. Connect Sentinel to Collect Logs

* **Why**: To analyze events using KQL inside Microsoft Sentinel.
* **Action**:
  * Use Data Connector: "Windows Security Events via AMA" or "Sysmon via Log Analytics Agent"
  * Confirm ingestion of `DeviceFileEvents`, `SecurityEvent`, and Sysmon events.

---

### ✅ Phase 2: Simulate Data Exfiltration Attempt

#### 5. Create Sensitive Directory and Files

* **Why**: Mimics a real insider scenario where sensitive data is accessed and renamed for obfuscation.
* **Action**:
  * Open PowerShell as administrator.
    ```powershell
    cd C:\
    mkdir HR
    cd HR
    echo "Confidential Employee SSNs" > Employee_SSN.docx
    echo "Finance Quarterly Report" > finance_report.pdf
    ```

#### 6. Insert USB and Copy Files to D:\ Drive

* **Why**: This is the core exfiltration step.
* **Action**:
  * Connect USB drive (detected as `D:`).
  * Copy files:
    ```powershell
    Copy-Item C:\HR\* D:\Staging\
    ```

#### 7. Rename Files on USB for Obfuscation

* **Why**: Attackers often rename files to bypass detection.
* **Action**:
  * Navigate to `D:\Staging`
    ```powershell
    Rename-Item "Employee_SSN.docx" "employee_notes.docx"
    Rename-Item "finance_report.pdf" "credit_policy.pdf"
    ```

---

### ✅ Phase 3: Log Validation and Threat Detection

#### 8. Validate Logs Using Event Viewer

* **Why**: Confirm if Sysmon and MDE recorded file access and USB activity.
* **Action**:
  * Open Event Viewer → Applications and Services Logs → Microsoft → Windows → Sysmon → Operational
  * Look for **Event ID 11 (FileCreate)** and **Event ID 23 (FileCopy)**

#### 9. Run KQL Query in Sentinel

* **Why**: Simulate a SOC analyst detecting the exfiltration.
* **Action**:
  * Use Microsoft Sentinel > Logs > Run KQL:
    ```kql
    DeviceFileEvents
    | where ActionType == "FileCopied"
    | where FolderPath contains "D:\\"
    | where FileName endswith ".docx" or FileName endswith ".pdf"
    | project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, FolderPath, ActionType
    ```

#### 10. Capture Screenshots (To be added later)

* **Why**: Helps demonstrate each step visually.
* **Action**:
  * Capture Sysmon logs, Sentinel query results, USB drive content, and folder/file creation steps.

---

### 📌 Notes:

* This simulation mimics a real-world insider threat but is safe and controlled.
* Screenshots can be added later inside a `/Screenshots` folder.
* Project can be tied back to MITRE ATT\&CK TTPs such as:
  * T1052.001 (Exfiltration over Removable Media)
  * T1027 (Obfuscated Files or Information)

