
## 🧪 USB Data Exfiltration: Technical Procedure Documentation

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

### ✅ Phase 2: Data Exfiltration Attempt

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
* Project can be tied back to MITRE ATT&CK TTPs such as:

  * T1052.001 (Exfiltration over Removable Media)
  * T1027 (Obfuscated Files or Information)

---

This file documents everything needed to explain the simulation during interviews, in documentation, or on GitHub.
