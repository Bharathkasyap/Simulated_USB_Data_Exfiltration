# 📘 DLP vs. Azure Sentinel Detection Rules – Deep Dive for Reviewers

> This document serves as a learning and demonstration guide to show my understanding of **Data Loss Prevention (DLP)** and **Azure Sentinel Detection Rules**, despite not having direct enterprise-level access to Microsoft Purview.

---

## 🧠 Introduction: Why This Document Matters

Many showcase only hands-on detection work with tools like **Azure Sentinel**, but **this file is meant to demonstrate that I understand both detection and prevention strategies.**

Even without direct Purview access, I have broken down:
- The key differences between DLP and Sentinel analytics rules
- The logic behind both technologies
- The hands-on process to create a **DLP rule**

---

## 🤔 What Is the Difference Between DLP and Sentinel Detection Rules?

While both aim to improve organizational security posture, **they work in different layers and serve different purposes.**

| Feature | Azure Sentinel Detection Rules (Analytics) | Data Loss Prevention (DLP) Rules |
|--------|---------------------------------------------|-----------------------------------|
| **Goal** | Detect threats, anomalies, suspicious behavior | Prevent data exfiltration (accidental or intentional) |
| **Focus** | Logs, events, user behavior, system activities | Sensitive data itself (e.g., PII, credit cards) |
| **How It Works** | Uses KQL queries to analyze and correlate logs | Uses content inspection and policy-based controls |
| **Response Type** | Triggers alert, incident, automation | Blocks, encrypts, warns, or logs sensitive data movement |
| **Scope** | Entire digital environment (multi-system) | Specific locations like Exchange, OneDrive, SharePoint, endpoints |
| **Tools** | Azure Sentinel, Defender for Endpoint | Microsoft Purview, Endpoint DLP, M365 apps |

---

## 🛡️ Why Sentinel Cannot Replace Purview DLP

- **Sentinel is powerful for detection**, but **lacks deep content inspection** and cannot block the action.
- **Purview is specialized for prevention**, allowing the organization to inspect actual content, detect sensitive patterns, and **stop** risky actions.
- Sentinel reacts after an event has occurred (e.g., copying to USB), while DLP stops the copy altogether.

> 👉 **In summary:** Sentinel = Detect & Alert | DLP = Prevent & Educate

---

## ✅ Justifying My Current Project Scope

My current project focuses on the **detection phase** using **Azure Sentinel analytics rules** and **Microsoft Defender for Endpoint logs**. With limited access to enterprise DLP tools like Purview, I chose to simulate **insider threat scenarios** and build custom detection logic using **KQL queries** to identify exfiltration attempts.

Despite not directly using DLP tools, this project prepares me to:
- Ingest DLP alerts into Sentinel
- Correlate DLP violations with broader threat activities
- Support automation of responses using Sentinel playbooks

This hands-on foundation is easily transferable to Purview-based DLP enforcement in real-world SOC teams.

---

## 🛠️ Step-by-Step: Creating a DLP Policy in Microsoft Purview

### 🎯 Goal:
Prevent sending emails with **credit card numbers** to external users via **Exchange Online**.

### 📌 Prerequisites:
- Microsoft 365 E5 or Purview license
- Admin permissions (Compliance or Security Admin)
- Any sensitive data you want to protect (e.g., "Credit Card Number: 1234-5678-9012-3456")

### 🪜 Steps:

1. **Go to**: [Microsoft Purview portal](https://compliance.microsoft.com/)
2. **Navigate to** → Data loss prevention → Policies → **Create policy**
3. **Select Template** → Financial → U.S. Financial Data → Next
4. **Name your policy** → "Block Credit Card External" (You can choose any)
5. **Apply to** → Exchange email only
6. **Choose advanced setup** → Customize advanced DLP rules
7. **Create Rule**:
   - Name: `Block external sharing of Credit Card Number`
   - Condition: Content contains `Sensitive Info Type: Credit Card Number`
   - Action: `Block users from sending email externally`
   - User Notification: On, notify sender
   - Admin Alert: On, send to Security Admin

8. **Save the Rule** → Proceed → Policy Mode: `Simulation Mode`
9. **Test the Policy**: Send a test email to external user with fake credit card numbers
10. **Review Alerts** in Purview → `Data loss prevention > Alerts`

---

## 🔄 What You Can Still Do Without Purview

Using **Sentinel + Defender for Endpoint**, students or entry-level analysts can still:

- Detect **file transfers to USBs**
- Monitor **mass downloads**
- Alert on **abnormal outbound network traffic**

Here’s a basic KQL for detecting mass file copy to USB:

```kql
DeviceEvents
| where ActionType == "FileCreated"
| where InitiatingProcessFileName in~ ("explorer.exe", "cmd.exe")
| where AdditionalFields has "USB"
| summarize FileCount = count() by DeviceName, InitiatingProcessAccountName, bin(TimeGenerated, 1h)
| where FileCount > 100
```

> ❗ This **detects** the activity, but cannot **block** it. That's the core DLP vs Detection difference.

---

## 🚀 Conclusion

- I’ve worked extensively with **Azure Sentinel detection rules**.
- I **understand how Purview DLP policies work**, even without direct access.
- I can **correlate**, **triage**, **alert**, and even **simulate** data exfiltration scenarios.

This project showcases my readiness to work with DLP environments and SIEM tools—making me a strong fit for cybersecurity teams focused on **data security and insider threat prevention.**

---

📎 [Back to Project Scenario](../README.md)
