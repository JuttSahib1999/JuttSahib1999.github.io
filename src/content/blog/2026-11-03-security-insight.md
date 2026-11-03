---
title: "Detecting Kerberoasting Attacks: Active Directory Telemetry, Ticket Requests, and Detection Strategies"
description: "An in-depth guide on how Kerberoasting works in Active Directory, key telemetry from Windows Event ID 4769, and practical detection logic to spot ticket harvesting."
date: "2026-11-03"
tags: ["Active Directory", "Detection Engineering", "Security Operations", "Threat Detection"]
category: "Cyber Security"
difficulty: "Intermediate"
author: "Abdul Muqeet Tabraiz"
image: "/images/blog/2026-11-03-detecting-kerberoasting-attacks-active-directory-telemetry-ticket-requests-and-d.svg"
---

Kerberoasting remains one of the most reliable post-exploitation techniques used by attackers inside Active Directory (AD) environments. It requires no elevated privileges, produces minimal noisy endpoint indicators, and abuses legitimate features of the Kerberos authentication protocol. Because any valid domain user can request a Kerberos Ticket Granting Service (TGS) ticket for any service account with a Service Principal Name (SPN), traditional access controls will not block the activity by default.

For security operations teams and detection engineers, catching Kerberoasting requires an understanding of Active Directory domain controller event logging, Kerberos encryption types, and normal service behavior in your network.

---

## How Kerberoasting Works

To understand the telemetry Kerberoasting generates, we first need to look at how Kerberos handles service requests.

1. **Authentication Service Request (AS-REQ / AS-REP):** A user authenticates to the Key Distribution Center (KDC) on a Domain Controller and receives a Ticket Granting Ticket (TGT).
2. **Ticket Granting Service Request (TGS-REQ):** When the user wants to access a service registered in Active Directory (like a SQL server or web application), their client sends a `TGS-REQ` message to the KDC requesting a ticket for that service's SPN.
3. **Ticket Granting Service Reply (TGS-REP):** The KDC checks if the SPN exists. If valid, the KDC issues a `TGS-REP` containing an encrypted service ticket. Crucially, this ticket is encrypted using the password hash of the service account associated with that SPN.
4. **Offline Cracking:** The attacker extracts the encrypted ticket blob from memory or network traffic and takes it offline. They use tools like Hashcat or John the Ripper to brute-force the password hash. The Domain Controller is never contacted during the cracking phase, meaning failed password attempts do not trigger account lockouts.

If the service account relies on a weak, user-defined password, an attacker can recover the plaintext password in minutes or hours and gain full access to the underlying service and system.

---

## Key Telemetry: Windows Event ID 4769

The primary source of telemetry for detecting Kerberoasting is **Event ID 4769** (*A Kerberos service ticket was requested*) generated on Domain Controllers.

To capture this event, audit policies on your Domain Controllers must have **Audit Kerberos Service Ticket Operations** set to audit **Success** (and optionally **Failure**).

### Key Fields in Event ID 4769

When reviewing 4769 logs, several fields are critical for detection engineering:

*   **TargetUserName:** The account requesting the ticket (e.g., `jdoe@CONTOSO.COM`).
*   **ServiceName:** The service account associated with the SPN requested (e.g., `sql_svc` or `HTTP/web01.contoso.com`).
*   **TicketOptions:** Bitmask options requested for the ticket.
*   **TicketEncryptionType:** The cryptographic algorithm used to encrypt the requested service ticket.
*   **IpAddress:** The IP address of the host that sent the `TGS-REQ`.
*   **Status:** The result code of the request (`0x0` indicates success).

Here is a simplified example of an Event ID 4769 log generated during a ticket request:

```xml
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <EventID>4769</EventID>
    <Version>0</Version>
    <Level>0</Level>
    <Task>14337</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8020000000000000</Keywords>
    <TimeCreated SystemTime="2026-11-03T10:14:22.123456Z" />
    <Computer>DC01.contoso.com</Computer>
  </System>
  <EventData>
    <Data Name="TargetUserName">jdoe@CONTOSO.COM</Data>
    <Data Name="ServiceName">sql_svc</Data>
    <Data Name="TicketOptions">0x40810000</Data>
    <Data Name="TicketEncryptionType">0x17</Data>
    <Data Name="IpAddress">::ffff:192.168.10.45</Data>
    <Data Name="Status">0x0</Data>
  </EventData>
</Event>
```

---

## Identifying Suspicious Ticket Requests

Because legitimate applications constantly request TGS tickets for day-to-day operations, querying for Event ID 4769 directly will result in massive log volume and high false-positive rates. Detections must focus on specific anomalies.

### 1. Encryption Downgrade (RC4 Requesting)

Modern Active Directory environments primarily use AES encryption (`0x12` / AES256-CTS-HMAC-SHA1-96 or `0x11` / AES128-CTS-HMAC-SHA1-96). However, common attacker tools such as Rubeus, PowerView, or Impacket's `GetUserSPNs.py` often specifically request tickets using **RC4-HMAC (`0x17`)**.

Why do attackers prefer RC4? Because RC4 password hashes are significantly faster to crack offline with GPU acceleration compared to AES hashes. 

If a domain has AES enabled across hosts, a spike in `0x17` ticket requests for user-based service accounts is a strong indicator of Kerberoasting activity.

### 2. High-Volume or Rapid TGS Requests

Legitimate users typically request service tickets only when accessing specific application servers (e.g., requesting a ticket for `MSSQLSvc/sql01` when opening SQL Server Management Studio). 

Automated Kerberoasting scripts query Active Directory for all accounts with an SPN set, then systematically request a ticket for every identified service account in rapid succession. Observing a single user or IP address requesting dozens of service tickets within seconds or minutes is anomalous.

### 3. Account Type Filtering

When monitoring Event ID 4769, ignore requests where the `ServiceName` ends in `$`. Computer accounts (like `WEB01$`) automatically rotate long, complex 120-character passwords that are functionally impossible to crack offline. Attackers specifically target user accounts acting as service accounts (e.g., `svc_mssql`), as these rely on human-set passwords.

---

## Practical Detection Logic

Here are practical detection queries you can deploy in your SIEM to spot potential Kerberoasting activity.

### KQL (Microsoft Sentinel / Defender for Endpoint)

This query searches for non-computer accounts requesting multiple service tickets using RC4 encryption (`0x17`) within a 5-minute window:

```kql
SecurityEvent
| where TimeGenerated > ago(1h)
| where EventID == 4769
| where Status == "0x0"
| where TicketEncryptionType == "0x17" // RC4-HMAC
| where not(TargetUserName endswith "$")
| where not(ServiceName endswith "$")
| where ServiceName != "krbtgt" and ServiceName != "kadmin"
| summarize 
    TicketCount = count(),
    RequestedServices = make_set(ServiceName),
    StartTime = min(TimeGenerated),
    EndTime = max(TimeGenerated)
    by TargetUserName, IpAddress
| where TicketCount >= 5
```

### SPL (Splunk)

The equivalent search in Splunk aggregates ticket requests by source IP and user:

```spl
index=wineventlog EventCode=4769 Status=0x0 TicketEncryptionType="0x17"
NOT (TargetUserName="*$") NOT (ServiceName="*$") 
NOT (ServiceName="krbtgt") NOT (ServiceName="kadmin")
| stats count as ticket_count values(ServiceName) as target_services min(_time) as first_seen max(_time) as last_seen by TargetUserName src_ip
| where ticket_count >= 5
```

---

## Deploying Honey SPNs (Deception Strategy)

While log-based detection rules based on thresholds work well, deployable deception objects provide high-fidelity alerts with near-zero false positives.

A **Honey SPN** (or decoy service account) is a dummy user account created in Active Directory with an SPN configured, but never used by any real application or system. 

### Setting Up a Honey SPN

1. Create a user account in AD (e.g., `svc_backup_mgr`).
2. Give it a realistic description to attract automated enumeration tools.
3. Assign an SPN to the account using `setspn`:
   ```cmd
   setspn -A MSSQLSvc/backupdb01.contoso.com:1433 svc_backup_mgr
   ```
4. Configure an alert rule in your SIEM specifically targeting Event ID 4769 where `ServiceName` equals `svc_backup_mgr`.

Since no real service uses this account, any `TGS-REQ` issued for `svc_backup_mgr` indicates an entity enumerating and requesting tickets across the domain.

---

## Investigation Workflow

When an alert triggers for potential Kerberoasting, follow a structured triage process:

1. **Verify the Source Host:** Identify the `IpAddress` in Event 4769. Is it an employee workstation, a jump box, or an unmanaged host on the network?
2. **Review User Activity:** Check if the account associated with `TargetUserName` has shown other signs of compromise, such as unusual interactive logons (Event ID 4624) or anomalous process creation (Sysmon Event ID 1 / Event ID 4688) on the source workstation.
3. **Inspect the Target Accounts:** Check which service accounts had tickets requested. Are they members of privileged groups like Domain Admins or Account Operators?
4. **Determine the Scope:** Did the host request 3 tickets or 300? A small count might indicate manual targeted testing; a large burst suggests automated script execution.
5. **Remediation:** If compromised, isolate the source workstation, initiate a password reset for the affected domain user, and forcefully rotate the passwords of any service accounts that were ticketed—ensuring strong passwords (25+ characters) are applied.

---

## Common Pitfalls and Limitations

*   **Legacy Applications:** Older systems or unpatched enterprise applications might natively request RC4 tickets due to misconfigured Kerberos encryption types in Active Directory. Ensure you baseline benign legacy traffic before setting strict alerts on `0x17`.
*   **Domain Controller Audit Settings:** If auditing for Kerberos Service Ticket Operations is disabled on even one Domain Controller, requests routed to that DC will be missed entirely.
*   **Service Accounts Managed via gMSA:** Group Managed Service Accounts (gMSAs) feature automatically managed 128-byte passwords. While attackers can still request tickets for gMSAs, cracking them offline is computationally impractical. Prioritize monitoring legacy user accounts acting as service accounts.

---

## Summary

Kerberoasting takes advantage of essential authentication mechanics, making complete prevention difficult without architectural adjustments like gMSAs. However, by configuring Domain Controller audit policies, monitoring Event ID 4769 for RC4 encryption requests and volume anomalies, and placing Honey SPNs in your directory, defenders can consistently catch attackers during the recon and ticket-harvesting phase.
