---
title: "Detecting Kerberoasting: Telemetry, Event ID 4769, and Detection Engineering"
description: "Learn how Kerberoasting works, how to analyze Active Directory Event ID 4769 logs, and how to build resilient detection rules to spot ticket requests in your SIEM."
date: "2026-09-26"
tags: ["Cybersecurity", "Security Operations", "Active Directory", "Threat Detection"]
category: "Cyber Security"
difficulty: "Intermediate"
author: "Abdul Muqeet Tabraiz"
image: "/images/blog/2026-09-26-detecting-kerberoasting-telemetry-event-id-4769-and-detection-engineering.svg"
---

Kerberoasting remains one of the most effective post-exploitation techniques in Active Directory (AD) environments. Its popularity among attackers comes down to a fundamental architectural design in Kerberos: any authenticated domain user can request a service ticket (TGS) for any service that has a Service Principal Name (SPN) registered, and Active Directory will grant it without checking whether the user actually needs access to that service.

Because the returned ticket is encrypted using the password hash of the service account linked to that SPN, an attacker can extract the encrypted ticket from memory, take it offline, and perform brute-force or dictionary attacks against it without sending another packet to the network.

For SOC analysts and threat hunters, detecting Kerberoasting requires an understanding of Kerberos ticket traffic, Active Directory telemetry, and how to separate legitimate service traffic from automated extraction tools like Rubeus or Impacket's `GetUserSPNs.py`.

## How Kerberoasting Works Under the Hood

To understand the telemetry generated during an attack, it helps to review the standard Kerberos authentication flow.

```
+------------------+         1. AS-REQ          +--------------------+
|                  | -------------------------> |                    |
|   Domain User    |                            | Domain Controller  |
|   (Attacker)     | <------------------------- |       (KDC)        |
|                  |         2. AS-REP (TGT)    +--------------------+
+------------------+                                      |
         |                                                |
         |                   3. TGS-REQ                   |
         +----------------------------------------------->|
         |              (Request SPN ticket)              |
         |                                                |
         |                   4. TGS-REP                   |
         |<-----------------------------------------------+
         |             (Encrypted with Service            |
         |                  Account Hash)                 |
         v
+------------------+
|  Offline Cracking|
|  (Hashcat/John)  |
+------------------+
```

1. **Authentication (AS-REQ / AS-REP):** The user authenticates to the Key Distribution Center (KDC) running on a Domain Controller and receives a Ticket Granting Ticket (TGT).
2. **Service Request (TGS-REQ):** The user presents their TGT to the KDC and requests a Ticket Granting Service (TGS) ticket for a specific SPN (for example, `MSSQLSvc/db01.corp.local:1433`).
3. **Ticket Issuance (TGS-REP):** The KDC checks if the SPN exists in the directory. If it does, the KDC issues a TGS ticket. Crucially, the ticket payload is encrypted with the secret key (NTLM hash or AES key) of the service account associated with that SPN.
4. **Offline Extraction:** The requesting client receives the TGS-REP response. An attacker extracts the encrypted ticket blob, formats it, and feeds it into tools like Hashcat or John the Ripper to crack the plain-text password offline.

Because step 4 happens completely off the network, defenders cannot detect the cracking attempt itself. Detection must happen at step 3, when the attacker requests the TGS ticket from the KDC.

## Primary Telemetry Source: Event ID 4769

When Kerberos auditing is enabled on your Domain Controllers, every TGS request generates **Windows Security Event ID 4769** (*A Kerberos service ticket was requested*). 

To capture this event, the **Audit Kerberos Service Ticket Operations** subcategory must be set to log Success (and optionally Failure) events via Group Policy.

### Key Fields in Event ID 4769

A standard 4769 event contains several fields critical for detection logic:

* **TargetUserName:** The SPN being requested (e.g., `sql_service`).
* **ServiceName:** The name of the service account associated with the SPN.
* **ServiceSid:** The SID of the service account.
* **TicketOptions:** A bitmask representing flags requested for the ticket (e.g., `0x40810000`).
* **TicketEncryptionType:** The cryptographic algorithm used to encrypt the ticket.
* **IpAddress:** The IP address of the host that requested the ticket.
* **Status:** The result code of the request (`0x0` indicates success).

Here is a simplified example of what this event looks like in raw log telemetry:

```xml
An account requested a Kerberos service ticket.

Subject:
    Security ID:        CORP\jdoe
    Account Name:       jdoe
    Account Domain:     CORP.LOCAL

Service Information:
    Service Name:       sql_admin
    Service ID:         S-1-5-21-3829103948-3291829301-1829301928-1104

Network Information:
    Client Address:     ::ffff:192.168.10.45
    Client Port:        52104

Additional Information:
    Ticket Options:         0x40810010
    Ticket Encryption Type: 0x17
    Failure Code:           0x0
```

## Parsing Cryptographic Downgrades (0x17 vs 0x12)

Historically, Kerberoasting detection heavily relied on filtering for **TicketEncryptionType `0x17`** (RC4-HMAC). 

Attackers historically requested RC4-encrypted tickets because RC4 hashes are significantly faster to crack offline using GPUs than AES-128 (`0x11`) or AES-256 (`0x12`) hashes. Tools like Rubeus explicitly allowed users to request RC4 encryption via the `/rc4` flag, forcing a downgrade even if the domain supported AES.

Here are the common encryption type values seen in Event 4769:

| Value | Encryption Type | Cracking Speed | Relevance to Detection |
| :--- | :--- | :--- | :--- |
| `0x17` | RC4-HMAC | Very Fast | High indicator of legacy setups or explicit downgrade requests |
| `0x11` | AES128-CTS-HMAC-SHA1-96 | Slow | Modern standard |
| `0x12` | AES256-CTS-HMAC-SHA1-96 | Very Slow | Modern standard |
| `0x1` / `0x3` | DES-CBC-CRC / DES-CBC-MD5 | Deprecated | Extremely rare; often malicious or severely outdated legacy systems |

### The Detection Trap: Relying Solely on Encryption Type

Relying *only* on `TicketEncryptionType == 0x17` creates two distinct problems:

1. **False Negatives:** Attackers know defenders write rules targeting `0x17`. Modern offensive tools can request AES tickets (`0x12`). While AES is harder to crack offline, weak passwords (such as `Summer2024!`) will still fall to common wordlists regardless of the cipher used.
2. **False Positives:** Legacy applications, old service accounts, or environments where AES Kerberos encryption was never configured on account objects will naturally request RC4 tickets during normal operations.

Effective detection engineering must combine encryption types with **volume, account types, and request patterns**.

## Filtering Noise in Active Directory Telemetry

In an enterprise environment, Event ID 4769 generates millions of events per day. Most of these requests are completely benign. Computer accounts regularly request tickets to communicate with each other, and standard users request tickets to access file shares, web servers, and databases.

To build an actionable rule, you must exclude routine noise:

1. **Computer Accounts:** Filter out requests where `ServiceName` ends with `$`. Computer account passwords are 120-character randomly generated strings updated automatically every 30 days. They are practically uncrackable offline.
2. **Default System Accounts:** Exclude requests for `krbtgt` or domain controllers themselves (`HOST/` or `ldap/` entries pointing to infrastructure servers).
3. **Machine-to-Machine Noise:** Exclude requests where the requesting account (`TargetUserName`) is a computer account (ends with `$`).

## Building Effective Detection Queries

Instead of alerting on single occurrences, the most reliable strategy is searching for **volume anomalies**—a single user requesting TGS tickets for multiple distinct user service accounts within a tight time window.

### Example 1: Microsoft Sentinel / KQL Query

This KQL query aggregates Event 4769 logs, filters out computer account noise, and flags users requesting tickets for more than 5 distinct service accounts within a 10-minute window.

```kql
SecurityEvent
| where EventID == 4769
| where Status == "0x0"
// Filter out computer accounts and krbtgt
| where not(ServiceName endswith "$") and ServiceName != "krbtgt"
| where not(TargetUserName endswith "$")
// Optional: Focus on RC4 downgrade or evaluate all encryption types
| extend EncryptionType = TicketEncryptionType
| summarize 
    RequestedSPNs = make_set(ServiceName),
    SPNCount = dcount(ServiceName),
    EncryptionTypes = make_set(EncryptionType),
    StartTime = min(TimeGenerated),
    EndTime = max(TimeGenerated)
    by TargetUserName, IpAddress, bin(TimeGenerated, 10m)
| where SPNCount >= 5
| project StartTime, EndTime, TargetUserName, IpAddress, SPNCount, RequestedSPNs, EncryptionTypes
```

### Example 2: Splunk SPL Query

The same logic expressed in Splunk SPL:

```spl
index=wineventlog EventCode=4769 Status=0x0
| search NOT (ServiceName="*$" OR ServiceName="krbtgt" OR TargetUserName="*$")
| stats 
    dc(ServiceName) as SPNCount 
    values(ServiceName) as RequestedSPNs 
    values(TicketEncryptionType) as EncryptionTypes 
    earliest(_time) as FirstSeen 
    latest(_time) as LastSeen 
    by TargetUserName, IpAddress span=10m
| where SPNCount >= 5
| eval FirstSeen=strftime(FirstSeen, "%Y-%m-%d %H:%M:%S"), LastSeen=strftime(LastSeen, "%Y-%m-%d %H:%M:%S")
```

## Practical Triage and Investigation Workflow

When a threshold alert fires in your SOC, follow a structured verification process before taking disruptive action.

```
+--------------------------------------------------+
| Alert Triggered: High Volume 4769 TGS Requests   |
+--------------------------------------------------+
                         |
                         v
+--------------------------------------------------+
| 1. Validate Target Accounts                      |
|    - Are the requested accounts actual user SPNs?|
|    - Do any belong to sensitive groups (e.g.,    |
|      Domain Admins, Tier-0 Admins)?              |
+--------------------------------------------------+
                         |
                         v
+--------------------------------------------------+
| 2. Examine Requesting Identity & Source Host     |
|    - Is the user account normal for this host?   |
|    - Is the IP a workstation, VPN pool, or server|
+--------------------------------------------------+
                         |
                         v
+--------------------------------------------------+
| 3. Correlate Endpoint Telemetry (EDR / Sysmon)   |
|    - Look at source IP host at timestamp.        |
|    - Check for execution of tools like Rubeus,   |
|      PowerView, or unmanaged PowerShell code.    |
+--------------------------------------------------+
                         |
                         v
+--------------------------------------------------+
| 4. Determine Scope & Contain                     |
|    - If malicious: Reset user password, revoke   |
|      active sessions, isolate source host.       |
|    - Force password reset on targeted accounts.  |
+--------------------------------------------------+
```

### Step 1: Examine the Requested Accounts
Look at the `RequestedSPNs` field. If the user requested tickets for accounts like `sql_admin`, `backup_svc`, or `svc_deploy`, check whether those accounts belong to high-privileged groups such as Domain Admins or Account Operators. Compromising a service account that holds administrative rights leads directly to domain dominance.

### Step 2: Analyze Source Host and User Context
Look at the `IpAddress` and `TargetUserName`. Is `jdoe` logged into a HR workstation requesting 15 SQL and IIS service tickets in 3 seconds? That is abnormal behavior. Conversely, is the request coming from a central management server or a scanner account (like a vulnerability scanner) running routine inventory scripts?

### Step 3: Check Endpoint Telemetry
If you have EDR or Sysmon coverage on the host corresponding to `IpAddress`, query for process executions surrounding the alert timestamp. Look for:

* Execution of binaries like `Rubeus.exe`, `mimikatz.exe`, or `PSScriptAnalyzer`.
* PowerShell processes running commands containing `Get-DomainSPN`, `Get-NetUser`, or `GetUserSPNs`.
* Suspicious native API calls or unmanaged PowerShell execution (PowerShell core DLLs loaded into unusual processes like `rundll32.exe`).

## Practical Hardening and Prevention

Detection is vital, but reducing the attack surface renders Kerberoasting largely ineffective.

### 1. Implement Group Managed Service Accounts (gMSA)
Where possible, migrate standard service accounts to **gMSAs**. Active Directory automatically manages gMSA passwords, setting them to 128-character complex strings and rotating them on a schedule. Even if an attacker extracts a TGS ticket for a gMSA account, offline cracking is mathematically infeasible.

### 2. Enforce High-Entropy Passwords on Legacy Accounts
For legacy service accounts that cannot be converted to gMSAs, enforce passwords that are at least **25 to 30 characters long**. Randomly generated phrases make offline dictionary attacks practical impossibility.

### 3. Remove Unnecessary SPNs
Audit your Active Directory environment regularly for stale or unnecessary SPNs. Service accounts that no longer host active services should have their `servicePrincipalName` attribute cleared using PowerShell:

```powershell
# Find user accounts with SPNs set
Get-ADUser -Filter {servicePrincipalName -like "*"} -Properties servicePrincipalName | 
    Select-Object Name, UserPrincipalName, servicePrincipalName

# Remove an outdated SPN
Set-ADUser -Identity "svc_oldapp" -Remove @{servicePrincipalName="HTTP/oldapp.corp.local"}
```

### 4. Enforce AES Encryption for Kerberos
Disable RC4 encryption on user service accounts by checking the box **"This account supports Kerberos AES 128/256 bit encryption"** in Active Directory Users and Computers (ADUC), or enforce it via domain policy. Once AES is required, KDC responses will default to AES encryption types (`0x11` or `0x12`), significantly increasing the computational cost for an attacker attempting offline brute-forcing.

## Summary

Kerberoasting relies on legitimate functionality built into Active Directory, making it impossible to stop purely by blocking network traffic. Defensive success comes down to monitoring **Event ID 4769**, stripping away routine machine noise, and flagging anomalous spikes in service ticket requests across distinct user accounts. 

When paired with strong password policies and gMSA adoption, attackers lose both their ability to request tickets unnoticed and their capability to crack them off-site.
