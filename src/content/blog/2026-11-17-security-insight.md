---
title: "Detecting Kerberoasting: Service Principal Names, Event Logs, and Behavioral Alerts"
description: "A practical guide to understanding Kerberoasting attacks, analyzing Windows Event ID 4769 telemetry, filtering legitimate AD traffic, and building resilient detection rules."
date: "2026-11-17"
tags: ["Cybersecurity", "Security Operations"]
category: "Cyber Security"
difficulty: "Intermediate"
author: "Abdul Muqeet Tabraiz"
image: "/images/blog/2026-11-17-detecting-kerberoasting-service-principal-names-event-logs-and-behavioral-alerts.svg"
---

Kerberoasting remains one of the most reliable post-exploitation techniques encountered during internal security assessments and real-world intrusions. Because it abuses the core design of the Kerberos protocol in Active Directory rather than exploiting a software bug, blocking it outright is difficult without structural architectural changes.

For security operations teams, detecting Kerberoasting requires a solid understanding of Kerberos ticket granting workflows, Windows auditing configurations, and how to separate attacker behavior from normal service activity.

---

## How Kerberoasting Works

Kerberoasting targets user accounts that have a Service Principal Name (SPN) set in Active Directory. SPNs associate a service instance (like MSSQL, HTTP, or IIS) with a specific service account.

When a domain user wants to access a service registered with an SPN, the authentication flow follows a predictable sequence:

1. **AS-REQ / AS-REP:** The user authenticates to the Key Distribution Center (KDC) and receives a Ticket Granting Ticket (TGT).
2. **TGS-REQ:** The user requests a Ticket Granting Service (TGS) ticket for a specific service by supplying the target SPN.
3. **TGS-REP:** The KDC returns a TGS ticket encrypted with the password hash of the account tied to that SPN.

Because any valid domain user can request a TGS ticket for any valid SPN in the domain, an attacker with low-privileged domain access can request TGS tickets for all user accounts assigned an SPN. 

The attacker takes these encrypted tickets offline and attempts to brute-force the password hash using tools like Hashcat or John the Ripper. If the service account relies on a weak password, the plaintext password will eventually be cracked offline—without generating any additional logon failures or suspicious network traffic to the domain controller after the initial request.

---

## The Telemetry: Windows Event ID 4769

To detect Kerberoasting on the network, domain controllers must be configured to log Audit Kerberos Service Ticket Operations. When enabled, the KDC logs **Event ID 4769** ("A Kerberos service ticket was requested") every time a TGS ticket is issued or denied.

### Essential Fields in Event ID 4769

A typical Event ID 4769 generated on a Domain Controller looks like this:

```text
A Kerberos service ticket was requested.

Account Information:
    Account Name:        jdoe@SECURITY.LOCAL
    Account Domain:      SECURITY.LOCAL
    Logon GUID:          {A1B2C3D4-E5F6-7890-1234-56789ABCDEF0}

Service Information:
    Service Name:        MSSQLSvc/db01.security.local:1433
    Service ID:          S-1-5-21-123456789-987654321-1001

Network Information:
    Client Address:      ::ffff:192.168.10.45
    Client Port:         51204

Additional Information:
    Ticket Options:      0x40810000
    Ticket Encryption Type: 0x17
    Failure Code:        0x0
```

When building detection logic around Event ID 4769, focus on three specific fields:

1. **Ticket Encryption Type (`0x17` vs `0x12`):** 
   - `0x17` represents `RC4-HMAC-MD5`. Attackers historically request RC4-encrypted tickets because RC4 hashes crack significantly faster offline than AES hashes.
   - `0x12` represents `AES256-CTS-HMAC-SHA1-96` and `0x11` represents `AES128-CTS-HMAC-SHA1-96`. Modern Windows environments default to AES, but attackers can explicitly request RC4 in the `TGS-REQ` packet header to force a downgrade.

2. **Service Name:**
   - Computer accounts (ending in `$`) automatically generate TGS requests constantly as part of standard Windows networking.
   - Accounts tied to `krbtgt` are standard infrastructure requests.
   - The primary targets for Kerberoasting are service accounts associated with **user accounts** (e.g., `svc_sql`, `svc_backup`).

3. **Client Address & Port:**
   - Identifies the host requesting the ticket. While IP spoofing can complicate network analysis, in standard Active Directory Kerberos exchanges over TCP/UDP port 88, this field reflects the real source IP of the requesting machine.

---

## Filtering Noise from Signal

If you alert on every Event ID 4769 with encryption type `0x17`, your SIEM will be overwhelmed with false positives. Legacy applications, older Linux servers running Samba, or misconfigured legacy services may still request RC4 tickets routinely.

To create actionable alerts, apply the following baseline filters:

* **Exclude Machine Accounts:** Filter out requests where `Service Name` ends with `$` or equals `krbtgt`.
* **Exclude Service Accounts Requesting Tickets for Themselves:** Legitimate service startups often trigger TGS requests under their own context.
* **Focus on User Accounts with SPNs:** Target telemetry specifically at user accounts that function as service accounts.
* **Look for Volumetric and Rate Anomalies:** A single user requesting 15 or 20 TGS tickets for distinct user-managed SPNs within a 60-second window is almost always malicious activity or an automated discovery tool like Rubeus, BloodHound, or Empire.

---

## Writing Detection Queries

### Microsoft Sentinel (KQL)

This Kusto Query Language (KQL) query detects instances where a single user account requests multiple TGS tickets encrypted with RC4 (`0x17`) targeting non-computer accounts within a 5-minute window:

```kql
SecurityEvent
| where EventID == 4769
| where Status == "0x0" // Successful TGS Requests
| where TicketEncryptionType == "0x17" // RC4 Request
| where TargetUserName !endswith "$" and TargetUserName != "krbtgt"
| summarize 
    UniqueSPNsRequested = dcount(ServiceName),
    RequestedSPNs = make_set(ServiceName),
    StartTime = min(TimeGenerated),
    EndTime = max(TimeGenerated)
    by TargetDomainName, IpAddress, SubjectUserName
| where UniqueSPNsRequested >= 5
```

### Splunk (SPL)

The equivalent search in Splunk targeting Windows Security Event logs:

```spl
index=winlogbeat EventCode=4769 Status=0x0 Ticket_Encryption_Type=0x17
NOT (Service_Name="*$" OR Service_Name="krbtgt")
| stats dc(Service_Name) as unique_spns values(Service_Name) as requested_services min(_time) as first_seen max(_time) as last_seen by Target_Domain_Name, Client_Address, Account_Name
| where unique_spns >= 5
| eval duration = last_seen - first_seen
```

---

## Defensive Engineering and Mitigation

Detecting the attack is only half the battle. Reducing the attack surface makes Kerberoasting significantly harder or entirely ineffective for an adversary.

### 1. Enforce Group Managed Service Accounts (gMSA)
Where possible, migrate legacy user-based service accounts to **Group Managed Service Accounts (gMSAs)**. Active Directory automatically manages the password for gMSA accounts, rotating a complex 120-character password every 30 days. Even if an attacker collects the TGS ticket for a gMSA account, cracking it offline is computationally infeasible.

### 2. Disable RC4 Encryption Across the Domain
If your Active Directory environment fully supports AES, disable RC4 support for Kerberos via Group Policy (`Network security: Configure encryption types allowed for Kerberos`). 

When RC4 is disabled globally, attackers cannot downgrade ticket requests to RC4. Forced to crack AES256-encrypted tickets, the time and computational resources required increase by orders of magnitude.

### 3. Deploy Honeytoken SPNs (Deception)
Because Kerberoasting relies on enumerating all registered SPNs in Active Directory, deploying a "Honeytoken" service account is an extremely high-fidelity detection method.

1. Create a dummy user account (e.g., `svc_printer_admin`).
2. Assign it a realistic SPN (`HTTP/printmgr.domain.local`).
3. Set a strong, 64-character password so the account cannot actually be cracked.
4. Set an alert in your SIEM whenever **Event ID 4769** targets `HTTP/printmgr.domain.local`.

Since no real service uses this account, any TGS request targeting this SPN is guaranteed to be a scanner or an attacker running an enumeration script.

---

## Operational Limitations

While Event ID 4769 is the standard telemetry source for Kerberoasting, keep the following caveats in mind:

* **Log Volume:** Enable Event ID 4769 auditing carefully. On large domain controllers, auditing Kerberos Service Ticket Operations generates high log volume. Ensure your SIEM ingestion rules, storage retention, and filter logic are aligned to handle the data.
* **AES-Only Attacks:** If an attacker knows your environment requires AES, they may intentionally request `0x12` (AES256) tickets to blend in with normal traffic. Relying solely on `0x17` (RC4) filtering will miss these requests. Volume-based alerting (multiple TGS requests in a short window) must cover both AES and RC4 ticket types.

---

## Practical Checklist for Defenders

1. Verify that Audit Kerberos Service Ticket Operations is enabled on all Domain Controllers.
2. Ingest Windows Event ID 4769 into your central log repository or SIEM.
3. Build volume-based alert rules filtering out machine accounts (`*$`) and `krbtgt`.
4. Create at least one decoy SPN (Honeytoken) in your active directory domain to catch automated tools immediately.
5. Identify all user accounts with SPNs set (`Get-ADUser -Filter {ServicePrincipalName -ne "$null"}`) and audit their password complexity.
6. Migrate candidate accounts to gMSAs and disable RC4 domain-wide where legacy systems permit.
