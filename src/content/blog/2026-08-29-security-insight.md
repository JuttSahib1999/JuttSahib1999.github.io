---
title: "Detecting Kerberoasting: Analyzing Ticket Requests, Encryption Types, and Event ID 4769"
description: "A practical guide to understanding Kerberoasting mechanics, auditing Event ID 4769 telemetry, detecting downgrade requests, and implementing honey SPNs in Active Directory."
date: "2026-08-29"
tags: ["Active Directory", "Detection Engineering", "SIEM", "Cybersecurity"]
category: "Cyber Security"
difficulty: "Intermediate"
author: "Abdul Muqeet Tabraiz"
image: "/images/blog/2026-08-29-detecting-kerberoasting-analyzing-ticket-requests-encryption-types-and-event-id-.svg"
---

In Active Directory environments, credential theft techniques often rely on legitimate administrative protocols rather than software vulnerabilities. Kerberoasting remains one of the most effective examples. It allows an unprivileged domain user to request encrypted ticket grants for service accounts, take those tickets offline, and attempt to crack the underlying password hashes.

Because Kerberoasting relies on standard Kerberos ticket request flows, naive detections often fail—generating either massive volumes of false positives or completely missing targeted extractions. To detect this technique reliably, security analysts must understand the underlying protocol mechanics, audit the correct Security Event IDs, and evaluate key fields like ticket encryption types and request volume.

---

## How Kerberoasting Works Under the Hood

To understand why Kerberoasting works, you have to look at how Active Directory handles authentication for services using Service Principal Names (SPNs).

When a user wants to access a service registered in Active Directory—such as a SQL server (`MSSQLSvc/db01.corp.local:1433`) or a web application—the client requests a Ticket Granting Service (TGS) ticket from the Key Distribution Center (KDC), which runs on the Domain Controller.

1. **SPN Query:** The client searches Active Directory for accounts that have a `servicePrincipalName` attribute matching the desired service.
2. **TGS Request (KRB_TGS_REQ):** The authenticated user sends a request to the KDC asking for a service ticket for that SPN.
3. **TGS Response (KRB_TGS_REP):** The KDC issues a service ticket. Crucially, part of this ticket is encrypted using the password hash of the service account associated with that SPN.
4. **Offline Cracking:** The attacker extracts the encrypted portion of the TGS ticket from client memory or network traffic and uses tools like Hashcat or John the Ripper to brute-force the plaintext password offline.

The KDC does not verify whether the requesting user actually has permission to access the target service before issuing the ticket. It only verifies that the user is authenticated within the domain and that the requested SPN exists. 

Because service accounts often run with elevated privileges (such as local administrator or Domain Admin) and frequently use static passwords, a cracked service account hash often leads directly to domain privilege escalation.

---

## Key Telemetry: Windows Event ID 4769

To catch Kerberoasting, your primary source of host-based telemetry on the Domain Controller is **Event ID 4769: A Kerberos service ticket was requested**.

For Event ID 4769 to be generated, you must enable the audit policy:
`Computer Configuration -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> Audit Policies -> Account Logon -> Audit Kerberos Service Ticket Operations` (Success and Failure).

Here is a simplified view of the fields present in a standard Event ID 4769 log:

```yaml
Log Name:      Security
Source:        Microsoft-Windows-Security-Auditing
Event ID:      4769
Task Category: Kerberos Service Ticket Operations
Level:         Information
Subject:
  Account Name:        jdoe@CORP.LOCAL
  Account Domain:      CORP.LOCAL
  Logon GUID:          {a1b2c3d4-e5f6-7890-1234-56789abcdef0}
Service Information:
  Service Name:        svc_sql
  Service ID:          S-1-5-21-3820299839-2810360810-8503810-1105
Network Information:
  Client Address:      ::ffff:192.168.10.45
  Client Port:         51204
Additional Information:
  Ticket Options:      0x40810000
  Ticket Encryption:   0x17
  Failure Code:        0x0
```

### Critical Fields to Analyze

* **TargetUserName / Service Name:** The name of the account for which the ticket was requested (e.g., `svc_sql`). If the request targets a user account with an SPN, this field shows that account.
* **ServiceName / Service ID:** The Security Identifier (SID) of the service account.
* **Client Address:** The IP address of the system making the request. Note that IPv4 addresses often appear in IPv6-mapped format (`::ffff:192.168.x.x`).
* **Ticket Encryption Type (`TicketEncryptionType`):** This is one of the most critical fields for detecting Kerberoasting tools. Common values include:
  * `0x17` (23 decimal): `RC4-HMAC`
  * `0x12` (18 decimal): `AES256-CTS-HMAC-SHA1-96`
  * `0x11` (17 decimal): `AES128-CTS-HMAC-SHA1-96`
* **Failure Code (`Status`):** `0x0` indicates success. Non-zero codes represent Kerberos errors (e.g., `0x1b` means the ticket expired).

---

## Detection Strategies

Legitimate users constantly generate Event 4769 logs as they access file shares, databases, and internal web services. Alerting on every 4769 log will flood your SOC. Effective detection relies on identifying specific anomalies: **encryption downgrade requests**, **mass ticket harvesting**, and **access to honey accounts**.

### 1. The Encryption Downgrade Anomaly (`0x17` / RC4)

Modern Active Directory environments default to AES encryption (`0x12` or `0x11`) when both the client and service account support it. However, offline password cracking tools (like Hashcat) crack RC4-HMAC hashes significantly faster than AES hashes.

Because of this performance difference, many offensive tools (such as Impacket's `GetUserSPNs.py` or Rubeus) explicitly request RC4 encryption (`0x17`) during the TGS request, even if the service account supports AES.

If your domain accounts are configured to support AES, a request for an RC4-encrypted ticket for a user account with an SPN is a strong indicator of compromise.

#### Example KQL Query (Microsoft Sentinel / Azure Data Explorer)

```kql
SecurityEvent
| where EventID == 4769
| where Status == "0x0"
// Filter for RC4-HMAC encryption
| where TicketEncryptionType == "0x17"
// Exclude computer accounts ending with $
| where TargetUserName !endswith "$"
// Exclude standard infrastructure service names
| where ServiceName !endswith "$" and ServiceName !in~ ("krbtgt", "ldap", "host")
| project TimeGenerated, Account, TargetUserName, ServiceName, IpAddress, ClientPort, TicketEncryptionType
```

### 2. High-Volume Request Thresholds

Attackers frequently run automated scripts to enumerate and request tickets for *all* registered SPNs in the domain at once.

While a user might legitimately request 1 or 2 service tickets in a minute, requesting tickets for 10, 20, or 50 distinct service accounts in a short time frame from a single source host is abnormal.

#### Example Splunk Search (SPL)

```spl
index=winlogbeat event_id=4769 status=0x0
| search NOT TargetUserName="*$" NOT ServiceName="*$" NOT ServiceName="krbtgt"
| stats dc(ServiceName) as unique_services values(ServiceName) as requested_services by IpAddress, TargetUserName, span=5m
| where unique_services > 10
```

This query groups successful 4769 events in 5-minute buckets by source IP and user, alerting when a single identity requests tickets for more than 10 unique service accounts.

---

## Real-World Nuance and False Positives

When tuning these detections in a production environment, you will encounter edge cases that require adjustment.

### Legacy Systems and Machine Accounts
* **Machine Accounts:** Computer accounts (ending in `$`) automatically request service tickets for host-to-host communication. Always exclude machine accounts from basic Kerberoasting rules unless you are specifically monitoring for machine account misuse.
* **Legacy Applications:** Older Windows Server versions (e.g., Windows Server 2008 R2 or unpatched legacy application servers) may natively support only RC4. If legacy systems exist in your domain, track them and add targeted exclusions by IP or computer object rather than disabling the RC4 detection globally.

### Dual-Use Administrative Accounts
Domain administrators or IT engineers running diagnostic scripts or vulnerability scanners may trigger high-volume TGS request alerts. Ensure your team documents administrative tooling or isolates scanner IPs to prevent rule fatigue.

---

## Advanced Defense: Setting Up Honey SPNs

One of the most effective ways to detect Kerberoasting with near-zero false positives is to deploy a **Decoy SPN** (often called a Honey SPN).

### How it works:
1. Create a bogus user account in Active Directory (e.g., `svc_mssql_finance`).
2. Assign a non-existent Service Principal Name to the account:
   ```cmd
   setspn -A MSSQLSvc/fin-db01.corp.local:1433 svc_mssql_finance
   ```
3. Set a long, random password for the account and disable it, or ensure it has no rights anywhere in the environment.
4. Create an explicit detection rule monitoring for **any** Event ID 4769 request where `ServiceName` or `TargetUserName` equals `svc_mssql_finance`.

Because no legitimate user or system has any business requesting a ticket for `fin-db01.corp.local`, any TGS request for this account indicates active enumeration or Kerberoasting tooling in action.

---

## Practical Mitigation Beyond Detection

Detection is essential, but hard defenses reduce the impact if an attacker manages to extract a ticket.

1. **Group Managed Service Accounts (gMSA):** Migrate service accounts to gMSAs wherever possible. gMSAs use complex, 128-character automatically rotated passwords managed by Active Directory, making offline cracking mathematically infeasible.
2. **Password Complexity for Standard Service Accounts:** For legacy services that cannot use gMSAs, enforce passwords that are at least 25 to 30 characters long. Even under RC4 encryption, long passwords exponentially increase the time required to crack the hash.
3. **Disable RC4 Domain-Wide:** If your environment allows it, disable the `RC4_HMAC_MD5` encryption type in Kerberos policy via Group Policy (`Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> Network security: Configure encryption types allowed for Kerberos`).

---

## Summary Workflow for Responders

When an alert triggers for potential Kerberoasting:

1. **Verify the Source IP:** Determine if the IP address belongs to a workstation, a server, or a VPN pool.
2. **Inspect the Target Accounts:** Check if the requested SPNs belong to high-privilege accounts (e.g., members of Domain Admins or Account Operators).
3. **Check the Encryption Requested:** Note whether `0x17` (RC4) was explicitly requested for accounts supporting AES.
4. **Correlate with Endpoint Telemetry:** Examine process activity on the source host around the time of the event (e.g., looking for execution of `Rubeus.exe`, `powershell.exe` importing offensive modules, or Python scripts).
5. **Containment:** If confirmed malicious, isolate the compromised host and reset the password of any service account whose ticket was requested.
