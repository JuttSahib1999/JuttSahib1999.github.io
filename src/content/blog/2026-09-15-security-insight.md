---
title: "Detecting Kerberoasting Attacks: Ticket Telemetry, Encryption Downgrades, and Triage Logic"
description: "A practical guide to understanding Kerberoasting mechanics, analyzing Windows Event ID 4769 telemetry, and building detection rules that filter out domain noise."
date: "2026-09-15"
tags: ["Cybersecurity", "Security Operations"]
category: "Cyber Security"
difficulty: "Intermediate"
author: "Abdul Muqeet Tabraiz"
image: "/images/blog/2026-09-15-detecting-kerberoasting-attacks-ticket-telemetry-encryption-downgrades-and-triag.svg"
---

Kerberoasting remains one of the most reliable privilege escalation and credential access techniques in Active Directory environments. Because it abuses legitimate Kerberos functionality, stopping the attack at the network level without breaking service authentication is practically impossible. Defenders must instead rely on accurate endpoint and domain controller telemetry to spot the activity during execution.

This article breaks down how Kerberoasting works under the hood, what telemetry Windows Domain Controllers capture, how to write detection logic that minimizes false positives, and how to triage an alert when your SIEM flags suspicious Ticket Granting Service (TGS) requests.

---

## How Kerberoasting Works Under the Hood

To understand how to detect Kerberoasting, you first need to understand the underlying Kerberos protocol exchange.

In an Active Directory domain, any authenticated user can request a service ticket (TGS-REP) for any service that has a Service Principal Name (SPN) registered. The Domain Controller (specifically the Key Distribution Center, or KDC) does not check whether the requesting user actually has authorization to access the target application—it only checks whether the requesting user is a valid domain account.

Here is the basic sequence during a Kerberoasting attempt:

1. **Authentication (AS-REQ / AS-REP):** The attacker authenticates as a standard domain user and receives a Ticket Granting Ticket (TGT).
2. **Service Discovery:** The attacker queries Active Directory via LDAP to locate user accounts that have the `servicePrincipalName` attribute set. Machine accounts (`COMPUTER$`) also have SPNs, but attackers focus on user accounts because human-managed service accounts frequently use weak, non-expiring passwords.
3. **TGS Request (TGS-REQ):** The attacker requests a Kerberos service ticket for a specific SPN from the KDC. Crucially, the attacker can explicitly request an older, weaker encryption type—typically RC4-HMAC (`0x17`)—even if the domain supports AES.
4. **TGS Response (TGS-REP):** The KDC issues the service ticket, which is encrypted using the password hash of the account associated with the target SPN.
5. **Offline Cracking:** The attacker extracts the encrypted ticket portion from memory or network traffic and attempts to crack the service account's plaintext password offline using tools like Hashcat or John the Ripper.

Because the cracking occurs entirely offline on the attacker's local system, no failed login events (like Event ID 4625) are generated on the Domain Controller during the brute-force phase. The only signal generated on the network is the initial request for the TGS ticket.

---

## The Core Telemetry Source: Event ID 4769

When auditing for Kerberos tickets is enabled on your Domain Controllers, Windows logs **Event ID 4769: A Kerberos service ticket was requested**.

To capture this event, the following Audit Policy must be configured on all Domain Controllers:

* **Policy Path:** `Computer Configuration -> Policies -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> Audit Policies -> Account Logon`
* **Setting:** `Audit Kerberos Service Ticket Operations` set to **Success** (and optionally Failure).

### Key Fields in Event ID 4769

An Event ID 4769 payload contains critical fields for detection engineering:

```text
A Kerberos service ticket was requested.

Account Information:
    Account Name:        jdoe@CONTOSO.LOCAL
    Account Domain:      CONTOSO.LOCAL
    Logon GUID:          {12345678-1234-1234-1234-1234567890AB}

Service Information:
    Service Name:        mssql_svc
    Service ID:          CONTOSO\mssql_svc

Network Information:
    Client Address:      ::ffff:192.168.10.45
    Client Port:         51234

Additional Information:
    Ticket Options:      0x40810000
    Ticket Encryption Type: 0x17
    Failure Code:        0x0
```

To extract meaningful signals from this log, pay close attention to three specific attributes:

### 1. Target Account Type (`Service Name` / `Service ID`)
In normal domain operations, the vast majority of TGS requests are made for machine accounts (e.g., `DESKTOP-8A12$`, `WEB-SRV01$`, or `krbtgt`). Machine account passwords are 120-character randomly generated strings rotated automatically every 30 days. Attackers almost never request tickets for computer accounts because offline cracking is infeasible. Kerberoasting targets **user accounts** acting as service accounts.

### 2. Encryption Type (`Ticket Encryption Type`)
The KDC supports multiple encryption algorithms for ticket responses. The numerical values map to the following standards:

| Hex Value | Decimal | Encryption Type | Threat Level |
| :--- | :--- | :--- | :--- |
| `0x17` | 23 | RC4-HMAC | **High** (Legacy, easy to crack) |
| `0x12` | 18 | AES256-CTS-HMAC-SHA1-96 | **Low** (Modern standard) |
| `0x11` | 17 | AES128-CTS-HMAC-SHA1-96 | **Low** (Modern standard) |
| `0xFFFFFFFF` | -1 | Request Failed | **N/A** |

Attackers frequently request RC4 (`0x17`) because cracking an RC4 hash offline requires significantly less GPU computation time than cracking an AES hash. Even if a service account supports AES, requesting an RC4 ticket will force the KDC to issue an RC4-encrypted ticket as long as the account has an NTLM hash stored in Active Directory.

### 3. Ticket Options
Attackers using automated roasting tools often use static ticket option flags (like `0x40810000` or `0x40800000`). While ticket options alone are not a definitive signal, matching specific options across multiple ticket requests from a single source host can help flag automated toolkits like Rubeus or Impacket.

---

## Filtering Baseline Noise from Real Attacks

A common pitfall in Kerberoasting detection is alerting on *every* TGS request with `Ticket Encryption Type == 0x17`. 

Legacy applications, older network appliances, or misconfigured legacy Windows servers may still request RC4 tickets legitimately. Alerting blindly on `0x17` will overwhelm your SOC with false positives.

To build an effective detection strategy, filter your telemetry using these criteria:

1. **Exclude Computer Accounts:** Filter out any `Service Name` that ends with `$`. Machine account tickets are not useful to an attacker targeting weak passwords.
2. **Exclude `krbtgt`:** Requests for `krbtgt` occur during initial TGT generation and inter-realm requests, not standard service requests.
3. **Thresholding / Volatility:** Look for a single user account requesting multiple service tickets for distinct service accounts within a short time window.
4. **Encryption Downgrade Anomaly:** Identify service accounts that normally receive AES-encrypted tickets but suddenly receive an RC4 request.

---

## Practical Detection Logic

Here are two production-ready detection logic examples.

### Example 1: KQL Query (Microsoft Sentinel / Defender for Endpoint)

This query detects instances where a single account requests multiple RC4-encrypted service tickets for user-based service accounts within a 10-minute window.

```kql
SecurityEvent
| where EventID == 4769
| where Status == "0x0" // Successful requests
| where TicketEncryptionType == "0x17" // RC4-HMAC
| where not(TargetUserName endswith "$") // Exclude computer accounts
| where TargetUserName !in~ ("krbtgt", "guest")
| summarize 
    UniqueServiceCount = dcount(TargetUserName),
    RequestedServices = make_set(TargetUserName),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by SubjectUserName, IpAddress
| where UniqueServiceCount >= 3
```

### Example 2: Splunk Search Processing Language (SPL)

This Splunk query looks for suspicious RC4 TGS requests made to non-computer accounts, aggregating requests by source IP and requesting user.

```text
index=wineventlog EventCode=4769 Status=0x0 Ticket_Encryption_Type=0x17
| eval TargetUser=lower(Service_Name)
| where NOT match(TargetUser, "\$$") AND NOT TargetUser IN ("krbtgt", "guest")
| stats dc(TargetUser) as unique_spns, values(TargetUser) as targeted_services by Account_Name, Client_Address
| where unique_spns > 2
```

---

## Step-by-Step Triage Workflow

When a Kerberoasting alert fires in your SOC, follow this systematic workflow to determine if it is a true positive:

```
[ Alert Triggers ]
        |
        v
[ Identify Requesting Account & Source IP ]
        |
        v
[ Check Target Account Type ]
   ├── Is target a Computer Account ($)? ---> [ True Positive False Alarm / Close ]
   └── Is target a User Service Account? ---> [ Continue Investigation ]
        |
        v
[ Analyze Request Pattern ]
   ├── High volume in short time? ----------> [ Likely Automated Tool (e.g., Rubeus) ]
   └── Single target request? --------------> [ Targeted Roasting / Check User Baseline ]
        |
        v
[ Inspect Client Host Telemetry ]
   ├── Unusual process executing? ---------> [ Escalate to Endpoint Team ]
   └── Known legacy application server? ---> [ Document Baseline / Update Filter ]
```

### Step 1: Identify the Requesting Account and Source IP
Look at `SubjectUserName` (or `Account Name`) and `Client Address`. Is the request originating from an IP assigned to a standard workstation subnet, a VPN pool, or a domain controller? A workstation requesting multiple service tickets in seconds is suspicious.

### Step 2: Correlate Endpoint Telemetry
Cross-reference the time of the event with endpoint logs (Sysmon Event ID 1 or Windows Event ID 4688) on the source host:
* Which process generated network traffic on port 88 (Kerberos) at that moment?
* Look for known attack tools like `Rubeus.exe`, `powershell.exe` running encoded commands, or unquoted binary paths executing from `C:\Users\Public\` or `\AppData\Local\Temp\`.

### Step 3: Evaluate Account Privileges
Check the privileges of the account requesting the tickets. Did a compromised low-privilege user account suddenly initiate service discovery queries via LDAP right before requesting the tickets?

---

## Defensive Recommendations & Hardening

Detecting Kerberoasting is critical, but preventing it is much more effective. Implement these hardening controls to reduce your attack surface:

1. **Migrate to Group Managed Service Accounts (gMSAs):** 
   gMSAs use complex, 128-character automatically rotated passwords managed by Active Directory. Even if an attacker requests and receives a TGS ticket for a gMSA, cracking the password offline is mathematically infeasible.

2. **Disable RC4 Encryption on Service Accounts:**
   Configure active service accounts to support only AES128 and AES256 encryption. If RC4 is disabled for an account, the KDC will refuse to issue an RC4 ticket, rendering lower-cost cracking attempts impossible.

3. **Enforce Strong Passwords for Legacy Service Accounts:**
   If a user account must remain a standard user account with an SPN, ensure its password is at least 25 characters long. Passphrases of this length resist offline dictionary and brute-force attacks even when targeted with high-end GPU clusters.

4. **Deploy Honey SPNs:**
   Create a decoy user account with an attractive SPN (e.g., `MSSQLSvc/db-prod-01.contoso.local`), a complex password, and no actual permissions in the domain. Configure your SIEM to alert instantly whenever *any* TGS request is generated for this decoy account. Because legitimate users will never attempt to authenticate to this fake service, any request for its ticket is a high-confidence signal of malicious activity.

---

## Final Thoughts

Kerberoasting takes advantage of essential authentication mechanics within Active Directory, making complete suppression difficult. However, by monitoring Windows Event ID 4769, filtering out expected machine account activity, and focusing on encryption downgrades and request volumes, security analysts can reliably detect Kerberoasting activity early in the attack lifecycle before credentials are successfully cracked and reused.
