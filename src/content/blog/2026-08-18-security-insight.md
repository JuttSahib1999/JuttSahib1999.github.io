---
title: "Detecting DCSync Attacks: Auditing Directory Replication and RPC Telemetry"
description: "A practical guide to understanding DCSync mechanics, configuring Active Directory audit policies, and writing high-fidelity detections using Windows Security Event logs and RPC network telemetry."
date: "2026-08-18"
tags: ["Active Directory", "Threat Detection", "Security Operations", "Incident Response"]
category: "Cyber Security"
difficulty: "Intermediate"
author: "Abdul Muqeet Tabraiz"
image: "/images/blog/2026-08-18-detecting-dcsync-attacks-auditing-directory-replication-and-rpc-telemetry.svg"
---

When an adversary gains domain administrative rights or compromises an account with extended directory permissions, traditional credential harvesting techniques like LSASS memory dumping on a local host are often unnecessary. Instead, attackers can pull password hashes directly from a Domain Controller (DC) over the network without executing code on the DC itself.

This technique, known as DCSync, leverages legitimate Active Directory replication protocols to request secret data—including NTLM hashes, Kerberos keys, and AES keys for any account in the domain. 

For security operations center (SOC) analysts and detection engineers, DCSync is a critical threat vector to monitor. Detecting it reliably requires understanding how the Directory Replication Service (DRS) Remote Protocol operates, which Windows Audit Policies capture these actions, and how to separate attacker activity from legitimate replication traffic.

---

## How DCSync Works

DCSync simulates the behavior of a legitimate Domain Controller attempting to replicate directory data. It relies on the **Directory Replication Service Remote Protocol (MS-DRSR)** via RPC interfaces to interact with the Active Directory database (`NTDS.dit`).

When a legitimate DC needs to sync account updates with another DC, it invokes the `IDL_DRSGetNCChanges` RPC function. In response, the target DC returns naming context updates, which include user attributes, password hashes, and history.

An attacker executing a DCSync request (typically using tools like Mimikatz or Impacket's `secretsdump.py`) does not need to compromise the physical or virtual DC host. They only need access to a security principal (user or computer account) that possesses three specific Extended Rights on the Domain Object:

1. **DS-Replication-Get-Changes**  
   `GUID: 1131f6aa-9c0e-11d1-bf38-00c04fa93864`
2. **DS-Replication-Get-Changes-All**  
   `GUID: 1131f6ad-9c0e-11d1-bf38-00c04fa93864`
3. **DS-Replication-Get-Changes-In-Filtered-Set** (Required in specific environments, such as RODC read access)  
   `GUID: 89e12b03-ade3-11d6-bf77-00c04fa93864`

By default, members of the **Domain Admins**, **Enterprise Admins**, **Administrators**, and **Domain Controllers** groups have these permissions delegated. If an attacker controls an account within these groups—or an account that has been explicitly granted these rights via Access Control Lists (ACLs)—they can issue replication requests remotely.

---

## Configuring Required Directory Auditing

To detect DCSync attacks from host logs, default Windows auditing settings are usually insufficient. You must enable Advanced Security Audit Policies on all Domain Controllers and configure SACLs on the Domain Head object.

### Step 1: Enable Advanced Audit Policy
In Group Policy targeting all Domain Controllers (`Default Domain Controllers Policy`), navigate to:

`Computer Configuration -> Policies -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> Audit Policies -> DS Access`

Enable the following policy for **Success**:
* **Audit Directory Service Access**

### Step 2: Verify SACL Configuration
By default, access to extended attributes on the Domain Object generates audit events if `Audit Directory Service Access` is enabled. However, verify that the System Access Control List (SACL) on the root domain object audits successful accesses for `Control Access` operations by `Everyone` or `Authenticated Users`.

---

## Analyzing Event ID 4662

When a user or process requests directory object access that triggers an audit rule, the DC logs **Event ID 4662** in the Windows Security Event Log: *“An operation was performed on an object.”*

A standard Event ID 4662 for a DCSync attack contains several key fields:

```text
Log Name:      Security
Source:        Microsoft-Windows-Security-Auditing
Event ID:      4662
Task Category: Directory Service Access
Level:         Information
Keywords:      Audit Success
Description:
An operation was performed on an object.

Subject:
    Security ID:        DOMAIN\svc_aadconnect
    Account Name:       svc_aadconnect
    Account Domain:     DOMAIN
    Logon ID:           0x3E7A12

Object:
    Server:             DS
    Type:               domainDNS
    Name:               DC=corp,DC=internal
    Handle ID:          0x0

Operation Information:
    Operation Type:     Object Access
    Accesses:           Control Access
    Access Mask:        0x100
    Properties:         
        Control Access
        {1131f6ad-9c0e-11d1-bf38-00c04fa93864}
        {1131f6aa-9c0e-11d1-bf38-00c04fa93864}
```

### Key Fields to Interrogate:

* **Access Mask**: Look for `0x100` (Control Access / Extended Right).
* **Properties**: Must contain the Extended Right GUIDs for replication:
  * `{1131f6aa-9c0e-11d1-bf38-00c04fa93864}` (`DS-Replication-Get-Changes`)
  * `{1131f6ad-9c0e-11d1-bf38-00c04fa93864}` (`DS-Replication-Get-Changes-All`)
* **Subject / Account Name**: Identifies the account that performed the operation.

---

## Distinguishing Attackers from Legitimate Traffic

The primary challenge in DCSync detection is filtering out legitimate Active Directory replication. Domain Controllers constantly sync changes with each other using these exact rights and RPC calls. Additionally, legitimate administrative tools and hybrid identity services use them.

### Common Legitimate Sources:
1. **Machine Accounts of other DCs**: Computer accounts ending in `$` representing valid Domain Controllers (e.g., `DC02$`).
2. **Azure AD Connect / Entra Connect Accounts**: Sync accounts (often named `MSOL_...` or custom service accounts like `svc_aadconnect`) require `DS-Replication-Get-Changes` and `DS-Replication-Get-Changes-All` to read password hashes for Password Hash Sync (PHS).
3. **Identity Security Products**: Tools like Microsoft Defender for Identity (MDI) sensor or third-party PAM solutions may trigger replication reads depending on configuration.

### Detection Rule Baseline

A standard detection rule looks for **Event ID 4662** where `Access Mask` is `0x100`, the `Properties` field contains the DCSync GUIDs, and the invoking account is **not** an authorized source.

#### KQL Query (Azure Sentinel / Log Analytics)

```kql
SecurityEvent
| where EventID == 4662
| where AccessMask == "0x100"
| where Properties has "1131f6aa-9c0e-11d1-bf38-00c04fa93864" or Properties has "1131f6ad-9c0e-11d1-bf38-00c04fa93864"
// Exclude legitimate Machine Accounts (Domain Controllers)
| where AccountType != "Machine" and not(Account endsWith "$")
// Filter known, authorized service accounts (e.g., Azure AD Connect)
| where Account !has "MSOL_" and Account !has "svc_aadconnect"
| project TimeGenerated, Computer, Account, SubjectUserSid, AccessMask, Properties, Activity
```

#### Splunk SPL Query

```text
index=wineventlog EventCode=4662 AccessMask="0x100" 
(Properties="*{1131f6aa-9c0e-11d1-bf38-00c04fa93864}*" OR Properties="*{1131f6ad-9c0e-11d1-bf38-00c04fa93864}*")
NOT (AccountName="*$" OR AccountName="MSOL_*" OR AccountName="svc_aadconnect")
| table _time, Computer, AccountName, SubjectUserSid, Properties
```

---

## Network Telemetry and RPC Monitoring

Relying solely on host-based Event ID 4662 can present blind spots if audit logging fails, gets saturated, or experiences ingestion delays. Monitoring RPC network traffic provides an independent line of visibility.

When a DCSync attack takes place, the source IP sends traffic over **TCP port 135** (RPC Endpoint Mapper) and connects to a dynamic RPC port allocated for the Directory Replication Service.

Using network monitoring tools like Zeek, Suricata, or specialized NDR platforms, you can monitor for the specific UUID and opcodes of the `drsuapi` interface.

* **DRSUAPI Interface UUID**: `e3514235-4b06-11d1-ab04-00c04fc2dcd2`
* **Opcode 3**: `IDL_DRSGetNCChanges`

If network sensors observe an RPC connection invoking `DRSGetNCChanges` from an IP address that does not map to a known Domain Controller or Azure AD Connect server, it indicates an unauthorized replication request.

---

## Investigation and Triage Workflow

When a potential DCSync alert triggers, follow a structured investigation flow:

```
[ Alert Triggered: DCSync Activity Detected ]
                   │
                   ▼
       Is the source account a DC or 
      authorized sync service (e.g., MSOL)?
         │                       │
        Yes                      No
         │                       │
         ▼                       ▼
    [ True Positive     [ High-Severity Incident:
     False Alarm ]       Investigate Immediately ]
                                 │
                                 ├─► Check Source IP & Computer
                                 ├─► Audit Account Creation & ACL Changes
                                 └─► Revoke Credentials & Isolate Host
```

1. **Verify the Account & Host Source**:
   * What account executed the request? Is it a standard user, a compromised admin, or an unauthorized machine?
   * Match the `Logon ID` from Event ID 4662 back to **Event ID 4624** (Successful Logon) to identify the source IP address and workstation name.

2. **Inspect Domain Object ACL Modifications**:
   * Attackers who achieve temporary domain dominance often grant DCSync rights to standard accounts to maintain persistence.
   * Search for **Event ID 5136** (Directory Service Object Modified) where LDAP attribute `nTSecurityDescriptor` was modified on the domain root object.

3. **Check Target Accounts**:
   * Which accounts were targeted? Attackers typically request specific sensitive accounts first, such as `krbtgt`, `Administrator`, or service accounts tied to SQL/Kerberoasting targets.

---

## Defense and Mitigation

Detecting DCSync is essential, but preventing unauthorized delegation of these rights reduces the attack surface significantly.

### 1. Audit Domain Object ACLs Regularly
Perform periodic audits of the Active Directory ACLs to ensure no unauthorized accounts hold replication rights. PowerShell modules like `PowerView` or `BloodHound` can easily highlight these paths:

```powershell
Get-DomainObjectAcl -SearchBase "DC=corp,DC=internal" -ResolveGUIDs | 
Where-Object { 
    ($_.SecurityIdentifier -notmatch "S-1-5-21-.*-516") -and # Exclude Domain Controllers
    ($_.ObjectAceType -match "DS-Replication-Get-Changes") 
}
```

### 2. Implement the Tiering Model
Restrict Tier 0 assets (Domain Controllers, Identity Systems) from interacting with lower-tier workstations. Do not allow Tier 0 administrators to log in or leave credentials on Tier 1 (Servers) or Tier 2 (Workstations) machines where local admin compromise could lead to credential theft and subsequent DCSync execution.

### 3. Utilize Protected Users and SAM Name Restraints
Add high-privilege accounts to the **Protected Users** group to restrict weak Kerberos encryption types and delegation capabilities.

---

## Key Takeaways

* **Mechanism**: DCSync abuses legitimate `DRSGetNCChanges` RPC calls to extract password hashes without running local code on Domain Controllers.
* **Telemetry**: Require **Event ID 4662** with Extended Rights GUIDs (`{1131f6aa-9c0e-11d1-bf38-00c04fa93864}` and `{1131f6ad-9c0e-11d1-bf38-00c04fa93864}`) and Access Mask `0x100`.
* **Tuning**: Exclude legitimate DCs (`AccountName` ending in `$`) and identity sync service accounts (like Azure AD Connect).
* **Correlation**: Combine host logs with network RPC telemetry (`DRSUAPI` interface calls) to ensure complete coverage.
