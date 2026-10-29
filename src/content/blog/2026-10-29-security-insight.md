---
title: "Detecting DCSync Attacks: RPC Interfaces, SACL Configurations, and Detection Engineering"
description: "A deep dive into MS-DRSR protocol mechanics, Event ID 4662 auditing requirements, domain SACL configurations, and high-fidelity detection strategies."
date: "2026-10-29"
tags: ["Cybersecurity", "Active Directory", "Detection Engineering", "DFIR"]
category: "Cyber Security"
difficulty: "Expert"
author: "Abdul Muqeet Tabraiz"
image: "/images/blog/2026-10-29-detecting-dcsync-attacks-rpc-interfaces-sacl-configurations-and-detection-engine.svg"
---

DCSync remains one of the most critical privilege escalation and credential access techniques in Active Directory environments. Originally introduced by Benjamin Delpy and Laurent Gaffié in Mimikatz, the technique allows an attacker with sufficient permissions to simulate a Domain Controller (DC) and request user password hashes—including the KRBTGT account hash—without ever executing code directly on a DC.

While the conceptual flow of DCSync is well understood, detecting it reliably in enterprise environments requires a detailed understanding of the Directory Replication Service Remote Protocol (MS-DRSR), Windows Security Event log limitations, domain object SACL requirements, and RPC network behavior.

---

## Technical Mechanics: How DCSync Operates

DCSync does not rely on memory injection into `lsass.exe` on a Domain Controller. Instead, it utilizes legitimate Active Directory replication protocols exposed by the Directory Replication Service (DRS) Remote Protocol (`MS-DRSR`).

When a legitimate Domain Controller needs to synchronize directory changes with another DC, it initiates an RPC connection over the `drsuapi` interface. An attacker executing a DCSync command (via Mimikatz, Impacket's `secretsdump.py`, or custom tooling) mimics this behavior through the following RPC sequence:

1. **RPC Endpoint Resolution**: The client contacts the RPC Endpoint Mapper (port 135/tcp) on a Domain Controller to locate the dynamic TCP port for the `drsuapi` interface.
2. **RPC Interface Binding**: The client binds to the DRSUAPI interface UUID `e3514235-4b06-11d1-ab04-00c04fc2dcd2`.
3. **DRSBind Call**: The client issues a `DRSBind` (Opnum 0) request to establish an RPC context handle.
4. **DRSGetNCChanges Call**: The client calls `DRSGetNCChanges` (Opnum 3), requesting database updates for specific Directory Partition Naming Contexts (NC), specifying object GUIDs (such as the target user account or `KRBTGT`).

To execute `DRSGetNCChanges` successfully, the calling identity does not necessarily need Domain Admin or Enterprise Admin group membership. Active Directory enforces security checks at the Object-Specific Control Access level. The caller must possess three specific Extended Rights on the Domain Head object (`domainDNS`):

*   **DS-Replication-Get-Changes** (`1131f6aa-9c0e-11d1-bf38-00c04fc2dcd2`)
*   **DS-Replication-Get-Changes-All** (`1131f6bb-9c0e-11d1-bf38-00c04fc2dcd2`)
*   **DS-Replication-Get-Changes-In-Filtered-Set** (`89e22742-73f7-4231-8283-73d130c1757a`) — Required in specific partial attribute set configurations, such as Read-Only Domain Controllers (RODCs).

By default, members of **Domain Admins**, **Enterprise Admins**, **Administrators**, and **Domain Controllers** possess these rights. However, threat actors often establish persistence by granting these rights to compromised standard user accounts or service accounts, a technique commonly referred to as ACL backdooring.

---

## Telemetry Prerequisite: The SACL Blindspot

A common trap for detection teams is assuming that enabling default Windows Security auditing on Domain Controllers will capture DCSync activity. It will not.

By default, enabling the audit policy **Audit Directory Service Access** logs reads and writes to Directory Service objects via Event ID 4662 (*"An operation was performed on an object"*). However, Windows will only generate Event ID 4662 for extended rights requests if a System Access Control List (SACL) is explicitly defined on the Domain Head object targeting the Control Access mask.

### Auditing Configuration Steps

To ensure DCSync activity generates log telemetry, two components must be configured:

#### 1. Advanced Audit Policy
Ensure **Audit Directory Service Access** is configured for **Success** across all Domain Controllers.

```powershell
# Verify audit policy setting via auditpol
auditpol /get /subcategory:"Directory Service Access"
```

#### 2. Domain Object SACL
A SACL must exist on the root domain object (`DC=domain,DC=com`) auditing `Control Access` operations for Everyone or Authenticated Users.

You can audit and verify the presence of this SACL using PowerShell:

```powershell
Import-Module ActiveDirectory

$DomainDN = (Get-ADDomain).DistinguishedName
$DomainACL = Get-Acl -Path "AD:\$DomainDN" -Audit

# Check if an Audit rule exists for Extended Rights / Control Access
$DomainACL.Audit | Where-Object {
    $_.ActiveDirectoryRights -match "ExtendedRight" -or 
    $_.AccessControlType -eq "Success"
} | Select-Object IdentityReference, ActiveDirectoryRights, AuditFlags, InheritedObjectType
```

If the SACL is absent, it must be added to the domain root object. You can apply it using `dsacls`:

```cmd
dsacls "DC=lab,DC=local" /G "S-1-1-0:CA;;"
```

*Note: Granting SACL access (`/G` with audit flags) creates an entry that forces the Local Security Authority Subsystem Service (LSASS) to generate an Event ID 4662 whenever any principal requests extended access rights on the domain head.*

---

## Telemetry Analysis: Windows Security Event ID 4662

When configured properly, a DCSync execution triggers **Event ID 4662** in the Security log of the Domain Controller that serviced the request.

### Log Breakdown

An Event ID 4662 generated by a DCSync request contains specific structural indicators:

```xml
Log Name:      Security
Source:        Microsoft-Windows-Security-Auditing
Event ID:      4662
Task Category: Directory Service Access
Level:         Information
Keywords:      Audit Success
Description:
An operation was performed on an object.

Subject:
    Security ID:        LAB\attacker_svc
    Account Name:       attacker_svc
    Account Domain:     LAB
    Logon Id:           0x1F4A82

Object:
    Server:             Active Directory Domain Services
    Type:               domainDNS
    Name:               DC=lab,DC=local
    Handle Id:          0x0

Operation:
    Type:               Object Access
    Properties:         
        Control Access
        {1131f6bb-9c0e-11d1-bf38-00c04fc2dcd2}
        {1131f6aa-9c0e-11d1-bf38-00c04fc2dcd2}
        {48283114-505a-11d0-b929-00c04fc2dcd2}
    Access Mask:        0x10
```

### Key Event Fields to Parse

1. **ObjectType / Type**: Must equal `domainDNS` (or GUID `{48283114-505a-11d0-b929-00c04fc2dcd2}`).
2. **AccessMask**: Value `0x10` indicates a `Control Access` request.
3. **Properties**: This field contains the GUIDs of the requested extended rights. A DCSync signature includes:
   * `{1131f6aa-9c0e-11d1-bf38-00c04fc2dcd2}` (`DS-Replication-Get-Changes`)
   * `{1131f6bb-9c0e-11d1-bf38-00c04fc2dcd2}` (`DS-Replication-Get-Changes-All`)
4. **SubjectUserSid / Account Name**: The account that performed the operation.

---

## Detection Engineering and KQL Logic

When engineering a SIEM detection rule for Event ID 4662, simple string matching on the GUIDs will produce a massive volume of false positives due to legitimate Domain Controller replication traffic.

### Filtering Baselines

To eliminate noise, your query logic must exclude:
1. **Domain Controller Computer Accounts**: Accounts ending in `$` that belong to known DCs (or identified by account SID matching the Domain Controllers OU).
2. **Azure AD Connect / Entra Connect Sync Accounts**: Dedicated service accounts (often starting with `MSOL_` or custom naming conventions) designed to sync passwords to the cloud using replication rights.
3. **Exchange Servers**: In certain legacy active directory schemas, Exchange servers hold elevated rights, though `Get-Changes-All` is rarely required for modern setups.

### Practical KQL Detection Query (Microsoft Sentinel / Defender for Identity)

```kql
SecurityEvent
| where EventID == 4662
| where ObjectServer == "Active Directory Domain Services"
// AccessMask 0x10 = Control Access
| where AccessMask == "0x10" or AccessMask == "16"
// Filter for Domain Head Object Class
| where Properties has "{1131f6aa-9c0e-11d1-bf38-00c04fc2dcd2}" 
     or Properties has "{1131f6bb-9c0e-11d1-bf38-00c04fc2dcd2}"
// Exclude legitimate DC Computer Accounts (ending in $)
| where not(Account endswith "$")
// Exclude known Entra Connect / MSOL accounts (Adjust regex based on environment naming standard)
| where not(Account matches regex @"(?i)^MSOL_[a-f0-9]+")
| project TimeGenerated, Computer, Account, AccountDomain, SubjectUserSid, Properties, AccessMask
```

---

## Network Telemetry: RPC Traffic Analysis

Event ID 4662 provides host-based attribution, but it relies on Windows auditing infrastructure. Threat actors who control underlying host logging or exploit log pipeline latency can bypass initial detection. Analyzing RPC network traffic provides an independent, unalterable detection vector.

### Identifying DRSUAPI Traffic at the Network Layer

Using Network Detection and Response (NDR) tools, Zeek, or Suricata, you can inspect the RPC traffic between endpoints and Domain Controllers.

Key network indicators include:
*   **RPC Interface UUID**: `e3514235-4b06-11d1-ab04-00c04fc2dcd2` (DRSUAPI)
*   **Opnum 3**: `DRSGetNCChanges`
*   **Source IP Analysis**: Cross-referencing the client source IP against an inventory of legitimate Domain Controllers and Entra Connect hosts.

If an IP address outside the known DC subnet issues an RPC bind to `drsuapi` followed by `DRSGetNCChanges`, it should trigger an immediate high-severity alert.

### Example Suricata Logic

```snort
alert tcp $HOME_NET any -> $DC_SERVERS 135 (msg:"EXPLOIT-KIT DCSync RPC Endpoint Mapper Request"; content:"|e3 51 42 35 4b 06 11 d1 ab 04 00 c0 4f c2 dc d2|"; sid:1000001; rev:1;)
```

*(Note: Endpoint mapper traffic resolves to a dynamic TCP port range [49152-65535 in Windows Server 2008 R2+]. Deep Packet Inspection engines should track the dynamic port binding negotiated during the RPC `EPM` response).*

---

## Edge Cases, False Positives, and Evasion Techniques

### 1. The Entra Connect / AADConnect Edge Case
Azure AD Connect uses `DS-Replication-Get-Changes` and `DS-Replication-Get-Changes-All` to perform Password Hash Synchronization (PHS). This service account will constantly generate Event 4662 logs matching the DCSync pattern.

**Mitigation**: Hardcode the SID or exact SAMAccountName of the Entra Connect account into your baseline exclusions, but closely monitor this account for anomalous logon locations (e.g., Event ID 4624 type 3 logons originating from unauthorized IPs).

### 2. AdminSDHolder and ACL Persistence
Attackers often grant standard accounts replication rights via the `AdminSDHolder` object or by modifying the security descriptor on the domain head directly.

Monitoring for DCSync shouldn't just be reactive (detecting when the protocol is invoked); it must be proactive (detecting when permissions are granted).

#### Monitoring Permission Grants (Event ID 5136)
When an attacker grants replication rights to an account, Active Directory records **Event ID 5136** (*"A directory service object was modified"*) if Directory Service Changes auditing is enabled.

Look for modifications where `AttributeLDAPDisplayName` is `nTSecurityDescriptor` on the domain root, and the security descriptor payload adds the GUIDs `{1131f6aa-9c0e-11d1-bf38-00c04fc2dcd2}` or `{1131f6bb-9c0e-11d1-bf38-00c04fc2dcd2}` to non-standard SIDs.

### 3. Read-Only Domain Controllers (RODCs)
RODCs utilize `DS-Replication-Get-Changes-In-Filtered-Set` (`89e22742-73f7-4231-8283-73d130c1757a`) to replicate a restricted set of attributes. Attackers target RODCs or exploit partial replication paths to extract secondary user credentials. Detection queries should monitor all three replication GUIDs concurrently.

---

## Defensive Checklist & Verification Workflow

To validate your environment's resilience against undetected DCSync attacks:

1. **Verify SACL Deployment**: Run a script across all domain roots to ensure a `Success` audit SACL is applied for Extended Rights / Control Access.
2. **Audit Tier 0 Delegations**: Periodically scan Active Directory for any non-DC principals holding the `DS-Replication-Get-Changes` and `DS-Replication-Get-Changes-All` rights using tools like `BloodHound` or custom PowerShell queries:
   ```powershell
   Get-Acl "AD:\DC=lab,DC=local" | Select-Object -ExpandProperty Access | 
   Where-Object { 
       ($_.ObjectType -eq "1131f6aa-9c0e-11d1-bf38-00c04fc2dcd2" -or 
        $_.ObjectType -eq "1131f6bb-9c0e-11d1-bf38-00c04fc2dcd2") -and
       $_.AccessControlType -eq "Allow"
   } | Select-Object IdentityReference, ActiveDirectoryRights
   ```
3. **Deploy Multi-Layered Detections**: Do not rely strictly on host Event 4662 logs. Combine Windows Security event monitoring with RPC network layer filtering and MDI (Microsoft Defender for Identity) signal ingestion.
