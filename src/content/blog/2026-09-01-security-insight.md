---
title: "Detecting DCSync Attacks: RPC Interfaces, Directory Auditing, and Event ID 4662"
description: "Learn how DCSync abuses Active Directory replication protocols to extract credential hashes and how to detect it using Event ID 4662 and RPC telemetry."
date: "2026-09-01"
tags: ["Cybersecurity", "Security Operations", "Active Directory", "Threat Detection"]
category: "Cyber Security"
difficulty: "Intermediate"
author: "Abdul Muqeet Tabraiz"
image: "/images/blog/2026-09-01-detecting-dcsync-attacks-rpc-interfaces-directory-auditing-and-event-id-4662.svg"
---

Once an attacker gains domain administrative privileges or compromises an account with specific extended directory rights, they rarely need to log into individual domain controllers to execute code or dump LSASS memory. Instead, they leverage native Active Directory protocols to ask a domain controller to hand over account password hashes directly.

This technique, known as DCSync, abuses the Directory Replication Service Remote Protocol (MS-DRSR) to impersonate a domain controller requesting replication data. Because it uses legitimate administrative protocols, detecting DCSync requires an understanding of how directory replication permissions work, which telemetry sources log these requests, and how to separate legitimate domain controller synchronization from unauthorized access.

---

### How DCSync Works

Domain controllers constantly sync Active Directory database updates among themselves. When a user changes their password on Domain Controller A, that update must replicate to Domain Controller B. This mechanism relies on the Directory Replication Service Remote Protocol (`MS-DRSR`), which exposes RPC interfaces for directory synchronization.

An attacker does not need interactive shell access on a Domain Controller to pull credential data. As long as they have valid network routing to TCP port 135 (RPC Endpoint Mapper) and dynamic RPC ports on the DC, along with account credentials possessing specific Active Directory permissions, they can issue replication requests from any host on the network.

DCSync attacks specifically target three extended rights on the Domain Naming Context (`Domain-DNS` object):

1. **Replicating Directory Changes** (`DS-Replication-Get-Changes`)
   * GUID: `1131f6aa-9c0e-11d1-bf38-00c04fa9386d`
2. **Replicating Directory Changes All** (`DS-Replication-Get-Changes-All`)
   * GUID: `1131f6ad-9c0e-11d1-bf38-00c04fa9386d`
3. **Replicating Directory Changes In Filtered Set** (`DS-Replication-Get-Changes-In-Filtered-Set`)
   * GUID: `89e6ac50-d24d-11d1-a960-00c04f79e5d9`

By default, members of **Domain Admins**, **Enterprise Admins**, **Administrators**, and **Domain Controllers** possess these rights. Tools like Mimikatz (`lsadump::dcsync`) or Impacket's `secretsdump.py` utilize the RPC interface `DRSUAPI` (UUID: `e3514235-4b06-11d1-ab04-00c04fc2dcd2`) to call functions such as `IDL_DRSGetNCChanges`. The Domain Controller processes the request, packs the encrypted password hashes (including history and Kerberos keys like `krbtgt`), and sends them back to the client host.

---

### Prerequisites for Telemetry: Enabling DS Access Auditing

By default, Windows does not generate event logs every time someone queries directory objects with specific access rights. To detect DCSync via native Windows event logs, you must ensure two logging prerequisites are configured across all Domain Controllers:

1. **Advanced Audit Policy Configuration**:
   * Path: `Computer Configuration -> Policies -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> Audit Policies -> DS Access`
   * Setting: Set **Audit Directory Service Access** to **Success**.

2. **System Access Control List (SACL) on Domain Object**:
   * You must verify that the root domain object has a SACL configured to audit successful access attempts for extended rights. 
   * In `Active Directory Users and Computers` (Advanced Features enabled), right-click the domain root -> **Properties** -> **Security** -> **Advanced** -> **Auditing tab**.
   * Ensure an auditing entry exists for **Everyone** or **Authenticated Users** auditing `Success` for access to extended properties/replication rights.

Without proper SACL configuration, the security log will remain silent during a DCSync execution, leaving you reliant solely on network traffic capture or RPC telemetry.

---

### Windows Event Log Telemetry: Event ID 4662

When DS Access Auditing and domain SACLs are properly set, an unauthorized replication request generates **Event ID 4662** (*An operation was performed on an object*) in the Security Event Log of the domain controller that processed the request.

#### Key Log Fields in Event ID 4662

```text
Log Name:      Security
Source:        Microsoft-Windows-Security-Auditing
Event ID:      4662
Task Category: Directory Service Access
Level:         Information
Subject:
	Security ID:		DOM\j.doe
	Account Name:		j.doe
	Account Domain:		DOM
	Logon ID:		0x1A4F92

Object:
	Server:			DS
	Object Type:		domainDNS
	Object Name:		DC=corp,DC=internal
	Properties:		
		{1131f6ad-9c0e-11d1-bf38-00c04fa9386d}
		{1131f6aa-9c0e-11d1-bf38-00c04fa9386d}
		{191d3583-9979-11d1-a960-00c04f79e5d9}

Access Process Information:
	Process ID:		0x1f4
	Process Name:		C:\Windows\NTDS\ntdsatq.dll

Access Request Information:
	Accesses:		Control Access
	Access Mask:		0x100
```

To interpret this log effectively:
* **Subject Account Name**: Identifies the user or computer account performing the sync request.
* **Object Type**: `domainDNS` represents the root of the Active Directory domain.
* **Properties**: Contains the GUIDs of the rights exercised during the operation. Look for `{1131f6ad-9c0e-11d1-bf38-00c04fa9386d}` (`DS-Replication-Get-Changes-All`) and `{1131f6aa-9c0e-11d1-bf38-00c04fa9386d}` (`DS-Replication-Get-Changes`).
* **Access Mask**: `0x100` corresponds to `RIGHT_DS_CONTROL_ACCESS` (Control Access).

---

### Building Practical Detection Logic

The primary baseline rule for detecting DCSync is simple: **Replication extended rights should only be requested by computer accounts belonging to actual Domain Controllers, or legitimate sync service accounts like Microsoft Entra Connect (formerly Azure AD Connect).**

If a standard user account, a workstation computer account (`WORKSTATION123$`), or an unexpected administrative account requests these GUIDs, it is almost certainly a malicious attempt to pull domain credential hashes.

#### SIEM Detection Query (KQL)

```kql
SecurityEvent
| where EventID == 4662
| where ObjectType == "%{191d3583-9979-11d1-a960-00c04f79e5d9}" or ObjectType == "domainDNS"
| where Properties has "{1131f6ad-9c0e-11d1-bf38-00c04fa9386d}" 
     or Properties has "{1131f6aa-9c0e-11d1-bf38-00c04fa9386d}"
| where AccessMask == "0x100"
// Filter out legitimate Domain Controllers (Computer accounts ending in $)
| where not(AccountName endswith "$" and AccountDomain == "CORP")
// Filter out explicitly approved synchronization service accounts (e.g., Entra Connect)
| where AccountName != "svc_entra_sync"
| project TimeGenerated, Computer, AccountName, AccountDomain, SubjectUserSid, Properties, AccessMask
```

#### SIEM Detection Query (Splunk SPL)

```spl
index=winsec EventCode=4662 AccessMask="0x100"
("{1131f6ad-9c0e-11d1-bf38-00c04fa9386d}" OR "{1131f6aa-9c0e-11d1-bf38-00c04fa9386d}")
| eval Account = lower(Account_Name)
| search NOT (Account="*$") NOT (Account="svc_entra_sync")
| table _time, host, Account, Account_Domain, Properties
```

---

### Network and RPC-Level Telemetry

Event logs tell you *who* requested replication, but network and endpoint-level RPC telemetry provides additional context, including the source IP address of the attacker's machine.

Because DCSync leverages RPC over TCP, you can correlate Event ID 4662 with RPC endpoint connection logs or network stream data:

1. **RPC Interface ID**: `e3514235-4b06-11d1-ab04-00c04fc2dcd2` (DRSUAPI protocol).
2. **Opcode**: `IDL_DRSGetNCChanges` (Opnum `3`).

If you collect Zeek/Corelight network logs, NDR telemetry, or Windows Defender for Identity (MDI) alerts, you can inspect RPC transactions to identify traffic directed at Domain Controllers from non-DC IP subnets.

#### Key Network Anomalies to Track

* **Source IP Context**: A Domain Controller issuing a `DRSGetNCChanges` request to another DC is normal. An IP address assigned to a VPN range, workstation VLAN, or compromised jump box initiating `DRSGetNCChanges` is abnormal.
* **Kerberos Service Ticket Requests**: Prior to making the RPC connection, the client will request a Kerberos ticket for the target Domain Controller's DRS service (SPN format: `ldap/dcname.domain.com` or `GC/dcname.domain.com`).

---

### Handling Legitimate False Positives

When tuning DCSync detections, you will inevitably run into authorized tools that legitimate systems use to synchronize directory objects:

1. **Microsoft Entra Connect (Azure AD Connect)**:
   * Uses a dedicated service account to read account attributes and password hashes (if Password Hash Sync is enabled).
   * Generates Event ID 4662 entries containing the replication GUIDs frequently.
   * **Mitigation**: Strictly scope detection exclusions to the exact service account name used by Entra Connect, and optionally restrict that account's logon to the specific IP address or host running the sync service.

2. **Read-Only Domain Controllers (RODCs)**:
   * RODCs periodically issue replication requests for cached credentials.
   * Requests include the filtered set GUID (`89e6ac50-d24d-11d1-a960-00c04f79e5d9`). Ensure your detection logic distinguishes standard full-replication calls from filtered set requests depending on your environment's deployment.

3. **Identity Security Tools and CyberArk / Account Discovery Solutions**:
   * Security auditing software or privileged access management (PAM) solutions might conduct directory discovery. Verify these systems with system administrators and add explicit exclusions based on service account SIDs.

---

### Incident Investigation Workflow

When a DCSync alert fires for an unexpected user or system, treat it as a critical security incident indicating high-privilege domain compromise. 

```
[ Alert: Event ID 4662 / DCSync Detected ]
                  │
                  ▼
   Check Account Type & Source IP
                  │
        ┌─────────┴─────────┐
        ▼                   ▼
[ Machine Account ]   [ User Account ]
        │                   │
        ├─ Is it a DC?      ├─ Is it Entra Sync?
        │  (If no -> Alert) │  (If no -> Compromised Admin)
        │                   │
        ▼                   ▼
    Correlate IP with Network Logs / Network Session
                  │
                  ▼
 Identify Host Originating the RPC Connection
                  │
                  ▼
   Isolate Host & Revoke Compromised Credentials
```

#### Step 1: Identify the Source Host
Match the `Logon ID` from Event ID 4662 with **Event ID 4624** (Successful Logon) generated at or just before the replication event on the DC. This correlates the `Subject User SID` and `Logon ID` to the `Source Network Address` (Workstation IP).

#### Step 2: Determine Compromise Scope
Determine which target account hashes were pulled. Attackers running `lsadump::dcsync` often request the `krbtgt` account hash first to create Golden Tickets, followed by high-value accounts like `Administrator` or target service accounts.

#### Step 3: Containment
* Immediately isolate the source machine identified in Step 1.
* Terminate active sessions for the compromised user account used to initiate the sync request.
* Reset the password of the compromised user account twice if it was a domain admin.
* If the `krbtgt` account hash was queried, initiate your organization's `krbtgt` password reset procedure (resetting it twice over a staggered timeframe to invalidate existing TGTs without breaking active Kerberos tickets immediately).

---

### Hardening Against DCSync

Detection should always be backed by preventive measures. You can reduce your exposure to DCSync by enforcing strict access control policies on Active Directory objects:

* **Audit Domain ACLs Regularly**: Run tools like `BloodHound` or PowerShell modules (`PowerView`, `Get-Acl`) to locate non-standard accounts possessing `DS-Replication-Get-Changes` and `DS-Replication-Get-Changes-All` permissions. Remove unnecessary rights immediately.
* **Implement Administrative Tiering**: Restrict Domain Admin accounts from logging into lower-tier assets (Tier 1 servers, Tier 2 workstations). DCSync requires elevated domain privileges; preventing credentials from exposure on end-user machines stops attackers from harvesting the necessary access tokens in the first place.
* **Restrict RPC Traffic to DCs**: Enforce network boundary rules or host-based firewalls on Domain Controllers to ensure that RPC traffic for directory replication is only accepted from known, explicitly listed Domain Controller IP addresses and designated management servers.
