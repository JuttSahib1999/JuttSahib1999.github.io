---
title: "Detecting DCSync Attacks: Directory Replication Telemetry, Event ID 4662, and Network RPC Analysis"
description: "An in-depth guide to detecting DCSync attacks through Windows Event Log 4662, RPC network traffic, and identity telemetry while managing operational false positives."
date: "2026-09-20"
tags: ["Cybersecurity", "Security Operations"]
category: "Cyber Security"
difficulty: "Advanced"
author: "Abdul Muqeet Tabraiz"
image: "/images/blog/2026-09-20-detecting-dcsync-attacks-directory-replication-telemetry-event-id-4662-and-netwo.svg"
---

DCSync remains one of the most effective post-exploitation techniques against Active Directory. First integrated into Mimikatz by Benjamin Delpy and Vincent Le Toux, the attack allows an adversary with sufficient privileges to extract password hashes, Kerberos keys (including the `krbtgt` account hash), and historical passwords directly from a Domain Controller without executing custom code on the DC itself.

Because DCSync leverages native Directory Replication Service Remote Protocol (MS-DRSR) calls, traditional host-based endpoint detection and response (EDR) agents running on Domain Controllers often fail to flag the activity if they only inspect process creation or LSASS memory access. Detecting DCSync requires defenders to focus on object-level access auditing in Active Directory, RPC transport telemetry, and account baseline filtering.

## Mechanics of MS-DRSR and DCSync

Active Directory relies on multi-master replication. Domain Controllers continuously communicate with each other using the Directory Replication Service Remote (MS-DRSR) protocol over RPC to synchronize directory object state across the domain.

When a Domain Controller needs to fetch updates from a replication partner, it binds to the DRSR RPC interface and issues an `IDL_DRSGetNCChanges` request. The responding DC packages the requested naming context (NC) objects—including encrypted password attributes like `unicodePwd`—and transmits them back.

In a DCSync attack, the adversary does not compromise the host operating system of the Domain Controller to dump `NTDS.dit` or read LSASS memory. Instead, from any domain-joined host (or an unjoined host with network line-of-sight and valid credentials), the attack tool performs the following steps:

1. Connects to the target Domain Controller over RPC.
2. Binds to the MS-DRSR interface UUID: `e3514235-4b06-11d1-ab04-00c04fc2dcd2`.
3. Issues `IDL_DRSGetNCChanges` specifying the target domain object GUID and requested account attributes (e.g., `krbtgt`, `Administrator`).
4. Receives the directory data containing password hashes encrypted under the domain's session key and decrypts them locally.

```
+------------------+         RPC Binding: MS-DRSR (UUID: e3514235-...)        +-------------------+
| Attacker Machine | --------------------------------------------------------> | Domain Controller |
| (secretsdump /   |                                                          | (LSASS / NTDS)    |
|  Mimikatz)       | <------------------------------------------------------- |                   |
+------------------+     IDL_DRSGetNCChanges Response (Hashes Transmitted)    +-------------------+
```

Because this interaction uses valid RPC messages, the target Domain Controller treats the client as a legitimate peer performing directory synchronization, provided the account making the request holds the necessary control access rights.

## Active Directory Extended Rights Infrastructure

Active Directory enforces permissions for replication through specific Extended Rights (Control Access Rights) on the Domain Head object (`domainDNS`). To issue `IDL_DRSGetNCChanges` successfully, an security principal must hold two mandatory Extended Rights on the root object of the domain:

1. **DS-Replication-Get-Changes**
   * **Rights-GUID**: `1131f6aa-9c0e-11d1-bf38-00c04fc93692`
2. **DS-Replication-Get-Changes-All**
   * **Rights-GUID**: `1131f6bc-9c0e-11d1-bf38-00c04fc93692`

A third right exists for filtered attribute sets, typically assigned to Read-Only Domain Controllers (RODCs):

3. **DS-Replication-Get-Changes-In-Filtered-Set**
   * **Rights-GUID**: `89e1d49e-11d0-11d1-a99f-00aa00c67d42`

By default, these rights are granted only to members of the **Domain Admins**, **Enterprise Admins**, and **Domain Controllers** groups, as well as the **SYSTEM** identity of DCs. 

However, attackers often look for misconfigurations where administrative accounts have delegated these rights to non-standard service accounts or security groups. Furthermore, if an attacker gains control of a Domain Admin account, they can grant these rights to a compromised low-privileged account to establish persistent, low-profile credential harvest mechanisms.

## Endpoint Telemetry: Windows Event ID 4662

To capture DCSync requests at the endpoint level, Domain Controllers must be configured to audit Directory Services Access.

### Auditing Configuration

By default, Active Directory object access auditing is either disabled or configured too broadly without capturing specific control access rights. You must ensure the following Group Policy audit settings are active across all Domain Controllers:

* **Policy Path**: `Computer Configuration > Windows Settings > Security Settings > Advanced Audit Policy Configuration > Audit Policies > DS Access`
* **Setting**: `Audit Directory Service Access` -> Set to **Success**

Additionally, a System Access Control List (SACL) must exist on the domain root object auditing `Control Access` operations for `Everyone` or `Authenticated Users`. In default Active Directory deployments, this SACL is present out of the box, but it is critical to verify that object inheritance has not been broken.

### Analyzing Event ID 4662

When a client queries the domain object for replication, the Domain Controller generates **Event ID 4662** (`An operation was performed on an object`) in the `Security` log.

Below is an example snippet of a raw 4662 log generated during a DCSync execution via Impacket's `secretsdump.py`:

```xml
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <EventID>4662</EventID>
    <Version>0</Version>
    <Level>0</Level>
    <Task>14080</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8020000000000000</Keywords>
    <TimeCreated SystemTime="2026-09-20T14:22:10.118432100Z" />
    <EventRecordID>9841204</EventRecordID>
    <Execution ProcessID="680" ThreadID="1924" />
    <Channel>Security</Channel>
    <Computer>DC01.lab.local</Computer>
    <Security />
  </System>
  <EventData>
    <Data Name="SubjectUserSid">S-1-5-21-392817293-102938102-391827361-1105</Data>
    <Data Name="SubjectUserName">svc_backup</Data>
    <Data Name="SubjectDomainName">LAB</Data>
    <Data Name="SubjectLogonId">0x3e7a1f</Data>
    <Data Name="ObjectServer">DS</Data>
    <Data Name="ObjectType">%{19194120-12da-11d0-b92f-00a0c91e9b46}</Data>
    <Data Name="ObjectName">DC=lab,DC=local</Data>
    <Data Name="OperationType">Object Access</Data>
    <Data Name="AccessList">Control Access</Data>
    <Data Name="AccessMask">0x10</Data>
    <Data Name="Properties">
      {1131f6bc-9c0e-11d1-bf38-00c04fc93692}
      {19194120-12da-11d0-b92f-00a0c91e9b46}
    </Data>
  </EventData>
</Event>
```

Key fields to extract during parsing:

* **ObjectType**: `%{19194120-12da-11d0-b92f-00a0c91e9b46}` corresponds to the Schema Class GUID for `domainDNS`.
* **AccessMask**: `0x10` indicates `RIGHT_DS_CONTROL_ACCESS`.
* **Properties**: Look for the presence of the replication Extended Rights GUIDs:
  * `{1131f6aa-9c0e-11d1-bf38-00c04fc93692}` (`DS-Replication-Get-Changes`)
  * `{1131f6bc-9c0e-11d1-bf38-00c04fc93692}` (`DS-Replication-Get-Changes-All`)
* **SubjectUserName** / **SubjectUserSid**: The identity requesting the replication data.

## Network Telemetry: RPC Traffic Analysis

Relying solely on Event 4662 can leave blind spots if auditing is altered or if event logs are saturated. Complementing host logs with network telemetry provides an independent detection layer.

When monitoring network taps or analyzing PCAPs via Zeek, Suricata, or NDR platforms, DCSync traffic exhibits distinct characteristics:

1. **Transport**: RPC over SMB (TCP 445 via `\pipe\lsass` or `\pipe\netlogon`) or direct RPC over TCP using dynamic high ports endpoint mapped via TCP port 135.
2. **Interface UUID**: MS-DRSR Interface `e3514235-4b06-11d1-ab04-00c04fc2dcd2`.
3. **Opnum (Operation Number)**:
   * **Opnum 3**: `IDL_DRSGetNCChanges`

Using Zeek's DCE-RPC parser, you can track DRSR interface calls natively. A Zeek `dce_rpc.log` entry capturing a DCSync request will log:

```
#path dce_rpc
#fields ts uid id.orig_h id.orig_p id.resp_h id.resp_p endpoint operation
1790000530.12  CAb2131  192.168.10.45  51204  192.168.10.5  135  drsuapi  IDL_DRSGetNCChanges
```

If the source IP address (`id.orig_h`) does not map to a known Domain Controller, Read-Only Domain Controller, or authorized Entra Connect / Azure AD Connect sync server, the flow is anomalous.

## Constructing Detection Logic

To build effective SIEM alert logic, you must correlate the access operation (`0x10`) against the extended rights GUIDs while filtering out legitimate directory replication actors.

### Kusto Query Language (KQL) Implementation

This query searches Microsoft Sentinel / Defender XDR `SecurityEvent` tables for Event 4662 indicators matching DCSync patterns:

```kql
let KnownDCs = pack_array(
    "DC01$", 
    "DC02$", 
    "DC03$"
);
let AllowedSyncAccounts = pack_array(
    "MSOL_13ab902f1a2b$",
    "AAD_Sync_Service"
);
SecurityEvent
| where EventID == 4662
| where ObjectServer == "DS"
// 0x10 corresponds to Control Access
| where AccessMask == "0x10" or AccessMask == "16"
// Filter for Domain Object GUID class
| where ObjectType =~ "%{19194120-12da-11d0-b92f-00a0c91e9b46}" or ObjectType =~ "{19194120-12da-11d0-b92f-00a0c91e9b46}"
// Match Replication-Get-Changes or Replication-Get-Changes-All GUIDs
| where Properties has "1131f6aa-9c0e-11d1-bf38-00c04fc93692" 
     or Properties has "1131f6bc-9c0e-11d1-bf38-00c04fc93692"
// Exclude legitimate Domain Controller computer accounts
| where not(SubjectUserName in~ (KnownDCs))
// Exclude legitimate Azure AD / Entra Connect service accounts
| where not(SubjectUserName in~ (AllowedSyncAccounts))
// Exclude SYSTEM account on local DCs
| where not(SubjectUserName == "SYSTEM" or SubjectUserName endswith "$")
| project TimeGenerated, Computer, SubjectDomainName, SubjectUserName, SubjectUserSid, AccessMask, Properties, Activity
```

### Splunk Search Processing Language (SPL) Implementation

For Splunk users monitoring Windows Security Event Logs via the `WinEventLog:Security` sourcetype:

```spl
index=wineventlog EventCode=4662 ObjectServer="DS" (AccessMask="0x10" OR AccessMask="16")
| eval Properties=lower(Properties)
| search (Properties="*{1131f6aa-9c0e-11d1-bf38-00c04fc93692}*" OR Properties="*{1131f6bc-9c0e-11d1-bf38-00c04fc93692}*")
| search NOT (SubjectUserName="*$")
| search NOT (SubjectUserName="MSOL_*")
| stats count min(_time) as first_seen max(_time) as last_seen by Computer, SubjectDomainName, SubjectUserName, SubjectUserSid, AccessMask, Properties
| convert timeformat="%Y-%m-%d %H:%M:%S" ctime(first_seen) ctime(last_seen)
```

## Triage Workflow and Operational Exceptions

When a DCSync alert fires, SOC analysts must quickly differentiate between legitimate synchronization activity, benign administrative tools, and adversary tradecraft.

```
+-------------------------------------------------------+
|                 DCSync Alert Fires                    |
+-------------------------------------------------------+
                           |
                           v
        Is SubjectUserName a Machine Account ($)?
                         /   \
                       Yes    No
                       /        \
                      v          v
   Is source IP a known DC?     Check Azure AD / Entra Sync
          /          \          Service Account Allowlist
        Yes           No                    |
        /              \                    v
  [Legitimate]   [Suspicious Machine]   Is source IP verified?
  [DC Sync   ]   [Account / Rogue DC]      /          \
                                         Yes           No
                                         /              \
                                   [Legitimate]   [Compromised Account]
                                   [Entra Sync]   [CRITICAL SEVERITY  ]
```

### 1. Identify the Initiating Account

Verify the `SubjectUserName` and `SubjectUserSid`. 

* **Domain Controller Accounts (`DC-NAME$`)**: Machine accounts of existing DCs constantly execute `IDL_DRSGetNCChanges`. If the alert triggers on a machine account, cross-reference the source IP address in Network/VPN logs to ensure the request originated from the actual physical/virtual IP assigned to that Domain Controller. An attacker who has compromised a standard workstation could attempt to spoof a machine account name if operating within an unauthenticated session, though Kerberos authentication typically prevents arbitrary SID spoofing.
* **Entra Connect / Azure AD Connect Service Accounts**: Organizations running hybrid Active Directory environments rely on Azure AD Connect (now Microsoft Entra Connect) to sync hashes to the cloud. The service account used by Entra Connect requires `DS-Replication-Get-Changes` and `DS-Replication-Get-Changes-All`. These accounts (often named `MSOL_...` or custom service accounts like `svc-entraconnect`) will trigger Event 4662 continuously.

### 2. Validate the Source IP and Network Binding

Correlate Event 4662 with **Event ID 4624** (Successful Logon) on the Domain Controller using the `SubjectLogonId`. 

Inspect the `WorkstationName` and `IpAddress` fields in the corresponding 4624 event:
* If a domain administrator account (`admin_alice`) issued the request from a non-DC workstation IP (e.g., `10.200.4.15`), this is **high-confidence malicious activity**. Domain Admins do not naturally invoke replication protocols manually during routine tasks unless running specialized sync tools.

### 3. Assess the Replication Scope

Attackers running Mimikatz or Impacket usually request sensitive account targets immediately (`krbtgt`, `Administrator`). Review surrounding network packets or endpoint command lines (if EDR telemetry is available on the source host) for arguments such as `/domain:lab.local /user:krbtgt` or `-just-dc-user krbtgt`.

If the request fetches the entire directory database in a short timeframe, assess whether a rogue Domain Controller join operation occurred (e.g., via `ServerManager` or automated promotion scripts).

## Evasion Techniques and Detection Limitations

Adversaries are aware of Event 4662 monitoring and employ techniques to minimize detection footprints:

### 1. Filtered Replication Requests
Rather than requesting the entire domain object partition, an attacker may restrict replication requests to specific single user objects or attributes. While this alters the data payloads, it **does not** bypass Event 4662 logging because the control access checks on the domain object are still evaluated when the RPC interface processes `IDL_DRSGetNCChanges`.

### 2. Audit Suppression / Policy Modification
If an attacker achieves `SYSTEM` access on a Domain Controller, they can attempt to clear security event logs (`wevtutil cl Security`) or modify the DS Access SACL using `auditpol /set /subcategory:"Directory Service Access" /success:disable`. 

Defenders should pair DCSync detection rules with alerts that monitor for audit policy modifications (Event ID 4719) and event log clearing (Event ID 1102).

### 3. Bypassing EDR on the Target DC
Because DCSync processes entirely inside `lsass.exe` via legitimate RPC server threads, host EDRs running on the DC will not see malicious process creation (e.g., no `mimikatz.exe` is executing on the DC). Relying on EDR process creation trees on Domain Controllers to catch DCSync is an architectural failure; monitoring *must* center on network RPC interfaces and Active Directory DS access event logs.

## Hardening Active Directory Against DCSync

Detection is critical, but preventing unauthorized accounts from possessing replication rights reduces the attack surface significantly.

### Conduct ACL Auditing on the Domain Object
Run PowerShell queries using the `ActiveDirectory` module or PowerView to audit all explicit and inherited Access Control Entries (ACEs) on the root of the domain:

```powershell
Import-Module ActiveDirectory
$DomainDN = (Get-ADDomain).DistinguishedName
$Acl = Get-Acl "AD:\$DomainDN"

$ReplicationGUIDs = @(
    "1131f6aa-9c0e-11d1-bf38-00c04fc93692", # Get-Changes
    "1131f6bc-9c0e-11d1-bf38-00c04fc93692", # Get-Changes-All
    "89e1d49e-11d0-11d1-a99f-00a00c67d42"  # Filtered-Set
)

foreach ($Access in $Acl.Access) {
    if ($Access.ObjectType.ToString() -in $ReplicationGUIDs) {
        [PSCustomObject]@{
            Identity           = $Access.IdentityReference
            ActiveDirectoryRight = $Access.ActiveDirectoryRights
            AccessControlType  = $Access.AccessControlType
            ObjectType         = $Access.ObjectType
        }
    }
}
```

### Operational Guidance
1. **Remove Excessive Delegations**: Ensure no standard user, helpdesk tier, or unapproved service account holds `DS-Replication-Get-Changes` or `DS-Replication-Get-Changes-All`.
2. **Restrict Entra Connect Sync Servers**: Lock down the server hosting Azure AD / Entra Connect. The service account assigned to Entra Connect should be treated with the same operational security controls as a Domain Controller.
3. **Use Dedicated Privileged Access Workstations (PAWs)**: Require all administrative tasks to originate from hardened PAWs, restricting administrative IP spaces so network detectors can easily spot out-of-band RPC replication calls.
4. **Implement Tiered Administration**: Enforce strict administrative boundaries (Tier 0 / Control Plane). Domain Admin accounts must never log on to lower-tier hosts where credentials can be stolen to perform DCSync attacks.
