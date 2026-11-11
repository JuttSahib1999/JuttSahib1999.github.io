---
title: "Detecting DCSync Attacks: Telemetry, SACL Auditing, and Network RPC Analysis"
description: "A technical deep dive into detecting MS-DRSR abuse, configuring Active Directory SACLs for Event ID 4662, and filtering legitimate replication traffic."
date: "2026-11-11"
tags: ["Cybersecurity", "Security Operations", "Active Directory", "Detection Engineering"]
category: "Cyber Security"
difficulty: "Advanced"
author: "Abdul Muqeet Tabraiz"
image: "/images/blog/2026-11-11-detecting-dcsync-attacks-telemetry-sacl-auditing-and-network-rpc-analysis.svg"
---

A DCSync attack allows an adversary with sufficient Active Directory permissions to pull credential material—including NTLM hashes, Kerberos keys, and historical passwords—directly from a Domain Controller without executing arbitrary code on the DC itself. Because the technique relies on legitimate Directory Replication Service Remote Protocol (MS-DRSR) requests, traditional endpoint security solutions running on the DC often fail to flag the execution.

Detecting DCSync effectively requires combining Windows Event Log auditing (specifically Event ID 4662), System Access Control List (SACL) auditing on the domain head, and network-level RPC telemetry.

## The Protocol Mechanics of DCSync

To pull secrets from Active Directory, a DC uses the `MS-DRSR` RPC interface. When a legitimate Domain Controller needs to synchronize updates with another DC, it invokes the `IDL_DRSGetNCChanges` function (Opnum 3) over the DRSR interface.

An attacker utilizing tools such as Mimikatz (`lsadump::dcsync`) or Impacket (`secretsdump.py`) performs the following sequence:

1. **RPC Binding**: Connects to the Remote Procedure Call (RPC) Endpoint Mapper on TCP port 135 of a target DC to request the dynamic port assigned to the Directory Replication Service interface (UUID: `e3514235-4b6e-11d1-abda-0000f875ae93`).
2. **Bind Context**: Binds to the DRSR RPC interface.
3. **DRSConnect Request**: Calls `IDL_DRSBind` to negotiate protocol capabilities.
4. **DRSGetNCChanges Request**: Calls `IDL_DRSGetNCChanges` specifying the target Naming Context (NC) and requesting specific object attributes (such as `unicodePwd`, `dBCSPwd`, `supplementalCredentials`, or `keys`).

```
[ Attacker Workstation ]
        │
        ├─ 1. DCE/RPC Bind Request (Port 135 -> Ephemeral Port)
        │      Interface UUID: e3514235-4b6e-11d1-abda-0000f875ae93 (MS-DRSR)
        │
        ├─ 2. IDL_DRSBind Call
        │
        └─ 3. IDL_DRSGetNCChanges Call ────────────────────────┐
               (Requests Naming Context & Credential Attributes)│
                                                               ▼
                                                    [ Domain Controller ]
                                                       Evaluates ACLs:
                                                       - Replicating Directory Changes
                                                       - Replicating Directory Changes All
                                                       - Replicating Directory Changes In Filtered Set
```

Active Directory enforces permissions at the Domain Naming Context root object. To successfully issue `IDL_DRSGetNCChanges` for password data, the requesting security principal must hold three extended rights (or a specific combination depending on the domain functional level and targeted attributes):

* **DS-Replication-Get-Changes** (`1131f6aa-9c0e-11d1-bf38-0000f875ae93`)
* **DS-Replication-Get-Changes-All** (`1131f6ad-9c0e-11d1-bf38-0000f875ae93`)
* **DS-Replication-Get-Changes-In-Filtered-Set** (`89e280f1-64d1-4770-9f96-b78913956712`) — *Required in scenarios involving Read-Only Domain Controllers (RODCs) or Partial Attribute Sets.*

By default, members of **Domain Admins**, **Enterprise Admins**, **Administrators**, and **Domain Controllers** possess these rights. If an account outside these groups—or an compromised account granted explicit access—issues these requests, a DCSync attack is occurring.

---

## Host Telemetry and SACL Configuration

By default, Active Directory does not generate telemetry when an account exercises replication rights. Relying solely on default auditing leaves security operations blind to DCSync.

### Step 1: Enable Directory Service Access Auditing
Ensure that Advanced Audit Policy Configuration is configured across all DCs:

```
Computer Configuration -> Policies -> Windows Settings -> Security Settings ->
Advanced Audit Policy Configuration -> Audit Policies -> Account Management / DS Access ->
Audit Directory Service Access -> Success
```

### Step 2: Configure the Domain Head SACL
To force the DC to generate **Event ID 4662** ("An operation was performed on an object"), you must modify the SACL on the domain root object (`DC=domain,DC=com`):

1. Open `ADSI Edit` or `Active Directory Users and Computers` (with Advanced Features enabled).
2. Right-click the domain root node and select **Properties** -> **Security** -> **Advanced** -> **Auditing**.
3. Add an audit entry for **Everyone** (or `Principal: Everyone`).
4. Set **Type** to `Success`.
5. Set **Applies to** to `This object and all descendant objects` (or `This object only`).
6. In **Permissions**, check the boxes for:
   * **Replicating Directory Changes**
   * **Replicating Directory Changes All**
   * **Replicating Directory Changes In Filtered Set**

```
+--------------------------------------------------------------------------+
| Audit Entry for Domain Root                                              |
+--------------------------------------------------------------------------+
| Principal:   Everyone                                                    |
| Type:        Success                                                     |
| Access:      Control Access (Extended Right)                             |
| Applies to:  This object only                                            |
|                                                                          |
| Enabled Audit Rights:                                                    |
| [X] Replicating Directory Changes     {1131f6aa-9c0e-11d1-bf38-...}      |
| [X] Replicating Directory Changes All {1131f6ad-9c0e-11d1-bf38-...}      |
| [X] Replicating Directory Changes In Filtered Set                        |
|                                       {89e280f1-64d1-4770-9f96-...}      |
+--------------------------------------------------------------------------+
```

Once applied, exercising replication rights generates Event ID 4662 in the `Security` event log of the targeted DC.

### Event ID 4662 Structure Analysis

A standard 4662 log triggered by a DCSync execution contains critical fields:

```xml
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <EventID>4662</EventID>
    <Channel>Security</Channel>
    <Computer>DC01.corp.internal</Computer>
  </System>
  <EventData>
    <Data Name="SubjectUserSid">S-1-5-21-342890123-1123581321-987654321-1008</Data>
    <Data Name="SubjectUserName">svc_backup</Data>
    <Data Name="SubjectDomainName">CORP</Data>
    <Data Name="SubjectLogonId">0x3e7a12</Data>
    <Data Name="ObjectServer">DS</Data>
    <Data Name="ObjectType">%{19199383-063c-11d0-ad3b-00c04fd8d5cd}</Data>
    <Data Name="ObjectName">%15d03829-19c2-482a-9e23-7a1a45bb3e18</Data>
    <Data Name="OperationType">Object Access</Data>
    <Data Name="Properties">
      {1131f6ad-9c0e-11d1-bf38-0000f875ae93}
      {19199383-063c-11d0-ad3b-00c04fd8d5cd}
    </Data>
    <Data Name="AccessMask">0x100</Data>
  </EventData>
</Event>
```

Key fields to extract for detection rules:

* **Properties**: Contains the schema GUID of the requested right. `1131f6ad-9c0e-11d1-bf38-0000f875ae93` corresponds to `DS-Replication-Get-Changes-All`.
* **SubjectUserName** / **SubjectUserSid**: The identity requesting replication data.
* **ObjectType**: `{19199383-063c-11d0-ad3b-00c04fd8d5cd}` identifies the domainDNS object class.

---

## Detection Engineering and SIEM Analytics

Building a detection rule around Event ID 4662 requires isolating unauthorized replication access while filtering out expected infrastructure accounts.

### Baseline Noise Considerations

Legitimate accounts executing replication requests include:

1. **Domain Controller Computer Accounts**: Format `DC_NAME$` (e.g., `DC01$`, `DC02$`).
2. **Azure AD Connect / Entra Connect Service Accounts**: Often named `MSOL_xxxxxxxxx` or custom gMSA accounts used for directory synchronization.
3. **Microsoft Exchange Servers**: During installation or domain prep, Exchange setup handles extended rights.

If an account outside of these trusted identities requests `DS-Replication-Get-Changes-All` (`1131f6ad-9c0e-11d1-bf38-0000f875ae93`) or `DS-Replication-Get-Changes` (`1131f6aa-9c0e-11d1-bf38-0000f875ae93`), flag it immediately.

### KQL Detection Query (Microsoft Sentinel / Defender for Identity)

```kql
SecurityEvent
| where EventID == 4662
| where ObjectType == "%{19199383-063c-11d0-ad3b-00c04fd8d5cd}" or ObjectType == "{19199383-063c-11d0-ad3b-00c04fd8d5cd}"
| where Properties has "{1131f6ad-9c0e-11d1-bf38-0000f875ae93}" 
     or Properties has "{1131f6aa-9c0e-11d1-bf38-0000f875ae93}"
     or Properties has "{89e280f1-64d1-4770-9f96-b78913956712}"
// Exclude legitimate Machine Accounts (Domain Controllers)
| where not(SubjectUserName endswith "$")
// Exclude known Entra Connect accounts (Maintain a strict, audited watch list)
| where not(SubjectUserName startswith "MSOL_")
| project 
    TimeGenerated, 
    Computer, 
    SubjectDomainName, 
    SubjectUserName, 
    SubjectUserSid, 
    Properties, 
    AccessMask
```

### Splunk SPL Detection Query

```spl
index=wineventlog EventCode=4662 
(Properties="*{1131f6ad-9c0e-11d1-bf38-0000f875ae93}*" OR Properties="*{1131f6aa-9c0e-11d1-bf38-0000f875ae93}*")
NOT (SubjectUserName="*$" OR SubjectUserName="MSOL_*")
| stats count min(_time) as firstTime max(_time) as lastTime by Computer, SubjectDomainName, SubjectUserName, SubjectUserSid, Properties
| convert timeformat="%Y-%m-%d %H:%M:%S" timefield=firstTime
| convert timeformat="%Y-%m-%d %H:%M:%S" timefield=lastTime
```

---

## Network Telemetry and Network Detection Systems (NDS)

Relying exclusively on Event 4662 has a operational constraint: if an attacker manages to bypass Windows Event Logging or compromise a host generating massive event volume, network-level inspection provides an independent telemetry layer.

DCSync traffic relies on DCE/RPC calls over TCP. Security operations teams monitoring raw packet capture (PCAP) or using network sensors (Zeek, Suricata) can detect DRSR replication requests originating from non-DC IP addresses.

### Zeek Script Detection

Zeek's DCE/RPC analyzer parses RPC bindings and opcodes. The following script detects `MS-DRSR` RPC interface calls where the source IP address is not in a defined set of legitimate Domain Controller IP addresses:

```zeek
module AD_DCSync;

export {
    redef enum Notice::Type += { Suspicious_DCSync_Attempt };
    
    # Define known legitimate Domain Controller IP addresses
    const trusted_dcs: set[addr] = { 
        10.0.1.5, 
        10.0.1.6 
    } &redef;
}

event dcerpc_bind(c: connection, fid: count, ctx_id: count, uuid: string, ver_major: count, ver_minor: count)
{
    # Check for MS-DRSR Interface UUID: e3514235-4b6e-11d1-abda-0000f875ae93
    if ( to_lower(uuid) == "e3514235-4b6e-11d1-abda-0000f875ae93" )
    {
        if ( c$id$orig_h !in trusted_dcs )
        {
            NOTICE([$note=Suspicious_DCSync_Attempt,
                    $msg=fmt("Non-DC IP address %s attempted MS-DRSR RPC bind to DC %s", c$id$orig_h, c$id$resp_h),
                    $conn=c,
                    $identifier=cat(c$id$orig_h, c$id$resp_h)]);
        }
    }
}
```

### Suricata Rule

A Suricata detection rule can inspect DCE/RPC interface UUIDs over established SMB/RPC sessions:

```suricata
alert tcp any any -> [10.0.1.0/24] 135 (msg:"ET PROBE MS-DRSR RPC Interface Bind Request (DCSync Behavior)"; \
  flow:established,to_server; \
  dce_iface:uuid e3514235-4b6e-11d1-abda-0000f875ae93; \
  classtype:attempted-recon; \
  sid:2026111; rev:1;)
```

*Note: Replace `[10.0.1.0/24]` with your actual Domain Controller network segment.*

---

## Technical Edge Cases and False Positives

When tuning DCSync detections, security operations teams typically encounter several practical edge cases:

### 1. Entra Connect / AADSync Accounts
Microsoft Entra Connect requires directory replication permissions to sync password hashes (Password Hash Sync / PHS) to the cloud.
* **Risk**: If an adversary compromises the Entra Connect server or its service account credentials, they can execute a DCSync attack from that server.
* **Engineering Guidance**: Whitelist Entra Connect service accounts **only when the request originates from the assigned Entra Connect server IP address**. Do not blanket-whitelist the account across all network origins.

### 2. Read-Only Domain Controllers (RODCs)
RODCs use a restricted set of replication APIs and only replicate a subset of user credentials configured in their Password Replication Policy (PRP).
* Requests originating from RODCs typically include the `DS-Replication-Get-Changes-In-Filtered-Set` right. 
* Monitor for RODC computer accounts requesting `DS-Replication-Get-Changes-All`, which may indicate privilege escalation attempts or misconfiguration.

### 3. Temporary Administrative Scripts or Migration Tools
Tools like Active Directory Migration Tool (ADMT) or custom identity management tools may exercise replication rights during consolidation projects.
* **Engineering Guidance**: Enforce change management windows for migration tasks and temporarily tag operational maintenance windows in your SIEM rather than disabling detection rules.

---

## Defensive Recommendations and Hardening

Detection engineering is incomplete without reducing the attack surface. To mitigate the risk of DCSync attacks:

### 1. Audit Rights Assigned at the Domain Root
Periodically dump and inspect Active Directory ACLs at the domain head to ensure no non-standard accounts hold replication rights. Use PowerShell modules like `PowerView` or `DSACLs` to audit:

```powershell
Get-DomainObjectAcl -SearchBase "DC=corp,DC=internal" -ResolveGUIDs | 
    Where-Object { 
        ($_.ObjectAceType -eq "DS-Replication-Get-Changes" -or 
         $_.ObjectAceType -eq "DS-Replication-Get-Changes-All") -and
        ($_.AccessControlType -eq "AccessAllowed")
    } | 
    Select-Object IdentityReference, ObjectAceType, ActiveDirectoryRights
```

### 2. Enforce Tiered Administration Model
Ensure that domain administrative credentials never authenticate to lower-tier systems (Tier 1 servers or Tier 2 workstations). If an admin logs into a compromised workstation, an attacker can steal those credentials via LSASS dumping or token impersonation and immediately execute a DCSync attack.

### 3. Protect Entra Connect Synchronization Accounts
* Use Group Managed Service Accounts (gMSA) for directory synchronization services where supported.
* Restrict interactive logon rights for sync accounts across all endpoints.
* Enforce strict network segmentation on servers running synchronization software.

Combining targeted SACL auditing, event log parsing, and RPC network analysis creates a robust defense against DCSync techniques, ensuring that credential dumping attempts are flagged in real time before domain isolation is lost.
