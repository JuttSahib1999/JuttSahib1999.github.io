---
title: "Detecting NTDS.dit Extraction: Volume Shadow Copy Abuse, Esentutl, and Active Directory Database Telemetry"
description: "A practical guide for detection engineers and SOC analysts on identifying Active Directory database extraction techniques using process telemetry, ESENT application logs, and file creation events."
date: "2026-10-10"
tags: ["Cybersecurity", "Security Operations"]
category: "Cyber Security"
difficulty: "Intermediate"
author: "Abdul Muqeet Tabraiz"
image: "/images/blog/2026-10-10-detecting-ntds-dit-extraction-volume-shadow-copy-abuse-esentutl-and-active-direc.svg"
---

When an adversary gains elevated privileges on a Domain Controller, their immediate priority is often total domain dominance and long-term persistence. The fastest path to achieving this is extracting the `ntds.dit` file—the central database store for Active Directory that contains password hashes, Kerberos keys, user object metadata, and trust relationships across the entire domain.

Because the Active Directory Domain Services (`NTDS`) process maintains an exclusive lock on `ntds.dit` while the Domain Controller is running, attackers cannot simply copy the file using standard file system APIs. To bypass this lock, threat actors rely on system utility living-off-the-land techniques (LotL), native Windows services, or shadow copy creation.

This article breaks down how attackers extract `ntds.dit`, the telemetry generated during these extraction techniques, and how detection engineers can build reliable detection rules without triggering excessive false positives from legitimate backup workflows.

---

## Why `ntds.dit` is Locked and How Attackers Bypass It

The `ntds.dit` file is managed by the Extensible Storage Engine (ESE, formerly JET Database Engine). While the `NTDS` service is active, OS-level file locking prevents direct access or standard copy commands (like `copy` or `xcopy`) from reading the file contents.

Attackers work around this limitation using three primary approaches:

1. **Volume Shadow Copy Service (VSS):** Creating a snapshot of the volume housing `ntds.dit` frees the shadow volume copy from the active process lock. Attackers then copy the file directly out of the `\Device\HarddiskVolumeShadowCopyX` path.
2. **Native Built-in Utilities:** Windows provides administrative tools like `ntdsutil.exe` and `esentutl.exe`. `ntdsutil` includes an "Install From Media" (IFM) feature designed to generate AD database backups for domain controller promotion. Attackers leverage IFM to stage full copies of `ntds.dit` along with the `SYSTEM` registry hive.
3. **Raw Disk Access / API Manipulation:** Advanced tools or custom scripts read the raw physical drive sectors (`\\.\PhysicalDrive0` or volume handles) directly, parsing the NTFS structure to extract the file streams while completely bypassing Win32 file system locks.

Along with `ntds.dit`, an adversary must also retrieve the `SYSTEM` registry hive (`HKLM\SYSTEM`). The `SYSTEM` hive contains the Boot Key (SYSKEY), which is necessary to decrypt the NTLM hashes and Kerberos keys stored inside `ntds.dit`.

---

## Technical Breakdown of Common Extraction Vectors

Understanding the specific command sequences and processes used by adversaries allows us to map out the exact telemetry needed for detection.

### 1. `ntdsutil.exe` via IFM

`ntdsutil.exe` is a legitimate administrative command-line tool. The standard attacker workflow creates an IFM set directly into a staging directory:

```cmd
ntdsutil "ac i ntds" "ifm" "create full C:\Windows\Temp\staging" q q
```

When executed, `ntdsutil.exe` interacts with the ESE engine, leverages VSS behind the scenes, creates a snapshot, copies `ntds.dit`, and exports the required `SYSTEM` and `SECURITY` registry hives into `C:\Windows\Temp\staging`.

### 2. Manual Volume Shadow Copy Creation (`vssadmin` / `wmic`)

Attackers frequently create shadow copies manually using system utilities:

```cmd
vssadmin create shadow /for=C:
```

Or via WMIC:

```cmd
wmic shadowcopy call create Volume='C:\'
```

Once the shadow copy volume path is generated (for example, `\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1`), the attacker uses command line tools or scripts to copy `ntds.dit` out of the snapshot:

```cmd
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\ntds.dit C:\Windows\Temp\ntds.dit
```

They will then extract the Boot Key from the registry:

```cmd
reg save HKLM\SYSTEM C:\Windows\Temp\SYSTEM.hive
```

### 3. ESENT Engine Copying (`esentutl.exe`)

`esentutl.exe` is a database utility for ESE databases. Attackers can abuse its advanced command-line flags to copy locked files directly via VSS:

```cmd
esentutl.exe /y /vss C:\Windows\NTDS\ntds.dit /d C:\Windows\Temp\ntds.dit
```

The `/y` flag specifies a file copy operation, and `/vss` instructs `esentutl` to use the Volume Shadow Copy Service to clone the locked file.

---

## Telemetry Sources and Key Event Log Audit Strategy

Detecting AD database extraction requires enabling specific Windows audit policies and collecting process execution and application logs on Domain Controllers.

| Telemetry Source | Event ID / Log Channel | Practical Detection Value |
| :--- | :--- | :--- |
| **Process Creation** | Sysmon Event ID 1 / Security 4688 | Identifies command-line execution of `ntdsutil`, `vssadmin`, `esentutl`, and staging paths. |
| **ESENT Application Logs** | Application Log (Source: ESENT) / Event IDs 2004, 325, 327 | Logs when ESE starts, creates, and stops database snapshot operations. |
| **Directory Service Access** | Security Event ID 4662 / 4656 | Tracks access requests against the NTDS file object or Directory Services object handles. |
| **System Event Log** | System Event ID 7036 (VSS Service) | Logs state changes for the Volume Shadow Copy Service. |
| **File Creation** | Sysmon Event ID 11 | Tracks creation of `ntds.dit` outside its standard `%SystemRoot%\NTDS\` directory. |

---

## Analyzing Event Telemetry

### 1. Process Telemetry (Sysmon Event ID 1 / Event ID 4688)

When an adversary uses `ntdsutil.exe`, the process creation log reveals both parent and child command arguments.

```xml
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon" GUID="{57707319-3062-421e-9f35-570779388c78}" />
    <EventID>1</EventID>
    <TimeCreated SystemTime="2026-10-10T08:14:22.1029381Z" />
    <Computer>DC01.corp.internal</Computer>
  </System>
  <EventData>
    <Data Name="UtcTime">2026-10-10 08:14:22.102</Data>
    <Data Name="ProcessGuid">{A2B3C4D5-1234-5678-0000-0010A2C30000}</Data>
    <Data Name="ProcessId">4812</Data>
    <Data Name="Image">C:\Windows\System32\ntdsutil.exe</Data>
    <Data Name="CommandLine">ntdsutil "ac i ntds" "ifm" "create full C:\Windows\Temp\Exfil" q q</Data>
    <Data Name="CurrentDirectory">C:\Windows\system32\</Data>
    <Data Name="User">CORP\Administrator</Data>
    <Data Name="ParentImage">C:\Windows\System32\cmd.exe</Data>
    <Data Name="ParentCommandLine">cmd.exe /c ntdsutil "ac i ntds" "ifm" "create full C:\Windows\Temp\Exfil" q q</Data>
  </EventData>
</Event>
```

Key indicators in this log include:
- `ntdsutil.exe` called with `ifm` (Install From Media).
- Target directory in writable non-standard locations (such as `C:\Windows\Temp\` or `C:\Users\Public\`).
- Execution under a elevated user context (`CORP\Administrator` or `NT AUTHORITY\SYSTEM`).

### 2. ESENT Application Logs (Event IDs 2004, 325, and 327)

When `ntdsutil` or `esentutl` triggers an ESE snapshot, the Windows Application log registers events from the `ESENT` event source. These events are generated at the database engine layer and cannot easily be spoofed by command-line obfuscation.

- **Event ID 2004:** ESENT starting a database snapshot.
- **Event ID 325:** ESENT engine created a database snapshot.
- **Event ID 327:** ESENT engine stopped a database snapshot.

An example of ESENT Event ID 2004 in the Application event log:

```text
Log Name:      Application
Source:        ESENT
Date:          2026-10-10T08:14:22.3100000Z
Event ID:      2004
Task Category: Logging/Recovery
Level:         Information
Keywords:      Classic
User:          N/A
Computer:      DC01.corp.internal
Description:
ntdsutil (4812,D,50) Shadow copy instance 1 freeze started.
Database: C:\Windows\NTDS\ntds.dit
```

Notice that the process name (`ntdsutil`) and PID (`4812`) directly correlate back to the process creation event (Sysmon Event ID 1) shown above.

---

## Detection Engineering Queries

Below are production-ready detection logic examples for Splunk and Sigma to flag database extraction attempts on Domain Controllers.

### Splunk Search Processing Language (SPL)

#### Query 1: Suspicious `ntdsutil`, `esentutl`, or `vssadmin` Execution

```spl
index=win_logs sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| eval Command = lower(CommandLine)
| search (
    (Image="*\\ntdsutil.exe" AND (Command="*ifm*" OR Command="*create*"))
    OR (Image="*\\esentutl.exe" AND (Command="*/y*" AND Command="*/vss*"))
    OR (Image="*\\vssadmin.exe" AND Command="*create*" AND Command="*shadow*")
    OR (Image="*\\wmic.exe" AND Command="*shadowcopy*" AND Command="*create*")
  )
| table _time Computer User ParentImage Image CommandLine
```

#### Query 2: File Creation Events for `ntds.dit` Outside `C:\Windows\NTDS\`

```spl
index=win_logs sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=11
| eval Target = lower(TargetFilename)
| search Target="*ntds.dit" AND NOT (Target="c:\\windows\\ntds\\ntds.dit" OR Target="c:\\windows\\softwaredistribution\\*")
| table _time Computer User Image TargetFilename
```

### Sigma Detection Rule

```yaml
title: Active Directory Database Extraction via Native Tools
id: 5e6a711b-9411-4e89-a03d-2f0022a16d8a
status: experimental
description: Detects command-line execution of tools used to snapshot or copy ntds.dit.
author: Abdul Muqeet Tabraiz
date: 2026/10/10
logsource:
  category: process_creation
  product: windows
detection:
  selection_ntdsutil:
    Image|endswith: '\ntdsutil.exe'
    CommandLine|contains|all:
      - 'ifm'
      - 'create'
  selection_esentutl:
    Image|endswith: '\esentutl.exe'
    CommandLine|contains|all:
      - '/y'
      - '/vss'
  selection_vssadmin:
    Image|endswith: '\vssadmin.exe'
    CommandLine|contains|all:
      - 'create'
      - 'shadow'
  condition: selection_ntdsutil or selection_esentutl or selection_vssadmin
falsepositives:
  - Legitimate automated backup scripts. Exclude verified service accounts if necessary.
level: high
```

---

## Investigation Workflow for SOC Analysts

When a alert flags possible `ntds.dit` extraction on a Domain Controller, follow this triage procedure:

```
[ ALERT: NTDS Extraction / Shadow Copy Abuse Detected ]
                       │
                       ▼
    ┌─────────────────────────────────────┐
    │  Validate Process & Parent Process  │
    │  - Who executed the command?        │
    │  - Was it interactive or automated? │
    └──────────────────┬──────────────────┘
                       │
                       ▼
    ┌─────────────────────────────────────┐
    │  Examine Staging Paths & Output     │
    │  - Destination folder path          │
    │  - Was SYSTEM hive saved alongside? │
    └──────────────────┬──────────────────┘
                       │
                       ▼
    ┌─────────────────────────────────────┐
    │  Check Network & Exfiltration Logs  │
    │  - Large outbound SMB/WinRM traffic │
    │  - Staging archive tools (7z, zip)  │
    └──────────────────┬──────────────────┘
                       │
                       ▼
    ┌─────────────────────────────────────┐
    │  Correlate Authentication & Logs    │
    │  - Check recent Logon Events (4624) │
    │  - Verify ESENT Events (2004/325)   │
    └─────────────────────────────────────┘
```

1. **Verify the Process Lineage:** Identify the user account and parent process. Interactive execution from `cmd.exe` or `powershell.exe` spawned by an administrator account logged in via RDP or Remote PowerShell requires immediate triage.
2. **Inspect the Staging Path:** Check the file creation path where `ntds.dit` or shadow copies were output. Attackers commonly stage files in `C:\PerfLogs\`, `C:\Windows\Temp\`, or user profile directories. Check if the `SYSTEM` or `SECURITY` hives were saved nearby (`reg save HKLM\SYSTEM ...`).
3. **Check for Subsequent Archiving/Compression:** Attackers often compress `ntds.dit` using tools like `7z.exe`, `rar.exe`, or native PowerShell `Compress-Archive` to reduce network payload sizes prior to exfiltration.
4. **Monitor Network Egress and SMB Traffic:** Look for large file transfer operations leaving the Domain Controller shortly after the creation event—specifically SMB transfers to internal non-DC systems, or SSH/HTTP staging connections outward.

---

## Defensive Recommendations and Hardening

To mitigate the risk of `ntds.dit` exfiltration:

- **Restrict Domain Admin Privileges:** Access to Domain Controllers should strictly adhere to Tier 0 access model controls. Privileged identity management (PIM) and just-in-time (JIT) access significantly reduce unauthorized administrative sessions.
- **Audit Backup Scripts and Exclude Service Accounts:** Identify legitimate enterprise backup solutions (e.g., Veeam, Commvault, Windows Server Backup) that legitimately trigger VSS or ESENT events. Create baseline exclusions specific to known service account SIDs and binaries.
- **Enable Host-Based Firewall Rules:** Restrict SMB, WinRM, and RPC outbound network access from Domain Controllers toward workstation subnets. A Domain Controller should rarely initiate connections to user workstations.
- **Implement Credential Guard and LSA Protection:** While Credential Guard protects LSASS in memory, securing local administrative handles prevents credential harvesting that leads to DC compromise in the first place.

---

## Technical Limitations to Keep in Mind

Relying exclusively on command-line telemetry (`ntdsutil`, `esentutl`, `vssadmin`) leaves potential blind spots. 

Advanced adversaries may bypass command-line detections by:
- Using custom C/C++ or C# binaries that directly invoke the Volume Shadow Copy COM interfaces (`IVssBackupComponents`) without calling standard system utilities.
- Accessing raw disk handles directly (`\\.\PhysicalDriveX`) to parse NTFS headers and read file streams manually.
- Abuse of DCSync via Directory Replication Service (DRS) Remote Protocol RPC calls, which extracts user hashes directly over the network without ever accessing `ntds.dit` on the local disk.

To counter these evasion methods, pair command-line monitoring with kernel-level file monitoring (Sysmon Event ID 11), application snapshot telemetry (ESENT logs), and network detection rules for DCSync (RPC interface calls to `DRSGetNCChanges`).

---

## Summary

Extracting `ntds.dit` provides adversaries with complete access to domain credentials. While Active Directory locks the database during standard operation, attackers circumvent this using `ntdsutil`, `esentutl`, or manual Volume Shadow Copy creation. 

By combining process command-line logging with ESENT Application event correlation and file creation auditing, security operations teams can reliably detect database extraction attempts before host-level staging turns into domain-wide credential compromise.
