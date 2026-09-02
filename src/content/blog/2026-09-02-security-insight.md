---
title: "Detecting Active Directory Database Theft: Auditing VSS, ESENT Events, and File Access Telemetry"
description: "An operational deep dive into detecting offline NTDS.dit extraction using Windows Security Event logs, ESENT engine telemetry, Volume Shadow Copy auditing, and raw volume access artifacts."
date: "2026-09-02"
tags: ["Cybersecurity", "Security Operations", "Threat Detection", "Active Directory"]
category: "Cyber Security"
difficulty: "Advanced"
author: "Abdul Muqeet Tabraiz"
image: "/images/blog/2026-09-02-detecting-active-directory-database-theft-auditing-vss-esent-events-and-file-acc.svg"
---

When adversaries gain Domain Admin privileges or equivalent administrative rights on a Domain Controller (DC), their primary objective often shifts from lateral movement to full credential extraction. While online replication attacks like DCSync (utilizing the `MS-DRSR` RPC interface) receive significant detection coverage, adversaries frequently resort to offline extraction of the Active Directory database (`ntds.dit`).

Offline extraction allows attackers to dump every password hash, Kerberos key, and account attribute in the domain without sending anomalous RPC replication requests across the network. The resulting database and the corresponding `SYSTEM` registry hive are exfiltrated to an adversary-controlled host, where tools such as `secretsdump.py` parse the Jet database engine format locally.

Because the Active Directory database is continuously locked by the Local Security Authority Subsystem Service (`lsass.exe`) and the Extensible Storage Engine (ESENT), copying `ntds.dit` directly via standard Win32 APIs fails with file-locking errors. Attackers must bypass this lock using snapshot mechanisms, native database utilities, or raw disk access.

Detecting these techniques requires understanding the telemetry produced by the underlying storage subsystem, process executions, symbolic links, and object access auditing.

---

## Mechanics of NTDS Extraction

The `ntds.dit` file resides by default in `%SystemRoot%\NTDS\ntds.dit`. The ESENT database engine holds exclusive read/write handles on this file while the Active Directory Domain Services (AD DS) service (`NTDS`) is running.

To read the contents of `ntds.dit` without stopping the AD DS service (which would disrupt domain operations and instantly trigger service monitoring alerts), attackers rely on four main techniques:

1. **Native Native Database Utilities (`ntdsutil.exe`, `esentutl.exe`)**: Built-in administration tools that invoke the underlying ESENT snapshot interfaces to create a consistent, backed-up copy of the database.
2. **Volume Shadow Copy Service (VSS)**: Creating a VSS snapshot of the system volume containing `ntds.dit`, allowing reads from the shadow volume path (e.g., `\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\ntds.dit`).
3. **Direct Disk and Raw Volume Access**: Opening direct handles to the volume volume device object (`\\.\C:`) or physical disk (`\\.\PhysicalDrive0`), bypassing NTFS permission checks and OS file locks to read raw disk sectors.
4. **WMI and PowerShell Management Interfaces**: Invoking WMI classes like `Win32_ShadowCopy` programmatically to initiate shadow copies without spawning `vssadmin.exe`.

Additionally, offline decryption of password hashes stored inside `ntds.dit` requires the system boot key (PEK). This key is encrypted inside the `SYSTEM` registry hive. Therefore, an NTDS dumping operation almost always includes a secondary access vector targeting `HKLM\SYSTEM` (or raw access to `%SystemRoot%\System32\config\SYSTEM`).

---

## Telemetry Sources and Event Instrumentation

Detecting NTDS dumping requires layered auditing across process creation, system application events, Object Access SACLs, and raw volume interactions.

| Audit Category | Telemetry Source | Key Event IDs / Data | Defensive Value |
| :--- | :--- | :--- | :--- |
| **Process Execution** | Windows Security Log / Sysmon | Event ID 4688, Sysmon Event ID 1 | Identifies command-line parameters (`ntdsutil`, `vssadmin`, `esentutl`, `reg`). |
| **ESENT Engine** | Application Event Log | Source: `ESENT` (IDs 2001, 2003, 325, 327) | Catches database engine snapshot creation and detachment. |
| **Service Activity** | System Event Log | Event ID 7036 (VSS state changes) | Tracks Volume Shadow Copy service startup and execution. |
| **Object Access** | Windows Security Log | Event IDs 4656, 4663 | Captures handle requests and read operations on `ntds.dit`. |
| **Symbolic Link Creation**| Sysmon / Security Audit | Sysmon ID 1, Security ID 4688 | Detects `mklink` or symbolic link links targeting shadow copy volumes. |
| **Raw Volume Access** | Sysmon / EDR Telemetry | Sysmon Event ID 9 | Detects direct raw disk read attempts bypassing standard APIs. |

---

## Technical Breakdown of Dumping Vectors and Signatures

### Vector 1: Ntdsutil Install-From-Media (IFM)

`ntdsutil.exe` includes an "Install From Media" (IFM) function intended for staging domain controllers over slow networks. When IFM is invoked, `ntdsutil` takes a snapshot of the AD database, writes `ntds.dit` to a specified directory, and automatically dumps the `SYSTEM` and `SECURITY` registry hives into the same directory.

#### Attack Command Example
```cmd
ntdsutil "ac i ntds" "ifm" "create full C:\Windows\Temp\Staging" q q
```

#### Telemetry Analysis
When `ntdsutil` executes an IFM creation, two distinct log outputs are produced:

1. **Process Creation (Event ID 4688 / Sysmon Event ID 1)**:
   - Image: `C:\Windows\System32\ntdsutil.exe`
   - Command Line contains: `ifm`, `create`, `ac i ntds`, or `active instance ntds`.

2. **Application Log (Source: ESENT)**:
   The ESENT engine logs high-fidelity internal lifecycle events when generating snapshot backups.
   
   - **Event ID 2001**: `ntdsutil (PID) Shadow copy database engine instance X starting.`
   - **Event ID 2003**: `ntdsutil (PID) Shadow copy database engine instance X stopped.`
   - **Event ID 325**: `ntdsutil (PID) The database engine created a new database...`

```xml
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="ESENT" />
    <EventID>2001</EventID>
    <Level>4</Level>
    <Task>1</Task>
    <Channel>Application</Channel>
    <Computer>DC01.corp.internal</Computer>
  </System>
  <EventData>
    <Data>ntdsutil</Data>
    <Data>4812</Data>
    <Data>Starting snapshot backup...</Data>
  </EventData>
</Event>
```

> **Operational Insight**: Legitimately run `ntdsutil` IFM commands are rare on operational Domain Controllers outside of planned server promotions or scheduled backups. An interactive session spawning `ntdsutil` with `ifm` should be treated as a high-severity alert.

---

### Vector 2: Volume Shadow Copy (VSS) Mount and Symbolic Links

Adversaries often bypass `ntdsutil` by requesting the VSS service directly via native administrative binary utilities like `vssadmin` or WMI (`wmic shadowcopy call create`). Once created, the shadow snapshot is mounted via symbolic link or accessed directly.

#### Attack Command Sequence
```cmd
vssadmin create shadow /for=C:
cmd /c mklink /d C:\ShadowCopy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\
copy C:\ShadowCopy\Windows\NTDS\ntds.dit C:\ProgramData\ntds.dit
vssadmin delete shadows /shadow={GUID} /quiet
```

#### Telemetry Analysis

1. **VSS Process Creation**:
   - Monitoring process launches of `vssadmin.exe` with arguments matching `create` and `shadow`.
   - Monitoring `wmic.exe` with arguments containing `shadowcopy` and `create`.
   - Monitoring PowerShell scripts issuing `Get-WmiObject Win32_ShadowCopy` or `Invoke-CimMethod`.

2. **System Log (Service State Changes)**:
   - **Event ID 7036**: The `Volume Shadow Copy` service entered the `running` state.

3. **Symbolic Link Creation**:
   - Command-line parameters containing `mklink` where the target path includes `\Device\HarddiskVolumeShadowCopy`.
   - Alternatively, use of `cmd.exe /c copy` pointing directly to `\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy*`.

4. **VSS Deletion Artifacts**:
   - Attackers frequently clean up shadow copies after copying the database.
   - Command-line arguments containing `vssadmin delete shadows` or `wmic shadowcopy delete`.

---

### Vector 3: Direct Handle Access and Raw Volume Reading

Advanced frameworks (such as PowerShell script `NinjaCopy` or custom C/C++ tools using `CreateFileW`) bypass Win32 file locking entirely. By opening a handle directly to the logical volume drive (`\\.\C:`) with `GENERIC_READ` permissions, the tool reads the raw disk clusters containing `ntds.dit` without interacting with the file system layer.

#### Telemetry Gaps and Solutions
Standard file access auditing (`Event ID 4663`) on `C:\Windows\NTDS\ntds.dit` will **not** trigger when a program accesses the underlying raw volume object directly. The file system engine is never queried for a file open request.

To detect raw volume reads, you must leverage:

1. **Sysmon Event ID 9 (RawAccessRead)**:
   Sysmon monitors direct drive access by process.
   - Device: `\Device\HarddiskVolume0` or `\Device\HarddiskVolume1`
   - Image: Captures the process reading raw sectors (e.g., `powershell.exe`, `python.exe`, or an unbacked binary).

```xml
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon" GUID="{577C4845-B205-4779-8F26-5742E50756A3}" />
    <EventID>9</EventID>
    <Task>9</Task>
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
  </System>
  <EventData>
    <Data Name="UtcTime">2026-09-02 14:22:01.102</Data>
    <Data Name="ProcessGuid">{A2B1C3D4-1234-5678-90AB-CDEF12345678}</Data>
    <Data Name="ProcessId">6140</Data>
    <Data Name="Image">C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Data>
    <Data Name="Device">\Device\HarddiskVolume1</Data>
  </EventData>
</Event>
```

2. **Windows Security Event ID 4656 (Handle Request to Volume Device)**:
   Auditing Object Access on `\\.\C:` will generate an event when a handle is requested for `\Device\HarddiskVolumeX` with `AccessMask` matching `0x80000000` (`GENERIC_READ`) or `0x1` (`FILE_READ_DATA`).

---

### Vector 4: Companion Hive Staging (`SYSTEM` Registry Dump)

An extracted `ntds.dit` file cannot be decrypted without the boot key stored in the `SYSTEM` hive. Consequently, attackers execute command-line utility calls to dump the registry alongside the database.

#### Attack Command Examples
```cmd
reg save HKLM\SYSTEM C:\ProgramData\system.hive
reg save HKLM\SECURITY C:\ProgramData\security.hive
```
or via `reg.exe` export / PowerShell `Save-Hive` calls.

#### Telemetry Analysis
- **Event ID 4688 / Sysmon Event ID 1**: Process creation where `Image` ends in `reg.exe` and `CommandLine` contains `save` or `export` combined with `HKLM\SYSTEM` or `HKLM\SECURITY`.
- **Sysmon Event ID 11 (File Create)**: Creation of arbitrary binary files in untypical directories (e.g., `C:\ProgramData\`, `C:\Windows\Temp\`, `C:\Users\Public\`) originating from privileged processes.

---

## Detection Engineering & Analytics

Below are ready-to-deploy detection rules across KQL (Microsoft Sentinel / Defender for Endpoint) and Splunk Search Processing Language (SPL).

### Detection Query 1: Suspicious ESENT Engine Activity (KQL)

Identifies ESENT engine snapshot events generated by processes other than standard Windows Backup services.

```kql
Event
| where EventLog == "Application" and Source == "ESENT"
| where EventID in (2001, 2003, 325, 327)
| extend RenderedDescription = tostring(EventData)
| parse RenderedDescription with * "Process: " ExecutingProcess " " *
| where ExecutingProcess !endswith @"\wbengine.exe" 
    and ExecutingProcess !endswith @"\svchost.exe"
| project TimeGenerated, Computer, EventID, ExecutingProcess, RenderedDescription
```

### Detection Query 2: NTDS Extraction via Administrative Utilities (Splunk SPL)

Detects command-line execution of `ntdsutil`, `esentutl`, `vssadmin`, or `wmic` attempting database staging or shadow copy creation.

```spl
(index=wineventlog sourcetype="WinEventLog:Security" EventCode=4688) OR (index=sysmon sourcetype="XmlWinEventLog" EventCode=1)
| eval CommandLine=lower(coalesce(CommandLine, ProcessCommandLine))
| eval Image=lower(coalesce(NewProcessName, Image))
| where (
    (like(Image, "%ntdsutil.exe") AND (like(CommandLine, "%ifm%") OR like(CommandLine, "%ac i ntds%"))) OR
    (like(Image, "%esentutl.exe") AND (like(CommandLine, "%/y%") OR like(CommandLine, "%/v%") OR like(CommandLine, "%ntds.dit%"))) OR
    (like(Image, "%vssadmin.exe") AND like(CommandLine, "%create%") AND like(CommandLine, "%shadow%")) OR
    (like(Image, "%wmic.exe") AND like(CommandLine, "%shadowcopy%") AND like(CommandLine, "%create%"))
)
| stats count min(_time) as firstTime max(_time) as lastTime by Computer, User, Image, CommandLine
| convert timeformat="%Y-%m-%d %H:%M:%S" timefield=firstTime
| convert timeformat="%Y-%m-%d %H:%M:%S" timefield=lastTime
```

### Detection Query 3: Raw Volume Access on Domain Controllers (KQL)

Identifies direct drive handle access by non-standard binaries on Domain Controllers using Sysmon Event ID 9.

```kql
Sysmon_Event_9
| where EventID == 9
| where Device matches regex @"\\Device\\HarddiskVolume\d+"
| where Image !endswith @"\System32\svchost.exe" 
    and Image !endswith @"\System32\lsass.exe"
    and Image !endswith @"\System32\wbengine.exe"
| project TimeGenerated, Computer, Image, Device, ProcessId
```

---

## Handling Operational Noise & False Positives

When tuning these detections in production Active Directory environments, enterprise operations will generate legitimate events that must be baselined:

1. **Enterprise Backup Solutions**: Tools like Veeam, Commvault, Veritas, and Microsoft Azure Backup routinely trigger VSS shadow copies and interact with the ESENT storage engine.
   - **Triage Strategy**: Validate the parent process execution path and service account identity. Backup software typically runs under designated service accounts (e.g., `svc_backup`) and launches binaries signed by trusted vendors from standard `Program Files` directories.
2. **Domain Controller Maintenance & Upgrades**: System administrators executing legitimate AD maintenance or preparing IFM media for new branch DCs will trigger `ntdsutil` alerts.
   - **Triage Strategy**: Ensure IFM creation events correlate with documented administrative change requests. Interactive console sessions (`mstsc.exe` parent processes) executing `ntdsutil` should always require secondary operational confirmation.
3. **System State Restores**: System state backups generate ESENT events ID 2001/2003 natively. Verify if `wbengine.exe` (Windows Server Backup) is the primary engine driver.

---

## Defensive Hardening Techniques

Detecting NTDS dumping should be coupled with preventative controls designed to limit an attacker's access to Domain Controllers:

### 1. Enforce Tier 0 Security Boundaries
NTDS database extraction requires administrative access to the Domain Controller (Local Administrator privileges or rights granted to `Domain Admins`, `Enterprise Admins`, or users with `SeBackupPrivilege`).
- Enforce strict Tier 0 separation: Ensure Tier 0 accounts never log into lower-tier workstations or servers.
- Prevent local administrator password reuse using LAPS on all non-DC endpoints, and restrict interactively logged-on accounts on DCs.

### 2. Audit and Restrict User Rights Assignment
Review the following user rights in Domain Controller Group Policies (`GPO`):
- **Back up files and directories (`SeBackupPrivilege`)**
- **Restore files and directories (`SeRestorePrivilege`)**
- **Take ownership of files or other objects (`SeTakeOwnershipPrivilege`)**

Ensure these rights are restricted strictly to authorized backup service accounts and built-in administrative groups.

### 3. Apply File System SACLs on `ntds.dit`
Configure a System Access Control List (SACL) on `%SystemRoot%\NTDS\ntds.dit` to generate Event ID 4656/4663 whenever access is requested by non-SYSTEM accounts.

```powershell
# Example: Querying permissions on the NTDS folder via PowerShell
Get-Acl -Path "C:\Windows\NTDS\ntds.dit" | Format-List
```

---

## Conclusion

Active Directory database theft gives adversaries full control over domain authentication primitives without generating high-volume network telemetry. Defenders who rely exclusively on network monitoring or DCSync RPC detection will miss offline extraction vectors entirely.

By deploying structured detection analytics against ESENT Application events, process creation arguments, shadow copy creation, and raw volume disk access, security operations teams can catch attackers at the staging phase before extracted hashes are exfiltrated and decrypted offline.
