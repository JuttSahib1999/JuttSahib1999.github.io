---
title: "Detecting Bring Your Own Vulnerable Driver (BYOVD) Attacks: Telemetry, Driver Signatures, and Kernel Behavior"
description: "An in-depth analysis of BYOVD attack chains, telemetry sources, detection engineering logic, and kernel-level defensive controls."
date: "2026-10-18"
tags: ["Cybersecurity", "Security Operations"]
category: "Cyber Security"
difficulty: "Advanced"
author: "Abdul Muqeet Tabraiz"
image: "/images/blog/2026-10-18-detecting-bring-your-own-vulnerable-driver-byovd-attacks-telemetry-driver-signat.svg"
---

Modern Endpoint Detection and Response (EDR) agents rely heavily on kernel-mode callbacks to monitor process creation, thread injection, handle duplication, and memory allocation. To maintain integrity, 64-bit Windows enforces Driver Signature Enforcement (DSE), preventing unsigned code from executing in Ring 0. 

Attackers bypass DSE without exploiting zero-day vulnerabilities in the operating system through Bring Your Own Vulnerable Driver (BYOVD). By dropping and loading a legitimately signed, legacy, or third-party driver containing known memory-safety vulnerabilities, an adversary gains arbitrary kernel read/write primitives. Once inside Ring 0, the adversary can unhook kernel callbacks, strip process protection structures, or blind telemetry pipelines entirely before EDR user-mode hooks can flag the activity.

Defending against BYOVD requires understanding how these drivers are staged, how they interact with kernel objects, and how to build detection rules across service registration, kernel driver telemetry, and behavioral anomalies.

---

## Anatomy of a BYOVD Attack Chain

A standard BYOVD execution flow requires administrative privileges on the target system to register and load a kernel service. The attack generally follows four stages:

```
+---------------------+      +---------------------+      +---------------------+      +---------------------+
| 1. Staging          | ---> | 2. Registration     | ---> | 3. Kernel Load      | ---> | 4. Kernel Memory    |
| Drop vulnerable     |      | Create service via  |      | Service started via |      | Operations via      |
| driver to disk      |      | SCM / NtLoadDriver  |      | ZwLoadDriver        |      | IOCTL calls         |
+---------------------+      +---------------------+      +---------------------+      +---------------------+
```

### 1. Driver Staging
The attacker drops a validly signed driver binary (e.g., `RTCore64.sys`, `gdrv.sys`, or `procexp.sys`) onto the target filesystem. Because the driver binary is signed by a valid code-signing certificate (even if revoked or belonging to an older hardware vendor driver), standard file integrity controls may not immediately quarantine it unless a blocklist rule matches its hash.

### 2. Service Registration & Loading
The attacker registers the driver as a system service. This is commonly executed via `sc.exe`, PowerShell (`New-Service`), or direct calls to the Service Control Manager (SCM) API (`CreateServiceW` and `StartServiceW`). Alternatively, adversaries with `SeLoadDriverPrivilege` invoke the native API `NtLoadDriver` or `ZwLoadDriver` directly after populating the corresponding registry key under `HKLM\SYSTEM\CurrentControlSet\Services\`.

### 3. Direct IOCTL Communication
Once loaded, the driver registers a device object (e.g., `\Device\RTCore64`) and symbolic link (`\DosDevices\RTCore64`). The user-mode malware obtains a handle to this device via `CreateFileW` and issues Input/Output Control (IOCTL) codes via `DeviceIoControl`.

For example, Micro-Star's `RTCore64.sys` driver exposes IOCTLs `0x80002040` (read kernel memory) and `0x80002044` (write kernel memory). The user-mode process passes arbitrary kernel addresses to the driver, which executes the read/write operations on behalf of the user-mode caller.

### 4. Kernel Object Tampering
With kernel read/write primitives established, the attacker targets specific kernel structures:

*   **PPL (Protected Process Light) Stripping:** The attacker locates the `EPROCESS` structure of the security agent's executable (e.g., `MsSense.exe`) and modifies the `_PS_PROTECTION` byte field, clearing the `Type` and `Signer` bits. This allows normal user-mode processes to terminate the EDR service.
*   **Kernel Callback Removal:** The attacker traverses internal kernel arrays—such as `PspCreateProcessNotifyRoutine`, `PspCreateThreadNotifyRoutine`, and `PspLoadImageNotifyRoutine`—and clears the function pointers pointing to the EDR's kernel driver callbacks.
*   **ETW-Ti Disabling:** The attacker locates `EtwThreatIntProvRegHandle` and nullifies or alters registration pointers to disable Event Tracing for Windows Threat Intelligence (ETW-Ti) logging.

---

## Telemetry Sources and Event Artifacts

Detecting BYOVD requires monitoring events generated at file creation, service installation, driver loading, and process behavior.

```
+------------------------------------+---------------------------------------------------+
| Telemetry Category                 | Key Event Sources & Event IDs                     |
+------------------------------------+---------------------------------------------------+
| File Creation                      | Sysmon Event ID 11 / MDE DeviceFileEvents         |
| Service Installation               | System Event ID 7045 / Security Event ID 4697     |
| Driver Load                        | Sysmon Event ID 6 / MDE DeviceEvents (DriverLoad) |
| Registry Persistence/Configuration | Sysmon Event IDs 12, 13 / MDE DeviceRegistryEvents|
| Code Integrity / Blocklists        | Microsoft-Windows-CodeIntegrity Event ID 3033/3004|
+------------------------------------+---------------------------------------------------+
```

### Driver Loading Telemetry (Sysmon Event ID 6)
Sysmon ID 6 logs every driver load event, capturing the binary path, driver name, hashes, and signature verification status.

```xml
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon" Guid="{57701197-9910-4871-B806-37025687E235}" />
    <EventID>6</EventID>
    <TimeCreated SystemTime="2026-10-18T09:14:22.1029381Z" />
    <Computer>WORKSTATION01.corp.internal</Computer>
  </System>
  <EventData>
    <Data Name="UtcTime">2026-10-18 09:14:22.102</Data>
    <Data Name="ImageLoaded">C:\Windows\Temp\rtcore64.sys</Data>
    <Data Name="Hashes">SHA256=01264802830312B0112F842512C0198031221B00812938120019283120938102</Data>
    <Data Name="Signed">true</Data>
    <Data Name="Signature">Micro-Star International Co., Ltd.</Data>
    <Data Name="SignatureStatus">Valid</Data>
  </EventData>
</Event>
```

Key indicators in Sysmon Event ID 6:
*   `ImageLoaded`: Loading drivers from user-writable or staging locations (`C:\Users\Public\`, `C:\ProgramData\`, `C:\Windows\Temp\`) is rare for legitimate software.
*   `Hashes`: Matches known vulnerable driver catalogs (such as the LOLDrivers project).

### Service Creation (System Event ID 7045)
When a driver is registered through the Service Control Manager, Windows writes Event ID 7045 to the System log.

```xml
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Service Control Manager" Guid="{555908d1-a6d7-4695-8e1e-26931d2012f4}" EventSourceName="Service Control Manager" />
    <EventID>7045</EventID>
    <TimeCreated SystemTime="2026-10-18T09:14:21.9841203Z" />
  </System>
  <EventData>
    <Data Name="ServiceName">RTCore64</Data>
    <Data Name="ImagePath">system32\drivers\rtcore64.sys</Data>
    <Data Name="ServiceType">kernel mode driver</Data>
    <Data Name="StartType">demand start</Data>
    <Data Name="AccountName"></Data>
  </EventData>
</Event>
```

---

## Detection Engineering Strategies

Relying on a single detection point for BYOVD is ineffective. A comprehensive detection strategy must combine static signatures, path anomalies, and behavioral correlations.

### 1. Driver Hash and Certificate Matching
The most direct approach checks driver load events against known lists of vulnerable drivers (e.g., LOLDrivers database).

While attackers can alter file metadata or compile slightly different driver versions, the vast majority of BYOVD attacks use existing, unmodified binaries from hardware vendors because re-signing drivers requires a valid code-signing key.

### 2. File Path and Execution Anomalies
Standard enterprise Windows drivers reside in `C:\Windows\System32\drivers\`. Legitimate software occasionally installs drivers from `C:\Program Files\`. Drivers loaded from temporary directories, user profiles, or non-standard paths should be treated as suspicious.

### 3. Parent Process Context
Legitimate driver loading is typically managed by trusted installers (e.g., `msiexec.exe`, system deployment agents) or the System process itself (`services.exe`). If `sc.exe`, `powershell.exe`, or an unverified user-space binary in `C:\Users\Public\` initiates service creation for a driver, this represents a strong behavioral signal.

---

## Detection Queries

The following Kusto Query Language (KQL) rules demonstrate how to detect BYOVD activities in Microsoft Defender for Endpoint (MDE) or Microsoft Sentinel schemas.

### Query 1: Known Vulnerable Driver Load or Non-Standard Location Execution

This query detects drivers loaded from suspicious paths or matching known hash blocklists.

```kql
// Detect Kernel Driver Loads from Suspicious Locations or Known Hash Lists
let SuspiciousPaths = dynamic([
    @"C:\Users\",
    @"C:\ProgramData\",
    @"C:\Windows\Temp\",
    @"C:\Temp\",
    @"C:\PerfLogs\"
]);
DeviceEvents
| where ActionType == "DriverLoad"
| extend DriverPath = tostring(FolderPath)
| extend DriverHash = SHA256
| extend CertSubject = tostring(AdditionalFields.Issuer)
| where DriverPath has_any (SuspiciousPaths)
   or DriverHash in~ (
        // Example SHA256 hashes of known abused drivers (e.g., RTCore64, gdrv)
        "01264802830312b0112f842512c0198031221b00812938120019283120938102",
        "312984719238e1203912a2301928301928312093810293812093812093812093"
   )
| project Timestamp, DeviceName, DriverPath, DriverHash, CertSubject, InitiatingProcessFileName, InitiatingProcessCommandLine
```

### Query 2: Correlating Driver Drop, Service Creation, and Load Sequence

This query looks for a process dropping a `.sys` file and immediately registering it as a kernel service within a 5-minute window.

```kql
// Sequence Detection: File Drop -> Kernel Service Creation
let TimeWindow = 5m;
DeviceFileEvents
| where FileName endswith ".sys"
| where FolderPath has_any (@"\Temp\", @"\Public\", @"\ProgramData\", @"\Users\")
| project FileDropTime = Timestamp, DeviceName, DriverName = FileName, DriverPath = FolderPath, DroppingProcess = InitiatingProcessFileName
| join kind=inner (
    DeviceEvents
    | where ActionType == "ServiceCreation" or ActionType == "DriverLoad"
    | project EventTime = Timestamp, DeviceName, ServiceName = tostring(AdditionalFields.ServiceName), DriverPath = FolderPath
) on DeviceName
| where abs(EventTime - FileDropTime) <= TimeWindow
| project EventTime, DeviceName, DriverName, DriverPath, DroppingProcess, ServiceName
```

---

## Secondary Telemetry and Post-Exploitation Anomalies

When an adversary successfully uses BYOVD to terminate EDR mechanisms in memory, the EDR itself stops generating standard event logs. Detection systems must account for this by monitoring secondary signals:

1.  **EDR Heartbeat Disruption:** Set up SIEM alerts for endpoints that suddenly stop sending security telemetry while remaining active on the network (e.g., active network traffic reported by firewall or netflow, but zero endpoint logs).
2.  **Sudden PPL Process Termination:** Protected Process Light (PPL) processes like `MsSense.exe` or `SecHealthHost.exe` should not crash or exit abruptly under standard conditions. An event showing a PPL process terminating without a preceding soft reboot is a high-confidence signal of tampering.
3.  **CodeIntegrity Audit Events:** If Microsoft Vulnerable Driver Blocklist or Hypervisor-Protected Code Integrity (HVCI) blocks a driver, Windows logs Event ID 3033 or 3004 under the `Microsoft-Windows-CodeIntegrity/Operational` log. High volumes of blocked driver attempts indicate active driver staging.

```xml
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-CodeIntegrity" Guid="{4ee76db6-1f78-46cf-a481-762084b74a27}" />
    <EventID>3033</EventID>
    <TimeCreated SystemTime="2026-10-18T10:02:11.1298301Z" />
  </System>
  <EventData>
    <Data Name="FileNameLength">22</Data>
    <Data Name="FileName">rtcore64.sys</Data>
    <Data Name="ProcessName">sc.exe</Data>
    <Data Name="RequestedPolicy">VulnerableDriverBlocklist</Data>
  </EventData>
</Event>
```

---

## Preventive Controls and Mitigation Engineering

Detecting BYOVD post-execution is difficult because kernel memory manipulation occurs in microseconds. Prevention must form the primary line of defense.

### 1. Microsoft Vulnerable Driver Blocklist & WDAC
Windows supports Windows Defender Application Control (WDAC) and the Microsoft Vulnerable Driver Blocklist. When enabled, the kernel checks the hash and attributes of drivers against a built-in blocklist during the `ZwLoadDriver` operation.

To verify or enable Driver Blocklisting via PowerShell:

```powershell
# Enable Hypervisor-Protected Code Integrity (HVCI) and Driver Blocklist
Set-CiRuleOption -FilePath "C:\Windows\schemas\CodeIntegrity\ExamplePolicies\DefaultWindows_VulnerableDriverBlocklist.xml" -Option 11
```

In enterprise environments managed via Intune or Group Policy, ensure **Hypervisor-Protected Code Integrity (HVCI)** (also known as Memory Integrity) is enforced across all endpoints. HVCI prevents driver loading if the binary violates security policies or attempts to allocate executable memory dynamically in Ring 0.

### 2. Restricting Privileges
Loading a kernel driver requires `SeLoadDriverPrivilege` (typically restricted to `Administrators` and `NT AUTHORITY\SYSTEM`). Enforcing strict privilege boundaries, disabling default local administrator accounts, and removing unnecessary rights for domain users limits the threat surface.

### 3. Operational Trade-Offs and Maintenance
Maintaining blocklists requires ongoing updates. Attackers frequently find unindexed legacy drivers from smaller hardware vendors. SOC teams should rely on automated ingestion of vendor and community blocklists (such as LOLDrivers) into their SIEM detection rules while enforcing HVCI hardware security at the OS level.

---

## Defensive Engineering Checklist

To build a resilient posture against BYOVD attacks:

1.  **Enforce HVCI and Microsoft Vulnerable Driver Blocklist** across all Windows endpoints via policy.
2.  **Monitor Sysmon Event ID 6 and System Event ID 7045** for driver loads originating outside standard system directories (`C:\Windows\System32\drivers\`).
3.  **Alert on `Microsoft-Windows-CodeIntegrity` Event ID 3033** to capture blocked vulnerable driver load attempts.
4.  **Implement SIEM rules for agent heartbeat loss** to detect endpoints where security agents have been unhooked or terminated via kernel memory manipulation.
