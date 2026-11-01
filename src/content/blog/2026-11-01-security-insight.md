---
title: "Detecting Bring Your Own Vulnerable Driver (BYOVD) Attacks: Telemetry, Driver Signatures, and Kernel Defenses"
description: "An in-depth analysis of how adversaries leverage signed vulnerable drivers to bypass EDR kernel callbacks, the telemetry required to identify driver abuse, and practical detection engineering strategies."
date: "2026-11-01"
tags: ["Cybersecurity", "Detection Engineering", "Endpoint Security", "Threat Hunting"]
category: "Cyber Security"
difficulty: "Advanced"
author: "Abdul Muqeet Tabraiz"
image: "/images/blog/2026-11-01-detecting-bring-your-own-vulnerable-driver-byovd-attacks-telemetry-driver-signat.svg"
---

Modern Endpoint Detection and Response (EDR) agents rely heavily on Windows Kernel callbacks to monitor system activity. By registering callback routines such as `PspCreateProcessNotifyRoutine`, `PspCreateThreadNotifyRoutine`, and `ObRegisterCallbacks`, security software receives real-time execution events directly from kernel space. Because Windows Kernel Mode Code Signing (KMCI) prevents unsigned code from executing in Ring 0, attackers cannot easily load custom kernel drivers to disable these callbacks.

To bypass KMCI, threat actors frequently employ Bring Your Own Vulnerable Driver (BYOVD) attacks. Instead of writing a custom rootkit, the attacker brings a legitimately signed, third-party driver that contains an arbitrary memory read/write vulnerability. Once loaded, the attacker uses this vulnerable interface to patch kernel structures in memory—effectively stripping security agent callbacks, blinding telemetry collection, and terminating protected processes.

Catching BYOVD attacks requires defensive depth beyond traditional signature matching, as the malicious driver itself carries a valid digital signature. This article examines how BYOVD attacks operate, the telemetry generated during driver installation and execution, and strategies for engineering reliable detections.

---

## How BYOVD Attacks Work

In a BYOVD scenario, the attacker's execution flow typically follows a four-step sequence:

```
[ Unprivileged / Privileged Process ]
                 │
                 ▼  1. Drops & Registers Signed Vulnerable Driver
[ Service Control Manager (SCM) / Win32 API ]
                 │
                 ▼  2. Loads Driver into Kernel Space (Ring 0)
[ Vulnerable Kernel Driver (e.g., RTCore64.sys) ]
                 │
                 ▼  3. Sends IOCTL Requests (Arbitrary Read/Write Primitives)
[ Windows Kernel Memory / EDR Callbacks ]
                 │
                 ▼  4. Zeroes out Callback Arrays & Blind Telemetry
[ Terminated / Blinded EDR Agent ]
```

### 1. Privilege Acquisition and Driver Staging
Loading a kernel driver requires the `SeLoadDriverPrivilege` right, which is held by default by `Administrators` and `SYSTEM`. If an attacker operates within a high-integrity context, they stage the vulnerable driver binary (e.g., `RTCore64.sys`, `gmer.sys`, or `cpuz141.sys`) onto the local disk.

### 2. Service Registration and Execution
The attacker registers the driver as a system service using the Service Control Manager (`sc.exe` or `CreateServiceW` API) or directly via registry modification under `HKLM\SYSTEM\CurrentControlSet\Services\`. Once registered, the service is started (`StartServiceW` or `sc start`), invoking the kernel's image loader.

### 3. Exploiting IOCTL Primitives
Because the driver is legitimately signed by a recognized software vendor, KMCI permits it into kernel space. Once loaded, the user-mode payload opens a handle to the driver's device object (e.g., `\\.\RTCore64`) using `CreateFileW` and sends specific Input/Output Control (IOCTL) codes via `DeviceIoControl`.

Vulnerable drivers expose IOCTLs that allow user-mode processes to execute arbitrary kernel memory reads and writes without proper access validation.

### 4. Direct Kernel Object Manipulation (DKOM)
Using these read/write primitives, the attacker locates kernel data arrays that store EDR callback routines. By overwriting function pointers within these arrays (or zeroing out the array entries entirely), the attacker disables process creation monitoring, thread creation monitoring, and handle stripping without causing a bugcheck (Blue Screen of Death).

---

## Telemetry Sources for Driver Activity

Detecting BYOVD requires correlating events across multiple Windows logging facilities:

### 1. Windows System Event Log (Event ID 7045)
When a driver is registered via the Service Control Manager, Windows logs Event ID 7045 in the System event log. This event contains the service name, binary path, and service type (`Kernel Mode Driver`).

```xml
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <EventID>7045</EventID>
    <Channel>System</Channel>
    <Computer>WIN-WORKSTATION01.corp.internal</Computer>
  </System>
  <EventData>
    <Data Name="ServiceName">RTCore64</Data>
    <Data Name="ImagePath">C:\Users\Public\Downloads\RTCore64.sys</Data>
    <Data Name="ServiceType">kernel mode driver</Data>
    <Data Name="StartType">demand start</Data>
    <Data Name="AccountName"></Data>
  </EventData>
</Event>
```

### 2. Sysmon Event ID 6 (Driver Loaded)
Sysmon provides telemetry directly when a driver is loaded into the kernel, logging the driver image path, SHA256 hash, and signature status.

```xml
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <EventID>6</EventID>
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
  </System>
  <EventData>
    <Data Name="UtcTime">2026-11-01 10:14:22.102</Data>
    <Data Name="ImageLoaded">C:\Windows\Temp\driver.sys</Data>
    <Data Name="Hashes">SHA256=01A2B3C4D5E6F7... (RTCore64 signature match)</Data>
    <Data Name="Signed">true</Data>
    <Data Name="Signature">Micro-Star International Co., Ltd.</Data>
  </EventData>
</Event>
```

### 3. CodeIntegrity Operational Logs
The `Microsoft-Windows-CodeIntegrity/Operational` log tracks image verification. If a driver fails validation or violates Hypervisor-Protected Code Integrity (HVCI) policies, Event IDs `3004`, `3033`, or `3089` are generated.

### 4. Process and Handle Telemetry (Sysmon Event ID 1 & 10)
Monitoring process creation (`sc.exe` creating a kernel-mode driver service) and handle creation (a non-standard executable opening a handle to a device object under `\Device\` or `\\.\`) provides critical context for malicious driver execution.

---

## Detection Engineering Strategies

Detecting BYOVD requires combining static blocklist checks, path anomaly detection, and behavioral metrics.

### Strategy 1: Hash Matching Against Known Vulnerable Drivers
Maintaining a database of known vulnerable driver hashes (such as LSS or Microsoft's recommended blocklist) allows for deterministic detection when a vulnerable driver touches disk or loads into memory.

#### KQL Query (Microsoft Defender for Endpoint / Sentinel)
```kql
DeviceEvents
| where ActionType == "DriverLoad"
| extend SHA256 = tolower(SHA256)
| where SHA256 in (
    "01a2b3c4d5e6f789a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f789a0b1c2d3e4", // Example RTCore64 hash
    "1a2b3c4d5e6f789a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f789a0b1c2d3e4f"  // Example Gmer hash
)
| project Timestamp, DeviceName, FolderPath, SHA256, Signer, InitiatingProcessFileName
```

### Strategy 2: Staging Path Anomalies
Legitimate system drivers reside in `%SystemRoot%\System32\drivers\`, `%SystemRoot%\System32\DriverStore\`, or legitimate third-party application directories (e.g., `Program Files`). Drivers loaded from user profiles, temporary directories, or mounting points are highly anomalous.

#### Sigma Rule Definition
```yaml
title: Driver Loaded from Suspicious Path
id: f4a2b1c0-789a-4e2b-9123-abcdef123456
status: experimental
description: Detects kernel driver loading from non-standard directories like Temp or Public profiles.
logsource:
  category: driver_load
  product: windows
detection:
  selection:
    ImageLoaded|contains:
      - '\Users\Public\'
      - '\AppData\Local\Temp\'
      - '\Windows\Temp\'
      - '\PerfLogs\'
      - '\ProgramData\'
  filter_legitimate:
    ImageLoaded|startswith: 'C:\Windows\System32\drivers\'
  condition: selection and not filter_legitimate
falsepositives:
  - Custom internal administrative tools deployed via temp scripts.
level: high
```

### Strategy 3: Detecting EDR Telemetry Blackouts
When an adversary successfully unregisters EDR kernel callbacks, the endpoint agent stops transmitting process, file, and registry events while maintaining network connectivity or basic agent heartbeat.

Defenders can flag endpoints where heartbeat records remain active, but endpoint telemetry volume drops to zero over a short window.

```kql
// Telemetry Volume Anomaly Query
let TimeWindow = 1h;
DeviceProcessEvents
| summarize ProcessEventCount = count() by DeviceName, bin(Timestamp, TimeWindow)
| join kind=inner (
    Heartbeat
    | summarize HeartbeatCount = count() by Computer, bin(TimeGenerated, TimeWindow)
) on $left.DeviceName == $right.Computer
| where ProcessEventCount == 0 and HeartbeatCount > 0
| project Timestamp, DeviceName, ProcessEventCount, HeartbeatCount
```

---

## Operational Considerations and Limitations

When deploying detections and preventions for BYOVD, engineers face several operational challenges:

### Legitimate Administrative Tools
Tools like Process Hacker (`kprocesshacker.sys`), Process Explorer (`PROCEXP152.SYS`), CPU-Z (`cpuz141.sys`), and various hardware diagnostics load drivers that request extensive privileges. Blanket blocking of driver loads based solely on capability can break legitimate IT workflows. Baseline environments to identify allowed management tools before enforcing restrictive rules.

### Certificate Revocation Delays
KMCI checks certificate validity against CRLs (Certificate Revocation Lists) or OCSP during driver loading. However, revoked certificates may still pass local checks if the endpoint lacks real-time internet connectivity or if revocation caches are stale.

### Driver Modification
Attackers occasionally alter non-signed sections of vulnerable driver binaries (such as PE headers or resource tables) to alter file hashes while preserving valid signatures. Rule sets reliant strictly on file hashes can be bypassed. Detections must combine hash indicators with certificate signers and file creation paths.

---

## Defensive Recommendations and Hardening

### 1. Enable HVCI and Microsoft Vulnerable Driver Blocklist
Hypervisor-Protected Code Integrity (HVCI) uses hardware virtualization to isolate kernel integrity checks. Combined with Microsoft's recommended driver blocklist, HVCI blocks known vulnerable drivers from loading at the hypervisor layer.

- **Group Policy:** `Computer Configuration > Administrative Templates > System > Device Guard > Turn on Virtualization Based Security`
- **Registry:** Set `Enabled` to `1` under `HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity`.

```cmd
:: Enable Vulnerable Driver Blocklist via reg.exe
reg add "HKLM\SYSTEM\CurrentControlSet\Control\CI\Config" /v VulnerableDriverBlocklistEnable /t REG_DWORD /d 1 /f
```

### 2. Restrict `SeLoadDriverPrivilege`
Restrict the ability to load drivers (`SeLoadDriverPrivilege`) strictly to `LOCAL SYSTEM` and local administrators. Remove this right from standard user groups and service accounts via User Rights Assignment in Group Policy.

### 3. Audit Privileged Service Creation
Monitor Windows Security Event ID `4697` ("A service was installed in the system") alongside Event ID `7045`. Flag any service creation event where `Service Type` is `0x1` (Kernel Driver) or `0x2` (File System Driver), especially when initiated by non-standard parent processes.

---

## Summary

Bring Your Own Vulnerable Driver attacks bypass modern kernel security boundaries by converting signed, legitimate drivers into execution primitives against kernel memory. Because these drivers carry valid signatures, traditional binary trust models fail to prevent their execution.

Defending against BYOVD requires a layered detection strategy: enforcing hardware-enforced driver blocklists (HVCI), monitoring service registration telemetry (Event ID 7045), flagging non-standard driver load paths (Sysmon Event ID 6), and detecting telemetry gaps that signal disabled security callbacks.
