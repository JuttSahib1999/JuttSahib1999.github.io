---
title: "Detecting BYOVD Attacks: Kernel Telemetry, Blocklist Enforcement, and Callback Tampering"
description: "An operational guide to detecting Bring Your Own Vulnerable Driver (BYOVD) exploitation, monitoring driver loading telemetry, and analyzing kernel callback manipulation."
date: "2026-11-08"
tags: ["Cybersecurity", "Security Operations", "Detection Engineering", "Kernel Security"]
category: "Cyber Security"
difficulty: "Advanced"
author: "Abdul Muqeet Tabraiz"
image: "/images/blog/2026-11-08-detecting-byovd-attacks-kernel-telemetry-blocklist-enforcement-and-callback-tamp.svg"
---

Adversaries operating with local administrative privileges face a persistent challenge: Endpoint Detection and Response (EDR) agents running kernel drivers (`.sys`) to monitor system state. Modern EDRs leverage kernel callbacks to intercept process creation, thread creation, and handle duplication. 

To strip this visibility, attackers frequently rely on **Bring Your Own Vulnerable Driver (BYOVD)**. Rather than exploiting an unpatched kernel vulnerability directly, an attacker drops a legitimately signed, legacy, or obscure driver that contains an exposed vulnerability—such as an arbitrary kernel memory read/write primitive. By interacting with this driver through I/O Control (IOCTL) requests, the attacker executes arbitrary code inside Ring 0, bypassing Windows Driver Signature Enforcement (DSE) without needing a leaked digital certificate.

Understanding how to collect driver load telemetry, correlate kernel activity, and enforce effective blocklists is critical for defending modern enterprise endpoints.

---

## The Mechanics of BYOVD Exploitation

To execute a BYOVD attack, an adversary typically follows a specific execution sequence:

```
[ User Mode Payload ]
       │
       ├─ 1. Drops Signed Vulnerable Driver (e.g., RTCore64.sys) to disk
       ├─ 2. Calls CreateServiceW() & StartServiceW() [Requires SeLoadDriverPrivilege]
       ├─ 3. Obtains Handle via CreateFileW("\\\\.\\VulnerableDevice")
       └─ 4. Sends IOCTL via DeviceIoControl()
               │
               ▼
┌────────────────────────────────────────────────────────┐
│ Kernel Mode (Ring 0)                                   │
│                                                        │
│  [ Vulnerable Driver ]                                 │
│         │                                              │
│         └─ Accepts IOCTL (Arbitrary Read/Write)        │
│                 │                                      │
│                 ▼                                      │
│  [ Kernel Data Structures ]                            │
│         ├─ PspCreateProcessNotifyRoutine (Zeroed out)  │
│         ├─ PspCreateThreadNotifyRoutine (Zeroed out)   │
│         └─ EPROCESS.Token (Privilege Escalation)       │
└────────────────────────────────────────────────────────┘
```

### 1. Privilege Verification & Service Installation
Loading a kernel driver requires the `SeLoadDriverPrivilege` right, which is assigned to local administrators and `NT AUTHORITY\SYSTEM` by default. The attacker drops the signed vulnerable driver (for example, `RTCore64.sys`, `gdrv.sys`, or older versions of `procexp.sys`) to a staging directory like `C:\Windows\Temp\` or `C:\Users\Public\`.

The payload then registers a new system service via the Windows Service Control Manager (SCM) or directly creates registry keys under `HKLM\SYSTEM\CurrentControlSet\Services\`.

### 2. Device Interaction via IOCTL
Once the service starts, the driver registers a Symbolic Link to its Device Object. The user-mode payload opens a handle to this device interface using `CreateFileW` and issues requests using `DeviceIoControl`.

Vulnerable drivers fail to validate the memory pointers or buffer sizes passed from user-mode code. For instance, a vulnerable driver's dispatch routine might take an address supplied in an input buffer and directly execute a `memcpy` into kernel address space (`0x8000000000000000` and above on 64-bit systems).

### 3. Kernel Data Structure Tampering
With arbitrary kernel read/write capabilities, the attacker targets specific structures:

*   **Disabling Security Callbacks:** The kernel maintains arrays of function pointers for process and thread creation notifications (`PspCreateProcessNotifyRoutine` and `PspCreateThreadNotifyRoutine`) as well as object access filters (`ObRegisterCallbacks`). The attacker locates these arrays in memory and zeroes out the entry corresponding to the installed EDR driver.
*   **Token Stealing / Elevation:** The attacker locates the target process's `EPROCESS` structure, finds the `Token` member offset, and replaces it with the system token address retrieved from the System process (`PID 4`).
*   **Process Unlinking (DKOM):** Direct Kernel Object Manipulation is used to modify the `ActiveProcessLinks` doubly-linked list in the `EPROCESS` structure, hiding a process from utility APIs while leaving it schedulable by the kernel.

---

## Primary Telemetry Sources for Driver Loading

Detecting BYOVD requires visibility into driver staging, service creation, and driver initialization events before kernel callbacks can be unhooked.

### 1. Sysmon Event ID 6: DriverLoaded
Sysmon provides high-fidelity telemetry for kernel driver loads. Event ID 6 logs details such as image hashes, paths, and signature verification status.

```xml
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon" GUID="{57707310-5321-4309-9D06-42CE8D41769A}" />
    <EventID>6</EventID>
    <Level>4</Level>
    <Task>6</Task>
    <TimeCreated SystemTime="2026-11-08T14:22:05.1124310Z" />
    <Computer>WKSTN-FINANCE-04.corp.internal</Computer>
  </System>
  <EventData>
    <Data Name="UtcTime">2026-11-08 14:22:05.101</Data>
    <Data Name="ImageLoaded">C:\Windows\Temp\RTCore64.sys</Data>
    <Data Name="Hashes">SHA256=01A294B1B3207E5267A531A03F11E55E69C127F70535308611F17D5C761D6E21</Data>
    <Data Name="Signed">true</Data>
    <Data Name="Signature">Micro-Star International Co., Ltd.</Data>
    <Data Name="SignatureStatus">Valid</Data>
  </EventData>
</Event>
```

**Key Data Points:**
*   `ImageLoaded`: Staging paths outside standard system locations (`C:\Windows\System32\drivers\`) warrant immediate scrutiny.
*   `Hashes`: Matches known vulnerable driver hashes (e.g., cross-referenced with projects like [LOLDrivers](https://www.loldrivers.io/)).
*   `Signature`: Identifies non-standard or third-party signers loading drivers in environments where those vendors are not deployed.

### 2. Windows System Log Event ID 7045 & Security Log Event ID 4697
When a new driver service is created, the Windows Service Control Manager writes Event ID 7045 (System log) or Event ID 4697 (Security log if auditing is enabled).

```text
Log Name:      System
Source:        Service Control Manager
Event ID:      7045
Task Category: None
Level:         Information
Description:
A service was installed in the system.

Service Name:  RTCore64
Service File Name:  C:\Users\Public\RTCore64.sys
Service Type:  kernel mode driver
Start Type:    demand start
Account Name:  
```

### 3. Microsoft-Windows-CodeIntegrity Logs
When Hypervisor-Protected Code Integrity (HVCI) or Windows Defender Application Control (WDAC) blocks a vulnerable driver from loading due to policy or blocklists, logs are generated under `Microsoft-Windows-CodeIntegrity/Operational`:

*   **Event ID 3033:** File failed to meet code integrity policy requirements.
*   **Event ID 3076:** Drivers blocked by the Microsoft Vulnerable Driver Blocklist.
*   **Event ID 3077:** Driver revoke event triggered by policy evaluation.

---

## Detection Engineering & Analytics

Building resilient detections for BYOVD requires a dual strategy: detecting known vulnerable drivers via signature matching and detecting anomalous behavior during driver registration.

### Detection Query 1: KQL – Suspicious Driver File Paths & Known Vulnerable Driver Hashes
This KQL query monitors driver loads coming from non-standard directories or matching known vulnerable file signatures.

```kql
// Detect driver loads outside system driver directories or matching vulnerable hashes
Sysmon_EventID_6_DriverLoad
| where TimeGenerated >= ago(24h)
| extend ImageLoaded = tolower(ImageLoaded)
| where not(ImageLoaded startswith @"c:\windows\system32\drivers\" 
         or ImageLoaded startswith @"c:\windows\system32\driverstore\")
   or Hashes has_any (
       "01a294b1b3207e5267a531a03f11e55e69c127f70535308611F17D5C761D6E21", // RTCore64.sys
       "c1274f85e507204c854054a61d28f9d09e5f22d4f24c29759d57a4128f7311f9", // gdrv.sys
       "f27a4e69b5003c2007cf73b52668582d7335e95454b52c00994f1b51e44f0bfa"  // ENE.sys
   )
| project TimeGenerated, Computer, ImageLoaded, Hashes, Signed, Signature, SignatureStatus
```

### Detection Query 2: KQL – Service Creation with Kernel Mode Driver Type
This query flags newly created system services configured as kernel drivers loading from user-writable paths.

```kql
SecurityEvent
| where EventID == 4697
| where ServiceType == "0x1" // Kernel Mode Driver
| extend ServiceFileName = tolower(ServiceFileName)
| where ServiceFileName startswith @"c:\users\" 
   or ServiceFileName startswith @"c:\windows\temp\" 
   or ServiceFileName startswith @"c:\programdata\"
| project TimeGenerated, Computer, SubjectUserName, ServiceName, ServiceFileName
```

---

## Post-Exploitation Telemetry Blind Spots

A successful BYOVD attack targets the operational stability of security agents. Detection engineers must understand what happens **after** callback manipulation occurs.

```
       Timeline of BYOVD Telemetry Loss
       
  T0: Driver Staged        T1: Driver Loaded       T2: Callback Zeroed     T3: Post-Blinding Activity
───────┼────────────────────────┼───────────────────────┼───────────────────────┼────────────────────►
       │                        │                       │                       │
       ├─ Process Creation      ├─ Sysmon EID 6         ├─ PspCreateProcess     ├─ LSASS Dumping (No EID 10)
       │  (Payload execution)   │  (DriverLoad logged)  │  NotifyRoutine        ├─ CMD/Powershell (No EID 1)
       │                        │                       │  unhooked in kernel   │
       └─ Service Installation  └─ Event ID 7045        │                       └─ Telemetry Stream
          (Event ID 4697 logged)   logged by SCM        └─ EDR Callback Blinded    Silenced to SIEM
```

### The "Telemetry Silence" Signal
When an adversary successfully zeroes out callback arrays:
1.  **Sysmon / EDR Event Generation Ceases:** Process creation (`Event ID 1`), Thread Injection (`Event ID 8`), and Process Access (`Event ID 10`) stop emitting from the affected host.
2.  **ETW Threat Intelligence (ETW TI) Suppression:** If the driver patches `EtwTiProcessExecFull` pointers or disables provider registration, OS-level telemetry generated via `Microsoft-Windows-Threat-Intelligence` ceases.

### Detecting Telemetry Loss
Because the compromised agent can no longer report local events, detection must rely on **out-of-band monitoring**:

*   **Heartbeat Monitoring:** Monitor host heartbeat intervals in your SIEM/EDR console. A host actively sending security logs that suddenly stops emitting process creation events while remaining network-active (responding to network heartbeats or web proxy traffic) indicates potential sensor blinding.
*   **Correlation of Driver Load to Telemetry Drop:** Alert on driver load events (Sysmon 6 / Event ID 7045) that are followed by a total drop in process creation events from the same host within a 5-minute window.

---

## Defensive Strategies & Operational Mitigations

Relying solely on post-exploitation detection for BYOVD is risky, as successful execution strips the telemetry required to investigate. Prevention and kernel protection must take priority.

### 1. Enable HVCI (Hypervisor-Protected Code Integrity) / Memory Integrity
HVCI uses Virtualization-Based Security (VBS) to run Code Integrity checks inside a secure enclave isolated by the Hypervisor. 

HVCI prevents arbitrary execution in kernel space even if a driver contains a read/write primitive, as memory pages in kernel space cannot be simultaneously writable and executable ($W\oplus X$ enforcement).

### 2. Enforce the Microsoft Vulnerable Driver Blocklist
Microsoft maintains a recommended vulnerable driver blocklist that integrates directly with Windows Defender Application Control (WDAC) and HVCI. 

*   On modern Windows installations (Windows 11 / Windows Server 2022+), the blocklist is enabled by default.
*   Verify enforcement state via PowerShell:

```powershell
# Check if HVCI and Driver Blocklist are active
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard | 
Select-Object SecurityServicesConfigured, SecurityServicesRunning
```

### 3. Restrict `SeLoadDriverPrivilege`
Audit and restrict user accounts capable of loading kernel drivers. Standard administrative accounts should not carry driver load privileges unless explicitly required.

Group Policy Location:
`Computer Configuration` -> `Windows Settings` -> `Security Settings` -> `Local Policies` -> `User Rights Assignment` -> **Load and unload device drivers**.

Ensure this privilege is restricted strictly to `BUILTIN\Administrators` or specific privileged access workstations (PAWs), avoiding assignment to domain administrative groups across standard endpoints.

---

## Operational Considerations & Trade-Offs

Deploying strict driver blocking and HVCI introduces administrative and operational considerations:

1.  **Legacy Software Compatibility:** Enterprise environments running legacy system management utilities, specialized hardware tools, or outdated diagnostic software may rely on older drivers that are included on Microsoft's blocklist. Blocking these drivers can break legitimate applications.
2.  **Blocklist Maintenance Lag:** Blocklists are reactive. Adversaries continuously identify vulnerable signed drivers from obscure OEMs that are not yet cataloged in standard blocklists. Hash-based blocking must be supplemented with file path anomalies and certificate enforcement policies.
3.  **Hardware Requirements:** Enabling VBS/HVCI requires hardware virtualization support (Intel VT-x/AMD-V and SLAT) enabled in the system BIOS/UEFI. In legacy virtualized environments, nesting virtualization must be configured properly to avoid performance penalties.

---

## Summary Checklist for Defenders

| Objective | Defensive Mechanism | Key Telemetry / Artifact |
| :--- | :--- | :--- |
| **Prevent Driver Load** | HVCI & WDAC Vulnerable Driver Blocklist | `CodeIntegrity` Log Event 3076 / 3077 |
| **Detect Staged Drivers** | Monitor Driver Loading from Non-Standard Directories | Sysmon Event ID 6 (`ImageLoaded != system32\drivers`) |
| **Track Driver Installation** | Audit Kernel Mode Service Registration | Security Event ID 4697 / System Event ID 7045 |
| **Identify Blinded Agents** | Correlate Driver Load Events with Sudden Heartbeat Loss | SIEM Correlation Rule (Driver Load + Event Suppression) |
