---
title: "Detecting Process Reflection and LSASS Snapshotting: Telemetry Blind Spots, Kernel Handle Mask Auditing, and Call Stack Tracing"
description: "An in-depth technical analysis of process reflection and PSS API-based LSASS memory dumping, focusing on EDR telemetry gaps, GrantedAccess bitmask auditing, and practical detection logic."
date: "2026-09-10"
tags: ["Detection Engineering", "Endpoint Detection", "Threat Hunting", "Windows Internals"]
category: "Cyber Security"
difficulty: "Expert"
author: "Abdul Muqeet Tabraiz"
image: "/images/blog/2026-09-10-detecting-process-reflection-and-lsass-snapshotting-telemetry-blind-spots-kernel.svg"
---

Most detection rules targeting credential dumping focus on direct memory access to `lsass.exe`. Security teams routinely deploy alerting for `OpenProcess` or `MiniDumpWriteDump` calls where a process requests `PROCESS_VM_READ` (0x0010) or `PROCESS_VM_OPERATION` (0x0008) against Local Security Authority Subsystem Service.

Offensive tooling evolved past this direct interaction model long ago. Instead of reading LSASS memory directly while holding an open handle with read rights, modern threat actors and red teams rely on process reflection and the Windows Process Snapshotting (PSS) API. 

By instructing the kernel to create a clone or reflection of LSASS virtual memory space, attackers can perform memory dumping operations against an ephemeral worker process. This worker process lacks the security callbacks and handle monitoring built around LSASS, rendering traditional EDR handle-open rules blind.

Understanding the mechanics of process reflection, identifying the precise handle rights requested during the snapshotting sequence, and analyzing process creation anomalies allows detection engineers to close this telemetry gap.

---

## Process Reflection Mechanics: `PssCaptureSnapshot` and `RtlCreateProcessReflection`

Process reflection relies on native kernel capabilities designed for crash reporting and diagnostic tools (like Windows Error Reporting and Sysinternals `ProcDump`).

When an application calls the Win32 API `PssCaptureSnapshot` with the `PSS_CAPTURE_VA_CLONE` flag, the underlying subsystem invokes `ntdll!RtlCreateProcessReflection`.

```
User API: PssCaptureSnapshot(..., PSS_CAPTURE_VA_CLONE, ...)
   └─ Native API: ntdll!RtlCreateProcessReflection
        └─ Syscall: NtCreateProcessEx / NtCreateUserProcess
             └─ Kernel creates a cloned process sharing source Virtual Address Space (VAS)
```

At the kernel level, `RtlCreateProcessReflection` performs the following actions:

1. **Handle Acquisition:** The calling process opens a handle to the target process (`lsass.exe`). However, instead of requesting `PROCESS_VM_READ`, it requests `PROCESS_CREATE_PROCESS` (`0x0080`), often alongside `PROCESS_DUP_HANDLE` (`0x0040`) and `PROCESS_QUERY_INFORMATION` (`0x0400`).
2. **Process Cloning:** The kernel constructs a new process object whose virtual address space mirrors the source process. Address Space Layout Randomization (ASLR) offsets, mapped image sections, dynamic memory allocations, and heap structures are replicated via copy-on-write section objects.
3. **Thread Context Reproduction:** Threads are created in the target clone, suspended at the point of creation, or set up to run minimal initialization routines.
4. **Execution of Memory Extraction:** The attacker points `MiniDumpWriteDump` or custom memory parsing routines at the **cloned process PID**, not LSASS.
5. **Cleanup:** The target snapshot process is terminated via `NtTerminateProcess`.

Because `MiniDumpWriteDump` targets the cloned process PID rather than `lsass.exe`, EDR kernel callbacks registered via `ObRegisterCallbacks` for process access handles never trigger high-risk read alerts against LSASS during the actual dump phase.

---

## Telemetry Blind Spots in Standard EDR Implementations

Standard detection approaches fail against process reflection due to three architectural blind spots.

### 1. GrantedAccess Bitmask Filtering
Many Detection Engineers build Sysmon ID 10 (`ProcessAccess`) or Microsoft Defender for Endpoint (MDE) `DeviceEvents` (`ProcessPrimaryTokenModified`, `OpenProcessApiCall`) queries that strictly filter on explicit read rights:

```kql
// Common (but flawed) Detection Rule
DeviceEvents
| where ActionType == "OpenProcessApiCall"
| where TargetProcessFileName == "lsass.exe"
| where DesiredAccess has_any ("0x0010", "0x0008", "0x001F0FFF") // Misses 0x0080
```

`RtlCreateProcessReflection` does not require `PROCESS_VM_READ` on the source process to create a reflection. The kernel handles the memory copy internally during process creation. An attacker requesting `0x0080` (`PROCESS_CREATE_PROCESS`) bypasses detection logic that exclusively looks for memory read rights.

### 2. EDR Driver `ObRegisterCallbacks` Bypasses
`ObRegisterCallbacks` allows security drivers to inspect and strip requested access rights before a handle is returned to user mode. Many driver configurations only strip `PROCESS_VM_READ` or `PROCESS_VM_OPERATION` when non-SYSTEM processes open handles to LSASS. 

If the EDR driver does not strip `PROCESS_CREATE_PROCESS` (`0x0080`), the handle is returned successfully, and process reflection proceeds unimpeded.

### 3. Short Lifetimes and Missing Command Lines
The cloned process exists only for the duration of the dump (often less than 500 milliseconds). Because it is created via `NtCreateProcessEx` rather than `CreateProcessW`, standard user-mode Win32 structures (such as `PEB->ProcessParameters->CommandLine`) are uninitialized or empty. 

Security tools that depend solely on command-line logging (`Event ID 4688` / `Sysmon Event ID 1`) will record a process execution with blank or missing arguments, often ignoring it as noise.

---

## Analyzing Telemetry Artifacts

Detecting process reflection requires correlating handle creation events, process spawning telemetry, and kernel-level call stack states.

### Artifact 1: Sysmon Event ID 10 (Process Access)
When process reflection occurs, Sysmon records a process access event against `lsass.exe`. The critical indicator is the combination of `GrantedAccess` bits containing `0x0080` without standard process execution context.

```xml
<EventData>
  <Data Name="UtcTime">2026-09-10 14:22:01.412</Data>
  <Data Name="SourceImage">C:\Users\Public\loader.exe</Data>
  <Data Name="TargetImage">C:\Windows\System32\lsass.exe</Data>
  <Data Name="GrantedAccess">0x1480</Data> 
  <Data Name="CallTrace">
    C:\Windows\SYSTEM32\ntdll.dll+0x9d314|
    C:\Windows\System32\KERNELBASE.dll+0x2c4e0|
    C:\Users\Public\loader.exe+0x12a4
  </Data>
</EventData>
```

#### Breakdown of GrantedAccess Bitmask `0x1480`:
* `0x0080` — `PROCESS_CREATE_PROCESS` (Required for process reflection)
* `0x0400` — `PROCESS_QUERY_INFORMATION`
* `0x1000` — `PROCESS_QUERY_LIMITED_INFORMATION`

If an arbitrary binary (not signed by Microsoft, running outside standard system paths) requests `0x0080` against `lsass.exe`, it is almost certainly performing process snapshotting or reflection.

### Artifact 2: Anomalous Process Creation (Sysmon Event ID 1 / MDE ProcessCreationEvents)
The cloned process appears in telemetry as a new process instantiation of `lsass.exe`. However, its execution context deviates significantly from normal system behavior.

```json
{
  "Timestamp": "2026-09-10T14:22:01.440Z",
  "ProcessId": 8412,
  "Image": "C:\\Windows\\System32\\lsass.exe",
  "CommandLine": "",
  "ParentProcessId": 4108,
  "ParentImage": "C:\\Users\\Public\\loader.exe",
  "User": "NT AUTHORITY\\SYSTEM"
}
```

#### Key Anomalies:
1. **Parent-Child Disconnect:** Legitimate `lsass.exe` is executed once at boot by `wininit.exe`. Any `lsass.exe` process created with a parent other than `wininit.exe` (e.g., `loader.exe`, `powershell.exe`, `cmd.exe`) is an indicator of process cloning or masquerading.
2. **Missing Command Line:** Cloned processes do not execute standard startup parameters.
3. **Execution Duration:** The clone terminates almost immediately after creation.

---

## Developing Practical Detection Rules

Effective detection requires a multi-layered approach targeting handle access and process creation anomalies.

### Layer 1: KQL Rule for Handle Access to LSASS (Microsoft Defender for Endpoint)

This query targets non-standard processes acquiring `PROCESS_CREATE_PROCESS` handles against LSASS.

```kql
// Target processes requesting PROCESS_CREATE_PROCESS (0x0080) on LSASS
DeviceEvents
| where Timestamp > ago(24h)
| where ActionType in ("OpenProcessApiCall", "ProcessPrimaryTokenModified")
| where TargetProcessFileName =~ "lsass.exe"
// Bitwise check for 0x0080 (PROCESS_CREATE_PROCESS)
| extend GrantedAccessDec = toint(DesiredAccess)
| where binary_and(GrantedAccessDec, 128) == 128
// Filter out legitimate systemic callers
| where not(InitiatingProcessFolderPath  tolowerpath in (
    @"c:\windows\system32\svchost.exe",
    @"c:\windows\system32\msiexec.exe",
    @"c:\program files\microsoft defender\msmpeng.exe",
    @"c:\windows\system32\werfault.exe"
))
| project Timestamp, DeviceName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, TargetProcessFileName, DesiredAccess, GrantedAccessDec
```

### Layer 2: Sigma Rule for Anomalous LSASS Parent-Child Relationships

This rule identifies instances where `lsass.exe` is spawned by an invalid parent process.

```yaml
title: Cloned LSASS Process Execution via Process Reflection
id: e4d3a8b2-7f91-4e8c-a123-99120891bcfa
status: experimental
description: Detects instances of lsass.exe spawned by an unexpected parent process, typical of RtlCreateProcessReflection or PSS snapshotting.
author: Abdul Muqeet Tabraiz
date: 2026/09/10
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\lsass.exe'
  filter_legitimate_parent:
    ParentImage|endswith: '\wininit.exe'
  condition: selection and not filter_legitimate_parent
falsepositives:
  - Third-party security tools performing non-standard driver operations (rare).
level: high
```

### Layer 3: Call Stack Tracing for Unbacked Memory Operations

When threat actors execute `PssCaptureSnapshot` via reflective DLL injection or shellcode, the call stack reveals execution originating from unbacked memory (memory regions not associated with a mapped image on disk).

```
Call Stack Structure Analysis:
[Frame 0] ntdll.dll!NtCreateProcessEx
[Frame 1] ntdll.dll!RtlCreateProcessReflection
[Frame 2] KERNELBASE.dll!PssCaptureSnapshot
[Frame 3] UNBACKED_MEMORY (0x00007FFB12A00000) <-- Alert Condition
```

Detection logic leveraging ETW (`Microsoft-Windows-Threat-Intelligence` provider) can flag calls to `NtCreateProcessEx` or `OpenProcess` where the calling instruction pointer resides within `MEM_COMMIT` allocations that do not correlate with a valid `FILE_OBJECT`.

---

## Operational Tuning and Limitations

### Legitimate System Use Cases
Several native Windows processes and security tools legitimately perform process snapshotting:

1. **Windows Error Reporting (`WerFault.exe`):** When a process crashes, `WerFault.exe` uses process reflection to create a memory snapshot without freezing the thread context of the host process indefinitely.
2. **Sysinternals ProcDump:** When run with the `-r` flag, `ProcDump` explicitly leverages process reflection to minimize service disruption on target processes.
3. **EDR/AV Agents:** Modern endpoint protection tools occasionally snapshot high-value processes for deep memory inspection without causing thread-lock conditions.

### Tuning Strategy
To eliminate false positives without opening gaps:

* **Path Normalization:** Ensure paths to `WerFault.exe` are verified via code signing status (`Authenticode`) rather than image path strings alone, as attackers frequently rename payloads to `WerFault.exe`.
* **Combine Access Rights with Parent Context:** Do not suppress alerts for `WerFault.exe` if `WerFault.exe` was spawned by an untrusted parent process (e.g., `cmd.exe` or `powershell.exe`).

---

## Defensive Engineering Summary

Relying solely on `PROCESS_VM_READ` monitoring for LSASS leaves systems vulnerable to process reflection techniques. 

To build robust coverage:

1. Update handle access monitoring to include bitwise checks for `PROCESS_CREATE_PROCESS` (`0x0080`).
2. Implement alerts for anomalous parent processes spawning `lsass.exe`.
3. Audit call stack structures for unbacked memory frames calling native reflection APIs (`RtlCreateProcessReflection`).
4. Validate that existing EDR driver configurations block or strip `0x0080` handle permissions requested against `lsass.exe` by untrusted processes.
