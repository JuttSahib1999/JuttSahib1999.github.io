---
title: "Detecting Evasive LSASS Memory Snapshotting and Handle Duplication"
description: "An operational guide to detecting stealthy LSASS credential dumping using PssCaptureSnapshot, process handle duplication, call stack inspection, and kernel-level auditing."
date: "2026-09-27"
tags: ["Detection Engineering", "LSASS", "Windows Security", "Threat Hunting"]
category: "Cyber Security"
difficulty: "Advanced"
author: "Abdul Muqeet Tabraiz"
image: "/images/blog/2026-09-27-detecting-evasive-lsass-memory-snapshotting-and-handle-duplication.svg"
---

Most detection rules for LSASS memory dumping rely on a straightforward pattern: a process requests a handle to `lsass.exe` with broad rights like `PROCESS_VM_READ` (`0x0010`) or `PROCESS_ALL_ACCESS` (`0x1F0FFF`), followed immediately by a call to `dbghelp.dll!MiniDumpWriteDump`. Attackers adapted to this telemetry pattern long ago. Modern tradecraft rarely opens a direct, high-privilege handle to LSASS just to pass it straight to `MiniDumpWriteDump`.

Instead, adversaries bypass basic process access alerts using native process snapshotting APIs (`PssCaptureSnapshot`) or handle duplication (`NtDuplicateObject`). These techniques decouple the handle request from the dump operation, redirecting defensive monitoring toward non-standard process access behavior.

Detecting these evasive variants requires moving beyond simple process name and access mask combinations. You must analyze kernel object callbacks, inspect process call stacks in Sysmon Event ID 10, track handle table manipulation, and understand how the Windows Process Snapshot API alters execution flow.

---

## Evasive LSASS Dump Vectors Explained

### 1. Windows Process Snapshotting (`PssCaptureSnapshot`)

Introduced in Windows 8.1, the Process Snapshotting framework (`KERNELBASE!PssCaptureSnapshot`) allows applications to create a point-in-time snapshot of a target process's virtual memory, threads, and handle tables for debugging purposes.

```
+------------------+         1. PssCaptureSnapshot()         +------------------+
| Attacker Process | --------------------------------------> |    lsass.exe     |
+------------------+                                         +------------------+
         |                                                            |
         | 2. NtCreateProcessEx() creates shadow clone                v
         +--------------------------------------------------> [ Frozen Snapshot ]
         |                                                            |
         | 3. MiniDumpWriteDump() targets Snapshot handle             |
         +------------------------------------------------------------+
```

When an attacker calls `PssCaptureSnapshot` against LSASS:
1. The API executes `ntdll!NtCreateProcessEx` under the hood to create a cloned, frozen child process of `lsass.exe` (or a raw memory snapshot object).
2. The snapshot process inherits the memory pages of LSASS.
3. The attacker then invokes `MiniDumpWriteDump` against the handle of the **snapshot process**, not the live `lsass.exe`.

Because `MiniDumpWriteDump` reads memory from a cloned process handle rather than directly from `lsass.exe`, naive detection logic that alerts on `MiniDumpWriteDump` targeting `lsass.exe` fails entirely.

### 2. Handle Duplication (`NtDuplicateObject`)

Rather than requesting a fresh handle to `lsass.exe` via `OpenProcess`—which directly triggers EDR kernel callbacks (`ObRegisterCallbacks`)—an attacker can scan the system handle table for existing processes that already hold an open handle to LSASS.

System processes like `csrss.exe`, `svchost.exe`, or security agents frequently maintain open handles to `lsass.exe`. An attacker running with `SeDebugPrivilege`:
1. Opens a handle to the target process holding the LSASS handle (e.g., `csrss.exe`) using `PROCESS_DUP_HANDLE` (`0x0040`).
2. Calls `ntdll!NtDuplicateObject` to copy the pre-existing LSASS handle into their own process space.
3. Performs memory reads or snapshot operations using the duplicated handle.

While `ObRegisterCallbacks` still fires during the handle duplication request, the target of the initial `OpenProcess` call is `csrss.exe` or `svchost.exe`, not `lsass.exe`. The actual LSASS object modification occurs via kernel handle table duplication, which alters telemetry patterns.

---

## Telemetry Sources and Key Artifacts

To capture these subtle variations, defensive engineering relies on three primary data sources:

| Source | Telemetry Provider | Key Event ID / Facility | Primary Detection Artifacts |
| :--- | :--- | :--- | :--- |
| **Sysmon** | `Microsoft-Windows-Sysmon` | Event ID 10 (ProcessAccess) | `TargetImage`, `GrantedAccess`, `CallTrace`, `SourceImage` |
| **Windows Audit** | Security Log | Event ID 4656 / 4663 | `ObjectType: Process`, `AccessMask`, `ProcessName` |
| **ETW-Ti** | `Microsoft-Windows-Threat-Intelligence` | `KERNEL_THREATINT_KEY` | Kernel stack traces, direct handle requests, `PSCREATE_PROCESS_SNAPSHOT` |

### Analyzing Sysmon Event ID 10 Bitmasks

When analyzing process access logs, the `GrantedAccess` field represents a hex bitmask of requested permissions. The most critical process access rights relevant to LSASS inspection include:

* `0x0010` — `PROCESS_VM_READ`
* `0x0020` — `PROCESS_VM_WRITE`
* `0x0040` — `PROCESS_DUP_HANDLE`
* `0x0080` — `PROCESS_CREATE_PROCESS` (Required for snapshotting)
* `0x0400` — `PROCESS_QUERY_INFORMATION`
* `0x1000` — `PROCESS_QUERY_LIMITED_INFORMATION`

Classic dumping tools typically request `0x1F0FFF` (`PROCESS_ALL_ACCESS`) or `0x1410` (`PROCESS_VM_READ | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION`). 

Evasive tools using `PssCaptureSnapshot` require at least `0x0080` (`PROCESS_CREATE_PROCESS`) combined with `PROCESS_VM_READ` (`0x0010`) and `PROCESS_DUP_HANDLE` (`0x0040`), leading to common access masks like `0x1450` or `0x1410`.

---

## Practical Detection Engineering

### 1. Call Stack Inspection for `PssCaptureSnapshot`

The most reliable sign of process snapshotting targeting LSASS appears in the process `CallTrace` provided by Sysmon Event ID 10 or ETW-Ti. When a tool relies on the PssAPI infrastructure, the kernel captures user-mode call stack frames originating from `KERNELBASE.DLL` and `ntdll.dll` specific snapshot functions.

Here is an example Sysmon Event ID 10 log generated by a snapshot-based credential dumper:

```xml
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon" GUID="{57707312-8702-48ac-a8d0-f01643ce4400}" />
    <EventID>10</EventID>
    <TimeCreated SystemTime="2026-09-27T14:22:10.412801Z" />
  </System>
  <EventData>
    <Data Name="SourceImage">C:\Users\Public\Downloads\loader.exe</Data>
    <Data Name="TargetImage">C:\Windows\System32\lsass.exe</Data>
    <Data Name="GrantedAccess">0x1450</Data>
    <Data Name="CallTrace">
      C:\Windows\SYSTEM32\ntdll.dll+9d214|
      C:\Windows\System32\KERNELBASE.dll+61a20|
      C:\Windows\System32\KERNELBASE.dll!PssCaptureSnapshot+0x2f4|
      C:\Users\Public\Downloads\loader.exe+0x12b4|
      C:\Windows\System32\KERNEL32.DLL+0x17034|
      C:\Windows\SYSTEM32\ntdll.dll+0x4cb61
    </Data>
  </EventData>
</Event>
```

Notice the presence of `KERNELBASE.dll!PssCaptureSnapshot` in the `CallTrace` alongside a `GrantedAccess` mask that includes `0x0040` (`PROCESS_DUP_HANDLE`) and `0x0010` (`PROCESS_VM_READ`). Legitimate system utilities rarely call `PssCaptureSnapshot` directly on `lsass.exe`.

### 2. Detection Query: Snapshot API & Anomalous LSASS Access

The following KQL (Kusto Query Language) query detects non-standard process access to LSASS involving process snapshot calls or unbacked memory execution frames:

```kql
Sysmon_Event_10
| where TargetImage datetime_iso8601_equal(TargetImage, "C:\\Windows\\System32\\lsass.exe")
| extend CallTraceLower = tolower(CallTrace)
| where 
    // Flag explicit usage of the Process Snapshotting framework
    CallTraceLower has "psscapturesnapshot"
    or CallTraceLower has "pswalksnapshot"
    or CallTraceLower has "ntcreateprocessex"
    // Flag suspicious access masks commonly associated with snapshot creation (e.g., PROCESS_CREATE_PROCESS 0x0080)
    or (GrantedAccess in~ ("0x1450", "0x1410", "0x0080") and not(SourceImage endswith "\\svchost.exe" or SourceImage endswith "\\msmpeng.exe"))
| project TimeGenerated, Computer, SourceImage, TargetImage, GrantedAccess, CallTrace
```

### 3. Detecting Handle Duplication Chains

Detecting handle duplication requires tracking process access where the target process is *not* LSASS, but the granted access includes `PROCESS_DUP_HANDLE` (`0x0040`) against sensitive elevated processes (`csrss.exe`, `services.exe`), followed closely by memory read operations.

When an attacker attempts handle duplication:
1. `SourceImage` (e.g., `attacker.exe`) opens `TargetImage` (`csrss.exe`) with `GrantedAccess` containing `0x0040` (`PROCESS_DUP_HANDLE`).
2. The user-mode call stack contains references to `ntdll.dll!NtDuplicateObject` or `KERNELBASE.dll!DuplicateHandle`.

```kql
// KQL query for detecting suspicious handle duplication against system processes
Sysmon_Event_10
| where TargetImage endswith "\\csrss.exe" or TargetImage endswith "\\services.exe"
| where GrantedAccess has "0x0040" // PROCESS_DUP_HANDLE
| where CallTrace tolower() has "duplicatehandle" or CallTrace tolower() has "ntduplicateobject"
| where not(SourceImage endswith "\\wbem\\wmiprvse.exe" or SourceImage endswith "\\lsass.exe")
| project TimeGenerated, Computer, SourceImage, TargetImage, GrantedAccess, CallTrace
```

---

## Stack Walking and Unbacked Memory Detection

Attackers aware of call stack monitoring often execute their snapshot or handle duplication routines from dynamic, unbacked memory (e.g., shellcode allocated via `VirtualAlloc` without a corresponding module on disk).

In Sysmon Event ID 10 telemetry, an unbacked stack frame appears as a memory offset missing an associated module name. For example:

```text
C:\Windows\SYSTEM32\ntdll.dll+0x9d214|
UNKNOWN(0000021A4B820000)+0x12a0|
C:\Windows\System32\KERNEL32.DLL+0x17034|
C:\Windows\SYSTEM32\ntdll.dll+0x4cb61
```

If an access request targeting `lsass.exe` contains `UNKNOWN` or unmapped memory regions in the `CallTrace`, treat the event as high-confidence malicious activity regardless of the specific `GrantedAccess` value.

---

## Defensive Hardening & Operational Trade-Offs

While detection rules capture execution artifacts, proactive controls reduce the attack surface entirely:

### 1. LSA Protection (RunAsPPL)
Enabling LSA Protection configures LSASS to run as a Protected Process Light (PPL). This blocks non-protected processes from requesting handles with `PROCESS_VM_READ` or `PROCESS_DUP_HANDLE` rights.

```cmd
# Enable RunAsPPL via Registry
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "RunAsPPL" /t REG_DWORD /d 1 /f
```

*Note on Bypass Risk:* Attackers bypass PPL using Bring Your Own Vulnerable Driver (BYOVD) attacks to strip PPL protection flags from the LSASS `EPROCESS` structure in kernel memory. Therefore, monitoring kernel driver loading (`Event ID 6` in Sysmon) must complement PPL deployment.

### 2. Telemetry Overhead vs. Visibility
Configuring Sysmon to log all Event ID 10 access requests to `lsass.exe` can generate thousands of events per endpoint daily if not filtered correctly.

To optimize telemetry volume without losing visibility:
* Do not exclude process access purely by `SourceImage` if the `CallTrace` contains unbacked memory (`UNKNOWN`).
* Exclude known high-volume system binaries (`MsMpEng.exe`, `lsass.exe`, `svchost.exe`) *only* when the `GrantedAccess` matches expected baseline patterns (e.g., `0x1400` or `0x1000`).

---

## Verification and Testing

To safely validate your detection rules in an authorized environment without using full offensive frameworks, you can leverage native Windows APIs in C/C++ or PowerShell scripts that invoke `PssCaptureSnapshot` against a test process before attempting it against LSASS.

Key parameters to inspect during testing:
1. Verify if your EDR captures the `PSCREATE_PROCESS_SNAPSHOT` telemetry event via ETW-Ti.
2. Ensure your SIEM correlates Sysmon Event ID 10 calls containing `PssCaptureSnapshot` in the call stack.
3. Confirm whether handle duplication alerts fire when duplicating process handles from `csrss.exe`.

Detecting evasive memory access requires shifting baseline alerts from broad process handles to execution context. By auditing the combination of call stack frames, handle duplication requests, and explicit snapshot API usage, security operations teams can catch sophisticated credential access attempts that bypass traditional process monitoring.
