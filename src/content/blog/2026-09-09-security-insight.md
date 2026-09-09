---
title: "Detecting User-Mode ETW Patching: Telemetry Blind Spots, Kernel ETW, and Memory Auditing"
description: "An operational breakdown of how attackers blind user-mode Event Tracing for Windows, telemetry gaps in security stack monitoring, and strategies for detecting in-memory byte modifications."
date: "2026-09-09"
tags: ["Cybersecurity", "Security Operations"]
category: "Cyber Security"
difficulty: "Advanced"
author: "Abdul Muqeet Tabraiz"
image: "/images/blog/2026-09-09-detecting-user-mode-etw-patching-telemetry-blind-spots-kernel-etw-and-memory-aud.svg"
---

Security operations teams heavily rely on Event Tracing for Windows (ETW) to observe runtime process behavior. Many endpoint detection and response (EDR) agents, SIEM forwarders, and threat hunting tools ingest ETW events to monitor .NET execution, PowerShell activity, and API usage. 

Because user-mode ETW functions reside inside the address space of the process being monitored, unprivileged code can modify these routines in memory. When an adversary patches user-mode ETW routines inside a running process, any consumer relying solely on user-land event generation is blinded to subsequent execution in that process.

Understanding how user-mode ETW patching works, where the telemetry gaps exist, and how to build resilient detection strategies across kernel telemetry and memory auditing is critical for defender visibility.

---

## User-Mode ETW Architecture

ETW is a kernel-level tracing facility built into Windows. It consists of three main components:

1. **Providers**: Instrumentation points that generate events.
2. **Controllers**: Applications that enable, disable, and configure trace sessions (e.g., `logman`, EDR service engines).
3. **Consumers**: Applications that subscribe to trace sessions to read events (e.g., Sysmon, SIEM agents, custom security tools).

When a program calls a high-level framework logging routine—such as loading a .NET assembly via `System.Reflection.Assembly.Load`—the underlying runtime invokes user-land ETW functions provided by `ntdll.dll`.

```
[ Application Process ]
  ├── .NET CLR / PowerShell Routine
  └── ntdll.dll
        └── EtwEventWrite() / EtwEventWriteFull()
              │
              └── [ Syscall: NtTraceEvent ]
                    │
                    ▼
[ Windows Kernel ]
  └── ETW Subsystem (Routes events to active sessions)
        │
        ▼
[ Security Consumer ] (EDR / SIEM / Sysmon)
```

The primary API entry point for generating user-mode events is `EtwEventWrite` (or its extended variant `EtwEventWriteFull`) inside `ntdll.dll`. This function accepts an event descriptor, formats the payload, and makes a system call (`NtTraceEvent`) to transition execution into the kernel ETW subsystem.

---

## Mechanics of User-Mode ETW Patching

Because `ntdll.dll` is loaded into every user-space process, its memory pages are mapped directly into that process's virtual address space. By default, the executable code sections (`.text`) of `ntdll.dll` are mapped with `PAGE_EXECUTE_READ` permissions. 

An adversary running inside a process (or using `WriteProcessMemory` from another process running in the same user context) can alter these permissions and modify the instruction bytes of `ntdll!EtwEventWrite`.

### The Patch Sequence

1. **Locate the Function**: The offset of `EtwEventWrite` is resolved using `GetProcAddress(GetModuleHandle("ntdll.dll"), "EtwEventWrite")`.
2. **Change Memory Protection**: The process calls `VirtualProtect` to change the target memory region's permissions from `PAGE_EXECUTE_READ` (`0x20`) to `PAGE_EXECUTE_READWRITE` (`0x40`).
3. **Overwrite Prologue**: The original function instructions are replaced with byte sequences that force an immediate function return.
4. **Restore Memory Protection**: `VirtualProtect` is called again to restore the original memory flags, reducing passive anomalies during basic memory scans.

### Common Assembly Patch Payloads

On x64 architecture, standard function prologues inside `ntdll!EtwEventWrite` vary slightly across Windows builds, but usually begin with setup instructions like:

```assembly
mov     r10, rcx
mov     eax, 0x156   ; (Syscall number for NtTraceEvent on specific build)
syscall
```

To break this execution flow, an attacker overwrites the starting bytes with instructions that immediately return success (`ERROR_SUCCESS` or `0` in `RAX`):

* **Opcode Patch 1 (Return Immediately)**:
  ```assembly
  ret                ; Opcode: C3
  ```
  *(Returns whatever value happens to be in RAX at entry)*

* **Opcode Patch 2 (Clear RAX and Return)**:
  ```assembly
  xor eax, eax       ; Opcode: 31 C0  (or 48 31 C0 for x64 XOR RAX, RAX)
  ret                ; Opcode: C3
  ```
  *(Guarantees returning 0, mimicking a successful ETW event delivery without issuing the `NtTraceEvent` syscall)*

Once `EtwEventWrite` is patched, callers like the .NET Common Language Runtime (CLR) continue to invoke `EtwEventWrite` normally, but the call returns `0` instantly without ever reaching kernel space. Consequently, providers like `Microsoft-Windows-DotNETRuntime` stop emitting assembly load events, type resolution events, and method JIT compilation logs.

---

## Telemetry Gaps: User-Mode vs. Kernel-Mode ETW

A common misconception in threat detection is assuming that all ETW telemetry can be disabled via user-mode patching. 

ETW events originate from two distinct locations:

| Telemetry Type | Execution Context | Patchable from User Space? | Example Event Sources |
| :--- | :--- | :--- | :--- |
| **User-Mode ETW** | User Space (`ntdll.dll`) | **Yes** | `Microsoft-Windows-DotNETRuntime`<br>`Microsoft-Windows-PowerShell`<br>`Microsoft-Antimalware-Scan-Interface` |
| **Kernel-Mode ETW** | Kernel Space (`ntoskrnl.exe`) | **No** (Requires Ring 0) | `Microsoft-Windows-Threat-Intelligence`<br>`Microsoft-Windows-Kernel-Process`<br>`Microsoft-Windows-Kernel-File` |

If an adversary patches `ntdll!EtwEventWrite`, user-mode events generated by .NET or PowerShell applications are silenced. However, kernel-mode ETW providers that trigger on kernel callbacks—such as process creation, thread creation, image loads, and handle operations—remain completely functional because their execution never touches user-space `ntdll.dll` functions.

```
+-------------------------------------------------------------------+
| USER SPACE                                                        |
|                                                                   |
| [ Process Payload ] ──> [ Patched EtwEventWrite ] ──X (Silenced)  |
|         │                                                         |
|         └───> [ VirtualProtect Call ]                             |
+-----------│-------------------------------------------------------+
            │ Syscall
+-----------▼-------------------------------------------------------+
| KERNEL SPACE                                                      |
|                                                                   |
| [ Kernel Callbacks ] ──> [ Threat-Intelligence Provider ]         |
|                          (Generates Event ID 0x000B / Protection) |
+-------------------------------------------------------------------+
```

---

## Detection Engineering Strategies

Detecting ETW patching requires monitoring the actions taken to alter process memory, inspecting function integrity inside running processes, or relying on higher-privileged kernel sources.

### 1. Monitoring Memory Protection Changes (`VirtualProtect`)

Adversaries must modify memory access rights on `ntdll.dll` to perform the patch. Standard processes rarely modify executable memory pages inside core system DLLs after initialization.

Using kernel-based process auditing or EDR telemetry, focus on memory protection events where:

* **Target Module**: `ntdll.dll`
* **Allocation / Protection Change**: Transitions to `PAGE_EXECUTE_READWRITE` (`0x40`), `PAGE_READWRITE` (`0x04`), or `PAGE_EXECUTE_WRITECOPY` (`0x80`).
* **Target Memory Offset**: Addresses mapping into exported routines (`EtwEventWrite`, `EtwEventWriteFull`, `EtwNotificationRegister`).

#### Example Detection Logic (Targeting Memory Modification)

```yaml
title: Suspicious Memory Protection Modification on NTDLL
id: 3c9b7431-7e81-4b71-b0e2-881273da9120
status: experimental
description: Detects memory protection modifications targeting ntdll.dll execution routines commonly modified during ETW blinding.
logsource:
  category: process_access
  product: windows
detection:
  selection:
    TargetImage|endswith: '\ntdll.dll'
    GrantedAccess|contains:
      - '0x0020'  # PROCESS_VM_WRITE
      - '0x0008'  # PROCESS_VM_OPERATION
  protection_change:
    RequestedProtection: 'PAGE_EXECUTE_READWRITE'
  condition: selection and protection_change
falsepositives:
  - Security software injection mechanisms
  - Debuggers and profiling tools
level: high
```

### 2. Utilizing ETW Threat-Intelligence (`Microsoft-Windows-Threat-Intelligence`)

The `Microsoft-Windows-Threat-Intelligence` (ETW-TI) provider runs entirely in kernel space. It generates telemetry when processes execute sensitive operations, such as calling `VirtualProtectEx` or `WriteProcessMemory` against another process.

Key ETW-TI events related to memory tampering:

* **`KERNEL_THREATINT_VIRTUAL_PROTECT`** (Event ID: `0x000B` / `11`): Logs caller and target details when memory protections are altered.
* **`KERNEL_THREATINT_VIRTUAL_WRITE`** (Event ID: `0x000C` / `12`): Logs cross-process memory writes.

Because ETW-TI requires Microsoft Protected Process Light (PPL) signing for consumers, standard SOC teams access this data through EDR agents that implement ETW-TI drivers. If your EDR captures ETW-TI events, query for operations where `TargetProcess` equals `SourceProcess` and the requested protection mode includes write permissions on memory pages containing `ntdll.dll`.

### 3. In-Memory Function Integrity Inspections

If memory protection monitoring produces high volume in complex environments, defensive agents can perform direct memory integrity checks on critical exported functions in `ntdll.dll`.

A memory inspection routine reads the first few bytes of `ntdll!EtwEventWrite` and compares them against known clean function prologues.

#### Example Signature Pattern (YARA for Memory Scans)

The following rule scans process virtual memory for common ETW patch patterns at exported addresses:

```yara
rule Detect_ETW_Patch_In_Memory
{
    meta:
        description = "Detects patched EtwEventWrite prologue in process memory"
        author = "Abdul Muqeet Tabraiz"
        date = "2026-09-09"
        severity = "High"

    strings:
        // x64: XOR EAX, EAX; RET (31 C0 C3)
        $patch_xor_ret = { 31 C0 C3 }
        
        // x64: XOR RAX, RAX; RET (48 31 C0 C3)
        $patch_xor_rax_ret = { 48 31 C0 C3 }
        
        // Immediate RET (C3) at function entry
        $patch_ret_direct = { C3 }

    condition:
        // Match patches occurring at or near exported EtwEventWrite locations
        any of ($patch_*)
}
```

*Note: In production detection engineering, memory pattern scanning must account for normal export entry points to avoid matching standard `C3` instructions scattered throughout legitimate code sections.*

### 4. Telemetry Anomaly Correlation: `.NET Execution without CLR Logs`

A structural approach to detecting ETW suppression relies on correlating execution context against expected event streams:

1. **Process Indicators**: Process loads `mscoree.dll`, `clr.dll`, or `clrjit.dll` (indicating .NET execution).
2. **Missing Telemetry**: The SIEM/EDR receives **zero** `Microsoft-Windows-DotNETRuntime` events (e.g., Event ID 145 for `AssemblyLoad`, Event ID 87 for `MethodJittingStarted`) during the lifecycle of the process.

If `powershell.exe` or a custom unmanaged executable loads `.NET` runtime DLLs but emits no `DotNETRuntime` events over a 30-second window, there is a high probability that user-mode ETW has been patched or suppressed.

```
[ Telemetry Correlation Query Logic ]

Process Start Event (Sysmon ID 1 / Event ID 4688)
   │
   ├── Module Load: clr.dll / mscoree.dll
   │
   └── WHERE NOT EXISTS (
         ETW Event Source: "Microsoft-Windows-DotNETRuntime"
         AND ProcessID == TargetProcessID
       )
   │
   ▼
[ Trigger Alert: Potential ETW Telemetry Suppression ]
```

---

## Operational Considerations and Limitations

When deploying detection logic for ETW patching, defenders face several practical challenges:

### High Volume on Software Hooks
Third-party applications—such as application performance monitoring tools, legacy antivirus software, and enterprise DLP solutions—frequently apply user-mode API hooks to functions inside `ntdll.dll`. These tools may alter memory protections temporarily or insert jump instructions (`JMP`) at function prologues, generating false positives on naive memory modification alerts.

### Driver Requirements for ETW-TI
Accessing `Microsoft-Windows-Threat-Intelligence` telemetry directly requires an antimalware driver running with Protected Process Light (PPL) attributes. Defender operations must verify that their endpoint agent vendor consumes and surfaces ETW-TI data within exposed telemetry tables.

### Race Conditions
Adversaries can dynamically patch ETW, execute an assembly, and immediately unpatch (restore original bytes) to reduce their memory anomaly footprint. Continuous memory auditing at static intervals may miss transient patches. Detection must emphasize real-time kernel memory modification triggers (`VirtualProtect` hooks/ETW-TI) over scheduled memory polling.

---

## Defensive Recommendations

1. **Prioritize Kernel Telemetry**: Ensure endpoint security strategies depend on kernel callbacks (process/thread creation, image loads, handle duplication) rather than unvalidated user-mode logging sources alone.
2. **Alert on Memory Protection Changes**: Filter `VirtualProtect` events targeting `ntdll.dll` executable regions, focusing on non-standard parent-child execution chains (e.g., `cmd.exe`, `powershell.exe`, or `wmic.exe`).
3. **Audit Target Binary Integrity**: Implement endpoint agents capable of validating function prologues for critical user-land APIs (`EtwEventWrite`, `EtwEventWriteFull`, `AmsiScanBuffer`).
4. **Build Behavioral Correlations**: Combine module-load events with runtime ETW log absence queries to identify processes operating in telemetry dark zones.
