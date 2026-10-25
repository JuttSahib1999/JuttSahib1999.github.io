---
title: "Detecting Thread Execution Hijacking and APC Injection: Telemetry, ETW TI, and Detection Strategies"
description: "An in-depth technical analysis of Thread Execution Hijacking and Asynchronous Procedure Call (APC) injection, covering kernel telemetry, ETW Threat Intelligence, and practical detection logic."
date: "2026-10-25"
tags: ["Detection Engineering", "Windows Internals", "Threat Hunting", "Telemetry"]
category: "Cyber Security"
difficulty: "Advanced"
author: "Abdul Muqeet Tabraiz"
image: "/images/blog/2026-10-25-detecting-thread-execution-hijacking-and-apc-injection-telemetry-etw-ti-and-dete.svg"
---

Standard remote process injection relies on well-known APIs like `CreateRemoteThread` or `RtlCreateUserThread`. Because these primitives generate distinct telemetry and are aggressively monitored by Endpoint Detection and Response (EDR) sensors, threat actors frequently pivot toward less noisy in-memory execution vectors.

Two persistent alternatives are **Thread Execution Hijacking** (manipulating an existing process thread's execution context) and **Asynchronous Procedure Call (APC) Injection** (queuing executable code to a thread's APC queue). When combined with "Early Bird" execution techniques, attackers can run arbitrary code inside legitimate process boundaries before EDR user-mode API hooks are fully initialized.

Defending against these techniques requires looking beyond standard process creation events and analyzing cross-process handle permissions, kernel callbacks, and Event Tracing for Windows Threat Intelligence (ETW TI).

---

## Mechanics of the Attack Vectors

Understanding how these techniques execute at the Win32 and Native API levels highlights why standard process creation logging fails to catch them.

### 1. Thread Execution Hijacking

Thread Execution Hijacking target an already running thread in a target process. Instead of spawning a new thread, the attacker modifies the register state of an existing thread to point to injected code.

```
Attacker Process                        Target Process
  │                                           │
  ├── OpenProcess / OpenThread ──────────────>│
  ├── SuspendThread ─────────────────────────>│ (Target thread pauses)
  ├── VirtualAllocEx (Allocate RWX) ─────────>│
  ├── WriteProcessMemory (Write payload) ────>│
  ├── GetThreadContext ───────────────────────┤ (Retrieves register state)
  ├── SetThreadContext ───────────────────────┤ (Modifies RIP/EIP to payload)
  └── ResumeThread ──────────────────────────>│ (Target thread executes code)
```

The underlying native system calls mapping to this sequence are:

- `NtOpenThread`
- `NtSuspendThread`
- `NtAllocateVirtualMemory`
- `NtWriteVirtualMemory`
- `NtGetContextThread`
- `NtSetContextThread`
- `NtResumeThread`

Because `NtSetContextThread` directly alters the instruction pointer (`RIP` on x64, `EIP` on x86) stored in the target thread's `CONTEXT` structure, execution redirects to the payload address as soon as `NtResumeThread` is called.

### 2. Asynchronous Procedure Call (APC) Injection

An APC is a function that executes asynchronously in the context of a specific thread. Every Windows thread has an associated APC queue managed by the kernel. User-mode APCs execute only when the thread enters an *alertable state* (e.g., calling `SleepEx`, `SignalObjectAndWait`, or `WaitForSingleObjectEx` with the `bAlertable` parameter set to `TRUE`).

In a standard APC injection, the attacker:

1. Opens a target process and allocates/writes payload memory (`VirtualAllocEx`, `WriteProcessMemory`).
2. Enumerates existing threads in the target process.
3. Calls `QueueUserAPC` (or `NtQueueApcThread`) pointing to the allocated memory address.
4. When the target thread enters an alertable state, the kernel dispatches the queued APC, executing the payload.

### 3. Early Bird APC Injection Variant

To bypass the requirement of waiting for an existing thread to become alertable, attackers use the **Early Bird** variant:

1. Create a legitimate target process (such as `werfault.exe`, `svchost.exe`, or `notepad.exe`) in a **suspended state** using `CreateProcessA` with the `CREATE_SUSPENDED` (0x00000004) flag.
2. Allocate executable memory (`PAGE_EXECUTE_READWRITE`) and write the payload into the suspended target process.
3. Queue an APC to the main thread of the newly created process via `NtQueueApcThread`.
4. Resume the main thread using `ResumeThread` or `NtResumeThread`.

During thread initialization, `ntdll.dll!LdrInitializeThunk` processes the APC queue before the process main entry point is executed. This runs the payload before security solutions can inject user-mode hooks into the newly spawned process.

---

## Telemetry Sources and Blind Spots

Standard security telemetry captures parts of these attack chains, but individual events rarely provide complete visibility without correlation.

| Telemetry Source | Captured Event / API | Visibility Level | Limitations |
| :--- | :--- | :--- | :--- |
| **Sysmon Event ID 1** | Process Creation | High for `CREATE_SUSPENDED` flag tracking | Does not indicate if memory injection or APC queuing followed. |
| **Sysmon Event ID 8** | CreateRemoteThread | **Zero Visibility** | Does not fire for `SetThreadContext` or `NtQueueApcThread`. |
| **Sysmon Event ID 10** | ProcessAccess | High for cross-process handles | Generates high volume; requires aggressive filtering of normal system noise. |
| **ETW (Kernel-Process)** | Thread creation and handle operations | Medium | High volume; missing granular caller stack details without full tracing. |
| **ETW Threat Intelligence** | `SetThreadContext`, `ReadWriteVM` | High (Kernel-level) | Requires EDR running as an ELAM (Early Launch Anti-Malware) driver. |

### Sysmon Event ID 10 (ProcessAccess) Analysis

When an attacker process performs thread context manipulation or APC injection across process boundaries, it must request specific access rights from the kernel object manager.

Key access rights involved:

- `PROCESS_VM_OPERATION` (`0x0008`): Required to allocate or change protections on remote memory.
- `PROCESS_VM_WRITE` (`0x0020`): Required to write memory via `WriteProcessMemory`.
- `PROCESS_SUSPEND_RESUME` (`0x0800`): Required to suspend or resume the target process.
- `THREAD_SET_CONTEXT` (`0x0010`): Required to call `SetThreadContext`.
- `THREAD_SUSPEND_RESUME` (`0x0002`): Required to suspend target threads.

An access mask combining `0x0020` (VM Write), `0x0008` (VM Operation), and `0x0800` (Suspend/Resume) on an unrelated target process is an indicator of memory manipulation.

---

## Detection Engineering Strategies

To detect these techniques reliably, you need rules that combine kernel tracing data, process creation characteristics, and cross-process access behaviors.

### Strategy 1: Detecting "Early Bird" Suspended Process Spawning (Sysmon + KQL)

Detecting a process spawned in a suspended state where the parent process is an untrusted binary or living-off-the-land binary (LotL).

```kql
// KQL Query: Detecting Suspended Process Creation Followed by Cross-Process Access
let SuspendedProcs = 
    DeviceProcessEvents
    | where ProcessCreationEvents has "CREATE_SUSPENDED" or CreationFlags == 4
    | project SuspendedTime = Timestamp, TargetProcessId = ProcessId, TargetProcess = FileName, ParentProcess = InitiatingProcessFileName, ParentProcessId = InitiatingProcessId;
let ProcessAccessEvents = 
    DeviceEvents
    | where ActionType == "OpenProcessApiCall" or ActionType == "ProcessAccess"
    | extend GrantedAccess = tostring(AdditionalFields.GrantedAccess)
    // Check for VM_WRITE (0x20), VM_OPERATION (0x8), or SUSPEND_RESUME (0x800)
    | where GrantedAccess has_any ("0x20", "0x8", "0x800", "0x143a", "0x1f0fff")
    | project AccessTime = Timestamp, SourceProcessId = InitiatingProcessId, TargetProcessId = ToInt(AdditionalFields.TargetProcessId), GrantedAccess;
SuspendedProcs
| join kind=inner (ProcessAccessEvents) on TargetProcessId
| where AccessTime between (SuspendedTime .. SuspendedTime + 5s)
| where ParentProcessId == SourceProcessId
| project SuspendedTime, ParentProcess, TargetProcess, GrantedAccess, SourceProcessId, TargetProcessId
```

### Strategy 2: Sysmon Configuration for ProcessAccess Telemetry

To capture cross-process access without overwhelming your SIEM with noise, scope Sysmon Event ID 10 to monitor suspicious access masks requested by unprivileged processes against common injection targets (`svchost.exe`, `lsass.exe`, `werfault.exe`, `notepad.exe`, `spoolsv.exe`).

```xml
<Sysmon schemaversion="4.90">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <ProcessAccess onmatch="include">
        <!-- Target processes frequently used for injection -->
        <TargetImage condition="end with">werfault.exe</TargetImage>
        <TargetImage condition="end with">svchost.exe</TargetImage>
        <TargetImage condition="end with">notepad.exe</TargetImage>
        <TargetImage condition="end with">spoolsv.exe</TargetImage>
      </ProcessAccess>
    </RuleGroup>
    <RuleGroup name="" groupRelation="or">
      <ProcessAccess onmatch="exclude">
        <!-- Filter out expected native binaries -->
        <SourceImage condition="is">C:\Windows\system32\svchost.exe</SourceImage>
        <SourceImage condition="is">C:\Windows\system32\csrss.exe</SourceImage>
        <SourceImage condition="is">C:\Windows\system32\services.exe</SourceImage>
      </ProcessAccess>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
```

### Strategy 3: ETW Threat Intelligence Detection (`SetThreadContext`)

The `Microsoft-Windows-Threat-Intelligence` provider offers kernel-level instrumentation specifically designed to catch memory injection primitives.

When `NtSetContextThread` is invoked across process boundaries, ETW TI emits the event `KERNEL_THREATINT_KEY_SET_THREAD_CONTEXT`.

Key event fields to evaluate in your EDR/ETW pipeline:

- `CallingProcessId`: The PID executing `SetThreadContext`.
- `TargetProcessId`: The PID owning the thread being modified.
- `TargetThreadId`: The thread whose registers are altered.
- `NewRip` / `NewEip`: The memory address injected into the thread execution context.

A alert rule trigger condition:

$$\text{CallingProcessId} \neq \text{TargetProcessId} \quad \land \quad \text{MemoryType}(\text{NewRip}) \in \{\text{MEM\_PRIVATE}, \text{PAGE\_EXECUTE\_READWRITE}\}$$

If `NewRip` points to non-image memory (memory not backed by an executable file on disk, such as a mapped `.dll` or `.exe`), this strongly indicates shellcode execution via thread context hijacking.

---

## Investigation Workflow

When investigating alerts related to potential thread hijacking or APC injection, follow this structured response plan:

```
                  ┌─────────────────────────────────────┐
                  │ Alert Triggered: ProcessAccess /    │
                  │ ETW Thread Context Modification     │
                  └──────────────────┬──────────────────┘
                                     │
                                     ▼
                  ┌─────────────────────────────────────┐
                  │ 1. Verify Parent-Child Relationship │
                  │    - Was child spawned SUSPENDED?   │
                  │    - Is parent an expected binary?  │
                  └──────────────────┬──────────────────┘
                                     │
                                     ▼
                  ┌─────────────────────────────────────┐
                  │ 2. Analyze Target Process Memory    │
                  │    - Inspect allocation permissions │
                  │    - Identify RWX or unbacked code  │
                  └──────────────────┬──────────────────┘
                                     │
                                     ▼
                  ┌─────────────────────────────────────┐
                  │ 3. Evaluate Call Stack & Registers  │
                  │    - RIP pointing to unbacked memory│
                  │    - Check for stack spoofing       │
                  └──────────────────┬──────────────────┘
                                     │
                                     ▼
                  ┌─────────────────────────────────────┐
                  │ 4. Remediate & Isolate              │
                  │    - Terminate parent and target    │
                  │    - Collect memory dump            │
                  └─────────────────────────────────────┘
```

### Step 1: Analyze Call Stack and Memory Backing

Using tools like WinDbg, Process Hacker, or EDR volatile memory acquisition modules, analyze the threads of the target process:

1. Check the execution status of threads inside the target process. Look for threads whose starting address points to `PAGE_EXECUTE_READWRITE` (RWX) memory allocations rather than a module export (e.g., `ntdll.dll!RtlUserThreadStart`).
2. Run `address` queries in WinDbg against the instruction pointer (`RIP`) to verify backing store:
   ```cmd
   !address @rip
   ```
   If the state is `MEM_COMMIT`, type is `MEM_PRIVATE`, and protection is `PAGE_EXECUTE_READWRITE`, the thread is running inside dynamic unbacked memory—a clear signature of shellcode execution.

### Step 2: Correlate File Creation and Network Connections

Because APC injection and thread hijacking are used to host secondary stages (e.g., Command and Control beacons), inspect telemetry immediately following the context modification:

- Check for outbound network calls (`Sysmon Event ID 3`) originating from benign processes (`werfault.exe`, `notepad.exe`, `svchost.exe`) that rarely initiate external connections.
- Check for dropped payload files or named pipes created by the target process.

---

## Operational Considerations and Trade-offs

Building detections for thread execution hijacking and APC injection introduces specific operational trade-offs that SOC and Detection Engineering teams must navigate:

### 1. High Noise vs. Security Blind Spots in ProcessAccess Logging

Capturing `ProcessAccess` (Sysmon Event ID 10) for all system processes can severely impact endpoint CPU performance and exhaust SIEM ingestion limits. Legitimate administrative tooling, software management agents, debuggers, and security tools constantly query process handles with elevated rights.

**Mitigation:** Limit high-fidelity alerting to cross-process handles where the *source process* is untrusted (e.g., running from `C:\Users\Public\`, `\AppData\`, or executing out of temporary directories) and the *target process* is a known injection target.

### 2. ETW TI Availability Restrictions

`Microsoft-Windows-Threat-Intelligence` provides superior visibility into cross-process thread context modifications, but Microsoft restricts access to ETW TI. Only binaries running with Anti-Malware Light or Early Launch Anti-Malware (ELAM) protection can register for ETW TI events. Standard custom user-mode applications cannot directly register an ETW consumer session for this provider.

**Mitigation:** Rely on EDR vendors that expose raw ETW TI events through their sensor streams, or augment telemetry using custom kernel drivers (like `minifilter` drivers) that intercept `ObRegisterCallbacks` and `PspCreateProcessNotifyRoutine`.

### 3. Evading Basic Detections via Module Stomping

Advanced threat actors often bypass simple unbacked-memory detections (`MEM_PRIVATE` check) by using **Module Stomping** (or DLL Hollowing). They load a legitimate, unused system DLL into the target process, overwrite its `.text` section with shellcode, and direct the thread `RIP` or APC callback to that location.

In this scenario, the memory protection is restored to `PAGE_EXECUTE_READ` and the memory is backed by a file on disk (`MEM_IMAGE`), bypassing basic `MEM_PRIVATE` detection logic. To catch this, detection logic must verify file integrity on disk against memory contents or detect unexpected `PAGE_READWRITE` to `PAGE_EXECUTE_READ` protection transitions via virtual memory API callbacks.

---

## Practical Defensive Recommendations

1. **Deploy Attack Surface Reduction (ASR) Rules**:
   Enable Microsoft Defender ASR rules to block child processes spawned by Microsoft Office applications or script hosts (`wscript.exe`, `cscript.exe`, `powershell.exe`). This breaks the delivery mechanism before an attacker can spawn a suspended process for Early Bird injection.

2. **Implement Kernel Callbacks via EDR**:
   Ensure your EDR leverages `ObRegisterCallbacks` to strip high-privilege access rights (`PROCESS_VM_WRITE`, `THREAD_SET_CONTEXT`) requested by non-SYSTEM and non-protected processes attempting to manipulate target handles.

3. **Baseline Thread Start Addresses**:
   Implement threat hunting queries that flag system processes whose active threads execute from memory regions outside loaded module boundaries (`MEM_PRIVATE`).

4. **Monitor API Unhooking Behavior**:
   Combine process injection monitoring with detection rules for user-mode hook evasion (e.g., monitoring memory protection changes on `ntdll.dll`'s `.text` section from `PAGE_READONLY` to `PAGE_EXECUTE_READWRITE`).
