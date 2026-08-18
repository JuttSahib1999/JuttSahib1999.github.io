---
title: "Bypassing EDR Hooks via Indirect Syscalls: Mechanics and Detection Strategies"
description: "An operational deep dive into modern endpoint detection bypasses using indirect system calls, detailing execution mechanics, stack telemetry anomalies, and practical engineering controls for threat hunters."
date: "2026-08-14"
tags: ["EDR", "Windows Internals", "Threat Detection", "Detection Engineering"]
category: "Cyber Security"
---

Endpoint Detection and Response (EDR) platforms heavily rely on userland API hooking to monitor process behavior. By injecting a dynamic link library (DLL) into newly spawned processes, an EDR patches specific Native API functions inside `ntdll.dll` with an inline `jmp` instruction. This redirects execution flow to the security vendor’s engine, allowing real-time inspection of parameters passed to critical system functions like `NtOpenProcess` or `NtAllocateVirtualMemory`.

However, adversary techniques have evolved. Direct system calls (syscalls) were initially implemented to execute `syscall` instructions directly from allocated memory, completely bypassing userland hooks. As detection engines adapted to identify syscall execution originating outside of `ntdll.dll`, attackers refined their methodology toward **indirect syscalls**.

This article breaks down the technical mechanics of indirect syscalls, analyzes why traditional telemetry fails to catch them, and provides actionable strategies for detection using Event Tracing for Windows Threat Intelligence (ETW-TI) and call stack inspection.

---

## The Mechanics of Userland Evasion

To understand indirect syscalls, we must first review how API calls are intercepted and how direct syscalls operate.

### 1. Standard API Execution vs. Hooked Execution
In a standard execution path, an application calls an API in `kernel32.dll` or `kernelbase.dll`, which wrappers an unexported native API inside `ntdll.dll`. The native API sets up the System Service Number (SSN) in the `EAX` register and issues a `syscall` instruction to transition execution into kernel mode (`ntoskrnl.exe`).

When an EDR hooks a function inside `ntdll.dll`, it overwrites the prelude of the function:

```assembly
; Unhooked ntdll.dll stub (NtOpenProcess)
mov r10, rcx
mov eax, 0x26        ; SSN for NtOpenProcess
syscall              ; Transition to Kernel Mode
ret

; Hooked ntdll.dll stub
jmp <EDR_Monitoring_DLL_Address>   ; 5-byte relative jump
nop
nop
```

### 2. The Direct Syscall Problem
To bypass this `jmp` instruction, offensive utilities (such as SysWhispers2) dynamically parse `ntdll.dll` on disk or read an unhooked copy from memory to extract the target function's SSN. The malware then executes the syscall directly from its own code section (`.text` or dynamically allocated memory):

```assembly
; Direct Syscall executed within malware payload memory
mov r10, rcx
mov eax, 0x26        ; SSN extracted dynamically
syscall              ; Executed directly from payload memory space
ret
```

While this successfully avoids the EDR's inline hook, it introduces a severe anomaly: **the `syscall` instruction originates from memory space outside the valid address range of `ntdll.dll`**. Modern EDRs and Event Tracing for Windows (ETW) easily flag this pattern.

---

## The Indirect Syscall Solution

Indirect syscalls solve the memory location anomaly. Instead of executing the `syscall` instruction within the payload's memory space, the payload configures the SSN and register state, then jumps to a legitimate `syscall; ret` instruction located inside the official `ntdll.dll` module.

### Assembly Execution Flow
The attacker's assembly payload prepares the stack and registers, then issues a `jmp` to an address inside `ntdll.dll` that already contains the `syscall` opcode.

```assembly
; Indirect Syscall Execution Stub
mov r10, rcx
mov eax, [ssn_number]           ; Set the target SSN
jmp qword ptr [ntdll_syscall_addr] ; Jump to 'syscall; ret' inside ntdll.dll
```

When execution transitions to the kernel:
1. The kernel receives a valid `syscall` instruction.
2. The instruction pointer (`RIP`) during the syscall points to valid code space within `ntdll.dll`.
3. The userland hook injected at the beginning of the `ntdll` function is completely jumped over, preventing the EDR from inspecting function arguments.

---

## Technical Comparison: Execution Artifacts

| Execution Method | Hook Triggered? | Execution Location (`RIP`) | Call Stack Validity |
| :--- | :--- | :--- | :--- |
| **Standard API** | Yes | `ntdll.dll` -> `EDR.dll` | Legitimate |
| **Direct Syscall** | No | Unbacked / Payload Memory | Broken / Anomaly Present |
| **Indirect Syscall** | No | `ntdll.dll` | Legitimate RIP, Anomalous Stack Frames |

---

## Defensive Telemetry & Detection Strategies

Because userland hooks are bypassed by design during an indirect syscall, defenders must rely on kernel-level telemetry and deep thread context analysis.

### 1. Stack Telemetry and Unwinding Anomalies
Although the `RIP` register points inside `ntdll.dll` at the exact moment of the `syscall` instruction, the **call stack frame** immediately preceding the `ntdll` instruction will point back to the memory location that initiated the `jmp`.

When a thread transitions to kernel space via a syscall, the kernel records the calling context. By examining the return addresses on the call stack (stack unwinding), detection tools can spot anomalies:

* **Unbacked Memory Frames:** The return address points to dynamic executable memory (`PAGE_EXECUTE_READWRITE`) that is not backed by an image file on disk (e.g., an injected reflectively loaded DLL or beacon).
* **Missing Frame Transitions:** A call stack showing a direct transition from a private/unbacked memory region straight to a `syscall` offset in `ntdll.dll` bypassing the legitimate exported API entry points (like `NtOpenProcess` prelude).

#### Detecting Unbacked Return Addresses via ETW-TI
Using Event Tracing for Windows Threat Intelligence (`Microsoft-Windows-Threat-Intelligence`), kernel providers emit logs for operations like `KERNEL_THREATINT_TASK_ALLOCVM` and `KERNEL_THREATINT_TASK_SETTHREADCONTEXT`. 

Security analytics pipelines should correlate high-risk kernel operations with the call stack captured in the event:

```text
Event: KERNEL_THREATINT_TASK_PROCESS_READ
CallStack Frames:
  Frame 0: ntdll.dll!NtReadVirtualMemory+0x14  <-- Valid execution location
  Frame 1: [UNKNOWN_MEMORY_REGION]             <-- ANOMALY: No module backing this frame
  Frame 2: kernel32.dll!BaseThreadInitThunk+0x14
```

If Frame 1 lacks a valid module name (Image Base) or points to a non-file-backed allocation type (`MEM_PRIVATE`), the event should be flagged as suspicious immediately.

### 2. Hardware-Assisted Telemetry: Intel PT and LBR
For high-security environments, hardware features can be leveraged to catch indirect jumps:

* **Last Branch Record (LBR):** LBR stores CPU execution history in dedicated MSRs (Model Specific Registers). When a syscall occurs, the security driver inspects the LBR stack. An abrupt branch from non-module memory directly into the middle of an `ntdll.dll` function (skipping the function prolog) confirms an evasion attempt.

---

## Practical Engineering Controls

To defend against indirect syscalls, security operations must shift focus away from simple command-line signatures and API-level logs toward system state and stack integrity.

### Implementation Checklist
1. **Enforce Strict Memory Protections (ACG & Dynamic Code Enforcement):**
   * Enable **Arbitrary Code Guard (ACG)** and **Block Non-MS Signed Binaries** via Process Mitigation Policies where applicable to prevent the execution of unbacked executable memory regions.
2. **Deploy EDRs Utilising ETW-TI and Kernel Callbacks:**
   * Verify that your endpoint agent utilizes kernel object callbacks (`ObRegisterCallbacks`) to monitor process access attempts, rather than relying exclusively on userland DLL injection hooks.
3. **Configure Detection Engineering Rules for Stack Traces:**
   * Create alert logic querying stack traces for critical events (e.g., process injection, cross-process memory operations). Look for functions executing out of `RWX` or `RX` regions where `AllocationType` is `MEM_PRIVATE`.

---

## Conclusion

Indirect syscalls effectively neutralize user-mode hooks by abusing the inherent architecture of Windows API abstraction. However, they leave unmistakable traces within thread call stacks and kernel execution context. Modern defense depends on migrating detection capabilities down to the kernel level, leveraging ETW-TI, and validating stack trace integrity for anomalous thread execution flows.