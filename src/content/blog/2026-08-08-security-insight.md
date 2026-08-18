---
title: "Deconstructing Indirect Syscalls: Bypassing User-Land EDR Hooks and Building Stack-Aware Detections"
description: "A technical analysis of how modern adversaries leverage indirect system calls to bypass user-mode EDR hooks, and how detection engineers can leverage kernel telemetry and stack walk analysis to spot them."
date: "2026-08-08"
tags: ["Cybersecurity", "Threat Detection", "Security Operations", "EDR Bypass", "Windows Internals"]
category: "Cyber Security"
---

Endpoint Detection and Response (EDR) agents rely heavily on user-land API hooking to inspect software behavior before execution transitions into the kernel. By patching exported functions inside native libraries like `ntdll.dll`, EDRs insert inline jumps (`JMP` instructions) that redirect execution flow into an inspection engine DLL injected into the target process.

Over the past few years, red teams and threat actors have continuously refined techniques to circumvent these hooks. The transition moved from unhooking techniques (such as refreshing `ntdll.dll` from disk) to **Direct Syscalls**, and more recently, **Indirect Syscalls**.

Understanding the low-level execution mechanics of indirect syscalls is critical for defensive engineers responsible for authoring detection rules and evaluating endpoint protection capabilities.

---

## The Evolution of Syscall Evasion

To understand why indirect syscalls exist, we must look at how previous evasion techniques failed under modern detection heuristics.

### 1. Traditional Win32 API Execution
In standard execution, an application invokes a high-level API function (e.g., `VirtualAllocEx` in `kernel32.dll`). This function acts as a wrapper, calling an equivalent native API function inside `ntdll.dll` (e.g., `NtAllocateVirtualMemory`). 

```
[ Application ] -> [ Kernel32.dll: VirtualAllocEx ] -> [ NTDLL.dll: NtAllocateVirtualMemory ] -> [ Kernel Transition ]
```

EDRs inject hooks into `ntdll.dll` functions by overwriting the first few bytes with an assembly jump instruction (`JMP <EDR_Memory_Address>`). When executed, control transfers to the EDR for inspection before returning to the original routine.

### 2. Direct Syscalls
To bypass these user-mode hooks entirely, offensive tools (such as SysWhispers) began embedding inline assembly directly within the compiled binary. By hardcoding or dynamically resolving the System Service Number (SSN) associated with a target function, the payload prepares the arguments in memory and executes the `syscall` instruction directly, jumping straight into kernel mode without ever calling `ntdll.dll`.

```assembly
; Direct Syscall Pattern
mov r10, rcx
mov eax, 0x0018  ; SSN for NtAllocateVirtualMemory (varies by OS build)
syscall          ; Executes directly within the unbacked executable memory
ret
```

#### The Detection Signal
Direct syscalls introduce an obvious anomaly: a `syscall` instruction executing from memory outside the mapped image space of `ntdll.dll`. EDR vendors quickly adapted by leveraging **Kernel Callbacks** and **Event Tracing for Windows - Threat Intelligence (ETW-Ti)**. When a kernel function is executed, the EDR checks the Instruction Pointer (`RIP`) where the kernel transition originated. If `RIP` points to executable memory outside the `.text` section of `ntdll.dll` (or an unbacked memory region), an alert is triggered.

---

## How Indirect Syscalls Work

Indirect Syscalls solve the origin issue that exposed Direct Syscalls. Instead of executing the `syscall` instruction inside the custom application payload, the payload searches `ntdll.dll` memory for an existing, legitimate `syscall` byte sequence (`0x0F 0x05`) and jumps to that address.

### The Execution Flow

1. **SSN Extraction:** The payload reads `ntdll.dll` from memory or disk to dynamically determine the correct SSN for the target native API (e.g., `NtOpenProcess`).
2. **Gadget Location:** The payload searches `ntdll.dll` for a valid `syscall; ret` instruction sequence within the native function's address space.
3. **Register Preparation:** The application sets up the call parameters in registers/stack according to the x64 Calling Convention (`RCX`, `RDX`, `R8`, `R9`, and shadow stack space).
4. **Indirect Jump:** The payload moves the SSN into `EAX` and uses a `JMP` instruction to jump to the `syscall` instruction sitting *inside* `ntdll.dll`.

```assembly
; Indirect Syscall Pattern
mov r10, rcx
mov eax, [SSN_NtAllocateVirtualMemory]   ; Set SSN in EAX
jmp [Address_Of_Syscall_Gadget_In_NTDLL] ; Jump to legitimate ntdll memory
```

Because the `syscall` instruction actually executes within the memory boundaries of `ntdll.dll`, kernel-level checks evaluating the instruction pointer (`RIP`) see that the caller originated from a valid, signed library.

---

## Defensive Engineering: Detecting Indirect Syscalls

Because indirect syscalls satisfy basic return-address checks, defenders must analyze secondary artifacts created during thread execution.

### 1. Thread Call Stack Telemetry
While the `RIP` at the precise moment of the `syscall` points to `ntdll.dll`, the return address placed on the stack reveals the true caller. When an indirect syscall executes, the return address pushed onto the stack will point back to the calling function in executable memory—which may be an unbacked allocation, a suspicious DLL, or a custom binary.

Modern EDR engines and kernel-mode drivers utilize `PspCreateThreadNotifyRoutine` and kernel tracing to capture call stack states during sensitive operations (e.g., process injection, memory protection modifications).

#### Anomaly Indicators in the Call Stack:
* **Frame Pointer Discrepancies:** The call stack shows a transition into `ntdll.dll` without a corresponding `CALL` instruction preceding the `syscall` gadget.
* **Unbacked Memory Frames:** The return address in the call stack resolves to executable memory pages that are not associated with a disk-backed module (`MEM_COMMIT` without image mapping).
* **Missing Return Paths:** Standard execution pathways are bypassed. For instance, seeing `NtOpenProcess` called directly from a main execution loop without passing through higher-level APIs (`OpenProcess` in `kernel32.dll`) across non-system processes.

### 2. Leveraging ETW-Ti (Threat Intelligence)
Event Tracing for Windows Threat Intelligence (ETW-Ti) runs in kernel space and provides elevated visibility that user-land code cannot tamper with.

For example, when monitoring thread creation or remote memory allocation, ETW-Ti emits events such as `KERNEL_THREATINT_KEY_RET_ADDRESS_VALIDATION`. Defensive teams using custom drivers or specialized telemetry agents can inspect these events for stack integrity verification.

Key telemetry fields to correlate:
* `CallingProcess`: Process initiating the action.
* `TargetProcess`: Process receiving the operational change.
* `CallStack`: Complete array of frame return addresses.

### 3. Hardware-Enforced Countermeasures (Intel CET)
Intel Control-flow Enforcement Technology (CET) introduces **Shadow Stacks** at the hardware level.

* A hardware-managed stack tracks `CALL` and `RET` instruction pairs.
* If an indirect jump (`JMP`) is used to enter a `syscall` gadget instead of a standard `CALL` sequence, or if the return stack is manipulated (Call Stack Spoofing), the CPU generates a Control Protection Exception (`#CP`).
* Enforcing Intel CET via Windows Hardware-enforced Stack Protection renders basic indirect syscall implementations inoperative without complex stack spoofing frameworks (e.g., SilentMoonwalk).

---

## Practical Mitigation & Detection Rules

To harden systems against indirect syscall techniques, security operations and engineering teams should implement a layered defensive approach.

### Detection Strategies
1. **Enable Call Stack Collection for Sensitive APIs:**
   Configure EDR stack tracing rules for critical system calls:
   * `NtAllocateVirtualMemory`
   * `NtProtectVirtualMemory`
   * `NtWriteVirtualMemory`
   * `NtCreateThreadEx`
   * `NtOpenProcess`

2. **Flag Unbacked Executable Memory Calls:**
   Construct SIEM/Detection rules targeting events where the call stack contains frames pointing to memory regions where `Type = Private` and `AllocationProtect = PAGE_EXECUTE_READWRITE`.

3. **Monitor Return Address Anomalies:**
   Alert when a system call enters `ntdll.dll` via an indirect branch (`JMP`) rather than a standard function entry point.

### System Hardening Checklist
* **Enable Hardware-Enforced Stack Protection:** On supported CPU architectures, enable CET via Windows Exploit Protection settings.
* **Deploy Vulnerable Driver Blocklists:** Ensure Windows Kernel DMA Protection and Hypervisor-Enforced Code Integrity (HVCI) are active to prevent low-level kernel tampering.
* **Attack Surface Reduction (ASR):** Enable ASR rules to block child process creation and unbacked API calls originating from common initial access vectors (Office, PowerShell, Script Hosts).

---

## Conclusion

Indirect syscalls demonstrate how security boundary enforcement relying solely on user-mode hooks is inherently limited. As offensive techniques move deeper into memory manipulation and assembly-level evasion, defensive strategies must rely on robust kernel telemetry, call stack auditing, and hardware-enforced protection mechanisms.