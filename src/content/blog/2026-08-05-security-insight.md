---
title: "Defeating EDR Unhooking and Direct Syscalls: Advanced Memory Detection Strategies"
description: "A technical breakdown of user-mode EDR evasion using NTDLL unhooking and indirect syscalls, paired with concrete detection strategies using kernel callbacks, ETW Threat Intelligence, and call stack inspection."
date: "2024-03-15"
tags: ["Cybersecurity", "Threat Detection", "Endpoint Security", "Windows Internals"]
category: "Cyber Security"
---

Endpoint Detection and Response (EDR) agents have long relied on user-mode API hooking to inspect runtime process behavior. By injecting a DLL into user-space processes and patching native API functions inside `ntdll.dll` with unconditional jumps (`jmp`), security products redirect execution flow to their inspection engines before allowing the underlying system call to execute.

However, offensive tooling has evolved to routinely bypass user-mode telemetry. Techniques such as NTDLL unhooking, direct system calls (syscalls), and indirect syscalls render user-mode hooks effectively invisible. 

For threat detectors and SOC engineers, relying solely on user-mode telemetry creates critical blind spots. This analysis breaks down how these bypass mechanisms function at the assembly level and provides practical, kernel-level and memory-based detection strategies to catch them.

---

## The Failure Model of User-Mode Hooking

When a Windows application requires kernel execution (such as allocating virtual memory via `NtAllocateVirtualMemory` or creating a remote thread via `NtCreateThreadEx`), it routes the request through `ntdll.dll`. 

In an environment monitored by an EDR using user-mode hooks, the standard flow is altered:

1. The application calls `VirtualAllocEx`.
2. `kernel32.dll` / `KernelBase.dll` forwards the call to `ntdll.dll!NtAllocateVirtualMemory`.
3. The patched `NtAllocateVirtualMemory` function executes an inline `jmp` instruction pointing to the EDR's injected DLL (e.g., `edr_mon.dll`).
4. The EDR inspects the parameters, call stack, and context.
5. If clean, the EDR executes the original System Service Number (SSN) setup and issues the `syscall` instruction.

Adversaries operating inside an infected process have full read/write/execute permissions over their own process memory space. Because user-mode hooks exist inside the user-mode address space, the process can overwrite, modify, or completely bypass those hooks without requiring elevated privileges.

---

## Evasion Mechanics Breakdown

### 1. NTDLL Unhooking
The simplest bypass involves restoring the hooked `ntdll.dll` code section (`.text`) back to its original state on disk. Adversaries perform this by:

* Mapping a fresh, unhooked copy of `ntdll.dll` directly from disk into memory (`CreateFileA` + `MapViewOfFile`).
* Reading the clean `.text` section from the fresh mapping.
* Overwriting the hooked `.text` section of the currently loaded `ntdll.dll` in memory using `VirtualProtect` to temporarily grant write permissions.

Once replaced, the EDR's `jmp` instructions are wiped, restoring standard Windows Native API behavior and silencing user-mode telemetry.

### 2. Direct Syscalls
Instead of fixing `ntdll.dll`, direct syscall techniques bypass the DLL altogether. Red teams write custom assembly stubs that dynamically resolve or hardcode the target function's SSN and execute the `syscall` instruction directly.

```assembly
; Direct Syscall Stub for NtAllocateVirtualMemory (x64)
mov r10, rcx
mov eax, 0x0018  ; SSN for NtAllocateVirtualMemory (varies by OS build)
syscall
ret
```

Because execution never passes through `ntdll.dll`, user-mode hooks are never triggered.

### 3. Indirect Syscalls
Modern security tools adapted to direct syscalls by scanning running processes for `syscall` assembly instructions residing outside the memory bounds of `ntdll.dll`. To counter this, adversaries transitioned to **indirect syscalls** (popularized by tools like Syswhispers3 and RecycledGate).

Instead of issuing `syscall` directly from the custom assembly stub, the stub sets up the registers and executes a `jmp` instruction to a valid `syscall; ret` gadget already residing inside the legitimate, disk-backed `ntdll.dll` memory space.

```assembly
; Indirect Syscall Stub
mov r10, rcx
mov eax, 0x0018        ; SSN
jmp qword ptr [gadget]  ; Points to a 'syscall; ret' address inside ntdll.dll
```

This trick satisfies simple checks looking for execution of `syscall` from unmapped or non-NTDLL memory, making the call appear legitimate at first glance.

---

## Defensive Engineering: Catching User-Mode Bypasses

To catch advanced threat actors using these techniques, security teams must shift telemetry collection to the kernel and implement post-exploitation memory analytics.

```
       [ User Mode ]                     [ Kernel Mode ]
+-------------------------+       +---------------------------+
| Malicious Process       |       | Kernel Subsystems         |
|  - Custom Syscall Stub  | ----> |  - System Service Table   |
|  - Unhooked NTDLL       |       +---------------------------+
+-------------------------+                     |
                                                v
                                  +---------------------------+
                                  | ETW Threat Intelligence   |
                                  | Kernel Callbacks          |
                                  +---------------------------+
```

### 1. ETW Threat Intelligence (ETW-TI)
Event Tracing for Windows Threat Intelligence (ETW-TI) is a kernel-level provider (`Microsoft-Windows-Threat-Intelligence`) designed specifically to monitor behavior at the kernel boundary. Because it operates inside kernel space, user-mode unhooking has zero impact on its visibility.

Key events to monitor include:
* **`KERNEL_THREATINT_TASK_ALLOCVM`**: Triggers on kernel-level virtual memory allocation.
* **`KERNEL_THREATINT_TASK_PROTECTVM`**: Triggers on memory permission changes (e.g., transitioning memory from `PAGE_READWRITE` to `PAGE_EXECUTE_READWRITE`).
* **`KERNEL_THREATINT_TASK_READWRITEVM`**: Captures `NtReadVirtualMemory` and `NtWriteVirtualMemory` execution across process boundaries (process injection).

**Implementation Action:** Ensure your endpoint agent utilizes kernel-level ETW-TI telemetry rather than solely relying on `SetWindowsHookEx` or API inline patching.

### 2. Kernel Callbacks
Kernel drivers allow security products to register callbacks that run whenever specific operations occur within the operating system, regardless of how the user-mode application requested the action.

* **`ObRegisterCallbacks`**: Triggers on handle creation/duplication. When an adversary attempts to obtain a handle with `PROCESS_ALL_ACCESS` or `PROCESS_VM_WRITE` to perform injection, this callback fires at the kernel level.
* **`PsSetCreateProcessNotifyRoutineEx`**: Tracks process creation.
* **`PsSetCreateThreadNotifyRoutine`**: Tracks thread creation, catching remote thread injection (`NtCreateThreadEx`) even if called via indirect syscalls.

### 3. Call Stack spoofing & Unbacked Memory Detection
Even if an adversary uses indirect syscalls to execute a valid `syscall` instruction within `ntdll.dll`, the **Call Stack** often reveals anomalous context.

When inspecting suspicious execution events (such as thread creation or remote allocation), perform automated call stack unwinding:

* **Unbacked Memory Execution:** Check if the caller or return addresses on the stack point to unbacked memory space (memory allocated dynamically with `VirtualAlloc` that does not map to a real `.dll` or `.exe` file on disk).
* **Return Address Anomalies:** For indirect syscalls, verify if the frame preceding the `ntdll.dll` syscall instruction originates from an unexpected, non-module address space.
* **Stack Spoofing Detection:** Compare `RSP` (Stack Pointer) alignment and ensure stack frame frames correspond to valid `CALL` instructions rather than synthetic frames created to mimic legitimate execution flow.

### 4. Memory Integrity Scanning (PE-Sieve / YARA)
Regular, heuristic-based memory scans running in security automation pipelines can detect unhooking activity and suspicious execution stubs:

* **Detecting NTDLL Patching/Restoration:** Compare in-memory `.text` sections of critical DLLs against the clean copy stored in `C:\Windows\System32\ntdll.dll`. Discrepancies indicate unhooking or inline hooking bypasses.
* **Scanning for Assembly Patterns:** Run YARA rules across process memory targeting byte patterns characteristic of direct syscall stubs:

```yara
rule Direct_Syscall_Stub {
    meta:
        description = "Detects standalone x64 syscall stubs in execution space"
        author = "Security Operations Analyst"
    strings:
        // mov r10, rcx; mov eax, SSN; syscall; ret
        $syscall_x64 = { 49 89 CA B8 ?? ?? 00 00 0F 05 C3 }
    condition:
        $syscall_x64 in (0..filesize)
}
```

---

## Operational Takeaways for SOC and Detection Teams

1. **Audit Agent Capabilities:** Review your endpoint security stack. Determine explicitly which telemetry sources are derived from user-mode hooks versus kernel-level drivers or ETW-TI.
2. **Alert on Suspicious Memory Allocations:** Focus analytics on memory protection transitions (`PAGE_EXECUTE_READWRITE` / `0x40`). Legitimate software rarely requires memory space that is simultaneously writable and executable.
3. **Monitor NTDLL In-Memory Modifications:** Implement baseline alerts for processes modifying their own `ntdll.dll` `.text` section permissions via `NtProtectVirtualMemory`.
4. **Enforce Call Stack Visibility:** Ensure your Threat Detection / EDR platform exposes raw call stacks for high-risk process operations, allowing analysts to triage unbacked memory structures effectively.