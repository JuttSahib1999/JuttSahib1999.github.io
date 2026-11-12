---
title: "Detecting Direct and Indirect Syscalls: Telemetry, Call Stack Anomalies, and ETW-TI"
description: "A deep dive into evading EDR user-mode hooks via direct and indirect syscalls, analyzing kernel telemetry, ETW-TI, and detecting call stack anomalies in security operations."
date: "2026-11-12"
tags: ["Cybersecurity", "Security Operations"]
category: "Cyber Security"
difficulty: "Expert"
author: "Abdul Muqeet Tabraiz"
image: "/images/blog/2026-11-12-detecting-direct-and-indirect-syscalls-telemetry-call-stack-anomalies-and-etw-ti.svg"
---

Endpoint Detection and Response (EDR) agents historically relied heavily on inline user-mode API hooks installed inside `ntdll.dll`. By overwriting the first few bytes of sensitive Native APIs (such as `NtOpenProcess`, `NtAllocateVirtualMemory`, or `NtWriteVirtualMemory`) with a relative `jmp` instruction, security software redirects execution flow into an EDR inspection driver/DLL before allowing the system call to execute.

To bypass these inspection engines, red teams and adversary frameworks shifted toward executing system calls directly from custom binary memory, skipping `ntdll.dll` user-mode hooks entirely. As security vendors adapted by inspecting system call execution parameters in kernel space, offensive tools evolved from direct syscalls to indirect syscalls. 

Understanding how direct and indirect syscalls function at the assembly and kernel boundary is critical for detection engineers. Relying solely on user-mode API hooks or simplistic command-line logging leaves major blind spots during process injection, memory modification, and credential dumping activities.

---

## Anatomy of Syscall Evasion

To understand why traditional telemetry fails against syscall-based execution, we must first look at standard API invocation on x64 Windows.

### Standard Execution Flow

When a legitimate Win32 application executes an operation—such as opening a handle to another process—it follows a well-defined call chain:

```
Application (main) -> kernel32.dll (OpenProcess) -> KernelBase.dll (OpenProcess) -> ntdll.dll (NtOpenProcess) -> Kernel (syscall)
```

Inside `ntdll.dll`, the export stub for `NtOpenProcess` looks like this:

```assembly
mov r10, rcx
mov eax, 0x26        ; System Service Number (SSN) for NtOpenProcess
syscall              ; Transition to kernel mode (Ring 0)
ret
```

When an EDR hooks `ntdll.dll`, it replaces the initial bytes of `NtOpenProcess` with an absolute or relative jump:

```assembly
jmp edr_hooking_engine.dll+0x1020
```

If an application calls `NtOpenProcess`, execution pivots to the EDR's hook DLL, which inspects parameters, caller integrity, and stack frames before either blocking execution or jumping back to complete the system call.

---

### Direct Syscalls

Direct syscall techniques (popularized by tools like SysWhispers and Inline Whispers) bypass user-mode hooks by executing the assembly instructions required to transition to Ring 0 directly from private, executable memory within the attacker's payload.

Instead of calling `ntdll!NtAllocateVirtualMemory`, the attacker dynamically resolves or hardcodes the System Service Number (SSN) for the target OS build, allocates a custom stub within their own binary image, and issues the `syscall` instruction directly:

```assembly
mov r10, rcx
mov eax, [ssn_value] ; Dynamically calculated SSN
syscall              ; Executed directly from process memory, NOT ntdll.dll
ret
```

Because `ntdll.dll` in disk/memory is never executed for this routine, inline user-mode hooks are completely bypassed. The EDR's hook DLL is never notified that `NtAllocateVirtualMemory` was invoked.

---

### Indirect Syscalls

While direct syscalls bypass user-mode hooks, modern kernel-level telemetry and security sensors monitor the location from which a `syscall` instruction is issued. If a kernel callback (or ETW-TI telemetry) records a system call originating from private executable memory (e.g., `0x00007FF712341000`) rather than the legitimate text segment of `ntdll.dll`, it serves as a strong indicator of malicious intent.

Indirect syscalls (implemented in frameworks such as SysWhispers3, RecycledGate, and Halo's Gate) address this issue. Instead of executing the `syscall` instruction inside the attacker's memory allocation, the payload:

1. Prepares the parameters and populates `rax` with the SSN in private memory.
2. Locates a valid `syscall; ret` instruction byte sequence inside `ntdll.dll`.
3. Issues a `jmp` instruction to that valid memory address inside `ntdll.dll`.

```assembly
mov r10, rcx
mov eax, [ssn_value]
jmp ntdll_syscall_gadget_address ; Jumps to 'syscall; ret' inside ntdll.dll
```

From the perspective of basic kernel execution checks, the Instruction Pointer (`RIP`) at the moment the `syscall` instruction is executed points inside `ntdll.dll`'s legitimate address space.

---

## Telemetry Sources for Detection

Detecting direct and indirect syscalls requires looking past user-mode API logging and analyzing low-level kernel telemetry, memory region properties, and stack frame structures.

```
       [ Malicious Payload ]
                 |
    (Executes Indirect Syscall)
                 |
                 v
   [ ntdll.dll (syscall gadget) ]
                 |
  ============================== Kernel Boundary (Ring 0)
                 |
                 v
    [ Kernel System Service ]
                 |
       +---------+---------+
       |                   |
       v                   v
   [ ETW-TI ]      [ ObRegisterCallbacks ]
       |                   |
       v                   v
 [ Call Stack ]     [ Source Image & ]
 [ Analysis   ]     [ Memory State   ]
```

### 1. Event Tracing for Windows - Threat Intelligence (ETW-TI)

ETW-TI is a specialized provider (`Microsoft-Windows-Threat-Intelligence`, GUID: `{5581F141-099E-4177-9E18-D6B3BCD9EE2A}`) exposed by the Windows kernel to security vendors running under protected processes (PPL).

Unlike user-mode ETW, which can be easily patched in memory via `EtwEventWrite` hooking or `ntdll` patching, ETW-TI events are generated directly inside kernel-mode functions (such as `PspProcessOpen`, `NtAllocateVirtualMemory`, and `NtWriteVirtualMemory`).

Key ETW-TI events for monitoring memory and process operations include:

| Event Name | Event ID | Operational Context |
| :--- | :--- | :--- |
| `KERNEL_THREATINT_TASK_ALLOCVM` | 1 | Virtual memory allocation in target processes (`NtAllocateVirtualMemory`) |
| `KERNEL_THREATINT_TASK_PROTECTVM` | 2 | Changing memory permissions (`NtProtectVirtualMemory`) |
| `KERNEL_THREATINT_TASK_WRITEVM` | 3 | Cross-process memory writing (`NtWriteVirtualMemory`) |
| `KERNEL_THREATINT_TASK_READVM` | 4 | Cross-process memory reading (`NtReadVirtualMemory`) |
| `KERNEL_THREATINT_TASK_SETTHREADCONTEXT` | 7 | Modifying thread context for execution hijacking |

Crucially, ETW-TI events log the kernel call stack at the moment the event is emitted, capturing the exact addresses and module frames involved in the request.

---

### 2. Sysmon CallTrace Telemetry (Event ID 10 & Event ID 8)

For threat hunters and detection engineers who do not ingest raw ETW-TI streams directly into their SIEM, Sysmon provides usable stack trace telemetry via Event ID 10 (ProcessAccess) and Event ID 8 (CreateRemoteThread).

When a process attempts to open a handle to another process (e.g., `lsass.exe` or `svchost.exe`), Sysmon captures the `CallTrace` field by walking the user-mode call stack.

#### Normal CallTrace Example:
```text
TargetImage: C:\Windows\system32\lsass.exe
GrantedAccess: 0x1010
CallTrace:
 C:\Windows\SYSTEM32\ntdll.dll+0x9d4a4
|C:\Windows\System32\KERNELBASE.dll+0x2b810
|C:\Windows\System32\KERNEL32.DLL+0x17034
|C:\Program Files\ExampleApp\service.exe+0x43a1
```

Notice the clean execution sequence: the caller moves from the application executable through `KERNEL32.DLL` and `KERNELBASE.dll` down into `ntdll.dll`.

#### Direct Syscall CallTrace Example:
```text
TargetImage: C:\Windows\system32\lsass.exe
GrantedAccess: 0x1410
CallTrace:
 UNKNOWN(00007FF712341050)
```

Or:

```text
CallTrace:
 C:\Windows\SYSTEM32\ntdll.dll+0x9d4a4|UNKNOWN(00007FF712341020)
```

In the direct syscall model, `KERNELBASE.dll` and `KERNEL32.DLL` are entirely absent from the stack trace, and the call originates directly from an unbacked/unknown memory segment or raw binary location.

---

## Detection Strategies & Opportunities

### Detection Opportunity 1: Call Stack Anomalies (Direct Syscalls)

Direct syscalls leave severe structural artifacts in the user-mode call stack:

1. **Absence of Standard Subsystem DLLs:** Legitimate calls to native APIs originate from `kernel32.dll`, `KernelBase.dll`, `win32u.dll`, or `rpcrt4.dll`. A call stack for an inter-process memory operation that jumps directly from the main process binary to a `syscall` instruction omits these DLLs.
2. **Unbacked Return Addresses:** The return address immediately following the system call points to memory that does not map to a registered PE image on disk (`MEM_PRIVATE` memory assigned with `PAGE_EXECUTE_READWRITE` or `PAGE_EXECUTE_READ`).

#### Example Detection Rule (Sysmon Event ID 10)

```yaml
title: Direct Syscall Execution via ProcessAccess CallTrace
id: b682129c-6481-4f81-8e99-31e847c13031
status: experimental
description: Detects process access requests where the CallTrace lacks standard subsystem DLLs or originates from unbacked memory regions.
logsource:
  category: process_access
  product: windows
detection:
  selection:
    TargetImage|endswith:
      - '\lsass.exe'
      - '\winlogon.exe'
      - '\csrss.exe'
  anomalous_stack:
    CallTrace|contains:
      - 'UNKNOWN'
  filter_legit:
    CallTrace|contains:
      - 'C:\Windows\System32\KERNELBASE.dll'
      - 'C:\Windows\System32\KERNEL32.DLL'
  condition: selection and anomalous_stack and not filter_legit
falsepositives:
  - Just-In-Time (JIT) compiled code (e.g., browser engines, .NET CLR execution).
  - Anti-cheat solutions using custom hypervisors or security hooks.
level: high
```

---

### Detection Opportunity 2: Return Address Inspection (Indirect Syscalls)

Indirect syscalls solve the issue of issuing a `syscall` instruction from an unbacked memory block by jumping to a gadget inside `ntdll.dll`. However, they introduce a distinct stack artifact: **Return Address Mismatch**.

When a standard application calls `NtWriteVirtualMemory`:
1. `KernelBase!WriteProcessMemory` executes a `CALL` instruction to `ntdll!NtWriteVirtualMemory`.
2. The `CALL` instruction pushes the return address (pointing back inside `KernelBase.dll`) onto the stack.
3. `ntdll!NtWriteVirtualMemory` executes the `syscall` instruction.

When an indirect syscall executes:
1. The attacker's payload sets up registers in private memory.
2. The payload issues a `JMP` (or `CALL`) instruction directly to the `syscall; ret` gadget inside `ntdll.dll`.
3. Because the `JMP` instruction does not push a standard API frame, or because the `CALL` pushes a return address pointing back to the *attacker's private binary memory*, the stack frame directly below the `ntdll` gadget points back to an unbacked or non-standard memory location instead of `KernelBase.dll`.

#### Stack Walk Analysis Comparison

##### Legitimate Execution Frame:
```text
Frame 0: ntdll.dll!NtOpenProcess + 0x14         (RIP points inside ntdll)
Frame 1: KERNELBASE.dll!OpenProcess + 0x1a0      (Return address in KernelBase)
Frame 2: payload.exe!main + 0x45                (Return address in application)
```

##### Indirect Syscall Frame (Spoofed/Unbacked Caller):
```text
Frame 0: ntdll.dll!NtOpenProcess + 0x12         (Gadget location in ntdll)
Frame 1: payload.exe!0x1042                     (Return address points directly to custom binary, missing KernelBase)
```

If an EDR stack walker or threat hunter inspects the frame immediately preceding `ntdll.dll`:
- If the instruction preceding the return address is **not** a `CALL` to a valid `ntdll` export stub, or
- If the return address points back to executable memory that is not backed by an image file on disk,
the operation is an indirect syscall.

---

### Detection Opportunity 3: Synthetic Stack Frame Telemetry via ETW-TI

Advanced indirect syscall frameworks attempt to spoof the stack frame entirely by constructing a fake stack (stack duplication or frame unwinding trickery) before invoking the syscall gadget. 

To detect sophisticated frame spoofing, kernel telemetry monitors both the user-mode stack pointer (`RSP`) and the instruction pointer (`RIP`) during system call transitions. 

When an ETW-TI event is logged, the kernel captures:
- `CallingProcess`
- `TargetProcess`
- `BaseAddress`
- `RegionSize`
- Kernel Stack Trace & User Stack Trace

If an adversary populates a synthetic stack frame, they must maintain consistency during thread unwinding. Discrepancies between the dynamic stack unwinding sequence (using `.pdata` exception handler metadata) and the raw thread stack frames signal memory manipulation.

```
       [ Real Execution Pointer ] ---> Executes Syscall Gadget inside ntdll.dll
                  |
       [ User Stack (RSP) Pointer ]
                  |
    +-------------+-------------+
    |                           |
    v                           v
(Legitimate Frame)      (Synthetic Frame)
KernelBase.dll          Created manually in RAM
Proper unwind info      Invalid or inconsistent 
matches .pdata          unwind metadata (.pdata)
```

Detecting these anomalies in ETW-TI involves flagging instances where `KERNEL_THREATINT_TASK_ALLOCVM` or `WRITEVM` operations are triggered with:
1. User-mode stack frames that fail standard unwinding routines (`RtlVirtualUnwind`).
2. Mismatched call frames where the calling instruction is a `JMP` to `ntdll` rather than a standard `CALL`.

---

## Practical Engineering Limitations & Edge Cases

When deploying rules or logic to detect direct/indirect syscalls across enterprise fleets, detection engineers encounter several engineering edge cases.

### 1. JIT Engines and Managed Runtimes
Browsers (Chrome, Edge, Firefox) using V8/Spidermonkey engines, Node.js applications, Java Virtual Machines (JVM), and .NET CLR runtimes dynamically allocate and execute code from private executable memory (`MEM_COMMIT` without image backing). 

These engines routinely generate stack traces containing `UNKNOWN` frames. High-volume rules matching purely on `UNKNOWN` in Sysmon `CallTrace` without restricting the scope to sensitive target processes (like `lsass.exe`, `csrss.exe`, or cross-process operations) will flood SIEMs with false positives.

### 2. Performance Impact of Continuous Stack Walking
In-depth inspection of stack frames for *every* API call introduces measurable latency. Windows kernel callbacks (`ObRegisterCallbacks`) executing deep stack unwinding on high-frequency events (e.g., `NtReadVirtualMemory` issued by security tools or system services) can cause significant CPU overhead. 

For this reason, detection logic should prioritize high-risk combinations:
- Target processes: `lsass.exe`, `services.exe`, `smss.exe`, `winlogon.exe`.
- Operations: Cross-process thread creation (`NtCreateThreadEx`), cross-process memory modification (`NtWriteVirtualMemory`), and permission modifications (`NtProtectVirtualMemory` changing pages to `PAGE_EXECUTE_READWRITE`).

### 3. ETW-TI Availability
ETW-TI is restricted by Microsoft to processes running with Process Protection Light (PPL) Antimalware extension signatures. Standard user-mode applications and non-PPL security agents cannot consume raw ETW-TI telemetry directly. Defense teams must ensure their EDR agent natively leverages ETW-TI and exposes stack frame metadata into SIEM telemetry.

---

## Defensive Recommendations

To build resilient defenses against syscall evasion techniques:

1. **Transition from API Hooking to Kernel Telemetry:** Do not rely exclusively on user-mode hooks inside `ntdll.dll`. Enforce EDR solutions that utilize kernel callbacks (`ObRegisterCallbacks`, `PsSetCreateProcessNotifyRoutineEx`) and ETW-TI.
2. **Implement Stack Integrity Validation:** Configure detection rules to validate stack traces on high-risk events (Process Access to credential stores, Remote Thread Creation). Specifically flag call traces missing subsystem DLLs (`kernel32.dll`, `KernelBase.dll`).
3. **Monitor Memory Protection Changes:** Indirect syscalls are frequently preceded by allocating private memory (`NtAllocateVirtualMemory`) and setting execution permissions (`NtProtectVirtualMemory` to `0x40` / `PAGE_EXECUTE_READWRITE`). Track transitions where memory regions switch from RW to RX/RWX without a corresponding disk-backed DLL image (`ImageLoad`).
4. **Deploy Process Protection Light (PPL):** Enable LSA Protection (`RunAsPPL`) to restrict process handle requests to `lsass.exe`, rendering standard process access requests via indirect syscalls ineffective even if hooks are bypassed.

---

## Summary

Direct and indirect syscalls altered the threat landscape by rendering traditional inline user-mode API hooks insufficient. However, bypassing user-mode hooks does not make an operation invisible. 

By shifting detection focus toward kernel-level telemetry (ETW-TI), call stack unwinding anomalies, and unbacked memory execution, security operations teams can reliably spot syscall evasion techniques regardless of how the system service call was constructed.
