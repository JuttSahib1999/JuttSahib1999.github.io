---
title: "Detecting Direct and Indirect Syscalls: Call Stack Auditing, Kernel Telemetry, and ETW-TI"
    description: "An in-depth analysis of how adversaries bypass user-mode EDR hooks using direct and indirect syscalls, and how detection engineers leverage kernel call stacks and ETW Threat Intelligence to spot them."
    date: "2026-09-06"
    tags: ["Cybersecurity", "Security Operations", "Detection Engineering"]
    category: "Cyber Security"
    difficulty: "Advanced"
    author: "Abdul Muqeet Tabraiz"
    image: ""
date: "2026-09-06"
difficulty: "Advanced"
author: "Abdul Muqeet Tabraiz"
image: "/images/blog/2026-09-06-detecting-direct-and-indirect-syscalls-call-stack-auditing-kernel-telemetry-and-.svg"
---

Endpoint Detection and Response (EDR) agents historically built much of their real-time execution visibility around user-mode API hooking. By injecting a dynamic link library (DLL) into spawned processes and overwriting the preamble of native Windows APIs inside `ntdll.dll` with unconditional jumps (`JMP`), security tools could inspect parameters before execution reached kernel land.

Adversaries adapted by executing system calls directly, bypassing user-mode hooks entirely. As defenders began identifying the raw byte patterns and execution anomalies of direct system calls, offensive tooling evolved toward indirect system calls and call stack manipulation. 

Understanding how these execution techniques work—and where their telemetry footprints appear—is critical for detection engineers building detection logic beyond standard user-mode API monitoring.

---

## The Mechanics: User-Mode Hooking vs. Syscall Bypasses

To understand why user-mode telemetry fails, we need to trace how execution flows from user space to kernel space in Windows x64.

When an application calls a high-level Win32 API like `VirtualAllocEx`, the call transitions down through `Kernel32.dll` and `KernelBase.dll` into `ntdll.dll`, reaching the native export `NtAllocateVirtualMemory`.

Under normal conditions, `ntdll.dll` prepares the System Service Number (SSN) into the `EAX` register, sets up arguments, and issues the `syscall` instruction:

```assembly
mov r10, rcx
mov eax, 0x18       ; SSN for NtAllocateVirtualMemory (varies by OS build)
syscall
ret
```

When an EDR hooks `NtAllocateVirtualMemory`, it modifies the first few bytes of that stub in memory:

```assembly
jmp <EDR_Sensor_Engine.dll + Offset>
nop
nop
```

If execution flows through this modified stub, the control flow diverts into the EDR’s sensor, which inspects the arguments, caller context, and buffer locations before returning execution to `ntdll.dll` or terminating the process.

```
[ Application Code ] 
       │
       ▼
[ ntdll!NtAllocateVirtualMemory ] ──(EDR Hook Hooked JMP)──► [ EDR Engine DLL ]
                                                                     │ (If Benign)
                                                                     ▼
                                                             [ Kernel Transition ]
```

### Direct Syscalls

Direct syscall techniques—popularized by tools like SysWhispers, Hell's Gate, and Halo's Gate—bypass this inline hook. The malware manually reads or dynamically parses the required SSN from `ntdll.dll` on disk (or unhooked memory copies), embeds a custom assembly stub directly into its executable memory region, and executes the `syscall` instruction directly.

```
[ Malware Executable Memory ]
  ├── 1. Parse SSN dynamically
  ├── 2. Populate EAX with SSN
  └── 3. Execute 'syscall' instruction ────► [ Windows Kernel ] (Bypasses ntdll hooks completely)
```

Because control never passes through the hooked functions inside `ntdll.dll`, user-mode inline hook telemetry records zero activity.

### Indirect Syscalls

Direct syscalls leave a distinct architectural trace: the `syscall` instruction executes from a memory address outside the valid memory boundaries of `ntdll.dll` or `win32u.dll`. Security tools capable of inspecting execution origin or stack traces quickly flagged these execution sources.

Indirect syscalls solve this problem for the adversary. Instead of calling `syscall` within the adversary's custom memory space, the payload configures registers (`EAX` for the SSN, `R10` for parameters) inside its own assembly routine, but jumps (`JMP`) to a legitimate `syscall; ret` instruction already residing inside `ntdll.dll`.

```assembly
; Adversary Stub in Unbacked Memory
mov r10, rcx
mov eax, 0x18                  ; SSN
jmp qword ptr [gadget_address]  ; Address pointing to 'syscall; ret' inside ntdll.dll
```

Because the instruction pointer (`RIP`) resides inside `ntdll.dll` at the precise moment of kernel transition, naive checks verifying whether the `syscall` instruction originates from valid module memory are bypassed.

---

## Telemetry Blind Spots and Kernel Visibility

When direct or indirect syscalls are used, several security controls lose context:

1. **User-mode EDR DLLs:** Totally blind. No event logs, no argument inspections.
2. **Win32 API Auditing:** High-level API calls are omitted entirely since the code calls native routines directly.
3. **Standard Kernel ObRegisterCallbacks:** Kernel object callbacks notify drivers when process handles are created (`ObRegisterCallbacks`) or processes/threads spawn (`PspCreateProcessNotifyRoutine`). While useful, they miss the low-level memory manipulations (allocations and protection changes) that precede remote thread execution or process hollowing.

To spot indirect and direct syscalls, detection strategy must shift away from user-mode hook monitoring toward kernel instrumentation and thread stack validation.

---

## ETW Threat Intelligence (ETW-TI)

The primary kernel-level source for detecting low-level memory abuse on modern Windows systems is Event Tracing for Windows Threat Intelligence (ETW-TI). Built into the Windows kernel, ETW-TI emits telemetry from kernel functions like `NtAllocateVirtualMemory`, `NtProtectVirtualMemory`, `NtReadVirtualMemory`, and `NtWriteVirtualMemory`, regardless of how user-mode transition occurred.

The vendor driver must be registered as an Early Launch Anti-Malware (ELAM) driver to receive the full feed from the provider `{A68CA8B7-004F-D7B6-A529-8CEE96FC851D}` (`Microsoft-Windows-Threat-Intelligence`).

### Key ETW-TI Events for Memory Manipulation

| Event ID / Struct | Description | Defensive Value |
| :--- | :--- | :--- |
| `KERNEL_THREATINT_VIRTUAL_ALLOC` | Emitted during virtual memory allocation calls. | Captures caller process, target process, requested allocation size, and allocation permissions (`PAGE_EXECUTE_READWRITE`). |
| `KERNEL_THREATINT_VIRTUAL_PROTECT` | Emitted when memory protection flags change. | Detects transitions from `RW` to `RX` or `RWX` (common in shellcode execution staging). |
| `KERNEL_THREATINT_IMAGE_LOAD` | Driver/Image loading operations. | Identifies modified image mapping or unbacked executable loading. |
| `KERNEL_THREATINT_SUBMIT_THREAD` | Remote thread execution creation (`NtCreateThreadEx`). | Identifies cross-process thread creation targeting unbacked entry points. |

Because ETW-TI logs operations at the kernel edge (`Nt*` routines), direct and indirect syscalls trigger these events identically to standard Win32 API calls.

---

## Detecting Syscall Abuse via Call Stack Auditing

While ETW-TI captures the operation parameters, call stack auditing exposes the execution mechanics.

When a thread requests a kernel service via a `syscall` instruction, the kernel builds a frame containing caller information. Analyzing the return addresses on the call stack reveals anomalies introduced by direct and indirect syscall stubs.

### 1. Identifying Unbacked Memory Execution (Direct Syscalls)

In a legitimate execution flow, the return address following a system call points back to the module that initiated the request, usually backed by an executable file on disk (e.g., `kernelbase.dll`, `rpcrt4.dll`).

If an adversary uses direct syscalls from unbacked memory (memory dynamically allocated via `VirtualAlloc` without a backing PE file on disk), the stack unwind reveals a stack frame originating from `Unbacked / Private` memory space.

```
Legitimate Stack Unwind:
0: ntdll.dll!NtProtectVirtualMemory + 0x14
1: KERNELBASE.dll!VirtualProtect + 0x38
2: target_app.exe!main + 0x120

Direct Syscall Stack Unwind (Anomalous):
0: <Unbacked Memory / Private RWX Region> + 0x42  <-- Direct Syscall execution frame
1: <Unbacked Memory / Private RWX Region> + 0x100
```

### 2. Identifying Indirect Syscall Stack Frames

With indirect syscalls, the kernel transition occurs inside `ntdll.dll`. However, the return address directly following the `ntdll` execution frame reveals the evasion attempt.

In standard indirect syscalls, the offset jumping into `ntdll.dll` skips the API entry function's setup logic. When the call stack unwinds, the frame directly below `ntdll.dll` points back to unbacked memory, or skips expected intermediate library calls (`KERNELBASE.dll` or `kernel32.dll`).

```
Indirect Syscall Stack Frame:
0: ntdll.dll!NtAllocateVirtualMemory + 0x12  <-- Syscall executed here
1: <Unbacked Memory / Private Executable>     <-- JMP source (Missing KERNELBASE frame)
```

### 3. Stack Spoofing and Synthetic Frames

Advanced offensive tools attempt to spoof call stacks by building synthetic frames before issuing indirect syscalls, manipulating `RSP` and `RBP` to emulate a legitimate call stack (e.g., mimicking a call path through `kernelbase.dll!VirtualAlloc`).

Detection engineering at this level requires validating:

* **Return Address Backing:** Checking if every address in the stack trace points to memory mapped from a signed module on disk.
* **Frame Alignment and Unwind Info (`.pdata`):** Validating whether the return address corresponds to a valid `CALL` instruction location within the caller module.
* **Instruction Inspection:** When a thread unwinds from `ntdll.dll`, the instruction preceding the return address in the calling frame should be a `CALL` instruction (`E8` or `FF /1`). If an indirect syscall used a `JMP` instruction instead of a `CALL` to enter `ntdll.dll`, the location before the return address will not match a `CALL` sequence.

---

## Detection Logic and SIEM Query Strategies

To operationalize these concepts, detection rules must correlate kernel telemetry events with call stack attributes and thread characteristics.

### Example Detection Heuristic: Remote Allocation with Anomalous Call Stack

Below is a conceptual KQL query demonstrating how an engineer might search EDR telemetry enriched with kernel stack data for cross-process memory allocations initiated from unbacked memory:

```kql
TargetProcessEvents
| where EventType == "CrossProcessMemoryAllocation"
| where TargetProcessId != InitiatingProcessId
| where RequestedPermissions has_any ("PAGE_EXECUTE_READWRITE", "PAGE_EXECUTE_READ")
| extend TopStackFrame = TelemetryStackFrames[0]
| extend SubCallStackFrame = TelemetryStackFrames[1]
| where TopStackFrame.IsMemoryBacked == false 
   or (TopStackFrame.ModuleName == "ntdll.dll" and SubCallStackFrame.IsMemoryBacked == false)
| project Timestamp, 
          InitiatingProcessFileName, 
          InitiatingProcessId, 
          TargetProcessFileName, 
          TargetProcessId, 
          RequestedPermissions, 
          TopStackFrame.Address, 
          SubCallStackFrame.ModuleName
```

### Detection Logic: Memory Scanning for Direct Syscall Artifacts

Defenders can also use memory scanning (via YARA or custom process scanners) to spot raw `syscall` instructions outside legitimate system DLLs.

A simple YARA rule targeting raw x64 `syscall` stubs residing in dynamic memory allocations:

```yara
rule Suspicious_Direct_Syscall_Stub {
    meta:
        description = "Detects standalone x64 syscall stubs inside private executable memory"
        author = "Abdul Muqeet Tabraiz"
        severity = "High"
    strings:
        // mov r10, rcx; mov eax, <SSN>; syscall; ret
        $syscall_stub = { 49 89 CA B8 ?? ?? 00 00 0F 05 C3 }
    condition:
        $syscall_stub and process.memory_region.type == "PRIVATE" 
        and process.memory_region.protection == "PAGE_EXECUTE_READWRITE"
}
```

---

## Operational Considerations and Performance Trade-offs

Building detection pipelines based on ETW-TI and kernel stack tracing introduces concrete engineering trade-offs:

1. **Telemetry Volume:** Kernel memory events (`NtProtectVirtualMemory`, `NtAllocateVirtualMemory`) trigger at extremely high rates. Operating systems routinely allocate memory for legitimate applications, JIT compilers, and WebBrowsers (e.g., Chrome, Edge). Collecting full stack traces for every `VirtualAlloc` call across an entire enterprise endpoint fleet will quickly overwhelm network buffers and SIEM storage limits.
2. **False Positives from JIT Environments:** Just-In-Time (JIT) compilation engines—such as the .NET CLR (`clr.dll`), Java Virtual Machines, and browser V8 engines—dynamically allocate and execute code from unbacked or private RWX memory regions. Detection rules looking for unbacked memory calls must explicitly baseline these legitimate runtime environments using process lineage, executable signatures, and memory allocation attributes.
3. **ELAM Driver Dependencies:** Third-party applications cannot simply open an ETW handle to `Microsoft-Windows-Threat-Intelligence`. Accessing raw ETW-TI telemetry requires a driver signed with Microsoft's Early Launch Anti-Malware (ELAM) certificate context. Defenders without custom driver development infrastructure must rely on EDR vendors to expose these stack metadata fields inside their log schemas.

---

## Practical Defensive Checklist

To validate whether your security posture adequately addresses direct and indirect system calls:

* **Assess EDR Telemetry Depth:** Verify whether your current endpoint agent incorporates ETW-TI or kernel-level memory instrumentation, or if it relies solely on user-mode API hooks in `ntdll.dll`.
* **Audit Stack Trace Enrichment:** Check if your endpoint log schema exposes complete call stack arrays for memory manipulation and remote thread creation events.
* **Baseline RWX and Unbacked Memory:** Identify JIT-heavy applications within your environment to build exclusion baselines for legitimate unbacked execution.
* **Implement Memory Integrity Protection:** Enable Hypervisor-Protected Code Integrity (HVCI) and Exploit Guard capabilities (such as Hardware-Enforced Stack Protection via Intel CET) where supported by hardware. CET uses a secondary shadow stack to ensure return addresses cannot be tampered with by user-mode code, mitigating many call stack spoofing techniques entirely.
