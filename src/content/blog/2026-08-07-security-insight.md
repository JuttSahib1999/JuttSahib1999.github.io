---
title: "Detecting Indirect Syscalls: Bridging the Gap Between User-Mode EDR Evasion and Kernel Telemetry"
description: "An in-depth technical analysis of how modern adversaries bypass user-mode EDR hooks using indirect syscalls, and how security engineers can leverage ETW-Ti and call stack analysis to detect them."
date: "2026-08-07"
tags: ["Cybersecurity", "Threat Detection", "Security Operations", "Endpoint Security", "Reverse Engineering"]
category: "Cyber Security"
---

For years, Endpoint Detection and Response (EDR) agents relied heavily on user-mode API hooking to detect malicious activity on Windows endpoints. By patching the entry points of Native API functions inside `ntdll.dll` with unconditional jumps (`jmp`) to a security DLL, EDRs gained visibility into memory allocation, process creation, and thread injection techniques before execution ever reached kernel space.

However, modern adversary techniques have evolved. Threat actors routinely bypass user-mode hooks through techniques like manual DLL unhooking, direct system calls (Direct Syscalls), and more recently, **Indirect Syscalls**.

This analysis explores the mechanics of indirect syscall execution, why standard user-mode telemetry fails to catch it, and how security engineering teams can build resilient detection optics using kernel-level Event Tracing for Windows (ETW-Ti) and call stack validation.

---

## 1. The Breakdown of User-Mode API Hooking

To understand why indirect syscalls exist, we must look at how user-mode hooking works.

When a Windows application calls a high-level Win32 API function like `VirtualAllocEx`, execution flows through a well-defined chain:

1. `Kernel32.dll` (`VirtualAllocEx`)
2. `KernelBase.dll` (`VirtualAllocEx`)
3. `ntdll.dll` (`NtAllocateVirtualMemory`)
4. Kernel Transition (`syscall` instruction in x64)

```
[ Application Code ]
       │
       ▼
[ Kernel32.dll / KernelBase.dll ]
       │
       ▼
[ ntdll.dll (NtAllocateVirtualMemory) ]
       │  <-- EDR Places JMP Hook Here
       ▼
[ EDR Inspection Engine ] ──(If Clean)──► [ Kernel Transition (syscall) ]
```

EDR solutions inject a dynamic-link library (DLL) into every non-protected user-mode process. This DLL patches the beginning of sensitive functions inside `ntdll.dll` in memory.

### Typical Trampoline Hook Mechanics

An unhooked `NtAllocateVirtualMemory` stub in `ntdll.dll` looks like this on 64-bit Windows:

```assembly
mov r10, rcx
mov eax, 0x18       ; System Service Call Identifier (SSN) for NtAllocateVirtualMemory
syscall             ; Fast System Call
ret
```

When an EDR hooks this function, it overwrites the first few bytes with an assembly jump instruction redirecting execution to the EDR's monitoring DLL:

```assembly
jmp 0x7FFF10000000   ; Jump to EDR monitoring library memory space
nop
nop
```

If the payload evaluation passes, control returns to `ntdll.dll` to execute the `syscall` instruction.

---

## 2. Evolution of Evasion: Direct vs. Indirect Syscalls

Adversaries recognized that `ntdll.dll` lives within user-mode memory allocated to their own process space. Because the process owns its address space, it has full read, write, and execute permissions over its loaded modules.

### Stage 1: Direct Syscalls (Hell's Gate / Halo's Gate)
Tools like `SysWhispers` and implementation techniques like *Hell's Gate* dynamically extract the System Service Number (SSN) from disk-backed copies of `ntdll.dll` or by parsing the export address table (EAT) in memory. Once the SSN is recovered, the payload embeds the full syscall stub directly inside its own text segment:

```assembly
; Direct Syscall execution inside malicious payload
mov r10, rcx
mov eax, [extracted_ssn]
syscall             ; Executed directly from payload memory space
ret
```

**The EDR Problem**: The execution completely bypasses the `jmp` hook in `ntdll.dll`.
**The Defensive Counter**: Security tools started inspecting the instruction pointer (`RIP`) during system call processing or monitoring stack traces for syscalls originating from memory regions outside `ntdll.dll` (unbacked memory or private commit space).

### Stage 2: Indirect Syscalls (TartarusGate)
To bypass detection strategies targeting direct syscalls, indirect syscall techniques separate the assembly sequence. The payload sets up the function arguments and the `eax` register (SSN) inside its own memory space, but instead of executing the `syscall` instruction directly, it jumps to a legitimate `syscall` instruction existing within the address space of `ntdll.dll`.

```assembly
; Payload Assembly
mov r10, rcx
mov eax, 0x18       ; SSN set locally
jmp [address_of_syscall_in_ntdll] ; Jump into legitimate ntdll.dll memory
```

```
[ Malicious Payload ]
  │
  ├── 1. Sets up registers (r10 = rcx, eax = SSN)
  └── 2. Jumps to legitimate ntdll memory address
         │
         ▼
[ ntdll.dll ]
  └── Location: ntdll.dll + offset
      └── syscall  <-- Executed within legitimate DLL space
      └── ret
```

Because the `syscall` instruction executes from legitimate `ntdll.dll` memory:
* Simple RIP checks pass (the return address and execution address align with `ntdll.dll`).
* User-mode hooks are completely skipped.

---

## 3. Kernel-Level Visibility: ETW-Threat-Intelligence (ETW-Ti)

Since user-mode inspection points are compromised by design, effective detection must shift to the Windows Kernel. 

Microsoff introduced **Event Tracing for Windows Threat Intelligence (ETW-Ti)**, a kernel-level provider that emits telemetry directly from kernel functions (`Nt*` and `Zw*` routines) executed by the kernel executive layer.

```
[ User Space: Payload ]
       │ (Indirect Syscall)
       ▼
[ Kernel Space: nt!NtAllocateVirtualMemory ]
       │
       ├── Executed Kernel Logic
       └── Emits Event via ETW-Ti Provider ({A68CA8B7-004F-D7B3-A46B-E619C7B6D2EA})
               │
               ▼
       [ Kernel EDR Driver / Log Pipeline ]
```

### Key ETW-Ti Telemetry Providers for Syscall Defense

* **`KERNEL_THREATINT_KEY_ACCOUNT_LOGON`**
* **`THREATINT_ALLOCVM_REMOTE`**: Emitted on `NtAllocateVirtualMemoryEx` targeting foreign processes.
* **`THREATINT_PROTECTVM_REMOTE`**: Emitted during memory protection alterations (`NtProtectVirtualMemory`).
* **`THREATINT_READWRITE_VM_REMOTE`**: Emitted on memory modification operations (`NtReadVirtualMemory` / `NtWriteVirtualMemory`).

ETW-Ti captures execution metrics that user-mode malware cannot forge, specifically the **Kernel Thread Call Stack**.

---

## 4. Detection Engineering: Call Stack Spoofing and Anomaly Detection

Detecting indirect syscalls requires analyzing the call stack for context anomalies when sensitive kernel functions trigger.

### Legitimate Call Stack Example
A standard memory allocation initiated by a legitimate process (`explorer.exe`) presents a full, continuous chain of return addresses:

```
Frame 0: ntdll.dll!NtAllocateVirtualMemory + 0x14
Frame 1: KernelBase.dll!VirtualAllocEx + 0x5e
Frame 2: explorer.exe!AllocateBuffer + 0x120
Frame 3: kernel32.dll!BaseThreadInitThunk + 0x14
Frame 4: ntdll.dll!RtlUserThreadStart + 0x21
```

### Indirect Syscall Call Stack (Unmodified)
When a simple indirect syscall implementation runs, `KernelBase.dll` and high-level wrappers are missing entirely:

```
Frame 0: ntdll.dll!NtAllocateVirtualMemory + 0x12
Frame 1: malicious_executable.exe!ExecutePayload + 0x88
Frame 2: kernel32.dll!BaseThreadInitThunk + 0x14
Frame 3: ntdll.dll!RtlUserThreadStart + 0x21
```

**Indicators of Compromise (IoCs):**
1. **Missing Module Transitions**: Execution transitions directly from `malicious_executable.exe` to a `syscall` offset in `ntdll.dll`, skipping the wrapper functions (`KernelBase.dll`).
2. **Instruction Offset Misalignment**: The jump targets a `syscall` instruction mid-function in `ntdll.dll`, rather than entering at the exported function symbol offset.

### Advanced Detection: Unbacked Call Stack Frames

Adversaries often attempt frame spoofing or run payloads out of dynamically allocated memory (e.g., shellcode executed from `MEM_COMMIT` private memory).

When analyzing thread call stacks via Sysmon Event ID 10 (Process Access) or ETW-Ti trace data, look for **unbacked memory modules**:

```xml
<!-- Example Sysmon Event ID 10 CallTrace -->
<Provider Name="Microsoft-Windows-Sysmon" />
<EventData>
  <Data Name="SourceImage">C:\Users\Target\AppData\Local\Temp\update.exe</Data>
  <Data Name="TargetImage">C:\Windows\System32\lsass.exe</Data>
  <Data Name="CallTrace">
    C:\Windows\SYSTEM32\ntdll.dll+9dce4 |
    UNKNOWN(0x00007FFD2A111050) |           <-- Unbacked Memory Region
    C:\Windows\System32\kernel32.dll+0x14d23 |
    C:\Windows\SYSTEM32\ntdll.dll+0x70b3c
  </Data>
</EventData>
```

---

## 5. Practical Sigma Rule: Detecting Anomalous Stack Frames

To operationalize this visibility, detection engineers can construct Sigma rules targeting call stack traces captured by endpoint agents (such as Sysmon, CrowdStrike, or SentinelOne).

```yaml
title: Indirect Syscall Memory Allocation from Unbacked Memory
id: 3c2f218a-4d33-40a1-9a70-8b1e1136dfa4
status: experimental
description: Detects memory allocation or protection calls where the calling frame points to unbacked execution space combined with ntdll syscall execution.
author: Security Operations Center
logsource:
  category: process_access
  product: windows
detection:
  selection:
    TargetImage|endswith: 
      - '\explorer.exe'
      - '\lsass.exe'
      - '\svchost.exe'
    CallTrace|contains:
      - 'UNKNOWN'
  syscall_pattern:
    CallTrace|contains|all:
      - 'ntdll.dll+'
      - 'UNKNOWN'
  filter_legit:
    SourceImage|startswith:
      - 'C:\Program Files\'
      - 'C:\Program Files (x86)\'
  condition: selection and syscall_pattern and not filter_legit
falsepositives:
  - Just-In-Time (JIT) compilers (.NET, Java, Web Browsers) allocating executable memory dynamically.
level: high
```

---

## 6. Defensive Takeaways for Security Engineering Teams

1. **Do not rely on user-mode API hooking alone.** User-mode EDRhooks provide operational context, but offer zero guarantee of integrity against modern loader designs.
2. **Prioritize Kernel-based Optics.** Ensure your endpoint solutions ingest ETW-Ti telemetry and register object callbacks via kernel drivers (`ObRegisterCallbacks`).
3. **Enforce Call Stack Validation.** Focus detection strategies on stack frame analysis—specifically searching for unbacked memory pointers, missing DLL layers in execution chains, and call trace jumps directly into internal `syscall` instruction offsets.
4. **Implement Memory Guarding Policies.** Utilize Windows security controls like **Arbitrary Code Guard (ACG)** and **Code Integrity Guard (CIG)** where applicable to prevent processes from creating executable private memory regions or loading unsigned modules.