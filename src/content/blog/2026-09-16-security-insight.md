---
title: "Detecting Direct Syscalls and Call Stack Spoofing: Telemetry Blind Spots, ETW-Ti, and Stack Walking"
description: "An in-depth analysis of how advanced threat actors bypass user-mode EDR hooks using direct and indirect system calls, how call stack spoofing defeats stack trace analysis, and how detection engineers can build robust detections using ETW-Ti and unbacked memory telemetry."
date: "2026-09-16"
tags: ["Detection Engineering", "Cybersecurity", "Endpoint Security", "Windows Internals"]
category: "Cyber Security"
difficulty: "Advanced"
author: "Abdul Muqeet Tabraiz"
image: "/images/blog/2026-09-16-detecting-direct-syscalls-and-call-stack-spoofing-telemetry-blind-spots-etw-ti-a.svg"
---

Endpoint Detection and Response (EDR) agents rely heavily on user-mode API hooking to monitor process behavior. By placing inline hooks (typically `jmp` instructions) inside high-level APIs or low-level Native API functions in `ntdll.dll`, security tools inspect function parameters before execution transfers to the Windows kernel.

Adversaries recognized this limitation years ago and adapted. Instead of routing execution through hooked user-mode libraries, malware authors bypass hooks entirely by invoking system calls directly from custom code or crafting indirect syscalls that leverage legitimate executable regions. To counter EDRs that analyze kernel-level call stacks, attackers now combine syscall evasion with call stack spoofing.

Understanding how these techniques function at the assembly and OS kernel levels is critical for modern detection engineering. User-mode telemetry is useless against direct syscalls; detection depends on kernel telemetry, call stack unwind analysis, and memory page inspection.

---

## User-Mode Hooking and the Evasion Evolution

When a userland process requests an operation from the operating system—such as allocating memory with `VirtualAlloc` or opening a handle to another process with `OpenProcess`—the request passes through a defined call hierarchy:

1. Application code calls a Win32 API (`Kernel32.dll` / `KernelBase.dll`).
2. Win32 functions validate parameters and call the corresponding Native API exported by `ntdll.dll` (e.g., `NtOpenProcess`).
3. `ntdll.dll` loads the System Service Number (SSN) into the `EAX` register and executes a `syscall` instruction.
4. The CPU transitions from User Mode (Ring 3) to Kernel Mode (Ring 0), placing execution into `KiSystemCall64`.

```
[ Application / Malware ]
         │
         ▼
[ kernel32.dll / KernelBase.dll ]
         │
         ▼
[ ntdll.dll ]  <--- EDR Places Inline Hook Here (e.g., JMP to edr_x64.dll)
         │
         ▼
 [ syscall Instruction ]
         │
         ▼
   ( Ring 0 Kernel )
```

### Direct System Calls
To bypass the inline hook in `ntdll.dll`, an attacker parses `ntdll.dll` on disk or in memory to extract the raw System Service Number (SSN) for the target API. The attacker then implements the `syscall` instruction natively within their own executable memory space:

```assembly
; Direct syscall for NtOpenProcess (example SSN = 0x26)
mov r10, rcx
mov eax, 26h
syscall
ret
```

Because execution never touches the modified `ntdll.dll` bytes inside the process, user-mode EDR hooks fail to capture the event. Techniques like Hell's Gate, Halo's Gate, and TartarusGate automated the dynamic retrieval of SSNs even when `ntdll.dll` is actively patched or hooked in memory.

### Indirect System Calls
Security vendors responded by adding kernel-level monitoring (via ETW-Ti or kernel driver callbacks) to log the memory address execution originated from when the `syscall` instruction was issued. 

If the kernel sees a `syscall` originating from executable memory assigned to `malware.exe` or an unbacked dynamic heap page rather than `ntdll.dll`, the activity is immediately flagged as anomalous.

To defeat this check, attackers transitioned to **Indirect System Calls**. Instead of executing the `syscall` instruction inside their payload, the payload manually sets up the register context (`r10` and `eax`), locates a legitimate `syscall; ret` instruction gadget inside the offset of `ntdll.dll`, and jumps directly to that address.

```assembly
; Indirect syscall: SSN is set, but the syscall instruction executes inside ntdll.dll
mov r10, rcx
mov eax, 26h
jmp [pNtOpenProcessSyscallGadget] ; Points to 'syscall; ret' inside legitimate ntdll.dll
```

Now, the kernel sees that the `syscall` instruction executed from an address belonging to `ntdll.dll` on disk, bypassing basic return-address checks.

---

## Call Stack Spoofing: Masking the Execution Trail

When kernel-level telemetry (such as Microsoft Threat Intelligence ETW) logs sensitive actions—like opening a handle to `lsass.exe`—it records the execution call stack at that precise moment.

Even with an indirect syscall, a standard call stack unwinding operation reveals the dynamic allocations leading up to the `ntdll.dll` gadget:

```
# Normal Call Stack (Legitimate)
0x00 ntdll.dll!NtOpenProcess+0x14
0x01 KernelBase.dll!OpenProcess+0x42
0x02 ProcessHacker.exe!OpenTargetProcess+0x105
0x03 ProcessHacker.exe!main+0x20

# Suspicious Indirect Syscall Call Stack (Unspoofed)
0x00 ntdll.dll!NtOpenProcess+0x14
0x01 [Unbacked Memory / Private Allocation @ 0x021F0000]+0x450  <-- ANOMALY
0x02 kernel32.dll!BaseThreadInitThunk+0x14
0x03 ntdll.dll!RtlUserThreadStart+0x21
```

The presence of an **unbacked memory region** (executable memory not backed by an image file on disk) directly on the call stack is a high-confidence indicator of process injection, shellcode execution, or indirect syscall abuse.

### Spoofing Mechanics

To erase this indicator, threat actors manipulate the thread's call stack before invoking the kernel transition. Call stack spoofing techniques modify frame pointers, fake return addresses, or synthesize fake stack frames using structural unwind metadata (`.pdata` / `RUNTIME_FUNCTION`).

A common method works as follows:
1. **Locate Legitimate Frames**: Identify valid code locations in benign loaded DLLs (e.g., `kernel32.dll`, `KernelBase.dll`).
2. **Construct Synthetic Frames**: Allocate dynamic stack frames that mirror the layout expected by x64 stack unwinding rules.
3. **Overwrite Return Addresses**: Replace the true return addresses on the stack with addresses inside legitimate functions, pointing to instructions immediately following a standard `call`.
4. **Execute Gadget and Restore**: Trigger the indirect syscall. Once the kernel returns control, restore the original, valid stack pointers and frame context so the application does not crash.

Advanced frameworks (such as SilentMoonwalk or ThreadStackSpoofer) construct fake unwinding paths that completely pass Windows `RtlVirtualUnwind` routines without triggering structural unwinding errors.

---

## Telemetry Sources and Defensive Blind Spots

Building detections against direct syscalls and stack manipulation requires choosing telemetry sources that operate below the user-mode execution layer.

| Telemetry Source | Direct Syscall Visibility | Indirect Syscall Visibility | Call Stack Telemetry | Limitations |
| :--- | :--- | :--- | :--- | :--- |
| **User-Mode API Hooks** | None | None | None | Easily bypassed by unhooking or direct assembly calls. |
| **Sysmon / Event Log** | Partial (Kernel Callbacks) | Partial (Kernel Callbacks) | Limited (CallStack string) | ProcessAccess (Event ID 10) provides call stacks, but lacks deep stack unwinding validation. |
| **Kernel Callbacks (`ObRegisterCallbacks`)** | High | High | Moderate | Captures process/thread operations, but stack traces must be gathered on-thread in real time. |
| **ETW Threat Intelligence (`ETW-Ti`)** | High | High | High | Extremely detailed, but requires Microsoft authorization (PPL) for custom consumer agents. |

### ETW Threat Intelligence (ETW-Ti)

ETW-Ti is embedded within the Windows kernel (`ntoskrnl.exe`). When a thread executes sensitive system operations—such as `NtReadVirtualMemory`, `NtWriteVirtualMemory`, `NtAllocateVirtualMemory`, or `NtOpenProcess`—the kernel logs telemetry via the `Microsoft-Windows-Threat-Intelligence` provider (GUID: `{23012759-792B-4809-B817-A0E00021A527}`).

Crucially, because this logging occurs *inside* the kernel during the system call handler, user-mode hooks cannot disable it.

Key fields supplied by ETW-Ti events include:
- `CallingAddress`: The actual RIP/EIP instruction pointer value executing the `syscall`.
- `TargetProcess`: The destination process object.
- `DesiredAccess`: The requested access mask bitmask.
- `CallStack`: The complete user-mode stack trace evaluated at the time of kernel entry.

---

## Detection Engineering Strategies

Effective defense requires correlating telemetry across multiple layers rather than relying on single signature matches.

### Strategy 1: Unbacked Executable Memory Detection

Whether an attacker uses direct or indirect syscalls, shellcode usually resides inside dynamically allocated memory (`MEM_COMMIT`) that lacks an image file backing on disk (i.e., not loaded via `LoadLibrary` or mapped from a PE image).

Detection logic evaluates every thread entry point or caller address against process memory maps:

```
IF (CallStack.Address.State == MEM_COMMIT)
AND (CallStack.Address.Type == MEM_PRIVATE OR MEM_MAPPED)
AND (CallStack.Address.AllocationProtect CONTAINS PAGE_EXECUTE_*)
AND (CallStack.Address.ImageName IS NULL)
THEN FlagAsSuspicious("Unbacked Memory Execution")
```

### Strategy 2: Call Stack Unwind Validation

Legitimate x64 Windows applications strictly adhere to the structured exception handling (SEH) unwind standards defined in the PE header's `.pdata` section. Synthetic stack frames generated by simple stack spoofers often break these conventions.

To detect stack spoofing, detection engines or kernel drivers perform stack walking and validate each frame:

1. **Return Address Mapping**: Every return address on the stack must reside within an executable section (`.text`) of a recognized module loaded in the Process Environment Block (PEB).
2. **Instruction Call Validation**: The byte sequence preceding the return address must correspond to a valid `CALL` instruction (e.g., `E8`, `FF /2`). If a return address points to an instruction after a non-call instruction (like `nop`, `mov`, or `add`), the stack frame was forged.
3. **Stack Pointer Sanity**: The stack pointers (`RSP`) must progressively move from lower memory addresses to higher memory addresses during unwinding. Any backward movement or stack address outside the thread's stack boundaries (`NT_TIB.StackLimit` to `NT_TIB.StackBase`) signals tampering.

### Strategy 3: Syscall Instruction Source Telemetry

When processing kernel syscall events (e.g., via ETW-Ti or EDR driver callbacks), inspect the precise memory module owning the `CallingAddress` (the RIP executing the `syscall` instruction).

- If `CallingAddress` falls inside `C:\Windows\System32\ntdll.dll` or `C:\Windows\System32\win32u.dll`, it passes initial execution checks (potential Indirect Syscall).
- If `CallingAddress` falls inside any other module or an unbacked memory range, it is an **explicit Direct Syscall**.

```
# Pseudocode for Direct Syscall Detection in EDR Callback
VOID OnKernelSyscallEntry(PSYS_EVENT_DATA EventData) 
{
    PVOID CallingIP = EventData->CallingAddress;
    PLDR_DATA_TABLE_ENTRY Module = FindModuleByAddress(EventData->TargetProcess, CallingIP);

    IF (Module == NULL) {
        Alert("Direct Syscall executed from unbacked memory location: " + CallingIP);
    } 
    ELSE IF (!IsSystemNTDLL(Module->FullDllName) AND !IsSystemWin32U(Module->FullDllName)) {
        Alert("Direct Syscall executed from unexpected binary module: " + Module->FullDllName);
    }
}
```

---

## Practical Detection Rules

Below are practical detection implementations designed for detection platforms that process EDR and ETW stack telemetry.

### KQL Query: Detecting Process Access via Spoofed or Unbacked Stack Frames

This query leverages Windows Event ID 10 (Sysmon ProcessAccess) or equivalent EDR kernel telemetry to identify sensitive handle acquisition originating from unbacked callers or abnormal stack patterns targeting critical processes like `lsass.exe`.

```kql
// Detect LSASS Handle Creation via Unbacked or Anomalous Call Stack
Sysmon_ProcessAccess_CL
| where TargetImage endswith @"\lsass.exe"
| where GrantedAccess in ("0x1410", "0x1010", "0x1F0FFF", "0x143A") // Common high-privilege access masks
| extend CallStackLines = split(CallStack, "|")
| mv-expand CallStackLines
// Look for call stacks referencing unknown/unbacked locations or raw addresses
| where CallStackLines matches regex @"^\?\?\?\?.*" 
   or CallStackLines matches regex @"^UNKNOWN.*"
   or (CallStackLines !contains "ntdll.dll" and CallStackLines !contains "kernel32.dll" and CallStackLines !contains "KernelBase.dll")
| summarize 
    FirstSeen = min(TimeGenerated), 
    LastSeen = max(TimeGenerated), 
    EventCount = count() 
    by SourceImage, TargetImage, GrantedAccess, CallStack
| sort by FirstSeen desc
```

### Sigma Rule: Direct Syscall Execution via Unbacked Memory Range

```yaml
title: Direct Syscall Execution via Unbacked Memory
id: 3c92f14e-4b2a-4a21-bc30-8a12409f9871
status: experimental
description: Detects process access or memory operations where the execution address originates from unbacked executable memory regions, indicative of direct syscalls or shellcode execution.
author: Abdul Muqeet Tabraiz
date: 2026-09-16
tags:
    - attack.defense_evasion
    - attack.t1055
    - attack.t1106
logsource:
    category: process_access
    product: windows
detection:
    selection_target:
        TargetImage|endswith:
            - '\lsass.exe'
            - '\csrss.exe'
            - '\winlogon.exe'
    selection_stack:
        CallStack|contains:
            - 'UNKNOWN'
            - '?'
            - 'unbacked'
    condition: selection_target and selection_stack
falsepositives:
    - Legacy third-party security software modifying thread stacks
    - Game anti-cheat software running custom user-mode drivers
level: high
```

---

## Operational Considerations and Trade-offs

Engineering robust detections around syscall abuse requires navigating technical limitations and performance trade-offs:

1. **JIT Compilers and Interpreted Runtimes**: Runtimes such as .NET (CLR), Java (JVM), and browser engines (V8 in Chrome/Edge) routinely allocate `PAGE_EXECUTE_READWRITE` memory and execute code from unbacked dynamic heap regions. Simple "unbacked execution" rules will generate heavy false-positive noise unless tuned to exclude legitimate JIT binaries (`dotnet.exe`, `java.exe`, `chrome.exe`).
2. **Performance Overhead of Kernel Stack Tracing**: Deep stack walking on every system call introduces significant CPU overhead. Production EDR agents selective filter stack unwinding to high-risk APIs (e.g., `NtOpenProcess`, `NtAllocateVirtualMemory`, `NtWriteVirtualMemory`, `NtCreateThreadEx`).
3. **ETW-Ti Access Restrictions**: Microsoft restricts access to the ETW-Ti provider using Protected Process Light (PPL) requirements. Custom internal tools cannot subscribe to `Microsoft-Windows-Threat-Intelligence` unless they run as an ELAM (Early Launch Anti-Malware) driver signed by Microsoft.

---

## Defensive Engineering Summary

Relying exclusively on user-mode API monitoring leaves significant blind spots. As offensive toolkits incorporate automated indirect syscalls and context-aware stack spoofing, defenders must elevate their operational architecture:

- Collect and ingest kernel-level telemetry (ETW-Ti, Sysmon Process Access, or vendor EDR driver logs).
- Validate memory region properties (`MEM_COMMIT` vs. image-backed storage) for every sensitive process cross-handle request.
- Implement stack frame unwind validation heuristics to verify return address locations and structural call consistency.

Detecting advanced evasions is not about matching static byte signatures; it is about validating whether an execution sequence respects the structural rules imposed by the operating system platform.
