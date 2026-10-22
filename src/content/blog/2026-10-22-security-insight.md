---
title: "Detecting Indirect Syscalls and Native API Evasion: Telemetry Gaps, Call Stack Analysis, and ETW Threat Intelligence"
description: "An in-depth technical analysis of indirect system call evasion techniques, kernel-level telemetry limitations, stack walk anomalies, and detection engineering strategies using ETW Threat Intelligence."
date: "2026-10-22"
tags: ["Detection Engineering", "Endpoint Security", "DFIR", "Threat Hunting"]
category: "Cyber Security"
difficulty: "Expert"
author: "Abdul Muqeet Tabraiz"
image: "/images/blog/2026-10-22-detecting-indirect-syscalls-and-native-api-evasion-telemetry-gaps-call-stack-ana.svg"
---

User-mode API hooking has served as a primary telemetry pillar for Endpoint Detection and Response (EDR) agents for over a decade. By placing inline jumps (`jmp` instructions) at the entry points of Native API functions inside `ntdll.dll`, EDRs inspect arguments before control transitions to kernel space.

To bypass this visibility, offensive tools evolved from calling high-level Win32 APIs (`VirtualAllocEx`, `WriteProcessMemory`) to executing direct system calls via custom assembly stubs. When detection engineering adapted by flagging `syscall` instructions originating from execution space outside `ntdll.dll`, adversaries pivoted to **indirect system calls**.

Indirect syscalls execute the kernel transition instruction (`syscall; ret`) from inside the legitimate memory space of `ntdll.dll`, neutralizing simple instruction pointer checks. Detecting this technique requires moving past binary pattern matching and evaluating kernel telemetry, call stack frames, return addresses, and execution context.

---

## From User-Mode Hooks to Indirect System Calls

Understanding how indirect syscalls subvert endpoint controls requires examining how user-mode hooks operate and where direct syscalls fell short.

### 1. User-Mode API Hooking

When a process calls `VirtualAllocEx` in `kernel32.dll`, control flows into `KernelBase.dll` and ultimately calls `NtAllocateVirtualMemory` inside `ntdll.dll`. Under normal conditions, `NtAllocateVirtualMemory` sets up the System Service Number (SSN) in the `RAX` register and issues the `syscall` instruction:

```assembly
mov r10, rcx
mov eax, 0x0018    ; SSN for NtAllocateVirtualMemory (Windows version dependent)
syscall
ret
```

An EDR hooks this function by overwriting the first few bytes of `NtAllocateVirtualMemory` in memory with an absolute or relative jump pointing to its hooked dynamic library (`edr_hook.dll`):

```assembly
jmp edr_hook.dll + 0x1234
nop
nop
```

If the hooked DLL deems the memory allocation safe, it executes the original overwritten instructions and returns control to `ntdll.dll` to perform the `syscall`.

### 2. Direct System Calls

Adversaries bypassed user-mode hooks by allocating or embedding their own syscall stubs directly within their payload's `.text` section or dynamically allocated memory. Modern implementations (such as SysWhispers2/3) dynamically resolve SSNs at runtime by parsing the Export Address Table (EAT) of an unhooked `ntdll.dll` copy (or sorting export addresses) to avoid hardcoding version-specific SSNs.

```assembly
; Direct Syscall Stub embedded in offensive binary
mov r10, rcx
mov eax, [ssn_NtAllocateVirtualMemory]
syscall            ; Executed directly from payload memory space
ret
```

Direct syscalls completely bypass `edr_hook.dll` because control never enters the hooked entry point in `ntdll.dll`.

### 3. Detection of Direct Syscalls

Security vendors countered direct system calls by inspecting execution context at the kernel boundary or via ETW Threat Intelligence (ETW-TI). When a kernel callback (e.g., `ObRegisterCallbacks` or `PsSetCreateProcessNotifyRoutineEx`) triggers, or when an ETW-TI event is generated:

1. The kernel records the Instruction Pointer (`RIP`) at the moment of the system call transition.
2. If `RIP` falls outside the legitimate memory range of `ntdll.dll` (or `win32u.dll` for graphics calls), the invocation is flagged as an anomaly.
3. Memory scanning tools look for executable pages (`PAGE_EXECUTE_READWRITE` or unbacked `PAGE_EXECUTE_READ`) containing the binary opcode `0F 05` (`syscall`).

### 4. Indirect System Calls

Indirect system calls overcome instruction pointer checks by splitting the stub's execution:
1. The payload dynamically resolves the required SSN.
2. The payload searches `ntdll.dll` memory for a valid `syscall; ret` instruction sequence (gadget).
3. The payload populates registers (`RAX`, `R10`, arguments) in its own execution context.
4. Instead of issuing `syscall`, the payload executes a `jmp` instruction targeting the `syscall` gadget inside `ntdll.dll`.

```assembly
; Indirect Syscall Stub
mov r10, rcx
mov eax, [ssn_NtAllocateVirtualMemory]
jmp qword ptr [address_of_syscall_gadget_in_ntdll]
```

When the CPU processes the `syscall` instruction, `RIP` points inside `ntdll.dll`. Simple checks verifying whether the system call originated from `ntdll.dll` memory space pass without raising alerts.

---

## The Telemetry Architecture: Where Visibility Breaks and Holds

Detecting indirect syscalls requires understanding what telemetry sources observe during execution.

```
+-------------------------------------------------------------------+
|                        User-Mode Execution                        |
|                                                                   |
|  [ Offensive Payload ] --(jmp)--> [ ntdll.dll (syscall gadget) ]  |
|         |                                    |                    |
+---------|------------------------------------|--------------------+
          | (Bypasses User-Mode Hooks)         |
          v                                    v
+-------------------------------------------------------------------+
|                         Kernel Boundary                           |
|                                                                   |
|   - ObRegisterCallbacks: Sees Handle Creation (No Call Stack)     |
|   - ETW Threat Intelligence: Captures Event + Thread Call Stack   |
+-------------------------------------------------------------------+
```

### Telemetry Blind Spots

1. **User-Mode Hook Telemetry**: Dead. Because entry points in `ntdll.dll` are bypassed via mid-function jumps to internal `syscall` instructions, hooked user-mode functions are never executed.
2. **Standard Kernel Object Callbacks (`ObRegisterCallbacks`)**: Callbacks trigger when process handles are created or duplicated (`NtOpenProcess`). However, these callbacks only provide process IDs, requested access masks, and object types. They do not natively capture user-mode stack frames without costly manual stack unwinding inside the kernel callback routine.

### Retaining Visibility: ETW Threat Intelligence (ETW-TI)

The primary kernel-level engine capable of capturing the necessary telemetry is the `Microsoft-Windows-Threat-Intelligence` provider. Built directly into the Windows kernel (`NTOSKRNL`), ETW-TI emits telemetry during critical security operations independent of user-mode hooks.

Key ETW-TI events relevant to indirect syscall detection include:

| Event ID / Struct Name | Description | Common Trigger |
| :--- | :--- | :--- |
| `KERNEL_THREATINT_KEYED_EVENT` | Memory allocation/protection alterations | `NtAllocateVirtualMemory`, `NtProtectVirtualMemory` |
| `KERNEL_THREATINT_JOB_READ_WRITE` | Remote process memory reads/writes | `NtReadVirtualMemory`, `NtWriteVirtualMemory` |
| `KERNEL_THREATINT_SUSPECT_THREAD` | Context manipulation / Thread creation | `NtCreateThreadEx`, `NtSetContextThread` |

Crucially, ETW-TI events include kernel-captured call stack traces (`EVENT_HEADER_EXTENDED_DATA_ITEM` with `ENDPOINT_BINARY_TRACKING_INFO` or stack frame arrays). When ETW-TI is consumed by an EDR driver, it receives the complete thread call stack at the exact moment the kernel function executes.

---

## Call Stack Anomalies Produced by Indirect Syscalls

While indirect syscalls successfully spoof the instruction pointer (`RIP`) at the moment `syscall` is executed, they leave distinct anomalies in the call stack structure.

### Legitimate Call Stack Structure

A legitimate user-mode invocation of a Native API function follows a standard chain:

```
Frame 0: ntdll.dll!NtWriteVirtualMemory + 0x14  <-- RIP at Kernel Transition
Frame 1: KERNELBASE.dll!WriteProcessMemory + 0x42
Frame 2: main_application.exe!WriteData + 0x88
Frame 3: main_application.exe!main + 0x20
Frame 4: KERNEL32.DLL!BaseThreadInitThunk + 0x14
Frame 5: ntdll.dll!RtlUserThreadStart + 0x21
```

Notice three key features:
- **Return Address Continuity**: Frame 0 returns to `KERNELBASE.dll`, which returns to the caller module.
- **Function Entry Alignment**: Frame 0 starts at the beginning of `NtWriteVirtualMemory` and executes linearly to the `syscall` offset.
- **Valid Call Instructions**: The instruction preceding each return address in higher frames is a `CALL` instruction (`E8` or `FF /2`).

### Indirect Syscall Stack Structure

When an offensive payload executes an indirect syscall by jumping directly to a `syscall; ret` gadget inside `ntdll.dll`, the stack frame reveals anomalies:

```
Frame 0: ntdll.dll!NtWriteVirtualMemory + 0x12  <-- Gadget Address (NOT Function Entry Point)
Frame 1: offensive_payload.exe!UnbackedOrRawOffset + 0x1A0
Frame 2: KERNEL32.DLL!BaseThreadInitThunk + 0x14
Frame 3: ntdll.dll!RtlUserThreadStart + 0x21
```

#### Anomaly 1: Missing Intermediary Subsystem DLLs
The stack completely lacks frames from `KERNELBASE.dll` or `kernel32.dll`. Unless a developer is natively linking against `ntdll.lib` (which is rare for standard applications), direct jumps into `ntdll.dll` bypass higher-level Win32 wrappers entirely.

#### Anomaly 2: Mid-Function Execution (Gadget Offset Mismatch)
In legitimate execution, Frame 0 returns to a location immediately following a `CALL` instruction to `NtWriteVirtualMemory`. In an indirect syscall, Frame 0's execution pointer points directly at the `syscall` or `ret` instruction. The return address pushed onto the stack by the payload points back to `offensive_payload.exe`, but the stack frame for `ntdll.dll` shows that execution did not start at `ntdll.dll!NtWriteVirtualMemory` entry point (`+0x0`). Instead, it entered mid-function at `NtWriteVirtualMemory + 0x12`.

#### Anomaly 3: Preceding Instruction Validation (Missing `CALL`)
If a detection mechanism unwinds the stack from Frame 1 back to Frame 0, it evaluates the bytes immediately preceding the return address in `offensive_payload.exe`.
- In a legitimate call, the preceding instruction is a `CALL` instruction (e.g., `E8 xx xx xx xx` or `FF /2`).
- In an indirect syscall executed via a `JMP` instruction, the preceding instruction is NOT a `CALL`. It might be a `MOV`, `JMP`, or another setup instruction. When the stack trace unwinder sees a return address where the preceding bytes do not form a `CALL` instruction, it flags an **invalid return address anomaly**.

---

## Detection Engineering Implementation

To detect indirect syscalls in production environments, detection logic must evaluate telemetry from ETW-TI, stack unwinding libraries, or memory inspection drivers.

### 1. ETW-TI Call Stack Unwinding Rules

If you are building detection logic over raw ETW-TI telemetry or using an EDR that exposes raw thread stack frames, focus on three specific conditions.

#### Logic Condition A: Unbacked Module Return Address
Flag any process invoking high-risk system calls (`NtAllocateVirtualMemory`, `NtProtectVirtualMemory`, `NtWriteVirtualMemory`, `NtCreateThreadEx`) where a call stack frame points to execution memory that is not backed by an image file on disk (`PAGE_EXECUTE_READWRITE` dynamic allocations, heap, or stack memory).

#### Logic Condition B: Return Address Preceding Instruction Check
When an event occurs:
1. Inspect Frame 1 (the caller frame immediately below `ntdll.dll`).
2. Read the bytes immediately preceding the return address pointer.
3. Verify if the instruction is a valid `CALL` opcode (`0xE8`, `0xFF`, `0x41 0xFF`). If the frame was reached via `JMP` (`0xEB`, `0xE9`, `0xFF /4`), trigger an alert.

#### Logic Condition C: Subsystem Skip Anomaly
Flag non-system binaries (excluding known runtimes like Go or Java) where system call execution enters `ntdll.dll` directly from the base executable image without passing through `KERNELBASE.DLL`.

### 2. Detection Example: Kernel-Level Call Stack Validation (Pseudocode)

Below is operational pseudocode illustrating how an EDR driver or analytical pipeline evaluates a stack trace captured during an `NtWriteVirtualMemory` ETW-TI event:

```cpp
typedef struct _STACK_FRAME {
    ULONG64 InstructionPointer;
    ULONG64 ReturnAddress;
} STACK_FRAME, *PSTACK_FRAME;

BOOLEAN AnalyzeStackForIndirectSyscall(PSTACK_FRAME StackFrames, ULONG FrameCount) {
    // Frame 0 must be inside ntdll.dll
    PVOID ntdllBase = GetModuleBaseAddress("ntdll.dll");
    ULONG ntdllSize = GetModuleSize("ntdll.dll");

    if (StackFrames[0].InstructionPointer < (ULONG64)ntdllBase || 
        StackFrames[0].InstructionPointer >= ((ULONG64)ntdllBase + ntdllSize)) {
        // Direct Syscall: RIP is completely outside ntdll.dll
        ReportAnomaly(EVENT_DIRECT_SYSCALL_DETECTED);
        return TRUE;
    }

    // Check if Frame 0 entered at a valid function export start
    ULONG64 offsetFromExport = GetOffsetFromNearestExport(StackFrames[0].InstructionPointer);
    if (offsetFromExport > 0x20) { 
        // Execution jumped into the middle of the function (likely a syscall gadget)
        ReportAnomaly(EVENT_INDIRECT_SYSCALL_MID_FUNCTION_JMP);
        return TRUE;
    }

    // Inspect Frame 1 (The Return Frame back in the calling binary)
    ULONG64 returnAddr = StackFrames[1].InstructionPointer;
    
    // Check 1: Is return address in unbacked memory?
    if (IsMemoryUnbacked(returnAddr)) {
        ReportAnomaly(EVENT_UNBACKED_EXECUTABLE_STACK_FRAME);
        return TRUE;
    }

    // Check 2: Inspect preceding instruction in caller frame
    UCHAR precedingBytes[3];
    if (CopyMemoryFromProcess(precedingBytes, (PVOID)(returnAddr - 3), 3)) {
        // Check for common CALL instructions: 
        // 0xE8 (CALL rel32) or 0xFF (CALL r/m64)
        BOOLEAN isCallInstruction = (precedingBytes[2] == 0xE8) || 
                                    (precedingBytes[1] == 0xFF) || 
                                    (precedingBytes[0] == 0xFF);

        if (!isCallInstruction) {
            // Frame reached via JMP or stack spoofing mismatch
            ReportAnomaly(EVENT_INDIRECT_SYSCALL_MISSING_CALL_INSTRUCTION);
            return TRUE;
        }
    }

    return FALSE; // Stack appears legitimate
}
```

### 3. YARA Rule: Hunting for Indirect Syscall Gadget Resolution Patterns

While runtime stack analysis catches execution, threat hunters can identify binaries compiled with indirect syscall frameworks by scanning for memory/disk patterns where `ntdll` is parsed for `syscall; ret` instructions.

```yara
rule Hunt_Indirect_Syscall_Gadget_Search {
    meta:
        description = "Detects binaries searching ntdll for syscall; ret instruction gadgets"
        author = "Abdul Muqeet Tabraiz"
        date = "2026-10-22"
        severity = "High"

    strings:
        // Opcode sequence: syscall (0F 05) ret (C3)
        $syscall_ret = { 0F 05 C3 }

        // Opcode sequence: sysenter (0F 34) ret (C3)
        $sysenter_ret = { 0F 34 C3 }

        // Common string references used in custom NTDLL resolvers
        $ntdll = "ntdll.dll" ascii wide nocase
        $str_alloc = "NtAllocateVirtualMemory" ascii
        $str_write = "NtWriteVirtualMemory" ascii
        $str_thread = "NtCreateThreadEx" ascii

    condition:
        uint16(0) == 0x5A4D and
        $ntdll and
        2 of ($str_*) and
        any of ($syscall_ret, $sysenter_ret)
}
```

---

## Edge Cases, False Positives, and Performance Realities

Implementing stack-based indirect syscall detection introduces operational edge cases that must be tuned to prevent performance bottlenecks and false positives.

### 1. Legitimate Binaries Bypassing Subsystem DLLs
Not all direct or non-standard calls into `ntdll.dll` are malicious:
- **Go Runtime Executables**: The Go programming language runtime does not use `kernel32.dll` or `KERNELBASE.dll` for all OS operations on Windows. Go handles low-level process and memory management by directly interacting with system calls or native API entry points.
- **Just-In-Time (JIT) Compilers**: Runtimes such as .NET (CLR), Java (JVM), and V8 (Chromium) dynamically generate executable code in heap memory (`PAGE_EXECUTE_READWRITE`). Stack traces originating from JIT memory segments will naturally appear as "unbacked" memory unless cross-referenced with JIT memory allocations registered by the runtime.
- **Anti-Cheat & DRM Software**: Video game anti-cheat engines (e.g., Easy Anti-Cheat, BattEye) heavily employ custom obfuscation, dynamic stack manipulation, and direct native calls to prevent reverse engineering and hooking by game cheats.

### 2. Performance Overhead of Kernel Stack Walking
Enabling full stack unwinding on every ETW-TI event across an entire enterprise endpoint fleet imposes significant CPU overhead. 

To mitigate performance degradation:
- Apply stack unwinding conditionally based on process risk profiles.
- Target high-risk native APIs (`NtCreateThreadEx`, `NtWriteVirtualMemory`, `NtMapViewOfSection`, `NtUnmapViewOfSection`) rather than high-frequency telemetry events (`NtReadFile`, `NtQueryInformationProcess`).
- Implement kernel-level filtering in driver code to drop telemetry processing early if the calling process is a trusted, hardcoded system binary operating with an unmodified signature.

### 3. Advanced Evasion: Stack Spoofing and Call Stack Duplication
Adversaries are aware that defenders analyze call stacks for indirect syscalls. Advanced frameworks (such as SilentMoonwalk or custom thread pool exploitation techniques) implement **synthetic stack spoofing**.

By unwinding, altering, and spoofing the x64 frame pointers before calling `jmp [syscall_gadget]`, adversaries craft synthetic frames that simulate a complete call sequence (`KernelBase -> ntdll`). 

Detecting synthetic stack spoofing requires deeper stack frame inspection, such as:
- Validating thread kernel stack memory boundaries (`InitialStack` vs. `StackLimit` in the Thread Environment Block / `ETHREAD`).
- Checking for discrepancies between the unwound stack frames and the actual CPU registers (`RSP`/`RBP`) recorded during the kernel callback.
- Checking whether return addresses in the stack map to non-executable memory or addresses that do not align with function boundary limits.

---

## Practical Defensive Checklist

To validate your security controls against direct and indirect system call techniques:

1. **Audit EDR Capabilities**: Test whether your endpoint agent relies solely on user-mode hooks or ingests kernel-level ETW-TI stack traces. Run test stubs utilizing indirect syscalls to verify if memory allocation and remote thread creation trigger alerts.
2. **Configure Kernel Telemetry Filtering**: Ensure ETW-TI events (specifically `KERNEL_THREATINT` providers) are actively captured and mapped to your SIEM/SOAR rules for remote thread creation and cross-process memory modification.
3. **Hunt for Stack Anomalies**: Query endpoint telemetry for processes executing critical native APIs where the stack trace lacks intermediary DLL frames or originates from executable memory pages that do not map to a signed PE file on disk.
4. **Implement Attack Surface Reduction (ASR)**: Combine stack telemetry with strict memory protection policies (e.g., Arbitrary Code Guard / ACG) to prevent executable memory allocation on dynamic stacks and heaps where direct/indirect syscall stubs reside.
