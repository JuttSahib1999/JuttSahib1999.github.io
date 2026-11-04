---
title: "Detecting Unmanaged .NET Execution: ETW Telemetry, Assembly Loads, and Detection Engineering"
description: "An operational breakdown of how attackers execute C# tooling inside native processes via unmanaged CLR hosting, and how to detect it using ETW DotNETRuntime provider telemetry."
date: "2026-11-04"
tags: ["Cybersecurity", "Detection Engineering", "Threat Hunting", "Windows Telemetry"]
category: "Cyber Security"
difficulty: "Advanced"
author: "Abdul Muqeet Tabraiz"
image: "/images/blog/2026-11-04-detecting-unmanaged-net-execution-etw-telemetry-assembly-loads-and-detection-eng.svg"
---

Command-line logging and PowerShell Script Block Logging (Event ID 4104) made traditional PowerShell post-exploitation noisy and high-risk for red teams. In response, modern attack frameworks pivoted heavily toward managed code execution—specifically running C# assemblies entirely in memory through unmanaged Common Language Runtime (CLR) hosting.

Tools like Cobalt Strike’s `execute-assembly`, Donut, and various inline C# loaders allow an attacker to spawn a standard native Windows process (like `rundll32.exe`, `regsvr32.exe`, or `spoolsv.exe`) or inject into an existing one, manually instantiate the CLR, and execute compiled .NET binaries without ever writing an assembly to disk or spawning `powershell.exe`.

If your detection strategy relies solely on command-line arguments or process execution events (Sysmon Event ID 1 / Windows Event ID 4688), these execution techniques are completely invisible. This article explores how unmanaged CLR hosting operates under the hood, the precise telemetry required to observe it, and how to build high-fidelity detections using Event Tracing for Windows (ETW) while accounting for attacker evasions like user-land ETW patching.

---

## How Unmanaged CLR Hosting Works

To run a .NET assembly, Windows requires the Common Language Runtime (CLR)—the execution engine that manages memory, garbage collection, and thread execution for managed code. 

Normally, when a compiled .NET executable (like `app.exe`) starts, the Windows loader sees the CLR header in the PE structure and automatically initializes the runtime. However, a native, unmanaged binary (written in C or C++) can manually load and initialize the CLR programmatically using legitimate COM interfaces provided by Microsoft.

The standard execution chain for unmanaged hosting follows these stages:

```
[ Native Host Process ]
        │
        ├── 1. Load MetaHost DLL (mscoree.dll) via LoadLibrary
        │
        ├── 2. Invoke CLRCreateInstance() -> ICLRMetaHost
        │
        ├── 3. Query ICLRRuntimeInfo -> GetInterface(CLSID_CLRRuntimeHost)
        │
        ├── 4. Call ICLRRuntimeHost::Start()
        │
        ├── 5. Bind to default AppDomain -> Obtain System.AppDomain interface
        │
        └── 6. AppDomain.Load(byte[]) -> Invoke EntryPoint
```

1. **CLR Initialization**: The unmanaged process loads `mscoree.dll` and calls `CLRCreateInstance` to retrieve an `ICLRMetaHost` interface.
2. **Runtime Resolution**: The host queries the installed .NET versions on the system (e.g., `v4.0.30319`) and calls `ICLRRuntimeInfo::GetInterface` to instantiate `ICLRRuntimeHost`.
3. **Execution Engine Start**: Calling `ICLRRuntimeHost::Start()` initializes the execution engine within the native process's virtual memory space.
4. **AppDomain Allocation**: The native host retrieves a pointer to the default `AppDomain` using COM interface queries (`ICorRuntimeHost` or `AppDomainSetup`).
5. **In-Memory Loading**: Using `AppDomain.Load(SAFEARRAY pBytes)`, the process passes a byte array containing the compiled C# executable directly from memory.
6. **Execution**: The process resolves the entry point (`Main`) of the loaded assembly and executes it in memory.

Because the assembly is loaded directly from a byte array via `AppDomain.Load(byte[])`, no PE file touches the disk, no file-creation telemetry is triggered, and standard binary load events (`ImageLoad`) only report native CLR DLLs (`clr.dll`, `mscorlib.ni.dll`), not the C# assembly itself.

---

## The Telemetry Gap and ETW

Standard EDR hooks and process creation logs fall short when inspecting in-memory CLR execution:

* **Process Creation (Event ID 4688 / Sysmon 1)**: Shows `rundll32.exe` spawned with no command-line arguments or standard benign flags.
* **Image Load (Sysmon Event ID 7)**: Captures `clr.dll` or `mscoree.dll` loading into an unexpected process, but provides zero visibility into *what* C# code executed inside the runtime.

To get visibility inside the execution engine, defenders must tap into the runtime's own instrumentation provider: **`Microsoft-Windows-DotNETRuntime`** (GUID: `e13c0d23-ccbc-4e12-931b-d9cc2eee27e4`).

When the CLR loads an assembly, compiles Just-In-Time (JIT) code, or creates an `AppDomain`, it emits ETW events regardless of whether the host process is a native .NET application or an unmanaged host wrapper.

### Critical ETW Event IDs

To detect unmanaged hosting and in-memory execution, three specific ETW events from the `DotNETRuntime` provider are critical:

| Event ID | Event Name | Description | Key Fields to Monitor |
| :--- | :--- | :--- | :--- |
| **154** | `AssemblyLoad` | Emitted when an assembly is loaded into an AppDomain. | `AssemblyPath`, `FullyQualifiedAssemblyName`, `AppDomainID` |
| **143** | `ModuleLoad` | Emitted when a module within an assembly is loaded. | `ModuleILPath`, `ModuleNativePath`, `Guid` |
| **87** | `JITMethodLoadVerbose` | Emitted when the JIT compiler compiles a method to native code. | `MethodName`, `MethodNamespace`, `FullyQualifiedNamespace` |

When a standard .NET application runs from disk (e.g., `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe`), the `AssemblyPath` field in Event ID 154 contains the explicit file path on disk.

When an assembly is loaded in-memory via unmanaged CLR hosting (`AppDomain.Load(byte[])`), the runtime cannot resolve a disk location. As a result, `AssemblyPath` is either:
* Completely empty / blank
* Only contains the simple assembly name (e.g., `Seatbelt`, `Rubeus`, `SharpUp`)
* Set to a dynamic module identifier string

---

## Collecting DotNETRuntime ETW Telemetry

To operationalize this telemetry, you can capture events using native tools like `logman`, Sysmon (via ETW provider tracking in recent versions), or specialized telemetry agents like SilkETW, OpenTelemetry Collectors, or custom EDR components.

### Quick Verification via Logman

To verify what your system emits during an `execute-assembly` run, you can create a real-time ETW trace session targeting the `DotNETRuntime` provider:

```cmd
:: Create an ETW trace session targeting Assembly & Module loads
logman create trace DotNetTrace -o C:\PerfLogs\dotnet_trace.etl -p "{e13c0d23-ccbc-4e12-931b-d9cc2eee27e4}" 0x8 0x5

:: Start the trace
logman start DotNetTrace

:: [ Execute suspicious C# in-memory loader or test harness ]

:: Stop and flush the trace
logman stop DotNetTrace
```

*Note on Keywords*: Flags `0x8` maps to `AssemblyAndModuleNativeKeyword`, which specifically instructs the CLR provider to emit `AssemblyLoad` and `ModuleLoad` events. Combining this with keyword `0x10` (`JITTracingKeyword`) provides method-level detail, though at significantly higher event volume.

---

## Detection Engineering Strategies

Detecting unmanaged .NET hosting requires a multi-layered approach: pairing binary load anomalies (`ImageLoad`) with runtime assembly characteristics (`ETW AssemblyLoad`).

### Layer 1: Native Process Runtime Ingestion (ImageLoad Correlation)

Native processes that have no legitimate business requirement to host the CLR should rarely, if ever, load `clr.dll` or `mscoree.dll`.

Common target processes used by red teams for process injection or hosting include:
* `rundll32.exe`
* `regsvr32.exe`
* `svchost.exe`
* `spoolsv.exe`
* `explorer.exe`
* `verclsid.exe`

#### Sigma Rule Example: Unexpected CLR DLL Loading

```yaml
title: Unmanaged Process Loading CLR Runtime Architecture
id: d4e102f9-2c38-4e8a-a432-8232230a1120
status: experimental
description: Detects native Windows processes loading core .NET runtime libraries (clr.dll/mscorwks.dll), indicating potential unmanaged CLR hosting.
logsource:
  category: image_load
  product: windows
detection:
  selection:
    ImageLoaded|endswith:
      - '\clr.dll'
      - '\mscorwks.dll'
      - '\mscoreei.dll'
  filter_legitimate_parents:
    Image|startswith:
      - 'C:\Windows\Microsoft.NET\Framework'
      - 'C:\Windows\Microsoft.NET\Framework64'
      - 'C:\Program Files\dotnet\'
      - 'C:\Program Files (x86)\dotnet\'
  filter_known_hosts:
    Image|endswith:
      - '\mmc.exe'
      - '\Powershell.exe'
      - '\powershell_ise.exe'
      - '\pwsh.exe'
  condition: selection and not (filter_legitimate_parents or filter_known_hosts)
falsepositives:
  - Third-party management software written in C++ that hosts CLR for plugins.
level: high
```

### Layer 2: In-Memory Assembly Load Detection (ETW Telemetry)

When querying ETW telemetry directly (via SIEM or local agent), filter for `AssemblyLoad` events where the executable hosting the runtime is a native process, or where the loaded assembly lacks a valid path on disk.

#### KQL Query (Microsoft Sentinel / Defender for Endpoint via DeviceEvents)

```kql
// Detect in-memory Assembly loads in non-standard processes
DotNetRuntimeEvents
| where EventID == 154 // AssemblyLoad
| extend AssemblyName = parse_json(EventData).FullyQualifiedAssemblyName,
         AssemblyPath = parse_json(EventData).AssemblyPath,
         ProcessName  = parse_json(EventData).ProcessName
| where isempty(AssemblyPath) or AssemblyPath !has ":\\"
| where ProcessName !in~ ("powershell.exe", "pwsh.exe", "MSBuild.exe", "devenv.exe")
| project TimeGenerated, ProcessName, ProcessId, AssemblyName, AssemblyPath
```

If using raw ETW telemetry logs where `AssemblyPath` maps to an empty string, an empty `AssemblyPath` correlated with an explicit assembly identity like `Seatbelt, Version=0.0.0.0...` is a high-confidence indicator of in-memory execution.

```json
{
  "EventID": 154,
  "ProviderName": "Microsoft-Windows-DotNETRuntime",
  "ProcessId": 4812,
  "ProcessName": "rundll32.exe",
  "Payload": {
    "AssemblyID": "0x000001D21A4B9010",
    "AssemblyPath": "",
    "FullyQualifiedAssemblyName": "Seatbelt, Version=1.1.1.0, Culture=neutral, PublicKeyToken=null",
    "AppDomainID": "0x000001D218201A10"
  }
}
```

---

## Attacker Countermeasures: ETW Patching

As defense teams deployed ETW-based detections, red teams responded with ETW patching techniques. Because the `Microsoft-Windows-DotNETRuntime` provider runs inside the user-space context of the process hosting the CLR, the process has full write permissions to its own memory space.

### Mechanics of User-Land ETW Patching

ETW functions reside in `ntdll.dll`. When the CLR wants to emit an event, it calls functions like `EtwEventWrite` or `NtTraceEvent`.

An attacker executing inside an unmanaged host process can patch the entry point of `ntdll!EtwEventWrite` in memory prior to initializing the CLR:

```c
// Practical representation of an EtwEventWrite bypass patch
HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
void* pEtwEventWrite = GetProcAddress(hNtdll, "EtwEventWrite");

// Opcode for: xor eax, eax; ret (Return 0/STATUS_SUCCESS without executing)
unsigned char patch[] = { 0x31, 0xC0, 0xC3 };

DWORD oldProtect;
VirtualProtect(pEtwEventWrite, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProtect);
memcpy(pEtwEventWrite, patch, sizeof(patch));
VirtualProtect(pEtwEventWrite, sizeof(patch), oldProtect, &oldProtect);
```

Once `EtwEventWrite` is patched, subsequent calls by the CLR return instantly with a success code (`0`), effectively blinding any user-land ETW consumers (including SIEM agents relying on standard ETW subscriptions).

---

## Defensive Counter-Strategies

Defenders cannot rely solely on user-land ETW if attackers patch `ntdll.dll` before loading the CLR. To counter user-space patching, combine user-space events with kernel-level instrumentation and memory diagnostics.

### 1. Leverage Kernel-Level Telemetry (ETW Threat Intelligence)

While standard `DotNETRuntime` events are generated in user space, the Windows Kernel also maintains the `Microsoft-Windows-Threat-Intelligence` (ETW TI) provider. ETW TI runs in kernel space (Ring 0) and cannot be bypassed by user-land memory patching in `ntdll.dll`.

ETW TI captures memory allocations, protection changes (`VirtualProtect`), and remote thread creation. Look for:
* Memory allocations inside native processes changing to `PAGE_EXECUTE_READWRITE` (0x40) followed by execution.
* Direct calls to `NtProtectVirtualMemory` targeting `ntdll.dll` memory ranges (indicating ETW or API patching attempts).

### 2. Monitor for Memory Patching Operations

Detecting the modification of `ntdll.dll` itself provides a high-fidelity meta-detection. benign applications almost never modify the execution code of core system DLLs loaded in their address space.

* **EDR Memory Scanning**: Modern EDRs periodically scan module headers in running processes to detect deviations between in-memory DLL text sections (`.text`) and the corresponding binary on disk.
* **YARA on Process Memory**: Execute periodic or triggered scans targeting modified prologues in `EtwEventWrite` or `EtwEventWriteFull`.

#### YARA Rule: Detecting Patched EtwEventWrite

```yara
rule Detect_EtwEventWrite_Patch {
    meta:
        description = "Detects patched EtwEventWrite in process memory (xor eax, eax; ret)"
        author = "Abdul Muqeet Tabraiz"
        scope = "memory"
    strings:
        // xor eax, eax (31 c0) or xor rax, rax (48 31 c0) followed by ret (c3)
        $patch_x86   = { 31 c0 c3 }
        $patch_x64   = { 48 31 c0 c3 }
        $patch_mov   = { b8 00 00 00 00 c3 } // mov eax, 0; ret
    condition:
        any of them
}
```

### 3. Track Process Integrity and Host Mismatches

If an attacker successfully patches user-land ETW and suppresses `AssemblyLoad` events, you can still catch the execution by monitoring process creation anomalies:

1. **Parent-Child Inconsistencies**: Native binaries like `spoolsv.exe` or `lsass.exe` spawning outbound network connections (C2 channels).
2. **Suspicious Thread Executions**: Threads created in unbacked memory regions (memory allocated via `VirtualAlloc` without an associated file mapping on disk).

---

## Operational Considerations and Performance Trade-offs

Enabling `.NET` runtime tracing across an enterprise requires careful planning due to potential volume and performance impacts.

1. **Volume Management**:
   * Enabling `JITTracingKeyword` (0x10) emits an event for *every single method* compiled by the CLR. On a enterprise network, this will generate gigabytes of logs per endpoint daily.
   * **Recommendation**: Restrict continuous logging to `AssemblyAndModuleNativeKeyword` (0x8). This captures high-value `AssemblyLoad` events (Event ID 154) with minimal overhead.

2. **Scoping High-Value Targets**:
   * If broad deployment is limited by log licensing costs, deploy `DotNETRuntime` ETW monitoring selectively to high-risk native binaries (`rundll32.exe`, `regsvr32.exe`, `wmic.exe`, `mshta.exe`, `powershell.exe`) or core tier-0 assets (Domain Controllers, Privileged Access Workstations).

3. **Telemetry Pipeline Architecture**:

```
[ Process Space ]              [ Endpoint Agent ]             [ SIEM / Data Lake ]
┌─────────────────────────┐    ┌─────────────────────────┐    ┌────────────────────┐
│ Unmanaged Host Exec     │    │ ETW Consumer Engine     │    │ High-Fidelity Alert│
│                         │    │ (e.g., Sysmon / Agent)  │    │                    │
│  ├── clr.dll Loaded     ├────┼─► Sysmon Event ID 7     ├────┼─► DLL Anomaly Rule │
│  │                      │    │                         │    │                    │
│  └── Assembly.Load()    ├────┼─► ETW ID 154            ├────┼─► In-Memory Load   │
│      (Blank AssemblyPath)│    │   (DotNETRuntime)       │    │   Correlation      │
└─────────────────────────┘    └─────────────────────────┘    └────────────────────┘
```

By correlating native DLL loads (`clr.dll`) with ETW assembly events missing on-disk file paths, security operations teams can catch managed post-exploitation tooling regardless of how deeply wrapped or obfuscated the launcher is.
