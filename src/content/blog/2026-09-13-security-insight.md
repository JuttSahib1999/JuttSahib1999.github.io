---
title: "Detecting Parent PID Spoofing and Command-Line Spoofing: Telemetry Gaps, ETW-Ti, and Detection Engineering"
description: "An in-depth technical analysis of how adversaries manipulate process metadata through PPID spoofing and PEB command-line modification, paired with detection strategies using kernel telemetry and process access events."
date: "2026-09-13"
tags: ["Cybersecurity", "Detection Engineering", "Endpoint Security", "Windows Internals"]
category: "Cyber Security"
difficulty: "Advanced"
author: "Abdul Muqeet Tabraiz"
image: "/images/blog/2026-09-13-detecting-parent-pid-spoofing-and-command-line-spoofing-telemetry-gaps-etw-ti-an.svg"
---

Most detection engineering rules targeting process execution rely on two fundamental operational assumptions: that process trees accurately reflect parent-child relationships, and that command-line telemetry captures the true arguments executed on host endpoints.

Adversaries routinely break both assumptions. By abusing native Windows APIs during process creation, an attacker can specify an arbitrary parent process (PPID spoofing) or alter the Process Environment Block (PEB) memory structure to disguise execution parameters (command-line spoofing). 

When these techniques are executed cleanly, standard event logs such as Windows Security Event ID 4688 or baseline Sysmon Event ID 1 can report misleading metadata, causing detection logic designed around process lineage or command-line string matching to fail.

Defenders need to understand the underlying mechanics of these techniques, where specific telemetry sources fail, and how kernel-level auditing (such as ETW-Ti) and handle access correlation allow us to detect them reliably.

---

## Technical Mechanics of PPID Spoofing

PPID spoofing takes advantage of features introduced in Windows Vista. When calling `CreateProcessW` or `CreateProcessAsUserW`, developers can pass explicit extended process attributes via the `STARTUPINFOEX` structure.

The workflow operates as follows:

1. The calling process obtains a handle to an existing process (e.g., `explorer.exe` or `lsass.exe`) with `PROCESS_CREATE_PROCESS` (Access Mask `0x0080`) rights.
2. The calling process initializes an attribute list using `InitializeProcThreadAttributeList`.
3. The attribute `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS` (Value `0x00020000`) is updated using `UpdateProcThreadAttribute`, pointing to the handle of the chosen parent process.
4. `CreateProcessW` is invoked with the `EXTENDED_STARTUPINFO_PRESENT` flag (Value `0x00080000`).

```cpp
// Simplified representation of PPID spoofing mechanics
STARTUPINFOEXA si;
PROCESS_INFORMATION pi;
SIZE_T attributeSize;

InitializeProcThreadAttributeList(NULL, 1, 0, &attributeSize);
si.lpAttributeList = (PPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attributeSize);
InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &attributeSize);

// hParentProcess is an open handle to a target parent like explorer.exe
UpdateProcThreadAttribute(
    si.lpAttributeList, 0, 
    PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, 
    &hParentProcess, sizeof(HANDLE), NULL, NULL
);

si.StartupInfo.cb = sizeof(STARTUPINFOEXA);

CreateProcessA(
    NULL, (LPSTR)"powershell.exe", NULL, NULL, FALSE, 
    EXTENDED_STARTUPINFO_PRESENT | CREATE_NEW_CONSOLE, 
    NULL, NULL, &si.StartupInfo, &pi
);
```

### Telemetry Discrepancies in PPID Spoofing

When this code executes, the Windows kernel creates the process object. However, there is a divergence between **User-Mode/Auditing Telemetry** and **Kernel Reality**:

* **Kernel Reality (Real Parent)**: The kernel thread executing the `NtCreateUserProcess` syscall belongs to the actual actor process (e.g., `malicious.exe`, PID 4412).
* **Explicit Parent (Spoofed Parent)**: The process handle supplied in `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS` (e.g., `explorer.exe`, PID 1024).

Standard user-mode monitoring tools and basic kernel process notifications using `PsSetCreateProcessNotifyRoutineEx` report the explicit parent declared in `STARTUPINFOEX`. Consequently, Event ID 4688 logs `explorer.exe` (PID 1024) as the Creator Process Name, masking the execution of `malicious.exe`.

---

## Technical Mechanics of Command-Line Spoofing

Command-line spoofing misdirects detection mechanisms that parse execution strings at startup. This technique targets the Process Environment Block (PEB) in memory.

When a process starts, parameters are stored in the PEB structure under `RTL_USER_PROCESS_PARAMETERS`:

$$\text{PEB} \longrightarrow \text{ProcessParameters} \longrightarrow \text{CommandLine} \; (\text{UNICODE\_STRING})$$

An adversary abuses this layout using the following sequence:

1. **Suspended Spawn**: The attacker calls `CreateProcessW` with the `CREATE_SUSPENDED` flag (Value `0x00000004`), supplying a **dummy, benign command line** (e.g., `powershell.exe -Help`).
2. **PEB Retrieval**: The attacker calls `NtQueryInformationProcess` with `ProcessBasicInformation` to locate the target process's remote PEB address.
3. **Memory Overwrite**: Using `ReadProcessMemory` and `WriteProcessMemory`, the attacker locates `PEB->ProcessParameters->CommandLine.Buffer` and overwrites the dummy argument string with the actual malicious payload string (e.g., `powershell.exe -enc aW52b2tl...`).
4. **Thread Resume**: The attacker calls `ResumeThread`.

```
[Attacker Process]
       │
       ├─── 1. CreateProcess("powershell.exe -Help", CREATE_SUSPENDED) ───► [New PowerShell Process]
       │                                                                            │
       ├─── 2. WriteProcessMemory(PEB->ProcessParameters->CommandLine) ────────────► (PEB updated to -enc ...)
       │                                                                            │
       └─── 3. ResumeThread() ──────────────────────────────────────────────────────► Executes malicious payload
```

### Telemetry Gaps in Command-Line Spoofing

The efficacy of command-line spoofing depends on *when* defensive telemetry samples the process memory:

* **Static Logging at API Boundary**: Providers that capture command-line parameters directly from the input arguments of `CreateProcess` (such as Windows Security Event ID 4688 or Sysmon Event ID 1) record the dummy string (`powershell.exe -Help`).
* **Runtime Execution**: When the main thread resumes, the application parses its own command line directly from its PEB address space, executing the updated malicious command.

Conversely, if an attacker creates a process with a *malicious* command line, allows the kernel to log it, and then quickly overwrites the PEB memory with a *benign* string post-creation, memory-scanning security tools interrogating the live PEB will observe only the benign string.

---

## Kernel Telemetry: ETW-Ti vs Standard ETW

To catch these evasions, defenders must rely on kernel-level providers that distinguish between the caller thread and requested process attributes.

The most critical provider for resolving PPID spoofing is **`Microsoft-Windows-Threat-Intelligence` (ETW-Ti)**. Unlike standard user-mode ETW or basic kernel process logging, ETW-Ti operates within the kernel space and is restricted to processes running with Early Launch Anti-Malware (ELAM) protection flags.

ETW-Ti emits the event `KERNEL_THREATINT_TASK_PROCESS_CREATE`. This trace contains fields that differentiate between the explicit request and the true execution context:

| ETW-Ti Field Name | Description | Value in Spoofed Execution |
| :--- | :--- | :--- |
| `ParentProcessId` | The process explicitly specified as the parent | `1024` (`explorer.exe`) |
| `CreatorProcessId` | The PID of the actual thread calling `NtCreateUserProcess` | `4412` (`malicious.exe`) |
| `ExecutingProcessId` | The newly spawned target process | `5892` (`powershell.exe`) |

When `ParentProcessId != CreatorProcessId`, PPID spoofing has occurred. Standard Windows Security Event 4688 lacks the `CreatorProcessId` separation, exposing a key telemetry gap when ETW-Ti telemetry is not ingested or evaluated by an EDR.

---

## Detection Strategies & Correlation Logic

Since ETW-Ti telemetry is often abstracted inside commercial EDR solutions, defenders can build high-fidelity rules by correlating complementary endpoint events: handle access telemetry, process creation events, and memory modifications.

### Strategy 1: Correlating Handle Access (Sysmon Event ID 10)

Before a process can perform PPID spoofing against a target parent (e.g., `lsass.exe`, `spoolsv.exe`, or `services.exe`), it must open a handle to that target with process creation rights. 

Using Sysmon Event ID 10 (`ProcessAccess`), we can detect suspicious processes requesting `PROCESS_CREATE_PROCESS` (Access Mask `0x0080`) or `PROCESS_ALL_ACCESS` (`0x1F0FFF`) against target binaries that do not typically act as handle sources for child spawns.

#### Sysmon Configuration Snippet:

```xml
<Sysmon configversion="4.50">
  <EventFiltering>
    <ProcessAccess onmatch="include">
      <!-- Capture access to sensitive processes with PROCESS_CREATE_PROCESS -->
      <Rule groupRelation="and">
        <TargetImage condition="end with">lsass.exe</TargetImage>
        <GrantedAccess condition="contains">0x0080</GrantedAccess>
      </Rule>
      <Rule groupRelation="and">
        <TargetImage condition="end with">spoolsv.exe</TargetImage>
        <GrantedAccess condition="contains">0x0080</GrantedAccess>
      </Rule>
      <Rule groupRelation="and">
        <TargetImage condition="end with">services.exe</TargetImage>
        <GrantedAccess condition="contains">0x0080</GrantedAccess>
      </Rule>
    </ProcessAccess>
  </EventFiltering>
</Sysmon>
```

### Strategy 2: Splunk Query for Handle Access vs Process Spawn Correlation

This search correlates process access events requesting cross-process handle access (`0x0080`) with subsequent process creation events where the target process claims to be a child of that same process within a short time window.

```spl
index=sysmon (EventCode=10 GrantedAccess="*0x0080*") OR EventCode=1
| eval JoinPID = if(EventCode==10, TargetProcessId, ParentProcessId)
| eval SourceActor = if(EventCode==10, SourceImage, ParentImage)
| eval CreatedProcess = if(EventCode==1, Image, null())
| stats 
    values(SourceImage) as AccessingProcess, 
    values(TargetImage) as TargetParent, 
    values(CreatedProcess) as SpawnedChild, 
    values(GrantedAccess) as AccessMask, 
    earliest(_time) as InitialTime, 
    latest(_time) as ExecutionTime 
    by JoinPID
| where isnotnull(AccessingProcess) AND isnotnull(SpawnedChild) AND AccessingProcess != TargetParent
| eval TimeDiff = ExecutionTime - InitialTime
| where TimeDiff >= 0 AND TimeDiff <= 5
| fields InitialTime, AccessingProcess, TargetParent, SpawnedChild, AccessMask
```

### Strategy 3: Detecting Command-Line Spoofing via Cross-Process Memory Writes

Command-line spoofing using suspended processes requires remote memory manipulation. When an adversary writes to a target PEB, the source process must open a handle to the target with `PROCESS_VM_WRITE` (`0x0020`) and `PROCESS_VM_OPERATION` (`0x0008`).

```
[Source: malware.exe] ──(OpenProcess: 0x0028)──► [Target: powershell.exe (Suspended)]
                                                          │
                                                WriteProcessMemory()
                                                          │
                                                  ResumeThread()
```

If your telemetry captures Sysmon Event ID 10 or kernel handle events, flag processes opening handles to newly created suspended processes with access masks containing `0x0028` (`PROCESS_VM_WRITE | PROCESS_VM_OPERATION`).

#### Sigma Rule: Cross-Process Memory Access to Suspended Children

```yaml
title: Potential Command-Line Spoofing via Remote PEB Modification
id: f4a298bc-2b9a-4c20-890d-3df3b879c9e1
status: experimental
description: Detects process access events where a non-system process requests VM modification rights on a child or target process shortly before thread execution.
logsource:
  product: windows
  service: sysmon
detection:
  selection:
    EventID: 10
    GrantedAccess|contains:
      - '0x0020'  # PROCESS_VM_WRITE
      - '0x0008'  # PROCESS_VM_OPERATION
  filter_legitimate:
    SourceImage|endswith:
      - '\devenv.exe'
      - '\msvsmon.exe'
      - '\CsEnabledService.exe'
    TargetImage|endswith:
      - '\conhost.exe'
  condition: selection and not filter_legitimate
falsepositives:
  - Software development environments (Visual Studio debugging sessions)
  - Native error reporting and crash dump generation utilities
level: high
```

---

## Operational Considerations and Detection Limitations

Deploying these detections requires balancing visibility against operational overhead.

### 1. High Volume of Sysmon Event ID 10
Monitoring process access events (`EventCode 10`) across an entire enterprise can generate massive log volumes. Filtering must target specific access masks (`0x0080`, `0x0020`) applied exclusively to sensitive target binaries (`lsass.exe`, `services.exe`, `smss.exe`, `svchost.exe`).

### 2. Legitimate Administrative and System Behaviors
Several native Windows processes legitimately use PPID spoofing or cross-process handle inheritance:
* **UAC Elevation (`consent.exe`)**: When a user elevates a process via UAC, `consent.exe` and `appinfo` service abstractions re-parent the elevated executable to `appinfo` or `svchost.exe`.
* **Windows Error Reporting (`WerFault.exe`)**: Spawns attached to failing processes to inspect memory handles.
* **Developer Toolchains**: Compilers and debuggers (`devenv.exe`, `msvsmon.exe`) frequently request `PROCESS_VM_WRITE` and manipulate thread structures directly.

### 3. Memory Verification Costs
Comparing static command-line parameters (captured during creation) against live PEB parameters via runtime querying (`NtQueryInformationProcess`) requires host-based agents or custom response scripts. Performing live memory parsing at scale can incur significant CPU and memory overhead on busy servers.

---

## Defensive Recommendations

1. **Deploy EDRs Utilizing ETW-Ti**: Ensure your endpoint protection vendor leverages the `Microsoft-Windows-Threat-Intelligence` provider to explicitly audit parent-child discrepancies (`CreatorProcessId` vs `ParentProcessId`).
2. **Audit Handle Request Patterns**: Focus Sysmon or EDR handle monitoring rules on rare access masks (`0x0080`, `0x0020`) targeting high-value processes.
3. **Avoid Pure String-Matching Rules**: Do not rely exclusively on command-line regex matches for detection. Combine command-line checks with process integrity levels, network connection events, and handle access history.
4. **Baseline Common Parent-Child Pairings**: Establish a baseline of expected parent-child execution paths within your environment to surface anomalous parents, regardless of whether spoofing was successful.
