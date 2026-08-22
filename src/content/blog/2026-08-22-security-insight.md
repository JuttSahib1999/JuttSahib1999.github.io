---
title: "Detecting LSASS Memory Access: Telemetry, Access Masks, and Detection Logic"
description: "A practical guide to detecting credential dumping against LSASS using Sysmon Event ID 10, Windows Security Auditing, and access mask telemetry."
date: "2026-08-22"
tags: ["Cybersecurity", "Detection Engineering", "Threat Detection", "Windows Security"]
category: "Cyber Security"
difficulty: "Intermediate"
author: "Abdul Muqeet Tabraiz"
image: "/images/blog/2026-08-22-detecting-lsass-memory-access-telemetry-access-masks-and-detection-logic.svg"
---

Once an attacker gains local administrator privileges on a Windows endpoint, their next logical step is usually credential harvest for lateral movement. The Local Security Authority Subsystem Service (`lsass.exe`) remains one of the primary targets because it holds active logon sessions, Kerberos tickets, NTLM hashes, and sometimes cleartext credentials in memory.

While endpoint detection and response (EDR) platforms frequently block known dumpers like Mimikatz or `procdump.exe`, adversaries routinely pivot to built-in binaries (`comsvcs.dll`), custom memory-dumping utilities, or reflective DLLs that evade signature-based alerts. 

To detect these attempts reliably, defenders need to look past process execution strings and analyze handle creation telemetry at the system level. This article explores how handle access works against LSASS, how to read access masks, and how to construct high-fidelity detections using Sysmon and native Windows event logs.

---

## How LSASS Memory Access Works

To extract credentials from LSASS memory, a process executing in user space must perform three main actions:

1. Obtain a handle to `lsass.exe` via Win32 API calls such as `OpenProcess` or `NtOpenProcess`.
2. Request specific process access rights that allow memory reading.
3. Pass that handle to a memory dumping function (such as `MiniDumpWriteDump` inside `dbghelp.dll`) or manually iterate over memory regions using `ReadProcessMemory` / `NtReadVirtualMemory`.

To issue a handle to `lsass.exe`, the requesting process almost always requires elevated privileges—specifically `SeDebugPrivilege`. Standard user processes cannot open handles to LSASS with memory-reading access rights.

### Access Masks Explained

When a process calls `OpenProcess`, it passes a bitmask specifying the desired access rights (`DesiredAccess`). Windows checks this request against the security descriptor of the target process. If granted, the system records the resulting rights as the `GrantedAccess` mask in event logs.

Here are the key process access rights associated with LSASS access and credential dumping:

| Access Right | Hex Value | Description |
| :--- | :--- | :--- |
| `PROCESS_TERMINATE` | `0x0001` | Required to terminate a process. |
| `PROCESS_CREATE_THREAD` | `0x0002` | Required to create a thread in the process. |
| `PROCESS_VM_OPERATION` | `0x0008` | Required to perform operations on the virtual memory space. |
| `PROCESS_VM_READ` | `0x0010` | Required to read memory in the process using `ReadProcessMemory`. |
| `PROCESS_VM_WRITE` | `0x0020` | Required to write memory in the process. |
| `PROCESS_DUP_HANDLE` | `0x0040` | Required to duplicate a handle using `DuplicateHandle`. |
| `PROCESS_QUERY_INFORMATION` | `0x0400` | Required to query process information (token, exit code, path). |
| `PROCESS_SUSPEND_RESUME` | `0x0800` | Required to suspend or resume a process. |
| `PROCESS_QUERY_LIMITED_INFORMATION` | `0x1000` | Subset of `PROCESS_QUERY_INFORMATION`. |
| `PROCESS_ALL_ACCESS` | `0x1F0FFF` | All possible access rights for a process object. |

When tools attempt to dump LSASS memory, they typically request a combination of `PROCESS_VM_READ` (`0x0010`) alongside query permissions (`0x0400` or `0x1000`).

Common `GrantedAccess` masks seen in credential dumping telemetry include:

*   **`0x1410`** (`PROCESS_VM_READ` | `PROCESS_QUERY_INFORMATION` | `PROCESS_QUERY_LIMITED_INFORMATION`): A classic access mask used by dumping routines (e.g., standard `MiniDumpWriteDump` calls).
*   **`0x1010`** (`PROCESS_VM_READ` | `PROCESS_QUERY_LIMITED_INFORMATION`): Minimal read access required to extract memory streams.
*   **`0x143A`** (`PROCESS_VM_READ` | `PROCESS_VM_WRITE` | `PROCESS_VM_OPERATION` | `PROCESS_QUERY_INFORMATION` | `PROCESS_CREATE_THREAD`): Often seen when tools attempt process injection alongside memory access.
*   **`0x1F0FFF`**: Full access, requested by tools that simply ask for maximum privileges without masking their request down.

---

## Telemetry Sources for LSASS Access

To observe process handle activity directed at LSASS, two main telemetry sources provide the required detail: **Sysmon Event ID 10** and **Windows Security Event ID 4656**.

### 1. Sysmon Event ID 10 (ProcessAccess)

Sysmon ID 10 is the most effective native telemetry source for process handle auditing. It records when a process opens a handle to another process, capturing both the requesting binary (`SourceImage`) and the target binary (`TargetImage`), along with the granted access mask and call trace.

Here is a redacted Sysmon Event ID 10 log representing a suspicious handle request to LSASS:

```xml
EventData
  RuleName: Technic-CredentialDumping
  UtcTime: 2026-08-22 14:15:32.102
  SourceProcessGuid: {A1B2C3D4-5678-90AB-CDEF-1234567890AB}
  SourceProcessId: 4820
  SourceImage: C:\Windows\System32\rundll32.exe
  TargetProcessGuid: {A1B2C3D4-0000-00AB-0000-000000000000}
  TargetProcessId: 672
  TargetImage: C:\Windows\System32\lsass.exe
  GrantedAccess: 0x1410
  CallTrace: C:\Windows\SYSTEM32\ntdll.dll+9d5c4|C:\Windows\System32\KERNELBASE.dll+2c12a|C:\Windows\System32\comsvcs.dll+1a420|UNKNOWN(00007FF81A2B0000)
```

#### Key Fields to Analyze:
*   `SourceImage`: The process opening the handle (e.g., `rundll32.exe`, `powershell.exe`, or an unknown executable running out of `C:\Users\...\AppData`).
*   `TargetImage`: The process being accessed (`C:\Windows\System32\lsass.exe`).
*   `GrantedAccess`: The exact access rights granted.
*   `CallTrace`: The stack trace leading to the handle creation request. This field is valuable for detecting in-memory attacks where an unbacked memory region (`UNKNOWN`) calls `OpenProcess`.

### 2. Windows Event ID 4656 (Handle to Object Requested)

If Sysmon is unavailable, standard Windows Auditing can log handle requests if audit policies for **Kernel Object Access** are configured and an SACL is set on the LSASS process object (or global process auditing is enabled).

Event ID 4656 provides:
*   `SubjectSecurityID` / `SubjectProcessId`
*   `ObjectName` (e.g., `\Device\HarddiskVolume3\Windows\System32\lsass.exe`)
*   `AccessMask` (Hexadecimal mask)
*   `ProcessName` (The requesting executable)

While 4656 yields similar information, it lacks the `CallTrace` field, making it harder to differentiate between signed binaries executing normal tasks and signed binaries hijacked via reflective DLL injection.

---

## Analyzing the Call Trace

The `CallTrace` field in Sysmon Event ID 10 tracks the DLLs and functions involved in requesting the handle. Legitimate applications opening handles to LSASS (such as antivirus agents, EDR components, or system services) typically exhibit a structured call trace composed entirely of signed, disk-backed system modules.

An example of a legitimate call trace from Windows Defender (`MsSense.exe`):

```text
C:\Windows\SYSTEM32\ntdll.dll+9cbf4|C:\Windows\System32\KERNELBASE.dll+2c12a|C:\ProgramData\Microsoft\Windows Defender Advanced Threat Protection\Classification\Engine\...
```

An suspicious call trace often displays one of two anomalies:

1.  **Unbacked Memory Execution**: The trace includes `UNKNOWN` modules. This occurs when an attacker executes shellcode or a reflective DLL directly in memory without writing the binary to disk.
    ```text
    C:\Windows\SYSTEM32\ntdll.dll+9d5c4|C:\Windows\System32\KERNELBASE.dll+2c12a|UNKNOWN(00007FF7A0000000)
    ```
2.  **Abnormal Module Invocations**: Execution of administrative DLLs known for credential operations, such as `comsvcs.dll` invoked by non-standard hosts.

---

## Detection Engineering & Rule Development

To build robust detections around LSASS access, we must combine `TargetImage`, `GrantedAccess`, and binary path filtering while expecting baseline noise from legitimate system processes.

### Detection Strategy 1: Non-Standard Binaries Requesting Read Access

The baseline detection logic flags any process accessing `lsass.exe` with `PROCESS_VM_READ` (`0x0010`) or `PROCESS_VM_WRITE` (`0x0020`) permissions, excluding known-good administrative processes and security software.

#### Sigma Rule Example

```yaml
title: Suspicious LSASS Process Access via Sysmon
id: 5f98a3b1-2e4a-4a89-912f-98bc211029df
status: experimental
description: Detects process access to lsass.exe with VM_READ privileges from untrusted binaries.
author: Abdul Muqeet Tabraiz
date: 2026-08-22
logsource:
  category: process_access
  product: windows
detection:
  selection:
    TargetImage|endswith: '\lsass.exe'
    GrantedAccess|contains:
      - '0x0010'
      - '0x1410'
      - '0x1010'
      - '0x1F0FFF'
  filter_legitimate:
    SourceImage|endswith:
      - '\system32\svchost.exe'
      - '\system32\csrss.exe'
      - '\system32\lsass.exe'
      - '\system32\wininit.exe'
      - '\Program Files\Windows Defender\MsMpEng.exe'
      - '\Program Files\Microsoft Security Client\MsMpEng.exe'
  condition: selection and not filter_legitimate
falsepositives:
  - Third-party AV/EDR agents not included in the filter.
  - Performance monitoring and management tools.
level: high
```

### Detection Strategy 2: Call Trace Anomaly Detection

Attackers often leverage process hollowing or DLL side-loading to disguise the `SourceImage` as a trusted binary (like `svchost.exe`). Filtering purely on `SourceImage` allows these techniques to bypass detections. 

By querying for handles where `CallTrace` contains `UNKNOWN`, we can catch memory-resident payloads regardless of the parent image name.

#### Splunk Searching Query Example

```spl
index=sysmon EventCode=10 TargetImage="*\\lsass.exe"
| eval SuspiciousAccess=if(match(GrantedAccess, "(?i)0x1410|0x1010|0x1f0fff|0x143a"), "Yes", "No")
| where SuspiciousAccess="Yes"
| search CallTrace="*UNKNOWN*"
| table _time, Computer, SourceImage, TargetImage, GrantedAccess, CallTrace
```

This query isolates requests targeting LSASS where memory reading rights were requested AND the stack trace includes unbacked memory regions (`UNKNOWN`).

---

## Common Noise Sources and Triage Workflows

When implementing these rules in a live environment, analysts will encounter noise. Tuning requires understanding which legitimate processes need broad access to LSASS.

### Common Baseline False Positives
1. **Security Tools**: EDR agents, local antivirus scanners, and identity protection tools inspect LSASS handles to verify security state or capture audit events.
2. **Management Infrastructure**: Tools like VMware Tools, Microsoft Endpoint Configuration Manager (SCCM), and system monitoring agents (`monitoringhost.exe`).
3. **Password Filter / Authentication Packages**: Custom LSA plugin binaries loaded directly by `lsass.exe`.

### Triage Workflow for High-Risk Alerts

When an analyst receives an alert for LSASS process access:

```
[LSASS Access Alert Triggered]
          │
          ├──> 1. Check SourceImage
          │       │
          │       ├── Is it a standard shell (powershell.exe, cmd.exe, rundll32.exe)? 
          │       │   └── HIGH SUSPICION: Verify command-line telemetry (Sysmon ID 1 / Event ID 4688).
          │       │
          │       └── Is it a known administrative tool (procdump.exe, taskmgr.exe)?
          │           └── MEDIUM-HIGH SUSPICION: Check user context and authorization.
          │
          ├──> 2. Inspect GrantedAccess Mask
          │       │
          │       └── Does it contain 0x1410, 0x1010, or 0x1F0FFF?
          │           └── Indicates direct memory read attempts.
          │
          ├──> 3. Examine CallTrace
          │       │
          │       └── Are there unbacked modules (UNKNOWN)?
          │           └── HIGH SUSPICION: Indicates reflective payload or process injection.
          │
          └──> 4. Correlate Secondary Indicators
                  │
                  ├── File Creation: Look for .dmp or .tmp files created shortly after the event.
                  └── User Privileges: Was the source process executing under SYSTEM or elevated Admin?
```

---

## Evasion Techniques and Telemetry Gaps

While process access auditing is powerful, detection engineers must recognize its operational limitations.

### 1. Handle Duplication
Instead of opening a new handle to `lsass.exe` via `OpenProcess`, an attacker with sufficient privileges can scan existing open handles across the operating system (using `NtQuerySystemInformation`). If an existing process (like an AV agent) already holds a high-privilege handle to LSASS, the attacker can duplicate that handle via `DuplicateHandle`. 

*Impact*: Depending on the Sysmon version and OS configuration, handle duplication may not trigger a standard `ProcessAccess` event in the same manner as `OpenProcess`.

### 2. Direct Kernel Callbacks & Vulnerable Drivers (BYOVD)
Attackers exploiting Bring Your Own Vulnerable Driver (BYOVD) tactics load a signed kernel driver to strip user-mode callbacks or read physical memory directly. Kernel-level memory extraction bypasses user-mode Win32 APIs entirely, rendering Sysmon ID 10 blind to the read operation.

### 3. Protected Process Light (PPL)
If LSASS is configured to run as a Protected Process Light (RunAsPPL), Windows restricts non-PPL processes from obtaining handles with `PROCESS_VM_READ` access, even if the caller is running as `NT AUTHORITY\SYSTEM`. Attackers must first bypass PPL (e.g., using a driver to unhook PPL flags in kernel memory) before extracting memory.

---

## Defensive Recommendations

Detecting handle access is only part of an effective defensive posture. To reduce reliance on detection engineering alone, apply these structural hardening controls:

1. **Enable LSA Protection (RunAsPPL)**:
   Configure LSASS to run as a protected process via Group Policy or Registry:
   * Key: `HKLM\SYSTEM\CurrentControlSet\Control\Lsa`
   * Value: `RunAsPPL` (DWORD = `1` or `2` for audit mode)
   This prevents non-protected processes from opening read handles to LSASS memory.

2. **Enable Windows Defender Credential Guard**:
   Credential Guard uses virtualization-based security (VBS) to isolate NTLM hashes and Kerberos tickets in a virtualized container (`lsaiso.exe`), preventing even processes with direct LSASS read access from extracting secrets.

3. **Restrict Debug Privileges (`SeDebugPrivilege`)**:
   By default, local administrators hold `SeDebugPrivilege`. Remove local administrative rights for standard users and use explicit policies to limit privilege assignment.

4. **Tune Sysmon Configuration Filters**:
   Ensure your Sysmon configuration explicitly includes handle audits for `lsass.exe`. Below is a baseline Sysmon configuration snippet:

```xml
<Sysmon schemaversion="4.90">
  <EventFiltering>
    <ProcessAccess onmatch="include">
      <TargetImage condition="is">C:\Windows\System32\lsass.exe</TargetImage>
    </ProcessAccess>
    <ProcessAccess onmatch="exclude">
      <SourceImage condition="is">C:\Windows\System32\svchost.exe</SourceImage>
      <SourceImage condition="is">C:\Windows\System32\lsass.exe</SourceImage>
      <SourceImage condition="is">C:\Windows\System32\csrss.exe</SourceImage>
    </ProcessAccess>
  </EventFiltering>
</Sysmon>
```

---

## Summary

Dumping LSASS memory remains a fundamental technique for post-compromise lateral movement. While tools and execution wrappers change, the underlying operating system requirements to access process memory remain consistent. 

By collecting process access telemetry, decoding GrantedAccess bitmasks, and inspecting CallTrace stacks, security operations teams can detect credential dumping attempts reliably—even when attackers rely on obfuscated scripts or living-off-the-land binaries. Pairing these detection strategies with LSA Protection and Credential Guard provides defense-in-depth against credential theft.
