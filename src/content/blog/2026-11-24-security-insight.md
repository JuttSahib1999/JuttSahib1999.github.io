---
title: "Detecting LSASS Memory Dumping: Telemetry, Handle Creation, and Event Log Auditing"
description: "Learn how attackers extract credentials from LSASS memory, what telemetry signals indicate credential dumping, and how to build resilient detection rules using Sysmon and Windows Event Logs."
date: "2026-11-24"
tags: ["Detection Engineering", "Endpoint Security", "Windows Security", "SIEM"]
category: "Cyber Security"
difficulty: "Intermediate"
author: "Abdul Muqeet Tabraiz"
image: "/images/blog/2026-11-24-detecting-lsass-memory-dumping-telemetry-handle-creation-and-event-log-auditing.svg"
---

Once an attacker gains initial access and escalates privileges on a Windows endpoint, their immediate goal is usually lateral movement. To move across the network, they need valid credentials. The Local Security Authority Subsystem Service (`lsass.exe`) is the primary target for this phase because it manages user authentication tokens, Kerberos tickets, and cached NTLM password hashes in system memory.

Even with modern endpoint detection and response (EDR) tools deployed, adversaries frequently attempt to dump LSASS memory using native utilities, custom scripts, or specialized tooling. As security analysts and detection engineers, understanding how processes interact with LSASS—and how to spot abnormal access patterns—is critical for catching intrusions before lateral movement scales.

---

## What LSASS Dumping Is and Why It Happens

`lsass.exe` is a core Windows system process running in user mode with `NT AUTHORITY\SYSTEM` privileges. It handles local security policy enforcement, domain authentication, and user password changes. To process authentication requests without repeatedly asking the user for credentials, Windows caches sensitive security data inside the memory space of `lsass.exe`.

This memory space can contain:

- **NTLM hashes** for local and domain accounts
- **Kerberos tickets** (TGTs and service tickets)
- **Cleartext passwords** (if legacy authentication providers like WDigest are enabled or improperly configured)

LSASS memory dumping occurs when a process running with administrative privileges (specifically `SeDebugPrivilege`) opens a handle to `lsass.exe`, reads its virtual memory, and writes that data to a dump file on disk or streams it directly across the network.

---

## Technical Mechanics: How Attackers Access LSASS

To dump LSASS memory, an offensive tool typically follows a specific Win32 API call sequence:

1. **Enable Debug Privileges:** The process calls `OpenProcessToken` and `AdjustTokenPrivileges` to acquire `SeDebugPrivilege`.
2. **Obtain Process ID (PID):** The tool enumerates running processes using `CreateToolhelp32Snapshot` or `EnumProcesses` to find `lsass.exe`.
3. **Open Process Handle:** The process calls `OpenProcess` to request a handle to `lsass.exe` with specific memory access rights.
4. **Read or Dump Memory:** The tool executes `MiniDumpWriteDump` (from `dbghelp.dll` or `comsvcs.dll`) or reads the memory directly using `ReadProcessMemory`.

### Access Masks to Monitor

When a process calls `OpenProcess` against LSASS, Windows checks the requested permissions (Access Mask). Common rights requested during credential dumping include:

| Access Right | Hex Value | Description |
| :--- | :--- | :--- |
| `PROCESS_VM_READ` | `0x0010` | Allows reading memory within the process. |
| `PROCESS_QUERY_INFORMATION` | `0x0400` | Allows retrieving process metadata. |
| `PROCESS_VM_OPERATION` | `0x0008` | Allows modifying memory space (often paired with read/write). |
| `PROCESS_ALL_ACCESS` | `0x1F0FFF` | Grants complete access to the process object. |

When combined, common suspicious GrantedAccess masks sent to LSASS include:

- **`0x1010`** (`PROCESS_VM_READ` | `PROCESS_QUERY_INFORMATION`)
- **`0x1410`** (`PROCESS_VM_READ` | `PROCESS_QUERY_INFORMATION` | `PROCESS_QUERY_LIMITED_INFORMATION`)
- **`0x1F0FFF`** (`PROCESS_ALL_ACCESS`)

Understanding these masks helps us separate legitimate system interactions from suspicious handle requests.

---

## Execution Methods: Native Utilities vs. Custom Tooling

Attackers rely on several techniques to dump LSASS. Recognizing the execution vector determines whether detection relies on command-line parameters or process access telemetry.

### 1. Native Binaries (Living off the Land)
Adversaries often leverage native Windows binaries to avoid dropping custom malware to disk:

- **Rundll32 with Comsvcs.dll:** Calls the exported `MiniDump` function directly.
  ```cmd
  rundll32.exe C:\windows\system32\comsvcs.dll, MiniDump <LSASS_PID> C:\Windows\Tasks\lsass.dmp full
  ```
- **Task Manager:** Administrators can right-click `lsass.exe` in Task Manager and select "Create dump file". Attackers abusing compromised GUI sessions or RDP will use this exact feature.
- **ProcDump (Sysinternals):** A legitimate Microsoft tool often abused by adversaries.
  ```cmd
  procdump.exe -ma lsass.exe lsass.dmp
  ```

### 2. Specialized Offensive Tools
Tools like Mimikatz (`sekurlsa::minidump`), Out-Minidump, and lsassy open handles to LSASS directly or automate the extraction and transfer of dump files.

---

## Telemetry Sources for LSASS Dumping Detection

To detect LSASS memory dumping effectively, rely on two main data streams: **Process Creation Telemetry** (for command-line abuse) and **Process Access Telemetry** (for direct handle creation).

### Source 1: Sysmon Event ID 10 (ProcessAccess)
Sysmon Event ID 10 logs when a process opens a handle to another process. This is the single most valuable telemetry event for detecting direct memory extraction.

Key fields to inspect:
- `SourceImage`: The executable requesting access (e.g., `C:\Windows\System32\rundll32.exe`, `C:\Temp\unknown.exe`).
- `TargetImage`: Should equal `C:\Windows\System32\lsass.exe`.
- `GrantedAccess`: The bitmask of permissions requested.
- `CallTrace`: The stack trace showing which DLLs and functions initiated the handle request.

#### Example Sysmon Event ID 10 Log:
```xml
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <EventID>10</EventID>
    <TimeCreated SystemTime="2026-11-24T14:22:05.1234567Z"/>
    <Computer>WORKSTATION01.corp.internal</Computer>
  </System>
  <EventData>
    <Data Name="SourceImage">C:\Users\Public\procdump.exe</Data>
    <Data Name="TargetImage">C:\Windows\System32\lsass.exe</Data>
    <Data Name="GrantedAccess">0x1f0fff</Data>
    <Data Name="CallTrace">C:\Windows\SYSTEM32\ntdll.dll+9d1a4|C:\Windows\System32\KERNELBASE.dll+2c744|C:\Users\Public\procdump.exe+5a12</Data>
  </EventData>
</Event>
```

### Source 2: Windows Security Event ID 4656 / 4663 (Handle Requests)
If Windows Audit Handle Manipulation is enabled in your Group Policy, Security Event ID 4656 (A handle to an object was requested) records process access attempts.

Key fields:
- `ObjectName`: `\Device\HarddiskVolume2\Windows\System32\lsass.exe`
- `ProcessName`: The initiating process executable path.
- `AccessMask`: The hexadecimal representation of permissions requested.

*Note: Enabling audit handle manipulation domain-wide generates significant log volume. Restrict auditing to core sensitive system processes if log storage is constrained.*

### Source 3: Sysmon Event ID 1 / Windows Security Event ID 4688 (Process Creation)
Process creation logs capture Living-off-the-Land execution vectors like `rundll32.exe` executing `comsvcs.dll` or `procdump.exe` being invoked from the command line.

---

## Building Practical Detection Rules

Relying on a single detection logic isn't sufficient. Combine process creation alerts for known command lines with handle manipulation rules for generic tool usage.

### Detection 1: KQL Query for Sysmon ProcessAccess (ID 10)
This query flags non-standard processes requesting memory read permissions against LSASS.

```kql
Sysmon_CL
| where EventID == 10
| where TargetImage =~ @"C:\Windows\System32\lsass.exe"
| where GrantedAccess in ("0x1010", "0x1410", "0x1f0fff", "0x1400")
| where not(SourceImage in~ (
    @"C:\Windows\System32\svchost.exe",
    @"C:\Windows\System32\csrss.exe",
    @"C:\Windows\System32\wininit.exe",
    @"C:\Program Files\Microsoft Security Client\Antimalware\MsMpEng.exe",
    @"C:\Program Files\Windows Defender\MsMpEng.exe"
))
| project TimeGenerated, Computer, User, SourceImage, TargetImage, GrantedAccess, CallTrace
```

### Detection 2: Sigma Rule for Comsvcs DLL LSASS Dumping
This Sigma rule identifies instances where `rundll32.exe` invokes `comsvcs.dll` to dump memory.

```yaml
title: LSASS Memory Dump via Comsvcs DLL
id: a9d841b8-6d27-4a11-9a72-7634f1e9c803
status: stable
description: Detects process creation of rundll32 loading comsvcs.dll with minidump arguments to dump LSASS memory.
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\rundll32.exe'
    CommandLine|contains|all:
      - 'comsvcs'
      - 'minidump'
  condition: selection
falsepositives:
  - Rare diagnostic scripts run by enterprise system administrators.
level: high
tags:
  - attack.credential_access
  - attack.t1003.001
```

---

## Investigation Workflow: Triaging an Alert

When an alert triggers indicating potential LSASS access, follow a structured investigation workflow:

```
[ Alert Triggered: Process Access / Command Line ]
                       │
                       ▼
         ┌───────────────────────────┐
         │ Analyze Source Executable │
         └─────────────┬─────────────┘
                       │
       ┌───────────────┴───────────────┐
       ▼                               ▼
[ Signed / Known Tool ]       [ Unsigned / Suspicious ]
       │                               │
       ▼                               ▼
Verify parent process          Inspect process ancestry,
and execution path             network connections, and 
(e.g., ProcDump via Admin)     file modifications (.dmp)
       │                               │
       └───────────────┬───────────────┘
                       │
                       ▼
       ┌───────────────────────────────┐
       │ Check CallTrace & File Writes │
       └───────────────┬───────────────┘
                       │
                       ▼
       ┌───────────────────────────────┐
       │ Determine Scope & Isolate Host│
       └───────────────────────────────┘
```

1. **Verify Source Binary Integrity:**
   - Is the `SourceImage` running from an expected system folder (e.g., `C:\Windows\System32`) or a staging path like `C:\Users\Public\` or `C:\ProgramData\`?
   - Check digital signatures. Attackers frequently rename utilities or compile custom loaders.

2. **Inspect Process Ancestry (Parent Process):**
   - Did `rundll32.exe` or `cmd.exe` originate from `wmiPrvSE.exe`, `psexesvc.exe`, or an unknown PowerShell process? Parent processes associated with remote management tools often signal lateral movement.

3. **Look for File Artifacts:**
   - Check endpoint file write logs for large `.dmp`, `.tmp`, or `.bin` files created shortly after the process access event in directories like `C:\Windows\Tasks\`, `C:\Users\Public\`, or `C:\Windows\Temp\`.

4. **Review Network Telemetry:**
   - Did the source process make outbound SMB (`445`), HTTP (`80`/`443`), or non-standard port connections immediately before or after the handle request? This indicates potential live memory streaming without writing a dump file to disk.

---

## Limitations and Defensive Engineering Mitigations

Detection telemetry is critical, but preventing LSASS access at the kernel layer reduces reliance on alerting alone.

### Common Detection Evasion Tactics

- **Direct Syscalls & Unhooking:** Advanced malware bypasses EDR user-mode hooks in `ntdll.dll` by invoking direct system calls, masking standard `OpenProcess` behavior.
- **Handle Duplication:** Instead of opening a new handle to LSASS, an attacker with elevated rights finds an existing process that already holds an open handle to LSASS (such as a security agent) and duplicates it using `NtDuplicateObject`.
- **Kernel-level Dumping:** Attackers using vulnerable drivers (Bring Your Own Vulnerable Driver / BYOVD) can drop to kernel mode (Ring 0) and directly copy memory pages, entirely bypassing user-mode handle auditing and Sysmon ID 10.

### Recommended Defensive Controls

1. **Enable LSA Protection (RunAsPPL):**
   Configuring LSASS to run as a Protected Process Light (PPL) prevents non-protected processes from reading its memory, even if the user has `SYSTEM` privileges.
   - Registry path: `HKLM\SYSTEM\CurrentControlSet\Control\Lsa`
   - Value: `RunAsPPL` = `dword:00000001` (or `dword:00000002` for PPL with audit mode on newer Windows 11 builds).

2. **Credential Guard:**
   Enables Virtualization-based Security (VBS) to isolate LSASS secrets within a virtualized container (`LsaIso.exe`). Even if a process successfully reads LSASS memory, it only accesses an empty shell while actual credentials remain isolated.

3. **Attack Surface Reduction (ASR) Rules:**
   If using Microsoft Defender, enable the ASR rule:
   - **Rule ID:** `9e714150-2478-4379-875c-0e4723aea30c` ("Block credential stealing from the Windows Local Security Authority subsystem").

---

## Summary

Detecting LSASS memory dumping requires a layered monitoring approach. Simple command-line signatures for tools like `comsvcs.dll` catch low-hanging fruit, but robust defense relies on process access telemetry like Sysmon Event ID 10 to capture unexpected handle requests and anomalous GrantedAccess bitmasks.

Pairing these telemetry-based detections with proactive system hardening—specifically LSA Protection (RunAsPPL) and Credential Guard—drastically reduces an attacker's ability to extract credentials during an intrusion.
