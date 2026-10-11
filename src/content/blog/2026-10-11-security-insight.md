---
title: "Detecting Named Pipe Impersonation: Telemetry Gaps, ETW Events, and Detection Logic"
description: "An operational look at Windows named pipe mechanics, token impersonation risks, Sysmon and ETW coverage, and practical detection engineering for IPC abuse."
date: "2026-10-11"
tags: ["Cybersecurity", "Detection Engineering", "Windows Internals", "Threat Hunting"]
category: "Cyber Security"
difficulty: "Advanced"
author: "Abdul Muqeet Tabraiz"
image: "/images/blog/2026-10-11-detecting-named-pipe-impersonation-telemetry-gaps-etw-events-and-detection-logic.svg"
---

Named pipes are fundamental to inter-process communication (IPC) in Windows. They allow local and remote processes to exchange data using standard file system APIs (`CreateFileW`, `ReadFile`, `WriteFile`). Because named pipes abstract complex RPC and network protocols into familiar file handles, both native OS components and security software rely heavily on them.

Adversaries leverage named pipes for two primary operational purposes: **lateral movement/pivot channels** (such as Cobalt Strike, Havoc, or Sliver SMB beacons) and **local privilege escalation** via token impersonation (exploiting utilities like PrintSpoofer, RoguePotato, or custom RPC relay primitives).

To detect named pipe abuse effectively, detection engineers must look past basic string matching on default pipe names. This requires understanding the underlying Win32 APIs, how the Named Pipe File System (`NPFS`) driver exposes events to telemetry agents, where usermode API hooks fail, and how to build durable detection logic using Kernel ETW and Sysmon.

---

## 1. Win32 Mechanics and Token Impersonation

Named pipes operate as virtual files residing in the Named Pipe File System namespace (`\\.\pipe\PipeName`, mapped internally to `\Device\NamedPipe\PipeName`). 

### Pipe Creation and Connection Flow

When a server process creates a named pipe, it calls `CreateNamedPipeW`:

```cpp
HANDLE hPipe = CreateNamedPipeW(
    L"\\\\.\\pipe\\TargetPipe",
    PIPE_ACCESS_DUPLEX,
    PIPE_TYPE_BYTE | PIPE_WAIT,
    1,                  // Max instances
    1024, 1024,         // Output/Input buffer size
    0,                  // Default timeout
    &securityAttributes // DACL controlling access
);
```

The server process then executes `ConnectNamedPipe(hPipe, NULL)` to block until a client connects via `CreateFileW(L"\\\\.\\pipe\\TargetPipe", ...)` or an RPC interface binds to the endpoint.

### The Mechanism of Impersonation

The security risk surfaces when a client connects to a server pipe. If the server process possesses the `SeImpersonatePrivilege` (or `SeAssignPrimaryTokenPrivilege`), it can call `ImpersonateNamedPipeClient(hPipe)`.

Under the hood, `ImpersonateNamedPipeClient` performs the following steps inside the kernel:

1. Translates the pipe handle (`hPipe`) to the underlying file object managed by `NPFS`.
2. Extracts the security context of the thread or process that initiated the connection on the client side.
3. Generates an **Impersonation Token** associated with the client's identity.
4. Assigns this impersonation token to the calling thread in the server process (`NtSetInformationThread` with `ThreadImpersonationToken`).

If a high-privilege service (such as `NT AUTHORITY\SYSTEM` running via `spoolsv.exe` or `trustedinstaller.exe`) connects to an attacker-controlled named pipe, the attacker’s unprivileged process captures the `SYSTEM` token. The attacker thread can then call `OpenThreadToken`, duplicate it into a primary token (`DuplicateTokenEx`), and execute a new process in the context of `SYSTEM` using `CreateProcessWithTokenW` or `CreateProcessAsUserW`.

```
[ Elevated Client Service (SYSTEM) ]
               │
               │  1. Connects to pipe: \\.\pipe\attacker_pipe
               ▼
   [ Attacker Server Process ] (Holds SeImpersonatePrivilege)
               │
               │  2. Calls ImpersonateNamedPipeClient()
               │  3. Thread token set to SYSTEM
               │  4. Calls DuplicateTokenEx()
               ▼
[ New Process Executed as NT AUTHORITY\SYSTEM ]
```

---

## 2. Adversary Tradecraft Context

### SMB Pivoting and C2 Infrastructure
Command-and-control (C2) frameworks use named pipes to stage internal pivots across segmented network boundaries. A peer-to-peer (P2P) agent running on an isolated host communicates via SMB (TCP port 445) to a staging pipe hosted on an egress-capable host.

Default frameworks use recognizable default string formats, though sophisticated operators customize these parameters:

| C2 Framework / Tool | Default Pipe Naming Pattern / Characteristic |
| :--- | :--- |
| **Cobalt Strike (Default)** | `\pipe\msagent_XX`, `\pipe\status_XX`, `\pipe\postex_XX` |
| **Cobalt Strike (Artifact Kit)** | `\pipe\mojo.5688.8052.18384893977270982618*` |
| **Sliver** | `\pipe\sliver-XX`, dynamic UUID formats |
| **PrintSpoofer (LPE)** | `\pipe\PrintSpoofer\Pipe` or random UUIDs requested from Spooler |
| **JuicyPotato / RoguePotato** | Custom local listener pipes bound to OXID resolver endpoints |

### Abusing RPC Primitives for LPE
In local privilege escalation exploits like PrintSpoofer, the attacker forces the `Print Spooler` service (`spoolsv.exe`) to execute `RpcOpenPrinter` pointing to a pipe location crafted by the attacker (e.g., `\\.\pipe\Foo\pipe\spoolss`). Because `spoolsv.exe` runs as `NT AUTHORITY\SYSTEM`, connecting to this pipe exposes the `SYSTEM` token to the lower-privileged listener.

---

## 3. Telemetry Sources and Blind Spots

To catch this behavior, detection engineers typically rely on Sysmon, Windows Security Event Logs, or EDR telemetry. Each source comes with specific collection trade-offs and visibility limits.

### Sysmon Event Logs

Sysmon provides two primary events dedicated to IPC monitoring:

*   **Event ID 17: Pipe Created** (`PipeName`, `Image`, `ProcessGuid`, `ProcessId`)
*   **Event ID 18: Pipe Connected** (`PipeName`, `Image`, `ProcessGuid`, `ProcessId`)

#### Sysmon Event ID 17 Example Payload:

```xml
<EventData>
  <Data Name="UtcTime">2026-10-11 14:22:01.412</Data>
  <Data Name="ProcessGuid">{A2B3C4D5-E6F7-11EE-9000-000C2931A1B2}</Data>
  <Data Name="ProcessId">4812</Data>
  <Data Name="PipeName">\PrintSpoofer\Pipe</Data>
  <Data Name="Image">C:\Users\Public\Downloads\exploit.exe</Data>
  <Data Name="User">WORKSTATION\UnprivilegedUser</Data>
</EventData>
```

#### Blind Spot #1: Filter Exclusions
Because system services generate thousands of pipe events per minute (e.g., `\pipe\lsass`, `\pipe\ntsvcs`, `\pipe\chrome.*`), default Sysmon deployment configurations often include aggressive exclusion filters. Attackers exploit these exclusions by mimicking legitimate pipe paths or target names excluded from logging (such as appending target strings to `\pipe\srvsvc`).

#### Blind Spot #2: Short-Lived Pipe Instances
Exploits that rapidly create a pipe, impersonate the token, and close the handle within a few milliseconds may bypass asynchronous usermode log collectors under high system load.

### ETW (Event Tracing for Windows)
For deeper visibility without relying exclusively on Sysmon, Kernel ETW provides reliable event streams directly from the driver layer:

*   **`Microsoft-Windows-Kernel-File`**: Captures file system operations, including creation and interaction with `\Device\NamedPipe\`.
*   **`Microsoft-Windows-RPC`** (`{6ad52b32-d609-4be9-ae07-ce862e5d76e0}`): Tracks RPC client/server bindings, crucial for spotting forced RPC authentication vectors before the pipe connection completes.

### Security Event Log: Event ID 4624 / 4672
When named pipe connections traverse the network via SMB, the destination host records:
*   **Event ID 4624** (Logon Type 3 - Network Logon).
*   **Event ID 4672** (Special Privileges Assigned to New Logon) if an administrative token is presented.

However, **local** pipe impersonation does not produce a Type 3 logon event because token impersonation happens in-memory within existing local logon sessions.

---

## 4. Detection Engineering Strategies

Relying on simple pipe-name string matches creates fragile detections that are easily bypassed by modified configuration profiles. A robust detection strategy relies on process context, privilege tracking, and architectural anomalies.

### Strategy 1: Detecting Non-Standard Pipe Creation Patterns (Sysmon Event ID 17)

Detecting known framework defaults is useful for catching opportunistic tradecraft, but rules should also flag binary paths executing out of non-standard directories (`\AppData\`, `\Users\Public\`, `\Temp\`) that instantiate *any* named pipe.

#### KQL Detection Query (Defender for Endpoint / Sentinel):

```kql
DeviceEvents
| where ActionType == "NamedPipeCreated"
| extend PipeName = tostring(AdditionalFields.PipeName)
| extend InitiatingProcessPath = FolderPath
| where InitiatingProcessPath startswith @"c:\users\public\" 
   or InitiatingProcessPath startswith @"c:\windows\temp\"
   or InitiatingProcessPath startswith @"c:\appdata\"
| where not(PipeName has_any ("\chrome.", "\edge.", "\firefox."))
| project TimeGenerated, DeviceName, ReportId, InitiatingProcessFileName, InitiatingProcessPath, PipeName, AccountName
```

### Strategy 2: Detecting Token Impersonation via Process Creation Anomalies

When privilege escalation succeeds, a low-privileged parent process or a process running under a user context spawns a child process running as `NT AUTHORITY\SYSTEM`. 

Correlate Sysmon **Event ID 1** (Process Creation) with parent-child privilege mismatches:

```eql
process where event.type == "start"
  and process.user : ("NT AUTHORITY\\SYSTEM", "NT AUTHORITY\\LOCAL SERVICE")
  and parent.user != null
  and not parent.user : ("NT AUTHORITY\\SYSTEM", "NT AUTHORITY\\LOCAL SERVICE", "NT AUTHORITY\\NETWORK SERVICE")
  and not parent.executable : (
      "C:\\Windows\\System32\\services.exe",
      "C:\\Windows\\System32\\svchost.exe",
      "C:\\Windows\\System32\\wininit.exe"
  )
```

This query detects instances where a process gains `SYSTEM` privileges despite being spawned by a normal user session—a strong signal of successful token impersonation via named pipes or token manipulation.

### Strategy 3: Detecting Forced RPC Pipe Relay (PrintSpoofer / Potato Patterns)

To spot PrintSpoofer or RPC-based pipe impersonation primitives, detect high-privilege system services connecting to unusual local named pipes created by non-SYSTEM processes.

1. Watch for Sysmon Event ID 17 (`Pipe Created`) where `User` is **NOT** `SYSTEM`.
2. Watch for Sysmon Event ID 18 (`Pipe Connected`) where `Image` is a core SYSTEM service (`spoolsv.exe`, `lsass.exe`, `svchost.exe`) connecting to the pipe instantiated in Step 1.

#### Sigma Rule Definition Example:

```yaml
title: High-Privilege Service Connection to User-Created Pipe
id: e4c23f11-9a71-4b13-8888-281b99a3c309
status: experimental
description: Detects core system services connecting to named pipes generated by unprivileged user accounts.
logsource:
  category: pipe_created
  product: windows
detection:
  selection_create:
    EventID: 17
  filter_system_user:
    User|contains:
      - "NT AUTHORITY\SYSTEM"
      - "NT AUTHORITY\LOCAL SERVICE"
      - "NT AUTHORITY\NETWORK SERVICE"
  condition: selection_create and not filter_system_user
falsepositives:
  - Custom internal software suites that instantiate user-space pipe servers for administrative agents.
level: high
```

---

## 5. Triage and Investigation Workflow

When investigating a alert indicating potential named pipe abuse, follow this workflow to validate the activity and establish the full attack chain.

```
 [ Pipe Alert Triggered ]
           │
           ▼
 1. Examine Executable Metadata & Path
    ├── Valid Signed Executable?
    └── Resides in standard location (e.g., C:\Program Files)?
           │
           ├── NO ──> High Suspicion: Inspect Process Handles & Memory
           │
           ▼
 2. Inspect Pipe Endpoint
    ├── Pipe Name matches C2 default pattern?
    └── Is an unprivileged process reading a SYSTEM pipe connection?
           │
           ▼
 3. Analyze Token Assignments (Thread vs. Process)
    ├── Does Thread Token display SecurityImpersonation?
    └── Check parent/child process privilege disparity.
```

### Step 1: Analyze Process Handles and Pipe Objects
Use Sysinternals `handle.exe` or PowerShell to inspect open handles associated with the suspicious process PID:

```powershell
# Querying open handles on a specific process PID
handle.exe -p 4812 -a -u
```

Look for file object handles referencing `\Device\NamedPipe\`. Examine whether the security context of the process holding the handle matches the process owner.

### Step 2: Thread Token Verification via Volatility or Live Memory Analysis
If analyzing a memory dump or using WinDbg on an endpoint, inspect the target thread's `ETHREAD` structure to check for an assigned Impersonation Token:

```text
0:000> !thread
...
ImpersonationToken: ffffd001a1234060 (Token Level: Impersonation)
DeviceMap: 0000000000000000
...
```

If the primary process token is `WORKSTATION\Bob` but the thread impersonation token is `NT AUTHORITY\SYSTEM`, an impersonation call (`ImpersonateNamedPipeClient` or `SetThreadToken`) was executed by that thread.

### Step 3: Check Parent/Child Process Execution Lineage
Correlate pipe connection timestamps with process creation logs. If a low-privilege application creates a pipe, receives a connection from `spoolsv.exe`, and immediately spawns `cmd.exe` or `powershell.exe` as `SYSTEM`, you have confirmed a successful token impersonation exploit.

---

## 6. Defensive Recommendations and Hardening

To mitigate named pipe tradecraft, implement defense-in-depth controls across process privileges, network access, and system configurations.

### 1. Restrict SeImpersonatePrivilege
The `SeImpersonatePrivilege` (`User Right Assignment: Impersonate a client after authentication`) allows a process to impersonate connected client tokens.

*   Remove `SeImpersonatePrivilege` from non-essential local service accounts.
*   Enforce local service isolation: restrict service accounts so they cannot run arbitrary binaries or write to world-writable staging directories.

```text
Group Policy Location:
Computer Configuration -> Windows Settings -> Security Settings ->
Local Policies -> User Rights Assignment -> Impersonate a client after authentication
```

### 2. Restrict Print Spooler Service
If the Print Spooler service is not explicitly required on a server (especially Domain Controllers and critical infrastructure systems), disable it entirely to close the primary RPC relay vector used by tools like PrintSpoofer:

```powershell
Stop-Service -Name "Spooler" -Force
Set-Service -Name "Spooler" -StartupType Disabled
```

### 3. Enforce Strict Named Pipe DACLs
When developing internal applications that use named pipes, explicitly define tight Discretionary Access Control Lists (DACLs) in `SECURITY_ATTRIBUTES`. Avoid using `NULL` DACLs or granting `EVERYONE` read/write access. Ensure that only specific required SIDs can establish client connections.

### 4. Segment Internal SMB IPC Traffic
Adversary named pipe pivots rely on SMB (port 445) communication between workstations. Implement host-based firewall policies (Windows Defender Firewall) to restrict inbound TCP 445 connections between workstation subnets. Workstations should only communicate over port 445 to designated infrastructure hosts, such as Domain Controllers and File Servers.

---

## Practical Summary

Named pipe impersonation remains a highly effective tactic because it relies on standard Windows API design rather than traditional software vulnerabilities. 

To maintain effective visibility:

*   Do not rely solely on default pipe-name string matching. Attackers can modify pipe strings in C2 frameworks and exploit binaries with minimal effort.
*   Monitor process execution context, focusing on user identity transitions between parent and child processes.
*   Combine Sysmon Pipe Events (IDs 17 and 18) with process creation logs and ETW providers to spot forced RPC connections.
*   Harden systems by auditing `SeImpersonatePrivilege` assignments and blocking unnecessary workstation-to-workstation SMB communications.
