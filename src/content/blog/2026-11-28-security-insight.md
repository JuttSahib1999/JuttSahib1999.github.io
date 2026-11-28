---
title: "Detecting PsExec Lateral Movement: Telemetry, Service Logs, and Network Artifacts"
description: "An operational breakdown of how PsExec executes commands remotely, the host and network artifacts left behind, and how to write practical detections for both standard and custom implementations."
date: "2026-11-28"
tags: ["Cybersecurity", "Security Operations", "Threat Detection", "Windows Telemetry"]
category: "Cyber Security"
difficulty: "Intermediate"
author: "Abdul Muqeet Tabraiz"
image: "/images/blog/2026-11-28-detecting-psexec-lateral-movement-telemetry-service-logs-and-network-artifacts.svg"
---

Sysadmins rely on PsExec for rapid remote management across Windows environments. Threat actors prefer it for the exact same reason: it uses legitimate administrative features, relies on standard Windows protocols, and executes code with elevated privileges.

Whether an adversary uses the official Sysinternals binary, Impacket's `psexec.py`, Metasploit, or Cobalt Strike, the core underlying mechanisms remain similar. Understanding how PsExec operates at the protocol and host levels allows defenders to build detections that catch both default tools and customized offensive variants.

---

## How PsExec Works Under the Hood

PsExec does not exploit a vulnerability. Instead, it relies on standard Server Message Block (SMB) file sharing and Remote Procedure Call (RPC) protocols to stage, install, and execute a temporary remote service.

A typical PsExec execution follows a specific operational flow:

```
[ Local System ]  ---( SMB 445 )--->  1. Authenticate & Connect to ADMIN$
[ Local System ]  ---( Copy Binary )-> 2. Write PSEXESVC.exe to C:\Windows
[ Local System ]  ---( RPC / SCM )-->  3. Create & Start Remote Service
[ Local System ]  <--( Named Pipes )-> 4. Redirect I/O (cmd / payload)
```

1. **Authentication and Share Access**: The client authenticates over SMB (TCP 445) using valid credentials and connects to the administrative share (`ADMIN$` or `C$`).
2. **Payload Staging**: The client uploads a service executable (by default, `PSEXESVC.exe`) to the target machine's `%SystemRoot%` directory (`C:\Windows\`).
3. **Service Management**: The client uses the Service Control Manager (SCM) via RPC over SMB (using the `svcctl` named pipe) to register and start a new service pointing to the staged binary.
4. **Command Execution & Pipe I/O**: The newly created service runs with `NT AUTHORITY\SYSTEM` privileges. It spawns the requested command processor (such as `cmd.exe` or `powershell.exe`) and redirects input, output, and error streams back to the client over named pipes (e.g., `\pipe\psexec` or randomized pipe names).
5. **Cleanup**: Upon termination, the service is stopped, unregistered, and the binary is removed from disk. If the execution crashes or is killed abruptly, these artifacts often remain behind.

---

## Host Telemetry and Event Auditing

Because PsExec interacts directly with the Windows Service Control Manager and local file system, it creates clear signals across multiple log sources.

### 1. Service Installation Logs

When a remote service is created, the Windows Service Control Manager logs an event to the System log. If Security Auditing is configured, a corresponding event is recorded in the Security log.

* **System Event ID 7045**: A service was installed in the system.
* **Security Event ID 4697**: A service was installed in the system (requires *Audit Security System Extension* enabled).

#### Example Event ID 7045 Log

```xml
Log Name:      System
Source:        Service Control Manager
Event ID:      7045
Task Category: None
Level:         Information
Description:
A service was installed in the system.

Service Name:  PSEXESVC
Service File Name:  %SystemRoot%\PSEXESVC.exe
Service Type:  user mode service
Start Type:    demand start
Account Name:  LocalSystem
```

While default Sysinternals executions use `PSEXESVC` as the service name, offensive frameworks usually randomize this string. For instance, Impacket's `psexec.py` generates random 4-character alphanumeric service names (e.g., `BkWx` pointing to `C:\Windows\BkWx.exe`).

### 2. Process Creation Telemetry

Monitoring process creation via Sysmon (Event ID 1) or Windows Audit Process Creation (Event ID 4688) highlights the parent-child relationship typical of PsExec:

* **Parent Process**: `services.exe`
* **Child Process**: `PSEXESVC.exe` (or a randomized binary in `C:\Windows\`)
* **Grandchild Process**: `cmd.exe`, `powershell.exe`, or malicious payloads (e.g., `rundll32.exe`)

```text
services.exe (PID: 748)
 └── PSEXESVC.exe (PID: 4312) [Path: C:\Windows\PSEXESVC.exe]
      └── cmd.exe (PID: 5120) [Cmdline: cmd.exe /c whoami]
```

A process running directly out of `%SystemRoot%` (and not a subdirectory like `%SystemRoot%\System32`) spawned directly by `services.exe` is an immediate indicator of service-based lateral movement.

### 3. Named Pipe Creation

PsExec relies on named pipes for inter-process communication and stdout/stderr redirection.

* **Sysmon Event ID 17**: Pipe Created
* **Sysmon Event ID 18**: Pipe Connected

Official Sysinternals PsExec uses predictable pipe patterns:
* `\psexec`
* `\psexec-SERVERNAME-PID-stdin`
* `\psexec-SERVERNAME-PID-stdout`
* `\psexec-SERVERNAME-PID-stderr`

Impacket and Cobalt Strike use distinct named pipe formats or allow operators to customize them. Identifying newly created pipes with non-standard naming formats coming from services spawned binaries can uncover covert lateral movement.

---

## Network Telemetry and Artifacts

Network telemetry complements endpoint logs, particularly when endpoint agents are absent or tampered with.

Key network artifacts to observe during PsExec activity include:

1. **SMB Traffic (TCP Port 445)**: High volume of SMB traffic between host IPs that do not typically manage each other (e.g., Workstation to Workstation).
2. **Administrative Share Connections**: Connect IPC calls targeting `ADMIN$` (`C:\Windows`) or `C$`.
3. **RPC Remote Service Calls**: RPC calls over SMB to the `svcctl` interface:
   * `CreateServiceW` or `CreateServiceA`
   * `StartServiceW`
4. **Network Logons (Event ID 4624)**: Target system records a **Logon Type 3** (Network) event immediately prior to service creation, identifying the originating IP address and account used.

---

## Practical Detection Engineering

Relying solely on the string `PSEXESVC.exe` will fail against any semi-capable adversary. Robust detections must focus on behavior: remote service installation targeting suspicious file paths or unusual parent-child process chains.

### Splunk Query: Detecting Suspicious Service Creation in C:\Windows

This query looks for services installed directly in `C:\Windows\` rather than expected subdirectories like `System32` or `SysWOW64`.

```spl
index=windows source="WinEventLog:System" EventCode=7045
| eval ServicePath=lower(ImagePath)
| match(ServicePath, "^(?i)%systemroot%\\\[^\\]+\.exe") OR match(ServicePath, "^(?i)c:\\windows\\\[^\\]+\.exe")
| table _time, Computer, ServiceName, ImagePath, AccountName
```

### Sigma Rule Concept: Services Spawned Out of System Root

```yaml
title: Service Executable Staged in System Root
id: e4b238a0-7612-4fdf-9118-2e0617551066
status: experimental
description: Detects process creation of executables located directly in C:\Windows\ spawned by services.exe, typical of PsExec and Impacket.
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    ParentImage|endswith: '\services.exe'
    Image|re: '(?i)^C:\\Windows\\[^\\]+\.exe$'
  filter_known_good:
    Image|endswith:
      - '\CcmExec.exe'
      - '\TSGHoq.exe'
  condition: selection and not filter_known_good
falsepositives:
  - Legacy administrative software installers that copy binaries directly to C:\Windows.
level: high
```

---

## Investigation Workflow for Security Analysts

When an alert fires for suspected PsExec activity, follow this step-by-step investigation sequence:

```
[ Alert Triggered: ID 7045 / Process Creation ]
                       │
                       ▼
         [ Step 1: Correlate Event 4624 ]
         Find matching Type 3 Logon from same timestamp
                       │
                       ▼
       [ Step 2: Identify Source IP & Account ]
       Determine source host and credential identity
                       │
                       ▼
      [ Step 3: Inspect Process Tree ]
      Check child processes of installed service binary
                       │
                       ▼
     [ Step 4: Validate Authorization ]
     Cross-reference with IT change tickets / Admin activity
```

1. **Identify Source IP and User Account**: Cross-reference the timestamp of Event ID 7045 or Sysmon Event 1 with Event ID 4624 (Logon Type 3) on the destination system to identify the source IP address and account used.
2. **Inspect Process Trees**: Look at what process was executed by the installed service. Did `PSEXESVC.exe` launch `cmd.exe /c powershell.exe -enc ...`? Or did a randomized service executable initiate outbound network connections?
3. **Analyze Disk Artifacts**: Inspect `C:\Windows\` for residual binaries. Extract host indicators (hashes, compile timestamps) if the file was not deleted upon cleanup.
4. **Determine Scope**: Query your SIEM for the same source IP or user account initiating similar SMB/Service creation activity across other network assets within the same time window.

---

## Defensive Recommendations and Limitations

Detecting PsExec is essential, but preventing unauthorized lateral movement is even better.

### Practical Hardening Steps

* **Restrict Workstation-to-Workstation SMB**: Workstations rarely need to talk to each other over TCP 445. Enforce host-based firewall rules (Windows Defender Firewall or EDR) blocking inbound TCP 445 between endpoint subnets.
* **Implement LAPS (Local Administrator Password Solution)**: PsExec requires administrative rights on the target host. Using unique local admin passwords prevents an attacker from using dumped credentials to move laterally across every machine.
* **Restrict Remote Service Creation**: Apply Group Policy settings to restrict permissions on the Service Control Manager so that standard or non-restricted administrative accounts cannot remotely create services.
* **Monitor Network Share Access**: Enable auditing for object access on sensitive shares to track unauthorized access to `ADMIN$` and `C$`.

### Common Limitations in Detection

* **Legitimate Administrative Noise**: If IT teams frequently use PsExec for software deployment or troubleshooting, alerts on standard `PSEXESVC.exe` paths will create high operational fatigue. Establish baselines of legitimate admin host IPs to filter out benign activity.
* **In-Memory Alternatives**: Modern threat actors sometimes favor methods that bypass service creation entirely (such as WinRM, WMI, or DCOM execution). Combining service-creation detections with WMI and WinRM auditing ensures broader coverage across lateral movement techniques.
