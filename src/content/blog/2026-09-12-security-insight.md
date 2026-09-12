---
title: "Detecting WinRM-Based Lateral Movement: Telemetry, Event Logs, and Correlation Logic"
description: "A practical guide to hunting and detecting Windows Remote Management (WinRM) lateral movement using process lineage, Windows Event Logs, and network correlation."
date: "2026-09-12"
tags: ["Cybersecurity", "Security Operations", "Threat Detection", "Windows Security", "Lateral Movement"]
category: "Cyber Security"
difficulty: "Intermediate"
author: "Abdul Muqeet Tabraiz"
image: "/images/blog/2026-09-12-detecting-winrm-based-lateral-movement-telemetry-event-logs-and-correlation-logi.svg"
---

Windows Remote Management (WinRM) and PowerShell Remoting are essential tools for system administrators managing enterprise environments. They allow administrators to execute commands, run scripts, and manage remote systems over standard HTTP/HTTPS channels.

Because WinRM is legitimate, built-in system management infrastructure, threat actors frequently leverage it for lateral movement. By using native administrative features—often referred to as Living off the Land—attackers can move across endpoints without dropping custom remote access tools onto the target host.

To defend against WinRM abuse, security operations teams need to understand the underlying architecture, identify the specific telemetry generated during remote sessions, and build correlation rules that separate legitimate administrative activity from unauthorized lateral movement.

---

## How WinRM Remoting Operates Under the Hood

WinRM relies on the WS-Management protocol, transmitting SOAP messages over TCP port 5985 (HTTP) or 5986 (HTTPS). When a user initiates a remote session (for instance, via `Enter-PSSession` or `Invoke-Command`), the following interaction takes place on the target system:

1. **Authentication:** The client authenticates against the target host's WinRM service using Kerberos or NTLM.
2. **Service Request:** The WinRM service, hosted within `svchost.exe`, accepts the connection request.
3. **Worker Host Spawning:** The WinRM service executes `wsmprovhost.exe` (Web Services for Management Provider Host) under the security context of the authenticated user.
4. **Command Execution:** Any commands sent through the WinRM session execute as child processes of `wsmprovhost.exe`.

```
[Attacker Host]
       │
       │ (TCP 5985 / 5986 - WS-Man SOAP)
       ▼
[Target Host]
   └── svchost.exe (WinRM Service)
        └── wsmprovhost.exe (Authenticated User Context)
             ├── powershell.exe (Remote Command execution)
             └── cmd.exe / net.exe / whoami.exe
```

Because `wsmprovhost.exe` acts as the host process for the remote session, its creation and subsequent child processes form the primary host-based telemetry footprint for WinRM usage.

---

## Key Telemetry Sources and Event Artifacts

Detecting remote execution via WinRM requires monitoring several event logs and system telemetry streams. Relying on a single log source usually creates blind spots; effective detection depends on cross-source correlation.

### 1. Security Event Log: Authentication Artifacts

When a user connects via WinRM, Windows logs a network authentication event on the destination host.

* **Event ID 4624 (Successful Logon):**
  * **Logon Type:** `3` (Network Logon)
  * **Logon Process:** `NtLmSsp` or `Kerberos`
  * **Process Name:** `C:\Windows\System32\svchost.exe` (hosting the WinRM service)

While Logon Type 3 events occur constantly in Active Directory networks (e.g., SMB share accesses), observing a Logon Type 3 event immediately preceding `wsmprovhost.exe` execution establishes the link between authentication and remote execution.

### 2. Sysmon / EDR: Process Creation Telemetry

Process creation monitoring (Sysmon Event ID 1 or EDR equivalent) provides the highest-fidelity signal for identifying WinRM activity.

Key attributes to watch for:

* **Parent Process:** `C:\Windows\System32\svchost.exe` (specifically with arguments containing `-k LocalSystemNetworkRestricted -p -s WinRM`)
* **Target Process:** `C:\Windows\System32\wsmprovhost.exe`
* **Child Processes:** Command interpreters or system tools spawned by `wsmprovhost.exe` (e.g., `cmd.exe`, `powershell.exe`, `net.exe`, `whoami.exe`, `certutil.exe`).

#### Sample Sysmon Event ID 1 (Process Creation)

```xml
<EventData>
  <Data Name="UtcTime">2026-09-12 14:22:05.112</Data>
  <Data Name="ProcessId">4812</Data>
  <Data Name="Image">C:\Windows\System32\wsmprovhost.exe</Data>
  <Data Name="CommandLine">C:\Windows\system32\wsmprovhost.exe -Embedding</Data>
  <Data Name="ParentProcessId">1240</Data>
  <Data Name="ParentImage">C:\Windows\System32\svchost.exe</Data>
  <Data Name="ParentCommandLine">C:\Windows\System32\svchost.exe -k LocalSystemNetworkRestricted -p -s WinRM</Data>
  <Data Name="User">DOMAIN\AdminUser</Data>
</EventData>
```

When commands are passed directly via `Invoke-Command -ScriptBlock { ... }`, `wsmprovhost.exe` executes the code directly within its own memory space or spawns sub-processes depending on what the script block executes.

### 3. PowerShell Script Block Logging (Event ID 4104)

If script execution occurs within the WinRM session, Windows PowerShell Script Block Logging records the raw code executed inside the session, even if the code was obfuscated before transmission.

* **Log Channel:** `Microsoft-Windows-PowerShell/Operational`
* **Event ID:** `4104`

This event logs the un-obfuscated script content, providing context on whether the remote session was used for routine maintenance or threat actor reconnaissance (e.g., executing discovery modules like PowerView or BloodHound).

### 4. WinRM Operational Logs

Windows includes a dedicated operational log channel for WinRM services: `Microsoft-Windows-WinRM/Operational`. While often disabled or uncollected by default in standard SIEM configurations, it provides explicit session details:

* **Event ID 91 (Creating WSMan Shell):** Logs when a remote shell session is requested, including the user account and shell identifier.
* **Event ID 168 (WSMan Request Processing):** Tracks incoming payload processing.

---

## Detection Strategies and Query Examples

To detect unauthorized WinRM movement, focus on three primary detection approaches: baseline anomalies, suspicious child process patterns, and network-to-endpoint correlation.

### Strategy A: Workstation-to-Workstation WinRM Traffic

In a structured enterprise network, administrative connections typically originate from designated jump hosts, Privileged Access Workstations (PAWs), or deployment servers. 

Direct WinRM connections originating from standard workstation IP ranges heading to other workstations are almost always anomalous and strongly indicate lateral movement.

**Detection Logic (Network/Firewall or EDR):**
* **Source Address:** Workstation Subnets (`10.x.x.x` / `172.16.x.x` desktop ranges)
* **Destination Address:** Workstation Subnets
* **Destination Port:** `5985` (HTTP) or `5986` (HTTPS)

### Strategy B: Suspicious Process Spawning under `wsmprovhost.exe`

While routine IT automation scripts may run administrative tools remotely, observing interactive shell usage, recon tools, or web-download utilities spawned by `wsmprovhost.exe` warrants immediate review.

#### Example Splunk Search Query

```spl
index=sysmon EventCode=1 ParentImage="*\\wsmprovhost.exe"
| stats count min(_time) as first_seen max(_time) as last_seen by Computer, User, Image, CommandLine
| search Image IN ("*\\cmd.exe", "*\\powershell.exe", "*\\whoami.exe", "*\\net.exe", "*\\net1.exe", "*\\nltest.exe", "*\\bitsadmin.exe", "*\\certutil.exe", "*\\rundll32.exe")
| eval first_seen=strftime(first_seen, "%Y-%m-%d %H:%M:%S")
| eval last_seen=strftime(last_seen, "%Y-%m-%d %H:%M:%S")
```

#### Example Sigma Rule (Process Lineage)

```yaml
title: Suspicious Process Spawning from WinRM Provider Host
id: 5a8e24fa-6c12-4f32-841f-0e78872e4b11
status: experimental
description: Detects suspicious child processes spawned by wsmprovhost.exe, indicating potential remote execution or lateral movement.
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    ParentImage|endswith: '\wsmprovhost.exe'
    Image|endswith:
      - '\cmd.exe'
      - '\powershell.exe'
      - '\pwsh.exe'
      - '\net.exe'
      - '\net1.exe'
      - '\whoami.exe'
      - '\certutil.exe'
      - '\rundll32.exe'
      - '\regsvr32.exe'
  condition: selection
falsepositives:
  - Legitimate remote administrative scripts using cmd or PowerShell utilities.
level: medium
```

---

## Practical SOC Investigation Workflow

When an alert triggers for suspicious WinRM activity, analysts should execute a structured investigation to establish context:

```
[ Alert: WinRM Execution Detected ]
               │
               ▼
[ 1. Analyze Parent/Child Lineage ] ──► Any downloaders (certutil) or recon (whoami)?
               │
               ▼
[ 2. Check Originating Source IP ]  ──► Is source a PAW/Jump Host or general endpoint?
               │
               ▼
[ 3. Inspect Event ID 4104 Logs ]   ──► What commands executed inside PowerShell?
               │
               ▼
[ 4. Assess Account Context ]       ──► Was it a service account or compromised user?
```

### Step 1: Identify Source and Destination
Cross-reference the Logon Type 3 (Event ID 4624) entry on the target machine with network telemetry to identify the source IP address and source machine name.

### Step 2: Validate the Source Host
Determine if the source system is an authorized management server or Privileged Access Workstation (PAW). If the connection originated from an standard end-user workstation, treat it as high priority.

### Step 3: Analyze the Executed Commands
Look at Script Block logs (Event ID 4104) and process command lines associated with `wsmprovhost.exe`. Look specifically for:
* Network reconnaissance (`net group "Domain Admins" /domain`, `nltest /dclist:`)
* Credential dumping attempts (calls to `lsass.exe`, MiniDump functions, or SAM registry exports)
* Defense evasion (disabling Windows Defender via `Set-MpPreference`)

### Step 4: Examine Account Context
Verify whether the user executing the remote session normally manages the target system. A user account authenticating to a critical server via WinRM for the first time without a corresponding change ticket is a key indicator of unauthorized activity.

---

## Common Defensive Gaps and Limitations

Detecting WinRM-based lateral movement comes with practical constraints that SOC teams must account for:

1. **Default WinRM Log Settings:** The `Microsoft-Windows-WinRM/Operational` log is often not enabled or forwarded to centralized SIEM systems by default, leaving analysts reliant purely on general process creation logs.
2. **In-Memory Script Execution:** Commands executed inside an interactive PowerShell session hosted by `wsmprovhost.exe` might not spawn a secondary child process. Without PowerShell Script Block Logging (Event ID 4104), host process logs will only show `wsmprovhost.exe` launching, obscuring the actual commands executed inside the session.
3. **Legitimate Noise:** Environments heavily reliant on automated management tools (e.g., Ansible, Microsoft Endpoint Configuration Manager) generate substantial `wsmprovhost.exe` activity. Analysts must baseline these management servers to suppress alerts for authorized automation.

---

## Hardening Recommendations

Detecting WinRM activity is only part of the strategy; limiting where and how WinRM can be used reduces the attack surface significantly:

* **Restrict Network Access via Host Firewalls:** Block inbound TCP ports 5985 and 5986 on standard workstations. WinRM should generally only accept inbound connections on servers, and even then, strictly from designated management subnets or jump boxes.
* **Enforce PowerShell Script Block Logging:** Enable Event ID 4104 logging via Group Policy (`Administrative Templates > Windows Components > Windows PowerShell > Turn on PowerShell Script Block Logging`) across all endpoints.
* **Implement Just Enough Administration (JEA):** Constrain what commands users can execute via WinRM by enforcing JEA endpoints, preventing users from getting full interactive shell access when only specific maintenance tasks are needed.
* **Disable WinRM Where Unneeded:** On endpoints that do not require remote management, disable the `WinRM` service entirely via GPO.

---

## Conclusion

WinRM is a powerful feature for enterprise administration, but its native access and encrypted transport make it an attractive pathway for lateral movement. Security operations teams cannot rely solely on simple authentication logs to spot abuse. 

By combining host-based process lineage (`svchost.exe` -> `wsmprovhost.exe`), deep script block inspection (Event ID 4104), and network directional baselining, defenders can reliably isolate malicious WinRM usage from routine system administration.
