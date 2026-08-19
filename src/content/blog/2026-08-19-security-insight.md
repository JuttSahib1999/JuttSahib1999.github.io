---
title: "Detecting RPC Coercion and Named Pipe Impersonation: Telemetry Architecture and Detection Logic"
description: "A deep dive into the mechanics of Remote Procedure Call (RPC) coercion attacks, examining kernel and endpoint telemetry streams to build high-fidelity detections beyond standard authentication logs."
date: "2026-08-19"
tags: ["Detection Engineering", "Active Directory", "Threat Hunting", "Telemetry"]
category: "Cyber Security"
difficulty: "Advanced"
author: "Abdul Muqeet Tabraiz"
image: "/images/blog/2026-08-19-detecting-rpc-coercion-and-named-pipe-impersonation-telemetry-architecture-and-d.svg"
---

When an adversary compromises a low-privileged machine or unauthenticated network segment, gaining access to a High-Value Target (HVT) or Domain Controller frequently requires coercing that machine to authenticate elsewhere. Techniques such as PetitPotam (MS-EFSR), SpoolSample (MS-RPRN), DFSCoerce (MS-DFSNM), and ShadowCoerce (MS-FSRVP) leverage legitimate Remote Procedure Call (RPC) interfaces exposed by Windows servers. 

Once an RPC method is invoked remotely, the target server initiates an outgoing SMB or HTTP authentication request—typically under the context of its own machine account (`COMPUTER$`)—to an attacker-controlled endpoint. Paired with NTLM relay attacks targeting Active Directory Certificate Services (AD CS) or HTTP-based Enterprise Web Enrollment endpoints, RPC coercion regularly leads to immediate domain compromise.

Most Security Operations Centers (SOCs) attempt to detect these attacks at the destination—focusing on incoming NTLM authentication logs (Event ID 4624 Type 3 or Event ID 4776 on Domain Controllers). However, relying solely on authentication logs yields significant blind spots. By the time a Domain Controller processes an authentication attempt, the coercion has succeeded. Detecting the attack requires instrumenting RPC server endpoints, monitoring IPC$ share connections, and dissecting RPC interface interactions.

---

## RPC Coercion Mechanics

RPC coercion exposes a structural design flaw in legacy and modern Windows services: certain RPC functions accept arbitrary network paths as parameters and instruct the local system to connect to those paths over SMB (`\\attacker_ip\share`) or HTTP.

```
+------------------+                    +------------------+                    +-------------------+
|  Attacker Host   | -- 1. RPC Call --> |   Target Server  | -- 2. SMB/HTTP --> | Attacker Listener |
|  (PetitPotam)    |    (MS-EFSR Bind)  |  (Domain Contr.) |    Auth (NTLM)     |  (Responder/ntlm) |
+------------------+                    +------------------+                    +-------------------+
                                                                                          |
                                                                                    3. Relay NTLM
                                                                                          v
                                                                                +-------------------+
                                                                                | AD CS / PKI Server|
                                                                                +-------------------+
```

### Key RPC Interfaces Targeted

1. **MS-RPRN (Print System Remote Protocol)**
   * **Pipe Name**: `\pipe\spoolss`
   * **Interface UUID**: `12345678-1234-ABCD-EF00-0123456789AB`
   * **Vector Function**: `RpcRemoteFindFirstPrinterChangeNotificationEx`
   * **Execution Context**: Runs under `spoolsv.exe`.

2. **MS-EFSR (Encrypting File System Remote Protocol)**
   * **Pipe Names**: `\pipe\efsrpc`, `\pipe\lsarpc`, `\pipe\samr`, `\pipe\lsass`
   * **Interface UUID**: `c681d488-d850-11d0-8c52-00c04fd90f7e` or `df194115-3d0b-4f5e-8438-128e503d6557`
   * **Vector Functions**: `EfsRpcOpenFileRaw`, `EfsRpcEncryptFileSrv`
   * **Execution Context**: Handled by `lsass.exe`.

3. **MS-DFSNM (Distributed File System Management Protocol)**
   * **Pipe Name**: `\pipe\netdfs`
   * **Interface UUID**: `4b324fc8-1670-01d3-1278-5a47bf6ee188`
   * **Vector Function**: `NetrDfsRemoveStdVariableProportion`
   * **Execution Context**: Managed by `NetSetupSvc` / `lsass.exe`.

The fundamental challenge with these methods is that they leverage valid SMB named pipes over the IPC$ share. Standard access checks allow authenticated users—and in many unpatched configurations, anonymous `NULL` sessions—to bind to the pipe and execute the RPC procedure.

---

## The Telemetry Gap in Standard Logs

A common mistake in detection engineering is attempting to catch coercion by querying Active Directory Domain Controller Security Logs for Event ID 4776 (`The domain controller attempted to validate the credentials for an account`) or Event ID 4624 (`An account was successfully logged on`).

While these events log the resulting NTLM logon attempt on the listening server, they fail to supply critical context:
* **No RPC Context**: Security Event ID 4624 shows an NTLM authentication originating from an IP address, but it cannot indicate *which* process or RPC interface triggered the outgoing connection from the target host.
* **Network Obfuscation**: If an attacker relays the credentials across multiple internal subnets or proxy tunnels, authentication telemetry alone fails to correlate the initial RPC trigger with the resulting NTLM authentication.
* **Null Session Anonymity**: Coercion initiated via unauthenticated IPC$ bindings leaves limited context in default Security Event Logs.

To achieve precise attribution, we must collect telemetry from the endpoint where the RPC call is *received* and *processed*.

---

## Endpoint and Kernel Telemetry Architecture

Effective detection of RPC coercion requires multi-layered telemetry targeting named pipe creation, named pipe access, RPC Event Tracing for Windows (ETW), and Windows Filtering Platform (WFP) network events.

```
+-------------------------------------------------------------------------+
|                              Host Kernel                                |
+-------------------------------------------------------------------------+
       |                                   |                       |
       v                                   v                       v
[Named Pipe Events]               [RPC Subsystem ETW]     [WFP Layer Events]
 Sysmon 17 & 18                   Microsoft-Windows-RPC   Event ID 5156
 (Pipe Create / Connect)          Provider                (Filter Engine)
       |                                   |                       |
       +-------------------+---------------+-----------------------+
                           |
                           v
              [SIEM / Correlation Engine]
```

### 1. Named Pipe Auditing (Sysmon & Security Event ID 5145)

When an attacker connects to an RPC interface over SMB, they open a file handle to a named pipe hosted on the `IPC$` share.

* **Sysmon Event ID 17 (PipeCreated)** and **Event ID 18 (PipeConnected)**: Sysmon captures named pipe connections. An Event ID 18 where `Image` is `System` or `lsass.exe` and `PipeName` matches a known vulnerable RPC interface (`\efsrpc`, `\spoolss`, `\netdfs`) indicates potential coercion activity when triggered from anomalous source processes or outside routine admin activity.
* **Windows Security Event ID 5145 (A network share object was checked for access)**: Requires enabling the `Audit Detailed File Share` policy. While high volume, this captures access to `IPC$` where `RelativeTargetName` matches `spoolss`, `efsrpc`, or `lsarpc`.

Example Event ID 5145 payload snippet:

```xml
<EventData>
  <Data Name="SubjectUserName">ANONYMOUS LOGON</Data>
  <Data Name="SubjectDomainName">NT AUTHORITY</Data>
  <Data Name="ShareName">\\*\IPC$</Data>
  <Data Name="ShareLocalPath"></Data>
  <Data Name="RelativeTargetName">efsrpc</Data>
  <Data Name="AccessMask">0x3</Data>
</EventData>
```

An `ANONYMOUS LOGON` accessing `RelativeTargetName: efsrpc` is an immediate indicator of unauthenticated RPC coercion attempts.

### 2. Deep RPC Telemetry via ETW (`Microsoft-Windows-RPC`)

To inspect the actual RPC calls, we must turn to Event Tracing for Windows (ETW). The `Microsoft-Windows-RPC` provider (`{6ad52b32-d609-4be9-ae07-0522ba949700}`) generates detailed events for RPC server interface bindings and method calls.

Key Event IDs within `Microsoft-Windows-RPC`:
* **Event ID 5**: Server call start. Captures the `InterfaceUuid`, `ProcNum` (Procedure Number), and `Protocol` sequence.
* **Event ID 6**: Server call stop.

By monitoring Event ID 5 for the `Microsoft-Windows-RPC` provider on sensitive systems (such as DCs), we can identify execution of specific Procedure Numbers corresponding to coercion primitives:

| Interface | Interface UUID | Coercion Procedure Number (`ProcNum`) |
| :--- | :--- | :--- |
| **MS-RPRN** | `12345678-1234-abcd-ef00-0123456789ab` | `ProcNum 15` (`RpcRemoteFindFirstPrinterChangeNotificationEx`) |
| **MS-EFSR** | `c681d488-d850-11d0-8c52-00c04fd90f7e` | `ProcNum 0` (`EfsRpcOpenFileRaw`), `ProcNum 1` (`EfsRpcEncryptFileSrv`) |
| **MS-DFSNM**| `4b324fc8-1670-01d3-1278-5a47bf6ee188` | `ProcNum 12` (`NetrDfsRemoveStdVariableProportion`) |

---

## Constructing High-Fidelity Detections

Below are practical detection logic implementations across common enterprise query languages.

### Detection 1: KQL Query for Sysmon Named Pipe Access to Vulnerable Coercion Interfaces

This KQL query detects incoming client connections to named pipes associated with MS-EFSR and MS-RPRN, filtered against expected administrative usage patterns.

```kql
Sysmon_Event_18
| where EventID == 18
| where PipeName has_any (@"\efsrpc", @"\spoolss", @"\netdfs", @"\lsarpc")
| extend ProcessName = tolower(Image)
| where ProcessName in ("c:\\windows\\system32\\lsass.exe", "c:\\windows\\system32\\spoolsv.exe")
// Exclude known administrative management subnets if applicable
| summarize ConnectionCount = count(), FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated) 
  by Computer, PipeName, ProcessName, SourceUser
| where ConnectionCount > 0
```

### Detection 2: Splunk SPL Query for RPC ETW Interface Invocations

Using data ingested from custom ETW collectors or EDR agents subscribing to `Microsoft-Windows-RPC`:

```splunk
index=windows_etw Provider_Name="Microsoft-Windows-RPC" EventCode=5
| eval InterfaceUuid=lower(InterfaceUuid)
| search (InterfaceUuid="c681d488-d850-11d0-8c52-00c04fd90f7e" AND ProcNum IN (0, 1, 2))
      OR (InterfaceUuid="12345678-1234-abcd-ef00-0123456789ab" AND ProcNum=15)
      OR (InterfaceUuid="4b324fc8-1670-01d3-1278-5a47bf6ee188" AND ProcNum=12)
| stats count min(_time) as firstTime max(_time) as lastTime by host, ClientAddress, InterfaceUuid, ProcNum
| convert ctime(firstTime) ctime(lastTime)
```

### Detection 3: Correlating RPC Calls with Immediate Outbound SMB (Network/WFP)

A robust detection logic pattern correlates an inbound RPC bind with an immediate outbound TCP/445 or TCP/80 connection originating from the target host within a tight timeframe ($\Delta t \le 3\text{ seconds}$).

```kql
let TimeWindow = 3s;
let InboundRPC = 
    SecurityEvent
    | where EventID == 5145
    | where RelativeTargetName in~ ("efsrpc", "spoolss", "netdfs")
    | project RPC_Time = TimeGenerated, Computer, ClientIP = IpAddress, TargetPipe = RelativeTargetName;
let OutboundConnection = 
    DeviceNetworkEvents
    | where ActionType == "ConnectionSuccess"
    | where RemotePort in (445, 80, 443)
    | where InitiatingProcessFileName in~ ("lsass.exe", "spoolsv.exe", "services.exe")
    | project Outbound_Time = TimeGenerated, Computer = DeviceName, DestinationIP = RemoteIP, InitiatingProcessFileName;
InboundRPC
| join kind=inner (OutboundConnection) on Computer
| where Outbound_Time between (RPC_Time .. (RPC_Time + TimeWindow))
| project RPC_Time, Outbound_Time, Computer, ClientIP, TargetPipe, DestinationIP, InitiatingProcessFileName
```

---

## Hardening Strategies and Architectural Mitigations

Detections provide visibility, but preventing RPC coercion requires reducing the attack surface. Relying entirely on detection logic without implementing structural controls leaves an enterprise vulnerable to zero-day coercion vectors.

### 1. Disabling Unnecessary Services

If a server does not function as an active Print Server, disable the Print Spooler service (`spoolsv.exe`) completely via Group Policy.

```powershell
Stop-Service -Name "Spooler" -Force
Set-Service -Name "Spooler" -StartupType Disabled
```

### 2. Enforcing RPC Filters via Group Policy

Windows supports native RPC filtering using Firewall RPC rules or the RPC Runtime Filtering Engine. You can block remote access to the MS-EFSR interface GUID while retaining local functionality.

Create an RPC filter via Netsh or Group Policy to block remote calls to interface `c681d488-d850-11d0-8c52-00c04fd90f7e`:

```cmd
netsh rpc filter add rule layer=um context=local_only ifuuid=c681d488-d850-11d0-8c52-00c04fd90f7e
```

### 3. Restricting NT Lan Manager (NTLM) Authentication

RPC coercion relies heavily on coercing NTLM authentication, as NTLM will automatically attempt to authenticate against arbitrary paths provided in RPC parameters.

* **Enable Extended Protection for Authentication (EPA)** on IIS/AD CS endpoints to prevent relayed NTLM tokens from being accepted.
* **Disable NTLM Across Active Directory**: Transition to pure Kerberos authentication by enabling `Network security: Restrict NTLM: NTLM authentication in this domain` via GPO. When Kerberos is enforced, coerced SMB connections fail to authenticate automatically without prior Kerberos ticket acquisition for the target listener SPN.
* **Require SMB Signing & SMB Encryption**: Enforce `EnableSecuritySignature = 1` and `RequireSecuritySignature = 1` across all infrastructure endpoints to block NTLM relaying over SMB.

---

## Operational Trade-Offs and Performance Considerations

Implementing deep RPC telemetry and aggressive security controls carries distinct operational trade-offs:

1. **`Microsoft-Windows-RPC` ETW Volume**: Ingesting raw RPC ETW events across thousands of domain-joined systems generates massive log volume. Enable ETW-based RPC tracing selectively—focusing strictly on critical assets like Active Directory Tier-0 infrastructure, PKI servers, and Key Distribution Centers (KDCs).
2. **Audit 5145 Performance Impact**: Enabling `Audit Detailed File Share` logs every single read/write operation against shares, including `IPC$`. On high-throughput Domain Controllers, this setting can cause log rollover within minutes and increase CPU utilization on the server. Filter this event locally using agent-side filtering (e.g., Winlogbeat, Sysmon, or Sentinel agent rules) to drop events where `RelativeTargetName` does not match high-risk pipe patterns before network transmission.
3. **Application Compatibility with RPC Filtering**: Indiscriminately blocking RPC interfaces (such as `MS-EFSR` or `MS-RPRN`) without verifying dependencies can break backup solutions, third-party deployment tools, and remote administration tools (e.g., SCCM, enterprise management suites). Always run RPC filtering in audit mode prior to enforcing blocks across production systems.

---

## Summary Strategy

| Vector | Telemetry Source | Signal Fidelity | Primary Mitigation |
| :--- | :--- | :--- | :--- |
| **MS-RPRN** (`\spoolss`) | Sysmon 18 / Event ID 5145 | High | Disable `spoolsv.exe` on DCs and Tier-0 servers. |
| **MS-EFSR** (`\efsrpc`) | RPC ETW (ProcNum 0,1) / Event ID 5145 | High | Implement RPC Netsh rules / Apply MS security updates. |
| **MS-DFSNM** (`\netdfs`) | Sysmon 18 / WFP Event ID 5156 | Medium-High | Restrict DFS management interface permissions. |
| **NTLM Relay Target** | Security Event 4624 / IIS Logs | Low (Post-Exploit) | Enforce EPA on AD CS, enforce SMB Signing, restrict NTLM. |

By moving detection engineering efforts upstream to the RPC runtime interface and pipe binding layer, SOC teams can reliably catch coercion attempts regardless of which protocol vector or obscure method an adversary employs.
