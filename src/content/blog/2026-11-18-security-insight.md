---
title: "Detecting BYOVD Attacks: Kernel Telemetry, Driver Blocklists, and EDR Evasion"
description: "An in-depth analysis of Bring Your Own Vulnerable Driver (BYOVD) tactics, kernel callback tampering, driver telemetry sources, and practical detection engineering strategies."
date: "2026-11-18"
tags: ["Cybersecurity", "Detection Engineering", "Threat Hunting", "Windows Security"]
category: "Cyber Security"
difficulty: "Advanced"
author: "Abdul Muqeet Tabraiz"
image: "/images/blog/2026-11-18-detecting-byovd-attacks-kernel-telemetry-driver-blocklists-and-edr-evasion.svg"
---

Kernel-level security controls form the baseline of modern Endpoint Detection and Response (EDR) platforms. EDR agents rely heavily on kernel notification routines—such as process creation, thread creation, and image loading callbacks—to monitor system activity and enforce protection policies. However, when an adversary gains ring 0 execution privileges, those telemetry streams can be suppressed or blindfolded entirely.

Because Driver Signature Enforcement (DSE) on 64-bit Windows prevents the execution of unsigned kernel drivers, threat actors rarely attempt to load completely unauthenticated binaries. Instead, they leverage Bring Your Own Vulnerable Driver (BYOVD) attacks. By dropping a legitimately signed, third-party driver containing known arbitrary memory read/write primitives, adversaries achieve kernel execution within a fully trusted context.

This article breaks down the mechanics of BYOVD attacks, how adversaries abuse kernel memory to blind EDR agents, the key telemetry sources required for detection, and practical strategies for detection engineering and mitigation.

---

## The BYOVD Execution Lifecycle

A BYOVD attack does not attempt to bypass code integrity checks at the cryptographic level. The driver binary is signed by a valid commercial Certificate Authority (CA) or a vendor certificate accepted by Windows. The underlying flaw resides in the driver's implementation logic—specifically, exposing insecure I/O Control (IOCTL) codes to user-mode processes without validating buffer parameters.

```
+------------------+         IOCTL Request          +-----------------------+
| User-Mode Process | ----------------------------> | Signed Driver (.sys)  |
|  (Malicious App)  | <---------------------------- | (Exposes Vulnerable   |
+------------------+     Kernel Memory Access       |  Read/Write Primitive)|
                                                    +-----------------------+
                                                                |
                                                                v
                                                    +-----------------------+
                                                    | Kernel Space (Ring 0) |
                                                    | - Unhook EDR Callbacks|
                                                    | - Patch Kernel Data   |
                                                    +-----------------------+
```

### 1. Privilege Check and Dropping the Driver
To load a kernel driver via standard Windows APIs, the user-mode process must execute under an elevated account (such as `NT AUTHORITY\SYSTEM` or a local administrator with `SeLoadDriverPrivilege` enabled). The adversary writes the vulnerable `.sys` binary to disk—frequently in non-standard locations such as `C:\Windows\Temp\`, `C:\Users\Public\`, or `AppData\Local\Temp\`.

### 2. Service Creation and Driver Loading
The adversary installs the driver as a system service. This can be accomplished through:
* Callouts to `CreateServiceW()` and `StartServiceW()` via the Windows Service Control Manager (SCM).
* Direct execution of command-line utilities like `sc.exe create` and `sc.exe start`.
* Native API calls such as `NtLoadDriver`, supplying a registry path under `HKLM\SYSTEM\CurrentControlSet\Services\`.

### 3. Exploitation via IOCTL Communication
Once loaded, the driver registers a device object (e.g., `\\Device\\VulnerableDevice`) and a symbolic link accessible from userland. The adversary opens a handle to the driver using `CreateFileW()` and issues `DeviceIoControl()` requests.

Vulnerable drivers such as `RTCCore64.sys` (Micro-Star International) or `gdrv.sys` (GIGABYTE) expose IOCTL handlers that perform mapping operations (`MmMapIoSpace`) or copy memory (`RtlCopyMemory`) between user and kernel addresses without boundary validation.

### 4. Kernel Telemetry Disruption
With an arbitrary kernel read/write primitive active, the adversary enumerates internal Windows kernel structures to blind security tooling:
* **Callback Array Stripping:** The adversary locates kernel structures like `PspCreateProcessNotifyRoutine`, `PspCreateThreadNotifyRoutine`, and `PspLoadImageNotifyRoutine`. By zeroing out or overwriting the pointers to the EDR's callback functions within these arrays, the EDR stops receiving process and thread creation events.
* **Object Table Tampering:** Modifying process handles in the kernel `_EPROCESS` structure to strip access rights or set `Protection` flags (Protected Process Light - PPL) on malicious processes while removing them from EDR binaries.
* **ETW-TI Disruption:** Patching kernel functions responsible for Event Tracing for Windows Threat Intelligence (ETW-TI), such as `EtwTiLogKernelEvent`.

---

## Key Telemetry Sources for BYOVD Detection

Defending against BYOVD requires catching the driver at installation, loading, or early execution before kernel callback arrays are corrupted. Relying solely on EDR process telemetry is insufficient because an effective BYOVD payload silences the agent after execution.

### 1. System Event Log: Event ID 7045 & Security Log: Event ID 4697
Whenever a new service is created to host a driver, Windows logs Event ID 7045 in the System log and Event ID 4697 in the Security log.

* **Event ID 7045 (System):**
  * `ServiceName`: Name of the created service.
  * `ImagePath`: System path to the `.sys` file.
  * `ServiceType`: `kernel driver` (0x1) or `file system driver` (0x2).
  * `StartType`: Typically `demand start` (0x3) or `system start` (0x1).

* **Event ID 4697 (Security):**
  * Requires auditing policy: **Audit Security System Extension**.
  * Contains identical service attributes along with the `SubjectUserSid` and `SubjectProcessId` of the process initiating service creation.

### 2. Sysmon: Event ID 6 (Driver Loaded)
Sysmon provides high-fidelity kernel driver loading events. Unlike basic service creation logs, Sysmon inspects code signatures and hashes at the moment of loading.

Key fields to monitor in Event ID 6:
* `ImageLoaded`: Full path of the driver file loaded into the kernel.
* `Hashes`: SHA256/MD5 of the driver binary.
* `Signed`: Boolean value indicating signature validity.
* `Signature`: Signing vendor/entity name.
* `SignatureStatus`: Details on certificate validity (e.g., `Valid`, `Expired`, `Revoked`).

### 3. Microsoft-Windows-CodeIntegrity Telemetry
The Windows CodeIntegrity ETW provider generates events when drivers fail validation or violate integrity policies:
* **Event ID 3033:** Code Integrity determined that a process tried to load an unsigned image or a driver failing integrity checks.
* **Event ID 3076 / 3077:** Driver load blocked due to policy rules or revoked signatures.
* **Event ID 3084:** Hypervisor-Protected Code Integrity (HVCI) violation events.

---

## Detection Engineering & Practical Queries

### Rule 1: Non-Standard Driver Load Paths (KQL)

Legitimate enterprise drivers are generally installed into standard directories (`C:\Windows\System32\drivers\`, `C:\Program Files\`, or `C:\Program Files (x86)\`). Malicious actors frequently stage drivers in writable staging directories.

The following Kusto Query Language (KQL) query flags driver loading events originating from abnormal locations using Sysmon Event ID 6 telemetry:

```kql
Sysmon_EventID_6_DriverLoad
| where TimeGenerated > ago(24h)
| extend ImageLoaded = tolower(ImageLoaded)
| where not(ImageLoaded startswith @"c:\windows\system32\drivers\" 
        or ImageLoaded startswith @"c:\windows\winsxs\"
        or ImageLoaded startswith @"c:\program files\"
        or ImageLoaded startswith @"c:\program files (x86)\")
| project TimeGenerated, Computer, ImageLoaded, Hashes, Signed, Signature, SignatureStatus
| sort by TimeGenerated desc
```

### Rule 2: Detecting Known Vulnerable Drivers via Sysmon Configuration

Sysmon rules can directly target known vulnerable driver hashes identified in public repositories (such as LSA Driver Blocklists or the CISA Known Exploited Vulnerabilities catalog).

Below is a Sysmon configuration snippet targeting known vulnerable driver hashes (e.g., `gdrv.sys` and `RTCCore64.sys` variants):

```xml
<Sysmon schemaversion="4.90">
  <EventFiltering>
    <RuleGroup level="include" default="include">
      <DriverLoad onmatch="include">
        <!-- GDRV.sys SHA256 -->
        <Hashes condition="contains">SHA256=31f4712532ed7858c4fad8100acd39b0079b392a02e60a9f5d1797e7592cf136</Hashes>
        <!-- RTCCore64.sys SHA256 -->
        <Hashes condition="contains">SHA256=01aa278edc1c872ea84412373831691a05a7289414d50db90967e0e830b2ed7d</Hashes>
        <!-- Catch drivers loaded from suspicious directories -->
        <ImageLoaded condition="begin with">C:\Users\Public\</ImageLoaded>
        <ImageLoaded condition="begin with">C:\Windows\Temp\</ImageLoaded>
        <ImageLoaded condition="contains">\AppData\Local\Temp\</ImageLoaded>
      </DriverLoad>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
```

### Rule 3: Abusive Service Creation Patterns (Sigma Rule)

Detecting the execution of command-line service tools (`sc.exe`) used to configure driver services dynamically:

```yaml
title: Driver Service Creation in Non-Standard Location
id: e4b2591a-7b3c-4a21-9311-d93510257321
status: experimental
description: Detects command-line service creation pointing to driver binaries located in user-writable directories.
author: Abdul Muqeet Tabraiz
logsource:
  category: process_creation
  product: windows
detection:
  selection_sc:
    Image|endswith: '\sc.exe'
    CommandLine|contains|all:
      - 'create'
      - 'type= kernel'
  selection_paths:
    CommandLine|contains:
      - '\AppData\Local\Temp\'
      - '\Users\Public\'
      - '\Windows\Temp\'
      - 'C:\Temp\'
  condition: selection_sc and selection_paths
falsepositives:
  - Custom legacy administrative scripts (should be baselined and excluded)
level: high
```

---

## Behavioral Post-Exploitation Signals

When an adversary successfully loads a vulnerable driver and zero-out process notification routines, telemetry drops off sharply. Detection engineers can hunt for these structural anomalies using secondary metrics:

### 1. Telemetry Silence (Heartbeat Gaps)
If an endpoint actively generating thousands of process creation events per hour suddenly stops reporting process execution telemetry while sending basic system heartbeats, this indicates potential callback unhooking.

```
Expected State:  [ Kernel ] ---> Callbacks ---> [ EDR Sensor ] ---> SIEM (Process Logs)
Attacked State:  [ Kernel ] -X-> Callbacks ---> [ EDR Sensor ] (Silent - Telemetry Severed)
```

### 2. Privilege Enumeration (`SeLoadDriverPrivilege`)
Processes issuing requests to adjust token privileges for `SeLoadDriverPrivilege` (Privilege 10) outside of standard installer routines (`msiexec.exe`, OS updating processes) represent high-risk activity. Tracking process access events for `TOKEN_ADJUST_PRIVILEGES` combined with `SeLoadDriverPrivilege` flags suspicious staging.

---

## Defensive Recommendations & Hardening

Detecting BYOVD is vital, but blocking driver execution at the hypervisor and OS levels is the most resilient strategy.

### 1. Enable Microsoft Vulnerable Driver Blocklist
Windows includes a built-in Vulnerable Driver Blocklist enforced via Hypervisor-Protected Code Integrity (HVCI) or Windows Defender Application Control (WDAC).
* Ensure **Memory Integrity (HVCI)** is enabled in Windows Security settings or via Group Policy (`Computer Configuration -> Administrative Templates -> System -> Device Guard -> Turn On Virtualization Based Security`).
* Verify that driver blocklisting is active. On Windows 11, this feature is enabled by default. On Windows 10, it requires enabling HVCI or S-Mode policies.

### 2. Deploy Windows Defender Application Control (WDAC) Policies
Custom WDAC policies can restrict driver execution strictly to a approved set of publisher certificates, blocking all unauthorized third-party signed drivers regardless of overall signature validity.

Example WDAC rule logic snippet for driver restriction:
```xml
<Rule ID="ID_DENY_VULN_DRIVER" Action="Deny">
  <FileNameCondition Name="gdrv.sys" />
</Rule>
```

### 3. Restrict `SeLoadDriverPrivilege`
Restrict driver loading permissions to local administrators only, and eliminate administrative privileges for standard corporate domain users. Implement Privileged Access Management (PAM) controls to audit elevated sessions capable of acquiring `SeLoadDriverPrivilege`.

---

## Operational Challenges and Limitations

When deploying BYOVD detections, security teams face specific operational trade-offs:

1. **Legacy System Support:** Older enterprise hardware monitoring utilities, specialized industrial tools, and legacy VPN clients frequently rely on drivers containing insecure code patterns. Blocking drivers universally via hash lists can cause immediate operational disruption if baseline testing is bypassed.
2. **Hash Mutation & Certificate Rollover:** Adversaries can rebuild signed driver binaries using slightly different compiler flags or alternative certificate signers, rendering strict SHA256 blocklists ineffective. Focus detections on path anomalies, certificate signer metadata, and service creation behavior rather than static file hashes alone.
3. **Out-of-Date Blocklists:** The Microsoft Vulnerable Driver Blocklist is updated primarily during major Windows updates or out-of-band security releases. Air-gapped or infrequently patched systems remain vulnerable to older signed drivers unless managed via custom WDAC enterprise policies.

---

## Summary

Bring Your Own Vulnerable Driver attacks highlight a key operational reality: a valid digital signature does not equate to secure execution. By leveraging vulnerable, trusted drivers, adversaries can gain ring 0 access and disable security monitoring tools from within the kernel.

Defenders cannot rely solely on process creation telemetry when operating in a post-exploitation kernel context. Resilient detection strategies require combining service creation auditing (Event ID 7045/4697), driver load validation (Sysmon Event ID 6), path-based anomaly detection, and kernel memory integrity protections like HVCI and WDAC driver blocklists.
