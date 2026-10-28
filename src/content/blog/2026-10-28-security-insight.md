---
title: "Detecting Malicious SSP Injection and LSA Persistence: Telemetry, Event ID 4622, and Memory Artifacts"
description: "An operational breakdown of Security Support Provider (SSP) persistence and dynamic LSASS injection, analyzing telemetry gaps, Event ID 4622, Sysmon event correlation, and detection logic."
date: "2026-10-28"
tags: ["Cybersecurity", "Security Operations", "Threat Detection", "Detection Engineering", "Windows Security"]
category: "Cyber Security"
difficulty: "Advanced"
author: "Abdul Muqeet Tabraiz"
image: "/images/blog/2026-10-28-detecting-malicious-ssp-injection-and-lsa-persistence-telemetry-event-id-4622-an.svg"
---

Security Support Providers (SSPs) are dynamic-link libraries (DLLs) loaded directly into the Local Security Authority Subsystem Service (`lsass.exe`) to implement Windows authentication mechanisms like NTLM, Kerberos, or Schannel. Because `lsass.exe` processes every cleartext authentication attempt on a system, injecting a custom SSP or modifying LSA configuration keys allows an adversary to capture cleartext credentials in real time and maintain persistence across reboots.

While endpoint detection and response (EDR) platforms have improved at flagging well-known post-exploitation frameworks, custom or modified SSP implementations still evade basic telemetry if your SOC relies solely on process creation events. Building reliable detections for SSP abuse requires combining Windows Security Event logs, Sysmon image loading telemetry, registry monitoring, and process memory inspections.

---

## Technical Architecture: How SSPs Interface with LSASS

The Local Security Authority (LSA) uses SSP interface functions to validate user credentials and generate authentication tokens. When an authentication request occurs, LSA passes the context down to the registered SSPs.

An SSP exports an entry point function named `SpLsaModeInitialize`. Within this function, the package returns a table of function pointers (`SECPKG_FUNCTION_TABLE`) to LSASS. Crucially, this table includes the `SpAcceptCredentials` callback function.

```
+-----------------------------------------------------------------------+
|                              lsass.exe                                |
|                                                                       |
|  +---------------------+      Calls      +-------------------------+  |
|  |   LSA Core Engine   | --------------->|  SpAcceptCredentials()  |  |
|  +---------------------+                 +-------------------------+  |
|                                                      |                |
|                                                      v                |
|                                         +--------------------------+  |
|                                         | Captures Cleartext Pass  |  |
|                                         | Writes to Disk / Memory  |  |
|                                         +--------------------------+  |
+-----------------------------------------------------------------------+
```

When a user logs on, changes their password, or authenticates locally or over the network, `lsass.exe` invokes `SpAcceptCredentials` for every registered package and passes the user’s account name, domain, and cleartext password in plaintext parameters:

```c
NTSTATUS NTAPI SpAcceptCredentials(
    SECURITY_LOGON_TYPE LogonType,
    PUNICODE_STRING AccountName,
    PUNICODE_STRING PrimaryDomain,
    PUNICODE_STRING Password,
    PUNICODE_STRING SupplementalCredentials,
    PULONG UserFlags
);
```

If an attacker injects a rogue DLL into `lsass.exe` that exports `SpAcceptCredentials`, they do not need to dump LSASS memory periodically or perform complex API hooking inside the LSASS address space. The operating system hands them cleartext credentials automatically whenever an authentication event occurs.

---

## Adversary Tradecraft: SSP Persistence vs. Dynamic Injection

Adversaries abuse SSPs using two primary mechanisms: disk-based registry persistence and in-memory runtime injection.

### 1. Registry-Based Persistence

To persist across reboots, an adversary drops a malicious DLL onto the disk (typically inside `C:\Windows\System32\`) and registers it in the Windows Registry under one of two keys:

- **Security Packages Key**:
  `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`
  *(Appends the DLL name without the extension to the `REG_MULTI_SZ` value).*
- **OS Configurations Key**:
  `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\OS Configurations\Security Packages`

When the system boots, `lsass.exe` iterates through the names listed in these registry values, loads the corresponding DLLs from `%SystemRoot%\System32`, and calls `SpLsaModeInitialize`.

### 2. Runtime Injection via `AddSecurityPackage`

Adversaries with `SeDebugPrivilege` do not have to wait for a system reboot. Using native Windows APIs like `AddSecurityPackage` (or `AddSecurityPackageW`), an attacker can dynamically load a custom SSP DLL into a running `lsass.exe` process.

Tooling like Mimikatz automates this via the `misc::ssp` module, which calls `AddSecurityPackage` pointing to `mimilib.dll` or a customized variant. When invoked, `lsass.exe` loads the target DLL from disk immediately, reads the exported function table, and registers `SpAcceptCredentials` in memory.

---

## Telemetry Sources and Event Artifacts

Detecting both persistence and dynamic injection requires telemetry from multiple Windows logging layers. Relying on a single log source leaves clear blind spots.

```
+--------------------------+-------------------------------------------------------+
| Telemetry Source         | Artifact Captured                                     |
+--------------------------+-------------------------------------------------------+
| Windows Security Log     | Event ID 4622 (Package Loaded by LSA)                 |
| Sysmon Event ID 7        | ImageLoaded into lsass.exe (Module path & signature)  |
| Sysmon Event ID 13/14    | Registry modification to LSA\Security Packages        |
| ETW Threat Intelligence  | Kernel memory allocation / Remote thread in lsass.exe |
+--------------------------+-------------------------------------------------------+
```

### 1. Windows Security Event ID 4622

Event ID 4622 is generated by the auditing subsystem when a security package is loaded by the Local Security Authority.

- **Audit Category**: Audit System Integrity
- **Default Status**: Enabled in standard baseline Windows Audit Policies, but often suppressed or uncollected in high-volume SIEM pipelines due to noisy boot-time logging.

A typical Event ID 4622 entry looks like this:

```xml
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <EventID>4622</EventID>
    <Version>0</Version>
    <Level>0</Level>
    <Task>12288</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8020000000000000</Keywords>
    <TimeCreated SystemTime="2026-10-28T14:22:10.124589100Z" />
    <EventRecordID>1048291</EventRecordID>
    <Channel>Security</Channel>
    <Computer>DC01.lab.local</Computer>
    <Security />
  </System>
  <EventData>
    <Data Name="SecurityPackageName">mimilib</Data>
  </EventData>
</Event>
```

**Key Observation**: Event ID 4622 fires both during system boot (for every registered SSP in the registry) and dynamically when `AddSecurityPackage` is executed. Notice that `SecurityPackageName` reflects the string passed to the API or loaded from the registry (often omitting the `.dll` extension).

### 2. Sysmon Event ID 7 (Image Load)

Sysmon ID 7 tracks module loads per process. Monitoring image loads specifically targeting `Image` ending in `\lsass.exe` provides crucial verification data:

- **OriginalFileName**: Discrepancies between the file on disk and its metadata.
- **Hashes**: SHA256 of the loaded DLL.
- **Signed / SignatureStatus**: Identifies unsigned or improperly signed DLLs loaded into `lsass.exe`.
- **ImageLoaded**: The full system path of the module loaded.

Legitimate default SSPs (such as `schannel.dll`, `msv1_0.dll`, `kerberos.dll`, `wdigest.dll`) reside in `C:\Windows\System32\` and are digitally signed by Microsoft. An attacker placing a custom DLL in `C:\Users\Public\ssp.dll` or `C:\Temp\mimilib.dll` stands out immediately in Sysmon ID 7 telemetry.

### 3. Sysmon Event ID 13 (Registry Value Set)

To catch the persistence vector before a reboot occurs, monitor modifications to the LSA registry path:

- **TargetObject**: `*\Control\Lsa\Security Packages`
- **EventType**: SetValue
- **Details**: Check if the string value contains non-standard entries.

---

## Detection Engineering Strategies

### Detection Rule 1: Dynamic or Unsigned SSP Loading (KQL)

This Kusto Query Language (KQL) query correlates Sysmon Image Load events (`Event ID 7`) with `lsass.exe`, flagging any loaded DLL that is either located outside `%SystemRoot%\System32` or lacks a valid Microsoft digital signature.

```kql
Sysmon_CL
| where EventID == 7
| where Image endswith "\\lsass.exe"
| extend ImageLoaded = tostring(EventData.ImageLoaded),
         Signed = tostring(EventData.Signed),
         SignatureStatus = tostring(EventData.SignatureStatus),
         Hashes = tostring(EventData.Hashes),
         Company = tostring(EventData.Company)
| where not(
    (ImageLoaded startswith "C:\\Windows\\System32\\" or ImageLoaded startswith "C:\\Windows\\SysWOW64\\") 
    and Signed == "true" 
    and Company == "Microsoft Corporation"
)
| project TimeGenerated, Computer, Image, ImageLoaded, Signed, SignatureStatus, Company, Hashes
```

### Detection Rule 2: Event ID 4622 Anomalous Package Registration (Sigma Format)

This Sigma rule detects Event ID 4622 occurrences where the package name does not match a baseline of standard Windows SSP modules.

```yaml
title: Non-Standard Security Support Provider Loaded in LSASS
id: c4b2a8f1-901d-4f1e-a12b-3e506e9f1201
status: experimental
description: Detects the loading of non-standard or custom Security Support Provider (SSP) modules into LSASS via Security Event ID 4622.
author: Abdul Muqeet Tabraiz
date: 2026-10-28
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4622
  filter_known_ssp:
    SecurityPackageName|lower:
      - 'schannel'
      - 'msv1_0'
      - 'kerberos'
      - 'tspkg'
      - 'pku2u'
      - 'cloudap'
      - 'wdigest'
      - 'negoexts'
      - 'negotiate'
      - 'ntlm'
      - 'credssp'
      - 'digest'
      - 'schannel'
  condition: selection and not filter_known_ssp
falsepositives:
  - Third-party enterprise authentication packages (e.g., Citrix Password Manager, Duo Security agents, Smart Card SSPs).
level: high
```

---

## Practical Investigation Workflow

When an alert triggers for an unusual SSP package or an unsigned DLL loading into `lsass.exe`, follow a structured investigation path:

```
+-------------------------------------------------------------------------+
|                        1. Telemetry Triage                              |
| Inspect Event ID 4622 & Sysmon Event ID 7 to isolate file path & hash.  |
+-------------------------------------------------------------------------+
                                   |
                                   v
+-------------------------------------------------------------------------+
|                       2. Registry & Disk Audit                          |
| Query HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages.      |
| Retrieve file metadata, compile timestamp, and authenticode status.     |
+-------------------------------------------------------------------------+
                                   |
                                   v
+-------------------------------------------------------------------------+
|                     3. Process Memory Analysis                          |
| Inspect LSASS executable memory structures for unbacked dynamic code.   |
+-------------------------------------------------------------------------+
                                   |
                                   v
+-------------------------------------------------------------------------+
|                   4. Remediation & Hardening                            |
| Scrub registry key, isolate endpoint, force credential reset, enable    |
| LSA Protection (PPL).                                                   |
+-------------------------------------------------------------------------+
```

### Step 1: Query Registry Baseline on the Endpoint

Verify the registry values for both standard and dynamic locations using PowerShell:

```powershell
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "Security Packages" | 
    Select-Object -ExpandProperty "Security Packages"
```

Look for anomalous string entries added to the list (e.g., `mimilib`, `ssp`, `kiwi`, or obscure random strings).

### Step 2: Validate Loaded Modules in Process Memory

If an adversary used dynamic injection without altering the registry, the registry check will appear clean. You must query loaded modules directly from the live `lsass.exe` process.

Using PowerShell (`Get-Process` combined with `.Modules` context):

```powershell
Get-Process lsass | Select-Object -ExpandProperty Modules | 
    Where-Object { $_.ModuleName -notmatch "msv1_0|kerberos|schannel|wdigest|pku2u|negoexts|credssp" } | 
    Select-Object ModuleName, FileName, Company, Size
```

If memory inspection is required via WinDbg or an EDR memory collection tool, inspect the `lsass.exe` loaded module list (`lm` command) and verify if the DLL's entry point maps to a valid, signed file on disk, or if it points to unbacked executable memory (`PAGE_EXECUTE_READWRITE`).

---

## Operational Considerations and Mitigations

### 1. Managing Enterprise False Positives

Third-party enterprise software occasionally installs legitimate custom SSPs. Common software that installs security packages includes:

- Multi-Factor Authentication (MFA) agents (e.g., Duo Security, Okta Credential Provider)
- Virtual Private Network (VPN) client adapters
- Virtual Desktop Infrastructure (VDI) credential providers (e.g., Citrix, VMware Horizon)
- Smart Card / Hardware Security Token driver packages

**Baseline Practice**: Build an environment-specific baseline. Hash and verify the digital signatures of legitimate third-party SSPs before adding them to your EDR/SIEM suppression rules.

### 2. Enforcing LSA Protection (PPL)

The most effective defensive control against unauthorized SSP loading is enabling **LSA Protection** (Protected Process Light / PPL). When enabled, Windows requires any code loaded into `lsass.exe` to be digitally signed with a specific Microsoft signature certificate. Unsigned or non-compliant SSP DLLs fail to load, even if the process possesses `SeDebugPrivilege`.

To enforce LSA Protection via Registry:

```cmd
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL /t REG_DWORD /d 1 /f
```

To verify whether LSA Protection is active on a endpoint, check Event ID 12 in the `Microsoft-Windows-CodeIntegrity/Operational` log or execute the following PowerShell command:

```powershell
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL"
```

*Note on Bypass Risk*: Sophisticated adversaries operating with administrative privileges can bypass PPL using Bring Your Own Vulnerable Driver (BYOVD) attacks (e.g., abusing signed, vulnerable kernel-mode drivers to clear the `EPROCESS` process protection flags in kernel memory). Therefore, monitoring kernel driver load events (Sysmon ID 6) remains an essential complementary control.

---

## Summary Baseline Checklist

To defend against SSP persistence and injection:

1. Enable **Audit System Integrity** in group policy to ensure Event ID 4622 is captured.
2. Ingest Sysmon Event ID 7 (Image Loaded) targeting `lsass.exe` into your SIEM and flag unsigned or off-path DLL loads.
3. Monitor `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages` for unauthorized modifications using Sysmon Event ID 13.
4. Enable LSA Protection (`RunAsPPL = 1`) across all Windows Workstations and Servers to enforce code-signing requirements on LSASS modules.
5. Baseline legitimate non-Microsoft SSPs in your environment to eliminate alert fatigue.
