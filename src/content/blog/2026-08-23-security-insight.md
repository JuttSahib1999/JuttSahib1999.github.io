---
title: "Detecting BYOVD Attacks: Telemetry Architecture, Driver Blocklists, and Kernel Auditing"
description: "An advanced technical breakdown of Bring Your Own Vulnerable Driver (BYOVD) tactics, driver load telemetry, detection logic using KQL, and engineering controls to prevent EDR blinding."
date: "2026-08-23"
tags: ["Cybersecurity", "Detection Engineering", "Endpoint Security", "Threat Hunting"]
category: "Cyber Security"
difficulty: "Advanced"
author: "Abdul Muqeet Tabraiz"
image: "/images/blog/2026-08-23-detecting-byovd-attacks-telemetry-architecture-driver-blocklists-and-kernel-audi.svg"
---

Endpoint Detection and Response (EDR) agents rely heavily on Windows kernel notification callbacks to maintain visibility and enforce protections. Routines such as `PspCreateProcessNotifyRoutine`, `PspCreateThreadNotifyRoutine`, `PspLoadImageNotifyRoutine`, and object manager callbacks (`ObRegisterCallbacks`) allow security tools to intercept process creation, thread injection, module loads, and direct process memory access.

Adversaries operating with local administrative privileges face a fundamental problem: user-mode API hooking and DLL unhooking can bypass user-land telemetry, but they cannot disable kernel-level callbacks directly from Ring 3. To strip these kernel hooks or blind the EDR agent, attackers frequently resort to **Bring Your Own Vulnerable Driver (BYOVD)** attacks.

By dropping and loading a legitimately signed, legacy, or vulnerable third-party driver, an attacker leverages arbitrary kernel memory read/write primitives exposed via unsafe IOCTL (Input/Output Control) handlers. Once executed, the attacker can overwrite kernel structures, unhook EDR notification routines, terminate protected anti-malware processes (AMSI/PPL), or hide processes entirely without triggering Driver Signature Enforcement (DSE) violations.

This article details the mechanics of BYOVD exploitation, the telemetry generated during execution, practical KQL detection rules, and the architectural trade-offs inherent in driver blocklisting and detection engineering.

---

## Anatomy of a BYOVD Attack

To load a driver on modern Windows systems without exploiting zero-day kernel vulnerabilities, an attacker must satisfy Driver Signature Enforcement (DSE). DSE mandates that all kernel-mode drivers loaded into the OS possess a valid digital signature from a trusted certificate authority or Microsoft's Windows Hardware Compatibility Program (WHCP).

In a BYOVD scenario, the attacker brings an older, legitimately signed driver that contains known security vulnerabilities—typically arbitrary physical/virtual memory read and write primitives exposed to user-mode code through symbolic links and device objects.

```
+-------------------------------------------------------------------+
|                        User Mode (Ring 3)                         |
|                                                                   |
|   [ Malicious Executable ] --(1. sc create / NtLoadDriver)----->  |
|             |                                                     |
|             +-------------(2. CreateFileW: \\.\DeviceObject)----> |
|             |                                                     |
|             +-------------(3. DeviceIoControl: Read/Write IOCTL)->|
+-------------|-----------------------------------------------------|
              |                                                     
              v                                                     
+-------------------------------------------------------------------+
|                       Kernel Mode (Ring 0)                        |
|                                                                   |
|   [ Vulnerable Signed Driver ] (e.g., RTCore64.sys)               |
|             |                                                     |
|             +----(4. Arbitrary Kernel Write)-------------------->  |
|                                                                   |
|   [ Kernel Memory ]                                               |
|     - PspCreateProcessNotifyRoutine  <-- [ Zeroed out / Patched ] |
|     - EPROCESS ActiveProcessLinks    <-- [ Direct Kernel Modification ]
+-------------------------------------------------------------------+
```

### The Execution Lifecycle

1. **Staging the Driver File**: The attacker writes the vulnerable driver (`.sys`) to disk (frequently in `C:\Windows\System32\drivers\`, `C:\Windows\Temp\`, or `C:\Users\Public\`).
2. **Service Registration**: The attacker creates a kernel-driver service entry in the registry under `HKLM\SYSTEM\CurrentControlSet\Services\<DriverName>`. This is executed via `sc.exe`, PowerShell (`New-Service`), or direct Win32 API calls (`CreateServiceW`).
3. **Driver Loading**: The driver is loaded into Ring 0 using `StartServiceW`, `sc start`, or the native API `NtLoadDriver`. This step requires the `SeLoadDriverPrivilege` (enabled by default for Administrators).
4. **Device Interaction**: The user-mode malware obtains a handle to the driver’s exposed device object using `CreateFileW` (e.g., `\\.\RTCore64` or `\\.\GDRV`).
5. **IOCTL Payload Execution**: The user-mode process sends crafted input buffers via `DeviceIoControl` triggering vulnerable driver routines. 
   - *Example*: The driver `RTCore64.sys` (MSI Afterburner utility) exposes IOCTL `0x80002048` and `0x8000204C`, which allow arbitrary 1, 2, or 4-byte reads and writes to physical memory addresses without privilege checks.
6. **Kernel Manipulation**: Using the primitive, the malware traverses kernel structures (`EPROCESS` chains, `PspCreateProcessNotifyRoutine` arrays) to patch kernel routines or strip EDR process callbacks, effectively blinding defense controls for subsequent malicious activity.

---

## Telemetry Sources and Event Artifacts

Detecting BYOVD requires capturing events across driver drop, service installation, driver load, and registry operations. Relying on a single telemetry source often creates gaps due to volume throttling or agent-blinding race conditions.

### 1. Service Installation Telemetry

When a driver service is created, the Windows Event Log records details about the service name, image path, and service type.

* **Windows System Log - Event ID 7045**: *A service was installed in the system.*
  * `ServiceType`: `0x2` specifies a Kernel Driver (`SERVICE_KERNEL_DRIVER`).
  * `ImagePath`: The file path pointing to the `.sys` binary.
  * `AccountName`: The context executing the installation (typically `SYSTEM` or an administrative user).

* **Windows Security Log - Event ID 4697**: *A service was installed in the system.*
  * Emitted when "Audit Security System Extension" is enabled. Contains matching fields to 7045, including the `SubjectUserSid`.

### 2. Sysmon Telemetry

Sysmon provides granular event logging specifically tailored for detection engineering:

* **Sysmon Event ID 6 (Driver Loaded)**:
  * Triggers via `PspLoadImageNotifyRoutine` whenever a module is loaded into driver space.
  * Essential fields:
    * `ImageLoaded`: Absolute path of the loaded kernel driver.
    * `Hashes`: SHA256/MD5 of the driver on disk.
    * `Signed`: Signature status (`true` / `false`).
    * `Signature`: Signer identity (e.g., "MICRO-STAR INTERNATIONAL CO., LTD.").
    * `SignatureStatus`: Validity status (`Valid`, `Expired`, `Revoked`).

* **Sysmon Event ID 11 (File Create)** & **Sysmon Event ID 1 (Process Create)**:
  * Captures the staging process writing the `.sys` file to non-standard paths and any anomalous processes (e.g., `cmd.exe`, `powershell.exe`, or custom unpacked executables) initiating the drop.

### 3. Registry Auditing

Driver service creation modifies the Windows Registry. Monitoring the following key paths yields high-fidelity context:

* `HKLM\SYSTEM\CurrentControlSet\Services\<DriverName>\ImagePath`
* `HKLM\SYSTEM\CurrentControlSet\Services\<DriverName>\Type` (Value `1` or `2` denotes Kernel/FileSystem drivers)
* `HKLM\SYSTEM\CurrentControlSet\Services\<DriverName>\Start` (Value `2` = Auto Start, `3` = On Demand)

**Windows Registry Auditing (Event ID 4657)** or **Sysmon Event ID 12/13/14** captures these modifications even if an attacker attempts to bypass service management APIs by directly manipulating the registry hive via raw NT calls.

---

## Detection Engineering and Queries

A robust BYOVD detection program uses a multi-layered detection strategy combining **known-bad hash/signer matching** and **behavioral anomalies**.

### Strategy A: Matching Known Vulnerable Drivers (LOLDrivers Integration)

The open-source [LOLDrivers](https://www.loldrivers.io/) project catalogs hundreds of known vulnerable driver hashes, driver names, and certificate signers used in real-world attacks.

The following KQL (Kusto Query Language) rule queries Microsoft Defender for Endpoint (`DeviceEvents` / `DeviceFileEvents`) or Microsoft Sentinel to flag known vulnerable driver loads against Sysmon ID 6 or Endpoint Driver Load events:

```kql
// Detect Known Vulnerable Kernel Driver Loading (BYOVD)
let VulnerableDriverHashes = dynamic([
    "f2f1107d3f1105e463a502f69a8b111234ba4c8e76c11b15093557e4e8992e5c", // RTCore64.sys
    "17f22f7b11d33458c3f4e3c35e9858f9a2e6f4a860b8a2e1d0342938e234a41d", // GDRV.sys
    "0f898142a7c4f420551065113d0f0a827441a123a1a4a4b2a8f9a2e1d0342938"  // mhyprot2.sys
]);
DeviceEvents
| where ActionType == "DriverLoad" or ActionType == "NtLoadDriver"
| extend SHA256 = tolower(tostring(AdditionalFields.SHA256))
| extend DriverPath = tolower(FolderPath)
| where SHA256 in (VulnerableDriverHashes)
    or DriverPath endswith "rtcore64.sys"
    or DriverPath endswith "gdrv.sys"
| project Timestamp, DeviceName, DriverPath, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine, AccountName
```

### Strategy B: Anomaly-Based Driver Loading

Attackers frequently modify driver file names to evade basic string matching. Behavioral detections focus on **unusual paths**, **untrusted code signers**, or **non-standard driver creation processes**.

```kql
// Detect Kernel Driver Service Creation from Anomalous User/System Directories
DeviceRegistryEvents
| where ActionType == "RegistryValueSet"
| where RegistryKey has @"SYSTEM\CurrentControlSet\Services" and RegistryValueName == "ImagePath"
| extend DriverPath = tolower(tostring(RegistryValueData))
// Isolate Kernel Driver Services
| where DriverPath contains ".sys"
// Filter out standard Windows driver locations
| where not(DriverPath startswith @"c:\windows\system32\drivers\" 
         or DriverPath startswith @"\systemroot\system32\drivers\"
         or DriverPath startswith @"system32\drivers\")
| project Timestamp, DeviceName, RegistryKey, DriverPath, InitiatingProcessFileName, InitiatingProcessCommandLine, AccountName
```

### Strategy C: Correlating Driver Drop to Driver Load

In a typical administrative environment, legitimately installed software installs drivers via signed installers or Windows Update routines. An attacker performing a BYOVD execution usually performs the file drop, service creation, and execution within a very short temporal window (<60 seconds).

```kql
// Detect rapid File Creation -> Service Installation sequence for Kernel Drivers
let ThresholdMinutes = 3m;
DeviceFileEvents
| where FolderPath endswith ".sys"
| where ActionType == "FileCreated"
| project DriverDropTime = Timestamp, DeviceName, DriverPath = FolderPath, DropperProcess = InitiatingProcessFileName, DropperSHA256 = InitiatingProcessSHA256
| join kind=inner (
    DeviceEvents
    | where ActionType == "DriverLoad"
    | project DriverLoadTime = Timestamp, DeviceName, DriverPath = FolderPath, LoadedDriverSHA256 = SHA256
) on DeviceName
| where DriverLoadTime between (DriverDropTime .. (DriverDropTime + ThresholdMinutes))
| where not(DriverPath startswith @"c:\windows\system32\drivers\")
| select DeviceName, DriverDropTime, DriverLoadTime, DriverPath, DropperProcess, DropperSHA256, LoadedDriverSHA256
```

---

## Sysmon Configuration Engine Logic

To capture Driver Load events efficiently without flooding your SIEM with routine Windows kernel driver loads, configure XML rules with strict exclusions for Microsoft-signed standard system drivers.

```xml
<Sysmon schemaversion="4.90">
  <EventFiltering>
    <!-- Sysmon Event ID 6: DriverLoaded -->
    <DriverLoad onmatch="exclude">
      <!-- Exclude standard drivers in C:\Windows\System32\drivers signed by Microsoft -->
      <Signature condition="is">Microsoft Windows</Signature>
      <Signature condition="is">Microsoft Windows Component Publisher</Signature>
    </DriverLoad>
    <DriverLoad onmatch="include">
      <!-- Force log drivers loaded from user-writable directories -->
      <ImageLoaded condition="contains">C:\Users\</ImageLoaded>
      <ImageLoaded condition="contains">C:\ProgramData\</ImageLoaded>
      <ImageLoaded condition="contains">C:\Temp\</ImageLoaded>
      <ImageLoaded condition="contains">C:\Windows\Temp\</ImageLoaded>
      <!-- Force log revoked or untrusted signatures -->
      <Signed condition="is">false</Signed>
    </DriverLoad>
  </EventFiltering>
</Sysmon>
```

---

## Defensive Blindspots and Trade-offs

Detecting and mitigating BYOVD attacks presents distinct operational challenges that threat hunters and detection engineers must navigate.

### 1. The Kernel Telemetry Race Condition

The primary operational risk with BYOVD attacks is **telemetry blinding**. If an attacker drops a driver and immediately invokes an IOCTL to patch the telemetry driver's callbacks (`PspCreateProcessNotifyRoutine` array), the host telemetry agent may emit the initial ID 7045/Sysmon ID 6 event, but **all subsequent process, file, and network events on that endpoint are silenced**.

If your alerting infrastructure relies on stream-based detection that takes several minutes to correlate, the endpoint may already be unmonitored before an analyst opens the alert.

### 2. Driver Signing Certificate Abuses

Attackers do not strictly rely on vulnerable software binaries like `RTCore64.sys`. Stolen or leaked code-signing certificates are frequently used to sign custom kernel drivers with native rootkit capabilities. In this scenario:

* Known-vulnerable hash blocklists (LOLDrivers) **will fail** because the binary hash is completely novel.
* Certificate validation checks will pass unless the certificate serial number has been explicitly added to the Microsoft Certificate Revocation List (CRL) or local driver blocklists.

### 3. Hypervisor-Protected Code Integrity (HVCI) Limitations

Windows Hypervisor-Protected Code Integrity (HVCI) and Virtualization-Based Security (VBS) enforce strict kernel-mode code integrity checks, preventing arbitrary unsigned code from executing in kernel space. However:

* **HVCI does not stop BYOVD.** Because the vulnerable driver carries a valid digital signature, HVCI permits the driver to load into memory.
* The exploitation happens *within* valid driver logic via legitimate IOCTL communication. As long as the driver itself isn't executing dynamic unsigned code pages, HVCI sees the operation as valid kernel execution.

---

## Mitigation Strategies and Practical Recommendations

Relying strictly on post-exploitation detection logic is insufficient for BYOVD tactics due to the risk of agent blinding. Security teams must deploy preventative controls to restrict vulnerable driver loading natively.

```
+-------------------------------------------------------------------------+
|                    Layered BYOVD Prevention Model                       |
+-------------------------------------------------------------------------+
| 1. Microsoft Vulnerable Driver Blocklist (HVCI / WDAC Enablement)       |
|    -> Block known vulnerable driver hashes at kernel interface level.   |
+-------------------------------------------------------------------------+
| 2. Custom Windows Defender Application Control (WDAC) Policies          |
|    -> Whitelist allowed kernel drivers; deny arbitrary driver loads.    |
+-------------------------------------------------------------------------+
| 3. Privilege Access Management (PAM) & Least Privilege                   |
|    -> Prevent unauthorized accounts from acquiring SeLoadDriverPrivilege.|
+-------------------------------------------------------------------------+
| 4. Continuous Telemetry Monitoring                                      |
|    -> Real-time alerts on Sysmon ID 6, WinEvent 7045/4697.             |
+-------------------------------------------------------------------------+
```

### 1. Enable Microsoft Vulnerable Driver Blocklist

Microsoft maintains a native driver blocklist enforced via Windows Defender Application Control (WDAC) or HVCI. Ensure this policy is enforced across all Windows workstations and servers:

* **Registry Key Settings**:
  * Path: `HKLM\SYSTEM\CurrentControlSet\Control\CI\Config`
  * Value: `VulnerableDriverBlocklistEnable` (DWORD)
  * Data: `1`

* **Group Policy Path**:
  * `Computer Configuration -> Administrative Templates -> System -> Device Guard -> Enable Virtualization Based Security -> Vulnerable Driver Blocklist`

### 2. Deploy Custom WDAC Driver Policies

For high-security environments, transition from a blacklist model to an explicitly whitelisted driver deployment policy using WDAC. Configure WDAC rules to restrict kernel driver loading exclusively to a set of explicitly approved publisher certificates or hashes.

Example PowerShell command to generate a base WDAC driver integrity rule set:

```powershell
# Create a WDAC policy scanning current System32 drivers as trusted baseline
New-CIPolicy -FilePath "C:\WDAC\DriverPolicy.xml" -Level Publisher -DriverFiles -UserPEs:$false

# Convert Policy to Binary format for deployment
ConvertFrom-CIPolicy "C:\WDAC\DriverPolicy.xml" "C:\WDAC\DriverPolicy.bin"
```

### 3. Audit and Restrict Driver Loading Privileges

Verify that standard users and service accounts cannot elevate to grant themselves `SeLoadDriverPrivilege` (`SeLoadDriverPrivilege` maps to "Load and unload device drivers").

Auditing user rights assignment via Local Security Policy (`secpol.msc`):
* `Security Settings -> Local Policies -> User Rights Assignment -> Load and unload device drivers`
* Restrict this right exclusively to `BUILTIN\Administrators`. Remove service accounts or low-privileged user groups.

---

## Investigation Workflow for Security Operations

When an alert fires indicating an unrecognized or known-vulnerable driver load, follow this tactical triage workflow:

1. **Identify Parent Process and Lineage**:
   Query process creation logs for the execution context that created the driver service or wrote the driver to disk.
   * *Flag if parent process is*: `cmd.exe`, `powershell.exe`, non-standard administrative tools, or an executable located under `C:\Users\Public\`, `C:\ProgramData\`, or `AppData\Local\Temp\`.

2. **Retrieve Driver Metadata**:
   Extract the target driver binary and verify signature properties using PowerShell:
   ```powershell
   Get-AuthenticodeSignature -FilePath "C:\Path\To\SuspiciousDriver.sys" | Format-List
   ```
   Check the SHA256 hash against [LOLDrivers.io](https://www.loldrivers.io/) API or VirusTotal.

3. **Verify Kernel Telemetry Integrity**:
   Confirm whether the endpoint's EDR agent is still actively reporting. Run a harmless check or query host heartbeat logs. If EDR telemetry abruptly stops immediately following the driver load event, assume the host kernel has been compromised and isolate the host from the network at the hypervisor or network switch layer.

4. **Analyze Handle Operations**:
   Inspect whether non-system processes opened handles to `\\.\` device namespaces around the time of the event. System utility drivers are designed for specific management apps; arbitrary executables opening handles to hardware utility drivers (e.g., `RTCore64`) indicate exploitation.

---

## Summary

BYOVD attacks take advantage of legitimate administrative architecture to bypass modern endpoint security assumptions. By bringing validly signed but flawed software, attackers manipulate kernel space directly, bypassing Driver Signature Enforcement and blinding telemetry agents.

Defending against this technique requires moving beyond simple file hash matching. Security operations must combine preventative driver blocklists (HVCI/WDAC), real-time monitoring of driver installation events (Sysmon ID 6, WinEvent 7045), and tight controls over local privilege assignment. Aligning these controls prevents adversaries from converting legitimate kernel drivers into exploitation tools against your network.
