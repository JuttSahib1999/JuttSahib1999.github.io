---
title: "Dissecting BYOVD Attacks: Neutralizing Kernel-Level EDR Evasion"
description: "A technical breakdown of Bring Your Own Vulnerable Driver (BYOVD) tactics used to terminate security agents, alongside kernel memory mechanics and actionable detection strategies."
date: "2026-03-30"
tags: ["Threat Hunting", "Kernel Security", "EDR Evasion", "Windows Internals"]
category: "Cyber Security"
---

Endpoint Detection and Response (EDR) agents operate heavily inside user space (Ring 3) and rely on kernel callbacks (Ring 0) to monitor system activity, process creation, and memory allocation. Threat actors frequently hit a ceiling when attempting to blind these agents directly from user mode due to process protection mechanisms like Protected Process Light (PPL).

To bypass PPL and user-mode hooks, advanced threat actors—including ransomware operations like BlackByte, Akira, and LockBit—routinely employ **Bring Your Own Vulnerable Driver (BYOVD)** techniques. By dropping a legitimately signed, yet vulnerable, third-party kernel driver, attackers gain an arbitrary kernel read/write primitive. This allows them to patch security callbacks, terminate protected EDR processes, and operate unmonitored.

Here is an analysis of the execution mechanics behind BYOVD attacks, how kernel objects are manipulated, and how to build defense-in-depth detection and prevention controls.

---

## The Anatomy of a BYOVD Attack Vector

A BYOVD attack does not rely on zero-day driver exploits. Instead, it weaponizes known, vendor-signed drivers (such as `RTCore64.sys`, `gdrv.sys`, or `mhyprot2.sys`) that expose unsafe I/O Control (IOCTL) codes to low-privileged or administrative user-mode applications.

```
+-------------------------------------------------------------------+
|                        USER MODE (Ring 3)                         |
|                                                                   |
|   +-----------------------+        +--------------------------+   |
|   |  Malicious Installer  |        | Security Agent (User)    |   |
|   +-----------+-----------+        +--------------------------+   |
|               | DeviceIoControl()                                 |
+---------------|---------------------------------------------------+
|               v Device Object / IOCTL                             |
+---------------|---------------------------------------------------+
|               |        KERNEL MODE (Ring 0)                       |
|               v                                                   |
|   +-----------------------+        +--------------------------+   |
|   | Vulnerable Signed     | ---->  | Zero Out Callbacks /     |   |
|   | Kernel Driver         | Arbitrary Kernel  | Terminate EDR |   |
|   | (e.g., RTCore64.sys)  | Read/Write        | Drivers      |   |
|   +-----------------------+        +--------------------------+   |
+-------------------------------------------------------------------+
```

The attack progression generally follows four phases:

1. **Privilege Escalation / Staging**: The adversary achieves local administrative privileges (`SeLoadDriverPrivilege`) on the target machine.
2. **Driver Drop & Registration**: The actor writes the vulnerable driver to disk (typically in `C:\Windows\System32\drivers\` or `C:\Users\Public\`) and creates a service via the Service Control Manager (`sc.exe` or `CreateServiceW`).
3. **Handle Acquisition**: The malicious user-space process opens a handle to the driver's exposed device object via `CreateFileW` (e.g., `\\.\RTCore64`).
4. **Kernel Payload Execution**: The process sends crafted `DeviceIoControl` requests containing arbitrary read/write payloads to modify physical/virtual kernel memory.

---

## Kernel Memory Manipulation: Stripping EDR Callbacks

Security software registers kernel callbacks using documented Windows APIs such as:

- `PsSetCreateProcessNotifyRoutineEx`
- `PsSetCreateThreadNotifyRoutine`
- `ObRegisterCallbacks`

These routines place pointers into kernel arrays (e.g., `PspCreateProcessNotifyRoutine`). When a new process spawns, the Windows kernel iterates over this array and executes each registered callback function.

### How Vulnerable Drivers Grant Arbitrary Write
Vulnerable drivers like `RTCore64.sys` (Micro-Star MSI Afterburner driver) expose IOCTL handlers that accept user-defined memory addresses and read/write raw data without validation.

For instance, IOCTL `0x80002048` in `RTCore64.sys` accepts a structure containing a memory address and a value to write:

```c
typedef struct _RTCORE_MEMORY_WRITE {
    DWORD Unknown0;
    DWORD Address;
    DWORD Unknown1;
    DWORD Size;
    DWORD Value;
} RTCORE_MEMORY_WRITE, *PRTCORE_MEMORY_WRITE;
```

### Direct Kernel Object Manipulation (DKOM)
With arbitrary write capability, the malware locates the base address of `ntoskrnl.exe` and resolves array pointers such as `PspCreateProcessNotifyRoutine`.

The attacker then iterates through the routine array, identifies the driver routines belonging to installed EDR vendors (e.g., `csagent.sys`, `edrsensor.sys`), and overwrites the entry pointers with `0x0000000000000000` or an immediate `RET` instruction (`0xC3`).

Once overwritten:
- The EDR loses visibility into process execution.
- Memory allocation routines no longer trigger alerts.
- PPL structure flags (`_EPROCESS->Protection`) can be zeroed out, allowing standard user-mode processes to issue `TerminateProcess` against EDR binaries.

---

## Telemetry Gaps and Detection Engineering

Standard Windows Event Logs often fail to catch the actual memory modification step, as kernel write operations bypass user-mode API monitoring. Defense engineers must look for specific artifacts across driver loading, service registration, and IOCTL activity.

### 1. Monitoring Driver Load Events (Sysmon Event ID 6)
Sysmon provides high-fidelity telemetry for driver loads. Key fields to hunt on include unsigned drivers, unexpected load paths, and known hashes of vulnerable drivers.

```xml
<Sysmon severity="medium">
  <Group groupRelation="or">
    <DriverLoad onmatch="include">
      <ImageLoaded condition="contains">C:\Users\Public\</ImageLoaded>
      <ImageLoaded condition="contains">C:\ProgramData\</ImageLoaded>
      <Hashes condition="contains">SHA256=1112E2C7D1A25D783B0E9C0A74EB874C</Hashes> <!-- RTCore64.sys -->
    </DriverLoad>
  </Group>
</Sysmon>
```

### 2. Hunting Service Creation (Windows Event ID 7045)
Look for short-lived services created with dynamic names pointing to atypical driver paths:

```powershell
Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045} | 
Where-Object { $_.Properties[1].Value -like "*\Users\*" -or $_.Properties[1].Value -like "*\Temp\*" } |
Select-Object TimeCreated, Message
```

### 3. Sigma Rule: Vulnerable Driver Interaction Detection
This Sigma rule flags process execution attempting to create handles to well-known vulnerable driver device objects.

```yaml
title: Suspicious Access to Known Vulnerable Driver Device
id: 5f23b2c1-849a-4c2d-9831-29a3a123f111
status: experimental
description: Detects user-mode processes opening handles to drivers commonly leveraged in BYOVD attacks.
logsource:
  category: process_access
  product: windows
detection:
  selection:
    TargetDevice|endsWith:
      - '\RTCore64'
      - '\GDrv'
      - '\mhyprot2'
      - '\ATSZIO'
  filter_legitimate:
    SourceImage|endswith:
      - '\MSI\Afterburner\MSIAfterburner.exe'
  condition: selection and not filter_legitimate
falsepositives:
  - Legitimate hardware monitoring software installed in non-standard paths.
level: high
```

---

## Defensive Mitigation Strategies

Relying solely on post-exploitation detection is insufficient for kernel threats. Mitigation requires preventative boundary enforcement.

### Strategy A: Enforce Hypervisor-Protected Code Integrity (HVCI)
HVCI (Memory Integrity) uses Virtualization-Based Security (VBS) to run Kernel Mode Code Integrity (KMCI) inside a secure container. HVCI prevents unsigned pages from being executed in the kernel and restricts drivers from allocating executable memory dynamically, mitigating basic shellcode execution in kernel space.

Enable HVCI via Group Policy or Registry:
```cmd
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /v "Enabled" /t REG_DWORD /d 1 /f
```

### Strategy B: Deploy the Microsoft Recommended Driver Block Rules
Microsoft maintains a hardcoded blocklist of known vulnerable drivers accessible to Windows Defender Application Control (WDAC). 

To enforce driver blocking via WDAC:
1. Ensure **Vulnerable Driver Blocklist** is toggled **ON** in Windows Security under *Device Security > Core Isolation*.
2. Deploy custom WDAC policy targeting hashes of vulnerable drivers if running stripped-down Windows Enterprise/Server SKUs.

To verify driver blocklist status via PowerShell:
```powershell
Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard | 
Select-Object SecurityServicesConfigured, SecurityServicesRunning
```

### Strategy C: Restrict Driver Loading Privileges
Only local administrators with `SeLoadDriverPrivilege` (`User Right Assignment: Load and unload device drivers`) can load kernel drivers. 

- Audit system policies to ensure standard user accounts cannot acquire this privilege via misconfigurations.
- Remove `SeLoadDriverPrivilege` from local Administrator groups on non-domain controllers where driver installation is handled centrally via endpoint management platforms (e.g., Intune/SCCM).

---

## Conclusion

BYOVD attacks exploit a fundamental asymmetry in the Windows security model: administrative user-mode execution can leverage legacy kernel signatures to compromise Ring 0 integrity. 

A resilient posture against kernel evasion requires:
1. Hardening host configurations via **HVCI** and **WDAC blocklists** to stop vulnerable drivers at the execution boundary.
2. Monitoring low-level artifacts—specifically **DriverLoad events (Sysmon ID 6)** and **Service Creation (ID 7045)**—rather than relying strictly on process-level hooks.
3. Conducting regular threat hunts for unindexed driver files dropped in non-standard paths.