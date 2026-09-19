---
title: "Detecting DLL Side-Loading: Telemetry, Search Order Hijacking, and Detection Logic"
description: "Learn how adversaries exploit Windows DLL loading mechanisms to execute code through trusted binaries, and how to build targeted detections using Sysmon and EDR telemetry."
date: "2026-09-19"
tags: ["Cybersecurity", "Security Operations"]
category: "Cyber Security"
difficulty: "Intermediate"
author: "Abdul Muqeet Tabraiz"
image: "/images/blog/2026-09-19-detecting-dll-side-loading-telemetry-search-order-hijacking-and-detection-logic.svg"
---

When an adversary lands on a target system, executing malicious payloads directly through custom executables often triggers endpoint alerts. EDR platforms quickly flag unknown, unsigned binaries executing out of user-writable directories. To bypass basic application whitelisting and blend in with benign process activity, threat actors frequently rely on **DLL Side-Loading** and **DLL Search Order Hijacking**.

By leveraging legitimate, signed Windows or third-party executables to load malicious Dynamic Link Libraries (DLLs), attackers execute code in the context of a trusted process. This article breaks down how Windows loads dynamic libraries, how adversaries exploit search paths, what telemetry sources expose this activity, and how detection engineers build resilient rules against it.

---

## How DLL Loading Works in Windows

To understand how side-loading happens, we need to look at how the Windows loader (`ntdll.dll` / `LdrLoadDll`) locates a DLL requested by an executable via `LoadLibraryA`, `LoadLibraryW`, or implicit import tables.

When an application requests a DLL without specifying an absolute path (e.g., requesting `version.dll` instead of `C:\Windows\System32\version.dll`), Windows searches for the file in a defined sequence:

1. **Already Loaded DLLs**: The OS checks if the module is already mapped into memory for the calling process.
2. **KnownDLLs List**: Windows checks the preloaded system modules registered under the registry key `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`. System libraries like `kernel32.dll`, `ntdll.dll`, and `user32.dll` are loaded exclusively from `C:\Windows\System32` regardless of local file placement.
3. **The Application Directory**: The directory from which the calling executable was launched.
4. **System Directories**: The `System32` directory (`C:\Windows\System32`) and 32-bit `SysWOW64` directory on 64-bit systems.
5. **The Windows Directory**: `C:\Windows`.
6. **The Current Working Directory**: The directory from which the process was initiated (if `SafeDllSearchMode` is enabled, this step is pushed below step 5; `SafeDllSearchMode` is enabled by default in modern Windows releases).
7. **Directories in the `%PATH%` Environment Variable**: User and system environment paths.

```
+-------------------------------------------------------+
|  1. Is the DLL already loaded in memory?              |
+-------------------------------------------------------+
                           | No
+-------------------------------------------------------+
|  2. Is it in HKLM\...\Session Manager\KnownDLLs?      | --> Yes: Load from System32
+-------------------------------------------------------+
                           | No
+-------------------------------------------------------+
|  3. Application Directory (Where the EXE resides)     | --> Target spot for Side-Loading
+-------------------------------------------------------+
                           | Not found
+-------------------------------------------------------+
|  4. System32 / SysWOW64 Directory                     |
+-------------------------------------------------------+
                           | Not found
+-------------------------------------------------------+
|  5. C:\Windows Directory                              |
+-------------------------------------------------------+
                           | Not found
+-------------------------------------------------------+
|  6. Current Working Directory / PATH Variables        |
+-------------------------------------------------------+
```

### Side-Loading vs. Search Order Hijacking

While closely related, there is a distinct operational difference between the two techniques:

* **DLL Side-Loading**: An attacker drops a legitimate, signed executable into a user-writable directory (e.g., `C:\Users\Public\Downloads\`), alongside a malicious DLL named identically to a non-KnownDLL library that the executable imports (e.g., `D3DCompiler_47.dll` or `wwlib.dll`). Because the application directory is checked *before* `System32`, the trusted executable loads the attacker's DLL from its own folder upon launch.
* **DLL Search Order Hijacking**: An attacker places a malicious DLL in a directory higher in the search order than the location of the intended legitimate DLL, without moving the host executable. This often relies on applications dropping DLL calls down to secondary search paths or missing dependencies.

---

## Why Adversaries Use Side-Loading

1. **Evading Process Execution Controls**: Security controls like AppLocker or Software Restriction Policies (SRP) may allow execution based on publisher certificates or path-based rules. Running a legitimate executable digitally signed by Microsoft or Google bypasses these initial filters.
2. **Blending into Security Telemetry**: Defensive monitoring systems frequently ignore or lower the alert threshold for processes signed by reputable vendors.
3. **Inheriting Host Process Permissions**: When the malicious DLL is loaded into memory via `DllMain()`, it executes inside the address space of the legitimate process, inheriting its integrity level, tokens, and network access profiles.

---

## Telemetry Sources for Detection

To detect side-loading reliably, security operations teams need visibility into process creation events, binary execution paths, and image load operations.

### Key Data Sources

* **Sysmon Event ID 7 (Image Loaded)**: Crucial telemetry for identifying which DLLs are loaded by which executables. Key fields include:
  * `Image`: Full path of the loading executable.
  * `ImageLoaded`: Full path of the loaded DLL.
  * `Signed`: Boolean indicating digital signature status.
  * `SignatureStatus`: Details on certificate validity.
  * `Hashes`: File hash of the loaded library.
* **Sysmon Event ID 1 / Windows Event ID 4688 (Process Creation)**: Useful for identifying trusted executables running out of abnormal directories (e.g., `cmd.exe` or `calc.exe` executing from `AppData\Local\Temp`).
* **Sysmon Event ID 11 / Windows Event ID 4663 (File Creation / Access)**: Captures the moment a payload writes a DLL file alongside a target binary before execution.

---

## Detection Strategies and Logic

Because benign applications load legitimate DLLs thousands of times a day across an enterprise, alerting on every image load is impractical. Detections must rely on specific anomaly combinations.

### Pattern 1: Signed Binaries in Non-Standard Paths

Legitimate system binaries (e.g., `workfolders.exe`, `rcsi.exe`, `notepad.exe`) typically execute from `C:\Windows\System32\` or `C:\Program Files\`. If an adversary copies `workfolders.exe` to `C:\Users\Public\` to side-load a malicious `control.exe` or `version.dll`, the executable path itself is the anomaly.

#### KQL Query Example (Microsoft Defender for Endpoint / Sentinel)

```kql
DeviceImageLoadEvents
| where InitiatingProcessFolderPath !startswith @"C:\Windows\System32\"
    and InitiatingProcessFolderPath !startswith @"C:\Windows\SysWOW64\"
    and InitiatingProcessFolderPath !startswith @"C:\Program Files\"
    and InitiatingProcessFolderPath !startswith @"C:\Program Files (x86)\"
| where InitiatingProcessFileName in~ (
    "workfolders.exe", "rcsi.exe", "msconf.exe", 
    "calc.exe", "tracker.exe", "gasp.exe"
)
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath, FolderPath, FileName, MD5
```

### Pattern 2: Known System DLLs Loaded Outside System Directories

If a binary loads a common DLL (like `version.dll`, `dbghelp.dll`, or `userenv.dll`) from a location other than `C:\Windows\System32` or `C:\Windows\SysWOW64`, it often indicates a search order hijack or side-loading attempt (excluding cases where the DLL is in `KnownDLLs`).

#### Splunk Search Example (Sysmon Logs)

```splunk
index=sysmon EventCode=7
  (ImageLoaded="*\\version.dll" OR ImageLoaded="*\\dbghelp.dll" OR ImageLoaded="*\\winhttp.dll")
  NOT (ImageLoaded="C:\\Windows\\System32\\*" OR ImageLoaded="C:\\Windows\\SysWOW64\\*")
| table _time, Computer, Image, ImageLoaded, Signed, SignatureStatus, Hashes
```

### Pattern 3: Unsigned DLLs Loaded by Highly Trusted/Signed Binaries

A common side-loading pattern occurs when a validly signed Microsoft or third-party executable loads an unsigned DLL from a user-writable path.

```
[ Signed Executable: calc.exe ] ---> Loads ---> [ Unsigned DLL: Custom Payload ]
   (C:\Users\Public\calc.exe)                   (C:\Users\Public\WININET.dll)
```

#### Sigma Rule Logic

```yaml
title: Unsigned DLL Loaded By Signed Binary In User Directory
status: experimental
description: Detects unsigned DLL loads originating from user-writable directories by signed host executables.
logsource:
  category: image_load
  product: windows
detection:
  selection_path:
    Image|contains:
      - '\Users\'
      - '\ProgramData\'
      - '\Windows\Temp\'
  selection_status:
    Signed: 'false'
  filter_legit:
    ImageLoaded|startswith:
      - 'C:\Program Files\'
      - 'C:\Program Files (x86)\'
  condition: selection_path and selection_status and not filter_legit
falsepositives:
  - Custom internal software running portable builds from AppData directories.
level: medium
```

---

## Practical Investigation Workflow

When an alert flags potential side-loading, follow this step-by-step triage model:

```
+-------------------------------------------------------------------+
| 1. Compare Binary Location                                        |
|    Is the executable running from its expected standard path?    |
+-------------------------------------------------------------------+
                                  |
                                  v
+-------------------------------------------------------------------+
| 2. Analyze the Loaded Module                                      |
|    Is the loaded DLL signed? What is its compile timestamp?       |
+-------------------------------------------------------------------+
                                  |
                                  v
+-------------------------------------------------------------------+
| 3. Examine Parent & File Creation Events                          |
|    How did the binary and DLL arrive on disk? (Sysmon 11/15)      |
+-------------------------------------------------------------------+
                                  |
                                  v
+-------------------------------------------------------------------+
| 4. Inspect Post-Exploitation Activity                             |
|    Did the host binary spawn shell processes or make network C2?  |
+-------------------------------------------------------------------+
```

1. **Verify File Paths**: Check `InitiatingProcessFolderPath` and `FolderPath`. Is a system binary running from `C:\Users\<user>\AppData\Local\Temp`?
2. **Inspect the DLL File**: Analyze the metadata of the loaded module. Is it missing internal version information, company names, or digital signatures? Check the file hash against VirusTotal or your internal dynamic analysis sandbox.
3. **Trace Creation Telemetry**: Pivot to file creation events (`Sysmon Event ID 11` or Windows `4663`) occurring shortly before execution. Look for suspicious archive extractions (e.g., `.zip` files containing both an executable and a DLL) dropped by web browsers or email clients.
4. **Check Execution Behavior**: Look for anomalies downstream from the parent host binary. For instance, `calc.exe` should not open outbound HTTPS connections to external IP addresses or spawn `cmd.exe` or `powershell.exe`.

---

## Limitations and Practical Tuning

Deploying image load detection across an enterprise presents specific operational challenges:

* **High Telemetry Volume**: Enabling Sysmon Event ID 7 for *all* image loads creates massive log volume and can performance-impact endpoint agents. 
  * *Tuning Tip*: Restrict Event ID 7 logging to specific high-risk target directories (e.g., `\Users\*`, `\ProgramData\*`, `\Windows\Temp\*`) or track specific vulnerable executables.
* **Portable Software Noise**: Applications like Slack, Discord, and Teams update continuously within `%LocalAppData%` and frequently load unsigned or internally signed DLLs from dynamic folders. 
  * *Tuning Tip*: Exclude known vendor update paths using certificate issuer attributes rather than path wildcards where possible.
* **Manifest Overrides**: Applications compiled with embedded assembly manifests (`.manifest`) or strict activation contexts (`ActCtx`) can specify relative dependencies by design, causing benign behavior to mirror side-loading structures.

---

## Defense and Mitigation

Beyond detection, several defensive controls reduce exposure to DLL side-loading:

1. **Implement WDAC/AppLocker Path Auditing**: Prevent system binaries from executing outside default system paths (`C:\Windows\System32`, `C:\Program Files`).
2. **Enable SafeDllSearchMode**: Ensure `SafeDllSearchMode` remains enabled across system configurations (`HKLM\System\CurrentControlSet\Control\Session Manager\SafeDllSearchMode = 1`).
3. **Developer Controls**: Compile binaries with the `/DEPENDENTLOADFLAG` flag or use `SetDefaultDllDirectories` to ensure libraries load exclusively from `%System32%`.
4. **Restrict User Write Access**: Limit write privileges to common execution paths like `C:\ProgramData\` to prevent non-administrative users from dropping side-load payloads alongside service executables.

---

## Practical Takeaway

DLL side-loading remains popular because it effectively abuses trust in legitimate software. Detection engineers cannot rely solely on process creation monitoring; tracking module loads and evaluating signature integrity against execution paths is critical. Focus on identifying system executables running out of user-writable directories, monitoring unsigned DLL loads, and pairing these indicators with post-exploitation behaviors like unusual network traffic or unexpected child process generation.
