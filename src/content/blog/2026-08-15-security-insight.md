---
title: "Analyzing eBPF-Based Rootkits: Detection Engineering Beyond Kernel Modules"
description: "An in-depth technical analysis of how threat actors leverage extended Berkeley Packet Filters (eBPF) for stealthy persistence and memory obfuscation, along with practical strategies for runtime detection."
date: "2026-08-15"
tags: ["Cybersecurity", "Threat Detection", "Security Operations"]
category: "Cyber Security"
---

Traditional Linux threat detection models rely heavily on monitoring user-space activity, inspecting `/proc` filesystem entries, or analyzing loaded kernel modules (`lsmod`). However, sophisticated adversaries are increasingly shifting away from legacy Loadable Kernel Modules (LKMs) to avoid triggering kernel integrity checks like `CONFIG_MODULE_SIG`. Instead, modern Linux persistence and rootkit functionality are turning toward **eBPF (extended Berkeley Packet Filter)**.

Originally designed for non-intrusive performance monitoring and network packet filtering, eBPF allows unprivileged or privileged code to run directly inside a sandboxed virtual machine within the Linux kernel. When abused, eBPF enables stealthy process hiding, credential harvesting, network traffic redirection, and EDR blind-spot generation—all without loading traditional kernel modules or modifying disk binaries.

---

## Anatomy of an eBPF Threat Vectors

eBPF programs interact with kernel event hooks using tracepoints, `kprobes`, `kretprobes`, and raw tracepoints. When a specific kernel function executes, attached eBPF programs intercept the context, manipulate registers, or alter memory buffers before returning control to user space.

Adversaries exploit three primary execution concepts within the eBPF subsystem:

### 1. File and Process Hiding via `sys_enter_getdents64`
Traditional Linux utilities (`ls`, `ps`, `top`) rely on the `getdents64` system call to enumerate directory entries in `/proc` and the file system. 

An eBPF rootkit can attach a `kretprobe` to `sys_getdents64`. As the kernel populates the memory buffer with `linux_dirent64` structures, the eBPF program rewrites the buffer in memory via the `bpf_probe_write_user` helper function. By patching out target string matches (e.g., process IDs or hidden file names) directly in the return buffer, the application in user space never receives telemetry on the payload's existence.

```text
[ User Space Application: 'ps' or 'ls' ]
                   │
                   ▼
       [ System Call: getdents64 ]
                   │
                   ▼
      [ Kernel Prepares Dirent Buffer ]
                   │
                   ▼
 [ eBPF kretprobe: Overwrites Target Memory ] <── Hidden payload matched
                   │
                   ▼
[ User Space receives redacted buffer ]
```

### 2. Network Redirection via XDP and Socket Filters
By attaching eBPF programs to the Express Data Path (XDP) or network socket filters, an attacker can analyze and drop, forge, or redirect inbound network traffic before it reaches the Linux network stack (`iptables`, `nftables`, or standard raw socket captures).

*   **Command and Control (C2) Stealth:** Inbound packets containing specific payload signatures (e.g., magic bytes in TCP options) can trigger execution loops without ever appearing in standard socket listeners (`netstat`, `ss`).
*   **Bypassing Firewalls:** XDP hooks process packets at the network interface driver level before memory allocation in `sk_buff` structures occurs, effectively rendering host-based firewall rules blind to targeted C2 traffic.

### 3. Credential Harvesting with Hooked System Calls
By attaching hooks to `sys_enter_write` or `sys_enter_read`, eBPF programs can capture input/output buffers from SSH daemons, interactive bash shells, or sudo sessions. Because eBPF maps reside in kernel memory accessible via file descriptors, harvested strings can be staged silently in BPF maps and later exfiltrated without touching the local file system.

---

## Telemetry Blindspots and Detection Challenges

Standard Security Information and Event Management (SIEM) rules and basic Endpoint Detection and Response (EDR) agents face several distinct obstacles when analyzing eBPF activity:

1.  **No On-Disk Footprint:** Many eBPF payloads are loaded directly into memory using user-space loader scripts compiled via LLVM/Clang. Once loaded into the kernel, the original ELF binary on disk can be unlinked.
2.  **Bypassing Kernel Module Verification:** Tools like `chkrootkit` or `rkhunter` look for compromised `/proc` symbols or loaded LKMs. An eBPF program does not register as a kernel module, leaving `lsmod` output completely clean.
3.  **Kernel Memory Protection Limits:** While `bpf_probe_write_user` triggers a kernel warning log on some architectures when debugging flags are set, it remains a standard, supported helper function intended for tracing.

---

## Technical Mitigation & Defensive Blueprint

Securing modern Linux distributions against eBPF abuse requires a combination of strict privilege controls, system call auditing, and runtime inspection of installed BPF objects.

### 1. Restrict Unprivileged eBPF Execution
By default, unprivileged users should be barred from loading eBPF programs. Verify and enforce this via `sysctl`:

```bash
# Check current configuration
sysctl kernel.unprivileged_bpf_disabled

# Enforce permanent restriction in /etc/sysctl.d/99-security.conf
kernel.unprivileged_bpf_disabled = 1
```

Setting `kernel.unprivileged_bpf_disabled=1` restricts `bpf()` system calls strictly to processes with `CAP_BPF` or `CAP_SYS_ADMIN` capabilities.

### 2. Audit the `bpf()` System Call
Configure `auditd` to capture invocation of system call ID 321 (on x86_64 architectures) to track whenever a process attempts to load a program type or manipulate BPF maps.

Add the following rule to `/etc/audit/rules.d/audit.rules`:

```text
-a always,exit -F arch=b256 -S bpf -F key=ebpf_invocation
-a always,exit -F arch=b64 -S bpf -F key=ebpf_invocation
```

This log output allows threat hunters to map the parent process path (`exe`), target process permissions, and runtime invocation arguments whenever a loader binary attempts to attach BPF probes.

### 3. Inspect Loaded eBPF Programs using `bpftool`
SOC analysts and systems engineers must incorporate `bpftool` into routine forensic workflows. Run direct memory queries to list active programs and probes:

```bash
# List all active eBPF programs currently loaded in the kernel
bpftool prog list

# Inspect attached tracepoints and kprobes
bpftool perf list

# Dump JIT-compiled assembly of a suspicious program ID
bpftool prog dump jited id <PROGRAM_ID>
```

Indicators of compromise (IoCs) during `bpftool` analysis include:
*   Programs typed as `kprobe` or `kretprobe` attached to sensitive syscalls (`sys_enter_getdents64`, `sys_enter_ptrace`, `sys_enter_execve`).
*   eBPF programs lacking associated names or clear application tags.
*   Programs referencing `bpf_probe_write_user` in their helper function call trees.

### 4. Lock Down BPF JIT Compiler Optimization
To prevent attackers from using JIT spraying techniques to execute arbitrary shellcode via the eBPF VM, ensure kernel memory hardening features are active:

```bash
# Harden JIT compiler memory operations
sysctl kernel.bpf_jit_harden=2
```

---

## Practical Threat Hunting Scenario

When investigating a suspected Linux compromise where local processes appear hidden from utilities like `htop`, follow this triaging protocol:

1.  **Check BPF Object Count:** Compare total running processes against active BPF programs using `bpftool prog list`.
2.  **Verify Helper Usage:** Run `bpftool prog dump xlated id <ID>` on suspicious payloads. Look specifically for calls to helper `bpf_probe_write_user` (helper function ID `36`).
3.  **Trace Map Backings:** Identify associated BPF map IDs using `bpftool map list`. Dump map contents to inspect staged strings, network payloads, or hidden PID lists:

```bash
bpftool map dump id <MAP_ID>
```

By shifting defensive telemetry deeper into the kernel pipeline and proactively auditing runtime BPF objects, security operations teams can eliminate the blindspots introduced by high-stealth eBPF capabilities.