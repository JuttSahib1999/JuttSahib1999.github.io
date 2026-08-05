---
title: "Bypassing the Kernel: Analyzing and Detecting eBPF-Based Rootkits"
description: "A practical guide to understanding how attackers exploit Linux eBPF for persistent kernel-level evasion and how detection engineers can surface these covert programs."
date: "2026-08-05"
tags: ["Linux Security", "eBPF", "Rootkits", "Threat Detection", "Kernel Security"]
category: "Cyber Security"
---

Extended Berkeley Packet Filter (eBPF) has fundamentally altered Linux observability, networking, and security tooling. By allowing sandboxed programs to run directly within the kernel without recompiling modules or loading volatile third-party kernel drivers (`kmods`), eBPF provides unparalleled access to system internals.

However, the same characteristics that make eBPF valuable for performance monitoring make it highly dangerous when weaponized by an attacker who has already obtained `CAP_SYS_ADMIN` or root privileges. eBPF-based rootkits can manipulate syscall outputs, hide processes, inspect raw socket traffic, and bypass traditional User-Space EDR mechanisms—all while leaving zero trace on the filesystem and refusing to register as conventional loaded kernel modules (`lsmod`).

This article breaks down how eBPF rootkits operate under the hood, why traditional detection controls fail to spot them, and how system administrators and SOC teams can build effective detection engineering strategies against them.

---

## Anatomy of an eBPF Exploitation Primitive

To understand how an attacker uses eBPF defensively or offensively, we must look at how programs are loaded and attached within the Linux kernel.

An eBPF program is compiled from C into eBPF bytecode (often via Clang/LLVM), verified for safety by the kernel verifier, and Just-In-Time (JIT) compiled into native machine code. The program is then attached to a kernel hook point.

```
+-------------------------------------------------------------------+
|                            User Space                             |
|  [Attacker Control / Malware]        [Security Agent / EDR]       |
+-------------------------------------------------------------------+
                               | (sys_bpf)
                               v
+-------------------------------------------------------------------+
|                            Kernel Space                           |
|                                                                   |
|   +-----------------------+     +-----------------------------+   |
|   |   eBPF JIT Engine     | --> | Pinned Maps (/sys/fs/bpf)   |   |
|   +-----------------------+     +-----------------------------+   |
|               |                                                   |
|   Hooks:      +---> [ Tracepoints ] (e.g., sys_enter_execve)      |
|               +---> [ Kprobes/Kretprobes ] (e.g., sys_getdents64) |
|               +---> [ XDP / TC ] (Raw network packets)            |
+-------------------------------------------------------------------+
```

Attackers primarily target three hook types:

1. **Kprobes and Kretprobes:** Attached to dynamic kernel function entry points and returns.
2. **Tracepoints:** Static hooks hardcoded into kernel events.
3. **XDP (eXpress Data Path) & Traffic Control (TC):** Hooks running at the lowest layers of the network stack, processing packets prior to sk_buff allocation.

### Evasion Techniques Executed in Kernel Space

Once attached, an malicious eBPF program can alter runtime execution in several ways:

#### 1. Process and File Hiding via `sys_getdents64`
Commands like `ls`, `ps`, and `top` rely on the `sys_getdents64` system call to read directory entries (such as `/proc`). An attacker attaches a `kretprobe` to `sys_getdents64`. When the system call returns directory structures to user space, the attached eBPF program uses helper functions like `bpf_probe_write_user` to overwrite the returning buffer, effectively stripping target process IDs (PIDs) or filenames out of the array before the user-space process receives it.

#### 2. Credential Hijacking via `sys_enter_execve`
By placing a tracepoint on `sys_enter_execve` or `sys_enter_write`, an eBPF program can copy memory buffers containing authentication tokens, passwords, or SSH keys directly into an eBPF map shared with a covert user-space receiver, completely bypassing audit logs (`auditd`).

#### 3. Network Traffic Obfuscation via XDP
An eBPF program loaded at the network driver layer using XDP can inspect incoming network packets before `iptables`, `nftables`, or packet-capturing tools like `tcpdump` process them. The rootkit can intercept custom command-and-control (C2) packets, drop them before logging occurs, or craft responses entirely inside the kernel.

---

## Defensive Visibility Gaps

Why do standard security products miss these artifacts?

* **No File Artifacts Required:** eBPF programs live entirely in kernel memory once loaded. If an attacker deletes the loader executable after executing the `sys_bpf` call, traditional disk-scanning antivirus engine alerts will not fire.
* **Kernel Module Blindness:** Commands like `lsmod` query `module_list` pointers in the kernel. eBPF programs do not register as LKM (Loadable Kernel Modules).
* **Bypassing `auditd`:** Because the manipulation occurs inside kernel memory *after* system call arguments are parsed or *before* user-space returns are rendered, system call logging frameworks like `auditd` may reflect clean execution parameters while the application actually consumes mutated data.

---

## Technical Detection Strategies

Detecting eBPF rootkits requires moving operational controls closer to kernel state inspection and auditing the `bpf()` system call execution itself.

### 1. Auditing the `bpf` System Call

The `bpf` syscall (`sys_bpf`, syscall number 321 on x86_64) is required to perform operations like program loading (`BPF_PROG_LOAD`) and map creation (`BPF_MAP_CREATE`).

You can enforce telemetry around this call using audit rules (`/etc/audit/rules.d/audit.rules`):

```bash
# Monitor the bpf() system call for 64-bit architectures
-a always,exit -F arch=b256 -S bpf -F key=ebpf_activation
# Monitor loading of kernel modules as a baseline comparison
-w /sbin/insmod -p x -k module_insertion
-w /sbin/rmmod -p x -k module_insertion
-w /sbin/modprobe -p x -k module_insertion
```

When an unverified binary invokes `bpf()` to load bytecode, `auditd` records the process context, UID, command line, and executable path.

### 2. Inspecting Loaded eBPF Programs via `bpftool`

The standard utility for inspecting active eBPF structures is `bpftool`. Security teams should periodically poll active programs and maps via scheduled tasks or custom agents.

To list all running eBPF programs currently loaded in memory:

```bash
bpftool prog list
```

Example Output:
```text
12: kprobe  name handle_getdents  tag a0b1c2d3e4f56789  gpl
	loaded_at 2026-08-05T10:14:22+0000  uid 0
	xlated 248B  jited 142B  memlock 4096B  map_ids 5
```

Pay specific attention to programs attached to `kprobe` or `kretprobe` types without a recognized application owner (e.g., system observability tools like Cilium, Datadog, or Falco).

To inspect the raw byte instruction set of a suspicious program ID:

```bash
bpftool prog dump xlated id 12
```

To view attached hooks system-wide via the tracing filesystem:

```bash
cat /sys/kernel/debug/tracing/kprobe_events
```

If an entry in `kprobe_events` points to memory locations or symbols associated with process iteration or network handling without a clear software lineage, flag it for immediate triage.

### 3. Monitoring Pinned eBPF Filesystems

eBPF programs often use pinned maps to retain state across user-space loader restarts. These are stored within pseudo-filesystems, typically mounted at `/sys/fs/bpf`.

Check for unexpected mounts and pinned files:

```bash
find /sys/fs/bpf/ -type f -exec ls -la {} +
```

---

## Defensive Engineering and Hardening Controls

To prevent eBPF abuse entirely or severely limit its attack surface, implement the following architectural restrictions:

### Disable Unprivileged eBPF
Ensure unprivileged users cannot execute `bpf` calls. By default, modern enterprise Linux distributions restrict this, but it must be explicitly validated.

Check current state:
```bash
sysctl kernel.unprivileged_bpf_disabled
```

Enforce restriction via sysctl configuration (`/etc/sysctl.d/99-security.conf`):
```ini
kernel.unprivileged_bpf_disabled = 1
```

### Restrict CAP_SYS_ADMIN / CAP_BPF in Containers
Do not grant `CAP_SYS_ADMIN` or `CAP_BPF` Linux capabilities to containerized workloads unless strictly necessary. Without these capabilities, processes inside container namespaces cannot load kernel-level eBPF programs or inspect host-level telemetry.

### Enforce BPF LSM (Linux Security Module)
Modern Linux kernels (>= 5.7) include the BPF LSM framework. This allows security tools to control eBPF system calls using eBPF itself. You can enforce policies that restrict `BPF_PROG_LOAD` operations exclusively to signed executables or binaries located in root-owned, write-protected directories.

Ensure `bpf` is enabled in your bootloader options (`/etc/default/grub`):
```text
GRUB_CMDLINE_LINUX_DEFAULT="... lsm=landlock,lockdown,yama,bpf"
```

---

## Key Takeaways for Security Teams

eBPF is not inherently a vulnerability; it is a powerful kernel functionality. However, as defensive tools rely more heavily on eBPF for deep visibility, attackers are leveraging the exact same subsystems to obscure their presence.

* **Audit execution:** Collect events on `sys_bpf` execution; do not rely strictly on process creation logs.
* **Inventory baseline hooks:** Document which legitimate applications (EDR, CNI plugins) maintain loaded eBPF programs in your environment.
* **Integrate `bpftool` telemetry:** Include eBPF program listings and map metrics in host baseline configuration checks and forensic triage playbooks.
* **Principle of Least Privilege:** Strictly limit `CAP_BPF` and `CAP_SYS_ADMIN` across all production host environments and container instances.
