---
title: "Kernel-Level Evasion: Analyzing eBPF Weaponization and Detection Strategies"
description: "An in-depth technical analysis of how adversaries leverage extended Berkeley Packet Filters (eBPF) for stealth persistence and evasive kernel execution, alongside practical detection strategies."
date: "2026-03-30"
tags: ["Linux Security", "eBPF", "Threat Detection", "Kernel Security"]
category: "Cyber Security"
---

The shift toward kernel-space observability has driven widespread adoption of extended Berkeley Packet Filter (eBPF) technology across cloud-native environments. Modern endpoint detection and response (EDR) platforms, container security tools, and observability frameworks heavily rely on eBPF to trace system calls, inspect network packets, and track process execution without loading custom kernel modules.

However, the features that make eBPF attractive to security engineers—high performance, direct access to kernel primitives, and execution bypassing standard user-space hooks—also make it a powerful vector for adversaries. Offensive security researchers and sophisticated threat actors are increasingly using eBPF to deploy rootkits, evade user-space telemetry, and maintain persistent access to host operating systems.

---

## Understanding the eBPF Execution Model

To defend against eBPF-based techniques, security engineers must understand how the Linux kernel executes eBPF bytecode.

eBPF programs run inside an in-kernel virtual machine. They are triggered by event hooks, which can be attached to tracepoints, kprobes (kernel probes), uprobes (user-space probes), raw sockets, or Traffic Control (TC) subsystems.

```
+-------------------------------------------------------------------+
|                            User Space                             |
|  +---------------------+                  +--------------------+  |
|  |  eBPF Loader App    |                  |  bpftool / CLI     |  |
|  +----------+----------+                  +---------+----------+  |
+-------------|---------------------------------------|-------------+
              | sys_bpf()                             | Netlink
+-------------v---------------------------------------v-------------+
|                            Kernel Space                           |
|  +-------------------------------------------------------------+  |
|  |                        eBPF Verifier                        |  |
|  +------------------------------+------------------------------+  |
|                                 | JIT Compiler                    |
|  +------------------------------v------------------------------+  |
|  |                   Native Machine Code Execution              |  |
|  |  +------------------+  +-----------------+  +------------+  |  |
|  |  |  kprobe Hooks    |  |  Tracepoints    |  |  XDP / TC  |  |  |
|  |  +------------------+  +-----------------+  +------------+  |  |
|  +-------------------------------------------------------------+  |
+-------------------------------------------------------------------+
```

The standard lifecycle of an eBPF program follows a strict pipeline:

1. **Compilation:** C code is compiled via Clang/LLVM into eBPF bytecode (`BPF_PROG_TYPE_*`).
2. **Loading:** A user-space process calls the `bpf()` system call with the `BPF_PROG_LOAD` command.
3. **Verification:** The kernel verifier inspects the bytecode to enforce safety invariants: checking for unreachable code, out-of-bounds memory access, uninitialized variables, and bounded execution loops.
4. **JIT Compilation:** Validated bytecode is compiled into native machine instructions.
5. **Attachment:** The program binds to a specific kernel target (e.g., `sys_enter_execve`).

### The Security Dilemma of the Verifier

The eBPF verifier enforces **kernel safety**, not **intent safety**. It ensures that an eBPF program will not crash the kernel or access unallocated memory addresses. It does not determine whether an eBPF program is stripping malicious process identifiers (PIDs) from file listings or modifying network packet payloads on the wire.

If an attacker achieves `root` privilege or obtains the `CAP_BPF` / `CAP_SYS_ADMIN` capability, they can load arbitrary eBPF programs that pass verification while performing malicious actions.

---

## Adversarial Techniques: How eBPF is Weaponized

### 1. User-Space Evasion via System Call Tampering (`kprobe`/`kretprobe`)

Adversaries often aim to hide artifacts from commands like `ps`, `ls`, or `netstat`. Traditional user-space rootkits hook shared libraries (`LD_PRELOAD`), while traditional kernel rootkits patch system call tables. An eBPF rootkit achieves the same outcome by attaching to system call exit points.

For instance, process enumeration utilities read the `/proc` filesystem using the `sys_getdents64` system call. A malicious eBPF program attached as a `kretprobe` to `sys_getdents64` can execute the following logic:

* Intercept the returned buffer containing directory entries (`linux_dirent64` structures).
* Inspect the filenames within the user-space memory buffer.
* Match entries against a designated malicious filename or PID pattern.
* Overwrite the memory structures in place using `bpf_probe_write_user()`, reducing the byte length returned to the user-space process.

Because this modification occurs inside kernel routines before returning execution to user space, utilities like `ls` or `ps` never see the hidden artifacts.

```c
// Simplified logic for sys_getdents64 hook
SEC("kretprobe/__x64_sys_getdents64")
int handle_getdents_exit(struct pt_regs *ctx) {
    // Extract returned dirent structure from user memory
    // Search for target PID / Filename
    // Modify structure offset via bpf_probe_write_user()
    return 0;
}
```

> **Note on `bpf_probe_write_user()`:** The kernel prints a warning message (`bpf_probe_write_user[...] uses tainted kernel module or probe`) to `dmesg` when this helper is invoked. However, adversaries who accept this noise can still bypass real-time user-space detection tools.

### 2. Traffic Redirection and C2 Stealth via XDP and TC

By attaching eBPF programs to the eXpress Data Path (XDP) or Traffic Control (TC) layers, adversaries operate at the network interface driver level—far below standard socket filters, `iptables`, or packet capturing applications (`tcpdump`).

* **Inbound Packet Drop/Redirection:** Malicious XDP programs process raw network frames prior to socket buffer allocation (`sk_buff`). An attacker can intercept inbound C2 commands, extract the payload, and return `XDP_DROP`. User-space monitoring tools or firewalls never record the packet arrival.
* **Socket Hijacking:** An eBPF program attached to `BPF_PROG_TYPE_SK_SKB` can inspect outbound traffic, alter destination IP addresses or ports on the fly, and dynamically route traffic to secondary C2 nodes without alerting standard host-based logging.

### 3. Credential Harvesting via Uprobes

eBPF is not restricted to kernel symbols; uprobes allow hooks on arbitrary user-space binaries and dynamically linked libraries.

An attacker with loading privileges can attach a uprobe to `/lib64/libpam.so` at the `pam_authenticate` function entry. Every time a user executes `sudo`, attempts an SSH login, or authenticates locally, the eBPF uprobe extracts the plaintext password pointer from function parameters and stores it in an eBPF map (`BPF_MAP_TYPE_RINGBUF`). A background attacker-controlled process reads the ring buffer asynchronously.

---

## Telemetry Gaps and EDR Limitations

Traditional Linux host security architectures rely on specific sources for behavioral monitoring:

1. **Auditd Framework:** Intercepts system calls at the `audit` hook.
2. **User-Space Agents:** Monitor `/proc` changes, inspect `/var/log/`, and query system state.
3. **LSM Probes:** System security modules (AppArmor, SELinux) enforce access control policies.

These telemetry pipelines present clear blind spots against eBPF attacks:

* **No Syscall Invocations for BPF Execution:** Once loaded, an eBPF program runs entirely in response to internal kernel events. No new system calls are generated when an eBPF hook triggers.
* **Kernel-Level Precedence:** An eBPF program hooked earlier in the kernel execution chain can alter the arguments passed to downstream audit systems, rendering `auditd` logs incomplete or inaccurate.
* **Shared Infrastructure:** If an attacker drops or manipulates eBPF maps used by legitimate security agents, those agents may silently stop receiving event notifications.

---

## Defensive Engineering & Detection Strategies

Detecting eBPF misuse requires monitoring program lifecycle events, enforcing strict administrative limits, and implementing real-time verification of loaded BPF objects.

### 1. Monitor BPF Subsystem System Calls

Every eBPF interaction goes through the `sys_bpf` system call. Monitoring `sys_bpf` invocations via `auditd` or tracepoints provides visibility into program loading events.

Configure `auditd` rules to track the `bpf` system call for system architecture targets:

```ini
# Audit BPF system calls on 64-bit architectures
-a always,exit -F arch=b256 -S bpf -k ebpf_activity
-a always,exit -F arch=b32 -S bpf -k ebpf_activity
```

Key fields to extract from `AUDIT_BPF` system logs (introduced in Linux Kernel 5.7+):

* `prog_type`: Indicates the operational context (e.g., `BPF_PROG_TYPE_KPROBE`, `BPF_PROG_TYPE_XDP`).
* `prog_insn_cnt`: Instruction count of the program.
* `prog_digest`: SHA256 hash of the compiled eBPF bytecode.

### 2. Runtime Program Inspection with `bpftool`

Security teams should regularly inventory running BPF programs and active maps across infrastructure hosts. The kernel tracks loaded programs and maps in system memory.

Run the following commands to list loaded eBPF programs and inspect raw bytecode:

```bash
# List all currently loaded eBPF programs
bpftool prog show

# Output detailed information in JSON format
bpftool prog show --json

# Dump the translated instruction bytecode of a specific program ID
bpftool prog dump xlated id <PROG_ID>

# Identify attached tracepoints and probes
bpftool link show
```

#### Suspicious Indicators During Analysis

* **Unlinked Programs:** eBPF programs loaded into memory without clear attribution to running user-space PIDs.
* **Widespread Kprobes:** Programs attached to critical internal kernel symbols such as `sys_enter_getdents64`, `commit_creds`, or `sys_enter_write`.
* **Pinned Objects:** Programs or maps pinned to unusual locations outside standard security runtime directories (e.g., custom paths in `/sys/fs/bpf/`).
* **Helper Invocation:** Bytecode that uses potentially disruptive kernel helpers, specifically `bpf_probe_write_user` (Helper ID `36`) or `bpf_override_return` (Helper ID `69`).

### 3. Linux Kernel Hardening Tactics

Defenders should apply baseline kernel configuration options to minimize exposure to unauthorized eBPF loading:

#### Restrict Unprivileged eBPF Execution

Prevent non-root processes from invoking `sys_bpf`. Set the sysctl parameter `kernel.unprivileged_bpf_disabled`:

```bash
# Disable unprivileged eBPF permanently
sysctl -w kernel.unprivileged_bpf_disabled=1
echo "kernel.unprivileged_bpf_disabled=1" >> /etc/sysctl.d/99-security.conf
```

#### Enforce Capable Boundaries

Strip kernel capabilities from workloads and container runtimes. Ensure containers do not inherit:

* `CAP_BPF` (allows eBPF operations)
* `CAP_SYS_ADMIN` (legacy access to system admin tasks)
* `CAP_NET_ADMIN` (allows binding XDP and network filters)

#### Enable Kernel Lockdown LSM

The Kernel Lockdown feature prevents processes—even those with `root` access—from modifying execution space directly. Enable lockdown in `integrity` or `confidentiality` mode via kernel boot parameters:

```text
lockdown=integrity
```

In `integrity` mode, features that allow modifying the running kernel image (including loading unsigned kprobes and using `bpf_probe_write_user`) are disabled at runtime.

---

## Defensive Engineering Checklist

| Domain | Action Item | Technical Implementation |
| :--- | :--- | :--- |
| **System Tuning** | Disable unprivileged BPF access | Set `sysctl kernel.unprivileged_bpf_disabled=1` |
| **Auditing** | Track `sys_bpf` execution | Deploy kernel-level `auditd` rules matching system call `BPF` |
| **Container Security** | Drop BPF and administrative privileges | Remove `CAP_BPF`, `CAP_SYS_ADMIN`, and `CAP_NET_ADMIN` from container specs |
| **Integrity** | Lock down kernel runtime | Enable `lockdown=integrity` via boot arguments |
| **Monitoring** | Baseline eBPF program inventory | Execute `bpftool prog show` at scheduled intervals; flag `bpf_probe_write_user` invocations |

---

## Conclusion

eBPF remains an exceptional technology for low-overhead telemetry and modern networking infrastructure. However, its position inside the kernel execution pipeline means defenders must manage it as an attack surface, not just a security solution.

By combining strict access controls (`CAP_BPF` containment), sysctl hardening, explicit kernel auditing, and continuous inventory checks using native utilities like `bpftool`, security teams can preserve observability benefits while blocking kernel-level persistence and evasion vectors.