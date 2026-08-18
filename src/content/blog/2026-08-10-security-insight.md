---
title: "Detecting and Mitigating eBPF-Based Rootkits in Enterprise Linux Environments"
description: "A technical dive into how attackers abuse extended Berkeley Packet Filter (eBPF) for stealthy kernel-level persistence and evasion, along with actionable detection engineering strategies."
date: "2026-08-10"
tags: ["Linux Security", "Threat Detection", "eBPF", "Detection Engineering"]
category: "Cyber Security"
---

Extended Berkeley Packet Filter (eBPF) has transformed Linux performance monitoring, networking, and security observability. By allowing sandboxed bytecode to execute directly inside the Linux kernel without recompiling kernel source code or loading traditional Loadable Kernel Modules (LKMs), tools like Cilium, Falco, and Tetragon provide unprecedented low-overhead visibility.

However, the same characteristics that make eBPF ideal for security instrumentation make it an attractive utility for advanced threat actors. Once an attacker gains elevated privileges (`CAP_BPF` or `CAP_SYS_ADMIN`), eBPF primitives allow them to deploy rootkits that evade conventional EDR agents, modify user-space process memory on the fly, and manipulate network traffic before it hits the standard OS networking stack.

---

## Technical Attack Vectors in eBPF Exploitation

eBPF rootkits differ fundamentally from traditional LKM rootkits. They do not overwrite `sys_call_table` pointers directly, nor do they rely on rogue kernel modules that show up under `lsmod`. Instead, they attach JIT-compiled bytecode to existing kernel tracepoints, kprobes, uprobes, or network sockets via the `bpf()` system call.

```
+-------------------------------------------------------------------+
|                            USER SPACE                             |
|  [ps / top]        [SSHD / PAM]       [EDR Agent]                 |
+------|------------------|------------------|----------------------+
       |                  |                  | (Hooked Read Buffer)
=======|==================|==================|=======================
|      v                  v                  v                      |
|  sys_getdents64   sys_pam_authenticate   sys_read                 |
|      |                  |                  |                      |
|  +---|------------------|------------------|-------------------+  |
|  |   v                  v                  v                   |  |
|  | [Tracepoint]     [Uprobe]           [Kprobe]                |  |
|  |   |                  |                  |                   |  |
|  |   +----------+-------+-------+----------+                   |  |
|  |              v               v                              |  |
|  |       [Malicious eBPF Program Hook]                         |  |
|  |       - Alters Dirent Structures                            |  |
|  |       - Overwrites Memory via bpf_probe_write_user()        |  |
|  |       - Drops/Modifies Telemetry Packets                    |  |
|  +-------------------------------------------------------------+  |
|                            KERNEL SPACE                           |
+-------------------------------------------------------------------+
```

### 1. Process and File Hiding via `sys_enter_getdents64`

By attaching a kprobe or tracepoint program to `sys_enter_getdents64` and `sys_exit_getdents64`, an eBPF program can inspect the directory entries returned to user-space utilities like `ps`, `ls`, or `top`. 

When the kernel returns dirent structures containing a specific PID or filename associated with the attacker's tools, the eBPF helper modifies the returned buffer length or overwrites the dirent structure name length. As a result, the user-space process receives an incomplete directory tree, effectively rendering the attacker's files and processes invisible to standard monitoring utilities.

### 2. User-Space Memory Modification using `bpf_probe_write_user`

The `bpf_probe_write_user` helper function allows eBPF bytecode to write directly into the memory space of the currently running user-space process context. While designed to enable dynamic tracing patches for debugging, attackers use it to inject code into authenticated sessions.

Common exploitation scenarios include:
* **PAM Bypasses:** Hooking `libpam.so` using uprobes to overwrite authentication return values, allowing root logins with arbitrary passwords.
* **EDR Evasion:** Hooking specific user-space dynamic libraries used by security agents to mutate execution paths or strip telemetry buffers before transmission.

### 3. Network Evasion with XDP and Traffic Control (tc)

eBPF programs attached to Express Data Path (XDP) or Traffic Control (`tc`) run early in the network ingestion pipeline:

* **XDP Programs:** Execute directly at the Network Interface Card (NIC) driver level before packet memory (`sk_buff`) is allocated by the kernel stack. An attacker can filter out inbound/outbound command-and-control (C2) packets entirely, making C2 channels invisible to packet capture tools like `tcpdump` or host-based firewalls like `iptables`/`nftables`.
* **Socket Filters:** Programs attached to raw sockets can dynamically alter or drop log forwarding traffic destined for remote SIEM platforms without interrupting normal application layer operations.

---

## Defensive Engineering and Detection Protocols

Detecting eBPF abuse requires monitoring system calls, auditing object pins in pseudo-filesystems, and inspecting the Linux kernel's internal BPF data structures.

### 1. System Call Auditing (`sys_bpf`)

Attackers must invoke the `bpf()` system call (`sys_bpf`) to load programs or create BPF maps. Monitoring these syscall invocations via Linux `auditd` or explicit audit rules provides direct visibility.

Add the following rule to `/etc/audit/rules.d/ebpf.rules`:

```bash
# Monitor all bpf system call executions (Architecture specific, e.g., x86_64 = 321)
-a always,exit -F arch=b64 -S bpf -k ebpf_execution
```

Key sub-commands to filter for within the AUDIT_SYSCALL events include:
* `BPF_PROG_LOAD` (Cmd 5): Indicates a new eBPF bytecode array is being loaded into the kernel JIT engine.
* `BPF_MAP_CREATE` (Cmd 0): Indicates new persistent storage maps are being allocated.

### 2. Monitoring Virtual Filesystem Artifacts (`/sys/fs/bpf`)

eBPF objects can be "pinned" to the BPF virtual filesystem (`/sys/fs/bpf`) to remain persistent across application restarts or user-space process terminations. Unintended or suspicious files in this mount point often indicate persistence mechanisms.

Set up an inotify or file integrity monitoring (FIM) rule targeting `/sys/fs/bpf`:

```bash
# Example command using auditctl to monitor the bpf pseudo-filesystem
-w /sys/fs/bpf -p wa -k ebpf_filesystem_changes
```

### 3. Inspecting Loaded Programs using `bpftool`

Security teams should regularly run inventory checks on loaded BPF programs using the native `bpftool` binary.

#### List all loaded programs:
```bash
bpftool prog show
```

Look for flags or characteristics indicating suspicious activity:
* **Missing or Obfuscated Names:** Attackers often omit names or use misleading labels (e.g., naming a malicious kprobe program `cilium_net`).
* **Unusual Program Types:** Programs registered as `kprobe`, `tracepoint`, or `raw_tracepoint` on production servers where no profiling or performance tuning is actively occurring.
* **Helper Functions:** Look for usage of dangerous helper calls like `bpf_probe_write_user`.

#### Dump JIT-compiled assembly to inspect program logic:
```bash
# Obtain the ID from 'bpftool prog show'
bpftool prog dump xlated id <PROG_ID>
```

If the bytecode includes calls to helper function ID `36` (`bpf_probe_write_user`), this triggers an immediate high-severity alert.

```
  0: (79) r1 = *(u64 *)(r10 -8)
  1: (85) call bpf_probe_write_user#36   <-- HIGH RISK HELPER CALL
  2: (b7) r0 = 0
  3: (95) exit
```

---

## Hardening Strategies for Production Systems

To mitigate the risk of eBPF rootkits, implement the following operational controls across your Linux infrastructure:

### 1. Disable Unprivileged eBPF
Ensure unprivileged users cannot execute `sys_bpf`. Set the sysctl parameter `kernel.unprivileged_bpf_disabled` to `1` or `2`:

```bash
sysctl -w kernel.unprivileged_bpf_disabled=1
echo "kernel.unprivileged_bpf_disabled = 1" >> /etc/sysctl.d/99-security.conf
```

*Note: In modern Linux kernels (v5.13+), setting this to `1` permanently disables unprivileged BPF execution until the next reboot.*

### 2. Enforce Capability Restrictions
Restrict access to BPF functionality by managing Linux Capabilities. Avoid running containerized applications with full `CAP_SYS_ADMIN` or `CAP_BPF` permissions. Use strict Seccomp profiles to block `sys_bpf` entirely inside production workloads that do not explicitly require network orchestration or host monitoring tools.

### 3. Enable BPF JIT Hardening
Mitigate JIT-spraying attacks within kernel memory by enabling kernel JIT hardening:

```bash
sysctl -w net.core.bpf_jit_harden=2
echo "net.core.bpf_jit_harden = 2" >> /etc/sysctl.d/99-security.conf
```
Setting this value to `2` enables blinding for all users (including root), which randomizes JIT-generated immediate constants and prevents predictable opcode placement in kernel space.

---

## Response Playbook: Isolating an eBPF Intrusion

When malicious BPF activity is identified:

1. **Do Not Immediately Reboot the Host:** BPF programs reside in volatile kernel memory unless pinned. Rebooting will flush the program from memory, destroying volatile forensic artifacts.
2. **Dump the Raw Bytecode:**
   ```bash
   bpftool prog dump jited id <PROG_ID> > /var/log/forensics/malicious_bpf.jit
   bpftool prog dump xlated id <PROG_ID> > /var/log/forensics/malicious_bpf.xlated
   ```
3. **Detach and Unpin the Program:**
   Identify associated maps and pinned paths under `/sys/fs/bpf`. Unlink the persistent object to remove references:
   ```bash
   rm -f /sys/fs/bpf/<malicious_pinned_object>
   ```
   *Note: If the eBPF program is attached to a kprobe or network socket, detaching it requires detaching the file descriptor or terminating the user-space process controlling it.*
4. **Identify Parent Process:**
   Cross-reference the program creation timestamp and audit logs to find the parent process ID (PID) and binary path that invoked `BPF_PROG_LOAD`. Terminate the parent process to remove remaining handles.