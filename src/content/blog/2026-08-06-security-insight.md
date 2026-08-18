---
title: "Analyzing eBPF-Based Persistence and Rootkits: Detection, Telemetry, and Mitigation Strategies"
description: "A technical analysis of how adversaries leverage extended Berkeley Packet Filter (eBPF) for stealthy kernel-level persistence, alongside concrete forensic detection and mitigation strategies for Linux environments."
date: "2026-08-06"
tags: ["Linux Security", "Threat Detection", "Kernel Security"]
category: "Cyber Security"
---

Traditional Linux kernel rootkits historically relied on Loadable Kernel Modules (LKMs). However, modern enterprise security architectures—featuring mandatory module signing (`CONFIG_MODULE_SIG`), Kernel Address Space Layout Randomization (KASLR), and runtime integrity monitoring—have made LKM deployment increasingly difficult for attackers. 

To bypass these controls, adversaries are targeting extended Berkeley Packet Filter (eBPF). Originally designed for high-performance packet filtering and observability, eBPF allows unprivileged or privileged users (depending on kernel configuration) to execute sandboxed bytecode directly within the Linux kernel context without modifying kernel source or loading LKM binaries.

This analysis breaks down the technical mechanics of eBPF abuse, key telemetry indicators, and defensive strategies required to detect and neutralize eBPF-based persistence.

---

## The Mechanics of eBPF Abuse

eBPF programs run in an in-kernel virtual machine, operating on an event-driven architecture attached to tracepoints, kprobes, raw tracepoints, or network hooks (such as XDP or Traffic Control). 

While eBPF programs pass through an in-kernel verifier to prevent kernel panics and memory corruption, the verifier validates safety, not intent. An adversary who achieves root privileges (or possesses the `CAP_BPF` / `CAP_SYS_ADMIN` capability) can attach malicious eBPF programs to manipulate kernel behavior without raising typical LKM alerts.

```
+-------------------------------------------------------------------+
|                        User Space Application                     |
|  (Interacts via bpf() system call / reads eBPF Maps via fd)       |
+-------------------------------------------------------------------+
                                  |
                           bpf() Syscall
                                  v
+-------------------------------------------------------------------+
|                           Linux Kernel                            |
|  +-------------------+      +----------------------------------+  |
|  |   BPF Verifier    | ---> | JIT Compiler -> Native Machine   |  |
|  +-------------------+      +----------------------------------+  |
|                                              |                    |
|  +-------------------------------------------v-----------------+  |
|  | Attached Hooks:                                             |  |
|  | - sys_enter / sys_exit (Syscall Hiding)                     |  |
|  | - XDP / TC (Network Traffic Redirection / Packet Hiding)    |  |
|  | - kprobes / tracepoints (Credential Theft / Process Hiding) |  |
|  +-------------------------------------------------------------+  |
+-------------------------------------------------------------------+
```

### Key Adversarial Vectors

Adversaries leverage eBPF primarily for three operational objectives:

1. **Process and Artifact Hiding**: By attaching a `kprobe` or `fexit` hook to `sys_enter_getdents64` or `sys_exit_getdents64`, an eBPF program can rewrite the buffer returned to user space, stripping out specific filenames, process IDs (PIDs), or sockets from utility outputs like `ls`, `ps`, or `netstat`.
2. **Stealth C2 and Network Evasion**: Attaching BPF programs to Express Data Path (`XDP`) or Traffic Control (`tc`) ingress/egress layers enables low-level packet inspection and manipulation before packets hit the standard Linux network stack. Attackers can filter out specific C2 beacon packets so local packet captures (`tcpdump`) never observe them.
3. **Credential Harvesting and Privilege Escalation**: Hooking kernel functions related to authentication (e.g., `sys_enter_write` targeting `/etc/shadow` or SSH daemon buffers) allows silent credential logging into pinned BPF maps, which are subsequently read out by an attacker-controlled user-space process.

---

## Telemetry Gaps and Forensic Detection

Standard EDR products that rely exclusively on user-space API hooking or standard audit daemon (`auditd`) rules often miss eBPF execution because no file is written to disk in the traditional module directories (`/lib/modules/`), and no `init_module` or `finit_module` system calls are invoked.

Detecting malicious eBPF activity requires querying kernel state and monitoring BPF-specific system calls.

### 1. Inspecting Loaded Programs with `bpftool`

The primary utility for inspecting active BPF programs and maps is `bpftool`. SOC and Incident Response (IR) teams should routinely audit loaded BPF objects.

To list all loaded BPF programs currently loaded into the kernel:

```bash
bpftool prog show
```

Output example:

```text
12: kprobe  name sys_enter_getde  tag a0b1c2d3e4f56789  gpl
    loaded_at 2026-03-29T14:22:10+0000  uid 0
    xlated 288B  jited 184B  memlock 4096B  map_ids 5
    pids malicious_daemon(4102)
```

**Key Forensic Markers in `bpftool` Output:**
* **Unlinked Programs**: Programs loaded without an associated binary on disk or missing standard metadata tags.
* **Suspicious Types**: Unexpected `kprobe`, `tracepoint`, or `raw_tracepoint` program types attached to sensitive system calls (`sys_enter_execve`, `sys_enter_getdents64`, `sys_enter_connect`).
* **Pinned Maps**: Inspect persistent storage backing eBPF maps located in the BPF filesystem (typically `/sys/fs/bpf/`). Attackers use pinned maps to maintain data persistence across process restarts.

To inspect pinned objects:

```bash
bpftool fd dump jited
ls -la /sys/fs/bpf/
```

### 2. Auditing the `bpf()` System Call via `auditd`

To establish historical telemetry, configure `auditd` to capture every execution of the `bpf` system call (`sys_number 321` on x86_64).

Add the following rules to `/etc/audit/rules.d/audit.rules`:

```text
-a always,exit -F arch=b64 -S bpf -F key=bpf_syscall
-a always,exit -F arch=b64 -S perf_event_open -F key=perf_event_open
```

This ensures that whenever a process attempts to load a BPF program (`BPF_PROG_LOAD`) or create a map (`BPF_MAP_CREATE`), an audit log entry is generated detailing the `uid`, `pid`, `exe`, and command parameters.

Example Audit Log Analysis:

```text
type=SYSCALL msg=audit(1774794130.123:842): arch=c000003e syscall=321 success=yes exit=3 a0=0 a1=7ffe1234 a2=80 ... items=0 ppid=1200 pid=4102 auid=1001 uid=0 gid=0 exe="/tmp/.hidden/loader" key="bpf_syscall"
```

Tracking non-standard binaries issuing `syscall=321` provides high-fidelity detection for unauthorized eBPF loading.

---

## Defensive Hardening and Mitigation Architecture

Securing systems against eBPF abuse requires restricting runtime capabilities and enforcing strict policy controls over who can load BPF programs.

### Step 1: Restrict Unprivileged eBPF Execution

By default, modern kernels restrict unprivileged eBPF access, but legacy systems or custom configurations may leave it enabled. Enforce runtime restriction via `sysctl`:

```bash
sysctl -w kernel.unprivileged_bpf_disabled=1
```

To persist this across reboots, add the following line to `/etc/sysctl.d/99-security.conf`:

```ini
kernel.unprivileged_bpf_disabled = 1
```

Setting this parameter to `1` (or `2` to permanently lock the setting until the next reboot) prevents processes without `CAP_BPF` or `CAP_SYS_ADMIN` from executing the `bpf()` system call.

### Step 2: Enforce Capability Granularity

Ensure workloads operate under strict Linux capabilities. Do not grant broad `CAP_SYS_ADMIN` privileges to containers or user applications. 

If an application specifically requires eBPF functionality (e.g., a legitimate monitoring agent like Cilium or Falco), assign only `CAP_BPF` and `CAP_PERFMON` rather than full `CAP_SYS_ADMIN`.

Example Systemd Service Hardening (`/etc/systemd/system/example.service`):

```ini
[Service]
CapabilityBoundingSet=CAP_BPF CAP_PERFMON
AmbientCapabilities=CAP_BPF CAP_PERFMON
NoNewPrivileges=true
ProtectKernelTunables=true
```

### Step 3: Implement Linux Security Module (LSM) Hooks for BPF

Modern kernels (5.7+) support BPF LSM hooks, allowing security tools to control eBPF operations natively. Use AppArmor, SELinux, or custom BPF LSM policies to restrict which processes can execute `BPF_PROG_LOAD`.

Example SELinux policy directive to deny `bpf` capabilities to untrusted domains:

```text
neverallow untrusted_domain self:bpf { map_create map_read map_write prog_load prog_run };
```

---

## Incident Response Playbook: Investigating Suspected eBPF Persistence

If an eBPF rootkit or stealth mechanism is suspected during an incident response engagement, execute the following triage steps:

1. **Dump Active Programs and Maps**:
   ```bash
   bpftool prog dump xlated id <PROG_ID> > /tmp/prog_xlated.txt
   bpftool map dump id <MAP_ID> > /tmp/map_dump.txt
   ```
2. **Correlate Attach Points**: Identify where BPF programs are hooked:
   ```bash
   bpftool net list
   bpftool link list
   ```
3. **Identify Owning Processes**: Cross-reference the process ID owning the open file descriptors associated with the loaded program:
   ```bash
   ls -l /proc/*/fd/* 2>/dev/null | grep bpf-prog
   ```
4. **Force Unload Malicious Programs**:
   If a program is held open by a process, terminating the process PID will release the file descriptor and unload the program from kernel memory (unless pinned). If pinned, unmount or remove the pin file:
   ```bash
   rm -f /sys/fs/bpf/<malicious_pin>
   kill -9 <owning_pid>
   ```

---

## Summary Operations Checklist

| Defense Layer | Recommended Configuration / Action | Primary Value |
| :--- | :--- | :--- |
| **Sysctl** | `kernel.unprivileged_bpf_disabled = 1` | Blocks unprivileged users from issuing `bpf()` system calls. |
| **Audit Logging** | Monitor Syscall `321` (`bpf`) via `auditd` | Captures historical logs of binary paths attempting to load eBPF bytecode. |
| **System Integrity** | Automate `bpftool prog show` baseline checks | Detects unauthorized or unlinked kernel tracepoints and kprobes. |
| **Least Privilege** | Restrict `CAP_SYS_ADMIN` and `CAP_BPF` in container specs | Limits an attacker's ability to inject BPF programs even if root execution is achieved inside a container. |