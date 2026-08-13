---
title: "Hardening Linux Workloads Against eBPF-Based Rootkits and Telemetry Evasion"
description: "An in-depth analysis of how adversaries leverage extended Berkeley Packet Filter (eBPF) hooks to bypass security agents, along with actionable controls to harden Linux kernel telemetry."
date: "2026-08-13"
tags: ["Linux Security", "eBPF", "Threat Detection", "Security Operations"]
category: "Cyber Security"
---

The widespread adoption of Extended Berkeley Packet Filter (eBPF) has transformed Linux observability and security monitoring. Security platforms now rely heavily on eBPF to capture network traffic, observe system calls, and execute low-overhead behavioral tracking directly within the kernel. 

However, eBPF is a double-edged sword. The same privileges that allow endpoint detection and response (EDR) agents to hook into kernel primitives also allow sophisticated adversaries to achieve stealthy persistence, alter kernel memory execution paths, and blind monitoring tools.

This analysis breaks down the mechanics of eBPF abuse, examines how rootkits like BPFDoor subvert detection, and details practical hardening measures to protect modern Linux infrastructure.

---

## The eBPF Threat Model: Kernel Power Without Kernel Modules

Historically, kernel-level persistence required loading custom Loadable Kernel Modules (LKMs). Modern kernel defensive configurations (such as `CONFIG_MODULE_SIG_FORCE` and strict Secure Boot implementations) make unauthorized LKM loading difficult without raising high-severity telemetry alerts.

eBPF circumvents these restrictions. It allows raw code execution inside an in-kernel virtual machine without requiring direct LKM loading. While the kernel run-time verifier validates eBPF bytecode for memory safety and execution bounds, it **does not** evaluate malicious intent.

### Primary Vectors for eBPF Exploitation

*   **Network Packet Redirection:** Attaching `BPF_PROG_TYPE_SOCKET_FILTER` or `BPF_PROG_TYPE_SCHED_ACT` programs to network interfaces allows attackers to inspect, drop, or rewrite incoming traffic before it hits the local network stack or security agents (e.g., `iptables`, `tcpdump`).
*   **Syscall and Function Tampering:** Using `kprobes` and `fmod_ret` to modify return codes of critical kernel functions, altering what security monitoring agents observe in userspace.
*   **Telemetry Dropping:** Tampering with eBPF ring buffers (`BPF_MAP_TYPE_RINGBUF`) used by security agents (such as Falco or Tetragon) to quietly discard log events associated with specific Process IDs (PIDs) or IP addresses.

---

## Anatomy of an eBPF Rootkit

To understand how an eBPF-based rootkit operates, consider the execution flow of a typical user-mode process requesting a file read (`sys_read`) or executing a binary (`sys_execve`):

```
+-------------------------------------------------------------------+
|                            USERSPACE                              |
|  [ Malicious Actor / Shell ]        [ Security Agent (Falco/EDR) ]|
+-------------------------------------------------------------------+
       |                                     ^
       | Syscall: execve()                   | Reads Event
       v                                     | Ringbuffer
+-------------------------------------------------------------------+
|                            KERNEL                                 |
|  [ Syscall Table ] --> [ Malicious eBPF Hook (kprobe/fexit) ]     |
|                              |                                    |
|                              +-- Drops or alters event data       |
|                              v                                    |
|                        [ Kernel Execution Routine ]               |
+-------------------------------------------------------------------+
```

1. **Privilege Escalation:** The attacker obtains root access or `CAP_BPF` / `CAP_SYS_ADMIN` capabilities within a initial compromise vector.
2. **Bytecode Compilation & Injection:** The attacker compiles eBPF C code using `clang/LLVM` target `bpf` or injects pre-compiled bytecode using raw syscalls via `sys_bpf(BPF_PROG_LOAD, ...)`.
3. **Map Initialization:** Shared data structures (`BPF_MAP_TYPE_HASH` or `ARRAY`) are instantiated to maintain state (e.g., list of target PIDs to hide, magic port sequences for backdoors).
4. **Hook Attachment:** The program attaches to a tracing target, such as `sys_enter_execve` or `sys_enter_connect`.
5. **Telemetry Subversion:** When an administrative command (like `ps`, `netstat`, or `lsof`) executes, the eBPF hook executes prior to processing, systematically scrubbing references to the malicious process or socket connections.

---

## Technical Hardening Strategies

Defending against eBPF-based persistence requires restricting kernel capability allocations, strictly managing runtime configurations, and monitoring the system call layer.

### 1. Restrict Unprivileged eBPF Execution

Ensure unprivileged users cannot invoke the `bpf()` system call. Modern Linux distributions default to disabling this, but it must be explicitly validated across fleet instances.

Apply the following kernel runtime configuration via `sysctl`:

```bash
# Disable unprivileged eBPF access permanently
sysctl -w kernel.unprivileged_bpf_disabled=2

# Enable JIT Hardening to mitigate JIT-spraying attacks
sysctl -w net.core.bpf_jit_harden=2
```

*   Setting `kernel.unprivileged_bpf_disabled = 2` locks down the interface entirely; the setting cannot be lowered back to `0` or `1` without a full system reboot.
*   Setting `bpf_jit_harden = 2` enables constant-blinded JIT compilation for all processes, introducing extra randomness to prevent memory corruption exploits inside the kernel JIT engine.

### 2. Lock Down Capabilities via Systemd and Containers

Never grant runtime environments broad access. Modern Linux kernel split out dedicated capabilities (`CAP_BPF`, `CAP_PERFMON`, `CAP_NET_ADMIN`) from the monolithic `CAP_SYS_ADMIN`.

For systemd services, restrict BPF operations explicitly in service unit definitions:

```ini
[Service]
CapabilityBoundingSet=~CAP_BPF CAP_SYS_ADMIN CAP_NET_ADMIN
ProtectKernelTunables=yes
RestrictNamespaces=yes
```

For container runtime engines (Docker, Containerd), drop `CAP_BPF` and `CAP_SYS_ADMIN` unless the container explicitly requires it (e.g., your primary security sensor daemon).

### 3. Enforce Kernel Execution Restrictions with Seccomp

Use `seccomp-bpf` profiles to explicitly block the `bpf` system call for applications that have no operational business interacting with kernel tracing modules.

Example Minimal Seccomp Profile snippet:

```json
{
  "defaultAction": "SCMP_ACT_ALLOW",
  "architectures": [
    "SCMP_ARCH_X86_64",
    "SCMP_ARCH_AARCH64"
  ],
  "syscalls": [
    {
      "names": [
        "bpf"
      ],
      "action": "SCMP_ACT_ERRNO",
      "args": []
    }
  ]
}
```

---

## Detection and Telemetry Strategy

Because an eBPF rootkit can alter high-level runtime telemetry, detection engineering must focus on lower-level system interfaces, file descriptor monitoring, and immutable kernel events.

### 1. Audit System Call Invocations

Use `auditd` to monitor direct interactions with the `bpf()` system call and execution of tooling used to manipulate BPF objects (such as `bpftool`).

Add the following rules to `/etc/audit/rules.d/audit.rules`:

```systemd
# Monitor the bpf syscall across 64-bit architectures
-a always,exit -F arch=b64 -S bpf -k eBPF_syscall_activity

# Track execution of common eBPF management binaries
-w /usr/sbin/bpftool -p x -k eBPF_management_tool
-w /sbin/bpftool -p x -k eBPF_management_tool
```

### 2. Monitor Mounted BPF Filesystems

The eBPF virtual filesystem (typically mounted at `/sys/fs/bpf`) hosts pinned BPF maps and programs that persist even if the loading process exits. 

Establish baseline file integrity monitoring (FIM) or audit tracing over `/sys/fs/bpf`:

```bash
# Example command to inspect pinned BPF objects manually
bpftool prog show
bpftool map show
```

Alert on the creation of unindexed or unapproved objects within `/sys/fs/bpf`. Any process loading eBPF bytecode without matching an approved SHA-256 hash or binary path from an official deployment manifest should trigger a high-priority SOC alert.

### 3. Inspect Loaded Programs via `/proc` Interfaces

While a sophisticated rootkit might attempt to hook kernel functions, auditing raw program descriptors via `/proc` or `bpftool` directly from an out-of-band context (or isolated administrative namespace) can reveal hidden hooks.

Look for key indicators:
*   Programs of type `kprobe`, `tracepoint`, or `raw_tracepoint` attached to kernel security components or audit hooks (e.g., `audit_log_start`, `security_file_open`).
*   Loaded programs lacking associated standard application names or executable metadata.

---

## Engineering Checklist for Security Teams

To ensure Linux environments are resilient against eBPF-based techniques, verify the following baseline controls:

* [ ] **Kernel Parameters:** Ensure `kernel.unprivileged_bpf_disabled` is set to `2` in `/etc/sysctl.conf`.
* [ ] **JIT Hardening:** Ensure `net.core.bpf_jit_harden` is set to `2`.
* [ ] **Least Privilege:** Confirm that container runtimes explicitly drop `CAP_BPF` and `CAP_SYS_ADMIN` capabilities for workload pods.
* [ ] **Syscall Auditing:** Verify `auditd` rules are configured to record `bpf()` system calls enterprise-wide.
* [ ] **Sensor Integrity:** Ensure defensive EDR agents run with anti-tamper mechanisms and validate program registration state upon startup.
* [ ] **Asset Baselining:** Inventory all legitimate eBPF-reliant applications across the infrastructure (e.g., Cilium, Falco, Datadog Agent) and alert on anomalies outside this baseline.