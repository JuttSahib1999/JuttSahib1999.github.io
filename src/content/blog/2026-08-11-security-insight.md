---
title: "Deep-Dive: Engineering Linux Threat Detection with eBPF and BTF"
description: "An architectural breakdown of Extended Berkeley Packet Filter (eBPF) for runtime security, exploring kernel-level instrumentation, CO-RE, and detection patterns for container breakout vectors."
date: "2023-10-25"
tags: ["eBPF", "Linux Security", "Threat Detection", "Runtime Observability"]
category: "Cyber Security"
---

Traditional Linux threat detection architectures have long operated under a fundamental compromise: run security agents in user-space and suffer from missed events and high CPU overhead, or deploy Loadable Kernel Modules (LKMs) and risk kernel panics on host nodes.

Extended Berkeley Packet Filter (eBPF) shifts this paradigm by enabling sandboxed, event-driven programs to execute directly within the Linux kernel without modifying kernel source code or loading unstable modules. Combined with BPF Type Format (BTF) and Compile Once – Run Everywhere (CO-RE) primitives, eBPF allows security operations and detection engineering teams to achieve fine-grained observability across workloads with minimal overhead.

This analysis breaks down the architectural mechanics of eBPF-based security monitoring, examines event-hooking mechanisms, and walks through a practical implementation for detecting container escape attempts in real time.

---

## The Architectural Limits of Legacy Linux Instrumentation

To understand why eBPF is becoming the standard for runtime security, we must evaluate the failure modes of legacy tracing mechanisms:

1. **`ptrace` and User-Space Interception:** Tools relying on `ptrace` force a context switch on every system call (syscall). This introduces significant latency—often halting process execution—and is vulnerable to Time-of-Check to Time-of-Use (TOCTOU) race conditions where an attacker modifies memory buffers after execution checks complete.
2. **Auditd (Linux Audit Subsystem):** While reliable, `auditd` suffers from severe performance degradation under high syscall volumes (such as busy Kubernetes nodes). Its reliance on netlink sockets for log delivery can result in dropped events during traffic spikes, creating visibility blind spots.
3. **Loadable Kernel Modules (LKMs):** LKMs offer full visibility, but lack memory safety controls. A bug in an LKM causes a host kernel panic (`bug_on`), bringing down production workloads. Additionally, LKMs require recompilation or DKMS for every kernel version update across heterogeneous environments.

eBPF solves these operational constraints through the **eBPF Verifier**, a static analyzer that verifies code safety before loading programs into the kernel. The verifier enforces:
* Non-cyclic execution (guaranteed termination).
* Memory boundary checks (no arbitrary memory dereferencing).
* Strict program size limits and permitted kernel helper functions.

---

## Kernel Hooking Mechanics for Security Engine

eBPF programs run in response to specific kernel events. For threat detection, three primary hook types are utilized:

```
+-------------------------------------------------------------------+
|                            User Space                             |
|  +-------------------------------------------------------------+  |
|  |             Detection Engine / Security Agent               |  |
|  +-------------------------------------------------------------+  |
|                                 ^                                 |
|                    BPF_MAP_TYPE_RINGBUF Read                      |
|                                 |                                 |
+---------------------------------|---------------------------------+
|                            Kernel Space                           |
|                                 |                                 |
|  +------------------------------+------------------------------+  |
|  |                       eBPF Program                          |  |
|  +-------------------------------------------------------------+  |
|        |                        |                        |        |
|  +-----------+            +-----------+            +-----------+  |
|  |  Tracepoint|            |  kprobe   |            |  LSM Hook  |  |
|  +-----------+            +-----------+            +-----------+  |
|        |                        |                        |        |
|  Syscall Entry            Internal Kernel           Access Control|
|  (sys_enter_execve)       Function (do_sys_open)   (security_bprm)|
+-------------------------------------------------------------------+
```

### 1. Kprobes and Kretprobes
* **Kprobes (Kernel Probes):** Dynamic hooks that can be attached to virtually any internal kernel function instruction. They allow inspection of function arguments prior to execution.
* **Kretprobes (Kernel Return Probes):** Hook the return path of a kernel function, allowing the capture of return codes and output buffers.
* *Drawback:* Internal kernel function signatures change between kernel releases, breaking probe logic if not carefully managed.

### 2. Tracepoints
* Stable, static hooks placed intentionally by kernel developers at critical code paths (e.g., `tracepoint/syscalls/sys_enter_execve`).
* Tracepoints guarantee ABI stability across kernel updates, making them ideal for standard syscall monitoring.

### 3. BPF-LSM (Linux Security Module)
* Introduced in Linux Kernel 5.7, BPF-LSM allows eBPF programs to attach directly to kernel security hooks (e.g., `security_bprm_check`, `security_file_open`).
* Unlike kprobes or tracepoints, BPF-LSM hooks can **block** malicious operations by returning access control decisions (`-EPERM`), moving eBPF from passive detection to active inline prevention.

---

## Telemetry Transport: Ring Buffers and CO-RE

To process kernel events in user-space detection engines without dropping telemetry, eBPF utilizes specific map data structures.

### `BPF_MAP_TYPE_RINGBUF`
Legacy eBPF used `BPF_MAP_TYPE_PERF_EVENT_ARRAY`, which allocated separate memory buffers per CPU core. This led to memory inefficiency and out-of-order event delivery across cores. The modern `RINGBUF` map provides:
* A single, multi-producer, single-consumer shared memory region.
* Lockless memory submission via atomic memory operations.
* Guaranteed in-order event sequencing across all CPU cores.

### CO-RE (Compile Once – Run Everywhere)
Historically, eBPF required installing `clang` and kernel headers on target nodes to compile programs at runtime. CO-RE eliminates this requirement by combining:
1. **BTF (BPF Type Format):** Compact metadata format embedded in the kernel image that describes all internal kernel types, structs, and function signatures.
2. **`libbpf` Relocation Engine:** Adjusts field offsets in the compiled eBPF bytecode dynamically based on the target kernel's BTF data during program loading.

---

## Technical Scenario: Detecting Container Escape via `memfd_create` and Namespace Manipulation

A common post-exploitation technique in containerized environments involves creating fileless binaries in host memory (`memfd_create`) followed by namespace manipulation to break out of host isolation boundaries.

Below is an annotated, production-grade eBPF C program targeting `sys_enter_memfd_create` tracepoints to capture fileless payload execution attempts.

### eBPF C Kernel Program (`detector.bpf.c`)

```c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

struct event_t {
    u32 pid;
    u32 mntns;
    char comm[16];
    char name[256];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // 256KB Ring Buffer
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_memfd_create")
int handle_memfd_create(struct trace_event_raw_sys_enter *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;

    // Filter out known baseline benign processes if necessary
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    u32 mntns_id = BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);

    // Reserve space in the Ring Buffer
    struct event_t *event = bpf_ringbuf_reserve(&events, sizeof(struct event_t), 0);
    if (!event) {
        return 0; // Buffer full, event dropped
    }

    event->pid = pid;
    event->mntns = mntns_id;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    // Extract the 'uname' pointer argument from sys_enter_memfd_create context
    const char *uname_ptr = (const char *)ctx->args[0];
    bpf_probe_read_user_str(event->name, sizeof(event->name), uname_ptr);

    // Submit event to user-space engine
    bpf_ringbuf_submit(event, 0);
    return 0;
}
```

### User-Space Event Consumer Logic (Python / C Driver)

When the ring buffer triggers an event read, user-space pipelines correlate the payload name and the target `mntns` (mount namespace) against the host's root namespace ID (`4026531836`). If a process executing inside an isolated container namespace (`mntns != host_mntns`) triggers `memfd_create` and attempts to bind-mount host paths, an alert triggers:

```json
{
  "timestamp": 1698249600,
  "event_type": "FILELESS_EXECUTION_ATTEMPT",
  "process_id": 48291,
  "process_name": "malicious_entry",
  "mount_namespace": 4026532891,
  "file_descriptor_name": "elf_payload",
  "host_namespace_match": false,
  "severity": "CRITICAL",
  "mitre_technique": "T1620 - Reflective Code Loading"
}
```

---

## Operational Considerations and Limitations

Deploying eBPF at scale across infrastructure presents specific engineering challenges:

1. **Kernel Minimum Requirements:**
   * Full eBPF functional capability requires Linux Kernel **5.4+**.
   * BPF-LSM enforcement capabilities require Linux Kernel **5.7+** compiled with `CONFIG_BPF_LSM=y`.
   * BTF metadata availability (`/sys/kernel/btf/vmlinux`) is essential for CO-RE deployment.

2. **Evasion Considerations:**
   * **Syscall Hook Bypassing:** Hooking high-level syscalls directly can be susceptible to dynamic binary instrumentation or direct kernel wrapper calls if hooks are improperly specified. Defensive models should monitor underlying layer hooks (e.g., dynamic functions like `do_sys_openat2` instead of relying solely on `sys_enter_openat`).
   * **Map Exhaustion Attacks:** Adversaries attempting to cause Denial of Service (DoS) against monitoring agents may flood syscall interfaces, saturating the `RINGBUF` map. Agents must implement drop metrics via map statistics to signal loss of fidelity during exhaustion events.

3. **Performance Overhead Tuning:**
   * Avoid string parsing operations inside kernel space wherever possible. Extract raw integers, PIDs, and pointers within the kernel program, delegating string resolution and enrichment (e.g., resolving UIDs to usernames, container IDs to Kubernetes pod metadata) to user-space context engines.

---

## Defensive Engineering Summary

eBPF shifts Linux runtime security from low-fidelity, post-hoc log parsing to deterministic, low-overhead kernel observability. By implementing detection pipelines that combine static tracepoints, stable BTF relocations, and structured event streaming via Ring Buffers, security teams can construct high-throughput telemetry pipelines capable of identifying sophisticated fileless attacks, container breakouts, and privilege escalation primitives in production.