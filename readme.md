# Peekbeam

A lightweight, single-target eBPF observability CLI, written in Rust using `aya`. Point it at a container, pod, or PID and see what it's actually doing at the kernel level — syscalls, network activity, file access, and memory behavior — live, without deploying a heavyweight platform like Falco or Cilium.

**Status:** Planning
**Language/stack:** Rust, `aya` (eBPF), Linux kernel tracepoints
**Category:** Systems / observability portfolio project

---

## 1. Problem Statement

When a single container or process misbehaves, existing options are either too heavy or too shallow:

- **Falco / Cilium Tetragon** — excellent, but cluster-wide platforms with their own control plane, rule engine, and deployment overhead. Nobody spins these up just to answer "what is this one pod doing right now."
- **`strace`** — ptrace-based, slow, invasive, changes process timing, and has no concept of container/pod boundaries.
- **`bpftrace` one-liners** — powerful but ad hoc; no persistent scoping to a container, no aggregated live view, nothing reusable across incidents.

**Gap:** there is no simple "attach and watch" tool, scoped to a single container, that a developer can reach for interactively during an incident — the equivalent of `htop` or `tcpdump`, but for kernel-level container behavior.

---

## 2. Goals

- Give a developer a live, low-overhead view of exactly what one container/pod/PID is doing at the syscall, network, file, and memory level.
- Make that view understandable without requiring the reader to already know the Linux syscall table or kernel internals cold — plain-language framing by default, raw detail available on request.
- Require no cluster-wide agent, control plane, or persistent daemon — run it, point it, read it, exit.
- Be genuinely lighter-weight than existing platforms for the single-target use case.
- Produce a clean, well-documented, contributable Rust codebase — this is a portfolio piece as much as a tool.

## 2.1 Non-Goals (for v1)

- Not a security/policy enforcement platform (no blocking, no alerting rules engine).
- Not a replacement for Falco/Cilium in a cluster-wide security posture.
- Not aiming for multi-node/distributed data collection in v1 — single-host, single-target only.
- Not building a custom UI/dashboard beyond a terminal UI (no web frontend in v1).

---

## 3. Functional Requirements

### FR1 — Process/Container Targeting
- FR1.1: Accept a raw PID (`--pid <PID>`).
- FR1.2: Accept a container ID (`--container <ID>`) and resolve it to a cgroup ID via the container runtime's cgroup path convention (Docker/containerd).
- FR1.3 (Phase 4): Accept a Kubernetes pod name/namespace (`--pod <name> -n <namespace>`) and resolve it to a container ID via the container runtime API (CRI), then to a cgroup.
- FR1.4: Fail clearly and immediately if the target cannot be resolved (no silent no-op).

### FR2 — Syscall Tracing
- FR2.1: Attach to `raw_syscalls:sys_enter` / `sys_exit` tracepoints.
- FR2.2: Filter events by target PID or cgroup ID (from FR1) — do not trace unrelated processes.
- FR2.3: Aggregate live counts per syscall name: invocation count, total time spent, average latency.
- FR2.4: Refresh the aggregated view on a configurable interval (default: 1s).
- FR2.5: Support a "top N syscalls by time" sort mode, similar to `strace -c` output but live.

### FR3 — Network Visibility
- FR3.1: Hook `tcp_connect` and `tcp_close` tracepoints, scoped to the target's network namespace/cgroup.
- FR3.2: Hook `tcp_retransmit_skb` to surface retransmits attributable to the target.
- FR3.3: Show a live table of active connections: local/remote address, port, state, bytes sent/received.
- FR3.4: Show retransmit count per connection, updated live.

### FR4 — File Access Visibility
- FR4.1: Hook `vfs_open` scoped to the target, to show which files are being opened.
- FR4.2: Hook `vfs_read` / `vfs_write` to show read/write volume per open file descriptor.
- FR4.3: Provide a toggle to include/exclude high-frequency noise paths (e.g. `/proc`, `/sys`) since these can dominate output without being interesting.

### FR5 — Memory Visibility
- FR5.1: Hook `mm_page_alloc` / `mm_page_free` tracepoints (or `kmem:kmalloc` / `kmem:kfree`) scoped to the target, to observe kernel-level page/slab allocation activity attributable to the process.
- FR5.2: Hook page fault tracepoints (`exceptions:page_fault_user`) to distinguish minor vs major faults — major faults are a strong signal of memory pressure (swapping/reclaim), not just allocation volume.
- FR5.3: Read cgroup memory controller stats directly (`memory.current`, `memory.stat` — RSS, cache, active/inactive anon) on the configured refresh interval, scoped to the target's cgroup, as a lighter-weight complement to raw tracepoint data.
- FR5.4: Show a live view of: current RSS, page fault rate (minor/major), allocation/free rate, and — where the target is a known Go process — expose `pprof`-style heap stats (`Mallocs`/`Frees`, heap in-use) if the target opts in via a lightweight sidecar hook (stretch — most container targets won't expose this without cooperation).
- FR5.5: Highlight the RSS-vs-allocator-view mismatch pattern directly (RSS can look high while an app-level heap profile reports much less in active use) since this is a common source of confusion during incidents.

### FR6 — Terminal UI
- FR6.1: Live-updating terminal UI (`ratatui` or similar) with tabs/panels for: Syscalls, Network, Files, Memory.
- FR6.2: Sortable columns within each panel (by count, by time, by bytes).
- FR6.3: A summary header showing target identity (PID/container/pod), uptime of the trace session, and total event counts.
- FR6.4: Graceful exit (Ctrl+C) that detaches all probes cleanly — no orphaned eBPF programs left attached.
- FR6.5: Group raw syscalls into plain-language categories (e.g. "File I/O," "Networking," "Process/Thread," "Memory," "Synchronization") as the default view, with an expand toggle to drop into individual syscall names for anyone who wants the raw detail. Nobody should have to already know that `epoll_wait` is a networking-adjacent call to make sense of the panel.
- FR6.6: A one-line plain-language description on hover/select for every syscall, connection state, or file event shown — e.g. `futex` → "waiting on a lock," `TIME_WAIT` → "connection closed, waiting to make sure the peer saw it." Short, no jargon, pulled from a small static lookup table shipped with the binary.
- FR6.7: A persistent "what am I looking at" summary line per panel — plain-English rollup of the current state (e.g. "142 connections, 3 retransmitting" or "CPU-bound on locking, not I/O") rather than requiring the user to read the whole table and infer it themselves.
- FR6.8: Visually distinguish "notable" rows (high retransmit count, major page faults, a syscall dominating total time) from routine ones — color/highlight, not just raw numbers the user has to compare by eye.
- FR6.9: A built-in `?`/help overlay listing what each panel shows and what "good" vs "worth investigating" looks like for its key metrics — so the tool teaches as it's used rather than assuming prior kernel knowledge.
- FR6.10: A `--beginner` / `--verbose` mode toggle: beginner mode defaults to grouped categories + plain-language annotations (FR6.5/6.6) always visible; verbose mode shows raw syscall/kernel terminology for experienced users who find the annotations noisy.

### FR7 — Output Modes
- FR7.1: Interactive terminal UI as the default mode.
- FR7.2: A `--json` flag for structured, non-interactive output (for piping into other tools or logging during an incident).
- FR7.3: A `--duration <seconds>` flag to run for a fixed window and exit with a final summary (for scripted/CI use).

### FR8 — Permissions & Safety
- FR8.1: Detect and clearly report missing capabilities (`CAP_BPF`/`CAP_PERFMON` or root) with an actionable error message rather than a raw kernel error.
- FR8.2: Document minimum kernel version requirements and verify at startup, failing fast with a clear message if unsupported.
- FR8.3: Ensure all eBPF programs and maps are unloaded on exit, including on abnormal termination (signal handlers).

---

## 3.1 Deployment / Usage Modes

Peekbeam attaches to kernel tracepoints, and there's one kernel per node shared by every container on it — so a running instance only ever sees its own node's kernel. Target container/pod/PID filtering happens *within* that node's view, not across nodes. This shapes how it's actually invoked:

- **Mode 1 — SSH + direct run (default for Phase 1–3):** SSH into the node the target is scheduled on, run the static binary locally with root/`CAP_BPF`+`CAP_PERFMON`. Simplest, no deployment needed ahead of time. This is the primary incident-response flow and the one worth optimizing UX for first.
- **Mode 2 — `kubectl debug node/<node>` (Phase 4):** package Peekbeam as a container image; run it via an ephemeral debug pod that mounts the host's namespaces. Avoids needing direct SSH/node access if the user only has Kubernetes RBAC. Same privilege requirements as Mode 1, different path to get there.
- **Mode 3 — Privileged DaemonSet (Phase 4, opt-in):** one pod per node, `hostPID`/`hostNetwork` + eBPF capabilities, sitting idle until invoked via `kubectl exec`. Closer to how Cilium/Falco deploy — reintroduces some "always-on agent" overhead, so treat as optional, not default.

**Multi-node clusters:** finding *which* node the target is on is a separate step (`kubectl get pod -o wide`) — Peekbeam itself doesn't search across nodes. Mode 2 is the cleanest fit here since `kubectl debug node/<name>` already takes a node argument.

### FR9 — Cluster-Aware Invocation (Phase 4)
- FR9.1: Given a pod name + namespace, resolve the target node and container ID via the Kubernetes API (builds on FR1.3).
- FR9.2: In DaemonSet mode (Usage Mode 3), transparently locate the DaemonSet pod scheduled on the resolved node and `kubectl exec` into it, streaming output back to the user as if run locally — turning "find node → SSH or exec → run tool" into a single command: `peekbeam --pod my-app-7f8a3b --namespace default`.
- FR9.3: In SSH mode (Usage Mode 1), this requires a known node hostname/IP list to be configured — more brittle, so the orchestrator pattern is primarily intended for DaemonSet mode.
- FR9.4: The core eBPF tracing engine remains strictly single-node/single-kernel by design — this orchestrator is a thin layer on top, not a rearchitecture of the core.

---

## 4. Non-Functional Requirements

- **Overhead:** tracing should add negligible CPU/latency overhead to the target process — this is the entire value proposition versus `strace`. Benchmark and publish overhead numbers.
- **Clarity:** default output should be readable by someone who hasn't memorized kernel/syscall terminology — this is treated as a first-class requirement (FR6.5–FR6.10), not a documentation afterthought.
- **Portability:** support at least two recent LTS kernel versions; document CO-RE (Compile Once, Run Everywhere) support status per feature.
- **Reliability:** no crashes on malformed/unexpected kernel event data; probes must degrade gracefully (drop event, log, continue) rather than panic.
- **Documentation:** every eBPF hook point documented with *why* it was chosen and what it costs, in the same explanatory style as the blog content this project supports.

---

## 5. Architecture Overview

```
+-----------------------------+
|        CLI (userspace)      |   Rust, clap for args, ratatui for TUI
|  - arg parsing / target      |
|    resolution (FR1)          |
|  - event aggregation         |
|  - TUI / JSON rendering      |
+--------------+---------------+
               | ring buffer / perf events
+--------------+---------------+
|        eBPF programs          |   Rust (aya-ebpf), compiled to BPF bytecode
|  - syscall tracepoints (FR2)   |
|  - tcp tracepoints (FR3)       |
|  - vfs tracepoints (FR4)       |
|  - mm/page-fault + cgroup       |
|    memory stats (FR5)          |
|  - cgroup/PID filtering        |
+-------------------------------+
```

- **Userspace <-> kernel communication:** eBPF ring buffer (`BPF_MAP_TYPE_RINGBUF`) preferred over perf buffers for lower overhead.
- **Filtering strategy:** push PID/cgroup filter into the eBPF program itself (via a BPF map holding target IDs) rather than filtering in userspace, to avoid unnecessary event volume crossing the kernel/userspace boundary.

---

## 6. Build Phases

### Phase 1 — Single-PID Syscall Counter (weekend-scale)
- Implement FR1.1, FR2 (all), FR6.1-FR6.3 (syscall panel only), FR8.1.
- Implement FR6.5/FR6.6 (categorized syscalls + plain-language annotations) from the start rather than bolting them on later — this is the difference between "another `strace -c`" and something a wider audience will actually use.
- Deliverable: a live "mini `htop` for syscalls" — shippable and demoable on its own.

### Phase 2 — Network Visibility
- Implement FR3 (all), extend TUI with a Network panel.
- Reuses tracepoint knowledge directly from prior TCP internals work.

### Phase 3 — Container Scoping
- Implement FR1.2, cgroup-based filtering across all existing probes.
- This is the phase that makes the tool "per-container" rather than "per-process" — the key differentiator versus a raw `bpftrace` script.
- Natural point to add FR5.3 (cgroup memory.stat reads) since it depends on cgroup resolution already being solid — cheaper to land than the raw tracepoint side of memory visibility (FR5.1/5.2).

### Phase 4 — Kubernetes-Aware Mode (stretch)
- Implement FR1.3 — resolve pod name -> container -> cgroup via CRI.
- Implement FR9 — cluster-aware invocation (pod-name-only UX, DaemonSet exec orchestration).
- Implement FR4 (file access) and remaining FR5 memory tracepoints (page faults, alloc/free) if not already folded in earlier.
- Polish output modes (FR7), full FR8 hardening.
- Ship Usage Modes 2 and 3 (container image + optional DaemonSet manifest).

---

## 7. Known Challenges / Risks

- **eBPF verifier constraints:** loop bounds, map access patterns, and instruction limits will constrain program design, especially early on given `aya`'s relative maturity versus `libbpf-go`.
- **Kernel version differences:** CO-RE support in `aya` is improving but not universal — needs explicit testing across kernel versions targeted for support.
- **Root/capability requirement:** unavoidable for eBPF; must be documented clearly (FR7.1) so it doesn't read as a bug.
- **Cgroup resolution fragility:** container runtime cgroup path conventions differ (cgroup v1 vs v2, Docker vs containerd) — FR1.2/FR1.3 need explicit handling for both.
- **Memory stat source mismatch:** cgroup-reported RSS, raw page-fault/alloc tracepoint counts, and (where available) app-level allocator stats (e.g. Go's `pprof`) can all disagree — the tool needs to present these as distinct views rather than one blended "memory usage" number, or it will just recreate the confusion it's meant to resolve (FR5.5).
- **Annotation maintenance burden:** the plain-language lookup table (FR6.6) needs to stay accurate as syscalls/tracepoints are added across phases — treat it as a first-class, reviewed artifact rather than scattered inline strings, or it will drift and start misleading the exact audience it's meant to help.

---

## 8. Content Pipeline (side benefit)

This project is expected to generate its own blog content independent of the tool itself:
- "Building an eBPF syscall tracer in Rust" (Phase 1)
- "Why cgroup scoping is harder than it looks" (Phase 3)
- "RSS, page faults, and the allocator: three views of 'memory usage' that don't agree" (Phase 3/4, memory visibility)
- "What the `aya` verifier taught me about eBPF" (ongoing, cross-phase)

Natural spiritual sequel to the TCP internals post — extends the same live-kernel-visibility theme from a blog demo into a real, reusable tool.

---

## 9. Open Decisions

- [ ] Working name — needs a real project name before repo creation.
- [ ] License (MIT/Apache-2.0 dual license is common for Rust systems tools).
- [ ] Whether Phase 1 ships as a standalone repo immediately, or stays in a branch until Phase 2 (network) is in, so the first public release has more substance.
- [ ] Target kernel version floor (affects which tracepoints/CO-RE features are safe to rely on).
- [ ] Whether to build the TUI with `ratatui` or keep Phase 1 as plain stdout table output and add TUI in Phase 2.