# eBPF-Based Runtime Detection — Falco, Tetragon, Tracee Expertise

Operational reference for staff-security / detection-engineering / SRE running eBPF-based runtime detection on production Linux fleets and Kubernetes. Specialization of [[reference-detection-engineering]] (broader landscape covering Sigma/YARA/EDR architecture/ATT&CK), focused on the eBPF-generation runtime-detection tier. Sibling, not a redo, of [[reference-container-runtime-escape]] (the bugs being detected) and [[reference-linux-kernel-exploitation]] (eBPF as kernel attack surface, not just defense substrate).

Imperative voice. Real CVE/vendor names where groundable. `[unverified]` flags applied per Rule 28 fact-discipline.

---

## 1. Introduction — why this doc exists

Runtime detection is the discipline of observing host behavior in real time and flagging events that match an attack pattern. The EDR generation (CrowdStrike Falcon, SentinelOne, Microsoft Defender for Endpoint) built this on Windows via kernel callbacks (`PsSetCreateProcessNotifyRoutine`, `ObRegisterCallbacks`, MiniFilter), on macOS via `kauth` and EndpointSecurity, and on Linux via a mix of audit subsystem, LSM modules (SELinux/AppArmor stacked-LSM), and out-of-tree kernel modules.

The eBPF generation replaces the out-of-tree-kernel-module path on Linux. eBPF programs are JIT-compiled bytecode, sandbox-verified, attached to programmable kernel hooks (kprobes, tracepoints, LSM hooks, XDP, cgroup hooks), and read/write to maps that user-space can poll. The substrate is in-tree (no separate module install), CO-RE portable (one binary per architecture instead of one per kernel version), and verifier-bounded (a buggy probe can't crash the kernel — it gets rejected at load).

Three operational reasons this matters:

1. **No kernel-module install.** Out-of-tree kernel modules break on every kernel upgrade, taint the kernel, and require sign-off in regulated environments. eBPF programs load via `bpf(2)` and persist as files in `/sys/fs/bpf/` or attach lifetime-bound to a process.
2. **Per-pod policy granularity.** Tetragon's `TracingPolicy` CRD attaches detection policies to specific Kubernetes pods/namespaces. Falco's rules globally apply but Falcoctl + per-namespace plugins approximate the same.
3. **Post-incident forensic visibility into the syscall stream.** Tracee + Falco record syscall arguments + process tree at the kernel layer. When an incident occurs, the audit trail exists at the most-authoritative source (cf. [[reference-dfir-methodology]] §4 cloud-forensics — runtime-detection logs are increasingly the high-fidelity DFIR substrate on Linux/K8s).

This doc covers what the substrate makes possible, the three production tools (Falco, Tetragon, Tracee), the architectural trade-offs (observability vs enforcement; eBPF vs kernel module; LSM vs tracepoint vs kprobe), production realities (resource overhead, ring-buffer drops, deployment patterns), the 2024-2026 expansion into AI-workload telemetry, and honest failure modes.

---

## 2. eBPF substrate — what makes runtime detection possible

**History.** Berkeley Packet Filter (BPF) shipped in 1992 from McCanne + Jacobson at LBNL — a minimal in-kernel VM for packet filtering in `tcpdump`. Classic BPF was extended into eBPF by Alexei Starovoitov + Daniel Borkmann landing in Linux 3.18 (Dec 2014). The instruction set widened to 64-bit registers, more program types, and helper-function call interface. Programs are written in C, compiled with `clang -target bpf`, loaded via `bpf(2)`, JIT-compiled to native instructions, and attached to a hook.

**The verifier.** Before a program executes, the in-kernel BPF verifier walks the program's control-flow graph and rejects any program that could:
- Read uninitialized memory (uninitialized register or stack slot)
- Loop unboundedly (kernel ≤ 5.2 disallowed loops entirely; ≥ 5.3 allows bounded loops; ≥ 5.13 allows iter helpers)
- Access memory out of valid map/stack/context bounds
- Call non-allowlisted helpers from a given program type
- Exceed instruction-count limits (originally 4096; modernized to 1 million with subprog calling)

The verifier is the load-bearing safety primitive. It is also the historical attack surface — see §12 honest failure modes + [[reference-linux-kernel-exploitation]] for the CVE corpus.

**Map types.** eBPF programs share state with user space and across program invocations via maps:
- `BPF_MAP_TYPE_HASH` / `BPF_MAP_TYPE_LRU_HASH` — keyed lookups, optionally LRU-evicted
- `BPF_MAP_TYPE_ARRAY` / `BPF_MAP_TYPE_PERCPU_ARRAY` — index-keyed; per-CPU variants eliminate cache-line contention
- `BPF_MAP_TYPE_LPM_TRIE` — longest-prefix-match for IP/CIDR lookups
- `BPF_MAP_TYPE_RINGBUF` (kernel 5.8+) — high-throughput multi-producer-single-consumer ring buffer with epoll integration; replaced the older perf-event-array for most detection tooling
- `BPF_MAP_TYPE_STACK_TRACE` — bounded call-stack capture for syscall tracing
- `BPF_MAP_TYPE_PROG_ARRAY` + tail-calls — chain programs for large logic that exceeds verifier instruction limits

**Program types.** Each type hooks a different kernel event:
- **kprobe / kretprobe** — dynamic instrumentation of arbitrary kernel functions on entry/return. ABI-unstable across versions.
- **tracepoint** — statically-instrumented points (sys_enter_*, sched_*, net_*, signal_*). ABI-stable.
- **raw tracepoint** — lower-overhead variant skipping the perf-event wrapper.
- **fentry / fexit (kernel 5.5+)** — BPF-trampoline-based function entry/exit; lower overhead than kprobes.
- **LSM** (kernel 5.7+ with `CONFIG_BPF_LSM=y`) — attach to Linux Security Module hooks; return value mediates the operation (block on non-zero).
- **uprobe / uretprobe** — user-space probe; instrument application functions.
- **XDP / TC** — packet processing at NIC driver level.
- **cgroup_*** — socket/connect/sendmsg hooks on cgroup boundary.

**CO-RE (Compile-Once Run-Everywhere).** Andrii Nakryiko's libbpf project (Meta) introduced CO-RE: eBPF programs carry BTF (BPF Type Format) relocations, the kernel ships its own BTF descriptors (`/sys/kernel/btf/vmlinux`), and the BPF loader rewrites field offsets at load time. Without CO-RE, every kernel version needed a separate compile of the probe (the BCC model). With CO-RE, one probe binary works across most kernels on a given architecture. **Production fleets cannot run pre-CO-RE-BCC tooling without massive compile infrastructure** — CO-RE is the substrate that makes fleet deployment economic.

**eBPF as security risk** — defenders deploy eBPF for detection; attackers also use eBPF for in-kernel implants and EDR-evasion (bpfdoor, Symbiote, Boopkit). The same primitive that lets Tetragon observe syscalls lets an attacker hide them. The eBPF-verifier-escape CVE lineage (CVE-2021-3490, CVE-2021-4204, CVE-2022-23222 — Manfred Paul + tr3e wang + others) demonstrates the verifier itself is exploitable. See [[reference-linux-kernel-exploitation]] §6 for the full corpus.

---

## 3. Falco — Sysdig open-source

**Origin.** Loris Degioanni (founder of Sysdig, prior co-creator of WinPcap + libpcap contributor) authored Falco at Sysdig circa 2016. Sysdig's broader product is the Sysdig Secure CNAPP; Falco is the open-source detection engine.

**CNCF status.** Falco entered CNCF Sandbox 2018, Incubation 2020, Graduated February 2024. Graduation matters for vendor procurement in regulated environments.

**Architecture.** Three components:
1. **Driver layer** — one of: kernel module (legacy), eBPF probe (modern), or "modern_ebpf" CO-RE driver-less probe (Falco 0.34+). The driver reads syscall enter/exit + signal/sched/net events and pushes them to user space via ring buffer.
2. **Falco daemon (`falco`)** — user-space process. Reads events, applies rule engine, emits alerts. Written in C++.
3. **Falcosidekick** — separate Go service that fans out alerts to Slack / PagerDuty / S3 / Elasticsearch / Loki / Kafka / Webex / Teams / SMTP / GCP Pub/Sub / Azure Event Hubs. Decouples alert routing from detection.

**Rule format.** Falco rules are YAML. Three primary constructs:

```yaml
- macro: container
  condition: container.id != host

- list: shell_binaries
  items: [sh, bash, zsh, csh, ksh, dash]

- rule: Terminal shell in container
  desc: A shell was used as the entrypoint/exec point in a container
  condition: >
    container and shell_procs and proc.tty != 0
    and container_entrypoint
  output: >
    A shell was spawned in a container with an attached terminal
    (user=%user.name container_id=%container.id image=%container.image.repository
     shell=%proc.name parent=%proc.pname cmdline=%proc.cmdline)
  priority: NOTICE
  tags: [container, shell, mitre_execution]
```

Fields use Sysdig field-syntax (`proc.name`, `container.id`, `evt.type`, `fd.name`, `user.uid`). Priority levels follow syslog severity (EMERGENCY → ALERT → CRITICAL → ERROR → WARNING → NOTICE → INFORMATIONAL → DEBUG). Tags enable corpus filtering by MITRE technique or category.

**Default rule corpus.** Community rules in `falco_rules.yaml` (stable, bundled by default) + `falco-incubating_rules.yaml` + `falco-sandbox_rules.yaml`. Maintained by the Falco rules team (Mark Stemm (approver) + Lorenzo Susini (reviewer) + community). Tagged by `mitre_persistence`, `mitre_privilege_escalation`, `mitre_lateral_movement`, etc. Rules cover:
- Filesystem writes outside expected paths
- Process spawns of shells/interpreters in containers
- Sensitive file reads (`/etc/shadow`, SSH keys, cloud credential files)
- Outbound connections to non-allowlisted destinations
- Privilege-escalation primitives (setuid, capabilities, namespace creation)
- Container-escape attempts (write to `release_agent`, host filesystem mounts, kernel module loads)

**Plugins.** Falco's plugin framework (added Falco 0.31+) supports out-of-tree event sources:
- `k8s_audit` plugin — ingests Kubernetes API server audit log; rules trigger on suspicious K8s API events (exec into pod, secret read, RBAC changes).
- `cloudtrail` plugin — ingests AWS CloudTrail; rules trigger on cloud-API events (IAM policy changes, S3 bucket public-acl, KMS key disable).
- `github` plugin — ingests GitHub webhook events.
- `okta` plugin — ingests Okta events.

Plugins decouple Falco from syscall-only origins; the same rule engine + alert routing works across cloud-control-plane and runtime-syscall events.

**Production limitations.** The eBPF probe requires kernel BTF + matching kernel version. In noisy workloads (high syscall rate, e.g., ML training nodes with many subprocess spawns) the ring buffer can drop events. Falco emits an "events dropped" Prometheus metric — few teams alert on it. Default rule corpus generates alert volume operators frequently describe as "unmanageable" without tuning.

---

## 4. Tetragon — Isovalent / Cilium

**Origin.** Tetragon is the runtime-security component of Cilium, authored at Isovalent by John Fastabend + Mahé Tardy + collaborators. Isovalent was founded by Thomas Graf (Cilium project lead) + Dan Wendlandt; Isovalent was acquired by Cisco in April 2024. Cilium itself is CNCF Graduated (Oct 2023). Tetragon project status in CNCF `[unverified — separate project, status fluid]`.

**Architecture difference vs Falco — the load-bearing point.** Tetragon performs **synchronous enforcement** in kernel by overriding the return value of a hooked call (so the function is never executed) or by sending a signal such as SIGKILL to the process; hook points include kprobes, tracepoints, uprobes and LSM hooks. This means Tetragon can KILL a process or BLOCK a syscall from kernel context on policy match. Falco can only OBSERVE syscalls (via tracepoint) and emit alerts; any kill action is out-of-band by a user-space responder.

This is not a "Tetragon is better" claim — it is an architectural axis with trade-offs:
- **Synchronous enforcement** prevents the attack but risks corrupting application state when an in-flight syscall is blocked or a process killed mid-transaction.
- **Asynchronous observability** never disrupts the application but always sees attacks after they happen.

Conservative production posture: observability by default, enforcement only for narrow, well-tested policies (e.g., block writes to `release_agent`, block execve of known-bad binaries).

**Tetragon TracingPolicy CRD.** Declarative policy as Kubernetes CRD:

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: detect-shell-in-pod
spec:
  kprobes:
    - call: "sys_execve"
      syscall: true
      args:
        - index: 0
          type: "string"
      selectors:
        - matchArgs:
            - index: 0
              operator: "Equal"
              values: ["/bin/sh", "/bin/bash"]
          matchActions:
            - action: Sigkill
```

The CRD attaches to specific pods/namespaces via selectors. The `matchActions` field supports `Post` (emit event), `Sigkill` (kill process), `Override` (return arbitrary value from syscall), `FollowFD` / `UnfollowFD` (track file descriptors).

**Cilium integration.** Tetragon ships as part of Cilium's runtime-security capability. Service-mesh observability (Hubble) + network policy (Cilium NetworkPolicy + CiliumClusterwideNetworkPolicy) + runtime detection (Tetragon) all share the same eBPF substrate and management plane. In a Cilium-everything cluster this is the natural answer to "where do we put runtime detection." Cross-link [[reference-service-mesh-security]] for the broader integration story.

**Production posture.** Cisco-Isovalent maintains; Cilium's commercial product (Isovalent Enterprise for Cilium) is the support path for regulated customers. Tetragon OSS remains the same codebase.

---

## 5. Tracee — Aqua Security open-source

**Origin.** Tracee was authored at Aqua Security by Yaniv Agman (Aqua research team) in 2019. Aqua's broader product is the Aqua CNAPP; Tracee is the open-source runtime-detection engine.

**Architecture.** eBPF-based driver (Go user-space + C eBPF probe). Output is a streaming event log to stdout, file, or downstream services (Postee for alert routing).

**Differentiator.** Tracee's design emphasis is detection-rule expression as composable signatures rather than only filter conditions:
- **tracee-ebpf** — raw event collection.
- **tracee-rules** — signature engine that takes raw events and emits detection events. Signatures are Go code or OPA Rego policies.
- **Tracee plugins** include fileless-execution detection, container-image-supply-chain signal, and process-lineage tracking.

**MITRE ATT&CK tagging.** Tracee signatures explicitly carry MITRE ATT&CK technique IDs (e.g., `T1059.004` for unix-shell scripting, `T1611` for escape to host). Tracee output integrates with downstream SIEM via OCSF mappings.

**Production posture.** Aqua positions Tracee as both OSS and part of the broader Aqua Platform. The OSS community remains active; runtime detection in CNAPP marketing materials frequently references Tracee.

---

## 6. The eBPF vs kernel-module trade-off

The legacy detection-driver path on Linux is an out-of-tree kernel module (LKM). CrowdStrike Falcon historically used a kernel module on Linux; many EDR products still do for older RHEL support. The trade-off:

**Kernel module (legacy):**
- Pros: Full kernel privileges. No verifier restriction. Works on any kernel.
- Cons: Requires out-of-tree build per kernel version. Requires module-signing enrollment in Secure Boot environments. Crashes kernel on bugs (CrowdStrike July 2024 incident — Falcon Linux sensor crashes were rare but Windows sensor crash via a content channel update was widely reported; the failure mode of "vendor pushes a regression that panics every kernel in the fleet simultaneously" applies regardless of platform). Module-loading capability is itself a privilege escalation primitive — see [[reference-linux-kernel-exploitation]] §5 BYOVD (Bring Your Own Vulnerable Driver) on Linux.

**eBPF (modern):**
- Pros: In-tree (loaded via `bpf(2)`, no separate package install). Verifier-bounded (a buggy probe gets rejected at load, doesn't crash the kernel). CO-RE-portable (one binary per architecture).
- Cons: Verifier-imposed restrictions (no unbounded loops; bounded instruction count; restricted helper set). Requires kernel BTF (production pre-5.4 kernels often lack BTF). Probe complexity exceeds what the verifier accepts → fall back to multi-program tail-call chains.

**Some vendors still ship kernel modules** for RHEL 7 LTS (kernel 3.10, no useful eBPF) or for capability beyond eBPF verifier limits (deep call-stack walking, complex stateful logic that exceeds 1M instructions).

**Falco supports both** — kernel module legacy + eBPF + driverless modern_ebpf (CO-RE). The driver selection is a deployment config knob.

---

## 7. LSM hooks vs tracepoints vs kprobes — the policy-vs-observability distinction

The architectural axis distinguishing Tetragon from Falco. Pick the hook based on whether you need to OBSERVE (after the action) or ENFORCE (before the action).

**LSM (Linux Security Module) hooks.** Mediation points. The hook fires BEFORE the operation completes; returning non-zero blocks the operation with `-EACCES` or similar. ~250 LSM hooks defined across `file_open`, `inode_unlink`, `bprm_check_security` (execve), `task_kill`, `socket_connect`, `bpf` (recursive — controls who can load BPF programs), etc.

**BPF-LSM (`CONFIG_BPF_LSM=y`, kernel 5.7+, KP Singh at Google was primary contributor).** Exposes LSM hooks to eBPF programs. Now an eBPF program can mediate. This is Tetragon's enforcement substrate. Stacks with SELinux/AppArmor — BPF-LSM is one of several stacked LSMs; each can independently veto.

**Tracepoints.** Statically-instrumented kernel events. The kernel source code contains `trace_*()` calls at well-defined points: `sys_enter_execve`, `sys_exit_execve`, `sched_switch`, `net_dev_xmit`, `signal_generate`, `block_rq_complete`, etc. The ABI is stable across kernel versions (the kernel community treats tracepoints as user-facing API). Tracepoints fire AFTER the action — they're for observation, not enforcement. Falco's primary substrate.

**kprobes / kretprobes.** Dynamic instrumentation. Attach at any kernel function address. ABI-unstable — function names and signatures change between kernel versions. Useful for events that lack tracepoints (e.g., specific filesystem driver functions, new kernel features). Tetragon uses kprobes for matching specific syscall argument patterns.

**fentry / fexit (kernel 5.5+).** BPF-trampoline-based function entry/exit; lower overhead than kprobes (no int3 trap-and-fixup). Andrii Nakryiko + Alexei Starovoitov contributed. Increasingly the preferred mechanism over kprobes for stable function targets.

**uprobes.** User-space probe equivalent — attach at user-space binary addresses. Used for application-level events:
- TLS unencrypted bytes before kernel encryption (probe libssl `SSL_write`/`SSL_read` to extract cleartext for inspection — see `bpf-ssl-trace`/Pixie)
- JIT compiler invocations (probe V8/JSC functions for malicious-JS detection)
- Database query execution (probe libpq's `PQexec` to log SQL at the application boundary)

uprobes carry high overhead (uretprobe in particular triggers known performance pathology on heavily-used functions — overhead 10-100x kernel-side). Use sparingly.

**The enforcement-vs-observability split is the architectural axis distinguishing Tetragon from Falco.** Tetragon-via-BPF-LSM enforces; Falco-via-tracepoints observes. Each has its place.

---

## 8. Rule corpus and detection coverage

**MITRE ATT&CK coverage.** Falco's default rule corpus tags rules with MITRE technique IDs:
- **T1059** (Command and Scripting Interpreter) — shell spawn in container, scripting-interpreter execution.
- **T1611** (Escape to Host) — privileged container, mount of host filesystem, write to `release_agent`, container breakout via runc.
- **T1574** (Hijack Execution Flow) — `LD_PRELOAD` writes, write to system binary directories.
- **T1219** (Remote Access Software) — outbound connection to known C2 endpoints.
- **T1106** (Native API) — anomalous syscall sequences.

Cross-link [[reference-detection-engineering]] §3 for MITRE ATT&CK + D3FEND taxonomy framing.

**Container-escape detection.** This is where runtime detection earns operational cost. Specific rules (cross-link [[reference-container-runtime-escape]] §5 leaky-vessels + §7 CVE-2022-0492 `release_agent`):
- **"Write below root"** — process writes to `/etc/`, `/usr/`, `/bin/` from a container context that shouldn't.
- **"Write below binary dir"** — process writes to `/usr/bin`, `/usr/sbin`, `/bin`, `/sbin`.
- **"Mount Launched in Privileged Container"** — mount syscall from a privileged container.
- **"Outbound Connection to C2 Servers"** — connection to a known-bad IP (rule depends on threat-intel feed integration).
- **"Modify Binary Dirs"** — write or rename in `/usr/local/bin` etc.
- **"Container Drift"** — file added or modified in container that wasn't in original image.
- **"K8s ConfigMap Modification"** (via k8s_audit plugin) — anomalous configmap edits.

**Common detection-rule pitfalls.** Catalog them honestly:
- **Overly-broad rule generates noise.** "Process spawns in container" is true thousands of times per second on a busy cluster. Filtering to "shell process spawns in container" narrows but doesn't eliminate (init systems, healthchecks, sidecars).
- **Overly-narrow rule misses variants.** "Spawn of `/bin/bash`" misses `/bin/sh`, `/usr/bin/zsh`, `busybox sh`, and any renamed shell. Use macros + lists to enumerate.
- **Allowlist-driven rules require maintenance** to avoid coverage gaps as legitimate workloads change.
- **Fields with high cardinality (cmdline, full path) blow up downstream SIEM costs.** Project to lower-cardinality fields when possible.

**Falco's "noise" problem is the operational pushback most teams cite.** Default corpus alert volume is operationally unmanageable without tuning. Tuning is expensive (per-environment baseline gathering, allowlist construction, rule disable/enable cycle). Teams that don't tune disable rules wholesale → coverage gap.

**Application-specific rules.** Falco can extend to detect specific app-layer events via uprobes (TLS cleartext at `SSL_write`, libc functions). Tetragon TracingPolicy matchers hook specific syscall surfaces. Production detection-engineering teams write per-application rule corpora for their crown-jewel workloads — generic rules + targeted rules combined.

---

## 9. Production deployment realities

**Resource overhead.** Detection-tool footprint on a typical node:
- eBPF programs run in kernel context. Per-syscall overhead ~hundreds of nanoseconds to low microseconds depending on hook complexity.
- Falco user-space daemon: ~20-100MB RAM + 1-3% CPU at idle; higher under burst load.
- Tetragon similar; BPF-LSM hooks slightly heavier than tracepoints because of the mediation cost.
- Tracee similar to Falco.

**Event volume.** A busy production node generates 100k-1M syscalls/sec (depends on workload — CGI-style frequent-fork workloads run high; long-lived service processes run lower). Filtering must happen IN-KERNEL (eBPF program decides to push or drop) to avoid user-space CPU blow-up. Pushing every syscall to user space saturates the ring buffer immediately.

**Ring buffer drops.** Under burst load the BPF ring buffer between kernel and user space can overflow. Falco reports kernel-side buffer drops via `scap.n_drops_buffer_*` metrics. **Few teams alert on this metric.** Silent drops are a known coverage gap. Budget for this in noisy workloads — either over-provision ring buffer size or rate-limit at the kernel side.

**Kubernetes deployment patterns.** The canonical model:
```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: falco
spec:
  template:
    spec:
      serviceAccountName: falco
      hostPID: true
      hostNetwork: true
      containers:
        - name: falco
          image: falcosecurity/falco-no-driver:latest
          securityContext:
            privileged: true
          volumeMounts:
            - {name: dev, mountPath: /host/dev}
            - {name: proc, mountPath: /host/proc, readOnly: true}
            - {name: boot, mountPath: /host/boot, readOnly: true}
            - {name: lib-modules, mountPath: /host/lib/modules, readOnly: true}
            - {name: usr, mountPath: /host/usr, readOnly: true}
            - {name: etc, mountPath: /host/etc, readOnly: true}
```

DaemonSet per-node with privileged container + hostPID + hostNetwork. The privileged-container requirement is the structural security trade-off: the runtime-detection probe runs with full host privileges; compromise of the probe is full-node compromise. Cross-link [[reference-container-runtime-escape]] §11 for the hardening implications.

**Multi-cloud reality.** GKE / EKS / AKS each have slightly different default kernels and BTF availability:
- **GKE COS (Container-Optimized OS)** — modern kernel + BTF available; eBPF works out of box.
- **EKS Amazon Linux 2** — kernel 5.10 LTS in modern AMIs; BTF requires recent versions; test per AMI.
- **EKS Amazon Linux 2023** — modern kernel + BTF.
- **AKS Ubuntu / AzureLinux** — modern kernel + BTF.
- **OpenShift** — RHEL-based; BTF available on recent versions; older OpenShift clusters may require fall-back to kernel module driver.
- **Bottlerocket** — purpose-built for containers; eBPF-friendly.

Test per platform. Don't assume a probe binary that works on GKE works on EKS.

**Helm chart maturity.** All three projects ship Helm charts. Production deployment via Helm + ArgoCD/Flux is the canonical path.

---

## 10. AI workload / agent telemetry — the 2024-2026 expansion

**Why runtime detection matters for AI agents.** An AI agent (Claude Code subprocess, Cursor agent loop, a Devin VM, an MCP server) running on a node is just a process. Its outbound network connections, file writes, subprocess invocations are detectable at the syscall layer. The AI-tool's behavioral surface is observable via runtime detection without LLM provider cooperation. Cross-link [[reference-ai-incident-response-playbook]] §4 (forensic-surface collection order: runtime-detection logs sit alongside agent session JSONL + OTel GenAI spans + MCP tool-call logs as DFIR substrate) and [[reference-ai-assisted-coding-tool-security]] §11 (detection patterns for AI-IDE compromise).

**Clinejection-class detection.** When an AI coding agent writes to credential paths (`.aws/credentials`, `.npmrc`, `.netrc`, `.ssh/config`) or makes outbound connections to non-allowlisted endpoints, runtime detection catches it at the syscall layer. Example Falco rule shape:

```yaml
- rule: AI Coding Agent Writes to Credential Path
  condition: >
    container and proc.name in (ai_coding_agents)
    and (open_write or rename or unlink)
    and (fd.name startswith /root/.aws/
         or fd.name startswith /root/.ssh/
         or fd.name endswith /.npmrc
         or fd.name endswith /.netrc)
  output: >
    AI agent wrote to credential file
    (agent=%proc.name file=%fd.name container=%container.image.repository)
  priority: WARNING
  tags: [ai_agent, credentials, mitre_credential_access]
```

The hard part is enumerating `ai_coding_agents` as a list and keeping it current. Each AI tool's process name changes per upgrade. Production deployments maintain this as configuration alongside the rule.

**MCP-server-as-workload.** MCP (Model Context Protocol) servers run as processes — Node, Python, or compiled. Their tool-call patterns are observable via runtime detection. Patterns to detect:
- MCP server spawns subprocess (most MCP servers shouldn't fork)
- MCP server writes outside expected scratch directory
- MCP server makes outbound connection to non-allowlisted endpoint
- MCP server reads credentials it didn't read at startup

Cross-link [[reference-llm-agent-security]] for the broader MCP-attack-surface taxonomy + [[reference-ai-orchestration-harnessing]] §5 harness design (tool allowlist + audit logging as harness concerns runtime detection complements).

**OTel GenAI semantic conventions complement runtime detection.** OpenTelemetry's GenAI semantic conventions (`gen_ai.provider.name`, `gen_ai.operation.name`, `gen_ai.usage.input_tokens`) capture what the LLM thought it was doing. Runtime detection captures what actually happened on the kernel side. Both layers required:
- GenAI spans alone: "the LLM was asked to write to /tmp/output.txt" — but did it actually?
- Runtime detection alone: "process wrote to /etc/shadow" — but why?
- Both together: "the LLM thought it was writing to /tmp/output.txt but the file write was actually to /etc/shadow → prompt injection or tool-call hijack."

**AI-workload-detection rule corpus is emerging.** Falco community, Sysdig commercial, Aqua, and Isovalent are all contributing rules tagged for AI-tool-as-attack-target patterns. The corpus is immature relative to container-escape rules — expect rapid evolution 2025-2026.

---

## 11. Detection-engineering discipline applied to eBPF

The lifecycle of an eBPF-runtime-detection rule is identical to any detection rule (cross-link [[reference-detection-engineering]] §6 for the broader discipline):

1. **Draft.** Author the rule. Define condition, output, priority, tags. Reference a primary source (CVE, attack paper, incident postmortem).
2. **Corpus-test.** Run against historical events. Compute true-positive vs false-positive rate against a representative event corpus.
3. **Tune to <5% FP rate.** Add macros to narrow scope. Add lists for known-benign processes/paths. Iterate.
4. **Ship.** Deploy via GitOps (Helm chart values, custom rule ConfigMaps).
5. **Monitor FP rate in production.** Alert volume is the primary metric. If FP rate climbs above threshold, escalate.
6. **Tune.** Continuous iteration as workloads change.

**Replay testing.** Capture events to file, replay against rule set, compute TP/FP. Falco supports this via `falco -o engine.kind=replay -o engine.replay.capture_file=captured.scap` — feed a previously-captured event stream against the current ruleset. The capture-replay loop is essential for rule tuning without disrupting production.

**Coverage gaps.** Runtime detection sees process / network / file / kernel events. It does NOT see:
- **In-process memory corruption.** An exploit that achieves RCE without spawning a new process or making a syscall is invisible to runtime detection until the exploit DOES make a syscall. Most real exploits eventually call execve or open — but the pre-syscall corruption window is dark.
- **Encrypted application traffic.** TLS unless decrypted at endpoint (uprobes on `SSL_write` are the workaround; expensive).
- **Application-level logic flaws.** A SQL injection that exfiltrates data via a legitimate query path doesn't trip any kernel-layer detection.
- **Side-channel attacks.** Spectre/Meltdown-class — cross-link [[reference-hardware-side-channels]].

**Cross-link [[reference-detection-engineering]] for the broader detection-as-code discipline** (CI for rule changes, peer review, rule versioning, deprecation process).

---

## 12. Honest failure modes — load-bearing

The defender-pessimist view.

**eBPF detection sees what crosses the syscall boundary, nothing else.** A wholly in-memory exploit producing no syscalls is invisible. Process injection via `ptrace` is detected; in-process gadget execution before any syscall is not. The fundamental coverage limit.

**Ring buffer drops under load are easy to miss.** Bursty workloads lose events. Falco's shipped `falco.yaml` sets `syscall_event_drops` actions to `log` and `alert`, and the `n_drops` metric exists, but few teams alert on it. Build the alert. Budget for over-provisioning the ring buffer size in noisy clusters.

**"Noise" is the operational pushback most teams cite.** Default Falco corpus generates alerts at a rate operators describe as unmanageable. Tuning is expensive — per-environment baseline gathering, allowlist construction, rule disable/enable cycle. Teams that don't invest in tuning disable rules wholesale, creating a coverage gap.

**Privileged container requirement is a structural security trade-off.** The runtime-detection probe runs with hostPID + hostNetwork + capabilities (`CAP_SYS_ADMIN`, `CAP_BPF` kernel ≥ 5.8). Compromise of the probe is full-node compromise. Cross-link [[reference-container-runtime-escape]] §11 hardening. Defense-in-depth: minimize the privileged surface area, audit the probe binary supply chain, signing-verify the image.

**eBPF verifier escape CVEs erode the substrate.** Cross-link [[reference-linux-kernel-exploitation]] §6 for the CVE-2022-23222 lineage (tr3e) + CVE-2021-3490 (Manfred Paul, Pwn2Own Linux). Attackers running their own eBPF programs to evade detection (bpfdoor, Symbiote, Boopkit) is a known threat model — eBPF is dual-use. Defenders should restrict `CAP_BPF` to specific service accounts and audit `bpf(2)` syscall usage. Tetragon's own `bpf` LSM hook can mediate program loads.

**BTF availability is a deployment blocker on older kernels.** Pre-5.4 kernels often lack BTF; CO-RE doesn't work; runtime detection requires kernel-version threshold. Fleet uplift is the long-tail blocker; some regulated environments run RHEL 7 / kernel 3.10 indefinitely.

**Tetragon's synchronous-kill capability is operationally heavy.** Killing a process from kernel context can corrupt application state (mid-transaction database, partially-flushed buffer, in-flight network connection state). Use sparingly. Observability + out-of-band response (e.g., notify orchestrator to evict the pod) is the conservative default. Reserve in-kernel kill for narrow, high-confidence policies.

**Rule corpora rot.** When kernel ABIs change (rare for tracepoints, common for kprobes) OR new attack patterns emerge (Kubernetes API additions, new CRDs that introduce attack surface), rules need updating. Falco's default corpus needs periodic review; community-contributed rules vary in quality. Treat the corpus like dependencies — pin a version, review upgrades, test against your event corpus before adopting.

**Multi-tenant cluster considerations.** Per-tenant TracingPolicy isolation is non-trivial; one tenant's noisy policy can degrade detection for others by saturating the ring buffer. In a multi-tenant cluster (vendor SaaS, internal platform), TracingPolicies should be platform-team-owned with tenant input rather than tenant-self-service. Cross-link [[reference-zero-trust-workload-identity]] for the tenant-isolation framing.

**Vendor consolidation risk.** Falco (Sysdig); Tetragon (Isovalent) acquired by Cisco April 2024; Tracee (Aqua). Vendor strategy changes can disrupt OSS roadmap. CNCF status (Falco Graduated, Cilium Graduated) provides some governance protection — graduated projects can't be unilaterally pulled — but day-to-day maintenance bandwidth depends on vendor priorities. Diversify rule corpus across multiple tools where feasible.

**Detection-engineer staffing.** Running eBPF runtime detection well requires dedicated detection-engineering capacity. Tuning a rule from "fires 10k times/day" to "fires 5 times/day, all true positives" is days of work per rule. Most teams don't budget the headcount; the tool ships with default rules off → procurement happy, security capability missing.

**The "alert routes nowhere" failure.** Falcosidekick fans out to Slack / PagerDuty / S3 / Elasticsearch. Many production deployments route to Slack only → alerts sink in a channel nobody reads. Define on-call rotation + escalation policy for runtime-detection alerts on day one. Treat the alert routing as part of the deployment, not an afterthought. If alerts only land in S3 for forensic replay, document that explicitly — "we're collecting telemetry, not alerting" is a legitimate posture but should be a deliberate choice.

**Time-to-detect on stealthy attacks is high.** Runtime detection catches loud attacks (privileged container, shell spawn, sensitive file write). It catches stealthy attacks slowly or not at all (in-memory implants that avoid syscalls, low-and-slow exfil over allowed channels). Pair runtime detection with network-layer detection (egress monitoring) + control-plane detection (K8s audit log analysis via Falco's k8s_audit plugin) for layered coverage.

**Container image immutability assumption breaks.** Detection rules like "Container Drift" assume the image filesystem doesn't change at runtime. This assumption breaks for workloads that legitimately write to their own image filesystem (writable container layers, init-containers that patch binaries on startup, sidecar update mechanisms). Rule allowlists become permanent maintenance.

**eBPF program priority inversion.** When multiple eBPF programs attach to the same hook, the order of execution affects which observes/mediates first. In a stacked LSM (BPF-LSM + AppArmor + SELinux), the first to veto wins. Tetragon's policy-deny only sees the operation if SELinux didn't block it first. Multi-tool deployment requires architectural understanding of hook ordering.

---

## 13. 2024-2026 currency

**Falco CNCF Graduated 2024.** Graduated February 29, 2024. Graduation triggers vendor procurement availability in regulated environments.

**Cisco completed its acquisition of Isovalent April 12, 2024.** Tetragon roadmap continues under Cisco. Cilium remains CNCF Graduated independently.

**Sysdig status.** Falco governance is CNCF-protected; the Sysdig commercial product trajectory is vendor-dependent.

**Aqua status.** Tracee OSS remains active.

**eBPF for Windows.** Microsoft's port of eBPF to Windows kernel — the PREVAIL verifier runs in user mode and verified programs run in a kernel-mode execution context (uBPF JIT, or native drivers built via bpf2c). The project's GitHub releases (latest v1.7.0) are still marked pre-release. The strategic implication: runtime detection on Windows over the next 3-5 years may converge on eBPF rather than ETW callbacks + minifilter. Cross-link [[reference-windows-kernel-exploitation]] for the substrate context.

**BPF-LSM maturity 2024-2026.** Kernel 5.7+ widely deployed in production. BPF-LSM hook count growing (network mediation, signal mediation, capability checks). Tetragon and other BPF-LSM-based tooling can mediate more operations over time.

**AI-workload-detection rules.** Emerging community + vendor rule sets tagged for AI-tool-as-attack-target patterns. Falco community discussion of rules for prompt-injection-indirect-side-effects (file writes that match LLM-output patterns), MCP-server abuse signatures, agent-loop runaway detection. Maturity gap relative to container-escape rule corpus — expect rapid evolution.

**Kubernetes 1.36 promotes user-namespaces to stable (GA).** Reduces the privileged-container requirement for some workloads. Doesn't directly affect runtime-detection probes (probes still need privileges) but reduces the attack surface they protect.

**OpenSearch / Loki / Splunk integrations.** Falcosidekick + Tetragon log-export tooling now ships with first-class integrations for the major SIEM/log platforms. Detection-engineering can lean on commodity log search rather than custom alerting infrastructure.

**Confidential containers + runtime detection.** Confidential containers (Kata-CC, Confidential Containers project) move workload execution into TEEs. Runtime-detection probes outside the TEE can't see inside the TEE. This is a known coverage gap. Cross-link [[reference-confidential-computing]] §7 for the TEE/observability trade-off.

**Sigstore + signed rule corpora.** Falco rules are starting to ship signed via sigstore (`cosign verify` of rule bundles). Falcoctl tooling supports OCI artifacts for rule distribution. The supply chain on detection rules themselves matters — a tampered rule that disables critical detections is the inside-the-defender attack. Cross-link [[reference-supply-chain-provenance]] for the SLSA + sigstore discipline.

**Performance-isolation work.** 2024-2026 kernel work on per-cgroup BPF program scheduling + ring buffer per-cgroup partitioning aims to address multi-tenant noisy-neighbor problems. Status `[unverified specific kernel version]`; production deployments still treat noisy-neighbor as a tuning problem.

**Detection-as-code tooling maturity.** Falco rule unit testing (rule replay against captured events), CI integration (rule-changes-trigger-replay-suite) — the tooling stack for rules-as-code parity with application-code-CI is filling in. Treat the rule corpus like a software project with versioning, peer review, and regression tests.

---

## 14. Cross-link cluster

- [[reference-detection-engineering]] — broader detection-as-code discipline (Sigma/YARA/EDR/ATT&CK/D3FEND); this doc specializes the eBPF-runtime-detection tier
- [[reference-container-runtime-escape]] — the bugs being detected; §11 hardening references Falco/Tetragon as the catch-attempt-in-progress layer
- [[reference-linux-kernel-exploitation]] — eBPF as kernel attack surface (verifier escapes, BPF-as-rootkit); the dual-use dimension
- [[reference-dfir-methodology]] — runtime-detection logs as DFIR substrate; §4 forensic-surface collection order on Linux/K8s
- [[reference-ai-incident-response-playbook]] — AI-tool-compromise IR; runtime-detection logs alongside agent session JSONL + OTel GenAI spans
- [[reference-ai-assisted-coding-tool-security]] — AI-IDE compromise threat model; runtime detection as observability layer
- [[reference-ai-orchestration-harnessing]] §5 — harness design for AI agents; runtime detection complements harness audit logging
- [[reference-llm-agent-security]] — MCP attack surface; runtime detection catches MCP-server abuse
- [[reference-service-mesh-security]] — Cilium ecosystem context for Tetragon
- [[reference-zero-trust-workload-identity]] — tenant isolation framing for multi-tenant TracingPolicies
- [[reference-cicd-supply-chain]] — supply chain on the detection-probe image itself
- [[reference-container-k8s-security]] — broader K8s security context; DaemonSet + RBAC patterns
- [[reference-windows-kernel-exploitation]] — eBPF-for-Windows substrate
- [[reference-confidential-computing]] — TEE + runtime-detection coverage gap
- [[reference-hardware-side-channels]] — side-channel coverage limit for syscall-layer detection
- [[reference-threat-modeling-discipline]] — where runtime detection fits in defense-in-depth

---

## 15. Primary sources — verified researchers + practitioners

**eBPF substrate originators:**
- **Steven McCanne + Van Jacobson** (LBNL) — Berkeley Packet Filter 1992; foundational paper "The BSD Packet Filter: A New Architecture for User-level Packet Capture" USENIX Winter 1993.
- **Alexei Starovoitov** (Meta, kernel eBPF maintainer) — extended BPF (eBPF) kernel work since 2014; primary kernel-side architect.
- **Daniel Borkmann** (Isovalent/Cisco, kernel eBPF maintainer) — eBPF kernel work + Cilium co-founder.
- **Andrii Nakryiko** (Meta) — libbpf, CO-RE, BTF; the substrate that makes fleet deployment economic.
- **KP Singh** (Google) — primary BPF-LSM kernel-side contributor; the substrate enabling Tetragon's synchronous enforcement.
- **John Fastabend** (Isovalent/Cisco) — Cilium + eBPF kernel work.
- **Brendan Gregg** (OpenAI, prev Intel and Netflix) — eBPF performance + observability; BPF Performance Tools book; bpftrace + biosnoop + execsnoop tooling that detection engines build on.

**Tool authors + maintainers:**
- **Loris Degioanni** (Sysdig founder, WinPcap co-creator) — Falco original author + ongoing project sponsor.
- **Mark Stemm** `[unverified specific role title]` (Sysdig) — Falco maintainer + rule corpus.
- **Anna Kapuścińska** (Isovalent/Cisco) — Tetragon + Cilium.
- **Mahé Tardy** (Isovalent/Cisco) — Tetragon maintainer.
- **Thomas Graf** (Isovalent founder, Cisco) — Cilium project lead.

**eBPF verifier-escape research (the dual-use dimension):**
- **Manfred Paul** (independent) — CVE-2021-3490 eBPF verifier 32-bit ALU bounds bug, Pwn2Own 2021 Linux winner.

**Practitioner community:**
- **CNCF TAG-Security** — runtime detection guidance + CNCF Security WG.
- **eBPF Foundation** (governance body, Daniel Borkmann + others on the BPF Steering Committee) — substrate stewardship.

Anchor for future revisions: when extending this doc, ground new claims to primary-source papers (USENIX Security, NDSS, S&P, BlackHat/DEF CON) or vendor engineering blogs (Sysdig, Isovalent, Aqua, Tigera, Datadog Security Labs, Google Project Zero) rather than reuse of secondary sources.

---

## 16. Operational playbook — 12-item checklist for shipping eBPF runtime detection

For a staff-security / detection-engineer / SRE bootstrapping eBPF runtime detection on a production cluster. Sequence matters; don't skip steps.

1. **Inventory kernel versions across the fleet.** `uname -r` across nodes. Confirm BTF availability (`ls /sys/kernel/btf/vmlinux`). Identify nodes pre-5.4 — those are the blocker. Plan kernel-uplift or fall back to kernel-module driver for those nodes.

2. **Pick the tool based on architecture, not feature comparison.** Cilium-everything cluster → Tetragon. Multi-cluster with heterogeneous CNI → Falco (CNI-agnostic). Aqua CNAPP customer → Tracee for integration with rest of Aqua. Don't pick on a feature-comparison spreadsheet; pick on architectural fit.

3. **Deploy in observability-only mode first.** No enforcement. Capture event volume, ring-buffer drop rate, alert volume baseline. Two-week soak before any rule tuning.

4. **Establish alert routing on day one.** Falcosidekick → PagerDuty for CRITICAL, → Slack for WARNING, → S3 for forensic retention. Define on-call rotation. Document the routing.

5. **Build the alert-volume metric dashboard.** Alerts/hour by rule, by namespace, by priority. Ring-buffer drop rate. CPU/RAM overhead per node. Alert on metric anomalies, not just rule firings.

6. **Pick a starter rule corpus and prune.** The full Falco rules set (stable + incubating + sandbox) runs to dozens of rules — too many to tune simultaneously. Pick 10-20 highest-priority rules (container escape, credential file access, cryptominer execution, reverse shell, sensitive data exfil). Disable the rest until ready.

7. **Tune each rule to <5% FP rate before adding the next.** Allowlist legitimate process names/paths via macros + lists. Iterate. Document why each allowlist entry exists.

8. **Replay-test rule changes in CI.** Capture an event corpus from a representative production node (4-hour capture, replayed with `falco -o engine.kind=replay -o engine.replay.capture_file=dump.scap`). Run rule changes against the corpus as a CI step. Compute TP/FP delta before merging rule changes.

9. **Build the runbook per alert.** Every rule that fires should have a runbook: what to check, who to escalate to, criteria for incident declaration. No runbook → no rule.

10. **Add AI-workload rules deliberately.** Enumerate the AI tools running on the cluster (Claude Code, MCP servers, agent VMs). Add rules tagged for credential-path writes + non-allowlisted outbound + subprocess spawning. Cross-link [[reference-ai-incident-response-playbook]] §3 for the containment-lever inventory.

11. **Integrate with DFIR collection workflow.** Runtime-detection event archive (S3 or similar) is forensic substrate. When an incident occurs, the events from the affected node/pod/timeframe are the high-fidelity audit trail. Document the collection procedure in advance. Cross-link [[reference-dfir-methodology]].

12. **Quarterly rule corpus review.** Treat the rule corpus like dependencies. Pin a version. Review upstream changes quarterly. Test against your event corpus before adopting. Deprecate rules that haven't fired in 6 months OR fire constantly with no signal.

---

## 17. What's missing from this doc — next-shift candidates

Surfaced as work for future revisions.

- **Per-syscall hook performance table.** Quantitative overhead numbers per program type (kprobe vs tracepoint vs fentry vs LSM) across kernel versions. Brendan Gregg's BPF Performance Tools has numbers; needs synthesis here.
- **eBPF-for-Windows depth.** Microsoft's eBPF-for-Windows project + hook support + production GA status. Currently single-paragraph; warrants a dedicated subsection or sibling doc as Windows EDR converges on eBPF.
- **Comparison with commercial EDR on Linux.** CrowdStrike Falcon Linux sensor / SentinelOne / Sysdig Secure / Aqua / Datadog CWP — architecture comparison vs OSS Falco/Tetragon/Tracee. Useful for procurement context.
- **Worked rule-tuning example.** End-to-end: "default rule fires 10k/day → tuned to 3/day all TP" with the macro/list/condition changes shown step by step. Operational realism.
- **Hubble + Tetragon network observability integration.** Cilium's Hubble (network observability) + Tetragon (runtime detection) joint analysis — what cross-correlation can the combination produce that neither alone can.
- **Per-cloud BTF + kernel version compatibility matrix.** GKE COS / EKS AL2 / EKS AL2023 / AKS Ubuntu / AKS AzureLinux / OpenShift / Bottlerocket / SLES — kernel version, BTF availability, known eBPF issues. Maintenance burden; useful operational reference.
