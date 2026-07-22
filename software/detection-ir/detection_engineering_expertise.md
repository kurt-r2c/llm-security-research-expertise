# Detection Engineering — Rules, Telemetry, and the Dual to Static Analysis
## Synthesized from Florian Roth, Thomas Patzke, John Lambert, Roberto Rodriguez, Jared Atkinson, Andy Robbins, Olaf Hartong, Matt Graeber, Casey Smith, David Bianco, and Eric Hutchins

> **Researchers:**
> - **Florian Roth** — CTO and Head of Research at Nextron Systems; co-creator of the Sigma
>   rule format (with Thomas Patzke) and the THOR APT scanner; maintainer of large public YARA
>   corpora and the Valhalla rule feed; author of LOKI, yarGen, FENRIR, and a long line of
>   open-source detection tooling. His public work has shaped the de-facto signature-detection
>   conventions used across the open-source SIEM ecosystem.
> - **Thomas Patzke** — Co-creator and maintainer of Sigma alongside Florian Roth;
>   primary author of the pySigma library and sigma-cli; long-time SIEM and detection
>   engineer who first presented Sigma publicly at Hack.lu 2017. Owns much of the
>   conversion-pipeline machinery that turns vendor-neutral Sigma into native SIEM queries.
> - **John Lambert** — Corporate Vice President and Distinguished Engineer at Microsoft
>   Threat Intelligence Center (MSTIC); author of the canonical Defenders-Mindset essay
>   "Defenders think in lists. Attackers think in graphs. As long as this is true, attackers
>   win." His framing of network defense as graph problem rather than asset inventory has
>   become a load-bearing idea across the modern detection literature.
> - **Roberto Rodriguez** — Principal Threat Researcher at Microsoft Security Research;
>   founder of the Open Threat Research (OTR) community; author of the ThreatHunter-Playbook,
>   Mordor / Security-Datasets pre-recorded telemetry corpora, and the HELK lab. The
>   ThreatHunter-Playbook codified hypothesis-driven, ATT&CK-grouped Jupyter-notebook hunts
>   as a public methodology.
> - **Jared Atkinson** — Chief Technology Officer at SpecterOps; author of the Capability
>   Abstraction, Detection Spectrum, and On-Detection essay series; the structural-
>   abstraction-as-detection-design line of thinking is, alongside the Pyramid of Pain,
>   the most-cited methodology in detection engineering circles.
> - **Andy Robbins** — Principal Security Researcher at SpecterOps; co-creator of
>   BloodHound; author of the Attack Path Management Manifesto. The graph-theoretic
>   approach to identity attack surface mapping anchors much of the modern AD / Entra /
>   cloud-identity detection design.
> - **Olaf Hartong** — Defensive specialist at FalconForce; author of the sysmon-modular
>   project; long-running researcher on Microsoft Defender for Endpoint internals; runs
>   one of the most-used public Sysmon configs in production environments.
> - **Matt Graeber** — Researcher at Microsoft (formerly SpecterOps and Veris Group);
>   long-time PowerShell and Windows internals researcher; published the canonical
>   one-line AMSI bypass (`amsiInitFailed = $true`) in 2016 and the script-block-logging
>   evasion analyses that taught a generation of defenders how AMSI and Script Block
>   Logging actually work under the hood.
> - **Casey Smith** — Threat researcher who originated and led Atomic Red Team at Red
>   Canary; long-running offensive-research handle "subTee"; pioneered the per-technique
>   atomic-test idiom that turned ATT&CK technique IDs into executable detection-validation
>   probes.
> - **David Bianco** — Detection-and-response practitioner; author of the 2013 Enterprise
>   Detection & Response essay "The Pyramid of Pain" which named and ordered the
>   indicator-types (hash > IP > domain > artifact > tool > TTP) by cost-to-the-attacker.
>   The Pyramid remains the most-cited single artifact in detection-engineering pedagogy.
> - **Eric Hutchins** — Lockheed Martin Fellow and Chief Intelligence Analyst, LM-CIRT;
>   co-author with Michael Cloppert and Rohan Amin of the 2011 *Intelligence-Driven
>   Computer Network Defense Informed by Analysis of Adversary Campaigns and Intrusion
>   Kill Chains* paper that introduced the seven-stage Cyber Kill Chain.
>
> **Sources:** Sigma rule format and pySigma repositories (SigmaHQ); the ThreatHunter-Playbook
> and Security-Datasets repositories (OTRF); SpecterOps "Posts" Medium publication; FalconForce
> Medium; Florian Roth's Nextron Systems blog and `Neo23x0` GitHub corpus; David Bianco's
> *Enterprise Detection & Response* blog; Lockheed Martin's white-paper archive; MITRE ATT&CK
> and D3FEND; Red Canary's Atomic Red Team; OCSF specification; Falco and Tetragon
> documentation; canonical Sysmon configs (SwiftOnSecurity, ION-Storm, Olaf Hartong's
> sysmon-modular); CISA Joint Cybersecurity Advisories and the public corpus of attacker
> tradecraft documentation through May 2026.

---

## 1. The Detection-Engineering Discipline

### Detection engineering is the runtime sibling of static analysis

A static-analysis rule (see [Semgrep rule authoring](../static_analysis/semgrep_rule_authoring.md))
and a detection rule are the same shape of artifact. Both encode a hypothesis,
consume a signal, and produce alerts a human has to triage. The substrate is what
differs:

- **Static analysis** consumes source code at build/PR time. The signal is the
  syntax tree (or bytes for `pattern-regex`); the FP cost is engineer attention at
  merge; the rule's currency is precision against a reachability hypothesis.
- **Detection engineering** consumes runtime telemetry at incident-response time.
  The signal is process-creation events, network flows, identity sign-ins,
  control-plane operations; the FP cost is analyst attention in the SOC queue; the
  rule's currency is precision against a behavior-is-malicious hypothesis.

The structural moves are identical: sources (signal origin), sinks (dangerous
effect), patterns (syntactic or behavioral predicate), filters (FP allowlist), and
severity (prior on attacker leverage). The Semgrep author who has internalized
falsifiable-hypothesis discipline already has the mental model for detection
engineering. Where the two fork is the evidence: static analysis sees the universal
future and is blind to runtime context; detection engineering sees the particular
present in a sampled, lossy stream. The failure modes are dual — SAST over-fires on
dead code; detection under-fires on signal that never reached the collector.

The mature program runs both and closes the loop. A Semgrep finding for
`pickle.loads(user_input)` predicts a detection-engineering need to log
unsafe-deserialization-adjacent process behavior. A detection-engineering alert for
`powershell.exe -enc <base64>` predicts a static-analysis need to find the dropper.
Each side is a hypothesis generator for the other.

### The shift-left-vs-shift-right debate is a false dichotomy

Industry rhetoric pits "shift left" (preventive SAST, secure-by-default frameworks)
against "shift right" (detection engineering, observability, EDR). The framing is
wrong: the two cover non-overlapping failure modes.

- Static analysis catches bugs the developer wrote. It misses configuration bugs,
  bugs introduced after the merge gate, correct code abused by an attacker
  (process-injection via legitimate APIs), and bugs whose root cause is identity,
  network, or supply-chain.
- Detection engineering catches the attacker who is already in. It misses
  everything the telemetry didn't capture and fundamentally cannot prevent — only
  detect-and-respond.

Shift-left reduces the attacker's landing surface; shift-right detects the attacker
who landed anyway. Defense-in-depth is the admission that no preventive layer is
perfect. The two functions should report through the same security org, share
threat-intelligence inputs, and coordinate on what to instrument, rule on, and fix
at source. Imbalanced investment fails predictably: SAST-heavy shops with no SOC
are blind to post-exploitation; SIEM-heavy shops with no AppSec program watch the
same authentication bypass appear in three applications because no one fixed the
framework.

### The Pyramid of Pain: signature cost, attacker cost

David Bianco's 2013 Pyramid of Pain remains the most-cited artifact in
detection-engineering pedagogy. It captures the trade-off between rule-maintenance
cost and attacker-disruption cost across six indicator types, base to apex:

1. **Hash values.** Trivial for defender to capture; trivial for attacker to bypass
   by recompiling or repacking. A pure hash rule memorializes last week's incident.
2. **IP addresses.** Slightly more durable; the cost of swapping a C2 IP is hours.
3. **Domain names.** Registration costs money, leaves a paper trail, subject to
   registrar takedown. Real but bounded attacker cost.
4. **Network and host artifacts.** URL patterns, User-Agent strings, JA3/JA4 TLS
   fingerprints, mutex names, named-pipe layouts. Emergent properties of the
   attacker's tools; changing them requires modifying tooling or technique.
5. **Tools.** Cobalt Strike, Mimikatz, Sliver, BloodHound. Detecting the tool
   forces the attacker to switch or develop a new one — expensive in money and
   operational risk.
6. **Tactics, techniques, and procedures (TTPs).** The behavioral playbook for
   enumeration, escalation, persistence, lateral movement. TTP detection forces
   the attacker to change *how they operate*, not just *what they use*; often
   requires fundamental retraining.

Strategic implication: every hour at the apex buys disproportionately more durable
defense than the same hour at the base. A hash-feed rule depreciates in days; a
TTP rule depreciates in years. The corollary: invest in TTP detection first,
tool-level second, and treat IOC feeds as zero-touch background coverage. The
wrong shape is a SOC drowning in IOC hits while blind to the behavioral signal
that an attacker is pivoting through Kerberos delegation.

### The detection-engineering lifecycle

A detection's lifecycle is hypothesis → coverage check → write → test → deploy → tune → retire:

1. **Hypothesis.** "If attacker is doing X, the observable in our telemetry is Y."
   A falsifiable claim. A hypothesis without a named observable should not become
   a rule.
2. **Coverage check.** Do we collect Y, at what fidelity, with what retention? If
   not, the problem is upstream in instrumentation. Many rules get written against
   telemetry the org doesn't have and ship as silent zero-fire rules that survive
   years.
3. **Write.** Compose in the appropriate language (Sigma for portability, native
   for full power; §3). Encode known FP conditions in the filter, not in a comment.
4. **Test.** Replay against (a) a labeled positive corpus (Atomic Red Team, Mordor),
   and (b) recent production telemetry for noise. A rule that fires zero times on
   real telemetry usually means the coverage check was wrong.
5. **Deploy.** Through change control — PR-reviewed, syntax-validated,
   backtest-gated, with paging plan and severity.
6. **Tune.** Track FP rate weekly. If the rule exceeds the per-rule alert budget
   (5-15 alerts/analyst/shift), tighten filters, raise the threshold, or downgrade
   to informational.
7. **Retire.** When the threat retires (vulnerable version gone, TTP unused) or a
   superior rule supersedes. A corpus that only grows is rotting.

A team that runs the lifecycle is doing *engineering*. A team that writes rules
and never measures or retires is doing *content*. The discipline is the lifecycle,
not the YAML file.

---

## 2. Telemetry as the Precondition

### You cannot detect what you cannot see

The visibility doctrine is the single most-important precondition for detection
engineering and the most-commonly skipped step in immature programs. Before
authoring a rule, the engineer must answer two questions:

1. What telemetry source carries this signal (Sysmon process creation? CloudTrail
   control-plane? eBPF via Falco? Entra ID sign-in logs?)
2. Does our pipeline collect, retain, and surface it at the fidelity the rule
   requires?

A rule written against telemetry the organization does not actually capture is
worse than no rule — it gives the appearance of coverage while leaving the
visibility gap unaddressed. Coverage audits that map every rule to its required
telemetry source are the antidote. This is the runtime parallel to the SAST
coverage doctrine.

### Telemetry sources by layer

Each surface has its own fidelity, retention, latency, and bypass cost.

**Endpoint (per-host).** Highest fidelity; sees actual execution.

- **Windows Sysmon.** Process creation (1), network (3), image loads (7),
  CreateRemoteThread (8), raw access (9), process access (10), file create (11),
  registry (12-14), file-create-stream-hash (15), pipes (17-18), WMI subscriptions
  (19-21), DNS (22), file-delete (23), clipboard (24), process-tampering (25).
  Kernel-mode driver + user-mode service; XML-configured. Canonical starter configs:
  SwiftOnSecurity, ION-Storm, Olaf Hartong's sysmon-modular.
- **Windows ETW.** Underlying kernel mechanism for Sysmon, EDRs, in-box channels.
  Provider-based; tens of thousands of providers. Matt Graeber's research surfaced
  the AMSI / Script-Block-Logging / ETW interplay that drives modern PowerShell
  detection.
- **Linux `auditd`.** User-space daemon for kernel audit records; syscalls, file
  accesses, capability changes. Largely superseded by eBPF but still ubiquitous.
- **Linux eBPF** (BCC, Falco, Tetragon, Cilium). Modern in-kernel instrumentation;
  syscalls, network, file, kprobes/uprobes at low overhead. Substrate of modern
  Linux EDR.
- **macOS EndpointSecurity.** Replaced KAuth+kext in Catalina (10.15+); sanctioned
  API for process, file, signing, IPC; authentication and notification event classes.

**Process primitives** (cross-OS): process creation (parent-child, command line,
image hash, user, integrity level, signing posture); file ops (create/modify/
delete/rename + bytes written); registry/keychain; IPC channels (named pipes, Unix
sockets, mach ports); image loads (DLL/dylib/.so).

**Network.** Independent of any single host.

- NetFlow / sFlow / IPFIX: flow-level metadata; coarse but ubiquitous.
- DNS query logs: high-value because virtually every modern attack does DNS.
- TLS handshake metadata: JA3/JA4/JA4S fingerprints survive encryption (handshake
  is cleartext). Detects malware using non-browser TLS libraries.
- HTTP/HTTPS proxy logs: URL, headers, response codes.
- IDS/IPS: Snort, Suricata, Zeek. Zeek emits structured per-protocol event logs.

**Cloud.** The primary surface for SaaS-heavy organizations.

- AWS: CloudTrail (control plane), VPC Flow Logs (data plane), GuardDuty Runtime
  Monitoring (eBPF inside EC2/ECS/EKS).
- Azure: Activity Log (subscription control plane), Entra ID sign-in/audit logs,
  M365 Audit Log.
- GCP: Cloud Audit Logs (admin activity, data access, system events), VPC Flow Logs.
- Service-specific: S3 access logs, ALB/CloudFront, Lambda CloudWatch, EKS audit,
  Cognito user-pool events.

The cloud-detection asymmetry: control-plane events (who created/changed what) are
universally captured at high fidelity; data-plane events (who read what S3 object)
require per-service opt-in. Most cloud breaches happen via control-plane identity
misuse; visibility matches the threat model.

**Application.** Structured app logs (JSON); OpenTelemetry traces and metrics;
audit events from auth/authz layers (cross-link to `distributed_authz_expertise.md`
§6); database query logs.

**Identity.** Increasingly the primary perimeter; the place the attack story often
begins (compromised credentials, MFA fatigue, OAuth abuse).

- Entra ID sign-in (interactive + non-interactive), audit logs, risky-user/sign-in
  scores.
- Okta System Log: authentication, MFA, lifecycle events.
- Active Directory DC Security log: Kerberos events (4768/4769/4771), logon events
  (4624/4625), object access (4662). Cross-link to
  `active_directory_windows_security.md`.
- SCIM events: account provisioning/de-provisioning across SaaS apps.

### Anti-pattern: "log everything, query later"

The common failure mode: enable verbose logging everywhere, ship it all to a SIEM,
assume future analysts will write the right queries. This fails twice:

1. **Cost.** Storage grows linearly with volume; hot-query cost grows super-linearly
   with cardinality. An org shipping every Windows Event ID, every DNS query, every
   CloudTrail event buys storage the SOC never queries.
2. **Signal dilution.** Verbose untuned logs worsen signal-to-noise. The analyst
   scrolling 10M benign process-creation events misses the alert.

The right shape is *targeted telemetry*: collect what your detection portfolio
consumes; at the fidelity the most-demanding rule requires; with retention
matching IR timelines (typically 90 days hot, 365+ cold). New telemetry sources
require explicit cost-justification tied to a specific rule.

Olaf Hartong's "what is Sysmon configured to actually capture?" exercise is the
artifact that grounds this. Without it, telemetry decisions get made by inertia,
vendor defaults, and budget cycles.

### Cost-of-storage vs cost-of-missing-signal

For each source the engineer asks: what's the cost of collecting it (storage,
ingestion, agent CPU, bandwidth), and what's the cost of missing it (which attack
does the absence blind us to)? Without DNS query logs, no DNS-tunnel detection.
Without IMDSv1 hits, no SSRF-to-credential-theft detection. The right answer is
rarely "everything" or "nothing" — it's a priority-ordered list driven by threat
model. The pattern that fails: platform team turns off detailed DNS query logging
"to save money," and the SOC learns about it months later via external incident
notification.

---

## 3. Rule Languages — The Modern Corpus

The detection-engineering toolbox is fragmented by vendor lock-in. The pragmatic
engineer reads and writes several of these.

### Sigma — vendor-neutral detection

**Sigma** (Roth and Patzke, 2017) is the closest the industry has to a portable
detection format. It is YAML-shaped, encodes a log-event detection in vendor-neutral
terms, and compiles via pySigma backends to native queries for the consuming SIEM.

A minimal Sigma rule:

```yaml
title: Suspicious Encoded PowerShell
id: <uuid>
status: stable
description: Detects encoded PowerShell commands which are often used by attackers
references:
  - https://attack.mitre.org/techniques/T1027/
author: Florian Roth (and others)
date: 2018/12/03
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith:
      - '\powershell.exe'
      - '\pwsh.exe'
    CommandLine|contains:
      - ' -enc '
      - ' -EncodedCommand '
  condition: selection
falsepositives:
  - Penetration tests
  - Legitimate scripts that use encoded commands
level: high
tags:
  - attack.execution
  - attack.t1059.001
  - attack.defense_evasion
  - attack.t1027
```

The format encodes a source (`logsource.category`), selector clauses, a condition,
known FPs, severity, and ATT&CK tags. pySigma backends compile to Splunk SPL,
Elastic EQL/KQL, Sentinel KQL, CrowdStrike CQL, and Elastic Detection Engine rules.

Use Sigma when the detection is expressible in straightforward log-event-field
terms and you want portability across SIEMs or want the rule to live in a public
corpus. Sigma falls short for multi-event correlation, stateful session
reconstruction, or sub-query joins — its correlation extension is young and not
universally backend-supported. For complex behaviors, native-query is cleaner.

### YARA — binary pattern matching

**YARA** (Victor Alvarez, VirusTotal, 2013) is the canonical malware-file
pattern-match language. Strings (literal, regex, hex with wildcards) plus a
boolean condition. Used for malware classification, threat-hunting on file repos,
and increasingly for in-memory scanning by EDR.

```
rule SuspiciousCobaltStrikeBeacon {
    strings:
        $a1 = "%s as %s\\%s: %d" wide
        $a2 = "beacon.x64.dll" ascii
        $opcodes_x64 = { 4D 5A 41 52 E8 00 00 00 00 5B 48 ?? ?? ?? }
    condition:
        uint16(0) == 0x5a4d and ($opcodes_x64 or 2 of ($a*))
}
```

YARA scales to massive corpora; VirusTotal uses it to organize its sample database,
and Florian Roth's THOR uses it for live host scanning. **YARA-X** (2024+) is the
Rust rewrite; adoption is gradual. Write YARA when the target is a file or a
memory region.

### Network IDS: Snort and Suricata

**Snort** (Roesch, 1998) and the modern multi-threaded **Suricata** are the
canonical network-IDS rule formats. Suricata adds application-layer parsing
(TLS/SSL/SSH/HTTP) and multi-event correlation.

```
alert dns $HOME_NET any -> any any (
    msg:"DNS query for sinkholed C2 domain";
    dns.query; content:"badactor.example"; nocase;
    classtype:trojan-activity; sid:1000001;)
```

Network IDS rules live on the wire (inline or out-of-band). Load-bearing in
environments with structured perimeter defense and increasingly for east-west
detection.

### Elastic EQL / KQL / ESQL

The Elastic Stack offers three query languages: KQL (user-facing search), EQL
(sequence-and-correlation for ATT&CK-style behaviors with `sequence by`, `until`,
`with maxspan`), and ESQL (newer SQL-like piped language).

```
sequence with maxspan=10s
  [process where event.action == "process_started" and process.name == "powershell.exe"]
  [network where event.action == "connection_attempted" and destination.port == 443]
```

### Splunk SPL

Splunk's pipe-separated query language; first-class in Splunk ES and Splunk
Security Content. Powerful (statistical operators, lookups, time-series), with
vendor lock-in as cost.

```
index=windows EventCode=4688 process_name="powershell.exe" CommandLine="*-EncodedCommand*"
| stats count by host, user, CommandLine
```

### Microsoft KQL (Kusto)

The query language of Azure Data Explorer, Sentinel, Defender XDR, Log Analytics.
Pipe-based, SQL-adjacent, with a larger practical operator set. Dominant in
Microsoft-heavy environments; format of the public Sentinel Detection content
library.

```
SecurityEvent
| where TimeGenerated > ago(1h) and EventID == 4624 and LogonType == 10
| join kind=inner (SigninLogs | where ResultType != 0)
    on $left.Account == $right.UserPrincipalName
```

### Vendor-native (CrowdStrike CQL, SentinelOne Storyline)

Each major EDR ships its own query language. The mature team writes in Sigma where
portable, native where primitives require it. The "write Sigma, deploy everywhere"
doctrine is real but has limits — entity-graph queries (CrowdStrike NGSIEM) and
behavioral contexts (SentinelOne Storyline) are not Sigma-expressible. Some rules
exist in two languages.

### OCSF — vendor-neutral schema

OCSF (Splunk + AWS, 2022; now Linux Foundation) is not a query language but a
**vendor-neutral event schema**. Every event — login, process-creation, file-modify,
network-flow — gets a canonical schema. A detection written against the schema is
portable to any vendor whose pipeline normalizes to OCSF. Adoption is uneven as of
2026 but the direction is clear: vendor-neutral schema + vendor-neutral rule format
moves detection-as-code out of vendor lock-in.

---

## 4. EDR Architecture — What the Agents Actually Do

The detection engineer writing rules against EDR telemetry should understand what
the EDR is doing at the kernel level — attackers attack the collection plane, and
the engineer who knows the seams writes rules to catch the attack.

### Windows: kernel callbacks, ETW, and Sysmon

The Windows kernel exposes **notification routines** that drivers register against:

- `PsSetCreateProcessNotifyRoutineEx` — process create/exit; vetoable via
  `STATUS_ACCESS_DENIED`.
- `PsSetCreateThreadNotifyRoutine` — thread create/exit, including remote-thread
  creation (substrate of CreateRemoteThread injection).
- `PsSetLoadImageNotifyRoutine` — image load (EXE and DLL).
- `CmRegisterCallbackEx` — registry operations; pre/post interposition.
- `FltRegisterFilter` — file-system mini-filter callbacks; can veto.
- `ObRegisterCallbacks` — handle-open callbacks (process/thread handles gate
  LSASS-handle theft).

**Event Tracing for Windows (ETW)** is the parallel kernel + user-mode pub-sub
framework. Hundreds of in-box providers (Microsoft-Windows-Kernel-Process, -DNS-
Client, -PowerShell, -Antimalware-AMSI, -WMI-Activity) emit structured events for
agent consumption.

**Sysmon** (Russinovich, Garnier, Sysinternals) is the public unprivileged
supplement: signed driver + service, XML-configured, emitting to a Windows Event
Log channel. Not an EDR (no blocking, no cloud telemetry), but same signal quality;
foundation of many small-org and open-source programs.

### AMSI hooks — the script-engine inspection interface

**AMSI** (Antimalware Scan Interface; Windows 10+) is the kernel-and-user-mode
interface through which script engines (PowerShell, JScript, VBScript, Office VBA,
Excel 4.0 macros, .NET's `Assembly.Load`) submit their buffer-about-to-be-executed
to a registered AV/EDR for inspection. The script engine calls `AmsiScanBuffer`;
the registered provider responds clean/dirty.

Matt Graeber's 2016 one-line AMSI bypass — flipping the private static
`amsiInitFailed` field on `System.Management.Automation.AmsiUtils` via reflection —
works because the PowerShell runtime checks that field before calling
`AmsiScanBuffer`. From the EDR's view, AMSI is "working"; from PowerShell's view,
calls are no-ops.

Detection implications: trust `Microsoft-Antimalware-AMSI` ETW events but also
collect PowerShell Operational and Script-Block-Logging events (which survive some
bypasses); rule on the *bypass attempt* (in-memory patching of
`amsi.dll!AmsiScanBuffer`, reflection access to `AmsiUtils`, suspicious
`Set-ItemProperty` on AMSI registration keys), not the post-bypass behavior —
once AMSI is bypassed, script-content visibility is gone.

### Linux: eBPF as the modern instrumentation layer

Modern Linux EDR has consolidated on **eBPF** (extended Berkeley Packet Filter):
verifier-checked programs loaded into kernel space, attached to kprobes,
tracepoints, syscalls, or network hooks, output streaming to user-space via ring
buffers. Falco (CNCF) uses eBPF for rule-based runtime detection with Kubernetes
enrichment; Tetragon (Cilium) layers in-kernel enforcement on top of observation;
Cilium itself uses eBPF for the network data-plane and surfaces pod-to-pod flow
visibility that NetFlow cannot see. eBPF is the substrate that unifies
cloud-native detection engineering.

See [[falco_tetragon_runtime_detection]] for the deep-dive on Falco vs Tetragon
vs Tracee — including the **policy-vs-observability axis** (Tetragon's BPF-LSM
can synchronously KILL from kernel context; Falco's tracepoint/kprobe stream is
asynchronous observation) and the structural ceiling that eBPF-based detection
sees only what crosses the syscall boundary.

### macOS: EndpointSecurity framework

Apple deprecated `kext` and KAuth in Catalina (10.15, 2019). The replacement —
**EndpointSecurity (ES)** — is a user-mode API for authentication (synchronous,
vetoable) and notification (asynchronous) events on process, file, signing, IPC,
and login subjects. macOS EDR collection is now user-mode + sanctioned-API-based,
less likely to crash the system but also harder to hide from sophisticated
adversaries.

### The EDR-bypass cat-and-mouse

Bypass primitives the detection engineer should know:

- **Direct syscalls** (inline `syscall` with SSN in RAX) bypass user-mode NTDLL
  hooks on functions like `NtAllocateVirtualMemory`, `NtCreateThreadEx`.
- **Indirect syscalls** (SysWhispers, Hell's Gate, Halo's Gate) call the syscall
  inside NTDLL itself, defeating hook detection that looks for syscalls outside
  known NTDLL ranges.
- **Unhooking** — refresh NTDLL from disk in-memory to overwrite EDR hooks. The
  EDR's user-mode visibility goes blind; detection requires kernel-side callbacks
  or ETW.
- **BYOVD** (Bring Your Own Vulnerable Driver) — load a signed-but-vulnerable
  driver (RTCore64, GMER, AppCheck) and use its kernel primitives to disable EDR
  callbacks. Microsoft's HVCI / MDAC vulnerable-driver blocklist addresses this;
  the detection angle is "vulnerable signed driver loaded" as a rule.
- **Custom unhooked loaders** that avoid known patterns (no `0x4D5A` reflective
  headers; encrypted shellcode in `MEM_PRIVATE` regions).

The response: write rules higher on the Pyramid of Pain. A rule for "any thread
starts at an address not backed by a known module" (via ETW's
`Microsoft-Windows-Threat-Intelligence` provider) catches reflective loaders
regardless of evasion. Behavior-level rules win.

### Vendor inventory (2026)

| Vendor | Product | Substrate |
|---|---|---|
| CrowdStrike | Falcon | Kernel driver + ETW; NGSIEM-integrated |
| SentinelOne | Singularity | Kernel agent; Storyline behavioral graph |
| Microsoft | Defender for Endpoint | In-box; deep ETW + kernel integration |
| VMware (Broadcom) | Carbon Black | Kernel driver; Cloud Workload Protection |
| ESET | PROTECT / Inspect | Kernel driver |
| Sophos | Intercept X | Kernel + behavioral / deep-learning |
| Elastic | Elastic Security | eBPF (Linux) + kernel-driver (Windows); open-source |
| Wazuh / OSSEC | Open-source HIDS | Log-based; lighter than full EDR |
| Falco (CNCF) | Open-source runtime sec | eBPF; container-native |

The engineer is vendor-specific in deployment, vendor-aware in design.

### What is your collection plane configured to capture?

Olaf Hartong's hard question — *"what is Sysmon actually capturing?"* — applies to
every collection plane. Canonical Sysmon starter configs: **SwiftOnSecurity**
(conservative, signal-to-noise focus), **ION-Storm** (SwiftOnSecurity fork with
threat-intel-heavy rules), **Olaf Hartong sysmon-modular** (modular generation,
authoritative ATT&CK-mapped). Fork one, tune it, and *read* it. A rule firing only
on Sysmon EventID 7 is useless on a fleet that disabled EventID 7.

---

## 5. Detection-as-Code

### Treat detections like software

A detection program climbs the same maturity ramp as any engineering function:
version control, peer review, automated testing, CI/CD, observability. The state
of practice across SigmaHQ, Splunk Security Content, Elastic Detection Rules,
Microsoft Sentinel Content, and FalconForce Detection has converged on:

1. **Source of truth in Git.** YAML / JSON / vendor DSL files; PR-reviewed.
2. **Format validation in CI.** `sigma-cli check`; vendor-native validators.
3. **Compile / convert in CI.** pySigma backends on every PR; surface
   conversion failures.
4. **Test in CI.** Replay against labeled-positive corpus (Mordor /
   Security-Datasets, Atomic Red Team logs) AND a recent slice of production
   telemetry for FP backtesting.
5. **Deploy in CD.** Through vendor content API or IaC (Terraform for Sentinel,
   Splunk's content API).
6. **Observe in production.** Per-rule fire rate, MTTR, FP rate, analyst
   feedback; dashboards back to the DE team.

### Public corpora to learn from

- **SigmaHQ/sigma** — the canonical public Sigma corpus, ATT&CK-tagged.
- **detection.fyi** — SigmaHQ indexed and searchable.
- **Splunk Security Content**, **Elastic Detection Rules**, **Microsoft Sentinel
  Content** — vendor-published, ATT&CK-tagged.
- **Florian Roth Signature-Base** — public YARA corpus.
- **Roberto Rodriguez ThreatHunter-Playbook** — hypothesis-driven hunt notebooks.

### Atomic Red Team — adversary simulation as test fixture

**Atomic Red Team** (Casey Smith, Michael Haag, Red Canary) is the canonical
library of small, technique-mapped test cases ("atomics"). Each ATT&CK technique
has one or more atomic tests — short PowerShell or shell scripts that perform
the technique benignly and repeatably. Running the atomic generates telemetry;
the question is "did our rule fire?"

```yaml
- name: Encode in PowerShell with -EncodedCommand
  supported_platforms: [windows]
  executor:
    command: powershell.exe -encodedcommand "RwBlAHQALQBQAHIAbwBjAGUAcwBzAA=="
    name: powershell
```

Atomic Red Team + CALDERA + Stratus Red Team (cloud) + Infection Monkey (lateral
movement) + Vectr (purple-team tracking) form the modern detection-validation
stack. The loop: simulate → check telemetry → check rule fired → tune.

### CI gates: syntax, backtest, performance

Three gates per PR:

1. **Syntactic correctness.** Parses, schema-conforming, required fields.
2. **FP backtest.** Replay against the last 30 days of production telemetry;
   FP rate above the per-rule budget gates the PR.
3. **Performance budget.** Query within the SIEM's compute budget; no
   unbounded-time-range KQL, no terabyte-scanning SPL.

Shops without backtest CI discover FP rates in production with the on-call
analyst as absorber.

---

## 6. False-Positive Engineering

### Why high-FP detection rules get ignored

The most-cited cause of failed SOC programs is **alert fatigue**. An analyst
handling 200 alerts/shift develops the heuristic of ignoring anything with
historical FP >50%; high-fidelity 1% detections drown in 99% noise. A rule
firing 100 times with 99 FPs and 1 TP is net-negative — the analyst spends so
much time on the rule that they miss the next TP from a different rule.

The DE team's primary job, after writing the rule, is keeping FP rate inside
the per-rule budget. Dual to SAST FP triage (cross-link to
[`semgrep_rule_authoring.md`](../static_analysis/semgrep_rule_authoring.md) §7):
SAST maintains precision through pattern specificity and metavariable
constraints; detection maintains precision through filter clauses and
behavioral baselining.

### The tunable allowlist pattern

Every detection ships with a documented allowlist. Sigma's `falsepositives:`
field names known FP sources; the consumer decides whether to suppress.

```yaml
falsepositives:
  - Penetration tests
  - Legitimate IT administrator activity using PSExec
  - System center configuration management deploying packages
```

The allowlist should be expressed *in the rule itself*, not in a wiki. "Fires on
`psexec.exe` except when `user_sid in $admin_sids and host in $admin_hosts`" is
structurally more reliable than "fires on psexec.exe (see wiki for exceptions)."

### Anomaly vs signature

**Signature** asks "is this a known-bad pattern?" — high precision when specific,
low recall on variants. Right for tool-level and lower indicators.

**Anomaly** asks "is this statistically unusual given the baseline?" — higher
recall, lower precision, harder to tune. Right for TTP-level patterns where
the attacker's freedom of action is constrained by the goal (lateral movement
requires a connection from A to B; the attacker can obscure but not avoid it).

Mature portfolios mix both: anomaly rules surface candidates, signature rules
confirm. A "first connection from this host to this IP" anomaly + a "JA3 matches
known C2" signature is higher-confidence than either alone.

### Behavioral baselining

Per-entity baselines (user, host, service account, tenant) are the bread-and-
butter of UEBA. The question shifts from "absolutely suspicious?" to
"suspicious *for this entity*?" Per-user: login hours, geography, application
usage. Per-host: processes spawned, outbound connections. Per-service-account:
should be *more* predictable than human accounts — interactive login by a
service account is high-signal. Requires 30-90+ days retention and statistical
sophistication not always native to the SIEM; pragmatic shops adopt a UEBA
layer (Exabeam, Securonix, native).

### The alert budget

Empirical sustainable rate: 5-15 high-severity investigations / analyst /
8-hour shift. Above 15 quality drops; above 30 the SOC is triage-only. Every
DE decision implicitly spends this budget. A 1/100-FP rule firing against
1M events/day produces 10,000 alerts/day; the same rule against 100 events/day
produces 1. **Telemetry-volume gating belongs in the rule's filter.** "Any
process create" is meaningfully different from "any process create where parent
is `winword.exe`" — the second narrows the data plane to a high-leverage subset.

Writing the FP list before deployment is the DE analog of writing TN test cases
before shipping a Semgrep rule. If the engineer cannot articulate the FP class,
they have not understood the rule.

---

## 7. MITRE ATT&CK as Detection-Engineering Substrate

### ATT&CK as taxonomy

**MITRE ATT&CK** (2013+; Enterprise, Mobile, ICS, Cloud, Containers) catalogs
adversary behavior at three levels:

- **Tactics** — tactical goals (Initial Access, Execution, Persistence, Privilege
  Escalation, Defense Evasion, Credential Access, Discovery, Lateral Movement,
  Collection, C2, Exfiltration, Impact). 14 in Enterprise.
- **Techniques** — methods (T1027 Obfuscated Files, T1059 Command/Scripting,
  T1078 Valid Accounts, T1190 Exploit Public-Facing App). ~200 techniques.
- **Sub-techniques** — variants (T1059.001 PowerShell, T1059.006 Python).

Every public DE corpus tags rules with ATT&CK technique IDs. The taxonomy makes
portfolios comparable across orgs and vendors.

### ATT&CK Navigator for coverage mapping

The **Navigator** overlays per-technique coverage scores onto the matrix as a
heat map. Its load-bearing utility is the conversation it enables: "we have
70% coverage on FIN7 techniques; the gap is concentrated in Defense Evasion";
"the Lateral Movement gaps are upstream — we don't have the telemetry"; "the
next priority is APT29's Persistence techniques."

### TTPs as the high-leverage target

Per the Pyramid of Pain, TTP-level detection is the apex. ATT&CK is the lens.
Wrong shape: 200 rules at IOC/tool levels covering 30 techniques superficially.
Right shape: 50 high-quality behavioral rules covering the same 30 techniques
with structural detections that catch variants — not just the implementation
the threat-intel vendor mentioned this week.

### DETT&CT for measuring coverage

**DETT&CT** (Marcus Bakker and Ruben Bouman, Rabobank CDC) measures blue-team
coverage using ATT&CK. Inputs: data-source visibility scoring (per ATT&CK data
source, what fraction of assets emit it at what fidelity?), detection coverage
scoring (per technique, rule confidence × asset coverage), threat-actor mapping
(which techniques does the relevant actor use?). Outputs: ATT&CK Navigator JSON
that color-codes visibility, detection, and actor relevance. DETT&CT is to
detection coverage what burndown charts are to project management.

### Common pitfalls: coverage theater vs adversary coverage

The most-common pitfall in ATT&CK-driven detection programs is **coverage
theater**: writing one rule per technique because that improves the heat map,
without regard to the rule's quality or the technique's relevance to the
organization's threat model.

Symptoms:

- A rule per technique, each with FP rate >50%, none of which fires in
  production.
- The Navigator looks 90% green; the SOC has 3 actionable detections.
- Tickets get closed as "coverage added" without backtest evidence.

The remedy is the same as for all Goodhart's-Law failures: shift the metric
from "techniques covered" to "techniques covered *with rules that have shipped
detections this quarter and have an actionable FP rate*." Coverage maps that
include quality scoring beat coverage maps that don't.

### MITRE D3FEND for the defensive side

**D3FEND** (NSA + MITRE NSEC, 2021+) is the defensive-countermeasure taxonomy
counterpart to ATT&CK. Tactics: Model, Harden, Detect, Isolate, Deceive, Evict,
Restore. Techniques: 267 as of v1.3.0 (December 2025).

D3FEND is younger and less battle-tested than ATT&CK, and it overlaps with
NIST CSF, OWASP ASVS, and CIS Controls in ways that are still being
disentangled. For detection-engineering specifically, the D3FEND "Detect"
tactic provides a structured catalog of detection techniques (signature
detection, anomaly detection, baselining, deception, etc.) that the engineer
can use to label their rule's *method* alongside ATT&CK's labeling of the
*adversary behavior*.

The cross-walk: "this rule detects T1059.001 (PowerShell) via D3FEND's
'Anomalous System Call Detection' (D3-ASCD) technique." Less mature than
ATT&CK adoption but converging.

---

## 8. Threat Hunting as Research Discipline

### Hypothesis-driven hunting

**Threat hunting** is the proactive search through telemetry for adversary
behavior that no current rule fires on. It is the human-led R&D arm of the
detection-engineering program.

A hunt is a hypothesis: "if an attacker were doing X, what would I expect to
see in our telemetry?" Deliverables: candidate matches (some TP, some FP); a
characterization of why current rules don't catch these; a recommendation
(write a rule, change telemetry, or accept the gap). This is the offensive
cousin of the candidate-point methodology in
[`vulnerability_research_methodology_expertise.md`](./vulnerability_research_methodology_expertise.md)
§6 — hypothesis-driven recon over telemetry instead of source.

### ThreatHunter-Playbook

Roberto Rodriguez's **ThreatHunter-Playbook** (OTRF) is the canonical public
hunt-as-notebook library. Each hunt is a Jupyter notebook with: markdown
description, ATT&CK linkage, required data sources, hunt logic
(KQL/SPL/EQL against Mordor / Security-Datasets), validation queries, and
references to corroborating detection rules. The notebook format preserves
the hunt's *reasoning* — not just the conclusion.

### Hunt → detect maturation loop

Hunts that find consistently-true patterns become detection rules; hunts that
find consistently-noisy patterns become known-noise filters. The transition is
non-trivial: a hunt query firing 1000 times over 6 months may be too noisy as
a real-time rule. Tighten the predicate, constrain entity scope, or both. A
hunt is exploration; a rule is commitment.

### When to hunt vs rely on rules

Hunt when a new TTP is reported but not yet in any rule corpus; when incident
retro surfaces a behavior current rules missed; when an architectural change
introduces new surface; when the threat model expects sophisticated evasion.

Skip hunting when the basics aren't covered (IOC/tool-level rules first), the
telemetry foundation isn't there (fishing without bait), or the team isn't
tuning current alerts (hunting as performance).

---

## 9. Cloud Detection Specifics

### Why cloud detection is different

Three asymmetries:

1. **Control plane is the surface.** On-prem the surface is the endpoint; in
   cloud it's identity-and-API. The telemetry locus shifts from endpoint logs
   to control-plane audit logs (CloudTrail, Azure Activity Log, GCP Audit Log).
2. **Data plane is opaque.** Network flow logs exist but inter-service traffic
   is encrypted; the attack story lives in identity grants and API calls.
3. **Ephemerality.** Cloud workloads come and go on second-to-minute timescales
   (Lambda, Fargate, scale-to-zero). Queries assuming static asset identity fail.

### Identity-as-perimeter

The cloud unit of analysis is the **identity**, not the host. Content focuses
on:

- Authentication anomalies — new geo, new device, impossible travel,
  password-spray, MFA fatigue.
- Authorization anomalies — privilege grants outside change windows,
  service-principal role additions, conditional-access modifications.
- API anomalies — first-time API usage, low-frequency calls (GetCallerIdentity
  from non-admin role for fingerprinting), unusual source IPs.
- Token anomalies — refresh-token theft (same token from two IPs), session
  hijacking.

**Impossible travel** is the most-cited cloud-identity rule and the most
commonly poorly tuned. Naive geographic-distance-over-time alerts generate
enormous FP rates from VPNs, satellite ISPs, and geolocation imprecision.
Mature implementations factor user history, client-application fingerprint,
and corroborating signals (MFA challenge, IdP risky-sign-in score). Cross-link
to [`distributed_authz_expertise.md`](./distributed_authz_expertise.md) §6 on
access-decision logging.

### Cloud-CI-CD detection

CI/CD pipelines are a cloud-detection target — runners are ephemeral, secrets
ambient, blast radius large (cross-link to
[`cicd_supply_chain_expertise.md`](./cicd_supply_chain_expertise.md) §4).
Content: GitHub Actions workflow event anomalies (unexpected refs, self-
modifying workflows, anomalous secret access); cloud-IAM-role assumptions from
CI runners outside expected windows; container-image builds with unexpected
base images or steps.

### Cloud-native detection services

| Cloud | Service | Coverage |
|---|---|---|
| AWS | GuardDuty | TI + ML on CloudTrail, VPC, DNS, EKS, S3 |
| AWS | GuardDuty Runtime Monitoring | eBPF inside EC2/ECS/EKS |
| Azure | Defender for Cloud | Multi-cloud posture + workload |
| Azure | Sentinel | SIEM, deep Microsoft + connector support |
| Azure | Defender XDR | Endpoint + identity + email + cloud-apps |
| GCP | Security Command Center | Posture + threat detection |
| GCP | Chronicle Security Operations | Google-scale SIEM |

Cross-cloud third parties: Wiz, Datadog Cloud SIEM, Lacework, Orca, Sysdig.

### CSPM vs SOC

A real organizational tension: CSPM (Wiz, Lacework, Orca) and SOC (SIEM + EDR +
hunting) often live in different teams. CSPM is "what's misconfigured" (static);
SOC is "what's happening" (runtime). Both are needed and should share
intelligence — posture findings *predict where attackers will land*; detection
findings *validate which posture risks materialized*. **AWS GuardDuty Runtime
Monitoring** combines CSPM-style account-level TI with eBPF runtime inside
workloads; "one product spanning posture + runtime" is the direction the
industry is moving.

---

## 10. Detection for AI / Agent Runtimes

### The brand-new detection surface

The detection-engineering surface that did not exist before ~2024 and is now
load-bearing: **AI and agent runtimes**. LLM-powered code assistants,
autonomous agents, MCP servers — running in production in 2026, with detection
content in early days. Cross-link to
[`llm_agent_security_expertise.md`](./llm_agent_security_expertise.md) §6 on
detection patterns for LLM applications, §2.5 on memory-poisoning attacks,
and to
[`agentic_web_capabilities_expertise.md`](./agentic_web_capabilities_expertise.md)
§10 on agent-runtime code review and capability-discipline detection. The
offensive counterpart lives in
[`adversarial_ml_model_security_expertise.md`](./adversarial_ml_model_security_expertise.md)
§12 on static + runtime detection of ML attacks; this section is the
defensive complement.

The structural move: an agent runtime is the runtime sibling of the LLM
application, the way EDR is the runtime sibling of the OS. The same Pyramid
of Pain applies — IOC-level (poisoned prompt strings) is cheap to write and
cheap to evade; tool-call sequence anomalies and identity-relative behavioral
baselines climb the apex.

### 10.1 The agent-telemetry observability primitive: OpenTelemetry GenAI semconv

The canonical observability primitive for AI runtimes in 2026 is the
**OpenTelemetry Semantic Conventions for Generative AI Systems**. The spec
defines a portable span-and-metric schema for LLM client calls, agent
invocations, and tool-call execution; it is the OCSF-equivalent of the AI
runtime — vendor-neutral schema that detection can be authored against once
and consumed across vendors. Status as of May 2026 is "in development" but
the field names are stable enough to write rules against, and most major
observability vendors (Langfuse, Phoenix, Helicone) have shipped GenAI semconv
support.

The load-bearing span types ([OpenTelemetry GenAI agent spans](https://opentelemetry.io/docs/specs/semconv/gen-ai/gen-ai-agent-spans/)):

- **Create Agent (CLIENT)** — agent creation for remote services.
- **Invoke Agent Client (CLIENT)** — remote agent invocation (e.g., OpenAI
  Assistants, AWS Bedrock).
- **Invoke Agent Internal (INTERNAL)** — same-process invocation (LangChain,
  CrewAI, in-process orchestrators).
- **Invoke Workflow (INTERNAL)** — coordinated multi-agent workflows.

The required attributes are `gen_ai.operation.name` (e.g., `create_agent`,
`invoke_agent`) and `gen_ai.provider.name` (`openai`, `aws.bedrock`,
`anthropic`, etc.). Conditional but high-value fields the detection author
should expect:

- `gen_ai.agent.id`, `gen_ai.agent.name`, `gen_ai.agent.version`
- `gen_ai.request.model`, `gen_ai.conversation.id`
- `gen_ai.tool.definitions` — the catalog of tools the agent was given
- `gen_ai.input.messages`, `gen_ai.output.messages` — structured chat history
- `gen_ai.system_instructions` — system prompt, separated from history
- `gen_ai.usage.input_tokens`, `gen_ai.usage.output_tokens` — usage metrics

The mental model: the OpenTelemetry GenAI span is *the unit of analysis* for
agent detection the way the Sysmon EventID 1 (process create) is for
endpoint detection. A rule authored against `gen_ai.tool.name == "shell.exec"
WHERE gen_ai.agent.id NOT IN known_shell_agents` is portable across any
observability vendor that emits GenAI semconv. Detection-engineering teams
in 2026 should treat GenAI semconv compliance as a hard requirement on any
inference platform vendor they integrate.

### 10.2 Per-provider telemetry primitives

Even with semconv as the target, the engineer needs to know what raw signals
each inference provider emits, because the path from provider event → semconv
span depends on the local instrumentation library.

**Anthropic Claude API.** The Messages API emits tool-use blocks as
structured events (`{"type": "tool_use", "id": "...", "name": "...",
"input": {...}}`); responses include `usage` blocks (input/output tokens,
cache hit/miss) and `stop_reason`. The platform's audit logs as of 2026
cover ~30 typed events spanning identity, organization configuration,
project lifecycle, conversation lifecycle, and file uploads ([Anthropic Compliance API](https://support.claude.com/en/articles/13015708-access-the-compliance-api)).
Notable gap: standard audit logs do *not* record what tools Claude called
or what those tools returned; tool-content visibility requires
OpenTelemetry instrumentation with `OTEL_LOG_TOOL_CONTENT=1`, which enables
span events with full tool input/output content truncated at 60 KB per span
([Claude Code monitoring docs](https://docs.anthropic.com/en/docs/claude-code/monitoring-usage)).
This is the AI-runtime parallel of the cloud-control-plane / cloud-data-plane
asymmetry: identity events are universally captured, behavior-content events
are opt-in.

**OpenAI Responses / Assistants API.** Tool calls surface as `function_call`
items in the response stream; the Responses API exposes them as typed
output items. The OpenAI tracing platform (Workbench) shows per-turn token
counts, tool calls, and reasoning traces; OpenAI does not yet offer a
first-party customer-facing event-stream audit log of the same fidelity
Anthropic's Compliance API provides. Bridging via OpenTelemetry GenAI semconv
in the application layer is the standard path.

**Bedrock / Vertex AI / Azure OpenAI.** Cloud-hosted inference exposes the
control-plane events at the cloud provider's audit-log fidelity (CloudTrail
for Bedrock, Cloud Audit Logs for Vertex, Activity Log for Azure OpenAI).
The data plane — actual prompts and completions — is captured via cloud-
native trace integrations (Bedrock Model Invocation Logging,
Vertex AI Logs) but is *opt-in* and *separately retained*. This is the same
pattern as S3 data-plane logging.

### 10.3 The AI-observability vendor landscape

The post-2024 vendor space for LLM observability is now mature enough that
"build vs buy" is a real decision. The detection engineer should know the
landscape because rules will often consume traces from one of these
platforms ([Spheron observability survey](https://www.spheron.network/blog/llm-observability-gpu-cloud-langfuse-arize-phoenix-helicone/),
[Latitude observability comparison](https://latitude.so/blog/best-llm-observability-tools-agents-latitude-vs-langfuse-langsmith)):

| Vendor | Posture | Strength | Limitation |
|---|---|---|---|
| **LangSmith** | LangChain-native SaaS | Zero-config trace capture for LangChain/LangGraph; LLM-as-judge evals | Vendor lock-in to LangChain; per-trace pricing |
| **Langfuse** | OSS + self-hostable | Framework-agnostic, GenAI semconv emit, transparent pricing | Younger ecosystem than LangSmith |
| **Arize Phoenix** | OSS + Arize AX SaaS | OpenTelemetry-native, RAGAS hallucination eval, ML-monitoring heritage | Phoenix UI thinner than LangSmith |
| **Helicone** | Proxy-mode | One-line setup as HTTP proxy | Proxy only — no in-process span-level visibility |
| **Promptlayer** | Prompt-management focus | Prompt version tracking + observability | Less depth on tool-call telemetry |
| **W&B Weave** | ML-experiment-tracking extension | Tight integration with model training | Built for research, less ops-shaped |
| **LangWatch / Logfire / Braintrust** | Newer entrants | Various focused angles (eval, dev-loop) | Smaller adoption |

The detection-engineering posture: prefer GenAI-semconv-emitting platforms
(Langfuse, Phoenix, OpenTelemetry-direct) so that rules survive vendor
changes. Treat Helicone-style proxy-only telemetry as insufficient for
agent detection — it misses the structured tool-call signal that lives only
in-process. The same `targeted telemetry` doctrine from §2 applies: collect
what your detection portfolio actually queries.

### 10.4 Prompt-injection detection — three layers, three Pyramid tiers

The doctrine evolves from the original three-bullet sketch. Map each
detection approach to its Pyramid of Pain tier:

1. **Pattern matching on input** (IOC tier, base of the Pyramid). Known
   injection strings: `ignore previous instructions`, `you are now`,
   `--- new instructions ---`, Unicode-tag-smuggled payloads (`\u{E0000}-
   \u{E007F}`), base64-encoded directives, prompt-suffix marker tokens.
   Cheap; trivially evaded by paraphrase or encoding swap. Useful as a
   noisy-but-cheap allow-set complement, not as a primary defense.
2. **LLM-as-classifier** (artifact / tool tier). A second, smaller model
   evaluates "is this prompt injection?" against the input or
   retrieval-augmented context. Microsoft's XPIA (Cross-Prompt Injection
   Attempt) classifier sits in this tier. Higher recall than patterns;
   ongoing inference cost; subject to *meta-injection* (the classifier
   itself can be jailbroken — EchoLeak (§10.6) demonstrated this).
   Treat as a defense-in-depth filter, not as a hard gate.
3. **Behavioral / outcome anomaly** (TTP tier, apex). Detect the *result*:
   the model making tool calls it would not make for a legitimate input,
   accessing data outside the user's normal scope, or producing output that
   matches an exfiltration shape (markdown image tags pointing at
   non-allowlisted hosts, base64 blobs in chat output). This requires the
   tool-call audit and behavioral baseline of §10.5. Hardest to write,
   most durable.

The EchoLeak paper ([arxiv 2509.10540](https://arxiv.org/html/2509.10540v1))
codifies the defensive telemetry signals that bridge tiers 2 and 3:
**unusual output entropy or length relative to query complexity**, *external
URLs or network calls from internal-only operations*, *reference-style
links and embedded images in model outputs*, *cross-domain requests through
allowed proxy services*, and *anomalous data access patterns tied to
external content ingestion*. These are runtime detections, not input
filters; they fire on what the agent *did*, not what was *said to* the agent.

### 10.5 Tool-call audit and rate / sequence anomaly

The minimum-viable AI-runtime telemetry remains the **tool-call audit log**:
per invocation, log identity, model-stated reason (with known-jailbreak
caveat — see [`llm_agent_security_expertise.md`](./llm_agent_security_expertise.md)),
capability invoked, data accessed, and approval gating. With OpenTelemetry
GenAI semconv (§10.1), this becomes a structured artifact rather than
ad-hoc logging.

Detection patterns that consume the tool-call audit:

- **Per-(user × tool × time-window) rate anomaly.** Statistical baseline
  on tool-call frequency per identity. Simple z-score thresholds at
  3 standard deviations are a reasonable entry point; mature shops layer
  EWMA or seasonal-decomposition models on top
  ([ARMO baseline / drift writeup](https://www.armosec.io/blog/ai-workload-baseline-drift-detection/)).
  The classic positive case: a code-generation agent's normal pattern is
  2-3 search queries and 1-2 code-execution attempts per task; 15 searches
  with no execution suggests confusion or goal drift (or adversarial
  injection forcing reconnaissance behavior).
- **Tool-call sequence anomaly.** Call-A-then-call-B is suspicious when
  A and B are rarely sequential in baseline traffic. Worked example: a
  documentation-summarizer agent invoking `mail.send` after `drive.read`
  is sequence-anomalous in the absence of a user-initiated "share this"
  request. The detection lives in the *transition matrix*, not the
  individual events.
- **Cross-MCP-server tool-call patterns.** When an agent has access to
  multiple MCP servers, the pattern of which servers it consults across
  a session is itself a signature. An agent that suddenly invokes a
  newly-mounted MCP server for the first time within a single
  user-initiated conversation, especially via a `tools/call` after an
  `initialize` and `tools/list` it never performed for this user before,
  is following the canonical reconnaissance-then-exploit chain.
- **High-cost-prompt detection.** Very-long context window paired with a
  trivial-question completion ("summarize this 250k-token document in one
  sentence") is the AI-runtime version of cryptocurrency mining detection
  — high cost without proportionate output. Useful both for abuse
  detection (token-theft via account compromise) and for jailbreak
  reconnaissance (long-context preamble buffering an injected
  instruction). Rate-limit at the platform layer; alert at the SOC layer.
- **Sampling-mode abuse detection.** MCP servers expose a
  `sampling/createMessage` operation that allows the *server* to ask the
  client to invoke the model on the server's behalf. The capability flips
  the normal trust direction and is high-leverage for a malicious MCP
  server. Rule: any `sampling/createMessage` event from an MCP server not
  on the explicit sampling-allowlist is a finding. The Global Secure
  Access MCP log schema (§10.7) emits this as a first-class sub-activity.
- **Memory-poisoning detection.** Specific to agents that maintain
  cross-session memory (Copilot, ChatGPT memory). The Microsoft Defender
  Research advisory on AI Recommendation Poisoning (§10.8) gives the
  canonical pattern: hunt URL query parameters containing memory-
  manipulation keywords (`remember`, `memory`, `trusted`, `authoritative`,
  `future`, `citation`, `cite`) against AI-assistant target domains
  (copilot, chatgpt, gemini, claude, perplexity, grok). The pattern
  extends to email, Teams messages, and Safe Links click telemetry. Cross-
  link to [`llm_agent_security_expertise.md`](./llm_agent_security_expertise.md)
  §2.5 on the memory-poisoning offense.

### 10.6 The 2024-2026 AI-incident corpus — what shipped

The incident corpus through May 2026 has converged on a recognizable
class of attacks: **zero-click indirect prompt injection** against
RAG-enabled or connector-enabled assistants. Detection engineers should
read these advisories the way endpoint engineers read Mandiant's
M-Trends — they tell you what to instrument.

**EchoLeak (CVE-2025-32711, Microsoft 365 Copilot).** Discovered by Aim
Labs (Aim Security); disclosed June 2025; patched server-side prior to
release. The first publicly-named "zero-click prompt injection" against a
production LLM assistant. Exploit chain: crafted email evades the XPIA
classifier; reference-style Markdown links bypass output link redaction;
auto-fetched images eliminate the user-click requirement; allowed Teams
proxy URL routes the exfil through CSP-allowlisted infrastructure;
instruction to omit external-email mention leaves the victim unaware
([HackTheBox writeup](https://www.hackthebox.com/blog/cve-2025-32711-echoleak-copilot-vulnerability),
[Aim Labs / Securiti analysis](https://securiti.ai/blog/echoleak-how-indirect-prompt-injections-exploit-ai-layer/),
[arxiv paper](https://arxiv.org/html/2509.10540v1)). The paper formalizes
the class as "LLM Scope Violation" and recommends the defensive telemetry
signals enumerated in §10.4. Detection lesson: trust the XPIA-tier
classifier only as defense-in-depth; the durable signal is at the
*output side* (reference-style links pointing outside the user's tenant,
image auto-fetch to non-allowlisted hosts).

**AgentFlayer (ChatGPT Connectors).** Disclosed at Black Hat 2025 by
Zenity Labs. Zero-click exfiltration from Google Drive / SharePoint /
GitHub / Microsoft 365 connectors via a poisoned document containing
invisible-text indirect-injection payload. The agent embeds stolen data
into image URLs; the URLs make automatic fetches to attacker-controlled
infrastructure when rendered
([Zenity writeup](https://labs.zenity.io/p/agentflayer-chatgpt-connectors-0click-attack-5b41),
[HackRead summary](https://hackread.com/agentflayer-0-click-exploit-chatgpt-connectors-steal-data/)).
The detection move: image-URL fetches from agent output where the host
is not on a tenant-scoped allowlist, plus invisible-text detection on
documents ingested by the agent.

**ShadowLeak (ChatGPT Deep Research).** Disclosed by Radware in September
2025; patched by OpenAI in August 2025
([The Hacker News writeup](https://thehackernews.com/2025/09/shadowleak-zero-click-flaw-leaks-gmail.html),
[The Record writeup](https://therecord.media/openai-fixes-zero-click-shadowleak-vulnerability)).
Indirect injection via tiny / white-on-white text in Gmail emails; Deep
Research agent parses the injection while analyzing the inbox and
exfiltrates base64-encoded data via the `browser.open()` tool. Distinct
from EchoLeak / AgentFlayer in that the exfil happens from *OpenAI's
cloud infrastructure*, not the client — invisible to local or enterprise
network defenses. Detection lesson: client-side network monitoring is
insufficient when the agent's runtime is in the provider's cloud; the
detection has to live at the *provider's tool-call audit* layer.

**Microsoft AI Recommendation Poisoning (February 2026).** Microsoft
Defender Research advisory documenting a 60-day study where 50 distinct
URL-prompt-poisoning attempts originated from 31 companies across
14 industries, targeting AI-assistant memory via `?q=` and `?prompt=`
parameters in "Summarize with AI" buttons
([Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2026/02/10/ai-recommendation-poisoning/),
[Help Net Security summary](https://www.helpnetsecurity.com/2026/02/11/ai-recommendation-memory-poisoning-attacks/)).
Formally classified by MITRE ATLAS as **AML.T0080 Memory Poisoning**.
Detection signals encoded in three Advanced Hunting queries for Office
365 (email, Teams, Safe Links). The advisory is the first public
incident-detection corpus tying AI-runtime telemetry to MITRE ATLAS, in
the same shape MITRE ATT&CK ties endpoint telemetry to TTP IDs.

**Cursor / Claude Desktop / IDE-agent corpus.** Ongoing class of incidents
in which an AI coding assistant is instructed (via README, comment, or
referenced documentation) to perform actions outside the user's intent
— exfil from `.env`, push malicious commits, escalate shell privileges.
No single canonical CVE; the pattern is mainstream enough that capability-
discipline review (cross-link to
[`agentic_web_capabilities_expertise.md`](./agentic_web_capabilities_expertise.md)
§10) and tool-call audit are now baseline expectations for coding-agent
deployments. Detection move: parent-process-anomaly rules
(`bash -c <suspect>` spawned by `claude` or `cursor`) at the endpoint
layer, plus tool-call audit at the agent layer.

### 10.7 MCP servers as detection surface — what changed in 2026

Updates the original sketch with the concrete schema that has emerged.
**MCP (Model Context Protocol)** servers expose tools, prompts, and
resources to LLM agents via JSON-RPC. The protocol's standard
sub-activities ([MCP spec](https://modelcontextprotocol.io/specification/2025-06-18/server/tools))
are the natural detection event-types:

- `initialize` — handshake; response carries the server's capability
  catalog. *Detection target: shadow-MCP-server discovery (a new
  destination URL emitting `initialize` from a corporate identity).*
- `tools/list`, `prompts/list`, `resources/templates/list` — capability
  enumeration. Sequences of bulk-enumeration calls from a single agent
  session are reconnaissance-shaped.
- `tools/call` — the primary detection target. The MCP call carries
  tool name and input arguments; the response carries tool output.
- `prompts/get`, `resources/read` — passive data-pull operations.
- `sampling/createMessage` — server-to-client reverse model invocation,
  flagged in §10.5 as inherently high-leverage.
- `notifications/*/list_changed`, `notifications/resources/updated` —
  capability or content drift; detection target for *malicious tool
  re-registration*.

Microsoft Entra **Global Secure Access** shipped MCP traffic logging
(preview, March 2026) via deep-packet-inspection of MCP-over-TLS traffic
([Microsoft GSA MCP logging](https://learn.microsoft.com/en-us/entra/global-secure-access/how-to-view-model-context-protocol-logging)).
The captured schema is the closest thing to an MCP CloudTrail and worth
modeling against:

| Field | Notes |
|---|---|
| `CreateDateTime` | Event timestamp |
| `Activity` | `MCP` |
| `Sub-activity` | Standard MCP method (`initialize`, `tools/list`, `tools/call`, etc.) |
| `Content` | Payload of the MCP call (tool name + arguments for `tools/call`; server capabilities for `initialize`) |
| `Destination URL` | Server URL — *the reliable server identifier* (names are user-controlled) |
| `Event ID` | Per-operation; pairs request and response |
| `Event Type` | `Request` or `Response` |
| `Session ID` | Per-conversation; multiple events per session |
| `MCP Client Name` / `MCP Server Name` | User-controlled, not reliable |
| `Transaction ID` | Joins to Global Secure Access network traffic logs |
| `User Principal Name` | Identity whose traffic was inspected |

Two architectural caveats the detection engineer should plant deeply:

1. **GSA MCP logging requires TLS inspection** (or the Copilot Studio
   integration that routes traffic through GSA without TLS-inspect). MCP
   payloads ride encrypted; without TLS-inspect, only flow metadata is
   visible. Detection programs that include MCP coverage must coordinate
   with the platform team to deploy TLS-inspect or accept the
   coverage gap.
2. **GSA MCP logging only sees remote MCP servers** — local-MCP traffic
   (stdio / unix socket) has no network footprint and is invisible to
   any network-layer collector. Local-MCP detection requires
   *in-agent* instrumentation via OpenTelemetry GenAI semconv (§10.1)
   or vendor-specific hooks (Anthropic's compliance API tool-content
   events, Claude Code's OTEL exporter).

Work list for an MCP-aware detection program: (a) inventory of MCP
servers and their tools via captured `initialize` responses; (b) per-tool
capability classification (read-only, write, shell, egress); (c)
per-agent / per-user behavioral baselines on `tools/call` distributions;
(d) rule-set on the call chain (e.g., "tool never called by this agent
before invoking shell-execute"); (e) rate / sequence anomalies (§10.5);
(f) sampling-mode allowlist enforcement.

### 10.8 Behavioral baselining for agent traffic

Agent behavioral baselines are the UEBA of the AI runtime. The same
per-entity bucketing applies (per-user, per-team, per-tenant, per-agent
instance) with two new wrinkles:

- **Per-agent baselining is load-bearing in a way per-user wasn't for
  endpoint UEBA.** A code-generation agent's "normal" is completely
  unlike a documentation-summarizer agent's "normal." Baselining at the
  *agent identity* (or `gen_ai.agent.id`) is the high-leverage unit; the
  user identity is secondary.
- **The cold-start problem is worse.** A new agent has no baseline; a new
  user using an existing agent inherits the agent's baseline but has no
  personal one. The first-day behavior of a new deployment is the
  highest-risk window and the lowest-information window simultaneously.
  Pragmatic shops use *role-based bootstrap baselines* (a new
  code-gen agent inherits the median baseline of comparable code-gen
  agents in the tenant) and tighten with personal data over 14-30 days.

The three classic dimensions for an agent baseline
([ARMO behavioral monitoring writeup](https://www.armosec.io/blog/detecting-intent-drift-in-ai-agents-with-runtime-behavioral-data/)):

1. **Tool-call distribution.** Which tools, at what frequencies, in what
   sequence. Statistical drift on the distribution is the first-order
   signal.
2. **Data-access scope.** Which records, files, or rows the agent
   touches. Scope-creep is a high-precision intent-drift signal.
3. **Egress shape.** Where the agent sends output. Sudden new
   destinations are a high-precision exfil signal; the EchoLeak /
   AgentFlayer / ShadowLeak attack class all surface here.

Two failure modes specific to agent-runtime baselining:

- **Behavioral-cloning attack** (§12 of this doc, applied to AI). An
  attacker compromises an agent's prompt or tool-allowlist and slowly
  normalizes a malicious tool-call pattern (an extra `mail.send` every
  100 invocations) so the baseline drifts to accept it. Defense: combine
  anomaly with signature, reset baselines on suspected incidents, and
  maintain a *novel-behavior tracker* outside the baseline-updating
  pipeline.
- **False-positive economics are worse than for endpoint UEBA.** Each
  agent alert is not just analyst time — it implies *interrupting a
  user's task* (the agent is paused for human review) AND a model-cost
  bill for the inference that produced the alert. The FP-tolerance
  curve is steeper. The per-rule alert budget (§6) should be
  proportionally tighter on agent runtimes. A rule that would have been
  acceptable at 1% FP on endpoint may need to hit 0.1% FP on agent
  runtime before it can ship.

Cross-link to
[`anti_fraud_abuse_engineering_expertise.md`](./anti_fraud_abuse_engineering_expertise.md):
much of the bot-detection literature (browser fingerprinting, behavioral
biometrics, rate-anomaly) applies directly to agent traffic, with the
twist that agents are *legitimate* automated traffic that should be
distinguished from *malicious* automated traffic — a "good agent vs bad
agent" classification rather than "human vs bot." Cross-link to
[`game_theory_mechanism_design_security_expertise.md`](./game_theory_mechanism_design_security_expertise.md)
on the red-vs-blue repeated-game dynamics: agent runtime is the new arena
in which detection rules and adversary tradecraft co-evolve.

### 10.9 The AI-SOC analyst — emerging vendor space

The post-2024 vendor space for **AI-augmented SOC** has matured to the
point of named products. The category claim is: an autonomous LLM-powered
investigator that takes a SOC alert as input and produces a triage verdict
(true-positive, false-positive, scope-and-severity) without analyst
involvement. Major entrants ([Radiant Security 2026 roundup](https://radiantsecurity.ai/learn/best-ai-soc-for-enterprise-top-5-options-in-2026/),
[Dropzone product page](https://www.dropzone.ai/),
[Prophet Security site](https://www.prophetsecurity.ai/)):

| Vendor | Posture |
|---|---|
| **Dropzone AI** | Autonomous AI SOC analyst; integrates with 60+ security tools; investigation latency claim of <10 min/alert; per-investigation pricing |
| **Prophet Security** | Agentic AI SOC platform; alert triage + investigation + threat-hunting agents |
| **Radiant Security** | Adaptive AI SOC; agentic analyst with transparent-reasoning UX; ~90% claimed FP reduction |
| **Microsoft Security Copilot** | Embedded in Defender XDR / Sentinel; native pivot to Microsoft telemetry |
| **CrowdStrike Charlotte AI** | Embedded in Falcon; conversational hunt / triage |
| **Qevlar AI** | Triage / investigation agent (Google partner) |

The detection-engineering implication is structural, not cosmetic.
*Detection rules are now consumed by AI agents as well as humans.* The
fields a rule emits — title, severity, evidence, suggested next step —
become prompt context for the downstream AI-SOC analyst. Two practical
consequences:

1. **Rules should emit machine-readable rationale, not just an alert
   title.** A Sigma rule's `description` and `references` fields are now
   load-bearing as agent-readable context. The "explain why this is bad"
   prose pays off in agent-driven triage quality.
2. **The "AI agent vs AI agent" future is here.** Attacker tooling is
   increasingly AI-assisted (LLM-driven recon, payload generation,
   evasion); defender tooling is AI-augmented (triage, hunt, response).
   The detection engineer is now writing rules at the *intersection* of
   two agent populations, both of which generate telemetry that looks
   approximately like legitimate human activity. The Pyramid of Pain
   applies at the TTP level *of the agent population*, not just the
   human attacker.

Cross-link to
[`vulnerability_research_methodology_expertise.md`](./vulnerability_research_methodology_expertise.md)
on the hypothesis-driven research discipline the AI-SOC analyst is now
automating, and to the AI-in-IR section of the team's DFIR methodology
reference — the same agentic capabilities are appearing in
post-incident-response workflows (timeline reconstruction, IOC pivoting,
malware-config extraction). The mature posture: treat the AI-SOC analyst
as an additional consumer of detection content with its own quality
contract (machine-readable provenance, falsifiable rationale, structured
fields), not as a magic-replacement for the human analyst.

### 10.10 AI-PR-review compromise detection rules — concrete Sigma/KQL/SPL corpus

The AI-PR-review platform corpus (cross-link to
[`ai_pr_review_platform_expertise.md`](./ai_pr_review_platform_expertise.md)
and [`ai_assisted_coding_tool_security_expertise.md`](./ai_assisted_coding_tool_security_expertise.md))
has now produced enough named incidents — **PwnedRabbit** (Kudelski Security
Research / CodeRabbit, January 2025 disclosed / August 2025 published —
Rubocop un-sandboxed RCE → CodeRabbit GitHub App PEM exfil → write access
to ~1M repositories); **Clinejection / GHSA-9ppg-jx86-fqw7** (Adnan Khan,
disclosed January 2026, public February 2026 — issue-event prompt injection
into `claude-code-action` → npm install of attacker-fork → Cacheract cache
poisoning → token exfil → malicious `cline@2.3.0` published);
**Comment-and-Control class** (Johns Hopkins + Anthropic, October-November
2025 — PR-title prompt-injection → shell exec → secrets exfil via PR
comment, CVSS 9.4 on Claude Code Security Review, Gemini CLI Action,
Copilot Agent); **CurXecute / CVE-2025-54135** (Aim Labs / Cursor, August
2025); **EchoLeak / CVE-2025-32711** (Aim Labs / Microsoft 365 Copilot,
June 2025) — that the detection-engineering shop can ship rules against
their structural patterns rather than against vendor-specific log shapes.

The OpenTelemetry GenAI semantic conventions (§10.1) are the substrate;
the `gen_ai.*` attribute namespace makes these rules portable across any
observability vendor that emits semconv-compliant spans. Where the GenAI
semconv coverage is insufficient (e.g., for the CI-runtime layer below the
agent runtime), the rules drop to GitHub Audit Log, runner-process
telemetry, or PR-API webhooks.

#### Rule 1: Agent modifies its own runtime config mid-session

**Threat pattern.** AI-coding-agent or AI-PR-review bot writes to its own
configuration files (`.cursor/mcp.json`, `~/.claude/settings.json`,
`.continue/config.json`, `.github/workflows/*.yml`, `.aider.conf.yml`,
`.gemini/config.json`) within an active session — either directly via tool
use or indirectly via shell. This is the Comment-and-Control class
signature: the agent grants itself new capabilities while running, which
bypasses static-pre-run capability allowlisting entirely.

**Primary incident anchor.** Comment-and-Control class (Johns Hopkins +
Anthropic, October-November 2025, CVSS 9.4 on Claude Code Security Review
/ Gemini CLI Action / Copilot Agent); MCPoison (Check Point Research,
August 2025).

**Sigma.**

```yaml
title: Agent Self-Modifies Runtime Configuration Mid-Session
id: a1f6b8d0-3e91-4c75-9a2e-9c2d6f1f8b21
status: experimental
description: |
  Detects an AI agent (Cursor / Claude Code / Cline / Continue / Aider / Copilot
  / Gemini CLI / AI-PR-review bot) writing to its own MCP, tool, or workflow
  configuration files while executing a user-initiated session. Captures the
  Comment-and-Control class where an injected prompt grants the agent new
  capabilities at runtime.
references:
  - https://github.blog/security/vulnerability-research/   # Comment-and-Control class
  - https://research.checkpoint.com/2025/mcpoison-cursor-mcp/
  - https://www.aim.security/blog/echoleak-cve-2025-32711
author: detection-engineering
date: 2026/05/15
logsource:
  product: opentelemetry
  service: gen_ai
detection:
  agent_session:
    gen_ai.operation.name:
      - invoke_agent
      - execute_tool
    gen_ai.tool.name|contains:
      - 'fs.write'
      - 'file.write'
      - 'edit_file'
      - 'shell.exec'
      - 'bash'
      - 'run_command'
  config_target:
    gen_ai.tool.arguments|contains:
      - '.cursor/mcp.json'
      - '.claude/settings.json'
      - '.claude/settings.local.json'
      - '.continue/config.json'
      - '.aider.conf.yml'
      - '.gemini/config.json'
      - '.github/workflows/'
      - '.cline/'
  condition: agent_session and config_target
falsepositives:
  - Initial repository scaffolding (user explicitly asked agent to set up config)
  - Documented onboarding flows where the agent writes settings.json on first run
  - User-issued "/init" or equivalent capability-bootstrapping command
level: high
tags:
  - attack.t1098    # Account Manipulation
  - attack.t1546    # Event Triggered Execution
  - atlas.aml.t0051 # LLM Prompt Injection (MITRE ATLAS)
```

**FP economics.** The dominant FP source is legitimate scaffolding ("add
an MCP server", "/init a new repo"). Tune by allowlisting the *first*
config-write within N minutes of session start, and by requiring the
config-target rule to fire *without* a corresponding user message
referencing the config file (`gen_ai.input.messages` must not contain the
filename or its synonyms). A tighter variant requires the agent to have
already invoked `execute_tool` on untrusted input (issue body, README, PR
diff) in the same session — see Rule 6's canary pattern.

#### Rule 2: Anomalous tool-call sequence — untrusted-input read followed by package install

**Threat pattern.** Bot's tool-call sequence is `read-source / read-issue /
read-comment` (untrusted input) followed within the same session by
`shell.exec` or `terminal.run` invoking `npm install`, `pip install`,
`cargo install`, `gem install`, or equivalent. This is the Clinejection
chain: untrusted text → agent ingests → agent runs install command from
attacker-controlled context. The class generalizes to any CI bot that
ingests user-controlled text and has tool authority over package managers.

**Primary incident anchor.** Clinejection / GHSA-9ppg-jx86-fqw7 (Adnan
Khan, January-February 2026); Cline post-mortem
(`cline.bot/blog/post-mortem-unauthorized-cline-cli-npm`).

**Sigma.**

```yaml
title: AI Agent Runs Package Install After Reading Untrusted Input
id: c2a7e914-8f06-4d3b-9e51-7d3a4f1b2e95
status: experimental
description: |
  Detects an AI agent invoking a package-installer command (npm/pip/cargo/gem/
  pnpm/yarn/uv) after ingesting untrusted text (issue body, PR title, PR
  comment, README content) within the same session. Matches the Clinejection
  attack chain (untrusted text → prompt injection → npm install from attacker
  fork).
references:
  - https://github.com/advisories/GHSA-9ppg-jx86-fqw7
  - https://adnanthekhan.com/posts/clinejection/
  - https://cline.bot/blog/post-mortem-unauthorized-cline-cli-npm
author: detection-engineering
date: 2026/05/15
logsource:
  product: opentelemetry
  service: gen_ai
detection:
  untrusted_read:
    gen_ai.tool.name|contains:
      - 'github.issue'
      - 'github.pr'
      - 'github.comment'
      - 'fetch_url'
      - 'web_fetch'
      - 'read_file'
    gen_ai.tool.arguments|contains:
      - 'README'
      - '/issues/'
      - '/pull/'
      - '/comments/'
  install_exec:
    gen_ai.tool.name|contains:
      - 'shell.exec'
      - 'bash'
      - 'terminal.run'
      - 'run_command'
    gen_ai.tool.arguments|re:
      - '\b(npm|pnpm|yarn|pip|pip3|uv|cargo|gem|go)\s+(install|add|get)\b'
      - '\bcurl\s.*\|\s*(sh|bash)'
  condition: untrusted_read and install_exec | within 30m by gen_ai.conversation.id
falsepositives:
  - Legitimate dependency bootstrap (first install after repo clone)
  - Agent following a documented setup README on a user-trusted repo
level: critical
tags:
  - attack.t1195.002  # Supply Chain Compromise: Software Dependencies
  - attack.t1059      # Command and Scripting Interpreter
  - atlas.aml.t0051   # LLM Prompt Injection
```

**FP economics.** New-repo bootstrap is the noisiest legitimate source.
Tune by requiring the untrusted-read to reference content authored by a
GitHub identity *outside* the repo's collaborator set (use `actor.login`
membership check against the repo's `/collaborators` API), or by gating
on the install command targeting a package *not* in the repo's existing
lockfile. Per-session install rate over 3× the 7-day baseline is the
robust ML-friendly alternative.

#### Rule 3: Cross-tenant data access from a tenant-scoped agent

**Threat pattern.** An AI-PR-review platform serving multiple customers
accesses repository data from a tenant *different* from the one whose
webhook triggered the agent run. This is the PwnedRabbit blast-radius
shape: a single compromised reviewer instance has write access to every
repo in the platform's GitHub App installation set.

**Primary incident anchor.** PwnedRabbit (Kudelski Security Research →
CodeRabbit, January 2025 disclosed / August 2025 published — Rubocop
un-sandboxed RCE → CodeRabbit GitHub App PEM exfil → 1M-repo write access).

**KQL (Microsoft Sentinel / Defender XDR — applies to provider-side audit
of multi-tenant SaaS reviewer).**

```kql
// Cross-tenant access from a tenant-scoped AI-PR-review agent.
// Assumes a custom table AIReviewAuditLog_CL with fields:
//   TimeGenerated, AgentSessionId_s, TriggerTenantId_s, AccessedTenantId_s,
//   AccessedRepoFullName_s, AccessKind_s, BotIdentity_s, GitHubInstallationId_s
let lookback = 24h;
AIReviewAuditLog_CL
| where TimeGenerated > ago(lookback)
| where AccessKind_s in ("clone", "fetch", "diff_read", "comment_post",
                         "secret_read", "checks_write")
| where TriggerTenantId_s != AccessedTenantId_s
| where BotIdentity_s !in (dynamic(["platform-admin@coderabbit.ai",
                                    "platform-svc@<vendor>"]))
| project TimeGenerated, AgentSessionId_s, BotIdentity_s,
          TriggerTenantId_s, AccessedTenantId_s, AccessedRepoFullName_s,
          AccessKind_s, GitHubInstallationId_s
| summarize ViolationCount = count(),
            Examples = make_list(AccessedRepoFullName_s, 5),
            Kinds = make_set(AccessKind_s)
        by AgentSessionId_s, BotIdentity_s, TriggerTenantId_s,
           AccessedTenantId_s
| where ViolationCount >= 1
| order by ViolationCount desc
```

**FP economics.** Legitimate cross-tenant access is rare-but-real: shared
fork relationships, monorepo-spans-tenants edge cases, and platform-admin
audit sweeps. Tune by allowlisting platform-admin identities (above), by
treating the *first* cross-tenant access in a session as expected if
followed within 60s by a `webhook.fork_event` correlation, and by
sub-classifying by `AccessKind_s` — `checks_write` and `secret_read`
should be alert-immediately while `diff_read` can be summary-daily.

#### Rule 4: Agent emits PR comment containing high-entropy or credential-shaped payload

**Threat pattern.** The agent's output PR comment contains base64-encoded
blobs above N bytes, raw secret-prefix matches (`sk_`, `ghp_`, `ghs_`,
`AKIA`, `xoxb-`, `xoxp-`, `glpat-`, `gho_`, `xapp-`), JWT-shaped strings,
or URLs whose query-parameters carry sensitive-name path components
(`/secrets/`, `/.aws/`, `/.ssh/`, `id_rsa`). This is the Comment-and-Control
exfil channel — PR comments are an attacker-readable broadcast surface
across the public internet for any public-repo bot.

**Primary incident anchor.** Comment-and-Control class (Johns Hopkins +
Anthropic, October-November 2025); ShadowLeak (Radware / OpenAI ChatGPT
Deep Research, September 2025) for the exfil-via-bot-output pattern.

**Splunk SPL.**

```spl
index=github sourcetype=github:audit OR sourcetype=ai_review:audit
  (action="issue_comment.created" OR action="pull_request_review_comment.created"
   OR action="pull_request_review.submitted")
  actor_type="Bot"
| eval comment_len=len(body)
| rex field=body "(?<b64_blob>[A-Za-z0-9+/]{200,}={0,2})"
| rex field=body max_match=10 "(?<secret>(?:sk_(?:live|test)_[A-Za-z0-9]{16,}|ghp_[A-Za-z0-9]{36}|ghs_[A-Za-z0-9]{36}|gho_[A-Za-z0-9]{36}|AKIA[0-9A-Z]{16}|xoxb-[0-9A-Za-z-]{20,}|xoxp-[0-9A-Za-z-]{20,}|glpat-[A-Za-z0-9_-]{20}|eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+))"
| rex field=body "(?<sus_url>https?://[^\s)]*(?:/\.aws/|/\.ssh/|/secrets/|id_rsa|credentials|\.env))"
| where isnotnull(b64_blob) OR isnotnull(secret) OR isnotnull(sus_url) OR comment_len > 8000
| eval finding=case(isnotnull(secret),"credential_pattern",
                    isnotnull(sus_url),"sensitive_path_url",
                    isnotnull(b64_blob),"high_entropy_blob",
                    comment_len > 8000,"oversize_comment")
| stats count by actor, repo, pull_request_number, finding, _time
| where count >= 1
```

**FP economics.** Legitimate base64 blobs in PR comments come from CI logs
(test fixtures, image-diff snapshots, log-attachment summaries). Tune by
requiring the bot identity to match the AI-PR-review platform's actor
allowlist (CodeRabbit / Greptile / Bito / Cursor BugBot / etc.), by
allowlisting comment-bodies prefixed with conventional `<!-- ci-log -->`
or `<details><summary>` HTML wrappers, and by extracting comment context
— a base64 blob inside a fenced code block discussing an HTTP example is
lower-risk than the same blob in body text. Secret-prefix matches should
be alert-immediately regardless of context (the prefix shape is high-
specificity).

#### Rule 5: Prompt-injection canary detection — defensive instrumentation

**Threat pattern.** Defender embeds known canary strings (e.g., a unique
high-entropy token like `CANARY-AIPR-9f2c3a8b-1d4e-4f0a-b6e1-c8a93d7f2b1c`)
in repository files an attacker is likely to inject into (README, CONTRIBUTING,
CODEOWNERS, issue/PR templates). The detection fires when the canary
appears in *agent output* (PR comment, tool-call argument, model response
trace) — meaning the agent processed the canary and re-emitted it,
confirming the prompt-injection vector landed on it.

**Primary incident anchor.** Defensive instrumentation pattern; conceptually
adjacent to the EchoLeak CVE-2025-32711 (Aim Labs, Microsoft 365 Copilot,
June 2025) detection lesson that durable signal lives at the *output side*
of the agent.

**Sigma.**

```yaml
title: AI Agent Output Contains Prompt-Injection Canary Token
id: e5d4c612-2a9b-4f01-87e0-1c6a3b4d8e92
status: experimental
description: |
  Detects an AI agent's output (chat response, tool-call argument, or PR
  comment) containing a defender-planted canary token. Confirms that an
  indirect-prompt-injection payload reached the model and was reflected,
  regardless of whether downstream exploitation succeeded.
references:
  - https://www.aim.security/blog/echoleak-cve-2025-32711
  - https://embracethered.com/blog/                       # Rehberger canary patterns
  - https://atlas.mitre.org/techniques/AML.T0051
author: detection-engineering
date: 2026/05/15
logsource:
  product: opentelemetry
  service: gen_ai
detection:
  output_carries_canary:
    gen_ai.output.messages|contains:
      - 'CANARY-AIPR-'
      - 'CANARY-MCP-'
      - 'CANARY-REVIEW-'
  tool_arg_carries_canary:
    gen_ai.tool.arguments|contains:
      - 'CANARY-AIPR-'
      - 'CANARY-MCP-'
      - 'CANARY-REVIEW-'
  condition: output_carries_canary or tool_arg_carries_canary
falsepositives:
  - Canary appears in a developer's intentional test of the canary itself
  - The canary string is copied into agent input by an explicit user request
    to "summarize" or "echo" the file containing it
level: critical
tags:
  - atlas.aml.t0051   # LLM Prompt Injection
  - attack.t1059
```

**FP economics.** True positives have near-zero noise floor *if* the
canary token is high-entropy and not referenced anywhere in legitimate
developer workflow. The FP failure mode is the canary leaking into
documentation, test fixtures, or the agent's own training-context (if an
agent vendor scrapes the repo for fine-tuning). Tune by rotating the
canary token quarterly, by keeping the canary out of any commit message
or PR title, and by requiring the agent's input *not* to include the
canary on the same session (`gen_ai.input.messages` does not contain the
canary, but `gen_ai.output.messages` does — that gap is the signal).

#### Rule 6: Cache-poisoning shape — agent writes to package-manager cache directories

**Threat pattern.** Agent process writes to `~/.npm/_cacache/`,
`~/.cache/pip/`, `~/.cargo/registry/`, `~/.gem/cache/`, or
`/runner/_work/_actions/` outside the normal install flow (i.e., not
during an `npm install` / `pip install` / etc. child process). This is
the Cacheract / Clinejection chain compound: cache poisoning enables the
next CI run to consume a malicious cached artifact.

**Primary incident anchor.** Clinejection / GHSA-9ppg-jx86-fqw7 (cache
poisoning sub-step via Cacheract); GitHub Actions LRU eviction policy
change (November 2025) as the precondition.

**Sigma (endpoint / runner-process telemetry, not GenAI semconv — cache
writes happen below the agent abstraction).**

```yaml
title: CI Runner Writes to Package-Manager Cache Outside Install Flow
id: f7b3d825-91a4-4d8c-9b6f-2e1a5c8d3f47
status: experimental
description: |
  Detects writes to package-manager cache directories from a GitHub Actions
  runner / Buildkite agent / GitLab runner process tree, where the parent
  process is NOT a recognized package-manager binary invoking its own cache.
  Matches the Cacheract cache-poisoning step in the Clinejection chain.
references:
  - https://github.com/advisories/GHSA-9ppg-jx86-fqw7
  - https://adnanthekhan.com/posts/clinejection/
  - https://github.blog/changelog/2025-11-cache-eviction-policy/   # placeholder for the GHA LRU policy doc
author: detection-engineering
date: 2026/05/15
logsource:
  product: linux
  category: file_event
detection:
  cache_write:
    TargetFilename|startswith:
      - '/home/runner/.npm/_cacache/'
      - '/home/runner/.cache/pip/'
      - '/home/runner/.cargo/registry/'
      - '/root/.npm/_cacache/'
      - '/root/.cargo/registry/'
      - '/runner/_work/_actions/'
  not_install_parent:
    ParentImage|endswith:
      - '/node'
      - '/npm'
      - '/pnpm'
      - '/yarn'
      - '/pip'
      - '/pip3'
      - '/uv'
      - '/cargo'
      - '/gem'
  condition: cache_write and not not_install_parent
falsepositives:
  - Custom build scripts that pre-warm package caches via direct file writes
  - Cache-restore actions (actions/cache@v4) writing during the restore step
    — exclude by parent process or by file-write phase tag
level: high
tags:
  - attack.t1195.001  # Supply Chain Compromise: Compromise Software Dependencies and Development Tools
  - attack.t1565.001  # Stored Data Manipulation
```

**FP economics.** The Cache action (`actions/cache`) is the dominant
legitimate writer. Tune by allowlisting the action's process tree
(`/runner/_work/_temp/_runner_file_commands/` ancestor) and by gating on
runner-correlated GitHub Actions audit-log `actions.cache_restore` /
`cache_save` events surrounding the write. Cross-link to
[`cicd_supply_chain_expertise.md`](./cicd_supply_chain_expertise.md) §2.7
(cache poisoning) and §2.9 (Clinejection AI-era variant).

#### Implementation note

These six rules are *starting points*, not production-ready. Each one
needs a backtest pass against the team's actual agent traffic, a tuning
phase to drive FPs below the alert budget (§6), and an Atomic-Red-Team-
shaped test fixture (§5) so the rule can be regression-tested as
provider semconv attributes evolve. The OpenTelemetry GenAI semconv is
still "in development" as of May 2026 (§10.1) and attribute names may
shift — pin the rule's `gen_ai.*` fields to the version of the semconv
your inference platform emits and update on schema bump. Treat this
corpus as the AI-PR-review-specific complement to §10.5's general tool-
call audit patterns; cross-link to
[`ai_pr_review_platform_expertise.md`](./ai_pr_review_platform_expertise.md)
§7 (detection patterns) and
[`ai_assisted_coding_tool_security_expertise.md`](./ai_assisted_coding_tool_security_expertise.md)
§9 (AI-PR-review threat model) for the incident-corpus context these
rules consume.

---

## 11. Detection-Engineering Organizational Patterns

### SOC ↔ Detection Engineering ↔ Threat Intel

The mature security org has three interconnected functions: **SOC** operates
the rule corpus, triages alerts, runs IR; **Detection Engineering** authors
and tunes rules, manages the detection-as-code pipeline; **Threat Intel
(CTI)** tracks adversaries, produces actor profiles, feeds the DE hypothesis
pipeline. All three should sit in the same org and operate on the closed loop
CTI → DE rule → SOC alert → SOC triage → DE tune. When split, the loop
breaks — CTI produces reports that don't drive content, DE writes rules that
don't reflect actor patterns, SOC triages alerts that don't map to a story.

### Where to put detection engineering

Three common org placements: **Under SOC** (tight feedback; reactive risk —
"write a rule for last week's alert"). **Under CTI** (actor-aligned; drifts
from operational reality). **Standalone under CISO** (balanced; requires
headcount + tech-lead navigation). Standalone is best-practice above ~30
security FTEs; SOC-integrated below.

### Detection PR review

Every detection reviewed before deployment: hypothesis, telemetry coverage,
precision (expected FP + backtest result), tunability (allowlist documented),
severity, operational fit (who triages, what queue, what playbook). Untested
rules are operational debt.

### Backlog: detections vs coverage gaps

Track separately: **detections backlog** (rules to write/tune; bounded by team
capacity, prioritized by leverage) versus **coverage gaps backlog** (ATT&CK
techniques without any detection; bounded by ambition, prioritized by threat-
model relevance + telemetry feasibility). Conflating them produces either
coverage theater or perpetually-deferred gaps.

### Purple teaming as validation loop

Adversary simulation with real-time defender feedback. Surfaces detections
that fire as expected (confidence), false negatives (rule/telemetry broken),
false positives (tuning needed), and coverage gaps (new content needed).
Per-technique report; cadence quarterly to annually. Cross-link to
[`appsec_program_building_expertise.md`](./appsec_program_building_expertise.md)
§7 on engineering empathy applied to SOC analysts.

---

## 12. Variant Analysis — Under-Explored Frontiers

### LLM-as-detection-engineer

The most-actively-explored frontier in 2026: LLMs authoring detections from
natural-language threat-intel inputs. Workflow: TI feed publishes a report;
LLM extracts observable behaviors and proposes a Sigma template; engineer
reviews/adjusts; CI gates as normal. Promise: a TTP described in a paragraph
becomes a rule in minutes. Risk: subtly wrong predicates, hallucinated field
names, lack of falsifiability. Treat LLM output as a draft that must pass
the same review gates as human-authored rules.

### Behavioral cloning attacks against EDR baselines

The adversarial frontier of anomaly detection: attackers who slowly normalize
malicious patterns so the baseline drifts to accept them. The attacker, with
a low-privilege foothold, performs benign-looking actions tangentially
adjacent to the attack over weeks; the baseline learns these as "normal";
when the attack executes, anomaly detection does not fire. Defenses: reset
baselines after suspected incidents; combine anomaly with signature (the
attacker can drift the baseline but not the eventual TTP signature); maintain
a separate novel-behavior tracker that doesn't normalize.

### Cross-cloud detection

Multi-cloud orgs need unified content. Three approaches: per-cloud native
rules (comprehensive, no cross-cloud correlation); centralized SIEM
(correlation, ingestion cost); OCSF + portable rule format (promising but
uneven adoption as of 2026). Cross-cloud attacks (Azure AD compromise →
federated AWS role assumption) require cross-audit-log correlation; this is
the most-cited and least-instrumented scenario.

### Detection for serverless

Lambda, Cloud Run, Azure Functions, Fargate break several DE assumptions:
process telemetry is per-invocation not per-host; network logging is
constrained; file writes are ephemeral and `/tmp`-scoped. The shift: rules
become about function behavior relative to its own baseline, not host-level
events. AWS GuardDuty Runtime Monitoring for Lambda + AWS X-Ray traces are
the surface.

### Detection for ephemeral CI runners

GHA runners, GitLab CI, Buildkite agents — ephemeral compute, one job's
lifetime, then gone. Cannot deploy an EDR agent; logs may not survive the
job; attack surface is large (ambient secrets, often-unrestricted network,
CI permissions). The pattern that works: log CI events (workflow runs,
commands, network connections) to a central pipeline-audit store; write
detections at the *event-stream* level, not the *host* level. Cross-link to
[`cicd_supply_chain_expertise.md`](./cicd_supply_chain_expertise.md) §4.

### Detection-as-rebuttal-of-design

The most-staff-level move: when a rule *for a primitive that should not exist*
signals an architectural failure, the right output is sometimes "fix the
architecture," not "ship the rule." A detection for "service account
performing interactive login" signals the service account has a real password;
the architectural fix is passwordless service accounts. A detection for "user
accessing data outside their tenant" signals no row-level-security
enforcement; the fix is row-level security. A detection for "agent calling a
tool with over-scoped credentials" signals the agent's token doesn't follow
least-privilege; the fix is scope-down at the IdP. The rule may still ship as
a compensating control while architecture changes; the staff-level
contribution is recognizing the rule's *existence* as evidence the
architecture is wrong.

---

## 13. References

### Foundational papers and essays

- Hutchins, Cloppert, Amin. *Intelligence-Driven Computer Network Defense
  Informed by Analysis of Adversary Campaigns and Intrusion Kill Chains.*
  Lockheed Martin, 2011.
  <https://www.lockheedmartin.com/content/dam/lockheed-martin/rms/documents/cyber/LM-White-Paper-Intel-Driven-Defense.pdf>
- Bianco. *The Pyramid of Pain.* 2013.
  <http://detect-respond.blogspot.com/2013/03/the-pyramid-of-pain.html>
- Lambert. *Defenders think in lists. Attackers think in graphs.*
  <https://github.com/JohnLaTwC/Shared/blob/master/Defenders%20think%20in%20lists.%20Attackers%20think%20in%20graphs.%20As%20long%20as%20this%20is%20true,%20attackers%20win.md>
- Lambert. *Defender's Mindset.*
  <https://medium.com/@johnlatwc/defenders-mindset-319854d10aaa>
- Atkinson. *Capability Abstraction.*
  <https://specterops.io/blog/2020/02/06/capability-abstraction/>
- Atkinson. *Detection Spectrum.*
  <https://specterops.io/blog/2020/02/21/detection-spectrum/>
- Atkinson. *Detection in Depth.*
  <https://specterops.io/blog/2020/05/08/detection-in-depth/>
- Robbins. *The Attack Path Management Manifesto.*
  <https://posts.specterops.io/the-attack-path-management-manifesto-3a3b117f5e5>

### Frameworks and taxonomies

- MITRE ATT&CK. <https://attack.mitre.org/>
- MITRE D3FEND. <https://d3fend.mitre.org/>
- ATT&CK Navigator. <https://mitre-attack.github.io/attack-navigator/>
- DETT&CT. <https://github.com/rabobank-cdc/DeTTECT>
- OCSF. <https://github.com/ocsf/ocsf-schema>
- NIST CSF. <https://www.nist.gov/cyberframework>
- OWASP ASVS. <https://owasp.org/www-project-application-security-verification-standard/>

### Rule languages and corpora

- SigmaHQ. <https://github.com/SigmaHQ/sigma>
- Sigma docs. <https://sigmahq.io/docs/guide/about.html>
- pySigma. <https://github.com/SigmaHQ/pySigma>
- sigma-cli. <https://github.com/SigmaHQ/sigma-cli>
- YARA. <https://virustotal.github.io/yara/>
- YARA-X. <https://github.com/VirusTotal/yara-x>
- Florian Roth signature-base. <https://github.com/Neo23x0/signature-base>
- Snort. <https://www.snort.org/>; Suricata. <https://suricata.io/>;
  Zeek. <https://zeek.org/>
- Splunk Security Content.
  <https://github.com/splunk/security_content>
- Elastic Detection Rules.
  <https://github.com/elastic/detection-rules>
- Microsoft Sentinel Content.
  <https://github.com/Azure/Azure-Sentinel>

### EDR and instrumentation

- Sysmon. <https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon>
- Olaf Hartong sysmon-modular.
  <https://github.com/olafhartong/sysmon-modular>
- SwiftOnSecurity sysmon-config.
  <https://github.com/SwiftOnSecurity/sysmon-config>
- ION-Storm sysmon-config. <https://github.com/ion-storm/sysmon-config>
- Falco. <https://falco.org/>; Tetragon. <https://tetragon.io/>;
  eBPF. <https://ebpf.io/>
- Matt Graeber on AMSI / Windows internals.
  <https://posts.specterops.io/> and <https://mattifestation.medium.com/>

### Threat-hunting and adversary simulation

- Rodriguez. *ThreatHunter-Playbook.*
  <https://github.com/OTRF/ThreatHunter-Playbook>
- Rodriguez. *Security-Datasets (Mordor).*
  <https://github.com/OTRF/Security-Datasets>
- Atomic Red Team. <https://github.com/redcanaryco/atomic-red-team>;
  <https://www.atomicredteam.io/>
- MITRE CALDERA. <https://github.com/mitre/caldera>
- Stratus Red Team. <https://github.com/DataDog/stratus-red-team>

### Cloud detection

- AWS GuardDuty. <https://aws.amazon.com/guardduty/>
- AWS GuardDuty Runtime Monitoring.
  <https://docs.aws.amazon.com/guardduty/latest/ug/runtime-monitoring.html>
- Microsoft Sentinel.
  <https://azure.microsoft.com/en-us/products/microsoft-sentinel/>
- Defender for Cloud.
  <https://azure.microsoft.com/en-us/products/defender-for-cloud/>
- GCP Security Command Center.
  <https://cloud.google.com/security-command-center>

### AI / Agent runtime observability and detection

- OpenTelemetry Semantic Conventions for Generative AI Systems.
  <https://opentelemetry.io/docs/specs/semconv/gen-ai/>
- OpenTelemetry GenAI Agent and Framework Spans.
  <https://opentelemetry.io/docs/specs/semconv/gen-ai/gen-ai-agent-spans/>
- OpenTelemetry GenAI Spans (client LLM calls).
  <https://opentelemetry.io/docs/specs/semconv/gen-ai/gen-ai-spans/>
- OpenTelemetry GenAI Metrics.
  <https://opentelemetry.io/docs/specs/semconv/gen-ai/gen-ai-metrics/>
- OpenTelemetry "GenAI for OTel" launch post.
  <https://opentelemetry.io/blog/2024/otel-generative-ai/>
- Model Context Protocol specification (tools).
  <https://modelcontextprotocol.io/specification/2025-06-18/server/tools>
- Microsoft Global Secure Access — MCP traffic logging (preview).
  <https://learn.microsoft.com/en-us/entra/global-secure-access/how-to-view-model-context-protocol-logging>
- Anthropic Compliance API.
  <https://support.claude.com/en/articles/13015708-access-the-compliance-api>
- Anthropic Claude Code monitoring (OTel exporter, tool-content events).
  <https://docs.anthropic.com/en/docs/claude-code/monitoring-usage>
- MITRE ATLAS knowledge base. <https://atlas.mitre.org/>
- MITRE ATLAS — AML.T0080 Memory Poisoning.
  <https://atlas.mitre.org/techniques/AML.T0080>

### AI-runtime observability vendor landscape

- Langfuse. <https://langfuse.com/>
- Arize Phoenix. <https://phoenix.arize.com/>
- Helicone. <https://www.helicone.ai/>
- LangSmith. <https://www.langchain.com/langsmith>
- Promptlayer. <https://promptlayer.com/>
- W&B Weave. <https://wandb.ai/site/weave>
- Spheron survey of self-hostable observability platforms.
  <https://www.spheron.network/blog/llm-observability-gpu-cloud-langfuse-arize-phoenix-helicone/>
- Latitude — agent observability comparison (2026).
  <https://latitude.so/blog/best-llm-observability-tools-agents-latitude-vs-langfuse-langsmith>

### AI / Agent incident corpus (2024-2026)

- Aim Labs / Aim Security — EchoLeak (CVE-2025-32711) original disclosure.
  <https://www.aim.security/post/aim-labs-discloses-echoleak-cve-2025-32711-a-novel-attack-on-microsoft-365-copilot>
- HackTheBox CVE-2025-32711 / EchoLeak technical writeup.
  <https://www.hackthebox.com/blog/cve-2025-32711-echoleak-copilot-vulnerability>
- Securiti — EchoLeak indirect-prompt-injection analysis.
  <https://securiti.ai/blog/echoleak-how-indirect-prompt-injections-exploit-ai-layer/>
- arxiv 2509.10540 — *EchoLeak: The First Real-World Zero-Click Prompt
  Injection Exploit in a Production LLM System*.
  <https://arxiv.org/html/2509.10540v1>
- Trend Micro — EchoLeak preventing zero-click AI threats.
  <https://www.trendmicro.com/en_us/research/25/g/preventing-zero-click-ai-threats-insights-from-echoleak.html>
- Zenity Labs — AgentFlayer ChatGPT Connectors zero-click.
  <https://labs.zenity.io/p/agentflayer-chatgpt-connectors-0click-attack-5b41>
- HackRead — AgentFlayer summary.
  <https://hackread.com/agentflayer-0-click-exploit-chatgpt-connectors-steal-data/>
- The Hacker News — ShadowLeak ChatGPT Deep Research disclosure.
  <https://thehackernews.com/2025/09/shadowleak-zero-click-flaw-leaks-gmail.html>
- The Record — OpenAI ShadowLeak fix.
  <https://therecord.media/openai-fixes-zero-click-shadowleak-vulnerability>
- Microsoft Security Blog — AI Recommendation Poisoning advisory
  (February 2026).
  <https://www.microsoft.com/en-us/security/blog/2026/02/10/ai-recommendation-poisoning/>
- Help Net Security — AI Recommendation Memory Poisoning summary.
  <https://www.helpnetsecurity.com/2026/02/11/ai-recommendation-memory-poisoning-attacks/>

### Agent behavioral baselining and AI-SOC

- ARMO — Detecting Intent Drift in AI Agents with Runtime Behavioral Data.
  <https://www.armosec.io/blog/detecting-intent-drift-in-ai-agents-with-runtime-behavioral-data/>
- ARMO — AI Workload Baseline and Drift Detection.
  <https://www.armosec.io/blog/ai-workload-baseline-drift-detection/>
- arxiv 2505.24201 — *SentinelAgent: Graph-based Anomaly Detection in
  LLM-based Multi-Agent Systems*.
  <https://arxiv.org/html/2505.24201v1>
- Galileo — Real-Time Anomaly Detection for Multi-Agent AI Systems.
  <https://galileo.ai/blog/real-time-anomaly-detection-multi-agent-ai>
- Wiz — AI-Powered Behavioral Analytics.
  <https://www.wiz.io/academy/detection-and-response/ai-powered-behavioral-analytics>
- Dropzone AI (AI SOC analyst). <https://www.dropzone.ai/>
- Prophet Security (Agentic AI SOC platform).
  <https://www.prophetsecurity.ai/>
- Radiant Security (Adaptive AI SOC). <https://radiantsecurity.ai/>
- Radiant Security — Best AI SOC for Enterprise (2026 roundup).
  <https://radiantsecurity.ai/learn/best-ai-soc-for-enterprise-top-5-options-in-2026/>

### Florian Roth / Nextron

- Nextron blog. <https://www.nextron-systems.com/author/florian/>
- Sigma writing guide.
  <https://www.nextron-systems.com/2018/02/10/write-sigma-rules/>

### Cross-references (within this repo)

- [`semgrep_rule_authoring.md`](../static_analysis/semgrep_rule_authoring.md) — static-analysis sibling discipline.
- [`workflow_authoring.md`](../static_analysis/workflow_authoring.md) — AI-augmented static-analysis workflow design.
- [`active_directory_windows_security.md`](./active_directory_windows_security.md) — Kerberos / NTLM / DPAPI detection content.
- [`distributed_authz_expertise.md`](./distributed_authz_expertise.md) — access-decision logging and identity-perimeter detection.
- [`llm_agent_security_expertise.md`](./llm_agent_security_expertise.md) — detection patterns for LLM applications and memory-poisoning offense (§2.5).
- [`agentic_web_capabilities_expertise.md`](./agentic_web_capabilities_expertise.md) — agent-runtime code review and capability-discipline detection (§10).
- [`adversarial_ml_model_security_expertise.md`](./adversarial_ml_model_security_expertise.md) — static + runtime detection of ML attacks (§12), offensive complement to §10 of this doc.
- [`anti_fraud_abuse_engineering_expertise.md`](./anti_fraud_abuse_engineering_expertise.md) — bot-detection literature applied to agent traffic.
- [`game_theory_mechanism_design_security_expertise.md`](./game_theory_mechanism_design_security_expertise.md) — red-vs-blue repeated-game dynamics in agent runtime.
- [`vulnerability_research_methodology_expertise.md`](./vulnerability_research_methodology_expertise.md) — offensive cousin of threat hunting.
- [`code_review_expertise.md`](./code_review_expertise.md) — candidate-point methodology that maps onto hunt hypotheses.
- [`cicd_supply_chain_expertise.md`](./cicd_supply_chain_expertise.md) — ephemeral-runner detection and supply-chain telemetry.
- [`appsec_program_building_expertise.md`](./appsec_program_building_expertise.md) — engineering empathy and org-design of security functions.
- [`ai_pr_review_platform_expertise.md`](./ai_pr_review_platform_expertise.md) — AI-PR-review platform comparative analysis; primary source of the incident corpus consumed by §10.10 rules.
- [`ai_assisted_coding_tool_security_expertise.md`](./ai_assisted_coding_tool_security_expertise.md) — IDE-AI-coding-tool threat surface and 10-CVE 2025 corpus; §9 covers the AI-PR-review threat model that §10.10 rules detect.

## Document Cross-Links Updated 2026-05-15

- Added §10.10 — six concrete Sigma/KQL/SPL detection rules for AI-PR-review compromise patterns, anchored on PwnedRabbit, Clinejection (GHSA-9ppg-jx86-fqw7), Comment-and-Control (CVSS 9.4), CurXecute (CVE-2025-54135), and EchoLeak (CVE-2025-32711) incidents.
- New cross-references added to `ai_pr_review_platform_expertise.md` and `ai_assisted_coding_tool_security_expertise.md`; rules anchored on the OpenTelemetry GenAI semconv (`gen_ai.*`) substrate documented in §10.1.

---

*Last reviewed: 2026-05-14. Maintained against MITRE ATT&CK v14, MITRE ATLAS
(AML.T0080 Memory Poisoning), SigmaHQ rule corpus, OCSF v1.x, OpenTelemetry
Semantic Conventions for Generative AI Systems (in-development as of May
2026), the AI-runtime incident corpus through May 2026 (EchoLeak,
AgentFlayer, ShadowLeak, AI Recommendation Poisoning), and Sysmon
configuration baselines from SwiftOnSecurity, ION-Storm, and Olaf Hartong's
sysmon-modular.*
