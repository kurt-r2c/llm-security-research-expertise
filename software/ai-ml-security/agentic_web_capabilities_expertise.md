# Capability-Based Security and Agentic Runtimes — Doctrine, History, Application
## Synthesized from Jack Dennis & Earl Van Horn, Norm Hardy, Mark S. Miller, Jonathan Shapiro, Gernot Heiser & the seL4 team, Robert Watson, Marc Stiegler, Jed Donnelley, Lin Clark & the Bytecode Alliance, and Kurt Boberg

> **Researchers and primary sources:**
>
> - **Jack B. Dennis** and **Earl C. Van Horn** (MIT Project MAC). "Programming Semantics for Multiprogrammed Computations," *CACM* 9(3), March 1966 — the paper that named the *capability* and defined the **C-list** as a process's "sphere of protection." Every subsequent capability-systems paper cites this one.
> - **Norm Hardy** (Tymshare, Key Logic). Co-architect of GNOSIS and KeyKOS. "The Confused Deputy (or why capabilities might have been invented)," *ACM SIGOPS OSR* 22(4), 1988 — the canonical security argument, written from scar tissue: the 1977 incident where a privileged FORTRAN compiler at Tymshare was tricked into corrupting billing records. Lineage figure of practical capability computing; maintained `cap-lore.com`.
> - **Mark S. Miller** (Agoric, ECMA TC39, formerly Google Research, JHU PhD 2006). Principal designer of the **E language**; co-author with K. Eric Drexler of the 1988 Agoric Open Systems papers; dissertation *Robust Composition* (JHU, 2006). Co-introduced **ambient authority**. Co-author of "Capability Myths Demolished" with Ka-Ping Yee and Jonathan Shapiro. The modern theorist of object-capability systems.
> - **Jonathan S. Shapiro** (JHU, formerly UPenn). Principal architect of **EROS** (1991-2005) and successor **Coyotos**. Demonstrated capability OSes can match monolithic kernel performance — the "fast capability system" rebuttal.
> - **Gernot Heiser** and the **seL4 team** (UNSW Sydney; Trustworthy Systems). Co-lead with Gerwin Klein of the seL4 verification project. seL4 is a capability-based L4 microkernel formally verified from abstract spec to C — the first general-purpose OS kernel formally proven functionally correct. SOSP 2009 paper won SIGOPS Hall of Fame in 2019.
> - **Robert N. M. Watson** (Cambridge Computer Lab, FreeBSD). Lead author of "Capsicum: Practical Capabilities for UNIX" (USENIX Security 2010, with Anderson, Laurie, Kennaway) — Best Student Paper. Capsicum shipped in FreeBSD 9.0; the canonical retrofit onto POSIX. Continues in CHERI — DARPA-funded capability extensions driven to silicon (Arm Morello, 2022).
> - **Marc Stiegler** (HP Labs, E community). Author of Polaris and *Rich Sharing for the Web*. Long-time evangelist for the practical case that users *can* handle capability prompts with the right UX (CapDesk).
> - **Jed Donnelley** (Lawrence Livermore). Architect of **NLTSS**, one of the earliest *networked* capability systems — capabilities passed across machine boundaries in the early 1980s. Lineage figure connecting OS to distributed-capability discipline.
> - **Lin Clark** (Fastly Senior Principal Engineer, co-founder Bytecode Alliance). Communicator of the Component Model and WASI via Mozilla Hacks "Standardizing WASI" and *Code Cartoons*. Bytecode Alliance (Mozilla, Fastly, Intel, Red Hat) shipped WASI Preview 2 in January 2024 with the Component Model and WIT — the first widely-deployed capability-typed composition substrate in 30 years.
> - **Kurt Boberg** (`@lapt0r`, Semgrep Staff Security Researcher). Author of "Security Like It's 1977: Capabilities for the Modern Agentic Web" (semgrep.dev/blog, 28 January 2026) — the post this doc is in dialogue with. Prior posts: "A Security Engineer's Guide to MCP" (29 Sept 2025) and "A Security Engineer's Guide to the A2A Protocol." Cross-link to [[reference-llm-agent-security]] for the agent-runtime attack catalog; this doc is the doctrine.
> - **The MCP Working Group** (modelcontextprotocol.io; spec maintainers including Den Delimarsky, Aaron Parecki, and the broader Anthropic / community contributors). Maintainers of the MCP authorization spec (2025-11-25 revision) and the tool-annotations specification (2025-03-26 revision). The November 2025 spec requires OAuth 2.1, RFC 8707 audience binding (required since the 2025-06-18 revision), and PKCE with S256 when technically capable; the tool annotations are explicitly framed by the MCP blog as "risk vocabulary" not enforcement.
> - **The Bytecode Alliance + WASI Subgroup** (Lin Clark, Luke Wagner, Dan Gohman, Pat Hickey, Joel Dice, others). Shipped WASI Preview 2 + Component Model 1.0 features in January 2024; WASI 0.3 native-async preview targeted August 2025 with completion targeting November 2025. The reference substrate for capability-typed agent runtimes.
> - **Microsoft Hyperlight team** (Open Source / Azure incubation). Released Hyperlight Wasm in March 2025 as a CNCF Sandbox project; 1-2 ms cold-start hardware-isolated micro-VMs running WebAssembly components. The production rebuttal to "capabilities are slow" at agent-runtime cold-start latency.
> - **The Apple Private Cloud Compute team** (Apple Security Engineering and Architecture). Published the PCC security guide, transparency log, attestation framework, and Virtual Research Environment (VRE) for external research. Production capability-typed AI cloud with publicly-auditable code-running attestation.
> - **Trail of Bits** (Adelin Travers). Author of the June 2024 PCC analysis "Bold step forward, not without flaws" — the canonical independent assessment, naming both the design strengths (Secure Enclave + Secure Boot + compiled-Swift + non-targetability) and the bounded-attestation limitation.
> - **Anthropic Agent Skills team** (the Anthropic engineering teams). Released Agent Skills in October 2025 with an open standard in December 2025; published the three-tier progressive-disclosure loading model. Capability-shaped at the context-exposure layer; not yet at the runtime-authority layer.
> - **The UCAN Working Group, Eclipse Biscuit project, and SPIFFE/SPIRE community.** Maintainers of the three production-credible capability-token / capability-identity formats; Biscuit is now an Eclipse Foundation project.
> - **Palo Alto Networks Unit 42** (Yongzhe Huang, Akshata Rao, Changjiang Li, Yang Ji, Wenjun Hu). Published "New Prompt Injection Attack Vectors Through MCP Sampling" on 5 December 2025, documenting the structural capability-discipline gap in MCP's bidirectional sampling protocol.
>
> Sources: ACM DL (Dennis-Van Horn 1966, Hardy 1988, Klein et al. seL4 2009); papers.agoric.com; cap-lore.com; erights.org; cl.cam.ac.uk/research/security/capsicum/; sel4.systems; component-model.bytecodealliance.org; webstart.com/jed/; modelcontextprotocol.io/specification/2025-11-25/; opensource.microsoft.com/blog/; wasmcloud.com/blog/; security.apple.com/blog/; blog.trailofbits.com/; anthropic.com/engineering/; ucan.xyz; biscuitsec.org; spiffe.io; unit42.paloaltonetworks.com; semgrep.dev/blog/2026/security-like-its-1977-capabilities-for-the-modern-agentic-web/.

---

## 1. Why "Security Like It's 1977"

The thesis of Kurt Boberg's January 2026 Semgrep post is unsentimental:

> "The agentic web has a security problem, and we first proposed the solution forty-nine years ago." (Boberg, 2026)

The post is anchored in a 1977 Tymshare incident. A FORTRAN compiler had write access to `SYSX` for statistics. Users could specify debug output files. "Someone eventually realized they could specify `(SYSX)BILL` as a debug output target." The compiler dutifully wrote, because access was decided on *who the compiler was*, not *what it was asked to do*. The user could not write to billing records. The compiler could. The compiler did, on the user's instruction. This is the *confused deputy*: an authorized program induced to misuse its authority for an unauthorized principal.

Boberg's argument is that this is the same bug AI agents have today:

> "More concretely, the compiler's permissions were determined by *who it was*, not *what it was asked to do*." (Boberg, 2026)
>
> "Identity-based access control fundamentally cannot express 'do this, but only for this purpose, using only this authority.' Capabilities can." (Boberg, 2026)

An MCP-host LLM is a deputy. It serves the user. It also serves every system operator of every MCP server it has connected to. It has *ambient authority* — the union of every credential it holds in the session. When prompt injection arrives via a retrieved email body or scraped page, the injection becomes an instruction from a third principal, and the deputy cannot tell whose authority should govern the action. The agent acts under the user's identity. The blast radius is the union of every tool the agent has access to.

> "Word can do *anything you can do*. Send your files to Macedonia. Encrypt your disk. Delete your tax returns." (Boberg, 2026)
>
> "The consequences of this sort of 'identity transference' to an LLM agent is *bonkers*." (Boberg, 2026)

The structural fix is the **capability**: a single unforgeable token that *both designates a resource and authorizes a specific operation on it*. The slogan: *designation equals authority*. There is no ambient set of "things this program can do" — only the set of capabilities the program currently holds.

> "A capability is a single unforgeable token that both *designates* a resource and *authorizes* access to it. You can't name something you can't touch." (Boberg, 2026)
>
> "No ambient authority. No identity questions. No confused deputies." (Boberg, 2026)

Why now: agent runtimes are the first new computing layer in three decades where capability discipline is *necessary by construction*, not just elegant. In a workstation OS, ambient authority is a tolerated trade-off — the user trusts the programs. In a server environment, ambient authority is mitigated by network segmentation and process isolation. In an *agent* runtime, neither mitigation applies: the agent is a probabilistic instruction-follower, given a tool catalog by an operator, exposed to arbitrary untrusted content. Every byte is potentially an instruction. The defender's only structural option is to bound what authority any given instruction can exercise. Filter-based defenses fail because the filter is part of the same untrusted-data plane the model evaluates.

Cross-link to [[reference-llm-agent-security]] §1 on the three trust boundaries: the model↔tools boundary is exactly the confused-deputy boundary. Cross-link to [[reference-steelman-doctrine]] for the discipline of treating "we proposed the solution 49 years ago" as a Champion claim and surfacing the strongest Foil — Section 9 does that.

> "The agentic web **will** rediscover this the hard way, unless we take early, thoughtful action." (Boberg, 2026)

This doc is the doctrine layer. The technique catalog lives in [[reference-llm-agent-security]]; the application-layer authz bestiary in [[reference-distributed-authz]]. This file is the *why*.

---

## 2. The Capability Systems Lineage, 1966-2026

The intellectual history is well-documented but rarely consolidated. The shape of the argument has been stable for sixty years; only the deployment substrate has changed.

### 2.1 Dennis and Van Horn (MIT, 1966): the primitive

Dennis and Van Horn's "Programming Semantics for Multiprogrammed Computations" (*CACM* 9(3), March 1966) defines a model in which every process carries a **C-list** enumerating resources — memory segments, devices, other processes — it is permitted to operate on. Capabilities are first-class: passable between processes, used to construct subprocesses with strictly-attenuated authority, revocable through destruction of the object they name.

The conceptual move was treating *access to a resource* and *the name of the resource* as the same object. The capability is the name; possession is the access. A process cannot ask for an operation on a resource it cannot name. The C-list IS the security policy. The motivation was structural cleanliness for multiprogramming. The fact that the same model is the right one for adversarial environments was discovered later, and rediscovered repeatedly.

### 2.2 Plessey System 250 (1972) and IBM System/38 (1978): hardware capabilities ship

Plessey System 250 was the first commercial computer to implement capability-based addressing in hardware, shipped circa 1972. PP250 had eight 48-bit capability registers; every memory access was capability-gated by hardware. The PP250 served in Ptarmigan (British Army tactical packet-switched comms, first Gulf War). IBM System/38 (announced 1978, shipped 1980) brought capability addressing to commercial business platforms via 16-byte tagged pointers; the lineage continued through AS/400, iSeries, and modern IBM i, still running production banking and ERP.

Lesson: capability systems are not a thought experiment. They have shipped in production for high-reliability and high-integrity workloads. The "academic" claim has been falsified by 50 years of operational history.

### 2.3 Tymshare GNOSIS / Key Logic KeyKOS (late 1970s - 1980s)

Hardy at Tymshare built GNOSIS (post-acquisition: KeyKOS at Key Logic) as a capability OS for commercial timesharing. KeyKOS was deployed in production with the resilience properties capabilities enable — fine-grained authority decomposition, structural rollback, transparent persistence from the capability graph.

Hardy's "Confused Deputy" paper (1988) is the canonical security argument. ACL-based systems give every program the union of its caller's authority; the program cannot reliably distinguish "the operation for caller A using A's authority" from "the operation for caller A using *my own* authority that I have because of who I am." Capability systems force the distinction — every operation names the authority exercised by virtue of the capability passed in.

### 2.4 NLTSS (LLNL, early 1980s): capabilities cross machines

Donnelley's NLTSS was a capability system that extended capabilities across network boundaries — a client-server network operating system using password capabilities. Precursor to the Miller-Tribble distributed-capability discipline. Lesson for the modern agentic web: capabilities are coupled to an *unforgeable-reference* primitive, not to a single OS kernel. When carried across boundaries by signed tokens or trusted introducers, the discipline extends naturally to distributed systems. NLTSS is more directly applicable to MCP and A2A than any single-machine capability OS pattern.

### 2.5 The E language and the object-capability tradition (1990s)

Miller's E language reframed capabilities from an OS primitive into a *language* primitive. Every object reference is a capability; references cannot be synthesized, only received; possession is authority to invoke methods. Authority transfers by passing references, attenuates by wrapped references exposing subsets, revokes by destroying the wrapper.

This is the **object-capability (OCAP)** model. Key insight: an OO language with strong encapsulation (no static globals, no ambient namespace, no reference-synthesizing `eval`) is *already* a capability system if the runtime enforces "no synthesis" structurally. Caja and SES brought it to JavaScript; Cap'n Proto RPC to cross-process RPC; Spritely Goblins to networked services. Modern JavaScript with `Object.freeze`, `Proxy`, and SES Compartments is *very nearly* capability-compatible. Agent runtimes are mostly built on JavaScript and Python; the discipline can come along.

### 2.6 Java Security Manager (1997-2024): the cautionary tale

Java's **SecurityManager** model — every privileged operation calls into a global arbiter consulting a policy file based on the call-stack's class-loader chain. Failed because: stack-walking was fragile (confused-deputy bypasses, hundreds of CVEs); policy files were out-of-band (Java code and XML policy went out of sync); `AccessController.doPrivileged` became universal (any developer who needed something to "just work" elevated to system authority); deprecated JDK 17, permanently disabled JDK 24 — 25 years demonstrating that ambient-authority security cannot be retrofitted onto a language whose reference semantics are not capability-shaped.

Lesson for agents: *policy-as-config* is the wrong answer to ambient authority. Cross-link to [[reference-llm-agent-security]] §6 on why MCP's "tool descriptions are advisory; the host should decide" is structurally identical and will fail for the same reasons.

### 2.7 EROS, Coyotos, Capsicum, seL4 (1991-2009+)

**EROS** (Shapiro, UPenn/JHU, 1991-2005) was a *fast* capability microkernel demonstrating the 1990s "capabilities are slow" claim was false. Persistent state from the capability graph; performance comparable to monolithic UNIX. **Coyotos** was the planned successor, designed for formal verification with BitC. Shapiro's contribution: by 2005, "capability OSes can be both fast and formally analyzable" was no longer speculative.

**Capsicum** (Watson et al., FreeBSD, USENIX 2010) retrofitted capability discipline onto POSIX. A process starts in normal POSIX mode, opens the descriptors it needs, calls `cap_enter()` to drop into capability mode, and operates only on those. Shipped in FreeBSD 9.0; deployed in utilities (tcpdump, kdump); ported to Linux. Lesson for agents: even without native capability typing, you can *enter* capability mode after gathering resources for a task.

**seL4** (Heiser, Klein, UNSW, 2009+) is the first general-purpose OS kernel formally verified end-to-end — Isabelle/HOL abstract spec to C to binary refinement. Capabilities are unforgeable kernel objects; every operation is mediated through a handle; capabilities can be derived, copied with reduced rights, revoked, audited. seL4 ships in DARPA HACMS avionics, automotive, satellite payloads. Agent relevance: seL4 is what a host underneath a high-assurance agent looks like. Agent in WASI sandbox; sandbox on capability-typed host; kernel is seL4 — unbroken capability chain. DARPA has funded prototypes; what's missing is the agent-runtime tier.

### 2.8 The WebAssembly Component Model and WASI Preview 2 (2024+)

The Bytecode Alliance shipped WASI Preview 2 in January 2024 with the Component Model and WIT (WebAssembly Interface Types). The design is explicitly capability-typed: a component declares its imports (capabilities consumed) and exports (capabilities provided); the runtime composes by binding imports to exports; no ambient authority is reachable without an explicit capability grant from the composer.

This is the first widely-deployed *program-composition* capability substrate since E. Every major language (Rust, Go, C, Python, JavaScript, Java) is gaining Component Model bindings. WIT is a small, capability-typed IDL; components composed via WIT are necessarily composed via capabilities; the discipline is enforced by the compiler and runtime, not by developer politeness. Cross-link to Section 7 for agent-runtime application.

### 2.9 CHERI and Arm Morello (Cambridge / SRI, 2010+; Morello silicon 2022)

CHERI (Capability Hardware Enhanced RISC Instructions) is the descendant of Plessey-and-System/38. Cambridge and SRI International, DARPA-funded, designed capability extensions to RISC ISAs (MIPS, RISC-V, ARMv8-A) where pointer values include base/bounds/permissions and are *unforgeable in hardware*. Arm shipped Morello — a CHERI-extended ARMv8 prototype — in 2022. CHERI is not yet deployed in agent-runtime hosts but represents the *bottom* of the capability stack. The discipline composes vertically.

### 2.10 The 1966-2026 arc

Sixty years from the C-list to the Component Model. The argument has not changed. The implementation substrate has changed twice (hardware → OS → language → component). The deployment niches have shifted (multiprogramming; commercial timesharing; banking ERP; avionics; web-scale composition; agent runtimes). What has remained constant: *ambient authority is a denormalization of access control*, and like all denormalizations, it makes the table smaller but the bugs larger.

### 2.11 Capabilities production state, 2024-2026

The 2024-2026 period is the first in three decades where capability-typed substrates ship at production scale in multiple independent niches simultaneously. The doctrinal claim "capabilities are deployable" is no longer a 1990s folk theorem; the deployment evidence is in.

- **WASI Preview 2 + Component Model 1.0** (January 2024 onward). The Bytecode Alliance shipped WASI Preview 2 (also called WASI 0.2) in January 2024, finalizing the Component Model "major features" with the addition of capability-typed `resource` declarations in WIT. WASI 0.3 began the native-async refactor with a preview targeting August 2025 and completion targeting November 2025 (https://progosling.com/en/dev-digest/2025-08/wasi-0-3-native-async-aug-2025; https://wasi.dev/). Spin v3.5 shipped first WASIp3 RC support in November 2025 (https://thenewstack.io/hyperlight-wasm-azure-goes-the-final-wasi-mile/).
- **Production wasmCloud / Spin / Cosmonic / Fastly Compute deployments.** wasmCloud 1.0 brought WASI 0.2 and the Component Model to enterprise production in March 2024 (https://blog.cosmonic.com/engineering/wasmcloud-1-brings-components-to-enterprise/). Public references include Adobe and BMW.
- **Microsoft Hyperlight Wasm** (March 2025). Microsoft released Hyperlight Wasm — a hardware-isolated micro-VM ("micro-guest") for running WebAssembly *components* — under the CNCF Sandbox program (onboarded February 2025). 1-2 ms boot vs. ~125 ms for traditional VMs; dual-layer sandbox (Wasm + VM); explicitly designed for serverless and agentic workloads (https://opensource.microsoft.com/blog/2025/03/26/hyperlight-wasm-fast-secure-and-os-free/). The architecture exemplifies the capability-typed-composition discipline at production cold-start latency, which directly rebuts §9.1's "capabilities are slow" objection in the agent-runtime context.
- **wasmCloud + SPIFFE/SPIRE adoption** (March 2025). wasmCloud announced SPIFFE adoption for WebAssembly workload identity, binding component-model workloads to SPIFFE Verifiable Identity Documents (SVIDs) as JWTs or X.509 certificates within a trust domain (https://wasmcloud.com/blog/2025-03-04-why-were-adopting-spiffe-for-webassembly-workload-identity/). This is the cross-vendor, cross-substrate identity layer the capability-attribution audit trail of §8.3 was missing in 2010-2024. CNCF graduated both SPIFFE and SPIRE; in 2024 the IETF chartered a "Workload Identity in Multi System Environments" (WIMSE) working group with SPIFFE as the reference open-source representation.
- **Apple Private Cloud Compute** (June 2024 → continuing). The capability-typed cloud has shipped: PCC publishes measurements of all production code in an append-only cryptographically tamper-proof transparency log; node attestations validated by CloudAttestation and Thimble. Apple's Virtual Research Environment (VRE) launched in late 2024 lets external researchers list and inspect releases, verify log consistency, boot releases in virtual environments, and inspect a virtual Secure Enclave Processor (https://security.apple.com/blog/pcc-security-research/; https://security.apple.com/documentation/private-cloud-compute/inspectingreleases). Apple Security Bounty added PCC categories. Trail of Bits' independent analysis (June 2024) called the design "exceptional" — Secure Enclave + Secure Boot ensures only legitimate code runs; compiled Swift over dynamic languages avoids whole runtime attack classes; non-targetability is "an interesting design idea that hasn't been applied to ML before" — while flagging that attestation is bounded by "Apple effectively owns[ing] the attestation keys" and that PCC does not advance homomorphic encryption (https://blog.trailofbits.com/2024/06/14/pcc-bold-step-forward-not-without-flaws/).
- **Anthropic Claude Agent SDK + Skills + Plugins** (October-December 2025). Anthropic released Agent Skills in October 2025 with an open standard published in December 2025; Skills are directories containing a `SKILL.md` plus scripts and resources that the agent loads dynamically through three-tier progressive disclosure: metadata into system prompt at startup, primary `SKILL.md` content on task-match, supplementary files on demand (https://www.anthropic.com/engineering/equipping-agents-for-the-real-world-with-agent-skills; https://platform.claude.com/docs/en/agents-and-tools/agent-skills/overview). Plugins extend this with namespaced skill collections shareable across projects (https://platform.claude.com/docs/en/agent-sdk/plugins). The Skills loading model is *capability-shaped at the disclosure layer* — context exposure is attenuated by relevance — but the runtime authority model is not yet a formal capability system; Anthropic's published guidance to "install skills only from trusted sources" is the same admission MCP makes for tools. The structural fix is the same: per-skill capability declarations enforced by the host, not by the model and not by reviewer politeness.

The aggregate pattern is consistent. Substrate is solving the hard problem (Component Model, WASI 0.3 async, Hyperlight micro-VMs, SPIFFE identity, PCC transparency log). The *agent-runtime* tier — Skills, plugins, MCP tools — still ships with ambient defaults. The doctrinal task in 2026 is to close the gap, not to invent new substrate.

---

## 3. Foundational Concepts

The capability literature has a small vocabulary of structural primitives.

### 3.1 Ambient authority

Authority a program has by virtue of *who is running it*, available without being passed in:
- UNIX process has ambient authority to read every file the user can read — `open(2)` consults UID and mode bits.
- JavaScript in a browser has ambient authority to `fetch` to any CORS-permitted origin — `fetch` is a global rooted in the page's origin.
- MCP client process has ambient authority to invoke every tool every connected server publishes — flat namespace, no per-tool capability check beyond the install.

Defining property: the program could have obtained the authority *without anyone deciding to give it that specific authority for this specific operation*. This is what makes confused-deputy possible.

### 3.2 Capability-bearing authority

Authority a program has by virtue of *holding a specific capability* — an unforgeable reference binding a designated resource to an authorized operation. The capability was granted by a specific principal at a specific time for a specific purpose. The audit trail is the capability's provenance chain.

> "Agents receive capabilities, not credentials." (Boberg, 2026)

Credentials (API keys, OAuth tokens, session cookies) are *bearer authentication* — anyone holding them performs any operation the credential's principal is permitted. Capabilities are *bearer authorization with attenuation* — holding authorizes a specific operation on a specific resource, and cannot be amplified.

### 3.3 Designation equals authority

Miller-Tribble slogan. The act of naming a resource is the same act as authorizing operations on it. No separate access check downstream of the name. If the program holds the name, it holds the authority. The check is implicit in the type system or kernel mediation.

Cross-link to [[reference-distributed-authz]] §2: Zanzibar-style relationship tuples are the distributed-systems version of capability designation — the tuple `(resource, relation, principal)` IS the authority. The patterns rhyme.

### 3.4 Decomposition and attenuation

Every capability is decomposable into capabilities with strictly less authority. Directory → single file; read-write → read-only. Derivation is one-way; you cannot synthesize a more-authoritative capability. This is the *POLA enabler*: always pass less than you hold, never accidentally more.

**Attenuation** is a specific decomposition case: passing a capability that authorizes a *subset* of operations or resources. Boberg:

> "If the task is summarization, the capability permits reading, not writing." (Boberg, 2026)

This is what OAuth scope grants cannot express. OAuth scopes are session-wide; the discipline says capability grants should be *task-scoped* and die with the task.

### 3.5 Revocation

Capabilities can be revoked. EROS/KeyKOS: destroying the parent invalidates children. Object-capability languages: revocable forwarders (a wrapper that forwards calls, severable by destruction). Token-based systems: server-side invalidation or published revocation lists.

> "When the task completes, the capability dies." (Boberg, 2026)

Revocation closes the temporal blast radius. Even if leaked (prompt injection, compromised server, logging mistake), the leak's value is bounded by remaining lifetime. Task-scoped capabilities have very short lifetimes by construction.

### 3.6 POLA, distinct from POLP

POLP — Principle of Least *Privilege* — is the *operational* version: configure each program with minimum permissions. RBAC tightness, scoped API tokens, narrow UNIX groups. A recurring negotiation; often resolved in the developers' favor because excessive privilege is invisible until exploited.

POLA — Principle of Least *Authority* — is the *structural* version: design the system so each program *cannot* hold authority beyond what it needs, because the only way to acquire authority is to receive a capability. POLA is enforced by the runtime, not by configuration. POLA-compliant code looks different — it takes capabilities as arguments instead of looking them up ambiently.

The distinction matters: POLP applied to MCP tool installation is reactive ("don't install too many tools"). POLA applied to MCP tool *invocation* is proactive ("the model can invoke only the capabilities the orchestrator currently holds, scoped to the current task").

### 3.7 Confinement and the Granovetter operator

**Confinement** (Lampson, 1973; refined by Miller): a confined program cannot transmit information to an unauthorized principal *except through capabilities it has been explicitly granted for that purpose*. Default is no-transmission; transmission channels are themselves capabilities.

The **Granovetter operator** is Miller's name for the introduction primitive: when A holds a capability for B, and A passes it to C, then C now holds it. The name comes from sociologist Mark Granovetter's "Strength of Weak Ties" — capability ties propagate the way social ties do, by transitive introduction. An A2A capability handshake is structurally a Granovetter introduction.

---

## 4. Why Ambient Authority Is Bad for Agents

The Unix/POSIX model assigns every process the user's full ambient authority. Fine for the original use case (single-user, trusted-program workstations). It does not survive the move to agent runtimes.

### 4.1 The chain of ambient authority

Trace the chain for a typical MCP host:

1. User logs in. OS grants the user-session the union of the user's ambient authority — files, network, credentials.
2. User runs the MCP host (Claude Desktop, Cursor, VS Code+Continue). The host inherits everything.
3. The host spawns MCP server subprocesses. Each inherits the host's authority. The Slack server can read `~/.ssh/id_rsa`. The Postgres server can write to `~/.aws/credentials`.
4. Host loads the model. Tool catalogs are flattened into context. Model has no capability metadata — only descriptions, themselves a prompt-injection vector ([[reference-llm-agent-security]] §3.1).
5. User makes a request. Model picks a tool and arguments. The invocation runs in the server subprocess, exercising the user's full ambient authority.

At step 5, the agent is exactly Hardy's FORTRAN compiler. It serves the user. It also serves whoever wrote the tool description and whoever wrote the email it just summarized. The operation is determined by *whichever principal in the context window the model happened to follow at that token*.

> "Prompt injection in email → can invoke shell." (Boberg, 2026)

The agent runtime is the first programming environment where the principal whose authority is exercised is *determined by the content of untrusted strings*. Structural, not an implementation bug.

### 4.2 The OAuth illusion

Boberg's post argues OAuth's session-wide scopes do not solve the problem they appear to. OAuth grants are *consent-time* (one click, session-long retention); *not* per-action; *not* attenuable to task (same `slack:write` for `#alerts` summary and `#attacker-channel` exfiltration); *not* short-lived enough (refresh tokens stretch across hours/days). OAuth provides the *appearance* of capability-style management without the *substance*.

> "Agents receive capabilities, not credentials." (Boberg, 2026)

A bearer credential is a capability *only if* it's narrow, attenuated, and short-lived enough that exercise is bounded to its intended operation. OAuth tokens, as deployed, are none of those.

### 4.3 Tool authority accumulation

With 5-20 MCP servers connected (typical), the agent accumulates the *union* of their ambient authority. The user did not intend Slack's authority to compose with Postgres's; once installed, they compose. Prompt injection in any tool's output can invoke any other tool, with the union of authorities. Capability discipline forces composition to be *explicit*: a "summarize-and-post" task gets the capability to read the document and the capability to send to a specific channel — and nothing else. Cross-link to [[reference-llm-agent-security]] §1: capability discipline is what makes Willison's lethal trifecta defusable.

### 4.4 The deputy problem, restated for agents

The classic confused deputy serves two masters. The agent confused deputy serves *every principal in the context window simultaneously*, and principal-attribution is made by sampling at every token boundary. The model is *not* trying to be a confused deputy — it is structurally incapable of *not* being one. Capability discipline removes the problem structurally: the agent holds only the capabilities granted for the current task; whatever the model decides is bounded by those capabilities.

> "You cannot trust an LLM to color inside the lines." (Boberg, 2026)

So don't draw lines. Build walls.

---

## 5. Capabilities Applied to AI Agents — the Design Space

If you accept Sections 1-4, the practical question is: *what does a capability-disciplined agent runtime look like?* This section enumerates the design moves and ties each to Boberg's 2026 recommendations.

### 5.1 Tool capabilities

Each tool is a capability. The agent doesn't have access by virtue of installation; it has access by virtue of the orchestrator handing it a capability scoped to the task. Treat registered MCP servers as a *capability pool*, not the agent's catalog. "Summarize my recent emails" gets `gmail:read_messages` and `display_text` — not `slack:send`, `postgres:query`, or `shell:execute`. "Send the summary to #standup" adds `slack:send_to_channel(#standup)` and nothing else. Orchestrator is the gatekeeper. Cross-link to [[reference-llm-agent-security]] §4 on orchestrator/executor split.

### 5.2 Resource capabilities

The Capsicum pattern: host opens the file in ambient mode, passes the descriptor, tool operates in capability mode without synthesizing new descriptors.

- **Files**: `/var/log/app.log:read` handle. Tool cannot read `/etc/passwd` regardless of prompt-injected arguments.
- **Databases**: *prepared-statement capabilities* — host issues prepared statements and passes *result handles*. Tool iterates rows; cannot issue new queries.
- **Network**: *destination-scoped fetch* — `fetch(https://api.example.com/v1/orders/12345)`. No capability for `attacker.example.org` in the task's set.

### 5.3 Action capabilities

Side-effecting invocations *parameterized at construction*:

- `send_slack_to(#standup, body)` — body fillable; channel bound.
- `send_email_from(alice@example.com, to=bob@example.com, subject, body)` — bound recipient.
- `transfer_funds(from=acct123, to=acct456, amount_at_most=$100)` — attenuation on amount.

Model decides *content*; capability bounds *destination, action, magnitude*.

### 5.4 Time-bounded capabilities

Lifetimes — intrinsic ("revocable on task completion"), extrinsic ("expires in 60 seconds"), use-bounded ("usable once"). Default to short.

> "When the task completes, the capability dies." (Boberg, 2026)

Practical pattern: JWTs with `iat`/`exp` set to task lifetime, plus a `nonce` the host's authority server tracks for use-bounded capabilities.

### 5.5 Attenuating capabilities

Pass *the most attenuated capability sufficient*. Hold session-scope `slack:write`? Derive `slack:write_to(#standup)`. Hold `fs:read(/srv/app)`? Derive `fs:read(/srv/app/reports)`. Protocol sketch — agents *request* needed capabilities, orchestrator approves:

```json
{
  "task": "summarize_emails_from_last_week",
  "requested_capabilities": [
    "gmail:read_messages(from=now-7d, to=now)",
    "display:text"
  ]
}
```

Task-bound. Dies with the task.

### 5.6 Composing capabilities

Multi-step workflows compose multiple capabilities *explicitly*. "Research, write, post" is *three tasks*. Research gets `web:fetch(authorized_domains)`; writing gets `fs:write(specific_path)`; posting gets `slack:send_to(#specific_channel)`. Task transitions are the *capability-introduction point*.

### 5.7 Boberg's A2A capability negotiation proposal

The 2026 post sketches a design for A2A capability negotiation. Four imperatives (verbatim):

1. **Task-scoped requests**: "Agents MUST request capabilities scoped to the task, not the session." (Boberg, 2026)
2. **Attenuation**: "If the task is summarization, the capability permits reading, not writing." (Boberg, 2026)
3. **Revocation**: "When the task completes, the capability dies." (Boberg, 2026)
4. **Explicit delegation**: "When an agent invokes a sub-agent, it passes attenuated capabilities, not its full authority set." (Boberg, 2026)

Structural shape: each agent advertises a capability namespace; when A wants B to act on its behalf, A *requests a capability* from B scoped to task and parameters; B may *attenuate* the request; A invokes; task completion invalidates. Cross-link to [[reference-distributed-authz]]: the A2A handshake is structurally a *distributed Zanzibar tuple* — the consistency mechanics (revocation propagation, audit, attenuation derivation) are the same problems Zanzibar solved at the relationship-tuple layer.

### 5.8 The sampling problem

Boberg's post calls out **MCP sampling** as a capability-discipline failure. When an MCP server requests the host to perform a completion on its behalf, the server is *exercising the host's LLM capability with attacker-controlled input*. Sampling does not pass the prompt through a capability check; the server passes whatever string it wants, with whatever system message the host attaches. Capability fix: the host's "do an LLM completion" capability should not be ambient. Requested per-call, prompt visible to user or orchestrator policy, cost charged to the requesting capability. Sampling without per-call mediation is structurally identical to the FORTRAN compiler with write access to `(SYSX)BILL`.

---

## 6. MCP and Capability-Based Design

MCP is the most-deployed agent-tool interconnect in 2026. Its current design is ambient-authority-flavored. The capability reading is necessary because the protocol is what most production agents are built on.

### 6.1 MCP servers as capability providers (the lens shift)

Reframe: every MCP server is a capability provider, exposing operations as capabilities. The server's `tools/list` is the *capability advertisement*; `tools/call` is the *capability exercise*.

MCP has the right *shape* but the wrong *defaults*:

- Right shape: tools are named, parameterized, individually invocable.
- Wrong default: registered servers' tools are *automatically available* after one install click. The grant is session-wide and untyped.
- Wrong default: tool descriptions are advisory — the *model* decides whether to invoke. No per-call capability check on the host.
- Wrong default: invocations run with the server subprocess's full ambient authority, which inherits the host's, which inherits the user's.

### 6.2 Tool description as capability documentation

MCP tool descriptions are unstructured text. The agent reads them; the model uses them for invocation decisions. They are also the *prompt-injection vector* — "tool poisoning" (Invariant Labs) / "line jumping" (Trail of Bits), both disclosed in April 2025 ([[reference-llm-agent-security]] §3.1).

Under capability discipline, a tool description should be structured:
- *Designation*: what resource? (`gmail:read_messages` operates on the user's inbox.)
- *Authorization*: what operation? (read, write, send, delete, execute.)
- *Parameters*: what's bound vs. fillable? (`send_to(channel)` — channel bound, body fillable.)
- *Constraints*: max side-effect magnitude? (`transfer_funds` — max $100/invocation.)

Compare to OAuth scope strings: scopes encode the same information less structurally. Capability discipline pushes toward stricter typing — the tool's WIT signature IS the documentation.

### 6.3 What strict capability typing looks like for MCP

```
// Pseudo-WIT capability interface
package semgrep:agent-capabilities;

interface gmail {
  resource inbox-handle {
    read-messages: func(from: instant, to: instant) -> list<message>;
  }
  // No public constructor; inbox-handle can only be received as a capability.
}

interface slack {
  resource channel-handle {
    constructor(name: string);  // private; orchestrator-only
    send: func(body: string) -> result<unit, error>;
  }
}
```

The agent receives an `inbox-handle` scoped to a time range and a `channel-handle` scoped to `#standup`. There is no `inbox.read` ambient method; no `slack.send_to_arbitrary_channel`. The model can decide *what to do* within the handle's bounds; it cannot exceed them because the bounds are typed in. This is exactly the Component Model's discipline. Path forward: standardize WIT interfaces for MCP server capabilities and compose through the Component Model.

### 6.4 The marketplace risk

MCP marketplaces and Cursor plugin marketplaces are supply-chain attack vectors. Users install community servers; servers run with the user's ambient authority; a malicious server is full-takeover-on-install. Capability discipline at install: a server declares what *capabilities it requires* (filesystem scoped to `/home/user/projects`; network scoped to `api.example.com`; subprocess execution scoped to `git`). The marketplace reviews the declaration; the host enforces it. The iOS App Store entitlements model (cross-link to [[reference-macos-apple-security]]) applied to MCP.

### 6.5 MCP authorization spec evolution: OAuth-as-capability-flow

The MCP authorization specification matured significantly between June 2025 and November 2025. The 2025-11-25 revision is the most current published baseline as of this writing (https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization). The doctrinal reading: the spec has adopted OAuth 2.1 as the *transport* of capability tokens while leaving the *granularity* of those capabilities to implementors. This is progress on credential hygiene; it is not yet capability discipline.

What the 2025-11-25 spec mandates (verbatim from the spec):

- **OAuth 2.1 base.** Authorization servers MUST implement OAuth 2.1; MCP servers act as OAuth 2.1 resource servers; clients act as OAuth 2.1 clients.
- **RFC 8707 Resource Indicators MANDATORY.** Clients MUST include the `resource` parameter in both authorization and token requests, identifying the canonical URI of the MCP server. Servers MUST validate that tokens were issued specifically for them as the intended audience. This is the structural defense against token passthrough — the confused-deputy pattern where an MCP server forwards an inbound token to a downstream API and the downstream incorrectly trusts the token's audience.
- **PKCE S256 MANDATORY.** Clients MUST implement PKCE (Proof Key for Code Exchange) per OAuth 2.1, MUST use `S256` when technically capable, and MUST verify PKCE support via authorization server metadata before proceeding. Discovery is via `code_challenge_methods_supported` in OAuth Authorization Server Metadata or OIDC provider metadata; absence means refuse to proceed.
- **Token passthrough forbidden.** "If the MCP server makes requests to upstream APIs, it may act as an OAuth client to them. The access token used at the upstream API is a separate token, issued by the upstream authorization server. The MCP server MUST NOT pass through the token it received from the MCP client." This is the canonical confused-deputy structural defense, expressed in the spec's normative language.
- **Step-up authorization** via insufficient-scope `403` responses with `WWW-Authenticate: Bearer error="insufficient_scope"` headers — closer to per-action capability requests than session-wide grants.

The November 2025 revision also introduced **Cross App Access (XAA)** as the "Enterprise-Managed Authorization" extension and added Client ID Metadata Documents as the recommended client-registration path for the common case of no prior relationship between client and server (https://aaronparecki.com/2025/11/25/1/mcp-authorization-spec-update; https://den.dev/blog/mcp-november-authorization-spec/).

What the spec does NOT mandate, and what the capability doctrine reads as still missing:

- *Per-tool capability tokens.* Scopes are server-wide. A single token grants all scopes the user consented to at authorization; per-tool, per-task, per-resource attenuation is left to implementors. Spec text on `WWW-Authenticate` scope guidance is informational; servers' actual enforcement is per-implementation.
- *Capability lifetime bound to task.* OAuth 2.1 access tokens are "short-lived" — minutes to hours typical — but not bound to a single task. The §3.5 revocation discipline ("when the task completes, the capability dies") is not yet a wire-protocol feature.
- *Non-bearer credentials.* OAuth 2.1 tokens are bearer tokens. Anyone holding the token holds the authority. Sender-constrained alternatives (DPoP, mTLS) are referenced by OAuth 2.1 but not mandated by MCP.

Read directly against §3.2: MCP authorization 2025-11-25 is *bearer authentication with audience binding*. The audience-binding piece (RFC 8707) is real progress. The discipline gap is granularity and lifetime.

### 6.6 MCP tool annotations: the risk-vocabulary layer, not the enforcement layer

The MCP `2025-03-26` revision added **tool annotations** as four boolean hints on every tool: `readOnlyHint`, `destructiveHint`, `idempotentHint`, `openWorldHint` (https://blog.modelcontextprotocol.io/posts/2026-03-16-tool-annotations/; https://modelcontextprotocol.info/specification/2025-11-25/). Defaults are "deliberately cautious": absence implies *non-read-only, potentially destructive, non-idempotent, open-world*. The spec's central caveat is explicit and load-bearing for the doctrinal read:

> "Annotations are not guaranteed to faithfully describe tool behavior" (MCP spec, 2025-03-26).
>
> "An untrusted server can lie ... they aren't enforcement. If you need a guarantee that a tool can't exfiltrate data, that's a job for network controls or sandboxing, not a boolean hint." (MCP blog, "Tool Annotations as Risk Vocabulary," March 2026.)

The doctrinal read: tool annotations are *risk vocabulary*, not capability typing. They live in the same layer as OpenAPI `description` fields or HTTP `Allow` headers — useful for UX, useless for adversaries. The structural defense against a malicious or compromised tool is still §5 capability bounds, §8.2 sandboxing, §8.6 egress capabilities. Annotations help clients build approval dialogs ("this tool is `destructiveHint: true`, surface a confirm step"); they do not bound what the tool can actually do at invocation time.

This is the same lesson Java's SecurityManager learned (§2.6): *policy-as-config* is structurally insufficient when the policy lives in the data plane the model evaluates. A capability-typed tool's authority is enforced by the runtime; an annotated tool's authority is *suggested* to the client. The doctrine recommends: use annotations for UX hinting; do NOT use them as the security boundary.

### 6.7 MCP sampling: the unsolved capability gap

§5.8 introduced sampling as a capability-discipline failure. The 2025-11-25 spec doubles down rather than fixes it: sampling requests can now include tool definitions and tool-choice behavior, enabling MCP servers to "run their own agentic loops using the client's tokens" (https://blog.modelcontextprotocol.io/posts/2025-11-25-first-mcp-anniversary/). Palo Alto Unit 42 published "New Prompt Injection Attack Vectors Through MCP Sampling" on 5 December 2025 demonstrating three exploitation pathways: resource theft (servers consume the host's tokens/compute without consent), conversation hijacking (servers inject persistent instructions into LLM responses), covert tool invocation (servers manipulate prompts to trigger tool calls without user visibility) (https://unit42.paloaltonetworks.com/model-context-protocol-attack-vectors/). Unit 42's structural finding: "MCP sampling relies on an implicit trust model and lacks robust, built-in security controls."

This is the §5.8 prediction landing in production. The capability fix has not shipped at the protocol layer. The defense recommendations from Unit 42 and the MCP maintainers — visible-to-user prompt display, host-side rate and budget limits, model-choice control retained by host — are all *user-controlled mediation*, which is the right shape but is still policy not capability. A future spec revision that types sampling as a capability the server must hold (granted with prompt-shape constraints, token-budget caps, and rate limits per grant) would close the gap. The hardest design choice will be how to communicate the prompt-shape constraint to a non-cooperating server — likely through a typed `sampling-context` resource handle that bounds what the server can ask the host to complete on.

---

## 7. WebAssembly Component Model as the Substrate

The most consequential capability-system development between 2010 and 2026 is the WebAssembly Component Model — the first widely-adopted, language-neutral, capability-typed program-composition substrate. Treat it as the default for capability-disciplined agent runtimes.

### 7.1 What the Component Model is

Wasm Core (2017) gave us a sandboxed bytecode VM with no host access except through explicit imports. The Component Model (WASI Preview 2, January 2024) adds:

- **WIT (WebAssembly Interface Types)**: capability-shaped IDL. Components declare imports (capabilities consumed) and exports (capabilities provided). All cross-component communication is through WIT.
- **Resources**: typed handles to host-managed objects. A `wasi:filesystem/types.descriptor` is a capability to a specific file; cannot be synthesized, only received through an import.
- **Composition**: the composer wires imports to exports. The composition graph IS the capability allocation.

A WIT *world* is a component's import/export contract; the bindings ARE the capability grants. A component cannot accidentally access a capability it didn't import; the reachability graph is closed by construction.

Cross-link to [[reference-cicd-supply-chain]]: the Component Model is also the most defensible *supply chain* substrate. A component's WIT manifest can be reviewed, signed, attested.

### 7.2 The Bytecode Alliance vision and agent runtimes

The Bytecode Alliance (Mozilla, Fastly, Intel, Red Hat) frames the Component Model as a *secure-by-default composition substrate* — every cross-component call is a capability invocation. Pattern: components handling untrusted input never touch filesystem; components touching filesystem never make network calls; components making network calls do so to specific destination capabilities passed by the composer.

The vision is *more* applicable to agent runtimes than most existing software because agents have the strongest need: agents compose tools, tools handle untrusted input.

Path forward: MCP-host implementations run MCP servers as WASI Preview 2 components. Each server declares its WIT signature (imports — filesystem, network, LLM completion — and exports — its tools). The host composes server imports against host-provided capabilities, attenuated to installation policy. Server tools become typed handles the host hands to the agent per task.

```
host (capability-aware composer)
  ├── mcp-server-gmail (WASI component)
  │     imports: wasi:http/outgoing-handler (scoped to gmail.googleapis.com)
  │     exports: gmail-tools:{read-messages, send-message, ...}
  ├── mcp-server-postgres (WASI component)
  │     imports: postgres-conn (scoped to user's DB)
  │     exports: postgres-tools:{query, execute, ...}
  └── orchestrator-agent
        per-task capability sets derived from imports of above
```

A 2026 design, not a 2026 deployment. The doctrinal recommendation is to treat this as the target.

---

## 8. Practical Capability Discipline for Current Systems

Most agent runtimes in 2026 lack native capability typing. The doctrine still applies — discipline can be *approximated* by deliberately structuring authority allocation.

### 8.1 Token-scoped tool invocations

Each invocation requires a fresh, narrow capability token. Orchestrator holds broad credentials and generates per-task tokens — JWTs with claims for `tool`, `parameters_bound`, `iat`, `exp`, `nonce`. Tool-invocation interface requires the token; TTL task-bound (minutes, not hours). An additional layer *below* OAuth: OAuth scope is the orchestrator's broad authority, the capability token is the per-task attenuation.

### 8.2 Per-tool isolated subprocess + IPC

Each MCP server in an isolated subprocess with restricted ambient authority:

- Linux: systemd unit per server with `ProtectSystem=strict`, `ProtectHome=tmpfs`, `RestrictAddressFamilies`, `SystemCallFilter`, narrow `CapabilityBoundingSet`.
- macOS: `sandbox-exec` profiles, or Mach-based subprocess sandboxing.
- BSD: Capsicum mode after opening required descriptors.
- Cross-platform: WASI runtime per §7.

Write down what each server needs; grant only that. Malicious-server blast radius is bounded by the OS sandbox, not the user's ambient authority.

### 8.3 Audit every tool call with its capability

Every invocation logs principal, task ID, capability token, parameters, result hash. Ambient systems: "the process ran." Capability systems: "process exercised capability C derived from grant G initiated by principal P for task T at time t with result hash H." Reconstructable.

### 8.4 No "agent mode" with elevated permissions

Agent has *the same authority as the invoking user, never more*. No service-account-with-broader-permissions. Anti-patterns: admin token "to help administrators"; cross-tenant service account "to answer questions about any customer." In both cases, prompt injection becomes privilege escalation. For agents acting on behalf of multiple users (shared-channel bot), authority is the *intersection* of requesting user and bot capabilities — not the union.

### 8.5 Approval flows for high-impact capabilities

User re-approval at exercise time:

- **Send email**: re-approval for first send to a new recipient; bypass for recently-emailed recipients in the same thread.
- **Transfer funds, payment**: always.
- **Delete data, drop, destroy**: always, with the resource named.
- **External destination outside org allowlist**: always.

Task-grant said "agent can send email"; destructive-action says "agent is about to send `[body]` to `[recipient]` — approve?". OAuth scope dialogs weren't designed for this; capability-grant-plus-re-approval is. Cross-link to [[reference-llm-agent-security]] §8 (OWASP LLM06:2025): same pattern, policy-form.

### 8.6 Egress capabilities

Egress through a capability-aware proxy. Agent in a network namespace with no default route. Proxy holds capability tokens for specific destinations and enforces them per task. Forecloses the exfiltration leg of the lethal trifecta structurally. Even if injection induces an attempt to `attacker.example.org`, the proxy lacks the capability and the connection drops. Cross-link to [[reference-ssrf-url-parsing]] for URL canonicalization that makes destination capabilities reliable.

---

## 9. Common Objections and Rebuttals — the Steelman-Foil Section

Capability discipline has been argued against for sixty years. The arguments recur. Each has a structural rebuttal. Per [[reference-steelman-doctrine]] §3, the Champion-Foil-Adjudicator pattern is the right way to surface and resolve them.

### 9.1 "Capabilities are slow"

**Foil**: Per-call kernel/runtime mediation. Modern systems can't afford the latency.

**Champion**: Empirically false at production scale. KeyKOS was in commercial production use from 1983. EROS demonstrated parity with mainstream UNIX in the 1990s. seL4 ships in safety-critical avionics. The Component Model deploys at CDN-edge scale (Fastly Compute) with sub-millisecond cold starts. The "slow" claim is a 1990s folk theorem, refuted at every benchmark since.

**Adjudicator**: Reject. The performance argument was never empirical.

### 9.2 "Existing tools don't support capabilities"

**Foil**: The agent ecosystem is Python, JS, TS — no native capability typing. You can't retrofit.

**Champion**: True partially. False structurally. The Component Model is bringing capability typing to every WASI language; SES Compartments to JavaScript; CapPython to Python. Even without language support, the orchestrator-layer discipline of Section 8 approximates capability properties (narrower, token-scoped, audited grants) without runtime changes.

**Adjudicator**: Concede partial. The retrofit is real work, *clearly underway*. Push toward the substrate, don't abandon the discipline.

### 9.3 "Consent fatigue: users won't approve every grant"

**Foil**: Users click "approve" reflexively; security value collapses.

**Champion**: OAuth scope-dialog precedent shows users CAN handle the discipline when the UX is right. Specific-scope dialogs have non-trivial decline rates on unexpected requests. The OAuth failure mode isn't "users approve everything" — it's "scopes are too coarse to express the right question." Capability dialogs at finer grain ("This task wants to send a specific email to a specific recipient") would be *more* comprehensible than coarse scopes. Not every exercise needs approval; Section 8.5's pattern is the right balance.

**Adjudicator**: Concede partial. UX design is real work. The objection is a UX-research question, not a capability-discipline question.

### 9.4 "Capabilities don't compose across organizations"

**Foil**: Across organizations you're back to credential-bearer: anything given to a third party is a credential they can replay.

**Champion**: Miller's Granovetter operator addresses this. Inter-org capability flow is *exactly* the problem distributed-capability systems were designed for. Cryptographic primitives (signed tokens, attenuated delegation, revocation lists, audit chains) are well-understood. NLTSS demonstrated cross-machine capability flow in the 1980s; OAuth itself is a degenerate capability system; A2A negotiation per Boberg's post IS the cross-org capability protocol.

**Adjudicator**: Concede partial. Open research questions (revocation latency, key rotation, audit at scale) exist. Working prototypes (UMA 2.0, GNAP) exist. Push forward; retreat to credential-bearer is *worse*.

### 9.5 "Capabilities make the model less capable"

**Foil**: Narrow capability sets cripple the assistant.

**Champion**: Conflates *what the agent is asked to do* with *what authority it exercises*. The agent can be asked to do anything within the user's authority. The per-task capability set bounds the *exercise*. The "less capable" framing is the 1990s firewall argument ("you're crippling connectivity") and the 2000s parameterized-query argument ("you're making SQL harder"). Both turned out wrong because the alternative — uncontrolled connectivity, uncontrolled SQL — caused the systemic failures we've spent decades cleaning up.

**Adjudicator**: Reject. Capabilities don't restrict what the agent can do *as an agent*; they restrict what authority it exercises *as a deputy*.

### 9.6 "Prompt injection is unsolvable; capabilities won't help"

**Foil**: LLMs can't distinguish instructions from data. Capability discipline is a distraction from the real research problem (alignment).

**Champion**: Capability discipline doesn't *solve* prompt injection; it makes prompt injection *non-catastrophic*. The discipline assumes the model will be successfully injected and bounds what the injection can achieve. Cross-link to Willison's lethal trifecta — the structural defense is to break the trifecta by capability narrowing, not to harden the model. "Wait for alignment" is the same as "wait for X" in every prior security domain. It loses to "the bug ships today; capability bounds make it survivable."

**Adjudicator**: Reject. Capability discipline is *premised on prompt injection being unsolvable*. It is the structural defense layer below the un-hardenable model layer.

Cross-link to [[reference-steelman-doctrine]] §6.5 on premature convergence: "wait for alignment" is the canonical premature-convergence failure. The doctrine is, instead, *give the un-hardenable component the smallest blast radius it can survive at*.

---

## 10. Applying the Doctrine: Detection, Review, and Rule Authoring

This doc is the *why*. The practical question for Semgrep work is: how does this doctrine inform what we detect, how we review, what we ship?

### 10.1 Detection patterns for ambient-authority anti-patterns

Static-analysis signals for ambient-authority tool grants:

- **Full DB connections rather than scoped query handles.** Bad: `tool_db_query(conn=database.connect(...), sql=user_supplied)`. Good: `tool_db_query(prepared_stmt=database.prepare("SELECT ... WHERE id=?"), bind=[id])`. Semgrep: agent/tool receives `Connection` and constructs SQL from agent-controlled input.
- **Full filesystem access rather than specific path handles.** Bad: `tool_read_file(path=user_supplied)`. Good: `tool_read_file(handle=open(specific_path, "r"))`. Semgrep: `open(some_user_input)` in tool implementations.
- **Full HTTP-client access rather than scoped fetch.** Bad: `tool_fetch(url=user_supplied)`. Good: `tool_fetch_specific(url_capability=allowed_destination)`. Semgrep: generic `requests.get(user_input)` without allowlist enforcement.
- **OAuth tokens on agent state rather than per-task derivation.** Bad: `agent.session.oauth_token = full_session_token`. Good: `agent.current_task.capability_token = derive_for_task(full_session_token, scope=task_scope, ttl=task_ttl)`.
- **Service-account credentials in agent tool implementations.** Bad: `tool_admin_action(service_account_token=ADMIN_SVC_KEY, target=user_input)` (confused-deputy generator). Good: action runs under `task.user_token`.

Capability-discipline checks as static analysis. Cross-link to [[reference-distributed-authz]]: same patterns at the authz layer are the BOLA / BFLA family.

### 10.2 Code review questions for agent-runtime code

1. **What authority does this tool actually need?** (POLA.) "Summarize text" should not have filesystem write. "Send notification" should not read unrelated resources.
2. **Is authority bound at construction or at invocation?** (Designation-equals-authority.) Construction: fixed blast radius. Invocation: blast radius is whatever the caller — i.e., the model — provides.
3. **Can a confused agent escalate?** Trace the chain. "The agent's authority, union of all installed tools" → confused-deputy generator. "The specific capability the user authorized for this task" → capability-disciplined.
4. **Is authority revocable and attenuable?** Can the orchestrator pass a strict subset to a sub-task? Revoke before the natural task lifetime? If both no, structural defense is missing.
5. **What's the audit trail?** "Agent X did Y" is principal-attribution. "Principal P initiated task T, capability C from grant G, exercised on X, result Y" is capability-attribution — confused-deputy reasoning is possible.

The capability-discipline analog of [[reference-code-review-expertise]] §2's auth-homogeneity review.

### 10.3 Severity calibration

Apply the click-count severity model from [[reference-code-review-expertise]] §3.1:

- **Zero-click**: agent has ambient authority sufficient to exfiltrate on prompt injection without user action. Lethal trifecta present, no allowlist, no per-action approval. CRITICAL.
- **One-click**: agent executes after a single over-trusted confirmation (user reflexively approves; prompt doesn't show destination/payload). HIGH.
- **N-click**: multiple confirmations or active steering required. Discipline approximately right, bug in a specific bound. MEDIUM.

Click-count is a capability-discipline measurement: zero-click = no gating; one-click = inadequate gating; N-click = working gating with gaps. Cross-link to [[reference-vr-methodology]] §5: the agent attack surface IS the agent's current capability set.

### 10.4 Applying at Semgrep workflow scope

A production static-analysis authz-detection workflow is a real-world example of finding ambient-authority anti-patterns. The detection lane is well-established for traditional authz CWEs (287/306/308/862/863/1390). Agent-runtime extension is natural: "does the handler check authz on this resource?" generalizes to "does the agent's tool check capability on this invocation?" A future shard would target CWE-1390 / CWE-862 in MCP tool implementations — tools that accept a connection string and run arbitrary SQL; tools that accept a path and read arbitrary files; tools that accept a URL and fetch arbitrary endpoints. The detection lane exists; the corpus shifts to MCP-server source.

---

## 11. Variant Analysis — Under-Explored Frontiers

### 11.1 MCP sampling

MCP servers can request LLM completions on the host via sampling. Today this is *ambient* — server hands host a prompt, host completes against its model, cost is charged to host's API key. A malicious server samples arbitrarily, exfiltrating host context via the sample request and burning the host's budget. Capability fix: sampling is a capability the server must hold; host issues per-sample capabilities scoped to specific prompt structures, rate- and budget-limited.

### 11.2 A2A protocol

(Cross-link to §5.7.) Open questions: token format (JWT, macaroons with first-party caveats, GNAP continuation tokens, Component Model resource handles); cross-org revocation (published revocation list vs. active propagation); capability composition `(read X) AND (write Y)` without enabling accumulation.

### 11.3 AI coding assistants

Cursor, Copilot, Cody, Cline. Same ambient failure: the assistant has the user's filesystem, git credentials, deploy keys, npm tokens. Prompt injection in a README or dependency description becomes ACE. Discipline: filesystem scoped to current repo; network scoped to docs lookups and known-good registries; git/deploy capabilities per-action approved; MCP catalog per-project, not global. Cursor and Continue have shipped partial moves; not uniformly applied.

### 11.4 Marketplace world

Plugins and MCP servers are new principals in the user's trust graph. Discipline: marketplaces publish capability manifests; users approve manifests; runtimes enforce. The iOS App Store entitlement model is the precedent. Current state: most marketplaces don't review; most runtimes don't enforce.

### 11.5 Browser-based agents and same-origin policy

Browser-hosted agents (Claude.ai, ChatGPT browse, in-browser Cursor) operate under SOP for network access. SOP is itself a degenerate capability system — the origin is the capability. Open: agent network capabilities should be *narrower* than the page's origin (task-scoped destinations, not full origin reach). Right boundary between agent runtime (in-browser worker) and user session (cookies, IndexedDB) is: capability handles passed at agent spawn, not shared via global storage.

### 11.6 Mobile agents: iOS/Android entitlements

iOS entitlements are nascent capabilities; Android permissions are more ambient. When agents move to mobile (Apple Intelligence, Gemini on Pixel), the entitlement system is the natural capability layer. Agent tools as iOS extensions should get their own narrowed entitlement set, derived at extension load — not inherit the host app's. Cross-app calls should traverse XPC (capability-aware on macOS); the mobile equivalent is the right substrate.

### 11.7 CHERI silicon under agent runtimes

When CHERI silicon (Arm Morello, RISC-V CHERI) becomes available in agent hosts, the bottom of the capability stack becomes hardware-enforced. Agent's WASI runtime on a CHERI-aware OS on capability-typed hardware — unbroken from silicon to agent. Not 2026 deployment; plausibly 2028-2030. Design agent runtimes that *would benefit* from CHERI when it lands.

### 11.8 Capability-token formats: the production wire layer

The capability-doctrine question for distributed agents (cross-machine, cross-org, cross-trust-domain) is *what shape does the unforgeable reference take on the wire*. Four formats are in production or pre-production in 2024-2026, each with different trade-offs:

- **Macaroons.** Birgisson, Politz, Erlingsson, Taly, Vrable, Lentczner (Google, NDSS 2014). Bearer credentials embedding *caveats* that attenuate when, where, by whom, and for what purpose a target service should authorize requests; nested-HMAC construction allows attenuation without contacting the issuer. Deployed in some cloud providers (notably ForgeRock AM 7.0 added macaroon-based access tokens in 2020) and OAuth2 servers as a least-privilege drop-in. As Neil Madden notes, macaroons have "no standard" — no IETF RFC, no IANA registry — which has limited interop adoption. Status as of 2024: ongoing discussion in the authorization community but not standards-track (https://research.google/pubs/pub41892/; https://neilmadden.blog/2020/07/29/least-privilege-with-less-effort-macaroon-access-tokens-in-am-7-0/).
- **Biscuit.** Decentralized capability tokens with offline attenuation; public-key verification; authorization policies written in a Datalog-derivative logic language; revocation identifiers built-in. Moved under the Eclipse Foundation as Eclipse Biscuit (https://www.biscuitsec.org/; https://github.com/eclipse-biscuit/biscuit). Biscuit was originally created at Clever Cloud, not Cloudflare. Production adoption is niche (smaller SaaS providers using Rust); the Datalog policy language is the most novel feature and the largest adoption friction.
- **UCAN (User-Controlled Authorization Networks).** Trustless, local-first, decentralized capability authorization extending JWTs with capability/resource model and proof-chain delegation; uses decentralized identifiers (DIDs) as principals; chained certificates achieve public verifiability without a central issuer (https://github.com/ucan-wg/spec; https://ucan.xyz/specification/). Production deployment in storacha.network and Web3.Storage; UCAN Working Group continues active spec evolution. The decentralized model fits A2A capability negotiation (§5.7) better than OAuth bearer tokens — *delegation without sharing keys* is exactly the §3.7 Granovetter operator on the wire.
- **SPIFFE Verifiable Identity Documents (SVIDs).** Cryptographic workload identities issued by SPIRE; JWT-SVID or X.509-SVID; bound to a trust domain. CNCF-graduated; IETF chartered the WIMSE working group in 2024 with the CNCF SPIFFE/SPIRE project as a named collaborator. Production use at Red Hat OpenShift zero-trust workload identity manager, wasmCloud's component-model adoption (March 2025) (https://wasmcloud.com/blog/2025-03-04-why-were-adopting-spiffe-for-webassembly-workload-identity/; https://spiffe.io/).

The doctrinal read: SPIFFE/SPIRE is the *identity* layer (who is exercising this capability); UCAN is the *delegation* layer (how does authority transitively flow); Macaroons and Biscuit are the *attenuation* layers (caveats on a token's exercise). They are complementary, not competitors. A 2027-ready agent runtime would stack: SPIFFE/SPIRE for workload identity → UCAN for delegated capabilities across organizations → Biscuit-style attenuation for fine-grained operation bounds within a delegation. The OAuth 2.1 bearer-token-with-RFC-8707-audience-binding that MCP 2025-11-25 mandates is a structural compromise — production-deployable, capability-shaped, but neither delegable nor attenuable on the wire.

Cross-link to [[reference-distributed-authz]] §3 on token-format trade-offs.

### 11.9 Capability research literature, 2024-2026

The capability-discipline literature directed at AI agents has begun to materialize as a distinct sub-field. Notable directions:

- The 2025 AI Agent Index (arXiv 2602.17753) documents the origins, design, capabilities, ecosystem, and safety features of 30 deployed agentic systems.
- "AI Agents vs. Agentic AI: A Conceptual Taxonomy" (arXiv 2505.10468, May 2025) discusses long-horizon planning, cross-tool coordination, and adaptive learning loops — and the orchestration-layer mediation that the capability discipline §5.1 calls for.
- "Survey of Agentic AI and Cybersecurity" (arXiv 2601.05293, January 2026) frames the structured-reasoning + tool-use boundary as the new locus of structural security work.

The largest gap in the literature: there is not yet a canonical "Capabilities for AI Agents" paper analogous to Hardy 1988 or Watson 2010. Boberg 2026 is the closest in the practitioner press; the academic synthesis still owes its first review article. Mark Miller's continuing object-capability work (Agoric, ECMA TC39) remains foundational but is not directly addressed to agent runtimes; the bridging paper is open territory.

---

## 12. Steelman: Capability Discipline Adoption Barriers, 2024-2026

§9 enumerates the classic objections and their refutations. The doctrine's *adoption record* in production is a different question, and the steelman must engage it honestly. Per [[reference-steelman-doctrine]] Variant A (slate inclusion-exclusion), the Foil here is empirical: *if capabilities are so obviously correct, why is uptake at the agent-runtime tier slow?*

### 12.1 Foil: the empirical adoption rate is unimpressive

**Foil's case.** The 2024-2026 evidence is mixed at best:

- MCP's authorization spec (2025-11-25) requires audience binding (RFC 8707), PKCE, and token-passthrough prohibition — all correct, all OAuth 2.1 boilerplate, none of them *capability granularity* below the session level.
- MCP tool annotations are explicit risk-vocabulary, not enforcement.
- The Component Model has reached 1.0-ish maturity, but no major agent-runtime host (Claude Desktop, ChatGPT, Cursor, Continue) runs MCP servers as WASI components in production as of this writing. Claude Code skills ship with "install from trusted sources" guidance, not capability declarations.
- UCAN production deployment is niche (storacha.network, Web3.Storage). Biscuit is niche-SaaS adoption. Macaroons have had a decade and remain non-standard.
- SPIFFE/SPIRE is the bright spot — graduated CNCF, IETF WIMSE chartered in 2024, real enterprise adoption — but it is the *identity* layer, not the capability layer.

The doctrine is correct; the doctrine has been correct for 60 years; if the doctrine were the bottleneck, it would have won already. The actual bottleneck is *developer experience*: capability-typed APIs require composers/orchestrators to plumb capabilities through every call site; this is the same friction Java SecurityManager hit (§2.6) and the same friction OCAP languages have always hit at scale. Until DX friction drops to OAuth-comparable levels, adoption stays niche.

### 12.2 Champion's counter

The Foil's framing is too kind to the alternative. The "DX friction" objection compares capability-typed APIs against ambient-authority APIs *at the local-development surface*, where ambient authority is genuinely easier. It does not compare them at the production-incident surface, where ambient authority is the bug-of-record source for every prompt-injection-derived agent compromise of the last 18 months. The right comparison is: *capabilities cost more per-call-site at development time and orders-of-magnitude less per-incident at production time.* Foil collapses this to a single dimension.

Empirically, the substrate IS moving. WASI 0.3 shipped native async in June 2026; Hyperlight Wasm proves capability-typed components at 1-2 ms cold start; SPIFFE/SPIRE proves cross-vendor capability-identity at production scale. The substrate maturation is the precondition; the agent-runtime tier follows substrate by 2-4 years typically. The 2024-2026 pattern is "substrate matures; tier-above adopts the *appearance* of the discipline (OAuth 2.1 with audience binding, tool annotations) while leaving the structural work for the next revision." This is exactly Java in 1995-2005: bytecode verifier as substrate (capability-shaped); ambient SecurityManager as tier-above (not capability-shaped); the structural fix took 25 years and was abandoned via JEP 411. The lesson is *don't repeat the SecurityManager error*. The 2026 doctrinal task is to apply substrate-level capability typing at the tier-above directly, not defer it to a future revision that will face the same drift.

### 12.3 Foil's rebuttal

Conceded that incident cost is the right axis. But the *incident-evidence-to-runtime-adoption causal chain* is much slower than the Champion implies. The 2024-2026 production prompt-injection incidents (Microsoft Copilot data exfiltration, GitHub Copilot via README poisoning, the Invariant Labs MCP tool-poisoning disclosures) have prompted *guidance* changes, not *runtime* changes, at the major vendors. Anthropic's "install skills from trusted sources" and the MCP spec's tool-annotation caveats are exactly the policy-as-config response that Java SecurityManager pioneered and failed at.

The DX friction is also not symmetric across tier and substrate. SPIFFE/SPIRE succeeded because the workload identity question has *one* good answer per workload and the SPIRE agent does the plumbing. Capability granularity for agent tools is *N tools × M parameters × per-task-context*, which is a quadratic-or-worse expansion compared to identity. The DX answer may need to look more like static-analysis-derived capability declarations (capability requirements *inferred from the tool's call graph at build time*, not authored by the tool developer) before adoption tips. That is research, not engineering.

### 12.4 Adjudicator

Concede partial on both sides. The doctrine is structurally correct (§9's objections all fall); the deployment evidence is real but not yet decisive at the agent-runtime tier; the DX-friction Foil identifies a genuine open problem. The action items:

1. **Substrate-tier work continues.** WASI Preview 3, Component Model continued maturation, SPIFFE/SPIRE WIMSE standardization, UCAN cross-org delegation. The substrate is healthy.
2. **The tier-above is the open problem.** Static-analysis-derived capability declarations (Champion's research suggestion) is plausibly the DX answer. Semgrep specifically is well-positioned to contribute here: §10.1 detection patterns are the building blocks of capability inference.
3. **Reject premature convergence.** The doctrine remains the structural fix even if 2026-2028 production deployment is slow. Cross-link to [[reference-steelman-doctrine]] §6.5 — "we tried and adoption was slow" is the canonical premature-convergence form. The 60-year arc of capability discipline survived three "slow adoption" inflection points (mainframe → workstation → cloud); the agent-runtime inflection is the fourth.

Verdict: continue investing in the doctrine; track adoption metrics quarterly; expect substrate-tier wins to compound into tier-above wins on a 2-4 year lag; do NOT let "adoption is slow" become an argument against the *discipline*. The discipline is correct; the engineering is the work.

---

## 13. References

### Primary sources

- Dennis, J. B., and Van Horn, E. C. (1966). "Programming Semantics for Multiprogrammed Computations." *CACM* 9(3), 143-155. https://dl.acm.org/doi/10.1145/365230.365252
- Hardy, N. (1988). "The Confused Deputy (or why capabilities might have been invented)." *ACM SIGOPS OSR* 22(4), 36-38. https://dl.acm.org/doi/10.1145/54289.871709 ; http://cap-lore.com/CapTheory/ConfusedDeputy.html
- Miller, M. S. (2006). *Robust Composition*. PhD Dissertation, JHU. https://papers.agoric.com/assets/pdf/papers/robust-composition.pdf
- Miller, M. S., Yee, K.-P., and Shapiro, J. (2003). "Capability Myths Demolished." SRL2003-02, JHU. http://www.erights.org/talks/myths/
- Shapiro, J. S. (1999). *EROS: A Capability System*. PhD Dissertation, UPenn. https://repository.upenn.edu/dissertations/AAI9926195/
- Klein, G., Elphinstone, K., Heiser, G., et al. (2009). "seL4: Formal Verification of an OS Kernel." SOSP 2009. https://www.sigops.org/s/conferences/sosp/2009/papers/klein-sosp09.pdf
- Watson, R. N. M., Anderson, J., Laurie, B., Kennaway, K. (2010). "Capsicum: Practical Capabilities for UNIX." USENIX Security 2010. https://www.usenix.org/legacy/event/sec10/tech/full_papers/Watson.pdf
- Boberg, K. (2026). "Security Like It's 1977: Capabilities for the Modern Agentic Web." Semgrep Blog, 28 January 2026. https://semgrep.dev/blog/2026/security-like-its-1977-capabilities-for-the-modern-agentic-web/

### Historical and architectural sources

- Plessey System 250. https://en.wikipedia.org/wiki/Plessey_System_250
- IBM System/38. Houdek, Soltis, Hoffman (1981). "IBM System/38 support for capability-based addressing." *Proc. 8th SCA*. https://dl.acm.org/doi/10.5555/800052.801885
- KeyKOS / GNOSIS. http://cap-lore.com/ ; Miller, M. S. (2023). "Norm Hardy's Place in History." https://erights.medium.com/norm-hardys-place-in-history-cecf191df641
- Donnelley, J. NLTSS. http://www.webstart.com/jed/papers/Components/ ; https://en.wikipedia.org/wiki/NLTSS
- E Programming Language. http://www.erights.org/
- WebAssembly Component Model + WASI Preview 2. https://component-model.bytecodealliance.org/ ; Clark, L. Mozilla Hacks "Standardizing WASI" (2019). https://hacks.mozilla.org/2019/03/standardizing-wasi-a-webassembly-system-interface/
- CHERI / Arm Morello. https://www.cl.cam.ac.uk/research/security/ctsrd/cheri/

### Related work

- Lampson, B. W. (1973). "A Note on the Confinement Problem." *CACM* 16(10).
- Granovetter, M. (1973). "The Strength of Weak Ties." *AJS* 78(6).
- Birgisson, Politz, Erlingsson, Taly, Vrable, Lentczner (2014). "Macaroons: Cookies with Contextual Caveats for Decentralized Authorization in the Cloud." NDSS 2014. https://research.google/pubs/pub41892/
- OWASP LLM Top 10 (2025 v2). https://genai.owasp.org/
- JEP 411: "Deprecate the Security Manager for Removal." https://openjdk.org/jeps/411

### 2024-2026 capability production sources

- MCP Authorization Specification, 2025-11-25. https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization
- "Client Registration and Enterprise Management in the November 2025 MCP Authorization Spec," Aaron Parecki, 25 Nov 2025. https://aaronparecki.com/2025/11/25/1/mcp-authorization-spec-update
- "What's New In The 2025-11-25 MCP Authorization Spec," Den Delimarsky. https://den.dev/blog/mcp-november-authorization-spec/
- MCP Tool Annotations specification commentary, "Tool Annotations as Risk Vocabulary: What Hints Can and Can't Do," MCP Blog, 16 March 2026. https://blog.modelcontextprotocol.io/posts/2026-03-16-tool-annotations/
- "One Year of MCP: November 2025 Spec Release," MCP Blog, 25 Nov 2025. https://blog.modelcontextprotocol.io/posts/2025-11-25-first-mcp-anniversary/
- "New Prompt Injection Attack Vectors Through MCP Sampling," Palo Alto Unit 42, 5 December 2025. https://unit42.paloaltonetworks.com/model-context-protocol-attack-vectors/
- WASI 0.3 native-async preview status, Progosling Dev Digest, August 2025. https://progosling.com/en/dev-digest/2025-08/wasi-0-3-native-async-aug-2025
- "WASI and the WebAssembly Component Model: Current Status," Eunomia, 16 Feb 2025. https://eunomia.dev/blog/2025/02/16/wasi-and-the-webassembly-component-model-current-status/
- WASI Roadmap and Specification Index. https://wasi.dev/
- "Hyperlight Wasm: Fast, secure, and OS-free," Microsoft Open Source Blog, 26 March 2025. https://opensource.microsoft.com/blog/2025/03/26/hyperlight-wasm-fast-secure-and-os-free/
- "Hyperlight: Achieving 0.0009-second micro-VM execution time," Microsoft Open Source Blog, 11 Feb 2025. https://opensource.microsoft.com/blog/2025/02/11/hyperlight-creating-a-0-0009-second-micro-vm-execution-time/
- "wasmCloud 1.0 Brings the WebAssembly Component Model to Enterprise," Cosmonic Blog. https://blog.cosmonic.com/engineering/wasmcloud-1-brings-components-to-enterprise/
- "Adopting SPIFFE for Wasm Workload Identity," wasmCloud Blog, 4 March 2025. https://wasmcloud.com/blog/2025-03-04-why-were-adopting-spiffe-for-webassembly-workload-identity/
- "Equipping agents for the real world with Agent Skills," Anthropic Engineering. https://www.anthropic.com/engineering/equipping-agents-for-the-real-world-with-agent-skills
- Agent Skills Overview, Claude Developer Platform. https://platform.claude.com/docs/en/agents-and-tools/agent-skills/overview
- Plugins in the SDK, Claude Developer Platform. https://platform.claude.com/docs/en/agent-sdk/plugins
- "Private Cloud Compute: A new frontier for AI privacy in the cloud," Apple Security Research. https://security.apple.com/blog/private-cloud-compute/
- "Security research on Private Cloud Compute," Apple Security Research. https://security.apple.com/blog/pcc-security-research/
- PCC Inspecting Releases documentation, Apple. https://security.apple.com/documentation/private-cloud-compute/inspectingreleases
- "PCC: Bold step forward, not without flaws," Trail of Bits Blog, 14 June 2024. https://blog.trailofbits.com/2024/06/14/pcc-bold-step-forward-not-without-flaws/
- UCAN Working Group specification. https://github.com/ucan-wg/spec ; https://ucan.xyz/specification/
- Eclipse Biscuit project. https://www.biscuitsec.org/ ; https://github.com/eclipse-biscuit/biscuit
- SPIFFE documentation. https://spiffe.io/ ; CNCF graduated projects index.
- "Establishing Workload Identity for Zero Trust CI/CD: From Secrets to SPIFFE-Based Authentication," arXiv 2504.14760, April 2025. https://arxiv.org/html/2504.14760v1
- "The 2025 AI Agent Index," arXiv 2602.17753. https://arxiv.org/html/2602.17753v1
- "AI Agents vs. Agentic AI: A Conceptual Taxonomy, Applications and Challenges," arXiv 2505.10468, May 2025. https://arxiv.org/html/2505.10468v1
- "A Survey of Agentic AI and Cybersecurity," arXiv 2601.05293, January 2026. https://arxiv.org/html/2601.05293v1
- "Is that allowed? Authentication and authorization in Model Context Protocol," Stack Overflow Blog, 21 Jan 2026. https://stackoverflow.blog/2026/01/21/is-that-allowed-authentication-and-authorization-in-model-context-protocol/

### Semgrep-internal cross-references

- [[reference-llm-agent-security]] — agent-runtime attack catalog; this doc is its doctrinal companion. (Deepened with 2024-2026 attack-vector content; cross-link maintained.)
- [[reference-distributed-authz]] — relationship-tuple AuthZ; capability discipline at the authz plane.
- [[reference-steelman-doctrine]] — Champion/Foil/Adjudicator used in §9 and §12.
- [[reference-code-review-expertise]] — click-count severity, auth-homogeneity review applied in §10. (Recently deepened with 2024-2026 review-methodology content; capability discipline is now treated as a first-class review axis.)
- [[reference-vr-methodology]] — surface enumeration applied to capability sets. (Recently deepened with agent-runtime VR content; the agent attack surface is the agent's current capability set.)
- [[reference-cicd-supply-chain]] — Component Model as supply-chain-defensible substrate; WIT manifests as reviewable/signable/attestable composition contracts.
- [[reference-ssrf-url-parsing]] — URL canonicalization for destination capabilities.
- [[reference-macos-apple-security]] — iOS entitlements as platform-layer precedent; Apple PCC as production capability-typed cloud reference.
- [[reference-formal-verification-protocols-expertise]] — capability-protocol formal-verification techniques; seL4-style end-to-end verification applied to A2A capability handshake. (Doc authored post-original; relevant to §5.7 and §11.8.)
- [[reference-post-quantum-cryptography-expertise]] — PQC signature schemes for capability-token unforgeability; relevant to SPIFFE SVID, UCAN, Biscuit token-format choices in §11.8 under the 2030+ PQC migration deadline.
- [[reference-confidential-computing-expertise]] — TEE attestation plus capability discipline; the Apple PCC pattern (§2.11) generalized to the broader confidential-AI substrate.
- [[reference-semgrep-rule-authoring]] — rule authoring discipline; recently deepened with MCP integration content for static-analysis-derived capability inference (the §12.4 Adjudicator action item).

### Semgrep external posts cited

- Boberg, K. "A Security Engineer's Guide to MCP." Semgrep Blog, 29 Sept 2025.
- Boberg, K. "A Security Engineer's Guide to the A2A Protocol." Semgrep Blog.
- Boberg, K. "Security Like It's 1977: Capabilities for the Modern Agentic Web." Semgrep Blog, 28 January 2026. https://semgrep.dev/blog/2026/security-like-its-1977-capabilities-for-the-modern-agentic-web/ — the anchor for this doc.
