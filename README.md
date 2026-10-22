# llm-security-research-expertise

Staff-level domain reference guides for security research and secure code review. Each doc synthesizes the working knowledge for one domain — a language's footguns, a bug class, an operational discipline, or a methodology — written to be read by an LLM coding agent (or a security engineer) before working in that domain.

## License

**AGPLv3.** See [`LICENSE`](LICENSE). This is a deliberate choice, not a default: AGPLv3's network-use clause means that embedding this corpus into a hosted product or service — including feeding it into an LLM's context, fine-tuning on it, or otherwise incorporating it into a system users interact with over a network — triggers the same copyleft obligations as distributing modified source, with no "we only host it, we don't distribute it" exception. If your organization wants to use this corpus in a commercial product without those obligations, that requires a separate license from the copyright holder — it isn't available by default.

**Exception: [`benchmarking/`](benchmarking/) is MIT-licensed** (see [`benchmarking/LICENSE`](benchmarking/LICENSE)). It holds the ablation harness, raw run outputs and write-ups behind the talk "So Long And Thanks For All The Compute"; the evaluation method is meant to be reused without restriction. Its corpora are synthetic or public CVE code.

## Layout

`skills/` holds Claude Code skills; see [`skills/README.md`](skills/README.md).

`software/static_analysis/` holds `marp_expertise.md` (Marp slide-deck authoring).

`software/` holds the domain guides, grouped by category:

| Category | Covers |
|----------|--------|
| `methodology/` | Threat modeling, attack trees/graphs, STPA-Sec, CAST, code review, steelman, VR methodology, bug-hunting first principles, fuzzing, game theory, AppSec program-building — plus the bug-hunting mental-model diagrams (`kurt_bug_model*`). |
| `principles-voice/` | Practitioner principle docs (Heasman AppSec, Botros DBA). |
| `language-footguns/` | Per-language unsafe-by-default behavior: C/C++, C#, Go, Java, JS/Node, Kotlin, Lua, PHP, PowerShell, Python, Ruby, Rust, Scala, shell, SQL dialects, Swift, Elixir/Erlang. |
| `vuln-classes/` | Cross-language bug classes: deserialization, shell/template/SSTI injection, prototype pollution, ReDoS, SSRF, XML parser differentials, request smuggling, race conditions, JS sandbox escape. |
| `appsec-web/` | Web/API security, authN/Z, identity, sessions: HTTP/web, GraphQL, sessions, SAML, WebAuthn/passkeys, distributed authz, CIAM, GNAP. |
| `cloud-containers/` | Cloud IAM, k8s, container/runtime/VM escape, service mesh (Istio/Cilium), zero-trust + SPIFFE workload identity. |
| `crypto-trust/` | Cryptography, PQC + migration, HSM ops, hardware attestation, DICE/PUF device identity, RATS/Veraison, reference values, confidential computing, privacy engineering, formal verification, secrets management. |
| `exploitation/` | Kernel (Linux/Windows), browser JS engines, WebAssembly, hardware side channels, reverse engineering, macOS memory corruption. |
| `platform-security/` | macOS/Apple, Active Directory/Windows, mobile, mainframe/legacy. |
| `ai-ml-security/` | Adversarial ML, federated learning, LLM/agent security, AI coding-tool + PR-review security, AI red-team + IR playbooks, agent orchestration, agentic-web capabilities. |
| `supply-chain/` | CI/CD supply chain, SLSA/provenance. |
| `networking/` | DNS/network infrastructure, WebRTC/real-time comms, wireless/RF/satellite. |
| `embedded-iot/` | Firmware, RTOS/embedded OS, embedded-device hardening. |
| `industry-verticals/` | ICS/OT, automotive, aviation/aerospace, medical devices, building automation, drones/UAV, smart-contract/EVM, blockchain/wallet/consensus, game consoles. |
| `detection-ir/` | Detection engineering, Falco/Tetragon runtime detection, DFIR methodology, threat intel, a ransomware-family deep-dive. |
| `trust-safety/` | Anti-fraud/abuse engineering, misinformation/influence ops, privacy-preserving advertising. |

## Integrating with Claude Code (or any LLM coding agent)

The plumbing is one rule in a `CLAUDE.md` plus a local clone: tell the agent to read the applicable guide before it works in a domain.

1. Clone somewhere stable:

   ```bash
   git clone https://github.com/kurt-r2c/llm-security-research-expertise.git ~/expertise
   ```

2. Add this rule to your user-global `~/.claude/CLAUDE.md` (applies to every project) or a project `CLAUDE.md` / `.claude/rules/` file, pointing the path at your clone:

   ```markdown
   - Before working on a problem with relevant context in `~/expertise/`
     (e.g., deserialization, SSRF, cloud IAM, a specific language's footguns,
     threat modeling, secure code review), read the applicable
     `software/**/*_expertise.md` doc(s) first — they synthesize
     staff-level domain knowledge and should inform approach, recommendations,
     and framing. The guide index is this repo's README.
   ```

3. (Optional) For on-demand recall instead of an always-on rule, add a one-line pointer per doc to your Claude memory index (`~/.claude/.../memory/MEMORY.md`):

   ```
   - [Deserialization expertise](path) — Java/Python/PHP/.NET gadget chains; read before triaging deser findings
   ```

   Claude surfaces the matching pointer when a task looks relevant and reads the full doc on demand. This keeps the always-loaded context small while still routing to the right guide.

### Finding the right doc

Naming is predictable: `<domain>_expertise.md`, language footguns as `<lang>_footguns_expertise.md`. Grep the directory or skim the layout above; each doc opens with its scope and a numbered section list.

## Conventions

Docs follow a fixed shape: a scope statement, numbered sections, an honest "failure modes / limits" section near the end, and `[unverified]` markers on claims not anchored to a primary source. Keep that shape when extending.

## Contribution

These guides synthesize publicly available security knowledge into reference notes, with `[unverified]` markers and primary-source citations where they matter; they are not original research. PRs are welcome — any contribution is accepted under the same AGPLv3 terms as the rest of the repo.
