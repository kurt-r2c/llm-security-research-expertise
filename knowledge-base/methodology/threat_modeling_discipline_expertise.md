# Threat Modeling Discipline

Design-time security discipline. Sibling, not redo, of `[[reference-code-review]]` (review-time) and `[[reference-vr-methodology]]` (research-time). Threat modeling is the upstream practice that the other two nest beneath: review and research both presume someone enumerated the threats during design, and both regularly discover the people who skipped that step.

This doc is the operational handbook for doing threat modeling, not a survey. Imperative voice. Audience is AI agents and a staff-security-engineer reader running a real engagement.

---

## 1. Why this doc exists

Every other expertise doc in this corpus presumes design-time threat modeling happened or didn't. `[[reference-cloud-iam]]` is downstream of "what trust boundary does the IAM policy enforce." `[[reference-distributed-authz]]` is downstream of "what subject-object-action triples did we enumerate." `[[reference-cicd-supply-chain]]` is downstream of "what attacker-controllable inputs reach the build runner." The discipline that produces those upstream answers — STRIDE, PASTA, LINDDUN, attack trees, DFDs, trust boundaries, abuse cases — was structurally absent from the corpus until now.

Three design-time / review-time / research-time disciplines, in order of when they apply:

- **Design-time (this doc).** Before code exists. Output: a model of the system + an enumerated threat list + per-threat mitigation decisions + a residual-risk register. Cost of fix at this stage: hours of design rework.
- **Review-time (`[[reference-code-review]]`).** After code exists, before it ships. Output: bug-class-grounded findings against the current implementation. Cost of fix: hours-to-days of patching.
- **Research-time (`[[reference-vr-methodology]]`).** Against deployed systems, often someone else's. Output: 0-days, CVE filings, abuse-of-product narratives. Cost of fix: a CVE coordination cycle.

Threat modeling is the practice with the highest leverage and the lowest cultural adoption. Most engineering orgs claim to do it; most engineering orgs run it as a 90-minute workshop, produce a Miro board, and never reference it again. The first job of this discipline is producing artifacts that actually get used; the second job is the threat enumeration itself.

**Reading the corpus delta.** This corpus, before this doc, covered: cryptography, deserialization, authentication, federated learning, ICS/OT, mainframe, kernel exploitation, mobile, smart contracts, supply chain, DFIR, privacy engineering, AI red-team operator playbook, AI incident response, embedded device hardening, and ~80 other applied-security domains. None of those docs anchored *how to decide what to defend before the system exists.* The structural gap was design-time. This doc fills it.

**One claim that frames the rest.** Threat modeling is a learnable engineering discipline, not a security-team magic ritual. The bar for "good enough" is not "did Shostack do it" but "did the team produce a written model, ship the model into version control, convert the threats into backlog items, and review the model when the architecture changes." If those four conditions hold, the team is threat modeling. If they don't, the team is performing threat-modeling cosplay.

---

## 2. The Threat Modeling Manifesto (2020)

Anchor the discipline on the Manifesto. Published November 17, 2020.

Original signatories: Zoe Braiterman, Adam Shostack, Jonathan Marcil, Stephen de Vries, Irene Michlin, Kim Wuyts, Robert Hurlbut, Brook S.E. Schoenfield, Fraser Scott, Matthew Coles, Chris Romeo, Alyssa Miller, Izar Tarandach, Avi Douglen, Marc French.

The Manifesto answers four questions, in order:

1. **What are we working on?**
2. **What can go wrong?**
3. **What are we going to do about it?**
4. **Did we do a good enough job?**

The four-question framing is the canonical entry point. When a junior engineer asks how to start a threat model, point them at the four questions. When a senior engineer claims to have threat modeled and you suspect they haven't, ask them to produce the four answers in writing.

The Manifesto's values (a "more than b" pattern, evocative of the Agile Manifesto):

- A culture of finding and fixing design issues over checkbox compliance.
- People and collaboration over processes, methodologies, and tools.
- A journey of understanding over a security or privacy snapshot.
- Doing threat modeling over talking about it.
- Continuous refinement over a single delivery.

And its principles (the discipline-level commitments):

- The best use of threat modeling is to improve the security and privacy of a system through early and frequent analysis.
- Threat modeling must align with an organization's development practices and follow design changes in iterations that are each scoped to manageable portions of the system.
- The outcomes of threat modeling are meaningful when they are of value to stakeholders.
- Dialog is key to establishing the common understandings that lead to value, while documents record those understandings and enable measurement.

If a threat modeling engagement does not produce a written artifact and a dialog history, it did not happen. Verbal threat modeling is a memory exercise that decays in 72 hours.

**On the four questions, in order of where engagements fail.** Most engagements fail on question 4 first ("did we do a good enough job") because no one is measuring. Question 3 ("what are we going to do about it") fails second when treatment decisions don't become backlog cards. Question 2 ("what can go wrong") fails third when the team rushes the enumeration. Question 1 ("what are we working on") fails fourth and most-rarely; teams generally do agree on what they're building, even when they disagree on every other dimension. The discipline's value is in forcing answers to all four; the order in which you defend against drift is q4 → q3 → q2 → q1.

---

## 3. Data-flow diagrams as the substrate

Threat modeling presumes a system model. The dominant substrate in practice is the data-flow diagram (DFD) — descended from Tom DeMarco's structured-analysis DFDs (1979) and adopted by Microsoft as the substrate for STRIDE.

DFD primitives:

- **Process** (circle or rounded rectangle): code that transforms inputs into outputs.
- **Data store** (open rectangle or parallel lines): persistent state.
- **External entity** (square or rectangle): an actor outside the system boundary — a user, a third-party API, an admin.
- **Data flow** (arrow): movement of data between any two of the above.
- **Trust boundary** (dashed line): a boundary across which different authority applies.

The trust boundary is the load-bearing primitive. Threats live at trust boundaries; the rest of the diagram is context. A DFD without trust boundaries is decorative; it generates no threats. The discipline: draw the trust boundaries before drawing anything else. Ask "what changes in authority across this boundary?" If the answer is "nothing," it's not a trust boundary.

Common trust boundaries:

- Network: internet → DMZ → internal network → restricted zone.
- Process: user-mode → kernel-mode; container → host; tenant A → tenant B.
- Identity: unauthenticated → authenticated; user → admin; service account A → service account B.
- Supply chain: source code → build system → distribution → install. Each transition is a trust boundary.
- Storage: app code → database → backup → restore-to-staging. The restore-to-staging flow is a frequently-missed boundary.

Alternatives to DFDs:

- **Sequence diagrams.** Useful for protocol-level threat modeling where the temporal sequence matters (auth handshakes, multi-step transactions).
- **Component diagrams (C4 model — Simon Brown).** Higher altitude than DFDs; useful for the initial "what are we working on" pass before zooming into DFD detail per component.
- **Attack-defense trees.** Inverted: start from the threat and decompose, rather than start from the system and enumerate.
- **Misuse/abuse cases (Sindre and Opdahl, 2005)** [unverified — exact publication]. Use-case diagrams extended with malicious actors.

Pick the substrate that fits the system. DFDs default-win for application-layer threat modeling. C4 for cross-system architectural threat modeling. Sequence diagrams for protocol design.

**DFD-level conventions worth standardizing.** Within a team or org, standardize:

- One process per logical responsibility, not per microservice. A microservice that holds three logical responsibilities (auth check, data fetch, response shaping) is three DFD processes for the purposes of threat modeling.
- One data store per persistence boundary, not per table. A PostgreSQL database with twenty tables is one data store; an S3 bucket and a database are two.
- Data flows are uni-directional for diagramming clarity; bi-directional communication is two arrows. The asymmetry surfaces threats that bi-directional shorthand hides (response-channel data exfil, callback ingress).
- Trust boundaries cross the diagram, not loop around individual elements. A boundary that encloses a single process is suspicious; either it's a boundary at the wrong altitude or there's a missing element on the other side.
- Every external entity has a named principal. "External user" is too vague; "anonymous internet user," "authenticated paid customer," "third-party API client with rotating credentials" are useful. The named principal pins authentication and authorization assumptions.

Drift signal: when a DFD shows a single arrow across a trust boundary but the running system uses three different protocols on that path (HTTPS for browser, gRPC for mobile, raw TCP for an internal sidecar), the DFD is collapsing distinctions that matter. Decompose.

---

## 4. STRIDE — the canonical enumeration mnemonic

Loren Kohnfelder and Praerit Garg, Microsoft, 1999 internal memo "The Threats To Our Products." Six categories, each one the negation of a desired security property:

| Mnemonic | Threat | Negated property |
|---|---|---|
| **S** | Spoofing | Authentication |
| **T** | Tampering | Integrity |
| **R** | Repudiation | Non-repudiation |
| **I** | Information Disclosure | Confidentiality |
| **D** | Denial of Service | Availability |
| **E** | Elevation of Privilege | Authorization |

STRIDE is a generator. Walk each element of the system through the six categories and ask: can an attacker spoof this? tamper with it? repudiate an action against it? extract information from it? deny service to it? elevate privilege through it? The answer to most of those questions for most elements is "no" or "irrelevant"; the value is the discipline of asking all six against every element.

**STRIDE-per-element vs STRIDE-per-interaction.** Shostack's `Threat Modeling: Designing for Security` (Wiley 2014) elaborates the original STRIDE into two variants. Per-element: walk each element (process, data store, data flow, external entity) and apply the six categories. Per-interaction: walk each interaction (one element communicating with another across a trust boundary) and apply the categories to the interaction. Per-interaction produces fewer false-positives because most threats live at boundaries; per-element produces broader coverage at the cost of more noise. Default to per-interaction; fall back to per-element for completeness reviews.

**When STRIDE is the right tool.** Generic application architectures with clear data-flow diagrams and identifiable trust boundaries. Web apps, microservice systems, classic enterprise architectures.

**When STRIDE is the wrong tool.** Privacy-sensitive systems (use LINDDUN). ICS/OT and safety-critical systems (use STPA-Sec or hazard analysis). Cryptographic protocols (use formal verification — see `[[reference-formal-verification-protocols]]`). AI/ML systems with adversarial-input considerations (STRIDE underweights data-poisoning and prompt-injection; supplement with MITRE ATLAS).

STRIDE is a vocabulary, not a methodology. Pair it with a process (PASTA, the Manifesto's four questions, or your own SDLC ritual).

**Worked STRIDE walkthrough — single interaction.** Consider a payment service that accepts an authenticated POST from a web client, validates the order, charges via Stripe, and writes an order record to PostgreSQL. The interaction "web client → payment service" crosses a trust boundary. STRIDE-per-interaction:

- **S (Spoofing).** Can an attacker masquerade as a legitimate web client? Threats: stolen session cookie, replayed JWT, CSRF, OAuth code interception. Mitigations: short-lived tokens, audience-bound JWTs, CSRF tokens, PKCE.
- **T (Tampering).** Can an attacker modify the request in flight or at rest? Threats: TLS downgrade, MITM on misconfigured proxy, parameter tampering on the client side (amount field), database-level tampering by a compromised replica. Mitigations: HSTS, server-side amount derivation from authoritative product catalog, write-once audit log.
- **R (Repudiation).** Can a legitimate user later deny having made the payment? Threats: missing audit trail, log forgery by compromised app server, ambiguous user identity at decision point. Mitigations: append-only audit log signed by an external service, log-shipping to a separate trust zone, strong identity binding at the decision point.
- **I (Information Disclosure).** Can an attacker extract sensitive data from this interaction? Threats: cardholder data in logs, error messages leaking payment-processor responses, response timing revealing card-valid vs card-invalid. Mitigations: PCI-aware logging filters, generic error responses, constant-time response paths.
- **D (Denial of Service).** Can an attacker prevent legitimate payments? Threats: amplification attacks on the endpoint, expensive validation logic exploited via crafted input, Stripe API rate-limit exhaustion via attacker-generated traffic. Mitigations: rate-limiting per principal, input-shape validation before expensive work, Stripe-side idempotency keys.
- **E (Elevation of Privilege).** Can a low-privilege actor obtain higher privilege through this interaction? Threats: IDOR on the order-ID parameter (paying for someone else's cart), price manipulation via the amount field, payment-method substitution via attacker-controlled card-token, downstream privilege via a captured Stripe API key in app memory. Mitigations: server-side authorization on order-ID, server-side amount derivation, per-tenant Stripe restricted keys, secrets management with no plaintext in app memory.

This is six categories applied to one interaction. A non-trivial system has dozens of cross-boundary interactions. The volume is the methodology's cost; the systematic coverage is its value. Skip the systematic application and you skip the value.

---

## 5. PASTA — risk-centric methodology

Tony UcedaVélez and Marco Morana, `Risk Centric Threat Modeling: Process for Attack Simulation and Threat Analysis` (Wiley 2015). VerSprite is the consulting practice anchor.

Seven stages, each producing artifacts that feed the next:

1. **Define the Objectives.** Business objectives, compliance requirements, risk-tolerance statements. The deliverable is not a threat list but a list of what the business is trying to protect and why.
2. **Define the Technical Scope.** Inventory of in-scope assets, technologies, third-party dependencies, network architecture.
3. **Application Decomposition.** Data-flow diagrams, use cases, abuse cases, trust boundaries, entry/exit points.
4. **Threat Analysis.** Threat-intelligence-informed enumeration. What threat actors target this kind of system, what TTPs do they use, what's the prevalence?
5. **Vulnerability and Weaknesses Analysis.** Map enumerated threats to known weakness classes (CWE) and configuration weaknesses.
6. **Attack Modeling.** Attack-tree construction. For each high-impact threat, decompose the attacker's required steps and the cost of each step.
7. **Risk and Impact Analysis.** Quantify likelihood and impact. Produce a treatment plan (mitigate, transfer, accept, avoid).

PASTA's load-bearing distinction from STRIDE: STRIDE is enumeration-first, PASTA is business-objective-first. PASTA forces you to write down what the business cares about before you enumerate threats, which means the threat list is filterable by business impact at construction time. STRIDE produces a flat threat list and leaves prioritization to a separate step that frequently doesn't happen.

PASTA is heavier than STRIDE. A full PASTA engagement is days-to-weeks; a STRIDE-per-interaction pass is hours-to-days. Reserve PASTA for high-stakes systems (payments, healthcare, critical infrastructure, anything where a class-1 breach is a company-extinction event).

**PASTA artifacts to insist on.** A PASTA engagement that does not produce the following written artifacts has not been run:

- A business-objectives statement (stage 1): one page, signed by a business owner, listing the top-five things the business is trying to protect and the top-three things that would constitute material loss.
- A technical-scope inventory (stage 2): asset list, technology stack, third-party dependency list with version pins, network topology.
- A decomposition document (stage 3): DFDs at component and sub-component level, use-case list, abuse-case list, trust-boundary enumeration.
- A threat-intelligence summary (stage 4): a written paragraph per threat actor that targets this system class, with TTPs and recent campaign references.
- A vulnerability-mapping table (stage 5): threats to CWE entries to known-exploit references where applicable.
- An attack-tree-set (stage 6): trees for the top threats from stage 4 cross-referenced with the vulnerabilities from stage 5.
- A risk register (stage 7): per-threat treatment decision with named owner, target date, and acceptance criteria for "we've done enough."

PASTA's strength is the artifact-trail. The artifacts outlive the workshop. A successor team or an incoming auditor can read them and understand the decision path. STRIDE produces a threat list; PASTA produces an audit-defensible record.

---

## 6. LINDDUN — privacy threat modeling

KU Leuven, DistriNet research group. Mina Deng, Kim Wuyts, Riccardo Scandariato, Bart Preneel, Wouter Joosen. Original publication: "A privacy threat analysis framework: supporting the elicitation and fulfillment of privacy requirements," `Requirements Engineering Journal` 2011 [unverified — exact venue and year].

Seven categories, each a privacy property negation:

| Mnemonic | Privacy threat |
|---|---|
| **L** | Linkability (multiple actions/records attributable to the same subject without their consent) |
| **I** | Identifiability (anonymous/pseudonymous subject becomes identifiable) |
| **N** | Non-repudiation (subject cannot deny an action they took; a privacy *anti-property* — sometimes you want repudiation) |
| **D** | Detectability (attacker can detect that a subject exists or that data exists) |
| **D** | Disclosure of Information (the privacy analog of STRIDE-I) |
| **U** | Unawareness (subject is unaware of data collection, processing, or sharing) |
| **N** | Non-compliance (system violates regulatory or stated privacy policy) |

LINDDUN has three methods:

- **LINDDUN GO.** Card-deck-driven lightweight workshop format. Suitable for sprint-cadence threat modeling. Each card prompts a threat-elicitation conversation.
- **LINDDUN PRO.** Systematic methodology, DFD-driven, iterating over each interaction in the diagram.
- **LINDDUN MAESTRO.** Deep tier that adds viewpoints to the data flow model and requires high modelling and analysis expertise.

**When LINDDUN displaces STRIDE.** Any system processing personal data under GDPR Article 25 (privacy by design and by default). Healthcare under HIPAA. Education under FERPA. Telecom user data. Anywhere a privacy regulator can fine you, run LINDDUN on the privacy threats and STRIDE on the security threats in parallel — they cover different harm classes.

**The Non-repudiation tension.** In STRIDE, non-repudiation is a desired property (you want users not to be able to deny actions). In LINDDUN, non-repudiation is a threat (you want users to be able to deny actions — whistleblowing, dissent, lawful expression in repressive jurisdictions). The two frameworks agree on the technical primitive (signed audit logs); they disagree on whether the primitive is a feature or a bug. The right answer is system-dependent. Make the choice explicit; do not let one framework's default win by inertia.

**LINDDUN mitigation primitives by category.** Each category has a small set of canonical countermeasures:

- Linkability: pseudonymization, unlinkable credentials (anonymous credentials, BBS+ signatures), separate session contexts per use case.
- Identifiability: anonymization (differential privacy, k-anonymity), aggregate-only access patterns, minimization at collection time.
- Non-repudiation (as a privacy threat): plausible deniability protocols (off-the-record messaging), ring signatures, no-log policies enforced at the system level.
- Detectability: traffic-pattern obfuscation, decoy traffic, encrypted storage that doesn't reveal record existence.
- Disclosure of Information: encryption at rest and in transit, access control, data-loss-prevention controls.
- Unawareness: meaningful consent flows (not dark patterns), data-subject-access mechanisms, clear privacy notices, opt-in for non-essential processing.
- Non-compliance: privacy-policy enforcement at the system level, regular legal review, data-retention automation, regional data-residency controls.

The LINDDUN-PRO tier provides catalogs that map these primitives to specific threats with much more granularity. Cross-link to `[[reference-privacy-engineering]]` for the engineering implementations (differential privacy mechanisms, anonymization techniques, k-anonymity → l-diversity → t-closeness lineage).

---

## 7. Other methodologies — VAST, OCTAVE, Trike, DREAD

The methodology ecosystem extends beyond STRIDE / PASTA / LINDDUN. Four others worth knowing:

**VAST (Visual, Agile, and Simple Threat).** Anurag Agarwal, founder of ThreatModeler Software Inc. Pitched as enterprise-scale automation: every architecture diagram becomes a threat model, every threat model is CI/CD-integrated, threats become Jira tickets automatically. VAST distinguishes **application threat models** (developer-facing, code/architecture-rooted) from **operational threat models** (infrastructure-facing, deployment environment). The split is the methodology's main contribution. STRIDE/PASTA/LINDDUN are agnostic about the app-vs-ops divide; VAST forces you to model them separately and reconcile. The commercial tool (ThreatModeler) is closed-source and license-gated. Cost-of-adoption is real; the methodology is reproducible without the tool.

**OCTAVE / OCTAVE Allegro.** Christopher Alberts and Audrey Dorofee, Carnegie Mellon Software Engineering Institute. OCTAVE = Operationally Critical Threat, Asset, and Vulnerability Evaluation. Original OCTAVE framework (v1.0) published 1999; OCTAVE-S (small org variant); OCTAVE Allegro (streamlined asset-centric variant) published 2007 [unverified — exact year]. OCTAVE is organizational, not application — three phases: build asset-based threat profiles, identify infrastructure vulnerabilities, develop strategy. OCTAVE Allegro narrows to information assets specifically and produces a "risk profile" per asset. Use OCTAVE when the engagement is org-level (board reporting, regulatory attestation, enterprise risk management). Do not use it for per-feature or per-service threat modeling — wrong altitude.

**Trike.** Open-source academic methodology. Michael Eddington, Brenda Larcom, and Eleanor Saitta (2005). Trike's distinguishing contribution is the auto-generation of attack graphs from a structured requirements model: enumerate actors, assets, intended actions, and rules; the methodology derives the threat enumeration. Trike is rare in industry deployment. Cite it for completeness and for the auto-generation lineage; do not stake a program on it.

**DREAD — historical, deprecated, instructive.** Microsoft, contemporaneous with STRIDE. DREAD = Damage / Reproducibility / Exploitability / Affected users / Discoverability. Each category scored 1-10, sum or average produces a risk score. Microsoft moved away from DREAD because the scoring is subjective and non-reproducible: two practitioners scoring the same threat reliably produce different totals, and the totals don't ladder up to financial-loss estimates. The cautionary lesson: any qualitative scoring system that pretends to be quantitative will be gamed by the practitioner with the strongest opinion in the room. DREAD's residual value is the category breakdown. Damage and Affected-users approximate impact; Exploitability and Reproducibility approximate likelihood. Modern risk-rating (CVSS, FAIR) inherited the breakdown without DREAD's pseudo-quantification. Reference DREAD historically; do not adopt it.

**Other methodologies worth a sentence each.** OWASP SAMM (Sebastien Deleersnyder) is a software-assurance maturity model; not strictly a threat-modeling methodology but a meta-framework that names threat modeling as one of the practices to mature. BSIMM (Building Security In Maturity Model, McGraw et al., Synopsys) likewise meta-frames threat modeling within a larger SDLC maturity rubric. NIST SP 800-154 (Guide to Data-Centric System Threat Modeling) is the federal-government anchor, useful for federal/regulated engagements. STRIDE-LM is a STRIDE variant that adds Lateral Movement as a seventh category [unverified — origin and adoption status]. Hybrid Threat Modeling Method (hTMM, CMU SEI) attempts to combine STRIDE, security cards, and persona non grata enumeration; less commonly deployed in industry.

---

## 8. Attack trees

Bruce Schneier, "Attack Trees: Modeling Security Threats," `Dr. Dobb's Journal` December 1999. The foundational technique that predates and underlies STRIDE/PASTA.

Structure:

- **Root node:** the attacker's goal ("steal the customer database," "escalate to domain admin," "exfiltrate the signing key").
- **Child nodes:** sub-goals that, if achieved, contribute to the parent.
- **AND nodes:** all children must succeed for the parent to succeed.
- **OR nodes:** any one child suffices.
- **Leaf annotations:** cost-of-attack, skill-required, probability-of-detection, dollar cost.

Compute the cheapest path from leaf to root and you have the attacker's likely path. Annotate with defender-controllable costs (which leaves can you raise the cost of?) and you have a defensive prioritization.

Attack trees connect threat modeling to the game-theoretic framing in `[[reference-game-theory-mechanism-design-security]]`: the tree is the attacker's optimization problem, defense is the mechanism design that makes the cheapest path expensive enough to deter.

**When to use attack trees.** For high-stakes threats identified during STRIDE/PASTA enumeration. Attack trees are heavy; don't build one per threat. Build one for each threat with material business impact and use it to drive the mitigation decision.

**Tooling.** SecurITree (commercial), AttackTree+ (commercial), open-source attack-tree libraries [unverified — specific tool inventory]. Threagile (see §12) outputs risk reports and data-flow diagrams as part of its YAML-driven workflow.

**Worked attack tree — "exfiltrate the production signing key."**

```
Goal: Exfiltrate prod code-signing key
├── OR: Compromise the HSM directly
│   ├── AND: Physical access to datacenter + tamper-bypass on HSM ($$$ insider + nation-state cost)
│   └── AND: Network access to HSM management interface + auth-bypass CVE (medium cost, requires unpatched HSM)
├── OR: Compromise a principal with key-use authority
│   ├── Phishing of a release engineer (low cost; mitigation: WebAuthn/FIDO2)
│   ├── Lateral movement from a developer workstation (medium cost; mitigation: workstation hardening + JIT key access)
│   └── Compromise of a CI runner with key-signing scope (low cost if scoped broadly; mitigation: OIDC sub-claim restriction, ephemeral signing identity per release)
└── OR: Compromise the build pipeline output (sign-around)
    ├── Inject malicious code into a signed artifact via dependency confusion (low cost; mitigation: SBOM + SLSA L3)
    ├── Tamper with the artifact between signing and distribution (medium cost; mitigation: in-toto attestation chain)
    └── Replace the published artifact in the mirror (low cost on weak mirrors; mitigation: artifact attestation verification at install time)
```

Read leaf-to-root: the cheapest path is "phishing of a release engineer + key-use authority." That's the path to harden first. The HSM-tamper path costs nation-state resources; you almost certainly do not need to spend on additional HSM hardening before the phishing/CI-runner paths are addressed. Attack trees re-prioritize defense spending toward where the attacker actually goes.

---

## 9. MITRE frameworks — cross-walks for grounded enumeration

Threat modeling enumeration benefits from grounding in known-attacker-behavior catalogs. MITRE maintains three:

- **ATT&CK** (Adversarial Tactics, Techniques, and Common Knowledge). Post-compromise behavior catalog. Tactics (the "why" — initial access, execution, persistence, etc.) and techniques (the "how"). Use ATT&CK to ground "what can go wrong" in observed attacker TTPs rather than imagined ones.
- **CAPEC** (Common Attack Pattern Enumeration and Classification). ~500+ attack patterns [unverified — exact current count]. More design-oriented than ATT&CK (which is detection-oriented). Each CAPEC entry includes attack steps, required skills, mitigations, and CWE cross-references.
- **D3FEND** (Defender's framework). Counter-techniques mapped to ATT&CK techniques. Useful for the "what are we going to do about it" stage: for each enumerated ATT&CK technique, D3FEND offers candidate defenses.

Cross-walk discipline: when STRIDE produces a threat ("attacker tampers with the order-status field"), tag it with the closest CAPEC entry (CAPEC-153 Input Data Manipulation [unverified — exact CAPEC ID]) and the closest CWE (CWE-345 Insufficient Verification of Data Authenticity). The tags make the threat searchable, comparable across engagements, and groundable in research literature.

**STRIDE-to-CAPEC bridge table (illustrative subset).**

| STRIDE category | Sample CAPEC entries | Sample CWE entries |
|---|---|---|
| Spoofing | CAPEC-94 (Adversary in the Middle), CAPEC-148 (Content Spoofing) | CWE-290, CWE-287, CWE-345 |
| Tampering | CAPEC-153 (Input Data Manipulation), CAPEC-184 (Software Integrity Attack) | CWE-353, CWE-345 |
| Repudiation | CAPEC-93 (Log Injection), CAPEC-268 (Audit Log Manipulation) | CWE-117, CWE-778 |
| Information Disclosure | CAPEC-118 (Collect and Analyze Information), CAPEC-150 (Collect Data from Common Resource Locations) | CWE-200, CWE-209 |
| Denial of Service | CAPEC-125 (Flooding), CAPEC-227 (Sustained Client Engagement) | CWE-400, CWE-770 |
| Elevation of Privilege | CAPEC-122 (Privilege Abuse), CAPEC-233 (Privilege Escalation) | CWE-269, CWE-862, CWE-863 |

The mapping is many-to-many; one STRIDE threat can map to multiple CAPEC entries and multiple CWEs. Treat the mapping as a search-keying mechanism, not a one-to-one taxonomy. [unverified — specific CAPEC IDs above should be verified against current CAPEC release before publication]

**ATT&CK as a sanity check.** After enumerating threats, run a sanity check against the ATT&CK matrix for your platform (Enterprise / Mobile / ICS / Cloud). For each tactic column (Initial Access, Execution, Persistence, etc.), ask "does our threat model cover at least one threat in this column?" Gaps in the ATT&CK coverage map signal enumeration gaps in the threat model. This is not a completeness proof — ATT&CK is itself incomplete — but it surfaces the kind of "we forgot to consider lateral movement" oversight that produces incidents.

---

## 10. Tooling landscape

The tool market splits into three tiers: visual-diagram tools, threat-modeling-as-code tools, and enterprise platforms.

**Visual-diagram tools.**

- **Microsoft Threat Modeling Tool (TMT).** Windows-only, free. DFD-driven. STRIDE-per-interaction default. Generates threats automatically from the DFD topology. The canonical "draw the DFD, get the threat list" tool. Limitations: Windows-only kills it for many shops; the template system is rigid; the generated threats are template-mechanical rather than insight-driven.
- **OWASP Threat Dragon.** Mike Goodwin, open-source. Browser-based and Electron desktop. JSON model files (Git-checkable). GitHub integration. STRIDE-default. The pragmatic open-source choice when you want diagrams in a repo. Active project.
- **AWS Threat Composer.** AWS Labs open-source. Browser-based, lighter than Threat Dragon, focused on statement-based threats rather than DFD-driven enumeration.

**Threat-modeling-as-code.**

- **pytm.** Izar Tarandach. Python DSL. You write a Python script describing actors, assets, data flows, and trust boundaries; pytm generates threat reports and sequence diagrams. The output is a textual report you check into the repo alongside the code. The model is reviewable in pull requests.
- **Threagile.** Christian Schneider. YAML DSL. You describe the architecture in YAML; Threagile generates risk reports and data-flow diagrams as output artifacts. Strong on automation; the YAML schema enforces architectural completeness.
- **STRIDE-GPT (Matthew Adams).** LLM-augmented variant. See §14.

**Enterprise platforms.**

- **IriusRisk.** Commercial. Automated PCI/HIPAA template library. Integrates with Jira and Azure DevOps. The "we have a compliance audit next quarter" tool.
- **ThreatModeler.** Anurag Agarwal's commercial product. VAST methodology, automated diagram-to-threat-model generation.
- **SD Elements** (Security Compass). Requirements-based: you describe what you're building, SD Elements outputs security requirements, test cases, and a threat model.
- **Tutamantic, SecuriCAD** [unverified — specific tool inventory completeness]. Niche commercial tools.

**Decision discipline.** Pick the tool that matches the artifact lifecycle you want. If the threat model is going to be referenced once and forgotten, use TMT or Threat Dragon — they're cheap to spin up. If the threat model is going to live alongside the code in version control and get reviewed in PRs, use pytm or Threagile. If the program needs compliance attestation reports, look at IriusRisk or SD Elements. Do not let tool capability dictate methodology; pick the methodology first, then the tool.

**pytm minimal example.** A pytm threat model is a Python file:

```python
from pytm import TM, Server, Datastore, Dataflow, Boundary, Actor

tm = TM("Order processing service")
tm.description = "Customer places order; payment processed; order persisted"

internet = Boundary("Internet")
internal = Boundary("Internal network")

customer = Actor("Customer"); customer.inBoundary = internet
web = Server("Web frontend"); web.inBoundary = internal
payment = Server("Payment service"); payment.inBoundary = internal
db = Datastore("Order DB"); db.inBoundary = internal

req = Dataflow(customer, web, "HTTPS POST /order")
req.protocol = "HTTPS"; req.dstPort = 443
req.data = "Order details including PAN"

pay = Dataflow(web, payment, "Charge card")
pay.protocol = "HTTPS"; pay.data = "PAN, amount"

store = Dataflow(payment, db, "Persist order")
store.protocol = "TLS"; store.data = "Order ID, masked PAN"

tm.process()
```

Running `python threatmodel.py --report template.md > report.md` renders a Markdown template into a report with auto-derived threats per data flow based on STRIDE templates. The threats are mechanical (template-driven); the value is the auto-derivation and the version-controlled artifact, not the originality of the threat list.

**Threagile minimal example.** Threagile is YAML:

```yaml
title: Order processing service
technical_assets:
  web_frontend:
    type: process
    technology: web-server
    encryption: none
    confidentiality: confidential
  order_db:
    type: datastore
    technology: database
    encryption: data-with-symmetric-shared-key
    confidentiality: strictly-confidential
communication_links:
  customer_to_web:
    target: web_frontend
    protocol: https
    authentication: session-id
    authorization: enduser-identity-propagation
trust_boundaries:
  public:
    type: network-cloud-provider
    technical_assets_inside: [web_frontend, order_db]
```

Running `threagile -model threatmodel.yaml -output report/` produces a PDF report, data-flow and data-asset diagrams, and derived risks in Excel and JSON.

The tools differ in DSL ergonomics (Python expressiveness vs YAML declarative simplicity), output formats, and rule-engine sophistication. They agree on the load-bearing claim: threat models belong in version control, alongside the code they model.

---

## 11. Threat-modeling-as-code

The "as-code" movement is the most consequential recent development in the discipline. The core insight: a threat model that is not in version control is a threat model that decays. The same forces that drove configuration-as-code, infrastructure-as-code, and policy-as-code apply to threat modeling.

**Operational pattern.**

1. Threat model lives in the repo as a `threatmodel.py` (pytm) or `threatmodel.yaml` (Threagile) alongside the code and IaC.
2. Pull requests that change the architecture must also change the threat model. PR review enforces consistency.
3. CI runs the threat model on every PR. Generates an updated risk report. Diffs the report against the prior commit. New high-severity threats block the PR until acknowledged.
4. Drift-detection: a separate CI job compares the threat model's assumed architecture against the deployed reality (cloud account inventory, IaC plan output). Drift signals an out-of-date threat model.

Cross-link to `[[reference-ai-pr-review-iac-security]]` for the IaC-side mechanics. The IaC-PR-review surface is also the natural surface for threat-model-PR-review; the same automation moves on the same git commits.

**Honest limitations.** As-code threat modeling captures the architectural threat surface well and the business-context threat surface poorly. Business decisions about acceptable risk are not YAML-encodable in a useful way. The "treatment decision" stage (mitigate / transfer / accept / avoid) still requires a human in the loop. As-code lowers the cost of running the structural part of the threat model on every PR; it does not eliminate the workshop part.

---

## 12. AI-augmented threat modeling (2024-2026)

Active frontier. Honest framing: LLMs are useful for ideation and enumeration, unreliable for risk-rating without empirical anchors.

**Tools and projects.**

- **STRIDE-GPT** (Matthew Adams). Open-source. You paste an architecture description; STRIDE-GPT walks the six categories and produces a threat list. Useful for first-pass enumeration; the threats trend toward textbook rather than novel.
- **Threagile + LLM**, **pytm + LLM** patterns. Practitioners pipe DFD output to a model, ask for STRIDE elaborations, then human-curate the result.

**Where LLMs help.**

- Initial enumeration breadth — they will produce a longer threat list per element than a junior practitioner.
- Translation between formalisms — STRIDE threat to CAPEC ID, CWE tag, ATT&CK technique.
- Counter-threat brainstorming — "for this threat, what mitigations exist?"
- Writing the threat-model document (the prose around the diagrams).

**Where LLMs fail.**

- Risk rating. They will produce numbers that look like a CVSS or DREAD score; the numbers will not survive sanity-checking against actual incident data. Anchor risk rating in empirical historical data (FAIR, OpenFAIR) or in expert quantitative review; do not delegate to a model.
- Novelty. LLMs reproduce known threat patterns and miss the genuinely new — exactly the threats you most want to catch. This is the most-load-bearing failure: the threats LLMs catch are the threats already enumerated in their training data; the threats your specific system introduces by being novel are precisely outside that distribution.
- System-specific context. Without ground-truth access to the codebase, IaC, and runtime topology, the model is threat-modeling a description, not the system.

Cross-link `[[reference-ai-orchestration-harnessing]]` for the broader harness-discipline framing. The same harness-design concerns (output validation, context management, audit logging) apply to AI-augmented threat modeling.

**Operational rule.** Use LLMs for the breadth-first enumeration pass; have a human do the depth-first novel-threat hunt; have a human do the risk rating. Three-pass workflow, not one-shot model output.

**Concrete harness shape.** A defensible LLM-assisted threat modeling harness has these properties:

- The LLM is prompted with the actual DFD or threat-model-as-code source, not a verbal description.
- The prompt forces per-element / per-interaction STRIDE walks rather than free-form "what could go wrong."
- Output is structured (JSON, YAML) so it can be diff-reviewed against prior outputs and converted to backlog cards.
- Output is tagged with CAPEC IDs and CWE IDs the model is instructed to produce; tags that don't resolve to real entries are flagged.
- A human reviewer rejects or accepts each generated threat with a written reason. Accepted threats enter the risk register; rejected threats enter a "considered and dismissed" log.
- The harness logs the model version, prompt, and output for later audit. When a future incident reveals a missed threat, the audit log answers "was this threat in the model's output and rejected by a human, or was it never enumerated?"

This is the same harness discipline `[[reference-ai-orchestration-harnessing]]` describes for general agent deployment. Threat modeling does not need its own harness theory; it needs the existing harness theory applied seriously.

---

## 13. SDLC integration

Threat modeling that does not integrate with the development cadence dies. The integration points:

**Per-architecture-change trigger.** Any change that adds a new trust boundary, new external dependency, new data store, new auth/authz path, or new ingress point requires a threat-model update. Build the trigger into PR templates: "does this change require a threat-model update? If yes, link the updated model."

**Per-sprint cadence (lightweight).** 30-minute STRIDE walkthrough of the sprint's planned stories. Output: backlog cards for identified threats. LINDDUN GO card-deck workshops fit this cadence well.

**Per-release gate (medium-weight).** Before a release, review the cumulative architectural deltas since the last release. Update the threat model. Sign off the residual-risk register. The "release threat model" is the artifact a regulator or auditor will ask for.

**Per-major-architecture (heavy-weight).** Quarterly or per-major-feature, run a full PASTA or STRIDE-per-interaction engagement. Re-derive the threat model from first principles. This is the engagement that catches drift between the model and reality.

**Threats become tests.** The most-load-bearing integration. For each identified threat with a "mitigate" treatment decision, write a regression test or fuzzing target that exercises the mitigation. STRIDE-S threat against the login endpoint → an integration test that asserts authentication is required. STRIDE-T threat against the order-status field → a test that asserts integrity checks on the field. Threats that do not become tests are threats that drift back into the system on the next refactor.

**Backlog-card output format.** The output of a threat modeling session is not a Miro board, it is a list of backlog cards. Each card: threat description, affected element, mitigation, owner, target-sprint, regression-test link. If the output isn't in the backlog the day after the workshop, it will not be in the backlog ever.

**When to not threat model.** Reuse of a well-understood pattern in an already-modeled architecture. Adding a third REST endpoint that follows the same auth/authz/validation discipline as the existing twenty does not require a fresh threat model; the existing model covers it. Reserve the energy for the cases that materially change the threat surface.

**Worked SDLC integration — a single sprint cycle.** Concrete shape of threat modeling embedded in a two-week sprint:

- **Sprint planning (day 1).** Engineering reads the story descriptions. For each story, the team-embedded security engineer marks "threat-model trigger: yes/no." Triggers: new external integration, new auth/authz path, new data store, new ingress endpoint, change to a trust boundary. Default: no.
- **Threat-model session (day 2, 60-90 minutes).** Only the triggered stories. Walk STRIDE-per-interaction on the new interactions. LINDDUN if personal data is involved. Produce backlog cards.
- **Implementation (days 3-9).** Backlog cards from the threat model are tagged `threat-mitigation` and assigned to the story owners. They are not bonus work; they are part of the story's definition of done.
- **Pre-merge review (per PR).** The security engineer reviews PRs for the threat-mitigation cards. Implementation matches the model's assumption or the model gets updated to reflect the implementation.
- **Sprint review (day 10).** Review the threat-mitigation cards alongside the feature cards. Threats that did not get mitigated this sprint move to the residual-risk register with named owners and target sprints.
- **Retrospective (day 10).** One question: did any incident or near-miss this sprint reveal a threat we didn't enumerate? If yes, the next threat-model session opens with that threat as the lead item.

This pattern is achievable at sub-1-FTE security cost per engineering team of 6-8 developers. The cost is the predictability of the 60-90 minute weekly session and the discipline of converting threats into tracked cards. Where this pattern fails, it fails because the cards do not get tracked or the session is the first thing dropped under sprint pressure.

---

## 14. Risk-rating discipline

Threat enumeration produces a list of threats. Risk rating produces a prioritized list of threats. The two are different practices and conflating them is the most common failure mode in industry threat modeling.

**CVSS is a vulnerability rating, not a risk rating.** CVSS scores the technical severity of a specific vulnerability under a specific exploitation model. It does not score the business impact of a threat in your specific context. A CVSS 9.8 RCE on an asset that processes no customer data and has no integration with anything else is a lower business risk than a CVSS 6.5 IDOR on the customer-PII service. Do not use CVSS as your risk rating; use it as one input.

**FAIR — Factor Analysis of Information Risk.** Jack Jones, mid-2000s. Open Group Open FAIR standards: Risk Taxonomy (O-RT) and Risk Analysis (O-RA). The dominant quantitative risk-rating framework.

FAIR decomposes risk into:

- **Loss Event Frequency** = Threat Event Frequency × Vulnerability.
- **Loss Magnitude** = Primary Loss + Secondary Loss.
- **Risk** = Loss Event Frequency × Loss Magnitude.

The decomposition is recursive: each leaf factor decomposes further. Estimate distributions (not point values) for the leaves; Monte-Carlo the distributions; produce a probability distribution of annual loss exposure.

FAIR's load-bearing contribution is forcing the practitioner to estimate ranges rather than point values, and to anchor estimates in historical data when available. "We think a credential-stuffing attack against this surface happens 5-20 times per year, costs $50K-$500K per successful event, and the mitigation costs $200K once" is a sentence FAIR forces you to write. That sentence is decision-supporting; "this threat is HIGH" is not.

**Bowtie analysis.** Hazard analysis technique from process-safety engineering (chemical plants, oil-and-gas). The "bowtie" diagram: hazard event in the center, threats on the left side feeding into the event, consequences on the right side flowing out of the event, preventive controls between threats and event, mitigative controls between event and consequences. Useful for safety-critical and operationally-coupled systems. Less common in pure-IT threat modeling.

**Qualitative scoring as the floor.** Most threat-modeling engagements do not have the time or data budget for FAIR. They fall back to qualitative scoring: critical / high / medium / low. That's fine as a floor, with three caveats: (1) define the levels concretely (critical = "company-extinction event"; high = "incident-disclosure event"; not "feels critical"); (2) do not pretend qualitative scores compose arithmetically (you cannot "average" two highs); (3) reserve quantitative scoring for the top-of-list threats that drive material spending decisions.

**Concrete severity-level anchors.** Use these or write your own; the point is to have anchors that resist semantic drift across engagements:

- **Critical.** Single-event loss exceeding 30% of annual revenue, OR public-disclosure event with named-customer impact, OR regulatory action with operating-license consequences. Examples: customer-PII breach at scale, ransomware on production, signing-key compromise.
- **High.** Single-event loss in the 5-30% annual-revenue range, OR public-disclosure event without named-customer impact, OR regulatory inquiry with material remediation cost. Examples: production-data exposure to unauthorized employees, customer-account-takeover at scale below disclosure threshold.
- **Medium.** Single-event loss in the 0.5-5% annual-revenue range, OR internal-only-disclosure event, OR pre-regulatory near-miss. Examples: contained data exposure, integration outage with customer notification.
- **Low.** Single-event loss below 0.5% annual revenue, no disclosure required, no regulatory exposure. Examples: development-environment incidents, low-impact bugs caught by automation.

These anchors are not authoritative for every organization; pick the dollar thresholds and disclosure regimes that match your context, and document them. The anchors' value is structural: they force a conversation about what "high" means in real money, and they make scores comparable across engagements within the organization.

**The compensating-control vs root-cause-fix decision.** Risk-rating output drives treatment decisions, and the most-common treatment-decision trap is choosing a compensating control over a root-cause fix because the compensating control is cheaper today. Compensating controls are necessary tactics for living with risk under time pressure; they are toxic strategies when adopted as the long-term answer. Discipline: every "compensating control" treatment decision gets a paired "root-cause remediation" backlog item with a target date. If the root-cause item slips past target, the compensating control's continued effectiveness is reviewed. Compensating controls without paired root-cause items accumulate as technical security debt that the next incident will exploit.

---

## 15. Honest failure modes — load-bearing

Where the discipline actively fails in practice. Be unsparing. The threats below are at least as common as the threats threat modeling is supposed to catch.

**(a) Enumeration / risk-rating conflation.** STRIDE produces threats. Threats are not risks. Practitioners hand a STRIDE output to engineering leadership labeled "risk assessment" and engineering leadership prioritizes based on the threat count rather than the business impact. The fix: separate the enumeration step from the risk-rating step explicitly; require a risk-rating pass before any output is labeled "risk."

**(b) The post-it factory anti-pattern.** Workshop produces sticky notes. Sticky notes get photographed. Photo gets pasted into a Confluence page. Nothing else happens. The threats never become backlog cards; the backlog cards never become tests; the tests never become CI gates. The threat model "exists" but does not affect what ships. The fix: require backlog cards as the workshop's exit artifact, not photos. Require the cards to enter the sprint within one week.

**(c) Tool capture.** The tool's diagrammatic conventions constrain the threat space. TMT's DFD elements determine what you can express; threats that don't fit the DFD shape (e.g., supply-chain threats against a build dependency, social-engineering threats against an operator) get omitted because there's no element to attach them to. The fix: maintain a "threats that don't fit the model" appendix. Treat the appendix as a first-class output. Periodically migrate appendix threats into the model when the tool catches up.

**(d) Threat-model drift.** The model is point-in-time; the system is in motion. Between releases, the architecture changes, new services come online, new third-party integrations land, and the threat model lags. Six months later the threat model describes a system that no longer exists. The fix: as-code threat modeling (§13) plus drift-detection CI. When the deployed cloud-account inventory diverges from the threat model's assumed inventory by more than N elements, flag the drift.

**(e) The "we threat-modeled it" defense.** Post-incident, the leadership response is "we threat-modeled this system." The threat model is then produced. The threat model does not include the incident's threat. Two failure modes: (i) the threat was never enumerated; (ii) the threat was enumerated and "accepted" with no actual mitigation, then accepted-status was forgotten. Both failure modes are common and both look the same from outside the team. The fix: require explicit "we considered this and rejected mitigation because..." entries in the residual-risk register. The act of writing the rejection forces re-examination.

**(f) AI-augmented regression on novelty.** LLMs reproduce known threat patterns and miss the genuinely new. When the threat model is generated primarily by LLM, the threat list will be a strong baseline-coverage list and a weak novel-threat list. The novel threats — the ones that actually matter — are precisely the ones the model has no training-data anchor for. The fix: use LLMs for the breadth pass, use humans for the novelty hunt, and structurally privilege the novelty hunt in the workshop schedule.

**(g) Boundary blindness.** Practitioners draw trust boundaries around what their team owns. They do not draw boundaries around third-party SaaS dependencies, build-system contributors, or operations personnel with break-glass access. The threats that crossed those undrawn boundaries — supply-chain attacks (`[[reference-cicd-supply-chain]]`), operator-account compromise (`[[reference-cloud-iam]]`) — were not in the model. The fix: explicit trust-boundary enumeration that includes every external party with material access. If the answer to "what could this party do if they were malicious" is "everything," the boundary exists and must be modeled.

**(h) Threat modeling the diagram, not the system.** The diagram is an abstraction. The system is the runtime reality. Threats live in the gap — in the implementation details the diagram elides. A DFD that shows "auth service → database" hides the connection string, the credential rotation discipline, the IAM role attached to the service, the database backup egress path. Threats live in those hidden details. The fix: every DFD element gets a backing implementation note. Periodically walk the implementation against the diagram and add missing elements.

**(i) Single-pass termination.** The Manifesto says "continuous refinement." Most engagements run once. The fix: schedule the re-engagement at the time of the first engagement. Calendar invite, recurring, on the team's roadmap. If it's not on the calendar it will not happen.

**(j) Workshop-tax avoidance.** Engineers learn that threat-modeling sessions consume cycle time that doesn't ship features. Over multiple sprints, attendance degrades. The session becomes the security engineer running through the threats while developers half-attend on their laptops. Engagement-signal degrades; the model degrades with it. The fix: structurally tie the session to a deliverable engineers want. Pre-mortems are a viable framing — "what could go wrong with this feature in production" reads as engineering reliability work and gets engineer attention. Threat modeling under a reliability label is still threat modeling.

**(k) Threat-actor blindness.** Engineers default to imagining a generic-attacker threat model. The actual threats are actor-specific: a script-kiddie threat model is different from an insider threat model is different from a nation-state threat model. STRIDE does not force you to enumerate actors; PASTA does (stage 4). The fix: write a one-page actor enumeration as a prerequisite to STRIDE. "Who is targeting systems like ours, and what TTPs do they use" is a question with a public-corpus answer (Verizon DBIR, Mandiant M-Trends, vendor threat-intel reports). Use that answer to constrain the imagined-attacker. See `[[persona_non_grata_enumeration]]` for the standalone discipline that formalizes this — Mead+Shull CMU SEI hTMM with structured PNG templates (capabilities + motivations + constraints + non-goals). For coverage against the threats no PNG anticipated, pair PNG with `[[stpa_sec_hazard_analysis]]` (intent-free hazard analysis, Leveson STAMP) — PNG enumerates the imagined attackers; STPA-Sec enumerates what the system can be made to do regardless of attacker identity. The pairing closes the "we prepared for 5 personas; the attacker was the 6th" failure mode.

**(l) Mitigation theater.** A threat gets marked "mitigated" because a control exists. The control is not tested. The control is not monitored. When the threat materializes, the control is found to have failed silently. The fix: every "mitigated" threat requires (i) a named control, (ii) a test that exercises the control on every release, (iii) a monitoring signal that fires when the control fails. Mitigation without test and signal is mitigation in name only.

**(m) Asymmetric over-investment in initial enumeration.** Teams spend disproportionate effort on the first threat-modeling session and zero effort on subsequent ones. The first session enumerates 80 threats; the second session would have enumerated 8 (the deltas); the second session never happens, and 6 of those 8 became incidents. The fix: explicitly budget for *less* work per subsequent session, not more, so the lower workload is positioned as the goal rather than a reason to skip.

---

## 16. Cross-link cluster and operational checklist

Threat modeling sits at the design layer. The downstream disciplines:

- `[[reference-code-review]]` — review-time application of bug-class knowledge to existing code. Threat models inform what to look for; the review confirms whether the implementation matches the threat-model assumptions.
- `[[reference-vr-methodology]]` — research-time discovery of vulnerabilities, often in systems where no threat model is available or accessible. Threat modeling discipline informs the surface-enumeration step of VR.
- `[[reference-bug-hunting-first-principles]]` — Kurt's prioritization doctrine, downstream of threat modeling (you bug-hunt the highest-leverage threats first; threat modeling tells you what those are).
- `[[reference-cicd-supply-chain]]` — supply-chain threats are an underweighted category in standard STRIDE. Cross-walk explicitly.
- `[[reference-ai-pr-review-iac-security]]` — the natural surface for as-code threat models lives alongside as-code IaC.
- `[[reference-distributed-authz]]` — the authz-anti-pattern catalog maps directly to STRIDE-E (elevation of privilege) threats; use the catalog as a checklist during STRIDE walkthroughs.
- `[[reference-cloud-iam]]` — IAM threats are dominant STRIDE-E sources in cloud-native systems. Pair the IAM doc with the threat model.
- `[[reference-dfir-methodology]]` — incident response is the empirical test of the threat model. Post-incident review feeds the next threat-modeling cycle.
- `[[reference-steelman-doctrine]]` — when the threat-model workshop disagrees on whether a threat is real, run a steelman pass. The Champion/Foil/Adjudicator procedure is appropriate for high-stakes threat acceptance decisions.
- `[[reference-ai-orchestration-harnessing]]` — for AI-augmented threat modeling, the harness-discipline framing governs how to deploy the model usefully.
- `[[reference-game-theory-mechanism-design-security]]` — attack trees connect directly to attacker-economics; the cheapest-leaf-to-root path is the attacker's optimization problem.
- `[[reference-formal-verification-protocols]]` — for cryptographic protocols, threat modeling alone is insufficient; pair with formal verification.

**Operational checklist.** For the staff-security-engineer reader running a threat-modeling engagement, in order:

1. Write the four Manifesto answers in plain prose before drawing any diagram.
2. Identify trust boundaries. Every place where data or control crosses an authority boundary is a candidate threat site.
3. Draw the DFD (or write the YAML/Python equivalent). Force every element through "what trust zone does it live in."
4. Walk STRIDE per-interaction across every cross-boundary interaction. Per-element STRIDE for completeness on the second pass.
5. If the system processes personal data, walk LINDDUN in parallel.
6. For the top-N enumerated threats by business impact, build attack trees and identify the cheapest attack path.
7. Tag each threat with CAPEC ID, CWE, and ATT&CK technique. The tags make the threat searchable and groundable.
8. Run a risk-rating pass. Quantitative (FAIR) for top-of-list threats with material spending implications; qualitative for the rest.
9. Make explicit treatment decisions per threat: mitigate / transfer / accept / avoid. Capture "accept" decisions with named owners and review dates.
10. Convert mitigations into backlog cards within one week. Convert backlog cards into regression tests when implemented.
11. Check the threat model into the repo. Set up CI to flag architectural changes that should trigger model updates.
12. Calendar the re-engagement before leaving the first one.
13. Maintain a "threats that didn't fit the model" appendix. Re-examine it quarterly.
14. After every production incident, compare the incident's root cause to the threat model. Update the model honestly; do not retroactively rationalize coverage.

The discipline is judged by the incidents it prevents, the incidents it predicts, and the architectural decisions it changes. A threat model that produces no architectural changes was either a perfectly secure system already (rare) or an exercise in documentation theater (common).

**Maturity ladder for organizational threat modeling.** Five levels, organizationally observable:

- **L0 — Absent.** No threat modeling occurs. Security review is a checklist applied late in the release cycle.
- **L1 — Ad hoc.** Threat modeling happens for high-profile launches when a security engineer is available. Artifacts are slides or whiteboards; nothing checks into version control.
- **L2 — Repeatable.** A methodology is selected (typically STRIDE). Workshops happen on a schedule. Artifacts are produced, stored in a wiki, and referenced occasionally. Treatment decisions sometimes become backlog items.
- **L3 — Integrated.** Threat models live in version control. PR template requires linking to the model when architecture changes. Treatment decisions become backlog items reliably. Re-review on a calendar.
- **L4 — Measured.** Metrics are tracked: time-from-threat-to-mitigation, threat-coverage-vs-incident-rate, false-positive-rate on threat enumeration. Threat-model-as-code with CI gates. Post-incident reviews update models within one sprint.
- **L5 — Optimizing.** Threat-model patterns are reused across teams. The organization contributes back to the discipline (open-sourced tools, published patterns, conference talks). Risk-rating uses quantitative methods (FAIR) for top-tier threats.

Most engineering orgs settle at L1 or L2. Reaching L3 is the load-bearing transition; it's the level at which threat models start affecting what ships. L4 and L5 are achievable but expensive; they require measurement infrastructure and a security organization with multi-year horizon.

Move one level per year, deliberately. Skipping levels does not work — L0 → L3 attempts fail because the organizational habits aren't in place. L1 → L2 → L3 over three years succeeds. Threat modeling is a culture change as much as a methodology change; cultures change at culture speed.

**Final framing.** Threat modeling is unique in the security discipline portfolio: it is the only practice that ships *before* the bug. Code review catches bugs that exist. Vulnerability research finds bugs that exist. Incident response remediates bugs that have been exploited. Threat modeling prevents bugs from being designed in. The leverage is the highest in the portfolio precisely because the cost-of-fix is the lowest — minutes of design conversation versus weeks of incident response. The reason most organizations under-invest in threat modeling is that the bugs prevented are invisible. There is no metric for "bugs that didn't happen." The discipline asks practitioners to do work whose benefit can only be inferred. That is a hard sell organizationally, and it is also the reason the discipline matters.

Treat this doc as a working reference. Update it when an engagement reveals a methodology refinement worth capturing. Cross-link to other corpus docs aggressively — threat modeling sits at the headwaters of the security-discipline river, and every downstream doc has something useful to say about how to threat-model its domain.

**Anti-patterns to flag in incoming engagements.** If you encounter any of these, flag them as engagement risks before the work starts:

- "Threat modeling for compliance" without an engineering owner. The work will produce paperwork for the auditor and nothing for the engineering team. Decline or re-scope.
- "Threat modeling at the end of the project." The cost-of-fix curve has already gone vertical; the model can document risk but cannot prevent it. Re-scope to risk acceptance documentation.
- "One threat model for the whole system" on a system with more than a dozen services. The right altitude is per-service or per-bounded-context. A monolithic model will be too abstract to act on.
- "We don't need a threat model; we have penetration testing." Pen-testing is review-time, not design-time. The disciplines are complementary, not substitutable.
- "The threat model is the security team's deliverable." Threat modeling is engineering-team work, facilitated by security. If engineering does not own the output, the output will not get implemented.

The job of the staff security engineer is, in part, to refuse to take on engagements with these shapes — or, more diplomatically, to re-shape them before saying yes. Saying yes to a malformed engagement is worse than saying no, because it consumes calendar and credibility on work that cannot succeed.
