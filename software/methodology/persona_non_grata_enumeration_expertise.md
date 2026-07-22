# Persona Non Grata Enumeration — Expertise Reference

Naming and resourcing your attackers as a threat-modeling discipline.

---

## 1. Why this doc exists

Threat modeling without a named attacker is enumeration without a subject.

STRIDE produces threat categories per element of a system. PASTA marches a business-impact analysis through seven stages. LINDDUN catalogs privacy harms. Misuse cases narrate hostile scenarios. Attack trees branch attacker decisions by cost and probability. Attack graphs explore the state space the attacker can traverse. Read across the threat-modeling family in [[reference-threat-modeling-discipline]], [[reference-misuse-abuse-case-modeling]], [[reference-attack-trees]], and [[reference-attack-graphs]] and a pattern emerges: each technique produces threats, decisions, paths, or hazards — and none of them inherently captures *who the attacker is, what they want, and what they cannot do*.

Persona non grata (PNG) enumeration fills that gap.

PNG is a deliberately small discipline. It does not replace STRIDE or attack trees; it gives them an actor. A misuse case authored without a named PNG drifts toward "an attacker does X." A misuse case authored as "Disgruntled Engineer Alice, who has Tier 2 production-database read access, wants to exfiltrate the customer table before her last day on Friday, and will not use her work laptop because she knows DLP runs there" produces specific, testable, detection-actionable artifacts. The persona is the load-bearing artifact.

The structural insight: STRIDE × PNG produces concrete threats. Misuse case × PNG produces a concrete narrative. Attack tree × PNG produces a concrete branching with realistic cost and skill bounds. Without the persona, each technique drifts toward generic adversary stereotypes — the "hooded hacker" that yesterday's [[reference-threat-modeling-discipline]] §15 honest-failure-modes block called out as the threat-actor-blindness failure mode.

This doc is the dedicated treatment of that mode.

Audience: threat modelers, security architects, AppSec leads, and AI agents running an adversary-modeling step before STRIDE walkthrough or misuse-case authoring. Scope: how to build PNGs that survive their first meeting with a real engagement, how to compose them with the rest of the threat-modeling family, and the failure modes that turn the technique into theater.

---

## 2. Origin and canonical references

The technique as published in security literature begins at the Carnegie Mellon Software Engineering Institute.

**Nancy Mead** (CMU SEI Fellow, longtime SQUARE/security-requirements lead) and **Forrest Shull** (then CMU SEI, later Build Security In Initiative) formalized persona non grata for security in CMU SEI work circa 2012-2014, culminating in the Hybrid Threat Modeling Method (hTMM) technical note `[unverified specific TN number — frequently cited as CMU/SEI-2018-TN-002]`. The hTMM combines three techniques the SEI group considered complementary: Security Cards (a workshop deck developed at the University of Washington by **Tamara Denning** and colleagues, later refined with CMU), persona non grata, and STRIDE. Mead and Shull's framing: each component covers a blind spot of the others. Security Cards drive brainstorming over "who, why, what, how"; PNG turns brainstormed attackers into developed personas; STRIDE applies a per-element coverage sweep with each persona in mind.

Personas as a positive-design technique predate this by roughly a decade. **Alan Cooper** introduced personas to interaction design in *The Inmates Are Running the Asylum* (Sams 1999) and refined the technique in *About Face* (Wiley 2007). UX personas are constructed as composite representations of *desired* users — concrete enough to design for, statistical enough to cover the segment. PNG inverts the technique: develop a persona for users you explicitly do not want, then design *against* them.

Adjacent lineage: **Mike Howard** and the Microsoft SDL community used informal attacker profiles as part of threat-modeling workshops in the 2000s, though without the formal "persona non grata" label. **Donald Firesmith**'s security-use-cases work (Journal of Object Technology 2003) and **Guttorm Sindre + Andreas L. Opdahl**'s misuse case papers (REJ 2005) include a "mis-actor" notation element, but treat it as a notational marker rather than a developed persona. **Brook Schoenfield**'s *Securing Systems* (CRC 2015) and *Secrets of a Cyber Security Architect* (CRC 2019) discuss attacker characterization as architectural input but stop short of the PNG construction discipline. **Adam Shostack** (Threat Modeling Manifesto signatory; *Threat Modeling: Designing for Security*, Wiley 2014) treats attacker-centric modeling as one of three legitimate framings but is famously skeptical of leaning too hard on it — his STRIDE-per-element advice is deliberately attacker-agnostic. **Tony UcedaVélez** (PASTA co-author, *Risk Centric Threat Modeling*, Wiley 2015) integrates attacker modeling at PASTA Stage 4 ("threat analysis") with explicit threat-actor profiles; PASTA's framing is the closest sibling to PNG in the mainstream methodology literature.

Marketing and customer-experience disciplines have used negative personas ("the customer we don't want to acquire") since at least the early 2000s. PNG borrows the inversion technique but anchors the resulting persona in adversary economics and threat intelligence rather than CAC and churn.

Threat-actor frameworks provide the empirical scaffolding for PNG construction. **MITRE ATT&CK Groups** profiles `[unverified specific count, ~140+ as of 2026]` — APT28, APT29, FIN7, Lazarus, Sandworm, Volt Typhoon, and the rest of the corpus — give PNG authors pre-built adversary characterizations with tradecraft (techniques), tooling, and target preferences. Crimeware reporting from **Mandiant**, **CrowdStrike**, **Recorded Future**, **Kaspersky GReAT**, and **Microsoft Threat Intelligence** keeps the persona library current. Cross-link to [[reference-threat-intel-methodology]] for the discipline of consuming and producing this material.

---

## 3. What a persona non grata contains

A usable PNG has eight elements. Each is operationally load-bearing; trim any of them and the persona drifts toward stereotype.

**Name and identifying handle.** "Disgruntled Engineer Alice." "Nation-State Operator Charlie." "Script-Kiddie Brad." "Insider-Contractor Carol." The name is not whimsy — humans reason about humans far better than they reason about "an attacker." Workshop participants engage differently with Alice than with "the disgruntled-employee threat actor." The name carries the persona through the rest of the threat-modeling session.

**Role and access.** What permissions does this persona have by virtue of who they are? An external script kiddie has unauthenticated access only. A disgruntled engineer has whatever access their last commit grants them. A vendor-engineer has access through the vendor's privileged tooling. This is the *initial state* in attack-graph terminology — cross-link to [[reference-attack-graphs]] §4 (initial state + goal predicates).

**Skills.** Technical proficiency, specialization, and any non-technical skills that matter (social engineering, multilingual fluency, regulatory knowledge). Borrow attack-tree skill-annotation conventions — cross-link to [[reference-attack-trees]] §3 — and the MITRE ATT&CK technique catalog for vocabulary.

**Motivations.** Financial, ideological, espionage, disruption, personal grievance, curiosity, contractual obligation. Motivation drives target selection and tradecraft. A financially motivated attacker will not burn a high-value capability on a low-value target; an ideological attacker may.

**Resources.** Time, budget, tooling, organizational support, opportunity. A nation-state has analysts, custom malware, and persistence. A script kiddie has Metasploit and a weekend. The resource bound is what stops PNGs from collapsing into omnipotent caricatures.

**Target preferences.** What systems, data, and capabilities this actor pursues. A ransomware operator pursues whatever produces ransom payments. A nation-state SIGINT operator pursues whatever produces intelligence. The preferences determine whether *your* system is a target — and which part.

**Detection-avoidance behaviors.** What this actor will or won't do to avoid being seen. Nation-state actors typically avoid noisy techniques. Crimeware operators often accept detection in exchange for speed. Insider attackers worry about audit logs visible to their colleagues.

**Constraints and non-goals.** What this actor *cannot* or *will not* do. A ransomware crew may refuse to target hospitals because it generates law-enforcement heat (the [unverified] post-Colonial-Pipeline "ethical ransomware" framing). A nation-state may avoid public attribution. A disgruntled employee will not commit federal crimes that put them in prison. Constraints are as informative as capabilities — they bound the defender's response.

The persona document is typically one to two pages. Longer drifts toward fiction; shorter drifts toward checkbox.

---

## 4. The canonical PNG taxonomy

Most engagements draw from a stock library. Specialize each persona to the system under analysis — generic personas produce generic findings.

**External attackers.**

*Script kiddie.* Low technical skill. Broad opportunistic targeting using public tooling (Metasploit, Cobalt Strike pirated copies, off-the-shelf scanners). Motivations: bragging rights, low-effort fraud, DDoS-as-extortion. Most useful for evaluating the baseline of a system's exposure to commodity threats.

*Crimeware operator.* Moderate skill. Financial motivation. Tooling: ransomware-as-a-service kits, credential-stuffing botnets, malware loaders. Targets: anyone payable. Tradecraft: bulk phishing, exploit kits, supply-chain commodity attacks. Real-world anchors: Conti, LockBit, ALPHV/BlackCat operators.

*Organized crime / professional cybercriminal.* High skill. Financial. Spear phishing, insider recruitment, supply-chain compromise. Targets selected for value rather than volume. Anchors: FIN7, the Snowflake-customer attacker cluster of 2024 [[reference-ciam-consumer-identity]] §11, and the broader infostealer-driven ATO economy.

*Nation-state APT.* Very high skill and resources. Motivations: espionage, sabotage, pre-positioning. Long dwell times, custom tooling, willingness to burn zero-days. ATT&CK Groups corpus provides the source material — APT28, APT29, Sandworm, Volt Typhoon, Lazarus, Charming Kitten, MuddyWater. Sub-types matter: a Five Eyes SIGINT service has different constraints from a destructive APT.

*Hacktivist.* Variable skill. Ideological motivation. Goal is typically public disclosure or visible disruption rather than persistence. Anchors: Anonymous lineage, DDoSecrets, regional anti-government collectives.

*Competitor / industrial espionage.* Moderate skill. IP theft motivation. May be conducted by professionals hired by the competitor or by patriotic-hacker volunteers acting on behalf of state-aligned industry. Constraints: usually unwilling to risk discovery that would create legal exposure for the sponsor.

*AI-agent attacker.* New persona class as of 2024-2026. An agent (or agent operator) using LLM-driven tooling to scan, exploit, or pivot at machine speed. Distinct from script kiddie because LLM-augmented attackers can compose novel attack chains across the long tail. Treat as a separate persona for any system with public exposure.

**Internal attackers.**

*Disgruntled employee.* Moderate skill, insider access proportional to role, retaliation motive. Most damaging in roles with privileged access (engineering, finance, IT). Often has a clock: termination, denied promotion, or pending HR action.

*Departing employee.* Moderate skill, IP-theft motive, time-bounded by their notice period. The most-common insider threat in practice — they take customer lists, source code, or strategy documents.

*Negligent insider.* Low malice, accidental data exposure. Falls for phishing, mis-shares files, leaves cloud storage public. The threat model treats them as an attacker vehicle: defenses must contemplate that a credentialed user *will* be socially engineered.

*Privileged-access abuse.* High access, low-skill exploit path needed. May be coerced (financial pressure, extortion, blackmail). Distinct from disgruntled employee because the access already grants the capability.

*Compromised insider.* The attacker controls the insider's credentials via social engineering, infostealer malware, or supply-chain compromise. Pass-the-cookie, AitM phishing, and infostealer-driven SaaS takeovers (per [[reference-session-management]] §11) all produce this persona. The insider may not know.

**Vendor / supply-chain personas.**

*Insider-at-vendor.* Vendor's employee with access to your system via vendor's privileged tooling. Storm-0558-class. Cross-link to [[reference-cicd-supply-chain]] for the broader supply-chain threat model and to [[reference-ciam-consumer-identity]] §11 for the Okta-sub-processor incident shape.

*Compromised vendor.* Vendor's infrastructure is compromised; the attacker uses the vendor as a stepping stone. SolarWinds-class. CrowdStrike-channel-file-class. The vendor itself is the victim — the attacker is upstream.

**AI-system-specific personas (emerging).**

*Prompt-injection vandal.* Low skill, public injection of malicious instructions into web content / emails / shared documents an agent will retrieve. Goal: defacement, content manipulation, demonstration. Anchors: the public EchoLeak and ShadowLeak demonstrations.

*Data-exfil-via-tool-call operator.* Moderate skill, persistent. Targets specific organizations' agent deployments. Anchors: Clinejection, CurXecute, MCPoison, Comment-and-Control — see [[reference-ai-agent-session-management]] §9 for the 7-incident corpus.

*Prompt-reverse-engineer.* Low-skill, automated. Goal: reconstruct your system prompts, RAG sources, or model fine-tuning data. Often economically motivated (competitor doing model-distillation).

---

## 5. Hybrid Threat Modeling Method (hTMM) workflow

The CMU SEI hTMM is the canonical workflow integrating PNG with other threat-modeling techniques. It is one of several legitimate integrations — the workflow is illustrative rather than mandatory.

**Step 1: Security Cards workshop.** Use the UW/CMU Security Cards deck `[unverified current edition]` as a brainstorming aid. Cards prompt discussion across four dimensions: Human Impact, Adversary's Motivations, Adversary's Resources, and Adversary's Methods. The output is a brainstormed list of attacker concepts. Facilitator + 4-6 stakeholders. 1-2 hours.

**Step 2: Persona non grata development.** From the brainstormed list, select 3-5 personas. For each, fill in the eight elements from §3. Anchor in real-world threat intel (MITRE ATT&CK Groups, current threat reports). Develop constraints and non-goals as carefully as capabilities. 2-4 hours per persona; not all need to be developed in one sitting.

**Step 3: STRIDE-per-element walkthrough.** For each PNG, walk STRIDE across the data-flow diagram of the system. The persona's resources, skills, and motivations shape which threats are realistic and which are not. A nation-state PNG flags subtle threats (information disclosure via timing side channels) a script-kiddie PNG would skip. A disgruntled-employee PNG flags repudiation threats (the actor's identity is known; the question is what they can deny). 4-8 hours total across the persona set.

**Step 4: Risk rating and mitigation backlog.** Each threat produces an acceptance-criteria item or backlog ticket. The PNG provides the answer to "who would actually do this?" — a load-bearing input for risk rating that pure STRIDE elides.

Workshop tempo: a complete hTMM cycle for a moderately complex system is one to two weeks of part-time effort spread across stakeholders, with a half-day kickoff and a half-day closeout.

The 3-5 persona target is empirical. Fewer than 3 produces under-coverage; more than 5 produces fatigue and persona-quality decay. Drop personas that aren't producing distinct threats — overlapping personas waste workshop time.

---

## 6. PNG construction discipline

Most PNG failures trace to construction shortcuts. The following disciplines distinguish operational personas from sticker-on-the-wall theater.

**Avoid the "hooded hacker" caricature.** The default-generic external attacker — mysterious, unbounded, ski-masked — is operationally useless. They produce no specific threats and no specific mitigations. Replace with a named, role-specific persona drawn from real threat intel.

**Anchor in current threat intelligence.** A nation-state APT persona built without reference to ATT&CK Groups is fiction. A ransomware persona without reference to the current crimeware-operator landscape (LockBit succession, ransomware-as-a-service economics, dwell-time medians from Mandiant M-Trends or similar reports) misses the prevailing tradecraft. Refer to [[reference-threat-intel-methodology]] for the discipline of consuming threat reports without consuming the marketing.

**Bound resources realistically.** A nation-state actor is not omnipotent. They have priorities, target queues, deconfliction processes, and analysts who cost money. A small-business attacker is not a Hollywood mastermind — they use off-the-shelf tooling because writing custom tooling is uneconomical. Specific bounds beat vague capabilities every time.

**Develop constraints and non-goals.** What the persona will not do is as load-bearing as what they will. A nation-state actor may avoid public attribution; this informs which detection signals are useful (the actor will hide noisy techniques, so subtle techniques matter more). A ransomware crew may avoid hospitals (post-Colonial-Pipeline `[unverified informal norm]`); this informs sector-specific risk modeling. Constraints are *load-bearing* — without them every persona collapses to "infinite capability."

**Date your personas.** Tradecraft evolves. A PNG built in 2020 reflects 2020 tradecraft. By 2026 the same persona class uses LLM-augmented reconnaissance, infostealer-distributed pass-the-cookie, supply-chain pivots from SaaS sub-processors, and AI-agent-assisted spear-phishing. Refresh annually at minimum; refresh on major threat-landscape shifts (Snowflake-customer ATO wave, infostealer market consolidation, OAuth-grant-theft normalization).

**Make personas concrete, not statistical.** "The average ransomware operator" is less useful than "Brad, who runs a four-person LockBit affiliate cell out of a co-working space, has access to two zero-days that he keeps for high-value targets, and is currently working through a target list compiled from a public IP-camera index." The concrete persona surfaces specific defenses; the statistical persona surfaces averages.

**Document the persona source.** Where did this persona come from? Which threat report, which ATT&CK Group, which internal incident retrospective? Source-tagging keeps the persona auditable and refreshable.

Cross-link to [[reference-game-theory-mechanism-design-security]] for the adversary-economics framing — PNG construction implicitly assumes the attacker is rational under their own resource constraints, which is the Stackelberg-game framing.

---

## 7. PNG integration with sibling threat-modeling techniques

PNG composes with every other technique in the threat-modeling family. The pattern is the same in each case: the persona supplies the actor; the partner technique supplies the enumeration structure.

**PNG + STRIDE.** Walk STRIDE-per-element with each persona in mind. A script-kiddie PNG flags different STRIDE threats than a nation-state PNG. The composition is the hTMM workflow — see §5. Cross-link to [[reference-threat-modeling-discipline]] §4.

**PNG + misuse cases.** Each misuse case is told from a specific PNG's perspective. The mis-actor *is* the PNG. The misuse-case structured-text template (cross-link to [[reference-misuse-abuse-case-modeling]] §5) becomes far more concrete when the actor has a name, resources, and constraints. "Alice, Tier-2 access, last Friday, will not use her work laptop" produces a different basic-flow than "an attacker."

**PNG + attack trees.** Each PNG branches differently. The cost annotations, skill requirements, detection-risk weights, and time estimates are persona-specific. An attack tree built for a script kiddie has different branches and different probability weights from one built for a nation-state. Cross-link to [[reference-attack-trees]] §5 (quantitative analysis) and §10 (sensitivity analysis must be per-persona).

**PNG + attack graphs.** PNG defines the initial state (what the actor has at t=0) and the constraint set (what transitions are off-limits). Different personas explore different sub-graphs of the same overall state space. Cross-link to [[reference-attack-graphs]] §4.

**PNG + STPA-Sec.** STPA-Sec is deliberately intent-free — see [[reference-stpa-sec-hazard-analysis]] §5. The complement is to run STPA-Sec for intent-free hazard coverage and PNG for adversary-specific prioritization. The two techniques produce different but composable outputs; the PNG analysis ranks the STPA-Sec hazards by which adversary would actually pursue them.

**PNG + ATT&CK Groups.** ATT&CK Groups are pre-built persona templates for nation-state and crimeware actors. Importing a Group profile is the fastest way to bootstrap a PNG; the work is in adding system-specific context (what does this Group want from *your* system?). The mapping goes both ways: a PNG can be expressed as a subset of ATT&CK techniques the actor uses.

**PNG + adversary emulation.** Red-team exercises are PNGs operationalized. The red team plays the persona. Cross-link to [[reference-ai-red-team-operator-playbook]] for the operator-side discipline of running such engagements without slipping into capability theater.

---

## 8. Worked examples across domains

Four short worked examples illustrate the technique. Each compresses what a real workshop would expand.

**Web app: regional e-commerce site.**

*PNG 1 — Card-Stealing Crimeware Operator "Marco."* Moderate skill. Uses public Magecart-class skimming kits. Resources: a small affiliate budget and access to bulletproof hosting. Targets: any e-commerce site running a JS-injectable checkout. Tradecraft: third-party-script compromise via stolen developer credentials. Constraints: will not invest in custom zero-days for a single mid-tier target.

STRIDE × Marco produces: tampering of third-party scripts on the checkout page (the most-load-bearing threat), information disclosure of customer payment data, elevation of privilege via a compromised CDN account.

*PNG 2 — Competitor Scraper "ScraperOps."* Low skill, contracted by a competitor. Goal: pricing intelligence. Tooling: rotating residential proxies, headless browsers, off-the-shelf scraping platforms. Constraints: will not attempt account takeover (legal exposure).

STRIDE × ScraperOps produces: information disclosure via unauthenticated catalog endpoints, denial of service via aggressive scraping (incidental rather than intentional), no S/T/R/E/E in the classical sense.

*PNG 3 — Disgruntled Fulfillment-Warehouse Employee "Pat."* Low technical skill, high physical/insider access. Pat handles outgoing orders, sees customer addresses and order contents. Motivation: post-termination retaliation by leaking the customer list.

STRIDE × Pat produces: information disclosure via screenshot or manual export from the order-management UI. The defensive surface is HR-process, DLP, and audit logging — not crypto. This is exactly the kind of threat STRIDE-without-PNG would miss.

**CI/CD pipeline.**

*PNG 1 — Cryptominer Operator "TeamCM-class."* Moderate skill, financial. Targets: any cloud CI runner with credentials. Tradecraft: dependency confusion, malicious GitHub Action submissions, secrets-in-logs harvesting. Anchor: the TeamTNT lineage. Cross-link to [[reference-container-runtime-escape]] §13.

Attack-tree × TeamCM produces: branches rooted at "obtain CI execution," with leaves at "compromise a transitive npm dependency" (low cost), "register a typosquat" (low cost), "phish a maintainer for npm publish credentials" (moderate cost).

*PNG 2 — Nation-State Supply-Chain Attacker "SolarWinds-class."* Very high skill, espionage. Resources: development capacity for custom implants, OPSEC discipline. Targets: software vendors with downstream high-value customers. Tradecraft: long-dwell-time build-system compromise, signed-update channel abuse. Constraint: will not burn the implant on a low-value target.

Attack-tree × SolarWinds-class produces: a deep, low-probability-per-step tree culminating in signed-update poisoning. The mitigations are reproducible builds, SLSA L3+, sigstore — cross-link to [[reference-supply-chain-provenance]] and [[reference-cicd-supply-chain]].

*PNG 3 — Disgruntled Build Engineer "Sam."* Moderate skill, full admin on the build infrastructure. Motivation: retaliation against a planned layoff. Time-bounded: must act before HR offboarding completes.

Attack-tree × Sam produces: branches at "modify a build script," "exfiltrate signing keys," "introduce a logic bomb." The defensive surface is M-of-N approval for build-pipeline changes, signing-key HSM custody (cross-link to [[reference-hsm-operational-discipline]] §5), and audit-log monitoring with off-side review.

**AI-agent product (assistant with tool-use).**

*PNG 1 — Prompt-Injection Vandal "AnonInj."* Low skill, public. Plants malicious instructions in web pages, emails, or shared docs the agent retrieves. Goal: defacement and demonstration. Constraint: not interested in persistence.

*PNG 2 — Data-Exfil Operator "Clinejection-class."* Moderate skill, persistent. Targets specific orgs by injecting instructions into resources the agent accesses. Goal: long-running data exfiltration. Anchors: the 7-incident 2025 corpus referenced in [[reference-ai-agent-session-management]] §9.

*PNG 3 — Competitor Prompt Reverse-Engineer "Recon-Co."* Low skill, automated. Goal: reconstruct your system prompts and RAG sources. Tradecraft: bulk probing, prompt-leak techniques. Constraint: will not attempt destructive actions (legal exposure).

STRIDE × AnonInj highlights tampering of agent outputs. STRIDE × Clinejection-class highlights information disclosure and tampering of agent state. STRIDE × Recon-Co highlights information disclosure of prompt and corpus. Three personas, three distinct threat surfaces, three different mitigation backlogs.

**HSM / signing-key operations.**

*PNG 1 — Insider Collusion "Two of Five."* Moderate skill (operational), high access (each individual is an authorized key custodian). Goal: extract or misuse signing capability without detection. Constraint: must collude to defeat M-of-N quorum.

*PNG 2 — Social-Engineering Crew "SmartcardSE."* Moderate skill, social-engineering specialization. Goal: capture enough smart cards or PINs to assemble quorum. Tradecraft: pretexting against custodians, opportunistic theft.

*PNG 3 — Nation-State Hardware-Tampering "TPM-class."* Very high skill, espionage. Goal: side-channel or fault-inject the HSM under attacker-controlled conditions. Constraint: typically requires physical access; high attribution risk if discovered.

Cross-link to [[reference-hsm-operational-discipline]] §5 (officer roles + quorum) for the defensive surface.

---

## 9. PNG anti-patterns

Common construction failures, each of which converts the technique into theater.

**The hooded hacker.** A persona with no specifics. "An external attacker." "A sophisticated adversary." Produces no useful threats and no useful mitigations. The cure is naming, resourcing, and constraining.

**The infinite-resource adversary.** Every persona is a nation-state. Every attack is feasible. Produces either over-engineered defenses (build for the worst case, ignore feasibility) or paralysis (we can't defend against everything, so defend against nothing). The cure is bounded resources.

**The no-insider model.** The PNG set excludes credentialed actors. Misses the most-common real-world threats: departing employees, social-engineered credentials, infostealer-driven session theft. Always include at least one insider persona.

**One persona per system.** Different systems have different attacker pools. A B2B SaaS attracts different adversaries than a consumer e-commerce site. A national-security workload attracts different adversaries than a marketing site. PNG sets are system-specific.

**The persona without constraints.** Capabilities listed, constraints elided. Every adversary appears omnipotent. The cure is to write the constraints section first.

**The static persona.** Built once, never refreshed. Eventually models attackers who no longer exist while missing attackers who emerged. The cure is annual refresh on a schedule.

**The persona without operational integration.** PNGs documented in a wiki, never connected to backlog tickets, detection rules, or acceptance criteria. Same failure as misuse cases without mitigations — cross-link to [[reference-misuse-abuse-case-modeling]] §12.

**The persona that produces performative responses.** "Add more access controls" without addressing the social-engineering surface that defeated controls. Insider-threat personas in particular tempt this anti-pattern.

**The PNG-only program.** PNG without intent-free hazard analysis (STPA-Sec) misses threats no one's personas anticipate. The threat-modeling family is composable; rely on one technique alone at your peril.

---

## 10. 2024-2026 currency and AI-augmented PNG construction

The technique itself has not changed substantially since the hTMM publications, but the threat landscape it characterizes has shifted enough to require new persona templates and new construction tooling.

**LLM-augmented persona generation.** As of 2024-2026, LLMs are useful for brainstorming initial PNG candidates and drafting first-pass persona documents. The novelty-regression limit applies — see [[reference-threat-modeling-discipline]] §12 and [[reference-attack-trees]] §10. Use LLMs for breadth (cover the persona space), use humans for depth (add system-specific constraints, current-tradecraft anchors, and the constraints section that LLMs reliably under-develop). The three-pass workflow from threat-modeling-discipline §12 generalizes: LLM-breadth → human-novelty → human-risk-rating.

**AI agents as a new external-attacker persona class.** LLM-driven attackers can compose novel chains across the long tail at machine speed. Prompt-injection vandals, data-exfil operators, and prompt reverse-engineers are now first-class personas for any system with an LLM-mediated interface. The 7-incident 2025 corpus catalogued in [[reference-ai-agent-session-management]] §9 — Clinejection (Adnan Khan), CurXecute (Aim Labs), EchoLeak (Aim Labs), MCPoison (Check Point), Comment-and-Control (Johns Hopkins + Anthropic), PwnedRabbit (Kudelski → CodeRabbit), ShadowLeak (Radware) — provides concrete templates.

**AI agents as victims rather than attackers.** PNG inverts: the agent itself is the targeted "user" whose credentials and capabilities the attacker wants to abuse. The agent is not a persona; the *attacker driving the agent* is. Threat-model around the four agent-session shapes from [[reference-ai-agent-session-management]] §2.

**Infostealer-driven session theft as default tradecraft.** Pass-the-cookie / pass-the-token attacks have moved from niche to default in the 2023-2026 corpus. Crimeware-operator and crime-org PNGs should default to assuming infostealer-driven SaaS-session compromise rather than direct credential brute-force. Cross-link to [[reference-session-management]] §11 and [[reference-ciam-consumer-identity]] §11.

**Supply-chain personas have proliferated.** SolarWinds, Codecov, 3CX, MOVEit, the npm-worm corpus, the Snowflake-customer cluster, the Okta sub-processor incidents — each populates the supply-chain persona library. The vendor-insider and compromised-vendor personas should be developed for any system with non-trivial third-party dependencies.

**Behavioral biometrics for PNG-vs-real-user discrimination.** Emerging detection-side technique: distinguish a PNG-driven session from a legitimate user via behavioral signals. Cross-link to [[reference-anti-fraud-abuse-engineering]]. Useful for ATO-focused personas; not a replacement for upstream identity-binding.

**Threat-actor framework maturity.** ATT&CK Groups corpus has grown sufficiently that PNG construction for nation-state and crimeware personas can start from the Group profile and add system-specific context rather than starting from a blank page. This compresses Step 2 of hTMM substantially.

---

## 11. Honest failure modes

Where PNG goes wrong, and why.

**PNG construction is high-quality / low-volume.** A good persona takes 2-4 hours of focused work — drafting, threat-intel anchoring, constraint development, review. Teams that produce 10 personas in an afternoon produce 10 caricatures. The cap is empirical: 3-5 well-developed personas beat 15 thin ones.

**PNGs without constraints are theater.** The most-common failure mode. Capabilities lists are easy; constraint lists require thought about adversary economics. Without constraints, every persona is omnipotent and every threat is in scope. Write the constraints section *first*, before capabilities.

**PNG sets drift between teams.** The same product can have different PNG sets at the platform team, the application team, and the security team. Without cross-team coordination, threat-modeling outputs from different teams are not comparable. The fix is an org-level persona library that teams *adapt* rather than *recreate*.

**LLM-generated PNGs reproduce stereotypes.** Same novelty-regression as elsewhere in AI-augmented threat modeling. LLMs trained on threat reports reproduce the median description of each persona class; they under-develop constraints and over-develop tradecraft. Use them for breadth, not depth.

**PNGs decay.** A persona built in 2020 reflects 2020 tradecraft. The 2026 attacker uses AI-augmented reconnaissance, infostealer-distributed credential abuse, and supply-chain pivots through SaaS sub-processors. Annual refresh is the floor; refresh on major landscape shifts (Snowflake-customer wave, npm-worm publication, OAuth-grant theft normalization) is the operational reality.

**PNGs without operational integration are theater.** Every persona must produce backlog items: detection signatures, mitigation tickets, acceptance criteria, red-team scenarios. The structured chain — PNG → STRIDE/misuse-case → mitigation → test → green CI — must close. Cross-link to [[reference-misuse-abuse-case-modeling]] §12 for the parallel failure mode.

**Insider-threat PNGs often produce performative responses.** "Add more access controls" without addressing the social-engineering, employee-relations, or extortion vectors that defeat controls. The defensive surface for insider PNGs is HR-process, audit-log review, and detection-engineering — not just RBAC.

**PNG over-specification can blind to novel threats.** Defenders prepared for five specific personas may miss the sixth. PNG is necessary but not sufficient for coverage; pair with intent-free hazard analysis (STPA-Sec) for the threats no persona anticipates. Cross-link to [[reference-stpa-sec-hazard-analysis]] §12 for the symmetric failure mode (STPA-Sec produces robust defenses but cannot prioritize by adversary).

**Threat intel for PNG construction is uneven.** Nation-state APT data is rich (ATT&CK Groups, Mandiant APT reports, Microsoft Threat Intelligence profiles). Crimeware data is moderate (Mandiant M-Trends, CrowdStrike Global Threat Report, ransomware-victim leak sites). Insider-threat data is sparse — most insider incidents never become public, and the Verizon DBIR or CMU SEI insider-threat work `[unverified specific publications]` are the main public sources. Acknowledge the gaps when building insider personas.

**"We did PNG" as audit theater.** PNG appears in workshop slide decks but does not drive engineering work. Same failure shape as "we threat-modeled it" in threat-modeling-discipline §15 and "we did a CAST" in [[reference-cast-causal-analysis-stamp]] §12. The cure is operational integration: every persona ends in a backlog ticket.

---

## 12. Operational checklist

For threat modelers running a PNG exercise on a new system.

- Draft 3-5 PNGs spanning external, internal, and supply-chain categories. Resist drafting more in the first pass.
- For each persona: name, role/access, skills, motivations, resources, target preferences, detection-avoidance, constraints/non-goals. All eight elements.
- Source-tag each persona to a threat report, ATT&CK Group, or internal incident retrospective.
- Run STRIDE-per-element with each PNG. Note where personas produce different threats.
- For each surviving threat, produce a backlog ticket: mitigation, detection signature, or acceptance criterion.
- Pair with STPA-Sec or attack-graph analysis to cover threats no persona anticipated.
- Schedule annual refresh; set a calendar reminder.
- Publish the persona library at org level. Teams adapt rather than recreate.
- Connect PNGs to red-team / purple-team exercises. A persona that never gets emulated decays into fiction.
- Connect PNGs to incident response. Post-incident, ask: "Which of our PNGs would have anticipated this?" If none, add the new persona.

A persona is operational once it has produced at least one backlog ticket, one detection signature, and one red-team scenario. Until then, it is a document.

---

## 13. Cross-link cluster

- [[reference-threat-modeling-discipline]] — parent discipline; §15 honest-failure-modes anchors the threat-actor-blindness gap PNG fills
- [[reference-misuse-abuse-case-modeling]] — sibling; mis-actor in a misuse case *is* a PNG
- [[reference-attack-trees]] — sibling; PNG annotates trees with persona-specific cost/probability/skill
- [[reference-attack-graphs]] — sibling; PNG defines initial state and constraint set
- [[reference-stpa-sec-hazard-analysis]] — composable complement; STPA-Sec is intent-free, PNG is intent-specific
- [[reference-game-theory-mechanism-design-security]] — adversary economics; the Stackelberg framing implicit in resource-bounded personas
- [[reference-threat-intel-methodology]] — source discipline for PNG construction; ATT&CK Groups, threat reports
- [[reference-dfir-methodology]] — post-incident: which PNG matched, which was missed
- [[reference-ai-agent-session-management]] — §2 four-shape framing + §9 7-incident corpus drive AI-system PNGs
- [[reference-ai-red-team-operator-playbook]] — PNGs operationalized as red-team scenarios
- [[reference-cicd-supply-chain]] — supply-chain personas drawn from this corpus
- [[reference-hsm-operational-discipline]] — §5 quorum + ceremony as the defensive surface for insider-collusion personas
- [[reference-ciam-consumer-identity]] — §11 Snowflake-customer + Okta sub-processor incidents anchor compromised-vendor PNGs
- [[reference-anti-fraud-abuse-engineering]] — behavioral-biometric discrimination of PNG-driven vs legitimate sessions
- [[reference-code-review-expertise]] — review-time discipline; PNG informs which threats reviewers prioritize
- [[reference-session-management]] — §11 infostealer-driven session theft as default crimeware tradecraft
- [[reference-cast-causal-analysis-stamp]] — symmetric failure mode: "we did X" theater

A persona that never produces a backlog ticket is a sticker on a wall.
