# CAST — Causal Analysis based on STAMP

**Scope:** Post-incident systems-theoretic accident analysis methodology. Completes the STAMP-family trio with `stpa_sec_hazard_analysis_expertise.md` (pre-design hazard analysis with security extension). Distinct from `dfir_methodology_expertise.md` (NIST 800-61 IR lifecycle; CAST is the systems-theoretic methodology used inside the root-cause-analysis sub-phase) and from `ai_incident_response_playbook_expertise.md` (AI-tool-incident-specific operational playbook). Covers methodology + adoption in regulated industries + applicability to cybersecurity incidents + comparison with traditional root-cause analysis techniques.

**Audience:** Claude on future shifts + incident-response lead + safety / security engineer doing post-incident analysis in regulated industries (aviation, automotive, medical, nuclear) + organizations adopting STAMP family + CSRB-style cybersecurity review boards.

---

## 1. Why this doc exists

STAMP (Systems-Theoretic Accident Model and Processes) — Nancy Leveson's 2003-2011 reframing of accident causation — has two operational arms.
**STPA (System-Theoretic Process Analysis)** runs forward from design: enumerate hazards, derive unsafe control actions, propose constraints.
**CAST (Causal Analysis based on STAMP)** runs backward from a loss that already occurred: reconstruct the control structure, identify the inadequate control actions, surface the loss scenarios, recommend changes.

The STPA-Sec doc covers the forward arm with cybersecurity extensions. This doc covers the backward arm.
The two are deliberately symmetric — the control structure built for STPA analysis is the same artifact CAST reconstructs from an incident.
Organizations that have done STPA-Sec on a system can run CAST on incidents involving that system with most of the modeling already done.

The structural insight CAST makes operational: **most post-incident analyses focus on "what failed" — the component-failure model. CAST asks "why was the control structure inadequate" — the systems-theoretic model.**
Component-failure framing produces "patch the broken component" recommendations.
Systems-theoretic framing produces "redesign the control loop that allowed the broken component to cause loss" recommendations.
The latter are harder to derive and harder to implement, but they generalize.

The cybersecurity domain has historically used component-failure framing for incident review.
"The patch wasn't deployed." "The detection rule didn't fire." "The user clicked the link."
CAST applied to cybersecurity reframes: why was the patch-deployment control loop inadequate? Why did the detection-rule process model not capture this attack class? Why did the user-training feedback loop not develop the necessary process model in users?
The CSRB Storm-0558 review (April 2024 `[unverified specific date]`) is the closest publicly-available example of CAST-style analysis applied to a cybersecurity incident.

Read this doc when running a post-incident analysis on a complex socio-technical system.
Read alongside `dfir_methodology_expertise.md` for IR lifecycle context, `stpa_sec_hazard_analysis_expertise.md` for the pre-deployment counterpart, and `ai_incident_response_playbook_expertise.md` when the incident involves AI tools.

---

## 2. Origin and canonical references

CAST emerged from Nancy Leveson's STAMP research program at MIT. The methodology is documented across:

- **Nancy Leveson, *Engineering a Safer World: Systems Thinking Applied to Safety* (MIT Press, 2011).** Part III introduces CAST as the post-incident counterpart to STPA. The book is open-access on the MIT SafeWare site `[unverified specific URL]`.
- **Nancy Leveson, *CAST Handbook: How to Learn More from Incidents and Accidents* (MIT, ~2019) `[unverified specific publication year]`.** The operational manual — step-by-step procedure, templates, worked examples. Updated periodically as the methodology evolves.
- **John Thomas + MIT SafeWare collaborators** — ongoing CAST research; SafeWare lab publications extend CAST to AI-controlled systems + cybersecurity `[unverified specific paper attributions]`.
- **Nancy Leveson + Stuart Madnick** (MIT Sloan) — cybersecurity CAST applications. Madnick's CAMS (Cybersecurity at MIT Sloan) group has published CAST-based incident analyses `[unverified specific paper attributions]`.
- **MIT STAMP / STPA Workshops** — annual training events (in person + virtual) covering both STPA and CAST. The workshop materials are the operational tutorial Kurt-types and incident-lead-types consume.

Leveson defines accident as "an undesired or unplanned event that results in a loss." CAST analyzes realized losses. The methodology is applicable to near-misses but most published case studies analyze realized losses where the loss-event is unambiguous.

---

## 3. The CAST methodology — eight-step structure

CAST formalizes incident analysis as eight steps. The CAST Handbook groups the analysis into five steps (assemble basic information, model the safety control structure, analyze each component, identify control-structure flaws, create an improvement program); the eight steps here expand that sequence. Apply them in order; iterate when later steps reveal earlier-step gaps.

**Step 1: Identify the incident and the loss.** Define what happened in operational terms. The loss is the realized harm — patient death, aircraft destroyed, system compromised, customer data exfiltrated, deployment broken. Specificity matters: "the SolarWinds incident" is too broad; "Sunburst malware injected into Orion build pipeline, distributed to ~18,000 customers, used for follow-on intrusion at multiple federal agencies between March 2020 and December 2020" is the loss-scope CAST analyzes. Include the date range, the affected systems, the affected parties, the harm category, the harm magnitude.

**Step 2: Identify the system and the control structure.** Build the hierarchical control diagram — same artifact as STPA. Controllers (humans, software, organizations, regulators) at the top sending control actions down to controlled processes (the operational system) and receiving feedback up. For a cybersecurity incident the controllers might include: the vendor's engineering team, the vendor's security team, the customer's IT team, the customer's security team, the threat-intelligence-sharing community, the regulator (CISA, EU ENISA), the platform host (cloud provider). The controlled process is the deployed software. Control actions include: code commits, build executions, signing operations, deployments, detection-rule updates, threat-feed publications, advisory issuances. Feedback includes: telemetry, vulnerability reports, incident reports, audit logs, attestations.

**Step 3: Identify the inadequate control actions.** Walk through each controller-process relationship and ask: did the controller issue a control action that contributed to the loss? Or did it fail to issue one that would have prevented the loss? The categories match STPA's UCAs: provided when it shouldn't have been, not provided when it should have been, wrong timing or sequence, stopped too soon or applied too long. For Therac-25: the operator issued the radiation dose command at high energy because the software process model indicated low-energy mode — the control action was provided in conditions where it shouldn't have been.

**Step 4: Identify the loss scenarios.** For each inadequate control action, ask why the controller acted inadequately. The Leveson framework gives four categories:

- **Process model inaccurate.** The controller's model of the controlled process did not match reality. The Therac-25 operator's process model said "low-energy mode active" when the actual state was "high-energy mode active." The SolarWinds build-pipeline process model did not include "code injection by privileged attacker who has compromised the build server" as a state.
- **Inadequate control algorithm.** The controller's decision logic was wrong. The build pipeline did not have logic to verify integrity of intermediate artifacts. The detection system did not have logic to identify novel-but-similar-to-known attack chains.
- **Inadequate feedback.** The controller did not receive accurate or timely state information. Therac-25 operators received cryptic error messages that did not convey "the safety interlock has been bypassed." SolarWinds customers did not receive provenance attestations they could verify against build inputs.
- **Coordination failure between controllers.** Multiple controllers were involved and their actions did not compose correctly. The vendor security team and customer security team had no shared threat-intelligence channel that would have caught Sunburst earlier.

**Step 5: Identify the contextual factors.** What allowed the inadequate controls to develop? This is the systemic layer: organizational structure, regulatory environment, market pressures, training adequacy, staffing levels, communication channels, incentive structures. The Therac-25 manufacturer was operating in a regulatory environment that did not yet treat software-controlled medical devices as warranting the same scrutiny as hardware-controlled ones. The SolarWinds attackers exploited a build-pipeline culture across the software industry that had not adopted SLSA-style provenance.

**Step 6: Develop recommendations.** Based on the loss scenarios and contextual factors, propose changes. The recommendations target the control structure: change the control algorithm, add or modify feedback, change the process model, restructure coordination. The Therac-25 recommendations included: restore hardware interlocks, redesign error messages, require independent verification of safety-critical software, regulate medical device software. The SolarWinds-class recommendations included: SLSA L3+ build provenance, sigstore signatures on update channels, anomaly detection on update-channel-and-installation behavior, cross-vendor + cross-customer threat-intel sharing.

**Step 7: Translate to system changes.** Convert recommendations into concrete engineering, process, regulatory, or organizational changes with owners and timelines. This is the "make it happen" step that distinguishes CAST-as-report from CAST-as-improvement. Without step 7 the analysis is academic.

**Step 8: Implementation tracking.** Verify recommendations are applied, monitor for recurrence of the loss scenarios, update the analysis as the system evolves. This is the step most CAST analyses skip. The CAST report sits in a binder; the recommendations drift; the next incident reproduces the same control-structure inadequacy under different surface conditions.

The eight steps are presented sequentially but the methodology iterates. Step 4 often reveals that the control structure built in step 2 was incomplete (missing a controller, missing a feedback path); return to step 2. Step 5 may reveal a contextual factor that changes which control actions were truly inadequate; return to step 3.

---

## 4. Blameless framing — the cultural prerequisite

CAST presupposes blameless investigation. The systems-theoretic frame says: operators acted in ways that appeared reasonable given the information available to them and the process model they had developed; the question is why the control structure made wrong decisions appear reasonable.

This is not a courtroom argument. CAST does not exonerate; it analyzes. An operator who falsified a log entry is doing something with consequences, but CAST's question is not "punish the operator" — it is "why was the falsification incentive in place, why was the verification feedback absent, why did training not develop the process model that would have flagged the falsification as harmful." The recommendations then address the incentive, the verification, the training.

The "blame the operator" anti-pattern is the failure mode CAST exists to prevent. Traditional accident reports often conclude "pilot error" or "user error" or "operator error" and stop. CAST treats human error as the surface symptom of an inadequate control structure that allowed the error to cause loss. The deep question is not "did the human make a mistake" — humans make mistakes constantly — but "why did this mistake propagate to a loss instead of being caught by a controller higher in the control hierarchy."

Industries with mature safety cultures have adopted blameless analysis: commercial aviation (NTSB reports almost never recommend punishment as a primary outcome), nuclear power (INPO + NRC use blameless event review), commercial hospital systems with strong patient-safety programs (JCAHO-aligned). CAST formalizes the blameless frame within STAMP vocabulary, making the systems-theoretic argument explicit rather than depending on the analyst's intuition.

Cross-link to `dfir_methodology_expertise.md` for the broader Google-SRE-blameless-postmortem framing. The SRE postmortem template is CAST-compatible in spirit (action items target systems not individuals) but is less structured than CAST. CAST adds the control-structure diagram, the UCA categories, the loss-scenario enumeration.

The cultural prerequisite is load-bearing. CAST cannot be parachuted into an organization that demands a person-to-blame. The investigation will be performed but the recommendations will be filtered through the blame frame and emerge as personnel actions. If the organization is not ready for blameless analysis, the answer is not "do CAST anyway" — it is "build the blameless culture first, then do CAST."

---

## 5. CAST vs traditional root-cause analysis

Traditional RCA techniques are older than CAST, more widely deployed, and complementary in some uses. Know when to use which.

**5 Whys** — ask "why" five times to traverse a causal chain. Popularized by Toyota Production System. Strengths: fast, requires no training, surfaces obvious causal factors. CAST critique: linear chains oversimplify multi-controller systems. The Therac-25 loss was not "why → why → why → software bug" — it was the interaction of operator process model, software process model, hardware decommissioning decision, and regulatory environment. 5 Whys collapses this to a single chain and loses the structural insight. Useful as triage; insufficient as the only analysis.

**Fishbone (Ishikawa) diagrams** — brainstorm causes in categories (people, process, environment, equipment, materials, measurement).
Strengths: structured ideation, accessible.
CAST critique: useful for identifying candidate causes but does not capture control-structure relationships among them.
Ishikawa says "people and process contributed"; CAST says "control action from controller A to process B was inadequate because A's process model was wrong because A's feedback channel was inadequate."
The depth difference matters when recommendations have to land.

**Fault Tree Analysis (FTA)** — bottom-up component-failure decomposition.
Top event is the loss; children are immediate failures; descend until reaching basic events. Quantifies failure probabilities.
Strengths: rigorous for component-failure-dominated systems, supports probabilistic risk assessment.
CAST critique: FTA does not capture control-structure inadequacy.
If the system fails because two controllers' actions conflicted (neither component "failed" in isolation) FTA struggles.
FTA assumes failures compose by AND/OR; CAST recognizes control structures fail by interaction.

**Event Tree Analysis (ETA)** — forward scenario branching from an initiating event.
Used in nuclear PRA and aviation. Complementary to CAST: ETA enumerates how an initiating event propagates through barriers; CAST analyzes why the barriers were inadequate.

**AcciMap (Rasmussen + Svedung, 2000)** — systems-theoretic alternative mapping an accident across organizational levels from regulator down to physical processes.
Similar systems framing but less structured. Used as a lighter-weight CAST alternative.

**TRIPOD-Beta + STEP + MORT** — other event-and-causal-factors techniques in oil-and-gas / aviation / nuclear.
Each captures some systems-theoretic content. CAST distinguishes itself by grounding in control theory and providing the UCA-category enumeration as a systematic completeness check.

The strength of CAST relative to traditional RCA: the systematic enumeration of control-loop failure modes per UCA category. Given any inadequate control action, the analyst asks "process model inaccurate? control algorithm inadequate? feedback inadequate? coordination failure?" — and is forced to consider each. Traditional techniques rely on the analyst noticing the relevant causal factor; CAST forces a structured check.

The cost: CAST takes longer. A 5 Whys analysis takes 30 minutes. A fishbone takes 2 hours. A CAST analysis of a serious incident takes weeks of analyst time and produces a 30-100 page report. Use CAST when the incident is consequential enough to warrant the depth and when systemic recommendations are actionable.

---

## 6. Worked example — Therac-25 (Leveson's canonical case)

Therac-25 is Leveson's foundational case study. The radiation-therapy machine, developed by Atomic Energy of Canada Limited (AECL), delivered massive radiation overdoses to six patients between 1985 and 1987 (three died from the overdoses). The machine was a successor to Therac-6 and Therac-20, but with a critical architectural change: hardware safety interlocks present in earlier models were removed and replaced with software-controlled safety logic.

**Component-failure framing:** "software bug." The AECL initial investigation focused on the turntable-position microswitches; the now-famous data-entry race condition (when the operator changed parameters quickly, the machine was left in a state where the high-energy electron beam was active without the targeting filter in place) surfaced in later incidents. AECL fixes targeted the specific bugs. New incidents occurred. More bug fixes. More incidents.

**CAST analysis:** the systems-theoretic frame identifies multiple control-structure inadequacies that the component-failure frame missed.

*Inadequate control actions:* The software controller issued the "fire high-energy beam" control action when the targeting filter was not in place. Operators received error messages they could not interpret and chose to proceed. AECL did not pull machines from service after the first injury reports.

*Loss scenarios:*
- **Process model inaccurate.** The software's process model of the hardware state did not include the case where the operator had rapidly changed parameters; the model said "filter is in place" when the filter was not. The software replaced hardware interlocks that previously enforced the model-reality correspondence physically.
- **Inadequate control algorithm.** The software did not have logic to detect inconsistency between commanded-state and actual-state. There was no read-back of hardware position; the software trusted its model.
- **Inadequate feedback.** Operators received "MALFUNCTION 54" with no semantic explanation. The feedback channel from machine to operator did not convey "safety interlock has been bypassed; do not fire."
- **Coordination failure.** Multiple controllers (software, operator, AECL field engineers, regulatory bodies) were involved. AECL field engineers responded to early injury reports with assertion that the machine was safe; regulators (FDA in the US, CDRH at the time) did not yet have a strong framework for software-controlled medical devices. The threat-intelligence channel between hospitals that experienced incidents was nonexistent.

*Contextual factors:* The Therac-25 was developed in the early 1980s when software-controlled safety in medical devices was novel. AECL transitioned from a hardware-interlock design to a software-only design as a cost optimization. Regulatory frameworks had not caught up. Training for hospital physicists and operators did not include "the software might lie to you."

*Recommendations (CAST-style, Leveson 2011):* Restore independent hardware interlocks for safety-critical functions; redesign feedback (error messages with semantic content); require independent verification of safety-critical software; restructure regulatory oversight to keep pace with software-replaces-hardware transitions in medical devices; create cross-hospital incident-sharing channels.

**The lesson:** the "software bug" framing identified specific bugs and fixed them. The systems-theoretic framing identified that the architectural choice to remove hardware interlocks was itself the inadequate control action, and that no amount of software bug fixing would close the gap. The Therac-25 incidents drove much of the modern medical-device-software regulatory environment (IEC 62304, ISO 14971 — the medical device safety-engineering corpus). Leveson's analysis was foundational; cross-link to `medical_device_security_expertise.md` for the medical-device CVE corpus and FDA regulatory context.

---

## 7. Worked example — cybersecurity CAST (SolarWinds Sunburst, 2020)

Apply CAST to a cybersecurity incident. SolarWinds Sunburst (December 2020 disclosure) is one of the few cybersecurity incidents that has received quasi-CAST-style treatment in publicly-available analyses (CSRB has not published a Sunburst review as of `[unverified date]`; Mandiant + Microsoft + CISA + others have published partial analyses).

**The incident.** A threat actor (later attributed to APT29 / Cozy Bear / Russian SVR by US government attribution `[unverified specific attribution authority]`) injected the Sunburst backdoor into the SolarWinds Orion build pipeline, which delivered trojanized updates between March 2020 and June 2020. Compromised Orion updates were distributed to approximately 18,000 customers, including multiple US federal agencies and Fortune 500 companies. The attacker selected high-value subsets for follow-on intrusion. Discovery occurred in December 2020 when FireEye (now Mandiant) detected the attacker in their own environment.

**Control structure.** Controllers include: SolarWinds engineering team (controls the source code), SolarWinds build infrastructure (controls the build process), SolarWinds release engineering (controls the signing and distribution), SolarWinds security team (controls security monitoring), customer IT teams (control deployment), customer security teams (control detection), threat-intelligence vendors (control IOC publication), CISA (controls cross-government advisory), the broader software-vendor community (controls industry practice norms). Controlled process is the deployed Orion software and the downstream customer environments.

**Inadequate control actions.**
- The build-pipeline control did not detect injected code in compiled artifacts.
- The release-engineering control signed the compromised binaries (the signature attested to "SolarWinds built this" — true; not "this is what SolarWinds intended to ship" — false).
- The update-channel control distributed the compromised binaries to customers without provenance attestation customers could verify against build inputs.
- Customer security teams did not detect the post-install Sunburst behavior despite months of activity.
- Cross-customer + cross-vendor threat-intelligence channels did not surface the attack pattern earlier.

**Loss scenarios.**
- **Process model inaccurate.** SolarWinds build pipeline's process model did not include "code injection by privileged attacker on the build server" as a threat. The build server was treated as a trusted endpoint inside the SolarWinds perimeter; the process model assumed perimeter integrity.
- **Inadequate control algorithm.** Customer detection systems were configured for known signatures; Sunburst's behavior (delayed activation, DNS-based C2, low-and-slow data movement) was novel and signature-detection-resistant.
- **Inadequate feedback.** Customers received Orion update binaries but no provenance attestation. There was no in-band feedback that would have revealed the discrepancy between "code SolarWinds committed" and "code that ended up in the binary."
- **Coordination failure.** Cross-vendor threat intel sharing was immature. SolarWinds, FireEye, Microsoft, the affected federal agencies all had partial pictures; no controller had the integrated picture. The eventual detection came from FireEye noticing the attacker in their own environment, not from any vendor-level or customer-level detection of Sunburst itself.

**Contextual factors.** The software industry had not adopted SLSA-style build provenance. Vendor build pipelines were generally trusted as a black box. Cross-vendor threat-intel sharing was informal. Customer security tooling was signature-heavy. The Russian SVR threat actor had the patience and operational discipline to execute a multi-month build-pipeline compromise without detection.

**Recommendations.**
- **SLSA L3+ build provenance** with hermetic builds and independent build infrastructure attestation. Cross-link to `supply_chain_provenance_expertise.md`.
- **Sigstore signatures on update channels** with transparency log (cosign + Rekor) so customers can verify what was signed and detect divergence from public source.
- **Anomaly detection on update-channel content** comparing what was distributed to what should have been distributed based on source.
- **Per-installation behavior baseline** detecting novel-but-similar-to-known attack chains, not just known-signature attacks.
- **Cross-vendor + cross-customer threat-intel sharing** at machine speed with operational protocols.
- **Government-coordinated build-integrity standards** for vendors selling to federal agencies (later partially manifested as EO 14028 and CISA secure-software-development guidelines).

Cross-link to `cicd_supply_chain_expertise.md` for the GitHub Actions + build-pipeline attack surface and to `supply_chain_provenance_expertise.md` for the SLSA / sigstore / in-toto defense corpus.

The Sunburst CAST analysis illustrates the systems-theoretic frame applied to cybersecurity: the loss did not occur because SolarWinds engineers made a "mistake" or because customers were "careless." It occurred because the control structure across the software-vendor-ecosystem did not include controls that would have detected or prevented build-pipeline compromise by a sophisticated adversary. The recommendations are systemic — they require industry-wide adoption of new control practices.

---

## 8. CAST applied to AI/ML systems

AI-tool incidents (Clinejection GHSA-9ppg-jx86-fqw7, EchoLeak CVE-2025-32711, MCPoison, Comment-and-Control, ShadowLeak, CurXecute CVE-2025-54135) are amenable to CAST.
The methodology adapts naturally because AI systems have explicit controllers (LLM provider, AI-tool vendor, platform host, customer) with explicit control authorities.

**The control-structure question.** What controllers were involved? What control actions did they have? What process models did they maintain? What feedback did they receive?

For Clinejection: the AI-tool vendor (Cline) controlled its GitHub Actions issue-triage workflow, which ran `claude-code-action` with Bash, Write and Edit tools for any GitHub user. The LLM provider controlled the model.
The repository host (GitHub) controlled the Actions runner and the shared default-branch cache.
The control chain that produced the loss: attacker opens an issue whose title carries a prompt injection; the workflow interpolates the title into the agent prompt; the agent runs `npm install` on an attacker-controlled commit, giving code execution; the attacker poisons the Actions cache used by the nightly release workflows, exposing npm, VS Code Marketplace and OpenVSX publishing tokens. An unauthorized `cline@2.3.0` was published to npm on February 17, 2026.

**Inadequate control actions in the AI agent control structure.**
- The AI-tool vendor's MCP approval policy did not require re-approval when an already-approved MCP configuration was modified (MCPoison), and the triage workflow gave an agent fed untrusted issue text shell tools (Clinejection).
- The host's per-user customization (.cursorrules, AGENTS.md, CLAUDE.md) was treated as an instruction source without provenance verification.
- The customer's MCP-allowlist was either permissive-by-default or absent.
- The agent runtime's process model treated LLM output as authoritative rather than as a candidate action to be verified.

**The "trust the model" anti-pattern.** Treating LLM output as the process model rather than verifying it against an authoritative source. CAST identifies this as inadequate-control-algorithm at the agent runtime layer. The recommendation is structural: agent runtimes need a verification step between LLM-proposed-action and action-execution, especially for actions with write-effect (file modification, network requests, command execution). Cross-link to `agentic_web_capabilities_expertise.md` for the capability-based-security framing of what such verification should look like.

**The novel-pattern detection gap.** AI-tool incidents are mostly novel-pattern. Sunburst was novel-but-similar-to-known supply-chain compromise. Clinejection chained prompt injection via a GitHub issue title into a CI agent with Actions cache poisoning. The CAST loss-scenario category "process model inaccurate" covers it: the vendor's threat model did not include "issue title as agent-instruction-source" as a process-model element.

**Cross-vendor coordination at machine speed.** AI-tool incidents propagate quickly across the ecosystem (multiple agent runtimes share the same architectural pattern). The cross-vendor coordination control action is critical for AI-tool-incident class. Cross-link to `ai_incident_response_playbook_expertise.md` for the vendor-coordination playbook and `ai_agent_session_management_expertise.md` §9 for the incident corpus.

**Augmenting CAST with AI-tool process models.** When the controlled process is itself an AI agent, the process model the agent maintains is observable in the session history.
CAST analysis of an AI-tool incident can read the agent's actual reasoning traces from the transcript log.
This is unusual: traditional CAST analyses reconstruct controller process models indirectly (interviews, training records, log analysis). For AI agents the process model is verbatim. Use this.
The transcript provides direct evidence of what the agent "thought" the state was — and where the divergence from actual state occurred.

---

## 9. Regulatory adoption and applications

CAST has seen partial adoption across safety-critical industries. The pattern: the industry already had a systems-theoretic accident-analysis culture, CAST formalized it within STAMP vocabulary, and uptake followed.

**Aviation.** The NTSB (US National Transportation Safety Board), FAA (Federal Aviation Administration), ICAO (International Civil Aviation Organization) all use systems-theoretic accident investigation. NTSB reports rarely conclude "pilot error" without also recommending changes to training, equipment, regulation, or organizational structure. The methodology is not always called CAST but is CAST-compatible. Cross-link to `aviation_aerospace_security_expertise.md`.

**NASA.** Columbia (2003) — Leveson and colleagues have applied STAMP retrospectively. The Columbia Accident Investigation Board (CAIB) report explicitly used systems-theoretic framing. NASA's current accident-analysis practice incorporates STAMP-aligned elements `[unverified specific role of STAMP in current NASA practice]`.

**Medical.** FDA medical-device recall investigations, JCAHO (Joint Commission on Accreditation of Healthcare Organizations) patient-safety reviews, and Veterans Affairs hospital systems use blameless analysis that aligns with CAST. The patient-safety community has its own vocabulary (Root Cause Analysis (RCA²) framework, sentinel-event review) that is CAST-compatible. Cross-link to `medical_device_security_expertise.md`.

**Nuclear.** IAEA (International Atomic Energy Agency), INPO (Institute of Nuclear Power Operations), NRC (Nuclear Regulatory Commission) all use systems-theoretic event analysis. The nuclear industry's safety culture (developed in part as a response to Three Mile Island in 1979 and reinforced by Chernobyl in 1986 and Fukushima in 2011) is CAST-aligned `[unverified specific role of STAMP in nuclear practice]`.

**Process industries (oil + gas + chemical).** Bhopal (1984), Texas City refinery (2005), Deepwater Horizon (2010), West Fertilizer (2013) have been subject to CAST or CAST-aligned analyses. OSHA Process Safety Management + API standards incorporate systems-theoretic elements `[unverified specific framework alignment]`.

**Cybersecurity — Cyber Safety Review Board (CSRB).** The US CSRB, established by DHS in February 2022 pursuant to Executive Order 14028, is the closest cybersecurity analog to NTSB.
CSRB has produced reviews of Log4j (July 2022), Lapsus$ (August 2023), Storm-0558 / Microsoft Exchange Online (April 2024 `[unverified specific date]`).
The Storm-0558 review reads as CAST-style analysis — inadequate Microsoft control actions (key signing controls, rotation policy, detection of misuse), loss scenarios, contextual factors (Microsoft's market position, customer dependence), and recommendations.
See the Storm-0558 / Microsoft signing-key-compromise public post-mortem for a systems-theoretic (CAST-shaped) analysis of that incident.

**Automotive.** The Toyota unintended acceleration investigations (2010-2014), Tesla Autopilot incidents, GM ignition-switch recall (2014). The systems-theoretic framing has been applied by Leveson and others `[unverified specific publications]`. Cross-link to `automotive_security_expertise.md`.

**Industrial control / OT.** The Stuxnet, BlackEnergy / Ukraine 2015, NotPetya, Triton, Colonial Pipeline, Volt Typhoon incidents are amenable to CAST. Few publicly-available CAST-style analyses exist; the analyses tend to be vendor or government publications with different framing. Cross-link to `ics_ot_security_expertise.md`.

The pattern across industries: CAST adoption tracks the maturity of safety culture in the industry. Aviation, nuclear, medical, oil-and-gas have decades of safety-culture investment and adopt CAST naturally. Cybersecurity has historically lacked this culture; CSRB is the institutional shift.

---

## 10. Tooling

There is no widely-adopted CAST-specific tool.
The methodology is documented in books and handbooks; artifacts are produced by hand or with general-purpose tools.

**Word / Visio / draw.io / Lucidchart.** Most CAST analyses are long-form documents with embedded control-structure diagrams.
The diagram is the central artifact; the textual content (UCAs, loss scenarios, recommendations) wraps around it.
Visio is traditional; draw.io and Lucidchart are common for newer practitioners.
Mermaid + Graphviz are usable but the diagrams tend to be too complex for purely-text representations.

**XSTAMPP.** Open-source STPA tool from Asim Abdulkhaleq and Stefan Wagner (University of Stuttgart).
Primarily STPA-focused; XSTAMPP 2.0 added an A-CAST plugin for CAST accident analysis.
Free; runs as an Eclipse plugin.

**MIT SafeWare research tooling.** Academic; not production-deployed.

**Templates.** Organizations adopting CAST typically build internal templates based on the handbook and customize them.

**AI-augmented CAST.** Emerging research uses LLMs to generate candidate loss scenarios and recommendations from a control-structure diagram.
Same novelty-regression limit as AI-augmented STPA: LLMs are reasonable on known patterns, poor on novel ones — and CAST is most valuable on the unprecedented incidents.
Cross-link to `ai_orchestration_harnessing_expertise.md` for harness-discipline considerations.

**The typical artifact.** Executive summary, incident description, control-structure diagram, controller-by-controller UCA analysis, loss-scenario enumeration, contextual factors, recommendation list (prioritized), implementation tracking plan.
Report length scales with incident scope: a small incident produces 10-20 pages; a major incident (Sunburst-class, Therac-25-class, Air France 447-class) produces 60-150 pages.

The tooling gap is not the bottleneck. Analyst time and organizational willingness to act on systemic recommendations are.

---

## 11. Integration with other incident-response methodologies

CAST does not replace existing incident-response frameworks; it slots into them.

**CAST + NIST 800-61 IR lifecycle.** NIST 800-61 defines preparation, detection-and-analysis, containment-eradication-recovery, post-incident-activity. CAST applies in the post-incident-activity phase, specifically the root-cause-analysis sub-step. The other NIST phases (containment, eradication, recovery) precede CAST; the recovery phase decisions can themselves be inputs to a CAST analysis. Cross-link to `dfir_methodology_expertise.md`.

**CAST + blameless postmortem (Google SRE-style).** Google's SRE postmortem template is CAST-compatible in spirit but is less structured. SRE postmortems include action items but do not systematically enumerate UCA categories or loss scenarios per controller. CAST adds the structural discipline. For low-consequence incidents the SRE template is sufficient; for high-consequence incidents CAST adds value. Some organizations use both: SRE template for routine incidents, CAST for sentinel events.

**CAST + 5 Whys.** Complementary. 5 Whys is fast triage usable during incident response itself; CAST is deep analysis used post-incident. The output of a 5 Whys exercise is one input to the CAST analysis (the surface-level causal chain) but CAST goes further by identifying the control structure that allowed the chain.

**CAST + Tetlock-style forecasting.** Tetlock's superforecasting work covers calibration discipline applicable to CAST recommendations. After identifying recommendations, ask: under counterfactual conditions where each recommendation had been in place, how likely was the loss to have been prevented or detected? Calibrate against base rates of similar incidents in the industry. The hindsight-bias risk in CAST is real; Tetlock-style discipline mitigates it.

**CAST + adversarial review.** The recommendations should survive adversarial review. Cross-link to `adversarial_review_doctrine_expertise.md` for the Champion-Foil-Adjudicator procedure. Steelman the alternative explanation; check for hindsight bias; verify that the recommendation generalizes to related-but-different incidents, not just to the specific incident at hand.

**CAST + threat modeling.** STAMP-family treats threat modeling as a control-structure artifact (STPA-Sec produces it). When CAST analyzes an incident on a system that had STPA-Sec done, the existing control structure is the starting point. CAST then identifies which UCAs from the STPA-Sec analysis were realized and which were not predicted. The post-incident CAST can update the STPA-Sec analysis. Cross-link to `stpa_sec_hazard_analysis_expertise.md`, `threat_modeling_discipline_expertise.md`, `misuse_abuse_case_modeling_expertise.md`, `attack_trees_expertise.md`.

**CAST + lessons-learned + organizational learning.** CAST recommendations are inputs to organizational learning processes. The implementation-tracking step (step 8) connects to whatever organizational tracking system exists (Jira backlog, OKRs, regulatory commitments). Without the tracking connection CAST analyses are produced but not acted on.

---

## 12. Honest failure modes — load-bearing

CAST has limits. Name them.

**CAST is time-consuming.** A real-incident CAST analysis takes weeks of analyst time and produces a 30-100 page report. The analyst time required is the binding constraint for organizations considering adoption. Compress the analysis (skip steps, abbreviate the control structure) and you lose the systems-theoretic depth that distinguishes CAST from lighter-weight methods. For minor incidents the SRE postmortem template is more appropriate.

**Systems-engineering vocabulary requirement.** Same fluency gap as STPA-Sec. Reading a CAST report requires comfort with control structures, process models, feedback loops, control algorithms. Engineering teams without systems-engineering background struggle to consume the output. The translation step (CAST recommendations → engineering tickets) requires an analyst who speaks both vocabularies.

**Blameless framing requires organizational culture.** In organizations where leadership demands accountability (read: a person to blame), CAST collides with the culture. The analysis will be performed but the findings will be filtered through the blame frame; recommendations will surface as personnel actions ("retrain the operator," "discipline the engineer") rather than systemic changes. The cultural prerequisite is load-bearing. Organizations not ready for blameless analysis should not adopt CAST as their first step — they should build blameless culture first.

**Recommendations may be too systemic to land.** "Restructure the engineering organization" or "lobby for new regulation" are valid CAST outputs that no engineering PM can put in a sprint plan. Translation discipline: CAST recommendation → owner-specific actionable backlog items at the appropriate organizational level. A CAST recommendation that "the industry should adopt SLSA L3+" needs to be translated into "your team should adopt SLSA L3+ by Q3" at the implementation layer.

**Hindsight bias.** Reviewers see what controllers could not have seen. The control-structure diagram is built after the loss; the controllers operating in real time had partial information. CAST's blameless framing partially mitigates hindsight bias but does not fully eliminate it. The check: ask whether the recommendation would have appeared reasonable pre-incident with the information available then. If not, the recommendation may be hindsight-shaped and may not generalize.

**The "we did a CAST" defense.** Performative CAST analyses that consume time and produce reports without driving change. Same anti-pattern as "we threat-modeled it." The check: trace the recommendations 6-12 months after publication. Were they implemented? Did similar losses recur? If the answer is "no" and "yes" then the CAST was performative.

**Cybersecurity CAST is rare.** Most cybersecurity incidents get traditional post-mortems (incident timeline + lessons learned + action items). The CSRB Storm-0558 review is one of the few publicly-available CAST-style cybersecurity analyses. Cybersecurity organizations adopting CAST face a methodological gap: there are few worked examples in the cybersecurity domain to copy from. The aviation, medical, nuclear examples are useful but the cybersecurity adaptation is partly bespoke.

**Recommendation drift.** Implementation tracking (CAST step 8) is the step most CAST analyses skip. Recommendations sit in reports; the organization moves on; the next incident reproduces the same control-structure inadequacy under different surface conditions. The CAST methodology specifies the tracking step but does not enforce it; enforcement is an organizational responsibility.

**CAST output requires translation to engineering backlog.** Same chain as misuse cases and STPA-Sec: the analysis output is at a higher abstraction level than the engineering tickets that will implement it. Without an analyst who can translate, the output stays as report-text and the engineering team continues on its existing roadmap.

**AI-augmented CAST regresses on novel loss scenarios.** LLM augmentation of CAST analyses speeds routine work — generating candidate UCAs, drafting loss-scenario text, summarizing reports — but regresses on the novel patterns that make CAST analyses valuable. The novel patterns are exactly what the LLM has not seen in training. Treat AI augmentation as analyst-acceleration on routine work, not as replacement on the consequential analyses.

**Industry adoption is slow.** STAMP was published in 2004; *Engineering a Safer World* in 2011.
Two decades later, CAST adoption remains concentrated in safety-critical industries with strong systems-engineering cultures.
Expect adoption to track institutional structures (CSRB-style review boards, regulatory frameworks) rather than bottom-up.

**No standardized maturity model.** Unlike SLSA or BSIMM, there is no widely-adopted maturity ladder for "how good is your organization at CAST."
Practitioners and academics debate quality criteria; organizational benchmarking is difficult.

---

## 13. Cross-link cluster

- `stpa_sec_hazard_analysis_expertise.md` — pre-design STAMP family member; control structure built for STPA-Sec is the starting point for CAST on incidents involving that system.
- `threat_modeling_discipline_expertise.md` — STRIDE / PASTA / LINDDUN / kill chain models; CAST treats threat modeling as a control-structure artifact.
- `misuse_abuse_case_modeling_expertise.md` — abuse-case-driven requirements; CAST recommendations often translate to abuse-case test suites.
- `attack_trees_expertise.md` — bottom-up attack decomposition; complementary to CAST's top-down systems framing.
- `dfir_methodology_expertise.md` — NIST 800-61 IR lifecycle; CAST sits in the post-incident root-cause-analysis sub-phase.
- `ai_incident_response_playbook_expertise.md` — AI-tool-specific IR; CAST applies inside the post-incident analysis step.
- `ai_agent_session_management_expertise.md` §9 — AI agent incident corpus available for CAST treatment.
- `cicd_supply_chain_expertise.md` — GitHub Actions + build pipeline attack surface; Sunburst-class incidents.
- `supply_chain_provenance_expertise.md` — SLSA, sigstore, in-toto; Sunburst-class recommendations.
- `medical_device_security_expertise.md` — Therac-25 + medical device CVE corpus + FDA regulatory context.
- `automotive_security_expertise.md` — Toyota unintended acceleration + Tesla Autopilot + GM ignition switch.
- `aviation_aerospace_security_expertise.md` — Air France 447 + Boeing 737 MAX + NTSB investigation practice.
- `ics_ot_security_expertise.md` — Stuxnet, Triton, Colonial, Volt Typhoon for CAST treatment.
- `adversarial_review_doctrine_expertise.md` — Champion-Foil-Adjudicator procedure for steelmanning CAST recommendations.
- `agentic_web_capabilities_expertise.md` — capability-based-security framing for the agent-runtime-verification recommendation class.
- `ai_orchestration_harnessing_expertise.md` — harness-discipline considerations for AI-augmented CAST.

---

## 14. Operational checklist — running a CAST analysis

Work through these in order when running CAST on a real incident.
The checklist compresses sections 3-7 into operational steps.

1. **Define the loss scope precisely.** Date range, affected systems, affected parties, harm category, harm magnitude. If the scope is fuzzy, the analysis will be fuzzy.
2. **Establish blameless framing with stakeholders.** Get explicit agreement from leadership that the output will target the control structure, not individuals. If you cannot, escalate or decline.
3. **Build the control structure diagram.** Identify controllers, controlled processes, control actions, feedback channels. Include all organizational levels relevant to the loss.
4. **Enumerate inadequate control actions per controller** using the UCA categories: provided, not provided, wrong timing, wrong duration.
5. **For each UCA, walk the four loss-scenario categories.** Process model inaccurate? Control algorithm inadequate? Feedback inadequate? Coordination failure? Force the check.
6. **Identify contextual factors.** Organizational, regulatory, market, training, staffing, communication, incentive. Be specific; "culture" is not a contextual factor — "the engineering org reorganized 6 months pre-incident, leaving the build-pipeline security team understaffed" is.
7. **Develop recommendations targeting the control structure.** Each recommendation should map to a specific UCA or loss scenario.
8. **Translate recommendations to engineering backlog items.** Owner, timeline, acceptance criteria.
9. **Establish implementation tracking.** Whose job is verification? When will the review happen? What metric indicates the loss scenario has not recurred?
10. **Run adversarial review of recommendations.** Steelman the alternative; check for hindsight bias; verify recommendations generalize.
11. **Update the STPA-Sec analysis (if one exists) with CAST findings.**
12. **Publish or share findings appropriately.** Internal full report; external sanitized findings for industry threat-intel-sharing if the incident class generalizes.

---

CAST is the methodology for asking "why was the control structure inadequate" instead of "what failed."
It is the post-incident counterpart to STPA-Sec and completes the STAMP family.
The cybersecurity industry is in the early stages of adopting it; CSRB-style reviews are the institutional channel.
The methodology is well-documented but the cultural prerequisites (blameless framing, systems-engineering vocabulary, willingness to act on systemic recommendations) are not free. Build them deliberately.
