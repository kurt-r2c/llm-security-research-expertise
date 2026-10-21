# STPA-Sec Hazard Analysis Expertise

Systems-theoretic security analysis adapted from safety engineering. Sibling to `threat_modeling_discipline_expertise.md` + `misuse_abuse_case_modeling_expertise.md` + `attack_trees_expertise.md`. Where those three legs of the threat-modeling triangle catalog threats, abuse stories, and attacker-goal decompositions, STPA-Sec catalogs **unsafe control actions** in a hierarchical control structure and asks how an adversary could induce them.

---

## 1. Why this doc exists

STRIDE/PASTA/LINDDUN model threats to assets. Attack trees model attacker-goal decompositions. Misuse cases model adversarial narratives. STPA-Sec models something different: how **control structures fail to enforce constraints**, and how an attacker can induce that failure regardless of identity or motive.

The structural insight from STAMP (Systems-Theoretic Accident Model and Processes — Leveson 2011) is that complex software-intensive systems fail not primarily through component failure but through **inadequate control**. A pilot pushes the wrong switch because the cockpit's feedback loop misrepresents aircraft state. An operator trips a generator because the SCADA HMI shows stale telemetry. A self-driving car brakes hard because the perception controller's process model disagrees with reality. Each proximate "bug" is downstream of a control-structure inadequacy.

STPA-Sec (Young + Leveson, CACM 2014) extends this lens to security: an attacker who controls the right input, feedback, or process-model channel can induce an unsafe control action without ever exploiting a memory-corruption bug or a misconfigured authz check. The methodology enumerates **how a controller could be made to issue the wrong command** — spoofed sensor input, communication interference, corrupted process-model state — and derives defenses from that enumeration rather than from a threat catalog.

Scope: Leveson's STPA-Sec and its adoption in aviation (RTCA DO-326A/356A), automotive (ISO/SAE 21434), medical devices (FDA premarket cyber), and ICS/nuclear. Sibling to the threat-modeling triangle, **not a replacement**. Where the triangle is element-centric and adversary-centric, STPA-Sec is control-action-centric and hazard-centric. Mature programs use both.

Audience: AI agents + safety-critical systems engineers (aviation, automotive, medical, nuclear, ICS) + AppSec engineers at organizations bridging safety + security concerns + cyber-physical-systems researchers.

---

## 2. Origin and canonical references

- **Nancy Leveson**, *Engineering a Safer World: Systems Thinking Applied to Safety* (MIT Press 2011). Foundational text introducing STAMP and STPA. Reframes accidents from chain-of-events causation to control-structure inadequacy. Free-PDF release from MIT Press is the standard distribution.
- **William Young + Nancy Leveson**, "An integrated approach to safety and security based on systems theory," *Communications of the ACM* 57(2), February 2014. The CACM paper that introduces STPA-Sec as a security extension to STPA. Argues that strategic security analysis should start from "what must not happen" rather than "what could attack us."
- **Nancy Leveson + John Thomas**, *STPA Handbook* (MIT, March 2018). Operational manual for STPA practitioners. The four-UCA-type catalog (providing, not-providing, wrong-timing, wrong-duration) and the loss-scenario causal-factor taxonomy are codified here.
- **MIT SafeWare laboratory** (Leveson, Thomas, Young, and collaborators). Ongoing research output through MIT's Department of Aeronautics and Astronautics. Annual STAMP/STPA Workshop has run since 2012.
- **RTCA DO-326A** *Airworthiness Security Process Specification* (2014) + **DO-356A** *Airworthiness Security Methods and Considerations* (2018) + **DO-355A** *Information Security Guidance for Continuing Airworthiness* (2020) `[unverified specific publication year]`. The FAA/EASA-recognized cybersecurity framework for commercial aircraft. Reference STPA-Sec-compatible hazard-analysis methods without prescribing STPA-Sec by name.
- **ISO/SAE 21434:2021** *Road vehicles — Cybersecurity engineering*. Mandates TARA (Threat Analysis and Risk Assessment) and uses systems-theoretic vocabulary throughout. UNECE R155 + R156 reference 21434 for vehicle type approval.
- **FDA Premarket Cybersecurity Guidance** (2014, 2018 draft, 2023 final update `[unverified exact date]`). Compatible with STPA-Sec hazard framing; pre-market submission expects a hazard analysis covering cybersecurity.
- **NIST SP 800-160 Vol. 1** *Systems Security Engineering* (Ron Ross et al., 2016 with 2018 update).
- **IAEA Nuclear Security Series 17-T** *Computer Security at Nuclear Facilities* (2011; Rev. 1 published 2021) — compatible framing for nuclear-cyber.
- **DOE OE-417** electricity-incident reporting + **NERC CIP** standards — cyber-physical regulations for the US bulk electric system.

Aphorism: Leveson's framing — "safety is a control problem, not a failure problem" — is the load-bearing claim of the entire methodology. If you reject it, you reject STPA-Sec.

---

## 3. STAMP — the underlying systems-theoretic model

STPA-Sec inherits its conceptual framework from STAMP. Five primitives:

**3.1 Systems-theoretic vs component-failure model.** Classical safety engineering (FMEA, FTA, HAZOP) decomposes a system into components and analyzes how component failures propagate. STAMP rejects this for software-intensive systems on the grounds that most modern losses emerge from interactions among non-failing components — a sensor reports correctly, software computes correctly, an actuator actuates correctly, and yet the system harms a human because the **control structure** failed to enforce a constraint.

**3.2 Control structure.** A hierarchical model of the system as nested controllers and controlled processes:

```
Regulator / Standards Body
     |  (regulations, audits)
     v
Organization Executive
     |  (policy, resourcing)
     v
Engineering / Operations Management
     |  (procedures, training)
     v
Operators (pilots, drivers, plant operators)
     |  (control actions)
     v
Automated Controllers (autopilot, ECU, SCADA RTU)
     |  (control commands)
     v
Physical Process (aircraft, vehicle, generator)
     |  (feedback: telemetry, sensors)
     ^
     +-----------------------------------> back up the stack
```

Each level enforces constraints on the level below and reports state to the level above. Levels are connected by **control actions** (downward) and **feedback** (upward).

**3.3 Unsafe Control Actions (UCAs).** Per control action, four canonical types:

1. **Providing causes hazard** — controller issues the command when it should not (brake when no obstacle).
2. **Not providing causes hazard** — controller fails to issue the command when it should (no brake when obstacle).
3. **Wrong timing / order** — too early, too late, out-of-sequence (brake after collision; ignition cycle in wrong order).
4. **Wrong duration / intensity** — too long, too short, stopped too early (brake released before stopped; emergency-power cutoff applied indefinitely).

The four-UCA-type catalog is the operational heart of STPA. Every control action in the structure is examined against all four types in the appropriate context.

**3.4 Process model.** The controller's internal representation of the controlled process state. Pilots have a process model of the aircraft. Autopilots have a process model encoded in firmware. SCADA HMIs render a process model for the operator. **Disagreement between process model and actual process state is the dominant cause of UCAs.**

**3.5 Feedback loop.** The channel by which the controller observes process state. Feedback can be delayed, missing, corrupted, or spoofed. In STPA-Sec, the feedback channel is a primary attack surface — corrupt the feedback, corrupt the process model, induce the UCA.

---

## 4. STPA — the analysis methodology (safety side)

STPA proper, before the security extension. Six steps. Skip none.

**Step 1: Identify losses.** Top-level unacceptable outcomes the analysis exists to prevent. A loss is a harm state, **not a cause**. Examples: "loss of life or serious injury to passengers"; "uncontrolled release of radioactive material"; "loss of customer financial data confidentiality." Keep the list short (3-8) and at the right altitude — losses are board-level concerns, not engineering-task concerns.

**Step 2: Identify system-level hazards.** System states that, given worst-case environmental conditions, could lead to losses. A hazard is a **system state**, not an event. Example: "Aircraft violates minimum separation from terrain while in flight" (hazard) maps to "Loss of life from terrain impact" (loss). Hazards are denser than losses (typically 10-30 per system).

**Step 3: Identify system safety constraints.** What must hold to prevent each hazard. Constraints are the **inverse of hazards** stated positively: "Aircraft must maintain minimum separation from terrain while in flight." Each hazard yields at least one constraint.

**Step 4: Build the control structure.** Hierarchical diagram per §3.2. Identify every controller, every controlled process, every control action between them, every feedback channel. **Mis-drawn control structures yield wrong UCAs**; budget real time here. The hardest discipline is including organizational and regulatory controllers, not just software/hardware. Loss-causing scenarios frequently traverse organizational boundaries.

**Step 5: Identify Unsafe Control Actions.** For each control action in the structure, enumerate the four UCA types per context. Document each UCA with: control-action name, UCA type, context, linked hazard. Output is typically a table with hundreds of rows for a real aircraft or vehicle.

**Step 6: Identify loss scenarios.** For each UCA, ask: how could this UCA occur? Leveson + Thomas codify the causal-factor categories:

- **Inadequate control algorithm** — controller's logic is wrong, incomplete, or doesn't account for an edge case.
- **Incorrect process model** — controller's belief about process state diverges from reality.
- **Inadequate sensor / actuator** — feedback or actuation channel is missing, slow, noisy, or wrong.
- **Communication / coordination failure** — between controllers at the same level or across levels.
- **Inadequate control action execution** — actuator receives correct command but executes wrong.

Each loss scenario points to a defense.

**4.1 An illustrative STPA application — civil aviation autoland.**

Consider an autoland system on a commercial airliner. The control action under analysis is "autoland controller commands flare maneuver at radar altimeter reading X feet."

UCAs:
- Providing-causes-hazard: flare commanded above safe altitude (premature flare → hard touchdown or stall).
- Not-providing-causes-hazard: flare not commanded (no flare → high-rate landing).
- Wrong-timing: flare commanded after main-gear touchdown (nose-down moment, gear collapse).
- Wrong-duration: flare commanded but pitch authority withdrawn early (incomplete flare, hard touchdown).

Causal factors per UCA:
- Inadequate control algorithm: flare-altitude logic doesn't account for radar-altimeter wash-out over rough terrain in displaced-threshold approaches.
- Incorrect process model: radar altimeter reading aliased by snow accumulation; autoland's altitude belief diverges from actual altitude.
- Inadequate sensor: single-source altimeter without cross-channel comparison.
- Communication failure: between flight control computer and elevator actuator.
- Inadequate execution: elevator actuator saturated at command limit.

Each causal factor maps to a defense — redundant altimeters, GPWS cross-check, actuator-saturation monitoring, FCC voting across redundant channels. STPA's value is producing the defense set systematically; FTA could produce the same set for known failures but misses the algorithm-inadequacy class.

**4.2 The discipline of writing UCAs in context.** A common mistake is writing UCAs as "brake commanded" rather than "brake commanded **when no obstacle present and no driver request**." Context-free UCAs are uselessly general. Per the STPA Handbook, every UCA must be paired with the context in which the control action becomes unsafe. The context is what distinguishes a normal command from a hazard-inducing command.

---

## 5. STPA-Sec — the security extension

Young + Leveson (CACM 2014) extend STPA by reinterpreting causal factors as **adversarially induced** rather than naturally occurring. Same six-step structure.

**Losses expand to include security harms.** Data breach, exfiltration, reputational, regulatory, and financial losses sit alongside safety losses. The original STPA loss list was safety-only; STPA-Sec broadens it.

**Hazards expand to include security-relevant system states.** "System operates with compromised authentication state"; "System processes data from untrusted upstream"; "System exposes confidential data to untrusted boundary." The granularity matches STPA hazards — system states, not events.

**Unsafe-OR-INSECURE Control Actions.** The four UCA types apply unchanged; the analyst asks them about security-relevant control actions: "authentication-check is bypassed when it should be performed"; "encryption-of-data-at-rest is applied with degraded algorithm"; "fleet-update-deployment occurs before signature-verification completes."

**Loss scenarios incorporate adversarial induction.** The five causal-factor categories from STPA become attack channels:

- **Adversarially altered control algorithm** — firmware compromise, supply-chain attack on the controller binary, RCE on the operator workstation.
- **Adversarially corrupted process model** — false telemetry, sensor spoofing, replayed feedback, malicious HMI rendering.
- **Adversarially compromised sensor / actuator** — physical tampering, on-path injection, CAN-bus injection, sensor-spoofing.
- **Adversarially intercepted communication** — MitM on internal protocols, downgrade attacks, replay, traffic analysis.
- **Adversarially induced execution failure** — denial of actuator response, induced power-cycle, induced safe-mode.

**The intent-free framing.** STPA-Sec deliberately avoids modeling specific attackers, motives, or capability levels. Where STRIDE and PASTA orient around named threat actors, STPA-Sec asks the structural question: **regardless of cause, how could this control action become unsafe?** Young + Leveson argue this is a feature — it produces defenses that are robust to threat-model error. Critics argue it's a bug — without prioritization by adversary likelihood, the defense space is unconstrained. Both are right; STPA-Sec is best paired with a separate adversary-prioritization step (STRIDE elements or a kill-chain analysis).

The intent-free framing is the methodology's most-misunderstood feature. Practitioners coming from STRIDE consistently try to retrofit attacker personas; doing so collapses STPA-Sec back into STRIDE and loses the systems-theoretic advantage.

**5.1 What STPA-Sec adds beyond STPA.** The mechanical extension is small — the four UCA types and six steps are unchanged. The conceptual extension is large: every causal-factor category becomes a question about adversarial induction. Instead of asking "could this sensor fail randomly," the analyst asks "could this sensor be made to lie." Instead of asking "could this controller's algorithm have an edge case bug," the analyst asks "could this controller's algorithm be replaced with adversarial code via supply-chain compromise." Every random failure becomes a question about deliberate inducement.

**5.2 Coupling with adversary analysis.** Mature programs run STPA-Sec to enumerate structurally-possible UCAs, then a separate adversary-prioritization pass to rank by capability + cost + likelihood. The STRIDE-elements analysis, the kill-chain decomposition, or a red-team exercise feeds the prioritization. STPA-Sec without prioritization is a complete-but-unranked defense backlog; prioritization without STPA-Sec is a ranked-but-incomplete one. Both inputs are required.

**5.3 Worked-example anchors throughout the literature.** The literature applies STPA-Sec to aviation cockpit security (cross-link `[[reference-aviation-aerospace-security]]`), automotive ECU networks (cross-link `[[reference-automotive-security]]`), and SCADA control-center operations.

---

## 6. Worked example — automotive remote-attack scenario

Anchored on the Miller-Valasek 2015 Jeep canon. Cross-link `[[reference-automotive-security]]` for the attack lineage; this section uses STPA-Sec vocabulary to re-derive the defense surface.

**Loss L1**: Unintended vehicle deceleration causes occupant injury or collision.

**Hazard H1**: Brake actuator commanded to decelerate when no driver request, no autonomous-safety-trigger, and no validated remote-fleet command is present.

**Safety/security constraint C1**: Brake-deceleration command must originate from (driver-pedal-sensor input) OR (validated autonomous-safety-system output) OR (cryptographically authenticated remote-fleet-mgmt command from authenticated remote operator on validated channel).

**Control structure (abbreviated):**

```
Driver -> Brake pedal sensor -> Body-control-module -> Brake ECU -> Brake actuator
                                  ^
                                  |
Autonomous-safety system (forward radar, cameras) --+
                                  |
Cellular modem -> Fleet-mgmt service -> Brake ECU --+
```

**Control action under analysis**: "Brake ECU commands deceleration."

**UCAs**:
- UCA1 (providing): Brake ECU commands deceleration when no driver, no safety-system, no validated remote input → H1.
- UCA2 (not providing): Brake ECU fails to command deceleration when obstacle detected → leads to a different hazard (collision-with-obstacle).
- UCA3 (wrong timing): Brake ECU commands deceleration after collision-event → H1.
- UCA4 (wrong duration): Brake ECU commands deceleration indefinitely after release → H1 / loss of control.

**Loss scenarios for UCA1** (each maps to a defense):
1. Adversary on cellular link injects unauthenticated fleet-mgmt brake command. **Defense**: mutual TLS + per-message HMAC + replay-window enforcement on fleet-mgmt channel.
2. Adversary on internal CAN bus injects spoofed pedal-sensor frame. **Defense**: CAN message-authentication (SAE J1939-91 / AUTOSAR SecOC) + bus-segment isolation.
3. Adversary spoofs forward-radar input to the autonomous-safety system. **Defense**: sensor-fusion plausibility checks; cross-validation against camera/lidar.
4. Adversary compromises Brake ECU firmware via OTA update with no signature-verification. **Defense**: secure boot + signed updates + rollback protection.
5. Adversary compromises infotainment system and pivots to CAN gateway. **Defense**: gateway firewall + domain isolation (per ISO 21434 architectural pattern).

The Miller-Valasek 2015 attack chained scenarios 5 → 2. STPA-Sec re-derivation produces the same defense set without referencing the attack — the methodology is intent-free.

**6.1 Defenses traced back to ISO/SAE 21434 architectural mandates.** The defenses derived above map onto specific 21434-recommended architectural patterns: domain isolation (item 5), in-vehicle message authentication (item 2), secure boot + signed updates (item 4), cryptographically authenticated external channels (item 1), and sensor-fusion plausibility (item 3). The TARA artifact ISO/SAE 21434 expects can be derived directly from this STPA-Sec table.

**6.2 What the analysis misses.** The intent-free framing won't tell you that cellular-modem attack is more likely than CAN-bus physical access for a fleet attacker, or that supply-chain firmware compromise is the highest-leverage attack for a nation-state. Layer adversary prioritization on top.

---

## 7. Worked example — power-grid SCADA scenario

Anchored on CrashOverride / Industroyer 2 / Triton corpus. Cross-link `[[reference-ics-ot-security]]`.

**Loss L1**: Widespread blackout affecting >100K customers for >24h.

**Hazard H1**: Generator-trip command issued to multiple generators simultaneously without operational justification.

**Constraint C1**: Generator-trip commands must require multi-channel authorization with cross-channel integrity checks.

**Control structure (abbreviated):**

```
ISO/RTO dispatch -> EMS console operator -> SCADA workstation -> RTU -> Protection relay -> Breaker -> Generator
                                                ^                         ^
                                                |                         |
                                          Engineering WS               Field instrumentation
                                          (relay config)
```

**Control action under analysis**: "Protection relay trips breaker."

**UCAs**:
- UCA1 (providing): Trip occurs when no fault present → H1.
- UCA2 (not providing): No trip when actual fault present → equipment damage hazard.
- UCA3 (wrong timing): Trip during synchronization or restoration window → H1 cascading.

**Loss scenarios for UCA1** (each maps to a defense):
1. Adversary compromises engineering workstation, modifies protection-relay configuration to lower trip threshold. **Defense**: relay-config change-control + signed config files + offline-stored gold images + change-detection alerts.
2. Adversary compromises SCADA workstation, sends operator-issued trip command via legitimate ICCP/IEC 104 protocol. **Defense**: HMI integrity attestation + per-command operator MFA + dual-supervisor sign-off for trip-class commands.
3. Adversary injects spoofed protective-relay GOOSE/SV traffic on IEC 61850 station bus. **Defense**: IEC 62351-6 GOOSE authentication + bus segmentation.
4. Adversary feeds false telemetry to EMS → operator's process model shows fault that doesn't exist → operator issues trip. **Defense**: telemetry cross-validation + PMU-vs-RTU sanity checks + redundant data path.
5. Adversary deploys malware (CrashOverride payload) that directly drives RTU outputs. **Defense**: host-based application allowlisting + signed firmware + outbound network egress allowlisting.

Scenario 5 is the CrashOverride / Industroyer pattern. Scenario 4 maps to the Triton attack on safety-instrumented-system controllers — the attackers used compromised engineering workstations to push malicious logic that altered the SIS's process model.

**7.1 Why STPA-Sec is a natural fit for power-grid analysis.** ICS environments have well-defined control hierarchies (Purdue Reference Model), explicit feedback loops (telemetry → HMI → operator → SCADA → RTU → field), and consequence states (loss of generation, loss of load) that map cleanly onto STPA loss/hazard primitives. Stuart Madnick at MIT Sloan has argued for cybersecurity-as-systems-engineering specifically in critical-infrastructure contexts. Cross-link `[[reference-ics-ot-security]]`.

**7.2 The 2015/2016 Ukraine grid attacks as STPA-Sec exemplars.** BlackEnergy (2015) compromised operator workstations and used them to trip breakers through legitimate HMI sessions — a textbook case of "adversarially corrupted process model" combined with "adversarial control via authorized channel." Industroyer/CrashOverride (2016) added the protocol-native module that drove RTU outputs directly — a textbook case of "adversarially altered control algorithm" running adjacent to legitimate code on the same host.

---

## 8. STPA-Sec vs sibling methodologies

| Method | Centers on | Output unit | When STPA-Sec wins |
|---|---|---|---|
| **STRIDE** | Per-element threats (Spoof/Tamper/Repudiate/InfoDisclose/DoS/Elevate) | Threat catalog per data-flow element | STPA-Sec for systems with strong control hierarchy; STRIDE for protocol-flow analysis |
| **PASTA** | Business objectives → 7-stage risk model | Risk-rated threat scenarios | STPA-Sec for cyber-physical; PASTA for business-application risk |
| **LINDDUN** | Privacy threats (Link/Identify/Non-repudiate/Detect/Disclose/Unawareness/Non-compliance) | Privacy harms per data flow | LINDDUN for privacy; STPA-Sec can incorporate privacy hazards |
| **Misuse cases** | Adversarial user stories | Narrative scenarios | Misuse cases for stakeholder communication; STPA-Sec for engineering analysis |
| **Attack trees** | Adversarial-goal decomposition | Tree with leaf-cost annotation | Attack trees for "how to attack" enumeration; STPA-Sec for "how could this fail under any cause" |
| **HAZOP** | Process-deviation keywords (NO/MORE/LESS/AS WELL AS/PART OF/REVERSE/OTHER) | Deviation tables | HAZOP works for chemical-process plants; STPA-Sec better for software-intensive systems |
| **FMEA** | Bottom-up component failure modes | Failure-mode tables | FMEA for hardware reliability; STPA-Sec for software/control system safety |
| **FTA** (fault-tree) | Top-down event causation | Boolean fault trees | FTA when failure pathways are well-known; STPA-Sec when emergent behaviors dominate |

The deepest sibling-vs-STPA-Sec contrast is with FTA. Both are top-down. FTA decomposes an **undesired event** into Boolean combinations of contributing failures (gate logic: AND/OR). STPA-Sec decomposes an **unsafe control action** into causal-factor categories that include adversarial induction. FTA assumes you can enumerate failures; STPA-Sec assumes you cannot enumerate causes but can enumerate control-structure inadequacies. For modern software-intensive systems STPA-Sec is more productive; for well-understood hardware systems FTA remains more tractable.

Mature programs run multiple methodologies in parallel. ISO/SAE 21434 explicitly accommodates STPA-Sec, STRIDE-style asset analysis, and attack-tree TARA artifacts simultaneously.

**8.1 When to choose which.** Heuristic:
- High-consequence cyber-physical system (aircraft, vehicle, medical device, ICS) → STPA-Sec, paired with STRIDE for protocol-flow detail.
- Web application or SaaS product → STRIDE (or LINDDUN for privacy-heavy), with STPA-Sec only if the application drives a physical process or governs high-consequence decisions.
- Adversary-prioritization need → attack trees or kill-chain analysis.
- Stakeholder communication need → misuse cases.
- Compliance with safety-engineering regulation (DO-178C, ISO 26262, IEC 62304) → STPA + STPA-Sec integrated, since the safety side is required regardless.

**8.2 Methodology-blending in practice.** Modern programs rarely use a single methodology. A typical aircraft-program threat-model deliverable combines: STPA-Sec for hazard analysis; STRIDE-elements for protocol/architecture decomposition; attack trees for specific adversary scenarios deemed plausible; misuse cases for stakeholder-facing communication. The artifacts cross-reference. The total budget is higher than a single-methodology pass; the coverage is also higher and the methodology-bias is lower.

---

## 9. STPA-Sec adoption in regulated industries

**Aviation.** RTCA DO-326A *Airworthiness Security Process Specification* (2014) defines a security-airworthiness process compatible with STPA-Sec hazard framing. DO-356A (2018) provides methods and considerations. DO-355A (2020 `[unverified date]`) covers continuing airworthiness. The FAA Special Conditions process for Boeing 787 and Airbus A350 explicitly required hazard-based cybersecurity analysis. MITRE supported method development.

**Automotive.** ISO/SAE 21434:2021 *Road vehicles — Cybersecurity engineering* uses systems-theoretic vocabulary throughout. The TARA (Threat Analysis and Risk Assessment) process in 21434 admits STPA-Sec-style analysis as one of several compatible methods. UNECE Regulation 155 (CSMS — Cyber Security Management System) and R156 (SUMS — Software Update Management System) mandate cybersecurity engineering practices for vehicle type approval in Europe, UK, Japan, Korea, and other UNECE adopters. ISO/SAE 21434 became the de facto reference standard. Philip Koopman at CMU has written extensively on embedded-systems safety methodology compatible with STPA-Sec `[unverified specific STPA-Sec endorsement]`.

**Medical devices.** FDA *Premarket Cybersecurity Guidance* (2014 initial, 2018 draft revision, 2023 final `[unverified exact dates]`) expects a cybersecurity hazard analysis as part of premarket submission. STPA-Sec is compatible; many manufacturers use it alongside ISO 14971 risk management for medical devices. The 2023 update emphasizes Software Bill of Materials (SBOM) and threat modeling. Cross-link `[[reference-medical-device-security]]`.

**Nuclear.** IAEA *Nuclear Security Series 17-T* *Computer Security at Nuclear Facilities* (2011; Rev. 1 published 2021) recommends hazard-based analysis of digital instrumentation and control systems. NRC RG 5.71 (USA) is the comparable US regulatory guide. STPA-Sec maps cleanly onto the I&C-cybersecurity hazard analysis these regulations require.

**NIST SP 800-160 Vol. 1** *Systems Security Engineering* (Ron Ross, Michael McEvilley, Janet Oren, 2016, Update 1 2018).

**Electric power.** NERC CIP-005, CIP-007, CIP-010, CIP-013 standards mandate cybersecurity programs for the North American bulk electric system. DOE OE-417 covers incident reporting. STPA-Sec applies to control-center analysis but is not explicitly mandated.

**Industrial control systems.** ISA/IEC 62443 family (62443-3-2 for security risk assessment, 62443-4-1 for product security development lifecycle) accommodates STPA-Sec as a hazard-analysis method.

Common pattern across regulated industries: STPA-Sec is not mandated by name, but the methods/considerations the regulations expect are STPA-Sec-compatible, and STPA-Sec practitioners can produce conforming artifacts. The regulatory language tends to be method-neutral.

**9.1 The DO-326A pattern is the template.** A regulator wants a hazard-based analysis that addresses cybersecurity within the existing airworthiness safety framework. The regulation specifies what artifacts to produce (security risk assessment, security architecture, security operational concept, security verification) but not the analytical method. STPA-Sec produces conforming artifacts; STRIDE + an asset-based risk assessment also conforms. Multiple methods compete in a method-neutral framework. The same pattern repeats in ISO/SAE 21434 (TARA is a process; STPA-Sec / STRIDE / EVITA-derived methods all conform) and FDA premarket cybersecurity (hazard analysis is required; specific method is not specified).

**9.2 STPA-Sec automotive applications.** Researchers have published case studies applying STPA-Sec to specific automotive subsystems (e.g., hybrid-vehicle battery management, autonomous emergency braking). The SAE J3061 *Cybersecurity Guidebook for Cyber-Physical Vehicle Systems* (2016) was an early predecessor to ISO/SAE 21434.

**9.3 The crossover into safety-critical software development standards.** DO-178C (airborne software), ISO 26262 (automotive functional safety), IEC 62304 (medical-device software), and IEC 61508 (general functional safety) all assume a hazard-analysis input. STPA-Sec produces that input with a security-augmented hazard set. Programs that integrate functional-safety and security hazard analyses in a single STPA-Sec pass report tooling and review-cycle savings compared to running separate STPA (safety) and STRIDE (security) workstreams.

---

## 10. AI/ML systems — STPA-Sec applicability

Modern AI-augmented control systems are STPA-Sec's natural extension target. The ML model is a controller; the training data + model weights encode a process model; the model output is a control action. UCAs apply directly:

- "ML model issues control action when it should not" (autonomous vehicle commands lane-change into oncoming traffic — adversarial-perturbation attack).
- "ML model fails to issue control action when it should" (medical-image classifier misses tumor — distribution-shift or evasion attack).
- "ML model issues correct command at wrong time" (algorithmic trading latency-induced loss).

For **AI agent systems** (LLM agents with tool-use), STPA-Sec adapts further:
- The agent is a controller; its tools are actuators; its prompts, retrievals, and user inputs are feedback channels.
- UCAs include "tool invoked when not appropriate" (prompt-injection induces unauthorized file write); "tool not invoked when appropriate" (denial of legitimate function via context-window starvation); "tool invoked with wrong arguments" (parameter-pollution attack).
- Process-model corruption maps to context-poisoning attacks — adversarially controlled retrieval results or tool-output strings that change the agent's belief about the world.
- Loss scenarios incorporate Clinejection-class, EchoLeak-class, CurXecute-class patterns.

Cross-link `[[reference-ai-agent-session-management]]` and `[[reference-ai-incident-response-playbook]]` and `[[reference-ai-assisted-coding-tool-security]]`.

**Limitations for AI.** STAMP assumes controllers have well-defined, inspectable process models. Neural networks don't admit clean process models — their state is distributed across billions of parameters. This makes the "process model corruption" causal-factor harder to instantiate cleanly for ML controllers. STPA-Sec still helps frame the **interfaces** of an ML controller (input space, output space, tool surface), but the **internals** require complementary techniques (interpretability, formal verification of learned policies, adversarial-robustness analysis). Cross-link `[[reference-adversarial-ml-model-security]]`.

The deeper philosophical mismatch: STAMP was built for systems whose behavior is intended to follow a known control algorithm. ML controllers have **learned** algorithms whose behavior emerges from data. STPA-Sec adapts but does not fit perfectly; treat ML-controller analyses as STPA-Sec-influenced rather than orthodox STPA-Sec.

**10.1 Worked sub-example — agent-with-tool-use UCA enumeration.** Consider an AI coding agent with shell, file-edit, and git tools (Claude Code / Cursor / Aider). The control action under analysis is "agent invokes shell tool with command X."

UCAs:
- Providing-causes-hazard: shell invoked with destructive command (rm -rf, force-push to main, credential exfil) when user request did not authorize.
- Not-providing: shell not invoked when user explicitly requested a build/test step.
- Wrong-timing: shell command issued before user reviewed plan (auto-approve attack).
- Wrong-duration: shell invoked once but spawns long-lived background process (resource exhaustion).

Adversarial causal factors:
- Adversarially corrupted process model: prompt-injected README, malicious tool-output string, or poisoned retrieval result convinces the agent that user authorized the command (EchoLeak / Clinejection / Comment-and-Control class).
- Adversarially altered control algorithm: the model weights themselves are compromised (sleeper-agent class).
- Adversarially intercepted communication: MitM on the agent's API connection rewrites tool calls (less common than prompt-injection but possible on untrusted networks).

Defenses derived: permission gating (cannot invoke shell without confirmation), tool allowlist (cannot invoke arbitrary commands), session-bound capability tokens (capability-based-security primitive — cross-link `[[reference-agentic-web-capabilities]]`), audit logging (forensic substrate), and outbound-egress allowlisting (limits exfil even if UCA succeeds).

**10.2 Mary Cummings' framing.** Mary Cummings (George Mason University, formerly Duke and MIT) writes extensively on human-machine systems. Her work complements STPA-Sec for systems where human operators are critical controllers and adversaries target the human's process model (the classic phishing-of-the-operator pattern).

---

## 11. Tooling

**XSTAMPP** (University of Stuttgart, Asim Abdulkhaleq and Stefan Wagner). Open-source academic tool. Visual editor for control-structure diagrams + UCA tables + loss-scenario tables. Java/Eclipse-based. The widely-used reference implementation. Its predecessor was A-STPA, from the same group.

**MIT SafeWare research tools.** Internal MIT tooling supports the STPA Handbook examples; less production-deployed than XSTAMPP. The annual STAMP/STPA Workshop output occasionally yields new tools but few have reached production maturity.

**CAST** (Causal Analysis based on STAMP) — Leveson's incident-analysis methodology applied **post-incident** to derive systems-theoretic causal explanations from real losses. Compatible with STPA-Sec pre-deployment use: deploy STPA-Sec proactively, apply CAST to losses that occur anyway. CAST has been applied to Macondo / Deepwater Horizon, Air France 447, Tesla Autopilot incidents `[unverified specific CAST publications]`.

**Commercial tooling sparse.** A few commercial offerings exist; most STPA-Sec consulting engagements use Excel/Visio/Confluence with custom artifact templates. The lack of a strong commercial tooling ecosystem reflects STPA-Sec's concentration in regulated-industry consulting rather than mass-market software.

**LLM-augmented STPA-Sec.** Emerging 2024-2026 research uses LLMs to generate UCA candidates. Useful for known-pattern enumeration; regresses on novel UCAs. Same limitation as LLM-augmented STRIDE/attack-tree work. Accelerator for the routine 80%; humans hunt the unusual 20%.

**MBSE integration.** STPA-Sec control structures can be kept consistent with SysML / Capella / Cameo artifacts. Aerospace and automotive programs increasingly automate this check. The SafeWare group has published prototypes.

---

## 12. Honest failure modes — load-bearing

The methodology has well-documented limits. Surface them; don't oversell.

**12.1 Safety-engineering vocabulary fluency is a prerequisite.** AppSec engineers without systems-engineering background struggle with "control structure," "process model," "feedback inadequacy," "constraint enforcement." The vocabulary is foreign and the four-UCA-type catalog requires practice. Budget 2-4 weeks of methodology onboarding before expecting useful output.

**12.2 Control-structure modeling is a discipline of its own.** Mis-drawn control structures yield wrong UCAs which yield wrong loss scenarios which yield wrong defenses. Common mistakes: omitting organizational/regulatory controllers; conflating data flow with control flow; treating feedback channels as identical to data return paths. Hire or develop dedicated control-structure modeling skill.

**12.3 The intent-free framing is a feature and a bug.** Feature: defenses are robust to threat-model error. Bug: without adversary-prioritization, the defense space is unconstrained; teams cannot rank UCAs by attacker likelihood. Pair STPA-Sec with a separate threat-actor analysis (STRIDE elements, kill-chain analysis, or red-team output).

**12.4 Adoption is concentrated in regulated industries.** Aviation, automotive, medical, nuclear, and some ICS programs use STPA-Sec. Commercial software, financial services, and consumer technology rarely do. Cross-industry transfer requires translation from "loss-of-life" framing to "loss-of-revenue / loss-of-customer-data" framing. The translation is straightforward but non-zero work.

**12.5 Tooling is research-grade.** XSTAMPP is the most mature option and remains an academic Eclipse plugin. No commercial-quality production tool dominates the space. Custom Excel/Confluence templates remain common. Plan for tooling friction.

**12.6 Combines poorly with strict-agile cycles.** STPA-Sec demands upfront systems modeling; agile shops resist big-design-up-front framing. The pragmatic compromise: build the initial control structure during architecture definition; update incrementally as the system evolves; treat the control structure as a living artifact under version control alongside SysML or C4 models.

**12.7 LLM augmentation regresses on novel UCAs.** Same finding as threat-modeling-discipline + attack-trees + misuse-abuse-case-modeling siblings. LLMs accelerate the routine; they do not replace the systems-engineer who finds the unusual UCA.

**12.8 Hazard and loss enumeration scales poorly for software-intensive systems.** Real systems have hundreds of hazards. Without scoping discipline, analyses become unwieldy multi-thousand-row spreadsheets that nobody maintains. Scope every STPA-Sec engagement to a bounded subsystem; tile multiple analyses.

**12.9 Output requires translation to engineering backlog.** Like misuse cases, the loss-scenario → mitigation → acceptance-criteria → test → green-CI chain is the operational requirement. Without this translation, STPA-Sec output is a binder that never becomes code.

**12.10 Academic-vs-industrial vocabulary mismatch.** Leveson, Young, Thomas write for systems-engineering academic audiences. Industrial AppSec teams need translation. Plan for the Rosetta-stone problem; have one bilingual analyst per program.

**12.11 Process-heavy.** A full STPA-Sec analysis takes weeks-to-months for a non-trivial system. For short-cycle product work this is prohibitive. Reserve STPA-Sec for high-consequence subsystems; use lighter methods elsewhere.

**12.12 Verification of STPA-Sec output is hard.** How do you know your UCA catalog is complete? Coverage criteria are debated. Practitioners use peer review, expert elicitation, and red-team-style "what-did-we-miss" sessions. There is no formal completeness theorem.

**12.13 Cyber-physical-systems framing biases toward physical-loss thinking.** STPA-Sec works well for kinetic-consequence systems. For pure-information systems (databases, SaaS applications, identity systems) the "physical process" abstraction strains; analysts have to interpret information-state as the controlled process. Doable but less natural than STRIDE for that domain.

**12.14 Output coupling.** Unlike pen-test reports, STPA-Sec output is a model rather than a list of defects. Teams that succeed treat the control-structure diagram + UCA table + loss-scenario list as engineering artifacts under version control, tied to architecture docs and acceptance-criteria tests. Teams that fail treat it as a one-off consulting deliverable. The difference is process discipline, not methodology.

**12.15 Researcher concentration.** The STPA-Sec community is small and MIT-centric (Leveson, Young, Thomas, plus students). Industrial adoption has spread but methodology evolution remains driven by a tight academic cluster. Novel extensions (AI, quantum, autonomous swarms) currently emerge from a few groups.

---

## 13. Cross-link cluster

- `[[reference-threat-modeling-discipline]]` — parent threat-modeling overview; STPA-Sec is one option in the threat-modeling discipline alongside STRIDE/PASTA/LINDDUN.
- `[[reference-misuse-abuse-case-modeling]]` — sibling; misuse cases narrate adversary stories, STPA-Sec models control-structure failure.
- `[[reference-attack-trees]]` — sibling; attack trees decompose attacker goals, STPA-Sec decomposes unsafe control actions.
- `[[reference-ics-ot-security]]` — STPA-Sec target domain for SCADA, DCS, PLC, RTU, SIS.
- `[[reference-automotive-security]]` — STPA-Sec target domain for vehicle architectures, ISO/SAE 21434.
- `[[reference-aviation-aerospace-security]]` — STPA-Sec target domain for DO-326A/356A/355A compliance.
- `[[reference-medical-device-security]]` — STPA-Sec target domain for FDA premarket cyber.
- `[[reference-building-automation-security]]` — STPA-Sec target domain for BMS / HVAC / access-control.
- `[[reference-ai-agent-session-management]]` — STPA-Sec adaptation for AI agent control surfaces.
- `[[reference-ai-incident-response-playbook]]` — incident artifacts that map back to STPA-Sec loss scenarios.
- `[[reference-ai-assisted-coding-tool-security]]` — AI-tool UCAs (Clinejection / EchoLeak / CurXecute) as STPA-Sec loss scenarios.
- `[[reference-adversarial-ml-model-security]]` — adversarial-ML attacks as UCA-induction primitives.
- `[[reference-code-review-expertise]]` — STPA-Sec output translates to code-review focus areas (the control-structure defense surface).
- `[[reference-vr-methodology]]` — vulnerability-research methodology; STPA-Sec is the safety-engineering analog.
- `[[reference-detection-engineering]]` — STPA-Sec loss scenarios inform detection-rule design (what to alert on if a UCA is being induced).
- `[[reference-confidential-computing]]` — TEE primitives address specific UCA causal factors (process-model integrity, control-algorithm integrity).
- `[[reference-supply-chain-provenance]]` — SLSA / sigstore / attestations address adversarially-altered-control-algorithm UCAs.

---

## 14. Operational checklist for an STPA-Sec engagement

Twelve items. Apply per engagement.

1. **Scope to a bounded subsystem.** Avoid whole-aircraft / whole-vehicle / whole-grid analyses in one pass. Tile.
2. **Identify 3-8 losses** at the right altitude. Board-level harm states, not engineering tasks.
3. **Derive 10-30 hazards** per scoped subsystem. System states, not events.
4. **Express each hazard as one or more constraints.** Positive statements of what must hold.
5. **Draw the control structure**, including organizational and regulatory controllers. Budget real time. Peer-review the diagram.
6. **Enumerate control actions.** List every commanded transition in the structure.
7. **Generate UCAs** per control action using the four-type catalog. Capture in a table with hazard linkages.
8. **Derive loss scenarios** per UCA using the five causal-factor categories adapted to security adversarial induction.
9. **Map loss scenarios to defenses.** Each scenario points to one or more mitigations. Defenses become engineering backlog.
10. **Translate defenses to acceptance criteria + tests + CI gates.** Without this, the analysis dies in a binder.
11. **Cross-check against STRIDE / PASTA / kill-chain output** for adversary prioritization. STPA-Sec doesn't prioritize; it enumerates structurally.
12. **Version the control structure and UCA tables** alongside architecture artifacts. Update with system evolution. Apply CAST post-incident to validate the analysis.

Aphorism: STPA-Sec gives you a coherent enumeration of what could go wrong with control. Adversary prioritization, exploit feasibility, and defense cost-benefit are separate disciplines. Don't conflate them.

**14.1 The bilingual-analyst requirement.** STPA-Sec programs need at least one analyst who is fluent in both systems-engineering vocabulary (control structure, feedback loop, process model, unsafe control action) and security vocabulary (threat actor, attack surface, exploit primitive, kill chain). Pure safety engineers miss adversarial-induction patterns; pure security engineers miss the systems-theoretic insights. The bilingual analyst is rare; cultivate or hire deliberately.

**14.2 Where STPA-Sec output feeds.** The control-structure diagram becomes the canonical system map for cybersecurity discussions. The UCA table becomes input to threat modeling reviews, code review focus areas (cross-link `[[reference-code-review-expertise]]`), and detection-engineering rule design (cross-link `[[reference-detection-engineering]]`). The loss-scenario list becomes input to penetration-testing scoping and red-team objective setting. The defenses derived become engineering backlog items with acceptance criteria.

**14.3 Maintenance cadence.** Architecture changes invalidate parts of the control structure; new threat intelligence invalidates parts of the loss-scenario set. Plan for at least annual STPA-Sec model refresh, with incremental updates on architecture-change events. Tie the refresh cadence to the program's security risk-assessment cycle (yearly for most regulated industries).

---

## 15. Status

Authored 2026-05-21.

Sibling to:
- `threat_modeling_discipline_expertise.md` — parent overview
- `misuse_abuse_case_modeling_expertise.md` — narrative adversary stories
- `attack_trees_expertise.md` — attacker-goal decomposition

Completes the four-leg threat-modeling cluster:
1. Discipline overview (TM disc)
2. Misuse / abuse stories (MA cases)
3. Attacker-goal decomposition (attack trees)
4. Systems-theoretic hazard analysis (this doc)

Anchored on Leveson + Young + Thomas + MIT SafeWare corpus, with regulated-industry adoption coverage (DO-326A/356A, ISO/SAE 21434, FDA premarket, NIST SP 800-160 Vol. 1) and AI-system extension (agent UCA enumeration cross-linked to AI-IR + capability-based-security siblings).
