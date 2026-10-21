# Threat Intelligence Methodology — Pivot Graphs, Attribution, and the Intel Cycle
## Synthesized from Sherman Kent, Richards J. Heuer Jr., Sergio Caltagirone, Christopher Betz, Andrew Pendergast, Eric Hutchins, Joe Slowik, John Hultquist, Robert M. Lee, David Bianco, the Mandiant APT1 team, and the Citizen Lab

> **Researchers:**
> - **Sherman Kent** (1903–1986; Yale historian, OSS Research & Analysis, CIA Board of
>   National Estimates) — Author of *Strategic Intelligence for American World Policy*
>   (Princeton University Press, 1949), the foundational text of analytical intelligence
>   as a discipline. Kent argued intelligence is simultaneously *product*, *process*,
>   and *organization*; the tradecraft he formalized at CIA's Office of National
>   Estimates is the direct ancestor of every modern analytic program. Often called the
>   father of intelligence analysis.
> - **Richards J. Heuer Jr.** (1927–2018; CIA, 45 years) — Author of *Psychology of
>   Intelligence Analysis* (CIA CSI, 1999) and creator of Analysis of Competing
>   Hypotheses (ACH), developed for a 1984 interagency deception course on Soviet
>   arms-control behavior. The book collects CIA Directorate of Intelligence articles
>   from 1978–86. CIA Seal Medallion (1987). ACH is the most-deployed structured
>   analytic technique outside the academy and has been ported into cyber-attribution
>   practice by Dragos, Mandiant, and Recorded Future.
> - **Sergio Caltagirone, Christopher Betz, Andrew Pendergast** — Authors of *The
>   Diamond Model of Intrusion Analysis* (DTIC technical report, 2013). Each was a
>   senior US-IC analyst at the time of writing; Caltagirone later built Dragos's threat-intelligence team;
>   Pendergast went to ThreatConnect. The Diamond Model — four core features
>   (adversary, capability, infrastructure, victim) edge-connected as a diamond — is
>   the dominant operational intrusion-analysis framework. The paper's contribution is
>   formal: an atomic event structure supporting measurement, testability, and
>   repeatability across analysts.
> - **Eric Hutchins** (Lockheed Martin Fellow, Chief Intelligence Analyst LM-CIRT) —
>   Lead author with Michael J. Cloppert and Rohan M. Amin of *Intelligence-Driven
>   Computer Network Defense Informed by Analysis of Adversary Campaigns and Intrusion
>   Kill Chains* (2011). The Cyber Kill Chain adapted military doctrine to network
>   defense; the seven-stage model remains the most-taught attacker-lifecycle framework.
> - **Joe Slowik** — Threat-intel practitioner with senior roles at Los Alamos National
>   Lab, Dragos, DomainTools, Gigamon, and Huntress. Best known operationally for the
>   2020 SolarWinds attribution work at DomainTools and the *Threat Intelligence and
>   the Limits of Malware Analysis* Dragos whitepaper; methodologically for the
>   doctrine that attribution is a *product*, not *truth* — a calibrated communication
>   with explicit confidence intervals.
> - **John Hultquist** (Chief Analyst, Google Threat Intelligence Group; formerly VP
>   of Intelligence Analysis at Mandiant; led iSIGHT Partners cyber-espionage practice
>   pre-FireEye acquisition; founder of CYBERWARCON and SLEUTHCON). 15+ years across
>   US-IC and private-sector intel. Public writing on analyst OPSEC and the
>   intelligence-versus-reporting distinction is widely cited.
> - **Robert M. Lee** (CEO and co-founder, Dragos; former US Air Force Cyber Warfare
>   Operations Officer at NSA on critical-infrastructure threats). Author of SANS
>   FOR578 *Cyber Threat Intelligence* and SANS ICS515; originator of the Active Cyber
>   Defense Cycle (ACDC), a four-phase loop that operationalizes intel inside ICS/OT
>   environments.
> - **David Bianco** — Detection-and-response practitioner; author of the 2013
>   *Enterprise Detection & Response* essay "The Pyramid of Pain," originally
>   developed at Mandiant during the APT1 era. The Pyramid is the operational dual to
>   a threat-intel triage prior — every IOC type has a cost-to-attacker, and intel at
>   the apex (TTPs) imposes structurally durable defender advantage. Cross-link to
>   `detection_engineering_expertise.md` §1.
> - **The Mandiant APT1 team** (Kevin Mandia, Dan McWhorter, et al.) — Authors of
>   *APT1: Exposing One of China's Cyber Espionage Units* (Mandiant, February 2013).
>   The report identified PLA Unit 61398, named three specific operators (Wang Dong /
>   UglyGorilla, Mei Qiang / SuperHard, "DOTA"), released ~3,000 indicators, and
>   remains the canonical case study for attribution-by-OPSEC-failure. The 2014 US
>   indictment of five 61398 officers is the legal sequel.
> - **The Citizen Lab** (founded 2001 by Ronald Deibert at the Munk School, University
>   of Toronto) — Interdisciplinary research lab combining technical forensics, field
>   research, social science, and legal analysis. Their Pegasus / NSO Group research
>   (2016–present) — including the 2021 peer review of Amnesty Tech's forensic methodology
>   report and the 2023 disclosure of three iOS 15/16 zero-click exploit chains used
>   in 2022 against civil society — is the high-water mark for rigorous civil-society
>   targeting intel: forensic disclosure, signed evidence chains, named victims (with
>   consent), and named operators.
>
> **Sources:** Kent, *Strategic Intelligence for American World Policy* (1949) and
> CIA CSI essays; Heuer, *Psychology of Intelligence Analysis* (1999); Caltagirone,
> Pendergast, Betz, *The Diamond Model of Intrusion Analysis* (2013); Hutchins,
> Cloppert, Amin, *Intelligence-Driven Computer Network Defense* (2011); Mandiant
> *APT1* (2013); Joe Slowik blog (`pylos.co`) and Dragos/DomainTools/Gigamon
> publications; Bianco's *Enterprise Detection & Response*; Citizen Lab Pegasus
> archive (`citizenlab.ca`); Amnesty Tech *Forensic Methodology Report* (2021); MITRE
> ATT&CK / D3FEND / ATLAS; OASIS STIX/TAXII 2.1; FIRST.org TLP 2.0 (2022); MISP and
> OpenCTI; SANS FOR578; CISA Joint Cybersecurity Advisories; the published corpus of
> attribution disputes through May 2026.

---

## 1. What Threat Intelligence Actually Is

### Kent's tripartite definition

Sherman Kent's 1949 work fixed intelligence as three things at once: a *product* (the
report, the brief, the assessment), a *process* (the cycle by which raw data becomes
finished judgment), and an *organization* (the unit responsible for collection,
analysis, and dissemination). Most modern threat-intel program failures are diagnosable
as the collapse of one of the three — a program producing only feeds (product without
process), a process with no consumer organization, or an organization on the org chart
producing nothing falsifiable.

The discipline is older than the substrate. Every working analyst should read Kent's
*Strategic Intelligence* once and Heuer's *Psychology of Intelligence Analysis* twice;
both are public, both predate cyber, both anticipate modern CTI failures: groupthink,
premature closure, mirroring, satisficing, substituting activity for output.

### The four-level consumer model

The contemporary CTI community (anchored on SANS FOR578 and on Mandiant / CrowdStrike /
Recorded Future / Dragos reporting practice) divides intel by *consumer*, not source:

1. **Strategic** — boards, CISOs, regulators, policy. 6–24 month horizon; adversary
   motivation, geopolitical shifts, sectoral risk, RaaS macro economics. Prose, charts,
   scenarios. Rarely contains IOCs.
2. **Operational** — IR leads, hunt leads, SOC managers. Names campaigns and actors;
   describes TTPs; recommends posture changes. Narrative plus ATT&CK technique IDs plus
   hunt hypotheses.
3. **Tactical** — detection engineers and threat hunters. Specific TTP chains,
   observables, hunt queries, Sigma/YARA, signature heuristics. Highly structured.
4. **Technical** — SOC analysts and EDR/firewall/proxy tooling. Atomic IOCs (hashes,
   IPs, domains, URLs). Machine-readable. Highest perishability.

Every product declares its level and picks format accordingly. The most common authoring
failure is mixing levels — trying to address all four audiences in one PDF and reaching
none of them well.

### Why IOCs are the lowest-value form of intel

David Bianco's Pyramid of Pain (cross-link `detection_engineering_expertise.md` §1)
inverts the naive intuition. The technical-level outputs that consume the most pipeline
attention — hashes, IPs, domains — are exactly the indicators an attacker can rotate in
minutes for trivial cost. TTPs sit at the apex because changing how an actor operates
forces retraining, retooling, and operational risk. A feed of 100,000 IPs is worth less
than a single TTP write-up with an evidence chain. A program optimizing its dashboard
for "IOCs ingested per day" is measuring the wrong thing.

### The intel cycle

The canonical five steps (some texts split to four or six; same content):

1. **Planning and direction** — requirements drive everything. Without a consumer
   question, collection is exploration and analysis is rumination.
2. **Collection** — open source, vendor feeds, internal telemetry, partner sharing,
   HUMINT, commercial intel.
3. **Processing** — deduplication, normalization, enrichment, tagging. The unglamorous
   substrate. Bad processing makes good analysis impossible.
4. **Analysis and production** — applying frameworks (§2) plus analyst judgment;
   structured techniques (ACH, devil's advocate, red-team review); product calibrated
   to consumer level.
5. **Dissemination and feedback** — right format, right audience, TLP-marked; closing
   the loop on whether it was used.

Every modern reformulation (FBI, NATO, SANS) restates the same shape. Universal failure
modes: skipping planning (collection-first), no feedback loop, confusing reporting
(chronological event dump) with intelligence (falsifiable judgment).

### Cross-links

Intel is an input to other disciplines. The detection-engineering bridge is the most
load-bearing cross-link in this doc set: every intel finding generates "what would we
detect for this?" The VR bridge: intel pivots inform target selection — campaigns that
exploit a substrate predict where the next bug-hunting hours pay off. The steelman
bridge: ACH is structurally a steelman (hypotheses enumerated, evidence weighed,
flip-conditions recorded). See `detection_engineering_expertise.md`,
`vulnerability_research_methodology_expertise.md`, and `steelman_doctrine_expertise.md`.
§5 below walks a long-running supply-chain campaign track as a worked example.

---

## 2. Frameworks Worth Knowing

### The Diamond Model (Caltagirone, Pendergast, Betz, 2013)

The most-used operational intel framework. Every intrusion event is an atomic record
with four core features connected as a diamond:

- **Adversary** — the actor with intent to harm. Pseudonyms (APT28, FIN7, Volt Typhoon)
  are activity clusters, not necessarily one organization.
- **Capability** — tools, techniques, malware, exploits used.
- **Infrastructure** — domains, IPs, ASNs, redirector chains, hosting providers.
- **Victim** — targeted entity / person / asset; sector, geography, role.

Six meta-features attach: timestamp, phase (mapped to kill chain), result, direction,
methodology, resources. Two higher-level constructs: *activity threads* (phase-ordered,
causally linked events) and *activity groups* (clusters of related events and
threads).

The paper's formal contribution: a diamond is a graph node; threads and groups are
edges; pivots are explicit traversals.
Use it on every intrusion
you analyze — the discipline of writing the diamond forces articulation of what you
know per corner and what you don't. "Adversary: unknown" stated explicitly beats
"Adversary: probably Russia" stated sloppily.

### The Cyber Kill Chain (Hutchins, Cloppert, Amin, 2011)

Seven stages: reconnaissance → weaponization → delivery → exploitation → installation →
command and control → actions on objectives. Adapted from military doctrine. The
paper's load-bearing insight: *intelligence-driven* defense — each stage admits
intervention, and intel about adversary behavior at one stage predicts the next.

Best use: storytelling for non-technical audiences. Failure modes: linearity assumption
(real attacks loop, branch, restart); weak fit to insider, supply-chain, and identity
attacks (the model presupposes external perimeter penetration); MITRE ATT&CK
supersedes it for technical detail. Use Kill Chain for narrative skeleton; ATT&CK for
technique-level fill.

### MITRE ATT&CK and D3FEND

ATT&CK is the de-facto taxonomy. As of May 2026 (v19), the enterprise matrix covers 15
tactics, 222 techniques, 475 sub-techniques; separate matrices for mobile and ICS. Map every intel write-up to ATT&CK IDs — it's the consumer-side
lingua franca. D3FEND is the defender-side dual; less universally adopted but value is
the explicit mapping between defensive action and the offensive technique it counters.
Use D3FEND when proposing posture changes.

ATT&CK's failure mode is granularity inflation — coverage maps reporting "80% of
techniques detected" hide the fact that the techniques the adversary actually used are
the 20%. Coverage maps are directional, not report cards.

### STIX / TAXII

OASIS standards. STIX 2.1 (OASIS Standard, 2021) is the data model — ~20 object types
(indicators, malware, threat actors, campaigns, intrusion sets, identities, attack
patterns, courses of action, marking definitions including TLP). TAXII 2.1 is the
transport protocol — RESTful over HTTPS with Collections (repository); Channels
(pub/sub) are reserved but not specified in 2.1. Right substrate for inter-organizational sharing (governments, ISACs, vendor
feeds); overkill for internal use — most internal programs run MISP/OpenCTI with STIX
export only at the sharing boundary. Common failure: STIX-document maximalism (thousand-
object bundles with sparse fields). Discipline: emit minimum STIX satisfying the
consumer's query, not the full graph.

### The "framework tax"

Every framework is lossy. Diamond Model presupposes a discrete adversary (what about
ecosystems where groups share infra?). Kill Chain presupposes perimeter penetration
(what about insiders?). ATT&CK presupposes the technique is in the catalog (what about
novel?). The mature analyst chooses the framework that compresses *least* information
out of the intrusion. The flag of a bad write-up is forcing data into a framework that
does not fit — better to say "the adversary corner is plural" than invent a fake single
adversary to make the diagram complete.

---

## 3. Pivot Graphs and Infrastructure Intelligence

### The pivot-graph mental model

Every IOC has neighbors. Every neighbor has neighbors. The pivot graph is the implicit
network you traverse to expand a single indicator into a campaign characterization.
Canonical pivots, by yield-per-effort:

1. **Domain → IP** (passive DNS). Resolution history yields hosting-provider clusters,
   fast-flux, DGA patterns.
2. **IP → domains** (reverse passive DNS). Yields campaign clusters via co-hosted
   phishing kits.
3. **IP → ASN, hosting provider, geolocation.** Infrastructure provenance.
4. **Domain → nameservers, registrar, registrant, registration timestamp** (WHOIS).
   The "100 domains registered within 60 seconds through Namecheap with the same NS
   pair" is the canonical campaign-signature pivot.
5. **TLS certificate fingerprint → other domains on same cert** (Censys, urlscan.io).
   Wildcard and SAN-laden certs are goldmines.
6. **JA3 / JA4 / JA4S TLS-stack fingerprint** (cross-link `detection_engineering_expertise.md`
   §2). The TLS Client Hello is the attacker's tooling fingerprint, not the victim's.
   A single JA4 hash can cluster thousands of C2 callbacks across campaigns. See
   Althouse's JA3 (2017, Salesforce) and JA4+ (2023, FoxIO).
7. **HTTP headers, default page content, favicon hash, page title.** Default admin
   panels and Cobalt Strike team-server fingerprints have characteristic responses
   Shodan and Censys index directly.
8. **SSH host key, banner.** Less common; very high confidence — host-key reuse across
   IPs means re-imaged identical staging.
9. **Code-reuse pivots** (binary similarity) — Mandiant permhash, imphash, capa
   family-signature work; PE section-hash and Rich-header pivots.

Graph traversal, not list filtering. Each step is a hypothesis committed to, each node
yields 0/1/many neighbors, mark visited and avoid loops. Without graph discipline the
work turns into manual whack-a-mole.

### Tooling (May 2026)

- **VirusTotal** (Google) — file/URL/IP/domain corpus, YARA-livehunt, similarity
  clustering. Most load-bearing pivot platform.
- **Microsoft Defender Threat Intelligence** (formerly PassiveTotal / RiskIQ) — passive
  DNS, WHOIS history, SSL pivots, web-component detection. Dominant infrastructure
  platform.
- **urlscan.io** — URL-scanning corpus with favicon-hash, screenshot OCR, ASN/domain/IP
  cross-references.
- **Censys** — internet-wide TLS scans, JA3/JA4 search, banner search. Strongest for
  TLS-fingerprint pivots.
- **Shodan** — internet-wide service banner indexer; cheaper and more permissive than
  Censys for many pivots.
- **Validin** — purpose-built passive DNS / WHOIS / TLS pivot platform; strong on
  historical WHOIS.
- **Mandiant Advantage** (Google Cloud) — vendor-curated actor and infrastructure intel
  on the VT corpus; strongest commercial actor-attribution context.
- **DomainTools Iris** — WHOIS-history pivot; Joe Slowik's home base for SolarWinds
  attribution.
- **GreyNoise** — internet background-noise classifier. Inverse pivot: tells you when
  an IP is *not* worth investigating.

Domain pivots → PassiveTotal/Validin. TLS pivots → Censys. URL pivots → urlscan.
Malware-sample pivots → VirusTotal. Cross-link `dns_network_infrastructure.md` for DNS
pivot mechanics (passive DNS, sinkholes, DoH-induced visibility loss).

### The "campaign signature" pivot

A campaign signature is the recurring tuple of pivots that distinguishes an operation.
For long-running package-ecosystem supply-chain campaigns, a signature has included
things like specific chat-platform channels used for coordination, a characteristic
commenting or code style repeated across published artifacts, a small cluster of
registrant emails behind hundreds of typosquats, and common deployment artifacts
(specific README boilerplate, specific stager shape).

When a new indicator shows the same signature shape, attribution becomes
high-confidence quickly. When the signature changes, decide whether the campaign
evolved or a different group took over the infrastructure. Write the signature as a
structured object (MISP galaxy entry / OpenCTI threat-actor object); update on
evidence; treat its stability as a measurement of the actor, not a property of the
intel.

### WHOIS-history pivots

WHOIS has been progressively redacted (GDPR, ICANN policy); historical WHOIS remains
high-yield. The five most-useful patterns: registrant-email reuse (indexed even where
current WHOIS is redacted); nameserver tenancy (actors who run their own DNS or
consistently use the same authoritative NS); registrar choice (NameSilo, Internet.bs,
Namecheap, Porkbun, Tucows correlate with different actor populations);
registration-timestamp clustering (100 domains in 60 seconds = near-certain campaign
indicator); WHOIS-privacy provider patterns (less-mainstream privacy services cluster
actors).

### Cross-domain pivots

The mature analyst pivots between substrates. Breach disclosure → operators → handles
→ crypto addresses → exchange activity → KYC (subpoenable, not OSINT). Leaked
npm/PyPI/RubyGems package → maintainer email → other packages by same maintainer →
downstream consumers. Compromised GitHub Action (cross-link
`cicd_supply_chain_expertise.md`) → repos that consumed it during the window →
downstream secrets exposed. The pivot graph spans the whole attacker-economy
substrate; the analyst's job is to pick traversals that yield enough intel to justify
the time.

---

## 4. Attribution as a Discipline

### Attribution is a spectrum, not a binary

The most-frequent failure mode in threat-intel reporting is binary attribution: "this
was Russia" or "this was APT28" stated without explicit confidence. The audience reads
it as a fact; the analyst meant it as a hypothesis with moderate support.

Joe Slowik's "attribution as product, not truth" doctrine prescribes the fix: every
attribution claim carries an explicit confidence interval. The IC standard (ICD 203):

- **Almost no chance** 1–5%, **Very unlikely** 5–20%, **Unlikely** 20–45%,
  **Roughly even** 45–55%, **Likely** 55–80%, **Very likely** 80–95%,
  **Almost certain** 95–99%.

Every published attribution picks a band and defends it. A write-up that does not
commit is reporting, not intelligence.

### Five attribution evidence classes

1. **Code reuse / compiler-artifact reuse.** Shared modules; PE Rich-header reuse;
   .NET compiler-version fingerprints; packer signatures. High signal when controlled
   for; weak when the shared substrate is open source or leaked toolkit. The
   "code-reuse-is-not-shared-author" caveat: leaked Babuk, leaked Conti, and commodity
   red-team frameworks look like provenance but aren't.
2. **Infrastructure reuse / temporal co-location.** Shared C2 IPs, registrar account,
   overlapping registration windows. Medium-to-high signal especially combined with
   operator OPSEC failures.
3. **TTP overlap.** Same lateral-movement pattern, credential-access tooling, exfil
   channel design. Pyramid-of-Pain apex: highest-confidence class because changing
   TTPs costs the adversary the most.
4. **Victim-targeting overlap.** Same sectors, geographies, individual targets. Useful
   for narrowing — two campaigns against Mongolian dissidents likely share an
   interested party.
5. **OPSEC failures.** PII leaks, language artifacts (Cyrillic in comments, time-zone
   artifacts in commit metadata), accidental uploads to public scanners from operator
   workstations, account-creation patterns. The Mandiant APT1 model: Wang Dong's QQ
   chats and real-name social-media accounts.

A well-supported attribution chains three or more classes. Weak attribution leans on
one. "Single-source attribution" — one vendor report cited by every downstream source
without primary corroboration — is rampant and produces echo chambers.

### Heuer's ACH applied to attribution

The Analysis of Competing Hypotheses framework structures attribution as a matrix:

1. Enumerate every plausible hypothesis: APT28 / APT29 / FIN7 / criminal /
   false-flag / compromised legitimate operator / unknown.
2. List every piece of evidence as a row.
3. For each (evidence, hypothesis) pair, score consistent / inconsistent /
   not-applicable. Heuer's central insight: *inconsistent* evidence is more diagnostic
   than *consistent* (consistent evidence often supports multiple hypotheses;
   inconsistent eliminates one).
4. Drop hypotheses that accumulate too much inconsistent evidence.
5. Identify the most diagnostic evidence; collect more if possible.
6. Draw tentative conclusions from remaining hypotheses.
7. Calibrate confidence; flag dependency on key evidence pieces.
8. Name the indicators that would change the conclusion — Heuer's flip-conditions.

ACH is structurally identical to the steelman doctrine
(`steelman_doctrine_expertise.md`): enumerate alternatives, weigh evidence
inconsistently, commit explicitly, record flip-conditions. Senior analysts run ACH
mentally; junior analysts run it on paper.

### Common attribution failures

- **Single-source attribution.** Vendor X cites Vendor Y cites Vendor X. Substrate
  becomes vapor.
- **False-flag paralysis.** "Anyone could fake it." True in principle; in practice,
  well-resourced actors leave too many real artifacts to forge cheaply. Use
  false-flag as a hypothesis in ACH, not a license to refuse attribution.
- **Attribution from impact.** "Targeted a defense contractor, therefore nation-state."
  Many financially-motivated crews target defense contractors. Impact is weak signal
  versus TTP and infrastructure.
- **Time-zone determinism.** Eastern-European business hours could be Moscow, Kyiv,
  Tallinn, or Bangkok-via-VPN. Soft signal in a stack of others.
- **Language-artifact determinism.** Cyrillic in comments could be Russian, Bulgarian,
  Belarusian, or a non-Russian operator using a leaked Russian toolkit.
- **Nation-state / financial / hacktivist trichotomy as bright line.** Boundaries are
  porous. Conti-affiliated GRU adjacency; APT actors moonlighting for profit;
  hacktivist fronts hosting state ops.
- **Vendor branding inflation.** "APT-X" names are vendor conventions, not ground
  truth. Different vendors cluster differently; cross-vendor crosswalks (Recorded
  Future and others publish them) are non-optional.

### The Citizen Lab standard

Citizen Lab's Pegasus research is the modern gold standard for high-rigor attribution:
forensic evidence from consenting victims; technical analysis with chain-of-custody;
cross-references to infrastructure pivots from prior research; peer review of
Amnesty Tech's methodology publication (2021) for replicability; named victims (with consent)
and named operators where possible; public PDFs of the evidence chain.

The contrast with most commercial attribution is stark: Citizen Lab discloses
methodology, victims, and evidence; commercial vendors disclose vendor-branded actor
names and high-level findings. Both have a role; the standard for attribution intended
to drive policy or legal action is the Citizen Lab standard. Cross-link to
`vulnerability_research_methodology_expertise.md` §3 — the joint Google P0 / Citizen
Lab disclosure pattern on iOS exploit chains is the working model.

---

## 5. Campaign Tracking — the Long-View Discipline

### A campaign is a sustained operation, not an alert

A campaign is a sustained operation with consistent actors, consistent objectives,
evolving tooling, and a recognizable signature across events. The unit of analysis for
serious intel is the campaign, not the alert.

Tracking requires: a campaign object in the intel platform (MISP galaxy / OpenCTI
campaign), continuously updated; the Diamond Model in time-series form (each event's
diamond is a snapshot; the campaign is the trajectory); the campaign-signature object
from §3; an evidence-chain log of every observation that updated the object; and an
internal name. Stable internal identity is what lets a multi-year campaign track
survive analyst turnover. Track the public-mapping table (APT-X / ActorY / NameZ)
alongside.

### A long-running supply-chain track as worked example

A privately-tracked, long-running package-ecosystem supply-chain campaign illustrates
the discipline. Early phases covered initial discovery, infrastructure pivots,
registrant clustering, and package-ecosystem watering-hole mechanics. Later phases
expanded tooling and targeting and evolved delivery across chat platforms and multiple
package registries. Signature drift was the diagnostic that this was one operation
evolving, not multiple operations taking over the same infrastructure. The discipline
that made the arc tractable: every phase ended with a written artifact updating the
canonical campaign object, so the track survived analyst turnover and repeated
context resets without losing coherence — substrate discipline pays.

### "Tools change, infra changes, TTPs persist"

Across published multi-year campaigns (Equation, APT28/APT29, Lazarus, Volt Typhoon,
Sandworm, the FIN groups):

- **Tools rotate** months-to-a-year. Malware families get burned and retired.
- **Infrastructure rotates** days-to-weeks. C2 domains, IPs, redirector chains.
- **TTPs persist for years.** Lateral-movement patterns, credential-access
  preferences, exfil channel design, target-selection logic — stable operator-culture
  fingerprint.

Corollary: invest analyst time at the TTP layer. IOC feeds are snapshots; TTP
catalogues are tracks.

### Adversary lifecycle

Campaigns have a lifecycle: provisioning → operational ramp → tempo → degradation
(defender catch-up, signature blowback) → retirement or rebranding. Track:

- Volumetrics — domain registrations per week, C2 callback volume, VT submission rate.
- Tempo — hours-of-operation patterns (sanity check on attribution).
- Degradation — defender publications, takedowns, arrests.
- Rebranding — discontinuity in tooling combined with continuity in infrastructure
  (or vice versa). Conti → Royal → BlackSuit is the textbook example.

A campaign in ramp is the worst time to ignore it; a campaign in degradation is the
best time to publish defensive guidance because the actor struggles to recover.

---

## 6. Malware Family Clustering

### Static substrate

The canonical static-analysis hashes:

- **YARA rules** — pattern-matching DSL by Victor Alvarez (VirusTotal, formerly
  Hispasec); the de-facto standard for sample classification. Both signature and
  family-level rules. Cross-link `detection_engineering_expertise.md` §3.
- **ssdeep / TLSH (fuzzy hashing)** — sliding-window content-defined hashing yielding
  similarity scores 0–100; >50 meaningful, >90 near-duplicate. TLSH (Trend Micro) is
  more stable on small samples.
- **imphash** — PE file hash of imported-DLL/function sequence in import-table order.
  Compiler / toolchain fingerprint; excellent campaign-level signal, weaker for
  individual authorship. (Mandiant *Tracking Malware with Import Hashing*.)
- **Rich header analysis** — Visual Studio toolchain artifacts encoded in PE files.
  Pivots well within a campaign because actors rarely change build environments
  mid-operation.

Mandiant FLARE's `permhash` (2023) extends import-hashing to Chrome extensions and
other manifest-based artifacts (hash of the requested-permission set) — surfaced as a
VirusTotal feature.

FLARE's `capa` is the modern reference for *capability-based* clustering: identifying
what a binary *does* via static features mapped to ATT&CK techniques. A curated rule
corpus runs against an unknown sample and produces an ATT&CK-mapped capability summary.
The shift from family-name-based to capability-based clustering is one of the most
consequential mid-2020s methodology developments.

### Dynamic substrate

Sandbox detonation extracts process tree, network/registry/filesystem changes,
anti-analysis signals, and ATT&CK-mapped behaviors. The major sandboxes are CAPE
(open-source Cuckoo fork, the modern default), Joe Sandbox / VMRay / Any.Run
(commercial; richer instrumentation), and Hybrid Analysis (free CrowdStrike tier for
ad-hoc lookups). Dynamic is richer than static but brittle — the sample may not
detonate, may detect the sandbox, or may require specific config. Use dynamic to
enrich static clustering, not replace it.

### Authorship attribution and code stylometry

Stylometry attempts to attribute code to individual authors via variable naming,
control-flow preferences, library choices, and comment-language artifacts. Academic
studies (Caliskan-Islam et al., 2015) show >90% accuracy (94% across 1,600 Google Code Jam programmers) —
but it fails at production-actor scale because real campaigns reuse code, share
contributors, and adopt commodity malware. The "code-reuse-is-not-shared-author"
caveat (§4) dominates: leaked Babuk and Conti sources plus leaked red-team frameworks
(Cobalt Strike, Brute Ratel) produce code-reuse signals that look like authorship and
aren't. Use stylometry as one input in an ACH matrix, never the sole basis.

### ML-assisted clustering

ML helps with large-scale binary-feature clustering where signal-to-noise is high and
ground-truth labels exist (VirusTotal similarity clustering). It
over-promises on zero-day classification and individual-author attribution; marketing
claims routinely outrun empirical performance. Black-box classifiers without
explainable feature attribution are actively harmful — the IR analyst cannot defend
a verdict they cannot introspect. Treat ML as a cheap hint requiring manual
validation. Cross-link `vulnerability_research_methodology_expertise.md` §6 on the
same skepticism in ML-assisted bug-finding.

### The patch-diffing bridge

Malware family analysis and patch diffing (the Halvar Flake / BinDiff discipline)
share substrate. A patch is a code change; a family update is a code change. Both
reverse-engineer the same way: decompile, diff against prior version, identify the
semantic change, hypothesize the purpose (patched vuln / evasion of defender
signature / added capability). Cross-link
`vulnerability_research_methodology_expertise.md` §3 — the technique ports.

---

## 7. OSINT Methodology

### Pyramid and substrates

Four layers by access cost: **surface web** (indexed — vendor blogs, conferences,
GitHub, indexed forums), **deep web** (authenticated forums, mailing lists, Discord,
Telegram), **dark web** (Tor / I2P — BreachForums-lineage sites, ransomware leak
sites), and **HUMINT-adjacent** (informants, undercover personas, partner-shared
confidential intel). In 2026, most operator chatter for criminal and hacktivist ops
lives on Telegram; dark web is where breaches surface.

Tooling: Google dorking + Yandex (Russian) + Baidu (Chinese); Shodan / Censys /
BinaryEdge for service enumeration (§3 pivots); Maltego / SpiderFoot for entity
graphs; Telegram clients with logging (sock-puppet accounts, separate devices, never
personal identity); HaveIBeenPwned / Dehashed / IntelX for breach corpus; GitHub
advanced search + the GitHub Archive (near-realtime events dump — a goldmine for
deleted-but-cached commits and secrets in history); Wayback Machine for historical
content actors deleted.

**Telegram channels** dominate ransomware-affiliate ops, initial-access-broker
listings, hacktivist coordination (Killnet, NoName057(16)), stealer-log markets,
mobile-malware distribution. Discipline: sock-puppet subscription, log everything
(channels selectively delete), retain TLP marking, accept partial-visibility bias
(real channels are usually invite-only).

**Breach forums** are the substrate for stolen-data trade and operator
self-promotion. BreachForums-successor / RaidForums lineage is the canonical 2020s
example; operator continuity survives shutdowns via reputation systems. Pivot from
forum handle to real identity is high-yield but patient — high-OPSEC operators take
years to surface.

### Ethical OSINT

Public-figure OSINT on operators publishing under real names is fair game.
Civil-society OSINT (Citizen Lab style) requires victim consent and responsible
disclosure — never publish a victim identity without permission. Data minimization:
collect what the analytical question needs; hoarded PII is itself an attack surface.
Passive collection of public posts is normal; creating fake personas to elicit
information or exploiting platforms beyond ToS is gray zone where legal review is
non-optional. GDPR / CCPA / PIPL constrain commercial OSINT meaningfully when
collecting on foreign nationals.

### Analyst OPSEC

Threat-intel analysts are themselves targets — operators retaliate; nation-states
out analysts who get too close. Discipline: separate identities (persona accounts,
burner SMS, separate browser profiles, separate hardware where risk justifies);
infrastructure separation (research VPS for actor-domain fetches, never corporate
network; kasm or VM for opening attacker content); VPN / Tor for high-risk pivots
(don't fetch attacker C2 panels from home IP); personal-life pseudonymization (keep
personal LinkedIn, family photos, home address off the public web); threat model against
worst-case adversary identifying you. Closer to investigative journalism than
corporate security.

---

## 8. The Intel Cycle in Practice

### Planning — requirements come from the consumer

The most common program failure is collection-first: 500 feeds, weekly summaries, no
planning. The planning step asks: who is the consumer (CISO, SOC lead, IR team, exec,
product PM), and what decision could intel inform? Requirements are questions:

- "Should we invest engineering hours defending against TTP X?"
- "Has our org been targeted by campaign Y, and if so, what was the impact?"
- "Is published vulnerability Z likely to be exploited in the wild in the next 90
  days?"
- "Which ransomware affiliates target our sector, and what is their preferred
  initial-access vector?"

The Priority Intelligence Requirements (PIR) doctrine — from military intelligence —
formalizes this. PIRs are a prioritized question list; collection must be defensible
against the list; analytical hours trace to a PIR. Quarterly PIR re-rating against
changing business priorities is the discipline.

### Collection — sources matched to requirements

Five source families:

1. **Internal telemetry** (SIEM, EDR, IDS, identity logs). Most-trusted; limited to
   what your environment experiences. Cross-link `detection_engineering_expertise.md`
   §2.
2. **Open-source feeds** (public IOC lists, vendor blogs, conference talks). High
   volume, low signal-to-noise.
3. **Commercial feeds** (Mandiant, CrowdStrike Intel, Recorded Future, Flashpoint,
   Cyjax, Intel 471). Curated, often actor-attributed; quality varies; most programs
   buy two or three for cross-corroboration.
4. **Partner sharing** (ISACs, trusted-group rings, government-to-private — CISA AIS
   in the US). High quality when the partner is
   competent; political/contractual friction is real.
5. **HUMINT-adjacent and undercover** — persona-led collection on closed channels.
   Highest signal-per-yield; highest OPSEC cost; specialist teams with legal review.

Cost-yield analysis on every paid feed annually: a $200K/year feed earns its keep if
it answers two PIRs no other source addresses; otherwise drop it.

### Processing — the unglamorous foundation

Deduplication (cross-feed lineage tracking), normalization (IOC types, actor-name
aliases via MISP galaxies), enrichment (WHOIS, passive DNS, VT, sandbox detonation),
tagging (TLP, source confidence, expiration, PIR mapping, ATT&CK techniques), and
storage on a platform supporting time-based query, relationship traversal, and STIX
export (MISP and OpenCTI open-source; ThreatConnect and Anomali commercial). Stale or
broken dedup makes analysis untrustable. Most programs under-invest because
processing is invisible to consumers.

### Analysis — frameworks plus structured judgment

The disciplined analyst selects the framework that best fits (Diamond Model for
intrusion events, Kill Chain for narrative, ATT&CK for techniques); applies a
structured analytic technique from Heuer's catalog (ACH, devil's advocate, red team,
key assumptions check, indicators-and-warning, what-if scenarios) — each counters a
specific cognitive failure mode; documents the evidence chain so every claim ties to
source data, every confidence band to evidence, every flip-condition named; and
calibrates to the consumer level (§1).

Cross-link `steelman_doctrine_expertise.md` — Structured Analytic Techniques (SATs)
and the steelman doctrine are the same discipline in different domains. ACH is
steelman Variant B applied to an attribution claim; devil's advocate is structured
Foil-play; pre-mortem is flip-condition enumeration. Tetlock, Kahneman, Heuer
cross-cite. The practitioner working in both should treat them as one family.

### Dissemination — right format, right audience

- **Strategic** — exec brief / scenario / sector risk summary. PDF or slides;
  quarterly or event-driven.
- **Operational** — IR briefing, threat-hunt guidance, posture-change recs. Markdown
  or Confluence; weekly or campaign-driven.
- **Tactical** — Sigma, YARA, hunt queries, detection specs. Native SIEM format;
  continuous.
- **Technical** — STIX/TAXII feed, CSV, MISP push. Machine-readable; realtime.

Always with TLP marking, confidence calibration, and a named analyst owner. The
"wall-of-text dump" anti-pattern is endemic: a 60-page strategic report no exec will
read is dissemination failure regardless of analytical quality.

### Feedback — closing the loop

Did the consumer read the product (click-tracking, acknowledgment workflow)? Did it
answer the PIR (direct consumer interview)? Did the SOC use the tactical intel
(detection-engineering tickets traceable to intel reports)? Did anything fire in
production (SIEM-to-intel-source cross-reference)? What got missed (PIR gap analysis)?
Programs that skip feedback drift toward irrelevance.

---

## 9. Sharing Models

### TLP 2.0

The Traffic Light Protocol v2.0 (FIRST.org, August 2022):

- **TLP:CLEAR** — Unrestricted; spread to the world. For minimal-misuse-risk content.
- **TLP:GREEN** — Community sharing; peer community but not publicly-accessible
  channels. Common for vendor-CSIRT-to-customer-CSIRT.
- **TLP:AMBER** — Limited disclosure within recipient organization and clients on
  need-to-know. The most common marking for serious operational intel.
- **TLP:AMBER+STRICT** — Organization-internal only (no client sharing). New in 2.0;
  closes the "vendor over-shares to customers" gap.
- **TLP:RED** — Individual recipient only; no further disclosure even within their
  organization.

Markings capitalized, no spaces, on every page and in metadata. Forwarding a TLP:RED
brief to your team is a serious breach.

### ISACs, trusted-group rings, government programs

**ISACs** (Information Sharing and Analysis Centers) — sectoral nonprofits: FS-ISAC,
H-ISAC, E-ISAC, Auto-ISAC, Aviation-ISAC, IT-ISAC, MS-ISAC.
FS-ISAC and H-ISAC are widely regarded as the highest-utility. **Trusted-group rings**
— invite-only reputation-gated groups (OpsTrust, RSA-adjacent informal channels);
lighter than ISACs, higher trust-density, smaller scope. **Government-to-private** —
CISA AIS (US), NCSC (UK), ANSSI CERT-FR, BSI (DE), JPCERT (JP). Free; legally
encumbered (re-sharing requires permission).

Sharing discipline: contribute as much as you receive, never share upward without
authorization, mark with TLP, pseudonymize internal references when sharing
externally.

### Commercial feeds — when to buy

Buy when a feed answers a PIR no internal collection can (Mandiant / CrowdStrike for
actor reporting, Recorded Future for trend analysis, Dragos for ICS/OT). Don't buy
because "we should have a feed." Cross-corroborate (single-source vendor intel is
single-source attribution per §4 — run two vendors before high-confidence calls).
Annual cost-yield review.

### Intel-feed corruption

Low-quality feeds pollute downstream platforms. A noisy OSINT feed with thousands of
near-FP IPs ingested into MISP and distributed via TAXII contaminates SOC queues.
Defense: source-confidence scoring on ingest (drop or quarantine low-confidence
before detection); per-source expiration; IOC-effectiveness backtesting (a feed with
no true-positive in 12 months gets dropped). MISP and OpenCTI both support
source-confidence and expiration natively.

---

## 10. Operationalizing Intel

### Intel-to-detection — the load-bearing pipeline

Every intel finding should generate the question *what would we detect for this?*

- Campaign report cites a credential-access TTP → detection-engineering ticket to
  confirm SIEM-rule coverage.
- New malware family with characteristic process-tree pattern → Sigma rule authored,
  tested, deployed.
- Vendor brief describes phishing-kit fingerprint → URL-scanning rule, email-policy
  update.
- Attribution report names a JA4 fingerprint → network-detection rule.

An intel report that does not produce at least one detection-engineering ticket
should provoke the question: was the intel actionable, or narrative? Cross-link
`detection_engineering_expertise.md` §8. Mature programs track the ticket graph —
every intel artifact has linked detection tickets; every rule traces back to its
intel source; coverage metrics map to PIRs.

### Intel-to-vulnerability-management

Intel about active exploitation drives patch prioritization:

- **CISA Known Exploited Vulnerabilities (KEV)** — the most-load-bearing public
  signal; KEV-listed CVEs jump to top of patch queue.
- **Vendor exploitation data** — Mandiant exploitation tracker, CrowdStrike
  exploit-likelihood, Recorded Future vulnerability intelligence.
- **Internal red-team and pentest output** — last quarter's exploitable predicts
  this quarter's patch priority.
- **Asset criticality joins** — a CVE in your CRM DB outranks the same CVE in test.

Cross-link `appsec_program_building_expertise.md` §5 on program-level prioritization.

### Intel-to-hunting

Threat hunting is hypothesis-driven telemetry search; intel reports are hypothesis
generators. Campaign TTP → "do we see this in 90-day telemetry?" New credential-theft
pattern → "scan auth logs for the signature." Geographic-targeting trend → "anomalous
activity from these geographies?" Either outcome closes the loop. Cross-link
`detection_engineering_expertise.md` §8 for hunt methodology depth.

### Operational metrics

PIR coverage (percent answered per period); detection ticket conversion rate (intel
artifacts → detection tickets → deployed rules); hunt yield (hunts → findings →
IR-escalations); feed yield (per-feed true-positives in production); attribution
confidence distribution (too many "high" calls? too few?). Anti-metrics: IOCs
ingested, reports published, feeds subscribed — activity, not impact.

---

## 11. Common Intel-Program Failure Modes

- **Collection-first death.** "We have feeds; let's see what comes out." No PIRs, no
  consumer interviews. Fix: stop spending until PIRs are written; evaluate feeds
  against PIRs.
- **IOC-only intel.** Hashes, IPs, domains but no campaigns or TTPs. Pyramid-of-Pain
  inverted. SOC gets alert fatigue; CISO gets nothing decision-relevant. Fix: ratchet
  up the pyramid one level per quarter; IOC distribution becomes automated background.
- **Attribution theater.** Confident claims with no evidence chain. Blows up when an
  exec cites the report and a journalist asks for evidence. Fix: ACH discipline,
  calibrated confidence bands, explicit evidence chains.
- **Echo chambers.** Vendor A → Vendor B → Vendor C → back to A. Defense: track
  per-claim primary source; cross-reference across vendors with independent
  methodologies; require internal-collection corroboration before high-confidence.
- **Stale intel.** Recycled reports, unvalidated indicators, untouched campaign
  objects. Fix: per-indicator expiration; per-report archival policy; quarterly
  campaign-object review ("is this still active?").
- **Intel team isolated from SOC.** Reports SOC won't read; SOC wants TTPs intel
  doesn't produce. Fix: embed an intel analyst in the SOC; rotate SOC through intel;
  make detection-engineering tickets the canonical intel output, not PDFs.
- **Intel as marketing.** Vendor reports supporting sales narratives, sponsored
  attribution, manufactured urgency around vendor-named actors. Defense: independent
  verification; willingness to publicly contradict vendors when evidence justifies.
  Citizen Lab is the standard-bearer.
- **Cross-discipline isolation.** Intel siloed from detection, vulnerability mgmt,
  red-team, IR. Fix: cross-functional intel-sync; shared ticket queues; rotation
  programs; purple-team exercise discipline.

---

## 12. Variant Analysis — Under-Explored Areas

### AI-agent threats

Traditional intel evolved around malware, network intrusions, ransomware. AI-agent
threats (cross-link `llm_agent_security_expertise.md`,
`agentic_web_capabilities_expertise.md`) require adaptation. The campaign concept
transfers — LLM-powered scam ops, automated-vuln-discovery ops,
prompt-injection-as-a-service are sustained, signature-bearing, traceable. The
Diamond Model's infrastructure corner shifts: API keys, model versions, prompt
scaffolds, training-data corpora, fine-tune checkpoints, plugin configs replace C2
domains and IPs. TTP cataloguing lags — MITRE ATLAS is nascent. Attribution
complexity rises (LLM-driven attacks don't exhibit malware-style authorship;
stylometry of system-prompt design and harness code is the closest analog).
Greenfield in May 2026 — discipline portable, substrate novel.

### Supply-chain attacks

Package-ecosystem supply-chain attacks (cross-link `cicd_supply_chain_expertise.md`)
differ structurally from malware delivery. Victim corner is plural — a poisoned npm
package infects every downstream consumer; victims characterized by dependency-graph
position, not direct targeting. Infrastructure corner is the package registry (npm,
PyPI, RubyGems, crates.io, Maven Central, Go proxy, NuGet, Docker Hub); pivots are
registry-internal (maintainer-account graph, package-relationship graph). Timing
analysis dominates attribution — coordinated maintainer-account takeover, synchronized
typosquats, dependency-graph-aware payload selection. §5's long-running supply-chain
track is a worked example of this pattern. Requires package-registry observability
(every-publish tracking), maintainer-account graphing, and dependency-graph awareness —
none of which the traditional toolkit supplies.

### Cryptocurrency-laundering attribution

Specialized sub-discipline. Blockchain analysis (Chainalysis, TRM Labs, Elliptic,
Coinbase Analytics) traverses transaction graphs across BTC, ETH, major stablecoins.
Mixer / tumbler attribution (Tornado Cash forks, ChipMixer, Wasabi) — hard to defeat
operationally; input/output timing and amount heuristics yield clusters. Exchange KYC
subpoena targeting — once funds reach a KYC exchange, legal process gets operator
identity; the off-ramp is the attribution bottleneck. Cross-chain bridge analysis
treats bridges as funnel points and bridge-protocol exploits as their own intel
category. Most general programs subcontract this to specialists.

### Geopolitical intel adjacency

Cyber-intel and traditional military / political OSINT are converging.
Bellingcat-style open-source forensics — geolocating war-crime evidence, attributing
strikes via flight-track and weapon-fragment analysis — ports directly. Nation-state
cyber actors have geopolitical objectives visible in traditional substrates; timing
correlates with diplomatic/military events; targeting patterns (ministries, defense
contractors, dissidents, journalists) reveal strategic priorities. The analyst
pairing both methodologies gets a richer picture than either alone.

### AI-assisted analyst tools

LLMs help with report summarization, IOC normalization, draft generation,
cross-language translation, and ATT&CK-mapping suggestions. They fail at novel
attribution, calibrated-confidence judgment, and evidence-chain construction — the
"hallucinated attribution" failure mode is documented and recurrent. Actively
dangerous: ungrounded analytical output presented as analyst-validated. Cross-link
`llm_agent_security_expertise.md` §3. Draft-accelerator yes; judgment-substitute no.

---

## 13. References

### Foundational canon

- Kent, Sherman. *Strategic Intelligence for American World Policy.* Princeton, 1949.
  [Amazon (Princeton Legacy)](https://www.amazon.com/Strategic-Intelligence-American-Princeton-Library/dp/0691624046).
- Davis, Jack. *Sherman Kent and the Profession of Intelligence Analysis.* CIA CSI.
  [PDF](https://www.cia.gov/resources/csi/static/Kent-Profession-Intel-Analysis.pdf).
- Heuer, Richards J. Jr. *Psychology of Intelligence Analysis.* CIA CSI, 1999.
  [CIA edition](https://www.cia.gov/resources/csi/books-monographs/psychology-of-intelligence-analysis-2/) —
  [Internet Archive](https://archive.org/details/PsychologyOfIntelligenceAnalysis).
- Wikipedia. [Analysis of Competing Hypotheses](https://en.wikipedia.org/wiki/Analysis_of_competing_hypotheses).
- ODNI. *ICD 203: Analytic Standards.* IC calibrated-language standards.

### Cyber-intel frameworks

- Caltagirone, Pendergast, Betz. *The Diamond Model of Intrusion Analysis.* DTIC,
  2013. [PDF](https://www.activeresponse.org/wp-content/uploads/2013/07/diamond.pdf) —
  [DTIC](https://apps.dtic.mil/sti/citations/ADA586960).
- Hutchins, Cloppert, Amin. *Intelligence-Driven Computer Network Defense.* 2011.
  [ResearchGate](https://www.researchgate.net/publication/266038451_Intelligence-Driven_Computer_Network_Defense_Informed_by_Analysis_of_Adversary_Campaigns_and_Intrusion_Kill_Chains) —
  [Lockheed page](https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html).
- [MITRE ATT&CK](https://attack.mitre.org/), [D3FEND](https://d3fend.mitre.org/),
  [ATLAS](https://atlas.mitre.org/).

### Sharing standards

- OASIS [STIX 2.1](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html)
  and [TAXII 2.1](https://docs.oasis-open.org/cti/taxii/v2.1/os/taxii-v2.1-os.html), 2021.
- FIRST.org [TLP 2.0](https://www.first.org/tlp/), August 2022. [User guide PDF](https://www.cisa.gov/sites/default/files/2023-02/tlp-2-0-user-guide_508c.pdf).

### Case-study attribution

- Mandiant. *APT1: Exposing One of China's Cyber Espionage Units.* February 2013.
  [Mandiant PDF](https://services.google.com/fh/files/misc/mandiant-apt1-report.pdf) —
  [Mandiant blog](https://cloud.google.com/blog/topics/threat-intelligence/mandiant-exposes-apt1-chinas-cyber-espionage-units) —
  [NSA archive copy](https://nsarchive.gwu.edu/document/21484-document-83).
- Zetter, Kim. *How the Infamous APT-1 Report Came to Be.*
  [Zero Day](https://www.zetter-zeroday.com/how-the-infamous-apt-1-report-exposing-chinas-pla-hackers-came-to-be/).
- Citizen Lab [Pegasus archive](https://citizenlab.ca/tag/pegasus/).
- Citizen Lab. *Triple Threat: NSO Group's Pegasus Returns in 2022.*
  [citizenlab.ca](https://citizenlab.ca/research/nso-groups-pegasus-spyware-returns-in-2022/).
- Amnesty Tech. *Forensic Methodology Report: How to Catch NSO Group's Pegasus.* 2021.
  [PDF](https://www.amnesty.org/en/wp-content/uploads/2021/08/DOC1044872021ENGLISH.pdf).

### Practitioner writing

- Slowik, Joe. *Formulating an Intelligence-Driven Threat Hunting Methodology.*
  FIRST 2022. [PDF](https://www.first.org/resources/papers/conf2022/FIRST2022_Slowik_6.pdf).
- Slowik, Joe. *Threat Intelligence and the Limits of Malware Analysis.* Dragos.
  [PDF](https://www.dragos.com/wp-content/uploads/Threat-Intelligence-and-the-Limits-of-Malware-Analysis.pdf).
- Lee, Robert M. *The Active Cyber Defense Cycle.* Control Engineering.
  [Series](https://www.controleng.com/the-active-cyber-defense-cycle-a-strategy-to-ensure-oil-and-gas-infrastructure-cyber-security/).
- Hultquist, John. [Mandiant / Google TIG author page](https://cloud.google.com/blog/topics/threat-intelligence).
- Bianco, David. *The Pyramid of Pain.* 2013; SANS republication.
  [SANS](https://www.sans.org/tools/the-pyramid-of-pain).

### TLS and malware clustering

- Althouse, John. *TLS Fingerprinting with JA3 and JA3S.* Salesforce, 2017.
  [Medium](https://medium.com/salesforce-engineering/tls-fingerprinting-with-ja3-and-ja3s-247362855967).
- Althouse, John. *JA4+ Network Fingerprinting.* FoxIO, 2023.
  [Medium](https://medium.com/foxio/ja4-network-fingerprinting-9376fe9ca637) —
  [salesforce/ja3](https://github.com/salesforce/ja3).
- Mandiant. *Tracking Malware with Import Hashing (imphash).*
  [Article](https://cloud.google.com/blog/topics/threat-intelligence/tracking-malware-import-hashing/).
- VirusTotal. *Mandiant Permhash.*
  [Blog](https://blog.virustotal.com/2023/05/virustotal-mandiant-permhash-unearthing.html).
- Mandiant FLARE *capa.* [GitHub](https://github.com/mandiant/capa).

### Platforms

- [MISP](https://www.misp-project.org/), [OpenCTI](https://github.com/OpenCTI-Platform/opencti),
  [VirusTotal](https://www.virustotal.com/), [Censys](https://censys.io/),
  [urlscan.io](https://urlscan.io/), [DomainTools](https://www.domaintools.com/),
  [Microsoft Defender TI (formerly RiskIQ PassiveTotal)](https://www.microsoft.com/security/defender-threat-intelligence).

### Worked example and cross-references

- `detection_engineering_expertise.md` — runtime sibling; intel↔detection bridge.
- `vulnerability_research_methodology_expertise.md` — offensive cousin; intel pivots
  inform VR target selection.
- `steelman_doctrine_expertise.md` — ACH and Structured Analytic Techniques as
  steelman variants.
- `dns_network_infrastructure.md` — DNS pivot mechanics.
- `cicd_supply_chain_expertise.md` — supply-chain-attack intel substrate.
- `appsec_program_building_expertise.md` — program-level prioritization.
- `llm_agent_security_expertise.md`, `agentic_web_capabilities_expertise.md` —
  AI-agent-threat intel as variant analysis.
