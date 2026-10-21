# Automotive Cybersecurity — CAN, ECU, Telematics, and ADAS
## Staff-Level Technical Reference

---

## I. Researcher Profiles

Automotive cybersecurity as a public research discipline is roughly 16 years old. Before 2010 the field was a closed conversation between OEM safety engineers, Tier-1 supplier security teams (Bosch, Continental, Denso, Aptiv), and a small number of academic embedded-systems groups. Three things changed that: the 2010 Koscher/Savage UCSD-UW paper made automotive intrusion a peer-reviewed topic; Miller and Valasek's 2013-2015 work made it a press topic; and Sam Curry's 2023-2025 web-side disclosures made it an enterprise-security topic with named CVEs on individual OEMs. The names below span all three waves — academics, embedded-RE specialists, web-shaped researchers who turned car APIs into attack surface, and the AV / ADAS adversarial-ML lineage that emerged after 2017.

### Charlie Miller and Chris Valasek — Cruise / GM (formerly IOActive, Uber ATG)

**Career arc**: Miller — Ph.D., former NSA; first to publicly demonstrate remote exploits of the iPhone (2007) and MacBook Air (2008); long arc at Twitter and Uber ATG before Cruise. Valasek — IOActive, IBM X-Force, Uber ATG, Cruise. Both moved into AV security teams after concluding the realistic remediation path for the Jeep work was OEM-side architectural change, not bug-by-bug patching.

**Core contribution**: The 2013-2015 trilogy that anchored automotive security as a research discipline. (1) DARPA-funded 2013 wired work on a 2010 Toyota Prius and 2010 Ford Escape demonstrating CAN-injection control of steering, braking, instrument cluster, and seatbelts ("Adventures in Automotive Networks and Control Units," DEFCON 21). (2) 2014 "Survey of Remote Automotive Attack Surfaces" — the field's first comparative vendor-by-vendor remote-surface map. (3) 2015 Jeep Cherokee — fully remote compromise via Sprint cellular to the Uconnect head unit, pivoting to CAN through a Renesas V850 chip with rewritable firmware, seizing steering/braking/transmission/accelerator while Andy Greenberg of *Wired* drove. 1.4M-vehicle Chrysler recall — the first auto cybersecurity recall.

**Frame Miller and Valasek introduced**: Remote vehicle compromise is a *chain* problem (cellular → IVI → bus-gateway → CAN); each step is independently exploitable in 2015-vintage architectures. The defender's answer is *gateway segmentation* — every post-2015 OEM E/E-architecture rework explicitly cites this lesson.

### Karl Koscher — University of Washington Security and Privacy Research Lab

**Career arc**: Ph.D. under Tadayoshi Kohno at UW; research scientist at UW; Ph.D. student member of the Center for Automotive Embedded Systems Security (CAESS), whose co-PIs were Kohno and Stefan Savage (UCSD).

**Core contribution**: First author on "Experimental Security Analysis of a Modern Automobile" (IEEE S&P 2010, joint UW-UCSD), demonstrating CAN-side attacks on a pair of 2009 Chevy Impalas — disabling brakes individually, killing the engine at speed, falsifying instrument-cluster readings. The 2011 USENIX follow-up ("Comprehensive Experimental Analyses of Automotive Attack Surfaces") extended to remote surfaces: a buffer overflow in the CDMA telematics modem permitted cell-tower-side compromise; the hands-free Bluetooth system gave short-range reach; a malicious CD compromised the audio decoder. USENIX awarded a 2025 Test of Time Award.

**Frame Koscher introduced**: CAN-bus attacks are *consequence-realizable* on production vehicles; the realistic attacker does not need physical access — cellular, Bluetooth, Wi-Fi, USB, CD, RDS, and TPMS are all candidate first stages.

### Stefan Savage — UCSD

**Career arc**: Professor in Systems and Networking at UC San Diego; Irwin and Joan Jacobs Chair. NAE (2023); ACM Prize in Computing (2015); MacArthur Fellowship (2017). PI on the UCSD side of the CAESS collaboration. Cross-referenced in [[reference-credit-card-payments-security]] (spam-economy and click-fraud lineage).

**Core contribution**: Senior co-author on the 2010 Oakland and 2011 USENIX automotive papers. Savage's broader systems-level threat-model rigor (network worms, DDoS, spam, click fraud, BGP) gave the automotive work an adversary-economics frame the Tier-1 supplier community had not previously applied.

**Frame Savage introduced**: Automotive cybersecurity must be reasoned about from the *adversary's economics*, not the vendor's QA process. CAESS papers explicitly modeled which attacker classes (hobbyist, mechanic, repossession agent, thief, nation-state) would pursue which attack surfaces, and recommended defenses accordingly.

### Karsten Nohl — Security Research Labs (SRLabs)

**Career arc**: German cryptography and embedded-systems researcher; Managing Director and Chief Scientist of Berlin-based SRLabs since 2010. Ph.D. computer science, University of Virginia. Long arc of attacks against deployed crypto: GSM A5/1, MIFARE Classic Crypto-1, automotive immobilizers (DST40, Hitag2, Megamos), HiSilicon baseband, SIM OTA (Simjacker / WIBattack), railway signaling. Cross-referenced in [[reference-mobile-security]] (baseband, SIM-OTA).

**Core contribution**: SIGINT-2013 "Corroding Immobilizer Cryptography" — comparative cryptanalysis of the three transponder ciphers deployed across essentially every passenger vehicle: DST40 (TI; Ford, Toyota, Mitsubishi, Nissan historically), Hitag2 (NXP; ~34 makes), Megamos Crypto (EM Microelectronic; Audi, VW, Honda, Volvo, Fiat). All three proprietary, all three structurally weak relative to year-of-design, all three permitting practical key recovery.

**Frame Nohl introduced**: Automotive cryptographic primitives have a half-life of decades, but deployed cipher generations almost always lag the publication frontier by 20+ years. Defenders should expect newly-deployed automotive crypto to be one cryptanalysis cycle from broken.

### Flavio Garcia — University of Birmingham

**Career arc**: Professor of computer security at Birmingham (UK); previously at Radboud University Nijmegen where the Megamos / Hitag2 papers were authored with Roel Verdult.

**Core contribution**: Co-author (with first author Roel Verdult) on the most-cited automotive-cryptanalysis papers: "Dismantling Megamos Crypto" (USENIX Security 2013, embargoed; published 2015 after a UK High Court injunction at VW's request was settled); "Gone in 360 Seconds: Hijacking with Hitag2" (USENIX Security 2012); "Cryptanalysis of the Megamos Crypto Automotive Immobilizer" (*;login:* USENIX magazine December 2015). The Megamos work demonstrated practical recovery of the 96-bit secret key via three attacks (minutes with a partial key; hours full search exploiting cipher weaknesses).

**Frame Garcia introduced**: Litigating against vulnerability disclosure makes the disclosure more important, not less. The two-year embargo and eventual publication is now a canonical coordinated-disclosure case.

### Marc Rogers and Kevin Mahaffey — formerly CloudFlare and Lookout

**Career arc**: Rogers — Principal Security Researcher at CloudFlare (at the time of the 2015 work); previously Principal Security Researcher at Lookout. Mahaffey — co-founder and CTO of Lookout. The two collaborated on a multi-month audit of the Tesla Model S, presented at DEFCON 23 (August 2015).

**Core contribution**: "How to Hack a Tesla Model S" — the first public Tesla security audit. Six vulnerabilities reported, permitting (with physical access via the in-vehicle Ethernet port) operator-style commands: unlock, open trunk, darken speedometer, kill drivetrain at low speed. Tesla pushed an OTA fix to every Model S in the global fleet one day before the talk. The first time the public saw an OEM patch an entire fleet from a single signed update.

**Frame Rogers and Mahaffey introduced**: OTA update is the *primary structural defense* in modern automotive cybersecurity — if it works the vendor patches in days; if it doesn't every disclosure becomes a recall. Tesla's OTA pipeline became the reference architecture other OEMs have been chasing since.

### Sam Curry — independent researcher

**Career arc**: Web-side AppSec researcher with high-impact bug-bounty history against fintech and SSO surfaces. Pivoted into automotive web-shaped surfaces late 2022. Operates with a recurring collective (Brett Buerhaus, Maik Robert, Ian Carroll, Justin Rhinehart, Shubham Shah, Neiko Rivera) at samcurry.net. Cross-referenced in [[reference-credit-card-payments-security]].

**Core contribution**: "Web Hackers vs. The Auto Industry" (January 2023) — admin-panel and SSO-bypass vulnerabilities across 16+ OEMs (Ferrari, BMW, Rolls Royce, Porsche, Mercedes-Benz, Hyundai, Genesis, Toyota, Nissan, Infiniti, Honda, Acura, Kia, Ford, Jaguar, Land Rover, plus SiriusXM, Spireon, Reviver). Demonstrated remote start, lock/unlock, geolocation, trunk-open across nearly every connected-services SKU; BMW and Mercedes-Benz dealer SSO permitted internal-network reach to dealer portals, Slack, GitHub, hundreds of production apps. Follow-ups: Kia (2024); Subaru STARLINK (January 2025, with Shubham Shah — admin-panel password-reset without confirmation enabled location-tracking and remote-start on every U.S./Canada/Japan Subaru).

**Frame Curry introduced**: The OEM cloud is *the* automotive attack surface in 2023-2026 — not the ECU, the CAN bus, or the radio stack. VIN-as-auth-token, IDOR in admin panels, SSO trust between consumer apps and dealer infrastructure are the systemically-exploitable defects. Mature OEM-side mitigation looks like enterprise-AppSec, not embedded-systems hardening.

### Ralf-Philipp Weinmann — Comsecuris (founder)

**Career arc**: Long-running embedded-systems researcher; doctoral cryptology work at TU Darmstadt; postdoc at University of Luxembourg. Pre-automotive: "Baseband Attacks: Remote Exploitation of Memory Corruptions in Cellular Protocol Stacks" (USENIX WOOT 2012; Best Paper) — canonical demonstration of remote code execution against a cellular baseband. Cross-referenced in [[reference-mobile-security]] §11.

**Core contribution**: With Benedikt Schmotzle, built *T-BONE* for Pwn2Own 2020 (the automotive category was cancelled; reported via Tesla's bug bounty) — a Wi-Fi-side compromise of Tesla IVI's ConnMan service yielding local-network code execution without user interaction in 30-45 seconds. Demonstrated that Tesla's rich Linux IVI is exploitable by the same memory-corruption + sandbox-escape techniques that exploit desktop and mobile browsers.

**Frame Weinmann introduced**: The cellular baseband and the Wi-Fi/IVI stack are the *two* RF attack surfaces in a modern car, each carrying decades of C-code complexity. Phone-exploit techniques work against vehicles, and patch latency on vehicles is much worse.

### David Berard and Vincent Dehors — Synacktiv

**Career arc**: Researchers at Synacktiv, the French offensive-security firm. The most consistent professional research team in the Pwn2Own Automotive era (2023-2025).

**Core contribution**: Sustained Pwn2Own corpus against Tesla — (2023 Vancouver) TOCTOU bug against the Tesla Energy Gateway permitting arbitrary CAN bus messages; (2024 Automotive Tokyo) two-bug chain compromising Tesla IVI via the LTE card; (2024 Vancouver) integer overflow in the Vehicle Controller Secondary (VCSEC) module yielding control over Vehicle CAN; (2024 Hexacon) zero-click RCE on Tesla Model 3 through TPMS sensors.

**Frame Berard and Dehors established**: Even Tesla — with the strongest OTA hygiene and most-mature internal product-security team in the OEM market — still has exploitable C code at the boundary between trusted internal services and externally-reachable RF surfaces. Every Tesla generation in the last five years has had a chained-exploit path from a radio surface to CAN-bus messaging.

### Ken Munro — Pen Test Partners

**Career arc**: Founder and Partner at Pen Test Partners (UK), a long-running offensive-security consultancy with heavy IoT and embedded-systems specialty. ~200 disclosed vulnerabilities per year. Automotive-adjacent work since ~2015; EV-charging focus since ~2020.

**Core contribution**: Anchor of the EV-charger disclosure corpus. Pen Test Partners' 18-month, six-vendor audit (Project EV, Wallbox, EVBox, EO Hub, EO mini pro 2, Hypervolt, plus the ChargePoint public network) found API authorization-bypass enabling charger account takeover, a charging platform with no authorization at all, and chargers with no firmware signing permitting remote arbitrary-firmware push. Subsequent work extended to OCPP-protocol weaknesses, grid-impact analysis, and EV-as-grid-infrastructure risk modeling. The Pen Test Partners cadence is the most consistent public source of EV-charger CVEs.

**Frame Munro introduced**: EV charging infrastructure is a *grid-impact* attack surface, not just a customer-experience surface. The defensive priority extends beyond per-charger account takeover to the aggregate-load-manipulation case — synchronized on/off-toggling of large charger fleets to destabilize a feeder. Cross-link to [[reference-ics-ot-security]] §IV (Aurora Generator Test).

### Comma.ai / openpilot — George Hotz (founder, 2015-2022) and core team

**Career arc**: Hotz — first iPhone unlocker (2007); first PS3 root key (2010); founded comma.ai September 2015; released openpilot as open-source in November 2016; stepped down in November 2022 to work on tinygrad. comma.ai continues shipping openpilot on the comma 3 / comma 3X aftermarket hardware supporting over 325 vehicle models.

**Core contribution**: The first production-grade open-source ADAS. openpilot replaces OEM lane-keeping and adaptive-cruise control by interposing on the CAN bus at the radar or camera ECU. The combination of (1) open-source AV stack, (2) public CAN-message DBC files (github.com/commaai/opendbc), and (3) ~400M miles of fleet learning makes openpilot the single best-documented production-class ADAS in existence. Every academic and offensive-security researcher working on ADAS attacks uses it as a reference target because it's the only stack readable end-to-end.

**Frame Hotz and comma.ai introduced**: The OEM monopoly on understanding modern vehicle behavior is breakable. opendbc and openpilot turn each supported vehicle's CAN bus from a vendor-proprietary protocol into a public dataset; the field grows faster as a result.

### Roel Verdult — formerly Radboud University Nijmegen

**Career arc**: Long-time collaborator with Garcia on the Radboud-Birmingham automotive-immobilizer corpus.

**Core contribution**: Co-equal partner with Garcia on the Megamos / Hitag2 work — "Gone in 360 Seconds" (Hitag2, USENIX 2012), "Dismantling Megamos Crypto" (USENIX 2015), and the *;login:* cryptanalysis summary (December 2015). The Verdult-Garcia pairing established Radboud / Birmingham as the academic center of gravity for automotive cryptography 2010-2018.

**Frame Verdult contributed**: Attacks against RKE and immobilizer systems require attention to the *protocol shape* (replay tolerance, nonce structure) and *deployment economics* (key-refresh cadence) as much as to the cipher. The Verdult-Garcia attacks repeatedly exploited the protocol rather than the cipher when both were available.

---

## II. The Automotive Threat Model

### The "computer on wheels" reality

A 2024-vintage mid-range passenger vehicle: 100-150 ECUs; multiple in-vehicle buses (two-three CAN segments, LIN for body, possibly FlexRay, increasingly Automotive Ethernet for high-bandwidth); connectivity surface includes cellular (3G/4G/5G), Wi-Fi (2.4 / 5 / dual-band concurrent), Bluetooth Classic + BLE, NFC (Tesla, BMW keycards), AM/FM/HD/DAB with RDS, TPMS RF (315/433 MHz), GPS / GNSS, optional SiriusXM, increasingly V2X radios (DSRC 5.9 GHz or C-V2X PC5). Premium adds UWB for Phone-as-a-Key, 60 GHz mmWave for in-cabin sensing.

### Why automotive is uniquely hard

- **Safety-critical**. Brake-by-wire failure has direct kinetic outcome. Safety-critical software changes require regulatory certification (FMVSS, UN-ECE, GB-standards) and functional-safety re-verification under ISO 26262 / ASIL-D.
- **Multi-decade lifecycle**. A 2025 vehicle is on the road in 2045 running its shipping firmware in most cases. Tesla, Rivian, Lucid, and a few premium legacy OEMs have fleet-wide OTA for safety-critical ECUs. Cross-reference [[reference-ics-ot-security]] §II.
- **Supplier-tier complexity**. OEMs (Toyota, GM, Stellantis, VW, BMW, Mercedes, Ford, Hyundai-Kia, Nissan, Tesla, BYD) don't write most of their own software. Tier-1s (Bosch, Continental, Denso, Aptiv, Magna, ZF, Valeo, Hyundai Mobis) ship ECUs as black boxes; Tier-2s ship subsystems inside. OEM often lacks source code, keys, or build pipeline for components in its own vehicle. Tier-2 CVE propagation across Tier-1 SKUs and OEM model lines takes months.
- **Multi-jurisdictional regulation**. UNECE R155 / R156 mandatory in WP.29 countries (EU, UK, Japan, Korea) since 2024; ISO/SAE 21434 industry standard; NHTSA moving toward enforcement; China GB standards. Global programs satisfy the union.
- **Consumer market and brand exposure**. Automotive incidents have named consumer victims and a much larger reputational blast radius than ICS.

### Differences from ICS

The two domains are siblings but not twins:

| Axis | ICS / OT | Automotive |
|---|---|---|
| Mobility | Fixed in place | Mobile, owner-driven |
| Market | B2B, plant-owner-aware | B2C, retail |
| Lifecycle | 20-40 years | 10-25 years |
| OTA expectation | Almost none | Increasingly expected (Tesla-anchored) |
| Scale | Per-plant | Per-VIN, fleet-scale |
| Attack consequence | Process disruption, kinetic damage to plant | Kinetic damage to driver / occupants / pedestrians |
| Regulator | Sector-specific (NERC, EPA, TSA, etc.) | NHTSA + UNECE WP.29 |
| ISAC | E-ISAC, WaterISAC, etc. | Auto-ISAC + NMFTA for heavy-vehicle |

Cross-reference [[reference-ics-ot-security]] for the process-control analog; cross-reference [[reference-firmware-embedded-security]] for the embedded substrate that both domains share.

### The kinetic-effect axis

Automotive attack consequence runs on a spectrum from cyber-only to fully kinetic:

1. **Privacy / surveillance only**. Geolocation, microphone access, camera access. No effect on vehicle dynamics.
2. **Drain the battery / degrade the experience**. Persistent computation on the IVI, climate-control thrashing, fast-charging policy manipulation.
3. **Lock / unlock / start the engine**. The bulk of the Sam Curry corpus.
4. **Disable safety features at idle**. Open trunk while parked, disable alarm, lower windows.
5. **Manipulate non-dynamics features at speed**. Falsify speedometer, manipulate headlights, blast horn / music, fire seatbelt pretensioners.
6. **Manipulate vehicle dynamics at speed**. Steering, braking, accelerator, transmission. The 2015 Jeep Cherokee outcome. The serious consequence axis.
7. **Manipulate vehicle dynamics during autonomous operation**. ADAS perception attacks. Tencent Keen Lab's sticker-on-the-lane-line attack. Lateral / longitudinal control deception.
8. **Coordinated multi-vehicle action**. The fleet-level analog of (6). Requires backend compromise. Sam Curry's BMW dealer SSO chain could in principle reach this; no public demonstration of synchronized fleet-level dynamics manipulation exists yet.

Defensive priority correlates with the severity axis; insurance and regulatory priority do too.

### ISO/SAE 21434 + UNECE WP.29 R155/R156 regulatory baseline

ISO/SAE 21434 ("Road vehicles — Cybersecurity engineering," published August 2021) is the cybersecurity-engineering process standard for road vehicles. It defines cybersecurity activities across concept, product development, production, operations, maintenance, and decommissioning. The conceptual framing parallels ISO 26262 for functional safety: a Threat Analysis and Risk Assessment (TARA) feeds cybersecurity goals, which feed cybersecurity concept, which feeds component-level requirements.

UNECE Regulation 155 ("Uniform provisions concerning the approval of vehicles with regard to cyber security and cyber security management system") and Regulation 156 ("software update management system") are *type-approval prerequisites* in the WP.29 acceding countries (EU, UK, Japan, Korea, and others) since July 2022 for new vehicle types (July 2024 for all new vehicles). R155 requires the OEM to demonstrate a certified Cybersecurity Management System (CSMS); R156 requires a certified Software Update Management System (SUMS). The two regulations are operationalized via ISO/SAE 21434 (for R155) and ISO 24089 (Road vehicles — Software update engineering, for R156).

The combined regulatory effect is that, as of 2024, an OEM cannot sell a new vehicle type into the European market without a third-party-audited cybersecurity-engineering process and software-update governance. This is the strongest regulatory cybersecurity baseline in any consumer-product market in the world.

Cross-reference [[reference-ics-ot-security]] for the IEC 62443 ICS analog (similar process-standard model, sector-specific enforcement). Cross-reference [[reference-firmware-embedded-security]] for the embedded-substrate threat model that both ICS and automotive share.

---

## III. In-Vehicle Networks

### CAN bus (Bosch, 1986)

Published by Bosch 1986; ISO 11898 (1993). Broadcast, priority-arbitrated, differential two-wire bus. No IP-style addressing; every node sees every frame. 11-bit (standard) or 29-bit (extended) identifier doubles as priority (lower numerical wins arbitration). Typical rates: 500 kbit/s powertrain, 125 kbit/s body, up to 1 Mbit/s. Payload 0-8 bytes.

Security-relevant properties:

- **No authentication**. Any node can transmit any ID. The bus has no sender identity.
- **No encryption**. Payloads plaintext; passive listener captures everything.
- **No integrity beyond CRC**. The 15-bit CRC is for transmission error, not tampering.
- **DoS via priority arbitration**. A node transmitting frames with ID 0x000 wins every arbitration and starves the bus.
- **Bit-monitoring physical layer**. Each transmitter monitors the bus to confirm its bit appears as written; an attacker controlling a node can drive the bus dominant on selected bits during a target frame, forcing CRC failure and retransmission (used in "CAN bus off" exploitation).
- **Bus-off state**. Each node's transmit error counter; when it exceeds 255 the node enters bus-off and ceases transmitting until reset. An attacker forcing a target into bus-off has DoS'd that specific node.

CAN's security properties were designed for a 1986 "network inside a steel box" threat model that became invalid the moment cellular modems entered.

### CAN FD

CAN with Flexible Data-Rate (Bosch 2012; ISO 11898-1:2015). Backward-compatible physical layer; payload extended to 64 bytes; faster data-phase rates (2-5 Mbit/s data, 500 kbit/s-1 Mbit/s arbitration). No change to the security model. The wider payload makes MAC retrofitting practical — the load-bearing reason AUTOSAR SecOC adoption concentrates on CAN FD.

### LIN

Single-wire, master-slave, 20 kbit/s; ISO 17987. Body electronics — window switches, door modules, mirror motors, seat heaters. Unauthenticated and pivot-poor (no path to other buses). Matters for occupant-comfort attacks (annoyance, coercion) but not safety-critical compromise.

### FlexRay

Time-triggered, dual-channel, 10 Mbit/s; ISO 17458. Deployed on premium platforms (BMW X5 / 7-series, Audi A8) for x-by-wire applications. Static time-slot schedule makes injection harder than CAN; predominantly a physical-attack surface (workshop / Tier-1 access). Peaked 2010-2015; supplanted by Automotive Ethernet.

### MOST

Legacy infotainment ring-network over plastic optical fiber, 2000-2015 on European premium vehicles. Carries digital audio / navigation / phone audio. Largely retired; early Tencent Keen Lab Tesla work and BMW research traversed MOST-era buses on installed-base vehicles.

### Automotive Ethernet

The dominant in-vehicle backbone on new platforms. IEEE 802.3 over single twisted pair: 100BASE-T1, 1000BASE-T1, MultiGBASE-T1 (2.5/5/10 Gbit/s). Carries ADAS camera streams, infotainment, V2X aggregation. Zonal-architecture vehicles use Automotive Ethernet as backbone between zone gateways; CAN / LIN remain on spurs.

### SOME/IP and Ethernet AVB/TSN

**SOME/IP** — AUTOSAR's service-oriented middleware over IP. TCP / UDP plus SOME/IP-SD service-discovery multicast. No built-in authentication or encryption; expected to be wrapped in MACsec / IPsec / TLS, with deployment inconsistent across OEMs.

**AVB / TSN** — IEEE 802.1 bounded-latency Ethernet. AVTP carries streams; gPTP (IEEE 802.1AS) provides sub-microsecond time sync. Research has documented MITM on SOME/IP service discovery, AVTP replay, gPTP clock-desync. Hyundai HCRL's Automotive Ethernet Intrusion Dataset is the canonical public benchmark.

### Central-gateway and zonal-architecture topology

**Pre-2018 (domain-centric)**: ECUs clustered by function (powertrain CAN, body CAN, chassis CAN, infotainment) routed by a central gateway. Gateway compromise (the 2015 Jeep) routes arbitrary frames cross-segment.

**Zonal (post-2020)**: 4-6 geographic zones (front-left, front-right, rear-left, rear-right, cabin, trunk), each with a zone-gateway ECU connecting via Automotive Ethernet to a centralized compute resource. Tesla Model 3 was an early example (~3 km → 1.5 km harness; ~85% mass reduction). Most non-Tesla OEMs in zonal rollout on 2026+ platforms.

Security implications: zone-gateway compromise yields control over an entire physical region; centralized HPC running multiple hypervisor-isolated stacks is a higher-value target; bus-message authentication (MACsec, TLS-over-SOME/IP) becomes architecturally tractable in a way retrofitting CAN-with-MAC never was.

---

## IV. CAN Bus Protocol Attacks

### CAN injection

The canonical attack. An attacker who has physical or logical access to a CAN bus transmits frames with arbitrary IDs and payloads. Because the bus is unauthenticated and broadcast, the receiving ECUs cannot distinguish the attacker's frames from legitimate ones. The Koscher 2010 / Miller-Valasek 2013 work is the public-record reference; the 2023 wave of Toyota / Lexus thefts is the criminal-economy reference (see §IV "headlight CAN injection" below).

Attacker capability requires either (a) physical attachment — OBD-II port, headlight wiring, in-bumper diagnostic harness, in-cabin ports, sensor harnesses; or (b) compromise of an ECU on the bus, propagating from an externally-reachable surface (the Jeep cellular-to-CAN chain).

### CAN flood

Denial-of-service by saturating bus capacity. Sustained transmission of frames at the maximum priority (ID 0x000) wins every arbitration and starves all other traffic. CAN-flood is trivial for any node on the bus to execute and is detectable by intrusion-detection systems but not preventable at the protocol level. The defensive answer is bus-arbitration-aware IDS plus zone-gateway-side rate-limiting.

### Arbitration-loss exploitation

A weaker variant of CAN-flood: an attacker transmits a high-volume of low-ID frames, causing lower-priority legitimate traffic to repeatedly lose arbitration and miss its cycle deadline. For time-critical messages (e.g. the 10ms wheel-speed update from ABS to ESC), a sufficient arbitration-loss attack causes the receiver to enter a degraded state.

### Frame-priority manipulation

Closely related: an attacker claiming a low ID (high priority) that is conventionally reserved for the vehicle's most-critical messages dominates the bus. Some defensive implementations restrict ID ranges per-ECU (each ECU is "supposed" to transmit only certain IDs) but enforcement is rare in production.

### CAN bus-off attack

By forcing CRC errors on a target node's frames (the bit-monitoring physical layer permits this), an attacker can drive the target node's transmit error counter past 255, putting it in bus-off state and silencing it. The "Error Handling of In-Vehicle Networks Makes Them Vulnerable" academic paper (Cho and Shin, CCS 2016) is the canonical reference. Defensive mitigation requires either authenticated frames (so the attacker can't manufacture frames to corrupt) or out-of-band monitoring of each ECU's bus-off transitions.

### Diagnostic mode abuse — UDS (ISO 14229)

The Unified Diagnostic Services protocol is layered on top of CAN (via ISO-TP / ISO 15765 transport) and provides standardized commands for diagnostic and reprogramming operations on any ECU. UDS operations include: read DTCs (Diagnostic Trouble Codes), clear DTCs, read/write data identifiers, request firmware download/upload, request ECU reset, *enter a non-default diagnostic session*, *authenticate via the SecurityAccess service (0x27)*.

The SecurityAccess service is the load-bearing authentication primitive in UDS. The protocol is challenge-response: the client requests a seed (service $27, sub-function "odd"); the ECU returns a seed (typically 2-8 bytes); the client computes a key (via a proprietary algorithm known to the ECU and to the OEM's diagnostic tool); the client sends the key (service $27, sub-function "even"); the ECU validates and either grants or refuses the requested security level.

**Real-world weakness pattern**: The proprietary key-generation algorithm is often weak. Documented failure modes:

- The algorithm is a trivial function of the seed (rotate, XOR, lookup table). Reverse-engineered from the OEM diagnostic tool in days.
- The seed is generated without entropy — observed cases include time-of-day, an incrementing counter, or a constant. The "Formal Security Analysis of Vehicle Diagnostic Protocols" academic literature documents key recovery from observed seed patterns.
- Brute-force mitigations are bypassable via ECU reset (UDS service $11 ECUReset). Many implementations reset the brute-force counter on reset and may even reuse the same seed after reset.
- The algorithm is identical across many ECU SKUs from the same Tier-1, so reversing one diagnostic tool unlocks many vehicles.

UDS SecurityAccess weakness is the typical entry point for ECU firmware extraction and ladder-equivalent code modification in offensive automotive research. The 2014-2016 NXP-Vector papers and the more recent dissecto / I CAN Hack blog work document the attack pattern in detail.

### Routing manipulation via gateway misconfiguration

A central gateway ECU enforces inter-segment message filtering: only certain IDs may cross from infotainment-segment to powertrain-segment, and only certain UDS commands may pass through. Gateway misconfiguration — whether by attacker compromise of the gateway's configuration data or by an OEM forgetting to lock down a particular ID — opens cross-segment attack paths. The 2015 Jeep was a routing-manipulation outcome: the Uconnect head unit had a path to write CAN frames to the powertrain bus that should not have existed.

### The "CAN injection" car-theft wave (2023+)

A criminal-economy attack pattern that emerged ~2022 and became widely documented in 2023, primarily targeting Toyota / Lexus. The technique:

1. Thieves pry off the front bumper or trim to expose the headlight wiring harness.
2. The headlight ECU sits on the vehicle's CAN bus (modern headlights are smart enough to need their own ECU).
3. A purpose-built device — sold on dark-web sites for ~€5,000 in 2023, disguised as a JBL Bluetooth speaker — is wired into the headlight CAN harness.
4. The device transmits CAN frames that impersonate the legitimate key-fob authentication exchange, unlocking the vehicle and starting the engine.

The attack exploits the fact that the in-bumper CAN bus segment, after the headlight ECU, is effectively the same broadcast domain as the immobilizer / body-control segment in many architectures, and that the key-fob authentication exchange on CAN is unauthenticated past the initial RKE step. Defensive responses by Toyota and Lexus include retrofit aftermarket immobilizers and OEM software updates that add additional authentication on the bus; some markets have responded with insurer demands for steering-wheel locks. The 2023 CAN-injection theft wave is structurally a *physical-layer* defeat of the bus authentication assumption.

Separately, the *Kia Challenge* (2022-2023, peak winter 2022-spring 2023) is a different class entirely: 8.3 million Kia and Hyundai vehicles manufactured 2011-2021 without industry-standard engine immobilizers were stealable by removing the steering-column shroud and inserting a USB-A connector into the ignition slot. Theft rates spiked over 800% in Cook County, Illinois; NHTSA linked the trend to at least 14 crashes and eight deaths; Kia and Hyundai pushed software updates beginning February 2023. The Kia Challenge is not a CAN-bus attack — it is the *absence* of a basic anti-theft control. Mentioned here because the lesson is the same in both cases: physical-layer assumptions about the inaccessibility of the bus or the ignition switch were wrong.

### The Tesla Toolbox / dealer-tool corpus

A long-running subgenre of automotive research targets the *vendor diagnostic and service tools* themselves — Tesla Toolbox, Snap-on Verus Edge, Bosch KTS, JCB / Volvo diagnostic dongles — as a route to OEM-private cryptographic keys, undocumented diagnostic commands, and bypass routines used by dealer-level technicians. These tools embed the OEM's "real" authentication credentials; reverse-engineering them is a credential-extraction problem. Multiple research groups (Tencent Keen Lab, Synacktiv, several individual Tesla researchers) have publicly demonstrated Toolbox-shaped capability.

---

## V. ECU Exploitation

### The 100-150-ECU reality

A modern mid-range vehicle has ~100 ECUs; premium platforms 150+. Major classes:

- **ECM / TCM** — engine and transmission control; safety-critical (loss-of-power failure mode).
- **ABS / ESC** — wheel-speed input, brake-pressure modulation; safety-critical.
- **BCM** — lights, wipers, windows, door locks, alarm, immobilizer.
- **TCU** — cellular modem and CPU; remote services, OTA, eCall (EU mandatory since 2018), location.
- **IVI / Head Unit** — infotainment touchscreen; navigation, audio, phone integration.
- **Cluster (IPC)** — driver-facing instrumentation.
- **Central Gateway** (or zone gateways in zonal architectures).
- **ADAS controllers** — cameras, radars, optional LiDAR, fusion/decision ECU running perception + planning + control.
- **EV-specific**: BMS (cell balancing, thermal, state-of-charge; ASIL-C/D), inverter / MCU (traction motor torque), DC-DC, OBC.
- **VCSEC** (Tesla-specific) — Bluetooth + TPMS-aware; Phone-as-a-Key auth and startup. Pwn2Own 2024 target.
- **Steering / brake / suspension actuator ECUs** — by-wire where present.
- **ACU** — airbag control; safety-critical, tamper-evident.
- **HVAC, seat / mirror / door modules** (typically LIN-side).

### ECU firmware acquisition

1. **Dealer / repair-shop software** (Toyota Techstream, GM SPS, Ford IDS, Tesla Toolbox) often contains firmware images. Dealer tools are themselves research targets.
2. **Leaked OTA update files** from vehicle update channels, OEM CDNs, or dealer networks.
3. **JTAG / SWD / chip-off**. Debug-disable fuses on Infineon TriCore / Aurix, Renesas RH850 / V850, NXP MPC57xx, ST SPC57x, TI TMS570 are typically programmed in production. Chip-off + fault-injection (voltage glitching, EM-FI, optical FI) to bypass debug-disable, or direct flash read. Cross-reference [[reference-firmware-embedded-security]] §III.
4. **Debugger backdoor via UDS**. Tier-1 firmware sometimes ships with vendor-internal debug unlocked via a higher SecurityAccess level; reversing yields memory-read.
5. **Side-channel extraction** — cold-boot attacks and power-analysis-driven recovery.

### ECU programming environments

AUTOSAR is the dominant standard, in two variants:

- **AUTOSAR Classic** — hard real-time, deeply embedded. Statically-configured tasks, OSEK-derived OS, no dynamic memory. Powertrain and safety-critical ECUs run Classic.
- **AUTOSAR Adaptive** — higher-performance, dynamic process management, SOME/IP, POSIX. ADAS fusion controllers, central HPCs, IVI in zonal architectures.

Classic security stack: CryIf (cryptographic interface), Csm (Crypto Service Manager), SecOC (Secure Onboard Communication, §XIII), KeyM (Key Manager). Adaptive adds Identity and Access Management plus TLS-based service auth.

### Common ECU bug classes

- **Hardcoded credentials in firmware**. The UDS SecurityAccess seed-key algorithm and any cryptographic keys baked into firmware (RKE keys, immobilizer keys, OTA-update signing public keys). Recovery via firmware reverse engineering is routine.
- **Plaintext UDS over CAN**. The default UDS-over-CAN flow has no message-level encryption; SecurityAccess is the only authentication primitive. Anyone on the bus who can talk to the ECU during a diagnostic session can read or write firmware if SecurityAccess is bypassed.
- **Weak SecOC keys**. AUTOSAR SecOC depends on the OEM-managed symmetric keys provisioned into each ECU. Weak provisioning (default keys, reuse across SKUs, leaked keys) breaks the model. The "Extracting Secure Onboard Communication (SecOC) keys from a 2021 Toyota RAV4 Prime" disclosure (I CAN Hack blog, 2024) is a public reference for how a real OEM SecOC deployment was broken via firmware extraction.
- **Memory corruption in C-based protocol parsers**. CAN ISO-TP, UDS service handlers, SOME/IP service skeletons, MQTT clients for telematics, Bluetooth profile parsers — all written in C (or C++) for performance and supplier-toolchain compatibility, all subject to the usual buffer-overflow / use-after-free / type-confusion bug classes. Cross-reference [[reference-firmware-embedded-security]] §III.
- **Authentication bypass via protocol downgrade**. Some ECUs accept a fallback "factory mode" or "legacy mode" command that bypasses the standard SecurityAccess flow. Recovery via firmware analysis.
- **Insufficient firmware-update signature verification**. Update packages should be signed by an OEM key; the ECU should verify before flashing. Multiple disclosed cases of missing-or-broken signature verification, including the Pen Test Partners EV-charger work, indicate the failure mode persists across the automotive and EV-adjacent supply chain.

### Vendor-specific corpus

**Tesla**: Pwn2Own corpus (Synacktiv, Berard, Dehors, others) — IVI (Linux + Chromium), Gateway (TOCTOU 2023), VCSEC (integer overflow 2024), TPMS (zero-click RCE). Autopilot HW3 / HW4 are custom Tesla SoCs running stripped Linux. Service Mode and Toolbox are recurring targets.

**Toyota / Lexus**: 2023 CAN-injection headlight wave. 2021 RAV4 Prime SecOC key extraction (I CAN Hack blog) demonstrated that OEM-managed SecOC keys are recoverable from ECU. Connected Services / TCU researched by Synacktiv and VicOne.

**General Motors**: 2010 Koscher / Savage paper (unnamed Chevy Impala). OnStar telematics weaknesses, Bluetooth pairing attacks on Chevy / Buick infotainment.

**Stellantis (Chrysler, Jeep, Dodge, Fiat, RAM)**: Uconnect was Miller / Valasek's target. Multiple Uconnect security-architecture revisions since 2015.

**Hyundai / Kia**: Kia Challenge (absent immobilizer, not a software exploit). Curry 2022 disclosed remote-vehicle-control via Hyundai owner-portal API; 2024 follow-up reached Kia vehicles via the Kia dealer portal.

**BMW / Mercedes-Benz**: Curry's Web Hackers paper covered both. The 2018 Tencent Keen Lab BMW cluster (14 vulnerabilities, 7 CVEs, web-to-ECU) is the most comprehensive single BMW disclosure.

**VW Group**: Megamos Crypto litigation centered here. Subsequent immobilizer-weakness, infotainment-exploit, and connected-services disclosures across 2020+ model years.

**Tier-1 supplier corpus**: Bosch (ESP and others), Continental (TCU, ADAS), Aptiv (harnesses, gateways), Denso (Toyota), Marelli (Stellantis). Tier-1 vulnerabilities propagate across multiple OEM platforms; advisories are high-impact because of fleet propagation.

### Firmware reverse-engineering workflow

Cross-reference [[reference-firmware-embedded-security]]. Automotive-specific adjustments:

1. **Identify the CPU**. Powertrain / chassis commonly Infineon TriCore / Aurix (multi-core VLIW; Ghidra / Binary Ninja support improving). ABS / brake on TI TMS570 or NXP MPC57xx. ADAS increasingly ARM Cortex-A or Nvidia Drive AGX-class.
2. **Identify the RTOS**. Powertrain on AUTOSAR Classic + OSEK; vendor-internal RTOS variants from Continental, Denso; ADAS / IVI on Yocto-Linux variants or QNX on older premium platforms.
3. **Locate the CAN / UDS / SOME/IP message handlers**. The fastest entry point — CAN-frame state machine and UDS dispatcher identifiable from well-known constants (UDS service IDs, ISO-TP frame types).
4. **Locate the SecurityAccess seed-key algorithm** near the UDS dispatcher — typically a small function reading a vendor-specific DID and running a proprietary computation. Reversing this is the load-bearing step for further access.
5. **Locate the SecOC verification** inline in the message-receive path. Identifiable by the cryptographic primitive calls when SecOC is enabled.

Bench tooling: PCAN-USB / Vector CANcase / Kvaser / openCAN dongles for CAN; J2534 pass-thru adapters for UDS-over-CAN; ESI-tronic or dealer software for protocol traces; openpilot's panda for low-cost CAN bridging.

---

## VI. Wireless Attack Surface

### Cellular modem (TCU)

The primary remote-attack vector in production vehicles. 2G / 3G historically, currently LTE Cat-4 / Cat-6, increasingly 5G NR. Baseband chips from Qualcomm, MediaTek, HiSilicon historically, Samsung Exynos. Baseband runs an autonomous RTOS and exposes a serial / PCIe interface to an application processor running the customer-facing TCU software.

Two attack surfaces:

- **The baseband** — decades of C-code complexity in the cellular stack. Weinmann's "Baseband Attacks" line establishes GSM / UMTS / LTE / NR basebands as independently exploitable from a malicious base station (Stingray, attacker private 4G/5G core, co-opted commercial base station). Cross-reference [[reference-mobile-security]] §11. Auto-specific concern: baseband compromise typically yields control over the application processor on the same in-vehicle network.
- **The TCU application processor** — Linux or QNX, exposing services to the OEM cloud (HTTPS + mTLS in modern designs; plaintext + shared secret in older ones). The 2015 Jeep was a TCU AP compromise: Uconnect's D-Bus reachable from Sprint cellular on TCP 6667 with no authentication, permitting arbitrary code execution.

**SMS command channels**: Some older OEMs used SMS for emergency reset / remote unlock / stolen-vehicle-disable. Spoofable SMSC, guessable modem MSISDNs (sometimes derivable from VIN in early-generation telematics).

### Bluetooth Classic and BLE

Multiple surfaces per vehicle: HFP, A2DP, PBAP, MAP, BLE Phone-as-a-Key, BLE TPMS on some platforms, BLE diagnostic dongles.

- **KNOB (CVE-2019-9506)** — Antonioli, Tippenhauer, Rasmussen, USENIX Security 2019. Bluetooth Classic key-negotiation permits forcing key entropy to 1 byte, brute-forceable in real time. BLE-KNOB is structurally analogous. Patch propagation into the automotive deployed base remains slow.
- **BLE relay on Phone-as-a-Key** — NCC Group May 2022 against Tesla Model 3 / Model Y BLE Passive Entry. Link-layer relay with 8 ms RTT, well within typical 30 ms connection intervals, invisible to both endpoints. Two-attacker team unlocks and drives. Tesla mitigation: PIN-to-Drive (user-side); UWB ranging (architectural fix; Apple Car Keys with UWB on iPhone 11+).
- **NFC relay on Tesla Keycard** — IOActive 2022. NFC auth relayed via Bluetooth or Wi-Fi to co-attacker near vehicle.
- **HFP / A2DP / PBAP parser bugs** — crafted-pairing-flow exploits. 2017 BlueBorne (Armis) included profile-parser CVEs affecting automotive Bluetooth stacks.

### Wi-Fi

In-cabin hotspot, service / diagnostic Wi-Fi, CarPlay / Android Auto wireless (Wi-Fi-Direct after Bluetooth bootstrap), vehicle-as-Wi-Fi-client to phone hotspot, OTA-update Wi-Fi (Tesla's home-network path). Weinmann / Schmotzle *T-BONE* targeted Tesla ConnMan: malicious AP triggered IVI memory corruption on association, yielding user-space code execution. Canonical "evil twin → IVI compromise" demonstration.

### Key fobs — RKE and immobilizer

**Rolling-code RKE** at 315 / 433 MHz. Rolling counter defends against replay. Broken ciphers:

- **Hitag2** (NXP) — Garcia / Verdult 2012. ~360s active recovery, longer passive.
- **Megamos Crypto** (EM Microelectronic) — Verdult / Garcia / Ege 2012-2013, published 2015 after VW litigation. 96-bit key recoverable via cipher weaknesses.
- **DST40** (TI) — Bono et al., USENIX Security 2005. Practical key recovery.

Modern fobs are mostly AES-128 with proper KDF. Cryptanalysis pressure has shifted to protocol weaknesses (replay-window edge cases, predictable nonces) and physical relay.

**Relay attacks** — the canonical car-theft method. Two attackers (one near the fob in the home, one near the vehicle) relay the RF signal. Vehicle perceives the fob as adjacent and unlocks/starts. Mitigations: UWB ranging (time-of-flight detects relay); in-fob motion-required-for-unlock; PIN-to-drive.

### NFC — Phone-as-a-Key

Apple Car Keys (iOS 13.6+; UWB on iPhone 11+), Android Digital Car Keys (Android 12+), BMW Digital Key, Hyundai Digital Key. NFC tap-to-auth with vehicle-provisioned PKI credentials; BLE / UWB for proximity ranging. Attacks: NFC-side relay (IOActive Tesla Model Y), protocol layering between NFC / BLE / vehicle auth state.

### V2X

- **DSRC** (IEEE 802.11p / WAVE, 5.9 GHz) — FCC reallocated most of 5.9 GHz away from DSRC in 2020.
- **C-V2X** (3GPP PC5 sidelink, optional Uu uplink) — dominant in China; growing in EU and post-DSRC US.

Messages: BSM (10 Hz position / heading / speed / brake-status), SPaT (traffic-light timing from roadside units), MAP (intersection geometry). Auth via IEEE 1609.2 / ETSI ITS-G5 — complex PKI with pseudonym rotation for privacy. Attack surface: BSM injection (phantom braking), Sybil (one attacker, many vehicles), privacy attacks on pseudonym correlation, IEEE 1609.2 PKI complexity. Public research corpus thin pending scale deployment.

### GPS spoofing

SDR + GPS-signal generator (open-source gps-sdr-sim, HackRF) transmits forged signals strong enough to override real satellites. Effect on map-aligned ADAS (Tesla nav-on-Autopilot, GM Supercruise lane segments): incorrect lane choice, false off-ramp engagement. Tencent Keen Lab demonstrated as one of several ADAS-deception primitives. Mitigations: multi-constellation receivers (GPS + Galileo + GLONASS + BeiDou), RAIM, military-grade spoof detection.

Cross-reference [[reference-mobile-security]] (baseband, Bluetooth) and [[reference-cryptography-expertise]] (immobilizer cryptanalysis).

---

## VII. Telematics and Cloud Backends

### The OEM cloud as central attack vector

The 2023-2025 disclosure record establishes the OEM cloud — AWS / Azure / GCP / OEM-on-prem running connected-services APIs, dealer portals, fleet consoles, OTA distribution — as the dominant production attack surface. Curry's "Web Hackers vs. The Auto Industry" (January 2023, ~16 OEMs) plus follow-ups (Kia 2024, Subaru STARLINK 2025) are the load-bearing case studies. Mainstream web-app failures applied to vehicle-control APIs:

- **VIN-as-auth-token** — multiple OEMs treated VIN as sufficient ownership identifier. VINs are visible (windshield, registration, dealer listings) and frequently guessable.
- **Broken access control in admin panels** — Subaru STARLINK 2025: password reset of any employee account without confirmation token; admin panel could remotely start, stop, lock, unlock, locate any U.S. / Canada / Japan Subaru; adding authorized users generated no owner notification.
- **SSO trust between consumer-app and dealer-portal** — Curry BMW / Mercedes: consumer connected-services tokens reached dealer portals, Slack, GitHub, hundreds of internal apps after IDOR / SSO confusion.
- **Mass-assignment / IDOR on vehicle-bound endpoints** — `POST /vehicle/{vin}/command/unlock` accepting VINs not owned by the authenticated user.
- **PII exposure via geolocation-history APIs** — Subaru STARLINK: 1-year per-vehicle location history at 5m accuracy, accessible to any admin-panel auth.

### Fleet-management attack surface

Commercial telematics — Geotab, Samsara, Lytx, Verizon Connect, Trimble — operates consoles on fleets of 100s to 10,000s. Tenant compromise yields aggregate visibility (location, driver behavior, fuel) and sometimes vehicle-control (remote disable, geo-fence behavior). Standard enterprise-SaaS vulnerabilities at fleet scale. Pen Test Partners is a recurring disclosure source.

### OTA update mechanisms

Compromised OTA pipeline reaches every fleet vehicle through the legitimate channel. Cross-reference [[reference-cicd-supply-chain]] and [[reference-supply-chain-provenance]].

Tesla's OTA is the public reference: signed firmware per-ECU; encrypted packages from Tesla cloud over Wi-Fi (or LTE for small updates); signature verification; staged install across ECUs with rollback paths; driver authorization to activate. Structural defenses parallel supply-chain provenance: signed packages with OEM-controlled keys, reproducible builds, rollback, end-to-end per-ECU attestation. UNECE R156 makes this regulatory baseline.

Anti-pattern (unauthenticated OTA): documented in some EV chargers (Pen Test Partners) and non-Tesla TCUs. The vehicle-TCU equivalent is the worst-case automotive supply-chain compromise.

### Heavy-vehicle telematics

Commercial trucks use SAE J1939 (CAN variant). Telematics platforms parallel light vehicles — Daimler Truck Detroit Connect, Volvo Trucks Volvo Connect, Paccar PacLease / SmartLINQ, Navistar. NMFTA Heavy Vehicle Cyber Security is the sector forum; CISA flags as critical infrastructure. Structural concern: one compromised fleet-tenant could disable thousands of trucks (port-shutdown-class consequence).

---

## VIII. Infotainment (IVI) Exploitation

### IVI architecture

Modern IVIs run general-purpose Linux variants:

- **Yocto / OpenEmbedded Linux** — most OEMs (Toyota, Honda, GM, Ford, Stellantis, Mercedes, VW Group).
- **Android Automotive OS (AAOS)** — Google's automotive Android (Polestar, Volvo, GM Google built-in, Honda, Ford post-2023, Renault). Distinct from Android Auto (phone-projection protocol, not an OS).
- **QNX (BlackBerry)** — historically dominant on BMW, Audi, premium platforms. Losing share to AAOS on new programs.

Hardware: ARM Cortex-A SoCs — Qualcomm Snapdragon Auto (8155, 8295), Nvidia Tegra (older), Renesas R-Car, NXP i.MX, Samsung Exynos Auto, TI Jacinto. Multi-GB DRAM, eMMC / UFS flash, dedicated GPU.

Attack surface inherits from desktop / mobile Linux plus OEM customizations: Linux kernel (often old LTS with backported patches), Chromium-based browser, FFmpeg-derived media codecs (Stagefright-class), BlueZ / vendor Bluetooth stacks, wpa_supplicant, OEM HMI layer.

### Browser-shaped surface — Chromium IVI

Cross-reference [[reference-browser-js-engine-exploitation]]. The IVI browser is structurally desktop Chromium on automotive ARM — V8 type confusion, JIT side, kernel sandbox escape all transfer. Tencent Keen Lab Tesla 2016 / 2017 used browser chains to IVI then pivoted to CAN through a privileged service. Defense: sandboxed renderer, no direct path to vehicle bus from renderer IPC.

### CarPlay, Android Auto, AppLink

Phone-projection protocols turning the IVI into a display for an external phone. **CarPlay** (USB or Wi-Fi-Direct after Bluetooth bootstrap), **Android Auto** (Google's equivalent; AAOS is *not* Android Auto — AAOS replaces the IVI OS, Android Auto projects from a phone), **SmartDeviceLink (SDL)** (Ford open-source). Public exploit corpus thinner than the underlying Linux stack but the protocol parsers are independently attackable.

### DLNA, UPnP, legacy media servers

Older IVIs included DLNA-server functionality — C-based, broadly exposed, multiple vulnerability disclosures. Modern IVIs have retired DLNA in favor of CarPlay / Android Auto.

### Voice assistant as injection surface

Mercedes MBUX, BMW iDrive, GM with Alexa Auto / Google built-in, Tesla voice command. Cross-reference [[reference-llm-agent-security]]:

- **Adversarial speech** — synthesized audio perceived by humans as one phrase, transcribed by ASR as a different attacker-chosen phrase. Delivered via roadside speaker, in-car radio, podcast through CarPlay.
- **Prompt-injection into LLM-backed assistants** — Mercedes MBUX with ChatGPT, similar at other OEMs. Standard prompt-injection threat model with the added severity of vehicle-control-API access ("send my location," "lock doors," "set max speed").

### Tesla and premium-IVI research

Tesla is the most-targeted IVI platform because it offers the highest Pwn2Own bounties and the IVI runs rich Linux + Chromium. Public corpus: Tencent Keen Lab 2016 / 2017 / 2018 chains (browser → IVI RCE → CAN); Synacktiv Pwn2Own Automotive 2024 (LTE-card → IVI). The 2018 Tencent Keen Lab BMW disclosure cluster (14 vulnerabilities, 7 CVEs, across TCU, head unit, central gateway) is the most comprehensive non-Tesla single disclosure.

---

## IX. ADAS and Autonomous-Driving Attack Surface

### Camera-input adversarial perturbations

Adversarial perturbations in the camera's field — stickers, paint, projected images, modified road markings — can cause perception to misclassify objects or misperceive lane geometry.

- **Tencent Keen Lab Tesla Autopilot 2019** — small stickers on lane markings; Autopilot tracked the stickered "lane" and steered into the opposing lane in a controlled test. Also demonstrated wireless-gamepad steering control of Model S 2018.6.1 after Autopilot compromise. Tesla patched.
- **Eykholt et al., CVPR 2018** — adversarial stickers on stop signs made a CNN classify as "45 MPH speed limit." Generic classifier target; pattern transfers.
- **Lane-line vectors** — lane-following deception, false-lane induction, lane-confidence manipulation.

Cross-reference [[reference-adversarial-ml-model-security]].

### LiDAR spoofing

Synchronized laser sources inject spoofed returns. Cao et al., CCS 2019 ("Adversarial Sensor Attack on LiDAR-based Perception in Autonomous Driving") induced phantom obstacles in Baidu Apollo. A phantom vehicle 20m ahead triggers hard braking — DoS or accident-induction primitive. Defenses: sensor fusion (camera + radar should disagree on phantoms), pulse-timing randomization, multi-wavelength receivers.

### Radar jamming and spoofing

Automotive radar at 24 / 77 / 79 GHz. Jamming kills detections; spoofing injects phantoms. Academic literature only; no large-scale criminal / state deployment documented.

### GPS spoofing as ADAS deception

(See §VI.) Map-aware ADAS (Tesla nav-on-Autopilot, GM Supercruise) depends on GPS-aligned localization. Spoofing causes lane-choice errors, false off-ramp engagement, wrong-way maneuvers.

### V2X message authenticity attacks

BSM injection — falsified phantom-vehicle braking messages. Receiving vehicle engages emergency braking / steering avoidance. IEEE 1609.2 PKI is the defense; credential compromise is the attacker's path.

### The "fooled by a sticker" frame

Popular but undersells modern mitigation: Tesla / Mobileye / Waymo do not bet safety on a single ML classifier — they use sensor fusion (radar + camera + sometimes LiDAR), behavioral models, and ASIL-D safety controllers that can override ML decisions. Sticker-class attacks test fusion quality, not stack failure.

### ML attacks on perception

Cross-reference [[reference-adversarial-ml-model-security]]. ADAS-specific: training data does not exhaustively cover adversarial inputs. Defenses: adversarial training, certified-robustness primitives, sensor-fusion redundancy, explicit safety envelopes.

### AV stack landscape

- **Tesla Autopilot / FSD** — proprietary HW3 / HW4; camera-only (radar removed 2021, ultrasonics 2022); FSD Beta supervised on-road since 2020.
- **Mobileye EyeQ** — most-deployed ADAS perception globally; Mobileye Drive (L4) in robotaxi rollout.
- **Waymo Driver** — L4, LiDAR-heavy; commercial robotaxi in Phoenix, SF, LA, Austin, Atlanta, Miami (2024-2026 expansion).
- **Cruise** — GM L4; suspended after October 2023 San Francisco pedestrian incident; GM ended Cruise robotaxi development in December 2024.
- **Zoox** — Amazon-owned; purpose-built carriage-style robotaxi; multi-city testing.
- **Mercedes Drive Pilot** — first SAE Level 3 certified for U.S. retail; hands-off / eyes-off on specific Nevada and California highways.
- **comma.ai openpilot** — open-source L2; 325+ vehicles supported.

### openpilot as research target

openpilot's openness — codebase, opendbc, model architectures, training pipeline all public — makes it the only production-grade ADAS readable end-to-end without an NDA. Academic ADAS-security papers disproportionately target openpilot. The comma.ai responsible-disclosure culture is welcoming.

---

## X. EV-Specific Attack Surface

### Charging infrastructure — OCPP

Open Charge Point Protocol — the dominant management-plane protocol for EV charging. Open Charge Alliance. Versions: 1.5 (2012, legacy); 1.6 (2015, dominant deployment, SOAP or JSON, per-CP shared-secret auth, TLS-optional); 2.0.1 (2020, TLS mandatory, certificate-based auth, structured signed firmware-update, ISO 15118 PnC integration).

OCPP 1.6 attack patterns:

- **Charger impersonation** to CSMS via weak authentication.
- **DoS via duplicate WebSocket sessions** dropping legitimate charging.
- **Firmware push without signature verification** — multiple chargers accepted attacker firmware.
- **Identifier hijacking** (Saiflow 2023) — DoS via identifier-replay.

Pen Test Partners' six-vendor audit (Project EV, Wallbox, EVBox, EO Hub, EO mini pro 2, Hypervolt) plus ChargePoint network found API-authorization failures across the board.

### Plug-and-Charge (ISO 15118)

ISO 15118 — EV ↔ EVSE communication over PLC on the charging cable. Plug-and-Charge: certificate-exchange-based session auth and payment authorization (no card swipe, no app login). V2G PKI is hierarchical — V2G Root CA → OEM Sub-CAs, Mobility Operator (MO), Provisioning Service Operator (PSO), Charge Point Operator (CPO) Sub-CAs. Certificates rotate; mutual TLS between EV and EVSE mandatory. Editions: ISO 15118-2 (2014), ISO 15118-20 (2022, bidirectional V2G). Pwn2Own Automotive 2025 included PLC attacks: Synacktiv's signal-manipulation against ChargePoint Home Flex via the connector earned $57,500.

### Charging-station compromise as fleet-impact vector

A compromised CSMS managing thousands of chargers yields aggregate-load-toggling. Synchronous toggling on a specific feeder causes voltage anomalies, breaker trips, sub-transmission instability — the cyber-physical-grid risk Pen Test Partners emphasizes. Cross-reference [[reference-ics-ot-security]] §IV (Aurora-class consequences).

### Battery Management System (BMS)

Cell balancing, SoC estimation, thermal management, pack safety — disconnect cells, limit current, trigger coolant flow. A compromised BMS can drive the pack outside its safe envelope (overcharging, thermal runaway). ASIL-C / ASIL-D firmware; tight update gating; public disclosures sparse but threat model well-understood internally.

### Inverter / motor controller

Converts DC battery to AC for traction motor; controls torque, regen, thermal. Compromise yields direct torque control — kinetic-effect at the powertrain layer. Less-documented publicly than BMS; inverter firmware closely held by Tier-1s (Bosch, Denso, Hitachi); attack surface narrow (CAN-only to vehicle).

### Tesla Supercharger and Wall Connector

Tesla connector originally proprietary; now CCS in non-NA markets, NACS in NA. Attack surface: V2G PLC stack (when CCS-equipped), Tesla-cloud auth / billing / rate-management, physical charger hardware. Tesla Wall Connector exploits at Pwn2Own Automotive 2025 paid $129,500 on day two.

### Smart grid + EV charging cyber-physical risk

As EV penetration crosses 10-20% of regional fleets, charger-fleet behavior becomes a meaningful share of local distribution load. Coordinated synchronized cycling or aggregator manipulation becomes a credible grid-attack vector. Defense combines automotive cybersecurity, OCPP / ISO 15118 protocol-level controls, and bulk-electric-system protection. NERC CIP, R155 / R156, and OCPP-OA regimes are not yet integrated; this is a recognized open problem.

---

## XI. Real-Incident Corpus

The incidents below are the field's load-bearing case studies. Every automotive-security training session and every executive briefing references at least four or five.

### Miller / Valasek Jeep Cherokee (2015)

**Target**: 2014 Jeep Cherokee, Uconnect 8.4A head unit. **Effect**: Miller and Valasek remotely disabled the transmission of a Jeep on a public highway with Andy Greenberg of *Wired* driving; later disabled its brakes at low speed in a parking lot. 1.4M-vehicle Chrysler recall (first auto cybersecurity recall). **Technical detail**: Uconnect D-Bus reachable on Sprint's IP backbone on TCP 6667 with no auth; RCE on the head unit; reflash of an unsigned Renesas V850 chip bridging IVI to CAN; V850 transmits attacker CAN frames to powertrain bus. Black Hat USA 2015 paper "Remote Exploitation of an Unaltered Passenger Vehicle" is the technical reference. **Lesson**: Remote chains traverse cellular → IVI → bridge-MCU → CAN; gateway segmentation between IVI and powertrain is the structural defense. NHTSA voluntary guidance moved toward enforcement post-incident.

### Tencent Keen Lab Tesla (2016, 2017, 2018, 2019)

**Target**: Multiple Tesla models across firmware versions. **Effect**: Remote CAN injection (first remote-CAN on Tesla); progressively richer chains touching Autopilot perception and steering. **Technical detail**: 2016 chain combined malicious in-car-browser site with Wi-Fi / cellular escape, then privileged-service pivot to CAN; 2018 compromised Autopilot 2018.6.1; 2019 attacked Autopilot perception (lane-line stickers + wireless-gamepad steering). Tesla patched OTA each year. **Lesson**: Tesla's rich Linux + Chromium IVI with a path through privileged services to the CAN gateway was repeatedly chain-exploitable. Tesla's response (OTA + public bounty) became the industry reference.

### Megamos Crypto and Hitag2 (2012-2015)

**Target**: Audi, VW, Honda, Volvo, Fiat (Megamos). **Effect**: Practical key recovery against deployed immobilizer ciphers; VW litigation delayed Megamos publication two years. **Lesson**: Pre-2010 proprietary automotive crypto is structurally weak; replacement requires multi-model-year hardware-cycle. The 2023 CAN-injection wave is the criminal realization.

### 2023 CAN-injection vehicle-theft wave

**Target**: Toyota RAV4, Lexus RX, certain Range Rovers — UK and continental Europe most-documented. **Effect**: Theft rates spiked; insurers withheld coverage on affected models. ~€5,000 dark-web device + 2-3 minutes physical access per theft. **Technical detail**: Headlight CAN injection — device disguised as JBL Bluetooth speaker wired into bumper-area CAN harness after the headlight ECU; impersonates immobilizer / key-fob auth exchange. **Lesson**: Physical-layer CAN access is not as well-controlled as assumed; defenses include in-bus authentication, immobilizer retrofits, OEM ECU updates.

### Kia Challenge (2022-2023)

**Target**: 8.3M Kia and Hyundai vehicles, model years 2011-2022, U.S. **Effect**: Theft rates up 1000% in some U.S. cities; at least 14 reported crashes and eight fatalities. Kia / Hyundai software updates from February 2023. **Technical detail**: Absent industry-standard immobilizer. Steering-column shroud removal + USB-A in ignition slot. TikTok-amplified. **Lesson**: Absence of basic anti-theft controls on cost-reduced trims is a fleet-scale liability. Product-decision story, not software exploit.

### Sam Curry "Web Hackers vs. the Auto Industry" (2023, follow-ups 2024-2025)

**Target**: 16+ OEMs initially (Ferrari, BMW, Rolls Royce, Porsche, Mercedes-Benz, Hyundai, Genesis, Toyota, Nissan, Infiniti, Honda, Acura, Kia, Ford, Jaguar, Land Rover, SiriusXM, Spireon, Reviver). Kia 2024 (Round 2); Subaru STARLINK January 2025. **Effect**: Remote vehicle-control, location tracking, dealer-portal access, internal-network reach across nearly the entire OEM market in a single coordinated disclosure. **Technical detail**: Standard web-app failures at OEM scale — IDOR, SSO confusion, admin-panel reset without confirmation, mass-assignment, VIN-as-auth-token. **Lesson**: OEM cloud is the dominant 2023-2026 attack surface. OEM-side mitigation is enterprise-AppSec maturity — bounty programs, internal red-team, security-engineering review on new APIs.

### 2024 Tesla Pwn2Own corpus

**Target**: Tesla Model 3, Model S, Wall Connector; multiple ECUs. **Effect**: Synacktiv and others demonstrated remote / proximity exploits yielding CAN-bus control; $100K-$200K+ per vehicle exploit. **Technical detail**: TOCTOU on Gateway (Vancouver 2023); LTE-card → IVI two-bug chain (Tokyo 2024); VCSEC integer overflow (Vancouver 2024); TPMS zero-click RCE (Hexacon 2024). **Lesson**: Even Tesla — the most-mature OEM internal product-security — has exploitable C code at the radio/trusted-services boundary.

### Pen Test Partners EV-charger disclosures (2020-2024)

**Target**: Project EV, Wallbox, EVBox, EO Hub, EO mini pro 2, Hypervolt, ChargePoint Home Flex. **Effect**: Multi-vendor API-auth, firmware-signing, and authentication failures. **Lesson**: EV charging is a parallel attack surface with grid-impact consequences; charger-market defensive maturity lags vehicles by several years.

### Subaru STARLINK admin-panel takeover (January 2025)

**Target**: STARLINK admin panel covering U.S. / Canada / Japan Subarus. **Effect**: Full remote-control, 1-year location history (5m accuracy), PII access for any vehicle in affected regions. Disclosed by Shubham Shah and Sam Curry. **Technical detail**: Admin-panel password reset endpoint did not require a confirmation token. Resetting any employee's password yielded admin access; adding authorized users generated no owner notification. Patched within 24 hours. **Lesson**: Internal applications still require enterprise-AppSec review when they're on the public Internet.

### DEFCON Car Hacking Village (2015-present)

The longest-running automotive-security community event; structured CTF, vendor coordination, novel-attack-class disclosure venue. Raises the public-research bar across the field.

---

## XII. Defensive Frameworks

### ISO/SAE 21434

Cybersecurity-engineering process standard (August 2021). Sections: Cybersecurity Management; Cybersecurity in Concept (TARA, cybersecurity goals); Cybersecurity in Product Development; Cybersecurity in Production; Operations and Maintenance; Decommissioning. Parallels ISO 26262 for functional safety. TARA is the most-discussed deliverable.

### UNECE WP.29 R155 (CSMS)

Mandates a certified Cybersecurity Management System as type-approval prerequisite. The CSMS must maintain lifecycle cybersecurity risk management, identify and manage threats and vulnerabilities, verify supply-chain measures, and monitor vehicles post-sale with incident response. Mandatory for new vehicle types in EU since July 2022; mandatory for *all* new vehicles from July 2024.

### UNECE WP.29 R156 (SUMS)

Mandates a certified Software Update Management System. Must track all software components (SBOM), verify update authenticity and integrity, protect against unauthorized updates, restore on failed update, inform users. Operationalized via ISO 24089. Same cadence as R155.

### AUTOSAR Cybersecurity

- **SecOC** — message-level authentication, three profiles (CMAC variants + freshness). See §XIII.
- **Csm** — Crypto Service Manager.
- **KeyM** — Key Manager.
- **IAM for Adaptive AUTOSAR** — TLS-based service auth on Ethernet-based AUTOSAR Adaptive ECUs.

### SAE J3061

Historical predecessor to 21434 (2016). Older OEM processes built against J3061 are migrating.

### NHTSA voluntary best-practices (U.S.)

NHTSA "Cybersecurity Best Practices for the Safety of Modern Vehicles" (2016, 2022 update). Voluntary; NHTSA has authority under the Vehicle Safety Act to mandate safety-relevant cybersecurity. U.S. regime lags the European but is converging.

### Auto-ISAC

Industry-led ISAC for light- and heavy-duty OEMs, suppliers, commercial vehicles. Threat-intel sharing, vulnerability coordination, IR. Operates the Automotive Threat Matrix (ATM), an automotive-specific MITRE-ATT&CK analog.

### NMFTA Heavy Vehicle Cybersecurity

Working group covering commercial trucks: J1939 specifics, ELD mandates, telematics security, fleet-management protection. Coordinates with CISA and FMCSA.

### China GB cybersecurity standards

GB/T 40861 (information-security technical requirements for vehicles) and related standards apply to vehicles sold into China. CAC parallel authority over connected-vehicle data, with data-localization and cross-border-flow implications. Globally-shipping OEMs satisfy the union of European, U.S., and Chinese regimes.

---

## XIII. Detection and Monitoring

### Vehicle Security Operations Center (VSOC)

Auto-ISAC and major OEMs (Tesla, VW, BMW, Mercedes-Benz, Toyota, Stellantis, Ford, GM) operate or are building VSOCs for fleet-wide monitoring. Responsibilities: fleet-scale telemetry ingestion (billions of events / day); anomaly detection (CAN traffic baselines per make/model/firmware, BMS thermal profiles, unusual UDS sessions); threat-hunting; incident-response coordination; cross-OEM sharing via Auto-ISAC.

### In-vehicle IDS

Runs on gateway or central-compute ECU:

- **CAN-bus IDS** — frame-frequency anomalies, bus-load anomalies, ID-source consistency (an ECU receiving frames with its own transmit ID).
- **SecOC MAC-failure monitoring** — high failure rate indicates key mismatch (post-update) or active attack.
- **Automotive Ethernet IDS** — SOME/IP / AVTP / TSN traffic anomalies. HCRL dataset is the public benchmark.

Commercial offerings: Argus (Continental), Karamba Security, GuardKnox, Aurora Labs, Upstream (cloud-side), VicOne (Trend Micro subsidiary).

### Fleet-telemetry anomaly detection at OEM backend

Cloud-side analog. Detects: unusual dealer-portal auth patterns (credential-stuffing), unusual GPS-cluster patterns (relay-attack theft waves), unusual per-ECU error rates (firmware issue or exploitation), OTA completion-rate anomalies (distribution problem or attacker hold).

### OTA update audit trail

R156 requires per-vehicle audit trail: which VIN got which update, was signature verified, did install succeed, was user notified. Audit trail is itself an attack target; defensive design uses append-only semantics with out-of-band attestation.

### Cross-reference to detection-engineering

Cross-reference [[reference-detection-engineering]]. Automotive-specific:

- **Detection-as-policy**: in-vehicle IDS rules are policy-derived (frame X may only come from ECU Y on bus Z), not analyst-tuned.
- **Telemetry-cost economics**: cellular backhaul is metered; IDS summarizes on-device, not raw-ship.
- **Fleet-scale correlation**: many attacks only visible at fleet scale (credential-stuffing as a spike across vehicles).
- **Recovery time**: fleet-wide false-positive that disables vehicles is an unacceptable OEM-side DoS; IDS tuning is tighter than IT.

---

## XIV. Defensive Patterns

### AUTOSAR SecOC

Primary CAN-bus message-authentication primitive. AES-128-CMAC MAC + counter / trip-counter freshness value appended to each authenticated PDU; receiver verifies MAC against locally-held symmetric key. Considerations:

- **Bandwidth**: Classical CAN's 8-byte payload makes truncated MAC + partial freshness expensive; CAN FD's 64-byte payload makes overhead negligible. Current SecOC deployment concentrates on CAN FD.
- **Key provisioning**: Each ECU needs keys for every authenticated stream. OEMs provision via secure-bootloader-pinned keys derived from a vehicle-specific master secret.
- **Workshop key update**: When a new ECU is installed at a workshop, dealer tool / J2534 pass-thru updates keys. Dealer-tool credentials become a high-value target.
- **MAC-failure rate as IDS signal**: spike on a stable bus indicates key mismatch (post-update) or active attacker.

### Strong gateway between domains

The Stuxnet-equivalent defense. The 2015 Jeep failed because IVI had a write-path to the powertrain bus. Modern E/E architecture designs the gateway for minimal inter-segment messages enforced in firmware harder to compromise than the IVI. Zonal architecture concentrates the boundary at zone-gateway ECUs.

### OTA: signed packages + rollback + measured boot

The trio that makes OTA a net-positive rather than fleet-RCE:

1. **Signed packages** — every firmware artifact signed by hardware-protected OEM keys; ECU verifies before flashing.
2. **Rollback support** — previous firmware remains; failed boot reverts. R156 mandatory.
3. **Measured boot** — hash measurements at each boot stage (ROM, bootloader, kernel, user-space) signed by hardware key (TPM-equivalent) and reportable to OEM backend for remote attestation.

Cross-reference [[reference-supply-chain-provenance]]. Automotive-specific concerns: signing-key compromise affects entire fleet; key rotation across deployed ECUs is hard; quantum-safe migration is a multi-decade plan.

### Cellular modem isolation

TCU should not have a path to write arbitrary CAN frames. Miller-Valasek Jeep is the negative example. Architectural answers: TCU on its own segment, separated by a gateway with strict message filtering; authorized CAN messages limited to telematics functions; TCU OS separate from IVI.

### Defense-in-depth for safety-critical systems

Cross-reference [[reference-ics-ot-security]] §VII (SIS pattern). Automotive analog: safety-critical ECUs (ABS, ESC, airbag, braking) on physically-isolated buses or zonal segments, strict message filtering, redundant safety logic, out-of-band monitoring. ISO 26262 ASIL-D safety rigor; ISO/SAE 21434 cybersecurity counterpart.

### Coordinated disclosure programs

Tesla, GM, Stellantis, BMW, Mercedes-Benz, Ford, Hyundai and other major OEMs operate public bounty / coordinated-disclosure programs. Tesla has offered up to $600K at Pwn2Own for integrated multi-system chains. Auto-ISAC coordinates cross-OEM disclosure on Tier-1 vulnerabilities. Maturity gap between OEMs that engage with researchers and those that don't is the strongest predictor of security-engineering culture.

### Code-review checklist (12 items)

The automotive-specific code-review checklist for embedded firmware:

1. **No hardcoded SecurityAccess seed-key algorithm constants**. The algorithm is a high-value target; obfuscation does not help. Derive keys per-vehicle from a hardware-protected secret.
2. **No hardcoded cryptographic keys** in any source-checked-in file. Use the keystore / HSM abstraction.
3. **All inbound CAN frame handlers validate length before dereferencing** the payload. C-side buffer overflows on length-tagged inputs are a recurring failure.
4. **All UDS service handlers check current security level** before processing privileged sub-services. Easy to forget on a newly-added DID.
5. **SecOC MAC verification is on the receive path of every authenticated message stream**; no silent fallback to unauthenticated processing.
6. **Bootloader signature verification is on the path of every firmware acceptance**; no "developer mode" left enabled.
7. **Diagnostic-mode entry requires SecurityAccess at the appropriate level**; no "always-on" diagnostic backdoor.
8. **Logging does not include cryptographic keys, immobilizer seeds, or OEM-private credentials**.
9. **TLS / IPsec certificate validation is not disabled** in any TCU / IVI HTTPS client. Many old TCU implementations skip certificate-chain validation.
10. **Wi-Fi association does not auto-accept** unknown access points carrying an OEM-recognizable SSID; the association must require a credential.
11. **Bluetooth pairing flows enforce minimum key entropy** post-KNOB-attack patches; reject negotiated keys below 7-byte entropy.
12. **Firmware archives stored on the IVI / TCU for staged updates** are encrypted-at-rest and verified-on-read.

Cross-reference [[reference-firmware-embedded-security]] for the generic embedded-substrate checklist; this list is the automotive overlay.

---

## XV. Variant Analysis — Under-Explored Surfaces

### AI-agent-driven vehicle controls

The voice-assistant generation has been LLM-backed since 2023 (Mercedes MBUX with ChatGPT, BMW with Amazon's Alexa LLM, BYD with multiple Chinese LLM partners). The next step — an in-vehicle agent with read/write access to vehicle controls, calendar, contacts, payments, and external APIs — is already shipping in limited form. Cross-reference [[reference-llm-agent-security]].

The threat model:

- **Prompt-injection from passenger audio** — a passenger says (or has a media-source play) attacker-crafted content that the agent interprets as a privileged command. Same threat model as LLM-agent prompt injection on a phone or workstation, with the added severity axis that the agent can lock doors, set max speed, share location, or trigger emergency-call.
- **Prompt-injection from external API content** — the agent fetches a webpage / email / calendar entry that contains injected instructions. The mailbox-style injection pattern (see [[reference-llm-agent-security]]) ports directly.
- **Agent-mediated capability escalation** — the agent calls a vehicle-control API on the user's behalf; an attacker who can influence the agent's reasoning can drive arbitrary API calls.

Defensive answers parallel the LLM-agent literature: capability-narrowing (the agent's tool set should be the minimum required, not the maximum the OEM could provide), explicit-confirmation gates for any irreversible action, audit logging, and supervisor-model patterns.

### V2X security at scale

C-V2X deployment is ramping in 2025-2027; large-scale operational behavior is still emerging. Open problems: PKI scaling (billions of certificates rotated frequently), pseudonym-rotation privacy (an attacker who can correlate pseudonyms across rotations defeats the privacy property), Sybil-attack defense (one attacker presenting as many vehicles), and the cross-layer interaction between V2X messages and ADAS perception.

### Robotaxi-specific attack surface

Waymo, Cruise, Zoox, Pony.ai, Baidu Apollo. The robotaxi attack surface is qualitatively different because the OEM has continuous teleoperation supervision, the vehicle has no privileged-user (only riders), and the cloud-side fleet-management plane has direct vehicle-control authority. Compromise of the fleet-management plane is the worst case. Public disclosure cadence is thin; the field is closely-held.

### Truck platooning

DOT-sponsored research into close-following heavy-truck convoys (the leader truck dictates speed and braking via V2X; following trucks at short headways achieve fuel savings via reduced aerodynamic drag). Cyber-attacker capability against the leader's V2X broadcast permits coordinated multi-truck behavior change — a kinetic-scale attack with cascading consequences. Public deployment limited to test pilots; the security model is being built.

### Cross-link to game-console security

Cross-reference [[reference-game-console-security]].

### Maritime automotive parallels

Yacht electronics (Garmin, Raymarine, Furuno) and cargo-ship bridge systems (ECDIS) parallel automotive in many respects: CAN-bus-adjacent protocols (NMEA 2000 is a CAN-derived maritime protocol), embedded RTOS substrate, multi-decade product lifecycle, sparse OTA-update capability, and increasing cellular / satellite connectivity. The Pen Test Partners corpus includes maritime disclosures alongside automotive.

### Aviation parallels

General-aviation cockpit avionics (Garmin G1000, Avidyne IFD series) parallel automotive in product-cycle and embedded-substrate terms. Commercial aviation is a different regime entirely (DO-178C / DO-326A regulatory rigor far exceeds automotive). The general-aviation attack surface — particularly around connected EFB (Electronic Flight Bag) integrations and ADS-B Out spoofing — is an active research area that occasionally produces transferable insights for automotive V2X.

---

## XVI. References

### Foundational papers

- Koscher, K., et al. "Experimental Security Analysis of a Modern Automobile." IEEE Symposium on Security and Privacy (Oakland), 2010. http://www.autosec.org/pubs/cars-oakland2010.pdf
- Checkoway, S., et al. "Comprehensive Experimental Analyses of Automotive Attack Surfaces." USENIX Security 2011. http://www.autosec.org/pubs/cars-usenixsec2011.pdf
- Miller, C., and Valasek, C. "Adventures in Automotive Networks and Control Units." DEFCON 21, 2013. https://illmatics.com/car_hacking.pdf
- Miller, C., and Valasek, C. "Remote Exploitation of an Unaltered Passenger Vehicle." Black Hat USA 2015. https://illmatics.com/Remote%20Car%20Hacking.pdf
- Miller, C., and Valasek, C. "Survey of Remote Automotive Attack Surfaces." Black Hat USA 2014. http://illmatics.com/remote%20attack%20surfaces.pdf

### Cryptography of immobilizers and RKE

- Verdult, R., Garcia, F. D., Balasch, J. "Gone in 360 Seconds: Hijacking with Hitag2." USENIX Security 2012. https://www.usenix.org/conference/usenixsecurity12/technical-sessions/presentation/verdult
- Verdult, R., Garcia, F. D., Ege, B. "Dismantling Megamos Crypto: Wirelessly Lockpicking a Vehicle Immobilizer." USENIX Security 2015. https://www.usenix.org/conference/usenixsecurity15/technical-sessions/presentation/verdult
- Verdult, R., Garcia, F. D. "Cryptanalysis of the Megamos Crypto Automotive Immobilizer." ;login: USENIX magazine, December 2015, vol. 40, no. 6. https://www.usenix.org/system/files/login/articles/login_dec15_04_verdult.pdf
- Nohl, K. Immobilizer security talk. SIGINT 2013 / NoSuchCon 2013. https://nosuchcon.org/talks/2013/D2_05_KNohl_Immobilizer_Security.pdf
- Bono, S., Green, M., Stubblefield, A., Juels, A., Rubin, A., Szydlo, M. "Security Analysis of a Cryptographically-Enabled RFID Device" (DST40). USENIX Security 2005.

### Tesla and other modern-vehicle research

- Rogers, M., and Mahaffey, K. "How to Hack a Tesla Model S." DEFCON 23, 2015. https://archive.org/details/youtube-KX_0c9R4Fng
- Tencent Keen Security Lab. "Car Hacking Research: Remote Attack to Tesla Cars." September 2016. https://keenlab.tencent.com/en/2016/09/19/Keen-Security-Lab-of-Tencent-Car-Hacking-Research-Remote-Attack-to-Tesla-Cars/
- Tencent Keen Security Lab. "New Car Hacking Research: 2017, Remote Attack Tesla Motors Again." July 2017. https://keenlab.tencent.com/en/2017/07/27/New-Car-Hacking-Research-2017-Remote-Attack-Tesla-Motors-Again/
- Tencent Keen Security Lab. "Experimental Security Research of Tesla Autopilot." March 2019. https://keenlab.tencent.com/en/whitepapers/Experimental_Security_Research_of_Tesla_Autopilot.pdf
- Synacktiv. "Unlocking the Drive: Exploiting Tesla Model 3." CodeBlue 2023. https://www.synacktiv.com/sites/default/files/2023-11/tesla_codeblue.pdf
- Synacktiv. "0-click RCE on Tesla Model 3 through TPMS Sensors." Hexacon 2024. https://www.synacktiv.com/sites/default/files/2024-10/hexacon_0_click_rce_on_tesla_model_3_through_tpms_sensors_light.pdf
- Weinmann, R.-P., and Schmotzle, B. "TBONE — A zero-click exploit for Tesla MCUs." 2021.

### Web-shaped automotive disclosure

- Curry, S., et al. "Web Hackers vs. The Auto Industry: Critical Vulnerabilities in Ferrari, BMW, Rolls Royce, Porsche, and More." January 2023. https://samcurry.net/web-hackers-vs-the-auto-industry
- Curry, S., and Shah, S. "Hacking Subaru: Tracking and Controlling Cars via the STARLINK Admin Panel." January 2025. https://samcurry.net/hacking-subaru

### CAN-injection theft wave

- Tindell, K. "How thieves are stealing cars using CAN injection." Canis Automotive Labs, April 2023. https://kentindell.github.io/2023/04/03/can-injection/
- "Thieves Are Stealing Cars Through Headlight Wiring." Various outlets, 2023.

### Wireless and key-fob attacks

- Antonioli, D., Tippenhauer, N. O., Rasmussen, K. "The KNOB is Broken: Exploiting Low Entropy in the Encryption Key Negotiation Of Bluetooth BR/EDR." USENIX Security 2019. https://www.usenix.org/conference/usenixsecurity19/presentation/antonioli
- NCC Group. "Technical Advisory — Tesla BLE Phone-as-a-Key Passive Entry Vulnerable to Relay Attacks." May 2022. https://research.nccgroup.com/2022/05/15/technical-advisory-tesla-ble-phone-as-a-key-passive-entry-vulnerable-to-relay-attacks/
- IOActive. "NFC Relay Attack on Tesla Model Y." 2022. https://www.ioactive.com/nfc-relay-attack-on-tesla-model-y/

### ADAS perception attacks

- Eykholt, K., et al. "Robust Physical-World Attacks on Deep Learning Visual Classification." CVPR 2018.
- Cao, Y., et al. "Adversarial Sensor Attack on LiDAR-based Perception in Autonomous Driving." CCS 2019.
- Tencent Keen Security Lab Tesla Autopilot research (cited above).

### UDS and ECU exploitation

- ISO 14229-1:2020 "Road vehicles — Unified diagnostic services (UDS) — Part 1: Application layer services."
- Lauser, T., and Krauß, C. "Formal Security Analysis of Vehicle Diagnostic Protocols." ARES 2023. https://dl.acm.org/doi/fullHtml/10.1145/3600160.3600184
- I CAN Hack blog. "Extracting Secure Onboard Communication (SecOC) keys from a 2021 Toyota RAV4 Prime." 2024. https://icanhack.nl/blog/secoc-key-extraction/

### EV charging

- Pen Test Partners. "Hacking EV chargers poses a huge risk." https://www.pentestpartners.com/security-blog/in-the-news-story/28636/
- Pen Test Partners. "Smart car chargers. Plug-n-play for hackers?" https://www.pentestpartners.com/security-blog/smart-car-chargers-plug-n-play-for-hackers/
- Pen Test Partners. "EV batteries as grid infrastructure and the security risk that follows." https://www.pentestpartners.com/security-blog/ev-batteries-as-grid-infrastructure-and-the-security-risk-that-follows/
- Saiflow. "Hijacking EV Charge Points to Cause DoS." https://www.saiflow.com/blog/hijacking-chargers-identifier-to-cause-dos/
- OSTI. "Disrupting EV Charging Sessions and Gaining Remote Code Execution on Electric Vehicle Supply Equipment." https://www.osti.gov/servlets/purl/2431391

### Pwn2Own Automotive

- ZDI. "Pwn2Own Automotive 2025." https://www.thezdi.com/blog/2024/9/23/announcing-pwn2own-automotive-for-2025
- VicOne. Pwn2Own Automotive coverage. https://vicone.com/blog/

### Regulations and standards

- ISO/SAE 21434:2021 "Road vehicles — Cybersecurity engineering."
- UNECE Regulation No. 155 (CSMS). https://unece.org/transport/documents/2021/03/standards/un-regulation-no-155-cyber-security-and-cyber-security
- UNECE Regulation No. 156 (SUMS). https://unece.org/transport/documents/2021/03/standards/un-regulation-no-156-software-update-and-software-update
- ISO 24089:2023 "Road vehicles — Software update engineering."
- ISO 15118 family "Road vehicles — Vehicle-to-grid communication interface."
- ISO 11898 family "Road vehicles — Controller area network (CAN)."
- AUTOSAR Classic Platform documents (Specification of Secure Onboard Communication, etc.). https://www.autosar.org/standards/classic-platform
- NHTSA "Cybersecurity Best Practices for the Safety of Modern Vehicles." 2022. https://www.nhtsa.gov/sites/nhtsa.gov/files/2022-09/cybersecurity-best-practices-safety-modern-vehicles-2022-tag.pdf

### Industry and intel sources

- Automotive ISAC. https://automotiveisac.com/
- NMFTA Heavy Vehicle Cyber Security. https://nmfta.org/
- Auto-ISAC Automotive Threat Matrix. https://automotiveisac.com/press-news/the-auto-isac-launches-automotive-threat-matrix-atm-tool-to-enhance-vehicle-cybersecurity-governance

### Open-source automotive

- comma.ai openpilot. https://github.com/commaai/openpilot
- opendbc (CAN message database). https://github.com/commaai/opendbc
- CAESS (UCSD-UW) publications. https://www.autosec.org/publications.html

### Cross-references within this expertise corpus

- `firmware_embedded_security.md` — embedded substrate (CPU architectures, JTAG, fault injection, firmware unpacking), parent of automotive ECU work.
- `ics_ot_security_expertise.md` — process-control parallels (BPCS/SIS, Purdue model, IEC 62443, OT-IDS); cross-link for grid-impact analysis and SIS-pattern defense.
- `mobile_security_expertise.md` — baseband (cellular modem), Bluetooth Classic / BLE attack details.
- `browser_js_engine_exploitation_expertise.md` — Chromium-based IVI exploitation.
- `adversarial_ml_model_security_expertise.md` — ADAS perception attacks against ML models.
- `cryptography_expertise.md` — RKE / immobilizer cryptanalysis primitives, AUTOSAR SecOC MAC schemes.
- `cicd_supply_chain_expertise.md` — OTA-update supply-chain hygiene.
- `supply_chain_provenance_expertise.md` — signed-package distribution, measured boot, attestation patterns.
- `detection_engineering_expertise.md` — transferable detection-engineering patterns for VSOC and in-vehicle IDS.
- `llm_agent_security_expertise.md` — in-vehicle LLM-agent prompt-injection threat model.
- `code_review_expertise.md` — secure-code-review methodology applicable to automotive firmware audit.
