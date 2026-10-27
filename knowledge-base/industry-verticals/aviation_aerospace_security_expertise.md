# Aviation and Aerospace Cybersecurity
## Staff-Level Technical Reference

---

## I. Researcher Profiles

Aviation cybersecurity as a public research discipline is younger than its consequence profile suggests. Until 2013 essentially all serious work was inside OEMs (Boeing, Airbus, Embraer, Bombardier, Honeywell, Collins, Thales, Leonardo), national-aviation authorities (FAA, EASA), or three-letter agencies. Hugo Teso's 2013 Hack-In-The-Box talk and Ruben Santamarta's 2014 Black Hat SATCOM paper opened the field to the public-research community; ADS-B and ACARS research at Oxford, ETH Zurich, and EURECOM in 2012-2018 produced the canonical academic corpus; Pen Test Partners and Rapid7 added the consultancy-cadence disclosure stream in the 2018-2024 window; and the AcidRain / Viasat incident of February 2022 forced the wider security community to acknowledge that satellite ground segments are nation-state-grade targets. The names below span those waves.

### Hugo Teso — formerly N.runs Professionals

**Career arc**: Commercial pilot turned aviation-security consultant. Began at N.runs AG in Germany. A former commercial pilot — the rare combination of cockpit experience and embedded-RE skill that allowed his work to land credibly with the airworthiness-certification community rather than getting brushed off as theatre.

**Core contribution**: "Aircraft Hacking: Practical Aero Series" (Hack-In-The-Box Amsterdam, April 2013). The first public, end-to-end demonstration that the broadcast-based aviation data links (ACARS and ADS-B) could be used as attacker-controlled input into onboard Flight Management Systems. Teso built **SIMON**, an attack framework targeting FMS-class software running on a desktop simulator, and **PlaneSploit**, an Android front-end that selected ADS-B-located target aircraft and delivered crafted ACARS uplinks. Both deliberately constrained to non-airworthy targets: the FMS Teso compromised was the same software stack that ships on aircraft but running on a desktop trainer, not a real avionics line-replaceable unit. He was explicit about scoping at the press briefings.

**Frame Teso introduced**: ACARS uplinks are *attacker-influenced input* to a safety-critical software stack, and the entire avionics community had been treating ACARS as a transport rather than an attack surface. Every subsequent aviation security paper that cites "no authentication, no encryption, no integrity" on broadcast aviation data links is downstream of Teso 2013.

### Ruben Santamarta — IOActive

**Career arc**: Principal security consultant at IOActive; long-running embedded-systems research. Cross-referenced in `wireless_rf_satellite_security_expertise.md` for the SATCOM corpus more broadly. Spanish researcher with a heavy reverse-engineering specialty across satellite, industrial, and IoT firmware.

**Core contribution**: Two SATCOM-in-aviation papers anchor his contribution. "SATCOM Terminals: Hacking By Air, Sea, and Land" (Black Hat USA 2014; IOActive whitepaper) documented hardcoded credentials, backdoors, weak proprietary protocols, and Internet-and-RF-facing attack surfaces across Cobham (AVIATOR 700, EXPLORER, SAILOR), Harris, Hughes, Iridium, Inmarsat, JRC, and Thuraya products. The Cobham AVIATOR 700 finding was the headline because the product line is **certified for installation as the SwiftBroadband terminal on commercial aircraft** — meaning the cabin Wi-Fi network and the SATCOM channel used by FANS, CPDLC, and ACARS could share a terminal an attacker reached from the IFE network. Follow-up "Last Call for SATCOM Security" (Black Hat USA 2018) extended disclosure to hundreds of in-flight aircraft, naval vessels, and military bases.

**Frame Santamarta introduced**: SATCOM terminals in aviation are *bridges*, not endpoints — the same hardware carries passenger Wi-Fi traffic and cockpit-safety-services traffic, separated only by software-defined VLAN or QoS boundaries that a determined attacker can usually cross. The structural defense is hardware-level segregation, not software-defined isolation.

### Andrei Costin — University of Jyväskylä; Firmware.RE founder

**Career arc**: PhD from EURECOM (advisors Aurélien Francillon and Davide Balzarotti) on "Large-scale Security Analysis of Embedded Devices' Firmware." Founded Firmware.RE for automated firmware analysis. Currently Assistant Professor in the Cyber Security Group at University of Jyväskylä, Finland.

**Core contribution**: "Ghost in the Air(Traffic): On insecurity of ADS-B protocol and practical attacks on ADS-B devices" (Black Hat USA 2012). First systematic public treatment of ADS-B security weaknesses with practical attacks ranging from passive eavesdropping to active message jamming, injection, and replay. Costin's framing — that ADS-B lacks the minimal security mechanisms needed to protect air traffic — became the canonical academic reading.

**Frame Costin introduced**: ADS-B insecurity is not subtle. The protocol broadcasts unauthenticated position reports in the clear at known frequencies on a known schedule; a software-defined radio plus a few hundred dollars of off-the-shelf hardware is all that's needed to inject fake targets into receivers — including airborne TCAS receivers and ground ATC fusion systems. The defensive case must rest on **multilateration**, **primary surveillance radar**, and **vehicle-state plausibility filtering**, not on the integrity of ADS-B itself.

### Patrick Kiley — formerly Rapid7

**Career arc**: Senior Security Consultant at Rapid7 during the 2017-2019 aviation arc; previously a long career in network security and incident response. Builder of a kit aircraft, which surfaced his research question — a hobbyist context that gave him hands-on access to small-aircraft avionics that institutional researchers don't routinely get.

**Core contribution**: "Investigating CAN Bus Network Integrity in Avionics Systems" (Rapid7 white paper, 30 July 2019). First public-research demonstration of CAN-bus attacks against modern small-aircraft avionics. Kiley showed that an attacker with physical access could spoof engine telemetry, compass and attitude data, altitude, airspeed, and angle of attack by injecting CAN frames; the displays trusted the bus, and there was no authentication or integrity check. CISA/DHS issued **ICS-ALERT-19-211-01**. Cross-link to `automotive_security_expertise.md` §II (CAN heritage); the avionics CAN derivatives (ARINC 825, CAN aerospace) inherit the same trust model.

**Frame Kiley introduced**: General aviation is the most-overlooked attack surface in aviation cybersecurity. Commercial aircraft get certification rigor and ARINC 664 segregation; small aircraft get whatever the avionics vendor decided to ship, which is increasingly CAN-bus-derived and inherits all the automotive-CAN insecurity properties.

### Chris Roberts — One World Labs (formerly); independent

**Career arc**: Co-founder of One World Labs; long arc of consultancy and independent research. The April-May 2015 FBI episode reshaped both his career and the legal landscape for aviation researchers.

**Core contribution**: The Roberts case is studied as a *disclosure* case, not as a technical contribution per se. The technical claim Roberts made to the FBI (later disputed by him as having been mischaracterized) was: he had connected to in-flight entertainment system enclosures under his seat via a modified Ethernet cable, traversed network domains, and on one occasion induced lateral movement via an engine command. The aviation safety community immediately disputed the kinetic claim. The most-rigorous read: the *general direction* of his concerns (IFE-to-avionics network paths) was credible and corroborated by GAO and IG findings around the same period, but the *specific kinetic claim* was not technically supported.

**Frame the Roberts episode established**: Aviation researchers operate under unique legal exposure. CFAA enforcement on a transportation system carrying paying passengers is not the same as on an unattended IT asset, and the federal investigative posture is meaningfully harsher. The Aerospace Village and Boeing-and-Airbus formal vulnerability-disclosure programs that emerged in the late 2010s are the structural response.

### Brad Haines (RenderMan) — independent

**Career arc**: Canadian independent security researcher with long history in wireless and aviation topics. Long-running advocate for transparency in the FAA NextGen modernization program. Co-author of *Kismet Hacking* (Syngress, 2008).

**Core contribution**: Early public-research work on ADS-B spoofing with co-researcher Nick Foster. The DEF CON 20 (2012) talk "Hackers + Airplanes: No Good Can Come Of This" walked through ghost-target injection — coupling FlightGear (open-source flight simulator) output through a software-defined radio to ADS-B receivers, producing realistic but entirely synthetic aircraft tracks on ATC and pilot displays. The follow-up coverage included a demonstration of injecting a ghost flight near San Francisco International Airport. Haines's arc paralleled Costin's academic work and Teso's FMS-side work — three independent confirmations within an 18-month window.

**Frame Haines introduced**: Public-interest transparency on aviation systems is a defensive contribution, not an offensive one. **Public scrutiny of certification-grade systems is the only way to surface design issues before deployment**, and the alternative — closed-system trust — is exactly what produced the unauthenticated-by-design ADS-B mandate.

### Martin Strohmeier — Cyber-Defence Campus (ETH Zurich); Oxford

**Career arc**: Senior Scientist at the Swiss Cyber-Defence Campus (based at ETH Zurich); Visiting Fellow of Kellogg College, Oxford. DPhil at Oxford (2016) under Prof. Ivan Martinovic. Co-founder and board member of the **OpenSky Network**, the largest public crowdsourced ADS-B receiver network. The most-prolific academic researcher on aviation wireless security in the 2014-2026 window.

**Core contribution**: A multi-paper canon comprehensively characterizing the security and privacy posture of operational aviation wireless protocols. Key papers: "Security of ADS-B: State of the Art and Beyond"; "Realities and Challenges of NextGen Air Traffic Management"; the ACARS privacy series with Daniel Moser and Matthew Smith. Together these form the academic backbone of the field.

**Frame Strohmeier introduced**: Aviation wireless security must be analyzed as a *system*, not protocol-by-protocol. The dependency graph among ADS-B, Mode S, TCAS, ACARS, CPDLC, VDL Mode 2, SATCOM, and ATC ground systems means that a single protocol break propagates into ground-fusion errors, cockpit decision-support errors, and pilot behavior changes.

### Daniel Moser and Matthew Smith — ETH Zurich; Oxford

**Career arc**: Moser — ETH Zurich. Smith — DPhil at Oxford under Prof. Ivan Martinovic. Both collaborated closely with Strohmeier on the ACARS series.

**Core contribution**: "Undermining Privacy in ACARS" (PETS 2018) and "Economy Class Crypto: Exploring Weak Cipher Usage in Avionic Communications via ACARS." Demonstrated empirically — using more than 2 million ACARS messages collected over 16 months — that ACARS is essentially a public broadcast for the small fraction of users (government, military, business jets) who have a privacy interest in it. The "Economy Class Crypto" paper found that the small share of ACARS traffic that *is* encrypted uses weak or homebrew ciphers — easily recoverable plaintext from passive collection.

**Frame Moser and Smith introduced**: Privacy is a security primitive in aviation, not a separate concern. Passive ADS-B and ACARS collection is the dominant intelligence-gathering activity against operational aviation today.

### Lennert Wouters — KU Leuven COSIC

**Career arc**: Researcher at KU Leuven COSIC (Computer Security and Industrial Cryptography), Belgium. Long arc of hardware fault-injection and side-channel research against high-assurance consumer and infrastructure targets — including Tesla keyfob attacks and the Starlink work.

**Core contribution**: "Glitched on Earth by Humans: A Black-Box Security Evaluation of the SpaceX Starlink User Terminal" (Black Hat USA 2022). A **voltage fault-injection attack** against the Starlink user terminal that bypassed firmware-signature checks and yielded persistent code execution on the dish-side embedded Linux. The custom modchip cost approximately $25. The contribution is twofold: (1) it broke the implicit assumption that consumer satellite user terminals are not high-assurance targets, and (2) the SpaceX response — bringing the work into the bounty program and inviting further researcher engagement — became the reference for how a modern space-internet operator should treat external research. Cross-link to `wireless_rf_satellite_security_expertise.md`.

**Frame Wouters introduced**: User terminals for satellite internet services are the *consumer endpoint* of a critical infrastructure, and their hardware-attack surface is real. The structural defense is not preventing modchipping but ensuring that a compromised terminal *cannot pivot inward* against the constellation control plane.

### Ken Munro — Pen Test Partners

**Career arc**: Founder of Pen Test Partners (Buckingham, UK); pilot license-holder; long arc of consultancy disclosures across IoT, automotive, maritime, and aviation. The most consistent professional source of aviation cybersecurity disclosures in the 2018-2026 window, with an emphasis on EFB, IFE, and aviation app-side surfaces.

**Core contribution**: A decade-long disclosure cadence covering EFB authentication weaknesses (4-digit PINs, no MDM, BYO devices), IFE-network reachability paths from passenger seat-back to back-of-domain services, EFB software vulnerabilities (Airbus NAVBLUE Flysmart+ Manager, multiple smaller vendors), TCAS-spoofing research, and aviation-app supply-chain analysis. Cross-referenced in `automotive_security_expertise.md` §I (Munro's broader EV-charging arc).

**Frame Munro established**: EFBs are the practical bridge from the public internet to flight-critical decision-support. **EFB security needs MDM, hardening, signing, and supply-chain provenance** to the same standard as any other critical-systems mobile fleet — and the airline industry's pace of getting there is significantly behind enterprise IT's pace on equivalent fleet-management problems.

### Aerospace Village (DEF CON) and academic corpus

The **DEF CON Aerospace Village** first appeared in 2019 as the Aviation Village and was renamed the Aerospace Village in 2020. Founded by a coalition of aviation researchers, pilots, defense-industrial-base practitioners, and FAA-adjacent policy specialists, with explicit goals of *open conversation* and *researcher-vendor collaboration*. Hosts CTFs, hardware-hacking labs (Bricks-in-the-Air, avionics tear-downs), and joint sessions with the Voting Village, ICS Village, and Car Hacking Village. The Village exists because the open vulnerability-disclosure relationship between researchers and aviation vendors was historically broken; the Roberts episode (2015) is the canonical illustration. The Village normalized researcher engagement and reduced — though did not eliminate — the legal risk profile of aviation research.

The **academic ACARS/SATCOM/CPDLC corpus** lives across EURECOM (Costin et al.), Oxford System Security Lab (Strohmeier, Martinovic, Smith), ETH Zurich (Capkun, Moser), and KU Leuven (Wouters, Verbauwhede). The CPDLC security paper from Linköping University (Gurtov, Polishchuk, Wernberg, Sensors 2018) and the TCAS spoofing work led by Giacomo Longo (USENIX Security 2024) are the canonical examples — careful, threat-modeled, defensible-in-court contributions that drove real specification revisions.

---

## II. The Aviation Cybersecurity Threat Model

### Why aviation is uniquely consequential

The base consequence axis: **human lives** in three-figure batches per incident, **fleet-wide blast radius** when a software defect is in a Type Certificate'd component, **multi-decade lifecycle** for airframes and the avionics they ship with, and **regulatory layering** across international, national, and operator levels that makes patching a months-or-years process rather than a days-or-weeks process. A 2002-vintage commercial aircraft is in revenue service in 2026 with most of its original avionics; the LRUs (Line-Replaceable Units) running ARINC 429 buses on a Boeing 737NG or Airbus A320 are the same physical units that were certified 25 years ago. The combination of consequence severity and patching latency is unique to aviation — the closest analog is ICS/OT (cross-link `ics_ot_security_expertise.md`), and aviation is *worse* on both axes for commercial passenger flight.

### The safety-culture overlay

Aviation came from a *safety-engineering* culture that significantly predates the *computer-security* culture. The reliability-engineering vocabulary — FMEA, Fault Tree Analysis, MTBF, redundancy, defense-in-depth, fail-safe defaults, certification by independent third party — was largely built by aviation in the 1950s-1970s. When computer security entered the field in the 2000s, it found a culture that already understood adversarial-failure modeling but had a different *vocabulary* (hazard vs. threat, mitigation vs. countermeasure, safety case vs. risk assessment) and had limited tolerance for the offensive-research disclosure cadence that IT security had normalized.

The productive way to introduce a new cybersecurity finding to aviation is in the safety-case vocabulary. "ADS-B is broken" is not a useful sentence in this culture; "an injected ADS-B target produces a TCAS Resolution Advisory whose probability of causing an unsafe pilot response exceeds the catastrophic-failure threshold of 1×10⁻⁹ per flight hour under DO-326A" is the sentence that gets the attention.

### Trust boundaries: air-gap-by-design, increasingly bridged

The historical trust model: cockpit avionics are air-gapped from cabin networks, which are air-gapped from passenger networks. Modern reality:

- **EFBs** are the most-bridged single boundary. They connect to airline ground infrastructure, app stores, and increasingly to the aircraft via Aircraft Interface Devices (AIDs).
- **SATCOM** terminals share hardware between cockpit-services data and cabin-Wi-Fi data, with software-defined isolation.
- **Maintenance laptops** connect to engineering workstations, sometimes to avionics test ports, and to airline back-office networks.
- **OEM-vendor remote-diagnostics** channels (engine health monitoring, avionics telemetry, OEM cloud uplinks) are increasingly common and almost always poorly understood by airline IT.

Every bridge was added for a real operational reason. The bridges accumulated faster than the security posture of either side, and the post-Stuxnet ICS lesson — that air gaps are usually fiction — applies here too.

### Why "patch everything quickly" fails

A bug in an LRU certified to DO-178C Level A cannot be patched the way an IT asset can. The patch must go through:

1. Vendor change-impact analysis (weeks to months)
2. Re-verification against DO-178C Level A objectives (objective coverage, structural coverage including MC/DC, traceability)
3. Type Certificate Holder change-approval
4. Cybersecurity assessment under DO-326A / DO-356A (months)
5. National-aviation-authority approval (FAA Engineering Bulletin or EASA AMC)
6. Service Bulletin issuance and operator scheduling against fleet maintenance plans (months to years)
7. For mandatory action, an Airworthiness Directive (AD)

The end-to-end timeline for "critical avionics security patch deployed across a global fleet" is *years* in 2026. The structural slowness is a feature of the safety-certification model, not a bug.

Cross-link `ics_ot_security_expertise.md` for the safety-critical-OT analog; aviation patching is *worse* than power-utility patching on most axes.

---

## III. Avionics Buses and Protocols

The bus-and-protocol corpus below predates the modern threat model by 10-40 years. Authentication and encryption have been bolted on in modern variants but field deployment is rare.

### ARINC 429

Point-to-point one-shot serial digital data bus, defined by ARINC 429 in 1977. The most ubiquitous avionics data bus on Western commercial transport — Boeing 737, 747, 757, 767, A300, A310, A320, A330, A340 families.

- **Topology**: One transmitter, up to 20 receivers. No bus arbitration.
- **Data rate**: 12.5 kbit/s (low speed) or 100 kbit/s (high speed). 32-bit data words.
- **No authentication, no encryption, no integrity** beyond a single parity bit.
- **The bus model is its own defense**: ARINC 429 is read-only from the attacker's perspective unless they can physically connect, and the physical wire is inside a sealed bay. The attack surface is *firmware update*, *maintenance port*, and *LRU substitution*.

ARINC 429 security depends on **physical separation and supply-chain integrity** of LRUs, not on cryptographic message-level controls.

### AFDX / ARINC 664 Part 7

**Avionics Full-Duplex Switched Ethernet**, originally developed by Airbus for the A380 (2005). Ships on A380, A350, A400M, Boeing 787, ARJ21, Sukhoi Superjet 100.

- **Switched, full-duplex** 100 Mbit/s Ethernet with deterministic-QoS achieved through Virtual Links (VLs) — point-to-multipoint logical channels with reserved bandwidth.
- **Bandwidth Allocation Gap (BAG)**: each VL has a guaranteed minimum gap between frames; switches enforce non-conformant traffic shaping.
- **Redundancy**: two physical networks (A and B); receivers de-duplicate.
- **Deterministic latency** within a few milliseconds.

AFDX inherits Ethernet's lack of cryptographic protection at Layer 2, but its switched topology means an attacker reaching any single host has limited reach without compromising the switch. The recent attack surface is the **Aircraft Interface Device** and EFB-connected systems sitting at the edge, not the AFDX core itself.

### MIL-STD-1553

US military standard published in 1973 (revisions 1975, 1978, 2018). The dominant avionics serial bus on Western military aircraft for five decades — F-15, F-16, F-18, F-22, F-35, all transports, NASA Space Shuttle, ISS, Mars rovers.

- **Command/response**: Bus Controller initiates; Remote Terminals respond. Up to 31 RTs per bus segment.
- **Dual-redundant** physical buses; time-division-multiplexed transactions with Manchester encoding.
- **1 Mbit/s** raw rate.
- **No authentication, no encryption** in the base standard. The 2018 Revision C is functionally equivalent to 1553B.

The MIL-STD-1553 attack surface is **direct bus injection** by any actor with physical access.

### ARINC 825 (CAN aerospace)

Avionics-adapted CAN bus, standardized by ARINC in 2007 as a higher-layer protocol on CAN 2.0B with aviation-specific application objects. Used in helicopters (Sikorsky, Airbus Helicopters), business aviation (Cessna, Bombardier, Embraer), and increasingly general aviation kit aircraft. Same trust model as automotive CAN: bus access = full message-injection authority. Patrick Kiley's 2019 Rapid7 work is the canonical public disclosure.

### TTEthernet (SAE AS6802)

Time-Triggered Ethernet. Developed by TTTech Aerospace. Backbone for NASA Orion.

- **Time-triggered, deterministic Ethernet** that schedules frame transmission via a synchronous clock.
- **Mixed-criticality** support: time-triggered, rate-constrained (AFDX-style), and best-effort on the same physical infrastructure.
- **Security**: TTEthernet does not specify cryptographic message protection; relies on physical isolation, switch enforcement, and dataflow-validation at endpoints.

Attack surface is **endpoint code** and **switch firmware**, not the bus itself.

### Redundancy is the architecture

The defining structural feature of avionics buses is **redundancy as the primary defense against any failure**. Dual or triple redundancy on flight-critical channels plus voting/comparison logic means that **a single-channel cyber attack must succeed against multiple bus instances simultaneously** to produce a controllable kinetic effect. This is the structural reason most ADS-B / TCAS / ACARS / CPDLC research has consequence claims phrased as "pilot decision-support degraded" rather than "aircraft made unsafe": the redundancy boundary holds even when individual buses or radios are compromised.

The exceptions — where redundancy degenerates into single-point compromise — are the cases the safety case must catch: shared display systems where two redundant flight-control computers write to the same display LRU, shared sensor processing where two redundant air-data probes feed through the same Air Data Inertial Reference Unit (ADIRU) firmware. These are exactly what DO-326A's threat-modeling discipline tries to surface.

---

## IV. Air-Ground Data Links

### ACARS (Aircraft Communications Addressing and Reporting System)

The dominant air-ground text-messaging protocol since 1978. Carries flight-crew chat, position reports, weather updates, maintenance alerts, route changes, and increasingly FANS-1/A operational messages (CPDLC and Automatic Dependent Surveillance — Contract, ADS-C).

- **Three radio media**: VHF (POA-CSP and VDL Mode 2), HF, SATCOM (Inmarsat Classic Aero, SwiftBroadband; Iridium).
- **Plaintext by default**. 99% of ACARS traffic is unencrypted (Smith, Moser, Strohmeier 2017).
- **FANS-1/A** is the ACARS evolution carrying CPDLC and ADS-C; it runs inside the ACARS protocol rather than ATN and adds no cryptographic protection of the message body.
- **No sender authentication, no message integrity, no replay protection** for the bulk of operational ACARS traffic.

ACARS is the canonical "I assumed this channel was private and the academic literature proved it wasn't" example. Passive collection via inexpensive VHF/SATCOM receivers and online ACARS aggregation services produces a continuous, geolocated, content-readable stream of operational aviation messaging worldwide. Military, government, business-jet, medevac, and head-of-state flights all surface in the dataset.

### CPDLC (Controller-Pilot Data Link Communications)

Text-based replacement for voice ATC instructions. Used in oceanic, en route (FANS-1/A and ATN/B1 variants), and increasingly terminal-area airspace.

- **No application-layer authentication or encryption** in the deployed CPDLC base. Logon includes aircraft- and ATSU-identifier exchange but no cryptographic verification.
- **Attack surface**: any actor with an SDR in range of the relevant VHF or SATCOM frequencies can monitor messages, attempt injection, or replay captured messages.

The operational mitigation is **pilot verification of received instructions out-of-band** — pilots cross-check unusual CPDLC clearances against the flight plan and against voice ATC. The procedural defense holds for normal operations but is brittle under coordinated attack against multiple aircraft simultaneously.

### ADS-B Out and ADS-B In

**Automatic Dependent Surveillance — Broadcast**. Aircraft autonomously broadcast position, altitude, speed, heading, and identifier on **1090 MHz Mode S Extended Squitter** (commercial transport) or **978 MHz UAT** (general aviation in the US). Mandated for most US airspace since 1 January 2020 under FAA NextGen, and similarly in EU under SESAR.

- **Broadcast-only, no authentication**: any actor with a 1090ES-capable transmitter can emit a valid-form ADS-B message claiming to be any aircraft at any position.
- **Receivers do not check provenance**: ground ATC fusion, aircraft TCAS, and ground-based ADS-B aggregators (FlightRadar24, ADS-B Exchange, OpenSky) all accept whatever they receive.

The empirical attack surface (Costin 2012, Haines & Foster 2012, Teso 2013, Strohmeier et al.):

1. **Ghost-target injection**: insert phantom aircraft into ATC and cockpit displays.
2. **Aircraft disappearance**: jam or flood the 1090 MHz band so legitimate broadcasts are missed.
3. **Identifier spoofing**: claim to be a specific aircraft.
4. **Trajectory modification**: gradually drift a real aircraft's reported position.

The structural defenses are not in ADS-B but **alongside it**: multilateration (TDoA-based position cross-check), primary surveillance radar, Mode S, and ground-based fusion logic that flags inconsistencies.

### TCAS / ACAS

Mandatory equipment on most commercial transport aircraft since the 1990s. TCAS uses **Mode S interrogations and replies** (1030/1090 MHz) to compute relative aircraft positions and issue **Traffic Advisories (TA)** and **Resolution Advisories (RA)** to pilots. RAs are commands that pilots are trained to immediately follow.

- **No cryptographic authentication on Mode S replies**. TCAS spoofing is a real attack surface (Longo et al., USENIX Security 2024; Pen Test Partners 2020).
- **Spoofing distance**: up to 4.2 km demonstrated with commercial off-the-shelf SDR hardware.
- **Consequence**: an injected colliding-target RA forces a pilot to maneuver. In dense traffic, a cascade of spoofed RAs across multiple aircraft could create real conflict from synthetic data.

The defensive case is **TCAS II Hybrid Surveillance and ACAS X** — newer generations that fuse Mode S with passive ADS-B and have richer consistency-checks against position implausibility.

### VDL Mode 2, HF Data Link, SATCOM

**VDL Mode 2** is the 31.5 kbit/s VHF bit-pipe under terminal-area ACARS and CPDLC; D8PSK modulation; no application-layer cryptography. **HF Data Link** is long-range oceanic data link operated by ARINC and SITA across HF bands with adaptive frequency selection. **SATCOM** in aviation uses Inmarsat (Classic Aero, SwiftBroadband, Jet ConneX, GX Aviation) and Iridium (Iridium Aviator), with recent entrants Viasat, Intelsat, and Starlink Aviation. Cross-link `wireless_rf_satellite_security_expertise.md`.

### "Your aircraft's position is publicly broadcast"

The combination of ADS-B mandate and crowdsourced receiver networks means that essentially every commercial transport flight worldwide is publicly trackable in near real-time. **OSINT on government, military, business-jet, and head-of-state movements** is trivial. The historical regulatory response was the **FAA LADD program** (Limiting Aircraft Data Displayed) and **PIA program** (Privacy ICAO Address); effectiveness is partial, persistent OSINT analysts route around it.

### FAA NextGen and SESAR

**NextGen** (FAA, mandate ramp through 2020) and **SESAR** (EU) are the parallel ATC-modernization programs that mandated ADS-B Out, CPDLC adoption, and Performance-Based Navigation. Notable for *codifying as mandatory* the unauthenticated protocols (ADS-B, CPDLC-without-crypto) that the research community had already shown to be weak. The defensive posture rests on layered defenses rather than fixing the underlying protocols, which would have required global re-certification of every receiver in service.

---

## V. In-Flight Entertainment (IFE) and Connectivity

### IFE architecture

Modern commercial-transport IFE systems are computer networks installed in the cabin. Major suppliers: **Panasonic Avionics** (largest), **Thales InFlyt**, **Collins Aerospace**, **Astronics**, **Bluebox**. A typical wide-body installation has a head-end server in the avionics bay, a distribution network (often switched Ethernet or USB-over-fiber) to each seat, seat-back display units with embedded compute (often ARM Linux), USB port, audio jack, often Ethernet, optional cabin Wi-Fi, and optional ATG/SATCOM Internet.

### The separation question

The OEM threat-model claim is that the IFE network is **physically and logically separated** from the avionics networks. **Domain definitions** under ARINC 664 / DO-326A divide aircraft networks into four domains: Aircraft Control Domain (ACD; flight-critical), Airline Information Services Domain (AISD; operational), Passenger Information and Entertainment Services Domain (PIESD; cabin), Passenger-Owned Devices Domain (PODD; BYO). **Bridges** exist between domains for legitimate reasons (e.g., flight-route maps showing on IFE need real-time aircraft position). The bridges are supposed to be **one-way data diodes** or **filtered gateways**, but historical disclosures have shown they are imperfect in practice.

The current best-practice architecture uses **Aircraft Interface Devices (AIDs)** or **Cabin/Flight-Deck Servers** as explicitly bounded gateways with strict input validation, signed-firmware updates, and audit logging.

### In-flight Wi-Fi

The cabin Wi-Fi network is a normal Wi-Fi access-point fleet (typically 2.4/5 GHz, WPA2/WPA3), bridged to either an **ATG** ground-station network or a **SATCOM** uplink. Major providers: Gogo (ATG legacy, now Intelsat), Viasat, Inmarsat (GX Aviation), Panasonic, SpaceX Starlink Aviation. Same Layer 2 / Layer 3 attack surface as any other Wi-Fi; the upstream link is the interesting bit. Santamarta's 2014/2018 SATCOM work is the canonical demonstration that "cabin Wi-Fi as an entry point" is not theoretical.

### Chris Roberts 2015 — the controversy and what it surfaced

The Roberts case (§I) is the field's most-cited disclosure controversy. The disclosure consequences:

- The **specific kinetic claim** was not technically substantiated.
- The **general direction** (IFE-to-avionics network paths existed on some aircraft) was corroborated by GAO-15-370 (April 2015) and OEM internal reviews.
- The **legal precedent** chilled the public-disclosure culture for years afterward.

### Aircraft Interface Device (AID)

An AID sits between the EFB and the aircraft data buses, translating ARINC 429 / ARINC 664 traffic into a JSON-or-similar feed the EFB can consume. The AID is the most consequential single device in the modern EFB-to-avionics integration story:

- **Threat model**: a compromised AID can in principle inject crafted data into the avionics-side buses (subject to bus-direction and validation rules).
- **Defenses**: signed firmware, dataflow-validation, output filtering, isolation from any return-path from EFB to bus.
- **Reality**: AID quality varies. Some vendors (navAero, CMC Electronics, Astronics, Esterline) take the gateway role seriously; others ship lower-assurance hardware where the airline integrator carries the security burden.

The AID is *defined* to be a bridge: it has to expose aircraft data to a less-trusted device (the EFB) and accept some data back. The security depth required is comparable to that of an ICS-DMZ jump host (cross-link `ics_ot_security_expertise.md` §II).

### USB-to-IFE attack surface

Many seat-back IFE units expose a USB port for charging. The combination of USB physical reach and embedded Linux has produced multiple disclosures of trivial USB-host compromise. OEM mitigation has been to disable host-mode on the USB port (charging only, no enumeration); enforcement varies by fleet age.

---

## VI. Electronic Flight Bag (EFB)

EFBs replaced the paper "flight bag" (charts, manuals, checklists, performance calculations) with a tablet or laptop. The transition started in the early 2000s and is essentially complete on commercial transport by 2026. **Class 1/2/3 EFB** classification:

- **Class 1**: portable, not mounted, no aircraft data connectivity or dedicated aircraft power.
- **Class 2**: portable, may have aircraft connectivity (typically tablet with mounting bracket and aircraft-power port).
- **Class 3**: installed avionics, full aircraft integration, airworthiness certified.

The dominant deployment is **Class 2 iPads** with airline-provided apps used for performance calculations, navigation charts (Jeppesen, Lido, LATITUDE), and ops messaging.

### The EFB attack surface

1. **Tablet hardening**: iPad MDM is sometimes optional or weak. Pen Test Partners and others have documented PIN-only-4-digit, no remote-wipe, sideloaded apps, and pilot-owned devices outside MDM.
2. **App supply chain**: EFB apps are distributed via Apple Business Manager, Google Play, or vendor-private channels. Vendor-private channels often lack the security review of major app stores. Pen Test Partners disclosed disabled certificate validation (App Transport Security turned off) in **Airbus NAVBLUE Flysmart+ Manager**, reported to Airbus in June 2022 and published in February 2024.
3. **Network attack surface**: EFBs connect to airline networks (often via airport Wi-Fi), to OEM cloud services, and to the AID. Each is a separate trust boundary.
4. **AID interface**: see §V.
5. **Database integrity**: navigation databases, terrain databases, performance databases — all critical inputs to the EFB's calculations. The structural defense is signed databases distributed by the OEM through the EFB app's update channel.

### EFB malware as bridge into FMS

The worst-case EFB compromise scenario is **malware on a flight crew's tablet that uses the AID to inject crafted data into the Flight Management System**. The FMS is a high-trust device that computes flight paths and feeds the autopilot. Successful exploitation requires both EFB compromise *and* AID weakness *and* FMS input-validation weakness — but each link is plausibly compromisable individually, and the defense-in-depth argument hinges on no single link being trivially compromisable.

The defenses are EFB hardening (MDM, app signing, OS patching), AID input validation, and FMS input-validation hardening. The practical state: the EFB layer is the weakest, the AID layer is variable, the FMS layer is generally well-hardened. Cross-link `mobile_security_expertise.md` for the tablet-fleet management discipline.

### Public-Wi-Fi EFB download

A recurring failure mode: pilots download EFB updates over public airport or hotel Wi-Fi, which is a hostile network. The structural defense is **certificate pinning, signed app updates, and signed navigation-database content**; enforcement varies by airline and app.

---

## VII. Air Traffic Control (ATC) Systems

The US ATC system is operated by the FAA. Major components:

- **ARTCCs (Air Route Traffic Control Centers)** — 20 facilities in the contiguous US covering en route airspace. Runs **ERAM** (En Route Automation Modernization) replacing the legacy HOST mainframe in 2015.
- **TRACONs (Terminal Radar Approach Control)** — terminal-area control. Runs **STARS** (Standard Terminal Automation Replacement System); legacy ARTS in some facilities.
- **ATCT (Airport Traffic Control Tower)** — runway and immediate-vicinity. Increasingly digital with surface-surveillance (ASDE-X, ASSC).
- **ATCSCC (Air Traffic Control System Command Center)** — strategic flow management.

The European structure is similar but distributed: **EUROCONTROL** at the network level, national ANSPs (DFS, DSNA, NATS, ENAV, Aena), with SESAR coordinating modernization. Major ATC automation vendors: Leidos, Raytheon Technologies, Indra, Thales, Frequentis.

### Legacy substrate

Significant portions of the US ATC infrastructure run on platforms designed in the 1980s and 1990s, modernized through ERAM and STARS but inheriting application code and operational procedures from prior generations. The cybersecurity posture is correspondingly uneven.

### TFR trust model

FAA Temporary Flight Restrictions are issued via FAA NOTAM channels. The trust model assumes that NOTAMs are issued by authorized FAA personnel only; the dissemination channel has had reliability issues historically (the January 2023 nationwide ground stop due to a corrupted NOTAM database file — not a cyber attack, but illustrative of single-point dependencies).

### Spoof-an-ADS-B-target-to-cause-TCAS-RA

The compound attack discussed in academic literature: spoof an ADS-B target near a real aircraft → ATC fusion shows the ghost → real aircraft's TCAS doesn't see the ghost (because TCAS uses Mode S interrogation/reply, not ADS-B Out broadcasts directly) → ATC issues conflicting voice instructions. The pure-TCAS-attack variant (Mode S reply spoofing) is the 2024 USENIX paper; the combined attack — exploiting both ATC-side ADS-B reliance and pilot-side TCAS RA-following discipline — is plausible but has not been publicly demonstrated against operational aircraft. Defensive case rests on multilateration, primary radar, controller skepticism, pilot SOP for unusual RAs, and ACAS X.

---

## VIII. Drone (UAS) Security

### Consumer drones

**DJI** (Shenzhen) is the dominant consumer/professional drone manufacturer worldwide. The Mavic, Mini, Air, and Phantom families and the Matrice professional series ship with GPS/GNSS-based positioning, **OcuSync / LightBridge proprietary RF link** (2.4/5 GHz, AES-encrypted) between drone and controller, DJI mobile app, **geofencing** (No-Fly Zones in firmware), and **DJI Cloud** integration for flight logs and AeroScope identification.

The DJI firmware ecosystem has been the target of consistent reverse-engineering and modding since the mid-2010s. The 2017 disclosure of hardcoded private keys in DJI app source code (Kevin Finisterre) led to DJI's eventual hardening but also raised national-security concerns around DJI's data-handling that drove the 2018 US DoD ban on DJI products and the 2024 "Countering CCP Drones Act" debate.

### Commercial / professional and military drones

**Skydio** (US), **Parrot** (France), **Yuneec**, **Autel Robotics** (China), **EHang** (China, eVTOL). Skydio is the most prominent US-domestic alternative, with heavy autonomy focus. Cross-link `adversarial_ml_model_security_expertise.md`.

Military / dual-use: **Bayraktar TB2** (Turkey), **Shahed-136** (Iran), **Switchblade 300/600** (US, AeroVironment), **MQ-9 Reaper** and **MQ-1 Predator** (US, General Atomics), **RQ-170 Sentinel** (US, Lockheed Martin). The military-UAV security model is classified at most levels; public discussion focuses on the 2009 Predator video-link interception (unencrypted; $26 SkyGrabber) and the 2011 Iran RQ-170 capture.

### Iran RQ-170 (2011) — disputed GPS spoofing claim

On 5 December 2011, an RQ-170 was captured near Kashmar, Iran. Iran claimed it brought the UAV down by **GPS spoofing**, feeding false position data to make the drone land at what it thought was its home base in Afghanistan. The Iranian narrative is **disputed** by aviation engineers: RQ-170 navigation uses inertial navigation as primary, GPS as secondary, and INS is essentially unjammable. The disputed-but-public account illustrates the broader concern that GPS-dependent military drones are vulnerable to electronic warfare.

### Remote ID (FAA Part 89)

Mandatory in the US since 16 September 2023. Drones registered under 14 CFR Part 47 or 48 must broadcast Remote ID — identification and location information receivable through Bluetooth or Wi-Fi broadcast. Three compliance options: Standard Remote ID (built-in), Remote ID Broadcast Module (retrofit), or operation in a FAA-Recognized Identification Area (FRIA).

Security and privacy implications: **Aviation safety win** (law enforcement can identify drones in restricted areas). **Operator-privacy concern** (drone operations publicly broadcast). **Spoofability**: like ADS-B, Remote ID lacks cryptographic authentication.

### Drone jamming, GPS spoofing, C-UAS

GPS jamming and command-link jamming have been **mass-deployed** in the 2022-2026 conflict zones. Countermeasures: inertial navigation, visual-inertial odometry (Skydio can operate GPS-denied via vision/INS), terrain-matching, hardened RF links.

GPS spoofing against commercial drones has been observed in conflict zones, near airports, and maritime contexts. The structural defense is **multi-constellation GNSS** (GPS + GLONASS + Galileo + BeiDou cross-checking), **GNSS authentication** (Galileo OSNMA — Open Service Navigation Message Authentication, Initial Service declared July 2025), and **integrity monitoring** at the receiver. Cross-link `wireless_rf_satellite_security_expertise.md` §6.

Counter-UAS vendors: **DroneShield**, **Dedrone**, **Anduril** (Lattice mesh, Anvil interceptor), **Echodyne**, **D-Fend Solutions** (protocol-level take-over of consumer drones). The C-UAS product space *exploits* protocol weaknesses in consumer-drone command links on the defensive side. Cross-link `wireless_rf_satellite_security_expertise.md` §7.

---

## IX. Space-Asset Cybersecurity

### The aging-satellite problem

A typical GEO communications satellite has a 15-25 year operational lifetime. Satellites in service in 2026 were designed in 2000-2010, with compute substrates and software comparable to vintage embedded systems of those eras — radiation-hardened processors (RAD750, LEON-class SPARC), small memory, and software written in Ada, MISRA-C, or assembly. Cybersecurity posture is generally:

- **No TT&C authentication beyond shared-key encryption** where deployed. Many older satellites use unencrypted TT&C with operational-procedure-based controls.
- **No software-update channel** in many cases; the satellite ships with its launch firmware for its operational life.
- **Trust in the ground station** as the sole interaction point. If the ground station is compromised, the satellite is.

### Ground-station compromise as gateway

The dominant space-asset attack vector in 2026 is **compromise of the ground segment** — the network operations center, the antenna sites, the mission-control software. Once the attacker is on the ground-segment network, the spacecraft is reachable through legitimate command channels.

### Viasat / KA-SAT AcidRain (24 February 2022)

The canonical case study and the most consequential space-asset cyber incident to date.

- **Target**: Viasat KA-SAT satellite broadband service, operated by Eutelsat. Tens of thousands of fixed-broadband customers across Ukraine and Europe; some operational customers including a large wind-turbine fleet in Germany.
- **Method**: attacker accessed the KA-SAT management mechanism (the back-office network that pushes configuration to user modems), then used legitimate management commands to deploy **AcidRain**, a wiper malware targeting the Surfbeam2 / Viasat modem firmware.
- **Effect**: modems rendered inoperable across Ukraine and parts of Europe. The attack landed **one hour before the Russian invasion of Ukraine** began. Spillover: 5,800 Enercon wind turbines in Germany lost remote-monitoring connectivity.
- **Attribution**: EU and Five Eyes attributed the attack to Russia. SentinelOne assessed with medium confidence that AcidRain shares developmental similarities with a VPNFilter stage 3 destructive plugin.
- **Analysis**: SentinelOne (Juan Andres Guerrero-Saade and Max van Amerongen) published the canonical technical breakdown. The malware was a MIPS ELF binary (the Surfbeam2 modem CPU architecture) that brute-forced device file paths and wiped every file it could find.

The structural lessons:

1. **Ground segment is the dominant attack surface**, not the spacecraft itself.
2. **Legitimate management channels are weapons**: the attack used Viasat's own modem-management mechanism.
3. **Spillover is unpredictable**: civilian wind turbines in Germany were knocked out by an attack on Ukrainian satellite-broadband customers.
4. **Modem firmware needs the same care as endpoint firmware**: signed updates, integrity verification, recovery paths.

### LEO satellite security

LEO constellations are a different security model from GEO: thousands of small spacecraft, frequent replenishment, software-update channels designed in from the start. Cross-link `wireless_rf_satellite_security_expertise.md`. Starlink ground segment includes hundreds of gateway sites, NOCs, and the customer portal — all parts of the attack surface. **User-terminal compromise** (Wouters 2022) lets a researcher root the dish but doesn't yield constellation-control access. Starlink in Ukraine (2022-2026) operates under explicit security pressure: Russian electronic warfare, requested government access by allied governments, terms-of-service decisions with operational consequences.

### CubeSat security and Space ISAC

The CubeSat market is heavily university and small-commercial driven. Security practices vary wildly. Many CubeSats ship without authenticated TT&C; the practical defense being "the attacker has to acquire and operate a ground station capable of communicating with the spacecraft, which is non-trivial." US **Space ISAC** is the institutional analog of Auto-ISAC and E-ISAC — sector-specific threat intelligence sharing across commercial space operators, defense, and intelligence.

### NASA cybersecurity disclosures

- **JPL 2018 breach** — a Raspberry Pi on JPL's network gave attackers a 10-month foothold, exfiltrating ~500 MB including some Mars-mission material.
- **Voyager 1 anomaly 2024** — *not* a cyber incident, but a software anomaly in 46-year-old Voyager 1 software (Flight Data Subsystem) that took NASA engineers months to diagnose and remotely patch. Illustrates the *extreme* longevity of operational space-asset software.
- **JAXA 2023** — Japan Aerospace Exploration Agency breach (summer 2023, detected later). Attackers accessed JAXA's Active Directory and Microsoft 365 environment via VPN and M365 vulnerabilities. Launch-vehicle and satellite-operations data reportedly not accessed; corporate and personal data was. Attribution: state-affiliated, most observers pointing to China.

### Private launch

The 2010s-2020s growth of commercial spaceflight (SpaceX, Rocket Lab, Blue Origin, Relativity, Axiom, Sierra Space) brought new ground-segment and avionics targets: launch-vehicle avionics, crew capsules with onboard networks, ground-segment automation. The recurring pattern: commercial spaceflight inherits the same cybersecurity challenges as commercial aviation, with a younger industry-wide security posture.

---

## X. Aviation Incident Corpus

### Hugo Teso 2013 — "Aircraft Hacking: Practical Aero Series" (HITB Amsterdam)

The first comprehensive public demonstration of attacker-controlled input into FMS-class software via ACARS and ADS-B abuse. Conducted against a PC-based training simulator, not certified flight hardware. Established the field's threat model: broadcast aviation data links are attacker-controlled input to safety-critical software, not benign transports.

### Chris Roberts 2015 — United Airlines / FBI

April-May 2015: Roberts tweeted from a flight that he was probing IFE systems; FBI met the flight, detained him, seized equipment. The disputed kinetic claim (lateral motion from cyber input) was not technically substantiated, but the case became the canonical example of (a) IFE-to-avionics network paths existing on some aircraft, (b) the legal hazards of aviation research, and (c) the absence of a formal coordinated-disclosure framework at the time. Major OEMs and the FAA subsequently built formal CVD programs.

### Polish LOT June 2015 — DDoS against ground operations

21 June 2015: Polish flag carrier LOT's ground-side flight-plan-generation system was hit with a DDoS attack at Warsaw Chopin Airport. The system was unable to produce flight plans for departing aircraft; 10 flights cancelled and about a dozen delayed, ~1,400 passengers affected. Resolved in ~5 hours. **Aircraft in flight were not affected**; the attack was against ground IT, not avionics. First publicly-acknowledged cyber attack against airline operations that caused operational disruption.

### Pen Test Partners EFB / IFE corpus (2016-2026)

A decade of cumulative disclosures: Boeing 747 in-flight Wi-Fi reachable to cabin systems; Airbus A330/A340 IFE seat-back compromises; EFB app issues (NAVBLUE Flysmart+ Manager, others); 747 maintenance-laptop security; TCAS-spoofing demonstrations. The cumulative effect keeps operational aviation cybersecurity in front of regulators and OEMs.

### Patrick Kiley 2019 — CAN-bus attacks on general aviation

30 July 2019: Rapid7 disclosure of CAN-bus injection attacks on small-aircraft avionics. DHS/CISA issued ICS-ALERT-19-211-01. First formal recognition that general aviation has the same CAN-bus trust-model problem as automotive.

### Boeing 737 MAX MCAS (2018-2019)

Not a cybersecurity incident in the strict sense — MCAS was a software-design and certification-process failure that led to two fatal crashes (Lion Air 610, Ethiopian 302; combined 346 fatalities), the worldwide grounding of the 737 MAX fleet, and major changes to FAA Type Certification process. Studied in the cybersecurity literature because it illustrates the same risk class: **safety-critical software with insufficiently independent oversight, single-sensor input dependency, and pilot-procedural assumptions that didn't hold under adversarial-like sensor behavior**. Cross-link `code_review_expertise.md`.

### Viasat / KA-SAT AcidRain (24 February 2022)

See §IX. The most consequential cyber attack on a space-asset to date.

### JAXA 2023 breach

See §IX.

### Lennert Wouters / Starlink user terminal (August 2022)

Voltage fault-injection attack on a Starlink user terminal yielding code execution. ~$25 modchip. SpaceX response (bug-bounty incorporation, public engagement) is the canonical example of how a modern space-internet operator should engage with external research.

### CrowdStrike outage 19 July 2024

Not malicious — a faulty CrowdStrike Falcon Sensor content update caused Windows hosts running the agent to crash worldwide. ~8.5 million systems affected. **Delta Air Lines was uniquely impacted**: 7,000+ flight cancellations over five days, $500M claimed business impact, ~1.3M passengers affected, subsequent lawsuit against CrowdStrike. Other carriers recovered in hours; Delta took five days. Studied as the canonical software-supply-chain instability case for the aviation industry: a single shared dependency in airline crew-scheduling and ops systems caused fleet-grounding-equivalent operational consequences. Cross-link `cicd_supply_chain_expertise.md`.

### Aviation supply-chain ransomware (2022-2026)

Continued cadence of ransomware against aviation suppliers, airport ground-handling firms, MRO shops. Cumulative trend: long-tail supply-chain dependency of major airlines on cleaning, catering, baggage, and IT-support vendors driving intermittent operational disruption.

---

## XI. Regulatory and Standards Landscape

### National-aviation authorities

- **FAA** (US) — type certification, operational regulation, ATC operation.
- **EASA** (EU) — type certification and operational regulation across EU member states.
- **CAAC** (China). **DGCA** (India), **JCAB** (Japan), **CASA** (Australia), **TCCA** (Canada), **ANAC** (Brazil) — other major national authorities.
- **ICAO** — UN body publishing Standards and Recommended Practices (SARPs) that national authorities largely adopt.

### RTCA / EUROCAE airworthiness-security standards

The aviation cybersecurity standards canon is jointly produced by **RTCA Special Committee 216 (SC-216)** and **EUROCAE Working Group 72 (WG-72)**, both titled "Aeronautical Systems Security."

- **DO-326A** (Airworthiness Security Process Specification, 2014; EUROCAE ED-202A) — the foundational document. Defines the **Plan for Security Aspects of Certification (PSecAC)**. Establishes the **threat modeling, vulnerability assessment, and risk-management** processes that integrate with the safety case.
- **DO-356A** (Airworthiness Security Methods and Considerations, 2018; EUROCAE ED-203A) — methods for performing the DO-326A activities. Defines threat scenarios, attack paths, and consequence evaluation.
- **DO-355A** (Information Security Guidance for Continuing Airworthiness; EUROCAE ED-204A) — guidance for operators on maintaining the security posture of in-service aircraft.
- **DO-178C** (Software Considerations in Airborne Systems and Equipment Certification, 2011) — the core software-certification standard. Five Design Assurance Levels (DAL A = catastrophic, DAL E = no safety effect). Critical avionics typically certify to DAL A or B.
- **DO-254** — hardware-side counterpart to DO-178C.

### EASA equivalents and FAA Advisory Circulars

EASA: **ED-202A / ED-203A / ED-204A / ED-205** — European mirrors of the RTCA standards. Effectively-identical through joint authoring. **AMC 20-42** — EASA Acceptable Means of Compliance for aircraft cybersecurity-related certification.

FAA: **AC 20-115D / 20-152A / 20-174** — software, complex hardware, certification ACs. **AC 119-1A** — Operational Authorization of Aircraft Network Security Program (replaced AC 119-1, cancelled 2023). **FAA NextGen ADS-B Mandate** — 14 CFR 91.225/91.227, requiring ADS-B Out compliance in most US controlled airspace from 1 January 2020.

### Space-segment standards

- **NIST IR 8270** (Introduction to Cybersecurity for Commercial Satellite Operations, July 2023) — applies NIST Cybersecurity Framework to commercial satellite operators.
- **NIST SP 800-53** — generic baseline applicable to space-asset operators.
- **CISA Space Systems Critical Infrastructure** — emerging program.
- **CCSDS** (Consultative Committee for Space Data Systems) — international standards body for space-data protocols, including **SDLS** (Space Data Link Security) for authenticated/encrypted TT&C.

### ICAO and global coordination

- **ICAO Annex 17** (Security — Safeguarding International Civil Aviation Against Acts of Unlawful Interference) — international counter-terrorism baseline, increasingly extended to cyber threats.
- **ICAO Aviation Cybersecurity Strategy** + Cybersecurity Action Plan (CyAP).
- **TSA** is the relevant federal authority for aviation cybersecurity at the operator/airport level; cybersecurity directives for airlines issued in 2023-2026.
- **Aviation ISAC (A-ISAC)** — sector-specific threat intelligence sharing across airlines and aviation operators.

---

## XII. Defensive Architecture

### Network domain segmentation

The ARINC 664 / DO-326A four-domain model: **Aircraft Control Domain (ACD)** (flight-critical avionics), **Airline Information Services Domain (AISD)** (operational data), **Passenger Information and Entertainment Services Domain (PIESD)** (IFE, cabin Wi-Fi), **Passenger-Owned Devices Domain (PODD)**.

Cross-domain communication is restricted to defined paths through defined gateways with the **trust-flow direction**:

- ACD → AISD: occasional, controlled.
- AISD → ACD: rare, heavily-controlled (FMS database updates with signed packages).
- PIESD ⇄ ACD: **prohibited** by current best practice.
- PIESD → AISD: limited, gateway-mediated.
- PODD ⇄ all others: filtered, untrusted.

### Aircraft Interface Device (AID) as data-diode-style gateway

Modern AIDs explicitly implement (a) read-only views of aircraft data exposed to less-trusted networks, (b) cryptographic signing of any data that does flow inward, (c) audit logging of all cross-domain transactions, (d) firmware signature verification. Cross-link `cicd_supply_chain_expertise.md`.

### Code-signing on uploaded firmware

Modern avionics firmware is signed by the OEM and verified by the LRU before execution. The supply chain for the signing keys is high-assurance (HSM-backed, multi-party authorization). Cross-link `supply_chain_provenance_expertise.md` and `cryptography_expertise.md`. Older LRUs may not enforce signature verification; the **upload mechanism itself** (data-loader cart, maintenance laptop) is the historical attack surface.

### OTA update of avionics

Over-the-air update of safety-critical avionics is **rare** in commercial transport. The dominant model is **physical media plus maintenance personnel**: a maintenance technician brings a data-loader cart to the aircraft, connects to a maintenance port, and uploads signed firmware after offline verification. Some newer aircraft (787, A350) have introduced limited OTA for non-flight-critical components; flight-critical OTA is still an open question.

### Avionics SBOM

**Emerging requirement, not yet mandatory.** The DO-326A / DO-355A workflow effectively requires SBOM-like documentation for certification, but formal SBOM standardization in aviation lags broader industry adoption (cross-link `supply_chain_provenance_expertise.md` and `cicd_supply_chain_expertise.md`). EU Cyber Resilience Act and US EO 14028 are pushing SBOM adoption industry-wide; aviation regulators are integrating but slowly.

### Crew procedure as defensive layer

A defining feature of aviation cybersecurity is that **the flight crew is part of the defensive architecture**. Pilots are trained to recognize anomalous automation behavior, to manually override autopilots in defined failure modes, to cross-check ATC instructions, and to maintain situational awareness independent of automation. The crew procedure is the last line of defense against many cyber attack classes — an attacker who corrupts a navigation database may still be defeated by a crew that cross-checks the FMS against paper charts and ATC voice.

The cyber-versus-procedure tradeoff is explicit in the safety case: a class of cyber attacks is mitigated by crew procedure if and only if the crew procedure is robust under the attack conditions (which it usually is, by design).

### Defense-in-depth as airworthiness requirement

DO-326A explicitly requires defense-in-depth. **It is not optional**. The certification documents must demonstrate that no single failure (whether random or adversarial) can produce a catastrophic outcome.

### Code review checklist for avionics software work

1. **Threat-model in safety-case vocabulary**: every finding maps to a hazard, with severity expressed via DO-178C DAL or DO-326A consequence levels.
2. **Defense-in-depth check**: no critical assertion relies on a single layer.
3. **Input-validation rigor at all trust boundaries**: ACARS messages, ADS-B receives, CPDLC clearances, AID input, EFB-provided data, navigation-database content, all sensor inputs.
4. **Cryptographic primitives appropriate to the threat model**: AES-256, SHA-256/384, ECDSA P-256/384. Legacy DES, SHA-1, MD5 not acceptable in new designs.
5. **Replay protection on all authenticated channels**.
6. **Audit logging of all cross-domain transactions**.
7. **Signed firmware on all LRUs and gateways**.
8. **No hardcoded credentials, no debug backdoors, no commented-out secrets**. Cross-link `code_review_expertise.md`.
9. **Memory-safety discipline**: MISRA-C compliance or memory-safe languages (Ada/SPARK, Rust where certification allows).
10. **Fail-safe defaults**: if any input cannot be validated, revert to a known-safe state.
11. **Crew-overridability**: every automated function should have a clearly-documented manual override path.
12. **Compatibility with crew SOP**: design must not require behavior outside trained SOPs even under adversarial conditions.

---

## XIII. Detection and Incident Response for Aviation

### The "aviation IR is not IT IR" reality

A cyber incident on an aircraft is investigated through the same machinery that investigates any aviation incident:

1. **Initial response** — flight crew ensures safe state, follows procedure, lands at nearest suitable airport.
2. **Operator response** — maintenance, inspection, airworthiness decision.
3. **National-aviation-authority involvement** — FAA Aircraft Certification Office, EASA equivalents.
4. **OEM involvement** — Type Certificate Holder is notified and engaged.
5. **Independent investigation** — NTSB (US), BEA (France), AAIB (UK), JTSB (Japan) leads on safety incidents/accidents.
6. **Forensics** — flight-data recorder, cockpit voice recorder, ACARS message logs, ground-station logs, ATC transcripts, maintenance logs.
7. **Airworthiness Directive process** — fleet-wide issues issued through the regulatory pipeline.

The end-to-end timeline for a published cyber-incident-and-mitigation cycle is months to years. Cross-link `dfir_methodology_expertise.md` §10.

### "Anomalous ADS-B target" detection

ATC, OpenSky-style ground receiver networks, and aircraft fusion logic all do forms of ADS-B anomaly detection. Signatures: position-implausibility (impossible altitude/speed, instant teleports), identifier-uniqueness violations (two targets with same hex ICAO address), multilateration disagreement with reported position, primary-radar return inconsistency. Crowdsourced networks (FlightRadar24, ADS-B Exchange) have visibility into broader spoofing patterns.

### IFE-domain anomaly detection

Emerging discipline. Airlines and OEMs are starting to deploy network-anomaly monitoring on cabin/IFE networks (IDS/IPS appliances, NDR for cabin networks). Signal-to-noise issue is significant: cabin Wi-Fi traffic includes legitimate consumer traffic, malware-infected passenger laptops, and IFE-vendor update channels. Cross-link `detection_engineering_expertise.md`.

### EFB malware detection

Standard MDM and mobile-EDR controls apply: device-attestation, app-allowlisting, OS-version enforcement, content-signing verification. Cross-link `mobile_security_expertise.md`. The gap is that pilot-owned-device fleets (BYO Class 1 EFBs) often sit outside MDM.

### Aviation-IR playbook structure

1. **Detection** — typically by crew or by ground systems (ACARS log analysis, IFE-network IDS).
2. **Safety state** — secure the aircraft; this is the *immediate* priority.
3. **Notification** — operator's emergency operations center, OEM, ATC, national-aviation authority.
4. **Forensic preservation** — FDR/CVR, ACARS logs, maintenance data, IFE network captures.
5. **Root-cause analysis** — usually OEM-led with operator and authority participation.
6. **Mitigation** — operational procedure change, software patch (slow), or Airworthiness Directive (slow).
7. **Disclosure** — coordinated, often slow; formal mechanism is the Service Bulletin and AD.

Cross-link `dfir_methodology_expertise.md`.

---

## XIV. Variant Analysis — Under-Explored Surfaces

### AI in cockpit

The FAA / EASA "AI in cockpit" certification debate is active. Existing certification frameworks (DO-178C, DO-326A) assume deterministic software. Machine-learning components — even in operational support roles like predictive maintenance, weather prediction, or pilot decision support — break the deterministic assumption. EASA's **First Usable Guidance for Level 1 Machine Learning Applications** (2021) is the first formal regulatory step.

The cybersecurity angle: cross-link `adversarial_ml_model_security_expertise.md` and `llm_agent_security_expertise.md`. ML models in aviation are adversarial-attack surfaces (model poisoning, evasion, model-extraction), and the certification machinery doesn't yet have a satisfactory threat-model framework for them. The "agent with flight authority" discussion is academic for now — current AI in the cockpit is bounded to decision-support, with the pilot retaining final authority on every action. The structural question — *can a learning system be certifiable at DAL A?* — is open.

### Urban Air Mobility (eVTOL)

The emerging passenger-eVTOL market — **Joby Aviation**, **Archer Aviation**, **Lilium**, **Vertical Aerospace**, **EHang**, **Eve Air Mobility** — is producing a new class of aircraft with heavy reliance on fly-by-wire and software flight controls, substantial autonomy targets, heavy connectivity (cellular, V2X-style fleet coordination), and new certification frameworks (FAA Special Class, EASA SC-VTOL).

The cybersecurity surface is essentially the union of consumer-drone, automotive-ADAS, and commercial-aircraft surfaces — making eVTOLs an interesting integration target for adversarial researchers and a non-trivial certification problem for regulators. Cross-link `automotive_security_expertise.md` §V (ADAS) and `adversarial_ml_model_security_expertise.md`.

### General aviation cybersecurity

The Patrick Kiley 2019 disclosure surfaced general aviation as a domain. Continuing concerns: **Garmin, Avidyne, Dynon, Aspen Avionics** integrated-cockpit products use CAN-bus-derived buses with limited cryptographic protection; **ADS-B Out** is mandatory for general aviation as well; **maintenance practices** are less rigorous than in commercial transport. Market structure (small operators, owner-operated, limited industry-wide coordination) makes regulatory progress slower than commercial transport.

### Aviation maintenance system integration

MRO IT systems — **IBM Maximo**, **Trax**, **AMOS**, **Ramco** — are increasingly integrated with aircraft via OEM cloud services and AID-mediated data feeds. The cybersecurity model is generally enterprise-IT-style, but with the added consequence that compromised maintenance data could feed false work orders or hide actual mechanical issues.

### Crewless cargo aircraft

**Reliable Robotics**, **Xwing**, **Merlin Labs** — emerging market for crewless cargo aircraft. The certification path is unsettled. The cybersecurity model needs to address full autonomy without the crew-as-defense layer that commercial transport relies on.

### Spaceflight and private launch

Cross-link §IX. Continued growth of private spaceflight is creating new ground-segment, launch-vehicle-avionics, and crew-capsule-internal-network attack surfaces.

### V2X for aviation (UTM and aircraft cooperative surveillance)

The Unmanned Aircraft System Traffic Management (UTM) concept and the eVTOL Vertiport-Operations Management concept both require aircraft-to-aircraft and aircraft-to-ground cooperative information exchange. ADS-B-style unauthenticated broadcasts at higher densities (many drones in urban airspace) raise the consequence of spoofing.

### Quantum-resistant cryptography migration

Aviation's long device lifecycles mean that **today's cryptographic decisions ship for 25+ years**. RSA-2048, ECDSA P-256 — currently safe — will be at risk by mid-century if cryptographically-relevant quantum computers materialize. NIST PQC standardization (CRYSTALS-Kyber, CRYSTALS-Dilithium, Falcon, SPHINCS+) is the upstream input. Cross-link `cryptography_expertise.md`.

---

## XV. References

### Researcher contributions and primary disclosures

- Hugo Teso, "Aircraft Hacking: Practical Aero Series" (HITB Amsterdam 2013): https://archive.conference.hitb.org/hitbsecconf2013ams/materials/D1T1%20-%20Hugo%20Teso%20-%20Aircraft%20Hacking%20-%20Practical%20Aero%20Series.pdf
- Hugo Teso talk video: https://www.youtube.com/watch?v=wk1jIKQvMx8
- Ruben Santamarta, "SATCOM Terminals: Hacking By Air, Sea, and Land" (Black Hat USA 2014): https://blackhat.com/docs/us-14/materials/us-14-Santamarta-SATCOM-Terminals-Hacking-By-Air-Sea-And-Land-WP.pdf
- Ruben Santamarta, "Last Call for SATCOM Security" (Black Hat USA 2018): https://www.ioactive.com/article/ioactive-reveals-major-satellite-communication-and-operating-system-vulnerabilities-at-black-hat-usa-2018-def-con-26/
- Andrei Costin, "Ghost in the Air(Traffic)" (Black Hat USA 2012): https://www.s3.eurecom.fr/~costin/
- Patrick Kiley / Rapid7, "Investigating CAN Bus Network Integrity in Avionics Systems" (2019): https://www.rapid7.com/research/report/investigating-can-bus-network-integrity-in-avionics-systems/
- Brad Haines and Nick Foster, "Hackers + Airplanes" (DEF CON 20, 2012): https://defcon.org/images/defcon-20/dc-20-presentations/Renderman/DEFCON-20-RenderMan-Hackers-plus-Airplanes.pdf
- Martin Strohmeier publication page: https://www.cs.ox.ac.uk/people/martin.strohmeier/
- Smith, Moser, Strohmeier et al., "Undermining Privacy in ACARS" (PETS 2018): https://ora.ox.ac.uk/objects/uuid:4ca4c46a-6bff-4f5b-9cdf-62a6f826e0ce
- Lennert Wouters, "Glitched on Earth by Humans" (Black Hat USA 2022): https://i.blackhat.com/USA-22/Wednesday/US-22-Wouters-Glitched-On-Earth.pdf
- Pen Test Partners EFB blog: https://www.pentestpartners.com/security-blog/deploying-efbs-securely/
- Pen Test Partners — NAVBLUE Flysmart+: https://www.pentestpartners.com/security-blog/hacking-electronic-flight-bags-airbus-navblue-flysmart-manager/
- Longo et al., "On a Collision Course: TCAS Attacks" (USENIX Security 2024): https://www.usenix.org/system/files/usenixsecurity24-longo.pdf
- Pen Test Partners TCAS spoofing: https://www.pentestpartners.com/security-blog/jeopardising-aircraft-through-tcas-spoofing/

### Incident analyses

- AcidRain (SentinelOne): https://www.sentinelone.com/labs/acidrain-a-modem-wiper-rains-down-on-europe/
- Viasat confirmation: https://www.bleepingcomputer.com/news/security/viasat-confirms-satellite-modems-were-wiped-with-acidrain-malware/
- KA-SAT incident timeline (EuRepoC): https://eurepoc.eu/publication/major-cyber-incident-ka-sat-9a/
- MIT Technology Review on Viasat: https://www.technologyreview.com/2022/05/10/1051973/russia-hack-viasat-satellite-ukraine-invasion/
- Polish LOT 2015 DDoS: https://threatpost.com/polish-planes-grounded-after-airline-hit-with-ddos-attack/113412/
- Chris Roberts (Schneier): https://www.schneier.com/blog/archives/2015/05/more_on_chris_r.html
- Chris Roberts EFF context: https://www.eff.org/deeplinks/2015/04/united-airlines-stops-researcher-who-tweeted-about-airplane-network-security
- JAXA 2023: https://www.theregister.com/2023/11/29/jaxa_cyberattack/
- Iran-US RQ-170 (Wikipedia): https://en.wikipedia.org/wiki/Iran%E2%80%93U.S._RQ-170_incident
- RQ-170 GPS-spoofing analysis: https://theaviationist.com/2011/12/15/gps-spoofing/
- Delta CrowdStrike disruption: https://en.wikipedia.org/wiki/2024_Delta_Air_Lines_disruption
- Delta CEO on $500M impact: https://www.cnbc.com/2024/07/31/delta-ceo-crowdstrike-microsoft-outage-cost-the-airline-500-million.html

### Standards and regulatory references

- RTCA DO-326A: https://products.rtca.org/21dja1f/
- RTCA security hub: https://www.rtca.org/security/
- FAA NextGen: https://www.faa.gov/nextgen
- FAA Remote ID rules: https://www.faa.gov/uas/getting_started/remote_id
- 14 CFR Part 89 full text: https://www.ecfr.gov/current/title-14/chapter-I/subchapter-F/part-89
- NIST IR 8270: https://csrc.nist.gov/pubs/ir/8270/final
- NIST IR 8270 announcement: https://www.nist.gov/news-events/news/2023/07/introduction-cybersecurity-commercial-satellite-operations-nist-ir-8270
- DO-326A introduction (PTC): https://www.ptc.com/en/blogs/alm/do-326a-an-introduction-to-cybersecurity-safety-in-avaiation-and-aircraft-systems

### Avionics protocols and architecture

- ARINC 664 / AFDX overview: https://www.aim-online.com/products-overview/tutorials/afdx-arinc664p7-tutorial/
- AFDX Wikipedia: https://en.wikipedia.org/wiki/Avionics_Full-Duplex_Switched_Ethernet
- MIL-STD-1553 Wikipedia: https://en.wikipedia.org/wiki/MIL-STD-1553
- MIL-STD-1553 attack detection (Oxford, IEEE TAES 2023): https://www.cs.ox.ac.uk/files/14887/Targeted_Detection_for_Attacks_on_the_MIL-STD-1553_Bus.pdf
- CPDLC Wikipedia: https://en.wikipedia.org/wiki/Controller%E2%80%93pilot_data_link_communications
- CPDLC security paper (MDPI Sensors 2018): https://www.mdpi.com/1424-8220/18/5/1636
- CPDLC practical attacks (ACM CPSS 2021): https://dl.acm.org/doi/10.1145/3457339.3457985
- AID overview (Bytron): https://www.bytron.aero/aviation-news/what-is-an-aircraft-interface-device

### Community resources

- DEF CON Aerospace Village: https://www.aerospacevillage.org/
- OpenSky Network: https://opensky-network.org/
- Aviation ISAC: https://www.a-isac.com/
- Space ISAC: https://spaceisac.org/
- AIAA: https://www.aiaa.org/
- ICAO Aviation Cybersecurity Action Plan: https://www.icao.int/cybersecurity-action-plan

### Cross-domain bibliography

- `ics_ot_security_expertise.md` — safety-critical OT sibling.
- `automotive_security_expertise.md` — CAN-bus and ADAS parallels.
- `firmware_embedded_security.md` — embedded substrate.
- `wireless_rf_satellite_security_expertise.md` — SATCOM and GPS.
- `mobile_security_expertise.md` — EFB mobile-fleet management.
- `supply_chain_provenance_expertise.md` — avionics SBOM and signing.
- `dfir_methodology_expertise.md` — aviation IR adaptation.
- `cryptography_expertise.md` — crypto primitives and PQC.
- `detection_engineering_expertise.md` — anomaly detection.
- `llm_agent_security_expertise.md` — AI-in-cockpit threat model.
- `adversarial_ml_model_security_expertise.md` — ML in autonomous-aviation perception.
- `cicd_supply_chain_expertise.md` — avionics-firmware supply chain.
- `code_review_expertise.md` — secure code review for safety-critical software.
