# Industrial Control Systems and Operational Technology Security
## Staff-Level Technical Reference

---

## I. Researcher Profiles

The ICS/OT security field developed largely outside the mainstream offensive-security community for its first two decades. Most of the names below built reputations through consequence-level analysis (centrifuges, breakers, safety systems) rather than CVE counts. A serious ICS researcher today either came up through process-engineering or instrumentation work in the 1990s, or pivoted from IT-side red-team work after Stuxnet (2010) made the domain interesting to traditional security people. Both lineages are represented below.

### Ralph Langner — Langner Group / OTbase

**Career arc**: German control-system security consultant. Founded what became The Langner Group as an ICS-engineering consultancy in 1988; the firm shifted toward control-system cybersecurity after Stuxnet. Currently CEO of Langner, Inc. and the OTbase asset-inventory product. Non-resident fellow at the Brookings Institution.

**Core contribution**: "To Kill A Centrifuge: A Technical Analysis of What Stuxnet's Creators Tried to Achieve" (Langner Group white paper, November 2013). Deconstructed Stuxnet into two distinct attack routines: the widely-discussed centrifuge-rotor-speed routine, and a second, structurally-more-complex routine that manipulated centrifuge pressure (the "forgotten" routine, roughly an order of magnitude more complex). Langner argued the speed-attack was a noisier follow-on after the pressure-attack failed to achieve its objectives. The report remains the most-cited technical analysis of any ICS incident.

**Frame Langner introduced**: ICS attacks must be reasoned about at the *physical-process* layer, not the *information-system* layer. A network-layer description of Stuxnet ("Windows worm propagating via USB and SMB, dropping a kernel rootkit") fundamentally misses the point; the point is that the centrifuges spin faster than their tubes are rated for and the rotor explodes. Every serious ICS analyst since 2010 inherits this frame. 2011 TED talk ("Cracking Stuxnet, a 21st-century cyber weapon") was the wide-audience version.

### Eric Byres — Tofino Security (founder), Veracity Industrial Networks

**Career arc**: Co-founder and CTO of Tofino Security (acquired by Belden / Hirschmann). Previously founded the BCIT Critical Infrastructure Security Centre in 2001. ISA Fellow (2009); ISA Excellence in Leadership (2013). Joined Veracity Industrial Networks (2019) and the INETCO board. One of two people (the other being Joe Weiss) whose names came up if you searched "SCADA security" in 2001.

**Core contribution**: The Tofino Security Appliance — an ICS-specific firewall with deep packet inspection for Modbus, OPC, EtherNet/IP, DNP3, and other industrial protocols. First commercially-successful product to inspect ICS protocols at function-code granularity (e.g., allow Modbus function code 3 "read holding registers" but block function code 6 "write single register" between two zones). Licensed by Honeywell and Schneider Electric. Predates the OT-aware-firewall category by roughly a decade.

**Frame Byres introduced**: ICS firewalls cannot rely on IT firewall mental models because the protocol semantics are different. A Modbus connection is not a "TCP session that should be allowed or denied"; it is a request-response stream where each request encodes a process-control intent, and the firewall must reason at that semantic layer or it adds no security value.

### Joe Weiss — Applied Control Solutions

**Career arc**: Nuclear engineer; first job at GE Nuclear Power Division working in instrumentation and control systems. Managing partner of Applied Control Solutions. ISA Fellow; IEEE Senior Member. Founded the ICS Cyber Security Conference in 2002 (longest-running event in the space). Author of *Protecting Industrial Control Systems from Electronic Threats* (Momentum Press, 2010). Long-running "Unfettered Blog" at controlglobal.com.

**Core contribution**: Long-running advocacy for treating the ICS attack surface as fundamentally different from IT. Particularly associated with publicizing the **Aurora Generator Test** (Idaho National Lab, March 2007) — a DHS-sponsored demonstration in which a 27-ton diesel generator was physically destroyed via cyber-induced out-of-phase reclosure. Weiss has argued for nearly two decades that Aurora-class attacks remain under-defended in the bulk electric system.

**Frame Weiss introduced**: ICS security must reason about the physics of the process, not just the cyber attack path. The Aurora attack does not require any malware on the generator; it requires the attacker to open and quickly close a breaker on the upstream grid side of a synchronous generator before re-synchronization, inducing destructive torque. This is a control-action attack with a physics-driven consequence — a layer many ICS-cybersecurity products miss entirely.

### Robert M. Lee — Dragos (founder, CEO)

**Career arc**: Started as a U.S. Air Force Cyber Warfare Operations Officer tasked to the NSA, where he built a first-of-its-kind mission identifying and analyzing nation-state threats to industrial infrastructure. Co-founded Dragos in 2016 with Jon Lavender and Justin Cavinee (also from the NSA ICS mission). Author of SANS ICS515 (ICS Visibility, Detection, and Response), lead author of SANS FOR578 (Cyber Threat Intelligence), co-author of SANS ICS310. Helped lead the investigation into the 2015 Ukraine power-grid attack. Cross-referenced in [[reference-threat-intel-methodology]].

**Core contribution**: Operationalized ICS threat intelligence as a distinct discipline. The Dragos Activity Group naming taxonomy (XENOTIME, ELECTRUM, CHRYSENE, KAMACITE, COVELLITE, ALLANITE, RASPITE, WASSONITE, PETROVITE, VOLTZITE, etc. — named after minerals to avoid the "Bear / Panda" cliche) and the annual Dragos Year-in-Review reports are the de facto public reference for who-is-targeting-what in ICS. Co-author with Mike Assante and Tim Conway of the SANS/E-ISAC analysis of the 2015 Ukraine power-grid incident.

**Frame Lee introduced**: ICS incident response is a *consequence-driven* discipline. The defender must understand the process, the safety case, and the recovery timeline; the incident isn't over when the malware is removed, it's over when the process is back to safe state. Documented in his book *SCADA and Me* (2013).

### Sergio Caltagirone — Dragos (VP Threat Intelligence)

**Career arc**: Nine-year lead threat intelligence analyst at the NSA before Microsoft as head of threat intelligence, then Dragos in 2016 to start its dedicated ICS threat intelligence team. Co-creator of the Diamond Model of Intrusion Analysis (with Andrew Pendergast and Christopher Betz, 2013). Cross-referenced in [[reference-threat-intel-methodology]].

**Core contribution**: Brought the Diamond Model — already widely adopted in IT-side threat intel — to ICS. The Diamond Model frames every intrusion via four nodes (adversary, infrastructure, capability, victim) and is particularly well-suited to ICS because ICS-threat tracking lives or dies on *sector* + *vendor* combinations (e.g., XENOTIME → Triconex SIS → Saudi petrochemical → TRISIS along Diamond edges).

### Marina Krotofil — formerly Mandiant/FireEye, Honeywell

**Career arc**: Industrial cybersecurity researcher specializing in process-aware attacks. Doctorate from Hamburg University of Technology (TUHH) on rigorous cyber-physical-system risk modeling. Tenures at Honeywell, Mandiant/FireEye (where she did core TRITON/TRISIS analysis), BASF, and the European Network for Cyber Security. Co-author of the Mandiant 2017 TRITON technical report. Speaker at S4, Black Hat USA, CS3STHLM, CyberwarCon.

**Core contribution**: Co-authored (with Benjamin Green and Ali Abbasi, 2017) "On the Significance of Process Comprehension for Conducting Targeted ICS Attacks" — the canonical academic treatment of what it costs an attacker to actually cause physical damage. Argument: weaponized ICS exploitation requires *process comprehension* (P&IDs, safety case, historian data, control-loop tuning) that no purely cyber-side attacker can reverse-engineer from network traffic alone. This bounds the realistic attacker population to nation-states or insiders, and frames why TRITON took years of pre-positioning before its (failed) trigger.

**Frame Krotofil introduced**: Cyber-physical attack economics. The full kill chain isn't "implant + lateral + payload"; it's "implant + lateral + payload + process model + physics model + safety bypass." The last three steps are the expensive ones, and the public conversation routinely under-counts them.

### Reid Wightman — Dragos (Senior Vulnerability Researcher)

**Career arc**: Senior Vulnerability Researcher at Dragos' Intel team. Previously a security consultant at Digital Bond (under Dale Peterson) and IOActive. Lead Project Basecamp researcher and Metasploit-module author.

**Core contribution**: **Project Basecamp** (Digital Bond, 2012) — the first systematic, public vulnerability disclosure on commercial PLCs. Volunteer-led audit found decrepit hardware, buggy software, and pitiful or nonexistent security features made thousands of PLCs vulnerable to trivial attacks (unauthenticated firmware update, plaintext credentials, denial-of-service via malformed packets). Wightman developed Metasploit modules for the affected devices (GE D20ME, Koyo Direct LOGIC, Rockwell ControlLogix L61, Schneider Modicon Quantum, Schweitzer SEL-2032). The thesis embedded in Basecamp — that PLCs are "insecure by design" — became the operating assumption of ICS-vulnerability research thereafter. Continuing arc: discovered a MultiProg/ProConOs missing-authentication vulnerability (CVE-2014-9195) affecting firmware on dozens of PLC models from KW-Software's licensee ecosystem — a multi-vendor disclosure illustrating that ICS bug-classes propagate up the supply chain via shared firmware components.

### Jason Larsen — IOActive

**Career arc**: Principal Security Consultant for IOActive. Previously one of the founding members of the Cyber-Security Department at Idaho National Labs (host of ICS-CERT and the National SCADA Testbed). Performed live power-grid penetration tests in multiple countries while at INL. Black Hat USA 2014 / S4x16 speaker.

**Core contribution**: Operationalized "remote physical damage" research — going beyond demonstrating that a PLC can be compromised to demonstrating what happens to the process when it is. Larsen's S4x16 work showed an industrial Ethernet switch could be compromised by manipulating *the timing* of encrypted packets to exploit gaps between physical and logical states. He emphasized that ICS attackers reach arbitrary process states by *timing* packet delivery rather than *content*, an insight that breaks many ICS detection products focused on protocol-content anomaly.

**Frame Larsen introduced**: ICS attack research must close the loop from "I executed code on the device" to "I caused the desired physical effect," and the second step is often the harder one. The body of his work is essentially case studies of completing that loop on real equipment.

### Eireann Leverett — Concinnity Risks (founder)

**Career arc**: Founder of Concinnity Risks. Senior researcher on cyber risk at the Cambridge Centre for Risk Studies. Co-author of *Solving Cyber Risk: Protecting Your Company and Society* (Wiley, 2018).

**Core contribution**: First public-scale **internet-exposure surveys for ICS**. In his June 2011 Cambridge MPhil dissertation ("Quantitatively Assessing and Visualising Industrial System Attack Surfaces"), Leverett used Shodan to find approximately 10,000 ICS devices directly addressable from the public internet — Modbus, DNP3, EtherNet/IP, BACnet, S7 endpoints, all unauthenticated. The follow-up notification went through ICS-CERT and approximately 63 other national CERTs. Subsequent cyber-insurance modeling brought rigor to "what does an aggregate-loss event in OT look like?" — the answer informs the IEC 62443 risk-assessment process today.

### Stephen Hilt — Trend Micro (Senior Threat Researcher)

**Career arc**: Senior Threat Researcher at Trend Micro Forward-Looking Threat Research (FTR). Long arc of ICS-honeypot work going back to **GasPot** (2015, with Kyle Wilhoit, a simulated gas-tank monitoring system).

**Core contribution**: "Caught in the Act: Running a Realistic Factory Honeypot to Capture Real Threats" (Trend Micro, 2020, with Federico Maggi, Charles Perine, Lord Remorin, Martin Rösler, Rainer Vosseler). The honeypot used real Siemens, Allen-Bradley, and Omron PLCs; virtual machines for HMI, engineering workstation, and robotics workstation. Outcomes: cryptocurrency miners installed, two ransomware infections (Crysis and Phobos), and intruders who caused system shutdowns. The empirical finding — that **profit-driven cybercriminals are at least as common as nation-state actors** in the OT-exposed population — undermined the prevailing assumption that ICS attacks are exclusively APT-driven.

### Stuart Madnick — MIT Sloan

**Career arc**: John Norris Maguire (1960) Professor of Information Technology at MIT Sloan; founding director of Cybersecurity at MIT Sloan (CAMS), formerly (IC)³. Ph.D. in computer science, MIT 1972. Co-author (with David Hsiao and Douglas Kerr) of *Computer Security* (Academic Press, 1979) — one of the first textbooks in the field.

**Core contribution**: Academic-side research on cyber-physical-system attacks and metrics, particularly STPA-Sec (Systems Theoretic Process Analysis for Security) applied to industrial chillers, central utility plants, and variable-frequency drives. The MIT-CAMS work produces papers like "Identifying and Mitigating Cyber Attacks that could cause Physical Damage to Industrial Control Systems" — bridging operations-research / safety-engineering literature into ICS security. Complements Krotofil's work by formalizing process-comprehension as a systems-engineering discipline rather than a craft skill.

### Vladimir Dashchenko — formerly Kaspersky ICS-CERT (Head of Vulnerability Research)

**Career arc**: Headed vulnerability research at Kaspersky Lab ICS CERT. Graduated from Ural State Technical University in information security; first job at the Russian Federal Space Agency as a security engineer. Presents at S4, ZeroNights, BSides, via Kaspersky's annual ICS-CERT reports.

**Core contribution**: Kaspersky ICS-CERT's annual "Threat Landscape for Industrial Automation Systems" reports — the most consistent public dataset on actual ICS-malware infection rates by country, sector, and threat family. Kaspersky's installed base on engineering workstations and HMIs around the world (particularly in Russia, Eastern Europe, Central Asia, Middle East, and Asia) gives the dataset coverage no other vendor can match. Dashchenko's vulnerability-research arm separately discovered dozens of CVEs in PLCs, RTUs, and HMI software from ABB, Siemens, Rockwell, Schneider, Yokogawa, Honeywell.

---

## II. The ICS/OT Threat Model and Architecture

### The Purdue Reference Model

The **Purdue Enterprise Reference Architecture** (Theodore Williams, Purdue University, 1990s) is the universally-cited ICS network topology:

- **Level 0** — Physical process (motors, valves, sensors, actuators). Atoms-and-electrons layer; attacks at L0 are often physical (RF jamming, sensor spoofing, instrument tampering).
- **Level 1** — Basic control (PLCs, RTUs, IEDs). Microcontroller-class devices running ladder logic or structured text. Execution model is cyclic-scan: read inputs, run program, write outputs, every 10-100ms.
- **Level 2** — Area supervisory control (HMI, local SCADA, engineering workstation). Windows-or-Linux systems running operator interfaces, alarming, historian writes, programming environments. The single point of greatest attack risk in most plants.
- **Level 3** — Site operations (plant historian, MES, batch management).
- **Level 3.5** — The **Industrial DMZ** between IT and OT. Where modern ICS architecture puts data diodes, jump servers, reverse proxies.
- **Level 4** — Enterprise / business systems (ERP, email).
- **Level 5** — Internet / external.

The model is descriptive, not prescriptive — real plants have all kinds of cross-level connections. The value is that it lets defenders enumerate legitimate cross-level flows and treat everything else as suspicious.

### Why IT security mental models fail in OT

The differences are structural, not cosmetic:

- **Availability dominates the CIA triad**. In IT, breach of confidentiality is the marquee incident. In OT, an unavailable controller can kill people; confidentiality of recipe data is a distant third behind keeping the process running. Patching cadence (and its absence) is downstream of this.
- **20+ year device lifecycles**. A PLC installed in 2002 may still be running in 2026, with the same firmware it shipped with. Stuxnet's target was Siemens S7-315 / S7-417 PLCs — devices designed in the late 1990s. Most plants you visit will have devices older than the SOC analyst monitoring them.
- **Legacy protocols by design**. Modbus (1979), DNP3 (1990s), EtherNet/IP (2000), PROFIBUS (late 1980s), HART (1986) all predate any reasonable expectation of network adversaries. They were designed for serial buses with physical access control, not routed IP networks. Retrofitted authentication (DNP3 SAv5, OPC UA) is rarely deployed because it requires endpoint upgrades that the plant cannot afford and the vendor cannot certify against the safety case.
- **Engineer is the user**. The HMI's primary user is a process engineer or operator monitoring a plant 24/7, not a security analyst. UI changes have to be backward-compatible because operators retrain slowly and the consequences of confusing them are physical.
- **Change control through safety review**, not CI/CD. Every change to ladder logic, PLC firmware, HMI screen, or alarm threshold is reviewed against the safety case. Patching a controller is a months-long process involving plant manager, vendor support engineer, safety officer, and process engineer.
- **Recovery time matters more than detection time**. A plant that has lost ladder logic to a destructive attack may take days or weeks to restore. Defense investment is shaped by this asymmetry.

### BPCS vs SIS

Two parallel control paths in any safety-critical plant:

- **BPCS** (Basic Process Control System) — day-to-day controllers adjusting valves, pumps, temperature. Operates continuously.
- **SIS** (Safety Instrumented System) — *last-line-of-defense* controllers that **shut the process down** when it goes out of safe operating envelope. Designed to fail-safe; certified to Safety Integrity Level (SIL 1 through SIL 4 under IEC 61508).

The SIS is supposed to be independent of the BPCS, both in equipment and network topology. Independence is the whole point: if the BPCS is malfunctioning (or compromised) and driving the process to unsafe state, the SIS catches it. Triton/TRISIS (Section IV) is the canonical exemplar of *what happens when an attacker compromises the SIS itself* — the safety net is gone, and the next failure of the BPCS is unmitigated. This is the worst-case ICS incident class.

### Why ICS-IR is fundamentally different

Cross-referenced in [[reference-dfir-methodology]] and [[reference-threat-intel-methodology]].

- **Physical-process consequences**. Worst-case outcome is not data loss; it is injury, death, environmental damage, equipment destruction. The IR team's first call is to operations to confirm process state, not to forensics.
- **Slow recovery**. Restoring a compromised PLC requires the original ladder logic, the original firmware build, the original I/O wiring map, and a window of safe-shutdown.
- **Regulatory-driven postmortems**. NERC CIP fines, EPA water-sector reporting, CFATS for chemical, TSA pipeline directives all require formal incident reporting on specified timelines.
- **Vendor support entanglement**. Multi-decade support contracts may include contractual rights of refusal on "modifications" — including security analysis.
- **No EDR**. Most OT devices are non-Windows and cannot run a modern endpoint agent. Forensic data comes from network captures, switch logs, and limited device audit trails.

### The IT/OT convergence trend (post-2015)

Pre-2010, the typical industrial plant ran a hard air gap between OT and IT. Post-2015, that's increasingly fiction. Drivers:

- **Predictive maintenance**. Vendors push cloud-connected sensors so they can sell maintenance-as-a-service. The connection is usually from the vendor's cloud back to the plant — a remote-access tunnel into OT.
- **Remote operations**. Post-COVID acceleration of remote-access-for-engineers programs.
- **Industry 4.0 / smart manufacturing**. ERP-to-MES-to-DCS data flows are increasingly real-time and bidirectional.
- **Cloud-native SCADA**. Newer platforms (Ignition Cloud Edition, AWS IoT SiteWise) move historian and HMI workloads to AWS / Azure / GCP. The control loop stays on-premises; supervisory layer increasingly does not.

The net effect: the Purdue Level 3.5 DMZ is doing more work than designed for, and the convergence layer is where most new attack surface lives. Cross-reference [[reference-firmware-embedded-security]] for the hardware substrate; [[reference-threat-intel-methodology]] for who-is-targeting-the-convergence-layer.

---

## III. ICS Protocols — By-Design Insecurity

The protocol corpus below predates the modern threat model. Authentication and encryption have been bolted on later if at all, and field deployment of the secure variants is rare. Plant operators face a multi-decade depreciation curve, so even when a secure variant exists, realistic adoption timelines are decades.

### Modbus (1979, Modicon)

The original industrial-fieldbus protocol. Designed by Modicon (now Schneider Electric) for serial communication between a master (PLC, RTU, HMI) and slaves (field devices). Modbus TCP runs on Ethernet at TCP port 502.

- **Function codes**: 1-byte field naming the operation (1 = read coils, 3 = read holding registers, 6 = write single register, 15 = write multiple coils, 16 = write multiple registers). Codes 128-255 are reserved for exception responses.
- **No authentication, no encryption, no integrity**. Anyone with TCP-level reachability to port 502 can read or write any register. Modbus traffic is plaintext; passive captures reveal sensitive process state.
- **Replay is trivial**. No session, nonce, or sequence number distinguishes a replay from a legitimate command.

A Modbus Security variant (TLS-wrapped) exists but adoption is rare — most plants have hundreds or thousands of 10+-year-old Modbus endpoints whose firmware doesn't speak TLS.

### DNP3

Distributed Network Protocol version 3. Early-1990s vintage. Primarily North American electric power, water/wastewater, some oil and gas. Maintained by the DNP Users Group; standardized as IEEE 1815.

- **DNP3 Secure Authentication v5** (SAv5, IEEE 1815-2012) is the cryptographic-authentication variant. Defined in Clause 7 of IEEE 1815-2012. Uses challenge-response with HMAC-SHA-256 for message authentication and AES-256 Key Wrap for key exchange.
- **Deployment rate is low**. Published in 2011 but over a decade later field deployment is still rare. NERC CIP allows but does not require SAv5; utility deployment economics rarely justify the upgrade unless tied to major substation modernization.
- **Backward tolerance** simplifies rollout but means an attacker who compromises any device on the segment can downgrade communications.

### EtherNet/IP and CIP

Rockwell-Automation-dominant in North America; standardized by ODVA. Encapsulates the **Common Industrial Protocol (CIP)** over TCP/UDP. ControlLogix, CompactLogix, Micro800, MicroLogix PLCs all speak EtherNet/IP. CIP message routing is hierarchical (path-based) — powerful for cross-plant addressing and a robust target language for attackers. **CIP Security** (announced by ODVA in 2015) adds TLS-based authentication and encryption; deployment sparse outside new installations.

### PROFINET and PROFIBUS

Siemens-dominant in Europe and large parts of Asia. PROFIBUS is the older serial fieldbus; PROFINET is the Ethernet successor.

- **PROFINET RT** — soft real-time, deterministic within a few milliseconds.
- **PROFINET IRT** — hard real-time with sub-millisecond determinism via dedicated switching.

PROFINET Security layers TLS and certificate-based authentication. Deployment rare. Layer-2 frames are not encrypted; an attacker on the same broadcast domain can inject or modify cyclic data.

### IEC 61850

Dominant **substation automation** protocol family in electric utilities. Standardized by IEC TC57. Three transport profiles:

- **GOOSE** (Generic Object Oriented Substation Event) — Layer-2 multicast for fast trip and interlocking signals. Designed for **4ms** delivery between IEDs. No encryption by default; signed GOOSE (IEC 62351-6) exists but is rarely deployed because cryptographic overhead can break the 4ms timing budget on legacy hardware.
- **SV / SMV** (Sampled Values) — Layer-2 multicast for sub-cycle sampled voltage and current from Merging Units to IEDs. Tighter timing than GOOSE.
- **MMS** (Manufacturing Message Specification, ISO-9506) — TCP/IP client/server for configuration, status, measurement reports between station-level and bay-level devices. Easier to attack than GOOSE/SV because it sits on routable IP.

The 4ms GOOSE budget is the load-bearing reason authentication is hard to retrofit in IEC 61850.

### OPC Classic (DCOM-based)

The original OPC family (OPC DA, OPC HDA, OPC A&E) — late 1990s through mid-2000s. Built on Microsoft DCOM. Windows-only.

- **DCOM port allocation is dynamic** in the 49152-65535 range, making ICS-friendly firewall rules nearly impossible — most plants run overly-permissive firewall rules to keep OPC Classic working.
- **Data in transit is plaintext** by default; DCOM authentication is on the connection-setup handshake, not on the data stream.
- **Widely deployed and still in use** across HMIs, historians, and gateways manufactured before about 2015.

### OPC UA

OPC Unified Architecture. Released 2008. Platform-independent (Windows, Linux, embedded RTOS). Designed with security as a first-class concern:

- **TLS-based** transport encryption.
- **Certificate-based authentication** at the application layer (X.509 cert exchange between server and client).
- **Role-based access control** on per-method, per-variable basis.
- **Single configurable TCP port** (typically 4840/4843 for binary, 443 for HTTPS) — firewall-friendly.

The installed base of OPC Classic remains enormous; the migration is multi-year. OPC UA's security depends on the certificate-management lifecycle, and many deployments have stale, self-signed, or unverified certificates because plant teams don't run an internal PKI.

### HART

Highway Addressable Remote Transducer. 1986. For **smart instrumentation** — temperature transmitters, pressure transmitters, flow meters. Runs a 1200-baud FSK digital signal multiplexed over the same 4-20mA analog current loop. **HART-IP** is the routable IP variant. No authentication; defense is the physical inaccessibility of the field wiring in hazardous-area conduit. HART-IP removes that physical defense and is correspondingly more risky.

### CAN bus / J1939

Controller Area Network. Bosch, 1986. Dominant in-vehicle bus, increasingly common in heavy industrial machinery (J1939 is the heavy-duty-vehicle profile). No authentication; bus arbitration is by message ID. Cross-references [[reference-firmware-embedded-security]] §V (automotive).

### The "auth is bolted on later if at all" reality

Every ICS protocol in production today predates the modern threat model. Security has been retrofit by adding TLS, certificates, or HMACs in newer protocol versions, but deployment is slow: vendor certification against safety cases takes months; HMI / engineering workstation must support the new protocol; the new protocol must coexist with the old for years.

Strategic implication: ICS network defense cannot rely on protocol-level authentication being in place. The compensating control is *protocol-aware network monitoring* at the boundary, which is the value proposition of Dragos, Claroty, Nozomi, and similar OT-monitoring vendors (Section VIII). Cross-reference [[reference-dns-network-infrastructure]] for protocol-level defense framing.

---

## IV. The Canonical Incident Corpus

The incidents below are the load-bearing case studies of the field. Every ICS-IR class and every executive briefing references at least four or five.

### Aurora Generator Test (Idaho National Lab, March 2007)

**Target**: A 27-ton diesel generator on the INL test range.

**Effect**: Generator physically destroyed. CCTV footage widely circulated. DHS released the video in September 2007, and roughly 840 pages of experiment documents in July 2014 in response to a FOIA request.

**Technical detail**: No malware on the generator; attacker opens a breaker on the upstream grid side of a synchronous generator, then quickly re-closes it before the generator can re-synchronize. Out-of-phase reclosure induces enormous torque on the rotor — far beyond mechanical structure ratings — and destroys it in seconds. The attack target is the *breaker* between generator and grid, typically operated via remote SCADA in a substation.

**Lesson**: Cyber-physical attacks can cause cascading mechanical damage that no IT-side mental model anticipates. Defense must include physics-aware engineering (synchronism-check relays that block out-of-phase reclosure regardless of operator command).

### Stuxnet (discovered June 2010)

**Target**: Iranian uranium-enrichment centrifuges at Natanz. Specifically, cascades of IR-1 centrifuges controlled by Siemens S7-315 / S7-417 PLCs.

**Effect**: Roughly 1,000 of approximately 9,000 centrifuges destroyed over a multi-year campaign (per ISIS analysis of IAEA inspection reports). Some analysts estimated the setback to Iran's nuclear program at two to five years.

**Technical detail**: Two distinct attack routines per Langner's "To Kill A Centrifuge" — a speed attack driving rotors through resonance, and a more complex pressure attack closing isolation valves to condense UF6 gas inside the centrifuges. Stuxnet propagated via Windows zero-days (LNK MS10-046, Print Spooler MS10-061, two privilege-escalation 0days), targeted air-gapped networks via USB, and used signed driver certificates stolen from Realtek and JMicron. The PLC payload was Siemens STEP 7 ladder-logic injection — only fired when the PLC was attached to a specific number of Profibus slaves matching the centrifuge cascade topology.

**Lesson**: Nation-state attackers can develop and deploy cyber-physical weapons that destroy specific industrial equipment without leaving obvious network-side signatures. Network-layer defense alone is insufficient; engineering-workstation project-file integrity is critical.

### BlackEnergy / Ukraine power grid 2015 (December 23, 2015)

**Target**: Three Ukrainian regional electricity distribution companies — Prykarpattyaoblenergo, Chernivtsioblenergo, Kyivoblenergo.

**Effect**: ~225,000 customers lost power for 1-6 hours. First publicly-confirmed cyber attack causing a power outage.

**Technical detail**: Phishing-delivered BlackEnergy3 on operator workstations. Six months of pre-positioning. On the day, operators were locked out of HMI consoles via KillDisk wiping; adversary remotely operated breakers to open them. UPS at substations were disabled; call center flooded with TDoS to prevent customer reporting. Recovery required operators driving to substations to manually re-close breakers — the SANS analysis (Lee/Assante/Conway) is the public reference.

**Lesson**: Adversaries are willing to invest 6+ months of pre-positioning for a single coordinated outage. Defender must assume both SCADA is compromised AND manual recovery procedures will be exercised under stress.

### CrashOverride / Industroyer / Ukraine power grid 2016 (December 17, 2016)

**Target**: Ukrenergo high-voltage substation north of Kyiv (Pivnichna).

**Effect**: Roughly one-fifth of Kyiv lost power for approximately one hour.

**Technical detail**: ESET disclosed publicly as Industroyer; Dragos parallel analysis (briefed June 8, 2017 by ESET; public June 12) called it CRASHOVERRIDE. Unlike BlackEnergy/2015, this was a *purpose-built ICS malware framework* with four protocol-specific payload modules: IEC 60870-5-101 (serial), IEC 60870-5-104 (TCP/IP), IEC 61850, OPC Data Access. Plus backdoor, port scanner, DDoS module against Siemens SIPROTEC relays (CVE-2015-5374), wiper. Dragos attribution: ELECTRUM, with direct ties to **Sandworm** (Russian GRU Unit 74455).

**Lesson**: Adversaries can build modular, protocol-specific ICS attack frameworks that work against multiple vendors and substations without per-target development. ICS malware is now a category, not a one-off.

### Triton / TRISIS / HatMan (Saudi Arabia, 2017)

**Target**: A Saudi Arabian petrochemical plant. Specifically, Schneider Electric **Triconex Tricon** safety-instrumented system controllers (SIS, not BPCS).

**Effect**: A SIS controller went into safe-shutdown state, halting the plant. No physical damage occurred — but the attack's *intent*, if the payload had executed correctly, was to disable the SIS so a follow-on BPCS attack could cause undefended physical damage (explosion, fire, environmental release). The "almost killed people" incident.

**Technical detail**: Mandiant analysis (Krotofil and team) is the canonical reference. Custom framework targeting the Tri-station protocol — vendor-proprietary, undocumented. Attackers had access to the plant network for over a year; acquired and reverse-engineered Triconex controller hardware; developed a kernel-mode implant for the PowerPC-based processor. Plant operators detected the incident because the SIS itself fail-safed during testing of the payload — a defensive accident, not a defensive win. U.S. Treasury sanctioned **TsNIIKhM** (Russian Central Scientific Research Institute of Chemistry and Mechanics) in October 2020. Dragos tracks the activity group as **XENOTIME**.

**Lesson**: SIS is the last-line-of-defense against physical harm. Compromise of the SIS is the qualitatively worst ICS incident class. Defense must include strict separation of SIS from BPCS networks, cryptographic-authenticated engineering access to SIS controllers, out-of-band monitoring for SIS state changes.

### NotPetya (June 27, 2017)

**Target**: M.E.Doc accounting software supply chain in Ukraine; downstream propagation to multinationals.

**Effect**: $10B+ global damages. Maersk lost ~49,000 endpoints and most servers — rebuilt nearly the entire global domain from a single surviving domain controller in Ghana. Merck took ~$1.4B, leading to a long-running insurance dispute that helped clarify the "act of war" exclusion in cyber-insurance policies. Reckitt Benckiser, Mondelez, FedEx (TNT Express), Saint-Gobain all hit. Many manufacturing plants offline for weeks.

**Technical detail**: Worm spread via MEDoc auto-update, then via EternalBlue + EternalRomance + Mimikatz lateral movement. Disguised as ransomware but functionally a wiper. Attributed by U.S., UK, Australia to Russian GRU.

**Lesson**: IT-side malware can take down OT operations even without an explicit OT payload, simply by disabling IT systems the plant depends on for scheduling, MES, ERP, badge access, email workflows. The IT/OT boundary is not as protective as Purdue suggests when the entire IT environment is down.

### Norsk Hydro / LockerGoga (March 19, 2019)

**Target**: Norsk Hydro, Norwegian aluminum producer; 35,000 employees in 40 countries.

**Effect**: Roughly $71 million in damages. Automated production lines shut down across multiple smelters and extrusion plants; operations shifted to pen-and-paper. Recovery took weeks.

**Technical detail**: Initial compromise was a weaponized email attachment to a Norsk Hydro employee in December 2018 (three months before encryption), part of a legitimate business conversation. Attackers obtained domain admin and used Microsoft AD management tools to plant LockerGoga across the forest. LockerGoga logs off all users, disables network adapters, changes passwords, then encrypts. Aim was total shutdown, not ransom — note was nearly inaccessible after encryption.

**Lesson**: AD compromise plus mass-encryption of IT systems is sufficient to force fall-back to manual operation. Norsk Hydro's *transparent* incident communication (daily public press conferences, full operational disclosure) is now studied as gold-standard ICS-IR communication.

### Colonial Pipeline / DarkSide (May 7-13, 2021)

**Target**: Colonial Pipeline Company; largest refined-petroleum-products pipeline in the U.S. (~45% of U.S. East Coast fuel supply).

**Effect**: Pipeline shut down for 5 days. Gasoline shortages and panic-buying along the East Coast. Average national gasoline price rose to a 6-year high.

**Technical detail**: Initial access via an exposed VPN account credential without MFA. Attackers exfiltrated ~100 GB and encrypted IT systems with DarkSide ransomware. **OT systems were not directly impacted**; Colonial proactively shut down the pipeline because it could not be confident in IT/OT segmentation, and because the billing system (IT-side) was unavailable. Colonial paid $4.4M in bitcoin (75 BTC); FBI later recovered a portion.

**Lesson**: Precautionary OT shutdown driven by IT-side compromise is a real outcome. Modern ICS architecture must support continued OT operation when IT is unavailable, OR must accept OT shutdown as the conservative response. Most-cited single ICS incident in U.S. regulatory discussion since 2021; TSA Pipeline Security Directives 1 and 2 were issued directly in its wake.

### JBS Foods / REvil (May 30, 2021)

**Target**: JBS S.A., world's largest meat processor.

**Effect**: U.S., Canadian, Australian meat-processing plants shut down for several days. JBS paid $11M in bitcoin for the decryption key.

**Technical detail**: Ransomware compromise of IT systems; OT operations halted because of dependency on IT for scheduling, traceability, shipping logistics. Similar pattern to Norsk Hydro and Colonial.

**Lesson**: Critical infrastructure now includes food supply, and food-supply infrastructure has the same IT/OT-coupling weakness as energy and water.

### Industroyer2 / Sandworm (April 8, 2022)

**Target**: A Ukrainian electricity provider (high-voltage substations).

**Effect**: **The attack was thwarted.** ESET and CERT-UA detected and contained Industroyer2 before the destructive action executed. No outage occurred — a major defensive win.

**Technical detail**: ESET assessed with high confidence as an updated Industroyer used by Sandworm. Unlike 2016, Industroyer2 used **only IEC 60870-5-104** and had **detailed, hardcoded configuration** in the binary itself (the original used an .INI file). Each new target requires a recompile — stronger signal of operator-specific tooling. Scheduled for 2022-04-08 16:10 UTC; deployed alongside **CaddyWiper**, **ORCSHRED**, **SOLOSHRED**, **AWFULSHRED** destructive malware on ICS and Linux systems. CERT-UA with ESET support prevented the destructive payload from executing.

**Lesson**: ICS defense can win. OT-aware monitoring, vendor partnership, rapid IR — exactly what the field has advocated since 2015.

### CyberAv3ngers / Unitronics PLCs (November 2023+)

**Target**: U.S. water and wastewater utilities running Unitronics Vision Series PLCs (Israeli-manufactured). At least 75 devices compromised across multiple U.S. states and other countries.

**Effect**: Defacement ("You have been hacked, down with Israel. Every equipment 'made in Israel' is CyberAv3ngers legal target."). No process damage in confirmed incidents — but the precedent (direct PLC compromise of municipal water utilities by an IRGC-affiliated group) is the headline.

**Technical detail**: Attackers exploited internet-facing Unitronics PLCs and HMIs with default or no credentials. CyberAv3ngers assessed by CISA and FBI as IRGC-affiliated; U.S. Treasury sanctioned six IRGC-CEC officials in February 2024. CISA follow-up advisory (AA26-097A, 2026) expanded the scope to multiple Iranian-affiliated PLC targeting campaigns.

**Lesson**: Sub-municipal critical infrastructure (small water utilities, rural electric coops) is a soft target. The aggregate U.S. attack surface includes ~50,000 community water systems, many with fewer than five OT staff total. Federal response (CISA bulletins, EPA inspection authority) is shaping into a regulatory regime.

### Volt Typhoon / VOLTZITE (CISA reporting 2023-2026)

**Target**: U.S. critical infrastructure across communications, energy, transportation, water and wastewater. PRC state-sponsored.

**Effect**: No publicly-confirmed kinetic effect to date. Campaign assessed as **pre-positioning** for disruptive or destructive cyber attacks in the event of a major crisis or conflict — most plausibly a Taiwan-strait scenario.

**Technical detail**: "Living off the land" — wmic, ntdsutil, netsh, PowerShell, built-in Windows admin tools to evade EDR and look like legitimate IT activity. CISA's MAR-10448362-1.v1 documents indicators. U.S. authoring agencies observed Volt Typhoon maintaining access in some IT environments for at least five years before discovery. Dragos tracks an OT-side variant as **VOLTZITE**, observed inside electric and water-utility OT environments.

**Lesson**: Strategic-deterrence-level ICS pre-positioning is no longer hypothetical. The defender's mental model must include "this is not a ransomware actor; this is a state actor whose payoff function is held in reserve until a geopolitical trigger." Detection economics shift accordingly — hunt for low-and-slow lateral movement and persistence, not just noisy crypto activity.

---

## V. PLC Exploitation

### PLC architecture

A programmable logic controller is a microcontroller-class device (ARM, MIPS, or PowerPC) running a custom RTOS, executing a user-supplied program in a cyclic scan:

1. Read inputs.
2. Execute the user program (ladder logic, structured text, function block diagram, or instruction list — IEC 61131-3 languages).
3. Write outputs.
4. Loop. Cycle time typically 10-100ms.

IEC 61131-3 programming languages:

- **LD (Ladder Diagram)** — visual rungs of contacts and coils mimicking relay-logic schematics. Dominant in North America.
- **ST (Structured Text)** — Pascal-like. Increasingly common as programs grow complex.
- **FBD (Function Block Diagram)** — graphical interconnection of pre-built blocks. Common in process industries.
- **IL (Instruction List)** — assembly-like; deprecated.
- **SFC (Sequential Function Chart)** — flowchart-style for sequential state machines.

The user program is downloaded via a vendor-specific protocol (Siemens S7Comm, Rockwell EtherNet/IP CIP, Schneider Modbus UMAS, etc.). Some PLCs allow online edits without stopping the cycle (Run-mode programming).

### Project Basecamp (Digital Bond, 2012-2013)

Reid Wightman's project — the first systematic public vulnerability research on PLCs. Audited six devices, including:

- **GE D20ME** — unauthenticated firmware download/upload.
- **Koyo Direct LOGIC** — password mechanism with no lockout or timeout, so brute force is easy.
- **Rockwell ControlLogix L61** — unauthenticated EtherNet/IP CIP write; remote-stop, remote-restart, remote-program-modify.
- **Schneider Modicon Quantum** — multiple unauthenticated services (telnet, FTP, plaintext SCADA protocol).

Metasploit modules released. The "insecure by design" thesis held up: vendors mostly responded that the protocols were designed for trusted-network operation.

### Common PLC bug classes

- **Hardcoded credentials**. Vendor-default usernames and passwords baked into firmware, undocumented, often unchangeable.
- **Plaintext configuration protocols**. The same protocols used to read/write registers are used to read/write program memory.
- **Ladder-logic injection**. An attacker who can speak the programming protocol can upload arbitrary ladder logic. Stuxnet's payload was ladder-logic injection.
- **Unauthenticated firmware update**. Many PLCs accept firmware-update commands without authentication. Wightman's later work on ProConOs/MultiProg (CVE-2014-9195) showed this was a multi-vendor problem because of shared firmware-runtime licensing.
- **Authentication bypass via protocol downgrade**. Some PLCs support both authenticated and legacy unauthenticated modes; downgrade bypasses auth.
- **Memory corruption via malformed protocol frames**. The protocol parsers were written in C in the 1990s by control-engineering teams who weren't building under modern fuzz-testing assumptions; crashes and arbitrary-write conditions are widespread. Cross-reference [[reference-firmware-embedded-security]] §III.

### Vendor-specific corpus

**Siemens S7 family** (S7-200/300/400/1200/1500, TIA Portal):
- S7-300 / S7-400 — the Stuxnet generation. Used STEP 7 v5.x project files; project-file modification on the engineering workstation was the attack path.
- S7-1200 / S7-1500 — newer generation, programmed via TIA Portal. Web-server XSS CVE-2012-3040 (S7-1200). Multiple firmware vulnerabilities from IOActive, Positive Technologies, Eclypsium, Kaspersky ICS-CERT over 2015-2024.
- Ang Cui's 2023 cryo-mechanical RAM extraction (IEEE WOOT / REcon 2023) was demonstrated on Siemens S7-1500 — full extraction of encrypted firmware from runtime DRAM. Cross-reference [[reference-firmware-embedded-security]] §I.

**Rockwell ControlLogix family** (1756, CompactLogix, MicroLogix, Micro800):
- Project Basecamp covered 1756-L61. Claroty Team82 research has since found multiple authentication-bypass and code-execution vulnerabilities in newer ControlLogix firmware. CVE-2021-22681 (insufficiently protected credentials: the key Studio 5000 Logix Designer uses to verify it is talking to Logix controllers can be bypassed) allowed unauthenticated connection to the controller.

**Schneider Modicon family** (Quantum, M340, M580):
- Project Basecamp covered Quantum. The UMAS protocol (Unified Modbus Application Service, the Schneider programming protocol on top of Modbus) has been repeatedly attacked; Armis's ModiPwn research (2021, CVE-2021-22779) showed an M340/M580 authentication bypass allowing an unauthenticated attacker to take full control of the PLC.

**ABB / Emerson / Yokogawa / Honeywell**: Each has its own DCS corpus with proprietary protocols and engineering tools. Public vulnerability research is less dense than Siemens/Rockwell/Schneider but growing — Dragos and Claroty publish coordinated disclosures for ABB 800xA, Emerson DeltaV, Honeywell Experion. Extends to vendor-specific safety controllers (Triconex for Schneider, ProSafe for Yokogawa, FSC for Honeywell).

### PLC firmware reversing workflow

Cross-reference [[reference-firmware-embedded-security]] for embedded-substrate techniques. ICS-specific adjustments:

1. **Acquire firmware from the HMI / engineering tool**. The vendor's engineering software (TIA Portal, Studio 5000, Control Expert) ships with a copy of firmware for each supported device. The archive is often a CAB, ZIP, or vendor-specific container.
2. **Identify the CPU**. Most PLCs are ARM (S7-1200/1500, modern ControlLogix), MIPS (older Schneider, older GE), or PowerPC (Triconex Tricon). Some specialty controllers use AVR, ARM Cortex-M, or Xilinx FPGAs with embedded processors.
3. **Identify the RTOS**. VxWorks dominates older Siemens/Rockwell/Schneider; newer devices may run embedded Linux. Triconex Tricon used a custom RTOS.
4. **Load into IDA / Ghidra / Binary Ninja**. Cross-reference Ang Cui's OFRAK for the recursive unpacking layer ([[reference-firmware-embedded-security]] §I).
5. **Locate the protocol parser**. The fastest path is the function handling incoming programming-protocol frames; from there, find authentication checks (often weak or absent), command dispatch tables, and the ladder-logic interpreter.

---

## VI. HMI and Engineering Workstation Attack Surface

### Why HMIs and EWS are the canonical pivot

The PLC is the device that controls the process, but the **HMI** and the **engineering workstation** are what you actually attack to reach the PLC:

- Both are typically Windows machines (Windows 7, 10, sometimes Server) running vendor-specific application software.
- Both speak the proprietary programming protocols natively — TIA Portal can read or write a Siemens PLC's program; Studio 5000 can read or write a Rockwell PLC's program.
- Both are increasingly internet-adjacent due to remote-access requirements, vendor support tunnels, predictive-maintenance integrations.
- Patching is rare. The vendor often does not certify newer Windows versions for years after Microsoft ships them, leaving the plant on an unpatched OS for 5-10 years.

Stuxnet's attack path was "compromise the engineering workstation, then push malicious ladder logic to the PLC through the legitimate programming channel." Every serious post-2010 ICS attack follows this pattern.

### Canonical HMI / SCADA software

- **Wonderware InTouch** (now AVEVA InTouch HMI) — long-running, Windows-native HMI. Multiple memory-corruption vulnerabilities historically.
- **Rockwell FactoryTalk** suite (View, AssetCentre, Linx) — Windows-native. CVE-2021-27462 (FactoryTalk AssetCentre deserialization RCE) and others have allowed authentication bypass and RCE.
- **Siemens WinCC** — paired with Siemens S7 PLCs. Stuxnet replaced the STEP 7 communication library (s7otbxdx.dll) to intercept PLC block reads and writes, masking its infected code from WinCC. CVE-2012-2595 (WinCC web XSS) and many others.
- **Schneider Citect / Vijeo Citect** — long-running SCADA platform. CVE-2008-2639 (one of the earlier publicly-disclosed SCADA buffer overflows).
- **GE Cimplicity / iFix** — HMI/SCADA in process and discrete industries.

### Engineering workstation programming environments

- **TIA Portal** (Siemens) — programs S7-300/400/1200/1500, SIMATIC HMIs, SINAMICS drives. Single piece of software that, if compromised, gives the attacker full reach into a Siemens-shop plant.
- **Studio 5000 Logix Designer** (Rockwell) — programs ControlLogix, CompactLogix, FlexLogix, Micro PLCs. Analogous reach for Rockwell shops.
- **EcoStruxure Control Expert** (Schneider, formerly Unity Pro) — programs Modicon M340/M580.
- **ABB 800xA Engineering Workplace** — ABB DCS programming.
- **Emerson DeltaV Configuration Studio** — Emerson DCS programming.

These are the highest-value EWS targets: they speak the proprietary protocols, hold the master copy of ladder logic, and are the device-of-record for any forensic analysis of "what was running on the PLC."

### The "Stuxnet-style" pattern

1. Initial access to the engineering workstation (USB / network / supply chain).
2. Persistence on the EWS via a malicious WinCC DLL or STEP 7 plug-in.
3. Wait for the engineer to download a project to a target PLC.
4. Intercept the project file; inject malicious ladder logic.
5. The legitimate engineering protocol pushes the modified project to the PLC; the PLC executes the modified logic from then on.
6. (Optionally) intercept HMI displays to hide the malicious effect from the operator.

This pattern requires the attacker to understand the project-file format, ladder-logic semantics, and the operator UI. Expensive, vendor-specific, a defining capability of nation-state ICS actors.

### USB control as primary defense

Most engineering workstations sit in operational areas where USB is physically accessible. Stuxnet propagated via USB. USB-control programs (Microsoft Device Guard, Forescout, vendor-specific USB allowlists) are widely deployed in mature OT environments. Imperfect — the engineer's authorized firmware-update USB is the same USB stick that can be tampered with — but raises the bar significantly.

---

## VII. SIS (Safety Instrumented System) Attacks

### Why SIS attacks are the worst class

A safety-instrumented system is the *last line of defense* against physical harm. It is engineered to detect when the process has gone or is about to go outside the safe envelope and drive it to a safe state — closing a valve, stopping a pump, opening a relief valve, de-energizing a circuit. SIS is independent of BPCS by design: separate controllers, separate I/O wiring, separate engineering tools, separate firmware. Independence is critical because the SIS must catch *both* mechanical failures of the BPCS *and* operator error.

If the SIS is compromised, the entire safety case collapses; whatever combination of mechanical, software, and operator failure would otherwise be arrested is no longer arrested. Triton/TRISIS (Section IV) is the publicly-known exemplar — the attacker positioned themselves to disable the Triconex Tricon SIS so a follow-on BPCS attack would cause physical damage. The SIS itself fail-safed during testing of the payload — a defensive accident, not a defensive win.

### Triconex Tricon architecture

The Schneider Electric Triconex Tricon is the dominant SIS in petrochemicals. **Triple Modular Redundant** (TMR) — three independent main processors, each running the same safety program, voting on outputs. Designed for high availability under partial failure. Programmed via a proprietary protocol (**TriStation**), not publicly documented — the TRISIS attackers reverse-engineered it.

### Other SIS platforms

- Honeywell FSC (Failsafe Control)
- Emerson DeltaV SIS
- Yokogawa ProSafe-RS
- Siemens S7-400 F/FH (failsafe variants)
- HIMA HIQuad / HIMatrix (German pure-play SIS vendor)

### The process-aware-attacker requirement

Krotofil's framing applies most strongly here: to attack a SIS *effectively* the attacker must understand the process well enough to (1) know which SIS trip is the load-bearing safety case for the target damage, (2) disable that specific trip without triggering it, (3) drive the BPCS to a state where the now-defenseless process fails. This requires P&IDs, safety case documentation, the SIS program, alarm-management documents, operator training material — months to years of access to engineering data, not just network access. The cost of doing it well is part of why TRISIS-class attacks remain rare; the cost of doing it badly is what fail-safed the TRISIS payload.

### Defense-in-depth doctrine for SIS

Current consensus, codified across IEC 61511, IEC 61508, and ISA/IEC 62443:

- **Air gap** the SIS from the BPCS network. Even one-way data flows from SIS to BPCS (historian logging) should be unidirectional via a data diode.
- **Cryptographic authentication** on all engineering access. Don't trust the network; require certificate-based or HMAC-based authentication for any program-load or configuration change.
- **Out-of-band monitoring** of SIS state changes. Any change to the SIS program or operating mode should be logged and alarmed independently of the SIS's own logging.
- **Keyswitch enforcement** on engineering mode. The Tricon and most SIS controllers have a physical keyswitch that must be in PROGRAM position to accept changes. Operationally enforce that the key is held by the safety officer and only inserted during planned maintenance windows.
- **Vendor-supplied integrity verification** of the loaded program. Newer Tricons support checksum-based verification against a known-good baseline; alarm on mismatch.

### IEC 61508 and IEC 61511

Functional-safety standards family. IEC 61508 is generic; IEC 61511 is the process-industries application. Both define **Safety Integrity Level** (SIL) 1 through SIL 4 — quantified targets for probability of failure-on-demand. Cryptographic security is increasingly integrated via IEC 61511 (2016 edition) and ISA/IEC 62443's safety-system extensions. The unification of "functional safety" and "cybersecurity" is one of the active fronts in ICS standards work.

---

## VIII. Detection in ICS Environments

### Why classical EDR is ill-suited

Cross-reference [[reference-detection-engineering]].

Most OT devices are non-Windows: PLCs run vendor RTOSes, RTUs run minimal embedded Linux, HMIs are sometimes Linux, network devices are vendor-managed. The Windows footprint is mostly engineering workstations and Level 2/3 SCADA servers — so a CrowdStrike / SentinelOne / Defender-style EDR can cover roughly 10-20% of device population in a typical plant. The remaining 80-90% has no endpoint visibility.

Worse, when EDR *is* deployed on OT-side Windows, it frequently breaks operational expectations: CPU contention with HMI refresh cycles causes display lag (which operators read as a process problem); behavior-blocking rules tuned on IT-side benign software flag OT software anomalies; auto-update cycles cause unplanned reboots — a 5-minute HMI reboot during a critical operation is a safety incident. OT-tuned EDR variants address some of this, but the fundamental gap remains.

### Passive asset discovery as the first step

You cannot defend what you cannot see, and the typical mature plant has only a partial inventory of OT assets. Step zero in any serious OT-security program is **passive asset discovery**: span-port-tap into the OT network, parse all observed protocols, build a per-device inventory of vendor, model, firmware version, and observed function-code usage.

This is exactly what Dragos Platform, Claroty Continuous Threat Detection, Nozomi Networks Guardian, and Tenable.OT do. The competitive differentiation is in:
- Breadth of protocol parsers (Siemens S7Comm-Plus? IEC 60870-5-104? OPC UA over TCP and UDT?).
- Quality of device-fingerprinting (Triconex Tricon vs Tricon CX?).
- Latency between protocol-spec changes and parser updates.
- Threat-intel integration.

### Network-anomaly detection at the protocol layer

Once asset discovery is in place, anomaly detection follows:

- **New function codes**. A Modbus master that has only ever issued function codes 3 and 6 issuing function code 8 (diagnostics) or 90 (vendor-specific reset) is anomalous.
- **New register accesses**. A specific PLC register never written by any master, suddenly written, is anomalous. (This pattern was demonstrably present in CrashOverride — the IEC 60870-5-104 master was issuing breaker-control commands with no historical precedent on those circuits.)
- **New endpoints**. New IPs on the OT network are inherently suspicious — the OT inventory is small and changes slowly.
- **Engineering-program changes**. Any S7Comm "download" command, any CIP "download to processor," any UMAS "ladder logic write" should be alarmed. The platforms can extract ladder-logic from the wire and diff against last-known-good.

### Engineering-program-change detection

This deserves its own callout — the highest-leverage OT detection. The number of legitimate ladder-logic changes per year in a typical plant is small (single digits to low tens), scheduled and reviewed. Any unscheduled change is an incident until proven otherwise. OT-monitoring vendors that can extract and diff ladder logic from the wire are giving defenders the "did the program change?" signal that catches Stuxnet-class attacks.

### Sigma-shaped rules for ICS

Cross-reference [[reference-detection-engineering]] §3. The Sigma rule format has been adapted by OT-monitoring vendors and open-source community for ICS-protocol-specific rules. Targets: Modbus function code 90 from a non-engineering workstation; S7Comm CPU stop/start commands; CIP unconnected message overflow patterns associated with specific exploit tools; Tri-station protocol frames on networks where Triconex SIS is supposed to be air-gapped.

### "Every packet matters; every change is forensic evidence"

In IT, packet capture is rotated out after weeks or months because storage cost is high. In OT, the regulatory regime (NERC CIP, post-Colonial TSA directives, EU NIS2) increasingly requires multi-year retention, and per-device traffic volume is low enough that multi-year full-packet retention is economically feasible. The defender's posture is "we will have the packets when we need them" — which fundamentally changes IR economics post-incident. Cross-reference [[reference-detection-engineering]] §9 — cloud detection is moving toward *ephemeral* evidence (transient containers, billions of events per day); OT detection is moving toward *complete* evidence (stable inventories, multi-year retention, decade-scale device lifecycles). Different mental models.

---

## IX. ICS-Specific Threat Intelligence and Attribution

### ATT&CK for ICS

MITRE's ICS-specialized ATT&CK matrix. Released 2020. Canonicalizes ICS-specific tactics (Initial Access, Execution, Persistence, Privilege Escalation, Evasion, Discovery, Lateral Movement, Collection, Command and Control, Inhibit Response Function, Impair Process Control, Impact) and techniques (Modify Parameter, Block Reporting Message, Damage to Property, Loss of Productivity and Revenue, etc.). The "Impair Process Control" and "Inhibit Response Function" tactics are the ICS-specific additions without IT-side analogues. Lingua franca of ICS-incident postmortems — Dragos year-in-review, Mandiant ICS reports, CISA advisories all map findings to ATT&CK for ICS.

### Activity Group naming

Dragos uses **mineral names** (XENOTIME, ELECTRUM, CHRYSENE, KAMACITE, COVELLITE, ALLANITE, RASPITE, WASSONITE, PETROVITE, BENTONITE, BAUXITE, VOLTZITE) to avoid the "Bear / Panda / Tiger" stylistic clutter. Each activity group is defined by observed tradecraft, victimology, and tooling — not by attribution to a specific government, although attribution assessments are published in customer-facing intelligence. Mandiant tracks ICS actors under TEMP.*/UNC.* clusters. Microsoft uses weather-based names (Volt Typhoon, Mint Sandstorm). CrowdStrike uses bear/panda/jackal. The fragmentation is real — the same actor may be tracked as Sandworm / VOODOO BEAR / APT44 / ELECTRUM / Iridium across vendors. Cross-reference [[reference-threat-intel-methodology]] §1.

### Common targeting patterns

- **Electric power**: Russian (Sandworm, Energetic Bear / Berserk Bear / Dragonfly), Chinese (Volt Typhoon / VOLTZITE), and increasingly Iranian.
- **Oil and gas (especially Middle East)**: Russian (XENOTIME for SIS-targeting), Iranian (APT33 / HOLMIUM, Shamoon corpus).
- **Water and wastewater (especially small U.S. utilities)**: Iranian (CyberAv3ngers / IRGC-CEC), opportunistic ransomware.
- **Manufacturing**: Opportunistic ransomware (Norsk Hydro, JBS, many smaller events), some Chinese IP-theft motivated.
- **Pharmaceuticals**: Russian (NotPetya collateral on Merck), Chinese IP-theft.
- **Maritime / port automation**: Russian and Chinese pre-positioning; some criminal ransomware (Port of Lisbon 2022, Port of Antwerp-Bruges 2022).

### Nation-state vs commercial cybercrime

In the confirmed-major-incident corpus, **almost all destructive or process-affecting attacks are nation-state** (Stuxnet, BlackEnergy/CrashOverride/Industroyer/Industroyer2, TRITON, Volt Typhoon). Almost all *consequential* commercial cybercrime in OT-adjacent environments has been **IT-side ransomware that forced OT shutdown** (Norsk Hydro, Colonial, JBS). The Trend Micro factory-honeypot work (Hilt et al.) showed opportunistic cybercrime *does* find ICS on the public internet but is not (yet) systematically deploying process-affecting payloads — the criminal economics don't favor it.

Strategic implication: a plant operator's threat model is bifurcated. The likely attacker is opportunistic ransomware that doesn't intend to hurt the process but will halt it as collateral; the consequential attacker is a nation-state actor whose payoff function is held in reserve for geopolitical triggers. Defense for both is overlapping but not identical.

---

## X. Regulatory Landscape

The ICS regulatory regime has accelerated since Colonial Pipeline (2021); the post-Volt-Typhoon climate has pushed it further. Load-bearing corpus:

### NERC CIP

**North American Electric Reliability Corporation Critical Infrastructure Protection** standards. Longest-running mandatory ICS-security regime. Applies to entities that own, operate, or use Bulk Electric System assets in North America. 13 active standards: CIP-002 (BES Cyber System Categorization), CIP-003 (Security Management Controls), CIP-004 (Personnel and Training), CIP-005 (Electronic Security Perimeters), CIP-006 (Physical Security), CIP-007 (System Security Management), CIP-008 (Incident Reporting), CIP-009 (Recovery Plans), CIP-010 (Configuration Change Management), CIP-011 (Information Protection), CIP-012 (Communications between Control Centers), CIP-013 (Supply Chain Risk Management), CIP-014 (Physical Security of substations). Enforced by FERC. Non-compliance penalties can exceed $1M per day per violation. Mature regime, criticized as compliance- rather than threat-oriented; mature utilities use NERC CIP as a floor.

### TSA Pipeline Security Directives

Post-Colonial. **Security Directive Pipeline-2021-01** (May 28, 2021, mandatory incident reporting), **Pipeline-2021-02** (July 20, 2021, designated cybersecurity coordinator, vulnerability assessment, mitigation plan), and successors through 2026. Applies to TSA-designated critical hazardous-liquid and natural-gas pipeline operators. Less mature than NERC CIP; more rapidly evolving. TSA also has authority over rail, mass transit, air-cargo cybersecurity.

### EU NIS2 Directive (October 2024)

Network and Information Security Directive 2. Replaces 2016 NIS Directive. Substantially broader sectoral scope ("essential entities" — energy, transport, banking, healthcare, drinking water, waste water, digital infrastructure, public administration, space, food, chemicals, postal/courier, manufacturing of specified products). Required transposition into national law by October 17, 2024. Key new obligations: incident reporting within 24h (initial), 72h (assessment), 1 month (final); board-level cybersecurity accountability (directors personally liable); supply-chain risk-management requirements; penalties up to €10M or 2% of global turnover. Broadest OT-scope regulatory regime in the world; the multinational compliance overhead is the load-bearing driver of OT-monitoring purchases in EU plants since 2024.

### EU Cyber Resilience Act (CRA)

Adopted October 2024; enforcement begins in stages 2026-2027. Mandates security requirements for "products with digital elements" — explicitly inclusive of IoT, industrial IoT, ICS components. Requires CE-mark-conformant cybersecurity (vulnerability handling, security-by-design, no known vulnerabilities at point of sale, support window with security updates). Vendors of PLCs, RTUs, HMIs sold into the EU will be in scope; the long device-lifecycle reality of ICS will collide with the CRA's expected support window.

### CISA ICS-CERT advisories

The U.S. Cybersecurity and Infrastructure Security Agency's ICS-CERT is the primary public source for ICS vulnerability advisories. The feed at cisa.gov/news-events/ics-advisories runs several per week — vendor-coordinated disclosures for specific PLC firmware vulnerabilities, HMI software issues, protocol-implementation bugs. Cross-reference any ICS vulnerability research against the CISA ICS-CERT database before disclosure.

### ISA/IEC 62443

Canonical international ICS-security standards family. Developed by ISA99 / IEC TC65 WG10. Four parts:

- **62443-1**: General concepts (definitions, security lifecycle).
- **62443-2**: Policies and procedures (security program for asset owners).
- **62443-3**: System-level requirements (security levels, zones-and-conduits architecture).
- **62443-4**: Component-level requirements (security capabilities of products).

The **zones-and-conduits** architecture (62443-3-2) is the load-bearing concept: segment the OT environment into zones (collections of assets with common security requirements), define conduits (controlled communication paths between zones), assess each zone for a target security level (SL-T), engineer conduits to enforce that level. Increasingly cited by NIS2 and CRA as the recommended technical control framework.

### SOCI Act (Australia)

**Security of Critical Infrastructure Act 2018**, major amendments via SLACIP Act 2022. Applies to 11 sectors of critical infrastructure including energy, water, financial services, communications, food/grocery. Mandatory reporting to the Australian Signals Directorate (ASD); enables government-mandated remediation under exceptional circumstances. The "step-in" provision (government can directly intervene to defend critical infrastructure in a serious cyber incident) is one of the most extensive emergency authorities in any democratic country's cybersecurity regime.

### Sector-specific

- **Nuclear (US)**: NRC; 10 CFR 73.54 ("Protection of digital computer and communication systems and networks"). Most stringent cybersecurity requirements in any U.S. regulated sector.
- **Electric (US)**: FERC for bulk power; state public-utility commissions for distribution.
- **Water (US)**: EPA; America's Water Infrastructure Act of 2018 mandated cybersecurity vulnerability assessments for community water systems serving >3,300 people. CISA-EPA collaboration accelerated post-CyberAv3ngers.
- **Chemical (US)**: CFATS program, administered by CISA (statutory authority expired in July 2023 pending Congressional reauthorization).
- **Aviation (US)**: FAA for aircraft systems; TSA for airport/air-cargo cybersecurity.

### Regulation lags reality

Most ICS regulation today was drafted in response to specific incidents (NERC CIP after 2003 Northeast blackout; TSA after Colonial; EPA water-sector mandates after CyberAv3ngers). The regulatory regime is structurally reactive; the gap between an emerging threat class and the regulatory mandate addressing it is typically 2-5 years. Plant operators with ahead-of-regulation security programs survive the next-incident cycle without becoming a case study.

---

## XI. Defensive Architecture

### Network segmentation: the Purdue 3.5 DMZ

The single highest-leverage defensive control. A properly-implemented Industrial DMZ between IT and OT eliminates most of the IT-side-ransomware-causes-OT-shutdown failure modes that have dominated the post-2017 incident corpus. Key principles:

- **No direct connections** from Level 4 to Levels 0-3. All cross-boundary traffic terminates in the DMZ.
- **Authenticated jump servers** for engineer remote access. MFA on the jump server. Session recording. Time-limited access.
- **Data-historian replication** unidirectional from OT to DMZ to IT. Historical process data flows out; nothing flows back into OT.
- **Software-update staging** in the DMZ. AV signatures, vendor firmware patches, Windows updates land in DMZ-hosted repositories; OT endpoints pull from the DMZ, never directly from the internet.
- **Vendor remote access** terminates in the DMZ via a brokered tunnel (Cyolo / Claroty SRA) with per-session approval.

### Unidirectional gateways (data diodes)

For high-criticality boundaries (Level 3 historian to Level 4 enterprise BI; SIS to its monitoring), a one-way physical data diode is the strongest guarantee available. Vendors: **Waterfall Security Solutions** (widely deployed in nuclear, electric, pipeline), **Owl Cyber Defense**, **Fox-IT DataDiode**. The diode passes data optically and is *physically* incapable of carrying traffic in reverse. Where the safety case requires it, diodes are the canonical answer.

### OT-aware firewalls

Cross-reference Byres (Section I). Beyond Tofino, the modern OT-firewall market includes Cisco ISA 3000 / Industrial Ethernet switches with FirePower, Fortinet FortiGate Rugged, Palo Alto PA-220R, Check Point 1570R, Belden Hirschmann EAGLE. Differentiator: deep protocol inspection at function-code level on Modbus, EtherNet/IP CIP-service-code filtering, S7Comm function-call filtering, IEC 60870-5-104 ASDU-type filtering.

### Engineering workstation hardening

Cross-reference Section VI. Checklist:

- **Application allowlisting** (Microsoft AppLocker, Carbon Black App Control, Symantec Data Center Security). Only signed, approved binaries execute.
- **USB control** (allow only signed firmware-update USB sticks; alarm on any other device).
- **Network egress restriction**. The EWS should not reach the public internet. All updates flow through the DMZ.
- **Per-session authentication** to the vendor engineering software. Don't let the user run the engineering tool in a logged-in-from-yesterday state.
- **Project-file integrity** monitoring. The set of PLC project files in version control is small and changes slowly; modifications outside the approved change-management process should be alarmed.

### Patch management — "months-to-years-behind on purpose"

The operator must: wait for vendor certification against the safety case (months); stage in a test environment (rare and expensive); plan a maintenance window (quarterly or semi-annually); coordinate with downstream production scheduling (weeks of lead time). The result: routine months-to-years of known unpatched vulnerabilities. The compensating control is *not* faster patching (the constraints are real) but **more aggressive segmentation** and **more aggressive monitoring**. The mature operator's posture is "we know we have unpatched systems; we know they cannot be exposed; we will detect any access to them."

### Active scanning vs OT

Controversial in OT-security circles. Active vulnerability scanning (Nessus, Qualys, Tenable) sends crafted packets that can crash legacy ICS devices — scanning a Modicon PLC with an unsupported function code can crash its protocol stack, forcing a reboot. The modern consensus: **passive scanning** is the default; **active scanning** is allowed only during planned maintenance windows on documented-compatible devices, and never on SIS.

### Backup and restore at the PLC level

Standard practice: maintain a known-good copy of every PLC program in version control with cryptographic hashes pinned. Recovery from a corrupted or compromised PLC is "stop the device, load the known-good program, restart." The Stuxnet / TRITON / Industroyer corpus underlines that without offline-stored, integrity-protected PLC programs, recovery is open-ended. Vendor tools (TIA Portal, Studio 5000, Control Expert) support program export to file formats checkable into Git or object-locked S3. Discipline is operational, not technical.

### Vendor support contracts

OT operators are typically locked into multi-decade support contracts. Some vendors require remote-support tunnels that cannot be disabled without voiding warranty; some disclaim responsibility for customer network design; some push back on third-party tooling. Coordination is part of the work.

### Code review checklist for ICS-adjacent code

For code interacting with PLCs, RTUs, HMIs, or industrial protocols. Cross-reference [[reference-code-review-expertise]] and [[reference-appsec-program-building]].

1. **Does the code authenticate the device?** Most industrial protocols don't, so the code has to. mTLS, HMAC-based message authentication, or separate-channel verification at the application layer.
2. **Does the code validate the function code / command before executing?** A "write to register" command from an HMI should be sanity-checked against a known-safe register range, not blindly forwarded.
3. **Does the code handle protocol-level malformed input?** Industrial-protocol parsers historically crash. Fuzz the parser; constrain input.
4. **Does the code respect operational state?** Some commands are only safe in certain process states; encode the safety case in code.
5. **Does the code log the command for forensic recovery?** Every write logged with timestamp, source, command, target. Append-only; exported to a separate system.
6. **Does the code rate-limit?** A flood of writes from a stuck client can DoS the device or sequence the process into an unsafe state.
7. **Does the code handle disconnections gracefully?** Loss of HMI-to-PLC connection should not leave the PLC indeterminate; the safety case usually requires defined timeout behavior.
8. **Does the code use TLS where the protocol supports it?** OPC UA, EtherNet/IP CIP Security, Modbus Security, DNP3 SAv5 — use them.
9. **Does the code separate read-from-write privileges?** Many integrations only need read; don't grant write if not required.
10. **Does the code expose engineering operations?** Program-download, firmware-update, configuration-change should be on a separate, more-restricted path than data-access.
11. **Does the code validate certificates / pre-shared keys correctly?** OPC UA certificate validation has been the source of many bugs.
12. **Does the code clearly delineate IT and OT contexts?** Cross-boundary code is where many incidents originate; explicit separation in code structure (separate modules, authentication contexts, logging streams) is worth the engineering cost.
13. **Does the code alarm on its own state?** A protocol gateway should alarm on its own internal failures (queue depth, retries, certificate near expiry) — operators need to know when the gateway is degraded.

---

## XII. Variant Analysis: Under-Explored Surfaces

### Cloud-connected ICS (Industry 4.0)

Cross-reference [[reference-firmware-embedded-security]] §IX (cloud IoT). The convergence trend is moving OT data into AWS IoT SiteWise, Azure Industrial IoT, Google Cloud Industrial Solutions, MES-as-a-Service platforms. New attack surfaces:

- **Cloud-to-OT control loops**. Some vendors offer "cloud-driven" setpoint optimization (predictive maintenance, energy optimization, yield maximization). The control signal originates in the cloud and flows back to the PLC. Compromise of the cloud account = compromise of the plant.
- **Vendor management consoles**. The PLC vendor's cloud console (AWS-hosted Siemens Insights Hub) is often the single administrative reach into thousands of customer plants. A vendor-console compromise has the blast radius of a small nation-state.
- **OAuth / SSO ties to corporate identity**. Cloud-OT consoles increasingly federate to corporate IdP (Okta, Entra ID). Cross-reference [[reference-saml-federation]] — the same federation-misconfiguration risks apply with OT consequence.

### AI-driven process optimization

A 2024-2026 emerging surface. Honeywell Forge, Siemens Industrial Edge, Rockwell FactoryTalk Analytics, Cognite Data Fusion offer ML-driven setpoint optimization. The model proposes; the operator approves; the setpoint is pushed to the PLC. Risks as human-in-the-loop is reduced:

- **Model poisoning** during training. Cross-reference [[reference-llm-agent-security]] and [[reference-adversarial-ml-model-security]]. Corrupted training data shapes the model toward dangerous recommendations.
- **Adversarial inputs at inference**. Crafted sensor values that exploit ML blind spots to recommend unsafe setpoints.
- **Trust delegation**. As operators learn to trust the model, they approve with less scrutiny.

Consensus: AI-optimization should be **advisory only** for any safety-critical loop. Where the loop is closed (model directly drives PLC), the safety case must include an SIS that catches model-induced excursions.

### AI agents in industrial settings

Cross-reference [[reference-llm-agent-security]]. Pre-2026, LLM-driven autonomous agents have been mostly confined to IT-adjacent work. Early industrial deployments are now appearing — "ask the agent to summarize today's process data," "have the agent suggest the next maintenance action." Trajectory: agents that can read process state, interpret it, make recommendations. The transition from "agent reads OT data" to "agent writes OT setpoints" is the load-bearing safety question. Conservative posture: write actions to OT must be gated by human approval *and* safety-engineering review *and* SIS independence. The evaluation literature for industrial LLM agents is not where it needs to be for safety-critical operation.

### Building automation (BACnet)

Commercial-real-estate equivalent of ICS. BACnet (ASHRAE Standard 135) is the dominant building-automation protocol — HVAC, lighting, access control, elevators. Plaintext, unauthenticated, originally designed for trusted RS-485 networks, now widely deployed on IP. Building automation is increasingly cyber-physical (compromised HVAC degrades indoor air quality; compromised access-control enables physical intrusion; compromised elevators deny service). The defender community is small relative to industrial ICS; the incident corpus is just beginning to develop.

### EV charging infrastructure (OCPP)

Open Charge Point Protocol — de facto standard for communication between EV charging stations and backend management. Defines load-management, authentication, billing flows. OCPP 1.6 (current dominant deployment) has known security weaknesses; OCPP 2.0.1 adds TLS, certificate-based authentication, ISO 15118 plug-and-charge integration. Multi-million-charger global deployment. Compromise patterns: grid-load manipulation (mass simultaneous charge/discharge to destabilize local grid), billing fraud, payment-card harvesting at the charger HMI. In V2G (vehicle-to-grid) deployments the EV can push power back to the grid — turning every connected EV into a small ICS endpoint.

### Renewable energy: wind and solar inverters

Modern wind turbines and solar inverters are network-connected ICS devices. Solar inverter standards (IEEE 1547-2018, Rule 21 in California) increasingly require utility-controllable functions (volt-VAR, frequency-watt, anti-islanding) — meaning the utility can remotely command the inverter, meaning the inverter has an attack surface that can be used to destabilize the grid in aggregate. Recent CISA advisories on Solar-Log, SMA, Sungrow inverters reflect maturation. Wind farms are similarly networked; the Russia-attributed KA-SAT attack (February 2022) cut remote monitoring and control of 5,800 Enercon wind turbines in Germany as spillover — via the Viasat satellite-modem segment, not direct turbine compromise.

### Maritime ICS

Cargo ships are increasingly automated — bridge systems, engine-room monitoring, cargo-management, ballast-water systems all networked. Port automation (cranes, conveyors, gate systems) is similarly networked. Compromise patterns: navigation spoofing (GPS jamming/spoofing demonstrated in multiple academic contexts), engine-room remote attack surface, port-operations ransomware (Port of Lisbon 2022, Port of Antwerp-Bruges petroleum terminals 2022). IMO MSC.428(98) (2017) requires maritime operators to address cyber risk in their ISM Code safety management systems, with enforcement beginning January 1, 2021. The maritime regulatory regime is decades behind air-cargo and pipeline.

### Aviation Maintenance Operations Management (MOMs)

Aviation's MES-equivalent for aircraft maintenance — parts tracking, inspection scheduling, airworthiness directives. Not flight-critical (flight-critical avionics are a separate world under DO-178C and 14 CFR Part 25), but a MOM compromise can ground fleets via data-integrity failure ("we can no longer verify which aircraft has the required inspection").

### Cross-link summary

- [[reference-firmware-embedded-security]] — embedded substrate; PLC firmware, hardware root of trust, JTAG/SPI extraction.
- [[reference-threat-intel-methodology]] — Dragos / Mandiant intel taxonomy; Diamond Model.
- [[reference-detection-engineering]] — OT-specific detection patterns; cloud-vs-OT contrast.
- [[reference-dfir-methodology]] — ICS-IR vs IT-IR differences.
- [[reference-cryptography]] — legacy-crypto reality; DNP3 SAv5 / OPC UA / IEC 62351 primitives.
- [[reference-dns-network-infrastructure]] — protocol-level defense framing.
- [[reference-llm-agent-security]] — AI agents in industrial settings.
- [[reference-adversarial-ml-model-security]] — ML model risk in process optimization.
- [[reference-saml-federation]] — federation risks in cloud-OT consoles.
- [[reference-code-review-expertise]] — code-review heuristic stack.
- [[reference-appsec-program-building]] — program-level integration of OT into the appsec function.
- [[reference-mobile-security]] — mobile-app-to-ICS interfaces (operator mobile HMIs, vendor support apps).

---

## XIII. References

### Primary-source documents

- Ralph Langner, "To Kill A Centrifuge: A Technical Analysis of What Stuxnet's Creators Tried to Achieve" (Langner Group, November 2013). https://www.langner.com/wp-content/uploads/2017/03/to-kill-a-centrifuge.pdf
- Robert M. Lee, Michael J. Assante, Tim Conway, "Analysis of the Cyber Attack on the Ukrainian Power Grid" (SANS / E-ISAC, March 2016). https://www.nerc.com/pa/CI/ESISAC/Documents/E-ISAC_SANS_Ukraine_DUC_18Mar2016.pdf
- Dragos, "CRASHOVERRIDE: Analyzing the Malware that Attacks Power Grids" (Dragos, June 2017). https://www.dragos.com/wp-content/uploads/CrashOverride-01.pdf
- Anton Cherepanov, "Win32/Industroyer: A new threat for industrial control systems" (ESET, June 2017). https://www.welivesecurity.com/wp-content/uploads/2017/06/Win32_Industroyer.pdf
- ESET research, "Industroyer2: Industroyer reloaded" (April 2022). https://www.welivesecurity.com/2022/04/12/industroyer2-industroyer-reloaded/
- Mandiant, "Attackers Deploy New ICS Attack Framework “TRITON” and Cause Operational Disruption to Critical Infrastructure" (2017). https://cloud.google.com/blog/topics/threat-intelligence/attackers-deploy-new-ics-attack-framework-triton/
- Benjamin Green, Marina Krotofil, Ali Abbasi, "On the Significance of Process Comprehension for Conducting Targeted ICS Attacks" (CPS-SPC 2017, ACM). https://dl.acm.org/doi/10.1145/3140241.3140254
- Digital Bond, "Project Basecamp" archive. https://github.com/digitalbond/Basecamp
- Stephen Hilt et al., "Caught in the Act: Running a Realistic Factory Honeypot to Capture Real Threats" (Trend Micro, 2020). https://documents.trendmicro.com/assets/white_papers/wp-caught-in-the-act-running-a-realistic-factory-honeypot-to-capture-real-threats.pdf
- INL Aurora Test Report (partial public release; CSO Online summary at https://www.csoonline.com/article/566813/why-america-is-not-prepared-for-a-stuxnet-like-cyber-attack-on-the-energy-grid.html)

### CISA advisories

- CISA / FBI / NSA AA23-335A, "IRGC-Affiliated Cyber Actors Exploit PLCs in Multiple Sectors, Including US Water and Wastewater Systems Facilities" (December 2023). https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-335a
- CISA / FBI / NSA AA24-038A, "PRC State-Sponsored Actors Compromise and Maintain Persistent Access to U.S. Critical Infrastructure" (Volt Typhoon, February 2024). https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-038a
- CISA / FBI / NSA AA23-144A, "People's Republic of China State-Sponsored Cyber Actor Living off the Land to Evade Detection" (May 2023). https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-144a
- CISA AA26-097A, "Iranian-Affiliated Cyber Actors Exploit Programmable Logic Controllers Across US Critical Infrastructure" (2026). https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-097a
- CISA, "CrashOverride Malware" (June 2017). https://www.cisa.gov/news-events/alerts/2017/06/12/crashoverride-malware
- CISA, "Exploitation of Unitronics PLCs used in Water and Wastewater Systems" (November 2023). https://www.cisa.gov/news-events/alerts/2023/11/28/exploitation-unitronics-plcs-used-water-and-wastewater-systems
- CISA, MAR-10448362-1.v1 Volt Typhoon (February 2024). https://www.cisa.gov/news-events/analysis-reports/ar24-038a

### Standards and frameworks

- IEC 62443 series (Industrial automation and control systems security). https://webstore.iec.ch/publication/7029
- IEEE 1815-2012 (DNP3 with Secure Authentication v5). https://standards.ieee.org/ieee/1815/4720/
- IEC 61850 (Communication networks and systems for power utility automation). https://webstore.iec.ch/publication/6028
- IEC 61508 (Functional Safety). https://webstore.iec.ch/publication/22273
- IEC 61511 (Functional safety — Safety instrumented systems for the process industry). https://webstore.iec.ch/publication/24241
- NERC CIP Reliability Standards. https://www.nerc.com/standards/reliability-standards/cip
- ATT&CK for ICS. https://attack.mitre.org/matrices/ics/
- EU NIS2 Directive (Directive (EU) 2022/2555). https://eur-lex.europa.eu/eli/dir/2022/2555/oj
- EU Cyber Resilience Act (Regulation (EU) 2024/2847). https://eur-lex.europa.eu/eli/reg/2024/2847/oj
- TSA Pipeline Security Directives. https://www.tsa.gov/news/press/releases/2021/05/27/dhs-announces-new-cybersecurity-requirements-critical-pipeline-owners

### Vendor research and year-in-review reports

- Dragos Year-in-Review reports. https://www.dragos.com/year-in-review/
- Kaspersky ICS-CERT, "Threat Landscape for Industrial Automation Systems." https://ics-cert.kaspersky.com/publications/reports/
- Mandiant ICS-OT Threat Intelligence. https://cloud.google.com/security/resources/insights/ics-ot
- Claroty / Team82 research. https://claroty.com/team82/research
- Nozomi Networks Labs. https://www.nozominetworks.com/labs/

### Wikipedia anchors

- Stuxnet. https://en.wikipedia.org/wiki/Stuxnet
- Aurora Generator Test. https://en.wikipedia.org/wiki/Aurora_Generator_Test
- Industroyer. https://en.wikipedia.org/wiki/Industroyer
- Triton (malware). https://en.wikipedia.org/wiki/Triton_(malware)
- Colonial Pipeline ransomware attack. https://en.wikipedia.org/wiki/Colonial_Pipeline_ransomware_attack
- Modbus. https://en.wikipedia.org/wiki/Modbus
- IEC 61850. https://en.wikipedia.org/wiki/IEC_61850
- DNP3. https://en.wikipedia.org/wiki/DNP3

### Books and long-form

- Kim Zetter, *Countdown to Zero Day: Stuxnet and the Launch of the World's First Digital Weapon* (Crown, 2014) — the definitive long-form journalistic account of Stuxnet.
- Andy Greenberg, *Sandworm: A New Era of Cyberwar and the Hunt for the Kremlin's Most Dangerous Hackers* (Doubleday, 2019).
- Andrew Ginter, *SCADA Security: What's Broken and How to Fix It* (Abterra Technologies, 2016).
- Eric D. Knapp, Joel Thomas Langill, *Industrial Network Security* (Syngress, 2nd ed. 2014).
- Robert M. Lee, *SCADA and Me* (IT-Harvest Press, 2013; available via Dragos resources).
- Joe Weiss, *Protecting Industrial Control Systems from Electronic Threats* (Momentum Press, 2010).
- Andrew Coburn, Éireann Leverett, Gordon Woo, *Solving Cyber Risk: Protecting Your Company and Society* (Wiley, 2018).

### Conferences

- **S4** (Digital Bond, annual since 2007). https://s4xevents.com/
- **CS3STHLM** (Stockholm). https://cs3sthlm.se/
- **SANS ICS Security Summit** (annual). https://www.sans.org/cyber-security-summit/
- **ICS Cyber Security Conference** (Joe Weiss, annual since 2002). https://icscybersecurityconference.com/
- **Black Hat USA / DEF CON** — ICS track since ~2010.
- **IEEE / IFIP WG 11.10 International Conference on Critical Infrastructure Protection**.
