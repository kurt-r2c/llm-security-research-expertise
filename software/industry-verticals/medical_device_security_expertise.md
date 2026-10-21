# Medical Device Cybersecurity — Implantables, Hospital Infrastructure, and IoMT
## Staff-Level Technical Reference

---

## I. Researcher Profiles

Medical-device cybersecurity has three overlapping lineages, each distinct from mainstream IT security. The first is the academic/regulatory lineage from the Kohno-Fu collaboration at UW and UMass Amherst (2007-2012), which produced the canonical "Pacemakers and Implantable Cardiac Defibrillators" paper, the Archimedes Center, and the FDA medical-device-security office. The second is the practitioner/disclosure lineage anchored by Billy Rios and Jay Radcliffe, whose disclosures (infusion pumps, insulin pumps, pacemaker programmers) drove the first FDA recalls and CISA medical advisories. The third is the policy/advocacy lineage led by Joshua Corman, Beau Woods, Karen Sandler, and Marie Moe, which forced the regulatory regime the practitioners' disclosures alone could not move. Most senior researchers straddle two of the three.

### Karen Sandler — Software Freedom Conservancy (Executive Director)

**Career arc**: Attorney; previously Executive Director of the GNOME Foundation; Executive Director of Software Freedom Conservancy since 2014. Diagnosed with hypertrophic cardiomyopathy; implanted with a defibrillator. Describes herself as a "cyborg lawyer" because the proprietary firmware in her chest is unreviewable by her or her physicians.

**Core contribution**: Legal and ethical advocacy for the right to inspect the source code of life-supporting medical devices. Sandler's 2010 essay "Killed by Code: Software Transparency in Implantable Medical Devices" remains the canonical statement of the position. The argument is not primarily a security argument — closer to medical ethics and informed consent — but the security implications are direct: a device whose source nobody outside the vendor has reviewed cannot be independently assessed for vulnerability or safety.

**Frame Sandler introduced**: The implanted medical device is the strongest possible case for software transparency. The asymmetry between vendor and patient — neither the patient nor her cardiologist can audit the firmware running her heart — is structurally inconsistent with informed-consent medical ethics. The moral backbone of the "I Am The Cavalry" policy work.

### Kevin Fu — Northeastern University (Khoury College) / formerly FDA

**Career arc**: Professor at Northeastern; founded and directs the Archimedes Center for Healthcare and Device Security (originally University of Michigan). Served as the first Acting Director of Medical Device Cybersecurity at FDA's Center for Devices and Radiological Health (2021-2022). Co-author on the 2008 Halperin paper. IEEE Security & Privacy Test of Time Award. Research focus: "analog cybersecurity" — modeling threats to the physics of computation and sensing (acoustic injection into MEMS sensors).

**Core contribution**: Built the institutional infrastructure that makes medical-device cybersecurity a field rather than a series of one-off disclosures. The Archimedes Center is the canonical academic-industry-regulator convening venue. His FDA tenure pulled the agency's cybersecurity guidance from advisory-only to enforcement-backed.

**Frame Fu introduced**: Medical-device cybersecurity is a sensor-physics problem at least as much as a software problem. The defender's mental model must include the analog front-end of every clinical sensor. Cross-link to [[reference-hardware-side-channels]].

### Daniel Halperin and Tadayoshi Kohno — University of Washington

**Career arc**: Halperin — Ph.D. UW (advised by David Wetherall and Tom Anderson); later UW eScience Institute and Google. Kohno — Professor and Director of UW Security and Privacy Research Lab; co-author of *Cryptography Engineering* (Ferguson/Schneier/Kohno, 2010); long-running cross-domain security researcher. Cross-referenced in [[reference-automotive-security]] for the parallel 2010 Oakland and 2011 USENIX automotive papers.

**Core contribution**: First author (Halperin) and senior author (Kohno) on "Pacemakers and Implantable Cardiac Defibrillators: Software Radio Attacks and Zero-Power Defenses" (IEEE S&P 2008; Best Paper; later Test of Time). Reverse-engineered the wireless interface of a then-current Medtronic ICD operating in the 175 kHz band; demonstrated unauthenticated telemetry harvesting, magic-packet activation, parameter reprogramming, and battery-drain. Proposed "zero-power" RF-harvested authentication primitives. Co-authors: Heydt-Benjamin, Ransford, Clark, Defend, Morgan, Fu, and cardiologist William H. Maisel.

**Frame Halperin/Kohno introduced**: Implantable medical devices inherit all the vulnerabilities of consumer electronics. The clinician-and-vendor mental model of "it's on a private RF band so it's safe" did not survive contact with a software-defined radio. Every subsequent IMD-security paper is downstream of this work.

### Marie Moe — mnemonic / formerly SINTEF

**Career arc**: Norwegian information-security researcher; senior research positions at SINTEF, Norwegian NorCERT, now at mnemonic. Received a pacemaker in 2011. Began the Pacemaker Hacking Project in 2015 with Eireann Leverett.

**Core contribution**: The 32C3 talk "Unpatchable: Living with a vulnerable implanted device" (with Leverett) — a patient-researcher first-person account of the lifecycle of a single pacemaker with documented firmware bugs affecting her own clinical care. The 2020 CERT advisory she and her research team triggered identified five vulnerabilities in the Biotronik Home Monitoring Unit, with the vendor declining to issue a product security update — a useful case study in coordinated-disclosure failure modes for implantables.

**Frame Moe introduced**: The patient is a stakeholder. The implantable-device security conversation is a three-party negotiation: regulator, manufacturer, and the patient who carries the device. This frame is now baked into FDA postmarket guidance and EU MDR cybersecurity expectations.

### Billy Rios — WhiteScope (founder)

**Career arc**: Former Marine Corps cyber-warfare officer; security roles at Microsoft, Cylance, Qualys, Google before founding WhiteScope in 2014. Pivoted into medical-device, ICS, and physical-security research with multiple FDA-coordinated advisories per year. Cross-referenced in [[reference-ics-ot-security]].

**Core contribution**: The 2014-2015 Hospira infusion-pump corpus (LifeCare PCA, Plum A+, Symbiq). Documented hardcoded credentials, unauthenticated drug-library upload, telnet on port 23, lateral-movement primitives on the hospital network. The Symbiq advisory in July 2015 was the first time FDA explicitly urged hospitals to "discontinue use" of a medical device for cybersecurity reasons. Subsequent work with Jonathan Butts established baseline for implantable-cardiac-device infrastructure.

**Frame Rios introduced**: A hospital infusion pump is an internet-connected embedded computer with hardcoded telnet that delivers chemotherapy. The biomedical-engineering mental model of "it's FDA-regulated, it must be safe" is structurally wrong. Default-distrust until enumerated otherwise.

### Jonathan Butts — QED Secure Solutions (founder)

**Career arc**: Air Force veteran; Ph.D. computer science from the University of Tulsa; long-running ICS and embedded-systems researcher. Co-founded QED Secure Solutions with Rios.

**Core contribution**: With Rios, the 2017-2018 pacemaker-programmer research documenting ~8,000 known vulnerabilities in third-party libraries across programmers from four major implantable-cardiac vendors (Medtronic, Abbott/St. Jude, BIOTRONIK, Boston Scientific). The Black Hat 2018 talk demonstrated that the Medtronic CareLink 2090 programmer's software-update network delivered unsigned, unencrypted updates, permitting malicious firmware that could alter shock delivery.

**Frame Butts and Rios established**: The pacemaker programmer is the single highest-value target in the implantable-cardiac ecosystem. The implant's security model assumes the programmer is trusted; if the programmer is compromised, the entire trust chain collapses.

### Jay Radcliffe — Rapid7 (Senior Security Consultant)

**Career arc**: Type 1 diabetic; insulin-pump user. Became a security researcher after a self-funded reverse-engineering effort against his own Medtronic pump.

**Core contribution**: Black Hat USA 2011 "Hacking Medical Devices for Fun and Insulin: Breaking the Human SCADA System" — a live on-stage wireless attack that disabled his own insulin pump (a Medtronic Paradigm). Forced the medical-device industry into the public security conversation in a way the 2008 ICD paper had not, because the disclosing party was visibly downstream of the safety-critical bug class. Subsequent CVEs against OneTouch glucose meters and Animas pumps (CVE-2016-5085).

**Frame Radcliffe introduced**: The patient-researcher is a structurally different disclosure actor. Vendor counter-arguments about "theoretical attacks" do not work when the disclosing party is wearing the device and can demonstrate the kill on themselves.

### Justine Bone — formerly MedSec (CEO)

**Career arc**: Long-running security researcher with prior leadership at Bloomberg, Dow Jones, ISS X-Force. CEO of MedSec.

**Core contribution**: The 2016 MedSec / Muddy Waters short on St. Jude Medical — a categorically different disclosure model where MedSec partnered with activist short-seller Muddy Waters Capital to publish security findings on St. Jude's Merlin@home pacemaker-monitoring transmitter and ICDs after concluding vendor's prior responses had been inadequate. Muddy Waters shorted St. Jude stock; MedSec received research fees and trading-profit share. St. Jude sued; FDA opened an investigation; vulnerabilities were confirmed; firmware updates were issued. The canonical example of "what happens when conventional coordinated disclosure fails."

**Frame Bone introduced**: Market mechanisms can correct security misalignment when regulatory mechanisms do not. The case did not become the new normal but permanently changed vendor risk-calibration. Cross-link to [[reference-steelman-doctrine-expertise]] on disclosure-ethics adjudication.

### Joshua Corman — Institute for Security and Technology / I Am The Cavalry (Founder)

**Career arc**: Long arc of enterprise-security leadership (451 Group, IBM, Akamai, Sonatype). Founded "I Am The Cavalry" at DEF CON 21 (2013) as a volunteer-led grassroots organization addressing the convergence of security and public safety. Chief Strategist of CISA's COVID Task Force (2020-2022). Currently Executive in Residence for Public Safety & Resilience at IST. Senate HELP Committee testimony (May 2022) on healthcare cybersecurity.

**Core contribution**: Built the policy bridge between researcher disclosure and federal regulatory authority. The "Hippocratic Oath for Connected Medical Devices" (I Am The Cavalry, January 2016) became the public-facing draft of what later became the FDA premarket and postmarket guidance.

**Frame Corman introduced**: Public-safety language is the only effective lever for healthcare-cybersecurity policy. Compliance-language does not move regulators; patient-harm language does. Every effective healthcare-cybersecurity statute since 2016 (PATCH Act, EU MDR Annex I, CISA's HPH sector plan) frames its case in those terms.

### Beau Woods — I Am The Cavalry (Co-Founder) / Stratigos Security

**Career arc**: Founder/CEO of Stratigos Security. Co-leader of I Am The Cavalry with Corman. Cyber Safety Innovation Fellow with Atlantic Council. Senior Advisor with CISA. Entrepreneur in Residence with FDA. Long-running DEF CON Policy track leadership.

**Core contribution**: Operationalized Corman's framing into actual standards engagement. Sits on most relevant industry-standards bodies (AAMI, H-ISAC Medical Device Security Council) and is the most consistent translator between researcher and regulator communities. Cross-link to [[reference-appsec-program-building]] on standards engagement as an appsec function.

**Frame Woods introduced**: The medical-device security ecosystem is small enough that every relevant practitioner has met every other relevant practitioner at a conference. Standards engagement is the actual mechanism by which the field organizes itself.

### Eireann Leverett — Cambridge Centre for Risk Studies

**Career arc**: Senior researcher on cyber risk at Cambridge Centre for Risk Studies. Cross-referenced in [[reference-ics-ot-security]] for ICS internet-exposure work; included here for the Pacemaker Hacking Project collaboration with Moe (2015-2020) and ongoing healthcare-aggregate-loss modeling.

**Core contribution**: With Moe, the multi-year reverse-engineering of the Biotronik pacemaker ecosystem (HMU firmware, proprietary telemetry protocol, vendor cloud back-end). Cambridge healthcare-sector cyber-risk modeling feeds the IEC 80001 risk-management framework and cyber-insurance pricing used by H-ISAC members.

**Frame Leverett introduced**: Healthcare cybersecurity is also an actuarial problem. The medical-device community historically had no aggregate-loss models; that gap is now closing.

### Institutional contributors

**Health-ISAC**. Founded 2010; 1,000+ member organizations across 140 countries by 2025. The Medical Device Security Council (MDSC) within H-ISAC is the meeting venue where Health Delivery Organizations and Medical Device Manufacturers coordinate. Health-ISAC Indicator Threat Sharing (HITS) feed provides STIX/TAXII threat intelligence on healthcare-targeted campaigns.

**Archimedes Center** (Fu). The canonical academic-industry-regulator convening venue for medical-device cybersecurity.

**MedCrypt** (founded 2016 by Mike Kijewski and others). Dominant pre-market cryptographic-tooling and SBOM-management vendor for medical-device manufacturers. The 2023 MedCrypt / NetRise partnership operationalized FDA-mandated SBOM generation for embedded firmware. Cross-link to [[reference-supply-chain-provenance]] §6.

**MedISAO / MITRE / FDA CDRH**. Industrial-base and federal-side institutional anchors for vulnerability coordination.

---

## II. The Medical-Device Threat Model

### Why medical devices are uniquely consequential

Four dimensions distinguish medical-device cybersecurity from any other connected-systems domain:

1. **Direct dependency of human life on device function**. ICD shock decisions; insulin-pump dose calculations; ventilator FiO2 control; infusion-pump rate selection. Wrong output kills the patient on a timescale of seconds to minutes. No IT analog; even ICS failure modes are usually slower.

2. **Multi-decade device lifecycles**. A pacemaker is implanted 10-15 years before battery replacement. MRI scanners depreciate over 7-15 years. Infusion pumps remain on hospital wards 8-12 years. A pacemaker programmer in a 2026 cath lab may be running Windows Embedded Standard 7 (extended support ended October 2020). The "ship and patch" cadence of consumer software cannot apply.

3. **Regulatory-required design constraints**. FDA-cleared firmware cannot be patched without going through a 510(k) special, PMA supplement, or letter-to-file. Change-control is engineered to ensure clinical-safety review of every modification. Patch-deploy cycles are months-to-years, not days.

4. **Patient-data sensitivity**. PHI under HIPAA, Personal Data under GDPR, sensitive-category data under most state laws are subject to mandatory breach-notification. The disclosure burden is above and beyond the patient-safety dimension.

### Patient safety vs cybersecurity — how FDA reframed it

The 2014 FDA premarket cybersecurity guidance made the framing explicit: cybersecurity *is* a patient-safety control. A vulnerability that causes a device to deliver wrong therapy is functionally identical to a hardware fault causing the same outcome. The same risk-management framework (ISO 14971) that manufacturers already used for hardware safety must extend to software vulnerability. The 2016 postmarket and 2023 final premarket guidance walked this further. As of October 2023, FDA can reject marketing submissions lacking cybersecurity content. The patient-safety framing is now load-bearing in the regulatory architecture.

### Trust boundaries in the implantable ecosystem

A modern implantable cardiac device has at least five distinct trust boundaries:

```
Implanted device  <-- MICS/MedRadio 402-405 MHz -->  Bedside transmitter / programmer
       |                                                          |
       |                                                          |  Wi-Fi / cellular
       |                                                          v
       |                                                  Vendor cloud (Merlin@home,
       |                                                  CareLink, Latitude)
       |                                                          |
       |                                                          v
       |                                                  Hospital EHR / clinician
       |
       +---- Patient phone (BLE) ----> Vendor mobile app ----> Vendor cloud (alt path)
```

Each arrow is a separate authentication-and-integrity question. Halperin 2008 attacked the leftmost arrow (wireless interface from implant). Rios/Butts 2017 attacked the second-leftmost (bedside programmer). MedSec 2016 attacked the rightward chain (Merlin@home to St. Jude cloud). Moe 2020 attacked the cloud-to-clinician chain. Each disclosure surfaced different defensive failures because the trust model assumed each arrow was an enforcement boundary, when in practice it was just a hop.

### Physical-access assumptions vs remote-attack reality

The historical vendor defense for implanted-device security has been "the attacker needs physical proximity." MICS-band design range is ~2 meters; the proximity argument held intuitively. Three developments weakened it:

1. **Software-defined radio with high-gain antennae** extends realistic MICS-band attack range to 5-10 meters in clear-air conditions.
2. **Patient-side cloud-connected components** (Merlin@home, MyCareLink, CareLink, Latitude) bring the wireless surface to the patient's home Wi-Fi and transitively to the public internet via the vendor cloud.
3. **Mobile-app-bridged communication** (BLE between the patient's phone and the device, with the phone bridging to vendor cloud) creates a fully remote attack chain.

The defender's mental model in 2026: physical proximity is one of several reach mechanisms, not the limiting one. Cross-link to [[reference-wireless-rf-satellite-security]] §3 (BLE) and §5 (cellular reach).

### Privacy overlay

Even setting aside patient safety, every connected medical device handles regulated personal data. HIPAA Security Rule (45 CFR §164.302-318) imposes specific technical safeguards on covered entities and business associates. GDPR treats health data as Article 9 special-category data. State laws (CCPA, Washington My Health My Data Act) impose state-level privacy regimes. A medical-device security review must consider both the patient-safety surface and the data-protection surface; the controls for each often differ.

### Cross-references

- [[reference-ics-ot-security]] — safety-critical OT cousin; architectural lessons (Purdue model, BPCS vs SIS independence, change-control burden) transfer directly.
- [[reference-firmware-embedded-security]] — embedded substrate; secure boot, signed firmware, hardware root of trust.
- [[reference-rtos-embedded-os]] — many implantables run RTOS (FreeRTOS, ThreadX, MQX).
- [[reference-wireless-rf-satellite-security]] — MICS, MedRadio, BLE, Wi-Fi, cellular surfaces.
- [[reference-supply-chain-provenance]] — SBOM, VEX, component management for FDA-regulated devices.
- [[reference-cryptography]] — primitives and misuse in implantable wireless authentication.
- [[reference-dfir-methodology]] — hospital IR; chain-of-custody for medical devices.

---

## III. Implantable Medical Devices (IMDs)

The implantable category is the canonical hard case. The device is inside the patient's body; battery replacement requires surgery; firmware update is a clinical procedure (in many products, not field-updatable at all); failure modes terminate in patient injury or death within seconds to minutes.

### Pacemakers and ICDs

Dominant implantable cardiac category. Pacemakers initiate cardiac contraction; ICDs add defibrillation shocks in response to ventricular tachyarrhythmia. CRT-D devices combine both with three leads. Major 2026 vendors: Medtronic, Abbott (formerly St. Jude), Boston Scientific, BIOTRONIK, MicroPort. Wireless interfaces: legacy 175 kHz inductive (Halperin target); modern MICS/MedRadio 402-405 MHz; BLE on newer devices (Abbott Confirm Rx, Medtronic Azure/Astra); proprietary 2.45 GHz ISM on some devices.

### Insulin pumps

External (worn) or partially-implanted patch pumps. Examples: Medtronic MiniMed 780G, Tandem t:slim X2, Insulet Omnipod 5, Ypsomed YpsoPump. Closed-loop systems combine pump + CGM (continuous glucose monitor) + control algorithm that adjusts delivery autonomously. The closed-loop surface is materially more dangerous than manual because the control algorithm autonomously translates sensor reads into dose decisions; compromise of sensor input cascades into compromise of dose output. The 2011 Radcliffe demonstration was manual-override; in 2026 the equivalent attacker manipulates the control loop.

### Neurostimulators

Deep brain stimulators (DBS) for Parkinson's, essential tremor; spinal cord stimulators (SCS) for chronic pain; vagus nerve stimulators (VNS) for refractory epilepsy and treatment-resistant depression; sacral neuromodulators. Major vendors: Medtronic, Abbott, Boston Scientific, Nevro. The 2018 Marin et al. work extended pacemaker-analysis methods to neuromodulators and found similar architectural weaknesses.

### Cochlear implants

Audio prostheses for sensorineural hearing loss. Cochlear (dominant share), Advanced Bionics, MED-EL. Lower-stakes than cardiac or neurostim — failure modes terminate in "device no longer works" — but wireless interfaces exist and have been studied less rigorously.

### Drug-delivery pumps (intrathecal)

Implanted pumps delivering pain medication (morphine, ziconotide, baclofen) directly into cerebrospinal fluid. Medtronic SynchroMed is dominant. Dose-overrun is a direct lethality vector.

### Cardiac monitors (ILRs, CardioMEMS)

Implantable loop recorders (Medtronic Reveal LINQ, Abbott Confirm Rx, Boston Scientific LUX-Dx) record ECG continuously, upload to cloud back-end via paired phone or bedside transmitter. CardioMEMS is an implanted pulmonary-artery-pressure sensor; reads wirelessly extracted via external interrogator. Read-only from the implant perspective but carry the same wireless and cloud risks.

### Device + programmer + clinician trust triangle

Every IMD has a corresponding clinician-programmer (bedside computer the cardiologist/neurologist uses to configure the device). The trust model assumes (1) the programmer is physically secured, (2) only authorized clinicians have access, (3) programmer-device wireless is authenticated. All three have been documented to fail in practice. Programmers stored unsecured with shared logins; programmer-to-device auth often weak or absent; the Rios/Butts 2017 work demonstrated programmer firmware itself is vulnerable. **Programmer compromise is the single highest-consequence event in the IMD ecosystem.**

### Battery and lifespan constraints

A modern pacemaker runs on a coin-cell-class lithium battery for 8-12 years. Every cryptographic operation costs battery; every additional radio listen-mode costs battery. The defender's cryptographic budget per session is on the order of low single-digit milliJoules. This is the "zero-power defenses" frame Halperin et al. introduced: defenses must be cryptographically meaningful but energetically free. The proposed approach was RF-harvested authentication where the external programmer powers the exchange; the same architecture appears in subsequent NFC-style implant-authentication proposals.

### Closed-loop devices — the dangerous frontier

Closed-loop systems autonomously translate sensor reads into therapy adjustments. The compromise surface is bigger because the attacker can manipulate sensor input rather than control output, which is often a less-defended path.

For any closed-loop device, the review must include sensor-input attack surface as a first-class concern. Analog sensor attacks (Fu's work) and signal-injection attacks (spoofed glucose, spoofed heart rate, spoofed temperature) are now in the threat model.

---

## IV. Wireless Interfaces in Medical Devices

### MICS / MedRadio (402-405 MHz)

Dominant short-range RF band for implanted devices. FCC established MICS in 1999 (47 CFR Part 95) with 25 microwatt EIRP and 10 channels of 300 kHz each in the 402-405 MHz core band. Expanded in 2009 to MedRadio (401-406 MHz). Design intent: ultra-low-power transmission with propagation conducive to in-body RF. Designed range ~2 meters; effective attacker range with high-gain SDR antenna documented to 5-10 meters in clean conditions.

Security profile: the standard makes no requirements about authentication, encryption, or integrity. Vendor implementations vary; many older devices have no authentication at all. Newer designs add proprietary challenge-response but cryptographic primitive choice is constrained by energy budget.

### WMTS (Wireless Medical Telemetry Service)

Three blocks (608-614 MHz, 1395-1400 MHz, 1427-1432 MHz) reserved by FCC for in-hospital patient monitoring. Security profile similar to MICS: no standard cryptographic requirements; vendor implementations vary.

### Bluetooth / BLE

Increasingly common in newer implantables and external medical devices. Used in Abbott Confirm Rx, Medtronic Azure / Astra, Insulet Omnipod 5, Dexcom G6/G7, and most modern CGMs. Security profile inherits BLE's known weaknesses: pairing modes vary in cryptographic strength; many medical devices use Just Works pairing (no auth beyond proximity); BLE 4.x pairing is vulnerable to MITM during pairing; BLE 5.x Secure Connections with ECDH adoption lags consumer electronics. Cross-link to [[reference-wireless-rf-satellite-security]] §3.

### Wi-Fi

Hospital infrastructure (PACS, EHR clients, infusion-pump network connections, MRI/CT console connectivity). Patient-side cloud-connected components (Merlin@home, CareLink) connect via the patient's home Wi-Fi. Security profile is whatever the deployed infrastructure provides; in practice hospital biomedical-engineering teams often deploy on flat networks with minimal segmentation.

### Proprietary RF protocols

Many older devices use vendor-proprietary protocols at 433 MHz ISM or 2.4 GHz. The historical pattern: protocols designed without cryptographic review, often by hardware engineers without security background, vulnerable to SDR-based reverse engineering. Hospira infusion pumps, older Medtronic CareLink, Animas OneTouch Ping (CVE-2016-5084 — 900 MHz proprietary with no encryption between remote and pump) are representative.

### "Unencrypted by design"

A persistent pattern: protocol designed before serious cryptographic review was expected; the cryptographic primitives that would address the threats now exist but require firmware update or hardware replacement; the regulatory regime makes update slow and replacement uneconomic. The installed base in 2026 includes substantial unencrypted-by-design wireless medical devices, and the depreciation cycle will not retire them for another decade.

---

## V. Canonical Research Disclosures

### Halperin et al. 2008 — Pacemakers and ICDs

IEEE S&P (Oakland) May 2008; Best Paper; Test of Time. Target: Medtronic Maximo DR ICD (2003-market, 175 kHz inductive). Demonstrated attacks: telemetry harvesting without auth; magic-packet activation; therapy-parameter reprogramming; battery-drain via repeated wakeups. Proposed defenses: WISPer (RF-powered authentication zero-cost to the implant) and acoustic side-channel signaling. Architectural lesson — ultra-low-power RF auth is solvable if primitives match the energy budget — is now baked into AAMI TIR57 and IEC 81001-5-1.

### Radcliffe 2011 — Insulin pump remote dosing

Black Hat USA 2011, Medtronic MiniMed Paradigm series with 916.5 MHz proprietary RF interface. Used a Medtronic MiniMed ComLink transmitter to wirelessly disable the pump on stage from about 100 feet; said modifications could extend range to roughly half a mile. Triggered FDA/DHS ICS-CERT coordinated-disclosure relationships. Follow-up CVEs: Animas OneTouch Ping (CVE-2016-5085), Medtronic MiniMed 508.

### Rios + Butts 2017 — Pacemaker programmers

"Security Evaluation of the Implantable Cardiac Device Ecosystem Architecture and Implementation Interdependencies" (WhiteScope, May 2017). Cross-vendor analysis (Medtronic, Abbott/St. Jude, BIOTRONIK, Boston Scientific) found ~8,000 known vulnerabilities in third-party libraries on programmers — outdated OpenSSL, decrepit Windows components, unauthenticated remote-management. Follow-up Black Hat 2018 demonstrated that the Medtronic CareLink 2090 programmer's software-update network delivered unsigned, unencrypted updates, permitting malicious firmware that could alter shock delivery. CISA advisories ICSMA-18-058-01 (CareLink 2090 / Encore 29901 programmers) and ICSMA-18-219-02 (MiniMed pump remote controllers).

### Hospira infusion-pump corpus (2014-2015)

Rios disclosure series on Hospira (later Pfizer) pumps: LifeCare PCA (CVE-2015-3459), Plum A+ (ICSA-15-161-01), Symbiq (ICSA-15-174-01). Hardcoded credentials, unauthenticated drug-library upload, telnet on port 23 with no password, lateral-movement primitives. July 2015 FDA Safety Communication on Symbiq — first time FDA explicitly urged hospitals to "discontinue use" of a medical device for cybersecurity reasons.

### Sandler 2010 — Right-to-inspect advocacy

"Killed by Code: Software Transparency in Implantable Medical Devices" (Software Freedom Law Center, July 2010). Not a vulnerability disclosure; instead, the canonical legal/ethical argument that the patient and her physicians have a right to inspect the source of life-sustaining implants. Underlies every subsequent IMD-disclosure debate and is the moral backbone of the I Am The Cavalry Hippocratic Oath.

### Marie Moe — Pacemaker Hacking Project (2015-2020)

Multi-year reverse-engineering of the Biotronik pacemaker ecosystem by Moe (patient/researcher), Leverett, and Bour. Extracted HMU firmware via debug interfaces; reverse-engineered proprietary RF between HMU and pacemaker; reverse-engineered cellular protocol between HMU and Biotronik cloud; CERT advisories June 2020 documenting five vulnerabilities. Vendor declined to issue a product security update — useful documented case of coordinated-disclosure failure mode for implantables.

### MedSec / St. Jude (2016)

The MedSec / Muddy Waters short. MedSec partnered with Muddy Waters Capital after concluding St. Jude's prior responses to disclosure had been inadequate. Muddy Waters shorted St. Jude; FDA opened investigation; vulnerabilities were confirmed; St. Jude issued firmware updates; the company sued. Canonical example of disclosure-via-market-mechanism when coordinated disclosure fails.

### Medtronic CareLink Conexus (2019)

CVE-2019-6538. The Conexus telemetry protocol between Medtronic implants and CareLink programmers had no authentication or encryption; an attacker within radio range could modify or fabricate communications. FDA Safety Communication; Medtronic Conexus firmware update 2019-2020.

### Pneumatic tube system attacks — Translogic / Swisslog (2021)

"PwnedPiper" disclosure by Armis. Nine vulnerabilities in the Translogic PTS used in ~80% of North American hospitals to transport blood samples and medications between departments. Unauthenticated firmware update, hardcoded credentials, DoS primitives. Canonical for "non-device hospital-infrastructure cyber-physical risk" — not FDA-regulated as a medical device but compromise materially affects clinical operations.

---

## VI. Hospital Infrastructure Attack Surface

The hospital is heterogeneous: regulated medical devices, unregulated medical IoT, IT systems with PHI, operational systems that interact with patient care. Medical device is one of several attack surfaces.

### PACS (Picture Archiving and Communication System)

Hospital imaging infrastructure. Stores DICOM images from MRI, CT, X-ray, ultrasound, mammography; serves to radiologist workstations and the broader EHR. Dominant vendors: GE Healthcare Centricity, Siemens Healthineers syngo, Philips IntelliSpace, Sectra, Carestream.

#### DICOM file format attack surface

The DICOM standard (NEMA PS3) has a 128-byte preamble field of unstructured space at the file head — originally to allow DICOM files to be readable by non-DICOM viewers (a DICOM file can begin with a TIFF or PNG header in its preamble). The 2019 Cylera Labs research demonstrated the preamble can contain a full Windows PE executable header, producing a file simultaneously valid as a DICOM image (parseable by clinical viewers) and as a Windows executable (runnable by renaming .dcm to .exe). The term "PE-DICOM" was coined. https://labs.cylera.com/2019/04/16/pe-dicom-medical-malware/

Mitigation is straightforward (strip the preamble when storing/transmitting through anything other than the originating modality), but the implication is broader: an attacker with EHR-write access can embed Windows malware in DICOM images that survives HIPAA-mandated retention periods. The 2024 Praetorian ELFDICOM extension demonstrated the same principle for ELF executables, expanding the attack to medical devices running embedded Linux.

#### DICOM network protocol (DIMSE)

DICOM message exchange is generally unauthenticated by default. The standard has a TLS profile (Part 15) but field deployment is rare. Compromise of a PACS allows retrieve/modify/destroy of patient images. Modification has particular clinical consequence: a falsified MRI showing a brain tumor that does not exist (or vice versa) is a direct misdiagnosis vector.

### EHR (Electronic Health Records)

Dominant U.S. vendors: Epic, Cerner / Oracle Health, Meditech, Allscripts. EHRs increasingly are the primary integration point for orders, results, medication administration, clinical documentation. Attack surface includes: authentication/authorization weaknesses (the EHR sits behind hospital SSO; SSO misconfig provides entry — cross-link [[reference-saml-federation]]); the FHIR API surface (next subsections); interface engines (Mirth Connect, Cloverleaf, Rhapsody) that translate between protocols and yield cross-system reach if compromised; EHR data warehouses often less-protected than production.

### HL7 v2

Legacy messaging protocol for inter-system clinical messaging. Plaintext, unauthenticated, designed in the late 1980s for trusted MLLP transport. Any system that can connect to an HL7 listener can submit messages. In practice HL7 v2 traffic on a hospital network is trust-on-the-network with no authentication. Cross-link to [[reference-distributed-authz]] on the "trust-the-network" failure pattern.

### HL7 FHIR

Modern REST-based replacement using HTTP, JSON, OAuth2 with SMART on FHIR. The 21st Century Cures Act and ONC Cures Rule require EHRs to expose FHIR APIs to certified third-party applications. Security model is materially better than HL7 v2 (TLS by default, OAuth-based authn, scope-based authz), but the BOLA / BFLA shape remains. Alissa Knight's 2021 "Playing with FHIR" research documented BOLA in third-party FHIR aggregator and app implementations (not the EHR vendors' own FHIR APIs) — patient A authenticating with their own token could access patient B's records by changing the patient ID in the API path. Cross-link to [[reference-graphql-api-security]] and [[reference-distributed-authz]] for per-resource authorization patterns.

### Medication administration systems

Pyxis (BD), Omnicell, MedSelect — automated medication dispensing cabinets (ADCs) on wards. CVE-2022-22767 (BD Pyxis): hardcoded default credentials that were not changed during deployment, allowing privileged file-system access and ePHI exposure. A November 2024 FDA warning letter to BD mentioned 544 open software-defect tickets on Pyxis, 111 categorized as catastrophic or severe, including 4 cybersecurity issues. Compensating controls (segmentation, credential rotation) are the documented defense.

### MRI, CT, ultrasound console computers

Almost always Windows-based (Windows 7 Embedded, Windows 10 LTSC, occasionally Windows XP Embedded on older equipment). FDA-clearance constraints mean the console firmware/OS is not patched by hospital IT but by the modality vendor on a slow cycle. Windows XP-class consoles remain in service in 2026 at major academic medical centers because the vendor has not yet certified a replacement. WannaCry 2017 directly demonstrated console-level disruption — radiology and pathology departments were knocked out because the consoles were Windows-based and vulnerable.

### Networked beds, ventilators, monitors

Modern ICU equipment is increasingly networked. The clinical-impact gradient: monitor and telemetry compromise is largely data-integrity / privacy; ventilator and infusion-pump compromise is direct safety. A ventilator delivering wrong FiO2 or wrong tidal volume harms the patient on a timescale of minutes.

### "Ransomware kills patients"

Düsseldorf University Hospital 2020 was initially reported as the first documented patient death from a hospital ransomware attack; the Cologne public prosecutor's subsequent investigation concluded the patient's death was "entirely independent" of the cyber-attack delay, walking back the most direct causal claim. The broader pattern — hospital cyber-attacks force ambulance diversion, treatment delay, and procedure cancellation — is empirically documented across many incidents.

The Synnovis attack (June 2024) was identified as a contributing factor in at least one patient death from delayed blood-test results — a more direct causal chain than Düsseldorf because the missing pathology service materially altered clinical decision pathways.

---

## VII. IoMT — Internet of Medical Things at Scale

The "Internet of Medical Things" is the catchall for connected medical devices and clinical-adjacent IoT. Broader than the FDA-regulated-medical-device set.

**Connected pumps and monitors.** A typical ward has hundreds of connected devices; a large academic medical center may have tens of thousands. The aggregate is the largest IoT deployment most enterprises will manage.

**BYOD nurse phones and clinical apps.** Vocera, Epic Rover, Halo, PerfectServe integrate with the EHR and have substantial PHI access. Cross-link to [[reference-mobile-security]] on enterprise-mobile-management compromises.

**Pharmacy automation.** Compounding robots (RIVA, IntelliFill) have a direct safety surface — a compromised compounding robot may produce wrong-concentration IV bags. Dispensing systems record controlled-substance pulls; modification of those records is a federal crime.

**Lab equipment.** Blood-gas analyzers, hematology, chemistry, microbiology — all networked to the Laboratory Information System (LIS). Compromise allows falsifying lab results with direct clinical-decision consequence. Synnovis demonstrated the operational impact; falsification is the deception variant.

**Sterilization tracking** (Censis, SPM). Compromise yields the ability to falsify sterilization records — a Joint Commission compliance and infection-control issue with direct patient-safety implications.

**Real-time location systems (RTLS).** Asset and patient tracking via RFID, BLE beacons, ultrasound, Wi-Fi triangulation. Major vendors: CenTrak, AiRISTA, Sonitor, Versus. Compromise allows falsification of location data — consequence-bearing in workflows like hand-hygiene compliance monitoring or psychiatric-ward elopement prevention.

**The inventory problem.** The dominant operational problem for IoMT-aware security teams is inventory. Passive-discovery products (Cylera, Medigate / Claroty xDome, Asimily, Ordr, Armis) fill the gap.

**RTOS substrate.** Many medical IoT devices run FreeRTOS, ThreadX (Azure RTOS), MQX, Nucleus, VxWorks rather than Linux. URGENT/11 (2019, VxWorks) and Ripple20 (2020, Treck TCP/IP) specifically called out medical-device fleets in coordinated disclosure. RTOS-substrate vulnerabilities are typically slow to patch because vendor testing is regulatory-bound. Cross-link to [[reference-rtos-embedded-os]] §VII.

---

## VIII. Real-World Medical Cyber Incidents

The incident corpus below shaped policy and regulatory response. Each lesson is the load-bearing artifact.

**WannaCry NHS 2017** — May 12, 2017. NSA-leaked EternalBlue weaponized into ransomware. 600+ NHS organisations affected; 37 trusts infected and locked out of devices; an estimated 19,000 appointments cancelled; five A&E departments diverted patients. NAO report is the canonical post-mortem. Lesson: the medical-device fleet's exposure to commodity malware is not theoretical. Windows-embedded consoles inherited EternalBlue and could not be patched in the available window.

**NotPetya hospitals 2017** — June 27, 2017. Sandworm wiper masquerading as ransomware. Hit Heritage Valley Health System (Pennsylvania, two hospitals, dozens of clinics) — offline nearly a week. Merck lost HPV-vaccine manufacturing capacity; reported $870M in losses. Cross-link to [[reference-supply-chain-provenance]] §VIII. Lesson: collateral damage from nation-state operations is catastrophic for healthcare.

**Hollywood Presbyterian 2016** — February 2016. ~$17,000 ransom paid to restore operations after ransomware disabled clinical systems for ten days. First publicly-disclosed payment by a U.S. hospital. Lesson: hospital economics favor paying ransom over operational disruption; the externality is that the ransomware market is sustained by payments.

**Düsseldorf University Hospital 2020** — September 10, 2020. DoppelPaymer (via Citrix CVE-2019-19781) crippled clinical systems. A 78-year-old woman requiring immediate aneurysm treatment was diverted 19 miles; she died. Cologne prosecutor opened negligent-homicide investigation; subsequent ruling concluded the death was not causally attributable to the cyber-attack. The case nonetheless shifted public discourse around healthcare-sector ransomware from data-protection to patient-safety framing.

**Universal Health Services 2020** — September 27, 2020. Ryuk hit UHS, one of the largest U.S. hospital operators (400 facilities). Systems offline nearly three weeks; clinical operations reverted to paper. Financial impact $67M. Lesson: hospital systems must plan for weeks-long IT-outage scenarios.

**Scripps Health 2021** — May 2021. Ransomware disabled clinical systems for nearly a month. $112M in lost revenue and IR costs. Cyber-insurance market responded with material premium increases and reduced coverage limits for hospital-system clients.

**Vastaamo 2020** — Finnish psychotherapy chain breach. ~33,000 patients' session notes stolen. After failed corporate ransom, the attacker (Aleksanteri Kivimäki, sentenced 2024 to 6 years 3 months) extorted patients individually, threatening publication of their session notes. A victims' lawyer told the court that some patients had taken their own lives after the records were published. Lesson: the patient-data-confidentiality surface in medical contexts has unique harm dimensions not captured by standard breach-cost models. HIPAA-style regimes treat all PHI categorically the same; in practice certain categories (mental health, HIV, fertility, gender-affirming care) carry vastly higher individual harm potential. Cross-link to [[reference-privacy-engineering]].

**Change Healthcare 2024** — February 12, 2024. ALPHV/BlackCat accessed Change Healthcare via a compromised Citrix gateway without MFA. Change Healthcare processes ~50% of all U.S. medical claims and ~67,000 pharmacies' prescription billing. The outage created national pharmacy disruption for over a month. UnitedHealth paid $22M ransom; data was leaked anyway. UHG reported $2.4B in incident-response and operational costs. Lesson: U.S. healthcare-payment infrastructure is single-point-of-failure on a small number of clearinghouses.

**Synnovis NHS pathology 2024** — June 3, 2024. Qilin ransomware hit Synnovis, a pathology services provider to NHS London hospitals (Guy's, St. Thomas', King's College, Royal Brompton, Evelina). Disrupted blood-test results across multiple London trusts; 10,000+ outpatient appointments and 1,700+ elective operations cancelled. King's College Hospital identified the attack as contributing factor in at least one patient death. Lesson: hospital-vendor supply-chain ransomware can produce patient-safety outcomes one hop removed from the hospital.

### Common patterns

- **Entry vector**: perimeter VPN/Citrix/RDP vulnerability or phishing-driven credential compromise. Medical-device exploitation is rarely initial-entry; it's IT-network entry that subsequently affects medical-device operations.
- **Patient-impact pathway**: usually indirect (cancelled procedures, diverted ambulances, delayed lab results), occasionally direct (medication errors during downtime, device-firmware tampering).
- **Recovery time**: weeks rather than days. FDA-clearance constraints on each device prevent fast recovery.
- **Reporting fragmentation**: HHS OCR, CISA, FBI, state AGs, vendor breach-notification — multiple overlapping reporting requirements.

---

## IX. Regulatory Frameworks

### FDA premarket cybersecurity guidance

Three generations: 2014 ("Content of Premarket Submissions for Management of Cybersecurity in Medical Devices" — first formal FDA acknowledgement that cybersecurity is a premarket criterion); 2018 draft (expanded scope); **2023 final** ("Cybersecurity in Medical Devices: Quality System Considerations and Content of Premarket Submissions," September 27, 2023). The 2023 guidance operationalizes the PATCH Act. Specific requirements: cybersecurity risk plan; SBOM in CycloneDX or SPDX (JSON or XML); coordinated-vulnerability-disclosure procedure; postmarket-patching commitment. FDA can refuse to accept marketing submissions (510(k), De Novo, PMA) that don't include the cybersecurity content. For "cyber devices" (defined in FDCA §524B), this is now a market-access gate.

### FDA postmarket guidance (2016)

"Postmarket Management of Cybersecurity in Medical Devices" (December 28, 2016). Establishes the manufacturer's obligation to monitor for vulnerabilities and respond on a defined timeline. Distinguishes "controlled risk" (vulnerabilities with compensating controls that don't require notification) from "uncontrolled risk" (notification required within 30 days). The threshold is loose enough that vendor judgment is substantial.

### PATCH Act 2022 / FDCA §524B

The Protecting and Transforming Cyber Health Care Act, enacted as Section 3305 of the Consolidated Appropriations Act of 2023 (December 29, 2022). Effective March 29, 2023; full force October 1, 2023. Key provisions: defines "cyber device"; authorizes FDA to require cybersecurity information in marketing submissions; requires manufacturers to submit monitoring/identification/response plan, make patches available throughout lifecycle, provide SBOM, comply with other FDA cybersecurity requirements. Before PATCH Act, FDA's cybersecurity-content requirements were advisory; after, they're enforceable.

### EU MDR / IVDR cybersecurity annex

Medical Device Regulation (EU) 2017/745 and In Vitro Diagnostic Regulation (EU) 2017/746, in force May 2021 and May 2022. Annex I §17.2 (MDR) and §16.2 (IVDR) explicitly require cybersecurity for software-containing medical devices:

> "For devices that incorporate software or for software that are devices in themselves, the software shall be developed and manufactured in accordance with the state of the art taking into account the principles of development life cycle, risk management, including information security, verification and validation."

Serious incidents must be reported to competent authorities within 15 days (MDR Article 87). MDCG 2019-16 ("Guidance on Cybersecurity for medical devices") is the operational implementation reference.

### IEC 62304 — Medical device software lifecycle

Published 2006; amended 2015. Medical-device software-lifecycle process requirements (planning, requirements, architectural design, implementation, integration testing, system testing, release, problem resolution, configuration management). Software-safety classification: Class A (no injury possible), Class B (non-serious injury), Class C (death or serious injury). FDA recognizes as a consensus standard.

### IEC 81001-5-1 — Health software cybersecurity

Published 2021. The cybersecurity-process supplement to IEC 62304. Additional cybersecurity activities mapped to IEC 62304 lifecycle phases: security risk management integrated with ISO 14971; secure design including threat modeling, secure-coding standards, code review, static analysis; verification and validation as an independent security activity (pen testing, fuzz testing, vulnerability scanning) — explicitly required rather than implied; vulnerability handling with coordinated-disclosure process; configuration management for security-relevant components and SBOM. EN IEC 81001-5-1 (2022) is the state-of-the-art reference for MDR/IVDR Annex I compliance.

### ISO 14971 — Medical-device risk management

The risk-management standard for medical devices generally. Cybersecurity risk management under IEC 81001-5-1 is required to integrate with ISO 14971 — cyber-risk must use the same risk-analysis primitives (severity, probability, risk-acceptability matrix) as hardware-and-software safety risk.

### HIPAA Security Rule

45 CFR §164.302-318. U.S. health-data privacy and security baseline for covered entities and business associates. Technical safeguards (§164.312): access control, audit controls, integrity controls, person/entity authentication, transmission security. Enforced via HHS Office for Civil Rights (OCR); fines $100-$50,000 per violation, capped at $1.5M/year/provision. **NIST SP 800-66r2** (February 2024) is the implementation guide mapping HIPAA's required/addressable specifications to NIST CSF and SP 800-53 controls.

### AAMI TIR57

"Principles for medical device security — Risk management" (2016, reaffirmed 2023). U.S. industry-consensus reference on cybersecurity risk management integrating with ISO 14971. FDA recognizes as consensus standard.

### Cross-jurisdictional summary

For a global manufacturer: U.S. (FDA premarket + PATCH Act + HIPAA for providers); EU (MDR/IVDR Annex I + EN IEC 81001-5-1 + NIS2 for healthcare CI operators); Canada (Health Canada's "Pre-market Requirements for Medical Device Cybersecurity"); UK (post-Brexit MHRA tracking FDA + EU MDR); Japan (PMDA guidance, 2021); Australia (TGA guidance, 2019). Harmonization is narrowing. Most major manufacturers organize a single global cybersecurity QMS meeting FDA + EU MDR; IEC 81001-5-1 is increasingly the universal reference.

---

## X. SBOM and Supply Chain for Medical Devices

The FDA SBOM mandate (FDCA §524B(b)(3), effective October 1, 2023) makes medical devices the first regulated industry with statutory SBOM requirements at scale.

### SBOM content requirements

Per FDA 2023 final guidance: machine-readable format (CycloneDX or SPDX, JSON or XML); all software components (commercial, open-source, firmware, OS components, third-party dependencies); transitive dependencies to the level practically discoverable; updates when device software is updated; sufficient specificity for downstream vulnerability matching (component name, version, supplier, hash where available). Cross-link to [[reference-supply-chain-provenance]] §6 for format choice and broader tooling landscape.

### The 30-year device with the 30-year-old TLS library

A characteristic operational reality. A medical device shipped 2010 with OpenSSL 1.0.0 is still in service in 2026. The SBOM accurately documents this — but the manufacturer's inability to patch the TLS library in the field means the SBOM is essentially a list of unpatched vulnerabilities. The challenge is not generating the SBOM; it is what to do with the resulting vulnerability list when no patch path exists. The 2024 industry debate around "negative SBOMs" (SBOM required, manufacturer cannot remediate) is unresolved. Compensating-controls documentation (segmentation, allowlist firewalls, IDS signatures) is the typical workaround.

### VEX (Vulnerability Exploitability eXchange)

CycloneDX VEX and CSAF VEX let manufacturers assert which CVEs in their SBOM are actually exploitable on the device. The defender's question is whether to trust manufacturer VEX assertions; manufacturer incentive runs toward over-asserting "not exploitable" to reduce postmarket reporting burden.

### Information-sharing nodes

MITRE (CVE database); MedISAO (manufacturer-side consortium); H-ISAC (provider-side and manufacturer-side; Medical Device Security Council is the formal venue). As of 2026, a vulnerability disclosed to a manufacturer is typically shared with H-ISAC within hours via confidential channel, CISA/FDA within days. Public disclosure (CVE assignment, CISA advisory) follows patch availability.

### Lifecycle considerations

Unique to medical devices: SBOM lifecycle extends well beyond software EOL. A device implanted for 10-15 years requires the SBOM to remain valid (or be deliberately marked obsolete) for the patient's lifetime of the device. The SBOM-management tooling (MedCrypt Helm, NetRise, Finite State) is responding to this requirement.

---

## XI. Defensive Architecture

### Network segmentation

The foundational control. Hospital network zones: Clinical (EHR, PACS, RIS, LIS, clinical workstations); Medical-device VLAN / IoMT (infusion pumps, telemetry, ventilators, networked beds, ADCs, modalities, microsegmented by device class); Building/Facilities (HVAC, access control, elevators — cross-link [[reference-ics-ot-security]] §XII BACnet); Business/Administrative (ERP, email); Guest/Patient Wi-Fi (fully separate). Cross-VLAN traffic explicitly allowlisted and inspected.

### Microsegmentation for IoMT

Within the medical-device VLAN, microsegment by device class and clinical function. Infusion pumps talk only to their drug-library server and clinical-workstation client. Mature deployments use software-defined microsegmentation (Illumio, Akamai Guardicore, Cisco SD-Access) or per-device firewall policies on the network fabric.

### Device inventory

Persistently the most-skipped first step. Passive-discovery tools (Cylera, Medigate / Claroty xDome, Asimily, Ordr, Armis, Phosphorus, Sternum) fill the gap. Accurate inventory is the prerequisite for everything else.

### Vulnerability management

The realistic posture is "compensating controls" rather than "patch." The patch cycle for a regulated medical device is months to years; the operational risk window is now. Playbook: **discover** (SBOM-driven CVE matching, vendor advisories, H-ISAC feeds); **assess** (VEX, threat-informed prioritization); **compensate** (network controls, IDS sigs, traffic monitoring) — immediate; **patch** through the vendor's regulated update path — long-cycle; **replace** the device class when patching is infeasible — multi-year capital planning. For Class C devices with serious vulnerabilities and no patch path, replacement must be on the table (Hospira Symbiq 2015 is the canonical example).

### Anomaly detection

Protocol-specific anomaly detection (DICOM, HL7, FHIR, Modbus, BACnet, proprietary protocols). Generic NetFlow-level detection has limited utility for medical devices because baseline traffic is highly periodic; protocol-aware tooling that understands DICOM image-transfer patterns or HL7 message-flow surfaces real anomalies.

### Pen testing in hospitals

Coordination challenge — patients on the network 24/7. A pen test that disrupts the EHR for ten minutes during a Code Blue is a patient-safety event. Mature posture: out-of-hours testing windows for invasive scans; clinical-operations liaison; read-only-by-default; segment-scoped rather than enterprise-wide; medical-device-isolation for invasive tests against specific device classes (typically requires vendor-coordinated test instances). MDIC has published industry-consensus guidance on the coordination model.

### Coordinated disclosure

Routes through H-ISAC (threat-intel sharing) + FDA CDRH (premarket/postmarket-relevant) + CISA (advisory publication: ICSMA advisories) + MITRE (CVE assignment) + vendor PSIRT directly. MITRE-managed PSIRT roster for medical-device manufacturers is mature in 2026; most major MDMs have published vulnerability-disclosure policy.

### Procurement requirements

The highest-leverage defensive control. Write cybersecurity into procurement contracts. The MDS2 (Manufacturer Disclosure Statement for Medical Device Security) form is the industry-consensus procurement-question framework. Required items for any new device purchase: current MDS2 with specific responses to all 23 sections; SBOM in CycloneDX or SPDX; cybersecurity risk plan per AAMI TIR57; vulnerability-disclosure and patch-management commitment; VEX maintenance; vendor product-security contact. Procurement-time control is dramatically cheaper than post-deployment retrofit.

### Code review checklist for medical-device software

1. **Authentication on every wireless and network interface?** Hardcoded credentials, default credentials, and absent authentication are the dominant historical pattern.
2. **TLS on every IP connection?** Current TLS — not SSLv3, not RC4, not deprecated cipher suites.
3. **Integrity controls on firmware updates?** Code-signing, secure-boot, anti-rollback. Cross-link [[reference-firmware-embedded-security]].
4. **Input validation on every external surface?** DICOM and HL7 parsing surfaces are particularly fertile for memory-corruption and injection bugs.
5. **AuthN and AuthZ on every API endpoint?** BOLA / BFLA shape — every patient-keyed resource must check the requestor's authorization for that specific patient. Cross-link [[reference-distributed-authz]].
6. **Audit logging that survives an attacker?** Remote, append-only — not local-disk logs the attacker can scrub.
7. **Anti-tamper detection at device level?** Open-chassis detection, secure-element identity, attestation.
8. **Cryptographic primitives appropriate for energy budget?** For implantables, AES-128 or ChaCha20 (avoid RSA, ECDSA unless budget supports).
9. **Random-number-generation source quality?** Hardware RNG ideally; if pseudorandom, properly seeded with hardware entropy.
10. **Cleartext PHI in logs, errors, or telemetry?** Common failure mode — debug logging survives into production.
11. **Default-deny on network reach?** The device should reach only the specific cloud/network endpoints it needs.
12. **Recovery / safe-mode on cryptographic failure?** Right answer for life-supporting devices is "halt and signal clinician" — not "continue with unverified update."

---

## XII. AI in Medical Devices — Emerging Surface

FDA has cleared over 1,000 AI/ML-enabled medical devices as of 2025; the regulatory framework is rapidly evolving.

### FDA AI/ML PCCP guidance

The Predetermined Change Control Plan (PCCP) framework — drafted April 2023, finalized December 2024 — allows manufacturers to update the model post-clearance within a pre-defined change envelope without filing a new marketing submission. The PCCP must include Description of Modifications, Modification Protocol, and Impact Assessment. The PCCP is the regulatory primitive that makes "continuously updating ML model in a regulated medical device" tractable.

**Cybersecurity implication**: the PCCP is the documented attack surface against which an attacker can target. A successful poisoning attack against the manufacturer's retraining pipeline can deliver a modified model into the field without triggering a new regulatory submission — because the modification is within the pre-approved envelope. PCCP change-control needs cybersecurity controls on the training pipeline, not just on the deployed model.

### Image-diagnosis AI (radiology, pathology)

Dominant AI/ML-enabled medical-device class as of 2026: CADe and CADx for radiology images (mammography, chest X-ray, CT, MRI), pathology slides, dermatology. Major vendors: Aidoc, Annalise.ai, Lunit, Paige.AI, PathAI, Viz.ai, Heartflow.

Attack surface (cross-link [[reference-adversarial-ml-model-security]]): adversarial input perturbations (Finlayson 2018 demonstrated small image-imperceptible perturbations flip diagnostic classifications); training-data poisoning (manipulating training set to embed triggered backdoors — particularly relevant for federated multi-institution data); model extraction (recovering deployed model parameters via query interface); membership inference (determining whether specific patients' images were in training set — privacy violation against training cohort).

### Voice-AI clinical scribes

Nuance DAX, Abridge, Suki, Augmedix. Ambient recording captures clinician-patient conversations; LLM generates clinical notes; clinician signs off; note enters the medical record. Surfaces include audio capture (PHI in audio form, often retained for model improvement); LLM-generated clinical notes (hallucination or omission entering regulated record); cloud-side processing (clinical conversations to vendor cloud). Cross-link to [[reference-llm-agent-security]]. The clinical-LLM hallucination surface is materially worse than general LLM hallucination because the false output enters a regulated medical record and informs downstream clinical decisions.

### AI-driven robotic surgery

Intuitive da Vinci, Medtronic Hugo, CMR Surgical Versius. Today's platforms are teleoperated (surgeon controls robot directly); AI-driven autonomous surgery is research-status. Today's attack surface is the teleoperation link and platform embedded systems; future surface includes the autonomous-control algorithm.

### The "FDA recall of an AI model" emerging concept

As of 2026, FDA has not yet issued a recall specifically targeting an AI model (closest precedent: IBM Watson for Oncology delivery-of-care concerns and various CADe/CADx withdrawals). PCCP arguably reduces the need for AI-specific recalls — manufacturer can roll back the model within the PCCP. For AI failures causing clinical harm at scale, a formal recall mechanism is needed; FDA is reportedly developing it.

### Federated learning

Training a shared model across institutions without centralized data pooling. Privacy properties attractive (no raw patient data leaves the institution); security properties subtle (malicious participating institution can poison the global model; secure-aggregation primitives needed to prevent inference attacks during training). NVIDIA Clara, OpenFL, Flower are the dominant frameworks. Cross-link to [[reference-adversarial-ml-model-security]].

---

## XIII. Variant Analysis — Under-Explored Surfaces

**Veterinary medical-device security.** Same device classes (anesthesia machines, infusion pumps, monitoring, imaging) without the FDA regulatory regime. Cybersecurity posture generally weaker because regulatory pressure is lower; data-protection issues also lower (animal data is not PHI). Structural property: veterinary clinics are often integrated with their proprietor's home networks, providing a lateral-movement path from clinic to home.

**Dental equipment.** Dental imaging (panoramic X-ray, CBCT), CAD/CAM (CEREC, E4D), patient-management software (Dentrix, Eaglesoft). Dental practices are small, often with limited IT; patient data is regulated as PHI but security posture lags hospital systems by years. The 2019 PerCSoft (DDS Safe) ransomware attack — a dental-records cloud provider — affected ~400 dental practices simultaneously and demonstrated systemic risk in the dental software supply chain.

**Hospital pharmacy automation.** Compounding-robot surface particularly under-explored. IV-room compounding robots (Omnicell IV, RIVA) physically produce intravenous medications. Compromise of the control logic enables direct safety attacks on medication preparation that may not be detectable through standard infection-control or medication-safety monitoring.

**RTLS as clinical-decision integrity issue.** Most security attention has gone to RTLS-as-privacy; under-explored as a clinical-decision integrity surface. The relevant attack target is the RTLS server and the inference engine that translates location reads into clinical workflow signals.

**Surgical robot tele-surgery.** Latency-critical RTOS aspects make this particularly sensitive. The 2019 5G-Smart Hospital initiatives anticipated remote tele-surgery over 5G public networks; the cybersecurity-and-latency properties of this surface are still emerging. 2026 deployments are small-scale and proof-of-concept.

**Direct-to-consumer health devices.** Apple Watch ECG, Whoop, Oura, Garmin, Withings. Not FDA-regulated for most functions (some are De Novo-cleared for specific indications like AFib detection on Apple Watch). Data-protection regime is weaker (HIPAA only applies if integrated with a healthcare provider). The structural property worth noting: DTC health-device data is increasingly used to inform clinical care (cardiologists looking at Apple Watch ECG strips; sleep specialists looking at Oura data). The data-integrity surface — falsified biometric data influencing clinical decisions — is under-considered.

**Brain-computer interfaces (BCIs).** Neuralink, Synchron, Blackrock Neurotech, Paradromics. The 2024 Synchron switch-control trials and Neuralink human implant create a small but growing population. Attack surface combines implantable-device challenges with extreme consequence (read access to brain signals; in some architectures, stim access to brain tissue). Too young to have a canonical disclosure or attack pattern, but structural risk is among the highest in any embedded-device category.

**Consumer health-LLM advisory products.** OpenAI healthcare-adjacent ChatGPT applications, Google Med-Gemini, dedicated medical LLM products (Hippocratic AI, Glass Health, OpenEvidence). Not FDA-regulated as medical devices in most current deployments. Attack surface: prompt injection (cross-link [[reference-llm-agent-security]]), hallucinated recommendations, training-data leakage of PHI. Clinical-impact gradient is high because the consumer interpreting LLM output may take medical action without clinician review.

---

## XIV. References

### Primary-source documents

- Halperin, Heydt-Benjamin, Ransford, Clark, Defend, Morgan, Fu, Kohno, Maisel, "Pacemakers and Implantable Cardiac Defibrillators: Software Radio Attacks and Zero-Power Defenses" (IEEE S&P 2008). https://www.secure-medicine.org/hubfs/public/publications/icd-study.pdf
- Rios and Butts, "Security Evaluation of the Implantable Cardiac Device Ecosystem Architecture and Implementation Interdependencies" (WhiteScope, May 2017). https://web.archive.org/web/2017*/blog.whitescope.io/2017/05/understanding-pacemaker-systems.html
- Sandler, Ohrstrom, Moy, McVay, "Killed by Code: Software Transparency in Implantable Medical Devices" (Software Freedom Law Center, July 2010). https://softwarefreedom.org/resources/2010/transparent-medical-devices.pdf
- Moe and Leverett, "Unpatchable: Living with a Vulnerable Implanted Device" (CCC 32C3, December 2015); Moe, "My Heart Depends on Your Code" (O'Reilly Security Conference Amsterdam, 2016). https://blog.sintef.com/digital-en/security-testing-of-the-pacemaker-ecosystem/
- Radcliffe, "Hacking Medical Devices for Fun and Insulin: Breaking the Human SCADA System" (Black Hat USA 2011). https://www.blackhat.com/html/bh-us-11/bh-us-11-archives.html
- Picado Ortiz / Cylera Labs, "HIPAA-Protected Malware? Exploiting DICOM Flaw to Embed Malware in CT/MRI Imagery" (April 2019). https://labs.cylera.com/2019/04/16/pe-dicom-medical-malware/
- Praetorian, "ELFDICOM: PoC Malware Polyglot Exploiting Linux-Based Medical Devices." https://www.praetorian.com/blog/elfdicom-poc-malware-polyglot-exploiting-linux-based-medical-devices/
- Armis, "PwnedPiper: Pneumatic Tube System Vulnerabilities in North American Hospitals" (August 2021). https://www.armis.com/research/pwnedpiper/
- Finlayson, Bowers, Ito, Zittrain, Beam, Kohane, "Adversarial attacks on medical machine learning" (Science 2019). https://www.science.org/doi/10.1126/science.aaw4399
- Marin et al., "On the (in)security of the latest generation implantable cardiac defibrillators and how to secure them" (ACSAC 2016).

### FDA guidance documents

- FDA, "Cybersecurity in Medical Devices: Quality System Considerations and Content of Premarket Submissions" (September 27, 2023). https://www.fda.gov/regulatory-information/search-fda-guidance-documents/cybersecurity-medical-devices-quality-system-considerations-and-content-premarket-submissions
- FDA, "Postmarket Management of Cybersecurity in Medical Devices" (December 28, 2016). https://www.fda.gov/regulatory-information/search-fda-guidance-documents/postmarket-management-cybersecurity-medical-devices
- FDA, "Marketing Submission Recommendations for a Predetermined Change Control Plan for Artificial Intelligence-Enabled Device Software Functions" (December 2024). https://www.fda.gov/regulatory-information/search-fda-guidance-documents/marketing-submission-recommendations-predetermined-change-control-plan-artificial-intelligence
- FDA Cybersecurity landing page. https://www.fda.gov/medical-devices/digital-health-center-excellence/cybersecurity
- FDA Safety Communication, "Cybersecurity Vulnerabilities of Hospira Symbiq Infusion System" (July 31, 2015). https://www.fda.gov/medical-devices/safety-communications/cybersecurity-vulnerabilities-hospira-symbiq-infusion-system-fda-safety-communication

### EU regulatory documents

- Regulation (EU) 2017/745 on Medical Devices (MDR). https://eur-lex.europa.eu/eli/reg/2017/745/oj
- Regulation (EU) 2017/746 on In Vitro Diagnostic Medical Devices (IVDR). https://eur-lex.europa.eu/eli/reg/2017/746/oj
- MDCG 2019-16 Rev.1, "Guidance on Cybersecurity for medical devices." https://health.ec.europa.eu/document/download/b23b362f-8a56-434c-922a-5b3ca4d0a7a1_en

### Standards

- IEC 62304:2006 (Amd 1:2015), "Medical device software — Software life cycle processes." https://www.iso.org/standard/38421.html
- IEC 81001-5-1:2021, "Health software and health IT systems safety, effectiveness and security — Part 5-1: Security." https://www.iso.org/standard/76097.html
- ISO 14971:2019, "Medical devices — Application of risk management to medical devices." https://www.iso.org/standard/72704.html
- AAMI TIR57:2016/(R)2023, "Principles for medical device security — Risk management." https://www.aami.org/standards/aami-tir57
- IEC TR 60601-4-5:2021, "Medical electrical equipment — Part 4-5: Guidance and interpretation — Safety-related technical security specifications."
- NEMA DICOM PS3 (Digital Imaging and Communications in Medicine). https://www.dicomstandard.org/

### U.S. legislation

- PATCH Act / FDCA §524B (Section 3305 of Consolidated Appropriations Act of 2023, December 29, 2022). https://www.congress.gov/bill/117th-congress/house-bill/7084/text
- HIPAA Security Rule, 45 CFR Part 164.
- NIST SP 800-66r2, "Implementing HIPAA Security Rule" (February 2024). https://csrc.nist.gov/pubs/sp/800/66/r2/final

### CISA / ICS-CERT medical advisories

- CISA, "BD Pyxis" (ICSMA-22-151-01, May 2022). https://www.cisa.gov/news-events/ics-medical-advisories/icsma-22-151-01
- CISA, "Hospira Plum A+ and Symbiq Infusion Systems Vulnerabilities" (ICSA-15-161-01).
- CISA, "Hospira Symbiq Infusion System Vulnerability" (ICSA-15-174-01, June 2015). https://www.cisa.gov/news-events/ics-advisories/icsa-15-174-01
- CISA, "Medtronic Conexus Radio Frequency Telemetry Protocol" (ICSMA-19-080-01, March 2019). https://www.cisa.gov/news-events/ics-medical-advisories/icsma-19-080-01
- CISA, "Abbott Laboratories Defibrillator" (ICSMA-18-107-01).

### Incident retrospectives

- National Audit Office (UK), "Investigation: WannaCry cyber attack and the NHS" (October 2017). https://www.nao.org.uk/wp-content/uploads/2017/10/Investigation-WannaCry-cyber-attack-and-the-NHS.pdf
- "A retrospective impact analysis of the WannaCry cyberattack on the NHS" (npj Digital Medicine 2019). https://www.nature.com/articles/s41746-019-0161-6
- Schneier, "On That Dusseldorf Hospital Ransomware Attack and the Resultant Death" (November 2020). https://www.schneier.com/blog/archives/2020/11/on-that-dusseldorf-hospital-ransomware-attack-and-the-resultant-death.html
- Vastaamo data breach (Wikipedia anchor). https://en.wikipedia.org/wiki/Vastaamo_data_breach
- TechCrunch, "UnitedHealth confirms Russian ransomware gang behind Change Healthcare hack" (February 29, 2024). https://techcrunch.com/2024/02/29/unitedhealth-change-healthcare-ransomware-alphv-blackcat-pharmacy-outages/
- HIPAA Journal, "Patient Death Linked to Ransomware Attack on Pathology Services Provider [Synnovis]." https://www.hipaajournal.com/patient-death-linked-to-ransomware-attack/

### Industry / institutional sources

- Archimedes Center for Healthcare and Device Security. https://archimedescenter.org/
- Health-ISAC. https://health-isac.org/
- MedISAO. https://medisao.org/
- I Am The Cavalry "Hippocratic Oath for Connected Medical Devices" (January 2016). https://iamthecavalry.org/2016/01/19/i-am-the-cavalry-proposes-hippocratic-oath-for-connected-medical-devices/
- MDIC Medical Device Penetration Testing. https://mdic.org/our-work/medical-device-penetration-testing/
- Software Freedom Conservancy. https://sfconservancy.org/
- MedCrypt. https://www.medcrypt.com/

### Books and long-form

- Kim Zetter, *Countdown to Zero Day* (Crown, 2014).
- Paul Cerrato and John Halamka, *The Digital Reconstruction of Healthcare* (Taylor & Francis / HIMSS, 2021).
- Andy Greenberg, *Sandworm* (Doubleday, 2019).

### Wikipedia anchors

- https://en.wikipedia.org/wiki/Medical_device_hijack
- https://en.wikipedia.org/wiki/Implantable_cardioverter-defibrillator
- https://en.wikipedia.org/wiki/DICOM
- https://en.wikipedia.org/wiki/Medical_Device_Radiocommunications_Service
- https://en.wikipedia.org/wiki/WannaCry_ransomware_attack
- https://en.wikipedia.org/wiki/2024_Change_Healthcare_ransomware_attack
- https://en.wikipedia.org/wiki/Vastaamo_data_breach

### Conferences

- DEF CON Biohacking Village (medical-device village).
- Archimedes Center workshops (annual).
- H-ISAC Spring / Fall Summits.
- AAMI Annual Conference and MD Expo (clinical-engineering audience).
- HIMSS Cybersecurity Forum (annual; provider-side).
- Black Hat USA / DEF CON medical-device tracks (since ~2011).
- CCC (European medical-device disclosure venue, e.g. Moe's 32C3 talk).

### Cross-link summary

- [[reference-ics-ot-security]] — safety-critical OT cousin.
- [[reference-firmware-embedded-security]] — embedded substrate.
- [[reference-rtos-embedded-os]] — RTOS in medical IoT (URGENT/11, Ripple20).
- [[reference-wireless-rf-satellite-security]] — MICS, MedRadio, BLE, Wi-Fi, cellular.
- [[reference-supply-chain-provenance]] — FDA SBOM, VEX, component management.
- [[reference-dfir-methodology]] — hospital IR.
- [[reference-cryptography]] — primitives and energy budgets for implantable auth.
- [[reference-adversarial-ml-model-security]] — medical-AI adversarial inputs, training-data poisoning.
- [[reference-llm-agent-security]] — clinical LLM scribes and consumer health-LLM advisory.
- [[reference-distributed-authz]] — BOLA / BFLA in FHIR APIs.
- [[reference-graphql-api-security]] — modern healthcare API patterns.
- [[reference-saml-federation]] — hospital SSO / EHR federation.
- [[reference-mobile-security]] — BLE pairing; nurse phones and clinical apps.
- [[reference-privacy-engineering]] — sensitive-category data handling.
- [[reference-code-review-expertise]] — code-review heuristics.
- [[reference-appsec-program-building]] — program-level integration.
- [[reference-steelman-doctrine-expertise]] — disclosure-ethics adjudication.
