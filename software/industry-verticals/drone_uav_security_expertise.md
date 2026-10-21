# Drone, UAV, and Counter-UAS Security
## Staff-Level Technical Reference

---

## I. Researcher Profiles

Drone security as a public research discipline traces three overlapping arcs. The first is the 2013-2017 consumer-drone reverse engineering wave that took apart the Parrot AR.Drone and the early DJI Phantom families on a "Wi-Fi + open MAVLink + unsigned firmware" trust model that did not survive contact with researchers. The second is the 2017-2020 institutional disclosure wave during which DJI's bug bounty practices, US national-security concerns, and the FAA Remote ID rulemaking process forced the field into an enterprise / regulatory posture. The third is the 2022-2026 wartime wave: Ukraine's use of FPV drones, naval USVs, and one-way loitering munitions against the Black Sea Fleet, Russia's mass deployment of Shahed-136 against Ukrainian infrastructure, and the corresponding counter-UAS market expansion (Anduril, DroneShield, Dedrone, D-Fend, Echodyne, Robin Radar) into a multi-billion-dollar segment. The researchers below span those waves. This profile section is deliberately tighter than the parent `aviation_aerospace_security_expertise.md` — drone-specific work is the focus, not the whole aerospace canon.

### Samy Kamkar — independent

**Career arc**: Independent security researcher and serial public-disclosure author. The Myspace XSS worm (2005), evercookie, and a long arc of consumer-electronics reverse-engineering and side-channel work. The most-cited single piece of consumer-drone security research is his.

**Core contribution**: **SkyJack** (released 2 December 2013) — a Parrot AR.Drone 2.0 carrying a Raspberry Pi running Linux, an Alfa AWUS036H Wi-Fi card in monitor mode, and a Perl script driving `aircrack-ng` for `deauth` attacks. The script targets drones by MAC addresses carrying Parrot's vendor identifier and the well-known unauthenticated open Wi-Fi network on which the Parrot accepted control packets. SkyJack would deauthenticate the legitimate operator, associate to the now-vacant access point, and use `node-ar-drone` to take over flight control. Kamkar deliberately framed SkyJack as a hostile-aerial demo of an unfixable design issue: the Parrot AR.Drone's RF link had no authentication, encryption, or pairing, by design. Open-sourced on GitHub (`samyk/skyjack`) with full code, BOM, and operator instructions.

**Frame Kamkar introduced**: Consumer drones that broadcast unauthenticated open Wi-Fi as their command interface are a trivially compromisable network endpoint. The defense is not patching a bug — it is replacing the trust model. The Parrot architecture had no path to "fix" without a fleet-wide protocol break, which is why subsequent consumer drones (DJI OcuSync / Lightbridge, Skydio's encrypted link, Autel SkyLink) shipped with proprietary RF + AES from day one.

### Kevin Finisterre — independent

**Career arc**: Long-running independent security researcher (Department of Trust era, DigitalMunition); pilot; embedded-systems specialist. Best known publicly for the November 2017 DJI disclosure that produced an 18-page PDF titled "Why I Walked Away From $30,000 Of DJI Bounty Money" and reshaped how the drone industry talks about bug bounties.

**Core contribution**: In September-November 2017, Finisterre discovered DJI's private SSL certificate for `dji.com` exposed on a public GitHub repository (it had been there for up to four years), AES firmware encryption keys checked into the same repos, and AWS credentials for DJI's SkyPixel asset bucket. Pivoting on those credentials, he accessed customer-uploaded flight logs, aerial photos, and personally-identifiable documents — passports, drivers licenses, and government IDs. DJI initially offered the top-tier $30,000 bounty, then the two sides disagreed over the terms of a non-disclosure agreement DJI wanted bounty recipients to sign, and DJI warned him he may have broken US computer-hacking laws. Finisterre declined the bounty and published the full chain.

**Frame Finisterre established**: Drone vendors handle a customer-data footprint (locations, imaging, identity documents) that is more sensitive than the average consumer-electronics vendor, and their bug-bounty programs need legal-safe-harbor terms that match. The 2017 disclosure also became the canonical reference case for security-researcher legal protection in vendor bounty contracts. The 18-page writeup mirror lives at `regmedia.co.uk/2017/11/16/whyiwalkedfrom3k.pdf`.

### Nils Rodday — University of Twente; IBM

**Career arc**: Graduate research at University of Twente, Netherlands, on professional-grade UAV security. Subsequently IBM. Single canonical paper rather than a long arc — but the paper became the reference work on professional-class drone link insecurity.

**Core contribution**: "Hacking a Professional Drone" (Black Hat Asia 2016, March 2016). Rodday demonstrated a live hijack of a professional UAV — retail approximately US$28,000 — using less than US$40 of off-the-shelf hardware. Two vulnerabilities chained: (1) the telemetry link between tablet controller and ground station used WEP (Wired Equivalent Privacy) Wi-Fi, breakable in seconds with `aircrack-ng`; (2) the XBee 868 MHz link between ground station and drone, though built on hardware that supports AES, shipped with encryption disabled to reduce command-latency. A man-in-the-middle attacker could inject control packets from up to 2 km away. The thesis behind the talk: "Exploring Security Vulnerabilities of Unmanned Aerial Vehicles."

**Frame Rodday introduced**: Price-tier and certification-tier do not predict security posture in drone hardware. A professional / surveying / police-class platform priced 100x consumer drones can ship with WEP and unauthenticated XBee links because the integrator optimized for latency and battery life, not for adversarial threat models. The defensive case must rest on link-layer integrity (signed MAVLink 2.0 or proprietary AES) and physical-layer monitoring, not on the assumed competence of the price tier.

### Andrei Costin — University of Jyväskylä

**Career arc**: PhD at EURECOM under Aurélien Francillon and Davide Balzarotti; founder of Firmware.RE; Assistant Professor at the Cyber Security Group, University of Jyväskylä, Finland. Best known for large-scale embedded-firmware analysis methodology. Cross-referenced in `aviation_aerospace_security_expertise.md` for his ADS-B work.

**Core contribution**: While Costin's headline ADS-B work targeted manned aviation, his lineage of work on embedded firmware drives much of the drone-side analysis methodology. The Firmware.RE corpus and methodology, plus his teaching of large-scale firmware analysis to subsequent academic generations, underpins the consumer-drone reverse-engineering practice. Papers on UAV security from his lab and collaborators include surveys of MAVLink / Pixhawk / PX4 / ArduPilot attack surface and threat models, and the academic citation graph around drone firmware analysis runs through this lineage.

**Frame Costin's lineage contributed**: Drone firmware is embedded firmware. The full toolkit of `binwalk`, `firmadyne`-style emulation, `firmwalker`, hardcoded-secret scanning, and CVE-mapping that the IoT-firmware-research community built applies directly. Drones are not a special case requiring a separate methodology — they are a particularly safety-relevant subset of the embedded ecosystem. Cross-link `firmware_embedded_security.md`.

### Ken Munro and the Pen Test Partners drone team

**Career arc**: Founder of Pen Test Partners (Buckingham, UK). Drone work sits inside a broader aviation / EFB / IFE consultancy practice. Cross-referenced in `aviation_aerospace_security_expertise.md` §I for the EFB and TCAS work. Multiple staff at the firm hold pilot certifications, which gives them operational credibility for aviation-adjacent drone analysis (drone-bird-strike modeling for crewed aviation, drone-near-runway risk assessment).

**Core contribution**: A decade-long disclosure cadence on consumer-drone, app-store, and counter-UAS topics. DEF CON 30 Aerospace Village (2022) drone work; consistent blog disclosures of drone-app security flaws; integration of drone topics into the firm's broader Aerospace Village contributions. The Pen Test Partners practice does not have one canonical paper; instead, it is the dominant English-language consultancy-cadence voice on drone security disclosures, with the public-facing material at `pentestpartners.com/security-blog`.

**Frame Munro and team established**: Drones are not a special trust domain — they are mobile fleets of embedded devices with companion mobile apps, cloud back-ends, and supply-chain dependencies, all of which carry standard enterprise security risk profiles. The defensive case is mobile-fleet management, signed firmware, app-store hygiene, and operational separation between consumer telemetry and military / regulated-flight data.

### Aerospace Village (DEF CON) drone subgroup

The **DEF CON Aerospace Village** first appeared in 2019 (cross-referenced in `aviation_aerospace_security_expertise.md` §I) and has hosted dedicated drone CTFs, fly-in labs, and tear-down sessions. Notable contributors include the **Bricks-in-the-Air** introductory lab, the drone-radio-protocol reverse-engineering workshops, the joint Aerospace-Village / Car-Hacking-Village sessions on shared-platform attack chains, and the recurring `wsfuzz`-style fuzzing of MAVLink / DJI / ExpressLRS link-layer implementations. The Village is the highest-throughput open venue for drone-side disclosure and the de facto introduction point for new researchers entering the field.

### Commercial counter-UAS research teams

**Anduril Industries** (founded 2017 by Palmer Luckey, Trae Stephens, Brian Schimpf, and others) — Lattice software platform for sensor fusion + autonomous tracking; Anvil interceptor (a kinetic drone-on-drone takedown); Roadrunner reusable interceptor; Pulsar electronic-warfare counter-UAS family; Sentry tower system; Wisp / Spyglass / Spark complementary platforms. The March 2026 US Army enterprise contract vehicle worth up to $20B puts Anduril in the dominant US-military-counter-UAS-systems-integrator position.

**DroneShield** (Australian/US) — RF-detection focus (DroneGun and DroneSentinel families); AI-based passive RF classification; SaaS analytics back-end; commercial-and-military dual market. The 2024-2025 expansion saw the firm scale to roughly AU$500M annual manufacturing capacity.

**Dedrone** (US/Germany, acquired by Axon in 2024) — radar / RF / camera fusion focus; library-based DJI / Autel / Parrot fingerprint classification; deployments at airports, prisons, and stadiums.

**D-Fend Solutions** (Israeli) — protocol-level take-over rather than RF jam; targets consumer-drone command protocols and assumes control of the platform mid-flight.

**Echodyne** — metamaterial electronic-scanned-array (MESA) radar for low-altitude airspace; complements RF and EO/IR detection where RF is jammed or absent.

**Robin Radar** (Netherlands) — bird-and-drone radar specifically tuned for the avian / micro-UAV speed and RCS profile. The Iris X-band radar is the canonical airport-counter-UAS radar.

**Frame the commercial counter-UAS teams collectively establish**: The defensive market is large, fast-moving, and split between *sense / fuse / classify* (Lattice, Dedrone, DroneSentinel) and *defeat* (Anvil, DroneGun, Wisp, Coyote-class interceptors). Most institutional buyers under-invest in the detect side relative to the defeat side, despite detect being the harder, more frequently-needed capability and the only one most non-federal US operators are legally permitted to deploy (47 USC 333 / 49 USC 44810).

---

## II. The Drone Threat Model

### Categories: civilian, commercial, military, weaponized

**Civilian / consumer** — hobby and prosumer drones, broadly the DJI Mavic / Mini / Air / Phantom families, Autel EVO, Skydio (now Blue UAS approved consumer-of-record), Parrot Anafi, Holy Stone, and dozens of smaller vendors. Typical price band US$300-US$3,000. Wi-Fi or proprietary RF link. GPS + sometimes IMU + visual SLAM. Cloud telemetry by default on DJI.

**Commercial / professional** — surveying, inspection, agriculture, public-safety, cinematography. DJI Matrice, Skydio X10, Parrot ANAFI USA, senseFly, Yuneec H520. Price band US$5,000-US$50,000. AES-encrypted RF link, regulatory-compliant Remote ID, BVLOS waivers, often integrated with corporate fleet-management software.

**Military / dual-use, ISR** — General Atomics MQ-9 Reaper, RQ-4 Global Hawk, RQ-170 Sentinel (US); Heron, Hermes (Israel); Wing Loong (China). Encrypted satellite + line-of-sight links. Classified C4ISR architecture. Operationally segregated from civilian airspace except for transit corridors.

**Military / dual-use, strike and loitering munitions** — Bayraktar TB2 (Turkey, Baykar); Shahed-136 / Geran-2 (Iran, deployed by Russia in Ukraine); Switchblade 300/600 (US, AeroVironment); Lancet ZALA (Russia); SkyStriker (Israel, Elbit); HAROP (Israel, IAI). These are aerial single-use weapons with various payload, range, and loitering capability, plus an increasing share of FPV racing-drone derivatives carrying RKG-3 grenades or shaped-charge payloads.

**Military / autonomous swarm** — DARPA OFFSET (concluded 2021); Anduril Bolt-M; Saronic and Ocius unmanned surface vessels; emerging autonomous-swarm platforms across multiple defense ministries.

### Democratization

The asymmetric-warfare implication of consumer drones is the dominant security policy story of 2022-2026. A US$400 DJI Mini or a US$200 FPV racing build, plus a 3D-printed payload-release mechanism and a commercial off-the-shelf grenade, produces a weapon system that ten years ago required a state arms program. Ukraine's domestic FPV production scaled to roughly two million units in 2024 with the official 2025 target above three million. The threat model treats UAS-borne kinetic attack against soft targets — energy infrastructure, ports, ISR-platform garages, parked aircraft, stadium events — as a permanently realistic capability available to non-state and small-state actors.

### Counter-UAS market sizing

Estimates vary, but the global counter-UAS market is reported in the US$1-4B range as of 2024-2025 with consensus growth projections to US$10-15B by 2030. Anduril's March 2026 award of a US Army enterprise contract vehicle worth up to $20B (with a first $87M task order for Lattice counter-drone command and control) is the largest single procurement vehicle in the space. DroneShield reported AU$500M annual manufacturing capacity in 2025. Dedrone was acquired by Axon in 2024 with a counter-UAS product line absorbed into a public-safety portfolio.

### Remote ID (FAA Part 89, 2023+)

The FAA's Remote ID rule under 14 CFR Part 89, effective 16 September 2023 (enforcement transitioned to active in 2024-2025), requires drones registered under 14 CFR Part 47 or 48 to broadcast identification and location data. Three compliance paths: Standard Remote ID (built into the drone), Remote ID Broadcast Module (retrofit dongle), or operation in a FAA-Recognized Identification Area (FRIA — restricted to specific approved sites, primarily AMA model-aircraft fields). The broadcast medium is Bluetooth or Wi-Fi (FCC Part 15), receivable by any compliant ground receiver. Spoofability is structurally identical to ADS-B: no cryptographic authentication, no encryption, all fields publicly readable. The TM-RID (Trustworthy Multipurpose Remote ID) and other extensions adding authentication remain proposals as of 2026.

---

## III. Consumer Drone Ecosystem

### DJI dominance

**DJI** (Shenzhen, China; founded 2006) is the global consumer / professional drone manufacturer, reported in industry analyses at >70% of the global consumer market. The Mavic, Mini, Air, and Phantom families, plus the Matrice professional platforms, the Inspire cinema line, and the Agras agriculture line, span most of the prosumer-and-up market. The platform shipped from the mid-2010s onward with: GPS / GNSS positioning (GPS + GLONASS + Galileo + BeiDou on later models), proprietary RF link (`OcuSync`/`Lightbridge`, 2.4 / 5.8 GHz, AES-encrypted), a DJI mobile companion app (DJI Fly / DJI Pilot / DJI Go), in-firmware geofencing (GEO 2.0, defining No-Fly Zones around airports and sensitive sites that the drone refuses to enter or take off in), and DJI Cloud telemetry uploading flight logs and frequently imagery to DJI-operated servers.

### US restrictions and national-security concerns

- **August 2017**: A US Army memorandum (DAMO-AV, dated 2 August 2017) ordered the immediate cessation of all DJI use across the service citing operational security concerns.
- **January 2020**: US Department of Interior grounded its drone fleet (predominantly DJI).
- **2020-2024**: Pentagon banned DJI for defense customers; Commerce Department added DJI to the Entity List (December 2020).
- **2024**: "Countering CCP Drones Act" (HR 2864) passed the House attached to the FY2025 NDAA; would prohibit FCC authorization of DJI and Autel products for use on US communications infrastructure, effectively banning new product imports. Under Section 1709 of the enacted FY2025 NDAA, the FCC added foreign-produced UAS, including DJI and Autel, to its Covered List on 22 December 2025.
- **December 2021**: Treasury OFAC actions against DJI on alleged Xinjiang surveillance ties.

The defensive-investment market for DJI alternatives — Skydio, Parrot ANAFI USA, Teal Drones, Red Cat — accelerated after the bans. The **Blue UAS** list, created by DIU (Defense Innovation Unit) and transferred to DCMA in December 2025, catalogs the cleared platforms.

### Skydio, Parrot, Autel, Holy Stone

**Skydio** (San Mateo, CA; founded 2014) — visual-SLAM-first autonomy stack with onboard NVIDIA Jetson processing. The X10 / X10D and X2D are the current enterprise / defense platforms. Skydio drones operate in GPS-denied environments via visual-inertial odometry; six navigation cameras provide 360-degree obstacle avoidance. AES-256 link encryption; Blue UAS approved.

**Parrot** (Paris, France) — ANAFI Ai (4G-cellular link, Parrot Cloud, designed for enterprise BVLOS), ANAFI USA (Blue UAS approved). Pivoted toward enterprise / defense after the consumer AR.Drone era. Open SDK and developer-friendly approach contrasts DJI's closed firmware.

**Autel Robotics** (Shenzhen, China; founded 2014) — EVO Lite, EVO II, EVO Max 4T. The closest direct DJI competitor on consumer specs. Subject to similar US national-security pressure as DJI through 2024-2026.

**Holy Stone, Potensic, Ruko, others** — the long tail of toy-grade and entry-prosumer drones; typically Wi-Fi RF, low-cost STM32-class flight controllers, minimal security posture. The market footprint is large but the per-platform risk is bounded by short range and limited payload.

---

## IV. Radio-Link Attack Surface

### 2.4 GHz, 5.8 GHz, and ISM-band protocols

Most consumer and prosumer drones share two ISM bands. The 2.4 GHz band carries Wi-Fi (consumer toy-grade drones, plus telemetry and video on some platforms), proprietary frequency-hopping link protocols (DJI OcuSync legacy, FrSky ACCESS, Spektrum DSMX), and ExpressLRS / Crossfire / Ghost long-range FPV control links. The 5.8 GHz band carries analog FPV video (the dominant FPV-racing video transmission), digital HD FPV systems (DJI Digital, Walksnail, HDZero), and the modern OcuSync / O3 / O4 telemetry-and-control link. 868 MHz (EU) and 900 MHz (US) carry long-range telemetry (RFD900, XBee, ELRS in 915 MHz form).

### DJI OcuSync / Lightbridge

DJI's proprietary RF system (`Lightbridge` 1.0/2.0 on older platforms, `OcuSync` 1.0/2.0/3.0/4.0 progressively from Mavic Pro onward, currently `O4`) implements adaptive frequency-hopping across both ISM bands, AES-encrypted payload, automatic-channel-quality selection, and downlink video plus uplink control. The protocol is closed but has been partially reverse-engineered. The 2023 academic disclosure "Behind The Wings: The Case of Reverse Engineering and Drone Hijacking in DJI Enhanced Wi-Fi Protocol" (arXiv 2309.05913) demonstrated a proof-of-concept hijack against the DJI Mini SE using reverse-engineered control commands over the Enhanced Wi-Fi link variant. The link-layer encryption did not, on its own, defeat the attack — the attack chained protocol-level command-stream replay and injection.

### ExpressLRS / Crossfire / Ghost — FPV control link

**ExpressLRS** is the dominant open-source long-range RC control link for FPV drones in 2024-2026, replacing the proprietary Crossfire (TBS) and Ghost (ImmersionRC) systems on most builds. ELRS runs on SX1280 (2.4 GHz) or SX1276 (915 MHz / 868 MHz) LoRa-class transceivers; provides frequency-hopping; supports binding phrases as the pairing primitive. Earlier ELRS versions had documented vulnerabilities in the binding-phrase derivation and replay-attack windows; v3.x and v4.x improved the model. Defensive operators (mostly hobby community) treat the binding phrase as the security boundary — predictable phrases create cross-pilot interference and theoretical hijack windows.

### Wi-Fi-based control (consumer and toy drones)

The historical Parrot AR.Drone trust model — drone advertises an open access point named `ardrone_XXXXX`; operator's phone joins it; control packets are sent over UDP with no authentication — defines a class of consumer drone that is structurally `SkyJack`-able. Holy Stone, Potensic, Ruko, and many toy-grade DJI Tello-class drones all exhibit some variation of this pattern. The defense is to not use these platforms in any context where adversarial deauthentication / takeover is a concern; there is no patch path.

### SkyJack 2013 (Kamkar)

The Kamkar reference platform demonstrates the full chain: passive sniffing → deauth attack via aircrack-ng → MAC-address match against Parrot's vendor identifier → automatic join → command-stream injection via node-ar-drone. Hardware: Parrot AR.Drone 2.0 + Raspberry Pi + two USB Wi-Fi adapters (one for monitor mode, one for join). Cost was approximately US$400 in 2013 components. The open-source release on GitHub means the methodology is permanently in the public domain; the affected platform class (open-Wi-Fi-control consumer drones) remains in production and on the market in 2026.

Cross-link `wireless_rf_satellite_security_expertise.md` for the broader RF-link attack-surface treatment, including SDR-based generic protocol reverse-engineering workflow.

---

## V. GPS Spoofing of Drones

### Civilian GPS is unauthenticated

The fundamental security property of civilian GPS (L1 C/A signal) is that there is no cryptographic authentication of the navigation message. Any attacker with an HackRF, USRP, or LimeSDR plus a GPS-simulation toolchain (`gps-sdr-sim`, `bladeRF-gps`, `LabSat`, the GitHub gps-spoofing-frameworks lineage) can synthesize plausible GPS signals that a commodity receiver will lock onto. Counter-spoofing literature is extensive but the deployed civilian-receiver fleet — including in nearly every consumer drone, smartphone, and vehicle — is unprotected. Galileo's **OSNMA** (Open Service Navigation Message Authentication) reached Initial Service on 24 July 2025 for the Galileo constellation; uptake in receiver firmware remains uneven and most consumer drones do not validate OSNMA. Cross-link `wireless_rf_satellite_security_expertise.md` §6 (GNSS).

### Russian EW in Ukraine

The 2022-2026 Russia-Ukraine war is the largest single empirical demonstration of GPS denial / spoofing at scale. Russian electronic-warfare units have deployed wide-area GNSS jamming (Pole-21, R-330Zh Zhitel, Borisoglebsk-2) and spoofing across Ukrainian airspace and into Black Sea / Baltic / Eastern Mediterranean shipping lanes. Effects observed:

- Mass commercial-aviation GPS-loss reports across Eastern Europe and the eastern Mediterranean (the OpenSky and Flightradar24 data sets are public).
- Routine loss-of-link and route-failures on Ukrainian and Russian small drones in border regions; Ukrainian operators report consumer DJI failures within ~5-10 km of EW positions.
- Shahed-136 strike accuracy reportedly affected; counter-spoofing of incoming Shaheds is a Ukrainian defensive practice.

The strategic-policy implication is that GNSS-denied operations are now the realistic peer-conflict baseline, not an exception.

### Anti-spoofing: IMU, visual SLAM, multi-constellation, OSNMA

The defenses available to drone designers in 2026:

- **Multi-constellation GNSS** — receiving GPS + GLONASS + Galileo + BeiDou and cross-checking. Spoofing one constellation is easy; spoofing four coherently is hard but not infeasible for state actors.
- **Inertial navigation (IMU) dead-reckoning** — fall back to IMU when GNSS plausibility checks fail. The IMU drifts but covers minutes-to-hours of useful navigation depending on grade.
- **Visual-inertial odometry / SLAM** — Skydio's flagship capability. Computer-vision-based localization against environmental features. Fully GPS-independent for known or scanned environments. Vulnerable to adversarial-image attacks against the underlying ML models (cross-link `adversarial_ml_model_security_expertise.md`).
- **Multi-receiver cross-checks and CRPA antennas** — Controlled Reception Pattern Antennas (CRPA) on military platforms reject jamming-and-spoofing from known elevation / azimuth bands. Expensive; export-controlled.
- **OSNMA on Galileo** — cryptographic authentication of the Galileo navigation message; Initial Service declared July 2025; uptake patchy.
- **Receiver integrity monitoring (RAIM)** — plausibility checks against multi-satellite-geometry consistency; standard in aviation receivers; not standard in cheap consumer drone GNSS modules.

### Skydio "GPS-denied" marketing

Skydio's autonomy stack explicitly markets GPS-denied capability. The X10D platform retains navigation and "return-to-home" capability via visual-inertial odometry alone, navigating along a pre-planned visual map of the operating environment when GNSS is lost. This is the strongest commercial response to Ukraine-style EW environments available to Western drone operators as of 2026.

---

## VI. Drone Firmware Exploitation

### DJI firmware research lineage

DJI firmware research has been a continuous community activity since 2015. The **DJI Mavic** firmware unpacking work, the early **Phantom 3 / 4** modding scene that included flight-controller jailbreaks, the **DJI Assistant 2** USB-debug-interface analysis, and the 2017-2020 chain of disclosures around AES key recovery, no-fly-zone removal mods (the `NFZ-removal` community ran for years), and unsigned-update injection define the canonical attack surface. The 2017 Finisterre disclosure (see §I) was about exposed cloud keys; the parallel firmware-side work continued independently.

Hardware platforms inside DJI drones run heterogeneous SoCs (Ambarella image-processing SoCs, ARM Cortex flight controllers, custom radio baseband processors). Each is a distinct firmware-RE target. The community-driven `dji-rev` and adjacent projects produce ongoing reverse-engineering coverage.

### Pixhawk + ArduPilot / PX4

**Pixhawk** is the open hardware reference flight-controller (the Pixhawk Open Hardware Foundation maintains the standard; vendors include Holybro, mRo, CUAV). **ArduPilot** (DIY Drones lineage, GPLv3) and **PX4** (Dronecode Foundation, BSD-3-Clause) are the two dominant open autopilot stacks. Both run on NuttX RTOS (PX4) or ChibiOS (ArduPilot), expose MAVLink as the primary command / telemetry protocol, and integrate with QGroundControl / Mission Planner ground-station software.

The **MAVLink** protocol has a well-documented security posture: MAVLink 1.0 ships with no authentication or encryption; MAVLink 2.0 supports HMAC-SHA-256 message signing but the feature is opt-in and frequently disabled to reduce latency. Documented vulnerabilities:

- **CVE-2020-10282** — MAVLink 1.0 lacks authentication, allowing identity spoofing, unauthorized command injection, and person-in-the-middle attacks.
- **CVE-2026-1579** — PX4 Autopilot remote-command-execution vulnerability (CVSS 9.8) where insufficient authentication on the MAVLink interface allowed attackers with network access to execute arbitrary shell commands on the autopilot controller. The vulnerability illustrates the cost of opt-in signing.

The **MAVSec** paper (Allouch et al., 2019, IWCMC) catalogs MAVLink's threat model in detail: spoofing, replay, GCS impersonation, message-flooding DoS, hijack via heartbeat-injection. The recommended defenses are MAVLink 2.0 signing, transport-layer encryption (TLS / DTLS between GCS and vehicle when over IP), and ground-station authentication. Production deployments routinely fail to apply these.

### NuttX RTOS

PX4 runs on **NuttX**, a POSIX-like RTOS originally written by Greg Nutt. NuttX provides preemptive multitasking, POSIX threads, and a Linux-style filesystem layout on resource-constrained MCUs (STM32 H7, Kinetis K2x). Cross-link `rtos_embedded_os_expertise.md` for the broader RTOS security treatment. NuttX security vulnerabilities are tracked in the Apache Software Foundation CVE process; the kernel surface is small relative to Linux but the per-task isolation model is weaker.

### AeroScope (DJI surveillance system, discontinued 2023)

**AeroScope** was a DJI-built receiver system that demodulated DJI drone control signals to surface the drone's serial number, GPS position, altitude, speed, heading, and the operator's GPS position. Stationary units provided up to 50 km detection range; portable units provided 5 km. The system was sold to law enforcement, critical-infrastructure operators, and airports.

Two structural issues defined AeroScope:

- DJI confirmed during the Ukraine-war controversy (2022-2023) that the AeroScope signaling between drone and AeroScope receiver was *not encrypted* despite earlier DJI public statements suggesting it was. Russia obtained AeroScope receivers and used them in Ukraine to localize Ukrainian DJI-flying operators — turning a counter-UAS detection product into an offensive operator-finding tool.
- AeroScope only detected DJI drones, and not every DJI model. The detection surface was vendor-specific.

DJI discontinued AeroScope in 2023. Secondary-market units circulate. The episode is the canonical reference case for "your counter-UAS product depends on the cooperation of the platform it is supposedly countering."

---

## VII. Remote ID (FAA Part 89)

### Mandatory broadcast since September 2023

Under **14 CFR Part 89** (effective 16 September 2023; FAA enforcement active 2024-2025), drones registered under 14 CFR Part 47 or 48 must broadcast Remote ID. The broadcast carries:

- The drone's serial number or a session ID (Standard Remote ID), or the module's serial number (Remote ID Broadcast Module).
- The drone's current latitude / longitude / altitude.
- The drone's velocity.
- The control station's latitude / longitude (Standard Remote ID only).
- An emergency status flag.
- A timestamp.

Three compliance paths exist:

1. **Standard Remote ID** — built into the drone at manufacture; firmware-level broadcast from takeoff to shutdown.
2. **Remote ID Broadcast Module** — retrofit dongle for legacy drones; mounts to the airframe, broadcasts the same data plus the takeoff location (not live GCS position).
3. **FAA-Recognized Identification Area (FRIA)** — flight only within an approved fixed site (almost exclusively AMA model-aircraft fields). No Remote ID required within the FRIA boundary.

### Spoofing and operator-privacy concerns

The Remote ID rule shares ADS-B's structural property: no cryptographic authentication on the broadcast. Anyone with a Bluetooth / Wi-Fi receiver can decode the broadcast. Anyone with a software-defined-radio or modified Wi-Fi/Bluetooth chipset can transmit synthetic Remote ID packets matching the wire format and appear as a "ghost drone." The pattern is identical to ADS-B ghost-injection (cross-link `aviation_aerospace_security_expertise.md`).

Operator-privacy concerns:

- Live broadcast of the GCS position exposes operator location for the duration of flight — relevant for journalism, conflict-zone operations, surveillance-targets, and law-enforcement officers operating drones in adversarial environments.
- The serial-number broadcast is a vendor-specific persistent identifier across all flights of a given drone, defeating any operational-anonymity goal.

The **TM-RID** (Trustworthy Multipurpose Remote ID) IETF effort adds trust to broadcast Remote ID by authenticating messages. TM-RID and similar schemes are proposed but not yet a regulatory accepted means of compliance as of 2026.

### Evasion for malicious operators

A malicious operator has multiple low-effort options to evade Remote ID:

- Use a non-compliant drone (the rule applies only to registered drones above 0.55 lb; non-registered drones or sub-threshold platforms are exempt).
- Modify firmware to spoof a different drone's serial / position (community modding tooling exists; DJI Standard Remote ID has been firmware-patched out in some unofficial builds).
- Use a Remote ID Broadcast Module attached to a different drone than the one actually flying.
- Spoof multiple Remote ID signals from a SDR to flood the receiving fence with ghost drones.

The defensive realism: Remote ID is a compliance instrument for benign operators (the same population that registers with the FAA), not a counter-UAS detection layer. Counter-UAS for hostile drones must come from radar, RF detection, and EO/IR — not from Remote ID.

---

## VIII. Drone-as-Weapon

### Loitering munitions: Shahed-136, Switchblade, Lancet, HAROP, Bayraktar TB2

**Shahed-136 / Geran-2** (Iran HESA, designation reused by Russia) — delta-wing, ~200 kg gross weight, ~40 kg warhead, ~2,500 km nominal range, prop-driven by piston engine. Iran-designed circa 2019; mass deployment by Russia against Ukraine from September 2022 onward. Cost-per-airframe estimates run US$20,000-US$50,000 in Iranian production, lower in Russian-localized production (the `Geran-2` Yelabuga factory). Operationally used as a one-way attack vehicle, not as a "loitering" platform — RUSI noted that classification as a *loitering munition* is misleading; the Shahed-136 has been used in point-to-point cruise-missile-style profiles, not orbit-and-strike. The Institute for Science and International Security tracks monthly Russian Shahed deployment counts (`isis-online.org/isis-reports`); March 2026 single-day attacks have exceeded 900 UAVs in a 24-hour window.

**Switchblade 300 / 600** (US, AeroVironment) — Switchblade 300 is a 5.5 lb tube-launched anti-personnel loitering munition; range ~10 km, 15-minute endurance. Switchblade 600 is the anti-armor variant, ~33 lb munition (65 lb all-up round), ~40 km range, ~40-minute endurance, equipped with anti-armor warhead. Both deployed to Ukraine from 2022 onward.

**Lancet ZALA** (Russia, ZALA Aero Group / Kalashnikov Concern) — X-tail loitering munition, ~12 kg gross weight, ~3 kg warhead, ~40 km range. Optical-imagery-based terminal targeting. Heavy use against Ukrainian artillery and air-defense systems.

**HAROP** (Israel, IAI) — earlier-generation loitering munition (publicly unveiled 2009); 9-hour endurance, anti-radiation seeker variants, integrated into multiple national arsenals; the conceptual ancestor of the current loitering-munition class.

**Bayraktar TB2** (Turkey, Baykar) — medium-altitude long-endurance reconnaissance-strike UAV; carries MAM-L laser-guided munitions; first export (Qatar) in 2018; combat-proven by Azerbaijan in the 2020 Nagorno-Karabakh war, by Ukraine in early 2022, by Ethiopia, by Libya. The TB2 ushered in the prosumer / mid-budget national-arsenal armed-UAV era and is the geopolitical-cost benchmark against which competitors are measured.

### FPV racing drones repurposed

The single most consequential 2023-2026 evolution: commercial off-the-shelf 5-7-inch FPV racing drones, modified with payload-release mechanisms, used as expendable kinetic strike platforms. Ukrainian and Russian forces deploy them at scale — Ukrainian production reportedly two million units in 2024 with a 2025 target above three million. Costs run US$400-US$1,500 per unit. Payloads are typically RKG-3 anti-tank grenades, modified 40mm grenades, or shaped charges. Estimates through 2024-2026 hold that drone casualties (including FPV) account for ~80% of battlefield casualties in Ukraine by 2025, up from <10% at war start.

The FPV-repurposing trend has crossed into terrorism and criminal use — the December 2018 Gatwick episode (whatever its actual ground truth — see §XI) preceded confirmed criminal FPV-attack episodes against prisons (contraband delivery), data-center perimeters (intrusion testing), and stadium events (disruption).

### AI-driven targeting and autonomous engagement

The 2024-2026 wave of "AI-enabled" drone systems is partly hype and partly real. The verifiable real progress:

- **Visual terminal-homing** on Russian Lancet and Ukrainian-modified FPV drones using lightweight on-board CV models for last-mile target lock. Resilient to GPS jamming; vulnerable to camouflage and decoys.
- **Autonomous "fire-and-forget" engagement** in restricted-zone operations where command links are likely to be jammed; the drone takes off, navigates to a pre-loaded GPS / visual waypoint, and engages a class of target without a continuous human-in-the-loop.
- **Swarm-coordination algorithms** for multi-airframe ingress patterns; Russia's mass Shahed launches (140+/day in February 2025, 900+ in single 24-hour windows by March 2026) are coordinated at the launch-window level rather than in-flight.

The **lethal autonomous weapons (LAWS) debate** runs through the UN Convention on Certain Conventional Weapons (CCW) Group of Governmental Experts process. As of 2026 no binding international constraint exists; voluntary frameworks (the 2023 US "Political Declaration on Responsible Military Use of AI and Autonomy" signed by 50+ states) are non-binding. Drone-as-weapon proliferation effectively predates any treaty regime.

Cross-link `adversarial_ml_model_security_expertise.md` for the model-attack surface on terminal-homing CV. Cross-link `rtos_embedded_os_expertise.md` for the embedded-runtime substrate.

---

## IX. Counter-UAS Detection

### Radar

**Echodyne** — metamaterial electronic-scanned-array (MESA) radar; K-band (EchoGuard) and Ku-band (EchoShield); integrated into Anduril Lattice and standalone deployments. Low-altitude airspace coverage where conventional radar fails because of ground clutter and the small RCS of consumer drones. The MESA approach gives software-defined beam steering at hardware cost competitive with mechanical-scan systems.

**Robin Radar** (Netherlands) — Iris X-band radar specifically tuned for the bird-and-drone speed and RCS profile. Canonical at airport-counter-UAS deployments. Discriminates between birds (which are common, daily, and not actionable) and drones (which are not).

**Other radar**: Thales Squire, IAI ELI-4030 Drone Guard, Hensoldt Spexer.

Radar covers the **detect** half of the kill chain across all weather and lighting. RF-only systems fail when the drone is autonomous (no link), uses unknown protocols, or operates in heavy-RF-clutter environments. Radar fills those gaps.

### RF detection

**Dedrone** (Axon, 2024+) — library-based DJI / Autel / Parrot / FPV-protocol fingerprint classification. Maintains a fingerprint database that maps RF signature to drone model and (where possible) operator location. Deployed at airports, prisons, stadiums, large corporate campuses.

**DroneShield** — DroneSentinel passive RF detection; DroneSentry-X vehicle-mounted on-the-move detector; DroneSentry-C2 fusion platform. AI-based RF classification with quarterly fingerprint updates.

**Anduril Lattice / Pulsar** — RF detection integrated as one sensor lane within Lattice's broader fusion architecture; Pulsar adds counter-RF (defeat) capability.

**D-Fend Solutions** — EnforceAir; RF detection plus protocol-level take-over of common consumer drones (DJI, Autel) via spoofed control commands. Crosses from detect into the defeat category.

**Open-source / hobby**: HackRF + GNU Radio + Wireshark for DIY RF detection. Effective against consumer Wi-Fi-based drones; less effective against proprietary protocols without prior reverse-engineering work.

### Acoustic detection

Microphone arrays trained on drone-rotor acoustic signatures. Effective in quiet environments (prisons, rural critical-infrastructure perimeters); ineffective in urban / airport / industrial environments. Companies: Squarehead Discovair. Acoustic is a complementary sensor in fusion architectures rather than a standalone solution.

### Computer vision (EO/IR)

EO/IR cameras with object-detection models tuned for small-aerial-target classification. Resistant to RF jamming; sensor-limited in low-light, fog, and rain. Anduril Sentry tower system integrates EO/IR with radar and RF; Dedrone integrates EO/IR cameras with its detection stack. Vulnerable to adversarial-image attacks against the underlying classifier (cross-link `adversarial_ml_model_security_expertise.md`).

### Sensor fusion

The dominant 2024-2026 architectural pattern is sensor-fusion: combine radar + RF + EO/IR + acoustic in a single C2 platform that performs target identification, classification, and tracking with explicit confidence scoring per lane. Anduril Lattice, DroneShield C2, Dedrone DroneTracker, IAI Drone Guard fusion platforms — all converge on the same shape. The defensive correctness argument: no single sensor lane is reliable across all drone classes and conditions; the fusion overlap is where false-positive rate falls to deployable levels.

---

## X. Counter-UAS Defeat

### RF jamming

**DroneGun** family (DroneShield) — directional RF jammers covering ISM bands (2.4 / 5.8 GHz) and GNSS (L1 / L2 / L5). DroneGun Mk4 is the current flagship. Force the target drone into return-to-home or fail-safe descent.

**Black Sage**, **Battelle DroneDefender** — various RF-jam products with different form factors and band coverage.

RF jamming has two structural issues: (1) legal — under 47 USC 333, intentional jamming of authorized radio services is a federal offense in the US for non-federal operators; only federal agencies with statutory authority (DOJ, DOD, DOE, DHS components) can lawfully jam in US territory. (2) operational — RF jamming affects all RF in the band, not just the target drone; in urban environments and near critical infrastructure, the collateral RF impact on legitimate services (police radios, building security, cellular) is significant.

### GNSS spoofing

**Various Anduril and DroneShield products** include GNSS-spoofing capability as one defeat lane. Force the target drone's GPS receiver to lock to a manufactured signal that drives it to a predetermined safe-landing location.

GNSS-spoofing defeat is preferable to RF jamming when (a) the drone uses GPS for navigation and is not in a GPS-denied autonomy mode, and (b) the operator can establish a "safe landing zone" within range. Effectiveness against modern Skydio / military GPS-denied platforms is zero.

### Cyber takeover (protocol-level)

**D-Fend EnforceAir** is the canonical commercial example. Identify the drone protocol, inject crafted control-stream commands that the drone treats as authoritative, and assume control mid-flight. Effective against consumer DJI / Autel platforms where the protocol is reverse-engineered; ineffective against unknown / proprietary / military links. The advantage over jamming and spoofing is that the drone is recoverable (landed intact), which matters for forensics and for the legal-evidentiary case against the operator.

### Kinetic interception

**Nets** — handheld (SkyWall Patrol), vehicle-mounted (OpenWorks SkyWall Auto) or drone-mounted (Anduril Anvil) net-deployment systems that physically capture the target. Anvil specifically is an autonomous drone-on-drone kinetic intercept: a Lattice-cued Anvil interceptor launches, navigates to the target, and physically rams or nets it. Recoverable target; minimal collateral damage.

**Projectiles** — small-arms fire (the most common low-tech option globally); shotgun shells; specialized counter-UAS munitions like the Coyote Block 2 interceptor (Raytheon / RTX) used in US military counter-UAS deployments at scale through 2023-2026.

**Roadrunner** (Anduril) — reusable jet-powered interceptor; can be recalled mid-engagement if no longer needed; canonical example of the "intelligent interceptor" class.

### Laser and directed-energy weapons

**Israel Iron Beam, US AN/SEQ-3 LaWS, UK DragonFire** — high-energy laser systems for soft-kill of drones at range. Cost-per-shot is very low (electricity vs munition). Range and weather-dependence are the structural constraints. Used operationally in increasing capacity through 2025-2026.

### Microwave / HPM

**Epirus Leonidas** — High-Power Microwave (HPM) system that disables drone electronics across a wide cone with a single emission. Effective against swarms (multiple drones in the beam path are all neutralized). US Army awarded IFPC-HPM prototype contracts from 2023 and a Generation II contract in 2025.

**Anduril Pulsar** — electronic-warfare suite integrated into the Lattice architecture.

**Wisp** (Anduril) — sensing layer used alongside Pulsar.

### Coyote and tube-launched interceptors

**Raytheon Coyote Block 2** — tube-launched, jet-propelled interceptor; deployed against drone swarms in Middle East and Red Sea operations through 2024-2026. Block 2 is a kinetic kill; Block 3 (in development) is a non-kinetic / electronic-warfare variant for reuse.

---

## XI. Real Incidents (selected)

### December 2018 — Gatwick Airport (UK)

The most-cited counter-UAS reference case despite significant evidential uncertainty. Beginning approximately 21:03 on 19 December 2018, a security officer reported drone sightings at Gatwick. The airport closed for 33-36 hours over a three-day window. Approximately 1,000 flights were cancelled or diverted; approximately 140,000 passengers were affected. Airlines lost an estimated GBP 50M. The UK military (RAF Regiment) deployed counter-UAS equipment.

Subsequent investigation: A Freedom of Information request in 2024 revealed that the NPAS (National Police Air Service) recorded no drone sightings at Gatwick across the disruption window. In September 2021, Brendan Schulman (former VP, Policy and Legal Affairs at DJI; then moving to Boston Dynamics) publicly stated that "it is now clear the Gatwick incident did not involve a drone." The investigation lasted 18 months, cost approximately GBP 800,000, and involved five police forces; no arrests were sustained.

The Gatwick episode remains the canonical airport-counter-UAS justification regardless of ground truth. The defensive procurement that followed — multi-sensor detection deployments at major UK and European airports — is real and ongoing.

### September 2019 — Saudi Aramco Abqaiq and Khurais (Saudi Arabia)

On 14 September 2019, a coordinated drone-and-cruise-missile strike hit Saudi Aramco's Abqaiq oil-processing facility and Khurais oilfield. Saudi authorities reported 25 drones / missiles used; satellite-imagery analysis identified 19 individual strikes (14 puncturing storage tanks, three disabling oil-processing trains, two missing equipment). Production was reduced by approximately 5.7 million barrels per day, equal to ~5% of global supply, for several days. The Houthi movement in Yemen claimed responsibility; US and Saudi attribution placed the attack as originating from Iran or Iran-aligned forces in Iraq, traveling from north / east directions. The cruise-missile components resembled Iranian Ya-Ali / Quds-1 designs.

The structural lesson: low-altitude approach, multi-direction ingress, swarm-confused-radar tactics defeated a multi-billion-dollar Saudi air-defense procurement. The Patriot batteries deployed against high-flying targets did not detect or engage. The Aramco strike is the canonical reference for "critical infrastructure is realistically vulnerable to small-drone-and-cruise-missile saturation attack."

### 2022-2026 — Ukraine war drone usage

The most expansive empirical data set on drone warfare in history. Selected reference points:

- **September 2022 onward** — Russia begins mass Shahed-136 deployment against Ukrainian energy infrastructure. Iran-supplied initially; Russian-localized production at Yelabuga subsequently.
- **2022-2024** — Ukrainian USV (Unmanned Surface Vessel) strikes against Russian Black Sea Fleet at Sevastopol (October 2022 onward); RFS Ivan Golubets damaged October 2022; submarine Rostov-on-Don damaged September 2023 by Storm Shadow / SCALP cruise missiles and later claimed destroyed; RFS Ivanovets sunk 1 February 2024; RFS Caesar Kunikov sunk in a night attack; RFS Sergey Kotov sunk 5 March 2024. The cumulative impact forced Russia to relocate elements of the Black Sea Fleet to Novorossiysk. RUSI commentary identifies this as the largest-scale operational use of unmanned surface platforms in naval-warfare history.
- **2023-2025** — Ukrainian FPV-drone production scales toward 2-3 million units per year. Casualty share attributed to drones rises from <10% at war start to ~80% by 2025.
- **February 2025** — Russian Shahed daily-launch average rises to ~140 per day; February 23, 2025 single-day record of 267 drones.
- **March 2026** — Russia launches 948 Shahed-type UAVs in a single 24-hour window (23-24 March 2026) — the highest-ever recorded single-day UAV deployment.

The Ukraine arc is the dominant empirical reference for future counter-UAS doctrine in any peer-or-near-peer conflict.

### May 2023 — Moscow Kremlin "drone strike"

On 3 May 2023, two small drones approached the Moscow Kremlin Senate Building and exploded above the dome. Russian authorities characterized the incident as a Ukrainian assassination attempt against President Putin. Ukrainian officials denied responsibility. The strike's symbolic and information-warfare impact significantly exceeded its kinetic impact. Whatever the actual operator, the incident established that small drones can reach high-value, deeply-guarded targets in capital cities.

### November 2024 — Northeast US drone sightings

In November-December 2024, repeated drone sightings were reported across New Jersey, New York, and adjacent states. Cumulative reports ran into the thousands. Federal response (FBI, FAA, DOD) characterized the sightings as a mix of lawful drone operations, manned-aircraft misidentifications, and unknown actors. No malicious actor was conclusively identified through early 2025. The episode produced legislative pressure to expand the counter-UAS authority under 6 USC 124n (DHS / DOJ) to state and local law enforcement; the SAFER SKIES Act in the FY2026 NDAA (signed December 2025) did so.

The structural lesson: counter-UAS detection and attribution at the public-safety level is hard, and the political pressure when sightings cluster is significant regardless of underlying threat.

### 2024-2026 — Red Sea and broader Middle East drone operations

Houthi anti-shipping drone operations against commercial vessels in the Red Sea (2023-2025), US Navy counter-UAS engagement with the Coyote Block 2 interceptor at sustained operational tempo, Iran-Israel direct drone-and-missile exchange in April 2024 and October 2024. The cumulative operational data set has informed US Navy procurement and Israeli counter-UAS doctrine substantially.

---

## XII. Detection and Monitoring for Organizations

### Corporate campuses, data centers, prisons, stadiums

The dominant non-military counter-UAS buyer segments:

- **Critical infrastructure** — energy (power generation, refineries, pipelines), water utilities, data centers. The threat model includes both surveillance (overflight imagery of facility layout, employee patterns) and direct attack (Aramco-style kinetic strike, payload-delivery EMP / RF disruption).
- **Prisons** — contraband-delivery drones are the dominant operational concern. Reports of drone-delivered contraband (drugs, phones, weapons) across US, UK, and Australian prison systems run to the hundreds annually.
- **Stadiums and large events** — privacy and disruption concerns; FAA Temporary Flight Restrictions (TFRs) over major events provide regulatory cover; counter-UAS deployments at Super Bowl, World Cup, Olympics venues are standard.
- **Airports** — Heathrow, Schiphol, Frankfurt, Newark have multi-sensor counter-UAS deployments post-Gatwick. The FAA Reauthorization Act of 2024 expanded the federal counter-UAS framework.
- **Corporate executive protection** — drone-delivered surveillance and reputational-risk scenarios against high-net-worth principals; deployments are growing but boutique.

### Law-enforcement coordination and US legal constraint

The defining US legal constraint: **47 USC 333** prohibits non-federal entities from jamming radio communications, and **6 USC 124n** (DOJ / DHS) with related statutes limits counter-UAS *defeat* authority to specific federal entities — DOJ (Federal Bureau of Prisons), DOD (military installations), DHS (specified components including Coast Guard, Secret Service, USSS at NSSEs), DOE (nuclear facilities), and FAA (limited). Since the SAFER SKIES Act (FY2026 NDAA, December 2025), trained and certified state, local, tribal, and territorial law enforcement can be authorized under 6 USC 124n to mitigate credible drone threats.

Practical implication for a corporate or critical-infrastructure security team: legal options for response are limited to *detection*, *attribution*, and *coordination with federal partners*. Defeat actions against an actively-flying drone — even one demonstrably hostile — are unlawful for the operator unless an exception applies. Detection investment can proceed independently; defeat investment requires federal partnership or a specific statutory exemption.

### DOJ counter-UAS authority

The DOJ Federal Bureau of Prisons received counter-UAS authority under the 2018 Preventing Emerging Threats Act for the protection of federal prisons. Subsequent DOJ guidance has expanded counter-UAS operational authority to specific national-security and witness-protection contexts. The 2024 Reauthorization Act conversation included proposals to extend defeat authority to state and local law enforcement under a federally-coordinated framework; the SAFER SKIES Act in the FY2026 NDAA (December 2025) enacted such an extension.

### Practical organization-side workflow

For a corporate / critical-infrastructure operator:

1. **Risk assessment first** — identify which drone classes pose realistic threats (surveillance overflight, contraband delivery, kinetic strike). Most non-government operators do not face a realistic kinetic-strike threat from drones; the detection-first investment is what matters.
2. **Detection deployment** — multi-sensor (radar + RF + EO/IR) for high-value sites. RF-only for medium-value sites. Visual-only / observed-monitoring for lower-value sites.
3. **Detection-to-incident-response wiring** — drone detections fire alerts into the corporate SOC, not into a separate stovepipe. Cross-link `detection_engineering_expertise.md` for the broader SOC-pipeline framework.
4. **Federal-partnership relationships** — pre-establish coordination paths with local FBI field offices, DHS regional security advisors, and FAA Drone Response Plan stakeholders before an incident occurs.
5. **Incident drills** — tabletop exercises that include drone-sighting scenarios; the muscle memory for "who do I call" matters more than the technology purchased.
6. **Physical hardening** — overhead net systems, hardened cabin / building roofs, anti-shrapnel measures on critical equipment. The "tortoise" approach to drone-as-weapon risk is cheaper than detection-plus-defeat in many configurations.

---

## XIII. Defensive Patterns

### Architectural principles

Five rules carry most of the defensive load:

1. **Treat drone RF links as untrusted broadcast media** — same trust model as ADS-B / ACARS / Remote ID. Cryptographic authentication and signing belongs at the link layer; deployments that disable signing for latency are a known-bad pattern.
2. **Assume GNSS will be denied or spoofed** — design for graceful degradation. IMU + visual SLAM + multi-constellation cross-check + OSNMA where supported. Skydio-class GPS-denied capability is now table stakes for serious operators.
3. **Apply standard firmware-supply-chain discipline to drones** — signed firmware, secure boot, SBOM, vendor incident-response posture, hardware root of trust. Cross-link `firmware_embedded_security.md` and `cicd_supply_chain_expertise.md`.
4. **Detection-first, defeat-second** — for non-federal operators, detection is what is legally and operationally available. Defeat is a federal capability or a federal-partnership capability.
5. **Plan for sustained operations under EW and counter-EW** — peer-conflict and near-peer-conflict environments are not edge cases. The Ukraine baseline is now the conservative assumption.

### Code review checklist for drone / counter-UAS systems

When reviewing code or systems in this domain, the following 12 checks cover the dominant attack patterns:

1. **MAVLink signing enforced** — MAVLink 2.0 message signing (48-bit SHA-256-based signature with a shared 32-byte key) enabled and required; reject unsigned messages. The "opt-in by default" trap kills systems.
2. **GCS authentication** — Ground Control Station authenticates to the vehicle with vehicle-specific credentials, not a fleet-wide shared key. Rotate per-vehicle.
3. **GNSS plausibility checks** — multi-constellation cross-check; reject inconsistent fixes; degrade to IMU on plausibility failure rather than trusting the spoofed fix.
4. **OSNMA validation** — when Galileo is in the GNSS mix, validate OSNMA. Receiver firmware support is still patchy; verify the deployed chain.
5. **Firmware signature verification** — signed firmware, signature-verifying secure boot. No "developer mode" bypass shipped to production.
6. **No hardcoded credentials** — AES keys, AWS credentials, signing keys must not appear in source, build artifacts, or shipped firmware images. The 2017 DJI exposure is the canonical anti-pattern (cross-link `cicd_supply_chain_expertise.md`).
7. **Cloud / telemetry isolation** — drone-to-cloud telemetry channels segregated from command channels; cloud compromise should not yield vehicle command authority.
8. **Companion app supply chain** — drone vendor mobile apps treated as enterprise mobile fleet; signed builds, app-store integrity verification, no debug builds in production.
9. **Remote ID compliance** — for regulated operations, Standard or Broadcast Module Remote ID present and functioning; for sensitive operations, awareness of the operator-location-disclosure consequence.
10. **Geofencing not relied on as security boundary** — DJI No-Fly Zones / geofences are operator-convenience features, not adversary-resistant defenses. Defense-in-depth at airports / sensitive sites still requires detection.
11. **Logging and tamper-evidence** — flight-log integrity for forensics and post-incident analysis. Logs sealed with hardware roots of trust where supported.
12. **EW / GPS-denial test plan** — operating fleet has documented behavior under GNSS jamming and GNSS spoofing; failure modes are characterized; safe-landing / return-to-home logic does not rely on the same compromised fix.

For counter-UAS systems specifically, the additional checks: (a) sensor-fusion confidence-scoring is visible to operators rather than hidden; (b) false-positive rates are measured against a representative bird / kite / balloon / aircraft data set, not just drone-positive data; (c) the defeat-action authorization workflow has a clear human-in-the-loop step where legally required; (d) RF-detection fingerprint libraries are versioned and reproducible; (e) integration with federal-partner notification (FBI, DHS) is automated, not manual; (f) post-incident evidence preservation (RF capture, video, radar tracks) is automatic, not on-demand.

### Tabletop exercises and red-team scenarios

The highest-leverage organizational investment is repeatable tabletop drills with concrete scenarios:

- **Drone sighting near data-center perimeter at 02:00** — who is the first responder; what is the detection-to-alert latency; who notifies federal partners; what is the evidence-preservation workflow.
- **Multiple-drone swarm sighting at executive event** — does the protective detail have authority to act; what does ground-team radio discipline look like; how does the venue's counter-UAS deployment interact with local PD.
- **Drone delivery into prison yard observed and captured** — chain-of-custody; forensic analysis of the drone (firmware imaging, RF-link analysis, operator-attribution); coordination with FBI on prosecution.
- **Counter-UAS detection failure during a live event** — false-negative root cause; sensor-lane confidence-scoring review; vendor escalation.

### Cross-domain bibliography for further reading

- `aviation_aerospace_security_expertise.md` — parent treatment; manned-aviation adjacent surfaces.
- `firmware_embedded_security.md` — embedded substrate; signing, secure boot, SBOM.
- `wireless_rf_satellite_security_expertise.md` — radio link, GNSS, SATCOM details.
- `adversarial_ml_model_security_expertise.md` — model attacks on terminal-homing CV and counter-UAS classifiers.
- `rtos_embedded_os_expertise.md` — NuttX, FreeRTOS, autopilot runtime.
- `detection_engineering_expertise.md` — SOC integration and alert pipeline.
- `automotive_security_expertise.md` — CAN-bus parallels in small-aircraft and ground-station avionics.
- `ics_ot_security_expertise.md` — critical-infrastructure threat-model overlay.

---

## XIV. References

### Foundational drone-security research

- Samy Kamkar, SkyJack: https://samy.pl/skyjack/
- SkyJack source code (GitHub): https://github.com/samyk/skyjack
- SkyJack Wikipedia entry: https://en.wikipedia.org/wiki/SkyJack
- Kevin Finisterre, "Why I Walked Away From $30,000 Of DJI Bounty Money" (PDF): https://regmedia.co.uk/2017/11/16/whyiwalkedfrom3k.pdf
- The Register on Finisterre / DJI keys: https://www.theregister.com/2017/11/16/dji_private_keys_left_github/
- PetaPixel coverage of Finisterre / DJI: https://petapixel.com/2017/11/20/man-finds-dji-customer-data-exposed-gets-threat-rejects-30k-bounty/
- CyberScoop, "DJI bug bounty program has turned into a PR nightmare": https://cyberscoop.com/dji-bug-bounty-drone-technology-sean-melia-kevin-finisterre/
- Nils Rodday, "Hacking a Professional Drone" (Black Hat Asia 2016, PDF): https://blackhat.com/docs/asia-16/materials/asia-16-Rodday-Hacking-A-Professional-Drone.pdf
- Black Hat Asia 2016 speaker page: https://www.blackhat.com/asia-16/speakers/Nils-Rodday.html
- The Register on Rodday: https://www.theregister.com/2016/04/01/hacker_reveals_40_attack_to_steal_28000_drones_from_2km_away/
- The Hacker News on Rodday: https://thehackernews.com/2016/04/hacking-drone.html
- "Behind The Wings: The Case of Reverse Engineering and Drone Hijacking in DJI Enhanced Wi-Fi Protocol" (arXiv 2023): https://arxiv.org/abs/2309.05913
- MAVSec paper (Allouch et al., 2019, arXiv): https://arxiv.org/pdf/1905.00265
- MAVSec IEEE: https://ieeexplore.ieee.org/document/8766667/
- Alias Robotics, "Cybersecurity status of PX4" (PDF): https://aliasrobotics.com/files/cybersecurity_status_PX4.pdf
- Pen Test Partners aerospace blog: https://www.pentestpartners.com/security-blog/events/def-con-30-aerospace-village/

### Regulatory and standards references

- FAA Remote ID landing page: https://www.faa.gov/uas/getting_started/remote_id
- 14 CFR Part 89 full text (eCFR): https://www.ecfr.gov/current/title-14/chapter-I/subchapter-F/part-89
- FAA Remote ID Final Rule (PDF, 2021): https://www.faa.gov/sites/faa.gov/files/2021-08/RemoteID_Final_Rule.pdf
- FAA Safety Team Remote ID guide (PDF, 2024): https://www.faasafety.gov/files/gslac/library/documents/2024/Dec/415588/3-RID-Remote_ID_Main_2024.pdf
- Rupprecht Law Remote ID summary: https://jrupprechtlaw.com/remote-identification/
- 47 USC 333 (radio communications interference): https://www.law.cornell.edu/uscode/text/47/333
- 49 USC 44810 (FAA airport safety and airspace hazard mitigation and enforcement): https://www.law.cornell.edu/uscode/text/49/44810

### Counter-UAS commercial products

- Anduril Counter-UAS overview: https://www.anduril.com/counter-uas
- Anduril Anvil: https://www.anduril.com/anvil
- Anduril Industries Wikipedia: https://en.wikipedia.org/wiki/Anduril_Industries
- US Army $20B contract award to Anduril (DefenseScoop, 2026): https://defensescoop.com/2026/03/14/anduril-20-billion-dollar-army-contract/
- US Army counter-drone task order (Breaking Defense, 2026): https://breakingdefense.com/2026/03/army-awards-anduril-counter-drone-task-order-as-first-in-new-20b-contract-vehicle/
- Marines / Anduril for base defense (DefenseScoop, 2025): https://defensescoop.com/2025/03/13/marine-corps-anduril-contract-defend-installations-small-uas-drones/
- StreetWise Reports on counter-drone market (2025): https://www.streetwisereports.com/article/2025/03/20/us-642m-defense-deal-signals-surging-demand-for-ai-counter-drone-tech.html
- DroneShield product line: https://www.droneshield.com/
- Dedrone (Axon, 2024+): https://www.dedrone.com/
- AeroDefense technical perspective on DJI AeroScope: https://blog.aerodefense.tech/dji-aeroscope
- DJI AeroScope product (legacy): https://www.dji.com/aeroscope

### Autonomous swarm research

- DARPA OFFSET program: https://www.darpa.mil/research/programs/offensive-swarm-enabled-tactics
- DARPA OFFSET final field experiment (2021): https://www.darpa.mil/news/2021/offset-swarms-take-flight
- DSIAC OFFSET overview: https://dsiac.dtic.mil/articles/darpa-offset-autonomous-drone-swarms-for-warfighters/
- DARPA OFFSET vision paper (ResearchGate): https://www.researchgate.net/publication/367321998_DARPA_OFFSET_A_Vision_for_Advanced_Swarm_Systems_through_Agile_Technology_Development_and_Experimentation
- Overt Defense on OFFSET final test: https://www.overtdefense.com/2021/12/16/darpa-runs-final-test-for-offset-program-drone-swarm/

### Skydio and GPS-denied autonomy

- Skydio Autonomy overview: https://www.skydio.com/skydio-autonomy
- Skydio X10D for defense: https://www.skydio.com/blog/skydio-x10d-the-suas-for-defense-and-government-agencies
- Skydio X10: https://www.skydio.com/x10
- Skydio main site: https://www.skydio.com/

### Real incidents

- Gatwick Airport drone incident (Wikipedia): https://en.wikipedia.org/wiki/Gatwick_Airport_drone_incident
- Robin Radar, "Lessons from Gatwick": https://www.robinradar.com/blog/lessons-from-the-gatwick-airport-drone-incident
- Dedrone on Gatwick: https://www.dedrone.com/blog/gatwick-airport-drone-incident-shut-down-from-deliberate-drone-disruption
- Airprox Reality Check Gatwick analysis: https://www.airproxrealitycheck.org/gatwick2018/
- Abqaiq-Khurais attack (Wikipedia): https://en.wikipedia.org/wiki/Abqaiq%E2%80%93Khurais_attack
- NPR on Abqaiq: https://www.npr.org/2019/09/19/762065119/what-we-know-about-the-attack-on-saudi-oil-facilities
- Defense Update on Abqaiq missile analysis: https://defense-update.com/20190914_aramco_attack.html
- HESA Shahed 136 (Wikipedia): https://en.wikipedia.org/wiki/HESA_Shahed_136
- Institute for Science and International Security monthly Shahed deployment reports: https://isis-online.org/isis-reports/monthly-analysis-of-russian-shahed-136-deployment-against-ukraine
- ISIS 2025 comprehensive review: https://isis-online.org/isis-reports/a-comprehensive-analytical-review-of-russian-shahed-type-uavs-deployment-against-ukraine-in-2025
- Drone Warfare research on Shahed-136 economics: https://drone-warfare.com/research/shahed-136/
- CTC West Point on drone terrorism evolution: https://ctc.westpoint.edu/on-the-horizon-the-ukraine-war-and-the-evolving-threat-of-drone-terrorism/
- Hudson Institute on Ukraine drone lessons: https://www.hudson.org/missile-defense/impact-drones-battlefield-lessons-russian-ukraine-war-french-perspective-tsiporah-fried
- Navy Lookout on Black Sea drone warfare: https://www.navylookout.com/black-sea-battle-how-ukraines-drones-overpowered-the-russian-navy/
- TWZ on Ukrainian underwater drone attack: https://www.twz.com/sea/ukraine-claims-worlds-first-underwater-drone-attack-on-russian-submarine
- RUSI on uncrewed platforms in the Black Sea: https://www.rusi.org/explore-our-research/publications/commentary/uncrewed-platforms-have-been-critical-ukraines-success-black-sea
- Covert Shores Black Sea timeline: https://www.hisutton.com/Timeline-2022-Ukraine-Invasion-At-Sea.html

### MAVLink / autopilot CVEs

- CVE-2020-10282 (MAVLink no authentication) RVD reference: https://github.com/aliasrobotics/RVD/issues/3316
- CVE-2026-1579 PX4 RCE (Security Arsenal): https://securityarsenal.com/blog/cve-2026-1579-px4-autopilot-remote-command-execution-detection-and-hardening-guide
- GBHackers on PX4 critical vulnerability: https://gbhackers.com/critical-px4-autopilot-vulnerability/
- PX4 / Dronecode CVE listing: https://app.opencve.io/cve/?product=px4_drone_autopilot&vendor=dronecode

### Community and ongoing references

- DEF CON Aerospace Village: https://www.aerospacevillage.org/
- ArduPilot project: https://ardupilot.org/
- PX4 Autopilot project: https://px4.io/
- Pixhawk Open Hardware Foundation: https://pixhawk.org/
- Dronecode Foundation: https://www.dronecode.org/
- ExpressLRS project: https://www.expresslrs.org/
- OpenSky Network (ADS-B): https://opensky-network.org/
- FAA Drone Zone: https://faadronezone.faa.gov/
