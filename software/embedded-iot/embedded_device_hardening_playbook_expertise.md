# Embedded Device Hardening — Operations Playbook

Audience: the security or device-engineering lead at an organization shipping embedded products — consumer IoT, industrial sensors, medical devices, automotive ECUs, OT/ICS field gear, building-automation controllers. This is an operations playbook. It tells you what to instrument, what to disclose, what to patch, what to retire. It is the sibling of `[[reference-rtos-embedded-os]]`, which catalogs the OS-and-stack attack surface. This doc covers what the operations team does week to week so that catalog stays survivable in the field.

Register: imperative. The reader has 10M shipped devices and an inbound bug report.

---

## 1. Why this playbook is distinct from `[[reference-rtos-embedded-os]]`

`[[reference-rtos-embedded-os]]` is a reference catalog. It enumerates the kernels you might ship on (Zephyr, FreeRTOS, RT-Thread, mbedOS, NuttX, VxWorks, QNX, ThreadX), the TCP/IP-stack vulnerability corpus (Ripple20, URGENT/11, INFRA:HALT, AMNESIA:33, NAME:WRECK, NUMBER:JACK, BadAlloc — collectively Forescout's Project Memoria), and the in-kernel defenses (MPU regions, TrustZone-M, ARMv8-M secure-state partitioning). It answers: "what attacks exist against the OS and stack on this device?"

This playbook answers a different question: "how does the operations team build resilience around a fleet of devices that ships and stays in the field for five to fifteen years?" It is OS-agnostic. It is supplier-agnostic. It assumes you have already chosen a kernel and a BSP — `[[reference-rtos-embedded-os]]` and `[[reference-firmware-embedded-security]]` cover those choices. Here we cover what the org does once a device is in customer hands.

The distinction is not academic. Mirai (2016) was not an RTOS bug. Mirai was an operations failure: factory-default credentials, no update channel, no telemetry, no decommissioning policy. Krebs's writeup at `krebsonsecurity.com/2016/10/source-code-for-iot-botnet-mirai-released/` and Symantec's October 2016 analysis both attribute the 600 Gbps DDoS — and the subsequent 1.2 Tbps Dyn attack — to operational primitives that this playbook is designed to prevent: default passwords on Telnet ports, no firmware-update mechanism, devices on the public internet without segmentation. The vulnerabilities were ordinary. The operations were absent.

VPNFilter (Cisco Talos, May 2018, `blog.talosintelligence.com/vpnfilter`) tells the same story from the state-actor side. Sandworm achieved persistence on 500,000+ SOHO routers (Linksys, MikroTik, Netgear, TP-Link, QNAP) by exploiting old CVEs against devices that had no update channel and no telemetry-back-to-vendor. The kernel was incidental. The operations gap was the vulnerability.

If you are reading this doc, your job is to close the operations gap.

---

## 2. The 5-stage embedded device lifecycle

Frame your operations program around five phases. Each has an owner, a small set of KPIs, and a characteristic failure mode.

### Phase 1 — Design and threat modeling

**Owner:** product security lead, with device-engineering and product-management sign-off.

**Inputs:** product spec, BoM (bill of materials), intended deployment environment, regulatory regime (CRA, FDA, UNECE R155, NERC CIP — see §10).

**Method:** STRIDE for component-level decomposition; PASTA when you need attacker-centric modeling against a specific adversary class. For embedded specifically, add four threat shapes that desktop threat models routinely miss:
- **Physical access.** Assume the attacker has the device on a bench with logic analyzer and JTAG probe. Anything that survives this is a feature, not a bug.
- **JTAG / SWD / UART debug headers.** Default to disabled-in-production. If you must leave them for field RMA, gate behind a per-device challenge-response unlock (do not ship a master debug key).
- **Supply-chain weight for binary blobs.** Cellular modem firmware, Wi-Fi firmware, GPU drivers — these ship as opaque blobs from the silicon vendor. They are part of your TCB whether or not you audit them.
- **Backend-trust collapse.** If the cloud backend is compromised, what can it do to the device? The Ring 2019 incident (Motherboard reporting, Dec 2019) showed that credential-stuffed accounts gave attackers live audio and video on residential cameras; the device trusted the backend implicitly.

**KPI:** threat model is reviewed quarterly and out-of-cycle when the device gains a new capability (a new sensor, a new network protocol, a new cloud integration).

**Failure mode:** threat model is authored once at v1.0 and never revisited. The v1.5 firmware adds BLE provisioning, nobody updates the model, and the BLE pairing flow ships without a threat analysis.

### Phase 2 — Provisioning and secure-boot chain-of-trust

**Owner:** silicon / hardware-security lead, with HSM custody policy from the IT security team.

**Method:** see `[[reference-firmware-embedded-security]]` for the bootloader and secure-boot deep dive. Operations responsibilities at this phase:
- **Root key custody.** The signing key for the bootloader root-of-trust lives in an HSM (Thales Luna, AWS CloudHSM, YubiHSM, NXP EdgeLock). Documented two-person access. Never on a laptop.
- **Key-ladder design.** Root key signs intermediate keys; intermediates sign application keys. Rotate the application key annually; rotate intermediate every 3-5 years; rotate root only on compromise (it requires a manufacturing change).
- **Anti-rollback fuse policy.** Once a firmware version with a security fix has been deployed and validated in the field, burn the anti-rollback fuse such that older firmware cannot run. Be conservative: burn fuses only after telemetry confirms the new version is stable across the fleet (see §4).
- **Per-device identity.** Each device gets a unique identity (device certificate, PKI, ECC P-256 keypair typical) provisioned at manufacturing. Burned to OTP or stored in a secure element (NXP A1006/SE050, Microchip ATECC608, Infineon OPTIGA Trust M, ST STSAFE-A110).

**KPI:** zero devices ship with shared identity material. Provisioning yield is tracked.

**Failure mode:** the vendor ships a single hardcoded device key across a product line. The 2017 ESP32 secure-boot bypass and the 2020 NXP LPC55S69 fault-injection key-leak are reference incidents.

### Phase 3 — Deployment and telemetry-from-the-field

**Owner:** platform / observability team, with privacy-engineering review.

**Method:** see §3 for what to instrument. Operations responsibilities:
- Telemetry ingestion sized for fleet size. 10M devices reporting once per hour at 1 KB per beacon is 240 GB/day raw; budget for it.
- Aggregation before identification. The default report should be "1.2% of N. America-region devices failed boot integrity this hour" not "device serial 00:0a:95:9d:68:16 failed boot integrity."
- Privacy budget. What the device reports must be enumerable and reviewable by a privacy engineer. GDPR Art 25 (privacy by design), CCPA, the California IoT law SB-327 (default passwords), and the 2024 EU CRA all converge on this.

**KPI:** telemetry coverage rate (% of fleet that has reported in the last 7 days). Privacy review of the telemetry schema is on file and dated.

**Failure mode:** telemetry was set up by the analytics team for engagement metrics ("which channel does the user watch most"), then re-used by security. The privacy budget collapses. See §3.

### Phase 4 — In-life monitoring and incident response

**Owner:** SOC / detection-engineering team, with product-security on call.

See §3 (what to monitor) and §8 (how to handle a fleet incident). KPI: mean-time-to-detect (MTTD) and mean-time-to-contain (MTTC) for fleet-wide anomalies; tabletop exercise frequency.

**Failure mode:** telemetry is collected but never alerted on; the first you hear of the compromise is Brian Krebs emailing your PR team.

### Phase 5 — End-of-life and decommissioning

**Owner:** product management, with security-program sign-off.

See §9. KPI: documented minimum supported lifetime (EU CRA requires "expected product lifetime, with a minimum of 5 years" in most cases); customer notification 12+ months pre-EOL.

**Failure mode:** the product is quietly abandoned. Devices keep running, with vulnerable firmware, indefinitely. This is the Mozi-botnet substrate.

---

## 3. Monitoring and telemetry — what to instrument

The fleet is your detection surface. Telemetry is the only way to discover a fleet-wide compromise short of an external party telling you. Instrument the following classes. Cross-link `[[reference-detection-engineering]]` §10 for the runtime-detection rule corpus and Sigma/KQL/SPL shapes.

### 3.1 Boot integrity

Every boot produces a measured-boot record: hash of bootloader, hash of OS image, hash of root filesystem (or equivalent for your platform). The device reports this measurement to a trusted attestation service on first network attach.

- **What to alert on:** measurement does not match any signed-and-current firmware version. Cross-link `[[reference-firmware-embedded-security]]` for the secure-boot mechanism that produces the measurement.
- **Reference primitives:** TPM 2.0 PCRs (for capable platforms), ARM TrustZone-M secure-state attestation, vendor-specific (NXP EdgeLock 2GO, STM32 RoT services).

### 3.2 Runtime integrity

Inside the running kernel:
- Control-flow integrity (CFI) violations — on platforms with ARM PAC + BTI or RISC-V Zicfilp/Zicfiss, every violation produces a fault.
- MPU region faults — repeated faults in the same task are a tell for memory-corruption attempts.
- Watchdog resets per device — outlier devices with high reset rates correlate with exploit attempts.
- Kernel panic / oops counters and last-panic backtrace.

See `[[reference-rtos-embedded-os]]` for the per-RTOS surfaces that produce these signals (Zephyr `CONFIG_HW_STACK_PROTECTION`, FreeRTOS `configRECORD_STACK_HIGH_ADDRESS`, etc.).

### 3.3 Network anomalies

- Outbound connections to non-allowlisted domains. Your device has a known set of backend endpoints; anything else is suspicious.
- DNS to unusual TLDs, dynamic-DNS providers, freshly-registered domains. The Mirai DGA traffic, the VPNFilter C2 lookups, and the Mozi `dht.transmissionbt.com` bootstrap node were all observable here.
- TLS certificate-pinning failures. A spike across many devices is a routing or DPI event; from a single device it may be a SOHO MITM or a compromised firmware image.
- Connections to RFC 1918 ranges from devices that should only talk to the backend.

### 3.4 Authentication anomalies

- Failed-auth rate per device, with geographic and time-of-day baselines.
- Credential-stuffing patterns at the backend (the Ring 2019 case is canonical here): rapid successful logins from many IPs against a stable subset of accounts.
- Unusual successful logins from new geographies for a device that has been geographically stable.

### 3.5 Privacy guardrails

Telemetry is a liability surface. The default rule: only emit data that is necessary for security or operational health, and aggregate before exfiltrating.

In scope:
- Boot success / failure counts.
- Software version distribution.
- Crash counts and backtraces (with PC + LR; redact stack contents).
- Network anomaly counts (not destinations from a single device — destinations in aggregate).
- Authentication failure counts.

Out of scope by default:
- Which features the user used, when, and for how long.
- Sensor data tied to a device identity.
- Per-user identifiers in security telemetry (use opaque, rotating device IDs).

Regulatory anchors: GDPR Art 5 (data minimization), Art 25 (privacy by design); CCPA §1798.140; California SB-327 (mandates reasonable security features for connected devices sold in CA); EU CRA Annex I §1 essential requirements include data minimization.

---

## 4. Firmware-update discipline

This is the most operationally important section. A shipped device without a working update channel is a 5-to-15-year liability. A shipped device with a broken update channel is worse — devices get bricked, customers lose trust, and the next update has to overcome that history.

### 4.1 Update-channel software

Pick one and standardize:
- **Mender** (`mender.io`) — A/B partition updates, robust delivery infrastructure, common on industrial Linux.
- **RAUC** (`rauc.io`) — A/B and rootfs updates, common on automotive Linux and industrial gateways.
- **swupdate** (`sbabic.github.io/swupdate`) — image and incremental updates, BSD-style packaging.
- **SWUpdate** + **hawkBit** for management plane (the Eclipse Foundation stack).
- **ESP-IDF OTA** for ESP32 devices; **Zephyr MCUboot** for Zephyr / nRF / STM32 microcontrollers.
- Vendor proprietary — Tesla, Apple (over the years), most automotive Tier 1s; only justify proprietary if your scale demands it.

### 4.2 A/B dual-bank with anti-rollback

Two partitions; the running image lives in one, the new image is written to the other and booted. If the boot fails or the application fails to check in within a watchdog window, the bootloader reverts to the previous slot. This is the only sane operational design for unattended devices.

Anti-rollback fuse policy: burn the fuse for a specific version only after telemetry confirms it is stable. This prevents an attacker with code-execution from downgrading to an older signed image with a known exploit. The classic case is the iOS SHSH-blob downgrade attack era (2011-2014); Apple eventually moved to enforce anti-rollback in hardware.

### 4.3 Update-payload signing

The update is a signed package. Operational requirements:
- **Algorithm.** Ed25519 for new designs on resource-constrained MCUs (32 bytes signature, fast verify, no parameter footguns). RSA-PSS-2048 if you must interoperate with PKCS#11 HSMs that don't support Ed25519. Avoid RSA-PKCS#1 v1.5 for new designs; the 2023 Bleichenbacher-style attacks on padding-oracle implementations and the 2024 "Marvin attack" (NIST PQC-related disclosures) are sufficient reason.
- **Root key in HSM** (see §2 Phase 2).
- **Key rotation plan.** Document the cadence and the rollover procedure. The plan exists before you ship v1.0.
- **Defense in depth.** The bootloader verifies the bundle signature; the OS verifies individual file hashes after unpack. Independent code paths.

### 4.4 Delivery infrastructure

- **CDN-fronted** for typical consumer / commercial scale. Sign the bundle; the CDN does not need a trust relationship.
- **P2P (BitTorrent-style)** for very large fleets or constrained backhaul. Tesla and Mozilla (for Firefox at one point) have used this; the bundle signature is what makes it safe.
- **Local-network propagation** — devices on a LAN can share an update bundle with each other after the first device fetches and verifies. Common in industrial deployments behind constrained uplinks.
- **Bandwidth shaping** — do not push a 200 MB update to 10M devices in the same minute. Phased rollout (see §4.5) handles this naturally.

### 4.5 Phased rollout

- **1% canary** for 24-72 hours. Devices selected pseudo-randomly across geographies and hardware revisions. Telemetry: boot success rate, crash rate, watchdog reset rate, network anomaly rate, customer-support ticket rate.
- **10% stage** for 3-7 days. Confirm canary signal holds.
- **100% GA** after stage clears.
- **Rollback triggers** are explicit, automated, and the operator on call can pull the rollout without escalation:
  - Boot-success-rate drop below threshold.
  - Crash-rate spike above baseline.
  - Customer-support ticket-rate spike.
  - SOC alert.

### 4.6 When an update bricks devices

The procedure exists in writing before it happens.
- **Immediate halt** on the rollout (canary or stage gate).
- **Telemetry triage** — what is the failure signature? Boot-loop? Network detach? Single sub-population (one hardware rev, one regional firmware variant)?
- **Hot-fix push** — if A/B revert succeeded, the fleet is mostly OK and you push a corrected update. If revert is also failing, you have a deeper problem.
- **RMA path** — for bricks that revert cannot recover from, document the RMA process before the rollout begins. The Tesla 2023 OTA recall (FMVSS Part 573 notice) is a reference case.
- **Customer communication** — proactive. Within 48 hours. Acknowledge, describe scope, give an ETA. The 2024 Ring "factory reset" incident (where a buggy update reset device configurations) escalated because Amazon initially under-communicated.

### 4.7 Update-cadence policy

Document and publish:
- **Security patches** monthly at minimum; out-of-cycle within 30 days of an actively-exploited CVE in your BoM.
- **Feature updates** quarterly or as the product roadmap dictates.
- **LTS branches** for B2B / industrial / medical / automotive where customers need a slow track. Two or three concurrent LTS branches is typical; more becomes unmanageable.

---

## 5. Vulnerability-disclosure coordination — the inbound side

A researcher has found a bug in your device. The operations of receiving, triaging, and acting on that report are a measurable property of your security program.

### 5.1 Make it easy to report

- **`SECURITY.md` in the public repo** if your firmware is open or partially open.
- **`security.txt`** at `https://yourproduct.example.com/.well-known/security.txt` per RFC 9116. Include `Contact:`, `Encryption:` (PGP key URL), `Policy:` (link to disclosure policy), `Acknowledgments:`, `Preferred-Languages:`, `Expires:`. The `Expires:` field is mandatory — refresh annually.
- **Published security email alias** — `security@yourproduct.example.com` — monitored, ticketed, SLA'd.
- **Bug bounty or VDP** on HackerOne, Bugcrowd, or Intigriti. For embedded specifically: a VDP (vulnerability-disclosure program) without payouts is the minimum bar; a bounty signals seriousness and pulls higher-quality reports. Disclose Pwn2Own participation if applicable.

### 5.2 The first 24 hours

- Auto-acknowledge within 1 hour (template OK, but include a human contact).
- Human triage and confirmation of reproduction within 24-72 hours.
- If you cannot reproduce, ask the researcher for more data — do not close. Reproduction failure on the vendor side is common and is not the researcher's bug.
- Assign an internal tracking ID. Share it with the reporter.

### 5.3 SLA expectations

Industry norms (Project Zero's 90-day disclosure window is the gravitational anchor):
- **First response:** within 24 hours.
- **Triage / reproduce / severity:** within 7 calendar days.
- **Fix in shipping firmware:** 90 days typical for consumer; 120-180 days for industrial / medical where validation cycles are longer; document the timeline in your published policy.
- **Public disclosure:** at the earlier of (a) 90 days from initial report or (b) the date the fix ships to the field, with the researcher consulted on the embargo.

### 5.4 Coordinated disclosure via CERT/CC

For multi-vendor CVEs (your firmware uses Treck, Treck is used by 50 others) the right mechanism is the **VINCE** platform at `kb.cert.org/vince/`, run by CERT/CC at Carnegie Mellon SEI. VINCE handles the multi-vendor coordination, the embargo, and the publication. Be a participating vendor — register and respond to VINCE cases promptly.

The reference case is Ripple20 (JSOF, June 2020): 19 CVEs in the Treck TCP/IP stack, used in hundreds of millions of devices across Schneider Electric, Caterpillar, Rockwell, HP, and many others. CERT/CC coordinated the multi-vendor disclosure (`kb.cert.org/vuls/id/257161`). URGENT/11 (Armis, July 2019, `armis.com/research/urgent11/`) followed the same playbook for VxWorks IPnet: 11 CVEs across the install base.

### 5.5 Should you become a CNA?

Pro: you can assign CVE IDs without going through MITRE / CISA. Faster, more controlled, you can pre-allocate.

Con: you take on responsibility for following CNA rules, publishing in a structured way, and being responsive to MITRE / CISA.

Threshold: if you publish more than 5-10 CVEs/year in your own products, become a CNA. Below that, use MITRE's CVE Request form (`cveform.mitre.org`) or your platform CNA (HackerOne and Bugcrowd both have CNA status).

### 5.6 OT:ICEFALL and the multi-vendor pattern

Forescout's OT:ICEFALL disclosure (June 2022, `forescout.com/research-labs/icefall/`) covered 56 vulnerabilities across 10 OT vendors (Honeywell, Motorola, Omron, Siemens, Emerson, JTEKT, Bentley Nevada, Yokogawa, Phoenix Contact, Schneider). The category was "insecure-by-design" — protocols that were never designed for authentication. The coordination playbook here is unusual: where there is no fix, there is no embargo. The disclosure was about visibility for asset owners, not a fix. Operations implication: if your supplier disclosure path receives an "insecure by design" report, the answer is a compensating-controls advisory, not a firmware fix.

### 5.7 Anti-patterns

- Ignoring the report.
- Threatening the reporter with the CFAA or DMCA §1201.
- Claiming you "don't have a security team."
- Pushing the disclosure date past the researcher's stated embargo.
- Silently fixing without crediting and without publishing a CVE.

Every one of these has produced a public researcher writeup that did more reputational damage than the bug would have. Operate the inbound channel the way you would want a peer vendor to operate it.

---

## 6. Vulnerability-disclosure coordination — the outbound side

Your device has a vuln in a supplier's component. The operations of receiving an upstream advisory and getting a fix into your shipping firmware.

### 6.1 Tracking upstream advisories

- Maintain a CVE feed subscription for every component in your SBOM (§7). NVD JSON feeds, GitHub Security Advisories, vendor-specific feeds (NXP PSIRT, ST PSIRT, Microchip PSIRT, Intel PSIRT, Qualcomm PSIRT, etc.). Use a tool — Dependency-Track (`dependencytrack.org`), or commercial equivalents (Snyk, JFrog Xray, Anchore, Sonatype).
- Triage cadence: at least weekly review of new advisories against your SBOM. Triage classification:
  - **Critical exploitable** — fix in the next monthly cadence at the latest.
  - **High but not directly exploitable in your build** — issue a VEX statement (§7.2) and patch on normal cadence.
  - **Low / informational** — patch on routine LTS cycle.

### 6.2 Embargoed-disclosure participation

To be invited to vendor embargo lists (often TLP:AMBER under the Traffic Light Protocol from FIRST.org), demonstrate operational seriousness:
- Designated security contact, single point of email and phone.
- NDA on file with the supplier.
- Track record of acting on advisories without leaking.
- Coordinated disclosure history through your CNA or platform.

Operational implication: embargo means you know about a bug before the public does. Your patching pipeline must accommodate confidential fixes that ship without a public commit message until the embargo lifts. The standard practice is a feature flag or a generically-named fix commit; the corresponding CVE-citing changelog ships at embargo-lift.

### 6.3 Backporting

Upstream fixes a bug in `kernel 6.6`. You ship `kernel 5.10 LTS`. The fix needs to be backported.
- Subscribe to the LTS branch maintainer's advisories.
- Have an in-house engineer competent in upstream + your fork.
- Do not freelance the backport — apply the upstream patch, test against your fleet image, run the regression suite.
- Contribute the backport to the LTS maintainer if appropriate; this is how you offload future maintenance.

### 6.4 Supplier coordination

For every Tier 1 supplier, document:
- IR contact (name, email, phone).
- NDA expiry.
- Joint-disclosure terms (who publishes what, when).
- SLA the supplier owes you on critical advisories.

When you discover a bug in their component, follow §5 in reverse: contact, reproduce, embargo, fix, disclose. Be the kind of customer you want to receive reports from.

---

## 7. Supply-chain hardening for embedded

Cross-link `[[reference-supply-chain-provenance]]` for the SLSA / sigstore / in-toto reference. Operational specifics for embedded:

### 7.1 SBOM generation

- Generate on every build, not as an after-the-fact compliance artifact.
- Format: **CycloneDX 1.6** (richer ecosystem support) or **SPDX 2.3 / 3.0** (broader regulatory acceptance). EU CRA and the FDA Premarket Cybersecurity Guidance both accept either.
- Include every component, not just first-party: bootloader, OS, libraries, firmware blobs from silicon vendors, fonts, certificates.
- Sign the SBOM (in-toto attestation or cosign).
- Publish alongside the firmware (`firmware-1.2.3.bin`, `firmware-1.2.3.cdx.json`, `firmware-1.2.3.cdx.json.sig`).

Tools: `syft` (Anchore), `cyclonedx-cli`, vendor-specific (Yocto's `create-spdx.bbclass`, Buildroot's `BR2_LEGAL_INFO=y`).

### 7.2 VEX

The Vulnerability Exploitability eXchange format lets you publish "CVE-XXXX-YYYY is in our SBOM but is NOT exploitable in our build configuration because we disabled feature Z." This is operationally essential for embedded — your scanner finds 200 CVEs against your fleet image, and 180 are false positives because you compiled out the affected code paths. CycloneDX 1.6 includes VEX natively; the OpenVEX standard (`openvex.dev`) is an alternative.

Discipline: every VEX statement names the build configuration, the rationale, and the person on the security team who signed off. VEX-by-default is a regulator's red flag.

### 7.3 Firmware reproducibility

Bit-identical builds from clean source, by a different builder, on a different day. The Debian Reproducible Builds project (`reproducible-builds.org`) is the reference; the discipline transfers to embedded with some friction (timestamps in headers, randomized build paths, locale-dependent string sorting). Yocto and Buildroot both support reproducible-builds workflows; allocate engineering time to actually achieve it.

Why it matters operationally: a reproducible build lets a third party (security researcher, regulator, downstream integrator) verify that the firmware blob you shipped corresponds to the source you published. It is the foundation of every supply-chain transparency claim.

### 7.4 Build-pipeline hardening

Aim for **SLSA Level 2** as a baseline, **SLSA Level 3** for products in regulated verticals. See `[[reference-supply-chain-provenance]]` for the SLSA ladder in detail.

Operational requirements:
- Hermetic builds — no network access during compile.
- Ephemeral builders — fresh VM or container per build, destroyed afterward.
- Build provenance attestation — in-toto attestation signed by the build system.
- Build environment in source control — Dockerfiles, Yocto layers, Buildroot config, signed.

GitHub Actions Artifact Attestations and Sigstore's `cosign` give you most of this for free with modest setup. The 2024 SolarWinds-era guidance from CISA (Software Bill of Materials and Software Supply Chain Security guidance) is the regulatory anchor.

### 7.5 JTAG / SWD / UART debug headers

Default policy: disable in production. Mechanisms:
- ARM Cortex-M: read DBGMCU registers; on STM32 use `RDP Level 2` (irreversible after first deployment).
- NXP / Microchip: secure-debug authentication where supported.
- ESP32: efuse `JTAG_DISABLE` and `DOWNLOAD_DIS_TWO_STEP_BOOT`.

If field-debug is required: per-device challenge-response, gated by a server-side authorization, not a master key burned into the silicon vendor's HSM that an internal employee can walk off with.

### 7.6 Counterfeit-component detection

Supply-chain attacks at the silicon level are real (the Bloomberg "Big Hack" 2018 story is disputed; Operation Trojan Shield 2021 is not). Operational primitives:
- Authenticated components — silicon with on-die provisioned identity (NXP A1006, Microchip ATECC, Infineon OPTIGA) where you verify identity at first boot.
- Receiving inspection — incoming-goods sampling against a verified golden sample, XRF or decapsulation for high-risk lines.
- Trusted distribution — buy directly from the silicon vendor or from a small set of authorized distributors (Avnet, Arrow, Future, Mouser, Digi-Key for low-volume).

---

## 8. In-life IR — how the SOC handles a fleet incident

You have 10M devices in the field. Telemetry is alerting. Procedure:

### 8.1 Detection

Telemetry pipeline (§3) feeds a SIEM (Splunk, Elastic, Sumo, Sentinel, Chronicle). Detection rules from `[[reference-detection-engineering]]` §10 fire on the anomaly classes in §3.

### 8.2 Triage — single-device vs fleet-wide

The single most important early decision. Differentiating signals:
- Single device: anomaly is geographically localized, tied to a single account, no propagation.
- Fleet-wide: anomaly is broadly distributed, time-correlated, hardware-revision-agnostic (or revision-specific in a way that maps to a known vulnerability).

The Mirai 2016 telemetry signature would have been: rapid increase in outbound SYN to port 23 across many devices, geographically uncorrelated, time-correlated to the worm propagation. If you had had telemetry, you would have caught it.

### 8.3 Containment

Three levers, deployable in this order of speed:
- **Backend rate-limiting / blocking** — at the cloud, throttle or block the malicious traffic pattern. Minutes to deploy. Doesn't fix the device.
- **Certificate revocation** — revoke per-device certs at the CA. The device cannot authenticate to the backend. Minutes to hours to propagate.
- **Kill-switch firmware push** — a firmware update that disables the compromised functionality or pulls the device back to a known-good state. Hours to days to land (depends on phased-rollout discipline; an emergency push can skip stages).

### 8.4 Eradication

Push the fix update. Track deployment rate over 7-30 days; some devices will be offline. Maintain the containment levers (cert revocation, backend filtering) until deployment rate is acceptable.

### 8.5 Recovery

Restore normal backend operations. Communicate to customers — what happened, what they need to do (often nothing if you handled it well), what you changed to prevent recurrence.

### 8.6 Postmortem

Blameless. Internal first; published-summary version within 90 days of incident close. Examples to model on: Cloudflare incident postmortems, Honeycomb's writing, the Apple iOS security writeups that have appeared at Black Hat and BlueHat. CVE assignment (if not already done during disclosure coordination).

---

## 9. End-of-life and decommissioning

### 9.1 Supported-lifetime policy

Documented before launch. Minimums:
- **EU CRA** — "expected product lifetime" with a minimum of 5 years for consumer products entering the EU market after Dec 2027.
- **FDA medical device** — for the device's intended service life, often 7-15 years. The 2025 FDA Premarket Cybersecurity Guidance (final document, "Cybersecurity in Medical Devices: Quality System Considerations and Content of Premarket Submissions," FDA-2018-D-3443) makes this an explicit pre-market submission requirement.
- **Automotive** — UNECE R155 and R156 effectively require lifetime updates; OEMs commit to 10-15 years.
- **Industrial / OT** — often 15-25 years of operational life; the vendor must commit to security maintenance for at least 10 of those.

### 9.2 EOL signal-out

What does the device do once it is past EOL? Tradeoffs:
- **Cease accepting updates** — easy; risks customers running vulnerable firmware indefinitely.
- **Refuse to connect to backend** — bricks the product, customer outrage.
- **Display banner / LED indicator** — Apple's approach on old iPhones; user-visible without bricking.
- **Reduced-functionality mode** — degrade gracefully (e.g. local-only operation, cloud features off).

Document the policy in the product spec. The 2022 Insteon shutdown (cloud went dark with hours of notice) is a worst-case reference; Sonos's handling of legacy speakers (degraded mode, eventual EOL trade-in program) is a better case.

### 9.3 Cloud-backend decommissioning

- Certificate chain — when does the backend cert chain expire? Plan rotation past the device fleet's life.
- Telemetry pipeline — what runs the analytics on a fleet of 100K devices ten years post-launch?
- Customer data — GDPR and CCPA require deletion on EOL where applicable; document the retention schedule.
- Open-source contribution — if you EOL the product, consider open-sourcing the firmware so the community can keep it alive. The HP LaserJet community and the Synology DSM jailbreak scene are precedents.

### 9.4 Customer notification

Minimum 12 months pre-EOL for consumer products (FTC fairness guidelines and various state consumer-protection laws). For B2B and industrial, the contract specifies; commonly 24-36 months. The notification:
- Names the date.
- Names what will and will not work post-EOL.
- Offers a trade-in or migration path if available.
- Lists final firmware version with all known fixes.

---

## 10. Regulatory landscape (2026 H1)

Operations implications by jurisdiction and vertical.

### 10.1 EU Cyber Resilience Act — Regulation (EU) 2024/2847

Entered into force December 10, 2024. Substantive obligations apply from December 11, 2027. Manufacturer reporting obligations apply from September 11, 2026.

Operational must-knows:
- **24-hour reporting** to ENISA of actively-exploited vulnerabilities in your products. Initial notification; details follow.
- **72-hour notification** of incidents and known unpatched vulnerabilities being exploited.
- **CE marking** carries cybersecurity essential requirements (Annex I).
- **Supported lifetime** documented at sale; minimum 5 years in most cases.
- **SBOM** in machine-readable format on request.

Reference: `eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32024R2847`.

### 10.2 US Cyber Trust Mark

Voluntary FCC IoT label, finalized March 2024, first products labeled 2025. Compliance is built on NIST IR 8425 (Profile of the IoT Core Baseline for Consumer Products). Operational requirements include unique-default-credentials, automatic security updates, software update mechanism, secure development practices.

### 10.3 California SB-327

In force since January 2020. Requires "reasonable security feature(s)" for connected devices sold in California. The bar is loosely defined; the safe harbor is unique default passwords or forced-password-change at first setup. Most vendors comply by abolishing default passwords entirely.

### 10.4 NIST IR 8259 / 8259A / 8259B

NIST IR 8259 ("Foundational Cybersecurity Activities for IoT Device Manufacturers"), 8259A ("Core Device Cybersecurity Capability Baseline"), 8259B ("Non-Technical Supporting Capability Core Baseline"). Together they give the operational reference for what an IoT-manufacturer security program looks like. Reference for executive briefings and audit programs.

### 10.5 ETSI EN 303 645

European consumer IoT security baseline, published 2020. 13 high-level provisions: no universal default passwords, vulnerability-disclosure policy, keep software updated, securely store sensitive parameters, communicate securely, minimize exposed attack surface, ensure software integrity, ensure personal data is secure, make systems resilient to outages, examine system telemetry data, make it easy for users to delete data, make installation and maintenance easy, validate input data.

### 10.6 FDA Premarket / Postmarket Cybersecurity (medical)

Premarket Cybersecurity Guidance, final 2023 (with 2025 updates) — FDA-2018-D-3443. Postmarket Management of Cybersecurity in Medical Devices, 2016. The "SBOM mandate" — premarket submissions must include a machine-readable SBOM (HHS Section 524B of the FD&C Act). Cross-link `[[reference-medical-device-security]]`.

### 10.7 UNECE R155 / R156 (automotive)

R155: Cyber Security Management System. R156: Software Update Management System. UN regulations applicable for new vehicle type approval in WP.29 countries from July 2022 (new types) and July 2024 (all production). Operational reach: every vehicle ECU. Cross-link `[[reference-automotive-security]]`.

### 10.8 NERC CIP (bulk electric system)

NERC CIP-002 through CIP-013 cover bulk-electric-system OT. CIP-013 specifically addresses supply chain. Audit obligations are heavy and ongoing. Cross-link `[[reference-ics-ot-security]]`.

### 10.9 CISA Secure-by-Design pledge

Voluntary US program launched at RSA 2024. Seven goals: MFA adoption, default passwords reduction, reduction of one or more vulnerability classes, security patches at scale, published VDP, CVE transparency, evidence of intrusions. Signing the pledge is a public commitment with annual progress reporting.

---

## 11. 12-item AppSec-lead playbook checklist

In priority order — number one is the first thing to put in writing.

1. **Threat model is reviewed quarterly** and out-of-cycle when the device gains a new capability. Owner: product security lead. Cross-link `[[reference-vr-methodology]]` for the threat-modeling primitives.
2. **SBOM is generated on every build**, signed, published with the firmware. Format: CycloneDX 1.6 or SPDX 2.3+. Owner: build/release engineering. Cross-link `[[reference-supply-chain-provenance]]`.
3. **Update channel is dual-bank A/B with anti-rollback** fuse policy. Owner: device-engineering lead. Reference: §4.2.
4. **Update payloads are signed**; root key in HSM with two-person access; documented key-rotation plan. Owner: hardware-security lead. Reference: §4.3.
5. **`SECURITY.md` and `security.txt`** on the product website; published email aliases monitored with 24-hour first-response SLA. Owner: security-program manager. Reference: §5.1.
6. **CVE feed subscription** for every component in the SBOM, with weekly triage. Owner: vuln-management lead. Reference: §6.1.
7. **Telemetry pipeline emits** boot-integrity, runtime-integrity, network-anomaly, auth-anomaly signals; privacy review on file. Owner: platform / observability + privacy engineering. Reference: §3.
8. **Detection rules in the SIEM** align with `[[reference-detection-engineering]]` §10 and the anomaly classes in §3. Owner: SOC / detection-engineering lead.
9. **Quarterly tabletop exercise** simulating a fleet-wide compromise; rotate the scenario (firmware-supply-chain compromise, credential-stuffing, OT lateral movement). Owner: IR lead. Cross-link `[[reference-dfir-methodology]]`.
10. **EOL policy is documented** in the product spec with a minimum-supported-lifetime commitment that meets EU CRA. Owner: product management. Reference: §9.
11. **Bug bounty or VDP is publicly listed**; payout / SLA terms documented; CNA status decision in writing. Owner: security-program manager. Reference: §5.
12. **Annual third-party pentest** of at least one shipped product line; published high-level summary; remediation tracked to completion. Owner: security-program manager.

---

## 12. Cross-link cluster and known gaps

### Cross-link cluster

- `[[reference-rtos-embedded-os]]` — parent reference for kernel + TCP/IP + MPU/TrustZone-M attack surface.
- `[[reference-firmware-embedded-security]]` — bootloader, secure boot, hardware root of trust, supply-chain at the firmware layer.
- `[[reference-dfir-methodology]]` — incident-response lifecycle that §8 plugs into.
- `[[reference-supply-chain-provenance]]` — SLSA, sigstore, in-toto, SBOM and VEX reference.
- `[[reference-detection-engineering]]` — runtime-detection rule corpus referenced from §3 and §8.
- `[[reference-ics-ot-security]]` — adjacent for OT field gear; Purdue model, Stuxnet/Triton, ICS protocols.
- `[[reference-medical-device-security]]` — adjacent for medical-device specifics; FDA premarket/postmarket.
- `[[reference-automotive-security]]` — adjacent for automotive ECUs; UNECE R155/R156, ISO/SAE 21434.
- `[[reference-building-automation-security]]` — adjacent for HVAC, BMS, physical access control; OT:ICEFALL canonical anchor.
- `[[reference-cloud-iam]]` — for the backend identity plane that devices authenticate to.

### Known gaps

- **Per-RTOS deep-dive** lives in `[[reference-rtos-embedded-os]]`. This doc is OS-agnostic.
- **ICS / OT specifics** — Purdue model, ICS protocols, Stuxnet / Triton / CrashOverride / Volt Typhoon corpus — live in `[[reference-ics-ot-security]]`.
- **Medical-device specifics** — FDA submission content, IEC 62304, IEC 81001-5-1 — live in `[[reference-medical-device-security]]`.
- **Automotive specifics** — CAN/CAN FD/LIN/FlexRay/SOME/IP, Miller-Valasek, OEM-specific Tier-1 supply chains — live in `[[reference-automotive-security]]`.
- **Building automation specifics** — BACnet/KNX/Modbus, Tridium Niagara / Metasys / Desigo — live in `[[reference-building-automation-security]]`.
- **Hardware root-of-trust + secure boot** deep-dive lives in `[[reference-firmware-embedded-security]]`.
- **Wireless / RF specifics** — Wi-Fi / BLE / Zigbee / Thread / cellular — live in `[[reference-wireless-rf-satellite]]`.
- This playbook covers consumer-IoT, industrial-sensor, and crossover devices. It is not exhaustive on any single vertical; see the cross-links for vertical depth.

### Anchor incidents referenced (for searchability)

- **Mirai botnet** (Krebs, October 2016; Symantec analysis) — 600 Gbps OVH and 1.2 Tbps Dyn DDoS via default-credential Telnet on consumer IoT.
- **VPNFilter** (Cisco Talos, May 2018) — Sandworm-attributed compromise of 500,000+ SOHO routers.
- **Ring credential-stuffing** (Motherboard, December 2019) — account takeover surfacing as live camera audio.
- **Ripple20** (JSOF, June 2020, CERT/CC VU#257161) — 19 CVEs in Treck TCP/IP stack across hundreds of millions of devices.
- **URGENT/11** (Armis, July 2019) — 11 CVEs in VxWorks IPnet.
- **Verkada** (March 2021; APT-Reporter and Bloomberg coverage) — cloud-backend compromise yielding live access to 150,000 cameras; cross-link `[[reference-building-automation-security]]`.
- **TP-Link Archer A7 family** — recurring Pwn2Own SOHO category target across 2019-2024.
- **Hide N Seek (HNS)** botnet (Bitdefender, January 2018) — peer-to-peer IoT botnet, BitTorrent-DHT C2.
- **Mozi botnet** (360 Netlab, December 2019 onward) — successor to Mirai/Hajime, DHT-based, persistent on many SOHO routers and DVRs until 2023 takedown.
- **OT:ICEFALL** (Forescout, June 2022) — 56 vulnerabilities across 10 OT vendors; "insecure-by-design" multi-vendor disclosure.
- **Tesla 2023 OTA recall** — FMVSS Part 573 notice for Autosteer-related OTA fix; reference for "the recall happens by software push, but it is still a recall."
- **Ring 2024 reset incident** — buggy update reset device configurations; reference for §4.6 (when an update bricks devices).
- **Bybit $1.4B Lazarus heist** (February 2025) — out-of-scope here, but the operational lesson on update-pipeline trust transfers; cross-link `[[reference-blockchain-wallet-consensus]]`.

### Status

Doc opened 2026-05-15 as a new operations-playbook sibling to `[[reference-rtos-embedded-os]]`. Scope deliberately bounded to operations; expansion in the regulatory section (§10) and the IR section (§8) is the most likely next iteration as EU CRA enforcement actions accumulate from September 2026 onward.
