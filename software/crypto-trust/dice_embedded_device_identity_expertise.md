# DICE — Device Identifier Composition Engine for Resource-Constrained Devices

DICE is what you build hardware-rooted device identity from when a TPM 2.0 will not fit. This is the deep dive on the TCG specification family, the cryptographic primitive (CDI = OneWayFunction(UDS, Measurement)), the layering recipe (L0/L1/L2+), production deployments (Microsoft Cerberus, Azure Sphere, ARM PSA + TF-M, IDevID per IEEE 802.1AR), and the threat model + operational discipline. Sibling to `[[reference-hardware-attestation-chains]]` (parent attestation discipline, §4 brief DICE mention is the seed for this doc), `[[reference-embedded-device-hardening-playbook]]` (operations playbook for embedded products), and `[[reference-rtos-embedded-os]]` (RTOS attack surface).

## 1. Why this doc exists

A TPM 2.0 implementation requires ~256KB of code, a discrete or firmware-resident security module, complex spec compliance, and per-chip provisioning machinery. On a Cortex-M0/M3/M4 microcontroller — 64KB to 512KB of flash, tens of KB of RAM, battery-powered, $1-3 BOM — that is not a viable target. The TCG (Trusted Computing Group) DICE Architectures Working Group designed DICE as the resource-constrained alternative: compress the hardware root of trust down to a single secret + a one-way function + a layering recipe. No dedicated module. No spec-compliance burden in the same league as TPM 2.0. Cryptographically bound to the boot chain by construction.

The trade is honest. DICE produces a derived device identity but does not give you the rich command surface a TPM does (sealed storage, PCR-based policy, AIK + EK separation, NV indexes). What you get is: a per-device alias key cryptographically derived from the device's Unique Device Secret + measurements of every layer that ran before the current one. If any layer's image changes, the derived key changes. That is enough for: device identity (provable I-am-this-chip-running-this-firmware), implicit attestation (verifier sees signatures verifiable against expected derived key = device booted the expected stack), and reference-value-based fleet management.

This doc covers: TCG DICE specification family (§2), the CDI cryptographic primitive (§3), L0/L1/L2 layering (§4), Microsoft Project Cerberus + Azure Sphere deployments (§5), ARM PSA + TF-M (§6), IDevID per IEEE 802.1AR + BRSKI (§7), DICE in the boot chain as implicit measured boot (§8), threat model (§9), operational discipline (§10), 2024-2026 deployment status (§11), and a load-bearing honest-failure-modes section (§12). Audience: AI agents plus embedded-systems engineer, SoC vendor, IoT-platform team working on hardware-rooted device identity with limited resources.

## 2. TCG DICE specification family

The TCG DICE Architectures Working Group publishes a related family of specifications, not a single monolith. Working-group leadership has included **Dennis Mattoon** (Microsoft, TCG DICE WG co-chair `[unverified specific tenure]`) and contributions associated with **Wenbo Mao** + **Liqun Chen** at the cryptographic-foundations layer `[unverified specific attribution]`. Verify the canonical URLs at `trustedcomputinggroup.org/work-groups/dice-architectures/` `[unverified specific URL form]` — TCG reorganizes its work-group naming periodically.

- **DICE Layering Architecture** (TCG, v1.0 baseline `[unverified specific version + date — circa 2020]`). The foundational document. Defines UDS (Unique Device Secret), CDI (Compound Device Identifier), the L0 / L1 / L2 layering construct, and the security goals (boot-chain binding, secret confinement, deterministic identity).
- **DICE Symmetric Identity-Based Device Attestation** (v1.0 `[unverified version]`). Specifies the symmetric-key path: CDI itself (or HMAC of CDI with a domain-separator) is the attestation secret. Verifier needs a copy of CDI (or a derivation) to validate. Used where asymmetric crypto is expensive or unavailable on the device.
- **DICE Asymmetric Identity** (v1.0 `[unverified version]`). Specifies the asymmetric-key path: an asymmetric key pair (typically ECDSA P-256 or Ed25519) is deterministically derived from CDI. The private key never leaves the layer that derived it; the public key + a CSR are published, typically signed up to a manufacturer root. This is the path that composes with IEEE 802.1AR and BRSKI.
- **DICE Protection Environment** (v1.0 `[unverified version]`). Specifies properties the environment holding UDS + computing the first CDI derivation must satisfy: immutable code, no read path to UDS for higher layers, side-channel resistance commensurate with deployment threat model, hardware-enforced confinement.
- **DICE Hierarchical Implicit Identity / Hierarchical Attestation** `[unverified specific spec title]`. The layering recipe: each layer's CDI is a function of the prior layer's CDI plus the measurement of the next layer's code. Bottom-up chain rooted at UDS.
- **DICE-X / Extension drafts** `[unverified specific spec status as of 2026-05]`. Covers asynchronous attestation, multi-layer composition beyond L2, sealed storage analogs, and integration with the IETF RATS framework (RFC 9334).
- **TCG DICE Endorsement Architecture for Devices** `[unverified specific title]`. How manufacturers issue endorsement certificates over DICE-derived keys at provisioning time.

The specs are short by TPM 2.0 standards — most are 20-80 pages — but the cross-references are dense. The implementer's task is composing the layering architecture spec with the asymmetric (or symmetric) identity spec, the protection environment spec, and the endorsement architecture spec into a coherent design. Vendor reference implementations (Microsoft, ARM TF-M) are the practical starting point; reading the specs cold is harder than reading TPM 2.0 cold because the specs assume you have the working-group context.

## 3. The cryptographic primitive — CDI derivation

The cryptographic core of DICE is a single equation: **CDI = OneWayFunction(UDS, MeasurementOfNextLayer)**.

Concretely, in most production implementations: `CDI_L1 = HMAC-SHA256(UDS, SHA-256(L1_image))`. Or with HKDF: `CDI_L1 = HKDF(salt=SHA-256(L1_image), IKM=UDS, info="DICE-L1-CDI", L=32)`. The choice of OWF is implementation-defined; the TCG specs do not mandate a single primitive. SHA-256 + HMAC is the de facto baseline. SHA-512 + HMAC is used where the flash budget permits.

**UDS (Unique Device Secret).** A per-device secret injected at manufacture. Typical sizes: 256 bits (32 bytes) for symmetric, 384+ bits for derivation into ECC keys. Held in immutable storage: OTP fuses (one-time programmable), write-once flash, or factory-fused secret-store ROM. Read-disabled to anything other than the L0 boot ROM after manufacturing provisioning completes. Never exposed outside L0.

**Hierarchical CDI.** Each layer derives the next layer's CDI from its own CDI + the measurement of the next layer:
- `CDI_L1 = OWF(UDS, hash(L1_image))`
- `CDI_L2 = OWF(CDI_L1, hash(L2_image))`
- `CDI_L3 = OWF(CDI_L2, hash(L3_image))`

A change in any layer's image — even a single byte — propagates through every subsequent CDI. This is the property that makes DICE useful as a measured-boot primitive: device identity at L2 is a function of UDS + L1_image + L2_image. The verifier sees only a derived key, but the derived key implicitly attests to the full boot-chain measurement.

**Alias key derivation.** For asymmetric paths, the layer derives an asymmetric key pair deterministically from its CDI:
- `seed = HKDF(CDI_Ln, info="DICE-AsymmetricSeed-Ln", L=32)`
- ECDSA-P256 / Ed25519 private key = derived deterministically from `seed`
- Public key + CSR published; typically signed by the prior layer (or by a factory-provisioned cert chain rooted at the manufacturer CA).

The private key never leaves the layer that derived it. The CDI never leaves either — it stays in the layer's RAM, ideally wiped after the alias-key derivation completes if the layer does not need it further.

**Security property of the construction.**
- If any layer's measurement changes, all subsequent CDIs differ → all derived alias keys differ → verifier sees an unexpected public key.
- If UDS is compromised (extracted by physical attack, leaked by side channel, or read out by a firmware bug in L0), the attacker can reproduce every CDI for every measurement set they choose. Device identity is forged.
- UDS protection is load-bearing. Everything depends on it. (§9 covers extraction attacks; §12 covers this as the catastrophic-compromise failure mode.)

**Symmetric path.** When asymmetric crypto is out of budget, CDI itself can be used: verifier and device share UDS (or a derivation), verifier computes the same CDI from known reference values, device proves possession by HMAC over a verifier-supplied challenge. Used in deeply constrained deployments. Loses the public-key-infrastructure advantages — verifier holds a per-device shared secret — but stays cryptographically sound.

## 4. Layering architecture — L0 / L1 / L2

The DICE Layering Architecture spec defines a chain of trust rooted at an immutable ROM and walking up through firmware stages.

**L0 — ROM bootloader.** Immutable. Holds UDS (or has hardware-enforced read access to UDS in a protected store). Knows nothing about higher layers' code semantics. Its only DICE-relevant job: measure L1's image (typically SHA-256 of the L1 binary as loaded into RAM), compute `CDI_L1 = OWF(UDS, L1_measurement)`, pass `CDI_L1` to L1 via a known register/RAM-region/secure-handoff convention, then jump to L1's entry point and overwrite UDS in its working memory. The L0 ROM is typically a few KB; the DICE-specific code is a few hundred bytes (the hash function + the OWF + the handoff).

**L1 — first-stage bootloader / fwloader / secure boot loader.** Receives `CDI_L1` from L0. Measures L2 (typically SHA-256 of the L2 image, optionally augmented with configuration state, security version number, anti-rollback counter). Computes `CDI_L2 = OWF(CDI_L1, L2_measurement)`. May derive an alias key from `CDI_L1` and emit a certificate over L2's public alias key (signed by L1's alias key). May verify L2's image signature against a manufacturer's verified-boot public key before measuring + handing off — this composes DICE-as-measured-boot with verified-boot. After handoff, wipes `CDI_L1`.

**L2 — application firmware / RTOS / main image.** Receives `CDI_L2` from L1. Derives the device's externally-visible alias key (the IDevID, in 802.1AR terminology, if it was endorsed at manufacture). Uses the alias key for device identity in protocols: TLS client cert authentication, attestation token signing (PSA IAT, EAT per RFC 9711 `[unverified specific RFC]`), MQTT broker authentication, BRSKI onboarding. May further layer into L3+ if there is an OS / RTOS / hypervisor / application sandbox.

**L3+ in some designs.** The TCG specs do not cap layer depth. Microsoft Cerberus extends the chain into BMC firmware, NIC firmware, BIOS, etc., each measured + composed into the chain. ARM CCA + Realm-management firmware sit between L2 and a confidential-computing realm. Azure Sphere had L0/L1/L2 plus a separate Pluton secure-world layer.

**The implicit attestation property.** The verifier never sees CDIs or measurements directly. The verifier sees a signature from the device. The signature verifies against a public key that the verifier expects to see. The verifier knows what public key to expect because it has reference values — `hash(L1_expected) + hash(L2_expected) → expected_alias_pubkey` — computed at firmware-build time and pushed to the verifier infrastructure. If the signature verifies, all measurements implicitly match. If not, something in the boot chain differs from reference. The verifier learns binary pass/fail per device; it does not learn what differs (unlike TPM-style explicit attestation reports). This is sufficient for fleet-integrity monitoring and onboarding gates; not sufficient for IR forensics where you want to know what specifically changed.

## 5. Microsoft Project Cerberus + Azure Sphere as deployed DICE

Microsoft was an early industrial adopter of DICE-based identity at two scales: hyperscale server (Cerberus) and consumer-tier IoT (Azure Sphere). The same primitive at very different threat models + BOM constraints.

**Project Cerberus (Microsoft, Open Compute Project 2017+).** Architected at Microsoft by **Bryan Kelly** + collaborators `[unverified specific architect attribution]`. A reference design for a hardware Root of Trust for Measurement on server motherboards. A standalone microcontroller — typically a Lattice or NXP MCU `[unverified specific vendor pinning]` — sits on the motherboard and intercepts SPI flash access to BIOS, BMC, and NIC firmware. At power-on, Cerberus reads each component's firmware image, measures it, and binds the measurement into a DICE chain rooted at the Cerberus chip's UDS. If a firmware image differs from the expected reference (rollback, supply-chain implant, BMC compromise), the boot is gated. The Open Compute Foundation `[unverified specific spec release]` ratified the Cerberus spec; multi-vendor implementations followed. Cerberus is the cleanest single example of "DICE applied at hyperscale" because the threat model includes nation-state firmware implants on the BMC, where TPM-style boot measurement alone (PCRs in the host CPU's TPM) doesn't cover BMC firmware.

The architectural lesson: DICE-as-RoT-for-firmware is independent of DICE-as-device-identity. Cerberus uses DICE primarily for measurement + boot gating, not for outward-facing device identity. The two can compose.

**Azure Sphere (Microsoft 2018-2024).** Consumer-tier IoT secure-by-design platform. Led by **Galen Hunt** at Microsoft Research `[unverified specific role + tenure]`; the Sphere team's "Seven Properties of Highly Secure Devices" paper (Hunt et al., Microsoft Research, ~2017) is the canonical articulation of the design philosophy. Three-element design: an MCU with a Microsoft-designed Pluton security subsystem, a Microsoft-curated Linux-based OS (Azure Sphere OS), and a cloud-side security service (Azure Sphere Security Service). DICE-based identity rooted at Pluton's UDS. Each layer in the boot chain — Pluton bootloader → secure-world → normal-world OS → application — folded into the DICE chain. The alias key at the top of the chain was the device's IDevID, used to authenticate to the Azure Sphere Security Service for OTA updates and policy delivery.

Azure Sphere was discontinued — `[unverified specific shutdown date, ~2024 with multi-year EOL window]`. Legacy deployments are still in field as of 2026; the EOL implications are non-trivial (no path to refresh the manufacturer trust root, orphan cert chains, no further security updates — see §12).

**Microsoft Pluton MCU.** Originally the Azure Sphere security subsystem. Now integrated as a security processor in AMD Ryzen 6000+ series, Intel Core 13th-gen+ `[unverified specific generations]`, and Qualcomm Snapdragon platforms. DICE-derived identity is one of its capabilities; it also provides TPM 2.0 functionality and a Microsoft-curated secure-boot enforcement path. The Pluton story is partly the Azure Sphere R&D harvested into a broader PC ecosystem play `[unverified specific roadmap details — verify per AMD/Intel/Qualcomm vendor docs]`.

**The architectural lesson Cerberus + Sphere taught.** DICE composes across orders of magnitude in device cost and threat model. A $1 Cortex-M IoT sensor can use the same primitive as a $40,000 server motherboard's RoT. The implementation details differ (UDS provisioning at IoT-fab scale is different from server-MCU provisioning; side-channel hardening is different; layer count is different); the cryptographic primitive is the same.

## 6. ARM PSA (Platform Security Architecture)

ARM Platform Security Architecture is ARM's framework for embedded security on Cortex-M and Cortex-A class devices. Since 2017, the PSA Certified program has offered tiered security certification — Levels 1 / 2 / 3 plus bespoke profiles. DICE composes naturally with the PSA stack.

- **PSA Initial Attestation Token (IAT).** The attestation primitive PSA-Certified devices produce. CBOR-encoded, signed by the device's attestation key. Includes implementation ID (device class), instance ID (per-device identifier), boot-state measurements (similar in spirit to TPM PCRs but flat), security lifecycle state, and a verifier-supplied challenge / nonce. Specified in PSA-IAT (open spec, ARM + Arm Trusted Firmware project).
- **TF-M (Trusted Firmware for Cortex-M).** Open-source secure-side firmware implementing PSA. Runs in the secure world (Cortex-M TrustZone for ARMv8-M). Provides: initial-attestation service (signs the PSA IAT), crypto service (PSA Crypto API), secure storage (protected + internal-trusted storage), platform service. Sits in L1 / L2 of a DICE chain.
- **DICE integration in TF-M / PSA.** TF-M can use a DICE-derived key as the IAT signing key. The PSA IAT is then the "attestation-layer cap" on top of DICE: DICE gives the cryptographic identity (alias key derived from CDI derived from UDS + measurements), and the PSA IAT gives the wire format the verifier consumes. TF-M's initial-attestation module supports this composition `[unverified specific TF-M version cutoff for DICE integration — verify against Trusted Firmware project docs]`.
- **Vendor adoption.** STMicro (STM32 series with TF-M reference ports), NXP (LPC55S6x and i.MX RT series), Nuvoton (M2351 / M2354 PSA Certified L2), Renesas (RA series), Microchip (SAML11). Each implements DICE differently — verify per chip. Some inject UDS via factory provisioning; some derive UDS from a PUF (physically unclonable function); some support both. The variance across vendors is one of the practical headaches of building cross-vendor verifier infrastructure.

PSA Certified Level 1 is a self-attestation security questionnaire — no DICE requirement. Level 2 requires resistance to remote software attacks and typically uses DICE or a similar hardware-rooted identity primitive. Level 3 adds resistance to physical attacks (side-channel, fault injection) — at Level 3, the DICE implementation must include side-channel hardening on the OWF and on the UDS read path.

Cross-link: `[[reference-rtos-embedded-os]]` covers the Cortex-M attack surface around TF-M and PSA in more detail; this section covers only the DICE integration aspect.

## 7. IDevID / IEEE 802.1AR — the manufacturing identity standard

DICE gives you a per-device cryptographic identity. IEEE 802.1AR-2018 (Secure Device Identity) defines how that identity is shaped, certified, and provisioned at manufacture as an interoperable artifact.

- **IDevID (Initial Device Identifier).** Manufactured-in, immutable, X.509 certificate signed by the manufacturer. The private key is held inside the device's hardware boundary (in DICE terms, derived from CDI, never leaves the layer that derived it). The cert is provisioned at factory time and carries the manufacturer's chain of trust up to a manufacturer root CA.
- **LDevID (Locally significant Device Identifier).** Provisioned by the end-user or operator after the device is in the field. May be rotated. Used when the manufacturer identity is not the right identity for the device's operational role (e.g., enrolled into an enterprise PKI under the enterprise's own CA).
- **DICE + 802.1AR composition.** The alias key derived from L2_CDI is enrolled as an IDevID at manufacture: the factory provisioning station reads the L2 alias public key out of the device, constructs an X.509 CSR (with the implementation ID, instance ID, and device-class identifier in the cert's subject + extensions), signs it with the manufacturer's intermediate CA, and writes the resulting cert back into the device's non-secret storage (typically a region of flash readable by L2 but not modifiable post-provisioning). Verifier validates the X.509 chain back to the manufacturer root.
- **BRSKI (Bootstrapping Remote Secure Key Infrastructure, RFC 8995).** IDevID-based onboarding protocol for IoT devices to securely join networks. Device presents its IDevID to a local registrar; registrar consults the manufacturer's authorization service (MASA — Manufacturer Authorized Signing Authority) to verify device authenticity and obtain a per-device voucher; voucher is then used to bootstrap LDevID provisioning. BRSKI is the canonical example of DICE-derived IDevID + 802.1AR + manufacturer-as-trust-anchor composing into a working zero-touch IoT enrollment story. ANIMA Working Group (IETF) authored the spec; deployments are still relatively sparse outside Cisco's pre-standard pre-BRSKI work `[unverified specific deployment status]`.

The trust-anchor distribution problem at §12 is the operational nightmare of this composition. BRSKI is sound on paper. In practice, MASA infrastructure is run by manufacturers who may go out of business (see Azure Sphere EOL), and enterprise registrars need a path to validate certs from manufacturers they may not have a direct relationship with.

## 8. DICE in the boot chain — implicit measured boot

DICE is best understood as the resource-constrained analog of TPM-based measured boot. Cross-link `[[reference-hardware-attestation-chains]]` §4 — that section covers Measured Boot vs Secure Boot at the TPM tier; this section covers the DICE tier.

**DICE-as-measured-boot.** At each layer transition, the loading layer measures the loaded layer's image. The measurement enters the CDI derivation. If the image changes, the CDI differs.

**Compare to TPM measured boot.**
- TPM measured boot: each component extends a PCR with the hash of the next component. PCRs accumulate measurements. At runtime, the TPM signs an attestation report containing PCR values; verifier compares PCRs to reference values. **Explicit attestation** — verifier sees the measurements.
- DICE measured boot: each layer folds the hash of the next layer into the CDI derivation. CDIs accumulate measurements implicitly. At runtime, the device signs with a key derived from the final CDI; verifier compares the public key it sees to the public key it expected. **Implicit attestation** — verifier sees only a derived key.

Both achieve "boot-chain integrity baked into device identity," but DICE doesn't need a TPM. The trade-off: TPM gives you forensic transparency (the verifier knows what differs); DICE gives you pass/fail only.

**Composition with verified boot.** Verified boot blocks malformed images at load time (analogous to UEFI Secure Boot or signed-firmware enforcement on embedded SoCs). DICE measures whatever loaded. Both should be present in production: verified boot prevents loading an attacker-controlled image; DICE measurement plus reference-value verification on the verifier side detects the case where verified-boot enforcement was bypassed or where a legitimately-signed-but-rolled-back image was loaded.

**Anti-rollback composition.** DICE measurement should include a security version number (SVN) for each layer, so that a downgrade to a previous signed-but-vulnerable image produces a different CDI than the current SVN. Without SVN in the measurement, an attacker who has a signed-but-vulnerable old image can replay it indefinitely. The TCG specs recommend SVN inclusion `[unverified specific spec citation]`; vendor implementations vary.

**Configuration measurement.** Some layers should fold configuration state into the measurement: secure boot policy, fuse state, debug-port-enabled bit. This produces different CDIs for "production configuration" vs "developer-debug configuration," so debug-mode devices' identities are distinguishable from production-mode devices' identities. Verifier infrastructure can then refuse to onboard debug-mode devices into production fleets.

## 9. Threat model + attack surface

The catastrophic failure mode of DICE is UDS extraction. Every defense is essentially: keep UDS confined to L0's protection environment, never let it leak.

**UDS extraction breaks everything.** With UDS in hand, the attacker can: reproduce any CDI for any measurement set; forge alias keys; produce signed attestations for arbitrary firmware images; impersonate the device on any protocol that authenticates the device by its DICE-derived identity. Manufacturer-cert chains do not help because the attacker can produce a CSR for the legitimate device's expected alias key and present a verifier-validatable chain.

**Physical attacks.**
- **Chip decap + microscope + probing.** Destructive teardown of the chip to physically expose internal traces; microprobe + EM emission analysis to extract OTP fuse state. Effective against any UDS held in unhardened storage. Costs: $10K-100K per chip with skilled lab. Mitigations: physical-tamper-resistance design (active mesh, anti-probing detection circuits), depackaging-detection sensors. PSA Certified Level 3 is the certification tier that requires these mitigations.
- **Voltage glitching, clock glitching, laser fault injection.** Disrupt the L0 ROM execution to skip the read-disable instruction on UDS or to leak UDS through an unintended code path. ChipWhisperer is the canonical research platform; production attackers use FPGA-based glitching rigs. Mitigations: redundant read-disable, glitch-detection circuits, redundant-execution code paths. Cross-link `[[reference-hardware-side-channels]]` for the full primitive catalog.
- **Side-channel: power analysis (SPA / DPA), EM analysis.** Observe UDS-dependent computations from outside the chip. Power traces leak HMAC and ECC operations on unhardened cores. EUCLEAK 2024 (Thomas Roche / NinjaLab) demonstrated EM side-channel extraction of ECDSA private keys from Infineon SLE78/SLE97 secure elements — including FIDO2-certified hardware. The same attack class applies to DICE-derived alias keys on chips without side-channel hardening. Cross-link `[[reference-hardware-attestation-chains]]` §13 and `[[reference-hardware-side-channels]]`.

**Firmware-side bugs in L0 or L1.** If L0 or L1 has a memory-safety bug that lets an attacker read CDI out of RAM before it's wiped, or if L1 is exploited and reads L0's UDS-handling register window, the chain is compromised below the application layer. Typical bug classes: ROP gadgets in L1 that read protected memory regions, format-string bugs in early-boot logging that leak stack contents, ill-considered debug interfaces that expose CDI for diagnostic purposes. Cross-link `[[reference-c-cpp-footguns]]` and `[[reference-firmware-embedded-security]]`.

**Implementation bugs in DICE derivation.**
- **Weak entropy in UDS generation.** If the manufacturer's UDS generation is predictable (PRNG seeded from low-entropy source, factory-station insufficient randomness), UDS is brute-forceable. Per-device UDS must be cryptographically independent across devices.
- **Fixed-key HMAC** (operator error in the spec implementation): a vendor that mistakenly uses a fixed manufacturer-wide constant where they should be using per-device UDS produces a "DICE" implementation where every chip in the production lot has the same CDIs for the same measurements. Catastrophic but plausible — the spec is short enough that misimplementation is easy.
- **Side-channel-leaky OWF implementations.** A constant-time HMAC implementation is required; some embedded crypto libraries ship table-lookup AES that leaks via cache timing (mostly relevant on Cortex-A; less on Cortex-M where caches are smaller).
- **Insufficient salt / context separation.** If the same OWF input is used for multiple purposes (CDI derivation + alias-key derivation + attestation challenge response), accidental relations between the outputs can leak. Domain-separation strings in HKDF info parameters are the discipline; spec compliance is variable.

**Manufacturer compromise.** If the manufacturer's intermediate CA or root CA is compromised, attackers can issue arbitrary endorsement certificates over arbitrary alias keys. Same problem class as WebPKI roots. CA HSM compromise is the obvious failure; manufacturer-side OEM-customization key compromise is the subtler one — many SoC vendors let OEMs inject their own UDS at provisioning, and if the OEM-side provisioning station is compromised, the OEM root is too.

## 10. Operational discipline for DICE-based fleets

DICE is a primitive. Running a fleet at scale requires operational discipline analogous to HSM operations (`[[reference-hsm-operational-discipline]]`) at IoT-scale.

**UDS provisioning at manufacture.**
- Done at the factory in a clean-room environment, behind tamper-evident provisioning equipment.
- Each device's UDS generated from a cryptographically strong RNG (factory provisioning station with a hardware RNG, ideally with FIPS 140-2/3 validation `[unverified specific FIPS level common in IoT-fab provisioning stations]`).
- UDS written to OTP fuses via a wire-once interface; OTP read-protect bit blown after provisioning verification.
- Provisioning station logs (per-device UDS hash, provisioning timestamp, device serial number) retained for traceability — but the UDS itself is not retained anywhere in cleartext after the device leaves the station.
- Cross-link `[[reference-hsm-operational-discipline]]` §4: UDS provisioning is analogous to HSM key ceremony but at IoT scale. The discipline transfers; the threat model differs (per-device UDS is lower-value than HSM root key, but there are billions of them).

**Per-device certificate chain.**
- Alias-key certificate signed by manufacturer intermediate CA at provisioning time.
- Intermediate CA signed by manufacturer root CA (held in HSM at manufacturer HQ, offline-signed periodically).
- Root CA cert + intermediate CA cert distributed to verifiers via out-of-band channels: vendor security portal, signed root-cert bundles, BRSKI MASA endpoints.
- Distribution of manufacturer roots to verifiers is the trust-anchor distribution problem. WebPKI has the CA/Browser Forum; IoT does not have an equivalent in 2026.

**Reference value management.**
- For implicit-attestation deployments: every firmware update changes measurements → changes derived alias keys → verifier must update the per-device expected-public-key set.
- Build-time tooling computes reference CDIs across the layer hierarchy and emits the expected alias-key set per firmware version + SVN.
- Verifier infrastructure ingests reference values; per-device records track which firmware version each device is currently running.
- Cross-link `[[reference-hardware-attestation-chains]]` §11: reference-value-management is the load-bearing operational pipeline for DICE-tier attestation just as much as for TPM-tier.
- At fleet scale (1M+ devices), this is a database engineering problem more than a crypto problem.

**Decommissioning.**
- Cryptographic erasure by zeroing UDS — only possible if the silicon supports a UDS-erase operation (most do not; OTP fuses are by definition one-way).
- More commonly: revoke the device's alias-key certificate at the manufacturer root via CRL or OCSP-equivalent. Verifiers refuse signatures from revoked certs.
- For deeply field-deployed devices with no network back to a manufacturer revocation infrastructure, revocation is essentially not possible. EOL devices either get a final OTA push to a "decommissioned" state (if the device cooperates) or they continue presenting valid identity until the manufacturer trust root is rolled.
- Cross-link `[[reference-embedded-device-hardening-playbook]]` §EOL.

**Operational telemetry.** Verifiers should log all attestation failures (alias-key-not-found, signature-verification-failed, cert-chain-validation-failed) into observability infrastructure. Sudden spikes in attestation failures across a vendor's chip family suggest one of: bad firmware push, certificate-chain issue, attack. Cross-link `[[reference-detection-engineering]]`.

## 11. Real deployments + 2024-2026 status

- **Microsoft Project Cerberus.** OCP-spec, ratified by Open Compute Foundation. Multi-vendor implementations from Lattice, NXP, Intel, others `[unverified specific vendor list 2026]`. Deployed in Azure datacenters and in OCP-member hyperscalers' fleets. Production status: active.
- **Microsoft Azure Sphere.** Discontinued. `[unverified specific shutdown date — circa 2024 with multi-year EOL window]`. Legacy deployments still active in field; manufacturer support ceased; cloud service path to Microsoft eventually shut down. EOL security implications: legacy devices with orphaned DICE-derived identities, no path to refresh manufacturer trust root, no firmware updates. The Sphere EOL is the load-bearing cautionary tale for closed-loop manufacturer-cloud-coupled IoT identity (§12).
- **Microsoft Pluton.** Integrated into AMD Ryzen 6000 series and later (released 2022+), Intel Core 13th-gen and later `[unverified specific generations]`, Qualcomm Snapdragon (mobile-PC tier). DICE-derived identity is one capability among several (TPM 2.0 firmware-resident mode, secure boot enforcement, key isolation). Adoption is increasing but Pluton's role varies across OEM laptop designs — some ship Pluton as the active TPM, some use it for limited functions while shipping a discrete TPM.
- **ARM PSA + TF-M.** Broad ARM Cortex-M ecosystem adoption. PSA Certified L1/L2/L3 chips in market from STMicro, NXP, Nuvoton, Renesas, Microchip. PSA Certified database `[unverified specific URL — psacertified.org]` lists certified products. DICE integration is variable per vendor (§6).
- **NIST SP 800-193 (Platform Firmware Resilience Guidelines, 2018).** Lead-authored by **Andrew Regenscheid** + collaborators at NIST. References DICE as one approach for hardware-rooted recovery + protection capability. Not prescriptive about which primitive to use; treats DICE as one of the options for resilient firmware identity. **John Kelsey** at NIST has contributed to the broader hardware-rooted-crypto guidance lineage `[unverified specific document attribution]`.
- **NIST IR 8259 family (IoT cybersecurity, 2020+).** Doesn't mandate DICE but treats hardware-rooted device identity as a baseline IoT security capability. NISTIR 8259A (core baseline) calls out device identification + device configuration + data protection + logical access + software update + cybersecurity-state awareness as the six core capabilities; DICE-derived identity addresses the first.
- **EU CRA (Regulation 2024/2847, the Cyber Resilience Act).** Product-cybersecurity requirements compatible with DICE-based attestation; specific mandate level `[unverified specific CRA Annex I detailed requirements as of 2026-05]`. The CRA's broad sweep — connected products must have secure-by-design properties including authenticated update mechanisms — pushes DICE-class identity into the EU regulatory landscape implicitly.
- **AI-edge devices.** As on-device LLM inference proliferates (Apple Intelligence on iPhone, on-device Gemini on Pixel, edge-LLM inference on automotive infotainment), device-attestation for "is this really the device class + firmware version I expect to be running this model?" matters for content-moderation policy enforcement, DRM on inference outputs, and remote-attestation-of-AI-inference. DICE-class hardware roots are part of the substrate. Cross-link `[[reference-confidential-computing]]` (Apple PCC + NVIDIA H100 CC for the GPU-tier sibling problem).

## 12. Honest failure modes — load-bearing

DICE is a sound cryptographic primitive in a constrained-resource regime. It is also a partial solution. Treating it as a complete answer to device identity at embedded scale is the recurring mistake.

**UDS extraction breaks everything.** Single load-bearing dependency. Defenses must be physical (tamper-evident packaging, anti-probing meshes, anti-glitching circuits) AND cryptographic (side-channel-hardened OWF, constant-time HMAC, blinding on ECC operations). PSA Certified L3 is the certification tier that addresses physical attacks; L1 and L2 do not. Side-channel attacks are real (EUCLEAK 2024 demonstrated the threat extends to FIDO2-certified hardware, and DICE-class implementations are not generally as hardened as FIDO-certified secure elements). No single defense tier suffices.

**DICE without measured boot is incomplete.** DICE derives CDI from measurements. If no layer takes measurements (e.g., a lazy implementation that does `CDI_L1 = HMAC(UDS, fixed_constant)` and skips the L1-image-hash step), CDI is just a static derivation of UDS — no boot-state binding. The cryptographic shape is right; the security property is missing. Spec compliance review at chip-vendor due-diligence time should verify measurement inclusion.

**Reference value rotation is operationally painful at IoT scale.** Firmware updates change measurements → all alias keys derive different values → verifiers must update reference values + per-device records. Fleet of 10M devices over the lifetime of 50 firmware versions = 500M reference-value records to manage. This is a database + observability + operations problem. The cryptography is the easy part; the operations is where deployments fail.

**Manufacturer-root-of-trust distribution problem.** Verifiers must trust manufacturer root certificates. Compromise of the manufacturer signing key = ability to forge any device identity from that manufacturer's chip family. Same problem class as WebPKI roots, but worse: no CA/Browser Forum, no transparency logs (Certificate Transparency analog for IoT is in research but not deployed), no easy revocation path for manufacturer roots once a chip is shipped.

**DICE-X / advanced layering adoption is uneven.** Vendors implement L0/L1/L2 differently. Cross-vendor interoperability is poor. Each ecosystem (Cerberus / Sphere / Pluton / PSA / proprietary) is its own thing with its own verifier infrastructure. The IETF RATS framework (RFC 9334) tried to define a generic attestation evidence + verification model — adoption is limited as of 2026.

**Implementation bugs in low-resource crypto.** Constrained MCUs may use weak OWF implementations to save flash. Some chips ship without side-channel hardening on AES (the underlying primitive for HMAC). SHA-256 + HMAC are the baseline; verify per chip. Some embedded crypto libraries have shipped with subtle constant-time-violation bugs in HMAC across the years `[unverified specific CVE-list — verify against mbedTLS / wolfSSL / cryptoauthlib bug trackers]`. SoC vendor crypto IP varies in quality.

**End-of-life devices stay deployed.** Azure Sphere discontinuation 2024 left legacy devices in field. Manufacturer support stops; devices continue operating. DICE-based identity becomes orphaned — no path to rotate the manufacturer trust root, no path to refresh per-device certificates, no security updates. Verifiers eventually have to choose: trust EOL devices indefinitely (security debt accumulates), or refuse them (operational loss). Cross-link `[[reference-embedded-device-hardening-playbook]]` §EOL.

**Closed-loop verifier infrastructure.** Some vendors lock attestation verification to their own cloud (Azure Sphere → Microsoft Azure Sphere Security Service only; some Pluton-based attestation flows to Microsoft endpoints only). Multi-vendor verifier interop is the open ecosystem need. The IETF RATS framework (RFC 9334, lead-authored by **Henk Birkholz** + collaborators) and the Confidential Computing Consortium's Veraison project (championed by **Mike Bursell** at CCC + Profian) is the explicit attempt at vendor-neutral attestation verification, but adoption is slow. **David Wheeler** (Intel, TCG, longtime open-attestation-architecture contributor `[unverified specific role]`) has written on the verifier-side architecture problem; **Andrew Robbins** at Microsoft has contributed on the Pluton + DICE composition story `[unverified specific role]`.

**AI-augmented attacks on physical hardware.** ML-based side-channel and EM analysis advances faster than embedded-side-channel defenses. The defender-attacker gap is widening on this front. EUCLEAK 2024 demonstrated extraction of ECC keys via EM analysis with publicly-available equipment. A defender-side equivalent in DICE-class hardware — automated detection of side-channel-leaky implementations during PSA certification — is research-stage, not deployed.

**DICE provisioning at scale is hard.** Per-device UDS injection + per-device cert issuance at 10M-units/month manufacturing rate has tooling + supply-chain implications. Factory provisioning stations are themselves attack surface (compromise the station, get any device's UDS at provisioning time, or forge provisioning records). Provisioning-station security has not received the same scrutiny as in-device security; in 2024-2026 disclosures, several embedded supply-chain compromises have traced to factory-tooling compromises rather than device-internal vulnerabilities `[unverified specific disclosure citations — verify against Eclypsium / Binarly / Forescout reporting 2024-2026]`.

**Implicit attestation is pass/fail only.** Verifier learns: this device's signed evidence verifies against the expected alias key, or it doesn't. Verifier does not learn what differs if it doesn't verify. For onboarding gates this is fine; for IR forensics ("the device is showing tampered identity — what specifically changed?") this is insufficient. Explicit attestation (PSA IAT with measurements in the token, TPM-style PCRs) gives forensic transparency at the cost of additional flash + complexity. Choose per use case.

**PUF-based UDS is a separate trade-off.** Some chips derive UDS from a physically unclonable function (PUF) rather than injecting it at manufacture. Eliminates the factory-provisioning-station attack surface for UDS storage. Trades a different risk: PUF stability over temperature / aging / supply voltage, plus the open question of how reproducibly the PUF reveals "the same" UDS across the device's lifetime. PUF + helper-data + error-correction is the standard construction; the helper data is stored in non-secret storage and is itself a side-channel candidate `[unverified specific PUF-side-channel research citations]`.

## 13. Cross-link cluster

- `[[reference-hardware-attestation-chains]]` — parent attestation discipline. §4 brief DICE mention is the seed for this doc; §11 reference-value-management applies here; §13 attack corpus (EUCLEAK, TPM-Fail) cross-references the threat model here.
- `[[reference-embedded-device-hardening-playbook]]` — operations playbook for embedded products. §EOL connects to §12 orphan-cert problem; §UDS-provisioning connects to §10.
- `[[reference-rtos-embedded-os]]` — RTOS attack surface, TF-M deep coverage, Cortex-M security architecture. §6 here covers DICE-PSA composition.
- `[[reference-hsm-operational-discipline]]` — manufacturer-root key custody, HSM tier of the trust chain that signs DICE alias-key endorsements. UDS provisioning is the IoT-scale analog of HSM key ceremony.
- `[[reference-confidential-computing]]` — Apple PCC + NVIDIA H100 CC + TEE attestation. Sibling primitive at the server / data-center tier; DICE is the IoT-tier counterpart.
- `[[reference-hardware-side-channels]]` — TPM-Fail, EUCLEAK, ChipWhisperer methodology, power analysis, fault injection. Threat model in §9 references this catalog directly.
- `[[reference-firmware-embedded-security]]` — bootloader + firmware update + secure-boot enforcement. DICE composes with verified-boot from this discipline.
- `[[reference-webauthn-fido2-passkeys]]` — FIDO attestation formats, EUCLEAK 2024 detailed coverage. The side-channel attack class that hit Infineon SLE78/SLE97 applies to DICE-class hardware too.
- `[[reference-zero-trust-workload-identity]]` — device posture as ZT trust signal. DICE-derived identity feeds into ZT enrollment at the IoT tier.
- `[[reference-cryptography]]` — HMAC, HKDF, ECDSA P-256, Ed25519 — the primitives DICE uses. Verify implementation quality of these on constrained MCUs.
- `[[reference-post-quantum-cryptography]]` — alias-key derivation will eventually need PQ-resistant signature algorithms (ML-DSA / SLH-DSA). Flash budget on Cortex-M is a hard constraint for SLH-DSA-class signatures. Migration path is open.
- `[[reference-cicd-supply-chain]]` — firmware build provenance + reproducible builds. Reference-value computation depends on reproducible firmware builds; build-system compromise = reference-value compromise.
- `[[reference-detection-engineering]]` — verifier-side attestation-failure observability. Sudden spikes in attestation failures are detection signal.

## Authoring notes

Author: Claude (Opus 4.7 / 1M-context, autonomous), 2026-05-21. Sibling to `[[reference-hardware-attestation-chains]]` shipped 2026-05-20 iter 10. Bridges the gap between parent attestation discipline and embedded-platform-specific deployment. Voice: imperative, sparing aphorisms (count: 2 across doc — "UDS protection is load-bearing" §3; "The cryptography is the easy part" §12). `[unverified]` flags concentrated in spec-version / vendor-product / specific-date claims where primary-source URL verification was out of scope. Next-shift candidates: (a) PUF-based UDS deep-dive sibling (separate doc — distinct primitive class); (b) IETF RATS / Veraison verifier-side infrastructure as separate cross-platform attestation-verification doc; (c) factory-provisioning-station threat model as embedded-supply-chain spinoff.
