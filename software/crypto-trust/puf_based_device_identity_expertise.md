# PUF-Based Device Identity Expertise

Status: NEW 2026-05-21. Sibling to `dice_embedded_device_identity_expertise.md` (which §3 references OTP-fused and write-once-flash UDS sources only in passing). This doc is the depth-treatment of **Physical Unclonable Functions (PUFs) as an alternative UDS-generation primitive** — deriving the per-device root secret from intrinsic silicon variation instead of injecting a plaintext secret into eFuses.

Audience: Claude on future shifts, embedded-systems security engineers, SoC vendors, IoT-platform teams evaluating PUF-vs-OTP-vs-flash for the device-identity root.

---

## 1. Why this doc exists — and how to read it

The structure of this document:

- §2: silicon physics of PUF types
- §3: helper-data + fuzzy extractor cryptographic construction
- §4: PUF in the DICE chain
- §5: real deployments
- §6: attacks
- §7: strong vs weak PUFs
- §8: standards + certification
- §9: comparison to alternative UDS sources
- §10: operational discipline
- §11: 2024-2026 currency
- §12: honest failure modes (load-bearing)
- §13: worked example
- §14: cross-link cluster


The Unique Device Secret (UDS) is the cryptographic root of device identity. In DICE (TCG spec), every certificate, every measurement, every attestation chain traces back to the UDS via a one-way function. If the UDS leaks, the device's identity is permanently compromised — no software update fixes it.

`dice_embedded_device_identity_expertise.md` §3 enumerates UDS storage options as "factory-injected in OTP fuses or write-once flash." Both store a plaintext secret in silicon. Both are attackable by an adversary with physical access — focused-ion-beam decap, layer-by-layer microscopy, electrical probing of eFuse arrays. The decap-and-dump path is well-documented in the failure-analysis literature, and commercial reverse-engineering labs offer it as a service.

A Physical Unclonable Function takes a different approach. Instead of injecting a secret, derive it on every boot from intrinsic manufacturing variation:

- transistor threshold-voltage mismatch
- SRAM startup-state preference
- ring-oscillator frequency dispersion
- propagation-delay imbalance between symmetric paths
- gate-oxide thickness variation
- doping concentration fluctuations

The variation is determined by atomic-scale fabrication noise — outside the control of even the chip's manufacturer once the wafer leaves the fab. The secret is **never stored in non-volatile memory**. It exists only during the brief window of boot, when the PUF readout circuit is active. After the boot ROM extracts and uses the UDS, the PUF readout state is zeroed and the access path to the PUF circuit is locked until next power cycle.

The structural property: physical extraction requires **non-destructive PUF readout at the exact conditions** (temperature, voltage, aging state) the chip was characterized under. This is fundamentally harder than reading static eFuses. You cannot decap, store, and analyze offline — the act of decapping changes the substrate, and the PUF response changes with it. The defender gets a structural defense the attacker cannot easily route around.

The cost: PUFs are noisy. Raw readings vary 5-15% bit-by-bit across boots. The PUF is not a key — it is a noisy source from which a stable key is extracted via published helper data and a fuzzy extractor. The construction is information-theoretic but the implementation is full of footguns. Helper-data leakage, ML modeling attacks on strong PUFs, aging drift, and temperature extremes have each broken specific deployments.

This doc covers the silicon physics, the fuzzy-extractor construction, real deployments, the attack literature, and the operational discipline a vendor must apply to ship a PUF-based UDS responsibly.

---

## 2. PUF types — the silicon physics taxonomy

PUFs differ in **what physical phenomenon they measure**. Each type has distinct security properties, modeling attack susceptibility, and engineering trade-offs.

**SRAM PUF.** Uncommitted SRAM cells settle to a 0 or 1 at power-on based on the mismatch between the two cross-coupled inverters.

Each cell has a process-determined preference; collectively the startup pattern is per-chip-unique and per-chip-stable. The most-deployed PUF type in production silicon.

Pioneered for commercial use by Intrinsic-ID (founded out of Philips/NXP research circa 2008, acquired by Synopsys 2024 `[unverified specific date]`).

SRAM-PUF startup characterization was studied in depth by **Daniel Holcomb** (UMass Amherst, IEEE Trans. Computers 2009).

His work established that ~85-95% of SRAM cells exhibit stable startup preference, with the remainder being "fuzzy" cells averaged out by error correction.

**Ring Oscillator (RO) PUF.** Layout-identical ring oscillators have slightly different frequencies due to process variation in transistor delays. Pairwise frequency comparisons yield stable bits. Introduced by **G. Edward Suh and Srinivas Devadas** (DAC 2007). Larger silicon area than SRAM PUF but simpler to add to a design that doesn't already include SRAM at the right location.

**Arbiter PUF.** Two symmetric signal paths race through a series of switches; an arbiter latch decides which arrived first.

The race outcome depends on minute timing variation along the paths. A challenge string selects the switch configuration; many challenge-response pairs (CRPs) are derivable from a single PUF instance.

This made arbiter PUFs initially attractive for authentication protocols.

However, **Ulrich Rührmair** and collaborators (CCS 2010, "Modeling Attacks on Physical Unclonable Functions") showed that linear additive delay models can be learned from a few thousand CRPs, enabling response prediction for unseen challenges.

Production arbiter PUFs require XOR-arbiter or feed-forward variants, which raise the modeling-attack cost but remain attackable with sufficient ML compute.

**Optical PUF.** **Ravi Pappu's MIT thesis (2001)** — the foundational PUF work. Light shone through an inhomogeneous medium (epoxy with embedded scatterers) produces a speckle pattern unique to the medium. The pattern is sensitive to wavelength, angle, and the exact disposition of scatterers, so cloning requires reproducing the medium atom-by-atom. Foundational but not practical at IoT scale — requires a camera, light source, and mechanical alignment. Cited in nearly every subsequent PUF paper.

**Coating PUF.** Capacitive measurements through a deposited dielectric layer with random doping. **Pim Tuyls, Boris Škorić, and collaborators** (CHES 2006) — a deposited tamper-evident coating whose capacitance depends on the random distribution of metal/dielectric particles. Has the anti-invasive-attack property: removing the coating to probe the chip destroys the PUF response. Used in higher-assurance smart cards.

**Memory-based PUFs beyond SRAM.** DRAM-startup PUF (decay rate of un-refreshed cells), flash-startup PUF (program/erase variability), butterfly PUF (cross-coupled latches similar to SRAM but explicitly added). Each leverages the same principle — exploit existing memory technology's process variation — with different reliability and cost trade-offs.

**Emerging substrates.** Carbon-nanotube PUFs, memristor PUFs, photonic PUFs. Research-grade as of 2026; not in production silicon.

The decision tree: SRAM PUF if you already have SRAM at the right location and want to minimize area; RO PUF if you need a self-contained primitive; arbiter PUFs only with XOR/feed-forward wrapping and only if you genuinely need CRP-style authentication (most DICE deployments do not); coating PUF for high-assurance smart cards where anti-invasive properties dominate cost.

---

## 3. The helper-data construction — how PUFs become reliable secrets

Raw PUF response is noisy. A typical SRAM PUF has 5-15% bit-error rate (BER) across power cycles — the same cell that produced 0 last boot might produce 1 this boot if the local temperature shifted, the supply voltage drooped, or the cell happened to be near its decision threshold. You cannot use a noisy bit string as a cryptographic secret; encryption with a slightly different key produces gibberish on decrypt.

The solution is the **fuzzy extractor**, formalized by **Yevgeniy Dodis, Leonid Reyzin, and Adam Smith** in their Eurocrypt 2004 paper "Fuzzy Extractors: How to Generate Strong Keys from Biometrics and Other Noisy Data." Their construction is information-theoretic: publish auxiliary data (the "helper data") that, combined with a noisy reading w', deterministically reproduces the same key R that was extracted from the original reading w, provided w' is within Hamming distance t of w. The helper data leaks bounded information — the construction guarantees that even given the helper data, the residual min-entropy of R is high enough that R is indistinguishable from random.

The Dodis-Reyzin-Smith construction has two stages:

**Secure sketch.** Reduces the noisy reading to a stable value. Given w, output a sketch s such that anyone with s and any w' close to w can recover w exactly. The min-entropy loss is bounded by the entropy of the error pattern, not the entropy of w.

**Strong extractor.** Reduces the stable but possibly non-uniform value to a uniformly distributed key. Apply a randomness extractor (universal hash, HKDF, BLAKE2 with a random salt) to the recovered w → R.

The most common secure-sketch instantiation is the **code-offset construction**. At enrollment: pick a random codeword c from an error-correcting code C, compute helper data s = w XOR c, store s in flash. At reproduction: read noisy w', compute w' XOR s = c XOR (w XOR w') = c plus error. Decode this with C's decoder to recover c. Then w = s XOR c. Apply the strong extractor to w.

The error-correcting code choice matters. Concatenated codes (e.g., BCH + repetition) are common; the code rate trades off helper-data size and error tolerance. For an SRAM PUF with ~10% BER and a 128-bit final key, expect helper data on the order of 1-4 KB and ~10-50% boot-time CPU overhead for the decode + extract pipeline.

**Index-based syndrome coding (IBS).** An alternative that publishes indices of "reliable" cells instead of an XOR sketch. The idea: at enrollment, identify cells that read consistently across multiple reads at multiple voltage/temperature corners. Publish only the indices of reliable cells as helper data; the values of those cells become the PUF response. Avoids the XOR-based sketch's leakage in some attack models but reduces the effective PUF response length (only the reliable subset is used). **Yu and Devadas** (DATE 2010) and follow-up work explored IBS variants.

**Soft-decision decoding.** Rather than treating each PUF bit as a hard 0/1, treat it as a probability based on multiple reads. Soft-decision decoders (e.g., soft-input BCH) achieve better error-correction performance than hard-decision decoders. Cost: more reads at boot, more decoder complexity. Used in some Intrinsic-ID Quiddikey configurations.

**Reverse fuzzy extractors.** Standard fuzzy extractors put the heavy decoding on the device (where the PUF lives). Reverse fuzzy extractors invert this: the verifier does the decoding, the device just sends a noisy reading. Useful when devices are resource-constrained but verifiers are not. Trade-off: more bandwidth between device and verifier; the noisy reading must be transmitted protected.

Helper data is conventionally stored in unprotected flash. The fuzzy-extractor security analysis assumes the attacker can read it. The attacker just cannot **forge** it — if the attacker can modify helper data, they can bias the recovered key. Production designs sign the helper data with a key derived from a different (or hardware-bound) source, creating a chicken-and-egg problem that is usually solved by storing a hash of the helper data in a small OTP fuse region. The helper data itself is bulky; only its hash is hardware-anchored.

**Becker's lattice-PUF construction** (Georg Becker, CHES 2017+) extends the helper-data idea with lattice-based learning-with-errors hardness assumptions, providing modeling-attack resistance for strong-PUF use cases.

---

## 4. PUF-based UDS in DICE / device-identity context

Mapping to the DICE chain from `dice_embedded_device_identity_expertise.md` §3:

```
UDS = StrongExtractor(SecureSketch(PUF_response, helper_data))
L1_CDI = OneWayFunction(UDS, L1_measurement)
L2_CDI = OneWayFunction(L1_CDI, L2_measurement)
...
```

The PUF replaces the OTP-fused UDS. The rest of the chain is unchanged. From DICE's perspective, the UDS is a 256- or 384-bit secret; whether it came from eFuses or a fuzzy extractor over an SRAM-PUF reading is invisible to the upper layers.

**Advantage vs OTP UDS.** Physical extraction requires non-destructive PUF readout under the exact characterization conditions. Decap + microscopy on eFuses is a well-developed commercial service; non-destructive PUF readout requires more specialized capabilities and often fails because the act of accessing the cell disturbs the response. Note this is a **resistance multiplier, not an absolute defense** — see §6 for the attack landscape.

**Advantage vs hardware-encrypted-flash UDS.** No plaintext secret exists in any non-volatile medium. The encrypted-flash approach still has a chip-bound key somewhere; PUF eliminates that intermediate.

**Disadvantage: helper-data is semi-secret at best.** Information-theoretic analyses bound the min-entropy loss given helper data, but side-channel attacks during fuzzy-extractor evaluation and helper-data manipulation attacks consistently extract more than the theoretical bound. Treat helper data as semi-confidential — store it on the device, do not publish it externally, and integrity-protect it.

**Disadvantage: aging-induced drift.** PUF response shifts with NBTI/PBTI aging, hot-carrier injection, oxide degradation. Over 10-15 years of field deployment, the helper data sized for ~10% BER may face a ~15-20% BER and exceed the error-correction budget. Long-lived devices need periodic helper-data refresh; if the device boots cleanly, generate a new sketch from the current PUF reading using the recovered key as anchor.

**Timing in the boot flow.** The PUF readout must occur **before** the L1 measurement chain begins, otherwise an attacker who alters L1 could observe the PUF readout and learn the UDS. Most production designs gate PUF circuit access behind a one-shot fuse that locks after the first ROM stage reads it — same property as the OTP UDS.

---

## 5. Real PUF deployments

**Intrinsic-ID Quiddikey / BroadKey.** SRAM-PUF productized as IP cores. Licensed into many SoCs: NXP, Renesas, Microchip, and others integrate Quiddikey under license. The Intrinsic-ID founding team grew out of Pim Tuyls's research at Philips Research (the Tuyls–Škorić coating-PUF lineage). Acquired by Synopsys in 2024 `[unverified specific date]`. The acquisition consolidates the PUF IP licensing market.

**Maxim Integrated DS28E50 + DS28E84.** Secure ICs with PUF-derived keys. Small form factor; intended for accessory authentication, consumables management, and supply-chain attestation. Maxim is now part of Analog Devices.

**NXP A71CH / SE050 secure elements.** Modern variants incorporate PUF-class primitives `[unverified specific generations and implementations]`. Used in EdgeLock SE series for IoT identity.

**Microsoft Azure Sphere Pluton chip.** Pluton's secure MCU on Azure Sphere uses PUF-class primitives as a root of trust `[unverified specific implementation — Microsoft does not publish full Pluton silicon details]`. Pluton has subsequently been integrated into AMD Ryzen and Qualcomm SoCs as a Windows security processor.

**Apple Secure Enclave (UID derivation).** Apple's Secure Enclave Processor (SEP) on A-series and M-series chips uses a per-device UID. Apple has stated the UID is "fused into the SoC at manufacturing" but has not published whether the fusing is conventional OTP or PUF-class `[unverified specific approach — Apple Platform Security Guide is silent on the underlying primitive]`. Independent research (Tarjei Mandt + others on iPhone teardowns) suggests PUF-class primitives are plausible but unconfirmed.

**Google Pixel Titan M2 / Tensor G4 security IP.** Google's security chips use PUF-class primitives for device identity `[unverified specific approach — Google does not publish full Titan M2 silicon details]`.

**Xilinx/AMD Zynq UltraScale+ MPSoC.** Includes a PUF as an option for AES-key derivation (the "PUF helper data" stored in eFuses for sketch operation). Documented in the device security user guides. Provides a worked example of PUF + DICE-style chain in an FPGA SoC. The PUF is one of several key sources the configuration security unit (CSU) can select for bitstream decryption.

**Maxim DS28C36.** ChipDNA PUF technology — Maxim's branding for their SRAM-PUF-derived key generation in DeepCover secure ICs. Used widely in printer-cartridge authentication, medical-device accessory authentication, and similar accessory-attestation use cases.

**Microchip CryptoAuthentication / ATECC608.** Secure element with PUF-class key storage `[unverified specific PUF implementation — Microchip documentation describes "tamper-resistant key storage" without naming PUF specifically]`.

**Renesas Synergy / RA family.** Selected Renesas microcontrollers ship with Intrinsic-ID Quiddikey under license. The PUF-derived key wraps the device's secret store; secrets stored in flash are encrypted under the PUF-derived KEK.

**Lattice Semiconductor MachXO3.** Low-power FPGA with PUF for bitstream authentication.

---

## 6. Attacks on PUFs

**Machine-learning modeling attacks.** **Ulrich Rührmair et al.** (CCS 2010) showed that arbiter PUFs are vulnerable to linear-additive-delay model learning.

A few thousand challenge-response pairs train a model that predicts unseen CRPs with >95% accuracy.

Subsequent work extended the attack:

- XOR-arbiter PUFs: Becker 2015 demonstrated polynomial-time attacks at reasonable XOR depth.
- Feed-forward arbiter PUFs: Tobisch and Becker 2015.
- Some controlled PUF variants: subsequent literature 2017+.

**The practical consequence: strong PUFs used as authentication primitives without a hash-function wrapper are broken.**

Many published authentication protocols based on raw arbiter PUFs are insecure against an attacker who can observe CRPs.

**Side-channel attacks on PUF helper-data evaluation.** Becker and collaborators (CHES 2015 onward) demonstrated power-analysis and EM-analysis attacks during fuzzy-extractor evaluation.

The error-correction step processes the helper data combined with the PUF response; instantaneous power consumption leaks intermediate bits.

Mitigations:

- mask the helper data evaluation
- blind the error-correction step
- use fuzzy extractors specifically designed for side-channel resistance
- isolate the fuzzy-extractor accelerator in a power-domain shielded from external measurement

**Side-channel attacks on PUF readout.** Power analysis during PUF response generation can leak partial response bits. SRAM PUFs are particularly susceptible because the power signature at startup correlates with the count of 1-vs-0 cells in a power-domain. **Lejla Batina** (Radboud + others on embedded crypto side-channels) has contributed to the broader side-channel literature applicable to PUF readout `[unverified specific PUF-focused publications]`.

**Photon-emission analysis.** Switching transistors emit near-infrared photons. **Tajik et al.** (CCS 2017, "Physical Vulnerabilities of Physically Unclonable Functions") demonstrated photon-emission analysis on arbiter PUFs — backside imaging of the chip during PUF operation reveals which path won the race, completely breaking the PUF.

**Helper-data manipulation.** If an attacker modifies stored helper data, the fuzzy extractor outputs a different key — but a key the attacker may now know or control. Defense: integrity-protect helper data, ideally with a MAC keyed by a separate hardware-anchored secret.

**Cloning attacks.** Raw PUF cloning is physics-bound impossible (atomic-scale variation cannot be replicated). But **ML-modeled PUFs become soft-clonable**: the attacker holds a software model that responds to any challenge identically to the original PUF. For authentication protocols this is indistinguishable from physical cloning.

**Aging-acceleration attacks.** Force premature aging via voltage/temperature stress to drift the PUF response toward attacker-favored patterns. Theoretical attacks exist `[unverified specific feasibility in field conditions]`; practical demonstrations are limited.

**Invasive probing post-decap.** For coating PUFs the act of decapping destroys the response. For SRAM PUFs the decap process can damage the cells in question, but skilled labs can in some cases probe SRAM startup states post-decap. The Rührmair group has discussed this in workshop venues. The empirical question — what fraction of cells survive decap with their startup preference intact — is poorly documented in open literature because most relevant work is under vendor NDA or commercial confidentiality.

**Fault-injection attacks.** Voltage glitching, clock glitching, EM fault injection during the PUF readout or fuzzy-extractor evaluation can corrupt intermediate state in attacker-favorable ways. **Bar-El et al.** (Proc. IEEE 2006) laid the foundations; subsequent work on Differential Fault Analysis (DFA) of PUF systems has shown that injecting faults during the error-correction step can leak helper-data-conditioned secret bits. Production-grade defenses require redundant computation, signature verification of intermediate state, and tamper-detection circuits.

**Combined attacks.** The most effective real-world PUF attacks combine modalities:

- photon emission to narrow down the response space
- ML modeling on observed CRPs
- side-channel measurement during fuzzy-extractor evaluation
- helper-data manipulation to bias the recovery
- fault injection to corrupt the integrity check

Defense against any single modality is necessary but not sufficient.

**Reliability-based attacks.** Even weak PUFs can be attacked by observing which bits are reliable vs. unreliable across many reads. The reliability pattern leaks information about the underlying physical parameters. **Becker** showed in 2015 that this enables modeling attacks on XOR arbiter PUFs that were previously thought modeling-resistant.

Cross-link: `[[reference-hardware-side-channels]]` covers the broader side-channel attack landscape applicable to PUF readout and fuzzy-extractor evaluation.

---

## 7. Strong vs weak PUFs

The taxonomy matters because it determines what attacks are relevant.

**Strong PUF.** Exponential CRP space; many challenges per device. Useful in challenge-response authentication protocols where each challenge is fresh. **Vulnerable to ML modeling attacks.** Arbiter PUFs and their variants are strong PUFs. Production use as an authentication primitive without a controlled-PUF wrapper is broken.

**Weak PUF.** Small number of responses per device — often a single fixed response. The chip outputs the same secret on every readout (with noise removed via fuzzy extractor). Used as a key source, not as a CRP-style auth credential. SRAM PUFs are weak PUFs in practice (the "challenge" is just the power-on sequence; the response is the full startup pattern).

**DICE typically uses weak PUFs.** The UDS is one secret per device. The downstream DICE chain provides freshness via measurements, not via CRP exchange.

**Authentication protocols typically want strong PUFs** for the freshness property — but the ML-modeling result means the design space is constrained. Solutions:

**Controlled PUFs** (Blaise Gassend, Dwaine Clarke, Marten van Dijk, Srinivas Devadas — CHES 2002 "Silicon Physical Random Functions" and follow-ups 2008).

Wrap a strong PUF in a hash function:

1. User provides challenge c.
2. Chip computes c' = H(c, nonce).
3. Chip applies c' to the underlying PUF, gets response r.
4. Chip returns H(r, nonce).

The wrapper hash obscures the linear relationship between challenges and responses that ML attacks exploit. Adds latency but defends against modeling — the attacker can no longer observe the raw arbiter PUF challenges, only their hashes.

**Lattice-PUF constructions.** Becker and collaborators have proposed PUF designs whose modeling problem reduces to learning-with-errors-style lattice problems, conjectured hard. The construction inserts a lattice-LWE step between the raw PUF response and the exposed CRP output. Provably modeling-resistant under standard lattice assumptions; not yet at production scale as of 2026.

**Multi-PUF aggregation.** Combine outputs of multiple PUFs of different types — an SRAM PUF XOR'd with an RO PUF XOR'd with an arbiter PUF, for instance. Modeling all of them simultaneously is harder than modeling one. Practical complexity grows quickly in both area and ML attack difficulty.

**Reconfigurable PUFs.** PUFs whose mapping can be re-randomized by reconfiguring the underlying circuit (e.g., changing the switch-block configuration in an FPGA-based PUF). Each reconfiguration creates a new PUF instance, defeating long-term modeling.

**Decision criteria for weak vs strong:**

- Need one secret per device for key derivation: weak PUF.
- Need many fresh CRPs for authentication: strong PUF + controlled wrapper.
- Need long-lived authentication credentials: strong PUF + lattice or reconfigurable construction.
- Need certification (FIPS, CC): weak PUF; certifiers are more comfortable.
- Need protocol simplicity: weak PUF.

The honest summary: **if your protocol needs a strong-PUF authentication primitive, you are in 2026-research territory.** If you only need a UDS for DICE, use a weak PUF and avoid the modeling-attack quagmire. Most production PUF deployments are weak-PUF UDS use cases; very few production authentication protocols use strong PUFs directly.

---

## 8. Standards + certification

**ISO/IEC 20897.** Multi-part PUF standard. Part 1 (security requirements), Part 2 (test methodology), additional parts on family-specific specifications. Defines PUF security properties (intra-distance, inter-distance, uniformity, steadiness, randomness) and test procedures. Provides a vocabulary for vendors to specify what their PUF guarantees.

**Common Criteria evaluation profiles.** PUF-using products are evaluated under CC up to EAL5+ in the smart-card and HSM domains. Specific Protection Profiles (PPs) for PUF-based products exist `[unverified specific PP IDs]`. The PP defines the assurance the evaluation provides — but post-evaluation research has repeatedly demonstrated attacks on EAL-certified PUF products, so CC certification is necessary but not sufficient.

**FIPS 140-3 Annex E.** Allows PUF-derived keys as an approved entropy source under certain conditions, contingent on NIST SP 800-90B entropy validation `[unverified specific Annex section as of latest revision]`. The PUF is treated as an entropy source; the helper-data construction is the conditioning function; the SP 800-90B health-test requirements apply.

**NIST SP 800-90B.** Entropy-source validation. Applicable to PUF designs that claim to be entropy sources. Requires statistical tests (predictability, IID assumption testing) plus health monitoring during operation.

**TCG DICE specifications.** Do not mandate the UDS source. PUF is one valid UDS source; OTP eFuse is another; hardware-encrypted flash is a third. The DICE chain's security analysis depends on the UDS being a uniform secret of sufficient entropy — how that secret is generated is out of scope for the spec.

**EU CRA Annex I, IoT-specific standards.** As IoT device-identity requirements firm up under EU Cyber Resilience Act and similar regulations, PUF-based root-of-trust will likely be one of the named acceptable implementations `[unverified specific regulatory language as of 2026]`.

**PSA Certified (Platform Security Architecture).** ARM's certification program for IoT SoCs has profiles that accept PUF-based device identity. Multiple Cortex-M-class chips with PUF IP have achieved PSA Certified Level 2 or 3.

---

## 9. PUFs vs alternatives for the UDS-source decision

The decision a vendor or platform team faces: which UDS source for this product?

**OTP fuses (eFuses).** Factory-programmed, immutable, plaintext secret in silicon. Cheap to add (small eFuse arrays are standard cells). Extractable via decap + electrical probing or focused-ion-beam microscopy at commercial reverse-engineering labs. Suitable for most consumer-grade IoT where the threat model excludes funded physical attackers. Used by most non-PUF designs.

**PUF.** Factory-characterized (helper data generated at production test), boot-time-derived secret. Physical extraction much harder than eFuses. Helper-data leakage and ML-modeling attacks are the risks. Higher engineering cost (need fuzzy extractor logic, error correction, range/aging-aware enrollment). Suitable when threat model includes physical-attacker resistance.

**Hardware-tied flash with hardware encryption.** Secret stored in flash encrypted under a chip-bound hardware key (which itself must be stored somewhere — often a small eFuse region). Better than plaintext flash; worse than PUF because the encryption key is still extractable from its eFuse region. Used when flash is the only available non-volatile substrate and adding eFuses or PUF IP is impractical.

**External secure element.** Move the secret into a separate SE chip (which itself uses one of OTP/PUF/encrypted-flash internally). Cascades the same question one chip outward. Adds bill-of-materials cost and supply-chain complexity. Provides isolation: compromising the main SoC does not compromise the secret. Used in payment terminals, automotive security ECUs, and high-assurance industrial systems.

**TPM 2.0.** Off-SoC TPM chip with its own attested identity. Similar trade-offs to external SE; standardized interface.

**Decision matrix (rough heuristics):**

| Threat model includes | Recommended UDS source |
|----------------------|------------------------|
| Software-only attacker | eFuse OTP acceptable |
| Casual physical (lost device) | eFuse OTP or PUF |
| Funded reverse-engineering lab | PUF strongly preferred |
| Nation-state physical adversary | PUF + tamper-evident packaging + external SE |
| Long-lived device (>10 years) | PUF with helper-data refresh + aging-aware enrollment |
| Extreme temperature range | PUF with range-aware enrollment, larger ECC budget |
| High volume + cost-sensitive | eFuse OTP (lower production-test time) |
| Multi-sourcing requirement | eFuse OTP (PUF IP vendor lock-in is real) |
| FIPS 140-3 certification needed | PUF with SP 800-90B-validated entropy |

**Cost trade-off summary.** Per-chip cost delta of PUF vs. eFuse OTP is typically dominated by silicon area, production-test time (~0.1-1 second additional), and IP licensing fee per unit. Licensing dominates at high volumes.

**Multi-sourcing concern.** PUF IP is vendor-specific; switching PUF vendors mid-product-line requires re-architecting the boot ROM, re-enrollment infrastructure, and key-derivation pipeline.

---

## 10. Operational discipline

**Enrollment.** At manufacturing test, each chip's PUF is characterized: read the response, compute the helper data, compute and store the helper-data integrity hash in a small OTP region. The helper data itself goes into flash (typically a dedicated locked partition). Per-chip variance means there is no "golden" helper data; each chip is individually enrolled. This adds production-test time — budget 0.1-1 second per chip depending on PUF size and error-correction code.

**Reprovisioning.** If helper data is lost or corrupted (flash failure, intentional erase), can the chip be re-enrolled? Some PUF designs support multiple enrollment rounds (the PUF response is the same, so a new helper data set can be generated). Others use a fuse to disable re-enrollment after first use, preventing an attacker from re-enrolling a stolen chip with their own helper data. Design choice: fuse-lock for rollback-prevention vs. re-enrollable for field-recoverability. The fuse-lock choice is strictly more secure but eliminates recovery paths.

**Aging refresh.** PUF response drifts with age — NBTI, PBTI, hot-carrier injection slowly shift transistor characteristics. Over 10-15 years the bit-error rate can grow from 10% to 15-20%, exceeding error-correction budgets sized for the initial BER. Long-lived devices need periodic helper-data refresh: at boot, recover the key using existing helper data, then generate fresh helper data from the current PUF reading anchored to the recovered key, then overwrite the stored helper data. Some implementations automate this; others require explicit return-to-factory service.

**Temperature-extreme handling.** A PUF characterized at 25°C may produce a response at -40°C (or +85°C) that differs enough that fuzzy extraction fails. Industrial and automotive deployments require **range-aware enrollment**: characterize the PUF at multiple temperature corners, generate helper data that accommodates the union of response variations. This costs more bits of helper data and more error-correction overhead. Skipping this step is a common cause of field failures — devices that work in lab conditions but boot-fail in cold-weather field deployment.

**Supply-voltage variation.** PUF response depends on supply voltage. Brown-out events during boot, voltage droop under load, and voltage regulator tolerance all matter. Production designs include voltage monitoring and abort PUF readout if Vdd is outside the characterization window. This delays boot under abnormal conditions, which is the correct trade-off — better to retry than to derive a wrong UDS.

**Pre-boot PUF readout window.** The PUF must be read **once**, early in ROM, and the response (and intermediate fuzzy-extractor state) must be cleared from memory before any non-ROM code executes. Otherwise a compromised L1 boot stage could observe the PUF readout. Mainstream production silicon gates PUF circuit access behind a one-shot fuse that locks after the first read.

**Helper-data integrity.** Sign or MAC the helper data with a key derived from a chip-bound primitive (OTP-stored hash of helper data is the common pattern). Unsigned helper data is a soft target — modifying it biases the recovered UDS.

**Manufacturing-test attack surface.** The production-test fixture has full access to the PUF response during enrollment characterization. A compromised test fixture could log responses, enabling later impersonation of any chip that passed through it. Defense: minimize test-fixture data retention, sign per-chip enrollment records, audit fixture access logs. The supply-chain assumption that the chip vendor's test floor is trusted is load-bearing — if it isn't, the PUF advantage is voided.

**Key versioning + rotation.** PUF-derived UDS is by construction immutable (same PUF → same UDS, modulo aging refresh). Key rotation at the UDS layer is impossible without re-enrollment. The DICE chain accommodates this by deriving rotatable child keys; treat the UDS as the unrotatable anchor and rotate downstream.

**Secure boot interaction.** PUF-derived UDS is independent of secure-boot signature verification. Both must succeed for a clean boot: secure boot verifies the code integrity; PUF readout produces the identity secret. A code-signing-key compromise does not compromise the UDS; a PUF compromise does not bypass secure boot. Defense-in-depth.

**Provisioning record retention.** Enrollment metadata typically lives in a manufacturing-execution system (MES) for warranty and traceability. Treat the MES as a high-value target.

---

## 11. 2024-2026 currency

**Synopsys + Intrinsic-ID acquisition (2024).** `[unverified specific date]` Consolidates the dominant SRAM-PUF IP into a single EDA-vendor portfolio. Reduces vendor diversity; raises supply-chain concentration risk. Synopsys now licenses Quiddikey and related PUF IP to most SoC vendors that want PUF-based UDS.

**PSA Certified PUF profiles maturing.** ARM-based Cortex-M IoT SoCs increasingly ship with PSA Certified Level 2/3 evaluations using PUF-based UDS. Cross-link to `[[reference-embedded-device-hardening-playbook]]` for the regulatory landscape forcing this adoption.

**Apple Secure Enclave continued evolution.** A-series, M-series chips iterate on Secure Enclave Processor design. Whether Apple uses PUF-class primitives for the UID derivation remains undisclosed; **independent silicon teardowns (TechInsights, others) have not publicly resolved this** as of early 2026 `[unverified — Apple does not publish silicon-level details]`.

**Google Pixel Titan M2 / Tensor G4.** Google security ICs use PUF-class primitives `[unverified specific implementation]`. Cross-link to `[[reference-dice-embedded-device-identity]]` §5 for the broader DICE-in-mobile picture.

**Microsoft Pluton MCU integration.** Pluton is integrated into AMD Ryzen and Qualcomm Snapdragon PCs as a Windows security processor. PUF-class primitives are part of the Pluton root-of-trust design `[unverified specific silicon implementation]`. Cross-link to `[[reference-dice-embedded-device-identity]]` §5 and `[[reference-hardware-attestation-chains]]` §11.

**FPGA-side PUF integration.** Xilinx/AMD Zynq UltraScale+ MPSoC and similar parts ship with PUF options for AES-key wrapping. The FPGA reconfigurability landscape makes PUF-based key derivation attractive because re-flashing the FPGA bitstream cannot change the PUF response.

**Post-quantum migration.** PUF-derived UDS is independent of the signature/KEM choice in the upper attestation chain. Cross-link to `[[reference-post-quantum-cryptography]]` and `[[reference-hardware-attestation-chains]]` §10 for the PQC migration of certificates rooted in PUF-derived identity.

**Research frontier.** Lattice-PUF constructions (Becker and collaborators), in-memory-computing PUFs (memristor-based), photonic PUFs for high-bandwidth applications. None at production scale as of 2026.

---

## 12. Honest failure modes — load-bearing

The PUF literature can read as enthusiastic. The deployment record is more mixed. Vendors evaluating PUF-based UDS need to understand these failure modes before shipping.

**Helper-data leaks information.** Even with information-theoretic security analyses, side-channel leaks during helper-data evaluation and helper-data manipulation attacks reduce min-entropy below theoretical bounds. **Treat helper data as semi-secret.** Store it on-device, integrity-protect it, do not externalize it. Some published attacks (Becker side-channel work) recover the UDS from helper-data observation plus modest side-channel access.

**Strong-PUF ML modeling breaks most production strong PUFs.** Arbiter PUFs, XOR-arbiter PUFs, feed-forward arbiter PUFs have all been broken with reasonable CRP corpora and modest compute. If you use a strong PUF for authentication, wrap it in a controlled-PUF construction or use a lattice-PUF design. Most production deployments do not need strong PUFs — use weak PUFs for UDS derivation and stop there.

**Aging drifts the response.** Long-lived devices require helper-data refresh; if refresh is not supported in the design, expect field failures after 10-15 years (especially in elevated-temperature operation). This is a real failure mode for industrial and automotive deployments where 15+ year service life is contractually required.

**Temperature + voltage extremes break the fuzzy extractor.** Industrial (-40°C to +85°C) and automotive (-40°C to +125°C) ratings require **range-aware enrollment** and larger error-correction budgets. Cutting corners here causes intermittent boot failures that are extremely hard to debug in the field. The chip works at the bench, fails on a cold morning in the field, works again after warming up — and the field-replaceable-unit return reports "no fault found."

**PUF + DICE composition is non-trivial.** UDS-derivation timing matters; if PUF readout happens after the L1 measurement chain rather than before, alteration of L1 can observe the PUF readout and learn the UDS. Production designs gate PUF circuit access behind a one-shot fuse that locks after the ROM stage reads it — same locking property as the OTP UDS path.

**Helper-data integrity matters and is sometimes neglected.** Unsigned helper data is a soft target. Some vendor reference designs ship without helper-data integrity protection; integrators are expected to add it. Integrators sometimes miss this.

**PUF certification ecosystem is immature.** FIPS 140-3 and Common Criteria PUF-specific profiles are emerging but vendor implementations differ widely. A CC-EAL5 certification of a PUF-based product does not guarantee the post-evaluation research community will not break it next year. Treat certifications as evidence of process rigor, not as evidence of unbreakable design.

**Reprovisioning is often disabled.** Once enrolled, the chip cannot be re-enrolled in some designs. This is a feature (rollback prevention, anti-replacement-attack) and a bug (no recovery path if helper data is corrupted). Decide consciously which way you want the trade-off and document it.

**Side-channel attacks scale with attacker resources.** Photon emission, power analysis, EM analysis on PUF readout are research-active. Production devices that pass CC EAL evaluations have been broken by post-evaluation research repeatedly. If the threat model includes nation-state physical adversaries, PUF alone is insufficient — combine with tamper-evident packaging, anti-tamper sensors, and external SE isolation.

**Vendor consolidation reduces diversity.** Synopsys' acquisition of Intrinsic-ID consolidates the dominant SRAM-PUF IP portfolio. Fewer independent PUF IP vendors means more concentrated supply-chain risk. If Synopsys' Quiddikey IP has a yet-undisclosed flaw, the blast radius spans the SoCs of most major IoT silicon vendors.

**Enrollment-test time costs at scale.** PUF enrollment adds production-test time per chip (typically 0.1-1 second). At billion-unit IoT volumes this is non-trivial; some vendors trade off enrollment thoroughness for throughput, leaving devices with marginal helper data that fails in extreme conditions.

**Open-source PUF implementations are sparse.** Most production PUF IP is proprietary, evaluated only by the licensor and the licensee. Independent security review is limited. The fuzzy-extractor academic literature is rich; the implementation literature is thinner.

The aphorism: **a PUF does not store a secret; it remembers one.** Whether the chip remembers correctly across temperature, voltage, and time is an engineering problem, not a cryptographic one.

---

## 13. Worked example — PUF-based UDS in a hypothetical Cortex-M33 IoT SoC

Walk through a concrete deployment to ground the abstractions.

**Hardware.** Cortex-M33 with TrustZone-M, 512 KB internal flash, 128 KB SRAM. SRAM PUF instantiated as a 4 KB region of the SRAM array dedicated to PUF use (cannot be used for normal RAM). 256-bit OTP fuse array. AES-128 hardware accelerator. SHA-256 hardware accelerator. Anti-tamper sensors (active mesh, voltage monitor, temperature monitor).

**Enrollment at production test.** Test fixture cycles the device through three temperature corners (-40°C, +25°C, +85°C) and two voltage corners (Vdd_min, Vdd_max). At each corner the PUF region is read; the union of reliable cells across all corners is identified (a cell is "reliable" if it produces the same bit at every corner). Helper data is generated using a BCH(255, 21, 55) code wrapped with a 5x repetition code — total error-correction capability ~22% raw BER. Helper data size ~2 KB. SHA-256 hash of helper data is written into a 32-byte OTP fuse region. Helper data is written into a locked flash partition. A one-shot fuse is blown to lock the PUF circuit's enrollment mode; subsequent boots can only **read** (re-derive), not re-enroll.

**Boot flow.** ROM code executes from boot ROM. ROM reads PUF region, computes XOR with stored helper data, runs BCH+repetition decoder to recover the stable PUF response w. ROM hashes the stored helper data; compares against OTP-stored hash; aborts boot on mismatch. ROM runs HKDF over w to extract a uniform 256-bit UDS. ROM clears the PUF region (overwrite to zero) and the intermediate decoder state. ROM computes L1_CDI = HKDF(UDS, L1_measurement) where L1_measurement is SHA-256 of the next boot stage's code. ROM zeros UDS. ROM jumps to L1 with L1_CDI in a secure register. L1 derives its asymmetric identity key from L1_CDI, requests an attestation certificate from the upstream, derives L2_CDI for the next stage, zeros L1_CDI, jumps to L2. And so on through the DICE chain.

**Attack 1: physical decap + microscopy.** Attacker decaps the chip, attempts to read SRAM startup state under a microscope. The decap process damages the chip's surface metallization; subsequent power-on produces a different startup pattern. Even partial decap that preserves boot functionality alters the local thermal environment enough to shift the PUF response beyond the error-correction budget. Attack fails to extract a working UDS.

**Attack 2: ML modeling.** SRAM PUF is a weak PUF — only one response, no CRP space to observe. Modeling attacks not applicable.

**Attack 3: helper-data manipulation.** Attacker modifies stored helper data hoping to bias the recovered key. ROM hashes the helper data and compares against OTP-stored hash; mismatch causes boot abort. Attack detected.

**Attack 4: side-channel during boot.** Attacker measures power consumption during ROM execution. Power signature during PUF readout and fuzzy-extractor decode could leak partial UDS bits. Mitigation: masked AES, masked SHA-256, masked BCH decoder. Production-grade defenses require coordinated cryptographic-engineering effort beyond the scope of standard ARM Cortex-M33 deliverables.

**Attack 5: forced aging via voltage stress.** Attacker repeatedly applies elevated voltage/temperature stress to drive NBTI aging in target transistors. After enough aging, the PUF response drifts beyond the error-correction budget; boot fails. Attacker has not extracted the UDS; they have denied service. If a re-enrollment fuse exists and the attacker has access to it, they could re-enroll the chip with their own helper data — but the fuse was blown at production test.

**Field failure mode.** Device shipped without range-aware enrollment (only enrolled at +25°C). Field deployment includes cold-storage warehouses at -20°C. Devices boot-fail at first cold cycle. RMA reports "no fault found" because devices boot fine at the depot's room temperature. Root cause: PUF response shift exceeds error-correction budget at cold. Fix in next silicon revision: enroll at corners.

This worked example illustrates why PUF-based UDS is harder to engineer than OTP-fused UDS but provides meaningfully harder physical-extraction resistance. The trade-off is appropriate for products targeting funded-physical-adversary threat models; for software-only-adversary threat models the engineering cost may not be worth it.

---

## 14. Cross-link cluster

- `[[reference-dice-embedded-device-identity]]` — parent doc; §3 references UDS sources; this doc is the PUF deep-dive
- `[[reference-hardware-attestation-chains]]` — DICE certificates rooted in PUF-derived identity; PQC migration shared concerns
- `[[reference-hardware-side-channels]]` — power/EM/photon-emission attacks on PUF readout and helper-data evaluation
- `[[reference-confidential-computing]]` — TEE attestation parallels; remote attestation rooted in device identity
- `[[reference-hsm-operational-discipline]]` — HSM-class operational rigor applicable to PUF-based identity at scale `[unverified — sibling doc may or may not be present]`
- `[[reference-embedded-device-hardening-playbook]]` — operations playbook for embedded products using PUF UDS
- `[[reference-rtos-embedded-os]]` — RTOS-side considerations for PUF-derived key usage
- `[[reference-cryptography]]` — fuzzy extractor primitives, error-correcting codes, randomness extractors
- `[[reference-post-quantum-cryptography]]` — PQC migration of the upper attestation chain; PUF UDS independent of PQC choice
- `[[reference-webauthn-fido2-passkeys]]` — different identity layer (user, not device); some hardware tokens use PUF for credential storage
- `[[reference-cicd-supply-chain]]` — provenance attestation rooted in device identity for IoT supply chains
- `[[reference-vulnerability-research-methodology]]` — PUF attack research as a discipline (CHES, CCS venues)

---

## Researchers / primary sources cited

- **Ravi Pappu** (MIT 2001) — optical PUF foundational work
- **Blaise Gassend, Dwaine Clarke, Marten van Dijk, Srinivas Devadas** (CHES 2002, controlled PUFs 2008) — silicon physical random functions
- **G. Edward Suh, Srinivas Devadas** (DAC 2007) — ring oscillator PUF
- **Yevgeniy Dodis, Leonid Reyzin, Adam Smith** (Eurocrypt 2004) — fuzzy extractors and secure sketches
- **Pim Tuyls, Boris Škorić** (CHES 2006) — coating PUF; Intrinsic-ID lineage from Philips Research
- **Ulrich Rührmair** (CCS 2010 modeling attacks; subsequent strong-PUF attack lineage)
- **Georg Becker** (CHES 2015+ side-channel attacks on helper data; lattice PUF)
- **Roel Maes** (PUF surveys; Physically Unclonable Functions monograph 2013)
- **Daniel Holcomb** (UMass Amherst, IEEE Trans. Computers 2009) — SRAM PUF startup characterization
- **Shahin Tajik et al.** (CCS 2017) — photon-emission analysis on arbiter PUFs
- **Lejla Batina** (Radboud — embedded crypto side-channel literature applicable to PUF readout) `[unverified specific PUF-focused publications]`
- **TCG DICE Working Group** — DICE specifications (UDS source-agnostic)
- **NIST SP 800-90B working group** — entropy source validation applicable to PUF designs
- **ISO/IEC JTC 1/SC 27** — ISO/IEC 20897 PUF standard family

Vendors: **Intrinsic-ID** (founding team grew from Philips Research / Tuyls lineage; acquired by Synopsys 2024 `[unverified specific date]`); **Synopsys** (post-acquisition Quiddikey IP holder); **Maxim Integrated / Analog Devices** (ChipDNA, DS28E50/DS28E84/DS28C36); **NXP** (A71CH, SE050 secure elements); **Microsoft** (Pluton); **Apple** (Secure Enclave UID — implementation undisclosed); **Google** (Titan M2, Tensor G4 — implementation undisclosed); **Xilinx/AMD** (Zynq UltraScale+ MPSoC PUF option).
