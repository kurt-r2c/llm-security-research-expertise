# Hardware Attestation Chains — Expertise

Cross-cutting reference for hardware-rooted attestation: TPM → AK → platform → relying party. Sibling to `[[reference-confidential-computing]]` (TEE-as-enclave attestation), `[[reference-webauthn-fido2-passkeys]]` (FIDO attestation formats), `[[reference-zero-trust-workload-identity]]` (device posture in ZT), and `[[reference-hsm-operational-discipline]]` (hardware roots at the HSM tier).

Audience: AI agents; staff-security / platform-engineering / device-lead roles building or auditing hardware-rooted identity across server (TPM + measured boot), confidential-compute (TEE attestation), and mobile (Apple App Attest / Android Play Integrity / Pixel StrongBox) substrates.

## 1. Why this doc exists

Attestation is a cryptographic claim by hardware about its own state, or about software running on it, verifiable by a remote party. The structural insight: attestation moves trust from "I trust this device because I shipped it" to "I trust this device because the silicon vouched for it." That shift is what turns endpoint posture from self-report into evidence.

Sibling docs cover specific modes. `confidential_computing_expertise.md` covers TEE attestation as one mode (SGX EREPORT / TDX TDQUOTE / SEV-SNP attestation reports / Apple PCC). `webauthn_fido2_passkeys_expertise.md` covers FIDO attestation formats (`packed` / `tpm` / `android-key` / `apple`). `zero_trust_workload_identity_expertise.md` §7 references hardware attestation for device posture without anchoring it. `hsm_operational_discipline_expertise.md` covers attestation at the HSM tier (FIPS 140-3 + remote-quote primitives in Thales Luna / nCipher / YubiHSM2 / CloudHSM).

This doc anchors the cross-cutting discipline: what each substrate provides, how chains compose, where verification sits, where the chain breaks. Read once before standing up a new attestation program; reread §10 (verification discipline) before each onboarding of a new relying party.

## 2. TPM 2.0 architecture and primitives

TCG (Trusted Computing Group) is the standards body. TPM 1.2 (2003) → TPM 2.0 (Library Specification 2.0, 2014, ISO/IEC 11889). The Will Arthur + David Challener + Kenneth Goldman book "A Practical Guide to TPM 2.0" (Apress, 2015) is the canonical engineering reference. David Grawrock's "Dynamics of a Trusted Platform" (Intel Press, 2009) covers the pre-2.0 architecture and Intel TXT.

Key primitives:

- **Endorsement Key (EK):** RSA-2048 or ECC-P256 keypair injected at manufacture, never leaves the TPM. Certifies the TPM's identity. Manufacturer (Infineon / Nuvoton / STMicroelectronics / Intel PTT firmware-TPM / AMD fTPM) cross-signs the EK certificate. The EK is privacy-sensitive: a unique long-lived identifier per device, which is why direct use in attestation is avoided.
- **Attestation Identity Key (AIK in 1.2) / Attestation Key (AK in 2.0):** a TPM-resident keypair used as a privacy-preserving alias for the EK. The AK is signed either by a Privacy CA (which sees both EK and AK) or derived via Direct Anonymous Attestation. Multiple AKs can be created per TPM; rotation is supported.
- **Storage Root Key (SRK):** wraps user-level keys at rest under the TPM. The storage hierarchy is one of four hierarchies (endorsement / storage / platform / null).
- **PCRs (Platform Configuration Registers):** typically 24 registers (PCR 0-23), each holding a hash chain that records what code ran. Extension primitive: `PCR[i] = HASH(PCR[i] || measurement)`. PCRs 0-7 conventionally record BIOS/UEFI/boot-loader measurements. PCRs 8-15 record OS / kernel / IMA application measurements. PCRs 17-22 are reset on dynamic-root-of-trust (DRTM) events (Intel TXT / AMD SKINIT).
- **TPM2_Quote:** the attestation primitive. Inputs: PCR-set selection + nonce. Output: signed structure binding (selected PCR values + nonce + AK identity). The verifier checks the signature against the AK certificate, validates the certificate chain, and compares PCR values against expected reference values.
- **TPM2_Seal / TPM2_Unseal:** binds data (a wrapping key) to a PCR-state precondition. Unsealing only succeeds if PCRs match. The BitLocker key-protector pattern depends on this primitive. Cross-link to `[[reference-secrets-management-discipline]]`.
- **TSS 2.0 (TPM Software Stack):** ESYS (Enhanced System API) + FAPI (Feature API) + SYS (System API) layers. Intel-led OSS `tpm2-tools` is the canonical user-space utility set. `tpm2-tss` is the library.

The TPM is a slow co-processor. A `TPM2_Quote` round-trip takes roughly 100ms to several hundred ms depending on the chip. Production deployments cache attestations rather than verifying per-request.

**Hierarchies and ownership:** TPM 2.0 has four hierarchies — endorsement, storage, platform, and null. Each has its own owner password and authorization policy. The platform hierarchy is owned by the firmware (BIOS/UEFI) and not accessible to the OS in practice. The endorsement hierarchy is the privacy-sensitive one (holds the EK); creation of AKs is anchored there. The storage hierarchy is where user-level wrapping happens. Operational mistake to avoid: TPM clear operations zero the storage hierarchy, breaking BitLocker key sealing — recovery keys exist for this reason.

**Discrete vs firmware TPM vs vTPM.** Discrete TPMs are physical chips on the motherboard (Infineon SLB 9670, Nuvoton NPCT75x, ST33). Firmware TPMs (fTPM) run inside CPU firmware — Intel PTT (Platform Trust Technology) and AMD fTPM. Virtual TPMs (vTPM) are hypervisor-emulated TPMs bound to a VM. The security properties differ: discrete TPMs are physically isolated but slower and on a bus the adversary can probe (LPC / SPI sniffing on some boards); fTPMs share fate with CPU firmware (TPM-Fail anchor); vTPMs anchor in the hypervisor's host attestation rather than physical hardware.

**Direct Anonymous Attestation (DAA).** Ernie Brickell + Jan Camenisch + Liqun Chen introduced DAA at ACM CCS 2004. The privacy problem DAA solves: in the Privacy-CA model, a CA learns which EK is attached to which application identity (the AK). DAA produces signatures verifiable as "from a legitimate TPM" without revealing which TPM. TPM 2.0 supports ECDAA (Elliptic-Curve DAA) using Pedersen commitments + Camenisch-Lysyanskaya signatures with bilinear pairings (BN curves). The FIDO Alliance specified ECDAA for use in FIDO2 authenticator attestation. Operational adoption is limited. Most enterprise TPM deployments still use the Privacy CA model — the privacy/anonymity guarantees of DAA are not load-bearing for enterprise device identity. Consumer ecosystems care more (FIDO authenticators), but Apple Anonymous Attestation took a different design path (Apple issues a certificate for each credential public key, chained to Apple's WebAuthn Root CA) and Google Play Integrity is a service-mediated model rather than DAA. ECDAA deployments at scale are rare `[unverified — researchers cite the gap repeatedly]`. The structural insight on why DAA stays academic: enterprise IT *wants* the device-to-user mapping for inventory and IR. The privacy property DAA delivers conflicts with the audit property enterprise wants. The consumer FIDO ecosystem, which would benefit, has converged on batch-anonymous attestation as a "good enough" privacy posture without DAA's cryptographic complexity. This is a recurring pattern in security: theoretical optima lose to operational pragmatics, and that loss is sometimes correct.

## 3. Measured Boot vs Secure Boot

These are complementary, not alternatives. Confusing them is the most common entry-level mistake.

**Secure Boot (UEFI):** prevents unauthorized boot. The platform's UEFI firmware verifies signatures on bootloader / kernel modules at each stage. If a signature fails, boot stops. The chain of trust is rooted in:
- **PK (Platform Key):** the platform owner's RSA public key, set during manufacturing or by the device owner.
- **KEK (Key Exchange Key):** keys authorized by the PK to update the signature databases.
- **db (signature database):** authorized signers (Microsoft's UEFI CA is the practical default).
- **dbx (forbidden signature database):** revoked signatures (used to roll back compromised bootloaders).

Secure Boot is binary: pass or block. It does not record state.

**Measured Boot:** does NOT prevent boot. The platform records what booted, by extending PCRs in the TPM with measurements (hashes) of each loaded component. Boot proceeds even on unrecognized code; the measurement is the artifact for later verification.

The structural property: Measured Boot moves the trust decision from boot-time (where the device cannot consult a remote oracle) to attestation-time (where it can). An attacker who modifies the bootloader cannot prevent the modification from being measured — the modified PCR value will not match expected reference values when the device tries to attest.

**TPM Event Log:** a parallel record of what was extended into each PCR. Held in TPM-vendor-specific shared memory or in OS-accessible memory (`/sys/kernel/security/tpm0/binary_bios_measurements` on Linux). Verification replays the event log against the final PCR value: if the replayed hash chain matches the PCR, the log is consistent with what the TPM saw; the log entries identify which components measured. Cross-link to `[[reference-dfir-methodology]]` for forensic application — the TPM event log is one of the most-tamper-resistant boot-time forensic artifacts.

The event log is integrity-bound to the PCR but not itself authenticated. A privileged attacker can substitute the log; the only constraint is that the substituted log must replay to the same PCR value. Both PCR and log are needed for forensic-grade evidence (§13).

**DRTM (Dynamic Root of Trust for Measurement)** is the third leg. SRTM (Static RoT) measures from power-on through bootloader and OS — the chain anchored at the platform firmware. DRTM (Intel TXT via SENTER, AMD via SKINIT) lets a late launch establish a clean measurement environment without rebooting, by resetting PCRs 17-22 and re-measuring the loaded code. Intel TXT underlies the Trusted Boot reference architecture; AMD's equivalent underlies the SKINIT-based SVM secure-launch flows. DRTM is operationally rare today; Microsoft System Guard (in some Windows 10/11 SKUs) uses it, but most server fleets do not.

**TPM Reset attacks (`TPM Genie` / interposer-class):** physical attacks on the TPM-to-CPU bus (LPC / SPI / I2C) allow an interposer to substitute TPM responses, including TPM2_Quote outputs. Discrete TPMs on exposed buses are vulnerable. Jeremy Boone's TPM Genie research (NCC Group, 2018), an I2C bus interposer for discrete TPMs, demonstrated this. fTPMs avoid this since the bus is internal to the CPU package.

## 4. Remote attestation protocols and verification models

Two architectural patterns:

**Passport model:** the device collects attestation evidence locally, presents it to the relying party directly. The relying party verifies the evidence and decides. This places verification logic at every relying party.

**Background-check model:** the device sends evidence to a verifier; the verifier issues a verification result (an "attestation result" or "attestation token") that the relying party trusts. The relying party never sees raw evidence. AWS / Azure / GCP attestation services are background-check verifiers.

The trade-off: passport is simpler but pushes complexity to every RP. Background-check centralizes complexity but introduces the verifier as a new trust root. RFC 9334 covers both.

**IETF RATS Architecture (RFC 9334, January 2023 `[unverified exact publication date — confirmed 2023]`):** Henk Birkholz et al. The canonical modern terminology reference. Five roles:
- **Attester:** the device producing evidence.
- **Verifier:** the entity that checks the evidence against reference values + endorsements.
- **Relying Party:** the entity that consumes the attestation result and makes a trust decision.
- **Endorser:** the manufacturer or platform owner who attests to hardware identity (e.g., TPM manufacturer signing the EK cert).
- **Reference Value Provider:** the source of golden values (e.g., the OS vendor publishing expected boot-component hashes).

**TCG TAP (Trusted Attestation Protocol):** information model for attestation data flowing between attester and verifier. TCG-specific complement to RATS.

**DICE (Device Identifier Composition Engine):** TCG specification for hardware-rooted device identity in resource-constrained devices. CDI (Compound Device Identifier) derived from UDS (Unique Device Secret) + the measurement of the next-stage firmware: `CDI_n = HMAC(CDI_{n-1}, hash(stage_n))`. The next stage derives its own CDI from the previous CDI + its measurement. The chain produces a hardware-rooted identity that changes when any layer changes. DICE is the IoT / embedded analog of TPM-based attestation, intended for microcontrollers too small for a TPM. Cross-link to `[[reference-rtos-embedded-os]]` and `[[reference-embedded-device-hardening-playbook]]`.

**Endorsement vs attestation evidence — clarify terminology.** Endorsement is the manufacturer's claim about the hardware itself (the EK cert is an endorsement). Attestation evidence is what the device produces at runtime (the TPM2_Quote is evidence). RATS keeps these separate because verifiers consume both: they validate the endorsement chain once at provisioning + cache the resulting public key, then validate each piece of fresh evidence against that public key. Conflating them is a common architectural mistake — it leads to designs that fetch manufacturer certs on every verification.

## 5. Linux IMA (Integrity Measurement Architecture)

Mimi Zohar and Reiner Sailer (IBM Research) authored IMA — the canonical paper is Sailer et al., "Design and Implementation of a TCG-based Integrity Measurement Architecture," USENIX Security 2004.

What IMA does: a kernel security module hooks file opens, hashes the file content, extends a TPM PCR (PCR 10 by convention) with `HASH(file_hash || file_metadata)`. Files that get measured are controlled by an IMA policy — typically all executable file opens, library loads (mmap with PROT_EXEC), and kernel module loads.

Complementary primitives:
- **EVM (Extended Verification Module):** HMAC or asymmetric signature over file metadata (uid, gid, mode, security xattrs). Prevents an attacker who can write file content from updating extended attributes to bypass IMA-appraisal.
- **IMA-appraisal:** policy-mode enforcement. The kernel refuses to execute a file unless its measured hash matches a signed expected value. This converts IMA from purely-measurement to measurement + enforcement.

The IMA event log lives in user space at `/sys/kernel/security/integrity/ima/ascii_runtime_measurements`. The TPM PCR is the only tamper-evidence; the log itself is held in user space and can be substituted by root.

For attestation: the verifier requests a TPM2_Quote covering PCR 10, then asks for the IMA log. Replay the log → match the PCR → trust the log's contents. Compare measured file hashes against expected hashes for the OS package set. Mismatches identify which binaries deviated.

Operational pain: the IMA event log grows monotonically across boots until reboot. On long-uptime systems, a verifier must handle large logs. IMA policy tuning is a lab-grade activity — getting selectivity right requires understanding the boot's full file-access pattern.

## 6. Confidential-computing attestation flavors

Sibling section to `[[reference-confidential-computing]]` for full context; this section anchors the attestation-flavor structure.

**Intel SGX:** `EREPORT` instruction generates an SGX `REPORT` structure containing MRENCLAVE (the SHA-256 measurement of the enclave's code and data pages at load) + MRSIGNER (the signer's identity) + ISVPRODID + ISVSVN + attributes + a 64-byte report_data field that the enclave fills (typically a public key bound to a session). The REPORT is consumed by Intel's Quoting Enclave (QE), which converts it into a `QUOTE` signed with an EPID (legacy) or ECDSA (modern) key.

Intel Attestation Service (IAS) was Intel's first-party attestation backend; it has been deprecated in favor of DCAP (Data Center Attestation Primitives), where the service operator runs its own Provisioning Certification Caching Service (PCCS) and verifier. DCAP-based attestation is the modern default for Azure Confidential Computing operations against SGX.

**Intel TDX:** TDREPORT → TDQUOTE pattern. Module TDX 1.0 / 1.5 / 2.0 are the milestone versions; TD attestation uses Intel SGX quoting enclaves and the SGX (PCK) certificate infrastructure. Quote includes TDX module measurement + MRTD (initial measurement of the TD) + RTMRs (Runtime Measurement Registers, 4 of them, analog of PCRs).

**AMD SEV-SNP:** `snp_guest_request` HV-call from the guest returns an `ATTESTATION_REPORT` containing chip-id + launch measurement + report_data + TCB version + platform info. Verified via the AMD Key Distribution Service (KDS) for the public chip endorsement key; or via VLEK (Versioned Loaded Endorsement Key), derived from seeds allocated to an enrolled cloud service provider rather than unique per chip. The launch measurement covers initial guest memory + vCPU state.

**ARM CCA (Confidential Compute Architecture):** Realm Management Monitor (RMM) attestation. CCA Token format defined as a profile of the IETF Entity Attestation Token (EAT) in CBOR/COSE encoding. RMM signs a token covering Realm Initial Measurement (RIM) + Realm Extensible Measurements (REMs). Implementations in early stages as of 2026 `[unverified specific deployment maturity]`.

**Apple Private Cloud Compute (PCC):** stateless inference across hardware + Apple secure boot chain. Each request includes attestation evidence that the PCC node runs a specific signed PCC image. Not TPM-based; bespoke to Apple silicon. Apple publishes the signed images via the Apple Transparency Log — clients can verify the running image is in the public log before submitting requests. The public-build property is the load-bearing claim Apple makes about PCC.

**NVIDIA H100 Confidential Computing** (since 2023): NVIDIA Remote Attestation Service (NRAS) verifies GPU firmware + driver + confidential VM bindings. AI/ML workloads that need to keep model weights or training data confidential to the deploying party (and not the cloud operator) anchor on H100 CC. Cross-link to `[[reference-ai-orchestration-harnessing]]`.

## 7. Mobile platform attestation

**Apple Managed Device Attestation (iOS 16+ / macOS 14+):**
- **DeviceCheck App Attest** (iOS 14+): per-app keypair generated in the Secure Enclave; provides a token that says "this is from a legitimate iOS device" + "from this app instance" (the app's bundle ID is bound to the key). Token verified by the RP against Apple's public-key endpoint. The key is anonymous to Apple — Apple cannot identify which device, only that some legitimate device produced the assertion.
- **Managed Device Attestation** extends App Attest to ACME challenges for MDM scenarios — device enrolls a cert with the MDM CA, and the CSR is bound to a hardware attestation. Cross-link to `[[reference-zero-trust-workload-identity]]` for device posture in ZT enrollment.

**Android Key Attestation:**
- **Hardware-backed Keystore:** keys generated in TEE (TrustZone) or, on supported devices, in StrongBox (a dedicated secure element).
- **Attestation certificate chain:** rooted in Google's root attestation key. When an app calls `KeyStore.getCertificateChain(alias)`, the chain includes Google's root → manufacturer → device certificate with an attestation extension. The extension contains hardware-enforced properties (key purpose / algorithm / origin / OS version / patch level / boot state) and software-enforced properties.
- **Play Integrity API:** replaced SafetyNet Attestation. Deprecation announced 2022; full sunset by January 2025 `[unverified specific final deprecation date]`. Play Integrity provides device-integrity (MEETS_DEVICE_INTEGRITY / MEETS_BASIC_INTEGRITY / MEETS_STRONG_INTEGRITY) + app-integrity + account-integrity claims. Google-mediated; backed by Play Protect telemetry rather than purely cryptographic.

**Pixel StrongBox:** dedicated secure element in Pixel 3 onward. The StrongBox attestation chain is rooted in a Google-signed certificate; verifiers extract the AAGUID and validate via FIDO MDS for FIDO-related use, or via Google's attestation roots for keystore-related use.

**Samsung Knox attestation:** TIMA (TrustZone-based Integrity Measurement Architecture) on Knox-enabled Samsung devices. Provides measured-boot equivalent in the TrustZone secure world. Samsung-signed attestation. Less commonly used outside enterprise MDM scenarios.

**Platform attestation as bot-defense:** consumer apps + financial apps + ticketing apps use Play Integrity / Apple App Attest to gate transactions on "request originated from a real device, not a scraper / emulator / cloud-phone farm." This is the dominant production use case for mobile attestation today. Cross-link to `[[reference-anti-fraud-abuse-engineering]]` and `[[reference-ciam-consumer-identity]]`. The known weakness: cloud-phone farms with real hardware can produce valid Play Integrity tokens; attestation raises the cost of bot operations but does not eliminate them.

**Operational pain points for mobile attestation:**
- Google Play Integrity rate limits — apps exceeding quota fall back to lower-assurance verdicts. A production deployment needs careful budget planning for high-volume events.
- App Attest assertions are bound to the app's bundle ID; reinstalls produce a new key. The RP must handle the key-rotation flow.
- Both Play Integrity and App Attest assertions can fail on legitimate devices in edge cases (custom ROMs, dev-mode iOS, betas) — RPs must decide whether to deny those users.
- Rooted/jailbroken devices fail attestation by design. For developer tools or security testing apps, this is a feature; for general-purpose apps, this excludes a meaningful population.

**Server-side platform attestation extends to laptops/desktops:** Apple's Platform Single Sign-On (PSSO) for macOS uses Apple's hardware-attested device identity to feed enterprise IdPs (Okta, Entra, Ping). Microsoft Windows Hello for Business binds enterprise credentials to the TPM and provides hardware-attested device identity to Entra ID. Cross-link to `[[reference-saml-federation]]` for the IdP integration patterns.

## 8. WebAuthn attestation formats

Sibling to `[[reference-webauthn-fido2-passkeys]]` — this section anchors the format inventory; that doc covers the full ceremony and ecosystem.

WebAuthn attestation statement formats (registered in IANA WebAuthn registry):

- **`none`:** no attestation; common default for passkeys. The authenticator produces a zero-attestation statement. Privacy-preserving; the RP gets no model identification.
- **`packed`:** generic format. Signed attestation statement with AAGUID + signature over the authenticator data + client data hash. The default for most modern security keys.
- **`fido-u2f`:** legacy U2F attestation format, used for first-gen YubiKeys and similar pre-WebAuthn devices.
- **`android-key`:** Android hardware-backed Keystore attestation chain. The full Google-rooted cert chain with the attestation extension.
- **`android-safetynet`:** legacy; marked deprecated in the WebAuthn spec in 2024 following Google's SafetyNet deprecation.
- **`apple`:** Apple Anonymous Attestation for Apple platform authenticators (distinct from App Attest).
- **`tpm`:** TPM 2.0 attestation format. Windows Hello uses this — the Windows Hello credential is bound to the device's TPM and the WebAuthn attestation is a TPM2_Certify signature over the credential key (`certInfo`).

**AAGUID:** 128-bit identifier for the authenticator model. FIDO MDS (Metadata Service) endpoint resolves AAGUID → model metadata, certification status, supported algorithms, transports, and certification history. RPs that care about authenticator quality pin allowed AAGUID lists; RPs that don't (most consumer deployments) accept all AAGUIDs including AAGUID=zero for privacy.

The structural insight: WebAuthn attestation formats abstract over the underlying hardware-attestation substrate. A `tpm`-format WebAuthn attestation is a TPM2_Certify output; an `android-key`-format is an Android Keystore chain; an `apple`-format is an Apple Anonymous Attestation certificate. The format is the wire encoding; the substrate is the hardware-rooted chain.

## 9. Cloud-side platform attestation

**AWS Nitro Enclaves attestation:** Nitro Enclaves are VMs without persistent storage / external networking. PCRs 0-15 represent enclave image measurements (PCR 0 = SHA-384 of the EIF image, PCR 1 = kernel + boot ramfs, PCR 2 = application, PCR 3 = parent instance role ARN, PCR 4 = parent instance ID, PCR 8 = signing certificate of the enclave). The NSM (Nitro Security Module) signs the attestation. KMS condition keys (`kms:RecipientAttestation:PCR0`, etc.) gate decryption on PCR values — "decrypt only from this enclave." This is the canonical pattern for AWS confidential workloads.

**AWS Nitro System device attestation:** the parent EC2 instance attests via the Nitro Hypervisor. Not directly user-facing; underlies the trust chain for Nitro Enclaves.

**GCP Confidential GKE Nodes / Confidential VMs:** AMD SEV-SNP backed (Milan onwards) or Intel TDX backed (Sapphire Rapids onwards). Attestation evidence verifiable via Google's Confidential Space verifier or by the customer's own verifier consuming raw SEV-SNP / TDX quotes.

**Azure Confidential Computing attestation:** Microsoft Azure Attestation (MAA) is the verifier service. Endpoints per region; OAuth-protected. Returns a JWT containing the attestation result. SGX + TDX + SEV-SNP + Trusted Launch (vTPM) supported. The MAA JWT is the artifact RPs consume.

**Azure Trusted Launch:** vTPM + Secure Boot for VMs. Boot integrity attested via MAA. The vTPM is a Hyper-V-emulated TPM 2.0 bound to the VM identity; not a physical TPM, but cryptographically bound to Azure's host attestation.

**GCP Shielded VMs:** vTPM + Measured Boot + Secure Boot for VMs. Similar shape to Azure Trusted Launch; Google-attested rather than customer-attested for the host layer.

**Org-internal verifier alternatives:** Veraison (founded within Arm, now a Confidential Computing Consortium project in the Linux Foundation) is an open-source attestation verifier that supports PSA / CCA / TPM evidence formats. Org-internal verifiers reduce the cloud-provider as trust root, at the cost of operating verifier infrastructure.

## 10. Verification discipline

**Verifying a TPM2_Quote — the canonical flow:**

1. Parse the quote structure; extract signature + signed body + PCR digests + nonce.
2. Verify the signature against the AK public key.
3. Validate the AK certificate chain: AK → (Privacy CA OR DAA) → manufacturer EK certificate → TCG root. Reject chains with unknown roots.
4. Confirm the nonce matches the nonce the verifier issued in this attestation session. Reject if no match (replay protection).
5. Compute expected PCR values from the published reference values (golden values) for the boot configuration this device should be running.
6. Compare reported PCR values against expected. Mismatches identify which boot component deviated.
7. If using the TPM event log: replay the log against the final PCR value to confirm log integrity, then inspect log entries to identify which specific components measured.

**Reference values — golden vs runtime:**

Golden values must be established for each accepted boot configuration and updated when software changes. Examples of reference-value sources:
- OS vendor publishes expected hashes per release / patch level (Microsoft for Windows boot components; Red Hat / Canonical for kernel + initramfs).
- Hardware vendor publishes expected BIOS / UEFI measurements (Dell / HP / Lenovo / Supermicro).
- Internal builds publish expected measurements via the CI / CD pipeline.

Reference-value management is the soft underbelly of attestation programs. When a vendor ships a BIOS update, the golden values change. If the verifier's database doesn't update, the fleet attestation fails. Treat reference-value management as a real operational program with on-call ownership.

**TCB recovery:** if a vulnerability is found in a TEE microcode (SGX EPID-key leak, SEV-SNP firmware bug, TDX module CVE), previous attestations are no longer trustworthy. Intel, AMD, Microsoft, and Apple publish minimum acceptable SVN (Security Version Number) levels per vulnerability disclosure. Verifiers must enforce minimum SVN checks. After TCB recovery, devices must update their TEE firmware before they can produce trusted attestations.

**Freshness:** all attestation evidence must be tied to a verifier-issued nonce or short-window timestamp. A captured attestation from yesterday must not be replayable today. Production cache windows are typically minutes-to-hours; longer windows widen the replay attack surface.

**Verifier provenance:** who runs the verifier? The relying party must trust the verifier. AWS / Azure / GCP each run their own verifiers; using their attestation means trusting their verifier service. The org-internal alternative (Veraison) shifts the trust to in-house operations.

**Caching attestations:** production deployments verify-on-first-use + cache. An attacker who can game the cache can attack systems past their attestation window. Cache invalidation on TCB-recovery events, on device-key rotation, on policy change, and on attestation-result expiry are all needed.

**Endorsement vs evidence cadence.** Verifier infrastructure should treat endorsement validation (manufacturer cert chain) as a once-per-provisioning event and evidence validation (signature + nonce + PCR comparison) as a per-attestation event. Endorsement caching is OK with long TTLs; evidence caching needs short TTLs aligned to the threat model. A common architectural mistake: lumping these together and inflating evidence cache TTLs because endorsement validation is expensive.

**Verifier failure modes the RP must handle:**
- Verifier returns "indeterminate" — TCB version is below acceptable minimum, or platform info is unrecognized. The RP must have a policy for indeterminate (typically: deny + alert).
- Verifier returns "valid but stale" — the evidence cryptography is fine but the freshness nonce window expired. Treat as deny; re-attest.
- Verifier returns "valid but mismatched reference values" — the device booted, but with components not on the golden list. This is the most ambiguous case. A new firmware version not yet in the reference database is benign; a tampered bootloader is malicious. The distinguishing signal is operational: did the org just ship new firmware? Has the firmware been verified independently? The reference-value-management program owns this signal.
- Verifier outage — the cloud verifier service is down. The RP must decide whether to fail-open (accept) or fail-closed (deny). Fail-closed is the safer default; fail-open turns a verifier outage into a security-control outage.

**Multi-party verification** is emerging for the AI-agent identity case. A model-serving deployment may want the user to verify both the host attestation (cloud provider) and the GPU attestation (NVIDIA NRAS) and the model integrity (in-toto / SLSA provenance) before sending data. Chain-of-attestations rather than single attestation. Cross-link to `[[reference-supply-chain-provenance]]`.

## 11. 2024-2026 currency

- **IETF RATS RFC 9334 (Jan 2023 `[unverified exact month]`):** canonical modern terminology.
- **DICE adoption growing in IoT:** DICE is the IoT identity primitive for parts too small for full TPM.
- **Apple Private Cloud Compute (June 2024 announcement):** stateless inference + per-request attestation against the Apple Transparency Log. The public-build property is the unique design choice; cross-link to `[[reference-confidential-computing]]` §"Apple PCC" for full architecture.
- **Android Play Integrity supersedes SafetyNet:** full sunset by January 2025 `[unverified specific final date]`. App developers must migrate to Play Integrity API.
- **NVIDIA H100 Confidential Computing GA:** GPU attestation as a new substrate. Confidential AI inference depends on this for protecting model weights from cloud-operator inspection.
- **EU CRA (Reg 2024/2847):** Cyber Resilience Act includes attestation-style requirements for security claims by manufacturers (vulnerability disclosure timelines, secure-update obligations). Not directly an attestation mandate but related compliance pressure pushing hardware-rooted identity adoption.
- **Hardware-backed device identity for AI agents (emerging):** Cross-link to `[[reference-ai-orchestration-harnessing]]` and `[[reference-zero-trust-workload-identity]]`. The structural appeal: agent identity rooted in physical hardware prevents agent-loop credential exfiltration from being usable on another device.

## 12. Real attack corpus

- **TPM-Fail (CVE-2019-11090, CVE-2019-16863, Moghimi + Sunar + Eisenbarth + Heninger, 2019):** ECDSA timing side-channel in Intel fTPM and STMicroelectronics ST33TPHF2ESPI. Recovered TPM-resident ECDSA private keys via timing measurements on attestation operations. Anchor for "TPM is not a magic root of trust; specific implementations have specific bugs." Affected fTPM patched via Intel Management Engine firmware update; ST33 patched via firmware update. Cross-link to `[[reference-hardware-side-channels]]`.

- **EUCLEAK (September 2024, NinjaLab — Thomas Roche):** Infineon SLE78 family — used in some FIDO2-certified hardware tokens including older YubiKey 5-series and TPM modules. ECDSA private-key recovery via EM emanations during signing. Roche's paper "EUCLEAK Side-Channel Attack on the YubiKey 5 Series" demonstrates ~$11k equipment cost + physical access. Cross-link to `[[reference-webauthn-fido2-passkeys]]` and `[[reference-hardware-side-channels]]`. Implication for attestation: hardware-rooted does not mean physically-secure against side channels.

- **ROCA / Return Of Coppersmith's Attack (CVE-2017-15361, Matus Nemec + Marek Sys + Petr Svenda et al., Masaryk University, 2017):** Infineon RSA key-generation algorithm produced factorable keys. Affected TPM RSA EK / AK / SRK on many Infineon chips. Practical key-recovery: ~97 CPU-days for 1024-bit and ~140.8 CPU-years for 2048-bit keys. Massive industry response — Estonian ID cards affected, Microsoft / HP / Lenovo TPM firmware updates.

- **Intel AMT privilege escalation (INTEL-SA-00075, CVE-2017-5689, 2017):** escalation-of-privilege flaw in Intel Active Management Technology / Standard Manageability / Small Business Technology firmware versions 6.x-11.6.

- **Intel ME activation primitive (Goryachy + Ermolov 2017-2018):** Maxim Goryachy and Mark Ermolov (Positive Technologies) demonstrated Intel Management Engine activation primitives allowing firmware modification. ME runs below the OS and below the measured-boot point of reference — modifications can in principle subvert the measurement chain itself.

- **BootHole (CVE-2020-10713, July 2020):** GRUB2 grub.cfg buffer overflow allowing Secure Boot bypass. Affected nearly every Linux distribution shipping with Secure Boot. dbx update rollout was painful — updating dbx before the shim / bootloader left systems unable to boot, and Red Hat's initial fix packages caused systems to hang.

- **LogoFAIL (December 2023, Binarly):** UEFI image-parsing vulnerabilities in vendor BIOS firmware. Boot-logo parsers in firmware from AMI, Insyde, Phoenix had memory-corruption bugs exploitable by a UEFI-accessible crafted image file (e.g. BMP). Bypasses Secure Boot before Measured Boot can record. Cross-link to `[[reference-vulnerability-research-methodology]]` for the variant-analysis angle Binarly applied.

- **BlackLotus UEFI bootkit (March 2023, ESET — Martin Smolár):** first publicly-confirmed UEFI bootkit bypassing Secure Boot via Baton Drop (CVE-2022-21894, Microsoft). Persistent across reinstall + secure-boot-enabled. Available as a $5k commercial kit on cybercrime forums.

- **TPM sniffing on commodity laptops (2021, Dolos Group):** demonstrated bus-sniffing the SPI bus between a discrete TPM and the CPU on a Lenovo laptop, recovering BitLocker key material during boot. Anchor for "discrete TPM on exposed bus is not adversary-resistant against physical access." Mitigation: pre-boot PIN + virtual TPM in CPU (fTPM via Intel PTT / AMD fTPM, with their own caveats).

- **PixieFAIL (Quarkslab, January 2024):** nine vulnerabilities in the UEFI (TianoCore EDK II) PXE / TCP/IP network stack. Pre-boot remote code execution, before Secure Boot's signature-checking even applies to the loaded code. Bypasses attestation by occurring before the measurement chain begins.

- **GitHub Actions attestation supply-chain class (broader Shai-Hulud / TJ-actions corpus, 2024-2025):** not a TPM attack but a parallel — when build-system attestations (sigstore / SLSA) are themselves emitted by compromised CI runners, the attestation says "this artifact built in this CI" which is true and useless. Cross-link to `[[reference-cicd-supply-chain]]` and `[[reference-supply-chain-provenance]]`. The lesson generalizes: attestation tells you what signed, not whether the signing context was clean.

## 13. Honest failure modes — load-bearing

This section is where the doc earns its keep. Most failures are not in the cryptography — they are in how attestation is operationalized.

- **Attestation evidence is only as good as the reference values you compare against.** A perfect TPM2_Quote against unknown PCR values is uninterpretable. Without golden-value management, attestation is theater. The reference-value pipeline (vendor publishes hash → org imports → verifier database updates → fleet measurement passes) is the load-bearing operational program.

- **TEE attestation tells you what you signed, not whether the signed code is secure.** A vulnerable enclave still attests to its (vulnerable) MRENCLAVE / MRTD / launch-measurement. Attestation does not vouch for the code's safety properties — only its identity.

- **Side channels break attestation guarantees even when the attestation cryptography is sound.** TPM-Fail and EUCLEAK both recovered keys from chips that produced cryptographically valid attestations. The chips were doing what they were specified to do; the specification did not protect against the side channel. Compensating controls: physical-access controls + audit-trail correlation.

- **Cloud-provider verifiers are the trust root.** Using AWS / Azure / GCP attestation means trusting the cloud's verifier. Org-internal verifiers (Veraison) move the trust to in-house operations but require running verifier infrastructure. Choose deliberately.

- **Measured Boot without log integrity is performative.** The PCR is integrity-bound to the TPM; the event log is held in user space and is not. A privileged attacker can substitute the log. Both PCR and log are needed for forensic-grade evidence — and the log must be transmitted to the verifier through an integrity-protected channel.

- **DAA adoption is rare in practice** despite being the privacy-preserving option. Most production stacks use the Privacy CA model, which means a CA somewhere learns the device → user mapping. Privacy claims should be honest about this.

- **Mobile platform attestation is vendor-controlled.** Apple and Google sign the attestation. A vendor outage means the attestation chain cannot verify; a vendor policy change can break a working integration. Plan for graceful degradation.

- **TPM 2.0 spec is intricate; implementations have CVE histories.** TPM-Fail, ROCA, and various other TPM-firmware bugs over the years. Treat the specific TPM chip as a hardware-tier dependency with its own CVE feed and patch lifecycle. fTPM (firmware TPM in CPU microcode) bugs patch via CPU microcode update; discrete TPM bugs patch via vendor-specific tooling that is operationally painful at fleet scale.

- **Reference-value rotation lags reality.** When new firmware ships, golden values must update. The lag is typically weeks-to-months during which fleet attestation fails until ops catches up. Plan for staged rollout matching the firmware rollout cadence.

- **Verifying an attestation costs CPU and adds latency.** A `TPM2_Quote` round-trip on hardware TPMs has been measured at hundreds of milliseconds; an SGX QUOTE verification involves PCK certificate fetches. Production deployments verify-on-first-use + cache. The cache becomes the attack surface — an attacker who games the cache attacks systems past the attestation window. Cache invalidation policy must respond to TCB recovery, key rotation, and policy change.

- **Measured Boot does not measure runtime behavior.** Once the OS is booted and recorded, what the OS does afterward is not in the measurement chain. Runtime integrity (IMA-appraisal, eBPF runtime sensors, EDR) is a separate discipline. Cross-link to `[[reference-detection-engineering]]`.

- **Attestation can be replayed across devices in collusion attacks.** A device with a valid attestation can sign attestation requests on behalf of a tampered device, if the tampered device can route requests through the valid one. Per-device session binding (the report_data field bound to a session key fresh-generated in the enclave) is the defense.

- **Mobile attestation does not stop cloud-phone farms.** A farm of real hardware devices producing valid Play Integrity / App Attest tokens defeats device-attestation-as-bot-defense. Attestation raises operating costs but does not eliminate bots. Layered defenses (rate-limiting, behavioral analysis, account-integrity signals) remain necessary. Cross-link to `[[reference-anti-fraud-abuse-engineering]]`.

- **EK identity is privacy-sensitive and long-lived.** Treat EK certs and EK-derived identities as PII in compliance terms. Logging EKs into audit systems without privacy review repeats the mistake the EK→AK separation was designed to prevent.

- **TPM clear breaks sealing.** A factory-reset operation that clears the TPM zeroes the storage hierarchy. BitLocker, sshd host-key wrapping, and any other TPM2_Seal'd data become unrecoverable. Recovery keys exist for this reason; they must be backed up. Operationally: an MDM-pushed `tpm.msc clear` to a fleet without recovery-key validation is a customer-data-loss event.

- **Attestation policy must distinguish "first time" from "ongoing."** A device's first attestation establishes trust; subsequent attestations should validate against the device-bound credentials issued at the first event. Treating every attestation as the first means re-issuing device identity on each evidence cycle — operationally expensive and weakens the per-device audit trail.

- **`report_data` / `userData` field is a frequent misuse point.** The TEE attestation report includes a customer-controlled blob (typically 64 bytes). Binding the right value here is load-bearing: the field should contain a hash of the public key the enclave generated for the session, so that the attestation says "this enclave holds this private key." Common mistake: putting a constant in report_data, breaking the binding to the session and enabling replay across sessions.

- **TEE attestation does not protect against malicious enclave authors.** If you load an enclave from an untrusted developer, attestation tells you their malicious code is running — not that it is safe. The trust decision must include the MRSIGNER / signer identity, not just MRENCLAVE. Many SGX deployments configure MRSIGNER allowlists exactly for this reason.

- **Cross-substrate verification is operationally novel.** Verifying a chain that combines TPM evidence (host) + SGX evidence (enclave) + GPU NRAS evidence (NVIDIA accelerator) requires a verifier that understands all three formats and can reason about their composition. As of 2026, off-the-shelf verifiers that handle this gracefully are rare `[unverified]`. Veraison aims at this surface; production deployments typically build custom verifier orchestration.

## 14. Worked example + operational checklist

Concrete sequence for enrolling a corporate laptop into a zero-trust device-identity program using TPM attestation. Sibling to `[[reference-zero-trust-workload-identity]]` §7.

**Step 1 — provisioning (one-time, factory or IT depot):**
- Confirm TPM 2.0 present + enabled in firmware.
- Pull the manufacturer EK certificate. On Windows: `Get-TpmEndorsementKeyInfo` (`ManufacturerCertificates`). On Linux: `tpm2_getekcertificate`.
- Validate the EK certificate chain to the manufacturer root CA via the manufacturer-published intermediate certificates. Infineon, Nuvoton, ST, Intel, AMD publish these. Cache the validated EK public key in the provisioning database.
- Create an AK using `tpm2_createak` (or platform-equivalent). Optionally, request a Privacy CA to issue an AK cert that the verifier will accept. The AK is the durable cryptographic identity for this device.

**Step 2 — baseline measurement (golden values):**
- Boot the device through the corporate gold image.
- Capture the PCR values from a known-good post-boot state. Capture the TPM event log alongside.
- Store both in the reference-value database. Tag with image version + firmware version + applicable software-bill-of-materials.
- Repeat for each accepted boot configuration the org supports (Windows / macOS / Linux variants, hardware models, firmware versions).

**Step 3 — runtime attestation:**
- Verifier issues a nonce to the device's attestation agent.
- Agent calls `TPM2_Quote(AK, PCR-selection, nonce)`.
- Agent collects the current TPM event log.
- Both are sent to the verifier.
- Verifier: signature-verify with cached AK public key → check nonce match → replay event log against PCR → look up PCR values in reference-value database → produce attestation result (pass / mismatch / indeterminate).
- Result is consumed by the ZT enrollment service as a device-posture signal: high if pass, medium if known-firmware-update-pending, low if indeterminate, deny if mismatch.

**Step 4 — periodic re-attestation:**
- Trigger conditions: scheduled (daily / weekly), session-bound (each VPN connect), policy-change-driven (new firmware deployment campaign), or anomaly-driven (process behavior flag from EDR).
- The challenge with periodic attestation: PCRs only update on boot (for SRTM) — if the device hasn't rebooted, the attestation evidence is identical to the previous one modulo the nonce. Detection must include log-replay over the period to catch runtime modifications via IMA or similar.

**Step 5 — incident response on attestation mismatch:**
- Confirm: is this a known firmware/OS update not yet in the reference-value database? Check the operational rollout calendar.
- If yes: update reference values, re-attest, close as benign.
- If no: isolate device pending forensic review. Pull the TPM event log + correlate to EDR boot-time telemetry. The event log identifies which specific component deviated.
- Common false positives: pending Windows feature updates, Linux kernel upgrades, BIOS auto-updates pushed by vendor agents.

**Cost realism:** running this program at fleet scale (10k+ devices) requires dedicated operational ownership for reference-value management, verifier infrastructure capacity, and an IR runbook for mismatch triage. Programs that ship the cryptography and skip the operations consistently disappoint.

**12-item operational checklist** for AppSec / platform-engineering leads standing up a hardware-attestation program:

1. **Substrate inventory.** Catalog what attestation hardware exists in your fleet: discrete TPM models, fTPM CPUs, mobile devices by OS/OEM, server platforms with TEE support, cloud-VM attestation availability. The inventory drives every other decision.
2. **Trust roots inventory.** For each substrate, identify the trust root (TPM manufacturer EK cert chain, Apple attestation root, Google Play Integrity, cloud provider attestation root). Cache + validate these as provisioning artifacts.
3. **Reference-value pipeline.** Stand up the pipeline from vendor-published expected values → reference-value database → verifier. Without this, attestation is theater (§13).
4. **Verifier choice.** Cloud-provider verifier (AWS / Azure / GCP) or org-internal (Veraison)? Document the trust trade-off and revisit if requirements change.
5. **Cache policy.** Define separate TTLs for endorsement chains (long) and evidence (short). Define cache-invalidation triggers (TCB recovery, policy change, key rotation).
6. **Nonce-and-freshness discipline.** Every attestation evidence verification must consume a fresh nonce. No exceptions.
7. **TCB minimum-SVN enforcement.** For TEE-based attestations, enforce minimum SVN per vendor security bulletins. Update enforcement promptly after each TCB recovery.
8. **Failure-mode policy.** Document policies for verifier outage, indeterminate results, valid-but-mismatched results. Test the policies via fault injection.
9. **Reference-value update SLA.** Set a target SLA from vendor firmware release → reference-value database update. Track the SLA; treat misses as ops issues, not security issues.
10. **Forensic readiness.** Ensure TPM event logs (or substrate-equivalent) are collected to the SIEM with integrity protection on transmission. Cross-link to `[[reference-dfir-methodology]]`.
11. **Cross-substrate composition.** If your architecture composes multiple attestations (host + GPU + supply-chain), document the composition rules. Build (or buy) verifier orchestration that handles them.
12. **Tabletop the failure modes.** Run an incident-response tabletop for each: TCB recovery, vendor verifier outage, mass attestation mismatch following a fleet firmware push, TPM-Fail-style side-channel disclosure. The first time you encounter these in production should not be the first time you've thought about them.

## 15. Cross-link cluster

- `[[reference-confidential-computing]]` — TEE attestation flavors (SGX / TDX / SEV-SNP / CCA / Apple PCC / NVIDIA H100 CC). §7 expands what's summarized here.
- `[[reference-webauthn-fido2-passkeys]]` — FIDO attestation formats. §9 cross-walks to the WebAuthn-format wire encoding.
- `[[reference-zero-trust-workload-identity]]` — device posture as ZT trust signal. §11 reference-value-management feeds into ZT enrollment.
- `[[reference-hsm-operational-discipline]]` — HSM-tier hardware roots of trust. Sibling at the operational tier; this doc focuses on the chain semantics, that doc on key-custody operations.
- `[[reference-hardware-side-channels]]` — TPM-Fail, EUCLEAK, fault injection. §13 attack corpus cross-references the side-channel discipline.
- `[[reference-embedded-device-hardening-playbook]]` — DICE on embedded; secure boot + measured boot for IoT. §5 and §12 cross-link.
- `[[reference-rtos-embedded-os]]` — DICE on RTOS; PSA Certified.
- `[[reference-secrets-management-discipline]]` — TPM2_Seal for at-rest key wrapping. §2 cross-links.
- `[[reference-ai-orchestration-harnessing]]` — hardware-rooted agent identity (emerging SPIFFE+Secure-Enclave pattern); H100 CC for confidential AI inference. §7 and §12.
- `[[reference-anti-fraud-abuse-engineering]]` — mobile attestation as bot defense. §8 and §14.
- `[[reference-ciam-consumer-identity]]` — consumer attestation flows; Apple App Attest for app integrity in consumer flows. §8.
- `[[reference-dfir-methodology]]` — TPM event log as forensic artifact; boot-time integrity for IR. §4.
- `[[reference-threat-modeling-discipline]]` — attestation as a trust-boundary primitive; assumptions about hardware integrity in threat models.
- `[[reference-vulnerability-research-methodology]]` — Binarly's LogoFAIL variant analysis as a methodology example. §13.
- `[[reference-detection-engineering]]` — runtime integrity (IMA-appraisal, eBPF) as complement to boot-time measurement. §6 and §14.

## Authoring notes

This doc anchors hardware attestation as a cross-cutting discipline. It does not redo TEE attestation, FIDO attestation, or HSM custody — those siblings are referenced, not duplicated. The center of gravity is verification discipline (§10) and honest failure modes (§13): most attestation programs ship the cryptography correctly and break on operations.

Primary sources cited: Brickell + Camenisch + Chen (DAA); Sailer + Zhang + Jaeger + van Doorn (IMA, USENIX Security 2004); Grawrock (Intel TXT book); Arthur + Challener + Goldman ("A Practical Guide to TPM 2.0", Apress 2015); Moghimi + Sunar + Eisenbarth + Heninger (TPM-Fail); Roche (EUCLEAK 2024); Nemec + Sys + Svenda (ROCA); Goryachy + Ermolov (Intel ME); Binarly (LogoFAIL); Smolár / ESET (BlackLotus); Regenscheid (NIST RoT-M); Birkholz (RATS RFC 9334 lead); Arm (Veraison, donated to the Confidential Computing Consortium). Trammell Hudson's Heads / coreboot research is referenced indirectly via the measured-boot ecosystem `[unverified specific attribution]`.

Gaps surfaced for future revisions:
- A separate doc on **reference-value management at fleet scale** (operational playbook). Currently §10 is the only treatment; deserves its own ~30KB sibling.
- A separate doc on **attestation in CI/CD supply chain provenance** — how attested builders (SLSA L3+) compose with sigstore + in-toto + attestation chains. Currently distributed across `[[reference-supply-chain-provenance]]`.
- A dedicated **DICE deep-dive** for embedded — current §4 mention is summary-only.
