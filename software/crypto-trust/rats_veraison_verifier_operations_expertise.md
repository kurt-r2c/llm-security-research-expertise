# RATS + Veraison Verifier Operations Expertise

Operations-side complement to `hardware_attestation_chains_expertise.md` (evidence collection) and `reference_value_management_expertise.md` (RV pipeline). This doc covers the **Verifier role** at the operational layer: what IETF RATS specifies, what Veraison implements, and what running an attestation verifier in production actually looks like.

---

## 1. Why this doc exists

Attestation has three load-bearing roles in the IETF RATS model: an **Attester** produces evidence about itself; a **Verifier** consumes evidence + reference values + endorsements and produces an attestation result; a **Relying Party** consumes the attestation result and makes a trust decision. The Verifier is the keystone — without it, evidence is uninterpretable and reference values are unused. Get the verifier wrong and every downstream trust decision is wrong.

Most attestation deployments in production today outsource the verifier to the cloud provider: AWS Nitro Enclaves attestation through KMS condition keys; Azure Microsoft Azure Attestation (MAA); GCP Confidential Space attestation verifier. These are convenient and closed-loop — and they are vendor-locked, opaque, and cross-cloud unfederated. Running your own verifier is the alternative. The canonical OSS implementation is **Veraison**, Linaro-led, CCC-adjacent, multi-substrate. Veraison is moving from research to early-production deployments as of 2026 `[unverified specific production-readiness status]`; this doc covers the operational shape of that path.

Audience: AI agents plus AppSec / platform-engineering / SRE running attestation-verifier infrastructure that composes TPM + TEE + SLSA + GPU + DICE substrates through one verifier API.

---

## 2. IETF RATS RFC 9334 architecture

**RFC 9334** (January 2023, "Remote ATtestation procedureS (RATS) Architecture") is the canonical reference. Authors: **Henk Birkholz** (Fraunhofer SIT, lead), **Dave Thaler** (Microsoft), **Michael Richardson** (Sandelman Software Works), **Ned Smith** (Intel), **Wei Pan** (Huawei). The doc took roughly five years from BoF to publication; the architecture is deliberately substrate-agnostic so that TPM, SGX, TDX, SEV-SNP, CCA, PSA, DICE, and future schemes share one role model.

The 5-role model:

- **Attester** — the workload/device producing evidence about its own state. Produces signed claims about boot measurements, code identity, configuration, runtime state.
- **Verifier** — consumes evidence + reference values + endorsements; runs appraisal procedures; produces attestation result.
- **Relying Party** — consumes attestation result; makes the trust decision (grant access, release secret, admit to workload pool).
- **Endorser** — vouches for an attester. Typically the manufacturer or OEM, signing the long-lived attestation key (EK certificate for TPM; provisioning certificate for SGX; VLEK certificate for SEV-SNP).
- **Reference Value Provider** — publishes the known-good measurements / hashes the verifier appraises against. Often the OS vendor, firmware vendor, or build system (SLSA provenance). Cross-link to `[[reference-reference-value-management]]`.

Two information flows:

- **Passport model:** attester obtains attestation result from verifier, then presents the result to the RP. RP never talks to verifier directly. Token-based; good for offline RP. The attestation result is a signed token (typically EAT) that the RP validates by checking the verifier's signature. Trade-off: result lifetime determines staleness; the RP cannot ask "is this still valid?" without involving the verifier.
- **Background-check model:** RP receives evidence from attester, forwards to verifier, receives result. RP and verifier are tightly coupled; good for online/synchronous trust decisions. Trade-off: every RP request adds a verifier round-trip; verifier must be HA enough to be in the request path.

A third hybrid: RP caches attestation results from a verifier with short TTLs, refreshing on miss. Practically common; not formally one of RFC 9334's named flows.

The token format is **EAT (Entity Attestation Token)**, published as **RFC 9711** `[unverified specific publication date — was in late-stage IESG review through 2024-2025; finalized as RFC 9711 some time in 2024-2026]`. EAT is CBOR-encoded by default with a JWT-compatible JSON serialization; defines standard claims (`nonce`, `ueid`, `oemid`, `swname`, `swversion`, `dbgstat`, `location`, `secboot`, etc.) plus profile-specific extension claims.

Reference values are carried in **CoRIM (Concise Reference Integrity Manifest)**, a CBOR-encoded format still in draft `[unverified specific draft revision and IETF adoption status as of 2026]`. CoRIM composes Reference Integrity Manifests (RIMs) for individual components; a CoSWID identifies the software component being measured. See `[[reference-reference-value-management]]` §3.

---

## 3. Veraison — the OSS verifier

**Veraison** is the Linaro-led, multi-substrate, modular attestation verifier. Project home: `github.com/veraison`. Maintainership and contribution: **Thomas Fossati** (Linaro, project lead), **Yogesh Deshpande** (long-time Veraison contributor), **Mike Bursell** (Confidential Computing Consortium co-founder, Profian, Veraison contributor), **Sergio Lopez** (Red Hat, CoCo + Veraison). Contributing orgs: Linaro, Confidential Computing Consortium, IBM, Microsoft, Arm, Red Hat, Intel `[unverified specific contributor list as of 2026]`.

Architectural shape:

- **Services CLI** (`services-cli`) — the runtime verifier; exposes a REST API for evidence appraisal.
- **Provisioning CLI** (`provisioning-cli`) — loads CoRIM-formatted reference values, endorsement certificates, and trust anchors into the verifier's stores.
- **Scheme handlers** — per-substrate plugins (PSA, SGX, TDX, SEV-SNP, CCA, TPM 2.0, DICE, CoCo). Each handler knows how to parse one evidence format, validate its signature chain, and extract the measurements that policy will appraise.
- **Policy engine** — declarative appraisal policy; OPA-style. Takes parsed evidence + matched reference values; emits attestation result with per-claim trust verdict.
- **Verifier API** — issues nonces, receives evidence, returns attestation results signed by the verifier's own key.

The core operational pattern is **challenge-response**: the RP (or the attester directly) requests a nonce from the verifier; the attester signs `(nonce || measurements)` with its attestation key; the verifier validates the signature, matches measurements against CoRIM reference values, applies policy, and returns an attestation result. The nonce binds the result to a specific request and defeats replay.

Internal pipeline (per request):

1. RP calls verifier API with evidence + a session nonce.
2. Verifier identifies evidence type from the EAT profile claim or content-type header; routes to the matching scheme handler.
3. Scheme handler parses evidence, validates signature chain against loaded trust anchors, extracts claims.
4. Verifier matches claims against CoRIM reference values (per-claim appraisal).
5. Policy engine evaluates the per-claim appraisal results against the per-RP policy; emits an AR4SI-shaped attestation result with per-claim verdicts.
6. Verifier signs the result with its own key; returns to the RP.
7. Audit log entry captures `(RP identity, evidence hash, nonce, policy version, RV-set version, result, timestamp)`.

Production maturity as of 2026 `[unverified specific status]`: Veraison is moving from research-grade to early-production. Linaro and CCC are driving adoption. CNCF Sandbox or Incubation status `[unverified specific governance state]`. Most attestation deployments still use the cloud-provider closed-loop verifier; Veraison adoption is concentrated in confidential-computing, edge-IoT, and embedded-device deployments where vendor neutrality matters.

**Verifier API surface (high-level).** Veraison's REST API exposes:

- `POST /challenge-response/v1/newSession` — RP requests a nonce-bearing session; returns a session ID and a nonce the attester must sign over.
- `POST /challenge-response/v1/session/{id}` — attester submits evidence against the session; verifier appraises and stores the result.
- `GET /challenge-response/v1/session/{id}` — RP polls or retrieves the attestation result.
- Provisioning interfaces for loading CoRIM bundles, trust anchors, and per-RP policy bindings.

`[unverified specific API surface as of Veraison's current release; consult the project's OpenAPI spec for authoritative shape]`.

**RP integration ergonomics.** RPs typically integrate by registering with the verifier (mutual TLS), authoring a policy bundle, and pointing their secret-release / admission-control / authorization logic at the verifier API. A common pattern: the RP authenticates the attester via the verifier ("does this evidence appraise positively under my policy?") rather than via independent code paths. This concentrates trust decision logic in the verifier and policy, not in the RP — which is the desired property if the verifier is itself trustworthy.

---

## 4. Per-substrate scheme handlers

Veraison's modular design means each substrate gets its own appraisal logic. The substrate set as of 2026 covers the practical TEE + TPM + DICE landscape:

**PSA scheme.** Arm Platform Security Architecture; Cortex-M devices using TrustZone-M and TF-M. Evidence format is the PSA Initial Attestation Token (IAT), an EAT profile. Reference values include:

- The PSA implementation ID (a 32-byte unique-per-implementation identifier).
- The PSA instance ID (a per-device identifier derived from the device's Initial Attestation Key).
- Software components: each has a measurement value, measurement type, signer ID, and version. Veraison appraises each against CoRIM-formatted golden values.
- A measured-boot chain anchored in the immutable boot ROM.
- Lifecycle state (e.g., `SECURED` vs `DECOMMISSIONED`); reference values typically require `SECURED`.

Production-mature for IoT/embedded.

**SGX scheme.** Intel SGX evidence flow: the enclave's `EREPORT` (locally signed by the platform's CPU using an enclave's `REPORTKEY`) is consumed by the Quoting Enclave, which re-signs the contents as an ECDSA-signed quote (DCAP attestation; the legacy EPID flow is deprecated). Veraison's SGX scheme handler:

- Validates the quote's ECDSA signature against the platform's PCK (Provisioning Certification Key) certificate, which chains up through Intel's PCK Processor CA and ultimately the Intel SGX Root CA.
- Fetches the corresponding TCB Info and QE Identity structures from Intel's PCCS (Provisioning Certificate Caching Service) or a locally mirrored copy.
- Extracts the enclave identity claims: `MRENCLAVE` (measurement of the enclave's code + data), `MRSIGNER` (hash of the enclave signer's public key), `ISVPRODID` (product ID), `ISVSVN` (security version), `ATTRIBUTES` (debug bit, mode bits), `MISCSELECT`.
- Appraises these against CoRIM-formatted reference values; rejects if MRENCLAVE drifts from golden, MRSIGNER is not in the allowed signer set, or `ATTRIBUTES.DEBUG` is set in a production policy.
- Enforces platform TCB SVN minimum; rejects quotes whose TCB level is below the policy's floor (mitigates known-vulnerable microcode/firmware).

Production-mature.

**TDX scheme.** Intel TDX, the VM-level confidential-computing successor to SGX. Evidence is a TDREPORT converted to a TDQUOTE by the platform. Verification structure is similar to SGX (ECDSA against Intel PCK chain) but the measured boundary is the full guest VM measurement rather than an enclave's code measurement. Maturing through 2024-2026.

**SEV-SNP scheme.** AMD SEV-SNP attestation report (ATTESTATION_REPORT structure) verified against AMD's Key Distribution Service (KDS) certificate chain, or against a VLEK (Versioned Loaded Endorsement Key) for the newer flow. Veraison validates the report signature, extracts the launch-measurement and TCB version, and appraises against reference values. Mature for AMD EPYC confidential VM deployments.

**CCA scheme.** Arm Confidential Compute Architecture, the Realm-VM model on Armv9 with the Realm Management Monitor (RMM). Evidence is an RMM token plus a platform token. The combined chain attests both the Realm contents and the underlying platform's RMM and firmware. Maturity is early — CCA silicon is just beginning to ship at scale in 2025-2026 `[unverified specific deployment scale]`.

**TPM 2.0 scheme.** Classic TPM-quoted PCR (Platform Configuration Register) values. The chain:

- TPM2_Quote produces a signed structure binding (selected-PCR-values || nonce) under an Attestation Key (AK).
- The AK is certified by the Endorsement Key (EK) via TPM2_Certify or an equivalent AK-creation flow.
- The EK is shipped with a manufacturer-issued EK certificate signed by the TPM manufacturer's root CA (Infineon, ST Microelectronics, Nuvoton, Intel PTT for firmware-TPM, AMD fTPM for AMD's firmware-TPM).

Veraison validates the EK cert chain to a trusted manufacturer root, validates AK certification by the EK, validates the quote signature by the AK, parses the PCR digest list, and appraises against CoRIM-formatted golden values per PCR index. Common policy gates: PCRs 0–7 (firmware + boot loader + kernel measurements), PCR 14 (boot loader code identity if used by GRUB / shim), and event-log replay-and-match to catch silently-mismatched aggregate digests. Mature. Cross-link to `[[reference-hardware-attestation-chains]]` §5.

**DICE scheme.** PSA-DICE (Device Identifier Composition Engine) layered attestation. Evidence is a chain of certificates each signed by the layer above; alias key certificates carry per-layer measurements. Veraison validates the certificate chain back to a known UDS-derived root and appraises layer measurements against reference values. Early-stage. Cross-link to `[[reference-dice-embedded-device-identity]]` §5.

**CoCo scheme.** Confidential Containers (Kata + TEE backend); evidence is one of the above substrate types depending on backend (SGX, TDX, SEV-SNP, CCA), wrapped in a CoCo-specific envelope. Maturing.

Per-substrate honest framing: schemes mature at different paces. SGX, TDX, SEV-SNP, TPM 2.0, and PSA are production-ready. CCA, DICE, and CoCo are early-stage. Composite schemes (e.g., TDX + TPM + SLSA in one decision) are research-grade.

---

## 5. Policy engine architecture

Veraison's policy engine takes the parsed-and-validated evidence from a scheme handler and produces an attestation result. The decision language is OPA-style declarative (Rego or a Veraison-specific dialect `[unverified specific current implementation]`).

**Per-RP policy.** Different relying parties have different acceptance criteria. A secret-management service might require TPM PCR 0-7 + SGX MRENCLAVE both pass. An admission controller might accept TPM PCR 0-7 only. Veraison provides the policy framework; per-RP policies are authored separately and bound to the RP's authentication context.

**Reference value composition.** Policy can require multiple substrates simultaneously. Example: an AI inference service requires (a) TPM PCR-quoted boot chain matches golden, (b) GPU firmware version meets minimum SVN, (c) SLSA provenance for the model weights matches the registered build. All three must pass for the verifier to issue a positive attestation result. Cross-link to `[[reference-reference-value-management]]` §12.

**TCB minimum SVN enforcement.** Policy gates on the TCB Security Version Number; rejects attestations from outdated TCBs. This is critical for Intel SGX/TDX and AMD SEV-SNP, where vulnerable microcode releases get reflected in TCB SVN bumps. A verifier that doesn't enforce minimum SVN is silently accepting attestations from known-vulnerable hardware. Operational pattern:

- Track vendor-published TCB recovery events (Intel publishes them through the PCS / PCCS; AMD publishes through KDS).
- Update verifier policy floor on a schedule aligned with vendor publication.
- Provide a transition window where attestations below the new floor get a "soft-fail" verdict (logged + alerted) before becoming hard-fail; this catches drift in attester populations before it becomes an outage.

**Policy version pinning.** Each appraisal result should record the policy version that produced it. Cross-link to §9 audit-log pattern. Without this, audit reconstruction of past decisions is impossible when policy has evolved between decision and audit.

**Negative results: contraindication vs absence.** AR4SI distinguishes "Contraindicated" (a claim was appraised and failed) from "None" (the claim was not appraised at all). RPs must treat these differently: contraindicated is an active negative signal; absent is unknown. A common bug: RPs treat "no contraindication" as "appraised pass," accepting attestations where the verifier never even appraised the relevant claim.

**Result claims.** Veraison emits attestation results in the **AR4SI (Attestation Results for Secure Interactions)** format, which provides standard trust-tier claims: `instance-identity`, `configuration`, `executables`, `file-system`, `hardware`, `runtime-opaque`, `storage-opaque`, `sourced-data`. Each gets a trust-tier verdict (Contraindicated / Affirming / etc.). RPs consume these to make granular trust decisions rather than a binary pass/fail.

---

## 6. Operational deployment patterns

**Inline verifier.** Verifier sits in the RP's request path; every attestation call routes through it. Latency cost is one verifier round-trip per request, typically 10-100ms depending on substrate (TPM quote validation is fast; SGX quote validation against fresh PCK chains is slower). Operational benefit: every decision is live; no stale results. Use when trust decisions are tied to short-lived secrets, per-request authorization, or admission control where a stale result would be unacceptable.

**Background verifier.** Verifier produces signed attestation result tokens (EAT-formatted); RP consumes tokens out-of-band, validates the verifier's signature, and applies the result locally. Latency cost is amortized; one verifier round-trip serves many subsequent RP decisions. Operational risk: result staleness if not bounded by short token lifetimes.

**Cluster verifier.** Veraison as a Kubernetes deployment; multiple replicas behind a load balancer; shared reference-value store (etcd, Redis, or a database). HA is straightforward; the reference-value store becomes the SPOF that must be protected. Policy updates propagate through the store; rolling restarts apply policy without dropping traffic. Operational discipline:

- Replicas should run independently signed binaries (build provenance attached) to detect tampering of one replica without the others.
- Store-level integrity: signed reference value bundles; consumer replicas verify signature before loading.
- Per-replica health gates: a replica that fails its own self-attestation should be removed from the load-balancer pool automatically.

**Cloud-hosted alternative.** AWS Nitro Enclaves attestation + KMS condition keys (the relying party is KMS, which only releases keys if the Nitro attestation document satisfies a key policy condition). Azure MAA (Microsoft Azure Attestation) — managed verifier service. GCP Confidential Space attestation — managed verifier embedded in the Confidential VM platform. Each is closed-loop and convenient; each is a single-cloud lock-in.

**Edge verifier.** For IoT or industrial scenarios where attestation evidence shouldn't leave the local network (privacy, latency, regulatory). Veraison can run at the edge — small footprint, no cloud dependency. The reference-value provisioning pipeline still needs a path back to vendors for golden-value updates; that pipeline tolerates batch updates better than online queries.

**Air-gapped verifier.** For classified, OT, or regulated environments with no external network. Reference values must be hand-imported on physical media; vendor revocation lists similarly. The operational burden is high (manual processes for every vendor advisory) but the threat model is reduced (no online compromise path for the trust-anchor store). Used in defense + critical infrastructure deployments.

**Multi-region / multi-cloud verifier federation.** Doesn't exist as a productized pattern in 2026 `[unverified federation-spec status]`. Each cloud's managed verifier is siloed; Veraison instances across regions can be deployed but coordinated policy and shared reference values are per-deployment custom work.

**Operational checklist for a new Veraison deployment** (12 items):

1. Identify substrates in scope (TPM only? TPM + SGX? TPM + SEV-SNP + SLSA?).
2. Provision per-substrate trust anchors (TPM manufacturer roots; Intel SGX Root CA; AMD KDS / VLEK roots; PSA root keys; CCA root keys).
3. Define RV provenance (which signers will sign CoRIM bundles; rotation cadence; revocation handling).
4. Author per-RP policies (one Rego module per RP; version-pinned; reviewed at a higher bar than ordinary code).
5. Deploy verifier in HA configuration (≥3 replicas; per-replica self-attestation; load balancer with health gates).
6. Establish reference-value ingestion pipeline (vendor → RV signer → CoRIM bundle → verifier store).
7. Configure audit logging to tamper-evident external sink with hash chaining + external timestamping.
8. Set up monitoring and alerting (RV staleness, scheme handler error rates, policy fall-through rates, verifier replica health).
9. Author runbooks for each operational failure mode (verifier compromise, trust anchor rotation, RV signer compromise, policy bug, scheme handler crash).
10. Test negative paths (forged evidence, expired evidence, wrong-policy, contraindicated claims): verifier must reject all.
11. Plan substrate addition (when a new substrate is required, what's the rollout path? Per-substrate policy must be authored and reviewed before traffic).
12. Plan substrate removal (when retiring a substrate, how is consumer migration sequenced?).

---

## 7. The bootstrap-trust problem

The keystone problem: who attests the verifier? The verifier is trusted by relying parties to produce truthful attestation results; if the verifier is compromised, every result it issues is forged.

**Verifier-in-TEE.** Recursive attestation: run the verifier itself in a TEE (SGX enclave, TDX VM, SEV-SNP VM, CCA Realm); have a higher-tier verifier attest the verifier. This pushes the bootstrap problem up one level but doesn't eliminate it. Production deployments rarely go beyond two tiers. The practical pattern: a small "root verifier" running in TEE attests one or more "workload verifiers" that handle the bulk of appraisals. The root verifier has a smaller trust footprint and rotates less frequently than workload verifiers. RPs that need maximal assurance can verify against the root verifier; throughput-sensitive RPs use workload verifiers backed by the root's attestation.

**Endorsement key distribution.** Vendor PKI for hardware roots: TPM manufacturer root CAs, Intel attestation key chains, AMD VLEKs. Veraison needs the trust anchors loaded before it can validate any chain. Distribution is the operational pain — keeping the trust anchor set current as vendors issue new roots, revoke compromised intermediates, and rotate per-product certificates. Cross-link to `[[reference-hsm-operational-discipline]]` §13.1 for the analogous problem in HSM PKI.

**Reference value provenance.** CoRIM-formatted reference values are signed by the vendor (or build system); vendor signing-key compromise yields forged reference values, which yields silently-accepted-as-good measurements that are actually attacker-controlled. The reference-value provenance chain is as load-bearing as the attestation chain itself. Operationally:

- Verifier deployments should pin the set of trusted RV signers explicitly; transitive trust through an intermediate CA leaks if the CA is compromised.
- Rotation of RV signing keys must be propagated to all verifier instances before consumers' attestations under the new key arrive; out-of-order rotation breaks verification.
- A revoked RV signer's prior reference values may still be in the active set; per-RV expiry and explicit removal are both required.

See `[[reference-reference-value-management]]` §6.

**Audit log integrity.** The verifier logs every appraisal decision: which RP requested, which evidence was appraised, which reference values matched, which policy fired, which result was returned. Logs must be tamper-evident — append-only storage, hash-chained log entries, periodic external timestamping. A verifier whose audit log can be rewritten is a verifier whose past decisions can be denied. Practical operational patterns:

- Write logs to an external system with append-only semantics (object storage with object-lock; managed log service with immutability).
- Hash-chain log entries so that tampering with one entry invalidates all subsequent entries.
- Submit periodic log-head hashes to an external timestamping authority (RFC 3161 TSA or a transparency log).
- Replay-against-RV-set-version: capture the active reference value set version per decision so that historical decisions can be reconstructed deterministically.

---

## 8. Multi-substrate composition

Production AI deployments increasingly span multiple attestation substrates simultaneously: TPM for boot integrity of the host, SGX or TDX or SEV-SNP for confidential workload execution, SLSA provenance for build chain, GPU firmware attestation for inference accelerators, DICE for embedded sensors feeding the pipeline. Composing verification across these is non-trivial.

**The cross-substrate verifier problem.** Each substrate has its own evidence format, its own signature chain, its own reference value semantics, its own TCB versioning. A single attestation result that says "the entire compute pipeline is trustworthy" requires composing N independent verifications and binding them to one workload identity. Cross-link to `[[reference-reference-value-management]]` §12 for the RV side.

**Veraison's modular approach.** Scheme handlers + policy engine can express cross-substrate composition: a Rego policy requiring TPM appraisal-pass AND SGX appraisal-pass AND SLSA-provenance-match emits a single composite result. Operational maturity is early; the per-substrate handlers are independently sound, but real-world cross-substrate policies are sparsely deployed.

**Alternative composers.** Custom code in the RP path that calls N independent verifiers and ANDs the results. Cloud-provider managed composition (closed-loop; tied to one cloud's verifier services). Service-mesh-mediated attestation where SPIFFE/SPIRE-style identity carries attestation provenance forward into workload identity. Cross-link to `[[reference-zero-trust-workload-identity]]` and `[[reference-service-mesh-security]]`.

**Composition pitfalls.**

- Substrates have different time semantics: TPM measurements are boot-time; SGX measurements are enclave-launch-time; SLSA provenance is build-time; GPU firmware measurement is power-on-time. Composing requires reasoning about which evidence is current vs which is anchored at an earlier event.
- Substrates have different nonce semantics: not all substrates accept arbitrary verifier-supplied nonces (some require pre-provisioned challenge structures). Composing across them may force the verifier to use different freshness mechanisms per substrate.
- Substrates have different TCB version semantics: SGX/TDX/SEV-SNP have per-vendor TCB versioning; TPM uses firmware version; SLSA uses build version. The composer must keep per-substrate floors in sync with vendor advisories.
- Substrates fail differently: an SGX appraisal-fail might be "enclave debug-mode was set"; a TPM appraisal-fail might be "PCR 7 drift"; a SLSA fail might be "build provenance signed by an unauthorized signer." The composer must produce a result the RP can act on without leaking which substrate failed (in some threat models) while remaining diagnosable (in others).

---

## 9. Failure modes + operational anti-patterns

**Reference value staleness.** Verifier accepts outdated TCB minimums; RPs unknowingly accept attestations from hardware vulnerable to published CVEs. Mitigation: automated CoRIM ingestion from vendors; policy gates on rolling minimum SVN; alarms on stale reference-value sets older than threshold.

**Policy drift across RPs.** Different RPs accumulate different acceptance criteria; coordinated policy update is hard; some RPs lag, accepting evidence that newer RPs reject. Mitigation: centralized policy library with per-RP overlay; policy version pinning; audit of in-use policy versions. The pain is real — a verifier with 50 RPs running 50 slightly-different policies has 50 audit surfaces and 50 update sequences. Consolidation toward a small set of policy templates is the operational endgame.

**Verifier-as-SPOF.** Verifier outage = no trust decisions = workload admission stalls. HA discipline is mandatory for inline-verifier deployments. Background-verifier deployments are more outage-tolerant (cached results extend through verifier downtime) at the cost of staleness risk.

**Bootstrap-trust dependency.** Verifier compromise = all downstream attestation results forged. Mitigations are partial: run verifier in TEE, distribute verifier signing keys across HSMs, harden the verifier's host. No mitigation eliminates the recursion.

**Cross-cloud verifier federation doesn't exist.** AWS / Azure / GCP each run their own closed-loop verifiers; multi-cloud workloads need a "verifier-of-verifiers" pattern that doesn't exist as a productized capability in 2026 `[unverified specific federation-spec progress]`.

**Endorsement key revocation lag.** When a vendor revokes a signing key (TPM manufacturer issue, Intel PCK rotation, AMD VLEK refresh), verifiers must update their trust anchor sets. Coordination is operational pain; verifier instances on stale trust anchor sets either reject valid attestations or accept attestations under revoked keys.

**Closed-loop cloud verifier = vendor lock-in.** Azure MAA, AWS Nitro KMS conditions, GCP Confidential Space — each binds the trust decision to one cloud's verifier. Migration requires re-architecting the RP layer.

**Verifier API authentication tier.** RPs must authenticate to the verifier (otherwise any caller can request attestation appraisal); verifier must authenticate to RPs (otherwise an impostor can forge attestation results). Mutual PKI adds yet another trust tier; misconfiguration is common.

**EAT vs JWT format wars.** EAT is the CBOR-encoded RATS-native format; many web-integrated RPs expect JWT. Cross-format support is uneven; verifiers may emit one or the other but rarely both. Result: RP integration code becomes format-specific.

**Audit log gaps.** Verifier deployments that don't capture which reference value set was active at decision time cannot reconstruct past decisions after a reference-value update. Time-travel debugging fails. The audit log must include the active RV-set version, not just the evidence and result.

---

## 10. 2024-2026 currency

**RFC 9334 finalized January 2023.** The architecture is stable; profile work (EAT profiles per substrate) continues.

**RFC 9711 EAT.** Finalized as RFC 9711 some time in 2024-2026 `[unverified specific publication date — was through IESG review in late 2024]`. EAT profiles for PSA, SGX/TDX, SEV-SNP, TPM, CCA are at various draft maturity stages.

**CoRIM draft progress.** Still in draft as of 2026 `[unverified specific draft revision and IETF adoption status]`. Vendor adoption growing for TPM and PSA; SGX/TDX/SEV-SNP CoRIM tooling maturing.

**Veraison status.** CCC project; Linaro-stewarded; CNCF Sandbox or similar `[unverified specific governance state]`. Production deployments growing in confidential-computing and edge-IoT.

**CCA verifier scheme maturation 2024-2026.** Armv9 silicon shipping; Realm Management Monitor specifications stable; verifier-side support landing in Veraison. CCA's two-token shape (Realm token + platform token) is structurally novel — the Realm attests its own contents, but a separate platform attestation is required to trust the RMM that vouches for the Realm. Verifier scheme handlers must compose both before issuing an attestation result.

**Cross-substrate work in the IETF.** RATS WG charter through 2024-2026 includes profile work for per-substrate EAT bindings, CoRIM advancement, and AR4SI standardization `[unverified specific draft revisions]`. The composition problem itself is identified as future work; no spec currently mandates how cross-substrate attestation results compose.

**Cloud-provider managed verifier divergence.** Each provider's managed verifier evolves on its own schedule with proprietary extensions. As of 2026, there is no cross-cloud verifier interoperability spec. RPs that need multi-cloud trust must either pick one cloud or run their own verifier (Veraison or equivalent).

**AI-workload attestation as emerging frontier.** NVIDIA H100 GPU attestation provides signed measurements of GPU firmware and confidential-compute mode (NVIDIA's "remote attestation" feature gates confidential workloads on signed CC-mode evidence). Apple Private Cloud Compute publishes per-image attestation and transparency-log entries for every server image fielded. Veraison scheme-handler extensions for AI workloads are research-grade. The structural shape — attest the host, attest the accelerator, attest the model — is clear; the productized pipeline is not. The current state of practice: enterprise AI deployments rely on the cloud provider's closed-loop attestation (AWS / Azure / GCP confidential AI services); a vendor-neutral verifier-of-AI-workload pattern is the open frontier.

**Confidential AI inference attestation primitives** `[unverified vendor-product specifics]`:

- GPU firmware version + signed identity (NVIDIA H100, AMD MI300 confidential compute mode).
- Driver / runtime version (CUDA, ROCm) measurement.
- Model weights digest matched against an SLSA-attested build of the model.
- Inference framework integrity (vLLM, Triton, TensorRT-LLM).
- The host CPU TEE measurement (TDX or SEV-SNP) under which all of the above runs.

Composing these into one attestation result is exactly the "multi-substrate composition" problem from §8.

---

## 11. Honest failure modes (load-bearing)

**Most attestation deployments don't run their own verifier.** Cloud-provider managed is the default in 2026. Veraison adoption is research-grade and concentrated in confidential-computing, edge-IoT, and embedded segments. The "running your own verifier" expertise being documented here is rare-skill territory.

**Verifier operational expertise is rare.** Same fluency gap as STPA-Sec or SPIFFE/SPIRE federation. Engineers comfortable provisioning trust anchors, authoring CoRIM, debugging scheme-handler appraisal failures, and writing OPA policy gates against AR4SI claims are uncommon.

**Multi-substrate composition is unsolved at production maturity.** Per-substrate verification is sound; composing TPM + SGX + SLSA + GPU into one trust decision requires per-deployment custom code. No vendor-neutral "composer" exists as a productized capability.

**Bootstrap-trust is the chicken-and-egg.** Verifier must be trustworthy; trusting the verifier requires another verifier or out-of-band trust. The recursion ends somewhere — usually in vendor PKI for hardware roots — and that endpoint is non-negotiable trust.

**Reference value distribution lacks federation.** Cross-cloud RV federation doesn't exist; each ecosystem is siloed. CoRIM is the format-level enabler; the distribution infrastructure is per-vendor.

**Policy expressiveness vs simplicity trade-off.** Rego is expressive but hard to audit at the trust-decision boundary. Simple policies are easy to audit but cannot express cross-substrate composition. Production deployments settle on intermediate dialects with limited expressiveness in exchange for review tractability.

**Verifier API authentication adds another PKI tier.** RP-to-verifier and verifier-to-RP authentication usually use mutual TLS with per-RP client certificates. Certificate lifecycle for this tier is yet another operational burden; misconfiguration here silently breaks attestation enforcement.

**EAT vs JWT cross-format support is uneven.** Verifiers that emit only EAT cannot serve web-integrated RPs that expect JWT without a transcoder. Verifiers that emit only JWT lose the RATS-native CBOR efficiency. Format choice is per-deployment lock-in.

**Closed-loop cloud verifier services are convenient but vendor-locked.** Multi-cloud workloads suffer disproportionately. The economics favor lock-in: cloud-managed verifiers are integrated with KMS / IAM / admission control in ways Veraison cannot replicate without significant local engineering.

**AI-workload attestation extensions are research-grade in 2026.** Production AI deployments using Veraison scheme handlers for GPU + model-weight + inference-runtime composition are rare. NVIDIA's H100 attestation is real; Veraison handler maturity for it is early. Apple PCC is closed-loop. The frontier is open.

**Verifier supply chain.** The verifier's own binary and dependencies must be trustworthy. SLSA provenance for the Veraison build chain is a precondition; reproducible builds are an aspiration. Cross-link to `[[reference-supply-chain-provenance]]`.

**Verifier key compromise = retroactive attestation forgery.** If the verifier's signing key is compromised, an attacker can mint signed attestation results that any RP will accept. Mitigations: store verifier signing keys in HSM; rotate on a schedule; use short-lived signing certificates; submit issued attestation results to a transparency log so that retroactive forgery becomes detectable. Cross-link to `[[reference-hsm-operational-discipline]]`.

**Per-substrate handler version skew.** Veraison scheme handlers evolve as substrates evolve (new TCB SVN handling, new EAT profile claims, new vendor cert chain changes). Running mismatched handler versions across cluster replicas yields inconsistent appraisal results for the same evidence. Operational discipline: synchronized handler versions across replicas; canary deployment of new handler versions before fleet-wide rollout.

**Observability gaps.** Verifier deployments commonly under-instrument. Operators need per-substrate appraisal rates, per-policy fall-through rates, RV-set staleness, scheme handler error counts, trust anchor age, audit-log lag, and HSM signing latency. OpenTelemetry instrumentation per scheme handler plus a verifier-wide metrics surface is the minimum bar; deployments that skip this debug the next outage by reading code.

**Lack of negative-case test coverage.** Verifier deployments tend to test the happy path (valid evidence appraised against current RVs yields positive result). The interesting tests are negative: forged signatures, expired evidence, mismatched MRENCLAVE, below-floor TCB SVN, missing claims, replay of stale nonces. A verifier that hasn't been exercised against negative cases has unknown rejection behavior. Discipline: maintain a negative-case test corpus per substrate, run it in CI, alarm on regressions.

**Researcher fluency gap.** Few security researchers operate verifier deployments; few verifier operators read the RATS spec deeply. Cross-pollination is rare. The result: verifier deployments that satisfy compliance but not threat-model rigor, and threat models authored by researchers who don't know the operational constraints.

**Substrate-specific replay defenses vary.** EAT nonce binding defeats replay at the protocol level, but per-substrate evidence formats vary in how they bind nonces. SGX quotes include a `REPORTDATA` field bound to the nonce; TPM2_Quote includes the qualifying-data field; PSA IAT carries a nonce claim. SEV-SNP report carries a `REPORT_DATA` field. Verifier must enforce nonce-binding per substrate; gaps here enable replay attacks that look like valid attestations.

**Time-of-check / time-of-use gap.** A verifier appraises evidence at instant T; the RP uses the resulting attestation result at instant T+Δ. During Δ, the attester's state can change — firmware can be downgraded, an enclave can be terminated, configuration can drift. EAT lifetime claims (`iat` issued-at, `exp` expiry) bound Δ; RPs must enforce expiry; attestation results consumed past expiry are stale. The bound on Δ trades freshness against verifier load.

**Operator-error class: appraisal-pass without sufficient claims.** A policy that says "if any single substrate appraisal passes, return positive result" silently accepts incomplete attestations. Policy authoring discipline: require explicit ALL-of for composed attestations; explicit ANY-of only when documented intent. Default to require-all.

**Bug-class: scheme handler signature-validation flaws.** A scheme handler that mis-parses or skips signature validation accepts forged evidence. These bugs are equivalent to JWT alg-confusion or X.509 chain-validation flaws at impact. Cross-link to `[[reference-saml-federation]]` for the analogous defect class in identity tokens. Veraison's per-substrate handlers should be exercised against negative-case test corpora; per-handler fuzzing of parser inputs catches a substantial fraction of these.

**Bug-class: CBOR vs JSON parser asymmetry.** EAT supports both CBOR and JSON encodings of the same logical token. A verifier that handles both must ensure semantically-equivalent tokens produce identical appraisal results. Asymmetry — where CBOR claims are interpreted differently than JSON claims — is a parsing-differential bug class. Mitigation: shared claim-extraction logic across encodings; differential testing.

**Bug-class: trust anchor confusion across vendors.** Loading TPM manufacturer root certs alongside Intel SGX root certs alongside AMD KDS roots into one trust store creates risk that a chain validation routine accepts a chain rooted in the wrong anchor. Per-substrate scheme handlers should query disjoint anchor stores; cross-substrate anchor leakage is a high-impact bug.

**Operator-error: silently demoted policy.** If a policy gate is misconfigured to "warn" instead of "reject," failing attestations get logged but accepted. Without an alerting pipeline on warn-mode hits, operator gets no signal. Discipline: deploy policy in shadow mode first (decisions logged but RP still gets the legacy result), confirm zero false-rejects, then flip to enforce. Never run permanently in warn mode.

---

## 12. Cross-link cluster

- `[[reference-hardware-attestation-chains]]` — attester-side evidence collection across TPM/TEE/SLSA/GPU/DICE substrates.
- `[[reference-reference-value-management]]` — RV pipeline that feeds the verifier with CoRIM-formatted golden values.
- `[[reference-dice-embedded-device-identity]]` — DICE substrate that a Veraison DICE scheme handler consumes.
- `[[reference-puf-based-device-identity]]` — PUF-rooted device identity feeding attestation chains.
- `[[reference-confidential-computing]]` — TEE landscape (SGX/TDX/SEV-SNP/CCA) whose evidence Veraison appraises.
- `[[reference-hsm-operational-discipline]]` — analogous PKI / trust-anchor operational discipline for the HSM tier.
- `[[reference-secrets-management-discipline]]` — RP downstream of verifier; secret release gated on attestation result.
- `[[reference-supply-chain-provenance]]` — SLSA provenance composed alongside hardware attestation in multi-substrate decisions.
- `[[reference-webauthn-fido2-passkeys]]` — user-side attestation chain analogue; not RATS but adjacent trust-decision model.
- `[[reference-zero-trust-workload-identity]]` — workload identity downstream of attestation; SPIFFE-style binding.
- `[[reference-service-mesh-security]]` — mesh-mediated attestation propagation into workload identity.
- `[[reference-ai-orchestration-harnessing]]` — AI-workload attestation frontier; GPU + model-weight verification in agent runtimes.

---

A verifier you do not operate is a trust decision you do not control. The verifier-operations skill set — RATS architecture, Veraison scheme handlers, CoRIM provenance, policy authoring, trust-anchor lifecycle, bootstrap-trust recursion — is the rare-skill complement to attestation evidence collection. Build it once; it composes across substrates for the next decade.
