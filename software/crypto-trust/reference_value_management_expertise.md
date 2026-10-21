# Reference-Value Management at Fleet Scale

Operational discipline for the verifier-side database of "what good looks like." Companion to attestation-chain mechanics (`[[reference-hardware-attestation-chains]]`) and DICE identity (`[[reference-dice-embedded-device-identity]]`). Attestation evidence is cryptographic claims about a runtime; reference values are the rows the verifier checks them against. Wrong, missing, or stale reference values reduce attestation to theater.

Audience: AI agents; AppSec / platform-engineering lead / SRE running attestation verification at 10K-10M endpoints (server fleet, IoT product line, container fleet, mobile-app integrity, supply-chain provenance). Scope is operational — generation, distribution, storage, comparison, update, decommission — not single-device verification mechanics.

---

## 1. Why a separate doc

`[[reference-hardware-attestation-chains]]` §11 names "reference values golden vs runtime as load-bearing pipeline" as a top-3 load-bearing claim but does not develop it. `[[reference-dice-embedded-device-identity]]` §10 covers DICE-specific reference-value generation (CDI-derived alias-key public keys). Neither anchors fleet-scale reference-value management as its own discipline.

Reference-value management is operationally distinct from attestation-chain mechanics in three ways:

1. **State problem, not protocol problem.** Attestation chains are mostly cryptographic protocol questions — does the signature verify, does the certificate chain to a trusted root, is the nonce fresh. Reference-value management is mostly a database / pipeline / freshness problem.
2. **Fleet-scale automation is non-optional past ~100 endpoints.** Single-device verification can be hand-curated. A 50K-server fleet across 30 firmware revisions and 12 BIOS versions cannot.
3. **The verifier's policy lives here.** A verifier without reference values accepts every well-signed attestation, including the attacker's well-signed attestation from a known-vulnerable firmware. Reference values encode the policy that distinguishes good from compromised.

This doc covers what reference values are (§2), how they move through their lifecycle (§3), the IETF + TCG framing (§4), distribution channels (§5), fleet-scale operational discipline (§6), the TCB-recovery operational pain (§7), supply-chain reference values (§8), detection-engineering reference values (§9), real-world implementations (§10), 2024-2026 currency (§11), honest failure modes (§12), and cross-links (§13).

---

## 2. What "reference value" means across substrates

A reference value is a known-good measurement, hash, identity, or policy artifact that a verifier compares incoming attestation evidence against. The substrate determines the shape.

### 2.1 TPM PCR golden values

Measured-boot writes hash extensions into PCRs 0-23 (TPM 2.0). The reference-value set is the expected PCR contents per platform configuration:

- **PCR 0:** S-CRTM, BIOS, host platform extensions
- **PCR 1:** host-platform configuration (UEFI variables, SMBIOS)
- **PCR 2-3:** option ROM code and configuration
- **PCR 4-5:** IPL (initial program loader) code and configuration
- **PCR 7:** Secure Boot policy (PK / KEK / db / dbx contents)
- **PCR 8-9 (Linux):** kernel command line, initrd

A complete golden-value set is one row per (vendor × platform × BIOS revision × Secure Boot key set × kernel build). Multiply: a midsize fleet with 5 platforms × 8 firmware revisions × 3 kernel builds = 120 rows minimum, growing as firmware ships.

### 2.2 TEE MRENCLAVE / MRSIGNER + minimum SVN

Intel SGX exposes two enclave identities:

- **MRENCLAVE** — hash of enclave code + initial data + measurement of memory pages at load. Identifies a specific enclave build.
- **MRSIGNER** — hash of the public key that signed the enclave. Identifies the developer / signing authority.

Reference values are typically `(MRSIGNER, product_id, minimum_isv_svn, minimum_tcb_svn)` tuples. Accept any enclave signed by this MRSIGNER, with this product ID, at or above this ISV SVN, running on TCB at or above this version. See §7 for TCB recovery operational pain.

### 2.3 TDX / SEV-SNP measurements

- **Intel TDX:** `MRTD` (Trust Domain measurement) + `RTMR[0..3]` (runtime measurement registers) + `MRCONFIGID` / `MROWNER` / `MROWNERCONFIG`. Reference values cover guest kernel + initrd + cmdline + vTPM state.
- **AMD SEV-SNP:** launch digest + ID-block + initial VMSA measurement. Reference values mirror the launch-time guest image.

### 2.4 DICE CDI-derived public keys

DICE deterministically derives a per-device alias-key public key from the chain (UDS, firmware measurements). The reference value is the alias-key public key the verifier expects for a known-firmware device. Cross-link `[[reference-dice-embedded-device-identity]]` §10.

A subtlety: DICE reference values are per-device, not per-firmware. The firmware vendor cannot publish a single reference value good for a fleet; the verifier must derive expected alias-keys from a UDS-database the device manufacturer holds. This is why DICE deployments tend to live behind device-manufacturer-operated provisioning services.

### 2.5 Supply-chain provenance attestations

- **in-toto attestations** — generic supply-chain step evidence.
- **SLSA provenance** — `buildType`, `builder.id`, `invocation`, `materials`. Verifier policy specifies the expected builder identity and source repo.
- **sigstore signatures** — OIDC-identity-bound signatures (Fulcio short-lived certs) recorded in Rekor.
- **npm / PyPI Trusted Publishing attestations** — OIDC-bound provenance from GitHub Actions / GitLab CI publishing pipelines.

Reference values here are policy: "accept artifacts signed by this OIDC identity from this repo's main branch builds." Concrete sigstore comparison: `cosign verify --certificate-identity-regexp ... --certificate-oidc-issuer ...`.

### 2.6 Runtime golden values

- **Falco rule corpus** — expected vs unexpected syscall sequences. Cross-link `[[reference-falco-tetragon-runtime-detection]]`.
- **AppArmor / SELinux MAC profiles** — permitted-binary, permitted-access tuples.
- **Allowed-binary hash lists** — Microsoft Defender ASR rules, Apple Endpoint Security cdhashes, Linux IMA appraisal hashes.
- **eBPF LSM policy** — allowed syscall + ringbuf-shaped runtime constraints.

### 2.7 WebAuthn AAGUID + FIDO MDS

`[[reference-webauthn-fido2-passkeys]]` §4 covers the FIDO Metadata Service (MDS) as a reference-value provider for authenticator models. The AAGUID-keyed metadata entries publish supported algorithms, attestation root certs, certification level, known-issue advisories. Relying-party policy accepts AAGUIDs above a chosen FIDO Certified Level, rejects those with status reports of `REVOKED` or `USER_VERIFICATION_BYPASS`.

### 2.8 TLS certificate transparency

CT logs are a global reference-value substrate for X.509 certificates. CAs append issued certificates to logs; clients (browsers, agents) gate trust on SCT (Signed Certificate Timestamp) presence. Reference value: "this cert appeared in two trusted CT logs at this time." Operational use: Facebook / others run CT-monitoring services that flag unexpected certs for owned domains.

---

## 3. The reference-value lifecycle

Six stages. Every stage has failure modes.

### 3.1 Generation

The originating party measures + publishes. Examples:

- **Firmware vendor** measures the firmware blob during build, publishes the hash (ideally signed). Cisco, Dell, HPE, Lenovo, Supermicro do this with varying rigor.
- **Software build pipeline** measures the artifact + signs a SLSA provenance attestation. GitHub Actions OIDC + sigstore is the dominant 2024-2026 stack.
- **CA mints a cert** with a measurement extension (rare; some IoT device certs embed firmware hash in the cert SAN).
- **Enclave developer** publishes (MRSIGNER, product_id, expected MRENCLAVE list) per release.

### 3.2 Distribution

Consumer (operating org) fetches reference values from the originating party. See §5 for channels. The signal-to-noise problem dominates: vendors publish hashes on download pages with no machine-readable format, no PKI binding to the firmware, no freshness signal.

### 3.3 Storage

Consumer maintains a reference-value database. Options:

- **Veraison policy store** (OSS, Confidential Computing Consortium project) — explicit reference-value store with verifier integration.
- **Cloud-provider managed** — AWS KMS condition keys with PCR values; Azure MAA reference-value bundle; GCP Confidential Space attestation policy.
- **Custom database** — large enterprises build their own; significant engineering investment.
- **No store** — many "we do attestation" deployments compare incoming attestations against a hardcoded list or no list at all.

### 3.4 Comparison

Verifier matches incoming attestation evidence against stored reference values. Comparison is policy-rich:

- Equal-value comparison for PCRs / MRENCLAVE / image-digests.
- Range comparison for ISV SVN / TCB SVN (accept ≥ minimum).
- Set-membership for MRSIGNER (accept any of N approved signers).
- Identity-policy for OIDC subjects (accept matching regex from accepted issuer).
- Time-window for sigstore short-lived cert validity.

### 3.5 Update

Firmware vendor publishes new release. Consumer must accept new reference values within an update window. Two failure modes:

- **Update lag** — vendor publishes Tuesday, consumer's RVP service updates Friday. Endpoints that auto-update Wednesday fail attestation.
- **Update over-eagerness** — consumer auto-accepts every new reference value. Vendor signing-key compromise → consumer auto-accepts attacker firmware as good.

The right answer involves canary rollouts (§6.5) and signed reference-value provenance with delay windows.

### 3.6 Decommission

Retired hardware versions, EOL'd firmware. When to retire from reference store? Reasonable policy: keep accepting old reference values until decommission of the last fleet device on that firmware, then retire. Operational reality: organizations forget to retire, accumulating an ever-growing reference-value set including known-broken firmware that should be rejected.

---

## 4. IETF SUIT + RATS framing

Standardization status as of 2026.

### 4.1 IETF RATS (Remote ATtestation procedureS) Architecture — RFC 9334

Finalized January 2023 by **Henk Birkholz** + **David Thaler** + **Michael Richardson** + **Ned Smith** + **Wei Pan** (RFC 9334 authors). Defines core RATS roles:

- **Attester** — the device producing evidence.
- **Verifier** — consumes evidence + reference values, produces attestation result.
- **Relying Party** — gates access decisions on attestation result.
- **Reference Value Provider (RVP)** — publishes reference values that the verifier consumes. **First-class role in the architecture, not an afterthought.**

RFC 9334's contribution is naming the RVP role. Before RATS, reference-value distribution was an ad-hoc pre-RFC space. Naming the role created the standardization target.

### 4.2 CoRIM — Concise Reference Integrity Manifest

IETF draft `draft-ietf-rats-corim`, CBOR-encoded reference-value format. Co-authored by **Henk Birkholz** + **Thomas Fossati** + **Yogesh Deshpande** + others. CoRIM tags identify what's measured (firmware module, boot loader, kernel) + the expected hash + the signing identity.

CoRIM is the practical wire format that pairs with RATS. As of March 2026, draft status In WG Last Call (`draft-ietf-rats-corim-10`); some early Veraison + Intel + Arm deployments use it.

### 4.3 TCG Reference Integrity Manifest (RIM)

TCG's pre-IETF standard. EFI variable-based for UEFI components. Vendors publish RIMs covering firmware + boot stack.

Two RIM types: **base RIM** (vendor's golden reference) + **support RIM** (per-configuration). Adoption: Cisco + Dell + HPE + Lenovo publish RIMs for enterprise hardware lines. Consumer-side tooling for ingesting RIMs lags vendor publication.

### 4.4 IETF SUIT — Software Updates for the Internet of Things

WG chaired by **Dave Thaler** + **Dave Waltermire** + **Russ Housley** (later **Akira Tsukamoto** + **Jacqui McCall**). SUIT manifest format (RFC 9124 information model, RFC 9019 architecture) defines firmware-update manifest including reference-value hashes. **Brendan Moran** + **Hannes Tschofenig** + **Henk Birkholz** (RFC 9124) and **David Brown** + **Milosch Meriac** (RFC 9019, with Moran + Tschofenig) are core authors.

SUIT's contribution is that the update manifest itself carries the reference value the device will become after update. Verifier policy can pre-stage acceptance of new reference values based on SUIT manifests, smoothing the update-lag problem.

### 4.5 SBOM as adjacent format

**CycloneDX 1.6 integrity-hash extensions** + **SPDX 3.0** include integrity fields. Reference-value-as-SBOM-extension is an emerging pattern but not standardized — most SBOM consumers treat hashes as informational, not policy-enforced.

---

## 5. Reference-value distribution channels

Ranked by automation maturity (worst to best).

### 5.1 Vendor download pages

Firmware vendors publish hashes on download pages alongside binaries. SHA-256 in HTML text. No machine-readable format, no PKI signature on the page, no freshness guarantee. Most common channel. Manual scraping required.

### 5.2 Vendor-signed manifests

Cisco, Dell, HPE, Lenovo, and others publish signed RIMs or equivalent manifest files for hardware lines. PKI-based authenticity (vendor signing key). Better than HTML pages, but each vendor invents its own format. Federation across vendors absent.

### 5.3 TCG RIM Verification Service / IETF RVP services

Standardized exchange. Adoption growing but partial — most enterprises consume from vendor-specific channels rather than standardized ones.

### 5.4 Sigstore Rekor

Public append-only log for software signatures + attestations. **Luke Hinds** (Red Hat) and **Dan Lorenc** (Google) started sigstore. Rekor entries are inherently reference values for "this signature exists." Verifiable transparency via the public log + monitor patterns. Production at npm, PyPI, Kubernetes, many OSS projects.

### 5.5 OCI registry attestations

Container images with attached SLSA provenance + sigstore signatures. OCI 1.1 reference-types support out-of-band attestation attachment. Native to the runtime — `cosign verify-attestation` is the consumer command.

### 5.6 GitHub Artifact Attestations

GA June 25, 2024. GitHub-hosted attestation service for build provenance, using sigstore Fulcio for OIDC-bound short-lived certs + Rekor for transparency. As of 2026, the easiest path for GitHub-built artifacts. Adoption uneven across OSS ecosystems.

### 5.7 in-toto attestation framework

`[[reference-supply-chain-provenance]]` covers in-toto. **Santiago Torres-Arias** + **Justin Cappos** (NYU) + the in-toto / SLSA community led design. Generic supply-chain step attestation; broader than build provenance.

---

## 6. Fleet-scale operational discipline

Past ~100 endpoints, manual reference-value management breaks. The hard rules:

### 6.1 Automation is non-optional

If onboarding a new firmware revision into the RVP service requires a human ticket, the fleet drifts to a state where the latest firmware is unattested. Automate the ingest from vendor → org RVP. If the vendor doesn't publish machine-readably, write a scraper.

### 6.2 CI/CD integration

When the org's build produces new firmware/software, the CI pipeline should automatically publish the reference value to the org's RVP service. GitHub Actions + sigstore + custom RVP push step is the typical pattern. The action shouldn't require a human to remember to update the verifier.

### 6.3 Verifier configuration as code

Veraison + custom verifiers; OPA-style policy with reference-value lookup. Configuration lives in git, reviewed like any other code. Reject the operating-runbook pattern where a verifier admin SSHes in and adds reference values by hand.

### 6.4 Reference-value freshness SLAs

How long between vendor publishing a new firmware hash and the fleet's RVP service accepting it? Typical targets:

- **Hot path** (incidents in progress, urgent firmware update): hours.
- **Normal release cycle**: 1-7 days.
- **Cold path** (deprecated platform with low risk): days to weeks acceptable.

Measure the lag. Publish it as a fleet-health metric. Alert when lag exceeds SLA.

### 6.5 Update windows + canary rollouts

When a vendor publishes a new firmware revision, don't accept the new reference value across the entire fleet at once. Canary 1-5% of endpoints; observe attestation results, runtime behavior, customer-reported issues; expand to 25%, then 100%. The pattern mirrors **standard production rollout discipline** — reference-value acceptance is a deploy.

### 6.6 Rollback strategy

If a new reference value turns out to correspond to broken or backdoored firmware, can you revert acceptance? The mechanics:

- For PCR / MRENCLAVE comparisons: simply remove the new value from accepted-list. Trivial in a database; harder in a hardcoded verifier.
- For CT-style append-only logs: cannot remove. Must publish revocation alongside; verifier policy must consult both add and revoke channels.
- For sigstore + Rekor: short-lived cert expiration helps; revocation via Rekor logs is complex.

Design the verifier's reference-value store with revocation as a primary operation, not an afterthought.

### 6.7 Reference-value monitoring

Track per-reference-value attestation hit rate. If a reference value was last hit 90 days ago, the firmware it represents is no longer in the fleet — decommission candidate. If a reference value gets attestation failures (incoming evidence almost matches but differs in PCR 7), investigate.

---

## 7. TCB recovery — the minimum-SVN problem

The most operationally-painful reference-value workflow. Cross-link `[[reference-confidential-computing]]`.

### 7.1 What TCB recovery is

TCB (Trusted Computing Base) is dynamic. Vendors discover vulnerabilities in microcode / firmware / hypervisor / SGX QE / SEV-SNP firmware → patch → publish new TCB version (SVN — Security Version Number). The patched TCB has a higher SVN; the vulnerable TCB has a lower SVN. Verifier policy: accept TCB ≥ minimum_SVN.

Example: Intel publishes SGX TCB SVN bump after the XAPIC vulnerability fix (CVE-2022-21233 region) → verifiers should reject older attestations from machines still on the vulnerable TCB.

### 7.2 The operational pain

1. Vendor publishes TCB-recovery advisory + new SVN.
2. Fleet machines on older TCB throw attestation failures.
3. Update pipeline (BIOS / microcode patch) drives them to new TCB.
4. Until updated, attestation fails — workloads that depend on attestation can't run.

In practice, organizations either rush BIOS updates (risky) or relax verifier policy temporarily ("accept TCB N-1 for the next 30 days") which leaves a security gap.

### 7.3 Coordinated TCB recovery

Cloud providers (AWS, Azure, GCP) coordinate with Intel + AMD on TCB-recovery rollouts: receive advance notice, stage host fleet updates, then bump verifier reference values. Customers see a brief attestation-failure window; if they consume cloud-managed verifiers (Azure MAA, AWS Nitro), the cloud's reference-value update flows in for them.

Smaller vendors lack this coordination. Self-hosted SGX deployments coordinate independently with Intel via TCB advisories, lagging cloud-provider rollouts.

### 7.4 Minimum-SVN as policy decision

Setting minimum_SVN is a risk choice. Too aggressive: many fleet machines fail until updated. Too lenient: known-vulnerable TCB accepted indefinitely. The mature pattern: set minimum_SVN to current_SVN - 1, raise after fleet update completes, audit the lag.

---

## 8. Supply-chain reference values

A category distinct from runtime / hardware substrates, with its own primitive set.

### 8.1 SLSA provenance attestations

`[[reference-supply-chain-provenance]]` covers SLSA L0-L3. Reference values for "this binary was built by this build system from this source." Verifier policy: `cosign verify-attestation --type slsaprovenance --policy <rego>` matching `builder.id` + `materials[].uri` against expectations.

### 8.2 sigstore signatures

Reference values for "this signature was created by this OIDC identity at this time." Fulcio short-lived cert binds signing key to OIDC subject; Rekor log gates trust on transparency. Cross-link `[[reference-supply-chain-provenance]]`.

### 8.3 in-toto attestations

Generic supply-chain step evidence. Reference values can cover arbitrary steps — code review, scan, test, sign, publish. The trade-off: in-toto's generality makes policy expression heavier than narrow SLSA.

### 8.4 CycloneDX / SPDX SBOM hashes

Reference values for "this artifact contains these components with these hashes." Verifier policy: at deploy time, the artifact's SBOM must match a pre-attested SBOM produced by trusted build pipeline.

### 8.5 GitHub Artifact Attestations

Cloud-hosted reference-value provider since June 25, 2024 (GA). `gh attestation verify` is the consumer command. For GitHub-built artifacts, this is the lowest-friction path to provenance.

### 8.6 OCI image-digest pinning

The most basic reference-value pattern. Pin image to specific SHA-256 digest in Kubernetes manifest or Compose file; reject any other. Pre-dates the modern attestation stack and remains the operational floor.

---

## 9. Detection-engineering reference values

Cross-link `[[reference-detection-engineering]]` + `[[reference-falco-tetragon-runtime-detection]]`.

### 9.1 Falco rule corpus management

Rules are reference values for "expected vs unexpected syscall behavior." Maintained as YAML in falco-rules repo; orgs fork + extend. Distribution via Falcosidekick / artifacts hub; update via image pull or in-cluster ConfigMap reload.

### 9.2 Tetragon TracingPolicy management

Per `[[reference-falco-tetragon-runtime-detection]]` §8 — Kubernetes CRDs as reference values for eBPF runtime policies. GitOps + reconciler patterns deliver policy updates.

### 9.3 YARA rule corpus management

Reference values for known-malicious file signatures. Distribution via YARA-Rules GitHub repo, vendor feeds, commercial threat-intel platforms. Update cadence weekly to daily.

### 9.4 Sigma rule corpus management

Generic SIEM rule reference values. SigmaHQ central repo; community + vendor curation. Sigma rules compile to SIEM-specific query languages (Elastic, Splunk, Sentinel) — the reference value is the rule semantics, not the compiled query.

### 9.5 EDR allowlist hashes

Known-good binary hashes. Microsoft Defender ASR exclusion lists, Carbon Black approved hashes, CrowdStrike Falcon Pre-Approved Hash list. Distribution + update via vendor consoles; CI integration uneven.

### 9.6 Rule-corpus distribution

Sigma → SigmaHQ; YARA → YARA-Rules + vendor feeds; Falco → falco-rules + Falcosidekick. The pattern: community-maintained core corpus + per-org overlay + per-tenant tuning. Reference-value management treats the rule corpus as code, versioned, reviewed, deployed.

---

## 10. Real-world implementation patterns

### 10.1 Cloud-provider managed

- **AWS Nitro Enclaves + KMS condition keys.** KMS knows expected PCRs; key policy `kms:RecipientAttestation:PCR0` etc. gate decrypt operations. Reference values live in the KMS key policy. Convenient + AWS-locked.
- **Azure MAA (Microsoft Azure Attestation).** Cloud-managed verifier with reference-value bundle. Supports SGX, TDX, SEV-SNP, TPM. Policy expressed in Microsoft-specific policy language.
- **GCP Confidential GKE Nodes + Confidential Space.** Reference values via attestation policy attached to GCP IAM. Supports TDX + SEV-SNP guests.

### 10.2 OSS Veraison

OSS attestation verifier with reference-value store, adopted as a CC (Confidential Computing Consortium) project. **Thomas Fossati** + **Yogesh Deshpande** + others. Supports CCA, PSA, DICE, TPM evidence formats.

### 10.3 Vendor-locked services

- **Apple PCC (Private Cloud Compute).** Apple publishes measurements of every production PCC software image in an append-only transparency log; user devices send requests only to nodes whose attested measurements match a logged release.
- **Azure Sphere.** Closed-loop attestation; service retires July 31, 2031 (MT3620 chip EOL July 31, 2026). Reference-value data on existing deployments will be orphaned. Cross-link `[[reference-dice-embedded-device-identity]]` §12.7.
- **Microsoft Pluton.** Closed integration into Windows attestation.

### 10.4 Custom verifiers

Large enterprises (Google, Meta, Amazon, Microsoft, financial services) build their own. Reasoning: avoid cloud-provider lock-in, integrate with internal PKI + IAM, support custom hardware. Significant engineering investment but the only path for at-scale multi-platform fleets.

### 10.5 NIST SP 800-193

**Andrew Regenscheid** (NIST) authored 800-193 firmware resilience guidelines (Platform Firmware Resiliency, 2018). Specifies measurement + detection + recovery requirements. Reference-value management is implicit — the standard assumes a verifier with golden values to compare measurement against.

---

## 11. 2024-2026 currency

### 11.1 IETF RATS RFC 9334 (January 2023) finalization

Bedrock document for RVP role naming. **Henk Birkholz** + **David Thaler** + **Michael Richardson** + **Ned Smith** + **Wei Pan** as authors.

### 11.2 CoRIM IETF draft progress

In RATS WG Last Call as of March 2026 (`draft-ietf-rats-corim-10`). Multiple drafts published; not yet RFC. Implementation activity in Veraison + Intel SGX tooling + Arm CCA verifier.

### 11.3 GitHub Artifact Attestations GA 2024

GA June 25, 2024. Brought sigstore-bound build provenance to the largest CI population. Adoption uneven; many repos haven't opted in yet.

### 11.4 EU CRA (Regulation 2024/2847)

Product manufacturers face reference-value publication requirements implicitly via security claims. The CRA's vulnerability-disclosure + SBOM requirements push vendors toward publishing machine-readable reference values, though the regulation does not name reference values directly.

### 11.5 AI-system reference values

The frontier:

- **Model-weight hashes.** Apple PCC publishes measurements of every production software image in a public transparency log. Anthropic + OpenAI + Meta have not published comparable per-model reference values as of 2026.
- **Training-data attestations.** Operational concept; production deployments minimal.
- **System-prompt hashes.** Some agent-deployment frameworks experiment with hashing the system prompt; per-inference reference values not yet operational.
- **GPU firmware reference values.** NVIDIA H100 attestation includes firmware + microcode versions; reference values published as signed RIMs via the NVIDIA RIM Service, with NRAS performing verification.

### 11.6 Veraison maturity

OSS verifier moving from research to production deployments. Linaro release cadence + ecosystem contributions. CC working-group activity around shared verifier infrastructure.

### 11.7 SLSA + sigstore adoption

As of 2026, most npm / PyPI / OCI artifacts still lack provenance attestations. Trend curve is rising but slow. GitHub Artifact Attestations + npm Trusted Publishing + PyPI Trusted Publishers are the inflection points.

---

## 12. Honest failure modes

Load-bearing section. The disciplines above describe the target state; here is where deployments actually fall over.

### 12.1 Reference-value rotation lags reality

Vendor publishes new firmware; consumer's RVP service doesn't update for days/weeks; fleet attestation fails or accepts old reference values. The lag-vs-fleet-update race is the most common operational failure.

### 12.2 Manual reference-value management doesn't scale

Past ~100 endpoints, automation is non-optional. Most teams underinvest. The visible artifact: a Confluence page with a table of "expected PCR values," last updated 14 months ago.

### 12.3 TCB recovery is operationally painful

Vendor publishes minimum-SVN bump; fleet not yet updated → attestation failures; teams disable verification rather than fix → coverage gap. The temporarily-relaxed policy outlives its justification.

### 12.4 Reference-value provenance

Who signs the reference values? If a vendor's signing key is compromised, they can sign malicious reference values, and verifier consumers accept them as good. The HSM-protected vendor signing key + audit + transparency-log pattern is the defense. Cross-link `[[reference-hsm-operational-discipline]]` §13.1 + `[[reference-supply-chain-provenance]]`.

### 12.5 Cloud-provider managed RVP is convenient + vendor-lock-in

AWS / Azure / GCP each run their own; multi-cloud verification requires cross-provider RVP federation that doesn't exist as of 2026. Customers spanning clouds either run their own custom verifier or accept the lock-in.

### 12.6 SLSA + sigstore + GitHub Attestations are powerful but adopt slowly

The technology works; the adoption curve is the limiter. As of 2026, the majority of supply-chain artifacts in production lack provenance.

### 12.7 Reference values for AI systems are the frontier

Model-weight hashing scales (weights are blob-style), but per-inference reference values (system-prompt hashes, RAG-context hashes, tool-set hashes) are operationally untested. Apple PCC's per-image transparency log is a leading example; broad industry adoption is years out.

### 12.8 Closed-loop verifier services leave orphans

Azure Sphere retires July 31, 2031; existing devices have reference-value data in Microsoft-operated infrastructure that customers cannot migrate. Cross-link `[[reference-dice-embedded-device-identity]]` §12.7. Closed-loop verifiers carry this risk by design.

### 12.9 "We did attestation" without RVP discipline is theater

Attestation evidence without reference values to compare against = empty signature verification. The verifier accepts every well-signed claim, including the attacker's well-signed claim from compromised firmware. The deployment looks compliant; it provides no security.

### 12.10 Cross-substrate reference-value composition is unsolved

TPM PCRs + TEE MRENCLAVE + SLSA provenance + GPU firmware + container image digest — composing verification of all four for a single AI-inference workload requires a verifier that consumes all five evidence types and applies policy across them. As of 2026, each substrate is verified independently; cross-substrate composition is the next operational frontier.

### 12.11 Reference-value retention indefinite-by-default

Decommission discipline is rare. Reference-value stores accumulate entries for hardware that has been out of production for years, including hardware with known-CVE'd firmware that should be rejected. The store ages into a liability.

### 12.12 Reference-value formats fragment

PCR golden values, MRENCLAVE policies, SLSA provenance, AAGUID metadata, CoRIM tags, RIMs — each format is its own ecosystem. Consumer tooling rarely covers all formats; cross-format policy is hand-stitched. CoRIM aims to unify; adoption pending.

---

## 13. Cross-link cluster

- `[[reference-hardware-attestation-chains]]` §11 — claim that reference-value pipeline is load-bearing (this doc develops that claim).
- `[[reference-dice-embedded-device-identity]]` §10 — DICE-specific alias-key reference values; §12.7 closed-loop EOL.
- `[[reference-confidential-computing]]` — TEE MRENCLAVE / MRSIGNER + minimum SVN tracking.
- `[[reference-webauthn-fido2-passkeys]]` §4 — FIDO MDS as authenticator-model RVP.
- `[[reference-hsm-operational-discipline]]` §13.1 — vendor signing-key protection backing reference-value provenance.
- `[[reference-detection-engineering]]` — runtime golden values, rule corpus as reference values.
- `[[reference-falco-tetragon-runtime-detection]]` §8 — Falco / Tetragon rule corpus management.
- `[[reference-supply-chain-provenance]]` — SLSA + sigstore + in-toto provenance as reference-value category.
- `[[reference-cicd-supply-chain]]` — build pipelines publishing reference values via CI/CD integration.
- `[[reference-embedded-device-hardening-playbook]]` — fleet-scale firmware update + reference-value workflows.
- `[[reference-cryptography]]` — PKI underpinning vendor signing of reference values.
- `[[reference-zero-trust-workload-identity]]` — SPIFFE / SPIRE as workload-identity attestation, with reference values for accepted issuer.
- `[[reference-threat-modeling-discipline]]` — where verifier policy lives in the threat model.

---

The reference-value store is the policy. Get that right and attestation infrastructure is load-bearing. Get it wrong and the cryptography below is decoration.
