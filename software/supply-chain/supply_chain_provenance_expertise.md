# Supply-Chain Provenance — SLSA, sigstore, in-toto, SBOM
## Synthesized from Justin Cappos, Santiago Torres-Arias, Trishank Karthik Kuppusamy, Luke Hinds, Dan Lorenc, Bob Callaway, Priya Wadhwa, Adolfo García Veytia, Brandon Lum, Kate Stewart, Steve Springett, Russ Cox, Holger Levsen, Vagrant Cascadian, and Kurt Boberg

> **Primary researchers / teams:**
> - **Justin Cappos** (Professor, NYU Tandon Secure Systems Lab) — Creator of five Linux Foundation projects: TUF (2010), in-toto (2016), Uptane, SBOMit, and gittuf. TUF was the first specification project to graduate from CNCF (Dec 2019). Production use at Docker, VMware, Cloudflare, Microsoft, Amazon, Google, IBM, DigitalOcean, Datadog.
> - **Santiago Torres-Arias** (Assistant Professor of ECE, Purdue; formerly NYU Tandon PhD) — Team lead of in-toto. First author of the USENIX Security 2019 paper *in-toto: Providing farm-to-table guarantees for bits and bytes* with Afzali, Kuppusamy, Curtmola, and Cappos. TUF maintainer.
> - **Trishank Karthik Kuppusamy** (Staff Security Engineer, Datadog) — Led R&D of TUF and Uptane at NYU Tandon; co-author of in-toto USENIX 2019. At Datadog, led the team that combined TUF + in-toto for a compromise-resilient integration pipeline that Datadog described as the first of its kind discussed in the industry.
> - **Luke Hinds** (CTO, Stacklok; formerly Distinguished Engineer at Red Hat) — Creator of sigstore; current chair of the sigstore TSC. Launched Stacklok in May 2023.
> - **Dan Lorenc** (Co-founder + CEO, Chainguard; formerly lead of Google's Open Source Security Team) — Co-creator of sigstore (first release March 2021). Created Tekton; developed Minikube, Skaffold, Kaniko. Founded Chainguard in September 2021.
> - **Bob Callaway** (Google; sigstore TSC) — Sigstore co-founder; leads Google's Open Source Security Team.
> - **Priya Wadhwa** (Director of Engineering, Chainguard; sigstore TSC) — Maintainer of Rekor, Cosign, and Tekton Chains.
> - **Adolfo García Veytia ("puerco")** (Staff Software Engineer, Stacklok) — Original author of the OpenSSF Protobom project (universal IO layer between SBOM formats, partnered with CISA + OpenSSF + DHS). Original author of OpenVEX. Contributor to SPDX. Technical Lead with Kubernetes SIG Release.
> - **Brandon Lum** (Software Engineer, Google; formerly IBM) — Contributor to SLSA 1.0 / SPDX 3.0 build profile alignment; co-author of Kubernetes-release supply-chain hardening proposals.
> - **Kate Stewart** (VP of Dependable Embedded Systems, The Linux Foundation) — Co-founder of SPDX and current SPDX specification lead. Linux Foundation Open Compliance portfolio (SPDX, FOSSology, OpenChain) + Real-Time Linux + Zephyr.
> - **Steve Springett** (Director of Product Security at ServiceNow; Chair of OWASP CycloneDX; Chair of Ecma International TC54) — Founder of CycloneDX; creator of OWASP Dependency-Track; leads OWASP SCVS.
> - **Russ Cox** (formerly Tech Lead, Go team, Google) — Architect of the Go module-mirror checksum database; driver of Go 1.21's bit-for-bit reproducible toolchain. His "Surviving Software Dependencies" essay and the sumdb proposal are the canonical framing for moving beyond SSH-style "trust on first use" with a transparency log.
> - **Holger Levsen** (Debian; Reproducible Builds project) — Debian contributor since 2001, DD since 2007. Began systematic Debian-package reproducibility builds in Sept 2014; Reproducible Builds has been his primary focus since. Automated reproducibility testing across Debian, Fedora, Arch, FreeBSD, NetBSD, OpenWrt, coreboot.
> - **Vagrant Cascadian** (Debian; GNU Guix; Reproducible Builds project) — Long-running Debian package-reproducibility specialist. Empirical measurement: 88 of 154 (57%) packages in a minimal sid system reproduce independently.
> - **Kurt Boberg** (@lapt0r) — Staff Security Researcher at Semgrep. Co-author of *Popular GitHub Action tj-actions/changed-files is compromised* (semgrep.dev/blog, Mar 2025).
>
> Sources: ssl.engineering.nyu.edu; theupdateframework.io; in-toto.io; cerias.purdue.edu; sigstore.dev; chainguard.dev; openssf.org; stacklok.com; cyclonedx.org; spdx.dev; linuxfoundation.org; slsa.dev; reproducible-builds.org; go.dev/blog; usenix.org/conference/usenixsecurity19/presentation/torres-arias; github.com/{lukehinds,lumjjb,trishankatdatadog,santiagotorres,justincappos}; peps.python.org/{pep-0458,pep-0480,pep-0691,pep-0740}; semgrep.dev/blog/2025/.

---

## 1. Why Supply-Chain Provenance Matters

### The shifted threat model

Traditional software security treated the source repository as the trust root: "if I trust the project on GitHub, I trust the binary." That model is dead. Every layer between source and consumer is a tampering opportunity, and the 2020-2026 incident corpus has demonstrated tampering at every one. Provenance answers a single question:

> **"I trust the source repo. Does this artifact actually come from it?"**

A verifiable chain of custody from `git commit` through every transform — compile, link, package, sign, push to registry, redistribute via CDN — gives the answer. Each transform is performed by some actor (CI workflow, package maintainer, registry operator, mirror), trusted by name or by attestation. "Supply-chain compromise" is what happens when an actor is silently substituted or maliciously transforms the artifact.

### The chain of custody

```
git commit (developer signature)
   → build (CI + SLSA provenance) → package + sign (cosign + Rekor)
   → registry push (+ SBOM) → distribution (CDN) → consumer pull + verify
```

Each `→` is a transition with a verifiable attestation: issuer, subject, predicate, signature. A consumer pulling the artifact and verifying the chain detects any silent tampering between the developer's keyboard and their `docker pull`.

### Why this matters in 2026

The incident corpus that reframes the discussion:

- **SUNBURST / SolarWinds (Dec 2020)** — Build-environment compromise (SUNSPOT) injected a backdoor into signed `SolarWinds.Orion.Core.BusinessLayer.dll`. Signature real; source-to-build link broken. SLSA L3 would have invalidated the resulting provenance.
- **Codecov bash uploader (Apr 2021)** — Credential exfiltrated from Codecov's Docker build env.
- **ua-parser-js (Oct 2021)** — Maintainer npm-account hijack; provenance from build to publish would have flagged the divergence.
- **xz-utils CVE-2024-3094 (Mar 2024)** — Multi-year social engineering; backdoor hidden in the release tarball's m4 build script (not the git tree). Reproducible builds against the git tree would have caught the discrepancy.
- **tj-actions/changed-files CVE-2025-30066 (Mar 2025)** — PAT compromise + mutable-tag rewrite hit ~23,000 repos; Coinbase was the targeted endpoint. Sigstore-signed Action releases + consumer SHA pinning would have localized damage.
- **Dependency confusion (ongoing since 2021)** — Alex Birsan's namespace-shadowing across npm/PyPI/RubyGems remains the cheapest initial-access tool.

Full incident corpus: [`cicd_supply_chain_expertise.md`](cicd_supply_chain_expertise.md) §6. This doc is the "what defenses exist and how do they work" companion.

### Everything is a multi-link chain

A modern artifact's provenance spans: source-code commit (git signature), CI workflow definition (`.github/workflows/*.yml` pinned + reviewed), runner environment (hosted vs. self-hosted), base image (`FROM debian:bookworm` — what does that resolve to today?), build output, signature (cosign keyless or traditional code-signing + Rekor log), registry entry (npm publish / PyPI / Docker Hub), distribution mirror, and consumer verification path. SLSA, sigstore, in-toto, and SBOMs are the toolkit for building and verifying that cryptographic graph.

Kurt's Semgrep tj-actions blog (https://semgrep.dev/blog/2025/popular-github-action-tj-actionschanged-files-is-compromised/) was the operational shape of this thinking — once detected, the response was a graph walk: who pinned a mutable tag, what secrets ran under the compromised step, how do consumers verify a clean version. Those questions become tractable when the infrastructure provides cryptographically-verifiable answers.

---

## 2. SLSA — Supply-chain Levels for Software Artifacts

### The four-level ladder

SLSA v1.0 (published by the OpenSSF SLSA working group) defines a build-track ladder. The build track is the most-developed track; a source track was added later, in SLSA v1.2.

The build-track levels (from `slsa.dev/spec/v1.0/levels`):

- **Build L0** — No SLSA. The absence of supply-chain controls; the default state for any project that hasn't intentionally adopted SLSA.
- **Build L1** — Provenance exists. The artifact ships with a machine-readable description of how it was built: build platform, build process, top-level inputs. Distribution mechanism is unspecified; can be unsigned. The package consumer can read the provenance, but cannot meaningfully verify it against tampering.
- **Build L2** — Hosted build platform + signed provenance. The build runs on a hosted platform (GitHub Actions, GitLab CI, Google Cloud Build, etc.) rather than a developer workstation. The hosted platform generates and signs the provenance. Consumers can verify the signature establishes the platform's identity. A determined adversary who compromises the build environment can still forge the provenance, but the bar is "compromise the build platform," not "modify a YAML file in source control."
- **Build L3** — Hardened, non-falsifiable build. Forging the provenance or evading verification requires exploiting a vulnerability in the build platform itself. In practice, this means the build runs in an isolated environment where the build-platform service signs provenance using keys never exposed to the build runtime. GitHub Actions reaches L3 via the Artifact Attestations feature (with the right workflow shape); GCB and Tekton Chains can claim L3 under similar conditions.

(Earlier SLSA drafts included a fourth level — review-required source plus hermetic builds. SLSA v1.0 deferred that to source-track and other-track future work; the build track is L0-L3 in the current spec.)

### Build provenance — the core attestation

The build-provenance attestation is the SLSA artifact: a signed JSON document, structured as an `in-toto` statement with predicate type `https://slsa.dev/provenance/v1`. Schema (from `slsa.dev/spec/v1.0/provenance`):

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [{"name": "...", "digest": {"sha256": "..."}}],
  "predicateType": "https://slsa.dev/provenance/v1",
  "predicate": {
    "buildDefinition": {
      "buildType": "https://actions.github.io/buildtypes/workflow/v1",
      "externalParameters": {...}, "internalParameters": {...},
      "resolvedDependencies": [...]
    },
    "runDetails": {
      "builder": {"id": "https://github.com/actions/runner/..."},
      "metadata": {"invocationId": "...", "startedOn": "...", "finishedOn": "..."}
    }
  }
}
```

Three load-bearing fields: `subject` (what artifact this is provenance for), `predicate.buildDefinition` (the non-repudiable instructions — what was built, what inputs were consumed), and `predicate.runDetails.builder` (who built it — the platform identity). The signature is over the entire statement. A consumer who trusts the builder identity can read the build definition with confidence the platform asserts those inputs produced the output.

### SLSA v1.0 vs v1.1; Borg origin; what counts as L3

SLSA v1.1 tightened requirement language without re-defining the levels. Its changes: a verification procedure for VSAs, verifier metadata in the VSA format, and a further-refined threat model. The source track arrived later, in v1.2.

The intellectual ancestor of SLSA is Google's internal Borg + binary-authorization: every production binary must have a build-system attestation signed with a key no human ever holds. SLSA externalized that practice; Chainguard Images at L3 are the existence-proof for non-Google projects.

L3 intuition pump: *can an attacker forge valid signed provenance without compromising the build platform?* For GitHub Actions with Artifact Attestations, the OIDC token is signed by GitHub's IdP (not the workflow); the ephemeral Fulcio cert binds to the OIDC subject (workflow ref + actor + repository, unforgeable from inside the runner). A compromised runner can sign provenance but cannot forge OIDC-derived claims about *which* workflow it was. The debate is around edge cases: hosted runners isolate against runner self-modification; self-hosted runners cannot make that claim, so SLSA L3 on self-hosted is generally not claimable.

Mapping levels to common CI platforms (rough as of 2026):

| Platform | Achievable level (default) | Achievable level (with effort) |
|---|---|---|
| GitHub Actions (hosted) | L2 | L3 via Artifact Attestations |
| GitHub Actions (self-hosted) | L1 | L2 (with hardening) |
| GitLab CI (hosted) | L2 | L3 via SLSA Provenance |
| CircleCI | L2 | L3 |
| Buildkite | L1 | L2 (with hosted agents) |
| Jenkins (self-managed) | L0 | L2 (with effort; rarely L3) |
| Tekton Chains | L2 | L3 (SLSA Provenance v1 format) |
| Google Cloud Build | L2 | L3 |

The "default vs. with effort" column is judgment based on commonly-deployed configurations; consult `slsa.dev/spec/v1.0/levels` and each platform's own claim.

---

## 3. sigstore — the keyless-signing trinity

### Three components, one workflow

sigstore is a constellation of OpenSSF projects providing *keyless code-signing*: cryptographic provenance with no long-lived signing keys to steal, rotate, or audit. Three core components:

- **cosign** — user-facing CLI for signing containers, blobs, and attestations.
- **fulcio** — short-lived-certificate CA backed by OIDC.
- **rekor** — append-only transparency log (Merkle tree) of all signed attestations.

Load-bearing insight: *the signature is not the trust anchor; the signing identity is*. A traditional code-signing key (RSA on an HSM) is a long-lived secret; if compromised, all past signatures are retroactively suspect. A sigstore signature is made with an *ephemeral* key (~10 min validity), bound to an OIDC identity via a Fulcio-issued cert, logged to Rekor so the binding is auditable forever.

### The keyless signing workflow

Signer side: (1) obtain an OIDC token (from GitHub Actions OIDC, from an interactive browser flow, etc.); (2) generate ephemeral keypair locally; (3) present OIDC token + pubkey to Fulcio; (4) Fulcio validates the JWT against the IdP's published JWK, binds the pubkey to the OIDC subject claim (e.g., `https://github.com/my-org/my-repo/.github/workflows/release.yml@refs/tags/v1.0.0`), issues a short-lived X.509 cert; (5) sign the artifact with the ephemeral private key; (6) upload {signature, certificate, artifact-hash} to Rekor; (7) discard the ephemeral private key — the cert is the public artifact, the Rekor entry is the transparency record.

Verifier side: fetch artifact + signature + Rekor entry → verify Fulcio cert signed by Fulcio CA (trust root) → verify signature against cert pubkey → verify OIDC subject claim matches expected → verify Rekor Merkle-tree inclusion proof against current tree state → optionally verify signature timestamp via Rekor's signed timestamp.

The cert is expired (deliberately, ~10 min validity), but that doesn't matter for verification. What matters: *at the moment of signing*, the Fulcio CA was willing to issue a cert binding *this* pubkey to *this* OIDC identity. Rekor's signed timestamp anchors the moment.

### Why this beats traditional code-signing

The structural difference: traditional code-signing's threat model is "protect the long-lived key." Sigstore's is "trust the OIDC issuer." A traditional CA's root expiration causes industry-wide pain (Authenticode, S/MIME, Java JCE all bear scars). Fulcio's root cert can rotate; sigstore's TUF metadata distributes the new trust root; old signatures remain verifiable as long as Rekor preserves the Merkle tree. The IdP compromise (OIDC provider takeover) is the meta-threat, but IdP operational security is already a high-investment area (Microsoft Entra, GitHub OIDC) — a higher bar than "protect an HSM."

### Public Good Instance, failure modes

The Public Good Instance at `fulcio.sigstore.dev` / `rekor.sigstore.dev` is operated by the OpenSSF and backs the majority of npm, PyPI, GitHub Artifact Attestations, and Chainguard Image signatures. Private deployments exist (e.g., GitHub's own instance for private-repository attestations); the TUF metadata for a private deployment defines its own trust roots.

Failure modes: **Rekor downtime** prevents new signing and fresh-tree-head verification (mitigation: cache tree head). **Fulcio root rotation** requires overlapping deployment + TUF metadata update. **OIDC issuer compromise** is the meta-threat — defense is HSM-backed OIDC signing keys at the IdP. **Bring-your-own-key sigstore** brings back the long-lived-key threat model; only use when keyless is unavailable.

For cryptographic primitives (Ed25519, X.509, Merkle-tree transparency), see [`cryptography_expertise.md`](cryptography_expertise.md) §§4-6. CI-side integration: [`cicd_supply_chain_expertise.md`](cicd_supply_chain_expertise.md) §7.

### Concrete cosign workflow

```bash
# Sign (in a CI workflow with OIDC enabled):
cosign sign ghcr.io/my-org/my-image:v1.0.0

# Verify (consumer side):
cosign verify \
  --certificate-identity-regexp '^https://github.com/my-org/my-repo' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  ghcr.io/my-org/my-image:v1.0.0

# Attach an SBOM as a separate attestation:
cosign attest --predicate sbom.spdx.json --type spdxjson ghcr.io/my-org/my-image:v1.0.0
```

The `--certificate-identity-regexp` is load-bearing; cosign 2.x requires it (or `--certificate-identity`) for keyless verification. A loose pattern accepts any matching OIDC subject, including an attacker signing as a different `my-org/*` repo. The attestation is uploaded to Rekor; `cosign verify-attestation` reads back the predicate.

---

## 4. in-toto — the framework that predates sigstore

### The 2019 USENIX paper

*in-toto: Providing farm-to-table guarantees for bits and bytes* by Santiago Torres-Arias, Hammad Afzali, Trishank Karthik Kuppusamy, Reza Curtmola, and Justin Cappos, USENIX Security 2019 (https://www.usenix.org/conference/usenixsecurity19/presentation/torres-arias).

in-toto formalizes the supply chain as a **DAG of transformations**. Each *step* has a name, a set of authorized **functionaries** (humans or automated systems), and acceptable input/output artifacts. A *layout* enumerates the steps, functionaries, and rules. Each step produces a signed **link metadata file** recording what was produced and consumed. A *final inspector* walks the DAG, verifies each link's signature against authorized functionaries, and verifies the artifact chain.

The format defines `_type: "link"` and `_type: "layout"` envelopes. A pseudocode layout:

```yaml
keys: {dev-key, ci-key, qa-key}
steps:
  - name: checkout    functionary: dev-key   expected_products: ["src/**/*.go"]
  - name: build       functionary: ci-key    expected_materials: ["src/**/*.go"]
                                             expected_products:  ["myapp"]
  - name: test        functionary: qa-key    expected_materials: ["myapp"]
inspect:
  - name: verify-binary  run: "sha256sum myapp == <expected-hash>"
```

### Why in-toto is more general than SLSA

SLSA defines a single attestation type — build provenance — with one predicate type. in-toto can enforce arbitrary multi-step workflows: source review, static analysis, security audit, build, package, sign. Each step is its own functionary; each link is its own attestation.

The modern composition: SLSA build provenance (predicate) → in-toto statement envelope → cosign keyless signature → Rekor log entry. The in-toto envelope (`https://in-toto.io/Statement/v1`) is the *vehicle* for predicates. SLSA Provenance is the most common predicate; VEX (`https://openvex.dev/ns/v0.2.0`), SPDX, CycloneDX, and custom predicates all ride the same envelope.

### Production deployments

Tekton Chains generates in-toto SLSA-Provenance-v1 attestations for every TaskRun/PipelineRun. GitHub Artifact Attestations (GA June 2024) produces in-toto-formatted SLSA Provenance signed via sigstore. Datadog Agent's integration build pipeline uses TUF + in-toto end-to-end (Kuppusamy's work). Sigstore's own release pipeline uses in-toto + cosign keyless.

### The supply-chain DAG mental model

The biggest difference between in-toto and "just sign the build artifact" is that in-toto forces you to **model the entire supply chain as a graph** and define which functionaries can perform which transitions. This surfaces invariants traditional artifact-signing misses: "QA functionary must approve before release"; "same human cannot perform both code-review and release-cut" (separation of duties); "build input must equal source output" (no silent insertion of unreviewed code).

The cost is operational overhead. In production, in-toto is typically used as an envelope with one or two predicates; the supply-chain DAG remains implicit in the CI/CD platform's design.

---

## 5. TUF — The Update Framework

### Threat model and the five roles

TUF (Cappos, 2010, with Samuel et al.) is older than sigstore by a decade. Threat model: *protect against a fully compromised software repository*. Traditional code-signing assumed the repository was honest and the only adversary was a man-in-the-middle. TUF assumed the repository itself could be compromised. The answer: **threshold of keys** + **role separation**.

Five top-level roles, each signed by a distinct keyset:

1. **Root** — signs public keys for all other roles. Offline-only. M-of-N threshold (typically 3-of-5 or 5-of-9). Rotation requires explicit "key transition" metadata.
2. **Targets** — signs the authoritative target list. Can delegate to sub-roles (PEP 458 has PyPI delegate to hashed `bin-n` roles signed with online keys; per-project developer signing is deferred to PEP 480).
3. **Snapshot** — signs the current targets-metadata state. Online; protects against mix-and-match attacks.
4. **Timestamp** — signs a short-lived snapshot timestamp. Online; protects against freeze attacks.
5. **Mirrors** (optional) — signs acceptable mirror locations.

### Why role separation matters

**Offline root + offline targets + online snapshot/timestamp** is the canonical deployment. Root keys live on YubiKeys, never online. Targets keys belong to maintainers (or automated bins-delegations). Snapshot/timestamp are online services; an attacker owning the snapshot key cannot inject new targets — only freeze or mix-and-match. TUF assumes the high-volume online attack surface is *compromised by default* and arranges signing so the catastrophic primitives require compromising offline keys.

### Production deployments

- **PyPI** — implementing PEP 458 (TUF metadata distribution). Long-running; not yet in production as of mid-2024. PyPI's metadata via TUF, per-distribution attestations via sigstore PEP 740. Layered.
- **Docker Notary** — Docker's TUF implementation (Docker Content Trust). Retirement announced July 2025; Docker recommends Sigstore/Cosign or Notation instead.
- **Datadog Agent** — TUF + in-toto for integration delivery (Kuppusamy's work).
- **Uptane** — TUF for automotive over-the-air updates; IEEE-ISTO 6100 standard; widely deployed in major OEMs.
- **CNCF** — TUF was the first specification project to graduate (Dec 2019).
- **npm / Maven Central / RubyGems** — varying integration; PyPI is furthest along.

### TUF + sigstore composition; gittuf

Clean composition: TUF handles *metadata distribution* (which signing keys are currently trusted); sigstore handles *per-artifact signing*. The trust roots of a sigstore deployment (`fulcio_v1.crt.pem`, `rekor.pub`) are themselves distributed via TUF metadata. Without TUF, an attacker compromising sigstore Public Good infrastructure could substitute new root keys; with TUF, the M-of-N threshold for trust-root rotation protects against single-key compromise.

**gittuf** (Cappos, 2023+) is the newer project: TUF semantics applied to git repositories — role-separation and delegation applied to git refs. Early adoption. https://gittuf.dev/.

---

## 6. SBOM Formats — SPDX, CycloneDX, SWID

### Why three formats exist

The Software Bill of Materials (SBOM) is "an ingredient list for software." Its purpose: given an artifact, enumerate every dependency component that was included, with version and identity metadata sufficient to perform vulnerability lookup, license compliance, and supply-chain audit.

Three formats are in production use; they originated at different times for different primary purposes:

| Format | Lead | Year | Primary purpose | Common today for |
|---|---|---|---|---|
| **SPDX** | Linux Foundation (Kate Stewart) | 2010 | License compliance, package documentation | Distros, OSS license tracking, government procurement |
| **CycloneDX** | OWASP (Steve Springett) | 2017 | Security operations, vulnerability tracking | AppSec tooling, container scanning, VEX flows |
| **SWID** | NIST (ISO/IEC 19770-2) | 2009 | Software identification for asset management | Enterprise IT asset management; minimal SBOM use |

### SPDX in depth

SPDX (Software Package Data Exchange) is the elder format. Originally designed for FOSS license-compliance teams; grew into a general-purpose SBOM. **SPDX 2.3** uses a package-and-relationship model: packages listed individually, explicit `Relationship` entries describe how they relate (DEPENDS_ON, CONTAINS, BUILD_TOOL_OF, STATIC_LINK, DYNAMIC_LINK, etc.). **SPDX 3.0** (2024) restructured into profiles: Core, Software, Security, Licensing, Build, AI, Dataset. The Build profile is the SLSA-alignment target (Brandon Lum's work).

License data is SPDX's superpower. The SPDX License List (https://spdx.org/licenses/) is the canonical machine-readable identifier set for OSS licenses. CycloneDX leverages it via SPDX-LicenseRef; license-compliance teams default to SPDX as the carrier.

### CycloneDX in depth

CycloneDX is the security-first SBOM (Steve Springett; OWASP flagship; standardized as **ECMA-424** in 2024). Flat component-centric model with a separate `dependencies` array mapping component refs to dependents. Vulnerability scanners iterate the component list directly without traversing relationships.

Security-oriented native fields: `components[].evidence` (provenance for component identification), `components[].externalReferences` (VEX, advisories, source), top-level `vulnerabilities[]` with VEX-style statuses. CycloneDX has native VEX support; SPDX added VEX in the SPDX 3.0 Security profile.

### Recommendation and SWID

The empirical reality: enterprises commonly emit **both** formats from the same build — SPDX for license-compliance, CycloneDX for vulnerability management. Tools (syft, cdxgen, Trivy) emit either. If forced to pick one: CycloneDX for security-driven programs, SPDX for compliance-driven.

**SWID** (Software Identification Tags, NIST / ISO/IEC 19770-2) encodes software identity + patch evidence in XML. Minimal traction in the OSS SBOM ecosystem; shows up in DoD compliance contexts.

### VEX — Vulnerability Exploitability eXchange

VEX is the *companion* to SBOM. Given an SBOM that says "this artifact contains log4j 2.14.1" and a CVE database that says "log4j 2.14.1 has CVE-2021-44228," the naive scanner reports a critical finding. VEX is the structured statement: *yes, the component is present, but the vulnerable code path is not reachable in this product*.

Three VEX formats in production:

- **OpenVEX** (Adolfo García Veytia + OpenSSF) — minimal JSON-LD format. Embeddable in SBOMs or standalone. Designed to be the easy-on-ramp.
- **CycloneDX-VEX** — VEX inline in CycloneDX SBOM (`vulnerabilities[].analysis`).
- **CSAF-VEX** — OASIS Common Security Advisory Framework. Heavier; vendor-advisory-oriented.

A VEX statement has four canonical statuses:

- `not_affected` — the vulnerable code path is unreachable in the product. Often paired with a justification (e.g., `component_not_present`, `vulnerable_code_not_in_execute_path`, `inline_mitigations_already_exist`).
- `affected` — vulnerable.
- `fixed` — was vulnerable; has been remediated in this version.
- `under_investigation` — TBD.

VEX is **living document** material: a `not_affected` claim made at release time may become `affected` later if a new attack path is discovered. The VEX document is versioned and timestamped; consumers track the current statement.

The "SBOM is necessary but not sufficient" reality: an SBOM tells you what's present, but without VEX the consumer drowns in noise from components that have CVE matches but aren't actually exploitable. VEX is what makes SBOM operationally usable for vulnerability triage. See [`detection_engineering_expertise.md`](detection_engineering_expertise.md) §3 for the broader pattern of "match + context filter" in detection.

---

## 7. SBOM Toolchain

**Generation.** **syft** (Anchore, Apache 2.0) is the reference CLI: reads container images (Docker/OCI/Singularity), filesystems, archives; supports Alpine apk, Debian dpkg, RPM, Go, Python, Java, npm, Ruby, Rust, PHP. Outputs SPDX, CycloneDX, Syft-JSON. https://github.com/anchore/syft. **cdxgen** (CycloneDX project) is CycloneDX-native with better evidence + source-tracking. **Trivy** (Aqua Security) is dual-purpose SBOM + vulnerability scanner with its own DB. **GitHub native SBOM export**: `gh api repos/{owner}/{repo}/dependency-graph/sbom` — convenient, but lower-quality than syft because it's GitHub's static analysis, not build-time observation.

**Vulnerability scanning.** **grype** (Anchore) consumes SBOM and cross-references the Anchore DB (aggregates NVD + OS-vendor + ecosystem advisories). **Trivy** does combined scanning. **kubescape** covers Kubernetes manifests + container images.

**SBOM repository.** **OWASP Dependency-Track** (Springett's platform; https://dependencytrack.org/) is the closest thing to an SBOM database: ingest + continuous CVE re-evaluation; when a new CVE drops, every previously-ingested SBOM is re-evaluated.

**Deployment timing.** Three patterns: (1) **build-time** SBOM observes actual dependency resolution (highest accuracy; signed via sigstore alongside the binary); (2) **release-time** SBOM scans the artifact post-build (lower accuracy but simpler; supports retroactive SBOM for legacy artifacts); (3) **runtime / at-rest** SBOM scans deployed systems (lowest accuracy for in-source dependencies; useful for asset inventory). Mature programs do all three.

---

## 8. Reproducible Builds

### The property

**Reproducible build**: given the same source tree, the same build environment, and the same build instructions, any party can independently build the artifact and verify it is **byte-for-byte identical** to the published artifact.

The corollary: if my reproduction differs, *something is wrong* — either my environment differs, or the published artifact was built from different source than the public source tree.

### Why this matters

Reproducible builds is the structural defense against the SUNBURST class of attack. SolarWinds shipped a backdoored DLL signed by their legitimate Authenticode key; the source code in their git repository was clean. The signed binary was the discrepancy: it could not be reproduced from the source. *Anyone* with reproducible-build tooling could have noticed.

Russ Cox's framing (`design/25530-sumdb.md` and his 2019 "Surviving Software Dependencies" essay): the checksum database improves on SSH-style "**trust on first use**." When the Go module mirror records `sha256:abc...` for `golang.org/x/crypto@v1.0.0`, anyone can later rebuild that package and confirm the hash matches. Tampering — whether at the mirror, the build server, or in transit — becomes detectable in a single integrity check.

### The Debian Reproducible Builds project

Holger Levsen et al., 2014+ — systematic effort to make every Debian package reproducible. As of May 2025, over 95% of packages in Debian testing (trixie, amd64) were reported reproducible. Vagrant Cascadian's 2018 measurement: 88 of 154 (57%) packages in a minimal Debian sid system reproduce end-to-end. Remaining gaps cluster in: embedded timestamps (man pages, archive comments); embedded build paths (`__FILE__` in compiled binaries); non-deterministic compilers/build tools (older GCC, Java JIT, `/dev/urandom`-sourced IDs); archive-format non-determinism (tar/zip file ordering, timestamps).

Project toolkit: `diffoscope` (recursive diff that decompiles JARs, extracts ELFs, diffs PDFs); `strip-nondeterminism` (post-build cleanup); `reprotest` (deliberately-varied environments to surface non-determinism). https://reproducible-builds.org/

### Go's reproducible toolchain

Go 1.21+ is the first Go release with perfectly reproducible builds of the toolchain itself. Russ Cox's team eliminated sources of nondeterminism (map iteration order, embedded source paths, file metadata in archives, ARM floating-point mode defaults, others). Combined with the Go module checksum database (`sum.golang.org`, backed by Trillian's transparency-log infrastructure), every published module's hash is logged in a Merkle tree and the producing toolchain is itself reproducible. Trust root reduces to "trust the Trillian log + the public toolchain source." See https://go.dev/blog/rebuild and https://go.dev/blog/module-mirror-launch.

### NixOS, Bazel, and language-specific reproducibility

Two production approaches to **reproducibility-by-construction**: **NixOS / Nix** hashes the entire build environment (compiler version, flags, dependency hashes) into the install path; reproducibility rate consistently >90%. **Bazel** enforces hermetic builds via sandbox isolation and explicit dependency declaration. Both require upfront restructuring; build systems with implicit dependencies (a `Makefile` shelling out to whatever's on `PATH`) cannot be retrofitted easily.

Language-specific challenges: **C/C++** embeds `__FILE__` paths, `__DATE__`/`__TIME__`, debug-info paths (mitigation: `-ffile-prefix-map`, `SOURCE_DATE_EPOCH`, `-fdebug-prefix-map`). **Java** JAR/ZIP file ordering + embedded timestamps (mitigation: `strip-nondeterminism`, reproducible-jar plugins). **Python** `.pyc` source-path + wheel-creation timestamps (mitigation: `PYTHONHASHSEED=0`, `SOURCE_DATE_EPOCH` via setuptools). **JavaScript** is mostly OK because npm publishes source, not bytecode; transpilers can vary.

The `SOURCE_DATE_EPOCH` env var is the cross-language convention; set from the source commit's date (`git log -1 --format=%ct`) and reproducibility becomes tractable for most non-Bazel projects.

---

## 9. GitHub Artifact Attestations

Native first-party GitHub feature for **SLSA build provenance signed via sigstore**, introduced public beta May 2024 and GA June 2024. Components: `actions/attest-build-provenance` (generates SLSA Provenance v1.0); `actions/attest` (general in-toto attestations); server-side storage in GitHub; `gh attestation verify` for consumer-side verification.

The workflow shape:

```yaml
permissions: {contents: read, id-token: write, attestations: write}
jobs:
  build:
    steps:
      - uses: actions/checkout@<sha>
      - run: ./build.sh        # produces dist/myapp
      - uses: actions/attest-build-provenance@<sha>
        with: {subject-path: 'dist/myapp'}
```

Resulting attestation: in-toto-formatted SLSA Provenance v1.0, signed via Fulcio-issued ephemeral cert, logged in Rekor. Consumer side: `gh attestation verify dist/myapp --repo my-org/my-repo` checks the Fulcio cert signature, the OIDC subject matches `my-org/my-repo`, the Rekor entry confirms signing happened during cert validity, and the artifact's SHA-256 matches.

### Trade-offs

**Vendor lock-in.** Attestations live in GitHub storage; verification requires the `gh` CLI or HTTPS GET against GitHub's API. Constraint for air-gapped or federated-CI consumers.

**Simplicity.** For GitHub-resident projects, a 3-line addition. Compare standalone sigstore: provision OIDC trust, deploy cosign in CI, manage Rekor storage.

### Comparison

| Approach | Trust root | Storage |
|---|---|---|
| GitHub Artifact Attestations | GitHub OIDC | GitHub |
| Standalone sigstore Public Good | GitHub/GitLab/Google OIDC | Public Good Rekor |
| Private sigstore | Org OIDC + private Fulcio/Rekor | Self-hosted |
| in-toto only (no sigstore) | Pre-distributed pubkeys | Anywhere |
| Custom code-signing | HSM-backed long-lived keys | Anywhere |

The trend across npm provenance, PEP 740, GitHub Artifact Attestations, and Maven Central work: **ecosystem-native attestations backed by sigstore**, with the registry as trust intermediary. Consumers know "the ecosystem's trust root" — they don't manage individual maintainer keys.

Adoption snapshot (early 2026): Kubernetes, Wolfi, Homebrew core, and increasingly any security-conscious project.

---

## 10. Verifying Provenance — the Consumer Side

### The verification workflow archetype

Every consumer-side verification: fetch artifact → fetch attestation (in-toto envelope + sigstore signature + Rekor entry) → verify signature against OIDC-bound certificate → verify cert identity claims (subject, issuer) → verify Rekor Merkle-tree inclusion proof → verify predicate is what consumer requires (SLSA Provenance v1 with expected builder; SBOM with required ingredients) → policy decision: admit / warn / reject.

The OIDC subject check is load-bearing. *Any* sigstore-signed artifact is technically "valid" cryptographically; the question is whether it was signed by the *right* identity. A consumer accepting any sigstore signature is no better off than one accepting any GPG signature.

### Verifier tools

- **`slsa-verifier`** — reference SLSA Provenance verifier (https://github.com/slsa-framework/slsa-verifier). Checks in-toto envelope, validates signature, confirms `buildDefinition.externalParameters` matches expected source repo.
- **`cosign verify`** — online by default (requires network to fulcio.sigstore.dev + rekor.sigstore.dev). For air-gapped: `cosign initialize --mirror /path/to/sigstore-mirror` on a connected machine, then `cosign verify --offline ...`. Air-gapped requires pre-shipping the signature bundle + cert chain + Rekor inclusion proof.
- **`in-toto-verify`** — reads a signed layout, validates each link's signature against authorized functionaries, walks the input/output graph.

### Verifying SBOMs

Two parts: (1) **signature verification** — the SBOM is signed as a cosign attestation; standard verification. (2) **Content verification** — does the SBOM match the artifact? Re-generate via syft and diff; differences indicate tampering or generator drift.

### Policy-as-code frameworks

The verification primitives are necessary but not sufficient. To enforce "*all images deployed to production must be signed by `my-org/release-pipeline`*" requires a policy engine.

Production policy engines for supply-chain verification:

- **sigstore-policy-controller** — Kubernetes admission controller. Validates signatures and attestations on container images using cosign-format policies. Supports Cue and Rego policy languages. Operates on a per-namespace opt-in basis (`policy.sigstore.dev/include: "true"` label). https://github.com/sigstore/policy-controller.
- **Kyverno** — generic Kubernetes policy engine; supports image signature verification policies via `verifyImages` rule.
- **OPA Gatekeeper** — generic OPA-based admission controller; signature verification via custom Rego policies + image-scanning plugins.
- **Conftest** — OPA-based policy testing for non-Kubernetes contexts (config files, IaC).
- **Stacklok Minder** — supply-chain policy automation; integrates with GitHub artifact attestations + sigstore (Luke Hinds's Stacklok product).

The pattern is consistent: define policies as code (Rego, Cue, Kyverno), apply them at admission time (Kubernetes), at registry push (registry-side policies), or at build time (CI-side policies).

A canonical sigstore-policy-controller policy:

```yaml
apiVersion: policy.sigstore.dev/v1beta1
kind: ClusterImagePolicy
metadata:
  name: prod-images-must-be-signed
spec:
  images:
    - glob: "ghcr.io/my-org/**"
  authorities:
    - keyless:
        url: https://fulcio.sigstore.dev
        identities:
          - issuer: https://token.actions.githubusercontent.com
            subjectRegExp: "^https://github.com/my-org/.*"
```

This rejects any `ghcr.io/my-org/*` image not signed via GitHub Actions OIDC by a workflow in `my-org`.

---

## 11. Real-World Deployments

**Kubernetes core.** Signs release container images via sigstore since v1.24 (binaries, SBOMs and provenance since v1.26). The release process produces SHA-256 hashes, SLSA Provenance attestations, SPDX SBOMs, and cosign signatures. Consumers verify container images against the `krel-trust@k8s-releng-prod.iam.gserviceaccount.com` identity (issuer `https://accounts.google.com`).

**Distroless images (Google).** `gcr.io/distroless` is the minimal container base-image family with only the runtime — no shell, no package manager. All distroless images are cosign-keyless-signed.

**Wolfi / Chainguard Images.** Wolfi (https://github.com/wolfi-dev) is Chainguard's Linux undistro purpose-built for cloud-native supply-chain security. Every apk and image is sigstore-signed; SBOM is a cosign attestation; SLSA Build Level 3 compliant. Wolfi has no kernel — relies on the container runtime kernel. Chainguard Images ship distroless-built-from-Wolfi-apks with full provenance, CycloneDX + SPDX SBOMs, and continuous CVE remediation.

**Tekton Chains.** Generates SLSA Provenance v1 attestations for every TaskRun/PipelineRun. In production at IBM and Red Hat OpenShift Pipelines.

**PyPI's TUF + sigstore.** The PEP roadmap: **PEP 458** (TUF for PyPI metadata; long-running, partial); **PEP 480** (developer-side end-to-end signing; less-deployed); **PEP 691** (JSON simple API; substrate for richer metadata); **PEP 740** (index support for digital attestations; sigstore-backed, Trusted Publishers automatically generate attestations on upload). Layered composition: TUF protects metadata at the registry boundary; sigstore protects per-package provenance at the upload boundary.

**npm provenance.** Public beta Apr 2023, GA Sept 2023. `npm publish --provenance` in a GitHub Actions workflow fetches an OIDC token, signs via Fulcio (sigstore-js), uploads bundle to Rekor. Consumers: `npm view <pkg>@<v> dist.attestations`.

**Maven Central.** Longest-running supply-chain-modernization effort in Java. As of 2026: Sonatype has integrated sigstore-signing tooling; registry-side enforcement and Gradle/Maven consumer verification not yet end-to-end.

**Debian.** Signed Release files are the canonical distribution-layer-integrity example. Apt verifies Release signature against trusted-keys.gpg; Release pins SHA-256 of each Packages/Sources index; each Packages file pins per-package SHA-256 of the .deb. The Reproducible Builds project (Lunar, Levsen et al.) is the in-progress modernization adding independent verifiability; ~96% of Debian packages reproduce independently as of 2026.

---

## 12. Attack Patterns Against Provenance Frameworks

**Provenance forgery via build-platform compromise.** The catastrophic primitive: an attacker controlling the build platform's signing infrastructure can forge any provenance. SLSA L3 defends by requiring the signing key be isolated from build runtime. Detection: build-platform identity drift (provenance claiming `github.com/actions/runner/...` but signed with a non-GitHub OIDC issuer); source-repo / build-invocation mismatch (`externalParameters` references repo X but runner was invoked for repo Y); Rekor log gaps (signature time T but no corresponding entry). See [`detection_engineering_expertise.md`](detection_engineering_expertise.md) §5.

**SLSA-L2-claimed-but-actually-L1.** Producer asserts "L2" but build runs on a self-hosted runner without isolation. Mitigation: provenance attestations carry self-describing builder identity (`github.com/actions/runner/github-hosted`); consumers policy on hosted-vs-self-hosted.

**Rekor entry stuffing.** Not a real integrity attack — Rekor is append-only; entries cannot be modified. An attacker flooding Rekor to obscure malicious entries is a usability attack, not integrity. Defender query patterns (filter by OIDC issuer + subject) are unaffected.

**Fulcio root compromise.** Meta-threat. Mitigations: TUF-anchored trust distribution (M-of-N threshold for root rotation); HSM-backed Fulcio CA; defense-in-depth private sigstore deployments for high-value supply chains.

**OIDC issuer compromise.** If an OIDC issuer trusted by Fulcio is owned, an attacker can mint tokens for any workflow identity. Mitigations: HSM-backed OIDC signing keys at the IdP; short-lived token scope (minutes); workflow-scope identity claims (an attacker stealing a token for `test.yml@main` cannot use it to sign as `release.yml`).

**SBOM lies.** A producer publishes an SBOM that omits or misrepresents components; signing attests the SBOM was *produced by* this party, not that it's accurate. Mitigations: multi-source SBOM cross-check (consumer re-generates via syft + Trivy; differences indicate lying or generator drift); build-time SBOM via SLSA Provenance `resolvedDependencies`; reproducible builds (byte-identical artifact from claimed source detects SBOM lies about source-side dependencies).

**VEX abuse.** Producer claims `not_affected` when the vulnerable code is reachable. Mitigations: required `justification` fields; independent VEX cross-check (multiple issuers per vulnerability); VEX as living document with re-evaluation cadence.

**The three-leg stool.** The defensive structure has three legs: **provenance** (SLSA + sigstore + in-toto), **ecosystem** (registry-level trust intermediaries: npm, PyPI, Docker Hub, Maven Central), and **verification** (policy controllers, cosign-verify, slsa-verifier). Break any leg and the others don't fully compensate.

---

## 13. Practical Adoption Guidance

### The first 90 days of SLSA adoption

A pragmatic adoption ramp for a project moving from "nothing" to "SLSA L2":

- **Days 1-30**: SBOM in CI (syft/Trivy/cdxgen). Identify build-platform identity. Stand up sigstore keyless.
- **Days 31-60**: Add `actions/attest-build-provenance` to the release workflow. Validate locally with `gh attestation verify`. Document build identity in README + RELEASING.
- **Days 61-90**: Publish consumer-side verification instructions. Add SBOM + provenance to release page. Optionally deploy sigstore-policy-controller for your own upstreams.

Day 90 goal: SLSA L2 compliant. The L2→L3 jump is largely the build platform's responsibility; for GitHub Actions, Artifact Attestations alone provide Build L2; L3 requires reusable workflows that isolate the build from the calling workflow.

### Maturity ramp

```
Stage 0: nothing → 1: SBOM → 2: sigstore-signed releases → 3: SLSA L2 attestations
       → 4: SLSA L3 → 5: policy enforcement → 6: VEX program
       → 7: TUF-anchored updates → 8: reproducible builds
```

Stages 1-3 are achievable in <1 week for any GitHub-resident project. Stages 4-5 require organizational investment. Stages 6-8 are research-program territory; most organizations don't need them today.

### Public Good vs. private sigstore

Use **Public Good** for open-source, public-build-identity projects, and anyone without compliance-driven requirements for private infrastructure. Use **private sigstore** when the OIDC identity must stay confidential, compliance requires segregated transparency-log infrastructure, or volume would stress the Public Good Instance. Most projects start on Public Good and migrate only when compliance demands it.

### SBOM generation timing

Prefer **build-time SBOM** over post-build scanning — build-time observation captures actual dependency resolution; post-build re-derives from the artifact with lower accuracy. For containers: emit SBOM during the Dockerfile build (BuildKit SBOM emitters or `RUN syft ...`), upload as cosign attestation on the final image. The SBOM is bound to the image hash; consumers fetch both atomically.

### VEX as living document

Don't publish once and forget. Quarterly review of `not_affected` claims; automated alerts on CVEs that intersect your SBOM; versioned documents with explicit `issued` and `updated` timestamps. OWASP Dependency-Track ingests VEX and warns when claims age out.

Cross-links: [`appsec_program_building_expertise.md`](appsec_program_building_expertise.md) §6 for program-level posture choices; [`cicd_supply_chain_expertise.md`](cicd_supply_chain_expertise.md) §7 for CI-side wiring.

---

## 14. Variant Analysis — Under-Explored Frontiers

### Provenance for AI models

A trained model is the artifact; training data + hyperparameters + training code + checkpoints are the inputs. The "build" is the training run. SLSA-style provenance would attest to training data identity (hash, dataset-card), training code (commit + deps), hyperparameters, compute environment (hardware + drivers + framework), and output checkpoint hash. The **model card** format (Mitchell et al., 2019) is the documentation-side counterpart. Status: early; not yet at SLSA-for-code production levels.

Cross-link: [`adversarial_ml_model_security_expertise.md`](adversarial_ml_model_security_expertise.md) §8.

### Provenance for AI training data

Training datasets are software-like artifacts: versioned, built from sources (web crawls, curated corpora, synthetic), license-bound, silently modifiable. SBOM for training data is the natural framing. SPDX 3.0's Dataset profile is the canonical spec; CycloneDX has emerging support. Tooling adoption: infancy.

### Provenance for LLM-generated code

When an AI coding assistant commits code, two attestations apply: (1) the human's git commit signature (the default — attesting to the human who reviewed and committed); (2) an optional AI-tool attestation ("generated by Claude Sonnet 4.5 at <timestamp> with <prompt-hash>"). The second has limited industry adoption. The "AI tool produced code the human didn't actually review" risk is currently mitigated by human-review discipline, not attestation.

Cross-links: [`llm_agent_security_expertise.md`](llm_agent_security_expertise.md), [`agentic_web_capabilities_expertise.md`](agentic_web_capabilities_expertise.md).

### Provenance for AI agent tool definitions

In an MCP-based or agent-runtime context, the tool definition (name, input/output schemas, function body) is itself a supply-chain artifact. Possible attestation: sigstore-signed tool manifest binding tool name to function-body hash with publisher OIDC identity. Adoption: nascent.

### Multi-cloud + decentralized provenance

When an artifact is built on GCP, signed via GitHub Artifact Attestations (Public Good sigstore), pushed to AWS ECR, and consumed by an Azure workload, the trust path crosses three cloud roots plus GitHub plus sigstore. Mitigation: standardize on sigstore as the cross-cloud trust intermediary — the Public Good Instance is cloud-agnostic.

Decentralized provenance (blockchain-anchored attestations) is research-stage; Rekor already provides the Merkle-tree transparency log without blockchain overhead. Future relevance: see [`vulnerability_research_methodology_expertise.md`](vulnerability_research_methodology_expertise.md) for the methodology of evaluating these emerging frameworks empirically.

---

## 15. References

### SLSA

- SLSA v1.0 specification: https://slsa.dev/spec/v1.0/
- SLSA v1.0 levels: https://slsa.dev/spec/v1.0/levels
- SLSA v1.0 provenance schema: https://slsa.dev/spec/v1.0/provenance
- SLSA v1.1 requirements: https://slsa.dev/spec/v1.1/requirements
- SLSA verifier (reference implementation): https://github.com/slsa-framework/slsa-verifier
- SLSA blog — Bringing Improved Supply Chain Security to Node.js: https://slsa.dev/blog/2023/05/bringing-improved-supply-chain-security-to-the-nodejs-ecosystem
- SLSA blog — Securing software artifacts with Tekton Chains and IBM's DevSecOps: https://slsa.dev/blog/2024/04/tekton-chains-ibm-devsecops
- Chainguard Academy SLSA intro: https://edu.chainguard.dev/compliance/slsa/what-is-slsa/

### sigstore

- sigstore main site: https://www.sigstore.dev/
- sigstore docs: https://docs.sigstore.dev/
- cosign repo: https://github.com/sigstore/cosign
- fulcio repo: https://github.com/sigstore/fulcio
- rekor repo: https://github.com/sigstore/rekor
- policy-controller repo: https://github.com/sigstore/policy-controller
- sigstore blog: https://blog.sigstore.dev/
- sigstore "Life of a signature" (Chainguard): https://www.chainguard.dev/unchained/life-of-a-sigstore-signature
- Rekor introduction (Chainguard Academy): https://edu.chainguard.dev/open-source/sigstore/rekor/an-introduction-to-rekor/
- Cosign introduction (Chainguard Academy): https://edu.chainguard.dev/open-source/sigstore/cosign/an-introduction-to-cosign/

### in-toto

- in-toto main site: https://in-toto.io/
- in-toto USENIX 2019 paper (Torres-Arias, Afzali, Kuppusamy, Curtmola, Cappos): https://www.usenix.org/conference/usenixsecurity19/presentation/torres-arias
- in-toto USENIX 2019 PDF: https://www.usenix.org/system/files/sec19-torres-arias.pdf
- in-toto specs: https://github.com/in-toto/docs
- in-toto attestation framework: https://github.com/in-toto/attestation

### TUF

- TUF main site: https://theupdateframework.io/
- TUF history: https://theupdateframework.io/docs/project/history/
- TUF specification: https://theupdateframework.github.io/specification/
- gittuf: https://gittuf.dev/
- PEP 458 — Secure PyPI downloads with signed repository metadata: https://peps.python.org/pep-0458/
- PEP 480 — End-to-end signing of packages: https://peps.python.org/pep-0480/
- Justin Cappos's homepage (NYU): https://ssl.engineering.nyu.edu/personalpages/jcappos/
- Justin Cappos's Wikipedia: https://en.wikipedia.org/wiki/Justin_Cappos

### SBOM formats

- SPDX: https://spdx.dev/
- SPDX specifications: https://spdx.dev/specifications/
- CycloneDX: https://cyclonedx.org/
- CycloneDX specification overview: https://cyclonedx.org/specification/overview/
- CycloneDX joins OWASP as flagship project: https://owasp.org/executive/director/2021/06/11/cyclonedx-joins-owasp
- OWASP CycloneDX project page: https://owasp.org/www-project-cyclonedx/
- SWID via NIST IR 8060: https://csrc.nist.gov/publications/detail/nistir/8060/final
- Steve Springett's site: https://stevespringett.com/

### VEX

- OpenVEX (OpenSSF): https://openssf.org/projects/openvex/
- OpenVEX GitHub: https://github.com/openvex
- CycloneDX VEX: https://cyclonedx.org/capabilities/vex/
- CISA VEX Use Cases: https://www.cisa.gov/sites/default/files/publications/VEX_Use_Cases_Document_508c.pdf

### SBOM tooling

- syft (Anchore): https://github.com/anchore/syft
- grype (Anchore): https://github.com/anchore/grype
- Trivy (Aqua Security): https://github.com/aquasecurity/trivy
- cdxgen (CycloneDX project): https://github.com/CycloneDX/cdxgen
- OWASP Dependency-Track: https://dependencytrack.org/
- Protobom (OpenSSF, García Veytia): https://github.com/protobom
- kubescape: https://github.com/kubescape/kubescape

### Reproducible Builds

- Reproducible Builds main site: https://reproducible-builds.org/
- Reproducible Builds monthly reports: https://reproducible-builds.org/reports/
- NixOS Reproducible Builds: https://reproducible.nixos.org/
- Go reproducible toolchain blog post: https://go.dev/blog/rebuild
- Go Module Mirror + Checksum Database: https://go.dev/blog/module-mirror-launch
- Go sumdb proposal: https://go.googlesource.com/proposal/+/master/design/25530-sumdb.md
- Russ Cox, "Surviving Software Dependencies": https://research.swtch.com/deps
- SOURCE_DATE_EPOCH spec: https://reproducible-builds.org/specs/source-date-epoch/
- LWN "The history, status, and plans for reproducible builds": https://lwn.net/Articles/985739/

### GitHub Artifact Attestations

- GitHub artifact attestations docs: https://docs.github.com/en/actions/concepts/security/artifact-attestations
- GitHub blog: Introducing Artifact Attestations: https://github.blog/news-insights/product-news/introducing-artifact-attestations-now-in-public-beta/
- GitHub changelog: Artifact Attestations GA: https://github.blog/changelog/2024-06-25-artifact-attestations-is-generally-available/
- actions/attest-build-provenance: https://github.com/actions/attest-build-provenance
- actions/attest: https://github.com/actions/attest
- Achieving SLSA 3 with GitHub Actions + sigstore (Go modules): https://github.blog/security/supply-chain-security/slsa-3-compliance-with-github-actions/
- Enhance build security and reach SLSA L3: https://github.blog/enterprise-software/devsecops/enhance-build-security-and-reach-slsa-level-3-with-github-artifact-attestations/

### npm provenance

- npm package provenance announcement (Apr 2023): https://github.blog/security/supply-chain-security/introducing-npm-package-provenance/
- npm provenance GA (Sept 2023, sigstore blog): https://blog.sigstore.dev/npm-provenance-ga/
- npm provenance docs: https://docs.npmjs.com/generating-provenance-statements/
- npm provenance details: https://github.com/npm/provenance

### PyPI sigstore integration

- PEP 740 — Index support for digital attestations: https://peps.python.org/pep-0740/
- PyPI blog: PyPI now supports digital attestations: https://blog.pypi.org/posts/2024-11-14-pypi-now-supports-digital-attestations/
- Trail of Bits: Attestations — A new generation of signatures on PyPI: https://blog.trailofbits.com/2024/11/14/attestations-a-new-generation-of-signatures-on-pypi/
- pypi-attestations library: https://pypi.org/project/pypi-attestations/
- "Are we PEP 740 yet?" tracker: https://trailofbits.github.io/are-we-pep740-yet/

### Chainguard / Wolfi / distroless

- Wolfi overview (Chainguard Academy): https://edu.chainguard.dev/open-source/wolfi/overview/
- Wolfi project: https://github.com/wolfi-dev
- Chainguard Images: https://images.chainguard.dev/
- Chainguard blog (Unchained): https://www.chainguard.dev/unchained/

### Stacklok

- Stacklok blog: https://stacklok.com/blog
- Minder (supply-chain policy automation): https://github.com/mindersec/minder
- OpenSSF Podcast — Adolfo García Veytia on SBOMs and VEX: https://openssf.org/podcast/2024/06/18/whats-in-the-soss-podcast-7-stackloks-adolfo-garcia-veytia-digs-into-sboms-and-vex/

### Tekton Chains

- Tekton Chains docs: https://tekton.dev/docs/chains/
- SLSA Provenance in Tekton: https://tekton.dev/docs/chains/slsa-provenance/
- Signed Provenance Tutorial: https://tekton.dev/docs/chains/signed-provenance-tutorial/

### Sigstore Public Good Instance + operations

- sigstore Public Good Instance: https://docs.sigstore.dev/about/overview/
- "OSS Security: Chainguard Spring 2023 update": https://www.chainguard.dev/unchained/oss-security-chainguard-spring-2023-update
- Sigstore Announces General Availability at SigstoreCon: https://openssf.org/press-release/2022/10/25/sigstore-announces-general-availability-at-sigstorecon/

### Internal cross-references

- `software/supply-chain/cicd_supply_chain_expertise.md` — parent doc on CI/CD attack surface; covers tj-actions, pwn-request, the incident corpus, and how SLSA/sigstore wire into CI workflows
- `software/crypto-trust/cryptography_expertise.md` — signing primitives (Ed25519, X.509, Merkle trees) underpinning sigstore + TUF
- `software/detection-ir/detection_engineering_expertise.md` — attestation-anomaly detection patterns and the "match + context filter" structure that VEX adds to SBOM
- `software/methodology/appsec_program_building_expertise.md` — buying decisions and program-level posture choices for supply-chain controls
- `software/ai-ml-security/agentic_web_capabilities_expertise.md` — agent runtime attestation for tool definitions and capability binding
- `software/ai-ml-security/llm_agent_security_expertise.md` — provenance for AI-tool-generated code; agent supply-chain threats
- `software/ai-ml-security/adversarial_ml_model_security_expertise.md` — model provenance, training data SBOM, model-card formats
- `software/methodology/vulnerability_research_methodology_expertise.md` — methodology for evaluating supply-chain frameworks empirically
