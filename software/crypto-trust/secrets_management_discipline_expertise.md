# Secrets Management Discipline — Operational Expertise

> Audience: Claude (future shifts) + staff-security engineer running secrets discipline in a real product context. Imperative-voice operational doc, not a vendor pitch.
>
> Scope boundary: this doc is **operational secrets lifecycle** — provisioning, storage, distribution, rotation, revocation, audit. It is NOT crypto primitives (see `cryptography_expertise.md`), NOT TEE-isolated secrets handling (see `confidential_computing_expertise.md`), NOT PQC-era key migration mechanics (see `post_quantum_cryptography_expertise.md` §11). Read those for primitives; read this for the practice that uses them.

---

## 1. Why this doc exists

Secrets are the failure mode of the perimeter. The 2020-2026 incident corpus — SolarWinds, Codecov, CircleCI, LastPass-via-DevOps-Engineer, Okta-via-service-account-credential-in-personal-Google-account, Shai-Hulud npm worm, Clinejection 8-day Cline window, MOVEit, Snowflake credential-stuffing — keeps surfacing the same shape. The defenders had a perimeter. They had identity providers. They had EDR. The breach pivot was a credential that was supposed to be rotated, supposed to be short-lived, supposed to be revoked. It wasn't.

This is the cross-cutting discipline that connects three other domains in this corpus:

- **Supply chain** (`cicd_supply_chain_expertise.md`) — the dominant 2025-2026 worm class (Shai-Hulud, Mini-Shai-Hulud, Clinejection) pivots on stolen tokens that should have been short-lived OIDC and weren't, or were rotated at the UI but not revoked at the registry's API.
- **Identity** (`cloud_iam_expertise.md`, `zero_trust_workload_identity_expertise.md`) — IAM policy is theater if the workload presenting the token is using a 2019 IAM-user PAT pinned in a config file.
- **Incident response** (`ai_incident_response_playbook_expertise.md`, `dfir_methodology_expertise.md`) — the first containment action on most incidents is credential rotation. Doing it correctly — eradication-grade, not containment-grade — is the load-bearing skill.

Read this doc when you are designing a secrets stack, auditing one, or responding to a credential-compromise incident. The aphorism: **rotation that isn't verified at the issuing authority is not rotation**.

---

## 2. The secrets lifecycle

Six-stage canonical lifecycle. Every secret in your environment is in exactly one of these stages at any time. If you cannot place a given credential on this list, you do not have secrets discipline; you have secrets.

**Generation.** Entropy source matters. `os.urandom` / `crypto.randomBytes` / `/dev/urandom` are the right primitives; `Math.random()` and `time.time()`-seeded generators are not. Length 32 bytes (256 bits) minimum for symmetric secrets, 16 bytes (128 bits) acceptable for session tokens with binding. Format constraints come from the consuming service: API keys often have a fixed prefix (`sk-`, `ghp_`, `xoxb-`) that secret scanners depend on. Generate the secret at the issuing authority, not at the consumer.

**Provisioning.** Who issues, under what attestation? The control-plane question. For long-lived service credentials: a named human or automated identity must request, with an audit-loggable reason. For short-lived workload credentials: the workload presents an attestation (OIDC token, SPIFFE-SVID, EC2 instance identity document, GKE Workload Identity claim), and the issuer (Vault, AWS STS, GitHub OIDC provider) mints scoped credentials with TTL. The shift from former to latter in 2023-2026 is the single largest operational improvement in the discipline.

**Storage.** At-rest encryption is table stakes. The substantive question is *where the wrapping key lives*. KMS-as-KEK envelope encryption (§7) is the canonical pattern: the workload stores ciphertext, the KEK lives in a managed HSM that the workload can ask to unwrap. Anti-pattern: storing the wrapping key in the same blob as the wrapped secret. "Encrypted secrets in git" without an external KMS is base64-with-extra-steps.

**Distribution.** Three patterns, listed in order of operational maturity:
- **Broker pattern**: workload authenticates to a secrets broker (Vault, AWS Secrets Manager, ESO), receives credential at runtime, holds it in memory only. Best practice.
- **Injection pattern**: orchestrator (Kubernetes, ECS, Nomad) injects credential as environment variable or mounted file at workload startup. Common; acceptable if injection is via short-lived workload-identity-attested fetch.
- **Pull pattern**: workload pulls from a remote at startup. Bootstrapping problem — how did the workload authenticate to do the pull?

**Use.** Short-lived (TTL ≤ 1 hour) vs long-lived. Cache discipline: in-memory only, never written to disk, never logged, scrubbed on shutdown. The Go and Rust idioms (`zeroize::Zeroize`, `secrets::Secret`) and Python's lack thereof matter — see `python_footguns_expertise.md` on why string immutability + GC make in-memory zeroization unenforceable in CPython. Logging discipline: every modern logging library has happened to log a secret at least once in its life; assume your logging pipeline is hostile and either (a) tag secrets at type-level to enable redaction, or (b) keep secrets out of any object whose `__str__` / `Display` / `Debug` is called by logging code paths.

**Rotation + Revocation.** The load-bearing distinction (§9). Rotation is "new secret issued and consumer cuts over." Revocation is "old secret is now invalid at the issuing authority and cannot be presented." Most operational failures conflate them. Verify rotation by attempting authentication with the *old* token against the *issuing authority's API*. If that authentication succeeds, the secret was rotated, not revoked.

---

## 3. Vault landscape — HashiCorp Vault as the canonical reference

HashiCorp Vault (Mitchell Hashimoto + Armon Dadgar, 2015) is the reference implementation of the broker pattern. The conceptual model: a single API surface in front of an extensible plugin system that does both static-secret storage and dynamic-secret minting against backend systems.

**Primitives.**

- **KV v2 secrets engine** — static key-value storage with versioning. Soft-delete via version-pin metadata. Use sparingly; static secrets are the failure surface this whole discipline tries to reduce.
- **Transit secrets engine** — encryption-as-a-service. The application sends plaintext, gets ciphertext; Vault holds the key. Closest Vault primitive to a managed KMS; the keystore-as-API pattern.
- **Database secrets engine** — dynamic credentials for PostgreSQL, MySQL, MSSQL, MongoDB, Cassandra, Oracle, Redis. Workload requests credential, Vault issues a *new* per-session DB user with a TTL (inherited from the mount's default lease TTL, 768h unless tuned). When the lease expires, Vault drops the DB user. This is the canonical short-lived-credential pattern; deploy it and you eliminate the "shared DB password across 12 microservices" anti-pattern in §12.
- **PKI secrets engine** — dynamic X.509 certificate issuance for service-mesh integration (Consul Connect, Istio with Vault as upstream CA). Short-TTL certs eliminate the cert-rotation distributed-coordination problem.
- **AWS / Azure / GCP secrets engines** — dynamic cloud-IAM credentials. Workload requests AWS access keys, Vault assumes an IAM role and returns scoped STS credentials. Eliminates IAM-user-with-static-credentials at the cloud-platform boundary.
- **Kubernetes auth method** — workload presents its ServiceAccount JWT, Vault validates with the cluster's TokenReviewer API, returns a Vault token bound to a Vault policy.
- **AppRole auth method** — role-id + secret-id pair, intended for non-Kubernetes workloads. The bootstrapping problem in concentrated form: how does the workload obtain the secret-id? Standard answer: secret-id is wrapped (one-time-use token) and delivered out-of-band by an orchestrator. Still has a root-of-trust problem; see §12.
- **Vault Agent** — sidecar that handles auth + token renewal + template-rendering of secrets into files for the application. Production-grade pattern for k8s workloads is Vault Agent Injector (Kubernetes mutating webhook).

**Vault Enterprise vs OSS / OpenBao fork.** HashiCorp moved Vault from MPL 2.0 to Business Source License (BSL) in August 2023 `[unverified specific clause]`. IBM completed its acquisition of HashiCorp in February 2025. The OSS community responded with the **OpenBao** fork under the LF banner. For new deployments, evaluate OpenBao if license restrictions are material. Most patterns in this doc apply identically to both; the divergence is in enterprise-only features (HSM auto-unseal, namespaces, replication tiers, Sentinel policies).

**Concrete production patterns.**

- *Short-lived DB credentials*: configure database secrets engine for each service's DB user template; workload uses Vault Agent to fetch + renew; Vault lease expires automatically; no human ever holds the credential.
- *PKI dynamic-cert for mesh*: Vault as intermediate CA, mesh proxies (Envoy / Linkerd) fetch certs via Vault Agent on a short rotation interval.
- *Vault Agent sidecar injection*: Helm chart deploys Vault Agent Injector; pods annotated `vault.hashicorp.com/agent-inject: "true"` get a sidecar container injected; secrets are templated into a shared `emptyDir` volume; app reads from filesystem.

The pattern that fails: storing application config secrets in Vault KV v2 and never rotating them. Vault becomes a slightly-better filing cabinet. The operational substance of Vault is the dynamic engines and the lease-and-renew lifecycle.

---

## 4. Cloud-native secrets services

Every major cloud has a managed secrets service, a managed KMS, and a managed HSM tier. Use them when you are on a single cloud; bridge them with ESO or Vault when you are multi-cloud.

**AWS.**

- **Secrets Manager** — versioned secrets, cross-region replication, automatic rotation via Lambda. Rotation is opinionated: you provide a Lambda function with four phases (createSecret, setSecret, testSecret, finishSecret). The Lambda must coordinate with the consuming services. Built-in rotation templates for RDS / Redshift / DocumentDB.
- **Parameter Store (SSM)** — cheaper, less feature-rich; no built-in rotation, no replication. Use for non-secret configuration; use Secrets Manager for actual secrets despite the cost difference.
- **KMS** — envelope encryption authority. Customer-managed keys (CMK), AWS-managed keys, AWS-owned keys. Key policies + IAM policies + grants are three distinct authorization mechanisms; the eval order matters (`cloud_iam_expertise.md` §AWS).
- **CloudHSM** — dedicated FIPS 140-2 Level 3 hardware. Use when compliance demands hardware key custody you control; expensive, operationally heavy.
- **IAM Roles Anywhere** — cert-based workload identity for non-AWS workloads (on-prem, other-cloud). The PKI piece extends AWS IAM trust outside AWS.

**GCP.**

- **Secret Manager** — Cloud KMS-backed, versioning + replication. Per-secret regional / multi-regional replication policy. IAM-gated access.
- **Cloud KMS** — envelope encryption. Software-backed or HSM-backed (Cloud HSM tier). Customer-supplied encryption keys (CSEK) and customer-managed encryption keys (CMEK) are distinct: CMEK is GCP-stored, customer-controlled; CSEK is customer-provided per-request.
- **Cloud HSM** — FIPS 140-2 Level 3 managed HSM. Premium tier of Cloud KMS.
- **Workload Identity Federation** — OIDC for workload authentication. GitHub Actions / GitLab / AWS / arbitrary OIDC issuers can be configured as identity pools; workloads exchange their OIDC token for a short-lived GCP service-account token.

**Azure.**

- **Key Vault** — Standard (software-backed) and Premium (HSM-backed) tiers. Stores secrets, keys, certificates. Soft-delete + purge protection are required for compliance scenarios; turn them on by default.
- **Managed HSM** — dedicated FIPS 140-2 Level 3 HSM, similar to Cloud HSM / CloudHSM.
- **Managed Identity** — system-assigned (lifecycle bound to the Azure resource) and user-assigned (independent lifecycle, attachable to multiple resources). Workloads use Managed Identity to authenticate to Key Vault and other Azure services without storing credentials.

**Shared anti-patterns.** Across all three clouds, the recurring failure modes:

- **Service-principal long-lived secrets** in Azure: the service-principal client-secret with 1-year or 2-year expiry, set by a developer in 2022, still in production in 2026.
- **IAM-user with static access keys** in AWS: prefer IAM Roles + STS for everything; IAM users exist for legacy and emergency break-glass only.
- **Root account access keys** in any cloud: should not exist. If they exist, delete them; the root account has no legitimate API-access use case.
- **Cross-account access keys** when cross-account IAM roles would work: indicates the team that built it didn't know STS existed.

---

## 5. OSS secrets-broker landscape

Beyond Vault, the OSS ecosystem clusters around a few patterns:

**Sealed Secrets (Bitnami)** — Controller runs in cluster with a long-lived asymmetric keypair. Operators encrypt Kubernetes Secret manifests with the controller's public key using the `kubeseal` CLI; the ciphertext is committed to git. At reconciliation, the controller decrypts and creates a native Secret. Limitation: the encryption is bound to the cluster's controller key; you cannot move a SealedSecret to a different cluster without re-encrypting. Strength: zero external dependency, simple operational model.

**SOPS (Secrets OPerationS, originally Mozilla; CNCF Sandbox since 2023)** — Julien Vehent + Adrian Utrilla. File-level encryption with multiple backend support: AWS KMS, GCP KMS, Azure Key Vault, age, PGP. The git-friendly choice: encrypt the *values* in a YAML/JSON/ENV/INI file while keeping the *keys* in plaintext, so diffs are reviewable. Per-key encryption with `creation_rules` regex. The standard GitOps idiom is SOPS-encrypted secrets in git + Helmfile or Kustomize SOPS plugin + ArgoCD with the helm-secrets plugin.

**External Secrets Operator (ESO)** — Container Solutions; CNCF Sandbox (accepted July 2022). Pulls secrets from upstream stores (AWS Secrets Manager, GCP Secret Manager, Azure Key Vault, HashiCorp Vault, IBM Cloud Secrets Manager, Akeyless, Doppler, 1Password Connect, Bitwarden) into Kubernetes Secret objects. Most-deployed pattern in Kubernetes practice as of 2026 — it lets you keep the cloud-native store as source of truth while consuming workloads see standard Kubernetes Secrets. Refresh interval controls how often ESO re-pulls; set it short enough that rotated upstream secrets propagate before old ones are cached.

**age (Filippo Valsorda)** — modern crypto for file encryption. X25519 + ChaCha20-Poly1305. Small attack surface (no version negotiation, no parameter flexibility), the inverse of PGP's design. Used as a SOPS backend; also standalone for the "encrypt this file with my SSH key" idiom. Valsorda's `age` is what `gpg` should have been.

**The GitOps secrets idiom.** SOPS-encrypted YAML in git → Helmfile or Flux/Argo SOPS plugin → KMS decrypts at apply-time → native Kubernetes Secrets reconciled into the cluster. Combined with cluster-side ESO pulling from a cloud secrets store for runtime-injected credentials. Two distinct tools for two distinct lifecycles: SOPS for declarative-config secrets (DB password used by the deployment), ESO for runtime-fetched credentials (per-pod database session credentials issued at startup).

---

## 6. Enterprise commercial landscape

Discuss WHEN each is the right choice, not the feature matrix.

**Akeyless** — vaultless distributed-fragments approach. Key fragments are spread across regions and independent cloud providers, optionally with one held by the customer, and operations run without recombining them; no single region holds the full key. Marketed as the "DFC" (Distributed Fragments Cryptography) pattern. The right choice when regulatory constraints prohibit any single jurisdiction from holding the master key.

**CyberArk Conjur** — legacy enterprise; CyberArk's broader Privileged Access Management (PAM) suite. The right choice when you're already a CyberArk shop and need integration with PAS session-recording.

**Doppler** — developer-experience-first. CLI + GUI focused on environment variable management across dev/staging/prod with rotation hooks. The right choice for small-to-mid teams that want secrets-as-environment-variables without operating Vault.

**1Password Secrets Automation** — extends 1Password's password-manager UX to machine-to-machine secrets. The right choice when your humans already use 1Password and you want a unified secrets surface for both human and machine credentials.

**Infisical** — OSS-first SaaS. End-to-end-encrypted (client-side encryption with cloud-stored ciphertext). The right choice when you want a vendor-managed service but cannot accept the vendor having plaintext access.

**Delinea (formerly Thycotic)** — Secret Server is the legacy on-prem enterprise tool with deep AD integration. The right choice for Windows-heavy enterprise environments with established Delinea/Thycotic deployments.

**BeyondTrust Password Safe** — enterprise PAM with secrets management bolted on. The right choice when you need credential vaulting alongside session brokering and privilege elevation.

Do not pick based on Gartner Magic Quadrant placement. Pick based on (a) the workload-identity story you can implement, (b) the rotation and revocation primitives you actually need, (c) operational fit with the rest of your stack. A team running Vault badly is worse than the same team running Doppler well.

---

## 7. Key Management Service architecture

The KMS sits underneath the secrets service. Understand the architecture or you will design a system whose security claims do not hold.

**Envelope encryption.** The canonical pattern: data is encrypted with a Data Encryption Key (DEK). The DEK is encrypted with a Key Encryption Key (KEK) that lives in the KMS. The wrapped DEK travels with the ciphertext; the KEK never leaves the KMS boundary. KMS is not free — every Decrypt operation is audit-logged, rate-limited, and billed. Anomaly detection on KMS-call patterns becomes a primary defensive signal (§12).

Operational consequence: a compromised application cannot exfiltrate the KEK. The blast radius is bounded by what was wrapped under DEKs that were in memory at compromise time, plus what an attacker can subsequently coerce the KMS to unwrap via the compromised application's identity. This is *not* zero — see "KMS-as-keystroke-logger" in §12 — but it is meaningfully better than "the master key was a `.pem` file on the application server."

**HSM tier.** Hardware Security Modules. FIPS 140-2 Level 2 (tamper-evident) and Level 3 (tamper-responsive, identity-based authentication, separation of roles). FIPS 140-3 supersedes 140-2; FIPS 140-2 certificates moved to the CMVP Historical list on September 21, 2026. The compliance gradient:

- Software-backed KMS (AWS KMS default keys, Azure Key Vault Standard, GCP Cloud KMS software): adequate for most workloads.
- Cloud-managed HSM (CloudHSM, Managed HSM, Cloud HSM): FIPS 140-2 Level 3 with vendor operating the device. Use when audit or regulatory regime requires hardware key custody but you cannot operate an HSM yourself.
- Dedicated HSM (Thales Luna, Entrust nShield, Utimaco): on-prem or co-lo, customer-operated. Use only when regulation explicitly requires customer-operated hardware (some payment-card, some government).

**BYOK (Bring Your Own Key).** Customer generates the KEK off-cloud, imports it into the cloud KMS. The KEK is now in the cloud HSM but the customer controls the lifecycle (can re-import, can delete). Operational reality: most BYOK deployments are *compliance theater*. The KEK is in the cloud-provider's HSM the moment after import; the cloud provider has the same access they would have to a vendor-generated KEK. BYOK is meaningful when you have a robust import-deletion-cycle process that proves the cloud provider cannot persist the KEK; in practice few customers operate it that way.

**HYOK (Hold Your Own Key).** Customer holds the KEK entirely outside the cloud. The cloud service makes a call out to a customer-operated keystore (HSM, external KMS) for every wrap/unwrap. Operationally rare: high latency, high availability burden on the customer-operated keystore, mostly used for sovereign-cloud compliance scenarios. The Microsoft Double Key Encryption pattern is the highest-profile HYOK deployment `[unverified specific product status]`.

Choose the right tier for the threat model. Most teams do not need HSM-backed keys; they need to stop checking AWS access keys into GitHub.

---

## 8. Short-lived credentials and OIDC trusted publishing

The single largest operational improvement in the 2024-2026 period is the shift from long-lived Personal Access Tokens and IAM-user access keys to OIDC-issued short-lived tokens. Cross-link: `cicd_supply_chain_expertise.md` §7 (CI/CD identity), `zero_trust_workload_identity_expertise.md` (SPIFFE / workload attestation).

**The pattern.** A workload (typically a CI runner) holds no long-lived secret. The CI platform issues an OIDC token signed by its own JWT issuer at job start. The workload presents that OIDC token to a downstream service (cloud provider, package registry, secrets broker), which validates the JWT signature against the CI platform's public JWKS endpoint and checks claims (`sub`, `aud`, `repository`, `environment`) against a pre-configured trust policy. Downstream service issues a short-lived scoped credential.

**Production deployments.**

- **GitHub Actions OIDC → AWS IAM.** `sts:AssumeRoleWithWebIdentity` against an IAM role with a trust policy validating `token.actions.githubusercontent.com` as the issuer and `repo:org/repo:ref:refs/heads/main` (or similar) as the `sub`. Generally available since late 2021 `[unverified exact GA date]`. The reference pattern for cloud OIDC.
- **GitHub Actions OIDC → npm Trusted Publishing.** Generally available July 31, 2025. npm publishes the package with provenance attestation tied to the GitHub Actions workflow run. Eliminates the long-lived NPM_TOKEN that was the entry vector for Shai-Hulud and Mini-Shai-Hulud (`cicd_supply_chain_expertise.md` §2.9).
- **GitHub Actions OIDC → PyPI Trusted Publishing.** Launched April 2023. PEP 740 attestations layer cryptographic attestation onto the OIDC-bound publication.
- **HashiCorp Vault JWT auth via OIDC discovery.** Vault validates an external OIDC token (from GitHub Actions, Kubernetes, Auth0, Okta) and issues a Vault token bound to a policy. Eliminates AppRole bootstrapping for OIDC-aware workloads.
- **SPIFFE-SVID as cloud-agnostic equivalent.** Workload presents an SVID (SPIFFE Verifiable Identity Document, either X.509 or JWT), trusted by federated SPIRE servers. `zero_trust_workload_identity_expertise.md` covers the mechanism in depth.

**Operational gates.** Configure the trust policy as narrowly as the issuer's claims permit. For GitHub Actions OIDC → AWS, the trust policy should validate not just `repo:org/name:*` but the specific ref or environment. The default-permissive trust policy (`repo:org/name:*`) accepts any workflow in any branch.

**Honest limitation.** OIDC binding eliminates long-lived secrets *for the workload identity*. It does not eliminate the underlying secret that the workflow uses to do its job (the DB password, the SaaS API key, the customer encryption key). Short-lived workload identity is the *bootstrap* into the secrets discipline, not the entirety of it.

---

## 9. Rotation discipline — the load-bearing failure mode

This is the section to re-read before responding to a credential-compromise incident.

**Rotation-completion vs revocation-at-authority.** The most common operational failure. The Clinejection incident (disclosed by Adnan Khan and collaborators, advisory `GHSA-9ppg-jx86-fqw7`, see `ai_assisted_coding_tool_security_expertise.md` / `cicd_supply_chain_expertise.md` §10) is the canonical anchor: on February 9, 2026 Cline tried to rotate its exposed npm publish token, but the wrong token was deleted while the exposed one remained active. npm's org-level token page showed zero active tokens; the exposed token was not surfaced in that view. It stayed valid until February 17, after it had been used to publish an unauthorized `cline@2.3.0`. Cline's post-mortem names testing the actual credential, not checking a dashboard, as the missing practice; treat it as the primary source for this section.

Verification test: attempt authentication with the *old* token against the *issuing authority's API*. If it succeeds, the secret was rotated, not revoked.

```
# Verifying npm token revocation
$ npm whoami --userconfig <old-token-config-file>
# If this returns a username, the token is still valid. The rotation was incomplete.

# Verifying AWS access key revocation
$ AWS_ACCESS_KEY_ID=<old-key> AWS_SECRET_ACCESS_KEY=<old-secret> aws sts get-caller-identity
# Should return InvalidClientTokenId. If it returns identity, key is still active.
```

**Rotation cadence.**

- **Static secrets**: 90-day default. Shorter for high-blast-radius credentials (production DB master credentials, root certificate authority intermediate CAs).
- **Dynamic secrets** (Vault-issued, AWS STS, etc.): TTL ≤ 1 hour. The whole point is that there is no rotation; the credential simply expires.
- **Service-mesh certs**: 24-72 hour cert validity, automatic renewal at 50-66% of validity.
- **Human-held credentials** (operator passwords, MFA recovery codes): immediate rotation on personnel change; otherwise governed by org policy. Quarterly is common; arbitrarily short rotation pushes users to reuse + write-down anti-patterns and is counterproductive.

**Coordinated rotation.** When a static secret is shared across N consumers (the recurring DB-password-shared-by-12-microservices anti-pattern), rotation becomes a distributed-systems problem. Two strategies:

1. **Dual-credential overlap**: issue new credential, deploy to all consumers, verify all consumers have switched, revoke old credential. Requires deployment coordination + verification that no consumer is still on the old credential. The verification step is where most teams fail; they deploy the new credential, observe that everything still works (because the old one is still valid), and never confirm that no consumer is using the old one.
2. **Per-consumer dynamic credentials**: eliminate the shared secret entirely. Each consumer gets its own dynamic credential from Vault's database engine (or equivalent). Rotation is automatic and per-consumer. The work is in the migration, not in the steady state.

Worked dual-overlap rotation procedure for a shared DB password:

```
1. Generate new password at the DB. Both old and new are valid.
2. Update the secrets store with the new password (Vault KV, AWS Secrets Manager).
3. Roll all consumers. Track which consumers have picked up the new password.
4. Wait for any cached old-password connections to expire (connection pools, long-lived sessions).
5. Verify no consumer is using the old password. Read the DB audit log for any auth event using the old password.
6. Revoke the old password at the DB.
7. Verify revocation by attempting auth with the old password.
```

The verification at step 5 is what most teams skip. Without it, you have not completed rotation; you have added a new password. If you find yourself doing dual-credential overlap rotation as a steady-state practice, you have not finished the migration to per-consumer dynamic credentials. Schedule the migration.

**Break-glass credentials.** Emergency credentials that allow administrative access when the normal identity/auth path is broken (Vault is down, IdP is broken, network partition isolates the cluster). Discipline requirements:

- **Sealed envelope.** Physically or cryptographically sealed; using the credential leaves a visible trail (envelope torn open, KMS decrypt logged, alert fires).
- **Multi-party authorization.** Shamir-split or quorum-required (Vault supports both). No single individual holds usable break-glass. The Shamir threshold (k-of-n) is a design parameter: too low (2-of-3) and a small conspiracy or coincidence of laptop-compromise unlocks; too high (5-of-7) and you cannot assemble a quorum in a real outage where some operators are unreachable.
- **Quarterly fire drill.** Tested at known cadence so the credentials are known-good when needed. Rotated after each drill. Tested rotation procedures. The drill must include the physical / out-of-band steps (someone walks to the safe, retrieves the envelope, the shards are entered into the Vault unseal API in the correct order).
- **Audit-loggable.** Every use generates a high-priority alert + investigation ticket. Production break-glass invocation outside a drill should page the security on-call within minutes.
- **Inventory.** A documented, current list of break-glass credentials exists. The list lives somewhere accessible during an outage (not in the system that the credentials unlock).

Break-glass credentials that nobody knows about are the most common form of break-glass: they exist, they decay, they fail in the actual emergency. Run the drill; rotate after the drill; document the inventory; rinse and repeat quarterly.

---

## 10. Detection — secrets in code and in repos

Secrets-in-code is the failure mode of the *commit pipeline*. The discipline assumes secrets will occasionally land in repositories despite best practice; the question is how fast you detect and respond.

**TruffleHog (Dylan Ayrey, originally at Truffle Security).** The canonical OSS tool. Originally Python (v1-v2, from 2016), rewritten in Go (v3, April 2022) as the engine matured into a commercial offering. Entropy-based detection finds high-entropy strings; verifier-based detection validates candidate secrets against the issuing service's API to eliminate false positives (an AWS access key that doesn't authenticate against STS is not actionable). Historical-commit scan walks git history including dangling refs and force-pushed commits still present on the GitHub side. Production deployments scan as a CI gate (pre-receive hook or required PR check) and as a periodic full-history scan; the full-history scan catches credentials committed before TruffleHog was deployed.

TruffleHog's role in offense: The Shai-Hulud worm used TruffleHog as the *post-compromise discovery primitive*. After taking over an npm package and running malicious install scripts in victim CI environments, the worm ran TruffleHog against the local filesystem to harvest credentials it could use for the next propagation hop (`cicd_supply_chain_expertise.md` §10). The defender's tool is the attacker's tool; this is true throughout the discipline. Hardening implication: any host that has a copy of TruffleHog (or any secret-scanner) under attacker control will be used against you. Restrict installation, audit invocation logs, and treat the presence of an unexpected TruffleHog binary as an indicator of compromise.

**GitHub Secret Scanning + Push Protection.** Push protection generally available May 2023 (beta since April 2022). Covers partner-token formats with auto-revocation: GitHub partners with token-issuers (AWS, npm, PyPI, Slack, Stripe, others) to register format regexes; on detection, GitHub notifies the issuer and the issuer revokes the token. Push Protection blocks the push at the git protocol layer for these formats. Coverage is broader than any OSS tool for partner-token formats; coverage is essentially zero for bespoke internal credentials.

**GitLab Secret Detection** — analogous, available in all tiers since GitLab 13.3 (some features Ultimate-only); uses Gitleaks under the hood.

**detect-secrets (Yelp)** — pre-commit-hook-oriented. Plugin architecture for new secret types. Strength: low false-positive rate via the audit workflow.

**Gitleaks (Zachary Rice)** — Go-based, MIT-licensed, easy to embed in CI. Configurable rules engine. The most common drop-in for "scan my repos for secrets" without committing to TruffleHog's heavier dependency footprint.

**Commercial.**

- **GitGuardian** — SaaS that monitors public + private repos, alerts on detected secrets, integrates with the issuing services for revocation. The leading commercial tool by deployment count.
- **Spectral (Check Point)** — Acquired 2022, embedded into Check Point CloudGuard. The right choice for Check Point customers.
- **Aqua Security secrets module** — secrets scanning as part of Aqua's broader cloud-native security platform.

**Honest failure mode.** Detection finds secrets that *look like secrets*. Custom-format internal tokens — your service's bespoke API key format with no public prefix — evade entropy detectors because they look like ordinary base64 or hex strings, and evade regex detectors because nobody has shipped a regex for your format. The defense is to *publish* the regex for your format, contribute it to GitHub's partner program, and make it detectable. The other defense is to issue your bespoke tokens with a prefix that *is* high-entropy and recognizable (`sk_live_`, `myapp_token_`), so detection works.

Detection is necessary, not sufficient. The team that depends on TruffleHog as the perimeter has secrets in their repos that TruffleHog doesn't recognize.

**Runtime detection — beyond the commit gate.** Detecting secrets in code is the commit-time layer. Runtime detection of *secret usage* is the complementary discipline:

- KMS-call-rate anomaly detection on AWS KMS, Cloud KMS, Azure Key Vault. A workload that suddenly issues 100x its baseline Decrypt operations is exfiltrating secrets at full speed.
- Vault audit-log anomaly detection. A Vault token issuing reads against secret paths the role doesn't normally use is a privilege-creep signal or a token-compromise signal.
- Cloud IAM API call anomaly detection. CloudTrail + GuardDuty / Azure Defender for Cloud / GCP Security Command Center for unusual API patterns by identity.
- Token use from anomalous geographies. A GitHub PAT for a US-based engineer suddenly authenticating from a new country is a credential-compromise indicator.

Each of these is a separate detection pipeline. None of them are "secrets detection" in the commit-time sense; they are *use* detection. Cross-link: `detection_engineering_expertise.md` covers the broader runtime-detection discipline including Sigma rule formats for these patterns.

---

## 11. Incident response on credential compromise

Cross-link: `ai_incident_response_playbook_expertise.md` (AI-tool-specific IR), `dfir_methodology_expertise.md` (general DFIR lifecycle).

**Containment-grade vs eradication-grade rotation.** The doc's load-bearing distinction; the parallel to AI-IR §7.

- *Containment-grade rotation*: new credential issued, consumers updated. The old credential is "rotated" at the UI. Sufficient for stopping ongoing operator-controlled use; insufficient if the credential is still valid at the issuing authority. Adversary with the old credential can still authenticate.
- *Eradication-grade rotation*: old credential revoked at the issuing authority. Verified by failed-auth test (§9). The credential cannot be presented anywhere; the only path to re-establish access is through the (post-incident, hardened) provisioning flow.

For any credential-compromise incident, **target eradication-grade**. Containment-grade is acceptable as a fast first action only if eradication-grade verification is queued to follow within minutes-to-hours, not days.

**Per-vendor IR contacts.** Know these before you need them.

- **npm Security** — via `npmjs.com/support`. For supply-chain compromise involving npm packages; can revoke tokens, take down packages, force re-publication. Response SLA varies; engage in parallel with GitHub Security if the package author is a GitHub identity.
- **PyPI Security** — `security@pypi.org`. Similar role for Python ecosystem; can revoke PyPI tokens, yank releases, contact package maintainers.
- **GitHub Security** — HackerOne for vulnerabilities; Trust & Safety for malicious-account reports. For OAuth-app or Personal Access Token compromise, the right path is account-recovery + token-revocation via the user's settings + GitHub Security notification.
- **AWS Security** — `aws-security@amazon.com`. For IAM-credential compromise, the response is typically self-service (rotate keys, audit CloudTrail). For active-attack scenarios, AWS has a Customer Incident Response Team (CIRT) for support customers.
- **Microsoft Security Response Center (MSRC)** — `secure@microsoft.com`. For Azure / Entra ID credential compromise. Microsoft Defender for Cloud has Azure-side detection that may have already noticed.
- **Google Cloud Security** — security report form; Cloud Customer Care for active incidents.

The verification test on revocation is to authenticate with the *old* credential. Use the issuing service's audit-log endpoint or session-list endpoint to confirm the old credential is no longer presented.

**Customer notification.** GDPR Article 33 — the 72-hour clock starts at *awareness* of the breach, not at confirmation, not at root-cause-determination. If customer secrets were potentially exposed (you do not need certainty), the clock is ticking. Coordinate with legal/privacy team; do not wait for forensics to complete. Cross-link: `ai_incident_response_playbook_expertise.md` §6.

**Forensic preservation.** Before rotating, capture the audit trail proving when the secret was active and what it was used for:

- AWS CloudTrail / Azure Activity Log / GCP Cloud Audit Logs for the IAM identity tied to the secret.
- GitHub audit log for OAuth-app / PAT activity.
- Vault audit-log for token-issuance and secret-read events tied to the leased token.
- Application-level logs showing which user-facing operations used the credential.

Rotating *first* and capturing forensics *later* is a common mistake — once you've revoked, you've lost the live signal and you cannot tell whether the adversary was actively using the credential at revocation time. The order is: snapshot, then revoke, with both happening within minutes of each other.

**Worked runbook — credential-compromise incident response.** Adapt to your environment; the structure is invariant.

```
T+0   Triage. Confirm the credential type, the issuing authority, the rough age
      of compromise. Establish whether customer data was potentially exposed.

T+5m  Forensic snapshot. Export the audit log for the affected identity
      from the issuing authority (CloudTrail, GitHub audit log, Vault audit
      log, npm token-activity API). Preserve to a tamper-evident store.

T+10m Containment. Disable the credential at the issuing authority. For
      revocation paths that have lag (some registry APIs cache), also
      change downstream configuration so the credential is no longer
      presented even if revocation is delayed.

T+15m Eradication verification. Attempt to use the old credential against
      the issuing authority's API. Must fail. If it succeeds, escalate to
      the vendor's security team.

T+30m Rotation. Issue replacement credential. Update consumers. Verify
      consumers are using the new credential (not still holding the old
      one in memory or in a config file).

T+1h  Scope assessment. From the audit log, determine: (a) what API calls
      were made with the credential; (b) what data was accessed; (c) what
      writes occurred. Tag any anomalous activity.

T+2h  Customer-notification decision. If customer data was exposed,
      GDPR Art 33 72-hour clock has been ticking since T+0. Engage
      legal/privacy. Begin draft.

T+24h Post-mortem. Why was this credential compromised? Was it the wrong
      credential type (long-lived where short-lived was possible)? Was
      detection delayed? Was rotation rehearsed? Document the failure
      mode and the fix.
```

The runbook is intentionally fast — most credential-compromise incidents close within 24 hours operationally; the customer-notification and post-mortem work continues beyond.

---

## 12. Honest failure modes

The section that will save the next on-call shift the most pain.

**Long-lived static tokens persist by inertia.** Modern teams rotate their OIDC-issued tokens hourly. They forget the IAM-user PAT from 2019 in the production environment. The audit question is not "are we rotating?" — it is "what is our *oldest* active credential, and why does it exist?" If you cannot answer this in five minutes for any environment you own, you have a secrets-management gap. The Snowflake-credential-stuffing incidents of 2024 were not exotic; they were old static credentials harvested from info-stealer logs.

**"We use Vault" ≠ secrets discipline.** Vault is a tool. Long-lived static tokens stored in Vault KV v2 are still long-lived static tokens with a slightly nicer UI in front of them. The operational substance of Vault is the dynamic secrets engines (DB, PKI, AWS/Azure/GCP) and the lease-and-renew lifecycle. A Vault deployment that holds only KV v2 secrets is a filing cabinet with audit logs; it does not move the needle on the underlying risk.

**Vault token-as-secret — the bootstrapping problem.** Vault solves the secret-distribution problem by introducing a new secret: the Vault token. AppRole + Vault Agent + token-renewal is the standard answer, but the root-of-trust still has to come from somewhere — the Kubernetes ServiceAccount JWT (validated by Vault's k8s auth method), the EC2 IMDSv2 identity document (validated by Vault's AWS auth method), the GitHub OIDC token (validated by Vault's JWT auth method). The bootstrapping is not eliminated; it is *moved* to a place where it is cryptographically attested by the runtime (k8s API server, EC2 metadata service, GitHub OIDC issuer). That attestation chain becomes the load-bearing thing to audit.

**KMS-as-keystroke-logger.** Envelope encryption bounds the blast radius of *KEK* exfiltration. It does not bound the blast radius of a compromised application that legitimately holds an IAM role permitted to call KMS Decrypt. The compromised app calls KMS, decrypts every secret in its scope, exfiltrates plaintext. KMS audit logs (CloudTrail KMS events, Azure Activity Log for Key Vault, Cloud Audit Logs for Cloud KMS) will show the volume; anomaly detection on KMS-call rate is the defensive primitive. AWS calls this pattern out in CloudTrail-driven defense doctrine `[unverified specific publication]`.

**Detection drift.** Secret-scanner regex patterns become stale. Token formats change (GitHub re-issued its token format from `XXXX...` to `ghp_...` in 2021). Bespoke internal credential formats are usually never added to the scanners at all. Treat the scanner ruleset as a maintained artifact; pin the version, review the diff on upgrade, regression-test against known-format examples.

**Rotation-without-revocation.** The most common operational failure (§9). Anchored in the Clinejection 6-week Cline window. The corpus shows it happening at every major registry and many enterprise IdPs over the 2020-2026 period. Build the verification test (§9 code snippet) into your rotation runbook; make it a required step, not optional.

**Break-glass credentials that nobody knows about.** Sealed at deploy time, never tested, decayed. The fire drill is the test. Quarterly cadence is a minimum; for credentials critical to recovery from major outages, monthly. Test the entire chain: the safe-opening procedure, the credentials themselves, the systems they are supposed to unlock.

**Shared secrets as anti-pattern.** When 12 services share a single DB password, you have a coordination problem masquerading as a credential problem. The right answer is not "rotate it more often, with overlap" — the right answer is per-service dynamic credentials. If you cannot get there (legacy DB doesn't support per-session users, vendor product requires shared secret), document it as technical debt with a date, not as steady state.

**Service-account sprawl.** Every team creates ten service accounts during onboarding "just in case." Five of them never get used. Three of them get used once and forgotten. Two of them end up doing real work. The five unused ones are credential-compromise surface area. Quarterly audit: any service account with no activity in 90 days gets disabled; any service account disabled for 30 days gets deleted.

**Plaintext secrets in CI logs.** A workflow that prints a credential to stdout — for debugging, for "let me just check it's set correctly" — has now leaked that credential to wherever CI logs are stored. GitHub Actions log retention defaults to 90 days; CI logs are often accessible to a broader audience than the secrets themselves. The defense is library-level: structured logging that knows about secret types and refuses to print them. The retroactive fix once it happens is rotation (eradication-grade) and a post-mortem on the logging gap.

**Secrets in error-tracking systems.** Sentry, Rollbar, Bugsnag, Datadog APM. Application errors that include request payloads, headers, or environment data will eventually capture a credential. Configure scrubbing rules at the SDK level (every modern error-tracking SDK supports them) and audit periodically. Treat the error-tracking backend as a secrets-storage system in disguise.

**Cookies, JWTs, and session tokens as secrets.** Anything that authenticates the bearer is a secret. Session JWTs in browser-side localStorage, OAuth refresh tokens cached in mobile-app keychains, API tokens in `.env` files. These are sometimes excluded from "secrets management" scope on the theory that they are per-user not per-system. They are still credentials; they still need rotation paths and revocation paths. The OAuth refresh-token leak class (the 2022 Heroku-via-OAuth incident, the 2023 CircleCI session-token incident `[unverified exact attribution]`) shows the cost of treating them as out-of-scope.

---

## 13. 2024-2026 currency

**HashiCorp BSL license change (August 2023) + IBM acquisition (closed February 2025).** Vault Enterprise and OSS users have different license obligations from the pre-BSL era. OpenBao OSS fork is the LF-hosted alternative for users who cannot accept BSL terms. The license question is orthogonal to the operational discipline; both Vault and OpenBao implement the same primitives.

**npm Trusted Publishing GA (July 2025).** Eliminates long-lived NPM_TOKEN for OIDC-aware publishing workflows. The single largest hardening of npm against worm-class supply-chain attacks (Shai-Hulud, Mini-Shai-Hulud).

**PyPI Trusted Publishing + PEP 740 attestations.** PyPI rolled out Trusted Publishing in 2023; PEP 740 attestations layered on cryptographic attestation in 2024 (PEP 740 resolved July 2024; PyPI support finalized November 2024). The Python ecosystem's substantive response to supply-chain compromise.

**SLSA L3 + sigstore + npm provenance.** Supply-chain integrity primitives that complement secrets discipline. SLSA Level 3 (build-provenance, signed attestations, isolated build environments), sigstore (Cosign + Fulcio + Rekor) for keyless signing, npm provenance for cryptographic linkage between npm package and source repository. Cross-link: `supply_chain_provenance_expertise.md`.

**AI-agent secrets surface.** The 2025-2026 frontier. MCP server credential storage (servers often request long-lived API tokens), agent-tool-call audit-logging (the call to a tool is itself a secret-bearing operation), Claude API key rotation patterns (Anthropic-issued keys can be scoped per-workspace; rotation is a console operation). The Clinejection incident class lives at this layer. Cross-link: `ai_assisted_coding_tool_security_expertise.md` §13 (Semgrep AI-tool policy worked example) and §14 (devcontainer + settings.json + MCP allowlist).

**EU CRA.** EU Cyber Resilience Act (Regulation 2024/2847) requires secrets-management hygiene for product manufacturers, phased through 2027 with reporting obligations starting earlier. The compliance gradient: at minimum, no default credentials, mandatory rotation paths, vulnerability disclosure with secrets-leak handling.

**Confidential computing intersection.** TEE-isolated secrets handling (`confidential_computing_expertise.md`) is the high-end of the at-rest-and-in-use protection story. Apple Private Cloud Compute uses TEE attestation as the basis for secrets handling at scale. Most teams do not need this; the teams that do are operating at sovereign-cloud / regulated-AI-inference scale.

---

## 14. Worked example — a production-grade k8s secrets stack

A concrete reference deployment. Use as a starting point; adapt to your environment.

**Stack.**

- Kubernetes cluster (EKS / GKE / AKS, or self-hosted with k3s/Talos).
- HashiCorp Vault (or OpenBao) deployed in a dedicated namespace with auto-unseal via cloud KMS (AWS KMS / Cloud KMS / Azure Key Vault).
- Vault Agent Injector (mutating webhook) installed via Helm chart.
- External Secrets Operator (ESO) installed for ingestion from external stores when applicable.
- ArgoCD with the helm-secrets plugin for SOPS-encrypted deployment manifests.
- GitHub Actions for CI/CD, with OIDC trust configured to Vault's JWT auth method.

**Identity flow.**

1. CI runner in GitHub Actions has no long-lived credentials at job start.
2. The workflow's `permissions: id-token: write` instructs GitHub to mint an OIDC token signed by `token.actions.githubusercontent.com`.
3. The workflow calls Vault's JWT auth endpoint, presenting the OIDC token and a Vault role name.
4. Vault validates the OIDC signature against GitHub's public JWKS, validates claims (`repository`, `ref`, `environment`) against the role's bound_claims, and issues a Vault token with the role's policy attached.
5. The workflow uses the Vault token to fetch the credentials it needs (cloud-IAM via Vault's AWS engine, DB credentials via Vault's database engine).
6. Workflow completes; Vault token TTL expires; cloud credentials TTL expires; DB credentials are revoked via lease expiry.

**Workload flow (deployed services).**

1. Application pod is annotated `vault.hashicorp.com/agent-inject: "true"` plus `vault.hashicorp.com/role: "<role-name>"`.
2. Vault Agent Injector mutates the pod spec at admission, adding a Vault Agent sidecar container and a shared `emptyDir` volume.
3. Vault Agent uses the pod's Kubernetes ServiceAccount JWT to authenticate to Vault's k8s auth method.
4. Vault validates the JWT with the cluster's TokenReviewer API, issues a Vault token.
5. Vault Agent renders configured secret templates into files in the shared `emptyDir`. Templates can reference dynamic DB credentials, dynamic cloud-IAM credentials, KV v2 static secrets.
6. Application reads secrets from the shared volume. On secret rotation (DB lease renewal at 2/3 of TTL, etc.), Vault Agent re-renders the file and optionally HUPs the application or restarts it.

**Static-config secrets.**

- Application config that is not dynamic (third-party SaaS API keys, signing keys) is stored in SOPS-encrypted YAML in the GitOps repository.
- SOPS configured with AWS KMS (or GCP/Azure KMS) backend; the cluster has IAM permission to decrypt at apply-time via ArgoCD's helm-secrets plugin.
- Rotation: a CI job rotates the upstream SaaS credential, updates the SOPS-encrypted YAML, opens a PR. Merge triggers ArgoCD reconciliation; the new credential propagates to the cluster.

**Audit + observability.**

- Vault audit log shipped to the SIEM (Splunk / Datadog / OpenSearch). Audit log is mandatory for production Vault; without it you cannot answer "which workload accessed which secret when."
- KMS-call rate anomaly detection on the cloud KMS used for SOPS / Vault auto-unseal.
- GitHub Actions audit log for OIDC token issuance.
- Quarterly review of Vault policies, IAM role trust policies, ServiceAccount-to-role bindings.

**What this stack does NOT solve.**

- The bootstrapping problem at the bottom of the stack: Vault must itself trust *something* (cluster CA for ServiceAccount validation, cloud KMS for auto-unseal). That trust must be operated with care; changing the auto-unseal KMS key requires a seal migration with brief downtime.
- The Vault root-token problem: the initial root token (or recovery shards) must be sealed and treated as break-glass (§9). If you lose them and Vault becomes unrecoverable, you have a Vault-rebuild event with associated downtime.
- Detection of secrets *outside* Vault: developers will still occasionally paste credentials into config maps or environment variables. The detection layer (§10) is the safety net.

---

## 15. Cross-link cluster

This doc is a hub; the substance is in the spokes.

- `cicd_supply_chain_expertise.md` — §7 (OIDC short-lived tokens), §2.9 (Shai-Hulud token harvesting via TruffleHog), §10 (Clinejection 6-week Cline window).
- `cloud_iam_expertise.md` — KMS-as-rotation-authority, AWS 5-policy eval order, IMDSv2, OIDC sub-claim restriction.
- `zero_trust_workload_identity_expertise.md` — SPIFFE/SVID, workload attestation, federated trust.
- `ai_assisted_coding_tool_security_expertise.md` — §6 (MCP threat model), §13 (Semgrep AI-tool policy), §14 (devcontainer worked example).
- `ai_incident_response_playbook_expertise.md` — §3 (containment levers), §6 (GDPR Art 33), §7 (containment-vs-eradication).
- `dfir_methodology_expertise.md` — NIST 800-61 IR lifecycle, audit-log preservation order.
- `cryptography_expertise.md` — KEK/DEK primitives, AES-GCM vs ChaCha20-Poly1305, key derivation.
- `confidential_computing_expertise.md` — TEE-attested secrets, Apple PCC pillars, SGX/TDX/SEV-SNP.
- `post_quantum_cryptography_expertise.md` — §11 PQ migration for key wrapping (ML-KEM hybrid).
- `detection_engineering_expertise.md` — runtime detection of secret-access anomalies (KMS-call rate, Vault token anomaly).
- `supply_chain_provenance_expertise.md` — SLSA L3, sigstore, in-toto, attestation chain.
- `distributed_authz_expertise.md` — the credential is the authentication; authorization is separate.

---

## 16. Operational checklist (for the audit / incident review)

A 12-item checklist for evaluating a real secrets-management deployment:

1. **What is the oldest active credential in production, and why does it exist?** If the answer is older than 12 months and isn't a hardware root-of-trust, that's the first ticket.
2. **For every long-lived secret, who is responsible for rotation, and when was it last rotated?** "Nobody, never" is an audit finding.
3. **Are workload credentials short-lived OIDC where possible?** CI runners, k8s workloads, cloud functions should not hold long-lived secrets.
4. **Is there a verified-revocation test in the rotation runbook?** §9 code snippet. If rotation is not verified at the issuing authority, the runbook is incomplete.
5. **Are shared secrets eliminated where dynamic credentials are possible?** Vault DB engine, AWS RDS IAM auth, Azure Managed Identity for DB.
6. **What is the KMS architecture?** Envelope encryption, BYOK vs HYOK trade-off, HSM tier appropriate to threat model.
7. **Are break-glass credentials documented, sealed, fire-drilled quarterly?** Untested break-glass is not break-glass.
8. **Is secret-scanning enabled at the commit gate AND the historical-scan cadence?** Push Protection + periodic full-history scan + bespoke-format detection.
9. **Is there an IR runbook for credential compromise with per-vendor contact information?** §11. If you have to look up the npm security email during an incident, you've already lost time.
10. **Is forensic preservation ordered correctly relative to rotation?** Snapshot first, rotate within minutes.
11. **Is the OIDC trust policy narrow?** `repo:org/name:ref:refs/heads/main` not `repo:org/name:*`.
12. **Is service-account sprawl audited quarterly?** Unused accounts deleted, decayed accounts disabled.

---

## Closing

Secrets management is an operational discipline that survives or dies on the boring questions.

Are you rotating? Are you *revoking*? Is the audit trail captured before the rotation? Is the OIDC trust policy narrow? Is the oldest credential in production the one nobody remembers?

The exciting questions — vault architecture, BYOK vs HYOK, FIPS 140-3 transition — matter less than the boring ones. The corpus of 2020-2026 incidents bears this out.

The aphorism, repeating from §1: **rotation that isn't verified at the issuing authority is not rotation**. Build the verification test into every rotation runbook. Then build a habit of running it before declaring the incident closed.
