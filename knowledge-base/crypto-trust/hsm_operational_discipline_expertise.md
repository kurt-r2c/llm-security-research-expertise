# HSM Operational Discipline

Operational reference for staff-security-engineers, cryptographers, and compliance-engineers running Hardware Security Modules in regulated production. This is the **operations** layer: ceremonies, officer roles, audit, certification, lifecycle, decommission, vendor administration. Crypto primitives live in `cryptography_expertise.md`. Software-level keystroke / secret-store discipline lives in `secrets_management_discipline_expertise.md`. TEE / SGX / SEV-SNP (CPU-integrated trust) lives in `confidential_computing_expertise.md`. This doc is the **dedicated-hardware-module + human-ceremony** layer that those three touch but do not anchor.

The HSM does one thing well: it makes the private key not-extractable. Everything else — what gets signed, who can sign, when, under what witness, how the operator authenticates, how the device is replaced when it dies — is operational discipline that the hardware does not provide. This doc is about that operational discipline.

---

## §1 Why this doc exists

HSMs occupy a peculiar position in the security stack. They are dedicated, certified, expensive hardware devices whose entire purpose is to hold one or more cryptographic keys in a manner where the keys can be **used** (sign, decrypt, derive, wrap) but cannot be **extracted** in plaintext. The hardware boundary is real: tamper-resistant enclosures with zeroization on intrusion, FIPS-validated hardware random-number generators (NIST SP 800-90A/B/C), and a logical model (PKCS#11 or vendor-equivalent) that gates every operation on authenticated officer state.

The corpus already covers crypto primitives, secrets management, and confidential computing. None of those three docs covers the questions that an operator actually asks at 02:00 when an HSM partition is degraded:

- Who has the smart cards? Are M of them on-call?
- Was this key ever ceremonied? Where is the script?
- If we firmware-update this module, does our FIPS 140-2 L3 validation drop?
- Can we crypto-erase a key in CloudHSM without losing the cluster?
- The CA signed a certificate we didn't ask for — is the HSM compromised?

The hardware does not answer those. The discipline does.

Scope of this doc:

- HSM vendor landscape and the PKCS#11 lingua franca.
- Certification regimes: FIPS 140-2 / 140-3, Common Criteria, PCI HSM.
- The key ceremony: the load-bearing operational ritual that distinguishes a real root-of-trust from a marketing claim.
- Officer roles, M-of-N quorum, smart-card-backed authentication.
- The PKCS#11 API surface as the operator interacts with it.
- Cloud HSM operational realities (AWS / GCP / Azure / IBM) and the trust-handoff to the cloud provider.
- Key lifecycle: generation, backup, rotation, decommissioning, crypto erasure.
- FIPS 140-3 transition (active 2024-2026).
- Post-quantum migration impact on HSM operations (FIPS 203/204/205 finalized Aug 2024).
- Operational anti-patterns and a small incident corpus.
- Honest failure modes.

Out of scope:

- Crypto primitive design (`cryptography_expertise.md`).
- Software-level secret-stores like HashiCorp Vault, AWS Secrets Manager, Doppler (`secrets_management_discipline_expertise.md`).
- TEE / SGX / SEV-SNP (`confidential_computing_expertise.md`).
- PQC algorithm internals (`post_quantum_cryptography_expertise.md`).

---

## §2 HSM vendor landscape

The market is dominated by a handful of vendors with deep PKI / payment / government history. Every production HSM speaks PKCS#11 (RSA Labs → OASIS); many also speak JCE, KSP/CNG (Windows), KMIP, and vendor-proprietary APIs.

**Thales (formerly Gemalto + SafeNet).** Luna Network HSM 7 / Luna PCIe / Luna USB / Luna Cloud HSM. payShield 10K is the banking-specific module (PIN translation, card data encryption, PCI HSM L3). Thales acquired Gemalto in 2019; the Luna product line descends from SafeNet (acquired by Gemalto in 2015); payShield predates the Gemalto deal (Thales announced payShield 9000 in 2009). Long history in WebPKI and EMV payment processing; selected in 2024–2025 to replace the Keyper HSMs used for DNSSEC root-zone KSK (IANA) and ZSK (Verisign) signing.

**Entrust (formerly nCipher).** nShield Connect (network appliance), nShield Solo XC (PCIe), nShield as a Service. Entrust acquired nCipher from Thales in 2019 as a divestiture forced by the Gemalto deal. nShield has a strong presence in code-signing, document-signing, and PKI.

**Atos / Bull.** Trustway Proteccio. French sovereign-cloud and government deployments; common in EU-government and defense contexts.

**Utimaco.** SecurityServer / CryptoServer / u.trust Anchor / u.trust LAN. Acquired Atalla from Micro Focus in 2018; the Atalla NSP (Network Security Processor) is the legacy payment-HSM line.

**AWS.** CloudHSM (Marvell hardware in AWS data centers — `hsm1.medium` is the NITROX III module, CMVP cert #4218 — accessible via PKCS#11 / JCE / KSP from within your VPC). KMS Custom Key Stores (KMS API on top of CloudHSM cluster — managed KMS but with HSM-backed root). AWS Payment Cryptography launched June 2023 — managed payment-HSM service on PCI PTS HSM v3 / FIPS 140-2 L3 hardware for payment workflows.

**GCP.** Cloud HSM (part of Cloud KMS; Marvell LiquidSecurity hardware; FIPS 140-2 L3).

**Azure.** Managed HSM (dedicated single-tenant cluster, FIPS 140-3 L3). Dedicated HSM (Thales Luna 7 in Azure data center). Key Vault Premium (HSM-backed certificates and keys; not a dedicated HSM partition).

**IBM.** Cloud Hyper Protect Crypto Services (FIPS 140-2 L4 `[unverified — IBM is the rare claimant of L4]`). Z-series mainframes ship with on-board Crypto Express adapters supporting CCA, EP11, and PKCS#11. The mainframe HSM lineage is older than the appliance market and is anchored in z/OS environments (cross-link `[[reference-mainframe-legacy-security]]`).

**Oracle.** OCI Vault HSM. Smaller market presence; integrated into OCI for customers running Oracle DB workloads.

**OSS / appliance hybrids.**

- **SoftHSM2** (OpenDNSSEC project) — a software PKCS#11 implementation. Explicitly NOT FIPS-validated. Use for testing and CI; never for production. The PKCS#11 conformance is good enough to develop against.
- **YubiHSM 2** (Yubico) — small USB device, FIPS 140-2 Level 3 validated. PKCS#11 + native libs. Suitable for code-signing, SSH CA, and other low-throughput single-operator use cases; not for high-TPS payment workloads.
- **NitroKey HSM 2** — open-hardware HSM based on the SmartCard-HSM from CardContact. Common Criteria certification on the underlying smartcard; not FIPS 140-2/3 validated as a module.

**PKCS#11 as the lingua franca.** PKCS#11 v2.40 is the most widely deployed version. v3.0 (2020) added EdDSA, SHA3, and AES-XTS. v3.1 followed (Committee Specification 2022, OASIS Standard July 2023). Post-quantum mechanisms (ML-KEM, ML-DSA) arrive in v3.2. Every vendor's library implements PKCS#11 at minimum, often as the recommended primary interface. KMIP (Key Management Interoperability Protocol, OASIS) is a higher-level protocol used between key managers and HSMs but does not replace PKCS#11 for direct cryptographic operations.

---

## §3 Certification regimes

Certification is the language enterprise procurement speaks. Without FIPS, you do not sell to US federal customers. Without Common Criteria, you do not sell to EU government. Without PCI HSM, you do not sell to a card-issuing bank. The certifications matter operationally because they constrain which firmware versions you can run while remaining in a validated state.

### FIPS 140-2 / 140-3 (NIST)

Four levels, ascending in physical and logical assurance:

- **Level 1.** Software crypto module; no physical security beyond commodity enclosure. The minimum bar. A library that's been through CAVP for algorithm testing and CMVP for module testing.
- **Level 2.** Tamper-evident seals; role-based authentication. The seals show evidence of tampering but do not actively respond.
- **Level 3.** Tamper-resistant — zeroization triggered on intrusion. Identity-based authentication (not just role-based). Physical and logical separation between officer roles. **The de facto bar for production HSMs.** If a vendor is selling you a Level 1 or Level 2 device for production key custody, look elsewhere.
- **Level 4.** Envelope-level tamper detection including environmental attack resistance (voltage, temperature, EMI). Rare; specialty markets (defense, intelligence, IBM's Crypto Express claim). The price-performance step from L3 to L4 is steep.

**FIPS 140-3 supersedes FIPS 140-2.** NIST CMVP stopped accepting FIPS 140-2 submissions for new validation certificates on April 1, 2022. Existing FIPS 140-2 validations remain on the CMVP active list through September 21, 2026, after which they move to the historical list. Historical-list modules can still be purchased and operated, but federal procurement that requires "current FIPS validation" will not accept them.

**FIPS 140-3 references ISO/IEC 19790:2012 and ISO/IEC 24759:2017.** Major changes from 140-2: consolidated security requirements (11 areas in 140-3 vs 11 differently-organized in 140-2); non-invasive attack mitigation (side-channel) as a formal requirement area at higher levels; firmware integrity testing required.

**CMVP module states.** Active → Historical → Revoked. Active modules are currently validated. Historical modules were validated under a sunset standard. Revoked modules had their validation withdrawn (rare; usually for security-significant defects).

### Common Criteria (ISO/IEC 15408)

Seven Evaluation Assurance Levels (EAL 1-7). EAL 4 is typical for commercial HSMs. EAL 4+ AVA_VAN.5 + ALC_DVS.2 add vulnerability assessment (AVA_VAN.5 = "advanced methodical vulnerability analysis") and developer-environment security (ALC_DVS.2). The +AVA_VAN.5 augmentation is the hard one — it requires the evaluator to perform penetration testing against documented attack potentials.

**Protection Profiles.** PP for HSMs published by BSI (Germany) and ANSSI (France). PP-Configuration documents define the security target template that vendors evaluate against. EU-CC harmonization (under the EU Cybersecurity Act) is ongoing.

### PCI HSM

Payment Card Industry HSM standard, maintained by PCI SSC. Built on FIPS but adds:

- PIN translation requirements.
- Key block discipline (TR-31 ANSI standard for key transport).
- Dual control requirements (no single operator can perform sensitive operations).
- Specific attack-resistance requirements relevant to payment threat models.

Most production HSMs hold both FIPS 140-2 L3 (or 140-3 L3) AND Common Criteria EAL 4+ AVA_VAN.5 AND PCI HSM v3. Banks require all three. Procurement reads the cert IDs against the CMVP database, the BSI / NIAP CC portal, and the PCI SSC HSM list before signing.

---

## §4 The key ceremony

The key ceremony is the formal, recorded, multi-officer procedure by which a critical key is generated inside an HSM that has never seen another key. It is the load-bearing operational ritual that distinguishes a real root-of-trust from a marketing claim.

### What it is

A key ceremony is the act of bringing a key into existence with sufficient witnesses, sufficient procedural rigor, and sufficient record-keeping that anyone auditing the resulting key two decades later can verify:

- The hardware was authentic at the moment of generation.
- The hardware was in a known-good state (factory reset, firmware integrity verified).
- The randomness used to generate the key came from the HSM's certified RNG, not from an attacker-supplied source.
- The officers who initialized the partition were the people they claimed to be.
- The key shares (M of N) were distributed to officers under chain-of-custody.
- The key has never existed outside the HSM in plaintext.

### The script

Ceremonies follow a written script, prepared in advance, reviewed by all participants, and signed when complete. A typical script:

1. **Pre-ceremony.** Verify physical security of the facility. Audit attendance. Verify the HSM serial number against procurement records. Verify tamper seals intact.
2. **Factory reset.** Reset the HSM to factory defaults. Verify it boots clean. This is the moment the device is known to hold no keys.
3. **Firmware verification.** Confirm firmware version, signature, and configuration. Cross-check against vendor's published firmware hash. A compromised firmware can subvert the entire ceremony.
4. **Partition initialization under quorum.** Initialize the partition with M-of-N officer quorum. Each officer authenticates with their smart card and PIN. Set the partition policy: which mechanisms are allowed, which attributes are mandatory, what's the cloning/wrapping policy.
5. **Key generation.** Generate the key under the hardware RNG. Confirm that `CKA_EXTRACTABLE = FALSE` and `CKA_SENSITIVE = TRUE` on the private key object. Capture the public key.
6. **Backup.** Wrap the key (or split key shares) to smart cards distributed across officers. Sign a backup manifest.
7. **Attestation.** Sign an attestation of the ceremony with the HSM's internal device key (where supported). Capture the attestation in the ceremony record.
8. **Post-ceremony.** Seal the device. Log chain-of-custody to vault. Officers and witnesses sign the final ceremony record. Video recording is sealed and archived.

### Witnessing roles

- **Crypto Officer (CO).** Authenticates the operational use of the HSM. May initialize keys. Typically multiple COs forming the quorum.
- **Security Officer (SO).** Higher privilege than CO; can re-initialize the partition, change officer credentials, modify policy. Quorum-protected.
- **Auditor.** Observes but does not perform. Validates the script is followed. Signs the record.
- **Ceremony Master.** Runs the script. Often a senior cryptographer or operations lead.

**Role separation.** No single individual holds enough authority to extract or use a key on their own. The M-of-N quorum enforces this cryptographically; the witness structure enforces it procedurally.

### Web Trust audit anchor

Under WebTrust, an auditor witnesses a root CA's key generation ceremony and issues a Root Key Generation Ceremony report. Let's Encrypt announced its 2015 ISRG Root X1 key ceremony publicly and created ISRG Root X2 in September 2020. The discipline survives outside WebPKI in banking, government, and high-assurance code-signing.

Reading a published ceremony script is the best way to internalize what a key ceremony actually looks like. Let's Encrypt's `ceremony-demos` repository (github.com/letsencrypt/ceremony-demos) publishes config files nearly identical to those used in its root and intermediate ceremonies.

### Anti-patterns

- **Unwitnessed ceremonies.** "We'll just generate it quickly and document later." The result is a key that no one can attest to.
- **Ceremonies in non-secure facility.** Performing a root-CA ceremony in a normal office. Real ceremonies happen in a SCIF or equivalent secured facility with controlled access and no recording devices other than the official one.
- **M = 1 quorum.** A single officer can extract or use the key. The whole point of the quorum is lost.
- **Insufficient key-share custody.** Key shares stored on the same physical media, in the same building, by the same operator. The quorum is nominal but the practical security is single-point-of-failure.
- **Script invented during the ceremony.** Improvising the steps in real time. The script must be reviewed and approved before the ceremony begins.
- **Officers who don't understand what they're signing.** Officers who treat the ceremony as a procedural box-check without understanding the cryptographic claims they are attesting to.

---

## §5 Officer roles and quorum

### M-of-N share splits

The standard quorum is **M-of-N share split**: the key (or the authentication required to operate the key) is split into N shares, and M of them must be combined to perform a sensitive operation. The split is typically Shamir's Secret Sharing (Adi Shamir, 1979) in HSM-vendor implementations, or a vendor-proprietary equivalent.

Typical thresholds:

- **Root CA private key:** 3-of-5 or 5-of-7. Sometimes higher (5-of-9 has been used for top-tier roots).
- **Subordinate CA / service-tier signing key:** 2-of-3 or 3-of-5.
- **Service-tier operational keys:** 2-of-3 or even 1-of-1 with strict access control (preferring software automation for high-throughput operations).

The threshold should be high enough that no single individual — including the CISO, the CEO, or a compromised insider with administrative access — can extract or operate the key. The threshold should be low enough that operational ceremonies can be assembled without invoking emergency procedures.

### Role separation in PKCS#11 and vendor extensions

PKCS#11 defines two login states: **User** and **SO (Security Officer)**. The User state covers operational cryptographic use. The SO state covers administrative changes to the token. FIPS 140-3 Level 3 requires identity-based authentication (not just role-based), so vendors layer their own identity model on top.

Vendor implementations extend this:

- **Thales Luna:** Crypto Officer, Crypto User, Auditor, Partition Security Officer.
- **Entrust nShield:** Administrator Card Set (ACS), Operator Card Set (OCS). The ACS manages the security world; the OCS authenticates operational use.
- **AWS CloudHSM:** Crypto Officer (CO), Crypto User (CU), Pre-Crypto Officer (PCO), Appliance User (AU).
- **Azure Managed HSM:** RBAC-mapped roles (Managed HSM Crypto Officer, Crypto User, etc.).

### Smart-card backed officer authentication

The HSM officer is the human + smart card + PIN combination, not just a username + password. The smart card holds the officer's identity credential (often a private key with the matching public key registered to the HSM). Authentication is multi-factor by construction: something the officer has (the card), something the officer knows (the PIN), and something the officer is (in highly assured deployments, biometric attestation).

The smart card itself is a small HSM. Compromise of the smart card's PIN does not extract the credential; the smart card enforces the PIN attempt limit and locks on excessive failures.

### Quorum attack threat models

- **Insider collusion.** M officers collaborate to extract or misuse the key. Defense: pick M and N such that the collusion cost is high; select officers across geographies, teams, and management chains; rotate officers; mandate vacations and key-share inventory checks.
- **Social engineering at scale.** M officers tricked separately (one at a time, in unrelated conversations) into authorizing operations that, when combined, constitute key abuse. Defense: signed operation requests; out-of-band confirmation; mandatory wait periods between authorizations.
- **Smart-card supply chain compromise.** The smart-card manufacturer ships cards with weak randomness or backdoors. Defense: source smart cards from multiple vendors; perform entropy testing on issued cards; cross-link `[[reference-supply-chain-provenance]]`.
- **Physical coercion of M officers.** Defense: geographic dispersion; duress codes; "panic" PINs that authenticate but flag the operation as compromised.

---

## §6 PKCS#11 API surface

PKCS#11 is the de facto standard API for cryptographic tokens, including HSMs. Every production HSM ships a PKCS#11 library (often a `.so` or `.dll`) that applications link against.

### Model

- **Slot.** A physical or logical interface to a token. An HSM appliance may expose many slots.
- **Token.** The cryptographic device behind a slot. Has a label, serial number, manufacturer.
- **Session.** A connection from the application to the token. Sessions have a state: not-logged-in, logged-in as User, logged-in as SO.
- **Object.** A typed item inside the token: private key, public key, secret key, certificate, data object.

### Login states

Operations are gated on login state. `C_GenerateKeyPair` requires User login. `C_InitToken` takes the SO PIN as an argument and fails with `CKR_SESSION_EXISTS` if any session is open on the token; re-initializing an already-initialized token checks the supplied PIN against the current SO PIN and wipes the token. `C_Login` transitions the session into the requested state if the PIN (or smart-card challenge) succeeds.

### Object templates

Every object has a template — an attribute list defining its properties. Critical attributes for private keys:

- **`CKA_PRIVATE = TRUE`.** Object is private (visible only after authentication).
- **`CKA_SENSITIVE = TRUE`.** Object's value cannot be revealed in plaintext, even to authenticated callers. **Always set on private keys.**
- **`CKA_EXTRACTABLE = FALSE`.** Object cannot be exported, even wrapped, unless the policy allows wrapped export. **The all-time anti-pattern is setting `CKA_EXTRACTABLE = TRUE` on a private key.** The key should never leave the HSM in any form an attacker can convert to plaintext.
- **`CKA_WRAP = TRUE`.** Object can wrap other keys (i.e., it's a KEK).
- **`CKA_UNWRAP = TRUE`.** Object can unwrap other keys.
- **`CKA_DERIVE = TRUE`.** Object can be used in a key-derivation operation.
- **`CKA_TOKEN = TRUE`.** Object is persistent across sessions (stored in the token). If `FALSE`, the object exists only for the lifetime of the session.

### Wrapping discipline

Keys leave the HSM only **wrapped** under a separate Key Encryption Key (KEK). The wrap mechanism must be authenticated:

- **AES-KW** (RFC 3394) — older, deterministic, integrity-protected.
- **AES-KWP** (RFC 5649) — AES-KW with padding for arbitrary-length keys.
- **AES-GCM** — authenticated encryption; mind the IV uniqueness requirement.

Wrapping with bare AES-CBC or AES-ECB without authentication is broken; the wrapped key can be malleated.

### Operational primitives

- **`C_GenerateKeyPair`** — generate a new asymmetric key pair under the hardware RNG.
- **`C_GenerateKey`** — generate a symmetric key.
- **`C_Sign` / `C_Verify`** — sign / verify with stored keys.
- **`C_Encrypt` / `C_Decrypt`** — encrypt / decrypt with stored keys.
- **`C_WrapKey` / `C_UnwrapKey`** — export / import keys wrapped under a KEK.
- **`C_DeriveKey`** — derive a child key (e.g., ECDH shared secret, HKDF).
- **`C_Digest`** — hash. (HSMs are usually inefficient hash engines; software is faster.)

### PKCS#11 v3.0 additions (2020)

EdDSA (Ed25519, Ed448), SHA3, AES-XTS. Post-quantum mechanisms (ML-KEM, ML-DSA) arrive in PKCS#11 v3.2.

### Tooling

- **OpenDNSSEC** — DNSSEC signer that uses PKCS#11 to talk to HSMs holding zone keys.
- **OpenSSL `pkcs11` engine / `pkcs11-provider`** — OpenSSL backend to PKCS#11. The engine API is deprecated in OpenSSL 3.0+; the provider API replaces it.
- **libp11** — OpenSC's PKCS#11 wrapper library.
- **p11tool** — GnuTLS CLI for PKCS#11 administration.
- **pkcs11-tool** — OpenSC CLI; the operator's swiss-army knife for poking at HSMs.
- **AWS CloudHSM CLI / Client SDK** — vendor-specific tools for AWS CloudHSM.
- **Azure Key Vault / Managed HSM REST API** — Key Vault and Managed HSM expose a REST API; Managed HSM's only PKCS#11 surface is a limited TLS Offload library (PKCS#11 v2.40 subset, F5 and Nginx only). Azure Cloud HSM, a separate service, does expose PKCS#11. The operational model is different.

---

## §7 Cloud HSM operational realities

The cloud HSM is hardware in someone else's data center. The cloud provider operates the physical HSM, the facility, and the firmware update cadence. You operate the partition, the keys, and the policy. This trust-handoff is the load-bearing claim.

### AWS CloudHSM

Runs inside your VPC. Accessible via PKCS#11, JCE, KSP/CNG. Officer roles: Crypto Officer (CO), Crypto User (CU), Pre-Crypto Officer (PCO, used during cluster initialization), Appliance User (AU). You manage the partition contents and cluster membership; AWS manages the hardware and firmware. The cluster is multi-AZ for availability; key material syncs across cluster members.

Backups: AWS CloudHSM backups are stored in a service-controlled Amazon S3 bucket in the cluster's region. The HSM encrypts all data before it leaves the HSM, and AWS states it cannot decrypt backups because it lacks access to the decryption key. Verify the threat model before relying on cloud-HSM backups for high-assurance keys.

### AWS KMS Custom Key Stores

A KMS API surface on top of a CloudHSM cluster. The application calls `KMS.Encrypt` / `KMS.Decrypt`, KMS routes the operation to the CloudHSM cluster, the CloudHSM cluster performs the cryptographic operation. The "managed KMS but with HSM-backed root" pattern. Operationally cheaper than running CloudHSM directly (KMS handles the SDK / IAM / audit-log integration); operationally more expensive than vanilla KMS (CloudHSM cluster cost).

### GCP Cloud HSM

Part of Google Cloud KMS. FIPS 140-2 L3 (and FIPS 140-3 L3 in progress / available depending on region `[unverified specifics]`). Key generation happens in the HSM; the cleartext key never exists outside. The customer uses the Cloud KMS API (gRPC / REST); Google also ships an open-source PKCS#11 library (`libkmsp11`) that maps PKCS#11 calls onto Cloud KMS. The operational model is "you trust Google's HSM operations" — there's less direct visibility than with AWS CloudHSM.

### Azure Managed HSM

Dedicated single-tenant HSM cluster. FIPS 140-3 L3. Multiple HSM partitions per customer. RBAC for management plane (Azure AD identities); local RBAC ("data plane RBAC") for key operations. Granting control-plane access does not grant data-plane access — verify a Managed HSM local RBAC assignment exists before assuming a permission grant has taken effect.

### Azure Dedicated HSM

Thales Luna 7 deployed into Azure. You SSH to the HSM and run Thales tooling directly. More familiar to operators with on-prem HSM experience; less integrated with Azure-native services.

### AWS Payment Cryptography

Managed payment-HSM service on PCI PTS HSM v3 / FIPS 140-2 L3 hardware (launched June 2023). PIN translation, card-validation-value generation, card-data encryption. Eliminates the operational burden of running a banking HSM fleet for AWS payment customers.

### The audit-log gap

Cloud HSM audit logging is incomplete relative to on-prem HSM logs in several ways:

- The cloud provider's underlying hardware events may not be exposed to the customer.
- Officer-level events may be logged but not at the granularity an audit demands.
- The audit logs are written to the cloud provider's logging system (CloudWatch, Cloud Logging, Azure Monitor), which is itself a trust domain.

Operational practice: pull HSM audit logs into your SIEM, parse for officer-action events, and write alerts for "operations that should never happen" (e.g., key wrap with a non-approved KEK, partition policy change outside maintenance window).

### Cryptographic erasure as deletion

Cloud HSMs (and modern KMS systems) offer cryptographic erasure as a deletion primitive: destroy the KEK that wraps the DEK and the DEK becomes unrecoverable. This is faster than physical-media destruction and is the only practical "delete this customer's data forever" mechanism at cloud scale. Verify that the destruction is irreversible — some cloud providers offer a grace period during which destruction can be undone, which is operationally useful but is not "destruction" in the audit sense.

---

## §8 Key lifecycle in production

Keys have lifecycles. Operators manage them.

### Generation

- **Critical keys (root CA, code-signing root, master KEK):** under formal ceremony per §4.
- **Service-tier keys:** automated generation through the HSM API, with policy attached at generation time (`CKA_EXTRACTABLE = FALSE`, allowed mechanisms, usage counters).
- **Ephemeral keys:** session-scoped (`CKA_TOKEN = FALSE`); never persisted.

### Backup

- **Critical keys:** key-share backup to smart cards distributed across officers under chain-of-custody. The smart cards themselves are kept in geographically dispersed safes.
- **Service-tier keys:** vendor-specific backup mechanisms (cluster replication in CloudHSM, key transfer to a secondary HSM in on-prem deployments).
- **Cloud HSM backups:** consult the threat model. AWS CloudHSM backs up to an AWS-managed location encrypted under cluster-tied material. Azure Managed HSM offers Backup / Restore to customer-controlled storage with key wrapping. GCP Cloud KMS lifecycle is integrated; explicit backup is less surfaced.

### Rotation

- **TLS server certificates:** 90 days (Let's Encrypt convention); HSMs need not be involved in rotation if private keys are software-held, but for high-value endpoints (financial APIs, root domains) HSM-backed keys with regular rotation are standard.
- **Code-signing keys:** rotated per signing campaign or per release window. Often long-lived (years) due to operational friction; the trade-off is that a long-lived signing key is a high-value target.
- **Root CA keys:** 5-25 year validity. Rotation is a multi-year project: new root must be issued, distributed, trusted; old root cross-signs new root during transition.
- **PQC migration forces rotation regardless** — see §10.

### Decommissioning

- **Zeroize the key in HSM.** Using the vendor's destroy mechanism (e.g., `C_DestroyObject` in PKCS#11). Confirm with the HSM that the object is gone.
- **Document destruction.** Sign a destruction record including timestamp, officer attestation, HSM serial, key ID.
- **Publish revocation.** For PKI keys, publish CRL / OCSP revocation. For code-signing keys, publish a deprecation notice.
- **Archive public-key material.** Even after the private key is destroyed, the public key is needed for verification of historical signatures.

### Crypto erasure

Destroy the KEK that wraps the DEK; the DEK becomes unrecoverable. The classical pattern for envelope-encrypted data stores: data is encrypted under DEK, DEK is encrypted under KEK, KEK lives in HSM. Destroy KEK → all data encrypted under any DEK wrapped by that KEK is cryptographically erased.

The semantic gap with physical destruction: crypto erasure depends on the soundness of the encryption. If a future cryptographic break (or a leaked DEK from before erasure) is available, the erasure is undone. For long-retention regulatory regimes (some healthcare data), this matters.

### HSM hardware refresh

Vendor lifecycles drive scheduled migration. A typical HSM has a 5-10 year hardware lifespan; vendor end-of-support drives the upgrade cadence. The FIPS 140-2 → 140-3 transition is a current driving force across the industry (§9).

Migration shape:

1. New HSM is procured, ceremonied, brought online in parallel with the old.
2. Keys are migrated under wrap: the new HSM generates a transport KEK, old HSM wraps target keys under that KEK, new HSM unwraps and stores.
3. Applications are cut over to the new HSM.
4. Old HSM is decommissioned: keys zeroized, device wiped, physical destruction or vendor return.

Some key types do not migrate — keys generated `CKA_EXTRACTABLE = FALSE` cannot be transferred. New keys must be generated; the cryptographic identity changes. For root keys, this is by design: you don't migrate a root key, you ceremony a new one.

---

## §9 The FIPS 140-3 transition (2024-2026)

NIST CMVP transitioned new module submissions from FIPS 140-2 to FIPS 140-3 in 2022; the active-validation transition window for existing 140-2 modules runs through September 21, 2026.

### What changed in 140-3

- References ISO/IEC 19790:2012 + ISO/IEC 24759:2017 rather than the in-house FIPS 140-2 spec text.
- Non-invasive attack mitigation (side-channel) requirements formalized at higher levels.
- Firmware integrity testing required at the module boundary.
- Self-tests at startup and on-demand.
- New requirements around sensitive security parameter (SSP) generation and entry/exit.

### Vendor transition status

Most major vendors had FIPS 140-3 L3 validations either complete or in queue by mid-2026 `[unverified per-vendor specifics — Thales Luna 7 has 140-3 L3; nShield 5 has 140-3 L3; Azure Managed HSM has 140-3 L3 claim; AWS CloudHSM transition timeline varies]`. Check the CMVP website for current per-module status.

### Operational implications

- An enterprise running FIPS 140-2 L3 modules may need vendor-side firmware updates OR module replacement to maintain a current FIPS-validated posture once 140-2 validations move to historical.
- Plan FIPS 140-3 migration as a multi-year project for any non-trivial HSM fleet.
- Procurement contracts often specify "current FIPS validation" — once 140-2 moves to historical, contracts auto-trigger replacement obligations. Read the contracts.
- Federal customers under FISMA / FedRAMP require current validation. Commercial customers under SOC 2 may accept historical validations during transition.

---

## §10 PQC migration impact on HSM operations

NIST finalized FIPS 203 (ML-KEM, lattice-based KEM), FIPS 204 (ML-DSA, lattice-based signature), and FIPS 205 (SLH-DSA, stateless hash-based signature) in August 2024. Cross-link `[[reference-post-quantum-cryptography]]` and `[[reference-pqc-migration-playbook]]` for the algorithm-side and migration-strategy details.

### HSM-specific PQ implications

- **Vendor firmware updates required.** HSMs need new firmware to support ML-KEM / ML-DSA / SLH-DSA with hardware-accelerated implementations. Firmware updates may invalidate existing FIPS validations; check CMVP transitions before applying.
- **Algorithm selection by use case:**
  - **Code-signing CA / long-validity signing:** SLH-DSA is the conservative choice. It uses only hash-based crypto (no lattice assumption), so it survives even a future break of lattice problems. Signatures are large (~8KB to ~50KB depending on parameter set); signing is slow; verification is fast. Acceptable for code-signing where the signature is generated rarely and verified often.
  - **TLS server certificates / high-throughput signing:** ML-DSA. Faster than SLH-DSA, signature sizes ~2-5KB. Lattice-based; depends on the hardness of Module-LWE.
  - **KEM for hybrid TLS:** ML-KEM (X25519MLKEM768 is the deployed hybrid in 2025-2026 Chrome / Firefox).
- **Hybrid signatures.** ML-DSA + ECDSA combined into a single signature, verified separately. The verifier checks both; either failing invalidates the signature. HSM must support both algorithms and the hybrid composition. Most major vendors have announced hybrid support; check specific implementations.
- **Root CA private keys.** The hardest problem. Root CAs are usually generated under ceremony with 20+ year validity expectations. PQC transition forces re-ceremony and a new chain of trust. Plan the new-root ceremony years in advance.

### Stateful hash-based signatures (LMS / XMSS)

NIST SP 800-208 covers stateful hash-based signatures: LMS (RFC 8554) and XMSS (RFC 8391). These are alternatives to SLH-DSA for hash-only crypto, with smaller signatures but **state management between signatures**:

- Each signature consumes a one-time signing key from a Merkle tree.
- The state (the index of the next unused one-time key) MUST be incremented atomically with signature emission.
- A state reset — signing two different messages under the same one-time key — completely breaks the signature scheme.

State management is the operational risk. HSMs handling LMS/XMSS must:

- Persist the state inside the HSM with atomic update.
- Not allow backup-restore that resets the state.
- Detect cluster replication that would cause two HSMs to sign with the same state.

Most HSM operators have never handled LMS/XMSS. The class is gaining adoption for firmware signing (some HSM vendors support LMS/XMSS for code-signing). Treat it as a specialty operation requiring vendor support and rigorous procedure.

---

## §11 Operational anti-patterns and incident corpus

### Anti-patterns

- **Bypassing the HSM "for convenience."** Keys exported in plaintext to "test" then re-imported. The most common operational failure. Once a key has been outside the HSM, it cannot be brought back to non-extractable; you must rotate to a new key generated in-HSM.
- **Reuse of partition / slot ID across environments.** Dev partition accessible from prod application due to misconfigured network ACLs or IAM. Cross-link `[[reference-cloud-iam]]`. Dev and prod should be different HSM clusters or at minimum different partitions with no cross-IAM.
- **Ceremony skipped because "we'll do a proper ceremony later."** Never happens. The key is now perpetually under-witnessed. If you cannot do a real ceremony, do not generate the key; postpone the project.
- **Vendor-default officer credentials not rotated.** Default-creds anti-pattern shows up even at FIPS 140-3 L3 modules. The vendor ships with a documented default; you change it on first use. Verify with an audit script.
- **Backup tokens lost OR officer departures without quorum re-establishment.** The M-of-N quorum erodes over time as officers leave or lose smart cards. Without periodic re-establishment, a 5-of-7 degrades silently to 5-of-5 and then to 5-of-4, at which point you cannot perform M-of-N. Audit quorum membership quarterly.
- **TPM-as-HSM-equivalent confusion.** TPM (Trusted Platform Module) is a different hardware class with a different threat model: single key store integrated into the host platform, OS-level integration, optimized for host attestation and key sealing. TPMs are useful for what they do (boot integrity, sealing user keys to a specific machine) but they are not HSMs. Cross-link `[[reference-confidential-computing]]` §3.
- **Cloud HSM CO-role exposed via federated IAM to workforce IdP.** The cloud HSM CO must NOT be a federated identity from a workforce identity provider that could be compromised. The compromise of the IdP becomes the compromise of the HSM. Cross-link `[[reference-zero-trust-workload-identity]]`. CO authentication should require additional factors (smart card, hardware token) beyond federated SSO.
- **Audit logs written but not reviewed.** Volume + non-human-readable format + dependency on vendor tooling means audit logs accumulate untouched. Build the review pipeline: parse logs into structured records, ship to SIEM, write alerts for anomalies.
- **Application calls the HSM signing API without rate limiting.** A compromised application can sign anything the HSM is configured to sign, at the HSM's full throughput, until detected. Apply rate limits at the application layer; alert on rate anomalies.

### Incident corpus

- **Microsoft Storm-0558 (May 2023).** Microsoft consumer MSA signing key escaped its intended HSM tier and was used by a state-affiliated actor (Storm-0558, China-nexus) to forge access tokens for enterprise email accounts. Microsoft's post-incident analysis cited a series of failures including a crash dump that retained signing key material in memory, a debugging environment with reduced isolation, and key-validation logic that did not enforce the audience-scope of the consumer key. Anchor for "key-signing-authority-as-keys-to-kingdom" cross-link `[[reference-session-management]]` §11. The HSM containment failure is the load-bearing detail `[unverified specific HSM tier vs key-cache tier — Microsoft's public writeup focuses on the crash-dump path]`.
- **Mt. Gox (2014).** Bitcoin exchange keys held in cold storage of varying quality, not HSM-backed. Anchor for "HSM is not magic, but it is better than the alternative." When the exchange went insolvent, customer Bitcoin was missing; investigation suggests poor key custody contributed.
- **DigiNotar (2011).** Dutch certificate authority compromised; attacker (suspected Iranian state) issued fraudulent certificates for Google, Microsoft, Mozilla, and others. DigiNotar held an HSM; the HSM was not the failure point. The CA software had been compromised, and the compromised software made signing calls to the HSM. The HSM happily signed because that's its job. Anchor for "HSM defends key extraction; HSM does NOT defend against signing-API misuse." The CA was driven out of business; root trust was withdrawn by all major browsers.
- **Bybit (Feb 2025)** — exchange lost ~$1.4B in ETH to a Lazarus-attributed wallet exploit. Multi-sig signing process compromised at the UI / approval layer, not the HSM layer. Reinforces "the signing-API surface is the attack surface."
- **CrowdStrike Falcon channel-file incident (July 2024)** — not an HSM incident but an example of "code-signed update from a trusted vendor brings down 8.5M Windows hosts." The HSM signed what it was asked to sign. The discipline at the application / release-engineering layer is where the failure lived.

---

## §12 2024-2026 currency

- **FIPS 140-3 transition timeline** as documented in §9. CMVP last-accept date for 140-2 has passed; 140-2 certificates moved to the Historical list on 21 September 2026.
- **PQC algorithm integration** as documented in §10. FIPS 203 / 204 / 205 finalized August 2024. Vendor firmware updates rolling out 2024-2026.
- **AWS Payment Cryptography GA June 2023**. Managed service on PCI PTS HSM V3 / FIPS 140-2 Level 3 certified hardware for payment workflows.
- **Azure Managed HSM FIPS 140-3 L3 validation** `[unverified specific validation ID and date]`.
- **Thales product portfolio.** Thales acquired Imperva in late 2023 (data-security product line, distinct from HSM but adjacent). Luna 7 and payShield 10K remain the flagship HSM lines. `[unverified specific Thales-Imperva integration details]`.
- **Entrust acquisitions.** Entrust acquired Onfido in 2024 (identity verification / KYC), expanding from PKI / HSM into identity verification (completed April 2024).
- **EU Cybersecurity Act + Cyber Resilience Act (Reg 2024/2847).** Products handling secrets / signatures now have certified-component requirements under EU regulation. Cross-link `[[reference-supply-chain-provenance]]` for SBOM requirements; HSM vendors are themselves in scope.
- **Cloud-native HSM consumption growing.** Azure Managed HSM + AWS CloudHSM + GCP Cloud HSM as the cloud-native pattern for enterprises that don't want to operate physical HSMs. Maturity is uneven; verify per-region availability and per-feature parity before committing.
- **PCI DSS 4.0 (mandatory March 2025).** Increased requirements around cryptographic key management; HSM-backed key custody for stored cardholder data is increasingly expected even outside the strict PCI HSM domain.

---

## §13 Honest failure modes

These are the failure modes that no certification rules out. Load-bearing because they will bite an operator who hasn't internalized them.

- **HSM defends key extraction; HSM does NOT defend against signing-API misuse.** DigiNotar 2011 anchor. If your CA software, your code-signing pipeline, or your application that calls the HSM is compromised, the HSM will sign whatever the compromised software sends it. The HSM is one defense layer; application-level signing controls (request validation, rate limiting, human approval for high-value signatures) are the other.

- **Ceremony discipline rots without periodic exercise.** Officers forget the script. Smart cards get misplaced. Backup procedures go untested. Train officers annually. Rotate keys per policy. Conduct mock ceremonies. The discipline is a muscle that atrophies without exercise.

- **FIPS 140-3 L3 is the minimum bar for production, not the maximum security claim.** Validation is point-in-time at a specific firmware version. Firmware updates may move the module to a different validation (or out of validation entirely until re-evaluated). Lifecycle management — not the cert ID on the box — is the operational discipline that matters.

- **Cloud HSMs require trust in the cloud provider's physical-access controls.** "We own the keys" is partially true: you own the cryptographic material; the cloud provider owns physical access to the device. If the cloud provider's data center operations are compromised, your HSM is potentially in scope. This is not a reason to avoid cloud HSMs (the alternative is hiring your own data-center operators, which most enterprises do worse than AWS). It is a reason to acknowledge the trust boundary honestly.

- **PQC migration on long-lived signing keys is a multi-year project.** Root CA keys are usually generated under ceremonies intended to last 20+ years. PQC transition forces re-ceremony and a new chain of trust. Plan now; the work begins years before the first PQC-signed certificate is issued.

- **Stateful hash-based signatures (LMS / XMSS) are operationally dangerous.** State-reset compromises security catastrophically. Most HSM operators have never handled this class. If LMS / XMSS appears in your roadmap, treat it as a specialty workload requiring vendor support, restricted operator training, and rigorous procedure.

- **Quorum erosion over time is the silent failure.** Officers leave. Smart cards lost. Backups not refreshed. Without periodic re-establishment, M-of-N degrades to M-of-fewer over a few years. Audit quorum membership quarterly. Run a quorum-restoration ceremony when officer count drops below safe margin.

- **HSM audit logs may not be reviewable in practice.** Volume + non-human-readable format + dependency on vendor tooling means audit logs are written but rarely reviewed. Build the review pipeline. Parse into structured records. Ship to SIEM. Alert on anomalies. Cross-link `[[reference-detection-engineering]]`.

- **"BYOK" vs "HYOK" semantic confusion.** Both terms describe customer-controlled keys. **HYOK (Hold Your Own Key)** actually places the KEK outside the cloud — the cloud provider never sees the KEK in any form. **BYOK (Bring Your Own Key)** typically just changes the provisioning ceremony — the customer generates the key and imports it, but the key now lives in the cloud provider's HSM. Cloud HSM marketing conflates them. Read the architecture diagram, not the marketing brochure.

- **The signing-API surface is the attack surface.** Once authenticated to the HSM, the API is bounded only by the policy attached to the key and the API's verification of the request. The HSM does not know whether the requester is a legitimate application or a compromised one. Verify signing requests at the application layer: validate the request content, enforce per-application rate limits, require human approval for high-value signatures, alert on anomalies.

- **Cross-tenancy assumptions in cloud HSM.** AWS CloudHSM and Azure Managed HSM are single-tenant (your cluster, your HSM). Azure Key Vault Premium is HSM-backed but the HSM is shared across tenants with logical separation. GCP Cloud HSM is multi-tenant by default; Google also offers a Single-tenant Cloud HSM option. The threat model differs: in single-tenant, you trust the cloud provider; in multi-tenant, you trust the cloud provider plus the logical-separation implementation. Verify the tenancy model of the specific service before assuming.

- **HSM clock drift and key validity.** Some HSMs maintain internal clocks used for key validity periods. Clock drift, NTP failure, or replay of an old clock-reference can extend validity beyond intended. Audit clock-sync procedures and reject HSM-asserted timestamps in favor of an external trusted time source for high-value operations.

- **Smart cards are HSMs too — and they have lifecycle issues.** Smart cards holding officer credentials wear out. Vendor support ends. New card hardware may require ceremony to re-bind officers. Track smart card lifecycle alongside HSM lifecycle.

---

## §14 Cross-link cluster

Operationally adjacent docs in the corpus:

- `[[reference-cryptography]]` — crypto primitives that the HSM implements. The companion theory doc.
- `[[reference-secrets-management-discipline]]` — software-level secrets stores; KMS / Vault / secrets-broker patterns. The software complement to this hardware doc.
- `[[reference-post-quantum-cryptography]]` — FIPS 203/204/205 algorithm internals. Read for the PQ primitives this doc references.
- `[[reference-pqc-migration-playbook]]` — operational migration plan for PQ; the HSM-vendor coordination section connects directly to §10 here.
- `[[reference-confidential-computing]]` — TEE / SGX / SEV-SNP / Apple PCC. CPU-integrated trust; complementary to HSM dedicated-hardware trust.
- `[[reference-zero-trust-workload-identity]]` — workload identity; how applications authenticate to HSMs. Critical for the cloud-HSM CO-role gating discussed in §11.
- `[[reference-cloud-iam]]` — AWS / GCP / Azure IAM; the policy layer that gates cloud-HSM access.
- `[[reference-session-management]]` — token-signing-key lifecycle; the Storm-0558 anchor cross-links here for the consumer-MSA / enterprise-token boundary.
- `[[reference-dfir-methodology]]` — IR lifecycle; HSM-incident response sits inside the broader IR framework.
- `[[reference-threat-modeling-discipline]]` — threat models for key-custody systems; the M-of-N quorum design connects to threat-modeling on insider risk.
- `[[reference-supply-chain-provenance]]` — SLSA / sigstore / SBOM; HSM-backed code-signing keys are the load-bearing root of signature provenance.
- `[[reference-code-review-expertise]]` — secure code review; review HSM-calling code for the anti-patterns in §11.
- `[[reference-mainframe-legacy-security]]` — IBM Z Crypto Express adapters; mainframe HSM lineage older than the appliance market.
- `[[reference-detection-engineering]]` — Sigma / SIEM rules; HSM audit-log ingestion and anomaly detection.

---

## Notes on sourcing

The HSM operational corpus is anchored on practitioner / standards primary sources where groundable:

- **Adi Shamir** — Shamir's Secret Sharing (CACM 1979), the algorithmic foundation for M-of-N key share splits used in HSM-vendor quorum implementations.
- **Whitfield Diffie + Martin Hellman** — foundational asymmetric crypto; Diffie's later commentary on key-management practice is widely cited.
- **Niels Ferguson + Bruce Schneier + Tadayoshi Kohno** — *Cryptography Engineering* (2010), the practitioner reference for key management and HSM use.
- **Filippo Valsorda** — cryptographic engineering commentary including HSM-adjacent posts (age tool author, former Cloudflare crypto engineer).
- **Thomas Pornin** — cryptographer; long-running technical commentary on key-custody and HSM threat models.
- **Dan Boneh + Matt Green** — academic cryptography with practical key-management implications.
- **Apostol Vassilev** — NIST; former CMVP Technical Director.
- **Tim Hall** — NIST CAVP; former manager of the Security Testing, Validation and Measurement group that housed CAVP and CMVP.
- **Stephen Farrell** — long-running IETF crypto / PKIX contributor.
- **Phillip Hallam-Baker** — PKI veteran (VeriSign); historical context on the certificate authority + HSM operational model.
- **Josh Aas** — Let's Encrypt / ISRG executive director; published ceremony posts.
- **NIST CMVP / CAVP** — validation lists, IG documents, transition guidance.
- **PCI Security Standards Council** — PCI HSM v3 spec, key block mandates (ASC X9 TR-31).
- **OASIS PKCS#11 TC** — PKCS#11 spec v2.40, v3.0, v3.1.
- **Vendor primary sources** — Thales Luna documentation, Entrust nShield documentation, AWS CloudHSM Developer Guide, Azure Managed HSM documentation, GCP Cloud HSM documentation.

Where a specific researcher could not be confidently anchored, the `[unverified]` flag is used inline. Where specific dates / acquisition details / validation IDs / per-vendor claims could not be groundable in a primary source, the `[unverified]` flag is used. Operators acting on the contents of this doc should verify per-vendor and per-validation specifics against the CMVP database, the relevant CC certifying body, and the vendor's current documentation.
