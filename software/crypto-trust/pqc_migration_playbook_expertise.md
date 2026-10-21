# Post-Quantum Cryptography Migration — An Operational Playbook

> **Scope.** This document is the **operational playbook** complement to
> [`post_quantum_cryptography_expertise.md`](post_quantum_cryptography_expertise.md), which
> covers the **standards landscape** — NIST FIPS 203/204/205, the lattice / hash / code /
> isogeny family taxonomy, the eight-year NIST competition, and the cryptanalytic
> milestones that disqualified Rainbow and SIKE. That parent doc answers "what are the
> algorithms?" This one answers "what does the migration look like on a typical Monday?"
>
> The two docs are designed to be read together. Standards work explains *what* you are
> deploying; the playbook explains *how* you discover what you have, *who* you coordinate
> with, *what* you change first, *what* the failure modes look like, and *what* an
> auditor will ask for. Where the parent doc is structured around algorithm families,
> this one is structured around the migration phases an engineering organisation
> typically passes through: inventory → risk tier → hybrid deployment per protocol →
> long-tail upgrades → agility hardening → compliance evidence.
>
> **Framework.** Synthesises operational guidance and shipped deployments from ten
> researchers and institutional groups whose work defines what post-quantum migration
> looks like in production rather than in a paper:
>
> - **Lily Chen** (NIST Fellow; manager of NIST Cryptographic Technology Group
>   2012-2023) — led the 8-year NIST PQC standardisation through FIPS 203/204/205
>   publication; canonical institutional voice on the migration roadmap and NIST
>   IR 8547 transition document.
> - **Dustin Moody** (NIST PQC project lead; mathematician in NIST Computer
>   Security Division) — chaired the NIST PQC standardisation effort 2016 through
>   final publication; principal public face of NIST's PQC announcements at
>   PQCrypto, RWC, NIST PQC Standardisation Conferences.
> - **Filippo Valsorda** (Geomys, formerly Google Go cryptography maintainer) —
>   author of `filippo.io/mlkem768`, the ML-KEM-768 reference implementation in
>   pure Go that became upstream of `crypto/mlkem` in Go 1.24, now the default in
>   `crypto/tls`. His `words.filippo.io` posts on PQC for the Go ecosystem and
>   the 2025 Go cryptography State of the Union are practical PQC migration
>   writing of a kind that does not exist for most language ecosystems.
> - **Peter Schwabe** (Scientific Director, MPI-SP; part-time at Radboud) —
>   co-author on three of the four selected NIST PQC standards (Kyber, Dilithium,
>   SPHINCS+); his constant-time reference implementations are what most
>   production libraries derive from.
> - **Bas Westerbaan** (Cloudflare Research) —
>   drives PQC adoption at Cloudflare and at the Internet at large; co-author of
>   the IETF hybrid-key-exchange draft; operator of
>   pqtunnels.cloudflareresearch.com; author of Cloudflare's annual "State of
>   the post-quantum Internet" writeups (2024, 2025).
> - **Tanja Lange** (Professor of Coding Theory and Cryptology, TU Eindhoven) —
>   sits on the PQCrypto steering committee; Classic McEliece co-author; long-running advocate (with
>   Bernstein) for hybrid PQ/T as the only responsible deployment posture during
>   the migration window.
> - **Apple Security Engineering team** — published the iMessage PQ3 design and
>   deployment writeup (February 2024) defining the "Level 3" classification for
>   PQ-ratcheted protocols. Formal analysis by Linker, Sasse, Basin (eprint
>   2024/1395) gives PQ3 the most thoroughly modelled production PQ-protocol
>   provenance to date.
> - **Signal Foundation** (Ehren Kret, Rolfe Schmidt et al.) — shipped PQXDH
>   (September 2023, the first production post-quantum upgrade to X3DH) and the
>   Triple Ratchet / SPQR (October 2025), the first production protocol with a
>   continuous post-quantum ratchet on every chunked message.
> - **NSA / CISA / NIST migration guidance** — the institutional triad publishing
>   *Quantum-Readiness: Migration to PQC* (joint factsheet, August 2023),
>   CISA's *Automated PQC Discovery and Inventory Tools* strategy (September
>   2024), NSA's *CNSA 2.0* (September 2022, updated May 2025), and NIST IR
>   8547 *Transition to PQC Standards* (initial public draft November 2024).
> - **Open Quantum Safe team** (Douglas Stebila, Michele Mosca and contributors)
>   — maintainers of liboqs, oqs-provider, and oqs-demos. Despite the "not
>   commercially supported" caveat, the de facto pre-NIST experimentation
>   harness for every major PQC deployment effort.
>
> Sources: NIST CSRC publications (FIPS 203/204/205, IR 8547, SP 800-208);
> security.apple.com (PQ3 disclosure, February 2024); signal.org/docs/specifications
> (PQXDH, Double Ratchet, SPQR/Triple Ratchet); blog.cloudflare.com PQ archive
> (2022-2025 deployment writeups); pq.cloudflareresearch.com; OpenSSH release notes
> 9.0 / 9.9 / 10.0; openquantumsafe.org documentation; CycloneDX 1.6 specification
> and CBOM authoritative guide; CSI CNSA 2.0 algorithms specification (media.defense.gov);
> CISA Quantum-Readiness factsheet; RFC 8391, RFC 8554, RFC 9794, RFC 9802; NIST
> SP 800-208; eprint.iacr.org PQ3 and KyberSlash papers; words.filippo.io PQC
> writing; thalesdocs.com Luna HSM PQC documentation.

---

## 1. Why this playbook exists

The standards work is done. ML-KEM (FIPS 203), ML-DSA (FIPS 204),
SLH-DSA (FIPS 205) were published in August 2024. Cryptanalysis of
the selected families has been steady but not decisive — only
alternative families (Rainbow, SIDH/SIKE) were broken late in the
NIST process. Hybrid TLS (`X25519MLKEM768`) is default-on in Chrome,
Firefox, Edge, recent Apple OSes, Go 1.24, OpenSSL 3.5, Cloudflare,
and Google's frontends. Hybrid SSH (`sntrup761x25519-sha512`, then
`mlkem768x25519-sha256` as the OpenSSH 10.0 default since April
2025) has shipped since OpenSSH 9.0 in April 2022. The first
application-layer deployments (Signal PQXDH, Apple PQ3) are two
years old.

What remains is **the migration itself** — cryptographic inventory,
risk-tiering, vendor coordination, protocol-by-protocol playbook,
side-channel hardening (KyberSlash-class bugs), compliance evidence
an auditor or NSS program manager can act on. Operational work — a
structured change-management exercise with cryptographic
preconditions, of the kind that AppSec, infrastructure, and
compliance functions know how to run from a playbook.

The migration-urgency anchor is **Harvest Now, Decrypt Later
(HNDL)**. A capable adversary captures encrypted traffic today,
stores at petabyte-per-year scale, and decrypts retroactively when a
cryptographically relevant quantum computer (CRQC) arrives. Expert
surveys cluster on 2030-2040 for CRQC arrival, but any data with a
10-year confidentiality lifetime is already at risk from 2026
captures decrypted in 2036.

The institutional cadence is **CNSA 2.0** (NSA, September 2022,
updated May 2025) for U.S. NSS: January 2027 — new NSS acquisitions must support CNSA
2.0; December 2030 — deployed NSS software/firmware must use CNSA
2.0 signatures; December 2031 — full enforcement; 2035 — all NSS
fully quantum-resistant (aligned with NSM-10). CNSA 2.0 applies
only to NSS but sets the cadence U.S. federal civilian will follow
under NIST IR 8547. EU Cyber Resilience Act + NIS2 create parallel
pressure with similar enforcement-by-2030 contours.

The playbook needs to exist in 2026 rather than 2030 because the
migration is not flippable. Swapping all RSA for ML-DSA at midnight
breaks production. The migration is a years-long, hybrid-first,
inventory-driven, vendor-coordinated programme. Read as sibling to
[[reference-appsec-program-building]], which describes the people-
and-trust substrate any cryptographic migration depends on.

---

## 2. The cryptographic inventory phase

Before migrating anything, you have to know what you have. Inventory
is the first migration phase every NIST / NSA / CISA roadmap names,
and the phase organisations most consistently underestimate. The
reality at most enterprises is "we did not know we were still using
RSA-1024 there."

### 2.1 What an inventory must enumerate

A cryptographic inventory captures every *use* of cryptography, not
just every library. The same OpenSSL binary is used in dozens of
contexts (TLS server, TLS client, JWT signing, code signing,
password-hashing KDF, internal RPC) with different risk profiles.
The unit of inventory is **(crypto context, algorithm, key length,
key lifetime, data lifetime, sensitivity)**, not (library, version).

Minimal enumeration: (1) **TLS endpoints** — every listening port,
every outbound client, server cert algorithm, KEX families, peer
cert validation; (2) **SSH** — every sshd config, every CI runner
client config, every embedded implementation (libssh, paramiko,
golang.org/x/crypto/ssh, dropbear), host/KEX/signing algorithms; (3)
**VPN / tunnel** — IPsec/IKEv2, WireGuard, OpenVPN, Cloudflare
Tunnel, Tailscale, custom QUIC tunnels; (4) **code signing** —
kernel modules, firmware, container images, package sigs
(RPM/DEB/NuGet/pip wheels), driver signing, Apple/Google mobile-app
signing, Authenticode, Sigstore; (5) **document signing** — PDFs
(PAdES, PAdES-LTV), XML signatures, S/MIME, PGP, custom
contract-signing pipelines; (6) **password / credential** — KDFs
(Argon2 / scrypt / bcrypt / PBKDF2), HSM-backed public-key auth; (7)
**JWT / IAM tokens** — JWT signing keys, OAuth 2.0/2.1 / OIDC
clients, SAML signing keys, IdP trusts; (8) **at-rest encryption** —
DEKs and KEKs in object stores, DB TDE, FS encryption (LUKS,
BitLocker, FileVault) — KEKs are PQ-critical, DEKs are AES and
survive Shor; (9) **application-layer custom crypto** — the long
tail of "we wrote our own signing thing for our internal RPC" —
most commonly missed, most operationally fragile; (10) **smart
cards / HSMs / TPMs / secure enclaves** — every hardware-backed
key, PKCS#11 token, cloud KMS / HSM service; (11) **DNS / DNSSEC**
— every signed zone, every DS record up the delegation chain; (12)
**federation trust roots** — root CAs in trust stores, OS- and
SDK-delivered root chains. Record as a structured artifact, not a
spreadsheet — that's what CBOM is for.

### 2.2 CBOM — CycloneDX 1.6's cryptographic-asset format

CycloneDX 1.6 (OWASP CycloneDX, April 2024) introduced the
**Cryptography Bill of Materials (CBOM)** format, developed at IBM
Research. CBOM extends SBOM from "what components am I shipping" to
"what cryptographic assets, algorithms, protocols, certificates, and
keys are in use, and what is the dependency graph between them."

CBOM models four asset types: **algorithm** (RSA, ECDSA, ML-KEM-768,
Argon2id, AES-256-GCM with parameter sets, key sizes, curve IDs);
**certificate** (X.509 certs and their signing-algorithm-of-record,
including intermediates); **cryptographic material** (keys, secrets,
PSKs, KDF outputs); **protocol** (TLS 1.2 / 1.3, IPsec, SSH, S/MIME,
Authenticode, Sigstore). Related cryptographic material carries a **state**
(`pre-activation`, `active`, `suspended`, `deactivated`,
`compromised`, `destroyed`); assets carry **relationships** (TLS endpoint →
certificate → CA → algorithm). The relationship graph is what makes
CBOM useful for migration: you can query "which TLS endpoints
transitively depend on an RSA-2048 root cert with 2030 expiration?"
without walking every chain manually.

CBOM tooling: **CBOMkit** (IBM Research, since donated to the
Linux Foundation's PQCA) generates CBOM from source by static
analysis of Java and Python crypto library call sites; **cdxgen** (CycloneDX/cdxgen) generates CycloneDX
BOMs from source and container images with CBOM emission; **sslyze**
and **testssl.sh** scan TLS endpoints for negotiated suite per host
as the empirical check on a CBOM generated from source. Inventory is where [[reference-supply-chain-provenance]]
overlaps: CBOM is the SBOM's crypto cousin, same provenance
disciplines (signed, attested, retained across release boundaries,
queryable). Treat CBOM emission as a release-pipeline artifact, not
a one-off audit deliverable — the half-life of a hand-curated
inventory is one sprint.

### 2.3 The "we did not know we were still using" reality

Three categories consistently surprise teams: legacy RSA-1024 keys in
code-signing chains rolled forward from 2008 and never re-keyed; MD5
/ SHA-1 in HMAC or KDF positions inside custom RPC protocols ("just
a session token" that turns out to authorise privileged actions);
vendored crypto libraries statically linked three versions behind
upstream and missing side-channel fixes (especially common in
firmware and COTS appliances). PQC migration is when to fix all three.

### 2.4 Application-layer crypto — the long tail

Most-commonly-missed crypto uses: custom RPC with hand-rolled auth
tokens; embedded HMAC in URL signing (S3 / GCS / Azure presigned
URLs); license-key validation; WebCrypto JavaScript; wallet signing
([[reference-blockchain-wallet-consensus-security]]); custom-E2EE
support-chat features that exist in approximately every B2B SaaS.
For each: signature / KEM primitive, payload lifetime, migration
cost? Cross-link to [[reference-supply-chain-provenance]] for SBOM
lineage and [[reference-cryptography-expertise]] for the
classical-algorithm baseline.

---

## 3. Threat model and risk-tier classification

Inventory tells you *what you have*; risk-tiering tells you *what to
migrate first*. Inseparable in practice — write the inventory with
risk-tiering in mind, confirm tiering once the inventory exposes
surprises. Output: a ranked list of cryptographic uses with target
migration windows.

### 3.1 The "max-allowable-disclosure-window" exercise

For each cryptographic use, ask **how long the data this protects
must remain confidential**. **Decades** (legal docs, medical
records, intelligence, trade secrets, biometrics, IDs) — highest
priority, most HNDL-vulnerable. **Years** (retention-bound financial
records, contracts, archived PII) — high priority. **Months**
(operational data, log archives, soon-superseded build artifacts)
— medium. **Hours to days** (TLS session keys, short JWTs, OAuth
refresh) — lower HNDL priority, but authentication-now still
matters. **Ephemeral** (CSRF tokens, nonces) — lowest PQ priority.
Cross with **what the key authenticates**: auth-only keys are
lower-priority than confidentiality-protecting keys, except code
signing — a forged 2030 firmware signature is catastrophic, so it
gets its own playbook (section 6).

### 3.2 The four risk tiers

**Tier 1 — long-lived confidentiality (decades).** Legal contracts,
multi-decade-retention medical records, classified material, source
code / architecture docs for products with long market lifespans,
GDPR / HIPAA / SOX customer-data archives. Hybrid-first, urgent,
target window 2026-2028. Wait-and-see is not an option because the
harvest is happening now.

**Tier 2 — authentication-only / short-lived confidentiality.** TLS
for web traffic, JWT signing for short-lived API tokens, OAuth bearer
tokens, SAML response signing, most application-layer message
authentication. Hybrid-first, opportunistic, 2026-2030. Ride upstream
library defaults rather than running each as a standalone project.

**Tier 3 — code signing and long-lived authentication.** Firmware
signing on 10-30 year deployed hardware (ICS, automotive, aerospace,
medical, infrastructure SCADA); root CA keys with multi-decade cert
lifetimes; PAdES-LTV / long-archive document signing. Stateful hash
signatures (XMSS / LMS under NIST SP 800-208) and SLH-DSA for
stateless workflows. 2026-2028 for new signing infrastructure;
longer for already-issued certs.

**Tier 4 — sector-specific mandates.** Regulated NSS (CNSA 2.0
overrides internal threat-modelling); defence industrial base (DFARS,
CMMC-level-3+ inheriting CNSA expectations); financial services (PCI
DSS, SOX, MiFID II revisions over 2026-2030); healthcare (HIPAA
updates plus state regimes); consumer SaaS (latest movers, follow
upstream vendors — Cloudflare's edge has done most of the work
already).

### 3.3 The risk-tier table as a planning artifact

Output of this phase: a table with one row per cryptographic use and
columns for inventory ID, current algorithm, data-lifetime tier,
threat tier, target algorithm, target migration window, vendor
dependency, and migration owner. This is the master schedule. Without
it, the migration is unsequenced and the team spends 80% of its
budget on TLS endpoints that did not actually need to move first,
while long-lived code-signing infrastructure quietly carries the
highest residual risk for years.

---

## 4. Hybrid TLS deployment playbook

TLS is the highest-traffic, highest-visibility, lowest-friction
migration target with the most mature upstream support. Most
organisations can complete the TLS-server side in a single quarter
once inventory and risk-tiering are done. The recipe below anchors
on **X25519MLKEM768** — classical X25519 ECDH + post-quantum
ML-KEM-768 KEM — the de facto standard for production hybrid TLS
in 2026.

### 4.1 Why X25519MLKEM768, and why hybrid

Hybrid runs both X25519 ECDH and ML-KEM-768 encapsulation, combining
the two shared secrets into the TLS key schedule. Security argument
is two-sided: **against today's classical adversary** the connection
is at least as strong as the X25519 leg — if ML-KEM-768 has an
unknown weakness surfacing in 2027, X25519 still protects today's
traffic; **against a future quantum adversary** the ML-KEM-768 leg
protects against HNDL even if Shor breaks X25519. Pure-PQ (no
classical leg) lacks the first property — an undisclosed lattice
break would catastrophically affect connections hybrid would
survive. This is the **Bernstein-Lange "hedge"**, the consensus
reason every production deployment uses hybrid. RFC 9794 (June 2025)
formalises the terminology: PQ/T hybrid = post-quantum + traditional.

### 4.2 Server-side deployment recipe

In 2026, every major TLS library has shipped support. **OpenSSL 3.5+**
(April 2025) exposes the `X25519MLKEM768` group; configure
`Groups = X25519MLKEM768:X25519:secp256r1`. **BoringSSL** shipped
`X25519Kyber768Draft00` first (Chrome 116, August 2023); production
deployments now use the final-standard `X25519MLKEM768`. **rustls**
supports it via `aws-lc-rs` provider in `rustls` 0.23.x. **Go
`crypto/tls`** uses hybrid X25519MLKEM768 by default for any peer that
supports it as of Go 1.24 (February 2025). **NSS / Firefox 132+**
(November 2024) and **Apple URLSession / Network framework**
(iOS 26 / iPadOS 26) enable it by default. The
config change is one line; the dominant cost is verification —
debugging "why is my client negotiating X25519 instead of
X25519MLKEM768" against an opaque TLS library (section 4.4).

### 4.3 Client-side support landscape

Client support is already deployed: Chrome 131+ (November 2024), Firefox
132+ (November 2024), Edge (Chromium-based), Apple URLSession / Network
clients on iOS 26 / iPadOS 26, curl with OpenSSL 3.5 / BoringSSL (`--curves X25519MLKEM768`), Go
HTTP client (automatic since Go 1.24), `cloudflared`. **Enabling
X25519MLKEM768 on the server is sufficient** — major clients are
already there, hybrid serves classical-only clients via the X25519
leg, so server-side enablement is risk-free. The anti-pattern is
"wait until 100% of clients support PQ before enabling the server."

### 4.4 ALPN handshake debugging recipe

The common surprise: PQ is configured but connections still negotiate
the classical curve. Debug procedure: (1) capture the ClientHello with
`tshark -i any -f 'port 443' -V` against a PQ-capable client and look
for `X25519MLKEM768` (group ID `0x11ec`) in `supported_groups`; (2)
capture the ServerHello and inspect the `key_share` `selected_group`
to see what the server actually picked; (3) suspect middleboxes if
ALPN succeeds but PQ negotiation fails — some legacy appliances mangle PQ ClientHellos that expect
sub-1500-byte sizes; (4) check MTU — ML-KEM-768 client_share is ~1184
bytes vs X25519's 32 bytes, so the ClientHello swells to ~1700-1900
bytes (TCP segmentation handles it, but legacy middleboxes don't
always).

### 4.5 Performance overhead — what to expect

From large-scale deployment data: PQ ClientHello is ~1100-1200 bytes
larger than classical X25519 (~600 bytes baseline + ~1200 byte ML-KEM
client_share); server response ~1000 bytes larger. Net handshake
increase: ~5-15% of total page-load bytes for typical short-content
pages. ML-KEM-768 encapsulate / decapsulate cost is
comparable to a single X25519 scalar
multiplication. Cloudflare reports more than 45% of
human traffic was hybrid-PQ by September 2025; 52% by
end of 2025.

### 4.6 Fallback semantics

TLS 1.3 supported_groups negotiation gives the server's preference
order the deciding vote: put X25519MLKEM768 first to maximise PQ
uptake. Classical-only clients still negotiate classical — there is
no "PQ-required" mode in stock TLS 1.3. PQ-required postures need
either restricting `Groups` to PQ-only (breaks classical-only
clients), middleware-level rejection of classical handshakes, or a
future TLS "PQ-required" extension (IETF WG-stage in 2026). Cross-
link to [[reference-cryptography-expertise]] §16 and
[`post_quantum_cryptography_expertise.md`](post_quantum_cryptography_expertise.md)
§7.

---

## 5. SSH migration playbook

SSH is the next-easiest migration after TLS. OpenSSH shipped hybrid
PQ KEX in 9.0 (April 2022), well before final FIPS 203 publication
— the first major internet protocol with default-on hybrid PQ in
widely-deployed software.

### 5.1 OpenSSH version landmarks

**OpenSSH 9.0** (April 2022) added `sntrup761x25519-sha512`
(Streamlined NTRU Prime + X25519) as the default first preference in
`KexAlgorithms`. NTRU Prime wasn't selected in the final NIST round
(Bernstein-Lange chose it as a conservative alternative to NIST),
but in 2022 it was the most mature PQ scheme with deployable
reference; choice has held up. **OpenSSH 9.9** (September 2024)
added `mlkem768x25519-sha256` (ML-KEM-768 + X25519,
`draft-kampanakis-curdle-ssh-pq-ke`) as second PQ option. **OpenSSH
10.0** (April 2025) made `mlkem768x25519-sha256` the default first
preference; sntrup761x25519-sha512 retained for compatibility.
Expected 2026 steady state: 9.9+ negotiates mlkem768x25519-sha256,
9.0-9.8 falls back to sntrup761x25519-sha512, pre-9.0 falls back to
classical curve25519-sha256 (flag for remediation). GitHub enabled
PQ SSH (`sntrup761x25519-sha512`) for `git+ssh` in September 2025, making PQ the default
for the most common SSH use case at the largest hosting provider.

### 5.2 Server-side configuration

The relevant sshd_config line:
```
KexAlgorithms mlkem768x25519-sha256,sntrup761x25519-sha512,curve25519-sha256,curve25519-sha256@libssh.org
```
Order matters: put PQ first. For SSH the client's preference order
wins — the first algorithm on the client's list that the server also
supports is chosen (RFC 4253 §7.1) — so a client not offering PQ
still gets classical.

### 5.3 Client-side configuration

For `ssh_config`, the same `KexAlgorithms` line works. Modern OpenSSH
clients (9.0+) include PQ algorithms by default, so explicit config
is only needed for **force-PQ-only** (omit classical curves) in
high-assurance environments — breaks compatibility with pre-9.0
servers, deliberate posture choice — or **force-classical** for
compatibility with un-updated middleboxes / SSH monitoring (worst
posture, temporary only).

### 5.4 Audit recipe — what your peers negotiate

Fastest negotiation check: `nmap --script ssh2-enum-algos -v -p22 hostname` surfaces
server-advertised KEX; `ssh -vv user@hostname 2>&1 | grep 'kex:'`
shows the actually-negotiated algorithm. Fleet-wide: script
`nmap --script ssh2-enum-algos` against every inventoried host and emit CSV
for a PQ-readiness dashboard.

### 5.5 Embedded / non-OpenSSH SSH implementations

The long tail in SSH inventories: **Dropbear** (embedded; sntrup761 and ML-KEM PQ KEX since
2025.87, March 2025); **libssh** 0.12 (February 2026, PQ KEX added — Wireshark /
libcurl SSH inherit on rebuild); **libssh2** (hybrid ML-KEM KEX with OpenSSL 3.5 in
1.11.2-dev); **paramiko** (Python; `mlkem768x25519-sha256` since
5.1.0, October 2026, when `cryptography` exposes ML-KEM); **golang.org/x/crypto/ssh** (`mlkem768x25519-sha256` supported when
built with Go 1.24+); **PuTTY** 0.78 (October 2022, NTRU Prime PQ
KEX; ML-KEM since 0.83, February 2025). For embedded SSH on multi-year refresh hardware, note which
implementation is in use — upgrade cadence depends on the upstream
library, not OpenSSH. Cross-link to
[`post_quantum_cryptography_expertise.md`](post_quantum_cryptography_expertise.md)
§8 and [[reference-supply-chain-provenance]] for the GitHub `git+ssh`
context.

---

## 6. Code-signing migration

Code signing has the longest migration tail and the sharpest "must
verify in 2055" tail risk. Firmware signed today must verify on
hardware that may not be retired until 2050+. The signing-algorithm
choice now determines what industrial control, automotive, and
medical-device manufacturers can upgrade in the field 20+ years on.

### 6.1 The "30-year firmware signed today must verify in 2055" reality

Long-lived hardware contexts: **industrial control / SCADA** (20-40
year lifespans in power, water, oil/gas, discrete manufacturing);
**automotive** (15-20 years; ECUs, infotainment, telematics, ADAS);
**aerospace** (30+ years on commercial aircraft flight-control
firmware); **medical devices** (10-20 years on implanted devices
where physical replacement is invasive); **defence systems**
(multi-decade procurement cycles, CNSA 2.0). The central question is
"which algorithm signs the firmware update deployed in 2027 and
verified by a device still in the field in 2057?" — constrained by
NIST SP 800-208 (stateful hash sigs) and FIPS 205 (SLH-DSA).

### 6.2 SPHINCS+ / SLH-DSA — the conservative choice

SLH-DSA (FIPS 205, derived from SPHINCS+) is a **stateless**
hash-based signature scheme. Security reduces only to the underlying
hash function (SHA-256 / SHAKE-256) — the most conservative PQC
assumption available. Signature size: 7.8 KB to 49 KB depending on
parameter set; single-digit percent overhead for MB-scale firmware
images, prohibitive in protocol headers (TLS, DNSSEC). Sign speed:
milliseconds on modern CPUs, slow on constrained devices; verify is
10-100x slower than ECDSA but acceptable for once-per-boot. Choose
SLH-DSA when (a) verification time budget is not microseconds, (b)
signature can be stored alongside artifact, (c) the assurance
argument needs to be "as conservative as PQC gets."

### 6.3 XMSS / LMS — stateful hash signatures (NIST SP 800-208)

XMSS (RFC 8391, May 2018) and LMS (RFC 8554, April 2019) are
**stateful** hash-based signatures. NIST SP 800-208 approves them for
specific applications including code signing where state management is
guaranteed — reusing a one-time key catastrophically breaks the
scheme. Signature size: 2-3 KB for approved parameter sets (smaller
than SLH-DSA); sign speed comparable. Operational risk: state
corruption / replay across HSMs is a single-bit failure mode that
SLH-DSA does not have. Choose XMSS / LMS when signing happens in a
single well-controlled environment, signature size budget is tighter
than SLH-DSA permits, and the application fits SP 800-208's narrow
scope (code signing and similar — *not* general-purpose digital
signatures). RFC 9802 (June 2025) specifies HSS (multi-tree LMS) and
XMSS in X.509, opening the path for stateful-hash code-signing certs.

### 6.4 ML-DSA for code signing — when it's appropriate

ML-DSA (FIPS 204, lattice-based) is appropriate when: verification is
on a general-purpose computer (not a deeply-constrained MCU);
signature-size budget is small (ML-DSA-65 sigs are ~3.3 KB —
comparable to LMS); the signing application is short-to-medium-lived
(years, not decades), since lattice cryptanalysis surprises over a
30-year horizon remain possible while hash-based schemes do not have
this risk. Typical pattern: ML-DSA-65 default for CI / container /
package signing; ML-DSA-65 or hybrid ML-DSA + ECDSA for medium-lived
(drivers, 5-10 year apps); SLH-DSA or XMSS / LMS for long-lived
(firmware on 20+ year horizon).

### 6.5 Vendor-specific code-signing roadmaps

**Apple code signing** (Developer ID, App Store) — no public PQC
roadmap as of 2026; internal roadmap presumed given iMessage PQ3
leadership. **Microsoft Authenticode** — legacy SHA1 / SHA256 chains remain valid for
years. **Linux package signing** (DEB / RPM) — Debian / RPM tracking
PQ via GnuPG / Sequoia-PGP roadmaps; no defaults flipped 2026.
**Container image signing** — Sigstore cosign production defaults are
still ECDSA; Rekor transparency log
itself signed so the migration applies to both. **Driver signing**
(Microsoft WHQL, Apple kext) — long back-compatibility tails tied to
OS major-version cycles. **Code-signing CAs** — DigiCert, GlobalSign,
Sectigo have PQ-readiness roadmaps; production PQ code-signing certs
limited-availability in 2026.

### 6.6 Forward-compatible signing — "sign with PQ today, verify
with PQ tomorrow"

Hybrid pattern: sign with **both** classical and PQ signatures
during migration. A firmware image carries ECDSA + ML-DSA-65;
updated verifiers check both, unupdated verifiers check only
classical. Once field deployments are PQ-aware (years for long-lived
hardware), drop classical on new signings. The composite-signature
pattern (single object with classical + PQ components) is being
standardised in IETF LAMPS WG; until then hand-rolled
length-prefixed concatenation is the operational pattern. Cross-link
to [[reference-supply-chain-provenance]] §3 and
[[reference-firmware-embedded-security]].

---

## 7. Document signing and long-term preservation

Document signing is the "Tier 1 long-lived authentication" sibling
of code signing — high-value artifacts verifiable for decades. Use
cases: **PDF signing** (PAdES, PAdES-LTV / PAdES-LTA for long-term
archival — ETSI EN 319 142 defines profiles from "basic" B-B through "long-
term archival" LTA embedding signature-validation data in the
document); **S/MIME and CMS-signed objects** for email and B2B
message signing; **PGP / OpenPGP** for software distribution,
legal-evidence email archives, journalistic source protection;
**XML signatures (XAdES)** for SAML responses and XML-archival
legal documents.

### 7.1 The "signed contract from 2025 has to verify in 2055" use case

PAdES-LTV / PAdES-LTA is designed exactly for this: signatures
cryptographically verifiable for 30 years. Pattern: (1) sign at time
T with best-available algorithms; (2) embed full cert chain and
OCSP / CRL responses valid at T; (3) add RFC 3161 timestamps from a
TSA to bind to a specific point in time; (4) at intervals (5-10
years, or before algorithm deprecation), add **archive timestamps**
over the existing signature and validation data using algorithms
current at the new time. This transforms the long-term-verification
problem into "is the most recent archive timestamp still valid?"
PQ migration for already-RSA / ECDSA-signed PAdES-LTA documents is
**archive-timestamping with PQ signatures over the existing signed
object** — the original signature does not need re-doing; the new
archive timestamp under SLH-DSA / LMS establishes the signature was
valid before quantum threats matured. Most-conservative
back-compat pattern in long-term document signing.

### 7.2 Vendor migration timelines

**TSAs**
(DigiCert, GlobalSign, Entrust, Sectigo) — PQ-capable timestamping
rolling out 2026.

### 7.3 The hybrid signature pattern for documents

Sign at time T with ECDSA + ML-DSA-65 composite (or ECDSA + SLH-DSA
for highest assurance); add timestamps from TSAs supporting both
classical and PQ; periodically re-timestamp with current algorithms.
The composite verifies under classical today, under PQ in 2030+, and
survives any single algorithm's deprecation. Cross-link to
[[reference-cryptography-expertise]] for PAdES profiles and
[`post_quantum_cryptography_expertise.md`](post_quantum_cryptography_expertise.md)
for primitive choices.

---

## 8. Application-layer protocols — what production looks like

Below the TLS layer sit application-layer protocols with their own
crypto: messaging, VPNs, custom RPC, SaaS-internal binary protocols.
The most-fragile migration targets — no universal upgrade, each
protocol has its own deployment story.

### 8.1 Signal Protocol — PQXDH (Sep 2023) and Triple Ratchet (Oct 2025)

Signal's two-stage PQ migration is the canonical production reference.

**PQXDH** (Sep 2023) replaced classical X3DH at session start. The
shared secret derives from *both* X25519 ECDH and CRYSTALS-Kyber-1024
KEM. Rollout was incremental — older clients fell back to X3DH until
updating. **Important
property**: only initial key agreement is PQ-protected. Subsequent
message-rekeying used the classical Double Ratchet (X25519 + KDF
chain). A CRQC-equipped adversary capturing Signal traffic post-2023
could decrypt subsequent messages by recovering any post-handshake
per-message key, but session establishment was HNDL-safe.

**Triple Ratchet / SPQR (Sparse Post-Quantum Ratchet)**, deployed Oct
2025, extends PQ protection across the entire session. Construction:
the Double Ratchet (X25519 + symmetric KDF) is retained; SPQR runs in
parallel, exchanging ML-KEM-768 ciphertexts in erasure-coded chunks
across messages; outputs combine via KDF for message-encryption keys.
The "sparse" trick: ML-KEM ciphertexts (~1100 bytes) are too large to
send every message, so SPQR splits each ciphertext across multiple
messages with erasure coding for loss tolerance. Continuous PQ
ratcheting means ongoing sessions are HNDL-safe. Apple's PQ3 taxonomy
classifies pre-Triple-Ratchet Signal (PQXDH) as "Level 2" and PQ3
itself as "Level 3."

### 8.2 Apple iMessage PQ3 — Feb 2024, Level 3

Apple's PQ3, announced February 2024, is the other production
reference. Structure: (1) initial key agreement with classical ECDH +
PQ KEM (Kyber); (2) per-message symmetric ratchet for forward
secrecy; (3) per-message ECDH ratchet for fresh entropy; (4) periodic
PQ KEM ratchet — a new Kyber-768 key is mixed into the key derivation
about every 50 messages, and at least once every 7 days. This continuous-PQ
property defines "Level 3." Apple's whitepaper, Stebila's analysis,
and the formal verification by Linker, Sasse, Basin (eprint
2024/1395, USENIX Security 2025) give PQ3 the most thoroughly modelled
production-PQ-protocol provenance to date. Apple deployed continuous
PQ ratcheting from the start of PQ3 (Feb 2024); Signal matched it
with SPQR (Oct 2025). Both are now Level 3.

### 8.3 WhatsApp — roadmap

WhatsApp uses a Signal-derivative protocol; PQ rollout is presumed
to follow Signal Triple Ratchet, but Meta has not published a
specific date as of 2026. Migration is technically straightforward
once Triple Ratchet is integrated and battle-tested upstream — the
question is regulatory and rollout-cadence, not technical.

### 8.4 Email — S/MIME and OpenPGP

Email signing is the slowest application-layer migration because of
federation: every sender and receiver has independent infrastructure
and upgrade cadences. **S/MIME** is vendor-driven (Microsoft, Apple,
Google, mobile vendors) — PQ-capable implementations emerging 2026,
default-on unlikely before 2028. **OpenPGP / PGP** — GnuPG roadmap
targets PQ key types via draft-ietf-openpgp-pqc; contributor-driven,
not a default. Long-tail S/MIME in regulated sectors will be among
the slowest PQ migrations in the entire stack — decade-scale.

### 8.5 Custom RPC protocols — the per-organisation playbook

For custom RPC (gRPC, custom binary, internal service meshes):
(1) if RPC uses TLS for transport, TLS PQ migration handles
confidentiality and authentication — no protocol change needed;
(2) if RPC has application-layer auth tokens (signed JWTs, message
signatures, internal mTLS), see sections 9-10; (3) if RPC has
application-layer E2EE not piggybacking on TLS, a custom hybrid
construction is needed — Signal Triple Ratchet is the standard
reference. Common gotcha: "internal" RPC traffic assumed HNDL-safe
because it never leaves the VPC often crosses provider boundaries
(managed DB connections, third-party SaaS integrations, multi-region
replication). Treat every RPC channel as capturable until the threat
model proves otherwise. Cross-link to [[reference-distributed-authz]].

---

## 9. Identity, IAM tokens, and federation

IAM is structurally similar to application-layer protocols — each
token format has its own signing algorithm and migration cadence.

### 9.1 JWT — algorithm migration

JWTs use the `alg` header for signing algorithm identification.
Migration pattern: (1) update signers to issue new-algorithm
(`ML-DSA-65` or hybrid composite); (2) update verifiers to accept
both old and new; (3) wait for verifiers — where JWT migrations
stall on long-tail third-party integrations; (4) cut signers to
new-only. The `alg` value is in transition: the IETF COSE WG is standardising
JOSE PQ identifiers (`ML-DSA-65`, draft-ietf-cose-dilithium); some deployments use vendor-prefixed
values until the standard ships.

### 9.2 OAuth 2.1, OIDC, and the federation cost

OAuth 2.0 / 2.1 and OIDC use JWTs as the core token format, so PQ
OAuth migration is JWT migration plus the discovery-document and
JWKS-rotation infrastructure each IdP runs. The hard part is the
federation network — an IdP that flips to PQ JWTs breaks every
unsupported relying party. Practical pattern: IdPs publish multiple
signing keys in JWKS (one per algorithm), tag JWTs with the
appropriate `kid`, relying parties iterate JWKS and pick the first
algorithm they understand. Smooth incremental rollout without
all-at-once coordination.

### 9.3 SAML — the slow-mover

SAML XML signatures historically support RSA-SHA256 / RSA-SHA1 /
ECDSA. ML-DSA / SLH-DSA URIs are in IETF
draft-eastlake-rfc9231bis-xmlsec-uris as of 2026 but not deployed. SAML PQ migration will be the slowest identity-layer
migration: hundreds of relying parties with disparate cadences, and
the XML signature ecosystem has limited active maintenance.
Realistic pattern — wait for IdP vendor support (Okta, Microsoft
Entra ID, Ping Identity, ForgeRock), track JWKS-style multi-algorithm
publishing when it arrives. Production-ready window: 2027-2030.
Cross-link to [[reference-saml-federation]] and
[[reference-distributed-authz]].

---

## 10. Cryptographic agility — design for the next migration

The PQC migration is one migration. The next — replacing ML-KEM
after a 2032 lattice breakthrough, replacing ML-DSA after a
HertzbleedV2-style side-channel — has the same shape with different
algorithms. The most important durable investment from PQC migration
is **cryptographic agility**: the property that the next algorithm
change is a config change, not a re-architecture.

### 10.1 Crypto-agility as a design doctrine

Concrete properties of an agile cryptographic deployment: (1)
**algorithm choice is data, not code** — config specifies the
algorithm, library calls accept parameters; (2) **negotiable in
every protocol** — TLS cipher suites, SSH `KexAlgorithms`, SAML
`Algorithm` URI, JOSE `alg` header (custom protocols often forget
this); (3) **versioned algorithm identifiers** — formal OIDs
(`id-ml-dsa-65`) not nicknames (`dilithium3` is ambiguous across
Round 3 → final); (4) **library-level agility** — algorithm-list
APIs that ask for "strongest available in family X" push the
migration to the library version, not application code; (5) **key
rotation genuinely periodic** — quarterly-exercised rotation
infrastructure is the only kind that works under real migration
pressure.

### 10.2 The "bet on Kyber being the final answer" trap

Hardcoding ML-KEM-768 once FIPS 203 ships is short-sighted: lattice
cryptanalysis has surprised everyone before (Rainbow, SIDH — see
[`post_quantum_cryptography_expertise.md`](post_quantum_cryptography_expertise.md)
§9-§10), and a replacement-need horizon is closer to 10 years than
100. Assume ML-KEM-768 is temporary and design accordingly; the next
migration then costs 10x less than this one. Without that
investment, the next migration repeats the pain.

### 10.3 Negotiation in custom protocols — failure-mode catalog

Custom protocols get agility wrong predictably: **magic-byte
protocol versions** bake the algorithm into the wire format, forcing
simultaneous updates everywhere; **single-algorithm header fields**
have no slot for hybrid composite signatures; **hash-tied-to-
signature assumptions** thread SHA-256 through code that has to be
rewritten when a different hash family appears; **fixed-width
length-prefixed signature fields** cannot accommodate the dramatically
larger PQ signatures. Designing past these mistakes is the
difference between a 1-quarter agility investment and a 2-year
refactor. The PQC migration is the moment to find them — they need
fixing anyway.

---

## 11. Performance and storage considerations

PQ algorithms have different size and performance profiles than
classical. Differences matter most at protocol edges (DNS records,
smart-card transactions, TLS handshakes over constrained links) and
on resource-constrained devices.

### 11.1 Key and signature sizes — order-of-magnitude

| Algorithm                | Public key | Private key | Signature / Ciphertext |
|--------------------------|-----------:|------------:|-----------------------:|
| RSA-2048                 |   256 B    |  256 B      | 256 B                  |
| ECDSA-P256               |    64 B    |   32 B      |  64 B                  |
| Ed25519                  |    32 B    |   32 B      |  64 B                  |
| X25519                   |    32 B    |   32 B      |  32 B (shared secret)  |
| ML-KEM-768 (FIPS 203)    | 1,184 B    | 2,400 B     | 1,088 B (ciphertext)   |
| ML-DSA-65 (FIPS 204)     | 1,952 B    | 4,032 B     | 3,309 B (signature)    |
| SLH-DSA-128f (FIPS 205)  |    32 B    |   64 B      | 17,088 B (signature)   |
| SLH-DSA-256s (FIPS 205)  |    64 B    |  128 B      | 29,792 B (signature)   |
| Falcon-512 (FN-DSA)      |   897 B    |  1,281 B    | 666 B (signature)      |
| XMSS-SHA256-H10          |    64 B    |  varies     | 2,500-3,000 B          |
| LMS-SHA256-H10           |    60 B    |  varies     | 1,100-2,400 B          |

Takeaways: ML-KEM ciphertexts are ~30x larger than X25519 shared
secrets (TLS handshake impact); ML-DSA signatures ~50x larger than
ECDSA (JWT / CMS-signed-object impact); SLH-DSA signatures 100-700x
larger than ECDSA (reserves SLH-DSA for code signing and
non-handshake contexts); Falcon signatures are small (~660 B) but
require constant-time floating-point arithmetic that is
hardware-portability-sensitive.

### 11.2 DNS RR size limits — DNSSEC migration challenge

DNSSEC is the most-constrained context — practical DNS responses are
limited to ~1232 bytes (EDNS0 from the legacy 512-byte UDP cap),
beyond which fallback to TCP fails on poorly-configured
infrastructures. ML-DSA signatures (3.3 KB) don't fit; SLH-DSA
(8-50 KB) is catastrophic. The Verisign / IETF `pqc-dnssec` work
proposes hash-based signatures (XMSS / LMS) for ZSK with
Merkle-Tree-Ladder mode (amortises a single large signature across
many DNS records), dual-algorithm zone signing during migration, and
Synthesized Zone Signing Keys for key-rollover bloat. DNSSEC PQ
migration is expected to lag TLS / SSH by 2-3 years.

### 11.3 TLS handshake size vs MTU

TLS ClientHello + ServerHello with X25519MLKEM768 fits within typical
MTUs after TCP segmentation. Cost: ~5-15% handshake bandwidth
overhead and middlebox compatibility (legacy appliances with
hardcoded ClientHello-size assumptions fragment PQ handshakes; long
tail extends to 2027 in some enterprise networks). The Cloudflare
pqtunnels endpoint catches these in the wild.

### 11.4 Constrained-device memory budgets

For RTOS / IoT, RAM and flash are the constraints. **ML-KEM-768**
reference (PQClean `clean` in PQM4) uses ~14 KB stack on decapsulation; PQM4
optimised implementations get to ~3-6 KB. **ML-DSA-65** signing is
memory-intensive — may not be feasible on Cortex-M0 / M3. **SLH-DSA-128f**
is more conservative on memory but slow on constrained devices.
**XMSS / LMS** are the choice for verify-only constrained devices.
PQM4 (github.com/mupq/pqm4) maintains optimised PQ implementations
for ARM Cortex-M4 — pull from PQM4 for production constrained
deployments rather than desktop-optimised liboqs. Cross-link to
[[reference-rtos-embedded-os]] §13.

---

## 12. Side-channel hardening

PQ algorithms have their own side-channel profile, distinct from the
classical literature. Hardening discipline carries over; specific
failure modes are new.

### 12.1 KyberSlash — the canonical PQ side-channel

KyberSlash (Bernstein, Bhargavan, Bhasin, Chattopadhyay, Chia,
Kannwischer, Kiefer, Paiva, Ravi, Tamvada, 2024) is the reference timing side-channel in PQ
implementations. ML-KEM's reference does a division by Kyber prime
`q` in message decoding. On many platforms (ARM Cortex-A7,
Cortex-M4, x86 with certain compilers) integer division is not
constant-time, so it leaks bits of the secret via timing. The
exploit constructs chosen ciphertexts to amplify leakage and recover
the ML-KEM private key. The fix was upstreamed to pq-crystals and
most downstream libraries (Go, Rust, C bindings) in H1 2024. `KyberSlash1`
(`poly_tomsg`) was found by Tamvada, Bhargavan and Kiefer and
independently by Dan Bernstein; `KyberSlash2` (`poly_compress` /
`polyvec_compress`) was found by Ravi and Kannwischer. The lesson: PQ algorithms aren't secure by
virtue of being PQ. A migration that uses a side-channel-vulnerable
PQ implementation is worse than staying on hardened classical.

### 12.2 Side-channel and fault attacks on Dilithium

ML-DSA has been targeted by power-analysis attacks on
microcontrollers (key recovery from few signatures with a
power-trace oracle) and fault attacks that bypass rejection
sampling to induce signature forgeries. Mitigations are the same as for classical algos
with similar profiles: constant-time arithmetic, masked
implementations on high-assurance devices, fault-detection
countermeasures, and operational separation of assurance levels per
key.

### 12.3 Constant-time implementation discipline

Audited production PQ implementations (Apple's PQ3 stack,
Cloudflare's BoringSSL PQ, Filippo Valsorda's `filippo.io/mlkem768`
upstreamed to Go's `crypto/mlkem`, AWS-LC PQ) share four rules: no
secret-dependent branches (use `subtle.ConstantTimeEq` etc.); no
secret-dependent memory access patterns (linearly scan with
constant-time selection, no secret-indexed lookup tables); no
secret-dependent loop counts (fixed-iteration rejection sampling
with constant-time failure handling); automated verification
(`valgrind` memcheck + `ctgrind` patches, `dudect`, formal
verification like Cryspen's `hax`-verified ML-KEM in Rust).

### 12.4 Hardware acceleration trade-offs

Intel AVX2 / AVX-512 speeds up ML-KEM and ML-DSA via inner-loop
vectorisation. Use
AVX2 unless AVX-512 performance is measured and necessary; verify
the AVX-512 implementation is audited for the timing profile of your
configuration. Cross-link to [[reference-hardware-side-channels]].

---

## 13. Vendor coordination and testing infrastructure

PQ migration depends on every vendor in the stack: TLS library, HSM,
cloud KMS, protocol gateway, load balancer, CA, monitoring stack.
Vendor coordination dwarfs the technical-migration problem in most
enterprises.

### 13.1 HSM vendor PQ status

The HSM market is in coordinated transition. **Thales Luna HSM 7.9**
(firmware announced July 2025) ships native support for ML-KEM (FIPS 203) and
ML-DSA (FIPS 204) fully integrated into firmware (no functionality
modules); keys clone across partitions, back up / restore, and work
in HA groups — the production reference for PQ HSM in 2026. **Google Cloud KMS / EKM** —
ML-DSA, SLH-DSA and ML-KEM GA in Cloud KMS (July 2026). **Entrust
nShield, Utimaco** — PQ firmware updates 2025. Vendor-coordination
playbook: inventory HSM dependencies; identify the firmware version
with the algorithms you need; plan upgrade windows (HSMs require
scheduled-months-ahead maintenance); test in non-production first
(PQ workloads have different throughput, error codes, output sizes).

### 13.2 Cloud KMS PQ roadmaps

**AWS KMS** — ML-DSA signing keys available (June 2025);
CloudFront / CloudHSM integration rolling out. **Google
Cloud KMS** — ML-DSA, SLH-DSA and ML-KEM GA (July 2026). For
KMS-dependent SaaS, the migration is gated by the provider's
roadmap, not the SaaS team's own work.

### 13.3 The "wait for vendor X before migrating" coordination problem

Common pattern: TLS is ready but the application depends on a
vendor's signed-content distribution lacking PQ support. The
vendor's roadmap is 18 months out; the SaaS team's compliance
deadline is 12 months. Vendor-management work: inventory all vendors
with cryptographic touchpoints; survey public PQ roadmaps and chase
the silent ones; build contingency plans (proxy / wrapper layers)
for out-of-phase vendors; track wait-for-vendor dependencies in the
master schedule.

### 13.4 PQ test infrastructure

For end-to-end PQ testing: **Cloudflare PQ test endpoints**
(`pq.cloudflareresearch.com`) for any TLS client wanting to exercise
PQ negotiation against a known-good server. **Open Quantum
Safe** `oqs-demos` Docker containers (PQ-enabled OpenSSL, Apache,
nginx). **Cloudflare PQ tunnels telemetry**
(`pqtunnels.cloudflareresearch.com`) collects failure-mode data
useful for catching middlebox compatibility issues. Test endpoints
are how you catch "my network's middlebox eats PQ handshakes" before
production.

---

## 14. Compliance and audit trail

The compliance dimension is increasingly load-bearing as regulatory
frameworks update to incorporate PQ requirements.

### 14.1 FIPS 140-3 certification of PQ implementations

FIPS 140-3 is the U.S. federal crypto-module certification standard.
PQ algorithms are being added by amendment as FIPS 203/204/205 are
published. Status as of 2026: FIPS 140-3 modules with PQ
certification are rolling out from major HSM vendors (Thales, Entrust,
Utimaco) — module certification lags algorithm standardisation by
12-24 months. Software modules (OpenSSL FIPS provider, BoringSSL
FIPS module) are pursuing PQ-inclusive validation, with production
certifications expected 2026-2027. For organisations under FIPS 140-3
procurement requirements, the module's validation status is the
gating constraint, regardless of the algorithm's technical readiness.

### 14.2 CNSA 2.0 mandates

CNSA 2.0 (section 1) is the most-concrete PQ migration compliance
regime: 2027 — new NSS acquisitions must support CNSA 2.0; 2030 —
deployed NSS software/firmware must use CNSA 2.0 signatures; 2031 —
full enforcement; 2035 — all NSS fully quantum-resistant. For non-NSS
federal civilian agencies, NIST IR 8547 parallel: deprecated ~2030,
disallowed ~2035. For non-federal organisations, CNSA 2.0 / NIST IR
8547 set the cadence that procurement contracts, third-party risk
assessments, and cyber insurance underwriting will track.

### 14.3 EU CRA and NIS2 cryptography requirements

The EU Cyber Resilience Act (CRA) (in force since December 2024,
applicable from December 2027) includes Annex I essential
cybersecurity requirements touching cryptographic strength. The CRA
does not name PQ algorithms specifically but requires encryption by
"state of the art" mechanisms. NIS2 (transposed into EU member-state
law from 2024) has parallel critical-sector requirements with
national implementations varying in specificity. For
EU-market products, CRA + national NIS2 mirrors the CNSA 2.0
structure on a slightly later timeline.

### 14.4 CBOM in compliance reporting

CBOM (section 2.2) is increasingly requested in compliance audits as
structured evidence that a cryptographic inventory was performed.
Auditors are not yet universally CBOM-literate, but the trajectory
mirrors SBOM after EO 14028 (2021). Practical guidance: producing a
CBOM even when not asked positions the organisation ahead of the
audit-language curve and makes future audits cheaper.

### 14.5 Auditor expectations — CISA, PCI, SOC 2

**CISA / DHS quantum-readiness assessment** — federal contractors and
critical-infrastructure operators are increasingly asked to
demonstrate quantum-readiness in CISA reviews, with the
CISA / NSA / NIST quantum-readiness factsheet (August 2023) as the
assessor's reference. **SOC 2 Type 2** — auditors are starting to ask about
PQ migration plans under CC6; in 2026 this is "have a plan and
timeline," tightening to "show evidence of execution" over 2027-2030.

The compliance-readiness deliverable in 2026 is a written **PQ
Migration Plan** that includes: cryptographic inventory (CBOM);
risk-tier classification; per-tier target dates; vendor dependency
matrix; side-channel-hardening / library-selection policy; test
infrastructure and verification approach; compliance-mapping table
(CNSA 2.0 / NIST IR 8547 / CRA / etc.). This is both the auditor's
expected artifact and the technical team's execution document.
Cross-link to [[reference-supply-chain-provenance]] for CBOM / SBOM
compliance lineage and [[reference-appsec-program-building]] for the
program-building substrate.

---

## 15. Migration patterns and anti-patterns

Patterns that work: slow, disciplined. Anti-patterns: optimistic,
all-at-once.

### 15.1 Anti-pattern: "swap RSA for ML-DSA at midnight"

The all-at-once flip is the most common failure mode. It fails when
(1) downstream verifiers have not been updated and reject the new
signature, (2) HSM firmware does not yet support the algorithm, (3)
compliance reviewers demand migration evidence the team did not
prepare, (4) incident response is harder because the new signing
infrastructure has not been exercised under load. The correct pattern
is **hybrid-first, then disable classical, then exercise rotation**,
with months between steps and the hybrid period acting as a soak-test.

### 15.2 Pattern: hybrid-first, then disable classical

Canonical sequence: **Phase 0** inventory and plan (CBOM, risk tiers,
target windows, vendor dependencies); **Phase 1** enable hybrid where
supported (TLS X25519MLKEM768, SSH mlkem768x25519-sha256, hybrid JWT
alg) — risk-free, adds PQ without removing classical; **Phase 2**
measure and verify (telemetry on negotiated algorithms,
classical-only alerts); **Phase 3** enable PQ-preferred or
PQ-required where tolerable; **Phase 4** disable classical only after
Phase 3 soak shows reliable PQ negotiation; **Phase 5** exercise
rotation. 12-24 months per cryptographic context; multiple contexts
can run in parallel.

### 15.3 Anti-pattern: "wait for CNSA 2.0 deadline before starting"

"Start in 2029 to hit 2030" fails because inventory alone takes
months in a complex organisation, vendor coordination takes 12-24
months for long-tail deps, and hybrid-deployment soak takes 6-12
months. The "we are not government" pattern also fails: cyber
insurance, third-party risk reviews, customer procurement, and EU
CRA-derived national mandates close the deadline-free window over
2026-2028.

### 15.4 Pattern: workload-class migration windows

Cadence is per-workload-class, not per-org. **Tier 1** (long-lived
confidentiality) — start now (2026), hybrid by end-2027, classical
disabled by 2029. **Tier 2** (authentication-only) — opportunistic,
ride upstream defaults, expect classical off by 2030. **Tier 3**
(code signing) — hash-signature deployment by end-2026, dual-signing
through 2030. **Tier 4** (regulated) — track the specific deadline.

### 15.5 Pattern: ride the platform when you can

For most consumer SaaS and business-application contexts, **let the
platform vendor do the migration**. If the app uses TLS via the OS
library on iOS / Android / a browser, hybrid-PQ negotiation happens
automatically when the OS updates. The corollary: custom crypto
outside the platform defaults (application-layer signing, custom
binary protocols, custom token formats) is yours end-to-end. The
amount of custom crypto in a typical SaaS is usually larger than the
team realises — which is why the inventory phase matters.

### 15.6 Pattern: instrument before you migrate

Telemetry separates a controlled migration from a guessing exercise.
Capture per-handshake algorithm negotiation for every TLS / SSH /
protocol endpoint; per-signature and per-verification algorithm;
failure-mode counters for hybrid-negotiation failures, middlebox
fragmentation, algorithm-rejection. Cloudflare's pqtunnels endpoint
is a public example at scale; internally, structured logging plus
alerting on negotiation outcomes is sufficient.

### 15.7 Anti-pattern: skipping rotation rehearsal

Many organisations deploy PQ algorithms but never rotate the PQ
keys because rotation is a planned-quarterly exercise that gets
deferred. When a real algorithm-rotation event arrives (KyberSlash-
class emergency, faster-than-planned deprecation), the rotation
infrastructure has never been exercised and fails. Discipline:
rotate quarterly even when there is no operational reason. The
exercise is the value.

### 15.8 Anti-pattern: external "PQ consultant" without internal ownership

PQ migration is what consultants are best at supplementing and worst
at owning. An external team can do the inventory in 4 weeks vs 16,
but only the internal team can keep the inventory current after
they leave. Pattern that works: pair an external consultant with an
internal owner for inventory and plan phases, hand execution to the
internal team. Pattern that fails: consultant produces a beautiful
plan, presents to leadership, leaves, the plan goes unused. Cross-
link to [[reference-appsec-program-building]] for the people-substrate
framing.

---

## 16. References

**NIST and U.S. government.** FIPS 203 — ML-KEM
(https://csrc.nist.gov/pubs/fips/203/final). FIPS 204 — ML-DSA
(https://csrc.nist.gov/pubs/fips/204/final). FIPS 205 — SLH-DSA
(https://csrc.nist.gov/pubs/fips/205/final). NIST IR 8547 draft —
Transition to PQC Standards
(https://nvlpubs.nist.gov/nistpubs/ir/2024/NIST.IR.8547.ipd.pdf).
SP 800-208 — Stateful Hash-Based Signatures
(https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-208.pdf).
NIST PQC project home (https://csrc.nist.gov/projects/post-quantum-cryptography).
NCCoE PQC migration (https://www.nccoe.nist.gov/applied-cryptography/migration-to-pqc).
NSA CNSA 2.0 algorithms 2025
(https://media.defense.gov/2025/May/30/2003728741/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS.PDF)
and 2022 FAQ
(https://media.defense.gov/2022/Sep/07/2003071836/-1/-1/0/CSI_CNSA_2.0_FAQ_.PDF).
CISA Quantum-Readiness factsheet
(https://www.cisa.gov/resources-tools/resources/quantum-readiness-migration-post-quantum-cryptography).
CISA PQC inventory strategy
(https://www.cisa.gov/sites/default/files/2024-09/Strategy-for-Migrating-to-Automated-PQC-Discovery-and-Inventory-Tools.pdf).
CISA EO 14306 product categories
(https://www.cisa.gov/resources-tools/resources/product-categories-technologies-use-post-quantum-cryptography-standards).
GSA PQC Buyer's Guide 2025
(https://buy.gsa.gov/api/system/files/documents/final-508c-pqc_buyer-s_guide_2025.pdf).

**IETF.** RFC 8391 XMSS (https://datatracker.ietf.org/doc/html/rfc8391).
RFC 8554 LMS (https://datatracker.ietf.org/doc/html/rfc8554). RFC 9794
PQ/T terminology (https://www.rfc-editor.org/rfc/rfc9794.html). RFC
9802 HSS/XMSS X.509 (https://www.rfc-editor.org/rfc/rfc9802).
draft-josefsson-ntruprime-ssh
(https://www.ietf.org/archive/id/draft-josefsson-ntruprime-ssh-02.html).
draft-ietf-tls-hybrid-design
(https://www.ietf.org/archive/id/draft-ietf-tls-hybrid-design-16.html).

**Cloudflare deployment.** PQC overview
(https://developers.cloudflare.com/ssl/post-quantum-cryptography/). PQ
key agreement (https://pq.cloudflareresearch.com/). State of the
post-quantum Internet 2025 (https://blog.cloudflare.com/pq-2025/).
2029 roadmap (https://blog.cloudflare.com/post-quantum-roadmap/).
Auto-upgrade of 6M domains
(https://blog.cloudflare.com/automatically-secure/). Origin PQ
(https://blog.cloudflare.com/post-quantum-to-origins/). Bas
Westerbaan bio
(https://research.cloudflare.com/about/people/bas-westerbaan/) and
PQShield interview
(https://pqshield.com/publications/episode-1-inside-cloudflares-post-quantum-journey-bas-westerbaan-on-real-world-implementation/).

**Apple and Signal.** Apple PQ3 blog
(https://security.apple.com/blog/imessage-pq3/) and Stebila analysis
(https://security.apple.com/assets/files/Security_analysis_of_the_iMessage_PQ3_protocol_Stebila.pdf).
Formal PQ3 analysis (eprint 2024/1395,
https://eprint.iacr.org/2024/1395). Signal PQXDH spec
(https://signal.org/docs/specifications/pqxdh/) and blog
(https://signal.org/blog/pqxdh/). Signal SPQR / Triple Ratchet
(https://signal.org/blog/spqr/). Signal Double Ratchet
(https://signal.org/docs/specifications/doubleratchet/). Quarkslab
SPQR analysis
(https://blog.quarkslab.com/triple-threat-signals-ratchet-goes-post-quantum.html).
PQShield Signal PQ
(https://pqshield.com/diving-into-signals-new-pq-protocol/).

**Open Quantum Safe.** Site (https://openquantumsafe.org/). liboqs
(https://github.com/open-quantum-safe/liboqs). oqs-provider
(https://github.com/open-quantum-safe/oqs-provider). oqs-demos
(https://github.com/open-quantum-safe/oqs-demos). IBM Developer
quantum-safe OpenSSL tutorial
(https://developer.ibm.com/tutorials/awb-quantum-safe-openssl/).

**OpenSSH.** PQC page (https://www.openssh.org/pq.html). Release
notes (https://www.openssh.org/releasenotes.html). InfoQ on GitHub
PQ SSH
(https://www.infoq.com/news/2025/10/github-post-quantun-ssh-key/).
Ubuntu OpenSSH crypto config
(https://documentation.ubuntu.com/server/explanation/crypto/openssh-crypto-configuration/).

**CycloneDX / CBOM.** CBOM capability
(https://cyclonedx.org/capabilities/cbom/). v1.6 release
(https://cyclonedx.org/news/cyclonedx-v1.6-released/). OWASP CBOM
authoritative guide
(https://cyclonedx.org/guides/OWASP_CycloneDX-Authoritative-Guide-to-CBOM-en.pdf).
IBM CBOM (https://github.com/IBM/CBOM).

**Go ecosystem.** Valsorda mlkem768
(https://words.filippo.io/mlkem768/). 2025 Go Crypto SotU
(https://words.filippo.io/2025-state/). words.filippo.io
(https://words.filippo.io/). ECC-vs-Lattices long bet
(https://github.com/FiloSottile/ecc-vs-lattices-long-bet).

**Side-channel.** KyberSlash
(https://kannwischer.eu/papers/2024_kyberslash.pdf). PQShield Kyber
timing fix
(https://pqshield.com/pqshield-plugs-timing-leaks-in-kyber-ml-kem-to-improve-pqc-implementation-maturity/).
SPA-CCA on ML-KEM (eprint 2024/2051,
https://eprint.iacr.org/2024/2051.pdf). Cryspen verified ML-KEM in
Rust (https://cryspen.com/post/ml-kem-implementation/).

**HSM / KMS.** Thales Luna 7.9 PQC blog
(https://cpl.thalesgroup.com/blog/encryption/luna-hsm-pqc-quantum-safe-encryption)
and PQC FM docs
(https://www.thalesdocs.com/gphsm/integrations/guides/pqc/index.html).

**DNSSEC.** Verisign IETF Madrid PQ DNSSEC strategy
(https://www.verisign.com/assets/PQC_DNSSEC_IETF_Madrid.pdf) and blog
(https://blog.verisign.com/security/securing-the-dns-in-a-post-quantum-world-new-dnssec-algorithms-on-the-horizon/).
IETF draft-sheth-pqc-dnssec-strategy
(https://datatracker.ietf.org/doc/draft-sheth-pqc-dnssec-strategy/).
NIST PQ-diversity for DNSSEC
(https://csrc.nist.gov/csrc/media/presentations/2025/post-quantum-diversity-for-dnssec/post-quantum_diversity-harvey_1.15.pdf).

**Other.** NCSC on RFC 9794
(https://www.ncsc.gov.uk/blog-post/new-standard-for-post-quantum-terminology).
CSA on NIST IR 8547
(https://cloudsecurityalliance.org/blog/2025/03/20/nistir-8547-from-pqc-standards-to-real-world-implementations).
