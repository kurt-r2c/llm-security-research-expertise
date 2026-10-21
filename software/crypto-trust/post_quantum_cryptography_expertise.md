# Post-Quantum Cryptography — NIST PQC, Migration, and Hybrid Deployment

> **Scope.** This document is the dedicated post-quantum-cryptography (PQC) treatment in the
> expertise corpus. The parent [`cryptography_expertise.md`](cryptography_expertise.md) §11 covers
> the headline standards in capsule form; this file is the deep dive — the lattice / hash /
> code / isogeny taxonomy, the cryptanalytic history that disqualified one family, the migration
> playbook, side-channel hardening, and the "harvest now, decrypt later" threat model that makes
> 2026 the year to be deploying PQC rather than studying it.
>
> **Framework.** Synthesizes work from twelve researchers across four institutional families:
>
> - **Daniel J. Bernstein** (UIC; formerly TU Eindhoven) — SPHINCS+ co-author, NTRU Prime
>   designer, Curve25519, long-running advocate for conservative parameter choices and
>   verifiable curve generation.
> - **Tanja Lange** (TU Eindhoven) — chair of Coding Theory and Cryptology; Classic McEliece
>   co-author; long-running collaborator with Bernstein on
>   McEliece cryptanalysis (Bernstein-Lange-Peters 2008 attack).
> - **Vadim Lyubashevsky** (IBM Research Europe — Zurich) — co-designer of CRYSTALS-Dilithium
>   (now ML-DSA, FIPS 204) and CRYSTALS-Kyber (now ML-KEM, FIPS 203); principal architect of
>   the Fiat-Shamir-with-Aborts signature design that underpins Dilithium.
> - **Peter Schwabe** (Scientific Director, MPI-SP; part-time at Radboud) — co-author on three
>   of the four selected NIST PQC standards (Kyber, Dilithium, SPHINCS+); high-speed
>   constant-time implementations are his canonical contribution.
> - **Léo Ducas** (CWI Amsterdam; Professor of Mathematical Cryptology at Leiden) — co-designer
>   of Kyber and Dilithium; lattice-reduction cryptanalysis; "concrete-security
>   estimator" lineage.
> - **Joppe Bos** (NXP Semiconductors) — CRYSTALS-Kyber co-author; constrained-device PQC
>   implementation lead; technical lead of NXP's PQC team.
> - **Chris Peikert** (University of Michigan) — lattice-cryptography theorist; the 2008
>   Gentry-Peikert-Vaikuntanathan "hash-and-sign" paper directly underpins Falcon (FN-DSA); a
>   TCC Test-of-Time award recipient.
> - **Oded Regev** (NYU Courant) — proposed the **Learning With Errors** problem in 2005
>   ("On Lattices, Learning with Errors, Random Linear Codes, and Cryptography," STOC 2005);
>   2018 Gödel Prize; the foundation under all of ML-KEM, ML-DSA, FN-DSA.
> - **Andreas Hülsing** (TU Eindhoven) — XMSS (RFC 8391) and SPHINCS+ co-author; the
>   stateful/stateless hash-signature lineage.
> - **Ward Beullens** (IBM Research) — broke the **Rainbow** multivariate-quadratic signature
>   scheme in a weekend (CRYPTO 2022), a Round-3 NIST finalist; significant recent
>   cryptanalysis output on isogeny and code-based candidates.
> - **Wouter Castryck + Thomas Decru** (KU Leuven) — broke **SIDH/SIKE** in polynomial time
>   on a classical computer (July 2022, eprint 2022/975), terminating an entire PQC family.
> - **Lily Chen** (NIST Fellow; manager of NIST Cryptographic Technology Group) —
>   led the 8-year NIST PQC standardization project through FIPS 203/204/205 publication.
>
> Sources: NIST CSRC publications; FIPS 203/204/205 final standards; eprint.iacr.org
> archive; pq-crystals.org; openquantumsafe.org; sphincs.org; Signal PQXDH whitepaper; Apple
> security.apple.com PQ3 disclosure; Cloudflare Research; NSA CNSA 2.0 specification.

---

## 1. The Quantum Threat: Why PQC Now

### Shor's algorithm (1994)

Peter W. Shor's 1994 FOCS paper ("Algorithms for Quantum Computation: Discrete Logarithms and
Factoring"; expanded as 1997 SIAM J. Comp.) gave polynomial-time quantum algorithms for two
problems underpinning all deployed public-key cryptography:

1. **Integer factorization** — recovers p, q from n = pq in O((log n)^3) time. Breaks RSA at
   any key size; RSA-2048 vs RSA-4096 differs only by a constant factor on a CRQC.
2. **Discrete logarithm** — recovers x from g^x in any group with efficient operations.
   Breaks classical Diffie-Hellman, ECDH, ECDSA, EdDSA, BLS, Schnorr.

The algorithm's core is quantum period-finding via the QFT. Classical hardness rested on the
absence of any polynomial-time period-finder; quantum mechanics provides one.

**What survives:** symmetric primitives (AES, ChaCha20) and hashes (SHA-2/3, BLAKE3) are not
broken by Shor. **Grover's algorithm** (1996) gives a quadratic search speedup, halving
symmetric-key bit-security (AES-128 → 64 effective bits; AES-256 → 128). Post-Grover guidance:
double symmetric key lengths — AES-256 and SHA-384/SHA-512.

### CRQC and hardware reality

"CRQC" (Cryptographically Relevant Quantum Computer) is a fault-tolerant machine capable of
running Shor against RSA-2048 / ECC-256 in practical wall-clock time. Gidney/Ekerå
(arXiv:1905.09749) estimate ~6,200 logical qubits (3n + 0.002n lg n) for RSA-2048 — translating to ~20M physical
qubits via surface-code error correction. State of the art circa 2026:

- **IBM Heron R2** (Nov 2024): 156 physical qubits, 99.7% two-qubit gate fidelity. No
  demonstrated logical qubit outperforming physical qubits.
- **Google Willow** (Dec 2024): 105-qubit chip; first **below-threshold** quantum error
  correction on a distance-7 surface code, logical error rate 0.143% per cycle. One logical
  qubit, not the thousands needed for Shor.
- **IonQ Forte, Quantinuum H2** — trapped-ion, high-fidelity but smaller counts (~30-50).
- **Atom Computing, PsiQuantum, Microsoft Majorana-1** (Feb 2025) — alternative modalities;
  the Majorana topological-qubit claim has not been consensus-validated.

Expert surveys (Global Risk Institute Quantum Threat Timeline) cluster on 2030-2040 median
CRQC estimate, with significant tail risk both ways.

### Harvest Now, Decrypt Later (HNDL)

The threat model driving 2026 PQC deployment even with CRQC a decade+ out:

1. Capable adversary captures and stores encrypted traffic today.
2. Storage cost is petabytes/year — trivial at nation-state scale.
3. CRQC arrives; adversary decrypts stored traffic retroactively.

This makes PQC migration urgent for any data with 10+ year confidentiality lifetime:
classified communications, healthcare, financial transactions, genomic data, long-lived
corporate IP, regulated retention data.

**Asymmetry:** HNDL hits confidentiality, not authentication. A 2026 signature has no
HNDL exposure — its value expires when the operation completes. This drives the priority
order: hybrid key exchange first, signatures later.

### NSA CNSA 2.0 (September 2022): the U.S. government timeline

The NSA's Commercial National Security Algorithm Suite 2.0 sets the timeline for National
Security Systems (NSS):

| Year | Requirement |
|------|-------------|
| 2025 | Software/firmware signing and web browsers/servers/cloud services should support and prefer CNSA 2.0 |
| 2027 | All new NSS equipment acquisitions must be CNSA 2.0 compliant by default |
| 2030 | All deployed NSS software/firmware must use CNSA 2.0 signatures |
| 2031-2033 | Full enforcement across NSS; legacy systems retired or replaced |
| 2035 | All U.S. national security systems fully quantum-resistant (aligned with NSM-10) |

**CNSA 2.0 approved algorithms:** ML-KEM-1024, ML-DSA-87 (parameter set 5), AES-256,
SHA-384/SHA-512, LMS and XMSS (stateful hash-based) for firmware signing.

**Why CNSA 2.0 matters beyond NSS:** it sets a procurement floor for any vendor selling into
the U.S. government, and historically NIST/NSA cryptographic guidance has driven private-
sector practice on a ~3-5 year lag.

Cross-link: [`cryptography_expertise.md`](cryptography_expertise.md) §§4-5 (RSA, ECC — the
classical primitives being replaced); [`saml_federation_expertise.md`](saml_federation_expertise.md)
(federation signing primitives that need PQC migration).

---

## 2. The NIST PQC Standardization Process (2016-2024)

### Timeline

NIST's PQC standardization is the most thorough public cryptographic competition since
AES (1997-2001) and SHA-3 (2007-2012). Eight years, four rounds, dozens of submissions, and
substantial reshuffling along the way.

| Date | Event |
|------|-------|
| 2016 | NIST issues call for proposals; deadline November 2017 |
| 2017 | Round 1: 69 submissions accepted out of 82 received |
| Jan 2019 | Round 2: 26 candidates advance |
| Jul 2020 | Round 3: 7 finalists (4 KEM, 3 signatures) + 8 alternates |
| Jul 2022 | Round 3 selections announced: **Kyber** (KEM), **Dilithium** (signature), **Falcon** (signature), **SPHINCS+** (signature) |
| Jul 2022 | Round 4 KEM candidates: BIKE, Classic McEliece, HQC, SIKE |
| Jul 2022 | **SIDH/SIKE broken** by Castryck-Decru attack (eprint 2022/975) — see §6 |
| Aug 2023 | Draft FIPS 203/204/205 released for public comment |
| Aug 14, 2024 | **FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA) finalized and effective** |
| Oct 2024 | "Additional Digital Signatures" Round 1 → Round 2 announcement: 14 candidates (HAWK, MAYO, UOV, SQIsign, SNOVA, LESS, CROSS, FAEST, MQOM, PERK, Mirath, QR-UOV, RYDE, SDitH) |
| Mar 2025 | **HQC announced as 4th-round selection** — to become second standardized PQC KEM |
| 2025-2026 | FN-DSA (Falcon) draft FIPS 206 still in progress |
| May 2026 | Additional signatures Round 3: nine candidates advance (NIST IR 8610) |

Lily Chen, then-manager of the NIST Cryptographic Technology Group and now a NIST
Fellow, led the process.

### The four selected standards (FIPS 203/204/205 published August 2024)

#### FIPS 203 — ML-KEM (Module-Lattice-based Key Encapsulation Mechanism)

Formerly CRYSTALS-Kyber. Lattice-based KEM. Module Learning With Errors (MLWE) hardness.

| Parameter set | NIST security category | Public key | Ciphertext |
|---|---|---|---|
| ML-KEM-512 | 1 | 800 B | 768 B |
| ML-KEM-768 | 3 | 1184 B | 1088 B |
| ML-KEM-1024 | 5 | 1568 B | 1568 B |

ML-KEM-768 is the recommended general-purpose choice for hybrid TLS / Signal-class messaging /
SSH; ML-KEM-1024 is CNSA 2.0 mandated for NSS.

#### FIPS 204 — ML-DSA (Module-Lattice-based Digital Signature Algorithm)

Formerly CRYSTALS-Dilithium. Lattice signature. MLWE + Module Short Integer Solution (MSIS).
Uses Fiat-Shamir-with-Aborts construction. Three parameter sets:

| Parameter set | NIST level | Public key | Signature |
|---|---|---|---|
| ML-DSA-44 | 2 | 1312 B | 2420 B |
| ML-DSA-65 | 3 | 1952 B | 3309 B |
| ML-DSA-87 | 5 | 2592 B | 4627 B |

Compare Ed25519: 32 B public key, 64 B signature. ML-DSA is roughly 40-70× larger across both.

#### FIPS 205 — SLH-DSA (Stateless Hash-based DSA)

Formerly SPHINCS+. Pure hash-based signatures. Security rests **only** on hash-function
collision resistance — no algebraic structure to attack. The most conservative PQC choice.

Trade-off: signatures are large (8 KB to 50 KB depending on parameter set and `s`/`f`
sub-variant) and signing is slow (milliseconds). Recommended use cases: long-lived signatures
(firmware, code-signing root certificates, software releases where signature size matters less
than 30-year robustness).

#### FN-DSA (FIPS 206, draft) — Lattice signature with small signatures

Formerly FALCON. NTRU lattice + Gaussian sampling. Smaller signatures than ML-DSA
(~666 B at FALCON-512) but **much harder to implement safely** because Gaussian sampling
requires floating-point arithmetic with constant-time guarantees that subtle compiler choices
can break. FN-DSA is appropriate where signature size dominates; for everyone else, ML-DSA is
the safer pick.

Falcon's foundations trace directly to Gentry-Peikert-Vaikuntanathan (STOC 2008) — the
"hash-and-sign" lattice signature paradigm with trapdoor sampling. Peikert is one of the
listed researchers above.

### The "we need multiple backups" principle

The Castryck-Decru attack (August 2022) on SIKE — covered in detail in §6 — was the
defining lesson of the NIST PQC process: a Round-3 finalist with a decade of cryptanalytic
attention can fall to a polynomial-time classical attack overnight. The community response
was not "we got it wrong on SIKE" but "we should always have backup families across distinct
mathematical foundations."

Hence NIST's current four-pronged strategy:

1. **Lattice-based** (ML-KEM, ML-DSA, FN-DSA) — primary; well-understood; performant.
2. **Hash-based** (SLH-DSA, XMSS, LMS) — most conservative; only assumes hash security.
3. **Code-based** (HQC selected Mar 2025; Classic McEliece still under analysis) — independent
   mathematical foundation; large keys.
4. **Multivariate / other** (MAYO, UOV, SNOVA — Round 3 additional signatures) — backup
   family if lattices fall.

The on-ramp for additional signatures (nine Round-3 candidates as of May 2026) explicitly aims for diversity
across the mathematical foundations.

Cross-link: [`cryptography_expertise.md`](cryptography_expertise.md) §11 (capsule overview of
ML-KEM, ML-DSA, SLH-DSA, FN-DSA); §13 (crypto-agility and downgrade attacks).

---

## 3. Lattice-Based Cryptography: The Dominant Family

### LWE → Ring-LWE → Module-LWE

Lattice PQC traces to Oded Regev's 2005 STOC paper. The **Learning With Errors (LWE)**
problem: given samples (a_i, b_i = ⟨a_i, s⟩ + e_i mod q) with a_i uniform random in Z_q^n,
s fixed in Z_q^n, e_i small Gaussian noise, recover s.

Regev's worst-case-to-average-case reduction proves that average-case LWE is at least as hard
as worst-case GapSVP / SIVP on n-dimensional lattices under a quantum reduction. This is the
deepest result in lattice cryptography — breaking a random LWE instance is as hard as the
*hardest* lattice instance, a much stronger guarantee than factoring (some moduli weak) or
DLP (some groups weak).

**Ring-LWE** (Lyubashevsky-Peikert-Regev, Eurocrypt 2010) replaces vectors in Z_q^n with
polynomial-ring elements Z_q[X]/(X^n + 1). NTT-based multiplication runs in O(n log n);
hardness now rests on ideal-lattice SVP rather than general SVP — slightly weaker but robust.

**Module-LWE** (Langlois-Stehlé, DCC 2015) — vectors of polynomials. ML-KEM and ML-DSA both
use it because security level scales by adjusting module rank rather than polynomial degree,
enabling three parameter sets (44/65/87) from one fundamental design.

### CRYSTALS-Kyber → ML-KEM (FIPS 203)

Authors: Bos (NXP), Ducas (CWI), Kiltz (Ruhr-Bochum), Lepoint, Lyubashevsky (IBM), Schanck,
Schwabe (MPI-SP), Seiler (IBM), Stehlé (ENS de Lyon).

CCA-secure KEM built from a CPA-secure PKE via Fujisaki-Okamoto. The CPA-PKE is Module-LWE:

- Public key: matrix A ∈ R_q^{k×k} (derived from a seed via SHAKE-128) and t = As + e (s, e short).
- Encrypt: short r, e_1, e_2; ciphertext u = A^T r + e_1, v = t^T r + e_2 + ⌊q/2⌋·m.
- Decrypt: m ≈ v - s^T u; short noise cancels.

ML-KEM is competitive with ECC speed (ML-KEM-768 total keygen + encaps + decaps under 100 µs
on x86_64 AVX2). Public key and ciphertext are ~1 KB each — much larger than ECC's 32 bytes
but small enough for TLS handshakes.

### CRYSTALS-Dilithium → ML-DSA (FIPS 204)

Authors: Ducas, Kiltz, Lepoint, Lyubashevsky, Schwabe, Seiler, Stehlé.

**Fiat-Shamir with Aborts:**
1. Sample short masking vector **y** uniformly.
2. Compute commitment **w = Ay**, take high bits **w_1**.
3. Challenge **c = H(μ, w_1)** (μ = hash of pubkey and message).
4. Try response **z = y + cs_1** such that **z** is short and **w - cs_2** has recoverable
   high bits. **Abort and retry** if not.

The abort is critical for security (prevents z from leaking s_1) and a side-channel concern
(abort rate is secret-dependent; rejection-sampling timing leaks). Lyubashevsky's design
avoids the Gaussian sampling that plagues Falcon — all operations are small-range integer
arithmetic, constant-time-implementable with standard techniques.

### FN-DSA (Falcon, draft FIPS 206)

Authors: Fouque, Hoffstein, Kirchner, Lyubashevsky, Pornin, Prest, Ricosset, Seiler, Whyte,
Zhang.

Based on the NTRU lattice (Hoffstein-Pipher-Silverman 1996/1998) with Gaussian sampling
following the Gentry-Peikert-Vaikuntanathan "hash-and-sign" paradigm (STOC 2008).

**Gaussian sampling is the implementation trap:** the sampler must match the analyzed-secure
distribution without timing or value-dependent control flow that leaks the secret basis.
FIPS 206 prescribes the exact sampler to remove implementation ambiguity. Sizes: FALCON-512
— 897 B pubkey, 666 B signature; FALCON-1024 — 1793 B / 1280 B. Smaller than ML-DSA but
verification is more expensive. Trade case: DNSSEC, X.509 certificates where bandwidth is
constrained.

### NTRU Prime (not standardized)

Bernstein-Chuengsatiansup-Lange-van Vredendaal (eprint 2016/461). Alternative lattice
construction avoiding ring-structure concerns. OpenSSH used Streamlined NTRU Prime for
`sntrup761x25519` from version 9.0 (April 2022) through 10.0 (April 2025; replaced by
`mlkem768x25519-sha256`). Round-3 alternate; not selected but design choices influenced
subsequent work.

### Performance

On x86_64 AVX2 (pq-crystals.org benchmarks, in cycles): ML-KEM-768 keygen ~53K, encaps ~68K,
decaps ~53K (Haswell). Competitive with — often faster than — ECC. ML-DSA-65 (Dilithium3)
signing ~529K, verify ~179K (Skylake). Real-time-budget acceptable. Bandwidth (1-2 KB extra per
handshake) is the real cost, not CPU.

Cross-link: [`cryptography_expertise.md`](cryptography_expertise.md) §5 (ECC baseline being
replaced); [`hardware_side_channels_expertise.md`](hardware_side_channels_expertise.md) (timing
attacks on lattice arithmetic — see §10 below).

---

## 4. Hash-Based Signatures: The Conservative Family

Hash-based signatures rest on a single minimal assumption: collision-resistance (or for some
variants, only one-way + pseudorandom) of the underlying hash function. No number-theoretic
problem, no lattice, no algebraic structure to attack. If SHA-2/3 or BLAKE3 holds, the scheme
holds — and SHA-2 has weathered 20+ years of cryptanalysis. Trade-off: large signatures, slow
signing; stateful variants require strict state management since one-time-key reuse is
catastrophic (recovers the long-term key).

### Foundations: Lamport (1979) + Merkle (1979)

Lamport one-time signatures: for each message-hash bit, signer holds two preimages; pubkey is
their hashes; signature reveals the preimage matching the bit. Each key signs exactly one
message; reuse leaks preimages. Merkle trees combine 2^n Lamport keypairs into a tree whose
root is the pubkey; one root signs 2^n messages, but the signer must track used leaves.

### XMSS (RFC 8391, May 2018) and LMS (RFC 8554, April 2019)

**XMSS** authors: Andreas Hülsing (TU Eindhoven), Buchmann, Dahmen et al. Stateful — each
signature consumes one tree leaf; signer must track leaf index across crashes, reboots,
backups, replication. Reuse recovers the long-term key. Appropriate where state management is
strong: factory firmware-signing, audited HSM-backed code signing, bounded signing counts.

**LMS** (McGrew-Curcio-Fluhrer) — simpler stateful scheme optimized for throughput. NIST SP
800-208 approves both for firmware authentication; CNSA 2.0 mandates them for NSS firmware.

### SPHINCS+ → SLH-DSA (FIPS 205)

Authors: Bernstein (UIC), Hülsing (TU Eindhoven), Kölbl, Niederhagen, Rijneveld, Schwabe,
et al. Lineage: SPHINCS (Eurocrypt 2015) → SPHINCS+ (NIST submission) → SLH-DSA.

**Construction:** hypertree of XMSS+ trees + FORS (few-time signature) at leaves. The signer
pseudorandomly derives the leaf-signing key from a seed + message hash — no state to track.
Statelessness is the headline property.

**Cost:** signatures 8-50 KB; signing 1-50 ms; verify ≤ 10 ms.

| Parameter set | Pubkey | Signature |
|---|---:|---:|
| SLH-DSA-SHA2-128f | 32 B | 17,088 B |
| SLH-DSA-SHA2-128s | 32 B | 7,856 B |
| SLH-DSA-SHA2-192f | 48 B | 35,664 B |
| SLH-DSA-SHA2-256s | 64 B | 29,792 B |

`f`/`s` = fast-signing vs small-signature.

### Use cases

- **PQC root signing** — CA roots that sign intermediates rarely but verify billions. Signing
  latency irrelevant; 30-year-robust security matters.
- **Firmware signing** — XMSS / LMS with state discipline (CNSA 2.0 mandate).
- **PQC backup signing** — SLH-DSA alongside ML-DSA; if lattices fall, SLH-DSA validates.

**Not for:** high-throughput TLS / blockchain / document signing; replicated services with
fragile state-tracking; bandwidth-constrained protocols.

Cross-link: [`supply_chain_provenance_expertise.md`](supply_chain_provenance_expertise.md)
(hash-based for code signing); [`firmware_embedded_security.md`](firmware_embedded_security.md)
(XMSS / LMS for boot signing).

---

## 5. Code-Based Cryptography

### Classic McEliece (1978)

Robert McEliece's 1978 JPL Deep Space Network Progress Report introduced PKC based on Goppa
codes. Hardness: decoding random linear codes is NP-hard; decoding Goppa codes from a random
scrambling appears hard in average case.

- Secret: a binary Goppa code G + invertible S + permutation P.
- Public: G' = SGP — the "scrambled" generator matrix, appearing random.
- Encrypt: c = mG' + e (low-weight error e, matching Goppa correction capacity).
- Decrypt: apply P^-1, decode via Goppa, apply S^-1.

**The 48-year-old objection:** ~1 MB public key at NIST security level 5 (mceliece6688128).
Incompatible with TLS handshakes, X.509 certificates, anything bandwidth-sensitive.
Cryptanalytic status essentially unchanged in 48 years — Bernstein-Lange-Peters (2008)
polynomial-factor speedups still leave 2^{128}+ operations at recommended parameters. NIST has
declined to standardize it for now, citing skepticism that it will see widespread use given its
large public key (NIST IR 8545). Authors include Bernstein, Chou, Lange,
Misoczki, Niederhagen, Persichetti, Peters, Schwabe, Sendrier, Szefer, Wang.

### HQC (Hamming Quasi-Cyclic) — selected March 2025

Authors: Aguilar Melchor, Aragon, Bettaieb, Bidoux, Blazy, Bos, Deneuville, Gaborit,
Persichetti, Robert, Véron, Zémor.

NIST announced HQC as the second standardized PQC KEM in March 2025. Based on decoding in
quasi-cyclic codes — independent foundation from lattices. Sizes (HQC-128): pubkey 2249 B,
ciphertext 4433 B. Larger than ML-KEM, smaller than Classic McEliece. Final NIST publication
expected 2026-2027.

### BIKE

Round-4 candidate, quasi-cyclic codes with probabilistic decoder. Failure rates in
chosen-ciphertext-attack models + slower key generation lost to HQC. Not selected.

### Why code-based earns a NIST slot

Family diversity (lattice + hash + code) is the explicit lesson from the SIDH break (next
section). Code-based has independent attack surfaces and 50 years of cryptanalytic literature.
If lattices fall, HQC and Classic McEliece are immediate fallbacks.

Cross-link: [`cryptography_expertise.md`](cryptography_expertise.md) §12 (Another Look critique
— concrete security analysis).

---

## 6. Isogeny-Based Cryptography: The Family That Broke

### SIDH/SIKE

Jao-De Feo (2011). Supersingular Isogeny Diffie-Hellman: Alice walks 2-isogenies on
supersingular curves over F_{p^2}; Bob walks 3-isogenies; they publish endpoints + auxiliary
torsion-point images; reconstruct a shared curve whose j-invariant is the shared secret. The
NIST submission **SIKE** advanced to Round 4 in 2022 alongside Classic McEliece, BIKE, HQC.
The pitch: much smaller keys than lattices (a few hundred bytes).

### The Castryck-Decru attack (August 2022)

Castryck and Decru (KU Leuven ESAT/COSIC), "An Efficient Key Recovery Attack on SIDH"
(eprint 2022/975, July 30 2022). **SIKE broken in classical polynomial time.** The reference
Magma implementation breaks SIKEp434 (level 1) in ~10 minutes on a single 2.6 GHz core; the
Microsoft SIKE challenges $IKEp182 / $IKEp217 fell in 4 / 6 minutes respectively.

**Mathematics:** the attack exploits Ernst Kani's "glue-and-split" theorem (1997) plus tools
from Howe-Leprévost-Poonen (2000). The auxiliary torsion-point images Alice and Bob publish
turn out to be exactly the leverage needed to extract a secret isogeny via a genus-2 surface
construction. The attack relies on the *known endomorphism ring* of the starting curve —
which SIKE provides gratis.

NIST eliminated SIKE from Round 4. Castryck and Decru received Microsoft's $50K $IKEp217 challenge prize.

### Lessons

1. **A decade of attention is not enough.** SIDH had been studied since 2011; the breaking
   mathematics (Kani's theorem) had been published in 1997 and sitting unused.
2. **"Novel mathematics" is risk, not feature.** New problems have less cryptanalytic mileage;
   resilience-through-attention cuts both ways.
3. **Family diversity > absolute key-size optimization.** SIDH's keysize advantage was
   irrelevant the moment the scheme broke.
4. **Deploy lattice/hash/code primary.** Hold multivariate and isogeny-based in research-grade
   until multi-year cryptanalysis matures.

### SQIsign — under analysis

Authors: Basso, De Feo, Dartois, Leroux, Maino, Pope, Robert, Wesolowski. Signature scheme on
a different hardness assumption (endomorphism ring problem on supersingular curves); does NOT
share SIDH's auxiliary-point leak. Tiny pubkeys/sigs (sub-RSA-2048); hundreds-of-ms signing.
One of 14 Round-2 additional-signature candidates (October 2024). Has not yet survived the
cryptanalytic gauntlet ML-DSA did. Research-grade for deployment.

**Operating principle:** never deploy a single PQC family as your sole post-quantum defense.

Cross-link: [`cryptography_expertise.md`](cryptography_expertise.md) §6 (pairing-based, BLS —
also relies on supersingular curves but for pairing structure, not for SIDH-style isogeny
walks; pairings remain unbroken).

---

## 7. Hybrid Deployment: The Transition Pattern

### Why hybrid

"Hybrid" in PQC means combining a classical primitive (X25519, ECDH, ECDSA) with a PQC
primitive (ML-KEM, ML-DSA) such that an attacker must break **both** to compromise the
operation. This is the canonical transition strategy:

- **Risk of classical breaks:** Shor's algorithm (when CRQC arrives) breaks the classical side
  totally; the PQC side carries the load.
- **Risk of PQC breaks:** a Castryck-Decru-style discovery against ML-KEM (unlikely but
  possible — see §6 for why this is taken seriously); the classical side carries the load.
- **No regret:** so long as either primitive is unbroken, the hybrid scheme is secure. The
  cost is roughly the sum of the two primitives' bandwidth and CPU.

This is the cryptographic equivalent of a belt-and-suspenders argument, and it is the
unanimous current recommendation of the TLS WG, IETF, NIST (informally), and major deployers.

### Concrete hybrid constructions

**Hybrid KEM:** concatenate the two shared secrets, run the concatenation through a KDF
(HKDF-SHA256 typically) to derive the session key:

```
ss_hybrid = KDF(ss_classical || ss_PQC || context)
```

The order matters less than that both inputs are present and the KDF is collision-resistant.
**ChemPath:** TLS 1.3 derives the handshake_secret from the concatenated ECDHE+PQC output via
HKDF-Extract, in place of the (EC)DHE secret (draft-ietf-tls-hybrid-design).

**Hybrid signatures** are more contested:
- **Composite signatures** — sign with both, verify both must validate. Bandwidth-heavy
  (sum of two signature sizes).
- **Chained signatures** — outer-signs-inner construction. More compact but the failure mode
  is more subtle.
- **Concatenated** — emit both, verifier validates both. Simplest but no mutual binding.

The IETF lamps WG and NIST have been working on composite signature specifications through
2024-2025. Final guidance still emerging.

### TLS 1.3 hybrid: X25519MLKEM768

The TLS 1.3 hybrid named group `X25519MLKEM768` (IANA codepoint 0x11EC) combines:
- **X25519** — classical ECDH on Curve25519 (RFC 7748)
- **ML-KEM-768** — PQC KEM (FIPS 203)

Handshake flow:
1. Client sends X25519 ephemeral public key + ML-KEM-768 public key.
2. Server generates X25519 ephemeral, performs X25519(s, P) to get ss_classical.
3. Server encapsulates ML-KEM ciphertext, derives ss_PQC.
4. Both: shared_secret = ML-KEM_shared || X25519_shared.
5. handshake_secret = HKDF-Extract(shared_secret, early_secret).

Wire overhead: ~1184 B (ML-KEM-768 public key) + 1088 B (ML-KEM-768 ciphertext) per handshake,
on top of the 32 B X25519 keys. Roughly 2 KB extra in the handshake.

**Predecessor codepoint:** `X25519Kyber768Draft00` (codepoint 0x6399) used Kyber-round3 in
Chrome / Cloudflare's early experiments (2023). Replaced by the FIPS-203-final codepoint in
2024-2025; deprecation cycle ongoing.

### IKEv2 hybrid (RFC 9242, May 2022; RFC 9370, May 2023)

RFC 9370 specifies multiple key exchanges for IKEv2 via `IKE_INTERMEDIATE` exchanges (RFC 9242), each
contributing shared-secret material. Used in strongSwan, libreswan, Cisco IKEv2. WireGuard
has no native PQC as of 2026 — research-grade extensions only.

### SSH

- **OpenSSH 9.0 (April 2022):** `sntrup761x25519-sha512` enabled by default.
- **OpenSSH 9.9 (Sept 2024):** added `mlkem768x25519-sha256`.
- **OpenSSH 10.0 (April 2025):** `mlkem768x25519-sha256` becomes default.

GitHub added post-quantum SSH September 2025; GitLab followed.

### Cloudflare / Chrome adoption

Cloudflare research blog (`blog.cloudflare.com/pq-2025/`): March 2025 — 1/3 of human-web TLS
to Cloudflare is hybrid; late October 2025 — over 50%. Cloudflare-to-origin support: 3.7% in
2025, rising slowly. Chrome enabled hybrid X25519Kyber768 by default on desktop in Chrome 124 (April 2024),
switching to `X25519MLKEM768` in Chrome 131. Firefox followed late 2024.

### Performance overhead

Hybrid adds ~5-10% handshake CPU and 1-2 KB bandwidth. Public-internet TLS: acceptable.
High-frequency mesh-TLS: connection reuse and session resumption matter more. Long-lived
connections (replication, streaming): handshake amortizes to ~zero per transaction.

Cross-link: [`http_web_security.md`](http_web_security.md) (TLS handshake structure);
[`dns_network_infrastructure.md`](dns_network_infrastructure.md) (DNSSEC PQC migration —
RR size limits are a real protocol-level obstacle).

---

## 8. Real Deployments and Migration Progress

### Signal PQXDH (September 2023)

Whitepaper: Kret-Schmidt, "The PQXDH Key Agreement Protocol." X3DH extended with a
CRYSTALS-Kyber KEM step. Each prekey bundle adds a Kyber prekey; session key is HKDF(X3DH
output || Kyber shared secret). Signal chose Kyber-1024 (highest parameter set). Deployed
September 2023 using round-3 Kyber spec. Bhargavan et
al. (USENIX Security 2024) formally verified the protocol. Tens of millions of users — one of
the first PQC secure-messaging deployments at this scale.

### Apple PQ3 (February 2024)

Apple Security Research blog, Feb 21 2024. Goes beyond PQXDH with a "Level 3" claim:
- Level 1: default end-to-end encryption, no quantum security.
- Level 2: PQC in initial key establishment only (PQXDH).
- Level 3: PQC in initial key establishment **and ongoing message exchange (periodic post-quantum rekeying)**.

Rekeying is the differentiator: if PQC session keys are compromised, the next rekey restores
forward security. Bounds HNDL exposure to the rekey period (~every 50 messages, at most 7 days). Algorithm: Kyber-1024 (initial key establishment) and Kyber-768 (rekeying),
hybridized with classical ECC. Rollout: iOS 17.4 / iPadOS 17.4 / macOS 14.4 /
watchOS 10.4 (March 2024 GA); hard cutover during 2024. Linker et al. (USENIX Security 2025)
provide a formal proof.

### WhatsApp

Research ongoing; no production PQC as of early 2026. Built on Signal Protocol, so the path is
PQXDH-equivalent; timeline opaque.

### TLS 1.3 in the wild

| Deployer | Status | Algorithm |
|---|---|---|
| Cloudflare | Over 50% of human traffic (late Oct 2025) | X25519MLKEM768 |
| Chrome / Chromium | Default since Chrome 124 (April 2024) | X25519MLKEM768 (formerly X25519Kyber768) |
| Firefox | Default since v132 (Oct 2024) | X25519MLKEM768 |
| Edge | Inherits Chromium | X25519MLKEM768 |
| Apple (URLSession / Network framework) | Default since iOS 26 / iPadOS 26 | X25519MLKEM768 |
| AWS s2n | Available since 2019 | Multiple hybrids |
| Google ALTS | Internal hybrid deployment since 2022 | NTRU-HRSS+X25519; later ML-KEM |
| OpenSSL 3.5+ | Native ML-KEM hybrid support | X25519MLKEM768 |
| BoringSSL | Native; production at Google scale | X25519MLKEM768 |
| Microsoft SymCrypt | ML-KEM, ML-DSA, XMSS (SLH-DSA being added) | FIPS 203/204 |

Note that **server-side support lags client-side**. Browsers all support hybrid TLS, but only
sites behind Cloudflare or AWS (or self-hosted with OpenSSL 3.5+) actually negotiate it. The
non-PQC server is the bottleneck for most enterprise deployments.

### Code signing / firmware

NIST SP 800-208 (Oct 2020) approves XMSS and LMS for firmware signing; CNSA 2.0 mandates them
for NSS firmware. Linux kernel ML-DSA module-signing patches posted (2025-2026).
Microsoft SymCrypt supports ML-KEM, ML-DSA, LMS, and XMSS (no SLH-DSA in its changelog). Sigstore/cosign in-flight,
bounded by OCI image-signing spec updates.

Cross-link: [`supply_chain_provenance_expertise.md`](supply_chain_provenance_expertise.md)
(code signing migration); [`firmware_embedded_security.md`](firmware_embedded_security.md)
(LMS/XMSS for firmware).

---

## 9. PQC Implementations and Tooling

**liboqs** (`openquantumsafe.org`) — C library with uniform API for PQC primitives.
v0.14.0 (2025) supports KEMs (ML-KEM, Kyber, BIKE, Classic McEliece, FrodoKEM, HQC,
NTRU-Prime) and signatures (ML-DSA, SLH-DSA, Dilithium, Falcon, LMS, XMSS, plus Round-2:
CROSS, MAYO, SNOVA, UOV). Provider integrations for OpenSSL (`oqs-provider`) plus Python /
Go / Java / Rust / C++ bindings. Community-maintained; implementations from candidate teams
via PQClean.

**Reference implementations** (canonical sources):
- `pq-crystals/kyber` and `pq-crystals/dilithium` (Schwabe et al.) — C and AVX2.
- `sphincs/sphincsplus` (Bernstein-Hülsing-Schwabe et al.).
- `falcon-sign.info` (Thomas Prest et al.).

**Formally verified:**
- `mlkem-native` (PQ Code Package / Post-Quantum Cryptography Alliance) — ML-KEM in C90;
  C code proved memory- and type-safe with CBMC; AArch64/x86_64 assembly proved functionally
  correct and constant-time with HOL-Light.
- `libcrux` (Cryspen) — verified ML-KEM, Ed25519, others.
- HACL\* (INRIA / Microsoft) — verified C.

**Other production libraries:**
- Cloudflare CIRCL (Go) — ML-KEM, ML-DSA, SLH-DSA; production at Cloudflare.
- RustCrypto `KEMs` and `signatures` — community-maintained Rust.
- Bouncy Castle (Java) — all four FIPS standards; heavier API than RustCrypto-style.

**Hardware acceleration.** NTT and modular arithmetic benefit from SIMD: AVX2/AVX-512 give
5-10× over scalar; ARM NEON/SVE similar; RISC-V Vector experimental in PQClean. PQC ASICs/
FPGAs in development at Microsoft, AWS, NXP, Infineon. **SIMD constant-time care:** KyberSlash (§10) exploited variable-time division specifically.

Cross-link: [`hardware_side_channels_expertise.md`](hardware_side_channels_expertise.md)
(SIMD timing characteristics; data-dependent instruction timing).

---

## 10. Side-Channels in PQC

### Why PQC is more side-channel-fragile than classical

1. **Newer implementations.** Classical ECC has 30 years of constant-time hardening; PQC has
   5-10. Easy attacker wins still on the table.
2. **Rejection sampling.** Dilithium (Fiat-Shamir-with-Aborts) and Falcon (Gaussian) retry
   until a sample meets a condition; retry count is secret-dependent if naively implemented.
3. **Polynomial arithmetic.** Modular reductions (Barrett, Montgomery) and NTT have
   variable-time variants that leak.

### KyberSlash (2024)

Bernstein et al., eprint 2024/1049, June 2024. The Kyber reference `poly_tomsg` (KyberSlash1) and
`poly_compress`/`polyvec_compress` (KyberSlash2) functions used variable-time integer division
by q (q = 3329). Compilers emitted a
`DIV` instruction whose latency depends on the dividend value.

**Attack:** demonstrated on Raspberry Pi 2 (Arm Cortex-A7) and Arm Cortex-M4; secret keys
reliably recovered within minutes for KyberSlash2 and a few hours for KyberSlash1.

**Affected:** Kyber reference, Cloudflare CIRCL, Signal (during Kyber-round-3
phase). Reference patched December 1, 2023.

**Lesson:** the canonical `pq-crystals/kyber` repository carried the non-constant-time
division for the entire NIST evaluation period; Cryspen's formal-verification work surfaced
it. Code review is not sufficient — implementations need formal verification or
symbolic-execution analysis for constant-time properties.

### Hertzbleed against ML-DSA

Wang-Paccagnella-He-Shacham-Fletcher-Kohlbrenner, USENIX Security 2022. Intel/AMD DVFS reacts
to power consumption; frequency variation is observable via remote network timing. Applied to
ML-DSA: the rejection-sampling abort rate is secret-dependent; Hertzbleed-style observation
can in principle leak partial secret bits. Defense: disable DVFS for signing (Linux:
`cpufreq-set -g performance`) or run on fixed-frequency cores. HSMs inherently dodge this.

### Fault injection

Plundervolt (Murdock et al., 2020) and similar: undervoltage faults corrupt computations in
SGX. On ML-DSA, a fault during commitment computation produces a signature consistent with a
different nonce, leaking key info (analogous to ECDSA differential fault attacks). Defenses:
sign-then-verify before output; redundant critical-path computation; platform attestation for
undervoltage/glitch detection.

### Power analysis (DPA)

Exploits power consumption of NTT butterflies and modular multiplications. Demonstrated on
Kyber (Primas-Pessl-Mangard CHES 2017; Pessl-Primas LATINCRYPT 2019) and Dilithium
(Steffen-Land-Kogelheide-Güneysu PQCrypto 2023). Defenses: masking (secret-sharing operations), hiding
(random scheduling, dummy ops), hardware countermeasures. Production HSMs/smart cards apply
multiple layers.

### Deployment guidance

1. **Use formally verified implementations where available** (mlkem-native, libcrux, HACL\*).
2. **Dilithium:** prefer Schwabe's reference; review abort-rejection loop in vendor variants.
3. **Falcon:** defer to specialists. Gaussian sampling is notoriously fragile. Do not
   implement yourself.
4. **SLH-DSA's side-channel surface is minimal** — pure hash ops, no rejection sampling, no
   algebraic structure. Underrated advantage.

Cross-link: [`hardware_side_channels_expertise.md`](hardware_side_channels_expertise.md)
(Hertzbleed, Plundervolt, microarchitectural attacks).

---

## 11. PQC for Specific Use Cases

**TLS / HTTPS.** X25519MLKEM768 hybrid; ML-DSA-65 (or hybrid Ed25519+ML-DSA-65) for server
certs once the CA ecosystem catches up (DigiCert, Sectigo, Let's Encrypt have PQC roadmaps).
Handshake bandwidth +1-2 KB. Maintain classical-group advertisement for fallback but prefer
hybrid.

**SSH.** `mlkem768x25519-sha256` (OpenSSH 9.9+) preferred; `sntrup761x25519-sha512` for
backward compat. Disable non-hybrid classical KEX once population supports hybrid.

**Code signing / firmware.** Long-lived roots → SLH-DSA or XMSS (stateful conservative).
Intermediate/leaf certs → ML-DSA, optionally hybridized with RSA/ECDSA during transition.
NSS firmware → XMSS / LMS (CNSA 2.0 mandate; state discipline required).

**Document signing (PDF, PAdES).** ML-DSA-65. Hybrid composite signatures in flight.

**Mobile messaging.** Reference designs: Signal PQXDH, Apple PQ3. New protocols should clone
PQ3 Level-3 (periodic post-quantum rekeying), not just PQXDH's one-time hybrid.

**Cryptocurrency.** Hardest migration. Wallet addresses are hashes of public keys; upgrading
the signature scheme breaks every wallet. Paths: account abstraction (ERC-4337) for per-account
choice; one-shot migration windows (coordination-hard); PQC-from-genesis alternatives. BTC's
BIP-360 explores SLH-DSA as a Taproot-style upgrade. Multi-decade runway against CRQC, but
technical work needs to start now. Cross-link:
[`smart_contract_evm_security_expertise.md`](smart_contract_evm_security_expertise.md).

**Smart cards / HSMs.** Constraint: 8-256 KB RAM, 32-512 KB code, no SIMD. ML-KEM fits
barely; ML-DSA-44 marginal; SLH-DSA often doesn't fit. Falcon's FP-Gaussian needs FPU. Vendor
solutions: Entrust nShield HSM (ML-KEM, ML-DSA, SLH-DSA).

**Confidential computing / TEE attestation.** SGX, SEV-SNP, TDX, ARM CCA, AWS Nitro sign with
RSA-3072 or ECDSA platform keys. Migration: ML-DSA platform keys in new silicon (2026-2030);
hybrid during transition. Long tail: hardware-rooted keys cannot be rotated post-fab.
Cross-link: [`confidential_computing_expertise.md`](confidential_computing_expertise.md).

**IoT / constrained TLS.** Cortex-M0/M4 with 64 KB RAM, no FPU, no SIMD. ML-KEM-512 *barely*
fits; ML-DSA-44 feasible but expensive; SLH-DSA-128f (17 KB sigs) usually too large for MQTT.
Pragmatic stack: ML-KEM-512 for KEX, ML-DSA-44 for occasional device attestation, classical
Ed25519 for per-message signing where device lifetime is 5-10 years (bounded HNDL).
Cross-link: [`rtos_embedded_os_expertise.md`](rtos_embedded_os_expertise.md).

**Agentic web / capability tokens.** Short-lived tokens (minutes-hours) — HNDL irrelevant on
the payload, but the signing key must be CRQC-safe over the agent ecosystem's lifetime.
ML-DSA-65 signatures + hybrid PQC TLS. Cross-link:
[`agentic_web_capabilities_expertise.md`](agentic_web_capabilities_expertise.md).

---

## 12. Migration Challenges

The algorithms are the easy part. Operational migration is where organizations struggle.

**Discovery — where is your crypto?** Most organizations don't know where classical PKC is
deployed: application TLS endpoints, server-to-server VPNs, storage encryption (RSA-wrapped
DEKs), database TLS, replication, backups, code-signing cert chains, signed configurations
(Helm, OCI images), HTTPS clients with hardcoded TLS configs, IoT/firmware in 20-year
deployments, mobile cert pinning, hardware tokens/TPMs/HSMs with baked-in keys. Tooling:
crypto-bill-of-materials (CBOM) via CycloneDX extension; IBM CBOMkit; NIST NCCoE
crypto-agility playbook.

**Crypto-agility — can you swap algorithms without rewriting?** Anti-patterns: hardcoded
key sizes, hardcoded curve names, wire formats without algorithm-identifier bytes,
single-algorithm KDFs. Right patterns: algorithm-identifier prefixes everywhere (JOSE `alg`,
PKCS#7 OID, COSE codepoint, TLS named-group), KDF context binding to algorithm ID,
composite-signature formats (draft-ietf-lamps-pq-composite-sigs).

**Performance budgets.** Most apps tolerate. Edge cases: DNSSEC (3 KB ML-DSA vs 512-byte
EDNS RR — genuinely hard, RFC drafts exploring algorithm rollover and size amendments); HFT
(~50 µs ML-KEM vs ECDH may exceed latency budget — amortize via long-lived sessions);
real-time gaming/voip (initial bandwidth-bursty acceptable; steady-state AEAD unaffected).

**Storage.** PQC keys 5-100× larger. Backup, escrow, TPM/TEE storage all hit harder.

**Protocol limits.** DNSSEC (RR-size); EAP-TLS (RADIUS-frame fragmentation); SS7/T1
telephony (no realistic PQC path); OCSP responses (size budget tight).

**Vendor coordination.** Every layer must ship. Browser ↔ load balancer ↔ web server ↔ app
↔ DB. Any link without hybrid support falls back to classical. As of 2026: OpenSSL 3.5+,
BoringSSL, GnuTLS, SymCrypt, NSS all support X25519MLKEM768; older RHEL/Ubuntu and appliances
lag.

**CNSA 2.0 timeline (NSS):** 2025 support-and-prefer CNSA 2.0 for software/firmware signing, 2027 acquisitions
compliant, 2030 deployed firmware/signatures, 2035 full quantum-resistance. Commercial:
HHS/FDA/FDIC/SEC PQC guidance expected 2026-2028 with effective dates early 2030s.

Cross-link: [`appsec_program_building_expertise.md`](appsec_program_building_expertise.md)
(CBOM as program metric); [`supply_chain_provenance_expertise.md`](supply_chain_provenance_expertise.md)
(SBOM / SLSA / signing-chain inventory).

---

## 13. Cryptographic Agility: The Meta-Requirement

**"Don't bet on Kyber being the FINAL answer."** The Castryck-Decru SIKE break is fresh
enough that the community remembers a NIST fourth-round candidate falling. ML-KEM is unlikely to be
broken catastrophically — its hardness assumption is older and more studied than SIDH's — but
no specific primitive lasts 50 years guaranteed. RSA has lasted 50; DES lasted 25 before
Moore's law; SHA-1 lasted 20. **Crypto-agility is the engineering response to finite primitive
lifetimes.**

**Concrete patterns:**
- Per-message algorithm negotiation. Algorithm-identifier in every serialized object (JOSE
  `alg`, TLS named-group, COSE codepoint, PKCS#7 OID).
- Protocol-version negotiation with SCSV-style downgrade signaling.
- Hybrid as default during transition (§7).
- KDF context binds the algorithm choice:
  `session_key = HKDF(ss_hybrid, info = "TLS 1.3 X25519MLKEM768 application_data" || transcript)`.

**When agility goes wrong: downgrade attacks.** FREAK forced TLS to RSA-512 export; Logjam
forced 512-bit DH. The lesson: allow negotiation but disallow algorithms that should never be
negotiated. TLS 1.3 prunes to "currently safe" — no downgrade path. For PQC: drop pure
classical groups from negotiation once hybrid is universal, then move to PQC-only as classical
ages out.

**Designing for the next break:**
1. Algorithm identifiers everywhere — plumb new algorithms by adding identifiers, not by
   rewriting parsing code.
2. Hybrid signatures as architectural default — backup signature in a different family;
   graceful degradation when one falls.
3. Key-rotation infrastructure — assume you'll want short-notice retirement (days, not years).
4. Cryptographic governance — algorithm list as security policy, owned by a named team,
   fixed-cadence review, escalation path for new breaks.

Cross-link: [`cryptography_expertise.md`](cryptography_expertise.md) §13 (Dual_EC_DRBG and
the broader Schneier-on-Security framing of agility-as-policy).

---

## 14. Variant Analysis: Under-Explored Territory

Necessarily speculative; mostly active research.

**ZK proof systems.** STARKs are already PQC (hash-only via FRI + Fiat-Shamir over Merkle).
SNARKs (Groth16, PLONK, Halo2) use pairings or KZG on elliptic curves — broken by Shor.
Bulletproofs use DLP — broken. Migration: lattice-based ZK is emerging (Lyubashevsky-Nguyen-
Plançon CRYPTO 2022); production 2-5 years out. **Recommendation:** new PQC-requiring ZK
systems → STARKs. Size-critical → SNARKs with planned migration. Cross-link:
[`privacy_engineering_expertise.md`](privacy_engineering_expertise.md) §8.

**Blockchain consensus.** Ethereum's BLS-on-BLS12-381 broken by Shor. Paths: hybrid BLS +
ML-DSA aggregation; lattice aggregate signatures; account abstraction (ERC-4337) for per-account PQC choice. Cross-link:
[`smart_contract_evm_security_expertise.md`](smart_contract_evm_security_expertise.md).

**TEE attestation.** SGX/SEV-SNP/TDX/CCA platform keys are RSA-3072 or ECDSA. Migration:
new silicon ships with ML-DSA 2025-2030; legacy ages out 2030-2040. Hardware-rooted keys
can't be rotated post-fab — long tail of non-PQC hardware. Cross-link:
[`confidential_computing_expertise.md`](confidential_computing_expertise.md).

**AI model signing.** LLM weights, training data, in-toto attestations currently use Ed25519
/ RSA-PSS. Migration: ML-DSA-65 or hybrid Ed25519+ML-DSA. Model artifacts are GB-scale —
KB-level signature overhead is negligible. Cross-link:
[`supply_chain_provenance_expertise.md`](supply_chain_provenance_expertise.md).

**QKD vs PQC.** QKD (BB84, E91) is NOT a substitute for PQC: requires dedicated quantum
channel (no public-internet path); only does key exchange (no signatures/auth); still needs
classical channel authentication; expensive hardware. Narrow specialty use cases
(point-to-point gov-to-gov links). CNSA 2.0 explicitly de-emphasizes QKD in favor of PQC. The
geopolitical split (China/EU invested in QKD; US prioritized PQC) is real; both can coexist
for different threat models.

**Hybrid quantum-classical schemes.** Quantum-assisted PQC (QKD-derived seeds); quantum RNGs
as entropy injection; quantum-secure MPC. Research-grade as of 2026.

**Agent ecosystems.** Capability tokens are short-lived (no HNDL on payload) but signing
keys must be CRQC-safe over agent lifecycle. ML-DSA-65 signing + hybrid X25519MLKEM768 TLS.
Long-term agent identity certs: ML-DSA + hybrid Ed25519 transition → pure ML-DSA by 2030.
Cross-link: [`agentic_web_capabilities_expertise.md`](agentic_web_capabilities_expertise.md).

---

## 15. References

### NIST PQC core documents
- FIPS 203 (ML-KEM), final: https://csrc.nist.gov/pubs/fips/203/final
- FIPS 204 (ML-DSA), final: https://csrc.nist.gov/pubs/fips/204/final
- FIPS 205 (SLH-DSA), final: https://csrc.nist.gov/pubs/fips/205/final
- FIPS 206 (FN-DSA / Falcon) draft: https://csrc.nist.gov/projects/post-quantum-cryptography
- NIST PQC project site: https://csrc.nist.gov/projects/post-quantum-cryptography
- NIST PQC dig-sig project (additional signatures): https://csrc.nist.gov/projects/pqc-dig-sig
- NIST IR 8528 (Round 1 status, Oct 2024): https://csrc.nist.gov/pubs/ir/8528/final
- NIST SP 800-208 (XMSS/LMS stateful hash-based): https://csrc.nist.gov/publications/detail/sp/800-208/final
- NIST HQC announcement (Mar 2025): https://csrc.nist.gov/news/2025/hqc-announced-as-a-4th-round-selection
- Federal Register notice (Aug 14, 2024): https://www.federalregister.gov/documents/2024/08/14/2024-17956

### Foundational papers
- Shor, "Polynomial-Time Algorithms for Prime Factorization and Discrete Logarithms on a
  Quantum Computer," SIAM J. Comp. 1997 (preprint: quant-ph/9508027): https://arxiv.org/abs/quant-ph/9508027
- Regev, "On Lattices, Learning with Errors, Random Linear Codes, and Cryptography," STOC
  2005 / J. ACM 2009: https://cims.nyu.edu/~regev/papers/qcrypto.pdf
- Gidney-Ekerå, "How to factor 2048 bit RSA integers in 8 hours using 20 million noisy
  qubits," arXiv:1905.09749: https://arxiv.org/abs/1905.09749
- Castryck-Decru, "An Efficient Key Recovery Attack on SIDH," eprint 2022/975 (Jul 2022):
  https://eprint.iacr.org/2022/975
- McEliece, "A Public-Key Cryptosystem Based on Algebraic Coding Theory," JPL DSN Progress
  Report 42-44 (1978).

### Algorithm-specific resources
- pq-crystals.org (Kyber, Dilithium reference implementations): https://pq-crystals.org/
- SPHINCS+ project: https://sphincs.org/
- NTRU Prime: https://ntruprime.cr.yp.to/
- Falcon reference (Thomas Prest): https://falcon-sign.info/
- Classic McEliece NIST submission: https://classic.mceliece.org/

### Migration timelines and policy
- White House NSM-10 (May 2022): https://www.whitehouse.gov/briefing-room/statements-releases/2022/05/04/national-security-memorandum-on-promoting-united-states-leadership-in-quantum-computing-while-mitigating-risks-to-vulnerable-cryptographic-systems/
- NIST NCCoE Migration to PQC project: https://www.nccoe.nist.gov/projects/migration-post-quantum-cryptography

### Deployments
- Signal PQXDH whitepaper (Kret-Schmidt): https://signal.org/docs/specifications/pqxdh/pqxdh.pdf
- Signal PQXDH blog announcement: https://signal.org/blog/pqxdh/
- Apple iMessage PQ3: https://security.apple.com/blog/imessage-pq3/
- Cloudflare State of Post-Quantum Internet 2025: https://blog.cloudflare.com/pq-2025/
- Cloudflare research home: https://pq.cloudflareresearch.com/
- OpenSSH PQC notes: https://www.openssh.org/pq.html

### Tooling
- Open Quantum Safe (liboqs): https://openquantumsafe.org/
- liboqs GitHub: https://github.com/open-quantum-safe/liboqs
- oqs-provider for OpenSSL: https://github.com/open-quantum-safe/oqs-provider
- Cloudflare CIRCL (Go): https://github.com/cloudflare/circl
- Cryspen libcrux ML-KEM (formally verified Rust): https://cryspen.com/post/ml-kem-implementation/
- HACL\* verified cryptography (INRIA/Microsoft): https://hacl-star.github.io/
- PQClean reference implementations: https://github.com/PQClean/PQClean
- Bouncy Castle PQC (Java): https://www.bouncycastle.org/

### Side-channel papers
- KyberSlash (Bernstein et al.), eprint 2024/1049: https://eprint.iacr.org/2024/1049
- Hertzbleed (Wang et al.), USENIX Security 2022: https://www.hertzbleed.com/
- Pessl-Primas, "More Practical Single-Trace Attacks on the Number Theoretic Transform,"
  LATINCRYPT 2019.

### Protocol drafts and RFCs
- RFC 8391 (XMSS — eXtended Merkle Signature Scheme): https://datatracker.ietf.org/doc/html/rfc8391
- RFC 8554 (LMS Hash-Based Signatures): https://datatracker.ietf.org/doc/html/rfc8554
- RFC 9242 (Intermediate Exchange in IKEv2 — used for IKEv2 PQC hybrid): https://datatracker.ietf.org/doc/html/rfc9242
- draft-ietf-tls-hybrid-design (TLS 1.3 hybrid key exchange): https://datatracker.ietf.org/doc/draft-ietf-tls-hybrid-design/
- draft-ietf-tls-ecdhe-mlkem (X25519MLKEM768 in TLS 1.3): https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/
- draft-ietf-lamps-pq-composite-sigs (Composite ML-DSA certificate formats — IETF lamps WG, in progress).

### Researcher home pages (canonical bio sources)
- Daniel J. Bernstein: https://cr.yp.to/
- Tanja Lange: https://hyperelliptic.org/tanja/
- Vadim Lyubashevsky: https://vadimlyubash.github.io/
- Peter Schwabe: https://cryptojedi.org/peter/
- Léo Ducas: https://homepages.cwi.nl/~ducas/
- Joppe Bos: https://www.joppebos.com/
- Chris Peikert: https://web.eecs.umich.edu/~cpeikert/
- Oded Regev: https://cims.nyu.edu/~regev/
- Andreas Hülsing: https://huelsing.net/
- Wouter Castryck: https://homes.esat.kuleuven.be/~wcastryc/
- Lily Chen (NIST): https://www.nist.gov/people/lily-chen

### Cross-references in this expertise corpus
- [`cryptography_expertise.md`](cryptography_expertise.md) — classical cryptography (RSA, ECC,
  AES, hash functions) being supplemented and eventually replaced.
- [`hardware_side_channels_expertise.md`](hardware_side_channels_expertise.md) — side-channel
  primer; KyberSlash, Hertzbleed, Plundervolt in detail.
- [`confidential_computing_expertise.md`](confidential_computing_expertise.md) — TEE
  attestation with PQC; platform-key migration.
- [`supply_chain_provenance_expertise.md`](supply_chain_provenance_expertise.md) — PQC
  signatures for code-signing, SBOM, in-toto provenance.
- [`smart_contract_evm_security_expertise.md`](smart_contract_evm_security_expertise.md) —
  blockchain consensus and account-abstraction PQC paths.
- [`privacy_engineering_expertise.md`](privacy_engineering_expertise.md) — ZK proof systems
  (STARKs are inherently PQC, SNARKs are not).
- [`rtos_embedded_os_expertise.md`](rtos_embedded_os_expertise.md) — constrained-environment
  PQC; memory budgets and FP-less microcontrollers.
- [`agentic_web_capabilities_expertise.md`](agentic_web_capabilities_expertise.md) —
  capability tokens with PQ signatures; agent-to-tool TLS.
- [`firmware_embedded_security.md`](firmware_embedded_security.md) — LMS/XMSS for firmware
  signing; stateful-key management discipline.
- [`saml_federation_expertise.md`](saml_federation_expertise.md) — federation signing
  migration to PQC.
- [`http_web_security.md`](http_web_security.md) — TLS 1.3 handshake structure; PQC named
  groups.
- [`dns_network_infrastructure.md`](dns_network_infrastructure.md) — DNSSEC RR-size limits
  and PQC migration challenges.

---

## 16. Summary: What Defines Staff-Level PQC Expertise

**From the standards perspective:**
1. FIPS 203/204/205 are final (Aug 2024); FIPS 206 (Falcon) and HQC's KEM standard are in
   progress. ML-KEM-768 + ML-DSA-65 are the workhorses for general use; SLH-DSA is the
   conservative backup; FN-DSA is for size-constrained verifiers.
2. CNSA 2.0 sets the U.S. NSS timeline: 2027 acquisition deadline, 2030 deployment, 2035
   full transition. Commercial regulators follow on a multi-year lag.
3. The NIST Round-2 additional-signature process (14 candidates) is hedging against a
   future ML-DSA break. Treat as research-grade for deployment.

**From the cryptanalytic perspective:**
4. The Castryck-Decru SIKE attack (Aug 2022) is the canonical demonstration that even NIST
   fourth-round candidates can fall in polynomial time. Family diversity (lattice + hash + code) is
   not over-engineering — it is the lesson from a recent break.
5. Side-channels (KyberSlash, Hertzbleed-against-Dilithium, DPA on NTT) are the practical
   attack surface on production PQC implementations. Use formally verified implementations
   where available; treat constant-time as a verified property, not a code-review claim.
6. The migration cost is operational, not algorithmic. Discovery, inventory, agility, and
   coordination across the vendor ecosystem are the hard parts. The cryptography is the
   easy part.

**From the deployment perspective:**
7. Hybrid is the right transition strategy. X25519MLKEM768 for TLS, mlkem768x25519-sha256
   for SSH, hybrid composite signatures for code signing. Do not deploy pure-PQC until the
   ecosystem is mature, but do not deploy pure-classical for any HNDL-vulnerable data.
8. Signal PQXDH (Sep 2023) and Apple PQ3 (Feb 2024) are the reference designs for at-scale
   messaging PQC. PQ3's Level-3 periodic-rekeying property is the design to emulate, not
   PQXDH's simpler one-time-hybrid.
9. Crypto-agility is the meta-requirement. Wire formats with explicit algorithm identifiers,
   hybrid as default, per-message negotiation, KDF context binding — these are not optional
   features; they are how systems survive the next break.

**From the "harvest now, decrypt later" perspective:**
10. The CRQC timeline is uncertain (2030-2040 median expert estimate; significant tail risk).
    But HNDL means data with 10+ year confidentiality requirements is already at risk today
    if encrypted with classical primitives.
11. Authentication is not HNDL-vulnerable in the same way confidentiality is. Hybrid TLS
    handshakes can deploy gradually; signature migration can lag confidentiality migration.
12. The right posture for 2026 is **deploy hybrid PQC TLS now; plan signature migration over
    2026-2030; complete classical-primitive retirement by 2035**. This is aggressive enough
    to handle plausible CRQC timelines and HNDL exposure, and conservative enough to allow
    the ecosystem to mature.
