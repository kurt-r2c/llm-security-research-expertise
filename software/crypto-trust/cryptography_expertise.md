# Staff-Level Cryptography Guiding Principles
## Three Perspectives: Theoretical, Adversarial, and Bridge

> **Framework:** This document synthesizes four distinct epistemic roles in cryptography:
> - **Theoretical/professional** — Dan Boneh (Stanford) and Neal Koblitz (UWashington):
>   constructing provably secure primitives and critically evaluating security arguments
> - **Adversarial/red team** — David Wong (zkSecurity, ex-NCC/Meta/O(1)Labs): breaking real
>   implementations, finding protocol flaws, making cryptography legible to engineers
> - **Bridge** — Bruce Schneier (Schneier on Security): translating between theory and practice,
>   cipher design, policy implications, institutional trust in cryptographic systems
>
> **Key collaborators in scope:**
> - **Alfred Menezes** (UWaterloo) — MOV attack, *Handbook of Applied Cryptography*,
>   Another Look series with Koblitz
> - **Hovav Shacham** (UCSD) — BLS co-inventor, Return-Oriented Programming
> - **Matthew Franklin** (UC Davis) — Boneh-Franklin IBE, 2013 Gödel Prize
> - **Victor Shoup** (NYU) — Boneh/Shoup textbook, NTL library
> - **Niels Ferguson** — Twofish/Skein/Fortuna co-designer, Dual_EC_DRBG backdoor
> - **Tadayoshi Kohno** (Georgetown, ex-UWashington) — *Cryptography Engineering* co-author
>
> Sources: Stanford ACG publications; ePrint; Boneh/Shoup textbook (toc.cryptobook.us);
> Another Look series (uwaterloo.ca/~ajmeneze); cryptologie.net; schneier.com; NIST FIPS
> 203/204/205/206; NIST SP 800-227; NVD; RFC 8032/8439/9001/9180/9794.
>
> **Companion documents in this expertise library** (cross-referenced inline):
> - `post_quantum_cryptography_expertise.md` — dedicated PQC treatment (FIPS 203/204/205/206,
>   lattice/hash/isogeny families, migration mechanics, harvest-now-decrypt-later threat model)
> - `hardware_side_channels_expertise.md` — Spectre/Meltdown lineage, Hertzbleed, KyberSlash,
>   power analysis, microarchitectural attacks
> - `confidential_computing_expertise.md` — TEE-backed key custody (SGX/TDX/SEV-SNP),
>   attestation, sealed-key workflows
> - `formal_verification_protocols_expertise.md` — Tamarin/ProVerif/CryptoVerif analyses of
>   TLS 1.3, Signal, PQXDH, iMessage PQ3
> - `saml_federation_expertise.md` — XML signature wrapping, federated-identity crypto
> - `blockchain_wallet_consensus_security_expertise.md` — signature schemes in consensus
>   (BLS aggregation, Schnorr/Taproot, threshold signatures)
>
> **Currency note:** This document was originally authored before the NIST PQC FIPS
> finalizations of August 2024. Section 11 (PQC overview) and Section 16 (2024-2026 currency
> layer) reflect the post-finalization state; the dedicated
> `post_quantum_cryptography_expertise.md` is the authoritative reference for PQC depth.

---

## 1. Core Philosophy: Three Lenses

### The theoretical lens (Boneh, Koblitz): security must be argued, not assumed

**Dan Boneh's frame:** A cryptographic construction is only as good as its security reduction —
a proof that breaking the scheme in the security model implies solving a hard mathematical
problem. The reduction must be tight: if breaking the scheme requires advantage ε from an
adversary running in time t, then the reduction solves the hard problem with advantage roughly
ε using time roughly t. Loose reductions (where solving the hard problem requires time t² or
advantage ε²) provide near-zero concrete security at real-world parameter sizes.

**Neal Koblitz's counter-frame (the "Another Look" critique):** The theoretical community has
overclaimed. Security proofs in the random oracle model and generic group model use idealized
abstractions (hash functions as random oracles; groups where the only operation is the group law)
that do not correspond to real implementations. Reductions are routinely so loose that at
concrete security levels they provide no meaningful guarantee. The phrase "provably secure" in
a paper title is often misleading. Koblitz and Menezes documented cases where published
"proofs" contained errors that went unnoticed for years, and cases where schemes with proofs
were later broken by attacks that the proof structure simply did not address.

**The synthesis:** Both views are correct in different contexts. For protocol design, Boneh's
approach — model-based reduction to a hard problem — is the right discipline. For deployment
decisions, Koblitz's skepticism is warranted: a proof in the random oracle model is evidence,
not a guarantee. Concrete security analysis (how many bits of security at what key size given
current attacks) is more actionable than an asymptotic proof statement.

### The adversarial lens (David Wong): theory and practice diverge at the implementation boundary

The gap between a proven-secure construction and a secure deployed system is where most real
attacks live. From *Real-World Cryptography* and Wong's NCC Group work: the constructions are
often fine; the failures are in:
- Incorrect parameter choices (RSA-512, weak DH groups, static ECDH without forward secrecy)
- Nonce reuse (AES-GCM, ChaCha20-Poly1305, ECDSA — all catastrophically broken)
- Padding oracle exposures (Bleichenbacher, CBC padding oracle, Lucky 13)
- Timing side-channels (OpenSSL RSA, non-constant-time comparison)
- Protocol composition failures (TLS downgrade attacks, CRIME/BEAST, oracle attacks on
  the record layer)
- Implementation bugs in ASN.1/DER parsing, integer overflow in bignum arithmetic
- Subtle specification ambiguities (EdDSA malleability, BLS cofactor handling)

The red-team cryptographer assumes every implementation detail is an attack surface until
proven otherwise.

### The bridge lens (Schneier): cryptography is a component in a system, not a solution

From *Applied Cryptography* (1994/1996) and Schneier's own retrospective critique of it:
the original book was wrong to imply that cryptography solves security problems. Schneier later
wrote that a reader could implement everything correctly and still be insecure because cryptography
secures communication channels, not systems. The lock on a door is perfect cryptography; the
attacker goes through the window.

*Cryptography Engineering* (2010, with Ferguson and Kohno) corrected this: it teaches cryptography
as engineering discipline, covering not just what primitives do but how to combine them safely,
how to handle key management, and what assumptions underlie each choice.

Schneier's policy work extends this: institutional trust in cryptographic standards must account
for adversarial standards bodies (Dual_EC_DRBG), supply chain compromise (Juniper), and the
tension between national security interests and the security of the global internet.

---

## 2. Symmetric Cryptography

### Block ciphers: AES is the baseline, understand its limits

AES (Rijndael): 128-bit block, 128/192/256-bit key, 10/12/14 rounds of SubBytes + ShiftRows +
MixColumns + AddRoundKey. Best known attack: biclique cryptanalysis of AES-256 reduces to
2^254.4 (not practically relevant). The cipher itself is sound.

**What is not sound:** the mode of operation.

**ECB mode:** Each block encrypted independently. Identical plaintext blocks produce identical
ciphertext blocks. Never use for any data with structure (the "ECB penguin" problem). This is
not a theoretical concern — real deployments use ECB for structured data.

**CBC mode with PKCS#7 padding:** The Vaudenay padding oracle (2002): if an attacker can
submit arbitrary ciphertexts and observe whether decryption fails with an invalid padding error
(versus any other error), they can decrypt arbitrary ciphertexts one byte at a time via chosen-
ciphertext queries. O(256n) queries for n-byte plaintext. POODLE (2014) applied this to SSL 3.0.
Lucky 13 (2013) extracted the same oracle from timing differences in HMAC computation after
padding removal — even without an explicit error message.

**CTR mode:** Deterministic stream cipher from the block cipher; never reuse (nonce, key) pair.
Nonce reuse in CTR (and by extension any stream cipher mode including GCM and ChaCha20-Poly1305)
gives the attacker the XOR of plaintexts: C1 ⊕ C2 = P1 ⊕ P2. Combined with known/chosen
plaintext, full recovery of both plaintexts is possible.

### Authenticated encryption: the right abstraction for any encryption use case

From *Real-World Cryptography* (Wong, Chapter 4) and *Cryptography Engineering* (Ferguson/
Schneier/Kohno): encrypt-then-MAC is the correct composition (not MAC-then-encrypt or
encrypt-and-MAC). The MAC covers the ciphertext; decryption verifies the MAC before doing
any work on the ciphertext.

**AES-GCM (AEAD):**
- CTR mode encryption + GHASH authentication tag over AAD + ciphertext
- 96-bit nonce; NIST recommends never exceeding 2^32 encryptions under one key without rekeying
- Nonce reuse is catastrophic: reveals the authentication key H (H = E_K(0^128)), allowing tag
  forgery for arbitrary messages; also reveals P1 ⊕ P2
- Nonce generation: if random, 96 bits is borderline for 2^32 messages (birthday bound is 2^48);
  prefer a counter or use AES-GCM-SIV (nonce misuse resistant) for high-volume applications
- Tag truncation weakens authentication: 128-bit tags are standard; 96-bit minimum

**ChaCha20-Poly1305 (RFC 8439):**
- ChaCha20 stream cipher (add-rotate-XOR, no S-boxes, software-fast) + Poly1305 MAC
- Same nonce-reuse catastrophe as GCM: do not reuse (nonce, key)
- Preferred over AES-GCM on platforms without AES-NI hardware (mobile, embedded)
- Resistant to timing attacks by construction (no table lookups)

**Encrypt-then-MAC rationale (Ferguson/Schneier):** If you MAC-then-encrypt, the MAC
verification on decryption requires decrypting first — exposing the padding oracle if CBC is used.
Encrypt-then-MAC allows the MAC to be verified in constant time before any decryption work,
eliminating the oracle. This reasoning directly explains why TLS had years of padding oracle
vulnerabilities (it used MAC-then-encrypt until TLS 1.3).

### Stream ciphers

**Blowfish (Schneier, 1993):**
64-bit block, 16-round Feistel, 32–448-bit key. Key schedule: ~521 encryptions generating ~4KB
of subkey material (P-array of 18 32-bit words + 4 S-boxes of 256 32-bit words each) initialized
from the fractional hex digits of π, then XORed with the key in a carry-less manner. The expensive
key schedule is bcrypt's foundation: password hashing cost comes from repeated Blowfish
re-keying. **64-bit block is the critical weakness:** SWEET32 (2016) demonstrates birthday-bound
collision attacks at ~2^32 blocks (~32 GB) under the same key — feasible for long-lived TLS
sessions. Use 128-bit block ciphers for anything with large data volumes.

**Twofish (Schneier et al., 1998, AES finalist):**
128-bit block, 128/192/256-bit key, 16-round Feistel with PHT (pseudo-Hadamard transform) and
an MDS matrix over GF(2^8). Key-dependent S-boxes make differential/linear cryptanalysis harder
at the cost of complex key setup. Not broken, not standardized; AES won for implementation
simplicity and performance margins.

---

## 3. Hash Functions

### SHA-2 / SHA-3 / BLAKE

**SHA-256/SHA-512:** Merkle-Damgård construction with Davies-Meyer compression function.
Length-extension attack: given H(m) and len(m) but not m, can compute H(m || padding || m')
for any m' without knowing m. Never use raw SHA-2 as a MAC (use HMAC); never use it for
password hashing (use bcrypt, scrypt, Argon2id).

**HMAC:** H((K ⊕ opad) || H((K ⊕ ipad) || m)). Security proof reduces to collision-resistance +
PRF properties of the hash. HMAC-SHA256 is the standard MAC for non-AEAD contexts.

**SHA-3 (Keccak):** Sponge construction (absorb/squeeze), not Merkle-Damgård, so immune to
length-extension. Rate r, capacity c = 1600 - r bits. SHA3-256: r=1088, c=512; 24 rounds of
θ+ρ+π+χ+ι. The sponge also yields SHAKE128/SHAKE256 (XOFs), useful for variable-length output.

**BLAKE2/BLAKE3:** BLAKE2b (64-bit) and BLAKE2s (32-bit): ChaCha-based compression, faster than
SHA-2 in software, no length-extension. BLAKE3 (2020): Merkle tree structure enabling
parallelism + streaming; fastest of all at multiple GB/s on modern hardware.

**Skein (Schneier/Ferguson/Lucks et al., SHA-3 finalist):** Threefish block cipher (add-XOR-
rotate only, no S-boxes) in UBI chaining mode. Three internal sizes: 256/512/1024-bit. Unique
property: the Threefish cipher is separately standardizable. Not selected for SHA-3; no known
structural weaknesses.

---

## 4. Public-Key Cryptography and RSA

### RSA: correct parameter use is non-negotiable

RSA security rests on the hardness of factoring n = pq. Key points:

**Key sizes:** 2048-bit is
current minimum; 3072-bit for 128-bit security to 2031+; 4096-bit for long-term data.

**The Boneh-Durfee attack:** If the private exponent d < N^0.292, RSA is breakable via LLL
lattice reduction (Boneh/Durfee, 2000, extending Wiener's 1990 N^0.25 bound). Any implementation
choosing d for computational efficiency is vulnerable if the choice makes d small. Always use
full-size d; never choose e to make d convenient.

**Bleichenbacher's attack (1998):** If an RSA-PKCS#1 v1.5 decryption oracle reveals whether
the plaintext starts with 0x00 0x02 (i.e., is validly padded), an attacker can adaptively query
~2^20 ciphertexts to recover the plaintext for any captured ciphertext. This oracle is present
in any system that returns a different error for "bad padding" vs "decryption failed" — and even
in timing differences in error handling. David Wong (with Ronen, Gillham, Genkin, Shamir, and Yarom) documented Bleichenbacher oracles across
NSS (CVE-2018-12404), Mbed TLS (CVE-2018-19608), GnuTLS (CVE-2018-16868), Nettle
(CVE-2018-16869), and WolfSSL (CVE-2018-16870) in a coordinated disclosure. TLS uses RSA
for key exchange in pre-1.3 cipher suites; Bleichenbacher enables decryption of any TLS session
using those cipher suites.

**RSA-OAEP:** Fujisaki, Okamoto, Pointcheval, and Stern proved the IND-CCA2 (chosen-ciphertext) security of RSA-OAEP
in the random oracle model, after Victor Shoup showed a gap in the original OAEP proof. OAEP padding (RFC 8017) prevents Bleichenbacher-style attacks.
Never use PKCS#1 v1.5 for encryption; use OAEP with SHA-256.

**RSA signing:** Use PSS (probabilistic signature scheme), not PKCS#1 v1.5 for signing. PSS
has a tight security reduction; PKCS#1 v1.5 signatures have known existential forgery concerns
in certain contexts.

**Timing side-channels on RSA (Boneh/Brumley, USENIX Security 2003):** The first demonstration
that RSA private key operations could be recovered via timing measurements over a LAN — not
just local side channels. OpenSSL's sliding-windows CRT exponentiation without blinding leaked timing
information (Montgomery extra reductions, Karatsuba vs. normal multiplication) that exposed the factorization of the modulus. This caused OpenSSL to enable
RSA blinding (multiply by a random r^e before decryption, divide by r after) by default. Any
RSA implementation without blinding on the private key operations is timing-vulnerable.

---

## 5. Elliptic Curve Cryptography

### ECC foundations: Koblitz (1987) and Miller (1985)

The elliptic curve DLP (ECDLP) was independently proposed by Neal Koblitz ("Elliptic Curve
Cryptosystems," *Mathematics of Computation* 48:177, January 1987, submitted October 1985)
and Victor Miller (Crypto 1985 proceedings). Koblitz acknowledged Miller's preprint.

The group: points on E: y² = x³ + ax + b (Weierstrass form) over a prime field Fₚ, with the
point at infinity O. Group order is approximately p. ECDLP: given P and Q = kP, find k. Best
known algorithm: Pollard's rho, O(√n) — compare DLP in Fₚ which has subexponential GNFS.
ECDLP hardness allows much smaller keys: 256-bit ECC ≈ 3072-bit RSA for 128-bit security.

### Curve selection: not all curves are equal

**NIST P-curves (P-256, P-384, P-521):** Uses pseudo-random constants "selected in the late
1990s." The seed values for the curve parameters have unexplained provenance; Koblitz, Bernstein,
and others have raised concerns about whether the constants could have been chosen via a
number-station process to create discrete logarithm weaknesses only the curve designer could
exploit. No concrete attack is known. The concern is structural.

**Curve25519 / Ed25519 (Bernstein, 2006/2011):**
- Curve25519: v² = u³ + 486662u² + u over GF(2^255 - 19) (Montgomery form, birationally
  equivalent to the twisted Edwards curve edwards25519). Complete addition law (no special cases for point doubling/infinity) → no timing
  oracle. Cofactor h=8.
- Ed25519 (EdDSA on Curve25519): deterministic nonces (nonce = H(private_key_suffix || message)),
  preventing the ECDSA nonce-reuse catastrophe. 64-byte signatures. RFC 8032.
- Both designed with explicit, verifiable criteria; no unexplained constants.

**The ECDSA nonce catastrophe (documented by David Wong, Chapter 7):**
ECDSA signature: r = (kG).x mod n; s = k⁻¹(z + r·d) mod n. If two signatures share nonce k:
s₁ - s₂ = k⁻¹(z₁ - z₂) mod n → k = (z₁-z₂)·(s₁-s₂)⁻¹ mod n → d = (s₁k - z₁)r⁻¹ mod n.
This is the Sony PS3 attack (fail0verflow, 2010): the console used a static k. Any implementation
that reuses a nonce across two ECDSA signatures with the same key leaks the private key
immediately. Any ECDSA implementation using a weak or biased RNG for nonces is exploitable
via lattice attacks (Boneh/Venkatesan-style).

**EdDSA eliminates this:** nonce is deterministic from H(private_key_suffix || message).
No random number generator is involved in signing; the nonce cannot be reused because the
message is part of the input. Use EdDSA (Ed25519) over ECDSA wherever possible.

### The MOV attack: pairings as a weapon (Menezes/Okamoto/Vanstone, 1993)

For supersingular elliptic curves E/Fₚ, the Weil pairing maps E[ℓ] × E[ℓ] → μₗ ⊂ Fₚᵏ. This
reduces ECDLP on the supersingular curve to DLP in Fₚᵏ (the multiplicative group of an extension
field), where subexponential algorithms apply. For small embedding degree k, this is a practical
attack. Menezes, Okamoto, and Vanstone (Alfred Menezes's contribution) showed k ≤ 6 for most
supersingular curves — making ECDLP on supersingular curves reducible to DLP in Fₚ⁶ or
smaller, which is easy.

**Consequence:** Supersingular curves over small fields are cryptographically weak. All deployed
ECC curves (P-256, Curve25519, etc.) are non-supersingular (ordinary) and chosen to have large
embedding degree (k > 20 at minimum), making the MOV attack infeasible. Understanding MOV is
required for understanding why pairing-friendly curves (used intentionally in BLS/IBE) must be
carefully parameterized.

---

## 6. Pairing-Based Cryptography

### Weil and Tate pairings: the infrastructure

A pairing is a bilinear map e: G₁ × G₂ → Gₜ where G₁, G₂ are elliptic curve groups and Gₜ is
a multiplicative group in a finite field extension. Bilinearity: e(aP, bQ) = e(P, Q)^(ab).
This "magically" enables constructions impossible with standard groups.

**Pairing-friendly curves** (e.g., BN-254, BLS12-381): designed with small embedding degree k
(typically 12 or 24) to keep the target group Gₜ computationally accessible while maintaining
security. The embedding degree is chosen to be small enough for pairing computation but large
enough that GNFS on Fₚᵏ doesn't break security.

### BLS Signatures (Boneh, Lynn, Shacham — Asiacrypt 2001 / JOC 2004)

Private key: x ∈ Zₙ. Public key: X = xG₂. Hash-to-curve: H₁: {0,1}* → G₁.

**Sign:** σ = x · H₁(m) ∈ G₁.

**Verify:** e(σ, G₂) = e(H₁(m), X). Correctness: e(xH₁(m), G₂) = e(H₁(m), xG₂) = e(H₁(m), X).

**Signature size:** ~48 bytes on BLS12-381 (vs 64 bytes for Ed25519). Security: ~128 bits with
BLS12-381.

**Signature aggregation:** Given n signatures σ₁...σₙ on message m (or messages m₁...mₙ) from
keys X₁...Xₙ: σ_agg = σ₁ + σ₂ + ... + σₙ. Verify with one pairing equation (vs n pairings).
Trivially enables compact multisignatures and aggregate signatures (Boneh/Gentry/Lynn/Shacham
aggregate signatures, Eurocrypt 2003).

**Security warning for multi-message aggregation:** Rogue public key attack. If signatures are
on distinct messages and the adversary can choose X_n, they set X_n = xG₂ - X₁ - ... - X_{n-1}
so that e(H₁(m_n), X_n) compensates for all other terms. Defense: proof of possession (require
each signer to prove they hold the corresponding private key), or hash all public keys together.
BLS requires careful deployment.

**Deployed in:** Ethereum 2.0 (consensus layer validator signatures, ~860K validators
aggregated), Chia Network.

### Boneh-Franklin Identity-Based Encryption (Crypto 2001)

IBE: the public key is a string (an "identity" — email address, employee ID, phone number).
No certificate infrastructure required; the PKG (Private Key Generator) issues private keys.

**Setup:** PKG picks master secret s ∈ Zₙ, public key P_pub = sP ∈ G₁. Public: P, P_pub,
and hash functions H₁: {0,1}* → G₁, H₂: Gₜ → {0,1}^n.

**KeyGen(ID):** Private key d_ID = s · H₁(ID) ∈ G₁.

**Encrypt(ID, m):** Choose random r ∈ Zₙ. Ciphertext: C = (rP, m ⊕ H₂(e(H₁(ID), P_pub)^r)).

**Decrypt(d_ID, C=(U,V)):** m = V ⊕ H₂(e(d_ID, U)).
Correctness: e(d_ID, U) = e(sH₁(ID), rP) = e(H₁(ID), P)^(sr) = e(H₁(ID), P_pub)^r.

**Security:** IND-ID-CPA under the Bilinear Diffie-Hellman (BDH) assumption in the random oracle
model. Gödel Prize 2013 (Boneh + Franklin).

---

## 7. Zero-Knowledge Proofs

### The three properties

A ZK proof system for relation R = {(x, w) : (x,w) ∈ R} satisfies:
- **Completeness:** An honest prover with witness w for statement x convinces the verifier
- **Soundness:** A cheating prover without w cannot convince the verifier (except with negligible
  probability)
- **Zero-knowledge:** The verifier learns nothing beyond "the prover knows w"

### Comparison of major ZK proof systems

| System | Proof Size | Verification | Trusted Setup | PQ Secure | Main Use |
|--------|-----------|--------------|---------------|-----------|---------|
| Groth16 | 128 bytes (3 group elements) | O(1), fast | Per-circuit trusted setup | No | Zcash Sapling |
| PLONK | ~1KB | O(1), fast | Universal SRS (one-time) | No | zkEVM |
| Bulletproofs (Boneh et al., S&P 2018) | O(log n) | O(n) linear | None | No | Monero range proofs |
| STARKs | O(log²n) | O(log²n) | None | Yes (hash-based) | StarkWare |
| SNARK (generic) | O(1) | O(1) | Required | Varies | — |

**Bulletproofs (Bünz, Bootle, Boneh, Poelstra, Wuille, Maxwell — S&P 2018):**
No trusted setup. Inner Product Argument: prove knowledge of vectors a,b such that ⟨a,b⟩ = c
with O(log n) communication by recursively halving the vectors log n times. O(log n) proof size,
O(n) verification. Used in Monero for confidential transaction range proofs (proving output
values are in [0, 2^64] without revealing them).

**STARKs:** Arithmetization via AIR (Algebraic Intermediate Representation), FRI (Fast Reed-
Solomon IOPP) for polynomial commitment, Fiat-Shamir heuristic for non-interactivity. No
elliptic curves → post-quantum secure (hash-based). Larger proofs but transparent setup.

**SNARKs (Groth16/PLONK):** Require a trusted setup (toxic waste: if the SRS trapdoor is known,
fake proofs can be generated for any statement). Universal setups (PLONK) require the ceremony
once; circuit-specific setups (Groth16) require per-circuit ceremonies but produce smaller
proofs.

**David Wong's context (O(1) Labs, Mina/Kimchi):** Kimchi is a PLONK-variant with custom gates
for efficient encoding of cryptographic operations.

**Verifiable Delay Functions (Boneh, Bonneau, Bünz, Fisch — Crypto 2018):**
A VDF requires time T to compute f(x) but is fast to verify. Two constructions: (1) iterated
squaring in RSA group: y = x^(2^T) mod N; (2) iterated squaring in class groups of imaginary
quadratic fields (avoids trusted setup for RSA modulus). VDFs enable unbiasable randomness
beacons, fair ordering in blockchains, and proof-of-time.

---

## 8. Key Exchange and Secure Transport

### Diffie-Hellman: classical and elliptic

**Classical DH:** g^a mod p, g^b mod p → g^(ab) mod p. Security: discrete logarithm in (Z/pZ)*.
**Logjam (2015):** Weak DH groups (512-bit, even 768-bit) subject to precomputation. If two
parties negotiate a weak group (enabled by export cipher suites or misconfiguration), an attacker
who has precomputed discrete logarithms for that group can perform MITM in real time. TLS pre-1.3
allowed downgrade to these groups. Fix: require DHE groups ≥ 2048 bits, or use ECDH.

**ECDH:** Agree on curve point public keys; shared secret = x-coordinate of shared point.
Ephemeral ECDH (ECDHE) provides forward secrecy: session key derivation is independent of
the long-term key, so compromising the long-term key does not decrypt past sessions.

**Invalid curve attacks:** If a server does not validate that the client's DH public key is a
point on the specified curve, an attacker can send a point on a curve with small subgroup order.
The shared secret then lies in a small set, recoverable by brute force. Defense: validate that
received points are on the correct curve and in the correct subgroup (cofactor clearing). This is
well-specified for ECDH but has been implemented incorrectly in multiple TLS libraries.

**"How to Backdoor Diffie-Hellman" (David Wong, ePrint 2016/644):**
NOBUS ("Nobody But Us") backdoor construction via composite modulus with smooth order.
Choose p = 2q₁q₂...qₖ + 1 where the qᵢ are attacker-known primes. The DLP modulo each qᵢ
is easy (Pohlig-Hellman), so CRT reconstructs the full discrete log. The backdoored p looks
like a safe prime to casual inspection. The attacker can solve any DH instance in that group.

### TLS 1.3: the correct design

From *Real-World Cryptography* (Chapter 9) and the IETF process:

TLS 1.3 (RFC 8446) eliminations: RSA key exchange (no forward secrecy), static DH, CBC mode,
RC4, SHA-1, MD5, export ciphers, compression (CRIME attack vector), renegotiation. All session
keys derived via HKDF from ephemeral key exchange (ECDHE/DHE). Only authenticated AEAD
(AES-GCM, ChaCha20-Poly1305). Session resumption via PSK with optional 0-RTT (with forward
secrecy caveats on 0-RTT data).

**TLS 1.3 handshake:** ClientHello (key_shares) → ServerHello (key_share) → both derive
handshake_secret via HKDF from ECDHE output + early_secret → ServerCertificate +
CertificateVerify + Finished → ClientFinished. All after ServerHello is encrypted. Server
authentication is via signature over the handshake transcript.

### Noise Protocol Framework (Trevor Perrin; taught by David Wong)

Noise (Chapter 9 of *Real-World Cryptography*) is a framework for designing handshake protocols
from composable patterns using DH, AEAD, and hash primitives. Each pattern specifies a sequence
of DH operations whose outputs are mixed into a running hash that authenticates the handshake.

Patterns (syntax: each message is a list of tokens):
- `NN`: no authentication. `→ e / ← e, ee`
- `KK`: both parties pre-know each other's static keys. `→ e, es, ss / ← e, ee, se`
- `XX`: mutual authentication, keys transmitted in handshake
- `IK`: initiator knows responder's static key

Properties: mutual authentication, forward secrecy, identity hiding — all explicit from the
pattern. No ambiguity in what a given pattern provides. Used in WireGuard (IKpsk2), WhatsApp,
Lightning, and many other modern protocols.

### Signal Protocol (X3DH + Double Ratchet)

From *Real-World Cryptography* (Chapter 10):

**X3DH (Extended Triple DH) key agreement:** Combines 3–4 DH operations mixing long-term and
ephemeral keys of both parties to establish a shared secret with forward secrecy and deniability.
The pre-key bundle (signed prekey + one-time prekeys) allows asynchronous key agreement.

**Double Ratchet:** Once a session key is established, messages use a symmetric ratchet (HKDF
chain) for forward secrecy within a session, combined with a DH ratchet for break-in recovery:
after each exchange of DH public keys, the chain keys are ratcheted forward, making past and
future sessions independent. If an attacker obtains a chain key at one point, they cannot
decrypt past messages and can only decrypt future messages until the DH ratchet turns.

---

## 9. Digital Signatures

### Schnorr signatures: the clean construction

Schnorr (1989/1991): choose k ∈ Zₙ; R = kG; c = H(R, message); s = k + c·x mod n.
Verify: sG = R + cX. Security: unforgeability under DLP + random oracle. Linear in the exponent
→ enables multi-signature schemes where partial signatures combine linearly: (R₁+R₂, s₁+s₂).
Patented until 2008; this is why ECDSA was standardized instead in the 1990s. EdDSA is
deterministic Schnorr over Edwards curves.

**MuSig2 (Nick, Ruffing, Seurin):** Two-round Schnorr multisignature. Each signer commits to
two nonces; the combined nonce is a linear combination (preventing Wagner's attack on naive
multi-party Schnorr). Output is a single Schnorr signature indistinguishable from a single-party
signature. Used in Bitcoin Taproot.

### Signature malleability

**ECDSA malleability:** If (r, s) is a valid signature, so is (r, -s mod n). This means the
same message can have two valid signatures under the same key, which caused problems in Bitcoin
transaction IDs (transaction malleability). EdDSA is non-malleable (the signature is canonical).

**EdDSA cofactor issues:** Ed448-Goldilocks has cofactor 4; Ed25519 has cofactor 8. Signatures
that don't clear the cofactor can allow signature forgery in some aggregation contexts. RFC 8032
specifies cofactor handling; implementations that deviate are subtly vulnerable. David Wong's
*Real-World Cryptography* calls this out explicitly.

---

## 10. Cryptographic Failures: The Red-Team Catalog

### Category 1: Nonce reuse (catastrophic across all stream-cipher AEADs)

Any encryption scheme using a nonce + stream cipher (AES-GCM, ChaCha20-Poly1305, AES-CTR) is
broken by nonce reuse:
- **Confidentiality:** C1 ⊕ C2 = P1 ⊕ P2; known-plaintext recovers the other
- **Integrity (GCM):** Nonce reuse reveals H = E_K(0^128) → GHASH key → forge any tag

Detection in multi-instance deployments: two ciphertexts with the same nonce XOR to plaintext
XOR. NIST recommends at most 2^32 random nonces under one AES-GCM key; for higher volumes, use
a deterministic counter or AES-GCM-SIV.

### Category 2: Padding oracle attacks

**CBC padding oracle (Vaudenay 2002):** The decryption of a CBC ciphertext block C_i is
P_i = D_K(C_i) ⊕ C_{i-1}. If the attacker can flip bits in C_{i-1} and observe whether
PKCS#7 padding is valid, they recover P_i byte by byte. O(256·n) oracle queries for n bytes.
Variants: POODLE (SSL 3.0), Lucky 13 (timing oracle), BEAST (chosen-plaintext).

**Bleichenbacher's RSA-PKCS#1 v1.5 oracle:** 2^20 queries to decrypt any captured RSA-encrypted
message. Variants: ROBOT attack (2018) found in F5, Citrix, Cisco, Erlang. David Wong
and co-authors (the CAT paper) broke seven of nine TLS implementations tested in a single disclosure.

**Countermeasure:** Constant-time rejection of any padding failure; return the same error
regardless of where in the padding verification the failure occurred; take the same time
regardless. TLS 1.3 removes all CBC and PKCS#1 v1.5 encryption, eliminating these oracle classes
at the protocol layer.

### Category 3: Timing side-channels

**RSA blinding (Boneh/Brumley):** Without blinding, modular exponentiation timing leaks bits of
the private exponent. Fix: multiply plaintext by r^e before decryption, divide by r after. Now
required in all compliant RSA implementations.

**Non-constant-time comparison:** `memcmp` returns early on first mismatch. Any MAC, signature,
or hash comparison using `memcmp` is a timing oracle that allows forgery by incrementally
discovering the correct value. Always use constant-time comparison (`CRYPTO_memcmp` / `hmac.equal`
/ language equivalent). This is not a theoretical attack — it is practical over LAN.

**Lattice attacks on biased nonces:** If ECDSA nonces are biased (e.g., top few bits are always
zero due to rejection sampling implementation), signatures reveal partial information about the
nonce, which translates to a Hidden Number Problem instance solvable via LLL. Practical against
some hardware security modules and smartcards. The number of required signatures scales with
the bias: a 1-bit bias requires ~2^20 signatures; a few-bit bias requires far fewer.

### Category 4: Weak randomness

**RNG failures:** Any cryptographic operation requiring a random value (key generation, ECDSA
nonce, DH ephemeral) is broken if the RNG is predictable. Historical failures:
- Debian OpenSSL (2008): `PID` was the only entropy source → 32,768 distinct keys
- Android SecureRandom (2013): Java's SecureRandom was not seeded correctly → Bitcoin wallet
  private keys recoverable
- Dual_EC_DRBG (NSA, 2004): see below

**Dual_EC_DRBG (Shumow/Ferguson, Crypto 2007 rump):**
The NIST standardized RNG uses two elliptic curve points P and Q. If P = e·Q (known to the
designer), then about 32 bytes of output allow
full state recovery and prediction of all future outputs. The P/Q relationship was identified
by Niels Ferguson and Dan Shumow at the Crypto 2007 rump session. Reuters (December
2013) reported NSA paid RSA Security $10M to make Dual_EC_DRBG the default in BSafe.
Juniper Networks used Dual_EC_DRBG with its own Q value rather than the NSA default Q; an attacker
(attributed to a nation-state) later changed Q to a different value, creating a second
backdoor that even the NSA couldn't exploit but the attacker could — the "cascading backdoor"
that Schneier documented in 2015/2021.

**Lesson:** Random number generator backdoors are the highest-impact cryptographic attack
because they break all key generation, all ephemeral key exchange, and all signature nonces
simultaneously.

### Category 5: Weak or broken algorithm choices

The still-deployed broken list:
- **MD5 / SHA-1:** Cryptographic collision attacks. MD5 collisions in seconds; SHA-1 SHAttered
  (2017). Never use for anything requiring collision resistance.
- **RC4:** Statistical biases in the first 256 bytes, long-term key stream biases. Forbidden in
  TLS (RFC 7465).
- **DES/3DES:** 56-bit DES: exhaustive search. 3DES: SWEET32 birthday attack on 64-bit block
  at ~2^32 blocks (~32 GB).
- **RSA < 2048 bits:** 512-bit keys factored with commodity cloud compute.
- **Static DH / ECDH without ephemeral:** No forward secrecy. Compromise of server private key
  decrypts all past sessions.

---

## 11. Post-Quantum Cryptography (NIST FIPS, Effective August 2024)

> **Pointer:** This section is a compact overview of the NIST PQC FIPS suite for the
> reader of this document. The dedicated `post_quantum_cryptography_expertise.md` covers
> lattice/hash/code/isogeny family construction details, KyberSlash and related implementation-
> level side channels, hybrid-transition migration mechanics, harvest-now-decrypt-later threat
> modeling, and the operational PQC migration playbook. Read that document for any deployment
> or migration work; this section establishes only the vocabulary needed for the cross-cutting
> failure-mode discussion below.

The NIST PQC standardization process (2016–2024) selected four algorithms, now published as
FIPS standards effective August 14, 2024 (Federal Register
[2024-17956](https://www.federalregister.gov/documents/2024/08/14/2024-17956/announcing-issuance-of-federal-information-processing-standards-fips-fips-203-module-lattice-based)):

### ML-KEM (FIPS 203) — Key Encapsulation Mechanism

Formerly CRYSTALS-Kyber. Security: Module Learning With Errors (MLWE). Three parameter sets:
- **ML-KEM-512:** 128-bit classical / ~100-bit PQ security. Public key 800B, ciphertext 768B.
- **ML-KEM-768:** 192-bit classical / ~128-bit PQ. Public key 1184B, ciphertext 1088B.
- **ML-KEM-1024:** 256-bit classical / ~160-bit PQ. Public key 1568B, ciphertext 1568B.

ML-KEM-768 is the recommended general-purpose choice. The scheme generates shared secrets via a
CPA-secure PKE (lattice-based encryption) hardened to CCA2-secure KEM via Fujisaki-Okamoto
transform. Replace ECDH with ML-KEM in TLS, SSH, and hybrid key exchange (X25519+ML-KEM-768
is the current recommendation for transitional deployments — neither alone is sufficient during
the transition period).

### ML-DSA (FIPS 204) — Digital Signature

Formerly CRYSTALS-Dilithium. Security: MLWE + Module Short Integer Solution (MSIS). Three
parameter sets (ML-DSA-44, ML-DSA-65, ML-DSA-87 at security levels 2/3/5). Uses Fiat-Shamir
with Aborts: sign by sampling a short masking vector y, compute commitment w = Ay, compute
challenge c = H(μ, w₁), attempt to produce z = y + cS₁ such that z and w - cS₂ are both
short; abort and retry if not. This abort-retry makes timing non-constant — implementations
must be careful to avoid timing leakage on the abort rate.

Public key ~1952 bytes, signature ~3309 bytes (ML-DSA-65), much larger than Ed25519.

### SLH-DSA (FIPS 205) — Hash-Based Signature (conservative backup)

Formerly SPHINCS+. Pure hash-based — security rests only on hash function collision resistance.
No algebraic structure to attack. Performance: slow signing (~milliseconds), moderate
verification, large signatures (~8-50KB depending on parameter set). Recommended as a backup
for scenarios where lattice cryptography assumptions are broken. SLH-DSA-SHA2-128f/128s/etc.
parameter sets trade signature size vs signing speed.

### FN-DSA (FIPS 206, draft) — Lattice Signature with Small Signatures

Formerly FALCON. Based on NTRU lattice with Gaussian sampling. Signatures are significantly
smaller than ML-DSA (~666 bytes for FALCON-512). Faster verification. **Implementation
challenge:** Gaussian sampling over NTRU lattice requires floating-point arithmetic; subtle
implementation errors (incorrect precision, timing leaks from Gaussian tails) can leak the
private key. Not recommended for general-purpose implementation without cryptographic engineering
expertise. For most applications, prefer ML-DSA.

### Hybrid key exchange (transitional recommendation)

During the transition period, use X25519+ML-KEM-768 for key exchange: an attacker must break
both ECDH and the lattice assumption to compromise the session. This is the current TLS WG
recommendation (draft-ietf-tls-hybrid-design). Do not wait to deploy PQC; "harvest now, decrypt
later" attacks (storing encrypted traffic today to decrypt once quantum computers arrive) are
active for long-lived sensitive data.

---

## 12. The Another Look Critique: What Security Proofs Actually Guarantee

Neal Koblitz and Alfred Menezes's "Another Look" series (2004–2019) identified
specific categories of overclaiming in the crypto literature:

**1. Random oracle model proofs ≠ instantiatable security.**
A scheme proven secure when the hash function H is modeled as a truly random function may be
insecure when H is any actual hash. The Canetti-Goldreich-Halevi impossibility result (2004)
shows there exist schemes secure in ROM but insecure under any hash instantiation. The existence
of these pathological cases doesn't mean all ROM proofs are worthless, but it means they are
evidence, not guarantees.

**2. Loose reductions provide no concrete guarantee.**
If the reduction from scheme security to hardness of problem P has factor 2^40, then a scheme
targeting 128-bit security only provides 88-bit security against the actual problem. Many
published proofs have slack of this magnitude. Without tight reductions, concrete parameter
selection based on the proof is unreliable.

**3. The HMQV controversy (2007).**
Menezes published an analysis of HMQV (a provably secure variant of MQV) finding
attacks in the Canetti-Krawczyk model that recovered static private keys under specific
conditions. The community response was hostile. This episode illustrates that:
- Peer review of security proofs is difficult and errors persist in published work
- Community social dynamics can impede legitimate critique
- The correct response to a claimed attack is technical engagement, not dismissal

**The applied lesson (synthesizing Boneh and Koblitz):** Use proofs as design guidance and as
evidence of security, not as guarantees. For any deployed cryptosystem, verify:
1. Is the underlying hard problem actually hard at the parameter sizes in use?
2. Is the reduction tight enough that the claimed security level is real?
3. Is the security model faithful to the actual deployment environment?
4. Has the proof been independently verified?

---

## 13. Standards, Backdoors, and Institutional Trust

### Dual_EC_DRBG: the anatomy of a standards-body backdoor

The Dual Elliptic Curve Deterministic Random Bit Generator was standardized by NIST (SP 800-90,
2006) with parameters specifying curve points P and Q. Niels Ferguson and Dan Shumow presented
at Crypto 2007 rump session that if log_P(Q) is known, each 256-bit DRBG output block reveals
sufficient state to predict all future outputs (~2^15 remaining search space). The P/Q
relationship was not published.

**The NSA confirmation (2013):** Snowden documents revealed NSA had introduced Dual_EC_DRBG into
the NIST standard and paid RSA Security $10M to make it the default in the BSafe toolkit.

**The Juniper cascade (2015, revisited 2021):** Juniper ScreenOS used Dual_EC_DRBG. An attacker
(reported by Bloomberg in 2021 as China-linked APT 5, though not formally attributed) replaced Q with a different
value, creating a second backdoor usable only by the attacker — exploiting the exact backdoor
structure that Ferguson/Shumow identified, but with a different Q. This demonstrates:
- A backdoor in a standardized component is an attack surface for any adversary who understands
  the mechanism, not only the original backdoor installer
- Supply chain compromise of a cryptographic primitive invalidates all higher-level security
  guarantees regardless of protocol or implementation quality

### Cryptographic agility: necessary evil or dangerous flexibility?

From Schneier's blog and the broader standards community: "cryptographic agility" — the ability
to negotiate different algorithms — was introduced to allow upgrading algorithms without
protocol redesign. It also created the attack surface for downgrade attacks: FREAK (force RSA
export), Logjam (force weak DH), POODLE (force SSL 3.0), BEAST (exploit CBC in TLS 1.0).

The correct answer is not "remove all agility" but "remove algorithms that should never be
negotiated." TLS 1.3 takes this approach: only strong algorithms are in the specification; there
is no downgrade path.

---

## 14. Teaching Cryptography: Three Models

### Boneh/Shoup "A Graduate Course in Applied Cryptography" (toc.cryptobook.us)

~900 pages, three parts:
- **Part I (Chapters 1–9):** Secret key cryptography — encryption, stream ciphers, block ciphers,
  chosen plaintext attacks, message integrity (universal hashing, collision-resistant hashing),
  authenticated encryption
- **Part II (Chapters 10–17):** Public key cryptography — public key tools, public-key encryption,
  chosen-ciphertext security, digital signatures, fast signatures from one-way functions, elliptic
  curves and pairings, attacks on number-theoretic assumptions, post-quantum crypto from lattices
- **Part III (Chapters 18–23):** Protocols — identification and login, sigma protocols,
  zero-knowledge, authenticated key exchange, threshold cryptography, secure multi-party computation

Rigorous treatment with full security definitions and proofs. The standard graduate cryptography
reference alongside Katz/Lindell.

### David Wong's "Real-World Cryptography" (Manning, 2021)

16 chapters in two parts: primitives, then protocols.
Uniquely: each chapter opens with "what problem does this solve?" framing. Covers TLS 1.3, Noise,
Signal, HPKE, PQC, ZK proofs, MPC, FHE. No prerequisites beyond basic programming. The correct
book for an engineer who needs to use cryptography correctly rather than construct proofs.

### Schneier's "Cryptography Engineering" (with Ferguson and Kohno, 2010)

Engineering focus. Distinctive contributions:
- **Encrypt-then-MAC** rationale (see above)
- **Fortuna PRNG:** Two-layer accumulator design — 32 pools collect entropy; reseed only when
  pool 0 has ≥ 64 bytes of entropy; pool i is used in reseed only if 2^i reseeds have occurred
  since last use of pool i. This makes Fortuna robust against entropy injection attacks and
  provides graceful recovery from state compromise. Replaced Yarrow (earlier Schneier/Ferguson/
  Kelsey PRNG) in macOS and iOS.
- **Side-channel countermeasures:** Specific implementation guidance on constant-time operations,
  avoiding compiler optimizations that break security invariants, power analysis countermeasures

---

## 15. Tooling and Practical Reference

| Tool / Resource | Author(s) | Purpose |
|----------------|-----------|---------|
| **NTL (Number Theory Library)** | Victor Shoup | C++ library for arbitrary-precision arithmetic, lattice algorithms (LLL), ZK proofs — research and implementation standard |
| **SageMath** | Community | Computer algebra system; standard for cryptographic research and attack implementation |
| **mimoo/RSA-and-LLL-attacks** | David Wong | SageMath implementations of Boneh-Durfee and Coppersmith attacks; 840 stars |
| **CryptoHack** | Community | CTF-style platform for learning cryptography by breaking intentionally vulnerable constructions |
| **toc.cryptobook.us** | Boneh/Shoup | Free ~900-page graduate cryptography textbook |
| **Handbook of Applied Cryptography** | Menezes/van Oorschot/Vanstone | Free reference; Chapter 4 (public key parameters), Chapter 11 (digital signatures) — still accurate for classical primitives |
| **Signal Protocol (libsignal)** | Signal Foundation | Reference X3DH + Double Ratchet implementation |
| **BLAKE3** | O'Connor et al. | Fastest general-purpose cryptographic hash; Merkle tree structure; use for non-keyed hashing where speed matters |
| **Disco** | David Wong (ePrint 2019/180) | Noise + STROBE: two-primitive (Curve25519 + Keccak) protocol framework |
| **bls-signatures / blst** | IETF / Supranational | BLS signature library (used in Ethereum 2.0); production BLS implementation |

---

## 16. The 2024-2026 Currency Layer

The original document (Sections 1-15 above) was authored before the NIST PQC FIPS finalizations
of August 2024. This section catches the document up to the post-finalization landscape: PQC
deployment in transport and messaging, side-channel research on the new lattice primitives,
the modern crypto-library CVE corpus, the rise of crypto-bill-of-materials inventory tooling,
and key-management evolution at the cloud/HSM tier. The dedicated
`post_quantum_cryptography_expertise.md` is the authoritative reference for PQC depth; this
section connects the rest of this document to the post-2024 state and cross-links the
companion expertise documents.

### 16.1 Post-quantum standardization milestones (Aug 2024 - 2025)

NIST published FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), and FIPS 205 (SLH-DSA) on August 13, 2024,
effective August 14, 2024
([CSRC announcement](https://csrc.nist.gov/news/2024/postquantum-cryptography-fips-approved);
[FIPS 203 final](https://csrc.nist.gov/pubs/fips/203/final)). FIPS 206 (FN-DSA, formerly FALCON)
remains in draft. NIST followed with **SP 800-227 "Recommendations for Key-Encapsulation
Mechanisms"** (initial public draft January 7, 2025; final published September 18, 2025) which
provides operational guidance — random number generation requirements, zeroization of
intermediate values, error-handling discipline, and side-channel mitigation
([NIST SP 800-227 final](https://csrc.nist.gov/pubs/sp/800/227/final)).

**CNSA 2.0 (Commercial National Security Algorithm Suite 2.0):** NSA's PQC roadmap for
National Security Systems
([CSI CNSA 2.0 FAQ, defense.gov](https://media.defense.gov/2022/Sep/07/2003071836/-1/-1/0/CSI_CNSA_2.0_FAQ_.PDF)):
- 2025 onward: web browsers, servers, cloud services should support and prefer CNSA 2.0
- January 1, 2027: all new NSS acquisitions must support CNSA 2.0 algorithms unless excepted
- December 31, 2030: equipment unable to support CNSA 2.0 phased out
- 2033: exclusive use in browsers, servers, cloud services; legacy applications updated/replaced
- 2035: all NSS quantum-resistant

CNSA 2.0 specifies ML-KEM-1024, ML-DSA-87, LMS/XMSS (firmware/software signing), SHA-384/512, and AES-256 (no AES-128). It
does NOT permit hybrid stacks for compliance — pure PQ algorithms only. This is a deliberate
break from the broader-internet "hybrid during transition" stance.

For the lattice/hash family construction details, alternative-family backups (HQE, classic
McEliece), and the migration sequencing across symmetric/asymmetric/protocol layers, see
`post_quantum_cryptography_expertise.md`.

### 16.2 TLS 1.3 hybrid PQC: X25519MLKEM768 and the post-handshake landscape

The IETF TLS WG has converged on **X25519MLKEM768** as the practical hybrid named-group for
TLS 1.3, specified in [draft-ietf-tls-ecdhe-mlkem](https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/).
Wire format: the client's `key_exchange` is the concatenation of the ML-KEM-768 encapsulation
key (1184 bytes) and the X25519 ephemeral share (32 bytes), total 1216 bytes; the derived
shared secret is the concatenation of the ML-KEM shared secret and the X25519 shared secret,
total 64 bytes
([draft-ietf-tls-ecdhe-mlkem-04](https://datatracker.ietf.org/doc/html/draft-ietf-tls-ecdhe-mlkem-04)).
Companion entries: SecP256r1MLKEM768 and SecP384r1MLKEM1024 for environments preferring
NIST P-curves.

**RFC 9794** (June 2025), "Terminology for Post-Quantum Traditional Hybrid Schemes," fixes
the vocabulary for PQ/T (post-quantum / traditional) hybrid combiners across IETF
work-streams. The "must break BOTH" argument from Section 11 is now standards-body
canonicalized: confidentiality holds as long as either constituent is unbroken at the time
of attempted decryption. Note this preserves the original document's framing: hybrid is a
transition tool, not an end state.

**Browser/server deployment status (2024-2026):**
- Chrome 124 (April 2024) shipped X25519Kyber768Draft00 by default; Chrome 131 (November 2024)
  switched to X25519MLKEM768.
- Firefox 132+ supports hybrid PQC on TLS 1.3.
- Cloudflare turned X25519MLKEM768 on for all their edges in 2024-2025
  ([Cloudflare PQC announcement](https://blog.cloudflare.com/post-quantum-for-all/)).
- AWS deployed hybrid ML-KEM PQ TLS in KMS, ACM, and Secrets Manager
  ([AWS Security blog](https://aws.amazon.com/blogs/security/ml-kem-post-quantum-tls-now-supported-in-aws-kms-acm-and-secrets-manager/));
  the predecessor CRYSTALS-Kyber support is being phased out across all AWS endpoints in 2026.

**Encrypted Client Hello (ECH):** TLS 1.3's last missing privacy piece. The unencrypted SNI
extension leaks the destination hostname even on a TLS 1.3 connection; ECH wraps the inner
ClientHello (including SNI) in HPKE encryption to a service-published public key, with the
outer ClientHello presenting only a fronting "client-facing server" name. Deployed by
Cloudflare and Firefox 118 in 2023; broader rollout 2024
([Cloudflare ECH blog](https://blog.cloudflare.com/announcing-encrypted-client-hello/)).
Russia began blocking ECH in late 2024; censoring states treat ECH as adversarial because
it removes the SNI metadata they had been using for selective filtering
([PETS FOCI 2025 paper](https://www.petsymposium.org/foci/2025/foci-2025-0016.pdf)).
ECH was published as RFC 9849 (March 2026).

**HPKE (RFC 9180, February 2022)** has matured from a primitive into infrastructure. ECH uses
HPKE; the IETF Messaging Layer Security (MLS, RFC 9420) protocol uses HPKE for sender-key
distribution; OHTTP (Oblivious HTTP, RFC 9458) uses HPKE for relay-resistant requests. The
HPKE API surface — `SetupBase[SI]`, `SetupAuth[SI]`, `Seal/Open` — is the modern public-key
encryption interface engineers should reach for instead of building from raw KEM + DEM
([RFC 9180](https://datatracker.ietf.org/doc/rfc9180/)).

**QUIC and TLS 1.3:** [RFC 9001](https://datatracker.ietf.org/doc/rfc9001/) (May 2021)
specifies how QUIC uses TLS 1.3 — QUIC adopts the TLS 1.3 handshake but replaces the TLS
record layer with QUIC packet protection (separate packet protection keys per epoch derived
via HKDF from TLS 1.3 secrets). HTTP/3 over QUIC reached ~35% of active websites by mid-2025.
QUIC's [draft-ietf-quic-extended-key-update](https://datatracker.ietf.org/doc/draft-ietf-quic-extended-key-update/)
builds on TLS Extended Key Update for long-lived QUIC connections. The cryptographic
implications: QUIC inherits TLS 1.3's AEAD-only, ECDHE-mandatory, no-renegotiation shape;
hybrid PQC named groups apply directly. No new attack surface specific to QUIC's
cryptographic core.

### 16.3 Side-channel research on the new lattice primitives

The original Section 10 catalog (nonce reuse, padding oracles, timing channels, weak RNG,
broken algorithms) is necessary but no longer sufficient. Side-channel research on the
NIST PQC finalists has produced two named result lines that staff-level practitioners must
know. For deeper microarchitectural treatment see `hardware_side_channels_expertise.md`.

**KyberSlash (KyberSlash1 + KyberSlash2, Bernstein et al., 2024):** Timing side-channels in
ML-KEM reference and library implementations. KyberSlash1 affects the `poly_tomsg` decoding
procedure; KyberSlash2 affects `poly_compress` and `polyvec_compress`. Both stem from
secret-dependent division operations whose timing on platforms with non-constant-time
integer division (notably Arm Cortex-A7 and Arm Cortex-M4) leaks bits of the secret key.
Practical: KyberSlash1 key recovery demonstrated on a Raspberry Pi 2 and KyberSlash2 on an
Arm Cortex-M4 ([eprint 2024/1049](https://eprint.iacr.org/2024/1049),
[kyberslash.cr.yp.to](https://kyberslash.cr.yp.to/faq.html)). Affected the official Kyber
reference, pq-crystals/kyber, mlkem-native, kudelskisecurity/crystals-go, and others;
patches landed January-March 2024.

**Lesson:** "constant-time" is a property of the (algorithm, compiler, target ISA) triple,
not the algorithm alone. The Kyber reference C code was written in C with patterns that
clang and gcc compile to constant-time code on x86_64 but NOT on Arm cores with variable-
latency division. Any new primitive needs constant-time verification on every target ISA.

**Hertzbleed lineage (USENIX Security 2022, continuing 2023-2025):** DVFS-induced frequency variation
leaks computation-dependent timing information without any explicit power-measurement
interface ([hertzbleed.com](https://www.hertzbleed.com/);
[IEEE Micro 2023](https://dl.acm.org/doi/abs/10.1109/MM.2023.3274619)). The original 2022
result broke SIKE; 2023 follow-up extended to "constant-time" ECDSA and Classic McEliece
implementations. IEEE S&P 2025 work demonstrates 5x-faster Hertzbleed-style attacks on
modern Intel CPUs even in the absence of frequency-side-channel leakage
([Hertzbleed continued lineage, S&P 2025](https://www.hertzbleed.com/)). The structural
defense — fixing CPU frequency — is rarely available in practice; the operational defense
is masking secret-dependent operations.

**Spectre-class continuing research:** Spectre/Meltdown variants continued to surface
from 2022 onward (RetBleed, Inception/Phantom, BHI, Reptar, GhostRace). All affect
microarchitectural timing channels rather than cryptographic primitives directly, but
their impact on cryptographic key custody — particularly for keys held in process memory
during signing or KEM-decapsulation — is the operational concern. Mitigation discipline:
keys in user-space process memory should be assumed leakable to a co-resident attacker
process; high-value keys belong in HSM, TEE, or kernel-only memory. See
`hardware_side_channels_expertise.md` and `confidential_computing_expertise.md` for the
mitigation taxonomy.

### 16.4 Modern crypto-library CVE corpus (2024-2026)

The Bleichenbacher/ROBOT-style multi-library coordinated disclosure pattern from Section 10
continues. Catalog of representative 2024-2026 CVEs in the major cryptographic libraries:

**OpenSSL** ([advisory feed](https://openssl-library.org/news/vulnerabilities/)):
- **CVE-2024-12797 (HIGH):** RFC 7250 raw public key authentication bypass — TLS/DTLS
  connections using raw public keys vulnerable to MITM. Affects OpenSSL 3.2–3.4.
- **CVE-2025-15467 (HIGH):** Stack buffer overflow in CMS AuthEnvelopedData parsing.
  Crafted AEAD parameters trigger out-of-bounds write BEFORE any authentication or tag
  verification — pre-auth memory corruption is the worst-case shape for a crypto library.
- **CVE-2025-9231 (MODERATE):** SM2 signature timing side-channel on 64-bit ARM. Private
  key recoverable via timing measurements. Same pattern as the OpenSSL RSA-blinding history
  in Section 10.4 — non-constant-time arithmetic on a private-key-bearing path.
- **CVE-2025-11187 (MODERATE):** PBMAC1 parameter validation gap in PKCS#12 → stack
  buffer overflow during MAC verification.
- **CVE-2025-9230 (MODERATE):** Out-of-bounds read/write in RFC 3211 KEK unwrap for
  password-based CMS encryption.
- **CVE-2024-6119 (MODERATE):** X.509 name checking DoS via otherName SAN entries.

**WolfSSL, mbedTLS, Botan, NSS, Libgcrypt:** the Bleichenbacher 2018 coordinated disclosure
pattern (Wong, Section 10.2) has been followed by intermittent re-disclosure of similar
side-channel and parsing issues in 2024-2025. The defensive practitioner posture: any
library implementing PKCS#1 v1.5 decryption at all is a Bleichenbacher liability surface
until proven constant-time and constant-error against the full corpus of historical
oracle variants (Bleichenbacher 1998, Klima-Pokorny-Rosa 2003, ROBOT 2018).

**libsodium** continues its conservative posture: no PKCS#1 v1.5, no CBC, no static
DH/ECDH, default APIs are AEAD-only and use Curve25519/Ed25519. The libsodium CVE rate
remains close to zero through 2024-2026 — a deliberate consequence of removing optionality
that history shows is dangerous. Use libsodium for new application-layer encryption work
unless you have specific reason to use a different library.

**BoringSSL / Google Tink:** Google's curated TLS stack and high-level crypto API,
respectively, have continued the "no-options dangerous API" approach. Tink supports
ML-DSA and SLH-DSA in C++ and Go; BoringSSL added X25519MLKEM768 in 2024.

**Library-side defense pattern:** prefer (a) AEAD-only APIs (libsodium, Tink, age),
(b) protocol-level libraries (rustls, HPKE implementations) over raw primitive libraries.
The CVE rate on "give me a raw RSA primitive" libraries dwarfs that of "give me an
authenticated channel" libraries — the surface area difference is the explanation.

### 16.5 Application-layer crypto: messaging-protocol post-quantum migration

**Signal — PQXDH (September 2023):** Signal's first PQ step. PQXDH augments the X3DH
session-establishment protocol by computing a shared secret that combines (a) X25519 key
agreement and (b) CRYSTALS-Kyber encapsulation, then mixes both into
the session root key
([signal.org/blog/pqxdh](https://signal.org/blog/pqxdh/);
[PQXDH specification](https://signal.org/docs/specifications/pqxdh/pqxdh.pdf)).
Hybrid security: an attacker must break BOTH X25519 ECDH AND ML-KEM to recover the session
root. The Double Ratchet (Section 8) is unchanged; PQXDH replaces only the initial X3DH
handshake. Formally verified at USENIX Security 2024
([Bhargavan et al.](https://www.usenix.org/system/files/usenixsecurity24-bhargavan.pdf)).

**Signal — Triple Ratchet + SPQR (October 2025):** Signal's second PQ step adds the Sparse
Post-Quantum Ratchet alongside the Double Ratchet. The Triple Ratchet mixes outputs from
the symmetric DR chain, the DH DR ratchet, and the new SPQR ratchet via KDF before
deriving per-message keys. Post-compromise security and forward secrecy now both hold
under PQ assumptions
([signal.org/blog/spqr](https://signal.org/blog/spqr/);
[SPQR repository](https://github.com/signalapp/SparsePostQuantumRatchet)).
Designed with PQShield, AIST, and NYU; based on Eurocrypt 2025 + USENIX Security 2025
papers. Formally verified before deployment. This is the second-generation PQ messaging
deployment, addressing the "PQXDH only protects session establishment" gap.

**Apple iMessage — PQ3 (February 21, 2024):** Released with iOS 17.4 / iPadOS 17.4 /
macOS 14.4 / watchOS 10.4
([security.apple.com/blog/imessage-pq3](https://security.apple.com/blog/imessage-pq3/);
[Stebila security analysis](https://security.apple.com/assets/files/Security_analysis_of_the_iMessage_PQ3_protocol_Stebila.pdf)).
Architecture: each device generates a CRYSTALS-Kyber public key alongside its ECDH key
during iMessage registration; session keys are derived from both during handshake; PQ3
adds **periodic post-quantum rekeying within conversations** so that a key compromise at
time t only exposes a bounded conversation window. Apple terms this "Level 3 security."
Formally analyzed at USENIX Security 2025
([Linker et al.](https://www.usenix.org/system/files/conference/usenixsecurity25/sec25cycle1-prepub-595-linker.pdf)).

**WhatsApp:** Public roadmap is less explicit than Signal/Apple, but research deployments
of hybrid Kyber + AES-256-GCM end-to-end encryption have appeared in 2024-2025 literature.
WhatsApp uses the Signal protocol under the hood, so the PQXDH / Triple-Ratchet adoption
curve is what to watch.

**Email crypto:** S/MIME and PGP/MIME ecosystems remain almost entirely classical. Modern
end-to-end email security (Hushmail, ProtonMail, Tutanota) layers passphrase-protected
private keys on classical primitives. PQC migration in S/MIME requires new CMS algorithm
identifiers (in progress at IETF LAMPS WG: ML-DSA in CMS, ML-KEM in CMS); deployment is
years behind messaging protocols. The operational consequence: long-lived email is the
single largest "harvest now, decrypt later" liability surface for most organizations.

### 16.6 Key management evolution (cloud KMS + HSM-as-a-Service)

The Section 13 framing — "cryptography is a component in a system" — translates directly
into key management. The 2024-2026 cloud KMS landscape has converged on a small set of
patterns worth knowing:

**AWS KMS:** ML-KEM hybrid PQ TLS for KMS endpoints (April 2025+); legacy CRYSTALS-Kyber
support phased out across AWS endpoints in 2026
([AWS Security blog](https://aws.amazon.com/blogs/security/ml-kem-post-quantum-tls-now-supported-in-aws-kms-acm-and-secrets-manager/)).
KMS supports envelope encryption (CMK wraps DEK), automatic key rotation (annual on
symmetric CMKs), and external key store (XKS) for customer-controlled HSM custody.

**Google Cloud KMS:** Post-quantum KEM support in preview from late 2025
([Google Cloud blog](https://cloud.google.com/blog/products/identity-security/announcing-quantum-safe-key-encapsulation-mechanisms-in-cloud-kms)).
Supports ML-KEM for asymmetric encryption; ML-DSA and SLH-DSA for digital signatures.
Cloud KMS HSM tier uses FIPS 140-2 Level 3 hardware.

**Azure Key Vault:** ML-KEM integration in 2025. Microsoft also introduced Azure Cloud HSM
in 2025, a single-tenant managed HSM based on Marvell LiquidSecurity adapters (FIPS 140-3
Level 3), replacing the older Dedicated HSM offering. The cloud-HSM-as-a-service shape —
provider-operated, customer-isolated — has converged across all three majors.

**Thales Luna HSM (firmware v7.9 / v7.9.1):** Production ML-KEM, ML-DSA, and LMS-HSS in
2024-2025
([Thales Luna PQC blog](https://cpl.thalesgroup.com/blog/encryption/luna-hsm-pqc-quantum-safe-encryption);
[firmware 7.9.1 release notes](https://data-protection-updates.gemalto.com/2025/09/24/new-luna-pqc-enhancements-luna-hsm-firmware-v7-9-1-and-universal-client-v10-9-now-available/)).

**PKCS#11 v3.1:** Approved as OASIS Standard in 2023, with implementation rollouts through
2024-2025 ([OASIS PKCS #11 v3.1 spec](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/csd01/pkcs11-spec-v3.1-csd01.html)).
ML-KEM and ML-DSA mechanisms arrive in v3.2 (v3.1 added LMS/HSS). Most cloud HSM and on-prem HSM vendors are at v3.1
parity through 2025.

**TEE-backed key custody:** Confidential computing platforms (Intel TDX, AMD SEV-SNP,
Arm CCA, Azure Confidential Computing, Google Confidential VM, AWS Nitro Enclaves) have
matured to the point where key-bearing services can be co-located with workloads in
hardware-isolated execution. The operational pattern: derive process-instance keys via
remote attestation, sealed by the platform measurement; rotate on every new enclave
launch. See `confidential_computing_expertise.md` for the attestation and sealing primitive
catalog.

### 16.7 Cryptographic agility frameworks: CBOM and crypto-inventory

The Section 13 caution about cryptographic agility ("necessary evil") has been operationalized
in 2024-2025 into structured crypto-inventory tooling. The PQC migration forced the question:
"What cryptography are we even running today?" The answer, for most organizations, was
"we don't know" — and that's the gap CBOM addresses.

**Cryptographic Bill of Materials (CBOM):** A structured inventory describing every
cryptographic asset in a software system — algorithms, keys, certificates, libraries, the
relationships between them — analogous to SBOM for general software components
([CycloneDX CBOM capability](https://cyclonedx.org/capabilities/cbom/);
[IBM/CBOM GitHub](https://github.com/IBM/CBOM)).
Standardized in **CycloneDX 1.6 (early 2024)** as a first-class extension, with native
support for cryptographic component types and `uses`/`implements` dependency relationships.
Etsi/IQC QSC 2024 workshop produced the standardization paper
([IBM Research](https://research.ibm.com/publications/standardization-of-cryptography-bill-of-materials-in-owasp-cyclonedx)).

**Why CBOM is load-bearing for PQC migration:**
1. **Discovery prerequisite:** You cannot migrate what you don't know exists. CBOM enumerates
   the algorithms, libraries, and protocols in use, including transitively-included
   dependencies. Modern codebases have hundreds of cryptographic touchpoints; manual
   inventory is intractable.
2. **Quantum-readiness assessment:** Once enumerated, each asset can be classified as
   quantum-vulnerable (RSA, ECDSA, ECDH, classical DH), quantum-safe (ML-KEM, ML-DSA, SLH-DSA,
   symmetric ≥AES-128), or hybrid. Migration sequencing follows the classification.
3. **Continuous monitoring:** CBOM is generated at build time alongside the SBOM, so
   algorithm/library drift is detected on every CI run. Replaces ad-hoc "is anyone still
   using RSA-1024 anywhere?" audits.

**CBOM ecosystem tooling (2024-2026):** sbomify, Checkmarx, QuSecure, Sandbox AQ, IBM
Crypto Discovery, and others build crypto-inventory scanners on top of the
CBOM schema. The integration model: CI pipeline produces SBOM+CBOM artifacts on every
build; an inventory store maintains organizational view; alerts fire on
deprecated-algorithm introduction.

**NIST SP 1800-38** (preliminary draft series, 2023) provides the NCCoE migration
playbook integrating CBOM with the broader cryptographic-modernization workflow. The
SP 1800-38B document is the inventory-and-discovery sub-workflow.

### 16.8 Random number generation: continued institutional caution

The Dual_EC_DRBG story (Section 13) is now 13+ years post-disclosure but the institutional-
trust lessons remain live. 2024-2026 developments in RNG-adjacent territory:

- **NIST SP 800-90 series** continues as the standardized DRBG framework (HMAC_DRBG,
  CTR_DRBG, Hash_DRBG; Dual_EC_DRBG officially deprecated and removed).
- **Intel CET / RDRAND posture:** RDRAND and RDSEED remain reachable on x86-64 but the
  practitioner default since the 2019 AMD bug in which RDRAND returned a fixed value after
  suspend/resume is to use RDRAND as one of multiple entropy sources, not
  as the sole source. Linux kernel's getrandom(2) blends RDRAND with /dev/urandom seeding;
  this hybrid posture is the right default.
- **Yarrow → Fortuna lineage** (Section 14) continues in production.
- **Hardware RNG quality controversies:** No new Dual_EC-magnitude incident has emerged
  publicly in 2024-2026. The continuing concern is opaque vendor-specific TRNG cores
  (especially in cheap embedded SoCs) where statistical testing is the only validation
  layer between the silicon and the higher-level entropy pool.

The defensive practitioner posture remains unchanged from Section 13: treat any
closed-process constant selection (curve parameters, DH groups, RNG seeds, TRNG vendor
implementations) as potentially hostile until verified by independent analysis.

### 16.9 Formal verification: now expected for new protocols

The 2024-2025 messaging deployments (PQXDH, iMessage PQ3, Signal Triple Ratchet) all
shipped with **published formal-verification proofs** before mass deployment, using tools
like Tamarin, ProVerif, and CryptoVerif. This is a marked shift from the 2010-decade norm
where formal verification was an academic post-hoc exercise (TLS 1.3 was famously verified
DURING design — the precedent that set this expectation).

The cross-cutting practitioner observation: any new cryptographic protocol designed in
2024+ without symbolic-model formal verification is taking on technical debt that the
community now considers avoidable. The tooling is mature; the cost is bounded; the
deployment-blocker risk of a Vaudenay/Bleichenbacher/Lucky-13-class flaw discovered
post-deployment is far higher than the verification cost. See
`formal_verification_protocols_expertise.md` for tool selection and case studies.

---

## 17. Summary: What Defines Staff-Level Cryptographic Expertise

**From the theoretical perspective (Boneh/Koblitz):**
1. Security definitions and reductions come first. A scheme without a reduction to a hard problem
   is an ad hoc construction. But also: verify the reduction is tight enough and the model is
   faithful before trusting the proof.
2. Concrete security matters more than asymptotic claims. At 128-bit security targets, a factor-
   2^30 reduction slack is the difference between "secure" and "broken."
3. The hard problems must actually be hard. LWE and MLWE appear robust; Shor's algorithm breaks
   ECC and RSA on a fault-tolerant quantum computer; deploy hybrid schemes now.

**From the adversarial perspective (Wong):**
4. Nonce reuse, padding oracles, and timing side-channels break more deployed systems than
   theoretical attacks. Audit every implementation against this failure catalog before worrying
   about lattice reduction attacks.
5. The implementation boundary is where theory and practice diverge. A provably secure scheme
   instantiated with PKCS#1 v1.5 padding, CBC mode, or a biased RNG is broken.
6. Format and parsing are attack surface. Bleichenbacher's attack exploits the structure of
   PKCS#1 v1.5 padding, not a flaw in RSA. The attack surface is in how the standard was applied.

**From the bridge perspective (Schneier):**
7. Cryptography is a component in a system. Perfect crypto does not save you if the key
   management is wrong, if the RNG is backdoored, or if the adversary can compromise the
   endpoint before encryption occurs.
8. Institutional trust in standards requires transparency. Dual_EC_DRBG happened inside NIST;
   the Juniper cascade happened inside an enterprise security product. Treat any closed-process
   constant selection (curve parameters, DH group generation, RNG seeds) as potentially hostile.
9. Encrypt-then-MAC, forward secrecy, authenticated encryption, and explicit algorithm lists
   with no downgrade paths are not theoretical preferences — they are engineering requirements
   demonstrated necessary by a decade of protocol attacks.
