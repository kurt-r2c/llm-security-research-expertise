# Privacy Engineering — Differential Privacy, MPC, Zero-Knowledge, and Data Subject Rights
## Staff-Level Privacy Engineering Guiding Principles

> **Framework:** Privacy engineering as a structural property of systems — distinct from
> compliance theater — drawing on the canonical lineages of differential privacy, secure
> multi-party computation, homomorphic encryption, zero-knowledge proofs, and the
> normative theory of contextual integrity.
>
> **Foundational researchers in scope:**
> - **Cynthia Dwork** (Gordon McKay Professor, Harvard SEAS; formerly Microsoft Research) —
>   co-author of *Calibrating Noise to Sensitivity in Private Data Analysis* (TCC 2006),
>   formalizing ε-differential privacy; co-author with Aaron Roth of *The Algorithmic
>   Foundations of Differential Privacy* (2014).
> - **Aaron Roth** (Henry Salvatori Professor, University of Pennsylvania) — DP textbook
>   coauthor; adaptive data analysis and the connection between DP and generalization.
> - **Frank McSherry** (founding scientist, Materialize Inc.; formerly Microsoft Research
>   SVC) — PINQ (*Privacy Integrated Queries*, SIGMOD 2009), first general-purpose DP
>   query platform.
> - **Ilya Mironov** (Meta; formerly Google Brain) — *Rényi Differential Privacy* (CSF
>   2017), the relaxation underlying RDP-based accounting in DP-SGD.
> - **Latanya Sweeney** (Daniel Paul Professor, Harvard Kennedy School; Data Privacy Lab)
>   — *k-Anonymity* (IJUFKS 2002); 1997 re-identification of Massachusetts Governor
>   William Weld from "anonymized" hospital discharge data.
> - **Andrew Chi-Chih Yao** (Tsinghua; 2000 Turing Award) — *How to Generate and Exchange
>   Secrets* (FOCS 1986), garbled circuits and the millionaires' problem.
> - **Shafi Goldwasser** (Simons/MIT/Weizmann; 2012 Turing Award), **Silvio Micali** (MIT;
>   2012 Turing Award), **Charles Rackoff** (Toronto) — *The Knowledge Complexity of
>   Interactive Proof-Systems* (STOC 1985), defining zero-knowledge proofs.
> - **Yehuda Lindell** (Head of Cryptography, Coinbase; Bar-Ilan on leave) — MPC
>   practitioner-research lineage; Unbound Security co-founder (acquired by Coinbase 2022);
>   IACR Fellow 2021.
> - **Craig Gentry** (TripleBlind; formerly IBM Research) — first FHE scheme (Stanford PhD
>   2009 under Dan Boneh; ACM Dissertation Award 2010).
> - **Pascal Paillier** (Cryptography Research, Inc.; CryptoExperts) — Paillier cryptosystem
>   (EUROCRYPT 1999); ISO/IEC 18033-6.
> - **Eli Ben-Sasson** (co-founder and President, StarkWare; formerly Technion) — zk-STARK
>   co-inventor; transparent succinct proofs with post-quantum security.
> - **Helen Nissenbaum** (Andrew H. and Ann R. Tisch Professor, Cornell Tech) —
>   *Privacy in Context* (2010), the contextual-integrity framework.
> - **Arvind Narayanan** (Princeton) and **Vitaly Shmatikov** (Cornell Tech) — *Robust
>   De-anonymization of Large Sparse Datasets* (Oakland 2008), Netflix Prize re-ident.
> - **Úlfar Erlingsson** (Apple; formerly Google) — RAPPOR (CCS 2014), first production-
>   scale local-DP deployment in Chrome.
> - **Keith Bonawitz** and **H. Brendan McMahan** (Google Research) — secure aggregation
>   (CCS 2017) and FedAvg (AISTATS 2017), Gboard's FL backbone.
>
> Sources: dwork.seas.harvard.edu publications; cis.upenn.edu/~aaroth/privacybook.html;
> Apple Differential Privacy Overview; arXiv 1702.07476 / 1605.02065 / 1607.00133 /
> cs/0610105 / 1611.04482; crypto.stanford.edu/craig; nissenbaum.tech.cornell.edu;
> eprint.iacr.org; SIAM J. Computing; ACM SIGMOD/CCS proceedings; US Census Bureau 2020
> Disclosure Avoidance documentation.

---

## 1. What Privacy Engineering Is, and Why It Is a Discipline

Privacy engineering is the practice of building systems whose privacy properties are
structural — guaranteed by the system's architecture and primitives — rather than procedural,
asserted by policy documents and incident playbooks. The discipline is distinct from privacy
compliance, which assesses whether existing systems satisfy regulatory checkboxes (GDPR
Article 6 lawful bases, CCPA opt-out mechanics, HIPAA Safe Harbor de-identification rules).
Compliance accepts the system as-is and asks "does this clear the bar?" Engineering changes
the system so the bar is irrelevant: the bad outcome cannot happen because the data was
never collected, the data was perturbed before storage, or the only operations defined over
the data preserve the privacy invariant by construction.

### The compliance vs. engineering failure mode

The dominant failure mode in industry is GDPR-by-process: a DPIA is filed, a consent banner
is added, annual training is completed, and the underlying system continues to store raw
PII indefinitely. The architecture has not changed; the legal artifacts have. Equifax 2017,
Marriott 2018, LinkedIn 2021, and Optus 2022 all involved companies with compliance programs
in place. Compliance is necessary; it is not sufficient.

GDPR-by-construction is the inverse: data minimization at collection time so the bad data
is not there to leak; cryptographic deletion so "right to be forgotten" is mechanical and
auditable; aggregate-only telemetry so the analytics surface is not a re-identification
attack surface; encryption that survives database compromise. GDPR Article 25's "data
protection by design and by default" mandate is the regulatory codification of this
distinction.

### The three pillars

A privacy-engineered system rests on three pillars:

1. **Data minimization** — collect, process, and retain only what is required for the
   declared purpose. The dominant violation is over-collection ("we might need this later"),
   converting data into permanent liability.
2. **Purpose limitation** — data collected for one purpose cannot be repurposed without
   re-consent. The dominant violation is purpose creep: analytics data later mined for ad
   targeting, abuse detection, law-enforcement requests, or model training.
3. **Technical privacy** — when data must be processed, apply mathematical constructions
   (DP, MPC, HE, ZK, federated learning, anonymous credentials) that bound information
   leakage. This pillar is where engineers have direct authority.

### Cross-references

- See [cryptography_expertise.md](cryptography_expertise.md) for the primitives layer
  (block ciphers, MACs, signature schemes, public-key encryption) that privacy
  constructions build on.
- See [adversarial_ml_model_security_expertise.md](adversarial_ml_model_security_expertise.md)
  §10 for DP-SGD as a defense against membership inference and model extraction.
- See [distributed_authz_expertise.md](distributed_authz_expertise.md) for anonymous-
  credential systems (BBS+, CL-signatures) as a privacy-aware authorization primitive.
- See [appsec_program_building_expertise.md](appsec_program_building_expertise.md) for
  the program-governance perspective: privacy as a stakeholder, DPOs, and incident
  response.
- See [smart_contract_evm_security_expertise.md](smart_contract_evm_security_expertise.md)
  for ZK-rollups and on-chain privacy mixers.
- See [detection_engineering_expertise.md](detection_engineering_expertise.md) for
  privacy-shaped flaws in code (PII logging, untracked telemetry flows).
- See [vulnerability_research_methodology_expertise.md](vulnerability_research_methodology_expertise.md)
  for surface enumeration that includes privacy as an attack target.

---

## 2. Differential Privacy: The Canonical Framework

Differential privacy (DP) is the most precise privacy notion that has been deployed at
production scale. Its definition, due to Dwork, McSherry, Nissim, and Smith
(*Calibrating Noise to Sensitivity in Private Data Analysis*, TCC 2006), captures privacy
as a property of randomized algorithms rather than a property of data:

A randomized algorithm M satisfies **ε-differential privacy** if for every pair of
neighboring datasets D, D' (differing in exactly one record), and for every measurable
output set S:

```
Pr[M(D) ∈ S] ≤ exp(ε) · Pr[M(D') ∈ S]
```

The intuition is that any individual's presence or absence in the dataset changes the
distribution of outputs by at most a multiplicative factor of exp(ε). When ε is small
(typically 0.1 to 10 in practice), an adversary observing the output cannot distinguish
whether any particular individual contributed.

This is a profound shift from earlier privacy notions (k-anonymity, l-diversity, naive
suppression). DP does not depend on assumptions about adversary background knowledge,
auxiliary datasets, or future linkage attacks. The guarantee is information-theoretic
within the model. The cost is that the guarantee is about randomized outputs, which means
exact answers are no longer available.

### Three workhorse mechanisms

**Laplace mechanism**: for numeric queries q with sensitivity Δq (max change over
neighbors), release M(D) = q(D) + Lap(Δq / ε). Satisfies ε-DP. Counting queries have
Δq = 1; Lap(1/ε) noise gives ε-DP. The workhorse for counting, summing, any bounded-
sensitivity query.

**Gaussian mechanism**: for (ε, δ)-DP, M(D) = q(D) + N(0, σ²) with σ = Δq · sqrt(2
ln(1.25/δ)) / ε for L2-sensitivity. Preferred for low-L2-sensitivity queries (typical
in ML gradients); scales better than Laplace for high-dimensional outputs. The δ
relaxation is what makes this practical — pure ε-DP would require Laplace, whose heavy
tails dominate the budget in high dimensions.

**Exponential mechanism** (McSherry-Talwar 2007): for non-numeric outputs (best of a
discrete set), sample r ∈ R with probability proportional to exp(ε · u(D, r) / (2 ·
Δu)) where u is utility and Δu its sensitivity. Canonical way to release discrete
answers.

### Privacy budget and ε accounting

The fundamental currency of DP is ε. Basic composition: k queries each at ε-DP yield
kε-DP. Advanced composition (Dwork-Rothblum-Vadhan 2010) gives a tighter (ε, δ)-DP
bound: k queries at (ε, δ)-DP compose to approximately (sqrt(2k ln(1/δ')) · ε +
k·ε(exp(ε) - 1), kδ + δ')-DP. The operational consequence: a ε = 1.0 lifetime budget
cannot accommodate 1000 queries at ε = 0.001 each — composition will give garbage
privacy. Real deployments allocate per-day budgets, query allowlists, and refuse queries
once exhausted.

### Rényi DP

Mironov's *Rényi Differential Privacy* (CSF 2017, arXiv 1702.07476) defines:

A mechanism M satisfies (α, ε)-Rényi DP if for neighboring D, D':

```
D_α(M(D) || M(D')) ≤ ε
```

where D_α is the Rényi divergence of order α > 1. RDP has cleaner composition (linear in
α): if M_1 is (α, ε_1)-RDP and M_2 is (α, ε_2)-RDP, the composition is (α, ε_1+ε_2)-RDP.
RDP converts cleanly to (ε, δ)-DP via a simple formula. This is the framework underlying
the privacy accountant in DP-SGD implementations (TF-Privacy, Opacus).

### Zero-Concentrated DP

Bun and Steinke (*Concentrated Differential Privacy: Simplifications, Extensions, and
Lower Bounds*, TCC 2016, arXiv 1605.02065) defines zCDP via the Rényi-divergence
formulation:

A mechanism is ρ-zCDP if for all α > 1: D_α(M(D) || M(D')) ≤ ρα.

Composition is additive: ρ_1-zCDP + ρ_2-zCDP = (ρ_1 + ρ_2)-zCDP. zCDP is widely used in
Census Bureau-style production deployments because the noise scaling and composition are
easier to reason about than (ε, δ)-DP.

### Local DP vs Central DP

In **central DP**, a trusted curator holds the raw dataset and applies noise to query
outputs. The privacy guarantee is against external observers; the curator sees raw data.
US Census Bureau, Microsoft Telemetry Insights, and most academic deployments use central
DP.

In **local DP**, each user perturbs their own data before sending it to a (potentially
untrusted) aggregator. The privacy guarantee holds even if the aggregator is malicious or
breached. The cost is much larger noise — local DP requires noise scaled to the entire
population, not just to query sensitivity. Apple Emoji/QuickType (since iOS 10), Google
RAPPOR (Chrome telemetry), and Microsoft Telemetry use local DP.

### Why people get DP wrong

Common deployment failures: adding Laplace noise without tracking budget ("we added
noise" is not a DP deployment; ε must be quantified and accumulated); treating ε as a
tuning knob (ε > 10 provides almost no guarantee against linkage; production targets
0.1-5, though Census 2020 used 17.14 after public debate); conflating ε with δ (δ must
be cryptographically small, δ ≪ 1/N for population N, not "small enough"); forgetting
post-processing immunity (functions of DP outputs are DP, but noise cannot be reduced
after the fact); ignoring budget exhaustion (Apple and Census enforce hard cutoffs; most
ad-hoc deployments do not); assuming DP protects against fingerprinting of the model
itself (DP-SGD bounds but does not eliminate training-data leakage; see §3 and
[adversarial_ml_model_security_expertise.md](adversarial_ml_model_security_expertise.md)).

---

## 3. DP in Machine Learning: DP-SGD

DP-SGD (Abadi et al., *Deep Learning with Differential Privacy*, CCS 2016, arXiv
1607.00133) is the canonical framework for training NNs with DP guarantees. Two
ingredients: **per-sample gradient clipping** (bound each example's gradient norm to C,
limiting per-example sensitivity); **Gaussian noise injection** (add N(0, σ²C²I) to the
summed clipped gradients before averaging). Privacy is tracked via an RDP accountant
over training iterations. Implementations: TF-Privacy (Google), Opacus (Meta/PyTorch),
JAX-Privacy (DeepMind).

### The privacy-utility tradeoff

DP-SGD costs accuracy. Rules of thumb: at ε 1-10 with dataset sizes 100K-10M, standard
image classification degrades 1-10 percentage points; small datasets make DP-SGD
infeasible (noise dominates signal); pretraining on public data + DP fine-tuning on
private data is often the winning pattern (public pretraining provides representational
learning; only the fine-tune step spends budget).

### Federated learning with DP

**User-level DP** — unit of privacy is one user (all their samples). Gboard's DP-FedAvg.
Strongest guarantee, largest accuracy cost. **Example-level DP** — unit is one example.
Cheaper, weaker; meaningful only when users contribute roughly equal data.

Cross-link: [adversarial_ml_model_security_expertise.md](adversarial_ml_model_security_expertise.md)
§10 covers DP-SGD as a defense against membership inference and model extraction;
privacy/utility curves there quantify the tradeoff.

---

## 4. DP in Production: Real Deployments

### Apple Emoji and QuickType (since iOS 10, 2016)

Apple's local-DP deployment uses count-mean sketch + Hadamard count-mean sketch
constructions over hashed strings. Each device performs randomized response on its local
distribution and submits a perturbed report. Per-feature budgets: emoji ε = 4 (one
donation/day); QuickType ε = 8 (two/day); lookup hints ε = 8 (two/day). These ε values
are higher than typical academic recommendations (≤1), reflecting the production-versus-
research tension on utility-privacy tradeoffs.

### Google RAPPOR (since 2014)

RAPPOR (Erlingsson, Pihur, Korolova; CCS 2014) is the first deployed local-DP system at
scale. Each Chrome user applies randomized response to a Bloom filter of categorical
values. Two-step randomized response (permanent + instantaneous) handles the longitudinal
setting where a user reports the same value many times: privacy does not degrade with
repeated reports.

### US Census Bureau 2020 — TopDown Algorithm

The largest production DP deployment ever. The Census Bureau's TopDown Algorithm applies
zCDP to the entire 2020 Decennial Census tabulation pipeline: inject calibrated Gaussian
noise at the lowest geographic level (block), then hierarchical post-processing (block
→ block group → tract → county → state → nation) enforces consistency (sums add up,
counts non-negative). Global budget: ε = 17.14, ρ ≈ 2.63 for zCDP. The choice was
controversial — civil-rights groups argued it was too high; statisticians argued too low
for small populations. The Census Bureau's working papers are the most thorough public
analysis of a production DP deployment.

### Common production patterns

Across these deployments: epsilon-per-day budgets (privacy consumed per day, not per
query); query allowlists (only pre-vetted queries allowed); post-processing immunity
exploited (analysts work on noisy outputs); hard budget cutoffs when exhausted; public ε
disclosure as part of the deployment's contract.

---

## 5. K-Anonymity, l-Diversity, t-Closeness: The Pre-DP Era

Before DP, the dominant privacy notion was syntactic anonymization. **k-anonymity**,
formalized by Latanya Sweeney (*k-Anonymity: A Model for Protecting Privacy*, IJUFKS
2002), requires every record to be indistinguishable from at least k-1 others with
respect to chosen "quasi-identifiers" — attributes usable for linkage (zip, DOB, gender,
race).

The empirical motivation was Sweeney's 1997 re-identification of Governor Weld's medical
records. The Massachusetts Group Insurance Commission released hospital discharge data
with names stripped; Sweeney showed that combining zip code, birth date, and gender
(present in both the discharge data and the publicly-available voter registration roll
she purchased for $20) uniquely identified Weld. She mailed him his medical records.
The episode became the canonical demonstration that quasi-identifiers defeat naive
de-identification.

### Why k-anonymity is broken by composition

Three structural weaknesses: **homogeneity attack** — if all k records in an equivalence
class share the same sensitive value, k-anonymity provides no privacy. Machanavajjhala
et al. (2007): Alice knows Bob is 31, American, male, zip 13053; the 4-anonymous patient
table has all four matching records diagnosed with cancer; Alice infers Bob's diagnosis.
**Background knowledge attack** — Alice knowing Bob doesn't have heart disease reduces
the effective diversity. **Composition attack** — two k-anonymous releases of the same
dataset (to different research groups) can break anonymity when joined.

The Narayanan-Shmatikov Netflix Prize attack (Oakland 2008) demonstrated all three
empirically. 8 movie ratings (allowing 2 errors, ±3 days) uniquely identifies 96% of
500K subscribers in the released dataset; cross-correlation against IMDb reconstructed
sensitive non-public information.

### l-Diversity and t-Closeness

**l-Diversity (Machanavajjhala et al. 2007)** — each equivalence class contains at least
l "well-represented" values per sensitive attribute. Variants: distinct l (≥l distinct
values), entropy l (entropy ≥ log(l)), recursive (c, l) (bounds on most-common value
frequency). Addresses homogeneity but not skewness/similarity attacks (l values
technically distinct but semantically near-identical: "stomach cancer," "lung cancer,"
"pancreatic cancer").

**t-Closeness (Li-Li-Venkatasubramanian 2007)** — sensitive-attribute distribution
within each equivalence class is close (within t earth-mover's distance) to the
dataset-wide distribution. Addresses skewness at significant utility cost.

### When k-anonymity is still useful

Single-release scenarios (composition doesn't apply); low-dimensional data (3-5 quasi-
identifiers); regulatory compliance (HIPAA Safe Harbor effectively requires k-anonymity-
style suppression of 18 quasi-identifiers). Operational rule: low-dimensional, single-
release, k ≥ 5, verify l-diversity for sensitive attributes. For anything else, use DP.

### The AOL search-log incident (2006)

August 2006: AOL released 20M search queries from 650K users with identifiers replaced
by random numbers but query histories intact. *The New York Times* identified
individuals within days; AOL retracted the data, fired the researchers, and the CTO
resigned. Identifier removal without thinking about quasi-identifiers is not
anonymization — the canonical industry example of a privacy release done wrong.

---

## 6. Multi-Party Computation (MPC)

MPC enables multiple parties holding private inputs to jointly compute a function of
those inputs without revealing the inputs to each other. The canonical example: two
millionaires want to know who is richer without revealing their wealth. The general
formulation: parties P_1, ..., P_n with private inputs x_1, ..., x_n want to compute
f(x_1, ..., x_n) such that each party learns only f(...) and what can be inferred
from it.

### Yao's Garbled Circuits (1986)

Yao's *How to Generate and Exchange Secrets* (FOCS 1986) introduced the garbled-circuit
construction for two-party MPC. Party A (garbler) takes a Boolean circuit for f and
assigns each wire two random labels (one per bit). For each gate, A computes a garbled
truth table encrypting the output label under the two input labels. A sends the garbled
circuit + A's input labels to B; B obtains its input labels via oblivious transfer (B
learns only its actual-input labels without revealing them); B evaluates gate-by-gate
and obtains output labels; A reveals the label-to-bit mapping. B learns f(x, y) only;
A learns nothing about B's input. Secure against semi-honest parties in the OT-hybrid
model.

### Subsequent constructions

- **GMW (Goldreich-Micali-Wigderson 1987)** — first proof that any function can be
  securely computed by n parties when a majority is honest. Uses secret sharing +
  multiplication protocols. Generalizes Yao to n > 2.
- **BGW (Ben-Or-Goldwasser-Wigderson 1988)** — information-theoretic MPC, honest-
  majority. Shamir secret sharing; local operations + re-sharing for multiplications.
  Requires t < n/3 corrupted (passive) or t < n/4 (active).
- **SPDZ (Damgård-Pastro-Smart-Zakarias 2012)** — modern dishonest-majority MPC. Secret
  sharing + information-theoretic MACs to detect cheating. Practical for n up to ~100.
  MASCOT, MP-SPDZ, SCALE-MAMBA are production references.

### Threshold signatures as canonical MPC application

Multi-party signature schemes where the signing key is never reconstructed. Deployments:
Coinbase MPC custody (threshold ECDSA/EdDSA/Schnorr); Fireblocks (institutional crypto);
Ethereum proposer-builder separation in some designs. Yehuda Lindell's lineage (Unbound
Security → Coinbase 2022) is the canonical practitioner path.

### Private Set Intersection (PSI)

Two parties each hold a set; both learn the intersection without revealing non-
intersecting elements. Deployments: **Apple-Google COVID Exposure Notification (2020)**
— phones generate daily rolling proximity identifiers (RPIDs) and broadcast via BLE;
positive-test users upload daily keys; other phones download and locally compute
proximity (PSI-flavored, not classical PSI). **Google password breach checking** — PSI
variants (k-anonymity + hashed prefixes) so Chrome warns of breach without sending the
full password hash. **Ad attribution measurement** — networks measure conversion without
revealing user-level click data.

### MPC vs HE: when does each make sense?

MPC is multi-round, requires online communication, but per-round computation is fast;
best for low-latency interactions among a small number of parties. HE is non-interactive
but 1000x-1M+ slower than plaintext; best for one-shot offloaded computation. Hybrid
protocols (HE-encrypt-and-compute + MPC-decrypt-and-share) dominate when both
flexibility and efficiency are required.

### Practical libraries

MP-SPDZ (Bristol; production SPDZ, Boolean + arithmetic); ABY (Darmstadt; mixed-protocol
two-party); libOTe (Visa; oblivious transfer); EMP-toolkit (Yale; general semi-honest);
MOTION (Aarhus; composable framework); PSI-Cardinality (Google), DPF-PIR (Princeton).

---

## 7. Homomorphic Encryption (HE)

HE allows arbitrary computations on encrypted data: given Enc(x) and Enc(y), one can
compute Enc(f(x, y)) for some class of functions f. Three regimes:

### Partial HE

Allows one operation only.

- **Paillier (Paillier 1999)** — additive. Enc(x) · Enc(y) = Enc(x + y). Used in ISO/IEC
  18033-6. The dominant choice for federated learning secure aggregation and for
  small-aggregate analytics queries.
- **RSA** — multiplicative (textbook RSA, not used in practice due to deterministic-
  encryption pitfalls).
- **ElGamal** — multiplicative (over groups); also extends to exponential ElGamal for
  additive in the exponent (useful for sums over small ranges).

### Somewhat HE (SwHE)

Allows a limited number of operations. The "circuit depth" is bounded by the noise
growth — each operation increases noise; once noise crosses a threshold, decryption
fails.

### Fully HE (FHE)

Allows unbounded operations. Gentry's 2009 breakthrough showed how to take a SwHE scheme
and "bootstrap" it: re-encrypt the ciphertext under the same scheme to refresh the noise
budget. The first FHE was based on ideal lattices; subsequent schemes use simpler
lattice structures.

### Modern FHE schemes

**BGV (Brakerski-Gentry-Vaikuntanathan 2012)** — integer arithmetic modulo a large
prime; SIMD via CRT packing. **BFV (Brakerski-Fan-Vercauteren 2012)** — similar to BGV
with different noise management. **CKKS (Cheon-Kim-Kim-Song 2017)** — approximate
arithmetic over real/complex numbers; the dominant choice for HE-on-ML because real-
valued operations don't require exact arithmetic. **TFHE (Chillotti-Gama-Georgieva-
Izabachène 2016)** — Boolean-circuit FHE with fast bootstrap (~10ms per gate); used in
Zama Concrete.

### The performance reality

FHE is slow. As of 2024-2025: single CKKS multiplication ~1-10ms; TFHE bootstrap
~10-100ms; neural network inference 1000x-1M+ slower than plaintext; ciphertexts
1000x-100,000x larger than plaintexts. FHE is not a drop-in for plaintext computation;
useful for small aggregate queries (sum/mean/dot product over a few thousand records),
small-model private-input inference, and batch processing where latency is not critical.

### When FHE is practical

HE inference on private input (model public, input private; medical imaging); private
set membership (encrypted query against Bloom filter or PSI structure); encrypted-index
small-result queries; confidential blockchain transactions (Aztec Network uses FHE-
flavored techniques alongside ZK).

### Production libraries

Microsoft SEAL (BFV/BGV/CKKS, MIT-licensed, dominant in industry); IBM HElib (BGV/CKKS,
mature); OpenFHE (PALISADE successor; BGV/BFV/FHEW/CKKS); Zama Concrete (TFHE compiler;
Python → FHE; most accessible developer experience); Concrete ML (scikit-learn-
compatible FHE-ML); Lattigo (Go CKKS/BFV).

Cross-link: [cryptography_expertise.md](cryptography_expertise.md) §11 covers the
lattice cryptography foundations (LWE, Ring-LWE) that FHE schemes build on.

---

## 8. Zero-Knowledge Proofs (ZKPs)

A zero-knowledge proof allows a prover P to convince a verifier V that a statement is
true without revealing why it is true. Three properties:

1. **Completeness** — if the statement is true, an honest prover convinces an honest
   verifier.
2. **Soundness** — if the statement is false, no cheating prover can convince an honest
   verifier (except with negligible probability).
3. **Zero-knowledge** — the verifier learns nothing beyond the truth of the statement.

### The foundational paper

Goldwasser, Micali, and Rackoff's *The Knowledge Complexity of Interactive Proof-Systems*
(STOC 1985; SIAM J. Computing 1989) introduced the formal definition. The original
constructions were for quadratic residuosity and discrete logarithm — interactive
protocols where the verifier asks random challenges and the prover responds.

### Fiat-Shamir transform

Fiat and Shamir (1986) showed how to make interactive ZK proofs non-interactive: replace
the verifier's random challenges with a cryptographic hash of the prior protocol
transcript. The resulting non-interactive proof is secure in the random oracle model.
Fiat-Shamir is the construction underlying Schnorr signatures, EdDSA, and modern
zk-SNARK constructions.

The "Frozen Heart" class of vulnerabilities (Trail of Bits 2022) showed that many
Fiat-Shamir implementations get the hash domain wrong — failing to include all
protocol-relevant data in the hash. This breaks soundness. Implementations of ZK
protocols must be audited specifically for Fiat-Shamir hash-input completeness.

### zk-SNARKs

Succinct Non-interactive Arguments of Knowledge — the dominant family of practical ZK
proofs. Proof size O(λ); verification time polylogarithmic in circuit size; single
message prover → verifier; computational soundness. Major constructions: **Pinocchio
(Parno-Howell-Gentry-Raykova 2013)** first practical SNARK, trusted setup per circuit;
**Groth16 (Groth 2016)** most-deployed SNARK in production blockchain (Zcash, Tornado
Cash), proof ~200 bytes, trusted setup per circuit; **PLONK (Gabizon-Williamson-
Ciobotaru 2019)** universal trusted setup, dominant modern construction; **Halo/Halo2
(Zcash 2019)** no trusted setup, recursion for amortization.

### zk-STARKs

Ben-Sasson et al.'s alternative (*Scalable, Transparent, and Post-Quantum Secure
Computational Integrity*, ePrint 2018/046): no trusted setup (soundness relies only on
collision-resistant hash); post-quantum secure (subject to hash function's resistance);
quasi-linear prover, polylogarithmic verifier; larger proofs (50-200KB vs ~200 bytes for
SNARKs). StarkWare (co-founded by Eli Ben-Sasson) productized via StarkNet and StarkEx.

### ZK-rollups and on-chain privacy

Cross-link: [smart_contract_evm_security_expertise.md](smart_contract_evm_security_expertise.md).
ZK-rollup pattern: thousands of off-chain transactions aggregated into a single proof of
state-transition validity, verified on-chain. Privacy variants: Tornado Cash (now
sanctioned) used Groth16 proofs of Merkle-tree membership for anonymous deposits/
withdrawals; Aztec Network uses PLONK for programmable privacy; zkSync, StarkNet,
Polygon Hermez are scalability-focused ZK-rollups.

### ZK for private credentials

**Anonymous Credentials (Camenisch-Lysyanskaya 2001)** — sign a set of attributes;
prove possession without revealing them. **BBS+ Signatures (Boneh-Boyen-Shacham 2004)**
— used in W3C Verifiable Credentials Data Model 2.0; the dominant selective-disclosure
choice. **U-Prove (Microsoft)** — less widely adopted. Cross-link:
[distributed_authz_expertise.md](distributed_authz_expertise.md) on anonymous credentials
as a privacy-preserving authorization primitive.

### WPA3-Dragonfly as ZK-flavored authentication

WPA3's SAE (Simultaneous Authentication of Equals) is a password-authenticated key
exchange where neither party reveals the password — conceptually similar to ZK. SAE-
Dragonfly had implementation bugs revealed in Vanhoef's Dragonblood 2019 disclosures
(see [cryptography_expertise.md](cryptography_expertise.md)).

### Practical libraries

Circom + snarkjs (iden3; Groth16/PLONK, Ethereum ecosystem); arkworks (Rust; full ZK
ecosystem); Halo2 (Zcash; plonkish circuits); Cairo (StarkWare; STARK-native DSL); Noir
(Aztec; Rust-like ZK language); EZKL/Ezkl-rs/ZKDL (zkML for ML inference proving).

---

## 9. Data Subject Rights Operationalization (GDPR/CCPA Reality)

GDPR (effective 2018) and CCPA/CPRA (effective 2020/2023) granted data subjects
enforceable rights over their personal data. The technical operationalization of these
rights is where compliance meets engineering.

### The Right to Be Forgotten (RTBF / Right to Erasure, GDPR Article 17)

Technical challenges:

1. **Backups.** Production deletion is easy; backup deletion is hard. Most organizations
   have 30-90 day backup retention. Pragmatic approach: production deletion within 30
   days; backup deletion on rotation (data is at most one rotation stale). DPAs accept
   this when documented and when backup access controls are tight.

2. **ML training data.** Data deletion does not remove the model's encoding of that
   data. The "machine unlearning" research area (Bourtoule et al. 2021, Ginart et al.
   2019) attempts removal of specific training examples' influence. Production
   approaches: periodic retraining with exclusions; federated unlearning; or disclose
   that the user's contribution is permanently encoded.

3. **Distributed systems.** A user record may be replicated across primary DBs, read
   replicas, caches (Redis, Memcached, CDNs), search indices, data warehouses
   (Snowflake, BigQuery), analytics tools (Mixpanel, Amplitude), CRMs (Salesforce),
   email (Mailchimp), support (Zendesk), and third-party processors. Deletion requires
   fan-out across all of them. Tooling: Privado, Bigid, Securiti, OneTrust
   DataDiscovery. Track via documented data inventory with declared sub-processors.

4. **Cryptographic deletion.** When physical deletion is hard (immutable backups,
   append-only logs, blockchain), encrypt with a per-user key; delete the key on RTBF.
   The ciphertext remains but is unrecoverable. Apple Private Cloud Compute uses this:
   the data volume's keys are randomized on reboot and not persisted, so a reboot is
   cryptographic erasure.

### Data Portability (GDPR Article 20)

The right to receive personal data in "structured, commonly-used, machine-readable
format." Export to JSON/CSV; document the schema (W3C Data Privacy Vocabularies,
schema.org, or custom); include both user-provided and derived data; distinguish "what
the user gave us" from "what we inferred." The EU Data Act 2024 extends portability to
IoT and connected-device data — a structural change most IoT vendors are not architected
for.

### Subject Access Requests (SARs) at scale

GDPR Article 15: 1 month. CCPA: 45 days. At scale this is a federated-query problem:
production DB extract, log-archive search (often requiring un-pseudonymization),
warehouse user-event queries, third-party processor SAR fan-out via DPA-defined
mechanisms. Mature programs have automated pipelines producing a packaged export within
SLA; immature programs treat each SAR as a manual project.

### Consent Management

Platforms (OneTrust, TrustArc, Sourcepoint, Didomi) display banners, record choices,
enforce server-side, update over time, and surface consent state to the back-end. The
dominant failure mode: user-hostile theater (accept-all prominent, reject-all hidden,
"legitimate interest" defaulted on, dark patterns on opt-out flows). The European Data
Protection Board has issued guidance against these (2022, 2023); CNIL fines (€100M
Google 2021, €60M Microsoft 2022, €40M Facebook 2023) targeted exactly this pattern.

### Apple Private Cloud Compute: GDPR-by-construction at scale

Announced June 2024. Architecture: hardware root of trust (custom Apple silicon with
Secure Enclave; Secure Boot guarantees only Apple-signed code runs); stateless inference
(each request executes on a node and the node is wiped; Secure Enclave randomizes data
volume keys on reboot and does not persist them); code integrity (all code in a trust
cache signed by Apple, immutable at runtime); verifiable transparency (Apple publishes
binaries + code-signing measurements; third-party auditors verify); privacy-preserving
routing (OHTTP-style relays so PCC infrastructure does not see request metadata). The
closest thing to "GDPR-by-construction" deployed at scale; the model competitors will be
measured against.

Cross-link: [appsec_program_building_expertise.md](appsec_program_building_expertise.md)
on privacy stakeholders (DPOs, Privacy Counsel) and SAR/RTBF governance.

---

## 10. Federated Learning + Private Analytics

Federated learning (FL) trains models without centralizing the training data. The
canonical formulation:

1. Central server has a global model G_t.
2. Server selects a subset of clients (devices, hospitals, organizations).
3. Each client downloads G_t, trains for some epochs on its local data, and uploads a
   model update (gradient or weight delta).
4. Server aggregates the updates to produce G_{t+1}.

The privacy story: raw data never leaves the client. But this is a weaker guarantee
than it appears — gradients can leak training data (see "gradient leakage attacks":
Zhu-Liu-Han 2019, Geiping et al. 2020). Production federated systems must combine FL
with additional protections.

### FedAvg (McMahan et al., AISTATS 2017)

The dominant FL algorithm. Each client runs E epochs of SGD on its local data; the
server averages the resulting weights weighted by dataset size. Variants: FedProx
(proximal regularization for client heterogeneity), FedAdam, FedYogi (adaptive
server-side optimizers).

### Production deployments

**Google Gboard** — Android predictive text trains a recurrent language model on
millions of devices' typing data without uploading raw text (Hard-Sutton-Konečný-McMahan
2018). **Apple QuickType** — similar iOS pattern, less public detail. **Cross-silo
medical research** — multiple hospitals jointly train without sharing patient records;
NVIDIA Clara FL, OpenMined PySyft, Flower.

### "Federated learning is not enough"

Bonawitz et al. (CCS 2017) and later Geiping et al. showed raw gradients can
reconstruct training data. Defense: combine FL with **DP-FedAvg** (DP at server
aggregation; user-level DP requires clipping each update and adding noise to the sum);
**secure aggregation** (server learns only the sum, not individual updates; Bonawitz et
al. 2017); **threshold cryptography** (no single server can decrypt an individual
update). Production stack: secure aggregation + DP at the server. Gboard uses this.

### Cross-device vs cross-silo

**Cross-device** — many (millions) clients, small datasets, unreliable participation.
Gboard, QuickType. Optimization: client sampling, asynchronous aggregation, on-device
training fitting in <100MB RAM. **Cross-silo** — few (2-100) clients, large datasets,
reliable participation. Medical consortia, cross-bank fraud. Optimization: richer
computation per round, possibly HE-protected aggregation.

### Practical libraries

TensorFlow Federated (Google; reference Python FL); Flower (open-source; PyTorch/TF/
JAX); PySyft (OpenMined; PPML focus); NVIDIA Clara FL (medical imaging); FATE (WeBank;
deployed in Chinese fintech).

---

## 11. Helen Nissenbaum's Contextual Integrity

The technical privacy literature has historically optimized for information-theoretic
guarantees: how much information leaks, under what adversary model. Nissenbaum's
*Privacy in Context: Technology, Policy, and the Integrity of Social Life* (Stanford
University Press, 2010) argues this framing is structurally incomplete. The right
question is not "does this leak information?" but "is the information flow appropriate
to the context?"

### The five parameters

A flow is defined by: **data subject** (the person the information is about), **sender**
(transmitting party), **recipient** (receiving party), **information type** (medical
record, financial record, political affiliation), and **transmission principle** (with
consent, for billing, for medical treatment, under court order). A flow is appropriate
when it conforms to contextual norms over all five parameters. Violations occur not when
information leaks but when the flow deviates from contextual norms.

### Worked examples

A patient telling their doctor about a symptom is appropriate; the doctor selling that
to a pharmaceutical company is not (same data, same subject, different recipient and
transmission principle). A user sharing location with Google for navigation is
appropriate; Google selling that location to advertisers is contextually inappropriate
even when "consent" has been buried in a ToS. An employee giving HR their address is
appropriate; HR sharing it with marketing is not.

### Operational application

Contextual integrity bridges technical privacy guarantees (DP, MPC, HE, ZK) and policy/
legal frameworks (GDPR, CCPA, HIPAA, FERPA). The technical guarantee — "we applied DP
with ε = 1" — is necessary but not sufficient; the remaining question is whether the
flow is appropriate at all.

For AI systems, contextual integrity surfaces underexplored harms: chatbot conversations
about symptoms have medical-conversation norms (reuse for training or advertising
violates them even if "consented to"); smart-speaker audio should flow only to intended
functions (not ad targeting, law-enforcement subpoenas, or third-party developer
access); wearable heart-rate data has medical norms (sharing with employers for
wellness/insurance is contextually inappropriate).

Engineering teams that internalize contextual integrity enumerate the contexts in which
data was collected, design uses that respect those contexts, and reject use cases that
violate contextual norms regardless of whether DP/MPC/etc. would technically allow them.

---

## 12. Adversarial Privacy: Deanonymization Attacks

The theory of privacy is shaped by demonstrated attacks. This section catalogues the
canonical empirical failures.

### Netflix Prize (Narayanan-Shmatikov 2008)

Released: 500K subscribers' movie ratings minus names/IDs. Narayanan-Shmatikov: 8
ratings + dates (2 errors, ±3 days) uniquely identifies 96% of subscribers. Cross-
correlating against IMDb reconstructs subscribers' identities along with their full
Netflix ratings — including politically- or sexually-sensitive content. The dataset was
withdrawn; Netflix canceled the second prize. Lesson: high-dimensional behavioral data
is uniquely identifying with very few features; k-anonymity on naive quasi-identifiers
does not generalize.

### AOL Search Log Release (2006)

20M search queries from 650K users; identifiers replaced with random IDs. *The New York
Times* identified individuals within days ("Thelma Arnold, 62, of Lilburn, Georgia,
frequently searched for landscaping, divorce-recovery, and her friends' surnames"). AOL
retracted; the CTO resigned. Lesson: search queries are diary entries — aggregation of
small queries reveals identity.

### Strava Heatmap (2018)

Strava published a global heatmap of 27M users' running/cycling routes. Australian
researcher Nathan Ruser noticed glowing paths in the Syrian desert where US/allied
military bases were located. Revealed: base perimeters in Iraq/Afghanistan/Syria,
supply routes, patrol patterns, identifiable soldiers' routes around CIA black-site
facilities. Lesson: aggregated data preserves uniquely-identifying patterns; aggregation
does not provide DP-style guarantees unless it explicitly preserves no individual
signal.

### Linkage attacks against k-anonymity

General pattern: adversary obtains a k-anonymized dataset and a non-anonymized dataset
with overlapping attributes, joins on those attributes, and re-identifies records with
unique combinations. Works against essentially all k-anonymized real-world data because
real-world data is high-dimensional and quasi-identifiers are everywhere.

### Mobile location data and biometric leakage

de Montjoye et al. (*Unique in the Crowd*, 2013) showed that 4 spatio-temporal points
uniquely identify 95% of 1.5M users in a European mobile-network dataset. Extended to
credit-card transactions: 4 transactions ≈ 90% unique. Location traces are biometrics.

Other biometric channels: gait (accelerometer data, papers since 2007), typing rhythm
(keystroke dynamics identify >90% accuracy, Killourhy-Maxion 2009), voice (modern
speaker-ID >99% on short clips), mouse movements (cross-session identification). Any
"anonymous" telemetry that includes timing, movement, or audio is collecting biometric
data even if not labeled as such.

### Membership inference as deanonymization

Cross-link: [adversarial_ml_model_security_expertise.md](adversarial_ml_model_security_expertise.md)
§5. Membership inference against a model trained on D determines whether a specific
individual was in D — the ML analog of deanonymization. For models trained on sensitive
data (medical, financial, demographic), this is a privacy violation even when the model
output never directly reveals individuals.

### Genome deanonymization

Gymrek et al. (*Identifying Personal Genomes by Surname Inference*, Science 2013)
showed male Y-chromosome STRs can be linked to genealogy databases (FamilyTreeDNA,
Ysearch, MyHeritage) to recover surnames. Extended to autosomal matches. The Golden
State Killer was identified in 2018 by uploading crime-scene DNA to GEDmatch and
reverse-genealogy-searching. Contributing to a genetic database puts relatives at
re-identification risk even when they never contributed.

---

## 13. Privacy-Preserving Telemetry and Analytics

"I want product analytics but I can't see user identity" is one of the most common
privacy-engineering use cases.

**Probabilistic sketches.** HyperLogLog (cardinality, O(log log n)), Count-Min Sketch
(heavy hitters, O(log n)), Bloom Filter (set membership), t-Digest (quantiles, O(log
n)). No formal DP guarantees, but limit per-individual retention by construction;
combining with DP noise gives formal guarantees.

**Plausible deniability via Local DP.** Each client randomizes before sending; the
aggregator sees noisy reports. Apple QuickType and Google RAPPOR are canonical.

**Chrome Privacy Sandbox.** Topics API (browser computes top topics locally; only the
topic is shared with k-anonymity aggregation; re-identification attacks by Cohen et al.
2023; substantially revised); Protected Audience API / FLEDGE (on-device ad auction);
Attribution Reporting API (event-level and summary reports with DP noise). UK CMA,
German FCO, and EU Commission reviewing.

**Apple PCM / SKAdNetwork.** K-anonymized per-campaign attribution; conversion data
delayed and randomized. ATT (2021) requires explicit cross-app tracking opt-in; ~80% of
users opt out.

**Server-side vs client-side.** Client-side (Mixpanel, Amplitude, Segment) is easy but
visible to tracking-protection. Server-side captures more but is less inspectable.
Hybrid (PostHog reverse-proxy, RudderStack) proxies through your backend. 2025 trend:
server-side + DP-aggregated, driven by Safari ITP, Brave, Firefox ETP, regulatory.

---

## 14. Detection: Privacy-Shaped Flaws in Code

Privacy is a static-analysis target. Taxonomy of privacy-shaped flaws (cross-link:
[semgrep_rule_authoring](../static_analysis/semgrep_rule_authoring.md)):

**PII logging.** Log statements including known-PII variable names (`email`, `ssn`,
`phone`, `credit_card`, `password`, `dob`, `address`); request-body logging without
filtering; structured-log fields that are known PII; stack traces including user input.

```yaml
rules:
- id: pii-in-logs
  pattern-either:
  - pattern: logger.info(... $EMAIL ...)
    metavariable-pattern:
      metavariable: $EMAIL
      patterns:
      - pattern-regex: '(email|ssn|password|credit_card|dob)'
  - pattern: logger.debug(f"... {$EMAIL} ...")
```

**Untracked data flows from input to telemetry.** Taint: source = user input (bodies,
headers, query params); sink = telemetry endpoints (analytics, error reporting, ad
networks). Source-to-sink flow without intermediate sanitization is a candidate flaw.

**Lack of DP-budget enforcement** on aggregate queries — detect direct access to
designated "private" tables that bypass the DP wrapper.

**Long-retained logs of sensitive data.** Loggers writing to S3 without lifecycle
policies; CloudWatch log groups without retention; Sentry/DataDog events without
scrubbers.

**Untracked third-party data egress.** Outbound calls to telemetry endpoints without
explicit consent gating.

**Cross-tenant data leakage** in multi-tenant systems — queries without a tenant filter.

### The "data flow as the new tainted flow" framing

Just as traditional taint analysis tracks attacker-controlled data into sensitive sinks
(SQL queries, command execution), privacy-aware taint analysis tracks user-data into
privacy-sensitive sinks (logs, telemetry, third-party APIs, ML training pipelines).
The same machinery applies; the labels are different.

Cross-link: [detection_engineering_expertise.md](detection_engineering_expertise.md)
covers detection-engineering frameworks; [vulnerability_research_methodology_expertise.md](vulnerability_research_methodology_expertise.md)
§5 covers surface enumeration that includes privacy as an attack target.

---

## 15. Defensive Patterns

Consolidated playbook:

1. **Data minimization at collection.** Highest-leverage action. Documented inventory
   keyed by class (PII, financial, health, behavioral, derived); per-class purpose
   justification; 6-month reviews delete purposeless data.
2. **Purpose-based retention TTLs.** Auth tokens (session, max 30d); audit logs
   (regulatory minimum, 1-7y financial, 30d general); support tickets (~2y); analytics
   events (90d, then aggregates only). Enforce via S3/GCS/R2 lifecycle, `expires_at` +
   reaper jobs, or TTL-native time-series DBs.
3. **Aggregation before persistence.** Counts per (campaign, day, bucket) instead of
   clicks; hourly statistics instead of sensor readings; derived metrics instead of
   chat messages.
4. **DP for any released aggregate** with explicit ε. Central DP if curator is
   trusted; local DP otherwise.
5. **Cryptographic deletion for RTBF with backups.** Encrypt per-user data with per-user
   key; on RTBF, delete the key. Backups remain but cryptographically erased.
   ```
   user_data = encrypt(raw_data, user_key)
   user_key = derive(master_key, user_id, salt)
   # On RTBF: delete(user_key) and audit-log
   ```
6. **MPC for cross-org sharing.** Replace "send data" with "compute jointly under MPC."
   PSI for ad attribution, federated medical research, cross-bank fraud.
7. **ZK proofs for credential verification.** Replace "send credentials" with "prove
   validity under ZK." KYC without identity, age without DOB, membership without list.
8. **Federated learning** when central training is unacceptable. Combine with DP +
   secure aggregation.
9. **Anonymous credentials** (BBS+, Camenisch-Lysyanskaya) for unlinkable
   authentication.

### 10. Code review checklist

Before merging code touching user data, verify: (1) data necessary for documented
purpose; (2) retention defined and enforceable; (3) log statements scrubbed of PII; (4)
telemetry gated on consent; (5) third-party flows documented in DPA; (6) aggregate
queries DP-protected with documented ε; (7) data class consistent with consent flow; (8)
cross-tenant queries scoped to tenant_id; (9) backup retention aligned with deletion;
(10) derived data (recommendations, segments) treated as personal data; (11) flow
consistent with contextual integrity (sender, recipient, type, transmission principle);
(12) if ML training, DP-SGD or federated alternative considered; (13) if cross-org
sharing, MPC/PSI considered; (14) per-user cryptographic deletion keys defined; (15)
threat model documented (adversary, observation surface).

---

## 16. Variant Analysis: Under-Explored Frontiers

**Privacy for AI agents.** Two new surfaces: what the agent remembers (history, tool
calls, external observations — each a retention question; cross-link
[llm_agent_security_expertise.md](llm_agent_security_expertise.md) §5 on exfil), and
what the agent leaks (tool invocations to third parties; responses may include prior-
turn data or other users' contexts via training-data leakage; cross-link
[agentic_web_capabilities_expertise.md](agentic_web_capabilities_expertise.md)).
Emergent practice: per-conversation key isolation, short TTLs (24h non-summary),
explicit cross-session memory consent, DP on aggregate fine-tuning.

**Privacy in multi-tenant LLMs.** When fine-tuned on Customer A and queried by Customer
B: training data extraction (B prompts regurgitation; defenses: DP-SGD, output filtering,
per-tenant isolation); membership inference (B determines record presence; defenses:
DP, output randomization); side-channel inference (latency, embedding patterns,
tokenizer behavior reveal A's distribution; defenses: padded responses, randomized
timing). The "private inference" line (Microsoft CrypTFlow, OpenMined PrivateMLPipeline)
does inference under HE.

**DP for graph data.** Edge DP (neighbors differ in one edge) models relationship
privacy; Node DP (neighbors differ in one node) models individual privacy — much
stricter, harder. Deployments: Facebook DP-tuned social-graph queries; Microsoft DP-GNN
research.

**Privacy-preserving advertising frameworks.** Beyond Privacy Sandbox: Apple PCM
(deployed in Safari); Mozilla IPA (proposed, MPC+DP); Meta Private Lift Measurement
(MPC, deployed for large advertisers). Common pattern: replace per-user impression data
with aggregate campaign measurements under MPC+DP.

**Anonymous-but-rateable.** Anonymous credentials allow unlinkable authentication but
make rate-limiting hard. Periodic credentials (one per day) or counter-based credentials
(ZK proof of ≤N requests, private counter). Helios voting, Privacy Pass (Cloudflare
CAPTCHA-bypass), and ZK abuse-prevention systems use these.

**Privacy for biometric authentication.** Templates cannot be revoked once breached.
Cancelable biometrics (user-specific transformation; re-enroll on breach); fuzzy
commitments (template + random codeword, error-corrected on auth); biometric encryption
(derive a key from biometric; template never stored). ISO/IEC 24745:2022 is the
standard.

**Smart-home / IoT privacy at scale.** Concerns: continuous capture, cross-device
correlation, third-party processor exposure. Mitigations: on-device wake-word
processing (Siri Local, Google Assistant On-Device, Alexa Local Voice Control),
explicit capture indicators, federated learning for updates, opt-in cross-device
correlation. HomeKit is closest to "privacy-by-construction" for smart home: device-to-
device E2EE, local-first, opt-in cloud-relay per accessory category.

---

## 17. References

### DP foundations

- Dwork, McSherry, Nissim, Smith. *Calibrating Noise to Sensitivity in Private Data
  Analysis*. TCC 2006. https://dwork.seas.harvard.edu/publications/calibrating-noise-sensitivity-private-data-analysis
- Dwork, Roth. *The Algorithmic Foundations of Differential Privacy*. 2014.
  https://www.cis.upenn.edu/~aaroth/privacybook.html
- Mironov. *Rényi Differential Privacy*. CSF 2017. https://arxiv.org/abs/1702.07476
- Bun, Steinke. *Concentrated Differential Privacy*. TCC 2016.
  https://arxiv.org/abs/1605.02065
- Abadi et al. *Deep Learning with Differential Privacy*. CCS 2016.
  https://arxiv.org/abs/1607.00133
- McSherry. *Privacy Integrated Queries*. SIGMOD 2009.
  https://www.microsoft.com/en-us/research/publication/privacy-integrated-queries/

### K-anonymity and deanonymization

- Sweeney. *k-Anonymity*. IJUFKS 2002.
  https://epic.org/wp-content/uploads/privacy/reidentification/Sweeney_Article.pdf
- Machanavajjhala et al. *l-Diversity*. ACM TKDD 2007.
- Li-Li-Venkatasubramanian. *t-Closeness*. ICDE 2007.
- Narayanan, Shmatikov. *Robust De-anonymization of Large Sparse Datasets*. IEEE S&P
  2008. https://www.cs.cornell.edu/~shmat/shmat_oak08netflix.pdf
- de Montjoye et al. *Unique in the Crowd*. Scientific Reports 2013.

### MPC

- Yao. *How to Generate and Exchange Secrets*. FOCS 1986.
  https://mit6875.github.io/FA23HANDOUTS/yao-garbled-circuits.pdf
- Goldreich-Micali-Wigderson. *How to Play Any Mental Game*. STOC 1987.
- Damgård-Pastro-Smart-Zakarias. *Multiparty Computation from Somewhat Homomorphic
  Encryption*. CRYPTO 2012. (SPDZ)
- Bonawitz et al. *Practical Secure Aggregation*. CCS 2017.
  https://research.google/pubs/practical-secure-aggregation-for-privacy-preserving-machine-learning/
- Lindell. *Secure Multiparty Computation*. CACM 2021.
  https://eprint.iacr.org/2020/300

### HE

- Gentry. *A Fully Homomorphic Encryption Scheme*. Stanford PhD 2009.
  https://crypto.stanford.edu/craig/craig-thesis.pdf
- Paillier. *Public-Key Cryptosystems Based on Composite Degree Residuosity Classes*.
  EUROCRYPT 1999.
- Cheon-Kim-Kim-Song. *Homomorphic Encryption for Arithmetic of Approximate Numbers*.
  ASIACRYPT 2017. (CKKS)
- Chillotti-Gama-Georgieva-Izabachène. *Faster Fully Homomorphic Encryption*.
  ASIACRYPT 2016. (TFHE)

### ZK

- Goldwasser-Micali-Rackoff. *The Knowledge Complexity of Interactive Proof Systems*.
  STOC 1985 / SIAM J. Computing 1989.
  https://people.csail.mit.edu/silvio/Selected%20Scientific%20Papers/Proof%20Systems/The_Knowledge_Complexity_Of_Interactive_Proof_Systems.pdf
- Fiat-Shamir. *How to Prove Yourself*. CRYPTO 1986.
- Groth. *On the Size of Pairing-based Non-interactive Arguments*. EUROCRYPT 2016.
  (Groth16)
- Gabizon-Williamson-Ciobotaru. *PLONK*. ePrint 2019/953.
  https://eprint.iacr.org/2019/953.pdf
- Ben-Sasson et al. *Scalable, Transparent, and Post-Quantum Secure Computational
  Integrity*. ePrint 2018/046. https://eprint.iacr.org/2018/046.pdf
- Camenisch-Lysyanskaya. *Efficient Non-Transferable Anonymous Credentials*. EUROCRYPT
  2001.

### Contextual integrity

- Nissenbaum. *Privacy in Context: Technology, Policy, and the Integrity of Social
  Life*. Stanford University Press, 2010.
- Nissenbaum. *Privacy as Contextual Integrity*. Washington Law Review 2004.
  https://digitalcommons.law.uw.edu/wlr/vol79/iss1/10/
- Barth-Datta-Mitchell-Nissenbaum. *Privacy and Contextual Integrity: Framework and
  Applications*. IEEE S&P 2006.

### Production deployments

- Apple. *Differential Privacy Overview*.
  https://www.apple.com/privacy/docs/Differential_Privacy_Overview.pdf
- Apple. *Learning with Privacy at Scale*.
  https://machinelearning.apple.com/research/learning-with-privacy-at-scale
- Apple. *Private Cloud Compute*. https://security.apple.com/blog/private-cloud-compute/
- Erlingsson-Pihur-Korolova. *RAPPOR*. CCS 2014.
  https://research.google.com/pubs/archive/42852.pdf
- US Census Bureau. *TopDown Algorithm*. HDSR Special Issue 2, 2022.
  https://hdsr.mitpress.mit.edu/pub/7evz361i/release/2
- Google/Apple. *Privacy-Preserving Contact Tracing*.
  https://covid19.apple.com/contacttracing
- McMahan et al. *Communication-Efficient Learning of Deep Networks from Decentralized
  Data*. AISTATS 2017. (FedAvg)

### Libraries

Microsoft SEAL (github.com/microsoft/SEAL), IBM HElib (github.com/homenc/HElib), OpenFHE
(openfhe.org), Zama Concrete (github.com/zama-ai/concrete), TF-Privacy
(github.com/tensorflow/privacy), Opacus (opacus.ai), Flower (flower.dev), OpenMined
PySyft (github.com/OpenMined/PySyft), MP-SPDZ (github.com/data61/MP-SPDZ), Circom +
snarkjs (docs.circom.io), arkworks (github.com/arkworks-rs).

### Standards and regulations

GDPR Articles 17 (Erasure), 20 (Portability), 25 (Privacy by Design); CCPA/CPRA Cal.
Civ. Code §§1798.100 et seq.; ISO/IEC 24745:2022 (Biometric Information Protection);
ISO/IEC 27701:2019 (PIMS); ISO/IEC 18033-6:2019 (Homomorphic Encryption); NIST SP
800-188 (De-Identifying Government Datasets).

### Incidents and critical perspectives

AOL Search Log, August 2006; Strava heatmap, 2018
(news.ycombinator.com/item?id=16249955); Gymrek et al. *Identifying Personal Genomes by
Surname Inference*, Science 2013; Anderson, *Why Information Security is Hard*, ACSAC
2001.

---

## 18. Summary: What Defines Staff-Level Privacy Engineering Expertise

**Foundations:**
1. Privacy is structural, not procedural. GDPR-by-construction beats GDPR-by-process
   in any incident.
2. ε-DP is the starting point for any aggregate release. Track budget; don't treat ε
   as a tuning knob; composition matters.
3. K-anonymity is broken by composition and background knowledge. Use only for single-
   release, low-dimensional, regulatory-required cases. Otherwise, DP.

**Constructions:**
4. MPC, HE, and ZK solve different problems. MPC for joint computation with online
   interaction; HE for offloaded computation on encrypted data; ZK for verifiable
   assertions without revealing the data.
5. FHE is real but slow. Use for small aggregate queries, private-input inference,
   encrypted indexing. Not a plaintext replacement.
6. ZK has crossed from theory to production. zk-SNARKs (Groth16, PLONK), zk-STARKs,
   and BBS+ anonymous credentials are deployed at scale.

**Adversarial:**
7. Real-world data is uniquely identifying at very low dimensionality. 4 location
   points = 95% unique; 8 movie ratings = 96% unique. High-dimensional behavioral
   data is inherently identifying.
8. Aggregated data preserves uniquely-identifying patterns unless the aggregation
   provides DP guarantees. Strava heatmap was "aggregated" yet revealed soldiers'
   routes around CIA black sites.
9. ML models are deanonymization surfaces. Membership inference reveals training-set
   membership; DP-SGD is the defense at known accuracy cost.

**Normative:**
10. Contextual integrity bridges technical and policy. Ask "is the flow appropriate
    to the context's norms?" — the technical guarantee is necessary, not sufficient.
11. Data subject rights are engineering problems. Cryptographic deletion is the
    highest-leverage primitive for RTBF.
12. Privacy is a first-class design concern alongside availability, performance, and
    security — not a constraint added at the end.
