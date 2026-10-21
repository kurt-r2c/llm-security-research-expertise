# Federated Learning Security — Distributed-Training Threat Model
## Synthesized from Eugene Bagdasaryan, Vitaly Shmatikov, Keith Bonawitz, H. Brendan McMahan, Ligeng Zhu / Zhijian Liu / Song Han, Jonas Geiping, Franziska Boenisch, Adam Dziedzic, Virat Shejwalkar, Amir Houmansadr, Peva Blanchard, El Mahdi El Mhamdi, Dong Yin, Xiangyi Chen / Xinyang Chen, Xinyi Cao, Thien Duc Nguyen, Daniel Demmler, Carmela Troncoso, the Apple Private Federated Statistics team, the Google Gboard team, the NVIDIA FLARE team, and Kurt Boberg

> **Scope note.** This doc covers federated learning (FL) and split learning (SL) as their own
> system class. The sibling [[reference_adversarial_ml_model_security]] catalogs the Biggio
> five-category taxonomy (evasion / poisoning / extraction / MIA / inversion) for centralized
> ML; this doc specializes in attacks that exist *only* because training data is distributed and
> only gradients or weights cross the network. [[reference_privacy_engineering]] is the DP / MPC /
> HE / ZKP primer that FL composes; [[reference_cryptography]] (file
> `cryptography_expertise.md`) covers the SecAgg cryptographic primitives; [[reference_confidential_computing]]
> covers TEE-attested aggregation. The four read as a stack: this doc is the system layer.
>
> Read this if you are auditing an FL deployment, evaluating an FL framework choice (Flower /
> TFF / NVIDIA FLARE / OpenFL / FATE / PySyft), or designing a threat model for a multi-tenant
> ML platform that ships FL as a feature. Audience: security engineer or ML-security researcher.

> **Anchor researchers (selected; not exhaustive):**
> - **Eugene Bagdasaryan** (Cornell Tech → UMass Amherst) and **Vitaly Shmatikov** (Cornell Tech) —
>   "How To Backdoor Federated Learning" (AISTATS 2020, arXiv:1807.00459). The canonical targeted
>   model-poisoning paper. Demonstrated that constrained-and-scaled malicious updates survive
>   FedAvg aggregation while embedding a backdoor (input pattern X → wrong output Y) that
>   honest-update divergence checks miss.
> - **Hongyi Wang**, **Kartik Sreenivasan**, **Shashank Rajput**, **Harit Vishwakarma**, **Saurabh Agarwal**,
>   **Jy-yong Sohn**, **Kangwook Lee**, **Dimitris Papailiopoulos** — "Attack of the Tails: Yes,
>   You Really Can Backdoor Federated Learning" (NeurIPS 2020, arXiv:2007.05084). Established the
>   tail-label class: backdoors hiding in low-frequency label regions evade norm-based defenses.
> - **Virat Shejwalkar** and **Amir Houmansadr** (UMass Amherst) — "Manipulating the Byzantine:
>   Optimizing Model Poisoning Attacks and Defenses for Federated Learning" (NDSS 2021). The
>   adaptive-attack paper. Demonstrated that the then-current robust-aggregation defenses
>   (Krum / Multi-krum / Bulyan / Trimmed-mean / Median / AFA) all admit attacker-optimized bypass.
> - **Peva Blanchard**, **El Mahdi El Mhamdi**, **Rachid Guerraoui**, **Julien Stainer** (EPFL) —
>   "Machine Learning with Adversaries: Byzantine Tolerant Gradient Descent" (NeurIPS 2017),
>   the Krum paper. First-order byzantine-robust aggregator.
> - **Dong Yin**, **Yudong Chen**, **Kannan Ramchandran**, **Peter Bartlett** (UC Berkeley) —
>   "Byzantine-Robust Distributed Learning: Towards Optimal Statistical Rates" (ICML 2018).
>   Coordinate-wise Trimmed Mean and Median; statistical optimality framing.
> - **El Mahdi El Mhamdi**, **Rachid Guerraoui**, **Sébastien Rouault** (EPFL) — "The Hidden
>   Vulnerability of Distributed Learning in Byzantium" (ICML 2018). The Bulyan composition.
> - **Ligeng Zhu**, **Zhijian Liu**, **Song Han** (MIT) — "Deep Leakage from Gradients"
>   (NeurIPS 2019, arXiv:1906.08935). The DLG paper. Pixel-level recovery of training data from
>   shared gradients.
> - **Bo Zhao**, **Konda Reddy Mopuri**, **Hakan Bilen** — "iDLG: Improved Deep Leakage from
>   Gradients" (arXiv:2001.02610, 2020).
> - **Jonas Geiping**, **Hartmut Bauermeister**, **Hannah Dröge**, **Michael Moeller** (University
>   of Siegen) — "Inverting Gradients - How easy is it to break privacy in federated
>   learning?" (NeurIPS 2020, arXiv:2003.14053). Scaled gradient-inversion to ImageNet resolution.
> - **Hongxu Yin**, **Arun Mallya**, **Arash Vahdat**, **Jose M. Alvarez**, **Jan Kautz**, **Pavlo
>   Molchanov** (NVIDIA) — "See through Gradients: Image Batch Recovery via GradInversion"
>   (CVPR 2021). Batch-scale gradient inversion.
> - **Franziska Boenisch**, **Adam Dziedzic**, **Roei Schuster**, **Ali Shahin Shamsabadi**,
>   **Ilia Shumailov**, **Nicolas Papernot** — "When the Curious Abandon Honesty: Federated Learning
>   Is Not Private" (EuroS&P 2023, arXiv:2112.02918). A dishonest server modifies the shared
>   model's weights (*trap weights*) to recover client data exactly from gradients; the follow-up
>   (arXiv:2301.04017) uses sybil devices to reconstruct data even under distributed DP + SecAgg. The structural lesson: server-side architecture control is itself a privacy
>   attack vector.
> - **Mislav Balunović**, **Dimitar I. Dimitrov**, **Nikola Jovanović**, **Martin Vechev** (ETH
>   Zurich) — "LAMP: Extracting Text from Gradients with Language Model Priors" (NeurIPS 2022,
>   arXiv:2202.08827). Text-domain gradient inversion using LM priors as the reconstruction prior.
> - **Keith Bonawitz**, **Vladimir Ivanov**, **Ben Kreuter**, **Antonio Marcedone**, **H. Brendan
>   McMahan**, **Sarvar Patel**, **Daniel Ramage**, **Aaron Segal**, **Karn Seth** (Google) —
>   "Practical Secure Aggregation for Privacy-Preserving Machine Learning" (CCS 2017). The original
>   SecAgg protocol using pairwise masks derived from Diffie-Hellman key exchange. The
>   cryptographic substrate of essentially every production cross-device FL deployment.
> - **James Bell**, **Kallista Bonawitz**, **Adrià Gascón**, **Tancrède Lepoint**, **Mariana
>   Raykova** (Google) — "Secure Single-Server Aggregation with (Poly)Logarithmic Overhead"
>   (CCS 2020). SecAgg+ scalability protocol with sparse mask sharing.
> - **H. Brendan McMahan**, **Eider Moore**, **Daniel Ramage**, **Seth Hampson**, **Blaise Agüera
>   y Arcas** (Google) — "Communication-Efficient Learning of Deep Networks from Decentralized
>   Data" (AISTATS 2017, arXiv:1602.05629). The FedAvg paper. Established the algorithmic shape
>   that every subsequent FL system has either used or argued against.
> - **Robin C. Geyer**, **Tassilo Klein**, **Moin Nabi** (SAP / ETH Zurich) — "Differentially Private
>   Federated Learning: A Client Level Perspective" (NIPS 2017 Workshop on Machine Learning on the Phone and other Consumer Devices, arXiv:1712.07557).
>   Early DP-FedAvg framing at the client level.
> - **Praneeth Vepakomma**, **Otkrist Gupta**, **Tristan Swedish**, **Ramesh Raskar** (MIT Media Lab)
>   — split learning ("Split learning for health: Distributed deep learning without sharing raw
>   patient data," arXiv:1812.00564, 2018). Also "NoPeek: Information leakage reduction to share
>   activations in distributed deep learning" (ICDM Workshops 2020).
> - **Thien Duc Nguyen** et al. — "FLAME: Taming Backdoors in Federated Learning" (USENIX
>   Security 2022). Clustering + clipping + noise-injection defense.
> - **Xiaoyu Cao**, **Minghong Fang**, **Jia Liu**, **Neil Zhenqiang Gong** — "FLTrust:
>   Byzantine-robust Federated Learning via Trust Bootstrapping" (NDSS 2021). Server-side trust
>   bootstrap from a small clean dataset.
> - **Vitaly Shmatikov** (cited above) is the through-line that links several of the FL privacy
>   papers to the broader privacy-research lineage in [[reference_privacy_engineering]].

---

## 1. What "federated learning" means in 2026

Federated learning trains a global model from data that never leaves the client devices. A
coordinator (the *server* or *aggregator*) broadcasts the current model, each client computes
an update on its local data, and the server aggregates those updates into a new global model.
Iterate until convergence. The training data — raw user keystrokes, medical images, banking
transactions — does not move. Only the updates do.

Four register-distinct variants:

- **Cross-device FL** — millions of mobile or IoT clients, each holding a tiny shard. Devices
  drop in and drop out per round. The canonical production deployments: Google Gboard
  next-word prediction (the FedAvg paper's motivating example) and Apple's federated
  statistics for QuickType / Siri (Local DP on the client side, aggregation server-side).
  Cross-device FL cannot strongly authenticate individual clients; the Sybil-resistance
  assumption is operationally fragile.
- **Cross-silo FL** — a small number of organizational clients. Hospitals training a joint
  cancer model. Banks training a joint fraud-detection model. Clients are strongly authenticated
  (PKI, mutual TLS, organizational legal agreements). The Sybil assumption is sound; the
  threat model shifts to an honest-but-curious or malicious server, plus the risk that one
  partner organization is compromised.
- **Split learning** (split-NN) — model bisected. Early layers run on the client; late layers
  run on the server; the *cut layer* activations cross the network during forward pass, and
  gradients cross back during backward pass. Different privacy / utility tradeoff than FL.
- **Federated analytics** — same aggregation infrastructure but the workload is
  population-level statistics (heavy-hitter discovery, histograms, count-distinct) rather than
  model training. Apple's "Private Federated Statistics" and Google's federated heavy-hitters
  protocol are the production examples.

Each variant has a different threat model. Reading this doc assumes you have already classified
which variant the system you are auditing belongs to.

---

## 2. What FL prevents vs what it does not

The load-bearing claim of federated learning is *client raw data never leaves the device*.
That claim is structurally true. It is also frequently confused with claims that are not true.

**What FL actually prevents:**
- Server-side data breach of the centralized training corpus, because there is no centralized
  training corpus. An attacker compromising the aggregator does not get a copy of every
  client's local data.
- Regulatory exposure under GDPR / HIPAA / state-data-residency rules for *data-at-rest in a
  central repository*, because the data does not rest centrally. Whether this clears the
  regulatory bar depends on jurisdiction; see §12.
- Mass-acquisition-of-training-data adversaries who win the moment they get the dataset blob.
  FL changes that economic shape: the attacker has to compromise per-client devices, or extract
  data from gradients (§4), or compromise the aggregator and craft a malicious model
  architecture (§4 Robbing the Fed). All of those are more expensive than copying a single
  database.

**What FL does not prevent:**
- **Gradient inversion** — the client update is a function of the client data. Pixel-level
  recovery has been demonstrated since 2019 (§4).
- **Model poisoning by malicious clients** — a client computes whatever update it wants, and
  the server has limited ability to distinguish malicious updates from honest ones (§3).
- **Membership inference at the model level** — the final trained model is still a model. Its
  outputs leak training-set membership signals just like centrally-trained models. See
  [[reference_adversarial_ml_model_security]].
- **Side channels on the aggregation server** — timing, memory, network-level metadata.
- **The model itself being a privacy leak once published.** Any ML model is a lossy
  compression of its training data. FL protects the training process; it does not change the
  privacy properties of the artifact.

The framing to hold: FL changes the threat model. It does not eliminate any threat class.

---

## 3. Model poisoning attacks by malicious clients

The defining federated threat class. Centralized ML lets you curate the training set; FL
hands the training-set-curation problem to your adversary, by construction.

### 3.1 Untargeted byzantine attacks

A malicious client submits gradients that maximize loss to degrade overall model quality. The
goal is denial of service, not steering. The structural defense is the honest-majority
assumption: as long as fewer than some fraction of clients per round are malicious, robust
aggregation (§5) bounds the damage. Blanchard et al. 2017 (Krum) tolerates f < (n - 2) / 2
byzantine clients out of n. Trimmed Mean and Median tolerate similar fractions with
different constants.

Untargeted byzantine attacks are the easy case. They produce statistically anomalous updates
that any norm-based or distance-based filter catches. The hard case is targeted.

### 3.2 Targeted backdoor attacks

A malicious client embeds a backdoor — input pattern X → wrong output Y — while staying close
enough to honest updates that the aggregator's divergence check does not flag them. Bagdasaryan
et al., "How To Backdoor Federated Learning" (AISTATS 2020), is the canonical paper. The
attack shape:

1. Train a local model that classifies normal inputs correctly *and* misclassifies
   backdoor-trigger inputs to the attacker's chosen label.
2. Compute the update (delta from global model).
3. Scale the update to compensate for being averaged with honest updates: if the server
   averages N updates, scale the malicious update by N to ensure the backdoor survives
   averaging.
4. Submit. The honest-majority averaging does not erase the backdoor because the scaling
   compensates for the dilution.

The Bagdasaryan attack defeats vanilla FedAvg. It does not defeat byzantine-robust aggregation
that filters by per-client norm — until you constrain the attack to stay within the norm
budget.

### 3.3 Stealth poisoning via constrained-and-scaled updates

The follow-on. The attacker stays within the L2-norm budget of honest gradients while embedding
the target update. The honest update distribution sets the budget; the attacker projects the
malicious gradient into the feasible region defined by that budget.

Wang et al., "Attack of the Tails" (NeurIPS 2020), anchors the tail-label class. The insight:
backdoors targeting rare classes (the tail of the label distribution) leave a smaller honest
gradient signal to disguise against, so the attack is easier to hide. Edge-case backdoors are
*harder to defend against* than common-case backdoors, which inverts a defender's intuition.

### 3.4 Coordinated multi-client (Sybil) attacks

Multiple Sybil clients colluding to bypass byzantine-robust aggregation. The Sybil-resistance
assumption is the load-bearing one:

- Cross-device FL cannot strongly authenticate individual devices. The aggregator sees a
  device attestation (Play Integrity, App Attest) but the attestation does not prevent a
  well-resourced attacker from running thousands of physical or emulated devices that each
  pass attestation individually.
- Cross-silo FL can authenticate (mutual TLS, PKI, organizational onboarding) but the Sybil
  resistance is then only as strong as the organizational onboarding process. One compromised
  partner organization is one Sybil.

The structural lesson: byzantine-robust aggregation assumes a bounded fraction of malicious
clients. The mechanism by which that fraction is bounded is *not part of the aggregation
defense* — it has to come from elsewhere (device attestation, organizational authentication,
rate-limiting per network identifier, geographic and behavioral anomaly detection).

### 3.5 Adaptive attacks vs known defenses

Shejwalkar and Houmansadr, "Manipulating the Byzantine" (NDSS 2021), demonstrated that all
then-current robust-aggregation defenses can be bypassed by adaptive poisoners. The attack
formulation: given knowledge of the defense, solve for the malicious gradient that maximizes
attack effectiveness subject to the defense not filtering it. This is a constrained optimization
problem; the attacker has time and compute to solve it.

The 2024-2026 follow-on landscape continues this arms race. Newer defenses (FLAME, FLTrust,
adaptive-clipping-with-DP) raise the cost of attack but no defense is known to be unconditionally
robust against adaptive poisoners with knowledge of the defense.

The honest framing: byzantine-robust aggregation is necessary-not-sufficient. It does not
solve poisoning; it bounds it. Operational FL deployments compose multiple defenses (robust
aggregation + DP + per-round anomaly detection + per-client identity binding) and accept that
a determined adaptive adversary will partially succeed.

---

## 4. Gradient inversion attacks (privacy of training data)

Client updates are not raw data. They are a function of raw data and the current model. That
function is lossy, but not lossy enough.

### 4.1 DLG (Deep Leakage from Gradients)

Zhu, Liu, Han, NeurIPS 2019 (arXiv:1906.08935). The canonical demonstration. Given the
gradients a client computed on a single training example (image + label), DLG recovers the
input image at pixel-level fidelity by solving:

```
minimize  || ∇W_attacker(x_dummy, y_dummy) - ∇W_observed ||²
   over   x_dummy, y_dummy
```

The attacker initializes a dummy input and label, computes the gradient that input would
produce against the same model weights, and gradient-descends until the dummy gradient matches
the observed gradient. The converged dummy input *is* the original input, up to recovery
quality determined by model architecture and batch size.

DLG is the foundational result. Every subsequent gradient-inversion paper improves on it.

### 4.2 iDLG, GradInversion, IG

- **iDLG** (Zhao et al. 2020) — the classification label is extractable analytically from the
  last-layer gradient sign, which removes the need to optimize over the label and improves
  recovery quality.
- **GradInversion** (Yin et al. CVPR 2021) — scales to recovering batches of inputs at ImageNet
  resolution, using batch-normalization statistics and a regularization prior to disambiguate
  the underdetermined batch-recovery problem.
- **Inverting Gradients (IG)** (Geiping et al. NeurIPS 2020) — scales gradient inversion to
  ImageNet-resolution single-image recovery using a cosine-similarity objective and an image
  prior. The "this is not safe" demonstration for production-scale models.

### 4.3 Robbing the Fed (malicious-server architecture)

Fowl et al., "Robbing the Fed" (ICLR 2022), and Boenisch et al. (EuroS&P 2023). The structural-novelty papers.

Earlier gradient-inversion work assumed an honest model architecture and asked: can the server
recover training data from the observed gradients? Robbing the Fed inverts the question: if the
server *gets to choose* the model architecture and the initial weights, can it craft an
architecture that leaks individual training data even under SecAgg + DP?

Yes. The "trap layer" attack:

1. The server inserts a wide linear layer somewhere early in the model. Each neuron in the
   trap layer is initialized so that it activates only for a narrow region of input space.
2. With high probability, each training example in a client's local dataset activates exactly
   one trap-layer neuron (different neurons for different examples).
3. The gradient with respect to that neuron's weights is a clean image of the activating
   training example.
4. Even after SecAgg averages updates across clients, the per-neuron gradient is dominated by
   the single client whose example activated that neuron — because most other clients had no
   example in that neuron's input region.
5. DP noise added to the aggregated gradient does not erase the leak if the noise budget is
   sized for ordinary signal magnitudes and the trap-layer signal is calibrated to dominate.

The structural lesson: SecAgg + DP combined does not bound malicious-server gradient inversion
when the server controls the model architecture. The defense requires either
client-side-verifiable model architecture (the client checks the architecture before training)
or TEE-attested aggregation (§11).

### 4.4 LAMP / text-domain gradient inversion

Balunović et al., NeurIPS 2022 (arXiv:2202.08827). Text-domain gradient inversion was harder
than image-domain because token gradients are sparser and the search space is discrete.
LAMP uses a language-model prior to reconstruct the input text from the gradients of a
text-classification model. The honest framing: text-domain gradient inversion is no longer
a hypothetical. NLP FL deployments have the same gradient-leakage exposure as vision ones.

The "Cocktail Party Attack" (Kariyappa et al., ICML 2023) is a separate published attack: it
treats aggregated fully-connected-layer gradients as a blind source separation problem and uses
ICA to recover inputs from aggregates over as many as 1024 samples.

### 4.5 Batch-size as defense parameter

Larger batches → harder inversion. A client computing one gradient over a 1000-example batch
leaks less per example than a client computing one gradient per example. This is true. It is
also insufficient: batch-recovery techniques (GradInversion) scale, and *one* recoverable
example per batch is already a privacy violation under most threat models.

The honest 2026 framing: batch-size-as-defense is not load-bearing. The structural defenses
are DP (noise added to the update, with a tracked privacy budget) and SecAgg (the server sees
only the aggregate, not individual client updates), and even those combine to fail against
malicious-server architecture (§4.3).

---

## 5. Byzantine-robust aggregation defenses

The set of aggregation rules that replace plain averaging with something that bounds the
influence of an adversarial minority.

### 5.1 Krum

Blanchard et al., NeurIPS 2017. The canonical first-order byzantine-robust aggregator.

Each round, for each client update u_i, compute the sum of squared distances to its
m = n - f - 2 nearest neighbors among the other client updates. Select the single update
with the smallest score. That update is the round's aggregate.

Why it works: an honest update is close to other honest updates (they were computed on
data drawn from the same distribution). A malicious update that strays far from the honest
cluster scores poorly and is not selected. A malicious update that stays close enough to be
selected has limited room to diverge from the honest direction.

Where it breaks: Krum picks a *single* update, which throws away most of the round's
information. Convergence is slow. Bypassed by adaptive attackers who craft malicious updates
that stay inside the honest cluster (Shejwalkar-Houmansadr).

Multi-Krum (production variant) averages the top-m closest updates instead of picking one.

### 5.2 Trimmed Mean

Discard the top-k and bottom-k of each coordinate across all client updates, then average the
remaining n - 2k updates coordinate-wise. Yin et al. ICML 2018.

Simple. Effective against untargeted byzantine attacks that produce outlier coordinates.
Bypassed by coordinated-direction attacks where multiple malicious clients agree on the
attack direction and stay within the central n - 2k range.

### 5.3 Geometric Median / Coordinate-wise Median

Yin et al. ICML 2018. Take the coordinate-wise median, or the geometric median, of the client
updates. Statistically robust against bounded-fraction byzantine attacks.

The geometric median is the more theoretically clean choice; the coordinate-wise median is
faster to compute. Both have similar empirical robustness profiles.

### 5.4 Bulyan

El Mhamdi et al. ICML 2018. A composition: run Krum repeatedly to select a robust subset, then
apply Trimmed Mean within that subset. Tighter theoretical guarantees than either alone.
Slower per round.

### 5.5 FLTrust

Cao et al. NDSS 2021. The server holds a small clean dataset (root-of-trust dataset) and
computes its own update on it each round. Client updates are then scored by cosine similarity
to the server's root update; updates with low or negative cosine similarity are downweighted
or rejected.

The structural shift: FLTrust assumes the server has a clean dataset that represents the
honest distribution. This violates the FL premise in spirit (the server is not supposed to
have the data), but in cross-silo deployments (hospital consortia, bank consortia) the server
often does hold a small representative dataset that can act as the trust anchor.

### 5.6 FLAME

Nguyen et al. USENIX Security 2022. Clustering + clipping + noise injection:

1. Cluster client updates by cosine similarity. Discard small clusters as outliers.
2. Clip the surviving updates to a per-update norm bound determined by the median of the
   cluster norms.
3. Add Gaussian noise to the aggregated clipped update.

Combines several defenses. The noise step doubles as a DP-like privacy mechanism, though
FLAME's noise calibration is set for backdoor mitigation rather than for ε-DP guarantees.

### 5.7 Honest framing

Every byzantine-robust aggregator known as of 2026 has a documented adaptive bypass against a
white-box adversary who knows the defense. The structural lesson:

- Robust aggregation is necessary-not-sufficient.
- The operational defense is composition: aggregation + DP + per-client norm clipping +
  per-round anomaly detection + per-client identity attestation + slow learning rates that
  cap per-round damage.
- The empirical robust-aggregation choice depends on attack model. For untargeted byzantine
  in a low-trust setting, Trimmed Mean is enough. For targeted backdoors against an adaptive
  adversary, no defense is sufficient alone.

---

## 6. SecAgg — secure aggregation cryptographic foundations

SecAgg is the cryptographic primitive that protects individual client gradient privacy from a
malicious server. The server sees only the sum of client updates, not the individual updates.
The protocol composes with byzantine-robust aggregation only awkwardly (because the server
cannot inspect individual updates to filter them) — see §6.4.

### 6.1 Bonawitz et al. 2017 — the original SecAgg

CCS 2017 (Bonawitz, Ivanov, Kreuter, Marcedone, McMahan, Patel, Ramage, Segal, Seth). The
foundational protocol.

The structural idea: each pair of clients (i, j) agrees on a pairwise mask s_{i,j} via
Diffie-Hellman key exchange. Client i adds + s_{i,j} for each j > i and - s_{i,j} for each
j < i to its update u_i before submitting. When the server sums across all clients, the
masks cancel pairwise:

```
Σ_i (u_i + Σ_{j > i} s_{i,j} - Σ_{j < i} s_{i,j}) = Σ_i u_i
```

The server sees the sum of true updates. The individual masked updates appear pseudorandom.

Two failure modes the original protocol handles:
- **Client dropout.** If client i drops out after submitting its masked update, the masks
  involving i fail to cancel. The protocol uses Shamir secret-sharing of the per-client seeds
  so that the server can recover dropped clients' masks by reconstructing the seed from shares
  held by other clients. This recovery step is what makes SecAgg dropout-resilient at the cost
  of round-trip complexity.
- **Malicious client trying to identify other clients' updates.** Authentication and signed
  messages bind each masked update to the client identity; the server cannot accept a
  malicious-client-injected impersonation.

### 6.2 SecAgg+

Bell et al. CCS 2020 (Bell, Bonawitz, Gascón, Lepoint, Raykova). The scalability follow-on.

Original SecAgg has Θ(n²) pairwise communications per round because each client establishes a
mask with every other client. SecAgg+ replaces the complete pairwise graph with a sparse
random graph: each client only masks against a logarithmically-sized random subset of other
clients. The aggregation correctness still holds (with high probability over the random graph)
but communication per client drops to O(log n).

SecAgg+ is the production-scale variant. Cross-device FL at the scale of Gboard requires it.

### 6.3 TurboAgg, BatchCrypt, Flamingo

Performance and scalability follow-ons. Without claiming specific advisory-grade detail
[unverified specific advisory] for each, the family pattern is:

- TurboAgg — circular-mask-style aggregation, claim of reduced round complexity.
- BatchCrypt — homomorphic encryption (Paillier-style) on quantized gradients for cross-silo
  FL where dropout is rare and the n² complexity is tolerable.
- Flamingo — multi-round secure aggregation with persistent setup that amortizes the per-round
  cost across many rounds of FL.

For an audit, check what the specific framework uses and trace the protocol claim back to its
paper rather than relying on framework documentation. Performance claims have been overstated
across this literature.

### 6.4 PQ-SecAgg — post-quantum variants

The original SecAgg's pairwise mask establishment uses Diffie-Hellman. DH is broken by a
sufficiently large quantum computer (Shor's algorithm). FL deployments with long-term privacy
requirements need post-quantum key establishment.

The migration target as of 2026 is hybrid X25519 + ML-KEM (Kyber) — the NIST FIPS 203 standard
finalized August 2024 — for the pairwise key agreement, mirroring the broader TLS migration.
See [[reference_post_quantum_cryptography]] for the standardization arc. The masking layer
itself does not need to change; only the key-establishment substrate does.

The harvest-now-decrypt-later concern: an adversary recording the masked SecAgg traffic today
and storing it for future quantum decryption can recover individual client updates if and when
DH is broken. For deployments where the underlying gradient data has long-term sensitivity
(medical, biometric, identity), PQ migration is not optional.

### 6.5 Threat model gaps

SecAgg protects against an honest-but-curious server seeing individual updates. It does not
protect against:

- **A malicious server crafting the model architecture** to enable gradient inversion. See
  §4.3 Robbing the Fed.
- **A malicious server colluding with one or more clients** to recover other clients' updates.
  If t clients out of n are colluding with the server, the colluders' masks are known to the
  server and the privacy of the other n - t clients reduces to the SecAgg-without-collusion
  case among them. The collusion-resistance is bounded by the share threshold.
- **Side channels.** Timing of client submission, network metadata, the set of clients
  participating in each round.

The structural lesson: SecAgg is one component of a defense-in-depth stack, not a complete
privacy solution.

---

## 7. Differential privacy in FL

DP applied to client updates. Three placements:

### 7.1 DP-FedAvg — client-side DP

Geyer et al. (NeurIPS 2017 PPML workshop) and McMahan et al. each contributed early DP-FedAvg
variants. The shape:

1. Each client clips its local update to a per-update norm bound C.
2. The client adds Gaussian noise scaled to (C, σ) to the clipped update.
3. The clipped-and-noised update is submitted.

This is "local DP" — the client trusts no one with its raw update. The cost is noise
accumulation: the noise added at the client is not erased by aggregation, so utility
degrades with the noise scale.

Per-client privacy is tracked across rounds. Rényi DP (Mironov, CSF 2017) or zCDP (Bun and
Steinke, TCC 2016) composition keeps the math tractable; vanilla (ε, δ) composition grows
linearly per round and exhausts the budget quickly. See [[reference_privacy_engineering]].

### 7.2 Central DP — server-side noise

The server clips client updates to a norm bound, sums them (possibly via SecAgg), and adds
Gaussian noise to the *aggregate* update before applying it to the global model. Utility is
better than client-side DP because the noise is added once over the sum rather than once per
client. The cost: the server has to be honest with respect to the noise calibration. A
malicious server can simply not add noise.

Central DP works in cross-silo settings where the server is a trusted aggregator (often a
neutral third party or a TEE; see §11). It does not work in cross-device FL against an
untrusted server.

### 7.3 Distributed DP — DP via SecAgg

The combination. Each client adds a small share of the total noise (e.g. Gaussian noise scaled
to σ / √n at each of n clients); the server sums via SecAgg; the total noise on the aggregate
sums to the required (C, σ) calibration. The server cannot see individual noisy updates
because of SecAgg, and the server cannot drop the noise because the noise was added before
masking. This achieves DP guarantees in a model where the server is malicious-but-not-
collusion-with-clients.

Distributed DP is the right shape for cross-device FL. It is also the most complex shape to
implement correctly — the noise distribution has to be discretized to work with finite-field
SecAgg arithmetic, and the discretization affects the DP analysis. Practical implementations
use the Skellam mechanism (difference of two Poisson distributions, which composes with
modular arithmetic) or discrete Gaussian.

### 7.4 Production deployments

- **Apple Federated Learning + Statistics.** Apple has published methodology papers on its
  Local DP system for QuickType / Siri / Lookup-in-Apps since 2017. ε per-event budget;
  daily aggregation with privacy budget reset. The methodology is public, the audited
  parameters are public, the implementation details (ε value, mechanism choice for specific
  features) have varied over Apple's deployment history [unverified specific advisory for
  current ε values per feature]. Apple Private Federated Statistics extends this to federated
  analytics for population-level statistics rather than model training.
- **Google Federated Analytics.** The federated heavy-hitters protocol used by Gboard for
  keyboard analytics (which emoji is popular, which words are misspelled commonly) has DP
  guarantees with public methodology. Trie-based heavy-hitter aggregation with DP at each
  level of the trie.
- **Google Gboard next-word prediction.** Cross-device FL with FedAvg. Production-scale DP
  has been published in research papers; the operational ε values per release are not
  generally public [unverified specific advisory].

### 7.5 The composition problem

Multi-round FL accumulates privacy cost. A cross-device FL deployment that runs thousands of
rounds per release cycle has to track per-client privacy cost across rounds. Practical
considerations:

- Per-client budget allocation. If client C participates in 100 rounds and the total per-client
  budget is ε = 5, each round can spend at most ε ≈ 5/100 (under simple composition; less under
  RDP). The smaller per-round ε is, the noisier the per-round update is, and the slower the
  model converges.
- Participation tracking. The accountant has to know which clients participated in which
  rounds. Cross-device deployments use Poisson subsampling — each round samples clients
  uniformly with probability q — and the privacy accounting accounts for the amplification
  effect of subsampling.
- Budget reset policies. Apple resets its per-event budget daily. Google's accounting per
  deployment is less public. The reset policy is part of the privacy claim; auditing it
  requires knowing it.

Operationally, DP-FL deployments do not run with academic-paper ε values (typically ε ≤ 1).
Production ε values are in the 5-20 range, sometimes higher per release. This is honest. The
academic recommendation is calibrated to ideal worst-case adversaries; the production
recommendation is calibrated to operational utility and a more bounded threat model. The
choice should be documented and defensible, not hidden.

---

## 8. Split learning specific threats

Split learning bisects the model. Early layers run on the client; late layers run on the
server. The cut-layer activations cross the network during forward pass, and gradients cross
back during backward pass.

The privacy story for SL: the client's raw data never leaves, only the activations do. The
activations are a transformation of the data through the early layers. Like gradients in FL,
activations are not raw data, but they are not random noise either.

### 8.1 Feature-inversion attacks

The server reconstructs the client's input from the cut-layer activations. The attack shape
mirrors gradient inversion (§4): treat the early-layer network as a (known) function and
invert it. Vepakomma et al. (NoPeek and related work) and follow-ons demonstrated practical
reconstruction.

Empirically, feature inversion is *worse* than gradient inversion in many SL deployments
because activations are richer-information than gradients. Gradients are derivative signals;
activations are the data run through several layers of feature extraction. The deeper the cut
layer, the more lossy the activations and the harder the inversion — but also the less work
the client is doing, which defeats the point of SL.

### 8.2 Label leakage from gradient direction

In SL with backward pass, the gradient at the cut layer flows back from server to client. The
sign and magnitude of the cut-layer gradient leaks the label class. For binary classification,
this is essentially full label leakage to the server. For multi-class, the top-class is
recoverable from the gradient direction.

This is a "private label" leak in deployments where the server should not learn the label
(e.g., the client knows the diagnosis but is consulting the server for joint training without
revealing the diagnosis).

### 8.3 Hybrid FL + SL deployments

Some production systems combine FL (for some layers, especially shared early layers) with SL
(for layers specific to one client or one tenant). The threat surface is the union — every
attack against FL plus every attack against SL.

### 8.4 NoPeek and noise-based defenses

Vepakomma et al., "NoPeek" (ICDM workshops 2020). The client adds a distance-correlation
term to its training loss, minimizing distance correlation between the cut-layer activations
and the raw input.

Same tradeoff as DP-FL: utility degrades with noise scale; the privacy guarantee depends on
honest noise calibration.

---

## 9. Production FL deployment landscape (2024-2026)

What is actually in production. Each entry has been confirmed against the framework's
publications or the deploying organization's published statements. Items I could not confirm
to that bar are marked [unverified specific advisory].

- **Gboard next-word prediction** (Google). Cross-device FL with FedAvg + DP. Production since
  the FedAvg paper (2017) and progressively extended. The motivating production example for
  most of the field.
- **iOS QuickType / Siri / Lookup** (Apple). Local DP for federated analytics since 2016;
  federated learning expansion to model training documented in subsequent Apple machine
  learning research blog posts.
- **NVIDIA FLARE** (NVIDIA Federated Learning Application Runtime Environment). Healthcare /
  cross-silo focus. Ships with homomorphic-encryption-based secure aggregation and DP
  modules.
- **Owkin Substra** (Owkin / open-source via Linux Foundation AI). Cross-silo healthcare FL
  platform. Cancer-research consortia, including the MELLODDY pharmaceutical consortium for
  drug discovery, and clinical-pathology federated training.
- **Federated Tumor Segmentation (FeTS)** (UPenn / Intel academic-industry consortium). Brain
  tumor segmentation across many participating hospitals. The largest-scale published clinical
  FL deployment as of the field's published surveys; specific participating-hospital count has
  varied across publications [unverified specific advisory for the current count].
- **OpenFL** (Intel; Linux Foundation AI & Data project). Cross-silo FL framework. Designed
  to integrate with Intel SGX for TEE-attested aggregation (see §11).
- **WeBank FATE** (Federated AI Technology Enabler). Chinese FL framework with banking and
  insurance deployments. WeBank publishes case studies; the operational scale claims are not
  independently audited.
- **Sherpa.ai** — referenced in earlier FL surveys; current status as a deployed FL platform
  [unverified specific advisory].

The composition of the deployed landscape: cross-device FL is concentrated in a few large
mobile-keyboard / mobile-OS operators (Apple, Google). Cross-silo FL is concentrated in
healthcare consortia and (regionally) Chinese financial sector. The general-purpose FL
platform market is small relative to centralized ML.

---

## 10. FL framework security analysis

Per-framework security posture as of 2026. The audit lens: what does the framework ship by
default, what is the user expected to configure, and where are the foot-guns?

### 10.1 PySyft (OpenMined)

Python-based FL / MPC library. Active open-source community since around 2017. The CVE corpus
is small but growing. Most FL framework security work in PySyft is in the user's hands: the
framework provides the primitives (FL, MPC, DP, HE), and the user composes them. Default
configurations are not production-secure for adversarial threat models.

For audit: check which aggregator the user picked, whether DP is wired up, and whether SecAgg
is actually used. Default examples often skip SecAgg for tutorial readability.

### 10.2 Flower (flower.ai)

Framework-agnostic FL library. Ships with FedAvg, FedProx, and additional
aggregation strategies. Security is mostly user-configured: the strategy plugin is where
robust-aggregation and DP get composed.

Default Flower deployments use plain FedAvg with no SecAgg, no DP, no robust aggregation.
This is fine for a tutorial; it is not fine for production. Audit point: is the deployment
using a non-default strategy?

### 10.3 TensorFlow Federated (TFF)

Google's reference implementation. Production-grade for Google's own use cases (Gboard).
Externally, TFF has been less battle-tested — third-party deployments are uncommon.

### 10.4 NVIDIA FLARE

Healthcare-focused cross-silo FL. Ships with homomorphic-encryption-based secure aggregation and DP modules; documentation is oriented
toward healthcare-grade deployments. Integration with Confidential Computing (NVIDIA H100 CC,
AMD SEV-SNP) is supported.

### 10.5 FedML (TensorOpera / fedml.ai)

Research and production tracks. Multi-cloud orchestration. Cross-silo and cross-device modes.
The production track has commercial backing; the security posture varies per the deployment
template chosen.

### 10.6 OpenFL (Intel)

Cross-silo, with first-class Confidential Computing integration. The OpenFL + SGX
combination is the canonical "TEE-attested aggregator" deployment shape. See §11 and
[[reference_confidential_computing]].

### 10.7 FATE (WeBank)

Large deployment footprint in Chinese financial sector. Ships with multiple aggregation
modes, HE-based MPC for cross-silo, and DP. Default configurations vary by deployment
template. Independent security audit of FATE is sparser in English-language literature than
for the Google / Intel / NVIDIA frameworks; audit by reading the source rather than the
documentation if you are evaluating it.

### 10.8 Audit checklist applicable to any FL framework

- Which aggregation rule is in use? Plain FedAvg, robust (Krum / Trimmed Mean / FLAME), or
  vendor-specific?
- Is SecAgg enabled? If yes, which variant (SecAgg, SecAgg+, custom)?
- Is DP enabled? Where (client-side, server-side, distributed)? What is the ε per round, the
  cumulative ε, and the budget-reset policy?
- How are clients authenticated? Device attestation (Play Integrity, App Attest, custom),
  PKI / mTLS, or no authentication beyond network identity?
- Is the model architecture client-verifiable? Or does the server hand out an opaque graph?
- Is the aggregator running in a TEE? If yes, what attestation is presented to clients?
- What is the dropout policy and recovery protocol? Dropout recovery is where SecAgg's
  share-reconstruction step happens; a poorly-implemented dropout recovery is a privacy bug.
- What anomaly detection runs on per-client updates? Norm clipping, cosine-similarity
  filtering, behavioral fingerprinting?

---

## 11. Confidential computing intersection

FL inside TEEs (Intel SGX / TDX, AMD SEV-SNP, ARM CCA, NVIDIA H100 Confidential Computing).
See [[reference_confidential_computing]] for the TEE landscape.

### 11.1 TEE-as-trusted-aggregator

The server runs the aggregation logic inside an enclave. Remote attestation proves to each
client that the aggregator is running the expected code (specifically, the expected model
architecture and the expected aggregation rule) before the client submits its update.

This defeats malicious-server gradient inversion of the Robbing the Fed class, because the
client refuses to participate if the attested code does not match the expected model
architecture. The attestation transcript itself becomes a load-bearing audit artifact.

OpenFL + SGX is the canonical deployment shape. NVIDIA H100 Confidential Computing enables
the same pattern for GPU-accelerated aggregation, which matters when the aggregation involves
nontrivial server-side computation (e.g., when the server runs the late layers of a split
learning model).

### 11.2 Encrypted gradients via enclave-decrypted submission

Clients encrypt updates to the enclave's attested public key. The enclave decrypts inside the
TEE, aggregates, and outputs only the aggregate to the broader server environment. SecAgg is
not strictly needed in this model because the enclave is the trust boundary, but most
deployments use both for defense in depth.

### 11.3 Side channels

The TEE attack surface (Foreshadow, ÆPIC, Downfall, TEE.Fail, the Spectre/Meltdown family) is
directly relevant to FL-in-TEE confidentiality. A side channel that leaks enclave memory
leaks gradient data and aggregation state. See [[reference_hardware_side_channels]] and
[[reference_confidential_computing]].

The audit lens: TEE attestation tells you the code, not the side-channel posture. A
correctly-attested SGX enclave running on hardware vulnerable to Foreshadow is still vulnerable
to Foreshadow. Hardware firmware level and microcode level matter.

### 11.4 The economic story

TEE-attested FL collapses a lot of the FL threat model. If you have a strongly-attested
aggregator with a small TCB and a sound side-channel posture, you do not need SecAgg's
pairwise-mask gymnastics and you can run central-DP with utility costs. The "if" is doing
work.

For cross-silo healthcare and finance, this composition (OpenFL + SGX, or NVIDIA FLARE
+ H100 CC) is increasingly the production answer. For cross-device FL at Gboard scale, TEE
on the aggregator is feasible but the client side cannot easily attest its own behavior, so
client-side malicious-client poisoning (§3) remains the dominant threat.

---

## 12. Honest failure modes

What the FL stack cannot defend against. The structural truths that no framework patch will
remove.

### 12.1 Malicious-server crafted model architecture

Robbing the Fed (§4.3). SecAgg + DP combined still fail when the server controls the model
architecture and chooses one that leaks individual training data through gradient signals
the noise budget did not anticipate. The structural defense is client-side model verification
or TEE-attested architecture (§11). Both are out-of-band of the standard FL stack.

If your FL deployment hands the model architecture to clients as a black box and does not
attest it, the malicious-server attack is open by construction.

### 12.2 Long-tail Sybil attacks

Cross-device FL cannot strongly authenticate individual devices. Play Integrity / App Attest
raise the cost of running thousands of Sybil devices but do not eliminate it. A
well-resourced adversary (state actor, organized fraud ring) can run physical devices at
scale, pass attestation per-device, and overwhelm honest-majority assumptions.

Byzantine-robust aggregation degrades gracefully as the malicious fraction increases up to
its threshold; past the threshold, the convergence guarantees fail. There is no FL defense
that survives "more than half the clients are colluding adversaries."

### 12.3 Out-of-distribution data on a single client

If one client's data is statistically different from the rest (a hospital with a unique
patient demographic, a Gboard user typing in a rare language), FL training treats that
client's signal as noise relative to the majority. The byzantine-robust aggregators
specifically filter it out as an outlier.

This is a known fairness / participation failure mode, not a security failure per se, but it
interacts with security: a privacy-preserving FL deployment that systematically erases the
contributions of edge-case populations is providing privacy at the cost of utility for those
populations. Audit by checking per-subgroup model quality, not just aggregate.

### 12.4 The trained model is itself a leak

A model trained via FL is still a model. Membership inference, model extraction, and
gradient inversion against the *final* model apply to FL models exactly as they apply to
centrally-trained models. FL protects the training *process*. It does not change the
privacy properties of the trained artifact.

A deployment that uses FL for training but then publishes the model openly (e.g., to client
devices for on-device inference) has the same model-as-leak exposure as a centrally-trained
model. See [[reference_adversarial_ml_model_security]] for the attack surface against the
final artifact.

### 12.5 Regulatory residue

GDPR / HIPAA / state data-residency law treats model parameters as derived personal data in
some jurisdictions. "The data never left the client" is not equivalent to "regulatory
exposure is zero":

- A model trained on EU residents' data and operated from a US server may still be a
  GDPR Article 3 controllership claim.
- HIPAA's de-identification standard does not generally apply to model parameters; the
  question of whether trained parameters are PHI is jurisdiction-dependent and unsettled in
  US case law as of 2026 [unverified specific advisory; FL-specific HIPAA case law is
  sparse].
- The right-to-erasure (GDPR Article 17, "right to be forgotten") interacts poorly with FL.
  Removing a single client's contribution from a trained model requires either retraining
  (expensive, defeats the point) or federated unlearning (a research area; production
  approaches are immature). See [[reference_privacy_engineering]] §"unlearning."

The structural lesson: legal and technical privacy claims are not the same. FL is a
technical control. Whether it meets a given legal standard depends on the legal standard,
the jurisdiction, and the specific deployment. Do not let the engineering team relax
regulatory diligence on the strength of an FL architecture claim.

---

## 13. Honest framing on AI / LLM-era FL (2024-2026 frontier)

Federated training of large language models has been proposed and prototyped. The
production reality as of 2026 is constrained:

- **Federated full fine-tuning of LLMs** — heavyweight. Per-client memory and compute costs
  for billion-parameter model gradient computation are out of reach for the typical mobile or
  edge client. Cross-silo (data-center-class clients) is feasible; cross-device is not.
- **FL + PEFT (parameter-efficient fine-tuning)** — LoRA-style adapters bring the per-client
  cost down by orders of magnitude. The client trains a small adapter on its local data; only
  the adapter parameters are shared. This is the realistic deployment shape for the medium
  term. Research is active; production deployments at scale are sparse as of 2026
  [unverified specific advisory for named-vendor production rollouts].
- **The threat model shifts modestly.** Adapter gradients are still gradients; gradient
  inversion applies. The attack surface narrows because adapter parameter counts are small,
  but does not vanish. SecAgg and DP compose with PEFT-FL as they do with traditional FL.
- **LLM-specific threats** (jailbreak transfer, training-data extraction via prompt-based
  attacks against the final fine-tuned model) compose with FL-specific threats. See
  [[reference_llm_agent_security]] for the runtime attack surface and
  [[reference_adversarial_ml_model_security]] for the model-artifact attack surface.

The honest framing: FL-for-LLMs is a research frontier, not a production substrate. Treat
claims of "federated LLM training in production" with the same scrutiny applied to any new
deployment shape — verify the framework, verify the privacy mechanism, verify the threat
model, verify the audit trail.

---

## 14. Cross-link cluster

- [[reference_adversarial_ml_model_security]] — the five-category catalog (evasion /
  poisoning / extraction / MIA / inversion) for general ML; this doc specializes in the
  federated case.
- [[reference_privacy_engineering]] — DP, MPC, HE, ZKP primer; FL is one application of
  these primitives (§6, §7).
- `cryptography_expertise.md` (no individual memory pointer) — SecAgg's cryptographic
  primitives: pairwise Diffie-Hellman, Shamir secret sharing, authenticated channels.
- [[reference_post_quantum_cryptography]] — PQ-SecAgg migration target (X25519 + ML-KEM)
  and the harvest-now-decrypt-later threat for long-sensitivity FL data.
- [[reference_confidential_computing]] — FL inside TEEs (Intel SGX / TDX, AMD SEV-SNP, ARM
  CCA, NVIDIA H100 CC). The structural defeat of malicious-server gradient inversion.
- [[reference_llm_agent_security]] — LLM runtime threat surface; relevant to FL-for-LLMs
  frontier (§13).
- [[reference_detection_engineering]] — runtime anomaly detection on FL updates: per-client
  norm clipping, cosine-similarity outlier filtering, behavioral fingerprinting, sigma rules
  on aggregation server telemetry.
- [[reference_bug_hunting_first_principles]] — first-principles lens for FL deployment
  audits. The §10.8 checklist is the operational distillation.
- [[reference_game_theory_mechanism_design]] — FL incentive design. Clients submit honest
  gradients because (in the cross-silo case) they have signed an organizational agreement,
  or (in the cross-device case) because the service they receive from the model is contingent
  on participation. Sybil resistance is fundamentally a mechanism-design problem.
- [[reference_hardware_side_channels]] — the TEE side-channel attack surface applicable to
  FL-in-enclave deployments.
