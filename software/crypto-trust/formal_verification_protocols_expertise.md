# Formal Verification of Cryptographic Protocols — Tools, Methodology, and Real Deployments

## Synthesized from Burrows, Abadi, Needham, Blanchet, Cremers, Basin, Bhargavan, Delignat-Lavaud, Meadows, Paulson, Barthe, Grégoire, Kobeissi, Fett, Küsters, Schmitz, and Lowe

> **Researchers:**
> - **Michael Burrows + Martín Abadi + Roger Needham** — authors of *A Logic of
>   Authentication* (DEC SRC Report 39, February 1989; *ACM TOCS* 8(1), 1990), which
>   introduced **BAN logic** — the first formal system explicitly designed to reason
>   about authentication protocols. Needham (1935-2003) was head of the University
>   of Cambridge Computer Laboratory and co-designer of the Needham-Schroeder
>   protocol (1978). Abadi (UC Santa Cruz, formerly DEC SRC and Microsoft Research)
>   went on to define the **applied pi-calculus** with Cédric Fournet, the symbolic
>   substrate underlying ProVerif. Burrows (Google) co-designed the AltaVista index
>   and Chubby lock service after his BAN-era work at DEC SRC.
> - **Bruno Blanchet** (Inria Paris, head of PROSECCO until its rename) — author of
>   both **ProVerif** (symbolic model, 2001+) and **CryptoVerif** (computational
>   model, 2006+). The canonical practitioner-researcher in this field: both tools
>   have been used to verify TLS 1.3, Signal, WireGuard, and dozens of other
>   real-world protocols. Teaches the *SECURE* course on protocol proofs at MPRI;
>   2026 PC member for IEEE CSF.
> - **Cas Cremers** (CISPA Helmholtz Center for Information Security; Professor of
>   Computer Science, Saarland University) and **David Basin** (Information Security
>   Group head, Department of Computer Science, ETH Zürich) — Tamarin Prover
>   co-creators. With Simon Meier, Benedikt Schmidt, Jannik Dreier, and Ralf Sasse,
>   they built the multiset-rewriting prover that has become the working tool for
>   stateful real-world protocols. Basin + Cremers + Sasse + Dreier received the
>   2026 **Levchin Prize for Real-World Cryptography** for Tamarin.
> - **Karthikeyan Bhargavan** (Cryspen co-founder and CRO; formerly *directeur de
>   recherche* at Inria Paris and head of PROSECCO) — leader of the **miTLS** and
>   **HACL\*** projects; ERC Grant recipient for the formal-methods work that
>   directly shaped the TLS 1.3 design. Co-author of the Triple Handshake attack
>   (2014), the SLOTH cross-protocol-collision attack (2016), and the verified
>   record-layer paper for TLS 1.3 (CCS 2017).
> - **Antoine Delignat-Lavaud** (Microsoft Research Cambridge; formerly Inria) —
>   key contributor to **Project Everest** (the verified HTTPS stack: F\*,
>   miTLS-F\*, EverCrypt, EverParse) and TLS 1.3 standards work at the IETF. Now
>   focused on Confidential Compute Framework (CCF) protocol design at Microsoft.
> - **Catherine Meadows** (US Naval Research Laboratory, Center for High Assurance
>   Systems; head of the Formal Methods Section) — principal developer of the
>   **NRL Protocol Analyzer (NPA)** in the late 1980s, one of the first tools to
>   find previously-unknown flaws in deployed cryptographic protocols. Lead
>   architect of its successor **Maude-NPA**, the canonical equational-theory
>   analyzer for crypto protocols.
> - **Lawrence C. Paulson** (Cambridge Computer Laboratory) — developed the
>   **Inductive Method** for protocol verification on top of Isabelle/HOL
>   (*Journal of Computer Security* 6:1-2, 1998). ACM Fellow (2008), Herbrand
>   Award for Distinguished Contributions to Automated Reasoning (2017). The
>   theorem-proving alternative to model-checking approaches.
> - **Gilles Barthe** (Max Planck Institute for Security and Privacy, Bochum;
>   formerly IMDEA Software) and **Benjamin Grégoire** (Inria) — co-creators of
>   **EasyCrypt** (2010+). Together with Federico Olmedo, François Dupressoir,
>   and others, they built the probabilistic relational Hoare logic (pRHL) that
>   underlies computer-aided cryptographic proofs. EasyCrypt is the canonical
>   tool for fully computational game-hopping proofs of real schemes.
> - **Nadim Kobeissi** (Symbolic Software, Paris; Alan Turing Institute external
>   researcher) — author of **Verifpal** (2019), the practitioner-oriented
>   protocol verifier modeled on ProVerif but with a syntax tailored to engineers
>   and pedagogy. Cryptocat designer (2011-2019). PhD *Formal Verification for
>   Real-World Cryptographic Protocols and Implementations* (2018).
> - **Daniel Fett + Ralf Küsters + Guido Schmitz** (Stuttgart / Trier) — authors
>   of the **Web Infrastructure Model (WIM)** and *A Comprehensive Formal
>   Security Analysis of OAuth 2.0* (CCS 2016, arXiv:1601.01229). The lineage
>   that produced the IETF *OAuth 2.0 Security Best Current Practice* (RFC 9700)
>   and the analogous formal treatment of FAPI and OpenID Connect.
> - **Gavin Lowe** (Oxford Computing Lab) — discovered the 1995 man-in-the-middle
>   attack on the Needham-Schroeder Public-Key Protocol using FDR (the CSP
>   refinement checker). The Lowe attack is the canonical historical example of
>   automated tooling finding a flaw missed by 17 years of human review.
>
> **Sources:** Burrows-Abadi-Needham *A Logic of Authentication* (DEC SRC RR-39,
> 1989; *ACM TOCS* 8(1), 1990; CMU host
> https://www.cs.cmu.edu/~dga/15-712/F07/papers/Burrows90.pdf); Bruno Blanchet
> homepage and ProVerif/CryptoVerif documentation
> (https://bblanche.gitlabpages.inria.fr/); Tamarin Prover documentation
> (https://tamarin-prover.com/, https://tamarin-prover.github.io/); EasyCrypt
> documentation (https://www.easycrypt.info/); Verifpal site
> (https://verifpal.com/); Karthikeyan Bhargavan homepage and miTLS publications
> (https://bhargavan.info/, https://prosecco.gforge.inria.fr/); Cas Cremers /
> CISPA Tamarin page (https://people.cispa.io/cas.cremers/); Squirrel Prover
> (https://squirrel-prover.github.io/); Project Everest
> (https://project-everest.github.io/); Lowe 1995
> https://link.springer.com/chapter/10.1007/3-540-61042-1_43; Fett-Küsters-Schmitz
> CCS 2016 (https://arxiv.org/abs/1601.01229); WireGuard formal verification
> (https://www.wireguard.com/papers/wireguard-formal-verification.pdf); EMV
> Break-Fix-Verify (https://arxiv.org/abs/2006.08249); 5G AKA analysis
> (https://arxiv.org/abs/1806.10360); Maude-NPA (https://maude.cs.illinois.edu/);
> Paulson Isabelle (https://www.cl.cam.ac.uk/~lp15/papers/Auth/).

---

## 1. Why Formal Verification of Protocols Matters

The publication record of cryptographic protocols is a 40-year sequence
of designs-with-prose-arguments-for-security broken by attacks discovered
years later. The pattern is consistent enough that "if your protocol is
in production and has not been formally analyzed, assume it is broken in
a way not yet published" is a defensible operating prior.

### Famous failures

**Needham-Schroeder Public-Key (1978; broken 1995).** Gavin Lowe found a
man-in-the-middle attack using FDR
(https://link.springer.com/chapter/10.1007/3-540-61042-1_43). Message 6
omits the responder's identity, letting an intruder interleave two
sessions and convince B it shares a key with A. The fix
(Needham-Schroeder-Lowe) adds B's identity. 17 years of human review
missed it; an automated refinement checker found it in minutes. Founding
parable of automated protocol verification.

**Kerberos v4** had ticket-replay and timestamp-only freshness flaws;
v5 addressed most. **MS-CHAPv1** had hash-chunk-isolation flaws reducing
work factor from 2^56 to 3×2^21 parallel. **WEP** combined a 24-bit IV
with RC4 in a polynomial-time-recoverable way (Fluhrer-Mantin-Shamir
2001). **Triple Handshake** on TLS (Bhargavan et al. 2014) exploited
unbound resumption. **DROWN, FREAK, Logjam, POODLE, BEAST, CRIME,
BREACH, Lucky 13, SWEET32** — the 2010-2020 enumeration of TLS attacks.
Each had a structural cause findable at design time with appropriate
model and tooling.

**OAuth 2.0** had multiple class-A attacks documented by Fett-Küsters-
Schmitz (CCS 2016, https://arxiv.org/abs/1601.01229) — third-party-login,
307-redirect credential leak, IdP mix-up — none obvious from prose
reading of RFC 6749. RFC 9700 (OAuth 2.0 Security BCP) is in significant
part the operational distillation of that formal analysis. Extended
treatment: `saml_federation_expertise.md` §5.

### The designer is not the attacker

The protocol designer reasons forward ("if A and B are honest, the
protocol completes correctly"). The attacker reasons backward from a
goal ("is there a sequence of network operations that reaches a state
where honest parties' beliefs differ?"). The designer's perspective
systematically misses combinations the attacker can manufacture.

Formal verification reverses this. The model encodes the protocol AND
the adversary AND the security property; the tool asks "is there a
counterexample trace?" or "can the property be derived?" The designer
no longer has to imagine every adversary action — the model spans them.
This is the same epistemic move as adversarial steelmanning
(`steelman_doctrine_expertise.md` — the Foil role), but mechanized.

### Boundaries

`cryptography_expertise.md` covers the underlying primitives — formal
verification assumes primitives are sound and reasons about composition.
`smart_contract_evm_security_expertise.md` uses different tools (Halmos,
Certora, K-EVM) because EVM adversary model differs.
`hardware_side_channels_expertise.md` covers what protocol verification
misses at the implementation/microarchitecture boundary.
`llm_agent_security_expertise.md` and
`agentic_web_capabilities_expertise.md` are emerging frontiers (§14).

---

## 2. Adversary Models

Every formal-verification claim is parameterized over an adversary model.
"Protocol P is secure" is meaningless without "under adversary class A
with capability set C against property set Π." Reading the model is the
first task with any formal-verification paper.

### Dolev-Yao (1983) — the symbolic baseline

Dolev-Yao, *On the security of public-key protocols* (IEEE TIT 29:2,
1983). The Dolev-Yao adversary controls the network (delete, replay,
fork, modify, inject), cannot break cryptography (encryption is a perfect
black box; signatures unforgeable without key; nonces unguessable), has
unlimited time, knows all public keys, and can be a protocol participant
with its own keys.

This lets the analyst reason about *structural* flaws — broken even with
perfect crypto. The Lowe attack on Needham-Schroeder is Dolev-Yao: it
works because of message/identity binding, not cryptographic weakness.

Symbolic models extend Dolev-Yao with *equational theories* capturing
algebraic properties: `dec(enc(m, k), k) = m`, `dh(g^x, y) = dh(g^y, x)`
for DH, XOR cancellation `m XOR m = 0`. ProVerif and Maude-NPA support
equational theories natively; Tamarin handles them through built-in
theories (DH, bilinear pairings, XOR, AC operators) and user-defined
equations subject to convergence and finite-variant requirements.

### Computational model — game-based

The adversary is a **probabilistic polynomial-time (PPT)** algorithm.
Security is defined via games (e.g., IND-CPA: adversary picks two
messages, challenger encrypts a random one, adversary tries to guess
which). The scheme is secure if `Pr[A wins] ≤ 1/2 + negl(λ)` for every
PPT adversary. Proofs proceed by **reduction**: any PPT adversary
winning the protocol game implies a PPT algorithm solving an underlying
hard problem (factoring, discrete log, LWE).

CryptoVerif and EasyCrypt operate in this model. Proofs are sequences of
games (Bellare-Rogaway "game-hopping") where each transition is a
syntactic transformation (adversary cannot distinguish) or an explicit
reduction to a primitive assumption.

### Symbolic vs computational — the trade-off

| Aspect | Symbolic | Computational |
|---|---|---|
| Crypto model | Perfect black-box | Reductions to hardness |
| Adversary | Dolev-Yao | PPT (advantage bound) |
| Catches | Structural flaws, replay, type confusion | Tightness, concrete security |
| Misses | Bit-level / advantage attacks | Sometimes structural composition |
| Tractability | Highly automated | Semi-interactive |
| Tools | ProVerif, Tamarin, Maude-NPA, Verifpal | CryptoVerif, EasyCrypt, Squirrel |

Both lenses are needed. Lowe is symbolic; SLOTH (Bhargavan-Leurent 2016)
is partly computational (MD5/SHA-1 collision tightness). TLS 1.3 used
both.

### Soundness theorems — bridging

Abadi-Rogaway 2000 (*Reconciling Two Views of Cryptography*, J.
Cryptology) showed that under certain conditions, symbolic equivalence
implies computational indistinguishability. Seminal result was for
symmetric encryption against passive adversaries; Cortier-Warinschi,
Backes-Pfitzmann, Comon-Cortier extended to active adversaries and
richer primitives. Each soundness theorem comes with restrictions (no
encryption-cycles, no key-cycles, specific encryption-scheme security
definitions); read them before relying on symbolic results for
computational guarantees.

### Other model dimensions

- **Active vs passive** — modern analyses (TLS 1.3, Signal, WireGuard)
  assume active by default. Passive-only is weaker.
- **Single-session vs multi-session** — most attacks (Lowe, OAuth IdP
  mix-up, EMV brand mix-up) require multiple concurrent sessions with
  adversarial roles. Modern tools analyze unbounded sessions by default.
- **Stateless vs stateful** — Tamarin's multiset rewriting handles
  state natively; ProVerif handles limited state via tables.
- **Post-quantum** — most tools are classical-only; Squirrel, EasyPQC,
  Tamarin-PQ extensions add QROM modeling.
- **Insider / key-compromise** — Tamarin's `Reveal_ltk(A)` rule is the
  canonical way to model long-term-key compromise. The 5G AKA paper used
  this to show what survives USIM compromise.
- **Coalition adversary** — handled natively by symbolic tools; harder
  in computational tools where reductions thread through multiple
  adversary roles.

---

## 3. BAN Logic — The Original (1989)

Burrows, Abadi, and Needham, *A Logic of Authentication* (DEC SRC
Research Report 39, February 1989; revised journal version *ACM TOCS*
8(1), Feb 1990; canonical PDF
https://www.cs.cmu.edu/~dga/15-712/F07/papers/Burrows90.pdf).

### What it is

BAN is a **belief logic** over agents and messages. The core operators:

| Notation | Meaning |
|---|---|
| `A |≡ X` | A believes X (A is entitled to believe X) |
| `A ⊲ X` | A sees X (A has received a message containing X) |
| `A |~ X` | A once said X (A sent a message at some past time containing X) |
| `A |⇒ X` | A has jurisdiction over X (A is authoritative about X) |
| `#(X)` | X is fresh (X has not been sent in a previous run) |
| `A ⇄ B (K)` | K is a good key shared between A and B |
| `→ A (K)` | K is A's public key |
| `{X}_K` | X encrypted under K |

### Inference rules (selected)

- **Message-meaning rule** (for shared keys): if `A |≡ A ⇄ B (K)` and `A
  ⊲ {X}_K`, then `A |≡ B |~ X`. (If A believes K is good for A↔B and A
  sees X encrypted under K, then A believes B once said X.)
- **Nonce-verification rule**: if `A |≡ #(X)` and `A |≡ B |~ X`, then `A
  |≡ B |≡ X`. (Fresh + said implies current belief.)
- **Jurisdiction rule**: if `A |≡ B |⇒ X` and `A |≡ B |≡ X`, then `A |≡
  X`. (If A trusts B about X and A believes B believes X, then A
  believes X.)

### Idealization, importance, decline

The most contested step in a BAN proof is **idealization** — converting
protocol messages into BAN-logic formulas. Not mechanical; requires
judgement, and bad idealization is the source of BAN's famous false
positives. Burrows et al. analyzed Kerberos and gave a clean proof of
authentication; later work showed BAN was silent on flaws that did
exist.

BAN was important as the first explicit formal system for
authentication; it made belief structure visible and spawned a family
(GNY, AT, SVO, CKT5). Two problems caused its decline by the late
1990s: idealization is informal (analysts can disagree on the same
protocol), and BAN has no adversary model (reasons about what honest
parties believe, not what adversaries manufacture — the Lowe attack is
invisible to BAN).

BAN remains the standard intro in every protocol-verification course
because the belief operators are intuitive, the proofs are short and
human-readable, and the historical examples are the same protocols
later tools were applied to. Reading the 1989 paper is still
recommended before using any modern tool — the discipline of writing
down what each party should believe at each step transfers to all
later formalisms.

---

## 4. ProVerif — The Workhorse

Bruno Blanchet, Inria. First release ~2001; continuously developed since.
Manual and source at https://bblanche.gitlabpages.inria.fr/proverif/.

### Model

Applied pi-calculus (Abadi-Fournet 2001) — an extension of the pi-calculus
with cryptographic primitives represented by function symbols and
equational theories. The protocol is written as a process; the adversary
is the implicit environment that the process runs in. Queries are formulas
expressing security properties: secrecy (`query attacker(s)`), authentication
(`query inj-event(e1) ==> inj-event(e2)`), observational equivalence (`process P
~ process Q`).

### Internal mechanics

ProVerif compiles the applied pi-calculus process and security query into
a set of **Horn clauses** representing what the adversary can derive from
network observations. Saturation of the clause set either:

- Terminates with no derivation of the query target → property holds.
- Derives the query target → attack found, with a witness trace.
- Fails to terminate → ProVerif is inconclusive (the abstraction is
  sound but not complete).

The Horn-clause abstraction over-approximates the attacker's power:
attacks found are real, but some genuine secure protocols may be flagged
as insecure due to spurious derivations.

### Strengths and weaknesses

Strengths: unbounded sessions by default; rich equational theories
(DH, XOR, blind signatures, homomorphic encryption — arguably better
than Tamarin for "pure crypto"); reasonably fast on simple protocols
(minutes to hours); 25+ years of development with a large model
library.

Weaknesses: false positives (Horn-clause abstraction can find phantom
attacks not corresponding to real traces; analyst must inspect each);
limited state (original ProVerif had none; `tables` feature added later
is awkward for ratchets, counters); less intuitive than Tamarin for
sequential composition.

### Real wins

TLS 1.3 (PROSECCO papers 2014-2018, Bhargavan-Blanchet-Kobeissi S&P
2017); Signal Protocol handshake and ratchet (Kobeissi-Bhargavan-
Blanchet EuroS&P 2017, alongside CryptoVerif); OPAQUE PAKE during CFRG
selection; X3DH; many others.

Note: the Fett-Küsters-Schmitz OAuth/OIDC line (CCS 2016, see
`saml_federation_expertise.md` §5) used their own Web Infrastructure
Model (a higher-level abstraction tailored to HTTP semantics) rather
than ProVerif directly. Methodology is in the ProVerif lineage; the
substrate differs.

---

## 5. Tamarin — The Modern Alternative

David Basin (ETH Zürich), Cas Cremers (CISPA), Simon Meier, Benedikt
Schmidt, Jannik Dreier (Université de Lorraine), Ralf Sasse (ETH).
Project began ~2009 in Basin's group at ETH; first version 2012 (Meier-
Schmidt theses). Tamarin Manual at https://tamarin-prover.com/.

2026 Levchin Prize awardees: Basin, Cremers, Sasse, Dreier
(https://cispa.de/en/levchin-prize,
https://ethz.ch/staffnet/en/news-and-events/internal-news/archive/2026/03/levchin-preis-fuer-forschende-des-d-infk.html).

### Model

**Multiset rewriting rules** over **facts**. Facts are typed predicates
on terms; the protocol state is a multiset of facts. A rewriting rule
has the form `Premises -[Actions]-> Conclusions`, where Premises and
Conclusions are multisets of facts and Actions are labels recorded in
the trace. Example rule (a server creating a fresh nonce and sending an
initial message):

```
rule S_1:
  [ Fr(~n) ]
  -[ ServerStart(S, ~n) ]->
  [ Out(<S, ~n>), ServerState(S, ~n) ]
```

Security properties are first-order logic over traces: "for all instances
of `ServerStart`, there exists a matching `ServerCommit` with the same
nonce" etc.

### Strengths and weaknesses

Strengths: explicit state and stateful protocols (multiset rewriting
handles mutable state, counters, key-update, ratchets, hardware tokens —
the biggest advantage over ProVerif for modern protocols); observational
equivalence via diff-equivalence (anonymity, unlinkability, privacy);
interactive mode for guiding constraint solving when automation fails;
built-in DH, XOR, bilinear pairings, signatures, asymmetric encryption,
user equational theories with convergence/finite-variant conditions;
reference book (Basin-Cremers-Dreier-Sasse, *Modeling and Analyzing
Security Protocols with Tamarin*, Springer 2025, ISBN 9783031909351).

Weaknesses: slower than ProVerif on simple stateless protocols; steeper
learning curve; finite-variant restriction excludes full ring theories
and some homomorphic schemes; large analyses often require interactive
guidance.

### Real wins

- **TLS 1.3.** Cremers, Horvat, Hoyland, Jacomme, van der Merwe (S&P
  2017) modeled the TLS 1.3 draft 21 in Tamarin and found and fixed
  issues prior to standardization. See
  https://tamarin-prover.com/publications.html.
- **5G AKA.** Basin, Dreier, Hirschi, Radomirović, Sasse, Stettler, *A
  Formal Analysis of 5G Authentication* (CCS 2018, arXiv:1806.10360).
  Identified missing security goals in the 3GPP standard; found that
  certain goals are violated without additional assumptions; led to
  3GPP-side updates.
- **EMV chip-and-PIN.** Basin, Sasse, Schaller, Toro-Pozo, *The EMV
  Standard: Break, Fix, Verify* (S&P 2021, arXiv:2006.08249;
  https://emvrace.github.io/). Found and demonstrated PIN-bypass
  attacks on Visa, V Pay, Mastercard, Maestro; built a proof-of-concept
  Android relay app. Mastercard rolled out brand-mixup defenses
  post-disclosure.
- **WireGuard.** Donenfeld and Milner, *Formal Verification of the
  WireGuard Protocol* (2018,
  https://www.wireguard.com/papers/wireguard-formal-verification.pdf).
  Hötzendorfer et al., *A Unified Symbolic Analysis of WireGuard* (NDSS
  2024, https://www.ndss-symposium.org/wp-content/uploads/2024-364-paper.pdf).
- **Noise Framework.** Kobeissi-Nicolas-Bhargavan *Noise Explorer*
  (https://eprint.iacr.org/2018/766.pdf) used both Tamarin and Verifpal
  alongside ProVerif to generate symbolic models for all 53 Noise
  patterns from the spec.
- **Signal Protocol post-quantum.** *Formal Verification of a Post-quantum
  Signal Protocol with Tamarin* (VECoS 2023,
  https://link.springer.com/chapter/10.1007/978-3-031-49737-7_8).

### Tamarin vs ProVerif — pragmatic guidance

| Choose ProVerif when | Choose Tamarin when |
|---|---|
| Protocol is stateless or minimally stateful | Protocol has rich mutable state, ratchets, counters |
| Equational theory is heavy (homomorphic, blind, XOR) | Observational equivalence / privacy properties matter |
| You want maximum automation | You want to interact with proofs |
| Speed matters (CI integration) | You need explicit trace counter-examples |

Many real-world projects use **both**. TLS 1.3 had analyses in ProVerif,
Tamarin, and CryptoVerif simultaneously. Multi-tool redundancy is the
state of the art for high-stakes protocols.

---

## 6. CryptoVerif — Computational Model

Bruno Blanchet, Inria. Same author as ProVerif. First version 2006;
manual at https://bblanche.gitlabpages.inria.fr/CryptoVerif/.

### Model

Game-based / sequence-of-games proofs in the computational model. The
protocol is written in a probabilistic process calculus; the user
specifies cryptographic assumptions (CDH, DDH, IND-CPA, EUF-CMA, PRF);
the tool transforms the initial game through a sequence of indistinguishable
steps until the desired property is syntactically apparent.

### What it gives you

A machine-checked reduction: the protocol's security advantage is bounded
by a polynomial combination of advantages against the underlying primitives,
plus negligible terms from random oracles, collision probabilities, and
counter increments. Concretely:

```
Adv^auth_Protocol(t) ≤ q^2 / 2^|N| + q · Adv^CDH_G(t') + Adv^euf-cma_Sig(t')
```

This is the *concrete-security* statement that practitioners actually
care about: at parameter sizes X, with at most Q queries, the protocol-
break probability is at most ε.

### Strengths

- Outputs machine-checked computational proofs — the strongest formal
  guarantee currently achievable for protocols.
- Tighter integration with cryptographic primitive assumptions.
- Game-hopping is the standard cryptographic proof technique; the proofs
  CryptoVerif produces look like what cryptographers write by hand, just
  mechanized.

### Weaknesses

- **Higher barrier to use** than ProVerif. The user must provide more
  guidance about which game transformation to apply.
- **Slower iteration.** Proofs may take days of analyst time to construct.
- **Cryptographic assumptions must be explicitly axiomatized**, and the
  axioms are the implicit attack surface — get the assumption wrong and
  the proof is meaningless.

### Real wins

- **TLS 1.3 record layer.** Bhargavan et al., *Implementing and Proving
  the TLS 1.3 Record Layer* (S&P 2017,
  https://inria.hal.science/hal-01674096/file/record.pdf). The
  computational proof for the record layer; complements the ProVerif
  symbolic analysis of the handshake.
- **WireGuard.** Lipp, Blanchet, Bhargavan, *A Mechanised Cryptographic
  Proof of the WireGuard Virtual Private Network Protocol* (EuroS&P 2019,
  https://bblanche.gitlabpages.inria.fr/publications/LippBlanchetBhargavanEuroSP19.pdf).
- **Signal Protocol.** CryptoVerif analyses of X3DH and Double Ratchet
  alongside the ProVerif work.
- **PQ-TLS hybrid key exchange.** Recent CryptoVerif work on post-quantum
  TLS/SSH key exchange (CSF 2024).

CryptoVerif is the canonical bridge from "we have a symbolic model" to
"we have a computational reduction to standard assumptions." For high-
assurance protocols, both are needed.

---

## 7. EasyCrypt

Gilles Barthe (MPI-SP), Benjamin Grégoire (Inria), with Federico Olmedo,
François Dupressoir, Pierre-Yves Strub, and many others. First version
~2010 from the IMDEA Software group. Site at https://www.easycrypt.info/.

### Model

**Probabilistic relational Hoare logic (pRHL).** A program logic that
relates two probabilistic programs by stating that for matched inputs
they produce matched outputs (in a relational sense). The relational
view aligns naturally with cryptographic game-hopping: each game
transformation is a pRHL judgement saying "the output distributions are
indistinguishable / equal up to a bound."

EasyCrypt is interactive — proofs are constructed via tactics by the
analyst. The proof-development experience is closer to Coq than to
ProVerif's "press button, see attack."

### Strengths

- **Full computational rigor.** Proofs are end-to-end reductions to
  standard primitive assumptions with concrete bounds.
- **General-purpose.** Not specifically a protocol verifier — pRHL can
  reason about almost any probabilistic algorithm. Used for signature
  schemes, encryption schemes, MPC protocols, e-voting privacy, and
  side-channel-resistance proofs.
- **PQC extensions.** EasyPQC (Barbosa et al., eprint 2021/1253) adapts
  EasyCrypt for post-quantum proofs with quantum-accessible random
  oracles.

### Weaknesses

- **Highest learning curve** of any tool in this document. Typical user
  is a PhD-trained formal-methods specialist.
- **Slow proof construction** — months to years for complex schemes.
- **Limited automation** — most tactics must be applied manually.
- Not the right tool for *finding* attacks; it is the tool for *certifying*
  designs you already believe are correct.

### Real wins

- **Helios voting protocol.** Cortier, Dragan, Dupressoir, Schmidt, Strub,
  Warinschi (S&P 2017,
  https://members.loria.fr/VCortier/files/Publications/b2hd-easycrypt-SP17.html).
  Modular machine-checked proofs of privacy for several hundred Helios
  variants. Followup work (Cortier et al., CSF 2018) extended to Belenios.
- **Authenticated key exchange.** Various S&P/CRYPTO papers using
  EasyCrypt for AKE schemes.
- **MPC and threshold signatures.** Increasingly the tool of choice for
  threshold-cryptography proofs that would be infeasible to verify by
  hand.
- **TLS handshake fragments.** Project Everest has used EasyCrypt for
  specific computational proofs that integrate with the F\* /miTLS line.

EasyCrypt is the "you need PhD-level cryptographers and 18 months" tool.
It is right for the small set of protocols where the cost is justified.

---

## 8. Verifpal — The Practitioner Tool

Nadim Kobeissi, Symbolic Software (Paris). First release 2019; manual at
https://verifpal.com/.

### Model

Symbolic, applied-pi-style — close enough to ProVerif's semantics that
many models translate. Distinguishing design choices:

- **Engineer-friendly syntax.** Models look like protocol-spec pseudocode.
- **Built-in queries.** `queries [ confidentiality, authentication,
  freshness ]` rather than ad-hoc query formulas.
- **First-class principal model.** `principal Alice [ generates a;
  knows password ]` rather than process calculus encoding.
- **Automatic reasoning.** No interactive proof; analyst writes the
  model and the tool runs.

### Strengths

- **Lowest barrier to entry.** A working cryptographer can write a
  Verifpal model in an afternoon.
- **Pedagogical fit.** Cryptography courses (including Kobeissi's own
  applied-cryptography material) now use Verifpal as the first
  formal-verification exposure.
- **Used by industry.** Google, Zoom, Bosch listed among Verifpal
  adopters (Symbolic Software self-report). The Cure53-audit pipeline
  occasionally produces Verifpal models alongside text reports.

### Weaknesses

- **Less expressive** than ProVerif/Tamarin. Some protocols cannot be
  modeled in Verifpal that can in the more general tools.
- **Younger.** Less battle-tested; fewer published proofs of major
  protocols compared to ProVerif/Tamarin.
- **Inherits Dolev-Yao perfect-crypto limits.** Not a computational-model
  tool.

### Real uses

- **Signal Protocol.** Multiple Verifpal models of X3DH / Double Ratchet
  published.
- **BBS+ signatures.** Selective-disclosure credential analysis.
- **Noise Framework** patterns (alongside ProVerif and Tamarin).
- **WireGuard** subset analyses.

### When to reach for Verifpal

- Pedagogy: teaching cryptographic protocols to engineers.
- Triage: rough security check before committing to a full ProVerif /
  Tamarin model.
- Documentation: shipping a formal model alongside a protocol spec for
  audit and review.

Verifpal is not a replacement for ProVerif / Tamarin in high-stakes
verification; it is the *entry point* for engineers to think formally
about their protocols. The Kobeissi PhD thesis (*Formal Verification for
Real-World Cryptographic Protocols and Implementations*, 2018) is the
canonical statement of this practitioner-first philosophy.

---

## 9. Other Systems Worth Knowing

### Maude-NPA

Catherine Meadows + Santiago Escobar, José Meseguer (Illinois). Builds
on Maude rewriting-logic. Distinguishing feature: natively reasons about
protocols whose cryptography satisfies non-trivial equational properties
— homomorphic encryption, exponentiation, XOR, cancellation — using
narrowing modulo the equational theory. Use cases: XOR-based protocols
(RFID, low-power IoT), group key agreement with explicit DH structure,
algebraic schemes where ProVerif and Tamarin struggle. Manual at
https://maude.cs.illinois.edu/.

### AVISPA / AVANTSSAR

EU FP5/FP7 projects (2003-2010) producing an integrated platform with
back-ends OFMC (Basin-Mödersheim-Viganò), CL-AtSe (Turuani), SATMC
(Armando), TA4SP. Front-end: HLPSL. Largely superseded by ProVerif and
Tamarin; the AVISPA library remains a useful reference.
http://www.avispa-project.org/.

### F\* + miTLS + Project Everest

Bhargavan, Delignat-Lavaud et al. F\* is a dependently-typed language
with effects (MSR + Inria). miTLS is F\*-verified TLS. Project Everest
(https://project-everest.github.io/) bundles miTLS-F\*, EverCrypt
(verified crypto primitives), EverParse (verified parsers for ASN.1,
QUIC, TLS formats). The key insight: protocol verification proves the
design; F\* + miTLS proves the implementation. Together they close the
spec-vs-code gap.

### Coq, FCF, Rocq Prover

Andrew Appel's Princeton group developed FCF (Foundational Cryptography
Framework) in Coq; Adam Petcher used it for HMAC and TLS-record-layer
proofs. Coq (now Rocq Prover) is also used directly — see Adam
Chlipala's *Fiat Cryptography* for elliptic-curve arithmetic. Highest
expertise barrier, most flexibility.

### Squirrel Prover

Baelde, Delaune, Jacomme, Koutsos, Moreau (Inria, S&P 2021,
https://inria.hal.science/hal-03172119/). Uses the Computationally
Complete Symbolic Attacker (CCSA) approach (Bana-Comon) — a meta-logic
where symbolic reasoning is sound for the computational model by
construction. Single interactive proof environment giving computational
guarantees with symbolic-style proof effort. Active development.
https://squirrel-prover.github.io/.

### HACSpec and Lean4

HACSpec (Bhargavan + Cryspen) is a Rust subset for writing cryptographic
algorithm specs that type-check in F\* and feed into Coq/Lean proofs.
Targets *algorithms* (AES, ChaCha20, Curve25519), not *protocols* — the
trusted base for HACL\*/EverCrypt. Lean 4 has nascent cryptographic
formalization in mathlib; not yet a mature protocol-verification tool
but worth watching.

---

## 10. TLS 1.3 — The Real-World Success Story

The most important demonstration that formal verification can be applied
to a real, standards-track, security-critical protocol *during design* —
not as post-hoc audit — is the TLS 1.3 effort, 2014-2018. After a decade
of TLS-1.x attacks (BEAST, CRIME, Lucky 13, FREAK, Triple Handshake,
POODLE), the IETF TLS WG was receptive to formal-methods input. Each
major draft was analyzed by multiple formal-verification teams in
parallel; RFC 8446 (March 2018) has more formal-verification artifacts
attached to it than any previous IETF protocol.

### Tools applied

- **ProVerif** — handshake symbolic analysis (PROSECCO Inria; Bhargavan-
  Blanchet-Kobeissi S&P 2017,
  https://bblanche.gitlabpages.inria.fr/publications/BhargavanBlanchetKobeissiSP2017.pdf).
- **Tamarin** — Cremers-Horvat-Hoyland-Jacomme-van der Merwe (S&P 2017);
  Hirschi-Schmidt for downgrade.
- **CryptoVerif** — record layer computational proof with concrete
  security bound.
- **miTLS-F\*** — verified reference implementation closing the spec-vs-
  code gap.

### What was caught BEFORE shipping

- **0-RTT replay** — formal analyses pushed WG to make 0-RTT opt-in,
  document as replayable, restrict to idempotent operations.
- **PSK / resumption key separation** — ProVerif and Tamarin both
  flagged subtle binding issues; PSK binders mechanism in RFC 8446 is
  the response.
- **Downgrade protection** — the downgrade-sentinel bytes in
  `server_random` are a direct consequence of cross-protocol-collision
  analyses (SLOTH, Bhargavan-Leurent 2016).
- **Cross-mode issues** between full handshake and resumption.

### Lessons

1. Engage formal-methods researchers during design, not as post-shipping
   audit. The TLS 1.3 WG actively invited and integrated feedback;
   TLS 1.0/1.1/1.2 were analyzed only post-hoc and accumulated a decade
   of attacks.
2. Multi-tool redundancy is the gold standard — four tools across
   symbolic, computational, and implementation levels.
3. Verified reference implementations close the spec-vs-code gap.
4. Marginal cost of formal verification amortizes over deployment
   lifetime — TLS handles trillions of dollars of commerce annually;
   the researcher-years spent on TLS 1.3 verification is among the
   highest-ROI investments in internet-security history.

See `cryptography_expertise.md` for the underlying primitives and
`http_web_security.md` for the application-layer surface TLS 1.3 protects.

---

## 11. Other Real Deployments

### Signal Protocol (X3DH, Double Ratchet)

Cohn-Gordon, Cremers, Dowling, Garratt, Stebila, *A Formal Security
Analysis of the Signal Messaging Protocol* (EuroS&P 2017,
https://eprint.iacr.org/2016/1013.pdf; *J. Cryptology* 2020) — first
comprehensive computational analysis of X3DH + Double Ratchet, treating
ratchet state as a "tree" of forking sessions. Concurrent ProVerif
work: Kobeissi-Bhargavan-Blanchet ProScript (EuroS&P 2017). Post-
quantum extension: VECoS 2023 Tamarin analysis informed Signal's PQXDH
and Triple Ratchet migrations.

### Noise Framework

Trevor Perrin's Noise (https://noiseprotocol.org/noise.html) — 53 named
handshake patterns. Kobeissi-Nicolas-Bhargavan *Noise Explorer* (eprint
2018/766) auto-generated ProVerif and Verifpal models for all patterns.
WireGuard, Lightning, WhatsApp IM all use Noise.

### WireGuard

Donenfeld-Milner 2018 Tamarin proof; Lipp-Blanchet-Bhargavan EuroS&P
2019 CryptoVerif computational proof; Hötzendorfer et al. NDSS 2024
*Unified Symbolic Analysis* re-confirmed security under updated threat
model.

### 5G AKA

Basin, Dreier, Hirschi, Radomirović, Sasse, Stettler, *A Formal Analysis
of 5G Authentication* (CCS 2018, arXiv:1806.10360). Tamarin model of
3GPP 5G AKA. Identified **missing security goals** in the spec text and
goal violations contingent on undocumented assumptions — the canonical
example of formal verification surfacing *specification ambiguities*
rather than design flaws.

### EMV chip-and-PIN

Basin, Sasse, Schaller, Toro-Pozo, *The EMV Standard: Break, Fix, Verify*
(S&P 2021, arXiv:2006.08249, https://emvrace.github.io/). Tamarin model
of the entire EMV family. Found practical PIN-bypass on Visa Credit/
Debit/Electron/V Pay, Mastercard Credit, Maestro; built working Android
relay-attack PoC. Mastercard rolled out brand-mixup defenses;
Visa-side issues partially open. Canonical "formal verification finds
attacks that industry audits missed."

### Helios / Belenios e-voting

Cortier et al. *Machine-Checked Proofs of Privacy for Electronic Voting
Protocols* (S&P 2017) — EasyCrypt machine-checked privacy proofs for the
Helios family. Belenios extension at CSF 2018.

### OAuth 2.0 / OpenID Connect / FAPI

Fett, Küsters, Schmitz, *A Comprehensive Formal Security Analysis of
OAuth 2.0* (CCS 2016, arXiv:1601.01229) used the Web Infrastructure
Model (applied-pi tailored to HTTP semantics). Found multiple attacks
against RFC 6749. The OpenID Connect (CSF 2017) and FAPI (2018) follow-
ups applied the same methodology. RFC 9700 (OAuth 2.0 Security BCP) is
in significant part the operationalization of these findings. Extended
treatment in `saml_federation_expertise.md` §5.

### WebAuthn / FIDO2, Bluetooth, Estonian i-voting

Hu et al. *Towards a Formal Foundation of Web Authentication* (POPL
2024) informed WebAuthn Level 3 governance. Cremers et al. Tamarin
analysis of Bluetooth LE Secure Connections (eprint 2023) found
protocol-level issues post-KNOB (USENIX Security 2019). Estonian
i-voting (Springall et al., 2014-2020) showed voting privacy holds
under stated assumptions but operational-security assumptions are more
fragile than the protocol spec suggests.

### Real-world pattern

The pipeline that now works: formal model → analysis (often Tamarin +
ProVerif) → attacks or spec ambiguities → responsible disclosure →
standard/implementation updates → final published model as canonical
security reference. Works less well for proprietary protocols where
models cannot be published.

---

## 12. What Formal Verification Doesn't Catch

The most important slide in any formal-verification briefing. The risk
is **proving the wrong thing and treating it as a guarantee**.

### Implementation bugs

A protocol proof is silent about implementation. Heartbleed (CVE-
2014-0160) was a buffer-overread in OpenSSL's heartbeat implementation;
no protocol-level verification would catch it. Verified implementations
(miTLS, HACL\*, EverCrypt) close this gap at 1-2 orders of magnitude
higher cost than protocol verification alone. Most deployed protocols
use unverified implementations.

### Side-channel attacks

Cache-timing, branch-prediction, power, EM emanations, acoustic.
Bleichenbacher (1998), Klima-Pokorny-Rosa (2003), Lucky 13 (2013),
Spectre (2018) — all are side-channel attacks invisible to protocol-
level analysis because the protocol model has no notion of timing or
microarchitectural state. See `hardware_side_channels_expertise.md`.

### Cross-protocol attacks

The protocol model assumes isolation. Real deployments compose: TLS
over TCP under HTTP, OAuth over TLS over HTTP. SLOTH (Bhargavan-Leurent
2016) exploited MD5/SHA-1 collisions across TLS+IKE+SSH simultaneously.
DROWN used SSLv2 oracles against TLS channels. Cross-protocol modeling
is possible but rarely done.

### Misuse by application layers

JWT (RFC 7519) is the canonical example — signature scheme is fine, but
the application-level "trust the `alg` header" pattern is
catastrophically wrong. Defense is interface design: protocol APIs
should make insecure usage impossible to express. See
`appsec_program_building_expertise.md` §6.

### Reading the model carefully

Every formal-verification claim is parameterized. Common gotchas:

- **"Assumes secure long-term keys."** Does not protect against key
  compromise unless the model includes reveal-key capabilities.
- **"Assumes the random oracle model."** ROM proofs are evidence, not
  guarantees — see Koblitz/Menezes "Another Look" critique in
  `cryptography_expertise.md`.
- **"Assumes honest server."** Many analyses are silent about insider
  threats.
- **"Assumes one party per identity."** Multi-device deployments need
  explicit modeling.
- **"Bounded number of sessions."** Older analyses prove only k-bounded
  security; modern unbounded-session proofs are preferred.

### Quantum-adversary capabilities

Most current tools are classical-adversary-only. Squirrel, EasyPQC, and
Tamarin's PQ extensions add quantum modeling; field is in transition.
See `cryptography_expertise.md` for the PQC roadmap.

### Agent-protocol formal verification (emerging)

LLM-agent protocols (MCP, A2A, OAuth-for-agents) involve capability
delegation under uncertainty, prompt-injection-as-adversary-capability,
sub-agent authorization. Existing tools can model these in principle
but abstractions are under-developed. See
`llm_agent_security_expertise.md`, `agentic_web_capabilities_expertise.md`,
and Section 14 below.

---

## 13. Practical Adoption Guidance

### Tool selection by protocol shape

- **Verifpal** for pedagogy, triage, shipping a model alongside a spec.
- **ProVerif** for unbounded-session stateless or lightly-stateful
  protocols with non-trivial equational theories.
- **Tamarin** when state dominates — ratchets, counters, multi-stage
  handshakes, hardware tokens.
- **CryptoVerif** when you need computational reductions with
  concrete-security bounds (regulatory, military, financial).
- **EasyCrypt** when full computational rigor is needed and PhD-trained
  personnel are available.

Multi-tool redundancy for high-stakes work: TLS 1.3 used ProVerif +
Tamarin + CryptoVerif + miTLS-F\* together.

### Co-develop model and spec; budget iterations

Retrofitting a model to a shipped protocol is harder than co-developing.
The TLS 1.3 lesson: invite formal-methods researchers into the working
group from Draft 0. If embedding is impossible: write a parallel formal
model alongside the spec, version-control both, revise the model on each
spec change, integrate verification into CI. Budget 6-12 months for a
non-trivial protocol from clean slate to publishable proof; the first
model is wrong, the second exposes new issues, models stabilize by
iteration 4-6.

### Publish the model alongside the spec

IETF protocol specs increasingly link to formal-verification artifacts
(TLS 1.3, OAuth BCP, QUIC). 3GPP, EMVCo, FIDO Alliance are slow adopters
as of 2026. Signal publishes formal models alongside spec releases.
Publishing enables external review, downstream re-use, and trust
calibration.

### When NOT to invest in formal verification

- Protocols with frequent breaking changes (modeling overhead dominates).
- Protocols where the crypto is the only interesting bit (use EasyCrypt
  for primitives; skip protocol-level analysis if no real protocol layer
  exists).
- Threat models fundamentally different from Dolev-Yao (physical-layer,
  supply-chain).
- Implementation gap so large that protocol-level verification is
  irrelevant (catastrophically buggy code under a verified spec).

See `appsec_program_building_expertise.md` §6 for the broader investment-
decision framework.

### Personnel and CI integration

Pool of Tamarin modelers is in the low thousands globally; EasyCrypt
proof authors in the low hundreds. For new efforts: hire one PhD-trained
formal-methods person to mentor engineers along Verifpal → ProVerif →
Tamarin; engage consultancies (Cryspen, Symbolic Software, Trail of Bits)
for major work; send engineers to Tamarin Summer School (CISPA/ETH) or
CryptoVerif training (Inria).

Modern verification workflows resemble normal CI: `.spthy` (Tamarin) or
`.pv` (ProVerif) files version-controlled alongside spec; build target
runs the tool on commit; CI fails on proof regression; tagged releases
include the formal-verification artifact. Treat the protocol *spec* as a
software artifact under the same engineering discipline as source code.

---

## 14. Variant Analysis — Under-Explored Frontiers

### LLM / agent protocol formal verification

MCP, A2A, OAuth-for-Agents, and capability-delegation schemes have novel
threat surfaces: prompt-injection-as-adversary-capability (the "network"
includes any text the agent reads), capability propagation under
uncertainty (sub-agents inherit partial capabilities; confused-deputy
generalizes naturally), authorization-to-act vs authorization-to-know
(classical OAuth bundles these; agent protocols need to split), and
multi-round adversarial planning (adversary as planner, not fixed-message
sender). Existing tools can model these in principle but no canonical
published analysis exists as of mid-2026. The right symbolic
representation of "the LLM believes the input is from a trusted source"
is the open abstraction question. Cross-link
`llm_agent_security_expertise.md` and `agentic_web_capabilities_expertise.md`.

### Post-quantum protocol formal verification

Symbolic-model PQ verification substitutes quantum-resistant primitives
(ML-KEM, ML-DSA) in the symbolic algebra and re-runs analysis — catches
structural issues, misses quantum-specific subtleties. Computational-model
PQ verification (EasyPQC, Squirrel-PQ) explicitly models quantum adversary
with QROM access. Bhargavan group's CryptoVerif PQ-TLS hybrid work (CSF
2024) is canonical. Operational pattern: Tamarin first for symbolic
composition; CryptoVerif/EasyCrypt for hybrid IND-CCA/EUF-CMA under
classical + PQ hardness. See `cryptography_expertise.md` for PQC primitives.

### MPC, threshold signatures, and ZK

MPC and threshold-signature schemes (FROST, ROAST, BLS-threshold) use
EasyCrypt as the canonical tool. ZK proof systems (Groth16, PLONK, STARK,
Halo2) are verified at the *scheme* level in Coq/Lean; their use *in*
protocols re-enters ProVerif/Tamarin as black-box symbolic operators —
the composition is the hazard zone. The incoming NIST PQC threshold
signature process will drive demand here.

### Smart contracts — wrong tools

Tamarin and ProVerif are the **wrong tools** for smart-contract
verification. Use Halmos (symbolic execution over EVM), Certora Prover
(specification-driven), K-EVM (formal semantics in K framework), or
hevm/Echidna/Foundry invariant testing. See
`smart_contract_evm_security_expertise.md`. The reason: EVM is a
state-machine with predictable semantics, not a network-protocol
abstraction. The intersection — protocols that include smart contracts
as components (cross-chain bridges, account abstraction, on-chain
attestation) — needs both layers.

### AI-assisted formal verification

LLMs can synthesize Tamarin lemmas, suggest Coq tactics, and generate
first-draft EasyCrypt proof skeletons (research-stage, 2025+). The risk:
LLM-synthesized proofs that type-check but reflect incorrect mathematical
intuitions. Defense: the proof still passes through the tool's kernel; a
kernel-rejected proof is no proof, a kernel-accepted one is as valid as
human-generated. Expected: by 2027-2028, LLM-assisted verification is
routine for the easy 80% of obligations; expertise concentrates on the
hard 20%.

### Privacy properties and hardware co-verification

Observational equivalence (Tamarin diff-equivalence, ProVerif `~`) is the
workhorse for anonymity, unlinkability, receipt-freeness — used for
Helios/Belenios voting, BBS+/Idemix credentials, Tor analyses. Hardware-
software co-verification (proving protocols under specific hardware
adversary models — Rowhammer, Spectre, voltage glitching against secure
boot) is its own field. See `hardware_side_channels_expertise.md`,
`firmware_embedded_security.md`, `privacy_engineering_expertise.md`.

---

## 15. References

### Foundational papers

- Burrows, Abadi, Needham, *A Logic of Authentication*, DEC SRC RR-39
  (1989); *ACM TOCS* 8(1) (1990).
  https://www.cs.cmu.edu/~dga/15-712/F07/papers/Burrows90.pdf
- Dolev, Yao, *On the Security of Public Key Protocols*, IEEE Trans.
  Info. Theory 29:2 (1983).
- Needham, Schroeder, *Using Encryption for Authentication in Large
  Networks of Computers*, CACM 21:12 (1978).
- Lowe, *An Attack on the Needham-Schroeder Public-Key Authentication
  Protocol*, Inf. Proc. Letters 56:3 (1995);
  https://link.springer.com/chapter/10.1007/3-540-61042-1_43 (TACAS
  1996 long version).
- Abadi, Fournet, *Mobile Values, New Names, and Secure Communication*,
  POPL 2001 (applied pi-calculus).
- Abadi, Rogaway, *Reconciling Two Views of Cryptography: The
  Computational Soundness of Formal Encryption*, J. Cryptology 15:2
  (2002).
- Bellare, Rogaway, *Code-Based Game-Playing Proofs and the Security of
  Triple Encryption*, EUROCRYPT 2006.

### Tool documentation and manuals

- ProVerif: https://bblanche.gitlabpages.inria.fr/proverif/ (manual,
  examples, publications).
- CryptoVerif: https://bblanche.gitlabpages.inria.fr/CryptoVerif/.
- Tamarin Prover: https://tamarin-prover.com/ (manual);
  https://tamarin-prover.github.io/ (project home).
- EasyCrypt: https://www.easycrypt.info/.
- Verifpal: https://verifpal.com/.
- Maude-NPA: https://maude.cs.illinois.edu/ (Maude); NRL Protocol
  Analyzer history on Catherine Meadows' page
  http://www.asecolab.org/people/catherine-meadows/.
- Squirrel Prover: https://squirrel-prover.github.io/.
- F\* and Project Everest: https://www.fstar-lang.org/,
  https://project-everest.github.io/.
- AVISPA / AVANTSSAR: http://www.avispa-project.org/.
- HACSpec: https://github.com/hacspec/hacspec.
- Isabelle/HOL: https://isabelle.in.tum.de/.

### Tamarin reference book

- Basin, Cremers, Dreier, Sasse, *Modeling and Analyzing Security
  Protocols with Tamarin: A Comprehensive Guide* (Springer, 2025;
  ISBN 9783031909351).

### Specific protocol verification papers

- Bhargavan, Blanchet, Kobeissi, *Verified Models and Reference
  Implementations for the TLS 1.3 Standard Candidate*, IEEE S&P 2017,
  https://bblanche.gitlabpages.inria.fr/publications/BhargavanBlanchetKobeissiSP2017.pdf.
- Cremers, Horvat, Hoyland, Jacomme, van der Merwe, *A Comprehensive
  Symbolic Analysis of TLS 1.3*, CCS 2017.
- Bhargavan et al., *Implementing and Proving the TLS 1.3 Record
  Layer*, IEEE S&P 2017,
  https://inria.hal.science/hal-01674096/file/record.pdf.
- Basin, Dreier, Hirschi, Radomirović, Sasse, Stettler, *A Formal
  Analysis of 5G Authentication*, CCS 2018, arXiv:1806.10360;
  https://people.inf.ethz.ch/rsasse/pub/5G-CCS18.pdf.
- Basin, Sasse, Schaller, Toro-Pozo, *The EMV Standard: Break, Fix,
  Verify*, IEEE S&P 2021, arXiv:2006.08249;
  https://emvrace.github.io/.
- Donenfeld, Milner, *Formal Verification of the WireGuard Protocol*
  (2018), https://www.wireguard.com/papers/wireguard-formal-verification.pdf.
- Lipp, Blanchet, Bhargavan, *A Mechanised Cryptographic Proof of the
  WireGuard Virtual Private Network Protocol*, EuroS&P 2019,
  https://bblanche.gitlabpages.inria.fr/publications/LippBlanchetBhargavanEuroSP19.pdf.
- Cohn-Gordon, Cremers, Dowling, Garratt, Stebila, *A Formal Security
  Analysis of the Signal Messaging Protocol*, EuroS&P 2017 (and
  *Journal of Cryptology* 2020); https://eprint.iacr.org/2016/1013.pdf.
- Kobeissi, Bhargavan, Blanchet, *Automated Verification for Secure
  Messaging Protocols and their Implementations*, EuroS&P 2017.
- Hötzendorfer et al., *A Unified Symbolic Analysis of WireGuard*, NDSS
  2024,
  https://www.ndss-symposium.org/wp-content/uploads/2024-364-paper.pdf.
- Kobeissi, Nicolas, Bhargavan, *Noise Explorer: Fully Automated
  Modeling and Verification for Arbitrary Noise Protocols*, eprint
  2018/766, https://eprint.iacr.org/2018/766.pdf.
- Fett, Küsters, Schmitz, *A Comprehensive Formal Security Analysis of
  OAuth 2.0*, CCS 2016, arXiv:1601.01229.
- Fett, Küsters, Schmitz, *The Web SSO Standard OpenID Connect: In-Depth
  Formal Security Analysis and Security Guidelines*, CSF 2017.
- Cortier, Dragan, Dupressoir, Schmidt, Strub, Warinschi,
  *Machine-Checked Proofs of Privacy for Electronic Voting Protocols*,
  IEEE S&P 2017.
- Paulson, *The Inductive Approach to Verifying Cryptographic
  Protocols*, J. Computer Security 6:1-2 (1998),
  https://www.cl.cam.ac.uk/~lp15/papers/Auth/jcs.pdf.

### Squirrel and emerging tools

- Baelde, Delaune, Jacomme, Koutsos, Moreau, *An Interactive Prover for
  Protocol Verification in the Computational Model*, IEEE S&P 2021,
  https://inria.hal.science/hal-03172119/.
- Bana, Comon-Lundh, *Towards Unconditional Soundness: Computationally
  Complete Symbolic Attacker*, POST 2012.

### Standards traceable to formal-verification

- RFC 8446 (TLS 1.3, 2018); RFC 9700 (OAuth 2.0 Security BCP); Noise
  Protocol Framework spec (https://noiseprotocol.org/noise.html).
- 3GPP TS 33.501 (5G AKA, post-Basin/Dreier/Hirschi/Sasse/Stettler).
- EMV Specifications post-Basin/Sasse/Schaller/Toro-Pozo (Mastercard
  brand-mixup defenses).
- FIDO Alliance WebAuthn Level 3 (increasing formal-analysis references).

### Cross-references within this corpus

- `cryptography_expertise.md` — primitives underlying protocols;
  Boneh/Wong/Schneier perspectives.
- `saml_federation_expertise.md` §5 — Fett-Küsters-Schmitz on
  OAuth/OIDC/SAML in depth.
- `steelman_doctrine_expertise.md` — adversarial verification mindset
  applied to non-cryptographic claims.
- `hardware_side_channels_expertise.md` — what protocol verification
  misses at the implementation/microarchitecture boundary.
- `smart_contract_evm_security_expertise.md` — different verification
  stack for a different domain (Halmos, Certora, K-EVM).
- `llm_agent_security_expertise.md` — agent protocol threat surfaces
  awaiting formal treatment.
- `agentic_web_capabilities_expertise.md` — capability-delegation
  protocols (MCP, A2A, OAuth-for-Agents).
- `appsec_program_building_expertise.md` §6 — investment-decision
  framework for when to deploy formal methods.
- `privacy_engineering_expertise.md` — privacy-property verification
  context (observational equivalence, anonymity).
- `firmware_embedded_security.md` — hardware/firmware adversary
  boundary.

---

End of document.
