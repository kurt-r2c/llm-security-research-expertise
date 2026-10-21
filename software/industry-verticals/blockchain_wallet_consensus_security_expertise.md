# Blockchain Wallet, Consensus, and Custody Security

> **Framework:** This document synthesizes practitioner perspectives on the
> *non-contract* slice of blockchain security: wallet design and threat
> surfaces, hardware wallet attacks, multi-party computation custody,
> consensus-layer attacks, validator and staking failure modes, cross-chain
> bridge custody, exchange operational security, and on-chain forensics. It is
> the sibling to the smart-contract / Solidity treatment and assumes the
> reader is grounded in EVM-level reasoning.
>
> **Researchers in scope:**
> - **Vitalik Buterin** (Ethereum Foundation co-founder) — canonical posts on
>   weak subjectivity, nothing-at-stake, economic-finality. Source:
>   blog.ethereum.org; vitalik.eth.limo.
> - **Andrew Miller** (UIUC, Decentralized Systems Lab director; IC3
>   associate director) — "Honey Badger of BFT," "Stubborn Mining," provable security
>   for cryptocurrencies. Source: soc1024.ece.illinois.edu.
> - **Emin Gün Sirer** (Cornell, Ava Labs CEO; former IC3 co-director) — with
>   Ittay Eyal, "Majority is Not Enough" selfish-mining paper. Source:
>   arxiv.org/abs/1311.0243; avalabs.org.
> - **Ittay Eyal** (Technion) — selfish-mining co-author. Source:
>   ittayeyal.github.io.
> - **Phil Daian** (Flashbots; formerly Cornell IC3) — lead author "Flash Boys
>   2.0" naming MEV. Source: arxiv.org/abs/1904.05234; pdaian.com.
> - **Ari Juels** (Cornell Tech IC3 director) — senior author Flash Boys 2.0.
>   Source: tech.cornell.edu.
> - **Ethan Heilman** (Boston University; co-founder/CTO Arwen / BastionZero) — first author
>   Bitcoin eclipse-attack paper (USENIX 2015). Source: ethanheilman.com;
>   eprint.iacr.org/2015/263.
> - **Sharon Goldberg** (Boston University; co-founder Arwen / Commonwealth
>   Crypto) — eclipse co-author; BGP-meets-Bitcoin research. Source:
>   cs.bu.edu/~goldbe.
> - **Yehuda Lindell** (Bar-Ilan; co-founder Unbound Security → Coinbase 2022;
>   Coinbase Head of Cryptography) — Lindell17/18 threshold ECDSA underpins
>   commercial MPC custody. Source: yehudalindell.com; eprint.iacr.org/2018/987.
> - **Tim Ruffing / Jonas Nick** (Blockstream) — MuSig2 + Schnorr-threshold
>   line shipped in libsecp256k1 / Bitcoin Core. Source:
>   blog.blockstream.com; eprint.iacr.org/2020/1261.
> - **Chelsea Komlo** (Waterloo / Zcash) and **Ian Goldberg** (Waterloo) —
>   FROST authors; FROST published as RFC 9591 (2024). Source: eprint.iacr.org/2020/852.
> - **Trail of Bits Blockchain Cryptography team** — Dan Guido, Stefan
>   Edwards, Josselin Feist plus reviewers; audits of Binance tss-lib, ZenGo
>   X curv, Keep Network keep-ecdsa, THORchain tss-lib, DFINITY threshold-
>   ECDSA. Source: blog.trailofbits.com; github.com/trailofbits/publications.
> - **Verichains** (Vietnam applied-crypto audit) — disclosed TSSHOCK key-
>   extraction on GG18 / GG20 / CGGMP21 (2023). Source: verichains.io/tsshock.
> - **samczsun / Sam Sun** (Paradigm, SEAL 911) — "Escaping the Dark Forest"
>   canonical whitehat-recovery essay; SEAL 911 is the ecosystem IR
>   coordination layer. Source: samczsun.com; securityalliance.org.
> - **Mudit Gupta** (Polygon Labs CISO) —
>   DeFi-exploit and exchange-opsec blogger. Source: mudit.blog.
> - **ZachXBT** (pseudonymous) — most prolific community on-chain
>   investigator; transaction-graph + OSINT.
> - **Chainalysis**, **Elliptic**, **TRM Labs**, **Mandiant**, **Crystal
>   Blockchain** — commercial forensics / threat-intel firms whose incident
>   reports define industry working knowledge of DPRK and other crypto-
>   adversary activity.
> - **bunnie Huang** (Precursor / Betrusted) — auditable secure-hardware work. Source: bunniestudios.com.
>
> **Audit firms cited beyond Trail of Bits:** OpenZeppelin, Halborn, Kudelski
> Security, NCC Group, SlowMist, CertiK, Quantstamp, Spearbit / Cantina.
>
> **Cross-links to ~/ai/expertise/software/:**
> [[smart_contract_evm_security_expertise.md]] (parent — Solidity / EVM / DeFi
> / contract bridges), [[cryptography_expertise.md]] (signature primitives),
> [[privacy_engineering_expertise.md]] (MPC at the cryptographic-protocol
> layer; mixers), [[confidential_computing_expertise.md]] (TEE-based custody),
> [[post_quantum_cryptography_expertise.md]] (signature migration against
> Shor's), [[hardware_side_channels_expertise.md]] (cold-wallet MCU attacks),
> [[browser_js_engine_exploitation_expertise.md]] (browser-extension wallet
> surface), [[detection_engineering_expertise.md]] (on-chain telemetry),
> [[threat_intel_methodology_expertise.md]] (transaction-graph pivots; DPRK
> tracking), [[dfir_methodology_expertise.md]] (cryptocurrency-incident IR),
> [[llm_agent_security_expertise.md]] (autonomous agents holding keys),
> [[agentic_web_capabilities_expertise.md]] (browser-driving agents signing
> permits), [[cicd_supply_chain_expertise.md]] (npm attacks — Ledger Connect
> Kit), [[supply_chain_provenance_expertise.md]] (hardware-wallet
> manufacturing), [[cloud_iam_expertise.md]] (Bybit-style session-token
> hardening).

---

## 1. The crypto-asset threat model

### "Code is law" and its limits

The maximalist framing — *what executes on-chain is the truth* — holds at
the EVM execution layer and breaks at the social layer. The DAO fork
(June 2016), Steem / Hive split (March 2020), and small-chain rollbacks demonstrate
"code is law" yields to "consensus is people" once asset value is high
enough. Working model: **every cryptocurrency system has a layer where
the social cost of not intervening exceeds the cost of intervening; that
layer's coordination ceiling determines the effective trust anchor.**
For wallet / custody: once funds reach a sanctioned mixer or
uncooperative counter-party, recovery falls toward zero. Historical
recovery rates for major hacks rarely exceed 10-15% absent friendly
counter-exploit.

### Your private key IS your wealth

No fraud-reversal primitive exists. A signed-and-included withdrawal is
settled. The bearer instrument is a 256-bit scalar; anyone with the
secp256k1 or Ed25519 secret controls the underlying funds. Defense
surface is *everything that touches the scalar*: entropy source, BIP-39
mnemonic, storage device, displayed-address screen, signing chip,
clipboard, requesting dApp, mediating extension, host OS, host firmware,
supply chain.

### The three-class custody spectrum + MPC

Traditional axis: **hot** (online, automated, low friction, high
surface) → **warm** (online, manual confirmation, hardware-backed) →
**cold** (air-gapped). Production exchanges: ~1-3% hot, 5-15% warm, 80%+
cold. **MPC custody breaks the binary** — the secret scalar is never
reconstructed; signing happens through a multi-round protocol among
shareholders. Third axis in §5: shares live anywhere from online HSMs to
mobile devices to operator TEEs.

### Scope boundaries

Solidity / EVM / DeFi contract-level threats:
[[smart_contract_evm_security_expertise.md]]. Signature primitives:
[[cryptography_expertise.md]]. MPC at the cryptographic-protocol layer:
[[privacy_engineering_expertise.md]] §6. PQ migration:
[[post_quantum_cryptography_expertise.md]].

---

## 2. Wallet types and threat surfaces

### Hot wallets: browser extensions and mobile apps

Dominant form: browser extensions — MetaMask, Phantom (Solana), Trust
Wallet, Rabby, Coinbase Wallet, OKX Wallet. Threat surface = browser
security model + dApp interaction model, wallet as signing oracle between.

Three recurring attack classes:

1. **Cross-extension / contentScript boundary.** The wallet injects
   `window.ethereum` / `window.solana` into every page's MAIN world via a
   contentScript. A malicious extension alongside can intercept calls
   before they reach the wallet's background service worker. Cross-link
   [[browser_js_engine_exploitation_expertise.md]] on isolated-worlds.
   Defense (extension-sandbox separation) is defeated by extension
   *installation* compromise.
2. **dApp frontend hijack via dependency compromise.** dApp loads JS from
   a CDN; wallet trusts whatever transaction object the dApp constructs;
   user signs whatever the wallet renders. A dependency injecting a
   transaction-modifying payload wins. Ledger Connect Kit (§3) is the
   archetype.
3. **Phishing of the signing UX itself.** Wallet renders a transaction;
   user clicks Confirm. Technically-correct but operationally-malicious
   transactions (`approve` for an unfamiliar token, a permit signature
   with no spending limit) drain funds. "Blind signing" — dominant retail
   attack vector.

MetaMask Snaps (v11+) extend the wallet with third-party plugins — same
trust-the-third-party-author pattern one level lower.

### Cold wallets: hardware devices

Cold wallets move signing to a dedicated device with its own MCU, screen,
buttons, storage. Canonical: Ledger (Nano S Plus, Nano X, Stax, Flex —
STM32 / ST33), Trezor (Model One/T, Safe 3/5 — OPTIGA Trust M secure element),
Keystone (air-gapped QR), BitBox (ATECC608B + Cortex-M4), Coldcard (Mk4).

Threat surface:

1. **Physical attacks** — voltage / clock glitching, EM probing,
   secure-element decapsulation. Cross-link
   [[hardware_side_channels_expertise.md]] §10-11. A lab adversary with a
   stolen older-model device can extract a seed; the question is whether
   a $50k-$500k attack budget is worth the held assets.
2. **Supply-chain device interception** — adversary intercepts in
   transit, replaces with a pre-loaded variant knowing a specific seed,
   reseals. Defense: manufacturer-direct purchase, verify the device
   generates a *fresh* seed on first boot. Pre-printed recovery cards are
   suspect.
3. **Seed-phrase extraction at the human layer** — paper backups
   photographed, mnemonics typed into phishing sites impersonating
   manufacturer support. The 2020 Ledger customer-data breach (~1M
   emails, ~272k physical addresses) seeded years of targeted physical-mail
   and "send-the-victim-a-fake-Ledger" mailings.
4. **Blind-signing on a small screen** — a 1.5-inch OLED cannot render a
   meaningful complex-DeFi summary; user sees "Sign message" and clicks
   confirm on an opaque hash. EIP-712 typed-data helps where firmware
   supports per-contract integrations.

### MPC wallets

Institutional form: **Fireblocks**, **Coinbase Custody / WaaS** (formerly
Unbound Security), **BitGo**, **Copper**, **Cobo**, **Zengo** (consumer
MPC), **GK8** (Galaxy Digital), **Curv** (acquired by PayPal 2021), exchange
WaaS offerings. Architecture: §5.

Key observation: MPC wallets replace "trust the device" with "trust the
protocol and the operator." Protocol adversaries exploit threshold-
signature implementation bugs (TSSHOCK class, §5); operator adversaries
exfil shares through cloud-account compromise or insider action. Bybit
February 2025 (§9) is the canonical demonstration that MPC + cold storage
is not a magic bullet — the attack moved up one abstraction layer and
compromised the *signing UX* presented to the operator.

### Smart-contract wallets and account abstraction

Fourth class: deployed contracts that hold funds and execute owner-defined
logic. Canonical: **Safe** (formerly Gnosis Safe), **Argent**, **Coinbase
Smart Wallet**, **Squads** (Solana), **Soul Wallet**, **Sequence**.

Threat surface adds:

1. **Contract-level vulnerabilities in the wallet itself.** Safe is among
   the most-audited EVM contracts; smaller wallets have shipped
   exploitable bugs. Cross-link
   [[smart_contract_evm_security_expertise.md]] §2-5.
2. **Module / guard / plugin extensibility.** Safe modules execute
   without owner signatures (recurring payments, automated rebalancing).
   A malicious module is functionally an authorized attacker. Module
   installation requires owner-signed transaction; signature-blindness on
   complex install data is the blind-signing problem repackaged.

ERC-4337 (Account Abstraction Using Alt Mempool, 2023) adds a **bundler**
(aggregates UserOperations, submits to EntryPoint) and a **paymaster**
(sponsors gas). Both add surface: bundlers can censor; paymaster contracts
have produced their own bug class (gas-sponsorship griefing where
paymaster pays gas for reverting UserOps). Paymasters must be staked and
must collect full payment during validation, not after execution.

### Custodial exchanges

Holding on Coinbase / Binance / Kraken / Bybit / OKX = choosing *the
exchange's operational security* as your custody model. Threat surface =
hot-wallet security + cold-storage operational procedure + employee
insider-risk + external-facing security (account takeover, SIM-swap,
password-reset integrity) + regulatory posture (asset freezes; FTX-style
custody-via-fraud collapse). §9 walks the historical catalog.

---

## 3. Phishing and signature-trust attacks

### The blind-signing problem

Every signing event has a human reading a transaction representation and
authorizing. Fidelity ranges from high (fully-decoded EIP-712 on a large
screen) to low (a 32-byte hash on a hardware-wallet OLED). Lower
fidelity = larger attacker substitution room. Architectural defense:
lift rendering to a trustworthy layer; have the signing device verify
the rendered transaction matches the signed one. Blockaid + MetaMask
and Ledger EIP-712 are partial implementations. Fundamental limit: the
signing device must *parse* to render; parsing requires per-contract
knowledge no device can ship universally.

### EIP-712 typed structured data

EIP-712 (Bloemen, Logvinov, Evans, 2017) standardizes structured-data
hashing. User signs a typed structure whose schema is part of the
payload. Wallets recognizing domain + types render ("Permit: USDC ->
0xRouter, amount=100") human-readably; opaque otherwise.

### Permit phishing

ERC-2612 Permit / Uniswap Permit2 allow off-chain signatures authorizing
spender + token + amount + deadline. Attacker collects the permit,
submits later, drains. Rendered "amount=100, spender=0xAttacker" can be
`uint256.max` with the spender address-mined to match legitimate
prefix/suffix (users compare 4 chars at each end). Defense: wallet
permit warnings, simulation of post-execution state, spender reputation
scoring.

### Set-Approval-for-All abuse

ERC-721 / ERC-1155 `setApprovalForAll(operator, true)` grants permission
to move ALL collection tokens — necessary for marketplace listings
(OpenSea, Blur, Magic Eden, Tensor), but a malicious marketplace clone
tricks the user into granting approval to an attacker contract that
drains the collection. CryptoPunks / BAYC / OpenSea phishing lineage
ran this at scale 2021-2023. Defenses: warning on
`setApprovalForAll` to low-reputation addresses, simulation, revoke.cash,
Etherscan approval viewer, periodic audits.

### Wallet-Drainer-as-a-Service

Attack tooling commoditized: **Inferno**, **Pink**, **Monkey**, **Angel**,
**MS Drainer** multi-tenant kits. Affiliate gets phishing-site templates
+ hosted drain-logic backend with profit-share (20-30% operator, 70-80%
affiliate). Per Group-IB (citing Scam Sniffer), Inferno Drainer alone drained $80M+ across
2022-2023. Kits provide address-mining, multi-chain support, permit
harvesting, mixer/bridge laundering, affiliate dashboards. Individual
phishing operators need traffic sources (X impersonation, Discord
takeovers, Google Ads, fake-airdrop SEO).

### The 2023 Ledger Connect Kit compromise

December 14, 2023. A former Ledger employee retained npm-org access after
employment; attacker compromised that account via session-token-bypass
phishing of 2FA. Malicious versions 1.1.5, 1.1.6, 1.1.7 of
`@ledgerhq/connect-kit` published. Many DeFi frontends (SushiSwap, Kyber,
Revoke.cash, Zapper, Hey, Galxe) consumed the package; the malicious
version embedded **Angel Drainer**, prompting users on dApp page load to
sign a wallet-draining transaction. Exploit window: ~5 hours from npm
publish to Ledger pushing a clean version; ~$600k drained across hundreds
of victims. Postmortems: Sonatype, SlowMist, Blockaid, Checkmarx, Socket.

Lessons: (a) **npm is a soft underbelly for the wallet ecosystem** —
cross-link [[cicd_supply_chain_expertise.md]]; SDKs shipping via npm into
dozens of customer frontends multiply blast radius. (b) **dApp frontends
do not pin versions strictly** — caret ranges (`^1.1.0`) pulled the
malicious patch automatically; per-build SHA pinning is the defense. (c)
**Session-token bypass of 2FA on npm is widely-exploited** — 2FA without
strict session scoping is roughly equivalent to single-factor auth for an
attacker willing to phish session cookies.

### Pre-sign simulation as structural defense

Blockaid, Pocket Universe, Stelo Labs, Wallet
Guard each implement a pre-sign simulator: fork chain state at the latest
block, execute the transaction in a sandbox, report resulting state
changes. User sees "this transaction will move 10 ETH from you to
0xAttacker" rather than the raw calldata hash.

Defense limits: (a) **Simulation bypasses** — attacker contracts branch on
`block.number`, `block.timestamp`, sender, oracle state; simulator's fork
won't match deployment-time mempool state. Blockaid's December 2024
writeup catalogs bypass techniques. (b) **Coverage gaps** — simulators
only see state changes within the transaction; off-chain permit signatures
don't move state at signing time, future-execution authorization is missed
unless simulator understands permit semantics. (c) **User fatigue** — a
simulator warning on every transaction trains users to click through.
Defense-in-depth: simulation + reputation scoring + permit-pattern
detection + visual warnings (red high-risk, yellow unfamiliar, green
known-good).

---

## 4. Hardware wallet attacks

### Side-channel attacks on secure elements

Three storage architectures: (1) plain MCU with seed in flash (older
Trezor, KeepKey); (2) certified secure element holding the seed with the
MCU as transport (Ledger Nano with ST33; BitBox02 with ATECC608A); (3)
air-gapped sealed device with QR I/O (Keystone, Coldcard, AirGap Vault).

Side-channel categories:

- **Power analysis (SPA / DPA)** correlates current draw during signing
  with secret-scalar bits. RFC 6979 deterministic-k is more resistant
  than naive randomized k; secp256k1 scalar multiplication is still
  subject to DPA on weak implementations.
- **EM emanation** is the wireless variant — near-field probe captures
  signal during signing. Cross-link
  [[hardware_side_channels_expertise.md]] §11.
- **Voltage / clock glitching** injects faults during specific instruction
  cycles to skip security checks or leak intermediates. Classic
  application: skip PIN-verification branch, read seed memory.
  ChipWhisperer-style hardware ($1k-$10k) is commercial; intermediate
  skill bar.

Defenses: certified secure elements (CC EAL5+) with glitch detectors,
randomized scalar multiplication with point blinding, tamper-detection
mesh on EEPROM, encrypted-at-rest seed with key in secure-element ROM.
Pragmatic: a lab adversary with physical access to a modern device and
several days has non-trivial seed-extraction probability; the question is
the value of held assets.

### Fault injection in production

Trezor One had a voltage-glitching extraction (Kraken Security Labs,
2020) — ~$75 of equipment on a stolen device. Trezor's response: BIP-39
passphrase (the "25th word") so fault-extracting yields a derived wallet
not the passphrase-protected one; and Safe 3/5 ship with a secure element
mitigating the underlying glitch surface. Ledger's Donjon team has
demonstrated faults against specific model generations; vendor response
cadence varies.

### Supply-chain attacks

Device-interception pattern: buy legitimate device → open packaging,
replace with pre-loaded variant knowing a specific seed → reseal → sell
on Amazon Marketplace, eBay, or legitimate-looking reseller. Victim sets
up using the pre-loaded seed (or restores from a recovery card included
in box), funds it; adversary withdraws. Defense: manufacturer-direct or
explicitly-authorized reseller. Structural: properly-configured device
generates a *fresh* seed on first boot — pre-printed recovery cards are
suspect.

### Hidden-screen attacks

The wallet screen is the *trusted display*. If firmware lies to the
screen, the trust anchor collapses. Defense: **firmware attestation** —
device cryptographically attests to manufacturer-signed firmware; host
verifies. Ledger's "genuine check" via Ledger Live and Trezor's
bootloader signature verification are production implementations. Bypass:
counterfeit attestation keys trusted by compromised host software, or
bootloader-bypass exploits.

### Recovery service controversy: Ledger Recover (2023)

May 2023 Ledger announced Ledger Recover: paid service encrypting the
seed, Shamir-sharding across three custodians (Ledger, Coincover,
EscrowTech), recovery via ID-verification. Community reaction was sharply
negative: (a) the product's existence implied firmware *could* exfiltrate
the seed; (b) trust model shifted to subpoena-able corporations; (c)
users feared future firmware enabling the feature without awareness.
Ledger walked back the rollout and committed to open-sourcing the OS.
Lesson: recovery services touching the seed alter the trust model;
community-acceptable recovery must be social (multi-sig, social recovery,
MPC) not custodial.

### Counterfeit hardware wallets

Amazon Marketplace, eBay, AliExpress have listed counterfeit Ledger /
Trezor devices for years, ranging from obvious clones to pixel-perfect
replicas with malicious firmware. Manufacturer-direct + runtime
genuine-check is the layered defense.

---

## 5. MPC and threshold signatures

### The primitive

MPC lets N parties jointly evaluate a function on secret inputs without
learning each other's inputs beyond the output. Applied to signatures: a
**threshold signature scheme (TSS)** where M of N parties produce a valid
signature *without reconstructing the full key*. Output is
indistinguishable from a regular signature; on-chain footprint identical
to a single-key signature.

Structural improvement over multi-sig (M-of-N separate signatures from
distinct EOAs): TSS produces a single signature with identical on-chain
footprint while distributing signing authority off-chain. ECDSA on
secp256k1 (Bitcoin, Ethereum) is intricate because ECDSA wasn't designed
for threshold operation; Schnorr (Bitcoin Taproot, Ed25519 via FROST) is
structurally cleaner. Cross-link [[privacy_engineering_expertise.md]] §6
for MPC at the cryptographic-protocol layer.

### Schnorr-based threshold (MuSig2, FROST)

**MuSig2** (Nick, Ruffing, Seurin, 2020 — eprint.iacr.org/2020/1261):
N-of-N Schnorr multi-signature; all N parties sign, output is a single
Schnorr signature on the aggregated key. Two rounds with the first
preprocessable. libsecp256k1's MuSig2 is canonical. Production: Bitcoin
Taproot multi-sig, Lightning channel funding.

**FROST** (Komlo, Goldberg, 2020 — eprint.iacr.org/2020/852): M-of-N
Schnorr threshold. FROST was published as RFC 9591 (June
2024, IRTF CFRG). **ROAST** (Ruffing et al., 2022 —
eprint.iacr.org/2022/550) adds robust asynchronous signing: even when up
to M-t of M signers are malicious or offline, the protocol terminates
with a valid signature after at most M-t+1 signing sessions.

For Ed25519 / EdDSA, **threshold EdDSA** via FROST adapts cleanly with
domain-separation. ChainSafe, Coinbase, others ship Ed25519-FROST in
production.

### ECDSA-based threshold (GG18, GG20, Lindell17/18, CGGMP21, DKLs23)

ECDSA threshold is intrinsically harder — the signing equation involves
modular inversion that doesn't linearize under secret sharing. Standard
approach: Paillier-encrypted shares with multiplicative-to-additive (MtA)
conversions + zero-knowledge range proofs.

- **GG18** (Gennaro, Goldfeder — eprint.iacr.org/2019/114) and **GG20**
  (eprint.iacr.org/2020/540) defined the canonical family. Production:
  Binance tss-lib, ZenGo X multi-party-ecdsa, Keep Network, THORchain,
  Swingby, many in-house.
- **Lindell17 / 18** (eprint.iacr.org/2017/552, eprint.iacr.org/2018/987)
  defined fast 2-of-2 and N-of-N ECDSA. The 2018 paper shipped in Unbound
  Security's product (acquired Coinbase 2022).
- **CGGMP21** (Canetti, Gennaro, Goldfeder, Makriyannis, Peled —
  eprint.iacr.org/2021/060): production-grade descendant with
  identifiable-abort and proactive-refresh (deviant signers identified;
  shares rotated without changing the public key).
- **DKLs23** (Doerner, Kondi, Lee, Shelat — eprint.iacr.org/2023/765):
  recent frontier with stronger proofs and improved round complexity.
  Trail of Bits has reviewed implementations.

### TSSHOCK: the GG20 key-extraction class

March 2023, Verichains disclosed **TSSHOCK** — novel key-extraction
attacks against threshold-ECDSA GG18, GG20, CGGMP21. Research began
October 2022; first disclosures December 2022; press announcement March
27, 2023; full details at Black Hat USA, August 10, 2023.

Technical core: zero-knowledge range proofs used in the MtA conversion
step of GG18 / GG20 had implementation-specific weaknesses allowing a
malicious signer to learn a victim signer's secret share over a sequence
of signing sessions. *Not* a break of underlying primitives — specific
implementation choices and proof omissions in popular open-source
libraries. Verichains estimated $8B+ of crypto assets at risk. Affected:
Binance tss-lib (most-forked GG20), ZenGo X multi-party-ecdsa (won't fix; unmaintained), multiple in-house
variants. Some affected libraries were still unfixed at public release.

Lessons: (a) **MPC bugs are extremely hard to find** — multiple audits
missed TSSHOCK; ZKP structure is among the most cryptographically
sophisticated patterns in production blockchain code; auditor bench depth
is the binding constraint. (b) **Open-source MPC has a forking-velocity
problem** — patched upstream, vulnerable downstream forks remain;
Verichains coordinated disclosure to specific vendor deployments. (c)
**TSS audits should require formal verification of ZKP completeness** —
standard audit checklists missed it.

### Production deployments

- **Fireblocks**: MPC-CMP (CGGMP21-style internal variant), TEE-backed
  share storage (Intel SGX / AWS Nitro Enclaves), institutional custody
  for hedge funds, exchanges, payment processors. SOC 2 Type II + CCSS
  Level 3. Policy engines cryptographically restrict signable transactions.
- **Coinbase Custody / WaaS**: built on Unbound Security tech. Coinbase
  open-sourced `cb-mpc` March 2025 (ECDSA, Schnorr/EdDSA two-party and
  multi-party with DKG and backups). Stance: institutional MPC should not
  depend on closed-source vendor cryptography.
- **ZenGo** (consumer): 2-of-2 ECDSA between phone and ZenGo cloud,
  biometric on phone side. Recovery via email-encrypted user-share
  backup; ZenGo share always required — solvency event would freeze user
  funds.
- **GK8** (Galaxy Digital, 2022): cold-MPC with offline key generation
  and air-gapped signing for institutional cold storage.

### Operator-vs-cryptographic risk

Core MPC threat-modeling distinction: **cryptographic risk** (protocol
bug like TSSHOCK lets an adversary extract keys without compromising
shares — defense: rigorous design, formal verification, multiple audits)
vs **operator risk** (protocol sound, operator compromised or coerced —
defense: multi-operator architectures requiring M-of-N collusion,
TEE-backed share storage per [[confidential_computing_expertise.md]] §3,
policy-engine constraints).

Bybit (§9) is operator-risk at the smart-contract-wallet layer — M-of-N
multi-sig cryptography was sound, operational signing flow compromised by
social engineering. Lesson recurs in MPC: cryptography buys fewer
guarantees than the operational signing UX.

---

## 6. Consensus-layer attacks

### 51% attacks: history and current relevance

Classical: adversary controls >50% of hash power (PoW) or stake (PoS) and
rewrites chain history to double-spend. Nakamoto's security analysis
assumed honest-majority hash power; below 50% an adversary can't achieve
consistent deep reorgs.

Production 51% attacks have happened, primarily on smaller-cap PoW chains:

- **Ethereum Classic (ETC)**: January 2019 (~$1.1M, $200k double-spent on
  Gate.io). July-August 2020 three incidents; the July 31-August 1 attack
  reorged 3,693 blocks, double-spending ~807k ETC
  (~$5.6M); attacker spent <$200k on rented hash power.
- **Bitcoin SV** (June-August 2021): three attacks in three months; August reorg up to 14 blocks deep.
- **Bitcoin Gold** (May 2018, January 2020): $18M and $70k via Equihash
  mining-rental.
- **Verge** (April 2018): consensus-bug-enabled.

For Bitcoin itself the concern is **mining pool concentration** — 3-5
pools have historically controlled ~70%+ of hash power; the 2014 Ghash.io
incident (single pool >50%) demonstrated the social-layer response is the
operational defense. For Ethereum (PoS), the analog is **staking pool
concentration** — Lido 25-33%; top 5 entities ~50%+. Slashing imposes
massive economic cost on misbehavior, but collusion-or-compulsion surface
is structurally similar.

### Selfish mining (Eyal, Sirer, 2013)

"Majority is Not Enough" (arxiv.org/abs/1311.0243) demonstrated that a
selfish-mining strategy lets an attacker with as little as ~25-33% hash
power earn revenue disproportionate to stake. When the attacker finds a
block they keep it private and continue mining; when they find a second
they release both at once, orphaning the honest miner's single block.
Revenue share grows because they capture more rewards relative to hash
power while honest miners do orphan-work. Follow-on work (Sapirshtein-
Sompolinsky-Zohar 2015; Nayak-Kumar-Miller-Shi stubborn mining + eclipse)
refined the threshold. Not observed at scale on Bitcoin (social-cost-to-
pools is severe); credible for smaller-cap PoW chains.

### Eclipse attacks (Heilman et al., 2015)

"Eclipse Attacks on Bitcoin's Peer-to-Peer Network"
(eprint.iacr.org/2015/263, USENIX 2015): attacker controlling enough IP
addresses monopolizes a victim node's connections, feeding the victim a
custom chain view. Mining / consensus decisions are made on the attacker's
view — N-confirmation double-spending, selfish-mining amplification,
engineered forks. Specific Bitcoin Core peer-table-management bugs
(`tried` / `new` eviction, addr-relay) made it practical with modest IPs;
Bitcoin Core shipped peer-table hardening, anchor-connection retention,
addr-relay filters. Marcus-Heilman-Goldberg (2018) demonstrated the
analog on Ethereum's Kademlia-derived peer discovery; go-ethereum
patched. DHT-style peer discovery → eclipse risk recurs across networks.

### Long-range attacks in PoS

PoS-specific failure with no PoW analog. Adversary acquires private keys
of validators active at some past epoch (validators who have since
withdrawn have no economic motive to refuse selling). Adversary re-signs
blocks from past epoch forward, building an alternative chain. To a new
node, the alternative is signed by the correct historical set — no
protocol-level distinguisher.

Buterin's 2014 essay "How I Learned to Love Weak Subjectivity"
(blog.ethereum.org/2014/11/25/proof-stake-learned-love-weak-subjectivity)
names the solution: **weak subjectivity**. New nodes (or returning after
long offline periods) must obtain an out-of-band trusted state checkpoint
from some recent epoch. Production: validator-key withdrawals time-delayed
(Ethereum ~27h minimum), withdrawn-validator signatures uncounted post-
withdrawal, clients ship periodically-updated checkpoints. Risk surface
reduces to compromising *current* (slashable) stake.

### Nothing-at-stake

In naive PoS, a validator signing on a fork pays no penalty — costless to
sign competing blocks at the same height. Rational validators sign every
fork; convergence fails.

Defense: **slashing**. Cryptographic detection of double-signing triggers
automatic stake confiscation. Ethereum slashing conditions: (a) two
different beacon-chain blocks at the same slot (proposer slashing); (b)
two attestations satisfying the "surround" relation (attester slashing).
Slashed validator loses an initial penalty (~1 ETH pre-Pectra; ~0.0078 ETH for 32 ETH post-Pectra) plus correlation penalty scaling
with mass-collusion. Detection is itself in-protocol incentive — anyone
can submit a proof and earn a portion of slashed stake, creating a
permissionless monitor network.

### Time-bandit and MEV-induced reorg

Daian et al.'s "Flash Boys 2.0" introduced the **time-bandit attack**:
when in-block MEV exceeds chain-replacement cost, a rational miner /
validator has incentive to rewrite history. Most acute in PoW; feasible
at then-current Ethereum parameters per the paper. Post-Merge: validators
face slashing for double-signing, raising reorg cost. MEV-Boost (§7)
centralizes MEV capture in builders, weakening the validator-layer
incentive. Trade-off: builder-layer centralization, with BloXroute,
beaverbuild, rsync-builder, Titan, manifold producing most blocks.

### Liveness and censorship

**Censorship by validator collusion**: validators agree not to include
specific transactions (sanctioned addresses, competitor protocols, low-fee
mempool). Chain runs; liveness for censored transactions is compromised.
Post-August 2022 Tornado Cash sanctions, ~70% of Ethereum blocks were
"OFAC-compliant" (Flashbots relay operated under US jurisdiction).
Mitigation: non-censoring relays (Agnostic, BloxRoute Max-Profit) and
self-built blocks. Cross-link
[[distributed_authz_expertise.md]].

### Routing-level (BGP) attacks

Apostolaki-Zohar-Vanbever "Hijacking Bitcoin" (IEEE S&P 2017): BGP-level
adversaries partition cryptocurrency networks by hijacking prefixes
carrying node-to-node traffic. Nation-state-class adversaries isolate
validators or miners, opening selfish-mining / eclipse windows at scale.
Mitigations: encrypted peer connections (Bitcoin BIP-324 v2, Ethereum
RLPx) prevent passive observation but not partition. Tor / I2P mitigates
BGP exposure with availability cost. Institutional defense: multi-region
+ diverse-upstream-ISP. Cross-link [[dns_network_infrastructure.md]].

---

## 7. Proof-of-Stake validator and staking specifics

### Ethereum staking mechanics

Validator: 32 ETH deposited to beacon-chain deposit contract (cap
balances decentralization against block-validation overhead). Validators
sign attestations every slot (~12s) and occasionally propose. Honest
~3-5% annual; misbehavior triggers slashing.

Key points: (a) **Withdrawal credentials** distinguish BLS-key-controlled
and ETH-address-controlled (0x01 prefix); most institutional validators
use 0x01 so withdrawal goes to a separately-keyed hot wallet. (b)
**Validator key vs withdrawal key** are distinct — signing-key compromise
alone lets an attacker slash the validator but NOT steal staked ETH. (c)
**Slashing** (duplicate blocks or "surround" attestations) costs 1-32 ETH
based on correlated-slashing population. (d) **Exit queue**: hours-to-
weeks for full validator exit; security feature (reduces long-range-attack
risk), operational drag (slow compromised-key rotation).

### Validator key compromise

Signing-key compromise → attacker can slash (costing staker, paying
nothing) or, with sufficient total stake, attempt reorgs. Withdrawal-
credential compromise → steal staked ETH directly. Typically distinct keys.

Storage: **solo stakers** (~5%): local laptop / RPi, encrypted-at-rest;
compromise via device theft / malware. **Staking pools** (Rocket Pool,
Lido operators): operator-controlled keys with operator-specific custody;
operator registration is the defense surface. **Cloud validators**: KMS
or HSM-backed; cloud-account compromise is the classic risk. **DVT**:
below.

### Lido + EigenLayer centralization

**Lido Finance** controls 25-33% of staked ETH. If Lido's operator set
were compelled, the chain would be materially affected. Defense
evolution: initial ~30 KYC'd professional operators → 2024 Community
Staking Module (CSM) admitting solo stakers (Early Adoption first, later
fully permissionless) with a 2.4 ETH bond (1.5 ETH for early adopters,
1.3 ETH per additional validator) → DVT pilot with Obol eliminating single-operator-controls-key
risk. Community pressure against exceeding 33% (one-third gives
attack-disruption power short of 51%) has held.

**EigenLayer** introduced **restaking**: validators re-pledge staked ETH
to secure additional services (AVSs) beyond Ethereum. Marginal capital
cost of new services drops; operators earn AVS rewards.

Structural risks: (a) **Cumulative slashing** — validator restaked
across N AVSs faces slashing from each; single mistake cascades. (b)
**AVS-quality dependence** — security depends on slashing-detection
accuracy; poorly-designed AVS fails to detect malicious behavior. (c)
**Operator selection concentration** — each AVS selects from the
restaker pool; concentration in few operators recreates centralization
one level up. (d) **Aggregate-risk modeling is hard** — restaked across
5 AVSs each bounded at 30% pledged → total potential loss 100% (parallel
slashing).

### Liquid Staking Derivatives (LSTs)

stETH (Lido), rETH (Rocket Pool), cbETH (Coinbase), pufETH (Puffer)
represent staked ETH as transferable ERC-20s. On-chain risk = any DeFi
token (cross-link [[smart_contract_evm_security_expertise.md]] §5);
staking-specific: validator slashing depletes the pool (LST redemption
falls); withdrawal-queue length determines exit speed (creates
premiums/discounts); operator-set risk (stETH depends on Lido's set not
collectively misbehaving). The 2022 stETH depeg during Celsius / 3AC
implosions demonstrated that LST-vs-ETH decoupling is a real liquidity
event — underlying stake was sound; redemption-discount reflected panic.

### Distributed Validator Technology (DVT)

DVT distributes a single Ethereum validator across multiple operator
nodes via BLS threshold signatures: M of N must cooperate to sign.
Compromise of M-1 nodes is insufficient to slash.

- **Obol Network**: cluster-based with Charon middleware, Distributed Key
  Generation (DKG) at key-creation time so no node sees the full key, BLS
  threshold signatures for validator duties.
- **SSV Network**: on-chain encrypted key-share storage with
  permissionless operator participation; operators can be added/rotated
  without coordination.

Lido's Simple DVT Module (sDVTm), approved Feb 2024, allows Lido
validators to run on Obol or SSV clusters, decentralizing the operator
surface.

Trade-offs: M-of-N tuned for safety (M near N) reduces single-operator-
fault risk but increases liveness risk; tuned for liveness (M near
majority) preserves uptime but admits collusion surface. Misconfigured
clusters can collectively get slashed (protocol treats the cluster as a
single validator that double-signed).

### MEV in PoS and MEV-Boost

The PoS Merge preserved MEV attack surface but changed accrual.
Flashbots' **MEV-Boost** (github.com/flashbots/mev-boost) implements
out-of-protocol Proposer-Builder Separation: **validators** propose
blocks; **builders** construct contents (transaction-ordering for MEV);
**relays** mediate the auction. Validator never sees block contents
until signing the header (relay holds payload in escrow) — protects
against validator stealing builder's MEV, requires trusting the relay
not to misrepresent validity.

Market: ~90%+ of blocks are MEV-Boost; ~5 relays handle ~95%+; ~10
builders produce ~95%+. Decentralization argument: any validator could
self-build; in practice MEV-capture rents are concentrated in the builder
oligopoly. Future: **enshrined PBS** (ePBS) moves PBS into the protocol.
2025 SoK papers (arxiv.org/abs/2506.18189) catalog design space;
ePBS itself (EIP-7732) is a headliner of the Glamsterdam upgrade.

---

## 8. Cross-chain bridge custody at the consensus level

### Trust models for bridges

Bridges connect chains by holding assets locked on origin while issuing
wrapped tokens on destination. Trust question: **who attests the lock
event happened?** Four models:

1. **Multi-sig / external validator set** — small committee signs lock
   attestations. M-of-N compromise = unbacked wrapped-token mint. Ronin,
   Multichain, Harmony Horizon, Heco all used this; all suffered
   committee compromise.
2. **Optimistic verification** — attestations with challenge period;
   any party can dispute via fraud proof. Secure if at least one honest
   watcher submits fraud proofs in time. Nomad shipped an initialization
   bug bypassing the system entirely.
3. **Light-client verification** — each chain's nodes verify the other's
   block headers, executing actual consensus logic. Trust rooted in
   chain consensus, not a separate committee. IBC (Cosmos), zk-IBC,
   Polyhedra, Succinct Telepathy. Computationally expensive without ZK.
4. **ZK-proof-based** — SNARK proves the lock per origin consensus
   rules. Cheap verification, expensive off-chain proof generation.
   Polygon zkEVM, zkLink, Linea, Scroll for L2-to-L1; Polyhedra /
   Succinct generalize across heterogeneous chains.

Implicit fifth: **trusted-validator-set + economic slashing** —
validators have staked tokens slashable on misbehavior. LayerZero DVN and
Axelar's delegated proof-of-stake validator set blend committee +
economic incentive; Wormhole's guardian network is proof-of-authority. Committee size + slashing rigor determine
security.

### Ronin Bridge ($625M, March 2022)

Sky Mavis operated Ronin Bridge with 9-validator multi-sig (5-of-9).
Attacker (later attributed by FBI to Lazarus / DPRK) gained 4 Sky Mavis
validator keys and abused a separate "gasless RPC" backdoor — set up to
let the Axie DAO validator delegate signing to Sky Mavis during a 2021
traffic spike — to obtain the Axie DAO validator's signature. With 5
signatures, the attacker forged 173,600 ETH + 25.5M USDC withdrawal.

Detection lag: attack March 23, detected March 29 (6 days later) via
user-reported failed withdrawal. Monitoring-as-detection is part of the
bridge threat model — lock-and-mint balance is invariant; deviations
must trigger immediate alerts. Sky Mavis raised $150M (Binance-led) to
refund users; on-chain seizures recovered $30M+ over subsequent years.
Bridge re-launched with stronger multi-sig discipline and the gasless-RPC
backdoor removed.

### Wormhole ($325M, February 2022)

Wormhole bridge between Solana and Ethereum used a guardian-set model
(19 guardians, 13-of-19). The exploit was *not* guardian compromise —
signature-verification bypass on the Solana side. A deprecated Solana
function (`load_instruction_at`) verified guardian signatures without
checking that the passed-in instructions sysvar account was the real
sysvar account (`load_instruction_at_checked` validates this).
Attacker passed a fake "verification program" account containing
pre-baked "verified" attestations; Wormhole accepted them and minted
120,000 wETH on Solana. Jump Crypto injected $325M to refill collateral;
user funds preserved; Solana program patched within hours. Cross-link
[[../static_analysis/semgrep_rule_authoring.md]] on verifying signatures
against an account-passed-as-argument without anchoring to a specific
program ID — Solana equivalent of forgetting an EVM authz check.

### Nomad ($190M, August 2022)

Nomad used optimistic verification: a Replica contract on destination
accepted attestations with a 30-minute fraud-proof window. A routine
upgrade initialized the trusted-root storage slot to `bytes32(0)`.
Message processing looked up each message's proven root in a mapping;
for a never-proven message that lookup returns the default `bytes32(0)`,
which matched the initialized trusted root (pre-confirmed in
`confirmAt`), so every unproven message verified as accepted.

Exploit was so simple that within hours hundreds of independent
addresses copied the original transaction (substituting their own
withdrawal addresses) and drained the bridge "crowdsourced" — total
~$190M; some recovery via whitehat watchers escrowing funds.

Lessons: (a) **Initialization mistakes in upgradeable contracts are an
entire bug class** — OpenZeppelin's Initializable catches many variants;
bespoke logic re-introduces risk. (b) **A `default(T)` matching a
sentinel is a failure mode** — Solidity `bytes32(0)`, Rust
`Option::None`, C null all participate; cross-link
[[code_review_expertise.md]] on "default values matching valid sentinels
are always suspicious." (c) **Optimistic systems require active
watchers** — Nomad's window meant nothing because the bug produced valid
proofs unrelated to legitimate messages.

### LayerZero, Wormhole, Axelar, Hyperlane

Post-2022 consolidation:

- **LayerZero V2**: Decentralized Verifier Networks (DVNs) — each
  application picks its validator set per route. Default DVN + optional
  additional DVNs.
- **Wormhole**: 19-guardian, 13-of-19; post-2022 emergency-response
  primitives + monitoring.
- **Axelar**: ~75-validator delegated proof-of-stake set; slashable.
- **Hyperlane**: modular interchain security — each application picks
  multi-sig / optimistic / ZK.

Progression: "small committee = bridge security" → "application-specific
trust with bridge infrastructure providing primitives but not opinions."

### MPC-based bridges

- **THORChain**: cross-chain swaps via MPC-controlled liquidity pools;
  TSS validators collectively hold native-asset wallets.
- **ChainPort**, **Multichain** (defunct after July 2023 ~$126M
  unauthorized withdrawals; its MPC node servers ran under the arrested
  CEO's sole control).

Inherits both MPC implementation-bug risk (TSSHOCK class) and
operator-trust risk.

### "Bridges are the most-attacked surface in crypto"

Cumulative bridge losses 2021-2025 exceed $2.5B+, with single incidents
($625M Ronin, $610M Poly Network, $325M Wormhole, $190M Nomad) repeatedly
setting records. Structural reasons: (a) **bridges concentrate value** —
$1B-locked = major-DeFi-TVL on one surface; (b) **bridges combine threat
surfaces** — contract bugs + validator-set compromise + cryptographic
protocol bugs + operational compromise; (c) **bridges are operationally
novel** — each new bridge relearns failure modes; (d) **bridges sit
between trust domains** — each chain's security is independent; the
bridge bears the cost of any mismatch. Cross-link
[[smart_contract_evm_security_expertise.md]] §5 for the contract-level
catalog.

---

## 9. Cryptocurrency exchange security

### Mt. Gox (2014): the formative incident

Mt. Gox handled ~70% of Bitcoin transactions at peak (2013). Over a
multi-year period (2011 onward), ~850,000 BTC exfiltrated ($473M at 2014
collapse price). Japanese civil-rehabilitation bankruptcy filed February
2014; CEO Mark Karpelès convicted on data-manipulation (separate from
the theft). 2023 DoJ indictment of Russian nationals Bilyuchenko and
Verner attributed ~647,000 of the stolen BTC. Repayment to creditors
began July 2024.

Lessons: (a) **Hot-wallet sprawl** — the dominant exfiltration vector;
attackers accessed hot wallets over years. (b) **Audit-and-attestation
is necessary, not sufficient** — no rigorous proof-of-reserves; ongoing
insolvency invisible until collapse. (c) **Operational IR was
non-existent** — theft identified retroactively when books didn't balance.

### Bitfinex (2016, ~$72M)

Bitfinex used BitGo multi-sig (BitGo + Bitfinex + customer signatures
with withdrawal limits). Attackers compromised the Bitfinex side in a
way that bypassed limits; ~120,000 BTC stolen. Response: socialized 36%
haircut; BFX debt tokens issued and bought back to par over 8 months;
recovered fully. 2022 arrest of Heather Morgan and Ilya Lichtenstein
attributed theft; ~$3.6B Bitcoin recovered at then-current price.

### Coincheck (2018, ~$530M)

~500M XEM in a hot wallet without multi-sig. Phishing-derived compromise
of employee account → wallet access → exfiltration. XEM tagging allowed
laundering trail tracking before mixing. Lesson: hot-wallet without
multi-sig is unacceptable for institutional custody. Japanese regulators
mandated multi-sig and cold-wallet thresholds.

### Bithumb (2017-2019)

Repeated hot-wallet compromises: 2017, 2018 (~$31M),
2019 (~$19M in EOS/XRP). Some attributed to insider collusion. Repeated breaches
demonstrate operational-security gaps aren't always closed after a single
incident.

### FTX (2022): custody-cum-fraud collapse

Not a "hack" — largest custody failure of the modern era. Alameda
Research borrowed customer deposits for leveraged investments; deposits
not segregated as user-facing terms claimed. FTT collapse → Alameda
underwater → withdrawal panic exposed gap. SBF convicted on seven federal
counts November 2023, sentenced 25 years March 2024. Bankruptcy returned
>100% in dollar terms at filing (less in original crypto terms due to
price appreciation).

Structural lesson: **proof of reserves is necessary but not sufficient.**
FTX could have produced a reserves attestation; the assets were borrowed
by Alameda. A proper proof requires reserves + liabilities + segregation.

### Bybit (February 2025): the largest crypto hack

February 21, 2025: Bybit lost ~$1.4B (401,347 ETH and equivalents) —
largest cryptocurrency theft ever recorded. Textbook demonstration that
**operational signing-UX compromise defeats cryptographic custody
architecture**.

Technical chain (per NCC Group, Mandiant, Elliptic, TRM Labs analyses):

1. **Initial access**: Safe developer social-engineered; workstation
   compromised.
2. **Cloud lateral movement**: attackers exfiltrated AWS session tokens
   from the workstation, bypassing MFA to access Safe's AWS account.
3. **Frontend injection**: attackers modified the Safe{Wallet} web UI
   (specifically the JS served to Bybit signers) to display a benign
   transaction (legitimate-looking ETH transfer to Bybit hot wallet)
   while the underlying transaction-to-sign was a `delegatecall` upgrade
   replacing the Safe's implementation with an attacker-controlled
   contract.
4. **Multi-sig execution**: three Bybit cold-wallet signers approved as
   displayed in the UI. They did NOT see raw form — they trusted the UI.
   Signed transaction modified the Safe to allow attackers to drain.
5. **Post-theft laundering**: ~$160M through DEXs and mixers in 48h;
   remainder dispersed across hundreds of wallets and chain-hopped
   through bridges over days.

Attribution: blockchain-analytics firms (Elliptic, TRM Labs) and
ZachXBT tied it to Lazarus / DPRK via wallet-clustering, mixing
preferences, timing patterns; the FBI confirmed on February 26, 2025
("TraderTraitor"). Bybit CEO Ben Zhou announced a $140M bounty; Bybit
covered customer balances from insurance + own funds; ~5% of stolen funds
recovered or frozen per Bybit's 2026 figures.

Structural lessons: (a) **The UI is part of the trust boundary.** No
matter how good the underlying multi-sig cryptography, if signers don't
see the raw transaction they're blind-signing. Hardware wallets that
parse and display the transaction independently are the structural
defense; in the Bybit case Ledger devices *should* have shown the
`delegatecall` to an unknown implementation, but operator workflow
accepted device display as confirmatory of UI display rather than
independently meaningful. (b) **Supply-chain attacks on signing
infrastructure are devastating.** Compromising the Safe-frontend
supply chain reached past every Safe customer's multi-sig using the
Safe-hosted UI. Self-hosted signing UIs are a structural mitigation;
few customers have the engineering depth. (c) **Cloud-credential
exfiltration via session-token bypass of MFA is now a standard DPRK
technique.** Cross-link [[cloud_iam_expertise.md]] on AWS session-token
revocation and SCP-based hardening.

### The triangle: hot, warm, cold + MPC + insurance

Modern exchange custody combines: ~1-3% hot (automated signing, accepted
small-blast-radius), ~5-15% warm (multi-sig with operational policies,
manual confirmation for large transactions), 80%+ cold (air-gapped
multi-sig or MPC; signing ceremonies for cold-storage withdrawal). A
subset in **MPC custody** with policy engines cryptographically
restricting signable transactions. **Insurance** covers some fraction
against custodian failure. **Proof-of-Reserves** (Merkle-tree for
customer balances + on-chain address proofs) periodic. Defense-in-depth
is real; Bybit demonstrated that even with MPC + cold storage + multi-
sig, the *signing-UX layer* is an unprotected surface.

### DPRK Lazarus as the dominant adversary

Chainalysis attributes $2.02B of 2025's $3.4B in crypto theft to North
Korean state-sponsored actors (Lazarus, APT38, TraderTraitor, BlueNoroff,
Andariel — "Lazarus" is a loose umbrella per Mandiant). Operational
characteristics: (a) **Reconnaissance** — months of social engineering
targeting operator accounts; job-offer phishing via LinkedIn / Telegram
is the canonical entry vector. (b) **Sophisticated malware** — cross-
platform implants (POOLRAT, FULLHOUSE.DOORED for macOS, KandyKorn).
macOS investment grew to target crypto-industry developers. (c)
**Cloud-credential exfiltration** with MFA-bypass via session tokens.
(d) **Patient laundering** — funds left dormant for weeks to months;
Wormhole funds sat dormant ~1 year before movement. Cross-link
[[threat_intel_methodology_expertise.md]] §3.

---

## 10. On-chain forensics and investigation

### Commercial tools

- **Chainalysis** (2014, Reactor + KYT): largest vendor; US Treasury /
  IRS, major exchanges, FIs. Annual "Crypto Crime Report" is a
  reference data source.
- **Elliptic** (London): similar surface, strong UK / EU regulatory.
- **TRM Labs** (2018): particularly active in DPRK / Lazarus tracking
  post-Bybit.
- **Crystal Blockchain** (Bitfury subsidiary): European-focused.
- **Merkle Science** (Singapore): APAC focus.
- **CipherTrace** (Mastercard 2021): compliance tooling.

Common features: **address clustering** (common-input ownership
heuristic for Bitcoin, transaction-pattern heuristics for Ethereum),
**entity attribution** (exchange-deposit-address discovery, KYC
partnerships), transaction graph visualization, real-time alerting,
compliance scoring.

### ZachXBT methodology (independent / community)

Small toolset (Etherscan, Arkham, Breadcrumbs, public exchange data) +
deep OSINT discipline:

1. **Funds-flow traversal** — trace outflow through DEX swaps, bridges,
   mixers; cross-reference attribution clusters.
2. **Behavioral fingerprinting** — timing (time-zone), mixing
   preferences (Tornado, Wasabi, JoinMarket, eXch have distinctive
   fingerprints), gas-price tendencies.
3. **OSINT pivots** — addresses to X handles, Discord usernames,
   GitHub, domain registrations. Crypto community is small enough that
   operational mistakes are often discoverable.
4. **Public disclosure** — long-form X threads with screenshots,
   addresses, narrative. Disclosure pressures exchanges to freeze
   funds; mobilizes community.

Has produced high-profile attributions (Inferno Drainer operators,
NFT-rug-pulls, FBI-assistance cases). Methodology transfers; binding
constraint is patience and pattern recognition.

### Following-the-flow patterns

Standard tracing: identify entry point → cluster immediate destinations
→ recursive expansion (DEX swaps / bridge crossings / mixer deposits
require branch-tracking) → prune branches consolidating at known
exchanges (pursue via law-enforcement) → pattern-match against
attribution catalogs (hop count before mixing, preferred mixer, exit
pattern). Mixer / bridge crossings are **information-loss boundaries**:
Tornado Cash 10/100/1000-ETH pool deposits made trails discontinuous;
bridge crossings move funds to a different ledger; cross-chain
laundering (ETH → BTC → Monero → USDT) multiplies analytical work.

### Mixer / tumbler analysis

- **Tornado Cash**: Ethereum's dominant mixer. OFAC-sanctioned August
  2022; reversed March 2025 after Fifth Circuit ruled OFAC overstepped
  by sanctioning immutable smart contracts. Roman Storm faces ongoing
  criminal charges. Most US-touching infrastructure still treats TC
  interactions as risky.
- **Wasabi Wallet** (Bitcoin CoinJoin): coordinator data subpoenable;
  participation patterns inferable.
- **JoinMarket**: P2P Bitcoin CoinJoin; more resistant to coordinator
  compromise, smaller liquidity pool.
- **Samourai Wallet** (Bitcoin Whirlpool): operators arrested April
  2024 for unlicensed money-transmission.
- **eXch** (cross-chain mixer): widely used by Bybit attackers; seized
  by German authorities (BKA) April 30, 2025.
- **Monero**: not a mixer per se but a chain with confidential default
  transactions. DPRK funds frequently exit ETH chains into XMR. Some
  timing/amount-correlation analysis still possible but substantially
  harder than transparent chains.

### Sanctions enforcement on-chain

OFAC SDN list includes crypto addresses; US-touching infrastructure
blocks transactions. Funds at listed addresses must discount to move
through non-cooperating venues. The Tornado-Cash sanctions tested
limits: OFAC sanctioned immutable smart contracts. Fifth Circuit 2024
ruling and March 2025 delisting clarified immutable contracts cannot be
"property" under IEEPA. Industry effect pending — most firms continue
TC-equivalent scrutiny.

USDC and USDT issuers will *freeze* addresses on-chain when ordered.
Frozen tokens visible but non-transferable — centralization at odds
with crypto-maximalist framing but operationally significant. Cross-link
[[threat_intel_methodology_expertise.md]] §3.

---

## 11. Wallet and protocol design defenses

### Defense layers for end users

1. **Simulation before signing** — Blockaid / Pocket Universe / Stelo /
   Wallet Guard. Cross-link [[code_review_expertise.md]]; raw calldata
   hash signing is the format-string equivalent.
2. **EIP-712 typed signatures** — render human-readable summaries; warn
   on unrecognized schemas.
3. **Time-locked withdrawals** — Argent, Safe timelock module,
   institutional custody. 24-72h delay = alarm window.
4. **Allowlist of contract interactions** — Safe modules enforce
   whitelists; off-list requires extra signers.
5. **Per-asset spending limits** — Argent daily limits; Fireblocks /
   Copper policy engines enforce per-asset, per-route, per-time caps
   cryptographically.
6. **MPC + biometric step-up** — ZenGo's model; institutional analogs
   for high-value operator actions.
7. **Hardware-wallet display as source of truth** — if the device
   cannot show destination + amount in plain form, don't sign. Larger
   screens (Ledger Stax, Trezor Safe 5, Keystone) + per-contract /
   per-EIP-712 firmware integrations.
8. **Social recovery** — Argent and ERC-4337 variants; quorum of
   trusted guardians recovers access if owner loses primary device.
9. **Multisig for treasuries** — Safe (Ethereum), Squads (Solana).
   3-of-5 common for DAO / institutional; 4-of-7 for higher value.

### Code-review checklist

1. **Entropy source for key generation** — hardware RNG? CSPRNG from
   `/dev/urandom`? Custom code? Bad randomness is catastrophic.
2. **BIP-32 derivation path** — standard `m/44'/60'/0'/0/x` for Ethereum?
   Non-standard fragments recovery.
3. **BIP-39 mnemonic generation** — correct wordlist, entropy length,
   checksum word? Faulty checksums = silent unrecoverability.
4. **Address format display** — full addresses or truncated? Truncated
   forms enable address-mining attacks.
5. **Transaction parsing** — ERC-20 `transfer/approve`, ERC-721
   `setApprovalForAll`, EIP-712 decoded? Lack of decoding = blind
   signing.
6. **Permit handling** — flagged distinctly; warn on unlimited
   approvals to unfamiliar spenders.
7. **Chain ID confirmation** — target network prominently displayed?
   Cross-chain replay exploits chain-ID confusion.
8. **Session-token handling on hosted UIs** — tokens scoped tightly;
   MFA on every privilege-escalation, not just login. Bybit exploited
   session-token reuse.
9. **Firmware attestation chain** — host verifies manufacturer
   attestation; attestation key list updateable; bootloader-bypass
   paths documented.
10. **Recovery flow integrity** — losing one factor locks user out OR
    makes wallet recoverable by attacker? Both bad; recovery needs
    dedicated threat modeling.
11. **MPC implementation provenance** — well-audited reference (Coinbase
    `cb-mpc`, Trail of Bits-reviewed fork) vs bespoke. TSSHOCK-class
    bugs cluster in less-maintained forks.
12. **Operator-side key-share storage** — TEE-backed (SGX, Nitro, SEV)?
    HSM? Raw KMS? Cross-link [[confidential_computing_expertise.md]] §3.

---

## 12. Detection and monitoring

### Forta Network

**Forta** is a decentralized runtime detection network. Bot operators
publish detection bots (TypeScript, Python, Rust) subscribing to chain
events and emitting alerts on pattern match. Bots run on a decentralized
node network; alerts aggregate to subscribers. Mariko Wakabayashi's
Forta bots reportedly flagged $300M+ of pre-exploit anomalies 2022-2024.
The 5-minute warning window is often sufficient to pause-guard a
protocol or coordinate counter-attack.

### OpenZeppelin Defender Sentinel

Defender Sentinel (commercial; hosted Defender was retired July 1,
2026 in favor of open-source Monitor) provided contract-monitoring with
custom-rule scripting and alerting integrations (PagerDuty, Slack,
email). Overlap with Forta exists; Defender is centralized and
customer-pays.

### Tenderly Alerts and pre-tx simulation

Simulation platform previews transactions against current chain state
with outcome assertions (revert reasons, state changes, gas). Alerts
fire on user-defined criteria. Used for pre-deployment validation and
runtime monitoring.

### MetaMask Snaps for transaction safety

MetaMask Snaps (late 2023) allow security vendors to integrate analysis
into the wallet. Blockaid's alerts ship natively in MetaMask (not as a
Snap), simulating transactions locally via its PPOM module before signing. Cross-link
[[browser_js_engine_exploitation_expertise.md]] §6 on Snap sandbox.

### Vendor onchain monitoring

- **Hypernative**: institutional-grade runtime threat detection.
- **Cyfrin**: monitoring + audit + Updraft education.
- **Quill / Quillscan**: BNB-chain-focused.
- **BlockSec / Phalcon**: simulation + monitoring + IR; strong on rapid
  post-incident analysis.
- **GoPlus**: API-driven token / address risk scoring; widely integrated
  into wallet UIs.

### "DeFi SOC" team model

Larger protocols (Aave, Compound, MakerDAO/Sky, Curve, Uniswap) operate
dedicated security operations: 24/7 on-call, custom monitoring on Forta
+ Defender + in-house, SEAL 911 relationships, Immunefi bug-bounty
operations, periodic war-game drills. Cross-link
[[detection_engineering_expertise.md]] §6 — transferable structure with
chain telemetry as event stream.

### SEAL 911 and Security Alliance

Security Alliance (SEAL, securityalliance.org) is the cross-protocol
incident-response coordination layer founded by samczsun. SEAL 911
rapid-response Telegram channel: protocols hit by active exploits reach
incident responders across audit firms, whitehat operators, exchange
security teams in minutes. Deliberate response to the 2021-2022 era
when incidents either resulted in immediate full-drain or chaotic
Twitter-mediated coordination. Have a SEAL 911 contact pre-established
*before* you need it.

---

## 13. Variant analysis — under-explored attack surfaces

### Stablecoin issuer custody

USDT ($100B+), USDC ($60B+), DAI / sDAI ($5B+), PYUSD (PayPal/Paxos),
FDUSD have distinct custody / issuance models.

Threat surfaces: (a) **Reserve backing** — USDT historically faced
scrutiny over reserve composition; NY AG settlement (2021) required
quarterly attestations. (b) **Issuance keys** — privileged contract
functions; control = arbitrary minting; both USDT and USDC use
cold-storage / multi-sig. (c) **Freezing capabilities** — USDC and USDT
can freeze addresses; operationally useful for sanctions but creates
attack surface if compromised. (d) **Off-chain liability** — reserves
in banks / money-market funds; bank failure → stablecoin depeg (USDC
during SVB collapse, March 2023).

"Stablecoin issuer = new central bank": each major issuer is
operationally equivalent to a small central bank with custody
requirements to match.

### TEE-based custody

TEEs (Intel SGX, AMD SEV, AWS Nitro Enclaves, Apple Secure Enclave)
provide hardware-backed isolation for crypto operations. Cross-link
[[confidential_computing_expertise.md]] §3.

Applications: **Key-share storage** in Fireblocks / Coinbase / GK8 uses
SGX or Nitro Enclaves to host MPC shares; operator-level cloud
compromise still faces TEE attestation. **Worldcoin orb biometric
custody** uses TEEs to compute iris-hash without exposing biometric.
**MEV-Boost relays** experimented with TEE-based block-withholding
(cross-link [[confidential_computing_expertise.md]] §8).

TEE-specific attacks (SGAxe, ÆPIC Leak, MMIO Stale Data, SGX-Step,
timing) all apply. SGX deprecation in Intel's consumer CPU line (11th
gen+) is shifting institutional custody toward Nitro Enclaves and AMD
SEV-SNP.

### Quantum threat to crypto signatures

Shor's algorithm breaks ECDSA, EdDSA, Schnorr on sufficiently large
quantum computers. NIST working assumption: 2030-2040 for
"cryptographically relevant quantum computer." Implications: (a)
**Address reuse risk** — Bitcoin P2PKH addresses derived from
hash(public_key) only expose the public key after first spend;
never-spent addresses are quantum-safe; spent addresses expose the
public key for future quantum derivation. (b) **Pre-quantum migration**
— ML-DSA / Dilithium, SLH-DSA / SPHINCS+ are NIST-standardized (FALCON / FN-DSA
still draft FIPS 206);
cross-link [[post_quantum_cryptography_expertise.md]]. Chain-level
migration is a consensus-fork event. (c) **Hash function security
against Grover's** — SHA-256 preimage / collision degraded but not
broken (security halved); RIPEMD-160 more exposed.

Pragmatic stance for 2026: PQ migration is a multi-year project that
should be planned now. Hybrid signatures (classical + PQ) are the
transition strategy.

### AI agents executing crypto transactions

Autonomous agents (LangChain trading bots, Eliza on-chain agents,
LLM-authored MEV bots) hold crypto and execute without per-step human
review. Surfaces: **prompt injection** against tool-calling redirects
transactions (cross-link [[llm_agent_security_expertise.md]] §4-6);
**key storage** is often expedient (env vars, local files); **dual-use
ambiguity** — arbitrage agent given prompt-injected instruction may
execute wash-trade or market-manipulation, agent has no legality
judgment; **agentic-web browser drivers** (Browser Use, Computer Use,
Operator) click "Approve" on permit dialogs (cross-link
[[agentic_web_capabilities_expertise.md]] §7).

Pragmatic: AI agents holding non-trivial crypto need per-transaction
value caps, allowlisted destinations, out-of-band human approval for
privilege escalation. Treat agent signing keys as permanently-online-
server keys.

### Real-World Assets (RWA) on-chain

Tokenized treasuries (Ondo OUSG, BlackRock BUIDL, Franklin Templeton
BENJI), tokenized real estate / commodities proliferated 2024-2026.
Custody for the underlying is *off-chain*; the on-chain token is a
claim depending on off-chain custodian honoring redemption.
Structurally back-to-tradfi-custody: token security is bounded by
issuer's traditional-finance operational security. New attack surface:
**redemption / minting bridge** — compromise of minting key or
attestation flow → mint unbacked tokens (stablecoin-issuer-compromise
analog).

### Privacy-preserving payment systems

Zcash (zk-SNARK shielded), Monero (ring signatures + RingCT + stealth
addresses), Aleo (private smart contracts). Custody / threat model:
**shielded balance recovery** — Zcash viewing-key loss = unrecoverable
balance; **mixer-quality analysis** doesn't apply (the chain is the
mixer); some timing/amount-correlation analysis still possible;
**compliance posture** — most US-touching exchanges delisted Monero
(Kraken 2024, Binance 2024-2025). Cross-link
[[privacy_engineering_expertise.md]] §5.

### Decentralized identity (DIDs)

DID-based identity (Ethereum ENS, .eth, Spruce Disco, Verifiable
Credentials) emerged 2023-2025. Surfaces: **DID resolution compromise**
(off-chain resolver compromise → identity impersonation); **VC issuer
compromise** (issuer-key compromise → credential forgery);
**selective-disclosure protocols** (BBS+, ZKP-based VC schemes) have
TSSHOCK-class cryptographic-protocol bug surface. Stack is early;
operational security practices still maturing.

---

## 14. References

### Foundational consensus papers

- Satoshi Nakamoto, "Bitcoin: A Peer-to-Peer Electronic Cash System" — bitcoin.org/bitcoin.pdf
- Eyal, Sirer, "Majority is Not Enough" — arxiv.org/abs/1311.0243
- Sapirshtein, Sompolinsky, Zohar, "Optimal Selfish Mining" — arxiv.org/abs/1507.06183
- Heilman, Kendler, Zohar, Goldberg, "Eclipse Attacks on Bitcoin's P2P Network" — eprint.iacr.org/2015/263
- Marcus, Heilman, Goldberg, "Low-Resource Eclipse Attacks on Ethereum's P2P Network" — eprint.iacr.org/2018/236
- Nayak, Kumar, Miller, Shi, "Stubborn Mining: Generalizing Selfish Mining and Combining with an Eclipse Attack"
- Apostolaki, Zohar, Vanbever, "Hijacking Bitcoin" (IEEE S&P 2017) — btc-hijack.ethz.ch
- Buterin, "How I Learned to Love Weak Subjectivity" — blog.ethereum.org/2014/11/25/proof-stake-learned-love-weak-subjectivity
- Buterin, "Why Proof of Stake (Nov 2020)" — vitalik.ca/general/2020/11/06/pos2020.html
- Miller et al., "Honey Badger of BFT" — eprint.iacr.org/2016/199
- Daian et al., "Flash Boys 2.0" — arxiv.org/abs/1904.05234

### MPC and threshold signatures

- Gennaro, Goldfeder, "GG18" — eprint.iacr.org/2019/114
- Gennaro, Goldfeder, "GG20" — eprint.iacr.org/2020/540
- Lindell, "Lindell17" — eprint.iacr.org/2017/552
- Lindell et al., "Lindell18" — eprint.iacr.org/2018/987
- Canetti et al., "CGGMP21" — eprint.iacr.org/2021/060
- Doerner, Kondi, Lee, Shelat, "DKLs23" — eprint.iacr.org/2023/765
- Nick, Ruffing, Seurin, "MuSig2" — eprint.iacr.org/2020/1261
- Komlo, Goldberg, "FROST" — eprint.iacr.org/2020/852
- Ruffing et al., "ROAST" — eprint.iacr.org/2022/550
- IETF FROST draft — datatracker.ietf.org/doc/draft-irtf-cfrg-frost
- Coinbase `cb-mpc` — github.com/coinbase/cb-mpc
- Blockstream MuSig2 — blog.blockstream.com/musig2-simple-two-round-schnorr-multisignatures
- Blockstream FROST — blog.blockstream.com/the-key-to-frost-what-is-distributed-key-generation
- Verichains TSSHOCK — verichains.io/tsshock
- Trail of Bits MPC publications — github.com/trailofbits/publications

### Standards and EIPs

- BIP-32 (HD Wallets), BIP-39 (Mnemonic), BIP-44 (Multi-Account Hierarchy), BIP-340 (Schnorr), BIP-341 (Taproot), BIP-324 (v2 Transport) — github.com/bitcoin/bips
- EIP-712 (Typed Structured Data), ERC-2612 (Permit), ERC-4337 (Account Abstraction), EIP-1559 (Fee Market) — eips.ethereum.org

### Incident postmortems

- Mt. Gox: justice.gov DoJ indictment of Bilyuchenko and Verner (2023)
- Bitfinex 2016 / Razzlekhan-Lichtenstein arrest 2022 — justice.gov
- Coincheck January 2018, Bithumb 2017-2019 — multiple postmortems
- FTX collapse + SBF conviction — justice.gov SDNY
- Bybit February 2025 — NCC Group (nccgroup.com/research/), Elliptic "The largest theft in history" (elliptic.co/blog), TRM Labs (trmlabs.com), IC3 FBI confirmation (ic3.gov/psa/2025/psa250226)
- Ledger Connect Kit December 2023 — ledger.com/blog/security-incident-report; Sonatype, SlowMist, Blockaid, Checkmarx, Socket postmortems
- Wormhole Feb 2022 — halborn.com/blog/post/explained-the-wormhole-hack-february-2022; chainalysis.com/blog/wormhole-hack-february-2022
- Ronin March 2022 — halborn.com/blog/post/explained-the-ronin-hack-march-2022; chainalysis.com/blog/axie-infinity-ronin-bridge-dprk-hack-seizure
- Nomad August 2022 — halborn.com/blog/post/explained-the-nomad-hack-august-2022; cloud.google.com/blog/topics/threat-intelligence/dissecting-nomad-bridge-hack
- Multichain July 2023 — chainalysis.com/blog
- Ethereum Classic 51% attacks — ethereumclassic.org/blog; coinbase.com/blog

### Threat intel and forensics

- Chainalysis Crypto Crime Report — chainalysis.com/blog
- Elliptic — elliptic.co/blog
- TRM Labs — trmlabs.com/resources
- Mandiant "Not So Lazarus" / "DPRK 2023" — cloud.google.com/blog/topics/threat-intelligence
- SlowMist — slowmist.medium.com
- ZachXBT — zachxbt.live
- Wiz "TraderTraitor: Deep Dive" — wiz.io/blog/north-korean-tradertraitor-crypto-heist

### Wallet, custody, detection tools

- Fireblocks — fireblocks.com/what-is-mpc
- Coinbase `cb-mpc` — github.com/coinbase/cb-mpc
- Safe — safe.global; Argent — argent.xyz; Coinbase Smart Wallet — wallet.coinbase.com/smart-wallet; Squads — squads.so
- Blockaid — blockaid.io; Pocket Universe — pocketuniverse.app; Stelo; Wallet Guard — walletguard.app
- Forta — forta.org; OpenZeppelin Defender — defender.openzeppelin.com; Tenderly — tenderly.co; Hypernative — hypernative.io; Cyfrin — cyfrin.io; BlockSec — blocksec.com; GoPlus — gopluslabs.io
- SEAL — securityalliance.org

### Staking and consensus infrastructure

- Lido — lido.fi; Rocket Pool — rocketpool.net; EigenLayer — docs.eigencloud.xyz; Obol — obol.tech; SSV — ssv.network
- Flashbots MEV-Boost — github.com/flashbots/mev-boost; boost.flashbots.net; writings.flashbots.net

### Bridges

- LayerZero — docs.layerzero.network; Wormhole — wormhole.com; Axelar — docs.axelar.dev; Hyperlane — docs.hyperlane.xyz; IBC — ibcprotocol.dev
- "SoK: Cross-Chain Bridge Hacks 2023" — arxiv.org/abs/2501.03423

### Hardware wallet research

- Ledger Donjon — donjon.ledger.com
- Trezor — blog.trezor.io
- Kraken Security Labs — blog.kraken.com
- bunnie Huang — bunniestudios.com
- Coldcard — coldcard.com; Keystone — keyst.one

### Sanctions and regulatory

- OFAC SDN — treasury.gov/ofac/downloads/sdn.csv
- TC sanctions (Aug 2022) — home.treasury.gov/news/press-releases/jy0916
- Fifth Circuit TC ruling (Nov 2024); OFAC TC delisting (Mar 2025) — treasury.gov
- Roman Storm — justice.gov SDNY

### Community education

- ethereum.org/developers; solanacookbook.com; coinbase.com/blog
- Trail of Bits Building Secure Contracts — github.com/crytic/building-secure-contracts
- Cyfrin Updraft — updraft.cyfrin.io
- samczsun "Escaping the Dark Forest" — samczsun.com/escaping-the-dark-forest

---
