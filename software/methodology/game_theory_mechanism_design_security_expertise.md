# Game Theory and Mechanism Design for Security — Incentives, Auctions, and Adversarial Equilibria
## Synthesized from Bruce Schneier, Ross Anderson, Tyler Moore, Allan Friedman, Stefan Savage, Phil Daian, Alvin Roth, Eric Budish, and the WEIS / bug-bounty / cybercrime-economics research community

> **Researchers:**
> - **Bruce Schneier** (b. 1963) — American cryptographer and security technologist;
>   fellow at the Berkman Klein Center, lecturer at the Harvard Kennedy School, board
>   member of the EFF. Author of *Applied Cryptography* (1996), *Secrets and Lies* (2000),
>   *Beyond Fear* (2003), *Liars and Outliers: Enabling the Trust That Society Needs to
>   Thrive* (Wiley, 2012), *Data and Goliath* (2015), *Click Here to Kill Everybody*
>   (2018), and *A Hacker's Mind* (2023). *Liars and Outliers* is the canonical popular
>   treatment of security-as-trust-at-scale: it synthesizes game theory, sociology,
>   evolutionary biology, and security engineering into the four-pressures framework
>   (moral, reputational, institutional, security) for inducing cooperation in groups too
>   large for personal trust. The *Schneier on Security* blog (since 2004) is the
>   daily-newspaper-of-record for the field.
> - **Ross J. Anderson** (1956-2024) — British researcher and Professor of Security
>   Engineering at the University of Cambridge Computer Laboratory; passed away
>   unexpectedly 28 March 2024 at age 67. Author of *Security Engineering: A Guide to
>   Building Dependable Distributed Systems* (Wiley, 1st ed. 2001, 2nd ed. 2008, 3rd ed.
>   2020). Co-founder of the **Workshop on the Economics of Information Security (WEIS)**
>   with the first workshop at Berkeley in 2002, following his ACSAC 2001 paper *Why
>   Information Security is Hard — An Economic Perspective*, which established the field
>   of security economics as a discipline distinct from technical security. Fellow of the
>   Royal Academy of Engineering (2009), BCS Lovelace Medal (2015), Royal Society of
>   Edinburgh (2023). Pioneer of hardware tamper-resistance, API analysis, security
>   usability, and the foundational claim that security failures are most often
>   misaligned-incentive failures rather than technical failures.
> - **Tyler Moore** (PhD Cambridge under Ross Anderson) — Tandy Professor of Cyber
>   Security and Information Assurance at the University of Tulsa; Director of the TU
>   Security Economics Lab; founding editor-in-chief of the *Journal of Cybersecurity*
>   (Oxford University Press). Long-running WEIS co-organizer. Research span:
>   phishing-site-takedown economics, cybercrime cost measurement, Bitcoin security, the
>   patching-as-public-good problem, and the empirical study of vulnerability markets.
> - **Allan Friedman** — former Senior Advisor and Strategist at the Cybersecurity and
>   Infrastructure Security Agency (CISA), which he left in July 2025; previously Director of Cybersecurity
>   Initiatives at NTIA, where he led the multi-stakeholder process that produced the
>   Software Bill of Materials (SBOM) standard. Widely known as the "Father of the SBOM."
>   Prior decade at Harvard Computer Science, the Brookings Institution, and George
>   Washington University Engineering. His policy-economics work is the bridge from
>   academic security-economics into operational federal cybersecurity strategy: SBOM,
>   coordinated vulnerability disclosure, and the EU Cyber Resilience Act adoption.
> - **Stefan Savage** — Professor of Computer Science, University of California San
>   Diego; ACM Prize in Computing (2015), MacArthur Fellowship, National Academy of
>   Engineering. Co-author with Geoffrey M. Voelker (UCSD) and Vern Paxson (UC Berkeley)
>   of *Click Trajectories: End-to-End Analysis of the Spam Value Chain* (IEEE S&P 2011)
>   — the canonical study that turned abuse research from pattern-matching into
>   supply-chain economics. The Click Trajectories paper found that spam-pharmaceutical
>   campaigns funneled through a handful of acquiring banks, making the
>   payment layer a far more concentrated intervention point than blocking the spam
>   itself. Savage's research program is the canonical "follow the money" approach to
>   cybercrime.
> - **Philip Daian** (PhD Cornell Tech) — Co-founder of **Flashbots**
>   (2020); previously IC3 (Initiative for CryptoCurrencies and Contracts). Co-author
>   with Steven Goldfeder, Tyler Kell, Yunqi Li, Xueyuan Zhao, Iddo Bentov, Lorenz
>   Breidenbach, and Ari Juels of *Flash Boys 2.0: Frontrunning, Transaction Reordering,
>   and Consensus Instability in Decentralized Exchanges* (arXiv 1904.05234, IEEE S&P
>   2020), which introduced the term **Miner Extractable Value (MEV)** — later
>   generalized to **Maximal Extractable Value** post-Merge. Flashbots subsequently
>   designed the **Proposer-Builder Separation (PBS)** architecture (MEV-Boost) that >90%
>   of Ethereum validators now use.
> - **Alvin E. Roth** (b. 1951) — Craig and Susan McCaw Professor of Economics at
>   Stanford University; Gund Professor emeritus at Harvard. Awarded the 2012 Nobel
>   Memorial Prize in Economic Sciences (with Lloyd Shapley) for the theory of stable
>   allocations and the practice of market design. Roth's research pioneered the
>   "microeconomic engineering" stance: matching markets for medical residents, kidney
>   exchange, public-school choice, and labor markets that do not clear by price. Author
>   of *Who Gets What — and Why: The New Economics of Matchmaking and Market Design*
>   (HMH, 2015). Not a security researcher, but the canonical mechanism-design framework
>   anchor for any auction, matching, or contract-design problem in security operations.
> - **Eric B. Budish** — Paul G. McDermott Professor of Economics and Entrepreneurship at
>   the University of Chicago Booth School of Business. Author with Peter Cramton and
>   John J. Shim of *The High-Frequency Trading Arms Race: Frequent Batch Auctions as a
>   Market Design Response* (*Quarterly Journal of Economics*, 2015). The paper
>   diagnoses the continuous-limit-order-book arms-race for trading speed as a
>   market-design failure rather than a technology failure, and proposes uniform-price
>   double auctions on a sub-second cadence as the structural remedy. The framework
>   transplants directly to MEV-mitigation in decentralized exchanges.
> - **WEIS / bug-bounty / cybercrime-economics research community** — L. Jean Camp
>   (Indiana), Rainer Böhme (Innsbruck), Marie Vasek (UCL), Sasha Romanosky (RAND),
>   Mingyan Liu (Michigan), Cormac Herley (Microsoft Research), Galina Schwartz (UC
>   Berkeley), Andreas Kuehn / Milton Mueller (Syracuse), and the HackerOne / Bugcrowd /
>   Intigriti / YesWeHack platform-economics teams. These researchers form the rotating
>   community that has run WEIS since 2002 and produced the empirical literature on
>   bug-bounty pricing, cyber-insurance market failure, abuse economics, and
>   policy-intervention measurement.
>
> **Sources:** Anderson, *Security Engineering* (Wiley, 3rd ed. 2020); Anderson, *Why
> Information Security is Hard — An Economic Perspective* (ACSAC 2001); Schneier, *Liars
> and Outliers* (Wiley, 2012) and `https://www.schneier.com/blog`; Workshop on the
> Economics of Information Security (`https://econinfosec.org`); Moore, *Journal of
> Cybersecurity* (Oxford UP); Daian et al., *Flash Boys 2.0* (arXiv 1904.05234);
> Flashbots documentation (`https://docs.flashbots.net`); Roth, *Who Gets What — and
> Why* (HMH, 2015); Budish, Cramton, Shim, *The High-Frequency Trading Arms Race* (QJE
> 2015); Levchenko et al., *Click Trajectories* (IEEE S&P 2011); HackerOne / Bugcrowd /
> Intigriti / YesWeHack platform documentation; Crowdfense and Zerodium public payout
> schedules; CISA SBOM documentation; EU Cyber Resilience Act (Reg. EU 2024/2847); OFAC
> cyber-sanctions advisories.

---

## 1. The framing — security as a game-theoretic problem

### Defenders and attackers are strategic actors with payoffs

Stop treating attackers as natural hazards; start treating them as strategic agents
with budgets, time horizons, and reservation prices. Weather is a stochastic process;
an attacker is a player. The defender's optimal posture against weather (insure against
the tail; harden against the mean) is structurally different from the defender's
optimal posture against an adversary who observes the defense, updates, and re-attacks.

This shift — hazard-frame to game-frame — is the load-bearing move in the
Schneier-Anderson tradition. Three immediate consequences:

1. **The defender's posture is a strategy in a game**, not an engineering specification.
   The question is no longer "is the system secure?" but "what does the attacker do at
   the equilibrium given the defender's posture?"
2. **Investment decisions depend on attacker payoffs**, not just defender costs. A
   defense that imposes $10K on the attacker is meaningless if the attacker's payoff
   from success is $10M.
3. **Equilibria are sometimes worse than no defense at all.** A defense that signals
   asset valuation may invite more attack (the "honeypot paradox" and "bug-bounty
   signaling" effects of §2).

### The "cost-to-attack vs cost-to-defend" framing

The simplest model: attacker with cost-to-attack `C_a` and value-on-success `V_a`,
defender with cost-to-defend `C_d` and loss-on-success `L_d`. Attacker attacks iff
`V_a > C_a`; defender defends iff `C_d < L_d * P(attack)`. The defender's defense raises
`C_a`, typically by a factor far less than `C_d`.

Three structural failure modes:

- **Defender pays full freight, attacker bears amortized cost.** A defender pays `C_d`
  once per asset; an attacker pays `C_a` once per attack class and amortizes across all
  defenders running the same software. This is the structural argument for monoculture
  risk.
- **Defender's value is private; attacker estimates it from observables.** Advertised
  revenue, customer count, breach disclosure, hardening budget — all reveal `L_d` to
  sophisticated attackers (the "honeypot tell").
- **Defender chooses first** — the Stackelberg-leader position. The defender's optimal
  posture is to maximize the minimum-`C_a` across attacker classes whose `V_a > C_a`;
  defense should bind on the marginal attacker, not the median.

Cross-link to `anti_fraud_abuse_engineering_expertise.md` §1 (adversary-economics):
the abuse-engineering tradition extends this to repeated-game, multi-vendor,
multi-victim settings where attacker reputation across victims is a strategic variable.

### The Schneier "trust at scale" framework

Schneier's *Liars and Outliers* (2012) reframes the entire security project as a
**cooperation-induction problem**. In small groups, cooperation is enforced by personal
trust: I know you, defection is socially visible. At scale, personal trust fails; we
need procedural substitutes. Schneier names four **societal pressures** that induce
cooperation in groups too large for personal trust: moral, reputational, institutional,
security (treated in detail in §10).

The framework's punchline: **defectors are inevitable**. The right question is not "how
do we eliminate defection?" (pressure cost approaches infinity as defection rate
approaches zero) but "how do we keep defection below the rate at which it disrupts
cooperation?" This is the design constraint that frames every security program.

### Why ad-hoc security is a coordination failure, not a technology failure

Anderson's *Why Information Security is Hard* (2001) made the foundational claim that
most security failures are misaligned-incentive failures, not technical failures. The
canonical example: a bank's online banking has a fraud problem; the bank could deploy
stronger authentication, but the fix costs more than the fraud losses the bank itself
bears (because, in Anderson's UK example, banks could shift liability for disputed
transactions onto customers). The
bank's privately-optimal posture is to accept the fraud; the socially-optimal posture
requires regulatory intervention.

This generalizes to **patching-as-public-good** (§5), **responsible-disclosure timing**
(§2), **SBOM-adoption** (§5, §12), and **TLS-CA-trust-root** (§5). The technical
solution is well-understood; the deployment failure is incentive-driven.

The implication for staff researchers: when a vulnerability class appears widely
deployed despite obvious technical fixes, the diagnosis is almost never "engineers
don't know better." It is "the engineers who would fix it are not the engineers who
bear the cost of not fixing it." Frame remediation as incentive-realignment, not
technical fixes.

---

## 2. Bug bounty pricing — auction theory applied

### The "race-to-the-bottom" criticism of bug bounty programs

Bug bounty programs are reverse auctions: many independent suppliers (researchers)
compete to deliver an asset (a vulnerability report) to a single buyer (the program
owner) at a price set by the buyer's policy schedule. Three structural reasons the
two-sided market drives researcher compensation toward the lower-tail of asset value:

1. **Duplicate submission resolution as Bertrand-competition simulation.** Most
   platforms pay only the first valid submitter. With N researchers hunting the same
   surface, expected payout per researcher is `bounty / N` — Bertrand competition with
   N-1 researchers getting zero.
2. **Severity-rating asymmetry.** The platform owner unilaterally rates severity; the
   researcher cannot effectively contest a low rating.
3. **Out-of-scope rejection risk.** Issues outside narrowly-defined scope are not paid;
   hunting cost is sunk.

The empirical literature (Sridhar & Ng, *Journal of Cybersecurity*, 2021, on HackerOne
data) finds price elasticities for security-researcher labor supply
between 0.1 and 0.2 at the median — researchers are motivated by non-pecuniary factors
(reputation, skill development, intrinsic interest), and increasing bounty payouts has
very low marginal effect on hunting hours.

### Crowdfense / Zerodium / Trenchant pricing as reverse-auction

The high-end of the vulnerability market is structurally different. **Zerodium**
(founded 2015) was the first platform to publish a full pricing chart: $5K to $1.5M per
exploit at launch, rising to $2.5M for full-chain zero-click Android and $2M for iOS
by 2024. **Crowdfense** (founded 2017, UAE-based) raised the ceiling: up to $9M for
zero-click SMS/MMS full-chain, $7M iOS, $5M Android, $2M-$3M Chrome, $2.5M-$3.5M Safari, $3M-$5M
WhatsApp/iMessage as of 2024.

These markets have three load-bearing features:

1. **Buyer-side concentration.** A small number of government/contractor buyers command
   the demand side; the platform aggregates and intermediates.
2. **Asset-substitutability is low.** A Chrome zero-click is not a substitute for an
   iOS zero-click; the buyer wants the specific capability.
3. **Asset-perishability is high.** The exploit's value drops to zero on patch.

Crowdfense's higher prices vs Zerodium signal three things: demand has shifted right;
defender hardening has shifted supply left; and the platform is competing for supplier
loyalty by leading on price (price-leadership in a duopoly).

### The signal-jamming problem: bounty pricing reveals defender's defensive depth

A bounty schedule is a price list; a price list is a signal of valuation. A vendor that
pays $1M for an RCE in product X is publicly stating they value preventing such an RCE
at >$1M. A sophisticated attacker reads the schedule and updates effort allocation:
high-bounty surfaces are well-defended, so the marginal hour of attacker effort produces
more value on **unbountied-but-equally-valuable surfaces** belonging to vendors that
haven't published.

The literature has not fully characterized the equilibrium implications; the operational
heuristic is that **bounty schedules should be published as ranges, not point values**,
and that the vendor should periodically randomize within the range to inject noise into
the signal.

### HackerOne / Bugcrowd / Intigriti / YesWeHack market dynamics

The four major Western platforms are a near-oligopoly. Three operational dynamics:

- **Researcher reputation as the multi-platform binder.** A researcher's reputation
  travels across platforms (Twitter handle, HackerOne profile, conference history); the
  platforms do not.
- **Triage-and-resolution-time SLA as the program-side quality signal.** Slow triage
  drives researchers away; the platform displays median-time-to-resolution publicly. A
  program with >30-day triage loses access to top researchers regardless of bounty
  schedule.
- **Private-program vs public-program asymmetry.** Private programs invite a curated
  researcher pool; public programs are open. Private programs receive higher quality
  submissions at lower bounty cost — price discrimination by researcher quality at the
  cost of crowd size.

### The "researcher reputation" multiplier (top-X percentile bounty bonuses)

Top researcher bonuses are a structural feature of platform
economics. The rationale is information-revelation: a researcher's past behavior is the
best predictor of future submission quality, and the platform internalizes this by
paying for it. The criticism is that the system amplifies winner-take-most dynamics. The defense is that the
variance reduction is socially efficient and the inequality is a feature of the
platform's information-extraction mechanism.

### Vulnerability disclosure as a contract-completeness problem

A bug-bounty submission is a contract-completion: the researcher delivers an asset, the
program delivers payment plus protective treatment. The contract is **incomplete**: most
clauses are ambiguous or unstated (what constitutes a valid submission, embargo
violation, researcher misbehavior — all judged by the program post-hoc).

The contract-completeness literature (Hart, Moore, Williamson) predicts incomplete
contracts generate **hold-up problems**: the party with residual control rights (the
program) can extract surplus from the other party (the researcher) after the asset is
delivered. Empirically this manifests as researchers being denied bounties they expected
or paid lower amounts than the schedule suggested.

Cross-link to `vulnerability_research_methodology_expertise.md` §15 (VR economics): the
methodology side asks "what should I hunt next?" given the contract; the economics side
asks "how should the contract be structured to align incentives?"

### The CRA Article 14 mandatory-disclosure regime

The EU **Cyber Resilience Act** (Regulation EU 2024/2847, in force 10 December 2024,
mandatory compliance December 2027) imposes coordinated-vulnerability-disclosure
obligations on every vendor placing digital products on the EU market. Article 14
requires a 24-hour early warning of actively-exploited vulnerabilities to the CSIRT
coordinator and ENISA, a 72-hour notification, and a final report within 14 days after a
corrective measure is available. Researcher safe-harbor is implicit
but not strongly codified; the CVD framework is explicit and references ISO/IEC 29147
and 30111.

The CRA's economic logic shifts the cost-bearing structure: vendors now bear
notification cost as a fixed compliance overhead; researcher safe-harbor reduces the
legal-exposure variance. The expected effect is higher researcher participation,
moderately lower bounty prices, and a shift of disclosed-vulnerability volume into
formal platform channels. Cross-link to `cicd_supply_chain_expertise.md`.

---

## 3. MEV economics — the on-chain instantiation

### Maximal Extractable Value as a worst-case adversarial-equilibrium playground

The Ethereum mempool is the cleanest empirical laboratory for adversarial-equilibrium
game theory the field has ever seen. Every transaction is public, every block is
deterministic, every order is sequenced by a known auction-like mechanism, and payoffs
are denominated in dollars on a public ledger.

The foundational paper, Daian et al., *Flash Boys 2.0* (arXiv 1904.05234, IEEE S&P
2020), introduced **Miner Extractable Value (MEV)** — value extractable by miners
through control of transaction ordering, beyond the protocol-defined block reward.
Post-Merge (September 2022), the term was generalized to **Maximal Extractable Value**
to capture extraction by validators, builders, searchers, and proposers in the
proof-of-stake architecture. The paper documented frontrunning bots and named the
**Priority Gas Auction (PGA)**: searcher bots competitively bid up transaction fees to
obtain priority ordering.

### Sandwich attacks as quasi-Cournot competition

A sandwich attack: a searcher observes a pending user trade T on a DEX, front-runs T
with a buy transaction B1, lets T execute (now at a worse price because of B1's market
impact), and back-runs with a sell B2. The searcher captures the spread; the user pays
it in slippage.

The competition between searchers running sandwich strategies on the same target T is
structurally a **Cournot competition**: multiple searchers independently choose the
size of their B1. The aggregate B1 determines the spread; the equilibrium is the
standard Cournot quantity. Two operational consequences:

- **More searchers → more user slippage**, holding everything else constant. The
  searchers compete with each other for the user's slippage, not for the user's
  business.
- **The user's defense is to commit to maximum slippage in the trade order**, which caps
  the searchers' aggregate B1. This is why modern DEXes default to 0.5%-1.0% slippage
  caps.

### JIT (Just-In-Time) liquidity as sniping

A **JIT liquidity** strategy on Uniswap V3 concentrated-liquidity pools: an LP deposits
liquidity in a narrow band right before a known large user trade T executes, collects
the trade fee, then withdraws immediately after. The LP captures the fee but provides
liquidity for zero time outside the trade window.

This is the **sniping** strategy from online-auction theory: the LP times participation
to the moment of highest reward and exits immediately. The victim is the long-term LP
whose liquidity would otherwise have earned the trade fee. Uniswap V4's hook
architecture allows pool designers to charge JIT LPs a withdrawal penalty or credit
fees to long-term LPs only — structurally the same defense as Amazon auctions' automatic
extension rule (Roth & Ockenfels 2002) against timed-bid sniping.

### Order-flow auctions (CowSwap, UniswapX) as second-price auctions

The MEV-mitigation literature has converged on **order-flow auctions (OFAs)**. Instead
of broadcasting the user's trade to a public mempool subject to front-running, the user
submits an **intent** (what they want to swap, what they will accept) to an off-chain
**solver** network. Solvers competitively bid to fill the intent; the winning fill
settles on-chain.

CowSwap's batch auction freezes a ~30-second window of intents, ships them to solvers,
and selects the solver whose proposed solution maximizes user welfare across all
intents — including coincidence-of-wants (CoW) settlements where two users' intents
fill each other directly without touching an AMM. The auction is structurally a
**second-price (Vickrey) auction**: the winning solver's payoff is the difference
between their solution's user-surplus and the second-best solver's user-surplus, making
truthful bidding the dominant strategy for solvers.

UniswapX implements a Dutch auction where initial fill-price is set by an off-chain
pricing oracle and decays over time until a solver fills. Empirical analysis (Bachu, Wan &
Moallemi, 2024) of UniswapX and 1inch Fusion finds statistically significant price
improvement, averaging 4-5 basis points.

### Frequent batch auctions (Budish-Cramton-Shim) — proposed remedy

Budish, Cramton, and Shim's *The High-Frequency Trading Arms Race* (*QJE* 2015)
diagnoses the continuous-limit-order-book in traditional equity markets as a
**market-design failure**: continuous time creates inevitable mechanical-arbitrage rents
that incentivize a socially wasteful arms-race for trading-speed. The proposed remedy:
replace continuous matching with **frequent batch auctions** at sub-second cadence
(e.g., 100ms uniform-price double auctions).

The argument transplants directly to MEV. Continuous block-by-block sequencing is the
on-chain analog of the continuous limit-order book; the PGA arms-race is the on-chain
analog of the HFT speed-race; the structural remedy — replace continuous ordering with
batch auctions — is precisely what CowSwap and modern intent-based DEX architectures
implement.

The remaining open question: should the **base layer** (consensus) move to a
batch-auction sequencer (SUAVE, Anoma), or is per-application batch mitigation
sufficient? The field's consensus as of 2026 is that per-application batch mitigation
captures most of the welfare gain.

### Proposer-Builder Separation (PBS) — Flashbots' partial mitigation

**PBS** separates two roles: **builders** assemble blocks; **proposers** (validators)
commit blocks. Flashbots' **MEV-Boost** implements out-of-protocol PBS; >90% of
Ethereum validators run MEV-Boost as of 2026. PBS decouples the centralization-risk of
MEV extraction (sophisticated builders) from the decentralization-requirement of
consensus (many validators). The criticism: PBS **centralizes the builder layer** —
three builders (beaverbuild, rsync, Titan) produced ~80% of MEV-Boost blocks from
October 2023 to March 2024, creating a single-point-of-control for transaction censorship (OFAC-
sanctioned address censorship observed 2022-2023). Mitigation: **enshrined-PBS (ePBS)**
with cryptographic censorship-resistance. Cross-link to
`blockchain_wallet_consensus_security_expertise.md` §8.

---

## 4. Ransomware-payment game theory

### The "should we pay?" decision under uncertainty

The ransomware-payment decision is the cleanest practical game-theory problem an
executive will ever face. The defender's data is encrypted; the attacker offers
decryption for a ransom. The game has two sequential moves with private information
(defender's data-valuation; attacker's reputation-cost of not delivering).

The literature (Cartwright & Castro, *Journal of Cybersecurity*, 2019; Caporusso, 2018) converges on five operational findings:

1. **Patience asymmetry favors the attacker.** The defender's recovery time horizon is
   short; the attacker's negotiation horizon is long. Bargaining theory predicts the
   more-patient party captures most of the surplus.
2. **Optimal ransom is the defender's data-valuation minus outside-option cost**
   (backup-restoration, data-loss acceptance, legal action with essentially zero
   recovery).
3. **Bargaining helps the defender only when backups are credible.** A working backup
   provides a walk-away threat; the attacker should reduce demand to keep payment
   incentive-compatible.
4. **Repeated game with attacker reputation matters.** Long-running campaigns (REvil,
   Conti, LockBit, BlackCat, ALPHV) make "delivers the key" a strategic reputation
   asset.
5. **Bayesian uncertainty over operator type drives strategy.** The defender cannot
   distinguish "professional" from "amateur/destructive" operators; payment is a
   Bayesian-update problem.

### Repeated game vs one-shot — operator reputation matters

The repeated-game framing has three operational consequences: operators publish "wall
of shame" leak sites (textbook **costly signaling**); operators run "negotiation
portals" with consistent tone and SLA (lower defender's posterior probability of
destructive operator type); operators offer proof-of-decryption on sample files (solves
credible-commitment problem). Defender countermeasures: verify backup integrity offline
before any communication; do not engage in early communication (latency is your friend
in bargaining); establish in advance an organizational position on payment.

### Coordination among victims vs free-rider problem

The aggregate-defender problem is a **collective-action problem** (Olson 1965). If no
defender pays, ransomware becomes unprofitable; if one pays, the attacker class
continues, with the paying defender free-riding on resistance. The Nash equilibrium is
that **at least some defenders pay**. Coordination devices (national CSIRT "do not pay"
guidance, industry no-pay pledges, OFAC sanctions, insurance-pool no-pay riders) shift
the equilibrium toward non-payment by raising individual cost of payment.

### Insurance + payment-coverage's perverse incentive effect

A cyber-insurance policy that covers ransom payment creates **moral hazard**: the
insured defender has reduced incentive to invest in prevention; the attacker can target
insured-defender populations preferentially because the payment-conversion rate is
higher.

Market responses followed: several
large insurers (AIG, Chubb, Lloyd's syndicates) introduced ransom-payment carve-outs or
co-pay structures starting 2022. France's January 2023 LOPMI law made ransom-payment-
coverage conditional on filing a criminal complaint within 72 hours, attempting to
convert insurance moral hazard into an investigation incentive.

### Government-policy interventions (OFAC sanctions on specific ransomware groups)

OFAC sanctions against operators (Evil Corp 2019, REvil 2021, Trickbot 2023, LockBit
2024) make ransom payment to designated entities a federal crime for U.S. persons. The
defender's payoff shifts to "ransom + recovery − OFAC-fine probability × fine magnitude
− DOJ prosecution risk." For large defenders the OFAC term dominates; payment is
unprofitable in expectation. The criticism (imposes costs on victims, not operators) is
rebutted by the collective-action argument: any victim-side intervention is essential
because individually-rational payment keeps the operator class profitable. Cross-link
to `dfir_methodology_expertise.md` §11.

### The "ransom-as-percentage-of-revenue" disclosure correlation

Coveware publishes quarterly statistics on median ransom demand and payment.
The interpretation of ransom sizing: operators perform revenue-discovery through automated OSINT
(company filings, employee count, industry classification) and price-discriminate
accordingly — textbook **first-degree price discrimination**. Defender-side
implication: **revenue-suppression of OSINT** is a low-cost mitigation.

---

## 5. Coordination problems + commitment devices

### Patching as a coordination problem

Patching is a textbook **public-goods** problem. Each defender's patching cost is
private (engineering time, downtime, regression risk). The benefit is partially public
(a patched defender no longer hosts a vulnerable instance attackers pivot from).
Defenders under-patch relative to the social optimum because they internalize private
cost but not public benefit. Empirical measurement (Mirai IoT persistence; long tail of
unpatched ProxyShell and Log4Shell) bears this out.

Three policy mechanisms shift the equilibrium: **mandatory disclosure with deadlines**
(CRA Article 14, NIS2, CISA BOD 22-01); **vendor-side EOL coordination** (Patch Tuesday,
Linux LTS cycles); **insurance-premium discounts for patched populations**.

### The "tragedy of the commons" in shared infrastructure (DNS, BGP, TLS roots)

Common-pool resources at Internet scale exhibit **tragedy-of-the-commons** dynamics:
**DNS namespace** (speculative registration; ICANN-WIPO UDRP response), **BGP routing**
(mis-announcements cause global routing failures — YouTube/Pakistan 2008, Amazon Route
53 2018; RPKI response: ROAs cover ~67-70% of routed prefixes as of 2026), **TLS CA trust roots** (mis-
behaving CAs like DigiNotar 2011 and Symantec 2017-2018 impose global trust costs;
Certificate Transparency response).

In each case, the **coordination mechanism is a transparency/audit infrastructure**: a
common audit log makes deviations detectable; the threat of detection induces
compliance.

### Time-locked commitment in software-update auctions

When a vendor discloses a vulnerability with a patch, every defender races to patch
before attackers reverse-engineer the patch. The N-day window is empirically 1-21 days.
The **time-lock commitment** mechanism is for the vendor to commit to a specific window
during which the patch is not publicly distributed but is available to privileged
defenders. The window provides head-start against patch-diffing-based exploitation.

The criticism is that **time-locked patches privilege large enterprises** over small
businesses. The defense is that patch-distribution lag is roughly proportional to
defender-side patch-deployment capability anyway; the time-lock formalizes the
asymmetry.

### Bilateral coordination via vulnerability-disclosure

A vulnerability disclosure between researcher and vendor is a **bilateral coordination
problem with private information**. The CERT/CC coordinated-disclosure framework, ISO/IEC
29147/30111, and the CRA CVD obligations are progressively-stronger formalizations
that reduce uncertainty about disclosure timing, embargo duration, credit-assignment,
and legal-protection.

The structural finding: **codified disclosure norms reduce researcher-vendor
contracting cost** and shift the equilibrium toward more disclosure. Researchers who
fear vendor retaliation under-disclose; codified safe-harbor reduces fear, increasing
disclosure volume and quality.

### Sigstore as a coordination mechanism for supply-chain trust

The supply-chain trust problem is a multi-party coordination problem: a developer
publishes a package; a downstream consumer wants to verify provenance; the registry
hosts; the build infrastructure produces the artifact. **Sigstore** (Linux Foundation /
Google / Red Hat / Chainguard) is the public-good coordination mechanism: developers
sign artifacts with ephemeral keys issued by a public CA (Fulcio); signatures are
published to a public append-only log (Rekor); consumers verify the signature chain
back to the developer's OIDC identity.

The economic claim is that Sigstore reduces the coordination cost of supply-chain
verification from O(N²) (each developer-consumer pair separately establishes trust) to
O(N) (each developer establishes identity once; each consumer verifies against the
common log). Canonical infrastructure-economics argument for public-good audit logs.
Cross-link to `supply_chain_provenance_expertise.md`.

### DNS namespace as common-pool resource

The DNS namespace exhibits **rivalrous-use** (a domain registered to one party is
unavailable to others) and **exclusion-by-registry**. The empirical pathologies —
domain-squatting, typo-squatting, IDN homoglyph attacks, expired-domain takeover for
malware delivery — are textbook common-pool over-exploitation. Mitigations (typo-squat
detection, IDN-display normalization, expired-domain-passive-DNS monitoring) are
tertiary; the structural fix would be a namespace re-design with stronger
natural-language anchoring, which has been politically unachievable.

---

## 6. Adversarial-search game theory

### Capture-the-flag dynamics as zero-sum game

CTF competitions are the cleanest pedagogical implementation of two-player zero-sum
security games. Three pure-strategy / mixed-strategy distinctions worth carrying into
operational security: **pure-strategy** (deploy the best defense you have — optimal
when you know the attacker's strategy ex ante); **mixed-strategy** (randomize among
defenses — optimal when the attacker can adapt); **information-asymmetry exploitation**
(hide your defense — the attacker's strategy is suboptimal against your specific
posture). Operational analog: SOC custom detection content (Sigma, SPL, KQL) is the
information-asymmetric layer; EDR-vendor signatures are public.

### Red-team vs blue-team as repeated game

Internal red-team engagements run as **repeated game** over months-to-years against the
same blue team. The repeated-game structure favors equilibria where red-team escalates
technique sophistication over time, blue-team builds detection content reactively, and
both converge on a **mutual-improvement equilibrium**.

This is the **TIT-FOR-TAT in iterated prisoner's dilemma** dynamic that Rapoport and
Axelrod identified: cooperative behavior emerges from repeated interaction even when
single-shot defection would be individually rational. The red-team/blue-team
collaboration only works because both sides are committed to organizational improvement
rather than individual win-rates. Cross-link to `steelman_doctrine_expertise.md` for
the institutional pattern.

### Pen-testing engagement contracting as principal-agent problem

A penetration test is a **principal-agent contract**: the client wants finding-
discovery; the pen-tester wants billable hours. Interests are imperfectly aligned
because client cannot observe effort directly (only outputs); pen-tester's reputation
is a long-term variable. Contract structures:
- **Time-and-materials** (most common for boutique pen-testing): aligns effort to
  billable hours but provides no incentive for finding-quality.
- **Fixed-price with deliverable** (most common for compliance-driven pen-testing):
  caps client cost but incentivizes minimal effort.
- **Outcome-based** (rare): pays per finding with severity multipliers. Aligns
  incentives tightly but exposes the pen-tester to scope-and-severity disputes.

The empirical equilibrium is **firm-reputation-mediated time-and-materials**: the
firm's multi-engagement reputation substitutes for contractible-effort verification.

### Adversarial-emulation (Atomic Red Team) as common-knowledge attack catalog

**MITRE ATT&CK**, **Atomic Red Team**, and **Caldera** are public-good catalogs of
adversarial techniques mapped to detection coverage. They function as a
**common-knowledge equilibrium-shifter**: when every defender knows every attacker
technique, the attacker's information advantage is reduced. Three effects:

1. **Attackers innovate more** (raises cost-of-attack).
2. **Defenders coordinate better**: a SOC running Atomic Red Team can quantify which
   ATT&CK techniques their EDR catches; this is a measurable benchmark that did not
   exist pre-ATT&CK.
3. **Vendor competition intensifies**: EDR vendors compete on ATT&CK-coverage
   benchmarks.

Cross-link to `detection_engineering_expertise.md` §5 (detection-as-code).

---

## 7. Mechanism design — auction primitives for security

### First-price vs second-price (Vickrey) auctions

**First-price** sealed-bid (highest bidder wins, pays their bid) invites **bid-shading**
below true valuation; equilibrium computation requires common-knowledge assumptions on
the distribution of valuations.

**Second-price (Vickrey)** (highest bidder wins, pays second-highest bid) is
**strategy-proof**: dominant strategy is to bid true valuation. Two security advantages:
**truthful revelation** (same property exploited by CowSwap's second-price solver auction in §3) and
**simple computation** (no need to estimate competitors' valuations). Disadvantage:
**seller-misrepresentation vulnerability** (shill second-highest bid); defense is
third-party auctioneer attestation or cryptographic sealed-bid commitments.

Second-price is dominant when truthful revelation is the design goal; first-price when
revenue maximization is the goal AND valuations are tightly clustered.

### Sealed-bid vs open-outcry

**Open-outcry** reveals information as bidding proceeds; **sealed-bid** reveals nothing
until close. Sealed-bid is preferred when post-auction privacy matters (vulnerability
purchasers don't broadcast interest); open-outcry produces better price discovery in
thin markets but is more vulnerable to collusion (signaling during bidding). For
bug-bounty design, the empirical equilibrium is **policy-schedule disclosure with
sealed researcher submission**.

### Best-bid-loses (lottery) for pen-test contractor selection

A counter-intuitive procurement mechanism: **best-bid-loses
lottery** — the LOWEST bid is excluded, the contract awarded by lottery among remaining
bidders. Discourages bid-shading races where bidders have asymmetric costs. For pen-test
contractor selection, **exclude the lowest-bid contractor (presumed under-investment)**
and randomize among the rest. Rarely used in practice; most procurement uses
bid-evaluation with qualitative scoring, which suffers from gameability.

### VCG (Vickrey-Clarke-Groves) mechanisms for "best truthful bid"

**VCG** generalizes Vickrey to multi-item, multi-bidder allocation: each participant
bids; allocation is welfare-maximizing; each winner pays the **externality they impose
on others**. Canonical strategy-proof mechanism for multi-item allocation, though seldom used in
practice (Ausubel & Milgrom, "The Lovely but Lonely Vickrey Auction"). For bug-bounty
multi-submission resolution, VCG could allocate the bounty in proportion to each
submission's marginal contribution; in practice, common-knowledge valuations are
absent and computational complexity (NP-hard in general) makes deployment impractical.

### The Myerson revenue-equivalence theorem and its security applications

Myerson's **revenue-equivalence theorem** (1981) states that under symmetric
independent-private-value assumptions, all standard auctions generate the same expected
revenue. Operationally important failure conditions: **asymmetric bidders** (first-price
extracts more from high-valuation bidder); **risk-averse bidders** (first-price extracts
more because risk-averse bidders shade less); **common-value components** introduce the
**winner's curse**.

For zero-day acquisition (§2), bidders are highly asymmetric (government agency vs
private buyer) with strong common-value components; revenue-equivalence fails. Empirical
equilibrium is **first-price-like with strategic bidding by the dominant buyer**.

### Roth's market-design lineage applied to security contracting

Roth's **microeconomic engineering** (Roth 2015) addresses markets that **do not clear
by price**: medical residency matching, kidney exchange, public-school choice. The
mechanism is structured matching with deferred-acceptance algorithms, not auction-style
price discovery. Transplanted to security:
- **Researcher-to-program matching** is a matching market, not price-clearing.
- **Disclosure-coordination matching** (which researcher coordinates with which
  vendor's PSIRT). CERT/CC functions as a Roth-style matchmaker.
- **Incident-response capacity matching**: clients prefer IR firms with deep prior
  knowledge of their environment, even if spot price is higher.

Where prices fail to clear, **structured matching with algorithmic-allocation** is the
canonical response.

---

## 8. Incentive design for security programs

### Engineer-bonus structures for security-finding-fixing

Most engineering compensation pays for feature delivery, not finding remediation. Three
structural fixes: **security-fix attribution in performance reviews** (line-items);
**security-debt budgets** (allocate engineering time explicitly); **security-champion
stipends** ($1K-$5K per quarter, institutional recognition). Cross-link to
`appsec_program_building_expertise.md` §8.

### "Security champion" programs as principal-multi-agent

A security champion program is a **principal-multi-agent** structure with three failure
modes: information bottleneck at the champion; role-confusion (agent of security vs
engineering); champion turnover with onboarding cost. Empirical practice: champions
are agents of engineering with security-team support (not security-team-spies); explicit
time budget ~10-20%; rotate every 12-18 months.

### Bounty-vs-fixed-bug-reward tradeoffs

**Bounty schedules** capture researcher heterogeneity better; **fixed rewards** avoid
severity-rating disputes and reduce administrative overhead. The empirical equilibrium
is **bounty schedules for high-value programs, fixed rewards for low-volume programs**;
the crossover (~50-100 submissions per year) is where the administrative cost of
disputes overtakes the researcher-segmentation benefit.

### The "punish-bad-code" vs "reward-good-code" empirical literature

The empirical literature (Reason 1997 on human error; Hollnagel 2014 on resilient
engineering; the blameless-postmortem corpus) converges on: **reward good behavior;
investigate bad outcomes without assigning individual blame**. The "no-blame postmortem"
practice from DevOps implements this. Punishing individuals for systemic failures
suppresses information flow; rewarding proactive risk reduction creates positive
incentive for security investment. The criticism (no-blame shields negligent behavior)
is rebutted by the observation that explicitly-egregious behavior is rare and the bulk
of failures are systemic.

### DevOps + security KPI alignment

The classic DevOps KPIs (deployment frequency, change failure rate, MTTR, lead time)
are well-aligned with security goals: faster deployment means faster patching; lower
change failure rate means fewer regression-induced vulnerabilities. The mismatch arises
when security teams operate on a separate KPI set; security teams that optimize their
KPIs in isolation can degrade DevOps KPIs.

The mechanism-design fix is **co-optimization**: define KPIs that include both DevOps
and security goals (e.g., "mean time from CVE-disclosure to patched production-
deployment"). Cross-link to `appsec_program_building_expertise.md`.

---

## 9. Insurance markets for cybersecurity

### Adverse selection (high-risk firms self-select into coverage)

Cyber-insurance is the textbook **adverse selection** case: firms with weak postures
have higher willingness-to-pay for coverage. Insurer response: **risk-rating** before
issuing a policy (questionnaire, scan, SBOM analysis, attestation). The 2020-2024
market moved toward **continuous risk-rating**: ongoing scans of insured firms' attack
surfaces (BitSight, SecurityScorecard) and real-time premium adjustment.

### Moral hazard (insured firms defend less)

Once insured, firms reduce defensive investment because their tail-loss exposure is
bounded by the policy limit. Empirically, the 2020-2024 cyber-insurance market saw
rising claim volumes and falling underwriting margins; the most common diagnosis is
moral hazard combined with ransomware-payment coverage. Insurer responses: co-pay
structures (10-30% of losses); pre-screening requirements; carve-outs (ransom payments,
regulatory fines, reputation damage excluded).

### The "claims data is a competitive moat" insurer-monopoly framing

Insurers accumulate proprietary claims data that academic researchers and regulators
cannot access. The result is **information asymmetry across insurers**: incumbents
(AIG, Chubb, AXIS, Beazley, Lloyd's syndicates) have a structural barrier-to-
entry moat. Policy proposals (public reinsurance backstop, Treasury 2022) — not adopted as of 2026.

### Cyber-insurance market post-Equifax / SolarWinds / Colonial Pipeline

Three high-impact incidents reshaped the market:
- **Equifax (2017)**: triggered widespread policy-coverage review.
- **SolarWinds (2020)**: supply-chain attack via trusted-vendor compromise triggered
  reconsideration of dependency-claim coverage.
- **Colonial Pipeline (2021)**: ransomware payout triggered debate about ransom-payment
  coverage and OFAC-sanctions exposure. AXA stopped writing ransom-payment
  coverage in France in 2021.

Cumulative 2021-2024 effect: premium increases of 50%-200%, coverage-limit reductions,
deductible increases, policy-language hardening. 2025-2026 stabilization visible but
market substantially less open than 2019.

### Aggregation risk (one incident affects many policies)

Cyber-insurance has **aggregation risk** unlike most other lines: a single
vulnerability or vendor compromise can trigger claims across many insured firms
simultaneously (Equifax, SolarWinds, Log4Shell, MOVEit). Insurer responses:
aggregation modeling; aggregate sub-limits (caps for named events); reinsurance to
Munich Re, Swiss Re, Lloyd's syndicates.

### Ransomware-payment-coverage debates 2022+

The most contested area is **whether ransom payments should be covered**. For: the
insured faces genuine economic loss the policy indemnifies. Against: ransom-payment
coverage creates moral hazard and indirectly subsidizes the attacker class. The
2022-2024 industry response is **conditional coverage** (pre-incident hardening
requirements, insurer-response-team approval, non-OFAC-sanctioned recipient, sub-limits
well below typical demand). The French LOPMI law (Law 2023-22 of 24 January 2023) goes further: coverage allowed
only if the firm files a criminal complaint within 72 hours.

---

## 10. Schneier's "Liars and Outliers" framework

### Four pressures on cooperation

Schneier's framework (*Liars and Outliers*, 2012) names four pressures by which
cooperation is induced in groups too large for personal trust:

1. **Moral pressure**: internalized norms. Most reliable when present; slowest to
   install (intergenerational); fragile under stress.
2. **Reputational pressure**: community judgment. Effective at medium group size;
   degrades at anonymity scale; can be hijacked (mob dynamics).
3. **Institutional pressure**: formal sanctions. Effective at large scale; expensive;
   creates secondary failure modes (regulatory capture, false conviction).
4. **Security pressure**: technical controls. Most specific (works only against threats
   designed-for); least scalable; worst collateral effect (high-security environments
   degrade routine cooperation, the "TSA effect").

### Each pressure has costs + side effects

The framework's analytic punch comes from explicit cost-accounting. The mechanism-design
implication: **a society's security posture is a portfolio of the four pressures, not a
single dial**. Excessive reliance on security pressure (the techno-libertarian extreme)
is structurally suboptimal because it ignores cheaper-and-more-reliable
moral/reputational pressures. Excessive reliance on institutional pressure (the
regulatory-state extreme) is suboptimal because it scales poorly and creates
capture risk.

### "Defectors" as inevitable; mitigation, not elimination

Schneier's key conceptual move: **defection is inevitable**. The right design question
is not "how do we eliminate defection?" (impossible; pressure cost approaches infinity
as defection rate approaches zero) but "how do we keep defection below the level at
which it disrupts cooperation?" Don't measure success by zero incidents; measure
success by incident rate below the disruption threshold. Cross-link to
`anti_fraud_abuse_engineering_expertise.md` §1 ("fraud is a tax, not a bug" framing).

### The "scaling cooperation" thesis

The four-pressure framework explains why cooperation **scales as societies grow**: as
groups grow, they add institutional and security pressure to compensate for the
weakening of moral and reputational pressure. The portfolio shifts with group size,
aggregate cooperation rate is preserved. Internet-scale platforms beyond personal-trust
scale must explicitly invest in institutional and security pressure (Wikipedia, Stack
Overflow do this; early Reddit, early Twitter failed to).

### Application to platform-trust-and-safety

Trust-and-safety operations at large platforms (Meta, Google, Reddit, TikTok)
operationally embody the Schneier framework, tuning all four pressures: moral
(community-guidelines, educational content), reputational (visible bans, public
removals with reasons, appeals), institutional (legal removals, DSA/NIS2 compliance,
LE cooperation), security (rate limits, account-creation friction, CAPTCHA, ML
classifiers). Cross-link to `anti_fraud_abuse_engineering_expertise.md` §10.

---

## 11. Adversarial ML + game-theoretic robustness

### "Attacker moves second" framework

The standard threat model for adversarial-ML robustness is that **the attacker observes
the defender's model before constructing the attack** — the **Stackelberg-leader-
follower game** applied to ML robustness. The empirical finding (2015-2024):
adversarial training improves robustness against the trained attack class but does not
transfer well to novel attack classes. The defender wins the Stackelberg game given the
assumed attacker; the attacker can move outside the assumed class.

### Robust optimization vs adversarial training

Two paradigms:
- **Adversarial training**: train on inputs + their adversarial perturbations.
  Empirically effective; computationally expensive; transfers narrowly.
- **Robust optimization**: formulate training as a minimax problem over an explicit
  perturbation set. Theoretically grounded; computationally hard at scale; provides
  certifiable guarantees over the perturbation set but no guarantees outside it.

Neither is universal; both should be deployed in layered defense.

### Mixed strategies for safety classifiers

A safety classifier with a deterministic decision rule can be adversarially probed (the
attacker submits queries until they find a decision-boundary) and then evaded
systematically. A **randomized (mixed-strategy)** classifier introduces stochasticity
that makes adversarial probing less efficient — the same mechanism as **mixed-strategy
Nash equilibria** in two-player zero-sum games. The cost is reduced determinism.

This dynamic is central to LLM-safety-classifier design (jailbreak resistance, prompt-
injection defense): explicit randomization can substantially raise the attacker's
per-attempt cost.

### The minimax framework for adversarial robustness

The general minimax framework:

```
min_θ E_(x,y) [ max_δ ∈ S(x) L(f_θ(x+δ), y) ]
```

Minimize over model parameters θ the expected maximum (over perturbation δ in set S(x))
loss L. The perturbation set captures attacker capability; the inner max is the
adversarial-attack subproblem; the outer min is the defender's training procedure.

The framework has been adapted to LLM-safety (Wei et al. 2023; Carlini et al. 2024),
prompt-injection and jailbreak defenses (arXiv 2510.09023, "The Attacker Moves Second", on adaptive attacks), and
detection-system safety. Cross-link to `adversarial_ml_model_security_expertise.md` §1
and `llm_agent_security_expertise.md`.

---

## 12. Open problems + research frontier

### Quantitative measurement of security-investment ROI

The most-frequently-asked question in security economics has no good answer. The
classical Gordon-Loeb 2002 model provides theoretical results (optimal investment
bounded by 36.8% of expected loss, concave in vulnerability), but the empirical
literature has not produced robust ROI estimates: pre-investment expected loss is
unobservable, post-investment loss-reduction is hard to attribute, reporting bias is
severe. The research frontier (Romanosky at RAND; Wolff at Tufts; Anderson and Moore
at WEIS) triangulates from breach-cost, insurance-claim, and self-reported data, but
quality is too poor for sharp inferences. Mandatory breach disclosure (CRA, NIS2, SEC
4-day rule) is helping but the data is years from being analyzable at scale.

### Cross-organizational incident-sharing under privacy constraints

How do organizations share incident data (TTPs, IOCs, root-cause patterns) without
exposing competitive information? Current solutions are **ISACs** (sector-specific),
**OFAC/CISA advisory channels** (state-actor threats), **private threat-intelligence
feeds** (asymmetric: customers get curation, non-customers get nothing). The research
frontier (privacy-preserving aggregation, differential privacy on threat-intel, zero-
knowledge breach-disclosure) attempts to mechanize sharing while protecting competitive
information; no production deployment as of 2026.

### "Why don't markets clear" for zero-days

A specific puzzle: the zero-day exploit market exhibits **persistent price levels** but
**infrequent transactions**. The market does not appear to clear in the standard sense.
Hypotheses: common-value uncertainty (buyers and sellers have different priors and the
difference exceeds the bid-ask spread); search costs (matching specific exploits to
specific buyer needs is high-cost); regulatory uncertainty (export controls under
Wassenaar Arrangement and EU dual-use regulations make buyer-side participation legally
risky).

The research frontier investigates the structure but lacks clean data: market
participants do not disclose prices or transaction volumes, and academic researchers
face access barriers.

### Incentive design for sigstore / SLSA L3 adoption

SLSA v1.0 defines build levels L0-L3 of provenance assurance. Most production projects
are at L1 or L2; L3 (hardened build) remains rare. The
adoption problem is a **coordination problem**: adopting L3 requires substantial
engineering investment, and the benefit accrues mainly to downstream consumers who have
not paid the cost. Mechanism-design questions: Can SLSA-L3 attestation become a
**gating criterion** for high-value contracts? **Default-on** verification in
distribution channels (npm, PyPI, Maven Central)? A **liability-shielding** mechanism
for vendors? Cross-link to `supply_chain_provenance_expertise.md`.

### AI-agent-economics as a new game

The 2024-2026 emergence of AI agents that take actions on behalf of users has opened a
new game-theoretic domain. AI agents operate at machine-speed, can be adversarially
probed at scale, and operate with delegated authority. Open questions:
- **Liability allocation**: if an agent takes an unauthorized action, who is liable —
  user, agent-developer, or platform?
- **Insurance**: how should AI-agent-action coverage be priced and structured?
- **Auditability**: what records must agents maintain to support post-hoc dispute
  resolution?
- **Market design**: how should agent-to-agent transactions be settled (two agents
  negotiating on behalf of two users — what's the auction structure?)?

Cross-link to `llm_agent_security_expertise.md` for the security-side framing; the
economic-side framing is still in flux as of mid-2026.

---

## 13. References

### Core texts
- Anderson, Ross J. *Security Engineering: A Guide to Building Dependable Distributed
  Systems*, 3rd edition. Wiley, 2020. `https://www.cl.cam.ac.uk/~rja14/book.html`
- Anderson, Ross J. *Why Information Security is Hard — An Economic Perspective*.
  ACSAC, 2001. `https://www.acsac.org/2001/papers/110.pdf`
- Schneier, Bruce. *Liars and Outliers: Enabling the Trust That Society Needs to
  Thrive*. Wiley, 2012. `https://www.schneier.com/books/liars-and-outliers`
- Schneier, Bruce. *Schneier on Security* blog. `https://www.schneier.com/blog`
- Roth, Alvin E. *Who Gets What — and Why*. Houghton Mifflin Harcourt, 2015.
- Roth, Alvin E. Nobel Prize Lecture: *The Theory and Practice of Market Design*,
  December 8, 2012. `https://www.nobelprize.org/uploads/2018/06/roth-lecture.pdf`

### Information-security economics
- Workshop on the Economics of Information Security (WEIS). `https://econinfosec.org/`
- Moore, Tyler. *Journal of Cybersecurity*. Oxford University Press.
  `https://academic.oup.com/cybersecurity`
- Anderson, Ross J., and Tyler Moore. *The Economics of Information Security*.
  Science 314(5799), 2006: 610-613.
- Gordon, Lawrence A., and Martin P. Loeb. *The Economics of Information Security
  Investment*. ACM Transactions on Information and System Security 5(4), 2002.

### Bug bounty economics
- Zhang, Leting, Emre M. Demirezen, and Subodha Kumar. *How to Make My Bug Bounty
  Cost-Effective? A Game-Theoretical Model*. Information Systems Research, 2024.
  `https://pubsonline.informs.org/doi/10.1287/isre.2021.0349`
- Kuehn, Andreas, and Milton Mueller. *Analyzing Bug Bounty Programs: An Institutional
  Perspective on the Economics of Software Vulnerabilities*. SSRN, 2014.
- *Simple economics of an external shock to a bug bounty platform*. Journal of
  Cybersecurity 10(1), 2024.
  `https://academic.oup.com/cybersecurity/article/10/1/tyae006/7667075`
- HackerOne. `https://www.hackerone.com`
- Bugcrowd. `https://www.bugcrowd.com`
- Intigriti. `https://www.intigriti.com`
- YesWeHack. `https://www.yeswehack.com`
- Crowdfense. `https://www.crowdfense.com`
- Zerodium. `https://www.zerodium.com`

### MEV and order-flow auctions
- Daian, Phil, Steven Goldfeder, Tyler Kell, Yunqi Li, Xueyuan Zhao, Iddo Bentov,
  Lorenz Breidenbach, and Ari Juels. *Flash Boys 2.0: Frontrunning, Transaction
  Reordering, and Consensus Instability in Decentralized Exchanges*. arXiv 1904.05234,
  2019. IEEE S&P 2020. `https://arxiv.org/abs/1904.05234`
- Flashbots documentation. `https://docs.flashbots.net`
- MEV-Boost. `https://boost.flashbots.net`
- Budish, Eric B., Peter Cramton, and John J. Shim. *The High-Frequency Trading Arms
  Race: Frequent Batch Auctions as a Market Design Response*. Quarterly Journal of
  Economics 130(4), 2015.
  `https://academic.oup.com/qje/article/130/4/1547/1916146`
- Budish, Eric B. Academic webpage. `https://ericbudish.org`
- CowSwap documentation. `https://docs.cow.fi`
- UniswapX overview. `https://docs.uniswap.org/contracts/uniswapx/overview`
- Bachu, Brad, Xin Wan, and Ciamac C. Moallemi. *Quantifying Price Improvement in Order Flow Auctions*.
  2024. `https://moallemi.com/ciamac/papers/uniswapx-pi-2024.pdf`

### Ransomware economics
- Cartwright, Edward, Julio Hernandez Castro, and Anna Cartwright. *To pay or not: game theoretic models
  of ransomware*. Journal of Cybersecurity 5(1), 2019.
  `https://academic.oup.com/cybersecurity/article/5/1/tyz009/5554879`
- Coveware quarterly ransomware reports. `https://www.coveware.com/blog`
- U.S. Treasury OFAC Cyber-Related Sanctions Advisories.
  `https://ofac.treasury.gov/recent-actions/cyber-related-sanctions`

### Cybercrime economics
- Levchenko, Kirill, et al. (Savage, Voelker, Paxson, et al.). *Click Trajectories:
  End-to-End Analysis of the Spam Value Chain*. IEEE Symposium on Security and Privacy,
  2011. `https://cseweb.ucsd.edu/~savage/papers/Oakland11.pdf`
- Anderson, Ross J., et al. *Measuring the Cost of Cybercrime*. WEIS 2012; updated
  WEIS 2019.

### Cyber-insurance
- NAIC. *The Current State of Cyber Insurance*. Journal of Insurance Regulation, 2023.
  `https://content.naic.org/sites/default/files/cipr-jir-2023-4.pdf`
- CISA. *Assessment of the Cyber Insurance Market*. December 2018.
  `https://www.cisa.gov/sites/default/files/2024-10/OCE%20Cyber%20Insurance%20Market%20Assessment_508.pdf`
- Romanosky, Sasha, et al. *Content Analysis of Cyber Insurance Policies*. Journal of
  Cybersecurity 5(1), 2019.

### Supply chain and SBOM
- CISA SBOM resources. `https://www.cisa.gov/sbom`
- Sigstore project. `https://www.sigstore.dev`
- SLSA framework. `https://slsa.dev`
- EU Cyber Resilience Act (Regulation EU 2024/2847).

### Auction theory and mechanism design (canonical references)
- Vickrey, William. *Counterspeculation, Auctions, and Competitive Sealed Tenders*.
  Journal of Finance 16(1), 1961.
- Myerson, Roger B. *Optimal Auction Design*. Mathematics of Operations Research 6(1),
  1981.
- Milgrom, Paul R., and Robert J. Weber. *A Theory of Auctions and Competitive
  Bidding*. Econometrica 50(5), 1982.
- Ausubel, Lawrence M., and Paul Milgrom. *The Lovely but Lonely Vickrey Auction*. In
  Combinatorial Auctions (MIT Press), 2006.
  `https://web.stanford.edu/~milgrom/publishedarticles/Lovely%20but%20Lonely%20Vickrey%20Auction-072404a.pdf`

### Adversarial ML and game-theoretic robustness
- Madry, Aleksander, et al. *Towards Deep Learning Models Resistant to Adversarial
  Attacks*. ICLR 2018.
- Carlini, Nicholas, et al. Adversarial-robustness LLM evaluations, 2023-2024.

### Cross-references within this expertise library
- `anti_fraud_abuse_engineering_expertise.md` — adversary economics, abuse-cost
  framing, platform trust-and-safety
- `vulnerability_research_methodology_expertise.md` — VR-economics; bug-bounty hunting
  strategy
- `blockchain_wallet_consensus_security_expertise.md` — MEV and sequencer economics;
  consensus-layer attacks
- `cicd_supply_chain_expertise.md` — CRA Article 14 / NIS2 disclosure obligations;
  supply-chain mandates
- `supply_chain_provenance_expertise.md` — Sigstore, SLSA, attestation infrastructure
- `appsec_program_building_expertise.md` — security-program incentive structures,
  executive comms
- `dfir_methodology_expertise.md` — ransomware incident response and decision-making
  under attack
- `adversarial_ml_model_security_expertise.md` — adversarial-ML threat models and
  minimax robustness
- `detection_engineering_expertise.md` — ATT&CK coverage, detection-as-code, red/blue
  dynamics
- `llm_agent_security_expertise.md` — AI-agent economics, delegated-authority risk,
  agent-runtime adversarial robustness
- `steelman_doctrine_expertise.md` — adversarial-collaboration as procedural
  cooperation-induction
