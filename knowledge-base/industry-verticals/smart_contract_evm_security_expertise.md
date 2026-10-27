# Smart Contract and EVM Security — Solidity, Bridges, and the Onchain Threat Model

> **Framework:** This document synthesizes practitioner perspectives on smart contract
> security across Solidity / EVM, non-EVM chains, DeFi protocol design, bridge architecture,
> and onchain detection. It anchors on a small set of named researchers whose work defines
> the modern field, and on incident postmortems where the attack primitive has been preserved
> in writing.
>
> **Researchers in scope:**
> - **Dan Guido** (Trail of Bits CEO) — built the blockchain security practice that produced
>   Manticore, Echidna, Slither; led the early industrialization of Ethereum smart contract
>   review. Source: blog.trailofbits.com author page; Trail of Bits podcast.
> - **Josselin Feist** — author of Slither, the canonical Solidity/Vyper static analysis
>   framework; until 2025 Engineering Director of Trail of Bits' Blockchain team; now
>   independent. Source: montyly.github.io; arXiv:1908.09878 (Slither paper).
> - **Gustavo Grieco / Alex Groce** — co-authors of the original Slither paper and ongoing
>   contributors to Echidna and Manticore. Source: arXiv:1908.09878.
> - **Mooly Sagiv** — co-founder of Certora (2018); principal researcher; PL/formal-methods
>   academic at Tel Aviv University; the Certora Prover is the industry-leading commercial
>   formal verification tool for Solidity. Source: certora.com/author/mooly.
> - **Mudit Gupta** — CISO at Polygon Labs; blogger and
>   incident-response practitioner on DeFi exploits. Source: mudit.blog; Polygon Labs
>   LinkedIn.
> - **samczsun / Sam Sun** — Paradigm Head of Security (as of 2024); leading the Security
>   Alliance (SEAL) 911 emergency response initiative; "Escaping the Dark Forest" is the
>   canonical first-person whitehat-recovery essay. Source: samczsun.com.
> - **Tincho** — security researcher at The Red Guild; former lead auditor at OpenZeppelin;
>   creator of Damn Vulnerable DeFi; the "Tincho methodology" for manual audits is widely
>   taught. Source: blog.theredguild.org/author/tincho.
> - **Christoph Michel (cmichel)** — independent smart contract auditor; published "How to become a smart
>   contract auditor" pedagogy. Source: cmichel.io.
> - **Patrick Collins** — Cyfrin founder; Updraft instructor; long-form pedagogy for smart
>   contract security from beginner to audit-track. Source: cyfrin.io.
> - **Mariko Wakabayashi** — machine learning engineer at OpenZeppelin; her Forta
>   ML detection bot flagged four hacks worth $23.5M before exploitation (Oct-Nov 2022). Source: github.com/mwakaba2;
>   cointelegraph author page.
> - **Adrian Hetman** — Head of Triaging at Immunefi; operates the
>   high-volume bug-bounty triage pipeline.
>   Source: linkedin.com/in/adrianhetman.
> - **Dennison Bertram** — early OpenZeppelin team member, co-founder of Tally; the
>   OpenZeppelin Contracts library is the canonical secure-defaults Solidity codebase.
>   Source: dennisonbertram.com; openzeppelin.com.
>
> **Audit firms cited (corporate corpora, not single-author):** Trail of Bits, OpenZeppelin,
> ConsenSys Diligence, Spearbit (Cantina), yAudit/yAcademy, Halborn, CertiK, ChainSecurity,
> Quantstamp.
>
> **Cross-links to this repo:**
> [[code_review_expertise.md]] (candidate-point auditing at extreme severity),
> [[fuzzing_discipline_expertise.md]] (Echidna as property fuzzing applied to contracts),
> [[cryptography_expertise.md]] (signature schemes, commitment, KDF),
> [[distributed_authz_expertise.md]] (DAO governance as distributed authz),
> [[detection_engineering_expertise.md]] (Forta/Defender as onchain telemetry),
> [[steelman_doctrine_expertise.md]] (audit reports as Champion/Foil/Adjudicator artifacts),
> [[llm_agent_security_expertise.md]] (LLMs as auditors, agent-controlled contracts),
> [[vulnerability_research_methodology_expertise.md]] (variant analysis methodology applied
> onchain),
> [Semgrep rule-writing docs](https://semgrep.dev/docs/writing-rules/overview) (Slither detectors as semgrep-shaped rules
> on a different IR).

---

## 1. The smart contract threat model

### Immutability removes the patch primitive

Bytecode at a deployed address is durable: every full node has a copy, consensus requires
agreement on every byte, no central operator can replace the code. Even where upgrade
patterns exist (proxy + implementation), the proxy is immutable; the upgrade is a state-
write authorized by an admin role under whatever timelock the proxy author enforced. The
audit phase is the only phase. Once a contract is deployed and capitalized, the cost of
fixing a discovered bug is the bug's full blast radius minus whatever can be salvaged via
emergency pause, governance vote, or whitehat rescue racing against the public mempool.

Severity calculus is distorted: a bug that would be "Medium — informational fix in next
release" in SaaS is "Critical — protocol drain" if it lives in a $100M TVL pool. Severity
is a function of TVL, not bug complexity. Cross-link [[code_review_expertise.md]] for the
click-count framework; in smart contracts, zero-click access to drainable funds is modal.

### Money as data: state is the asset

State IS the asset. The balance mapping `balanceOf[address] => uint256` is the token; an
LP-position NFT IS the claim on pool liquidity. No settlement layer underneath can be
rolled back. If an attacker mutates state to credit themselves a billion dollars in
tokens, those tokens are real within the contract's semantics and tradable on every other
contract that accepts the token's address.

This is what makes flash loans devastating. The attacker doesn't need capital — they need
a single atomic transaction that briefly puts them in a state where the contract believes
they are entitled to something. Within that atom they drain, then repay the loan, leaving
with the differential. No bank holds the differential in escrow.

### Public state, bytecode, mempool

Every transaction's calldata is visible to every node operator and searcher between
broadcast and inclusion. Every storage slot is readable via `eth_getStorageAt`; Solidity's
`private` keyword only restricts cross-contract calls, not read access from outside.
Designers writing "private state" assuming confidentiality have shipped a bug. Cleartext
parameters, state reads that reveal intent, rebalance triggers — all signals adversaries
watch for. See Section 8 on MEV.

### Gas as attack surface and defense

Every operation costs gas; every transaction has a gas limit. Gas griefing forces a
contract into a code path that consumes more gas than the caller paid, breaking liveness.
The reverse — assuming a sub-call succeeds within a fixed gas budget — fails when the
attacker arranges revert via gas exhaustion. Gas is also a defense: bounded iteration
limits attackers, but forces "pull pattern" designs where users withdraw individually
rather than the contract pushing payments.

### Economic incentives: attackers pay gas, profit on failures

Failed exploits cost gas but no funds. Attackers submit dozens of probe transactions
exploring state combinations cheaply.
When a bug is dropped onchain, generalized-arbitrage infrastructure replicates within
seconds — Nomad devolved into a "crowdsourced" exploit (Section 13).

### Chain-specific threat models

- **Ethereum mainnet**: full EVM, established MEV, 12s slots, ~13 min finality (two epochs), no
  sequencer.
- **L2 rollups (Optimism, Arbitrum, Base, zkSync, Linea, Scroll)**: single sequencer at
  the L2 layer; escape hatches via fault proofs (OP-stack Cannon 2024, Arbitrum BoLD
  2025) or validity proofs (zkSync). Cross-link [[distributed_authz_expertise.md]]
  on sequencer-as-trust-anchor.
- **Solana**: stateless programs + account state; Sealevel parallel execution; account-
  confusion is the dominant bug class; no recursive-call reentrancy.
- **Cosmos zones**: CosmWasm + Tendermint; IBC for cross-zone; IBC packet timeouts have
  produced bugs.
- **Move (Aptos, Sui)**: linear resource types structurally rule out double-spend.
- **Bitcoin Script**: minimal by design; inscription protocols (Ordinals, BRC-20) push
  most "smart contract" risk into off-chain indexer consensus.

### Real economic loss

Industry estimates (Chainalysis, Elliptic, Immunefi): 2022 (~$3.7B) and 2023 (~$1.7B) were worst. Bridges dominate —
Ronin ($625M), Poly Network ($610M), Wormhole ($325M), Nomad ($190M) alone exceed $1.7B.
The 2024-2025 trend shifts toward access-control compromise (stolen keys, multi-sig
phishing, frontend hijacks) as onchain bugs are more thoroughly audited out.

---

## 2. Solidity / EVM core attack surface

### Execution model

The EVM is a stack-based VM with 256-bit words. Memory is byte-addressable with quadratic
expansion gas. Storage is a 256-bit key-value store (20000 gas first SSTORE, 5000 modify).
Three execution-context primitives matter:

- **`call`** — fresh execution context; callee's `msg.sender` is the caller.
- **`delegatecall`** — callee's code in caller's storage context; `msg.sender` and
  `msg.value` inherited. The primitive behind proxies, libraries, and the Parity bug.
- **`staticcall`** — like `call` but reverts on state modification.

### Storage layout (the slot model)

Solidity packs state variables into 256-bit slots from slot 0. Mappings derive slots:
`mapping(K => V)` at slot `s` stores key `k` at `keccak256(abi.encode(k, s))`. Dynamic
arrays: length at slot `s`, elements at `keccak256(abi.encode(s)) + i`.

Three bug classes:

1. **Adjacent-slot collision in delegatecall proxies**: implementation declares a state
   variable in a slot the proxy uses for admin; implementation overwrites admin via normal
   assignment. ERC-1967 mitigates via namespaced keccak-derived admin slots.
2. **Storage layout change during upgrade**: reordering or inserting variables shifts all
   subsequent slot assignments. OpenZeppelin upgradeable contracts reserve via
   `uint256[50] __gap`.
3. **Hash collision via assembly-crafted storage keys**: bypassing slot namespacing in
   assembly can collide two logically distinct mappings.

### `msg.sender` vs `tx.origin`

`msg.sender` is the immediate caller; `tx.origin` is the EOA that initiated the
transaction. Authorization on `tx.origin` is broken: an attacker contract called by the
owner inherits the owner's `tx.origin` while having attacker `msg.sender`. The contract's
withdraw check `require(tx.origin == owner)` passes; funds drain. Rule: never use
`tx.origin` for authorization. ERC-4337 further complicates this (Section 14).

### Function selectors and 4-byte collisions

External functions identified by first 4 bytes of `keccak256(signature)`. Two exploit
shapes: (1) proxy admin function shadowing — Transparent Proxy routes to implementation
only if `msg.sender != admin`, so an implementation function sharing a selector with
`upgradeTo(address)` is unreachable; UUPS fixes by moving admin to implementation. (2)
honeypot tokens with selector squatting on `balanceOf` to fool wallets.

### Fallback / receive

`receive()` accepts plain ether; `fallback()` handles unmatched calldata. Bug surface:
reentrancy via fallback (Section 3); attacker contracts with always-revert fallbacks
brick contracts that assumed `.send()` would succeed silently.

### Delegatecall and the Parity multisig CVE

The Parity multisig wallet (November 2017, $280M frozen) implemented wallet logic in a shared
library. The library had `initWallet(...)` callable by anyone; a user called it on the
library directly, became owner, then `selfdestruct`-ed the library — bricking every
Parity wallet pointing at it.

Defensive rule: any `delegatecall` target must not have anyone-callable state-modifying
functions, must not have `selfdestruct`, must not have constructor-uninitialized state an
attacker can race to initialize.

### selfdestruct (deprecated)

EIP-6049 deprecated `selfdestruct` in 2023. Post-Cancun (2024), it only clears balance/code
when create + destroy happen in the same transaction. Modern contracts should not use it
at all; if you see it, treat as critical-severity pending mitigation analysis.

### Constructor vs runtime bytecode

Constructor code returns runtime bytecode; only runtime code lives at the address. Two
implications:

- `CREATE2` with a salt lets an attacker pre-compute deployment addresses and embed them
  in commitments.
- `extcodesize(addr) == 0` to gate "EOA-only" is bypassed by calling from within a
  constructor — runtime code isn't deployed yet, so `extcodesize` returns 0.

### Contract bytecode IS the contract

Etherscan/Sourcify provide source-level transparency over a bytecode-level chain.
Verification means source produces the same bytecode under a pinned compiler version,
optimizer settings, and metadata hash. A bug that only manifests under a specific compiler
version (Curve / Vyper, Section 13) requires verifying all pinning, not just the source.

---

## 3. Classical smart contract vulnerabilities

### Reentrancy

The DAO 2016 (~$60M then, much more now) updated user balance after sending ether:

```solidity
function withdraw() public {
    uint amount = balances[msg.sender];
    (bool ok,) = msg.sender.call{value: amount}("");
    require(ok);
    balances[msg.sender] = 0;  // BUG: after the call
}
```

Attacker contract's fallback re-enters `withdraw()`, sees the same non-zero balance,
drains repeatedly. Fix: checks-effects-interactions (CEI) — set balance to zero first.

Variants post-DAO:

- **Cross-function reentrancy**: function A's external call re-enters function B, which
  mutates state A is mid-reading. CEI within A is insufficient; OpenZeppelin
  `ReentrancyGuard` is the standard.
- **Cross-contract reentrancy**: A calls B; B calls back into A. Both CEI-clean in
  isolation can still compose into a vulnerable pair.
- **Read-only reentrancy**: a `view` function reads state mid-update. External
  integrators (oracle, lender) get stale data. Curve was vulnerable in 2022; consumers
  of Curve LP prices had to add reentrancy locks on their oracle reads.

Cross-link Curve July 2023 (Section 13) — cross-function reentrancy from a Vyper
compiler bug.

### Integer overflow / underflow

Pre-Solidity 0.8 arithmetic wrapped silently. BeautyChain BEC (April 2018) minted vast
quantities via batch-transfer overflow. Standard mitigation pre-0.8: SafeMath.

Post-0.8 reverts by default. The `unchecked` block opts out for gas optimization. Bug
surface shifts to: misplaced `unchecked` blocks; silent downcasts (`uint256` to `uint128`
truncates regardless of version — use OpenZeppelin SafeCast); inline `assembly` blocks
(no overflow protection).

### Access control

The most common audit finding. Three sub-types: missing modifier (developer forgot);
wrong modifier (auction-winner function gated by `onlyOwner`); role-confusion in
OpenZeppelin AccessControl (PAUSER_ROLE function gated by DEFAULT_ADMIN_ROLE, preventing
emergency response). Manual review of every external
`setX` is the baseline.

### Unchecked external calls

`.call()` returns `(bool success, bytes data)`. Developers sometimes ignore the bool:

```solidity
target.call{value: amount}("");  // BUG: no return check
```

Fix: `(bool ok,) = target.call{value: amount}(""); require(ok);` or OpenZeppelin
`Address.functionCall`.

### Price oracle manipulation

Dominant DeFi exploit primitive 2020-2022. Pattern: flash-loan asset X, dump into Uniswap
to crater spot price, victim protocol reads spot price as oracle, attacker borrows
against now-undervalued X collateral or mints synthetic Y at manipulated price, restore
price, repay loan. Canonical: bZx 2020 ($1M); also Harvest 2020 ($24M), Cheese Bank,
Cream 2021 ($130M), Mango Markets 2022 ($114M).

Defense: TWAP over multi-minute windows or Chainlink off-chain aggregation. Single-block
spot price is never acceptable. UniswapV3 `observe()` is defensible short-TWAP with
sandwich caveats.

### Signature replay

ECDSA over EIP-712 typed data is standard. Bug classes:

- **Missing nonce**: replay across uses. Include per-signer incrementing nonce.
- **Missing chainId**: replay across chains. Include `block.chainid` in domain separator.
- **Missing contract address**: replay across same-schema contracts. Include
  `address(this)` in domain separator.
- **Malleability**: ECDSA `(r, s)` and `(r, n-s)` both valid. OpenZeppelin ECDSA rejects
  high-s; raw `ecrecover` does not.
- **Missing expiry**: signature held indefinitely. Always include a deadline.

### Incorrect ERC-20 implementations

ERC-20 is underspecified. Two compatibility classes:

- **No return value**: USDT, BNB, OMG don't return bool from `transfer`. Consumer's
  `require(token.transfer(to, amt))` doesn't compile against actual interface. Use
  OpenZeppelin SafeERC20.
- **Fee-on-transfer**: tokens that deduct on transfer break consumers expecting
  `balanceBefore + amount == balanceAfter`. Measure actual delta, not the amount
  parameter.

### Block-timestamp manipulation

Post-Merge, consensus fixes `block.timestamp` to the slot time. Don't use as randomness;
don't use for sub-block windows; prefer block number for short intervals.

### Hash collision in mapping keys

Direct assembly-crafted storage keys can collide logically-distinct mappings; the keccak
slot-derivation namespacing prevents this when the high-level Solidity types are used.
Use `mapping(bytes32 => V)` with explicit pre-hashing instead of `mapping(bytes => V)`.

---

## 4. DeFi-specific attack patterns

### Flash loan attacks

A flash loan provides a large asset amount for a single atomic transaction, requiring
repayment within the transaction or full revert. AAVE, dYdX, Uniswap V3, Balancer offer
this. It removes capital as a defense — any bug requiring a large position is now
exploitable by anyone at gas-only cost on failure.

Notable incidents: bZx (Feb 2020, $1M), dForce (April 2020, $25M ERC-777 reentrancy),
Harvest Finance (Oct 2020, $24M), Cream (Oct 2021, $130M), Beanstalk (April 2022, $182M
governance attack — flash-loaned voting power passed a malicious proposal).

### Price-oracle TWAP attacks (Mango Markets, October 2022)

The Mango attacker bought MNGO on the three exchanges feeding Mango's oracle (Mango,
AscendEX, FTX); the oracle price jumped over 13-fold in 30 minutes; borrowed $114M against
inflated MNGO collateral. TWAPs defend against single-block manipulation, not multi-minute
campaigns. Defense: multi-source aggregation (Chainlink + DEX TWAP + offchain sanity);
listing thin-liquidity assets as collateral is a risk-engineering decision.

### Reentrancy + LP-token-burn race

KyberSwap Elastic (Nov 2023, $48M) exploited rounding in reinvestment-liquidity
calculation; attacker triggered LP burn at a state where rounding favored them by orders
of magnitude. Curve July 2023 (Section 13) was the same family. Defense: Echidna /
Foundry invariant tests with property "total LP value never exceeds total pool value."

### Bridge exploits

Largest single category of DeFi loss by volume: Ronin ($625M), Poly Network ($610M),
Wormhole ($325M), Nomad ($190M), BNB Bridge ($568M, partially frozen). Section 5 covers
in depth.

### Cross-chain message-passing bugs

Bridges using general messaging (Wormhole, LayerZero, Hyperlane) must verify source-chain
emission before destination-chain action. Failure modes: replay across chains (missing
destination chainId); replay on same chain (missing nonce); signature verification
skipped (Wormhole 2022).

### Governance attacks

DAOs whose voting tokens are liquid on flash-loan-enabled DEXs are vulnerable to
flash-loaned voting power. Pattern: flash-loan voting tokens, vote for malicious
proposal, wait for execution (often timelocked), repay loan, collect payout. Beanstalk
2022 is canonical. Defense: snapshot voting (Compound uses block-number snapshot; flash
loans don't span blocks); timelock with admin veto; checkpoint-based voting requiring
time-locked staking.

### Compound Proposal 62 (September 2021)

Compound's Proposal 62 was meant to fix a smaller bug; the patch had a comparison-operator
typo (`>=` vs `>`) that distributed ~$80M of COMP excessively to LPs. The proposal had
passed governance; the executor had no halt power; the bug ran. Mitigation via follow-up
proposal subject to its own timelock. Lesson: governance proposals are code and need code
review rigor; calldata-preview tooling (Tally, Etherscan) is essential.

---

## 5. Bridge security

A bridge represents a token on chain A as wrapped on chain B. Lock-and-mint (chain A
custody + chain B mint), burn-and-mint (CCTP, CCIP), liquidity-pool (Stargate, Across),
optimistic (Nomad, before exploit), or zk-based (Polyhedra zkBridge, SP1-based). In every
variant the bridge's job is to keep supply on B matched to locks on A; violating this
invariant infinite-mints the wrapped asset.

### Why bridges are uniquely fragile

Bridges concentrate value, often with verification depending on a small validator set or
multi-sig. The verification path is the bug surface: cryptographic gaps (Wormhole 2022),
access-control gaps (Ronin 2022), initialization gaps (Nomad 2022), message-forging gaps
(Poly Network 2021), proof-verification gaps (BNB Bridge 2022) directly drain the bridge.
Bridges deserve the most expensive review available: multi-firm audit, public contest,
formal verification of the verifier, sustained bug bounty.

### Ronin bridge (March 2022, $625M)

5-of-9 validator multi-sig for withdrawals. Lazarus Group (DPRK, FBI attribution)
spear-phished a Sky Mavis senior engineer via fake LinkedIn job interview, dropped
malware in the offer PDF, pivoted into infrastructure, compromised 4 validator keys.
Also exploited a stale delegation: Sky Mavis had been authorized to sign on behalf of
the Axie DAO validator during a load spike, never revoked. With 5/9 they forged
173,600 ETH and 25.5M USDC withdrawals. Undetected for six days — no outflow monitoring.

Lessons: validator key management is the entire trust model; HSM/MPC for signers;
expire delegations by default; outflow-magnitude alerting tied to ops on-call
(cross-link [[detection_engineering_expertise.md]]); 5/9 is a low threshold for
$600M+ TVL.

### Wormhole (February 2022, $325M)

19-Guardian multi-sig; 13/19 to mint on Ethereum based on Solana attestation. The Solana
program verified signatures by calling `load_instruction_at(idx)` (deprecated; doesn't
validate the account being read) and checking that the prior instruction called the
Secp256k1 verify program. Attacker passed a fake `Instructions` account they had
pre-populated to look like a real Secp256k1 call. The check passed without verifying
actual signatures; wrapped tokens minted. Patch: `load_instruction_at_checked`. Jump
Crypto covered the $325M loss from their treasury.

Lesson: deprecated APIs exist for a reason. Type-confusion at the cross-chain verifier
is catastrophic. Cross-link [[deserialization_expertise.md]] for type-confusion mental
model.

### Nomad bridge (August 2022, $190M)

Optimistic verification: messages assumed valid after a fraud-proof window. A routine
Replica upgrade initialized the trusted root to `0x00` — the same value the empty
`messages` mapping lookup returns by default. Effect: every unprocessed message hash
matched the trusted root; any message could be marked proven without proof.

Calldata visible in mempool. Dozens of unrelated actors
copied it, substituted their address, replayed. Total: $190M.

Lessons: zero-default semantics interact with sentinel values badly; auditor checklist
must verify every state variable's default. Public-mempool exploits replicate in
seconds.

### Poly Network (August 2021, $610M, returned)

Two contracts: `EthCrossChainManager` (entry point) and `EthCrossChainData` (validator
set). Manager exposed a function forwarding cross-chain messages with user-chosen target
and calldata; Manager owned Data. Attacker forwarded a Manager-originated call to
Data's `putCurEpochConPubKeyBytes`, replacing the validator set with attacker-controlled
keys. With their own validators "signing," they forged withdrawals. Attacker returned
funds within two weeks.

Lesson: privileged inter-contract relationships need access control at the boundary, not
just per function. Cross-link [[distributed_authz_expertise.md]] — separating manager
and data is meaningless if the manager can invoke arbitrary data functions.

### Cross-chain message-passing protocols (comparative trust)

- **LayerZero** (v1): independent oracle + relayer (default oracle: Chainlink). Trust:
  oracle and relayer do not collude.
- **Wormhole**: 19-Guardian 13/19 multi-sig. Trust: <7 Guardians compromised.
- **Hyperlane**: per-message ISMs (multi-sig, optimistic, or zk).
- **CCIP** (Chainlink): off-chain reporter network. Trust: Chainlink reporters.
- **Axelar**: validator-set PoS chain.
- **IBC** (Cosmos): light-client verification; strongest model, only between
  IBC-compatible chains.

Audit rule: identify the security model; validate implementation against the model's
claims; never accept "trustless" without checking the trust assumption.

---

## 6. Governance and tokenomics attacks

### DAO governance attack surface

Typical flow: token-holders submit proposals, vote during a window, passed proposals
enter timelock, after timelock anyone executes. Audit checklist per phase:

- **Submission**: threshold? flash-loanable? fee?
- **Voting**: power computed at proposal-creation snapshot, or rolling balance? Snapshot
  defeats flash loans.
- **Quorum**: fraction of supply? Adjustable by governance itself (circular-dependence)?
- **Execution**: anyone executes, or privileged keeper? Can it be DoS'd?
- **Timelock**: emergency multi-sig bypass? How controlled?

### Voting-power flash-loan attacks

Compound uses block-number snapshot; flash loans don't span blocks; defeated. Older or
smaller DAOs without this are vulnerable. Beanstalk April 2022 ($182M) is the warning
shot. MakerDAO's Emergency Shutdown Module lets MKR holders who deposit a threshold of MKR
trigger shutdown for catastrophic contingencies; cross-link [[distributed_authz_expertise.md]].

### Malicious proposals via timelock

Attacker slowly accumulates voting tokens, submits an innocuous-looking proposal whose
actual calldata transfers treasury or upgrades implementation to attacker code. Defense:
every proposal's calldata human-verified before execution; Tally and Snapshot decode
calldata and show side effects.

### Timelock bypass

A timelock with emergency-bypass multi-sig has the security of the multi-sig, not the
timelock. Treat as critical infrastructure: HSM signers, geographic/operational
separation.

### Token-supply manipulation

Rebase tokens (Ampleforth, OHM-style) have variable supply; balance changes without
transfer events; contracts storing snapshots must rebase-adjust on every read.
Fee-on-transfer tokens deduct on transfer — integrators expecting
`balanceBefore + amount == balanceAfter` are off by the fee. Honeypot tokens disable
selling via hidden conditions (transfer to non-whitelist reverts).

### LP-token economics and rug pulls

Rug pull = pool deployer keeps admin, drains the pool. Defense: verify no admin
functions exist, LP tokens locked/timelocked, contract not upgradeable. Renounced
ownership is the strongest signal; 6-month timelock is acceptable; mutable
non-timelocked admin is a red flag.

---

## 7. Solana and non-EVM smart contract models

### Solana

Programs are stateless code; state lives in accounts. Caller specifies accounts the
program will read/write; Sealevel parallelizes non-overlapping transactions; SBF
bytecode runtime. Bug classes specific to Solana:

- **Account confusion**: program accepts account parameter without strict type
  enforcement; attacker substitutes a different account with the same owner program ID.
  Anchor's `#[account]` macros mitigate; raw programs are vulnerable. Wormhole 2022 is
  this class.
- **Missing signer check**: every authorizing account must be `is_signer`-checked.
- **Missing owner check**: must verify account.owner matches expected program ID.
- **CPI reentrancy is absent** (no recursive-call semantics) but multi-instruction state
  inconsistency is a related concern.
- **Rent exemption**: programs that don't handle rent reclamation leak SOL.

Practitioner references: Solana Cookbook security section, neodyme.io and OtterSec
writeups.

### Move (Aptos, Sui)

Linear resource types: assets can't be copied or dropped, only moved. Rules out
double-spend at the type-system level. Move Prover is integrated formal verification.
Bug surface: `public(friend)` and `entry` function access control; generic resource
specialization attacks; off-chain validator-client bugs.

### Cosmos zones + CosmWasm

WASM smart contracts in Tendermint-consensus zones; IBC for cross-zone. Bug classes: IBC
packet timeouts, ack/timeout callback ordering, CosmWasm storage layout conventions,
hub-and-spoke trust where Cosmos Hub compromise affects connected zones.

### Bitcoin Script

Minimalist by design; mostly multi-sig + time-lock. Taproot/schnorr expansion (and
proposed OP_CAT, OP_CTV) adds surface. Inscription protocols (Ordinals, BRC-20, Runes)
are off-chain consensus games on top of Bitcoin; bugs live in indexer code, not the
chain. Indexer-consensus disagreements are real-money bugs.

---

## 8. MEV and the mempool

MEV (Maximal Extractable Value) is the value a block proposer can extract by including,
excluding, or reordering transactions. Post-Merge, validators are the proposers; on L2s,
sequencers play the role.

### Flashbots and MEV-Boost

Flashbots searchers submit transaction bundles to relays; relays forward to MEV-Boost
validators; most-profitable bundle wins. Private mempool eliminates searcher-vs-searcher
front-running but not the underlying extraction. Proposer-Builder Separation (PBS) is
the post-Merge architecture: specialized builders compete for block construction;
proposers choose any builder, limiting collusion.

### Sandwich attacks

User submits Uniswap swap with slippage tolerance S. Searcher front-runs with a buy
that moves price, lets victim swap execute worse, back-runs with sell, pockets
differential bounded by S. Defenses in order: private mempool (Flashbots Protect, MEV
Blocker); tight slippage; intent-based aggregators (UniswapX, 1inch Fusion, CoW Swap)
via auction settlement; batch auctions (CowSwap) at cost of latency.

### JIT (Just-In-Time) liquidity

Searcher observes a large UniswapV3 swap, deploys liquidity in the relevant tick range
immediately before, captures the fee, removes immediately after. Reduces passive LP
returns. Not a security bug; a market-structure issue.

### Cross-domain MEV

Independent sequencing on two chains lets MEV searchers exploit cross-chain arb
profitable only when both legs land in the same epoch. Open research; solutions involve
shared-sequencer designs (Espresso, Astria) and synchronous composability.

### Order-flow auctions

Wallets sell user order flow to MEV searchers in exchange for rebates or guaranteed
fills — Robinhood-style PFOF onchain. Auction format (English, Dutch) and surplus
distribution are the design parameters.

---

## 9. Tooling — static, dynamic, symbolic

### Slither (Trail of Bits) — canonical static analyzer

Python framework for Solidity/Vyper. Parses to SlithIR; runs ~100 built-in detectors
(reentrancy, access control, arbitrary calls, dangerous delegatecall, ERC-20 issues).
Custom detectors in Python against the SlithIR API — closest analog to Semgrep rule
authoring (cross-link [Semgrep rule-writing docs](https://semgrep.dev/docs/writing-rules/overview)).

Strengths: fast (whole-codebase in seconds); low FP on core detectors; CI-clean.
Weaknesses: shallow cross-contract analysis (source-level, not bytecode); detector
authors need Solidity expertise; complex DeFi math beyond rule-pattern scope.
GitHub: github.com/crytic/slither. Paper: arXiv:1908.09878 (Feist, Grieco, Groce).

### Mythril (ConsenSys) — symbolic execution

EVM bytecode symbolic execution. Targets overflow, unprotected functions, delegatecall
to user-controlled, suicidal contracts. Largely superseded by Echidna and Halmos for
practical use; symbolic execution explodes on loops and external calls.

### Manticore (Trail of Bits) — symbolic execution

Multi-target (x86, ARM, EVM). `manticore-verifier` accepts Solidity property tests in
the same format as Echidna, attempts to prove via symbolic execution. In maintenance
mode as of 2024-2025; Trail of Bits has shifted focus to Echidna.

### Echidna (Trail of Bits) — property-based fuzzing

Haskell-implemented property-based fuzzer. User writes property predicates as Solidity
functions returning bool; Echidna generates random transaction sequences via
coverage-guided fuzzing; reports violating counterexamples. The dominant fuzzer in
production audit firms. Cross-link [[fuzzing_discipline_expertise.md]]; Echidna is the
EVM-specific instance.

Strengths: actually finds bugs in math-heavy logic (LP curves, lending); coverage-guided
exploration discovers state combos human auditors miss. Weaknesses: writing good
properties is the hard part — missing properties mean missed bugs.

### Foundry / forge — modern test framework

Foundry (Paradigm) replaced Hardhat 2022-2024 as default Solidity dev environment.
Forge runs Solidity tests at native EVM speed; cheatcodes (`vm.prank`, `vm.warp`,
`vm.expectRevert`) make test-writing ergonomic; built-in `forge fuzz` and `forge
invariant` cover most non-symbolic property needs. Standard audit stack: Foundry +
Echidna or Halmos + Slither.

### Tenderly — execution tracing

Commercial tx simulator and tracer. Auditors use for "what does this tx actually do":
gas profile, state transitions, sub-call tree, decoded events. First stop in incident
response.

### Certora — formal verification

Certora Prover takes Solidity + CVL (Certora Verification Language) specs, produces
SMT-based proofs (or counterexamples). Used by Aave, Compound, MakerDAO, Lido, Uniswap
on highest-value contracts. Strengths: actual proofs (modulo prover soundness); finds
invariant violations beyond random-exploration state space. Weaknesses: CVL is a
distinct skill; commercial and expensive; proof times can be hours. Cross-link
[[cryptography_expertise.md]] on primitive vs protocol verification.

### Halmos (a16z) — symbolic testing with Foundry

Re-runs Foundry tests under symbolic input. Leverages existing test code as the spec —
no CVL to learn. Strengths: low setup; exhaustive over bounded loops. Weaknesses:
state-space explosion; unbounded loops need manual annotation. Not a full Certora
replacement. GitHub: github.com/a16z/halmos.

### Code4rena, Sherlock, Cantina — competitive contest platforms

Time-boxed competitive audit contests. Wardens/Watsons submit findings during the
window; judges rank; payout proportional to severity and uniqueness. Standard for
high-value contracts is multi-firm audit + competitive contest + ongoing bug bounty.
Contestant pool concentrates — cmichel earned >$1.3M on Code4rena from Q1 2021 to Q1 2022, top leaderboard is
a few dozen names.

### Immunefi — bug bounty

Dominant DeFi bounty platform. $1k-$10M per finding, scaled to severity and TVL. Adrian
Hetman heads triage. Continuous post-deployment detection; catches bugs that audits and
contests missed.

### Cross-link: Slither rules are Semgrep-shaped

Slither's SlithIR is conceptually similar to Semgrep's generic-tree pattern matching;
detectors pattern-match on IR. SlithIR carries Solidity-specific dataflow and
control-flow facts Semgrep doesn't have natively. Cross-function reachability → Slither;
syntactic pattern across many contracts → Semgrep could do it.

---

## 10. Audit methodology

### Three-pronged industry practice

High-value DeFi contracts use three parallel mechanisms:

1. **Pre-deployment audit** by a recognized firm. Multi-firm parallel audits standard
   for $100M+ TVL.
2. **Competitive contest** (Code4rena, Sherlock, Cantina, Hats) after audit. Surfaces
   missed bugs pre-shipment.
3. **Ongoing bug bounty** (Immunefi, internal) post-deployment.

Total cost for $100M-TVL: ~$500k-$2M. Cost of a single exploit: the entire TVL. Math
is clear.

### Audit firm roster

- **Trail of Bits** — broad portfolio across EVM, Solana, Move; tooling (Slither,
  Echidna, Manticore); thoroughness reputation.
- **OpenZeppelin** — canonical contracts library author; major DeFi and L2 audits.
- **ConsenSys Diligence** — Mythril authors; Ethereum-ecosystem infrastructure.
- **Spearbit / Cantina** — distributed-talent model; EF-alumni founders.
- **yAudit / yAcademy** — yearn-ecosystem; trains auditors via fellowship.
- **Halborn** — broad portfolio across non-EVM chains; strong public writeups.
- **ChainSecurity** — Swiss; MakerDAO, Curve; formal-verification emphasis.
- **CertiK** — large; mixed researcher-community reputation on report depth; Skynet
  monitoring is widely used.
- **Quantstamp** — long-established; reputation mixed in recent years.

### Cross-link: audit reports are steelman artifacts

Cross-link [[steelman_doctrine_expertise.md]]. Structure: **Champion** (developer
intent), **Foil** (auditor findings — "here's where the contract diverges from intent
exploitably"), **Adjudicator** (severity + mitigation). Falsifiable findings — concrete
attack scenario, concrete testnet demo, concrete fix — same discipline as a steelman
round. Vague findings produce low-yield reports.

### Cross-link: audit is candidate-point code review at extreme severity

Cross-link [[code_review_expertise.md]]. Three smart-contract modifications:

1. **Severity is multiplied by TVL**: missing modifier on low-TVL → Medium; same
   missing modifier on high-TVL bridge → Critical. Evaluate in deployment context.
2. **Click-count is usually zero**: external call surface is zero-click; auth is the
   only gate. TAOSSA's multiplicative preconditions apply but multiplier is usually 1.
3. **No-emit failures are silent and permanent**: missed bugs surface as drains, not
   as warnings. No patch-later safety net.

### Audit-as-process

Phases: (1) Scoping (2-5 days); (2) Preliminary review — docs, code top-to-bottom,
candidate-point identification (1-2 weeks); (3) Deep review with PoC exploits (2-4
weeks); (4) Reporting (1-2 weeks); (5) Mitigation review of developer fixes (3-7 days).
Compress at your peril. Neodyme's pre-exploit (January 2022) Wormhole Solana review missed the
verification bug — "audited" does not mean "secure."

### Tincho methodology

(1) Read all documentation first — learn the jargon and what the protocol should do;
docs-vs-code discrepancy is itself a finding class. (2) Measure complexity with tooling
(CLOC, Solidity Metrics) and work through contracts systematically, smaller ones first.
(3) Think adversarially: every token type, access control. (4) Keep notes; verify
suspicions with tests such as fuzz tests. (5) Time-box the work; report with
mitigations, then review the fixes.

### cmichel methodology

Study common building blocks (token standards, proxies, MasterChef, Compound,
UniswapV2) and read exploit post-mortems; budget roughly 200 lines of code per hour
plus 5-10 hours for the report.

---

## 11. Defensive patterns

### Use OpenZeppelin / SafeERC20

Don't reinvent ERC-20/721 transfer, access control, reentrancy guards, upgradability,
timelocks. OpenZeppelin Contracts is audited many times over and battle-tested across
thousands of deployments. SafeERC20 wraps `transfer`/`transferFrom`/`approve` with the
right reverts for both spec-compliant and non-compliant tokens (USDT missing return
value); use it everywhere you touch arbitrary tokens.

### Reentrancy guard

Use OpenZeppelin `ReentrancyGuard` on any function making external calls:

```solidity
function withdraw() public nonReentrant {
    uint amount = balances[msg.sender];
    balances[msg.sender] = 0;
    (bool ok,) = msg.sender.call{value: amount}("");
    require(ok);
}
```

Combined with CEI, this defends against DAO-class reentrancy. For cross-function
reentrancy, all functions touching shared state must be guarded. For read-only
reentrancy, view-function consumers need the guard.

### Pull-over-push payments

Don't push to users; let them pull. Avoids DoS-via-revert (attacker's fallback reverts,
blocks the function for all users) and reduces reentrancy surface at cost of one extra
transaction per recipient.

### Upgradability patterns

- **Transparent Proxy** (ERC-1967 + OZ TransparentUpgradeableProxy): proxy routes admin
  calls to itself, non-admin to implementation. Admin and implementation slots at
  namespaced keccak-derived addresses.
- **UUPS** (ERC-1822 + OZ UUPSUpgradeable): upgrade function on the implementation, not
  the proxy. Smaller proxy; more per-implementation responsibility.
- **Beacon Proxy**: multiple proxies share a beacon holding the current implementation.

Common pitfalls: storage layout collision (don't change variable type/order; use
`__gap` arrays); initializer locked (call `_disableInitializers()` in implementation
constructor or an attacker calls `initialize()` directly); constructor vs initializer
(constructors don't run via the proxy; use `initializer` modifier on a separate
`initialize()`).

### Multi-sig + timelock for admin

(1) Admin = Gnosis Safe N-of-M multi-sig. (2) Multi-sig holds the role calling
privileged functions. (3) Critical functions gated by OZ TimelockController with
24-72h minimum delay. (4) Emergency pause may bypass timelock but lives in a smaller
fast-response multi-sig with pause-only power (no fund-touching). Even if the multi-sig
is compromised, timelock buys community response time.

### Formal verification for high-value contracts

For $100M+ TVL, use Certora or Halmos to verify critical invariants: total supply equals
sum of balances; pool LP redemption never exceeds pool TVL; liquidation only when
health-factor < 1; no path drains the contract without authorization. Cross-link
[[cryptography_expertise.md]] on epistemic limits — proofs reduce trust to spec and
prover soundness.

### Bug bounty programs

Pre-arrange before launch so researchers know to look. Maintain a public Immunefi
bounty with clear scope and severity tiers.

### Monitoring

OZ Defender Sentinel: condition-based alerts to Slack/PagerDuty. Forta: decentralized
detection. Tenderly Alerts: onchain event and state-change triggers. Cross-link
[[detection_engineering_expertise.md]] — Forta is to onchain what EDR is to endpoint.

### Insurance

Nexus Mutual: community-pooled coverage. Sherlock: audit + payout-guarantee.

### Code review checklist (12 items)

1. Every external state-changing function has explicit access control.
2. Every external call return value is checked.
3. Every storage write follows CEI order or is `nonReentrant`-guarded.
4. All arithmetic uses pragma >=0.8 default-reverting OR SafeMath/SafeCast OR
   justified `unchecked` blocks.
5. No `tx.origin` for authorization.
6. No `block.timestamp` as randomness.
7. No `delegatecall` to user-controlled addresses.
8. No `selfdestruct`.
9. All ERC-20 interactions use SafeERC20.
10. All signatures include nonce + chainId + contract address (EIP-712 domain
    separator); use ECDSA library not raw `ecrecover`.
11. Upgradeable contracts reserve storage gaps and call `_disableInitializers` in the
    constructor.
12. Admin functions gated by multi-sig + timelock with documented emergency bypass.

This is baseline, not exhaustive — it catches the most common real-world patterns.

---

## 12. Onchain detection — runtime

### Forta Network

Decentralized network of detection bots running independent logic against live chain
state. Bot operators stake FORT; alerts published for wallets, protocols, SOCs to
subscribe. Bots in Python/JS/TS against the Forta SDK; subscribe to block, tx, or log
events. Mariko Wakabayashi's ML team at OpenZeppelin/Forta has produced detection bots
that flagged $300M+ of pre-exploit anomalies. Latency bounded by block time (12s) plus
bot processing; single-block exploits complete before alerts fire.

### OpenZeppelin Defender Sentinel

Commercial counterpart to Forta. Define conditions; alerts and optional auto-response
(automatic pause via admin multi-sig on match). Standard onchain SOC stack: Defender
for own-contract alerts + Forta for ecosystem context.

### Tenderly Alerts

Alerting fires on onchain transactions (success/failure), contract state changes, and
view-function return-value changes after a transaction, routed to email, chat, incident
tools, or webhooks.

### Phalcon / BlockSec

Tx simulation + attack-pattern detection + protocol-level monitoring. BlockSec's
research team produces postmortems and pre-disclosed advisories. MetaSleuth fund-flow
tracking is the IR standard.

### Onchain SOC model

Cross-link [[detection_engineering_expertise.md]] — onchain detection is detection
engineering applied to chain events instead of endpoint telemetry, with gas-cost
adversary economics instead of process-spawn cost. Discipline transfers; tools and
signatures are domain-specific.

### SEAL 911

Sam Sun's Security Alliance runs a 24/7 emergency response line for crypto-side
incidents. Whitehats coordinate fund rescue, exchange freezes, legal protection.
Protocols-in-exploit coordinate response. Closer to fire-department mutual aid than
commercial SOC — peer-to-peer ecosystem self-defense.

---

## 13. Real incident anatomies

Brief, primitive, mitigation lesson.

- **DAO (June 2016, $60M)**. *Primitive*: reentrancy via `splitDAO` sending ether before
  zeroing balance. *Lesson*: CEI ordering + ReentrancyGuard.
- **Parity multisig (November 2017, $280M frozen)**. *Primitive*: delegatecall to library
  with anyone-callable `initWallet`; user became owner, then `selfdestruct`-ed the
  library. *Lesson*: never delegatecall to a target with anyone-callable state-modifying
  functions or `selfdestruct`.
- **bZx (February 2020, $1M)**. *Primitive*: flash-loan-driven oracle manipulation —
  a bZx margin short routed via Kyber into Uniswap pumped WBTC spot;
  attacker sold 112 WBTC borrowed from Compound into the inflated pool. *Lesson*: single-block AMM spot is never an oracle. The first widely-
  publicized flash-loan attack.
- **Compound Proposal 62 (September 2021, up to $80M misdistributed)**. *Primitive*: bug
  in the upgraded Comptroller the proposal deployed over-distributed COMP. *Lesson*: governance proposals
  are code; calldata-preview tooling (Tally) is mandatory.
- **Poly Network (August 2021, $610M, returned)**. *Primitive*: Manager contract forwarded
  arbitrary calls under its privilege; attacker forwarded a call that replaced the
  validator set; minted withdrawals with their own validators "signing". *Lesson*:
  privileged inter-contract relationships need access control at the boundary, not just
  per function.
- **Ronin Bridge (March 2022, $625M)**. *Primitive*: Lazarus spear-phished 4 of 9
  validator keys + stale delegation = 5/9 to forge withdrawals; undetected six days
  (no outflow monitoring). *Lesson*: validator key management + delegation expiry +
  outflow alerting.
- **Wormhole (February 2022, $325M)**. *Primitive*: deprecated `load_instruction_at`
  accepted a fake Instructions account, skipping signature verification. *Lesson*:
  deprecated APIs are deprecated for a reason; type-confusion at cross-chain verifiers
  is catastrophic.
- **Nomad (August 2022, $190M)**. *Primitive*: trusted root initialized to `0x00`
  matched the default-zero mapping return; any message proven-by-default. *Lesson*:
  zero-default semantics interact with sentinel values badly; public-mempool exploits
  replicate in seconds.
- **BNB Bridge (October 2022, $568M, ~$100M extracted)**. *Primitive*: forged IAVL
  Merkle proof — verifier accepted malformed proof authenticating arbitrary leaves.
  *Lesson*: cryptographic proof verification is its own audit target; the chain halt set
  precedent that BSC could be paused by validators.
- **Euler Finance (March 2023, $197M, returned)**. *Primitive*: `donateToReserves`
  (added to fix a smaller bug) lacked the health-check other state-modifying functions
  had; attacker self-liquidated for 20% penalty. *Lesson*: patches add bug surface;
  every state-modifying function must enforce all invariants.
- **Curve / Vyper (July 2023, ~$70M, ~70% returned)**. *Primitive*: Vyper compiler
  0.2.15/0.2.16/0.3.0 emitted reentrancy locks per-function rather than at a global slot,
  enabling cross-function reentrancy in factory-pool deployments. *Lesson*: compiler
  bugs are contract bugs; pin exact compiler version; auditing source isn't enough —
  bytecode is what runs.
- **KyberSwap Elastic (November 2023, $48M)**. *Primitive*: rounding error in
  reinvestment-liquidity calculation; tick manipulation triggered LP burn returning
  vastly more than deposited. *Lesson*: complex math (concentrated liquidity) requires
  Echidna invariant fuzzing.
- **Radiant Capital (October 2024, $50M)**. *Primitive*: multi-sig signer UI
  compromise — signers thought they were signing a benign tx; actual tx upgraded
  LendingPool to attacker code. *Lesson*: hardware wallets aren't sufficient if the
  signing UI can be compromised; out-of-band tx-parameter verification on a separate
  device is needed for high-value signings.

### Pattern across incidents

The 2020-2022 era was dominated by onchain bugs (oracle, reentrancy, math). 2023-2025
shifts toward access-control compromise (stolen keys, multi-sig phishing, frontend
hijacks) — the onchain audit discipline has caught most pure-code bugs; the attack
surface has moved up the stack to opsec and human factors.

---

## 14. Variant analysis — under-explored

### Cross-chain messaging-protocol composition

Protocols compose multiple bridges and messaging layers — a trade flows Ethereum -->
LayerZero --> Arbitrum --> Stargate --> Optimism. Each hop is a trust assumption; the
composition inherits the union. A bug at any seam drains the trade. Most security firms
audit one protocol in isolation. Recommended variant analysis: pick the top three
composed-bridge integrations by TVL; audit the seam, not the individuals. Solutions
involve shared-sequencer designs (Astria, Espresso), atomic L2 composability, cross-
domain solver networks.

### L2 sequencer trust model

Most L2s (Optimism, Arbitrum, Base, zkSync) run a single sequencer. Escape hatches via
L1 fault proofs (OP Stack Cannon, Arbitrum BoLD) or validity proofs (zkSync, Linea). Bug
surface: sequencer outage = liveness failure; sequencer-side bugs (OP-stack 2024 fault-
proof bugs disclosed by Offchain Labs on testnet pre-launch); trust shifts during training-wheels phase
(Base reached Stage 1, "limited training wheels", in April 2025); reorg risk on weak-finality L2s. Auditor
checklist: identify trust assumptions for the L2's current stage; design for worst case.

### Account Abstraction (ERC-4337)

UserOperations submitted to alt-mempool, validated and bundled by Bundlers, settled at
EntryPoint. Smart-contract accounts are first-class users; Paymasters sponsor gas in
any token. Bug surface:

- **Paymaster DoS**: malicious account constructs UserOp that passes validation but
  reverts during execution, costing the Paymaster. ERC-4337 storage-access rules during
  validation mitigate this; rules are intricate and enforcement varies by Bundler.
- **Signature aggregator bugs**: BLS aggregation across UserOps; aggregator bug
  authorizes unauthorized UserOps.
- **Bundler censorship and front-running**: same MEV dynamics as mempool; Paymaster
  reputation system gameable.
- **Account-template bugs**: bugs in Safe{Wallet}, Kernel, Biconomy affect many users.

Highest-velocity new attack surface in 2025. Cross-link [[code_review_expertise.md]] on
heterogeneous-auth: ERC-4337's `validateUserOp(...)` diversity means "tx.origin is the
user" and "msg.sender is an EOA" are no longer reliable assumptions for any onchain
protocol.

### Modular blockchain stacks (EigenLayer, Celestia)

EigenLayer restaking: ETH validators opt into additional duties (AVS — Actively
Validated Services), staking ETH against both Ethereum consensus violations and new
slashing conditions. Bug surface: slashing-condition design bugs (too lenient = unsafe;
too strict = false-positive slashing); operator over-restaking with correlated risk;
cascade failures where slashing in one AVS triggers operator exits across many.
Security model still being formalized; audit discipline lags protocol launches.

### MPC wallet vendor compromise

Threshold signature wallets (Fireblocks, BitGo, Coinbase Custody): no single party
signs unilaterally; signing requires N-of-M. Bug surface: MPC protocol bugs (Fireblocks
disclosed a TSS bug in GG18/GG20 in 2023); vendor-side compromise degrades to
(N-1)-of-(M-1); policy-engine bypass on whitelists and daily limits. Cross-link
[[cryptography_expertise.md]] on threshold signatures — primitives are well-understood;
bugs live in deployment.

### AI-generated smart-contract code

Copilot, Cursor, Claude Code, ChatGPT widely used to generate Solidity in 2025.
Standard safe-defaults gaps: forgotten `nonReentrant`; missing or wrong access modifiers;
no SafeERC20 wrapper; `tx.origin` for auth; plausible-but-wrong math. 2023 OpenZeppelin
Ethernaut study (Wakabayashi, Wegener): ChatGPT-4 passed 20/28 — useful for boilerplate,
not production. For auditors: ask if code was AI-generated; if yes, scrutinize the
standard gaps first.

### LLM agents as smart-contract auditors

LLM-based audit tools attempt to automate the audit
pipeline: docs ingestion, code summary, candidate-finding generation, dedup against
past reports. Useful for triage; not a senior-auditor replacement.

Cross-link [[llm_agent_security_expertise.md]]: when an LLM acts as an agent calling
tools to interact with onchain systems, the bugs are the agent's, not the contract's. A
misguided agent calling `approve(attacker, uint256.max)` is a new threat smart-contract
doctrine doesn't yet answer.

Prompt injection into Etherscan source or doc pages an auditor-LLM ingests is a new
attack surface specific to LLM-driven auditing.

---

## 15. References

### Tooling

- Slither — github.com/crytic/slither
- Slither paper (Feist, Grieco, Groce, 2019) — arxiv.org/abs/1908.09878
- Echidna — github.com/crytic/echidna
- Manticore — github.com/trailofbits/manticore
- Manticore-verifier (Trail of Bits, 2020) —
  blog.trailofbits.com/2020/07/12/new-manticore-verifier-for-smart-contracts/
- Mythril — github.com/ConsenSys/mythril
- Foundry — getfoundry.sh, github.com/foundry-rs/foundry
- Halmos — github.com/a16z/halmos
- a16z post on Halmos —
  a16zcrypto.com/posts/article/symbolic-testing-with-halmos-leveraging-existing-tests-for-formal-verification/
- Certora — certora.com
- Tenderly — tenderly.co
- Forta — forta.org, docs.forta.network
- OpenZeppelin Defender — defender.openzeppelin.com
- Phalcon / BlockSec — blocksec.com

### Libraries and best practices

- OpenZeppelin Contracts — github.com/OpenZeppelin/openzeppelin-contracts
- OpenZeppelin Contracts docs — docs.openzeppelin.com/contracts
- ConsenSys Smart Contract Best Practices —
  consensys.github.io/smart-contract-best-practices/
- Trail of Bits Building Secure Contracts — github.com/crytic/building-secure-contracts
- Vyper — github.com/vyperlang/vyper
- Damn Vulnerable DeFi (Tincho) — damnvulnerabledefi.xyz
- Ethernaut (OpenZeppelin) — ethernaut.openzeppelin.com
- Capture The Ether — capturetheether.com

### Contest and bounty platforms

- Code4rena — code4rena.com
- Sherlock — sherlock.xyz
- Cantina (Spearbit) — cantina.xyz
- Hats Finance — hats.finance
- Immunefi — immunefi.com

### Audit firm public reports

- Trail of Bits — github.com/trailofbits/publications
- OpenZeppelin Blog — blog.openzeppelin.com
- ConsenSys Diligence — consensys.io/diligence/audits/
- Halborn — halborn.com/blog
- Spearbit — github.com/spearbit/portfolio
- ChainSecurity — chainsecurity.com/audits

### Incident postmortems

- The DAO retrospective —
  blog.ethereum.org/2016/06/17/critical-update-re-dao-vulnerability
- Parity multisig kill — github.com/paritytech/parity-ethereum/issues/6995
- bZx incident — peckshield.medium.com/bzx-hack-full-disclosure-with-detailed-profit-analysis-e6b1fa9b18fc
- Compound Proposal 62 — blocksec.com/blog/the-butterfly-effect-the-compound-security-incident-caused-by-a-bugfix
- Mudit Gupta's Poly Network writeup — mudit.blog/poly-network-largest-crypto-hack/
- Ronin Bridge — roninchain.com/blog/posts/back-to-building-ronin-security-breach-6513cc78a5edc1001b03c364
- Halborn on Ronin — halborn.com/blog/post/explained-the-ronin-hack-march-2022
- Wormhole — halborn.com/blog/post/explained-the-wormhole-hack-february-2022
- Wormhole technical analysis (Kudelski) —
  kudelskisecurity.com/research/quick-analysis-of-the-wormhole-attack
- Nomad Bridge — immunefi.com/blog/bug-fix-reviews/hack-analysis-nomad-bridge-august-2022/
- Halborn on Nomad — halborn.com/blog/post/explained-the-nomad-hack-august-2022
- BNB Bridge — blocksecteam.medium.com (BlockSec's writeup)
- Euler Finance — euler.finance/blog/war-peace-behind-the-scenes-of-eulers-240m-exploit-recovery
- Cyfrin Euler deep-dive — cyfrin.io/blog/how-did-the-euler-finance-hack-happen-hack-analysis
- Curve / Vyper —
  halborn.com/blog/post/explained-the-vyper-bug-hack-july-2023
- Curve Pool Reentrancy Exploit Postmortem (LlamaRisk) — hackmd.io/@LlamaRisk/BJzSKHNjn
- KyberSwap Elastic — chainsecurity.com (postmortem) and Kyber Network's official disclosure
- Radiant Capital — community-disclosed via Radiant's X account; multiple independent
  writeups

### Standards and EIPs

- ERC-20 — eips.ethereum.org/EIPS/eip-20
- ERC-721 — eips.ethereum.org/EIPS/eip-721
- ERC-1155 — eips.ethereum.org/EIPS/eip-1155
- ERC-1967 (Proxy Storage Slots) — eips.ethereum.org/EIPS/eip-1967
- ERC-1822 (UUPS) — eips.ethereum.org/EIPS/eip-1822
- ERC-2612 (Permit) — eips.ethereum.org/EIPS/eip-2612
- ERC-4337 (Account Abstraction) — eips.ethereum.org/EIPS/eip-4337
- EIP-712 (Typed Data) — eips.ethereum.org/EIPS/eip-712
- EIP-6049 (selfdestruct deprecation) — eips.ethereum.org/EIPS/eip-6049

### Education

- Cyfrin Updraft — updraft.cyfrin.io
- Patrick Collins (Cyfrin founder) on auditing —
  patrickalphac.medium.com/top-7-smart-contract-auditors-bec7bd70dd9f
- cmichel "How to become a smart contract auditor" —
  cmichel.io/how-to-become-a-smart-contract-auditor/
- samczsun "Escaping the Dark Forest" — samczsun.com/escaping-the-dark-forest/
- Tincho audit methodology video —
  updraft.cyfrin.io/courses/security/first-audit/process-tincho
- The Red Guild — theredguild.org

### Research and academic

- Slither paper — arxiv.org/abs/1908.09878
- "SoK: Decentralized Finance (DeFi) Attacks" (2023) — arxiv.org/abs/2208.13035
- "SoK: A Review of Cross-Chain Bridge Hacks in 2023" — arxiv.org/abs/2501.03423
- Certora technical papers — certora.com/publications

### Detection and incident response

- SEAL 911 (Security Alliance) — securityalliance.org
- Forta Network bot SDK — docs.forta.network
- Chainalysis incident reports — chainalysis.com/blog
- Elliptic incident reports — elliptic.co/blog

---
