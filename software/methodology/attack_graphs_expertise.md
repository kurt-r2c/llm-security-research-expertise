# Attack Graphs — Expertise

Operational handbook for attack graphs as a systemic-posture-analysis technique. The DAG-topology generalization of attack trees (`[[reference-attack-trees]]`). Use this doc when modeling multi-step attacker progression through interconnected systems where shared sub-states matter — network topologies, microservice meshes, cloud-IAM permission graphs, container clusters — and where automated generation from configuration is more tractable than hand-authored trees.

Audience: AI agents, security architects, network defenders, cloud-security engineers, threat modelers. Imperative voice. The graph is a defender's planning aid, not an attacker's playbook; the techniques in this doc tell you what the attacker *could* do, not what they *will* do.

---

## §1 — What this is and why it exists

An **attack graph** is a directed graph whose nodes encode attacker capabilities and exploit steps, and whose edges encode the transitions an attacker can drive between them. Where an attack tree decomposes a single attacker goal hierarchically (one root, branches downward), an attack graph models the **entire state-space of attacker progression** through a system. Multiple initial states (different external footholds), multiple goal states (different objectives), and — load-bearing — multiple paths converge on shared intermediate states.

The structural insight: real systems have shared sub-states. Compromising machine A might enable downstream attacks on B, C, and D; B might be reachable from A, from C, or via another chain. A tree cannot represent this convergence — every path is independent and the analyst either duplicates the shared sub-state across branches (size cost) or omits the convergence (fidelity cost). A graph represents convergence natively. One node, many incoming edges, many outgoing edges.

**Where the graph form earns its complexity:**
- **Network topologies.** Compromising a single jumphost enables reach to every host that trusts it. Tree-form duplicates the jumphost step N times; graph-form collapses it to one node with N out-edges.
- **Cloud-IAM permission paths.** `iam:PassRole`, `sts:AssumeRole`, and resource-policy chains produce permission graphs where one role's compromise yields access to many downstream roles, and multiple compromise paths converge on the same high-value target.
- **Container and microservice topologies.** Pod-to-pod reachability + service-account permissions + mesh-policy traversal are inherently graph-shaped. Cross-link `[[reference-container-k8s-security]]`, `[[reference-service-mesh-security]]`, `[[reference-multi-cluster-istio-topologies]]`.

**Where the tree form remains preferable:** tabletop exercises and stakeholder narratives (single attacker, single goal); single-system threat models with no shared sub-state; red-team operational planning for one objective. The graph's multi-goal generality is overhead for these uses.

Attack trees and attack graphs are complements, not substitutes. Use `[[reference-attack-trees]]` for hand-authored, narrative enumeration. Use this doc for auto-generated, posture-wide analysis of interconnected systems.

This doc covers origin and canonical references (§2), notation and structure (§3), generation techniques (§4), graph variants (§5), quantitative analysis (§6), Bayesian attack graphs (§7), MDP and game-theoretic extensions (§8), real-world adoption (§9), comparative analysis vs attack trees (§10), 2024-2026 currency (§11), and honest failure modes (§12). Read §12 before claiming "we do attack-graph analysis."

---

## §2 — Origin and canonical references

The academic lineage is denser and more formal than the attack-tree lineage. Attack graphs emerged from the model-checking and network-vulnerability-analysis communities rather than from the operational-security-consulting tradition that produced attack trees.

**Phillips and Swiler — pre-formalization.** Cynthia Phillips, Laura Painton Swiler, "A graph-based system for network-vulnerability analysis," *Proceedings of the New Security Paradigms Workshop* 1998 `[unverified exact year — sometimes cited 1998, sometimes 1999]`. Same Sandia lineage that pre-dates Schneier's attack-tree popularization (cross-link to `[[reference-attack-trees]]` §2). The first published treatment of attack-graph-style network-vulnerability reasoning.

**Ammann + Wijesekera + Kaushik — the scalability paper.** Paul Ammann, Duminda Wijesekera, Saket Kaushik, "Scalable, graph-based network vulnerability analysis," CCS 2002, pp. 217-224.

Introduced the **monotonicity assumption** that makes scalable attack-graph generation possible: once an attacker has a capability, they do not lose it. Under monotonicity, generation is polynomial rather than exponential in the number of attacker states.

The Ammann-Wijesekera-Kaushik paper is the citation that every subsequent scalability-focused attack-graph paper builds on.

**Sheyner + Haines + Jha + Lippmann + Wing — the model-checking paper.** Oleg Sheyner, Joshua W. Haines, Somesh Jha, Richard P. Lippmann, Jeannette M. Wing, "Automated generation and analysis of attack graphs," *Proceedings of the 2002 IEEE Symposium on Security and Privacy* (S&P 2002), pp. 254-265. CMU + MIT Lincoln Labs collaboration. Used the NuSMV symbolic model checker to generate exhaustive attack graphs from a formal system model. Foundational for the model-checking-based generation approach (§4). Exponential worst-case but produces sound and complete graphs.

**Jajodia + Noel — TVA and the GMU lineage.** Sushil Jajodia and Steven Noel at George Mason University's Center for Secure Information Systems (CSIS) produced a large body of attack-graph research from the early 2000s onward. Noel + Jajodia, "Managing attack graph complexity through visual hierarchical aggregation," *Proceedings of the 2004 ACM Workshop on Visualization and Data Mining for Computer Security* (VizSEC/DMSEC 2004), introduced visual aggregation techniques (§5). Subsequent papers developed **Topological Vulnerability Analysis (TVA)** — the GMU attack-graph platform — and **Cauldron**, the commercialized product `[unverified specific commercialization timeline]`. The Jajodia-Noel lineage is the single largest body of attack-graph academic work.

**Ou + Govindavajhala + Appel — MulVAL.** Xinming Ou, Sudhakar Govindavajhala, Andrew W. Appel, "MulVAL: A Logic-based Network Security Analyzer," *Proceedings of the 14th USENIX Security Symposium* (USENIX Security 2005), pp. 113-128. Princeton. **Multi-host, multi-stage Vulnerability Analysis**: a Datalog-based reasoning engine that takes facts (network topology, host vulnerabilities from OVAL/NVD, service connectivity) and produces attack graphs via logic-programming inference. Polynomial-time generation. Scales to thousands of hosts. Remains the most-cited open-source attack-graph generator. The MulVAL approach (§4) is the practical alternative to model-checking-based generation.

**Ingols + Lippmann + Piwowarski — NetSPA and the MP graph.** Kyle Ingols, Richard Lippmann, Keith Piwowarski, "Practical Attack Graph Generation for Network Defense," *Annual Computer Security Applications Conference* (ACSAC 2006), pp. 121-130. MIT Lincoln Labs. Introduced the **multiple-prerequisite (MP) attack graph** (§5), which tracks attacker progress through prerequisites and produces smaller graphs than the full bipartite state-vulnerability form. NetSPA — Network Security Planning Architecture — is the Lincoln Labs operational system. Predecessor to the commercial sector that followed.

**Wang + Singhal + Jajodia + Frigault — Bayesian attack graphs.** Lingyu Wang (Concordia), Anoop Singhal (NIST), Sushil Jajodia (GMU), and Marcel Frigault (Concordia) developed Bayesian attack-graph machinery in a series of papers including "Measuring the Overall Security of Network Configurations Using Attack Graphs" (Wang + Singhal + Jajodia, *DBSec 2007*) and "Measuring network security using dynamic Bayesian network" (Frigault + Wang + Singhal + Jajodia, *QoP 2008*). Established the Bayesian-network semantics for attack graphs (§7) and the dynamic time-evolving variant.

**Chowdhary + Huang — modern extensions.** Ankur Chowdhary and Dijiang Huang at Arizona State University produced a large body of work on attack-graph generation in cloud and SDN environments and on ML-extensions to attack-graph analysis approximately 2015-2022 `[unverified specific publication years]`. The ASU group is one of the active modern academic centers.

**Foundational textbooks and surveys.**

- Jajodia + Noel + O'Berry, "Topological Analysis of Network Attack Vulnerability," in *Managing Cyber Threats* (Springer 2005) — operational treatment.
- Sheyner's CMU PhD thesis, "Scenario Graphs and Attack Graphs" (2004) — most thorough formal treatment.
- Kordy + Piètre-Cambacédès + Schweitzer, "DAG-based attack and defense modeling: Don't miss the forest for the attack trees," *Computer Science Review* 13-14: 1-38 (November 2014) — surveys the broader DAG-based threat modeling landscape including both attack trees and attack graphs.

---

## §3 — Notation and structure

An attack graph has a precise structure. Three primitive node types and one edge type carry most of the technique.

**Privilege / state nodes.** A state node encodes an attacker capability or system state — "attacker has root on host A," "attacker has user-level access on host B," "attacker has read access to database D," "attacker controls service-account SA-1." State nodes are typed by (principal, capability, target). Drawn as rounded rectangles or ovals.

**Vulnerability / exploit nodes.** An exploit node encodes a specific attack step — "exploit CVE-2024-XXXX on host B's web service," "abuse `iam:PassRole` to assume role R," "exploit Spring4Shell on the WAR deployed to host C." Exploit nodes are typed by (CVE or vulnerability class, target). Drawn as rectangles.

**Edges — preconditions and postconditions.** Edges connect state nodes to exploit nodes (preconditions: which capabilities does the attacker need to attempt the exploit?) and exploit nodes to state nodes (postconditions: which capabilities does the attacker gain on success?). The graph is **bipartite** in the canonical formulation — every edge crosses between state and exploit nodes. State → exploit edges encode AND-preconditions (the exploit requires *all* incoming preconditions). Exploit → state edges encode the new capabilities gained.

**Initial states.** A distinguished subset of state nodes represent the attacker's starting capabilities. Examples: "external network reach," "valid low-privilege credential on host X obtained from leaked credential dump," "phishing-installed implant on workstation W." Multiple initial states are typical — the graph models all attacker starting positions simultaneously.

**Goal states.** A distinguished subset of state nodes represent the attacker's objectives. Examples: "root on production database," "domain administrator," "exfil access to PII bucket," "control of the model-signing key." Multiple goals are typical — the graph models all attacker objectives simultaneously.

**The DAG property — canonical formulation.** The canonical formulation requires the graph to be a directed acyclic graph (DAG). Cycles would imply an attacker losing capabilities and regaining them, which violates the **monotonicity assumption** (Ammann + Wijesekera + Kaushik 2002): once an attacker has a capability, they do not lose it. Monotonicity is what makes polynomial-time generation tractable. Without monotonicity, generation is exponential and graphs become unusable at modest scale.

**Cycles in non-monotonic variants.** Some variants relax monotonicity to model state-rollback — session loss, credential rotation, patching during the attack — at the cost of generation tractability. These variants are academic; production tools assume monotonicity.

**Convergence — the graph's load-bearing structural property.** A single state node typically has many incoming exploit-edges (many ways to achieve it) and many outgoing exploit-edges (many ways the capability is leveraged). This convergence is the single property that distinguishes the graph form from a tree. If an analyst draws an "attack graph" that is actually a tree (every state node has at most one incoming edge), the analyst has not modeled the convergence and has lost the benefit of the graph form.

**Worked example structure.** A two-network attack graph fragment in text form:

```
Initial states:
  S0: external reach to DMZ web server
  S1: credentials from leaked dump (alice@corp)
Exploits:
  E1: SSRF on DMZ web (CVE-2024-XXXX)   pre: S0  post: S2
  E2: Phish alice's session cookie       pre: S1  post: S3
  E3: From S2, port-scan + find DB       pre: S2  post: S4
  E4: alice has DB admin; query DB       pre: S3  post: S5
Goal: S5 (read access to production DB)
```

S5 is reachable by two converging paths: (S0 → E1 → S2 → E3 → S4 → ...) and (S1 → E2 → S3 → E4 → S5). The graph models both; a tree must duplicate or omit.

**Text vs visual form.** Production tools generate visual graphs. They become unreadable beyond ~50 nodes. Operational analysis uses text-form representations (DOT, JSON, Datalog facts) under version control with tool-driven analysis. Aggregation and filtering (§5) are required for any human consumption of large graphs.

---

## §4 — Generation techniques

How is an attack graph generated? Four canonical approaches, each with a different scalability-vs-completeness tradeoff.

**Model-checking-based generation (Sheyner + Jha + Wing 2002).** Encode the system as a finite-state model (network topology, host configurations, vulnerability preconditions and postconditions) in the input language of a symbolic model checker (NuSMV is the canonical choice; SPIN has been used). Specify the attacker's goal as a reachability property. The model checker exhaustively explores the state space and produces the set of all attack paths. **Pros**: sound and complete; produces all paths. **Cons**: exponential worst-case in the number of attacker states; scales to ~tens of hosts before blowing up. **When to use**: small high-value subsystems (authentication backbone, key-signing infrastructure, root CA chain) where completeness matters more than scale.

**Logic-programming-based generation (MulVAL, Ou + Govindavajhala + Appel 2005).** Encode the system as Datalog facts: network topology (`hacl(srcHost, dstHost, protocol, port)`), host vulnerabilities (`vulExists(host, vulnID, program)`, `vulProperty(vulnID, range, consequence)`), service connectivity, and access-control facts. Encode the attacker's reasoning as Datalog rules (`execCode(P, User) :- vulExists(P, ...), networkServiceInfo(...), ...`). Run the Datalog engine; derived facts are the attack graph. **Pros**: polynomial time generation under monotonicity; scales to thousands of hosts; rules are extensible. **Cons**: requires accurate input facts (network topology, vuln scan results); Datalog rule corpus must encode all relevant exploits. **When to use**: production network analysis at enterprise scale. **MulVAL is the open-source reference implementation.**

**Forward-search-based generation.** BFS or DFS from initial states. For each currently-reached state, enumerate exploits whose preconditions are satisfied, fire them, add resulting states to the frontier. Repeat until no new states are reached. **Pros**: simple to implement; works without a model-checker or Datalog engine. **Cons**: requires explicit exploit-rule encoding; can be slow without good pruning. **When to use**: targeted analysis where you want to compute "what can the attacker reach from this specific foothold?"

**Backward-search-based generation.** From a specific goal state, identify exploits whose postconditions match the goal. For each such exploit, recursively identify exploits whose postconditions match the exploit's preconditions. Backward-chain until reaching initial states. **Pros**: useful when you have a specific high-value goal and want only paths leading to it. **Cons**: requires same input quality as forward search; misses goal-irrelevant paths (which may matter for detection or risk-rating). **When to use**: forensic reconstruction after an incident, or "could this critical asset have been reached given this network?"

**Hybrid + heuristic-pruning approaches.** Combine forward and backward search with heuristics — meet-in-the-middle reachability checks, pruning of low-probability or high-cost paths, attacker-skill thresholds. Modern production tools (Skybox, Cauldron, the cloud-IAM-graph vendors in §9) use heuristic-pruned hybrid approaches because pure model-checking does not scale and pure unfiltered MulVAL output is too large for human review.

**The input-fidelity problem applies to every approach.** Generation accuracy is bounded by input accuracy. Network topology, host vulnerabilities, service connectivity, access-control configuration — these must be accurate at the time of generation. Stale inputs produce stale graphs (§12.4). Cloud-dynamic environments where pods come up and down within minutes are particularly hostile to attack-graph generation.

---

## §5 — Attack graph variants

The basic bipartite state-exploit DAG has been refined into several variants, each optimizing different properties.

**Logical attack graph.** The bipartite state-vulnerability-state form described in §3. Captures all possible attack paths. Most complete but most cluttered. Suitable for automated reasoning; usually unsuitable for visual analysis without aggregation.

**Multiple-prerequisite (MP) attack graph (Ingols + Lippmann + Piwowarski 2006).** Three node types: state nodes (attacker reaches host), vulnerability nodes (specific exploit), and prerequisite nodes (intermediate AND-preconditions explicit). The MP form is smaller than the logical form for typical networks because preconditions are factored once and shared. Lincoln Labs NetSPA uses MP graphs. The MP form is the standard for operational use where graph size matters.

**Personalized attack graph.** A graph specialized to a specific attacker — their starting capabilities, skill level, available resources. Produced by pruning a full graph against attacker constraints. Useful when modeling specific threat actors (state-sponsored attacker with zero-days vs commodity ransomware operator vs disgruntled insider). The personalization step is the input to threat-actor-specific risk-rating in §6.

**Time-evolving attack graph.** Nodes and edges have time-attributes — when an exploit is available (CVE publication date), when patches are deployed, when configuration changes. Suitable for incident reconstruction ("what could the attacker have done given the network state at time T?") and for forecasting ("what will the attacker be able to do at time T+30 days assuming current patch cadence?").

**Hierarchical / aggregated attack graph (Noel + Jajodia 2004).** Subgraphs are collapsed into supernodes for visual analysis. Aggregation rules: by host group, by network segment, by exploit class, by attacker capability tier. The hierarchical form preserves the underlying graph for analysis while presenting a human-readable view. Without aggregation, graphs beyond ~100 nodes are unreadable. Aggregation is not optional in production — it is the only way humans interact with non-trivial graphs.

**Risk-weighted attack graph.** Edges annotated with risk scores (typically CVSS base score on exploit-edge plus impact rating on goal-state) rather than (or in addition to) probability and cost. The most common production variant — it is what CNAPP vendor tools surface in their UIs.

**Cloud-IAM attack graph.** A specialization where nodes are principals (users, roles, service accounts) and edges are permission grants (`iam:PassRole`, `sts:AssumeRole`, resource-policy grants). This shape is structurally the same as the general attack graph but the exploit-rule corpus is specialized to IAM mechanics. Cross-link to `[[reference-cloud-iam]]`. Tools: AWS IAM Access Analyzer, Wiz, Orca Security, Lightspin, the open-source PMapper (`[unverified` 2026 maintenance status of PMapper).

**Microservice / mesh attack graph.** Nodes are pods or workloads; edges are network reachability + service-account permissions + mesh-policy traversal. Cross-link to `[[reference-container-k8s-security]]`, `[[reference-service-mesh-security]]`, `[[reference-multi-cluster-istio-topologies]]`. Tools: kube-hunter, kubectl-who-can, Falco rule corpus (cross-link to `[[reference-falco-tetragon-runtime-detection]]`), commercial Wiz / Orca / Cisco-Hypershield-Panoptica.

**Supply-chain attack graph.** Nodes are build steps, package versions, signing keys; edges are dependency and trust relationships. Cross-link to `[[reference-cicd-supply-chain]]`, `[[reference-supply-chain-provenance]]`. The supply-chain variant is younger and the standardized graph model is less mature than the network or cloud-IAM variants `[unverified claim of relative maturity]`. The Shai-Hulud npm worm 2025 and the xz-utils CVE-2024-3094 backdoor are recent canonical supply-chain incidents that retrospectively benefit from attack-graph reconstruction.

**Adversarial-AI attack graph.** Initial state: attacker controls untrusted input that reaches an agent's context. Exploit nodes: tool-call invocations that move the agent into more-privileged states (MCP tool execution, shell command, file read). Goal states: exfiltration or destructive action. Cross-link to `[[reference-ai-agent-session-management]]`. The variant is research-grade in 2026 but the 6-incident corpus (EchoLeak, ShadowLeak, CurXecute, Comment-and-Control, Clinejection, MCPoison) is amenable to retrospective attack-graph reconstruction.

---

## §6 — Quantitative analysis

The attack graph is a structure; quantitative analysis is what makes it actionable. Five canonical computations.

**Path-cost analysis.** Each exploit node carries an attacker-cost annotation (dollar cost, time cost, or composite). Compute the minimum-cost path from any initial state to a target goal state via shortest-path algorithms (Dijkstra under non-negative weights; Bellman-Ford if weights can be negative under some model). The minimum-cost path identifies the attacker's preferred entry point under cost-rational assumptions. **Caveat**: real attackers do not always minimize cost — they minimize cost-subject-to-skill, time-subject-to-stealth, or other multi-criteria objectives.

**Path-probability analysis.** Each exploit node carries a per-exploit success probability. Under independence assumptions, the path-probability is the product of per-exploit probabilities. Under non-independence (correlated exploits), probabilistic graphical models apply (§7). The probability-of-reaching-goal is the union over all paths, computed via inclusion-exclusion or Monte Carlo. **Caveat**: independence is almost never accurate (cross-link to `[[reference-attack-trees]]` §10 — same finding for trees).

**Risk-as-expected-impact.** Risk-rate a goal as P(reach goal) × impact(goal). The expected-impact framing produces a risk-ranking of goals. Useful when triaging which defenses to invest in. **Caveat**: impact estimates are usually political (cross-link to `[[reference-game-theory-mechanism-design-security]]` for risk-as-mechanism-design).

**Attack-surface metrics.** Count of goal states reachable from any initial state; count of distinct paths to specific goal; depth (number of exploits) to reach the closest goal. These metrics are useful for trending — does the attack-surface metric improve or worsen across configuration changes? — but absolute values are calibration-dependent.

**Defender-side optimization (the load-bearing operational question).** Which subset of vulnerabilities should I patch — or which subset of mitigations should I deploy — to maximally reduce attacker-paths-to-goals? Formally, this is a graph-modification optimization: minimize attacker-success-probability subject to a defender budget. **Several formulations**: minimum-cut problems (remove fewest edges to disconnect goals from initial states), set-cover problems (which mitigations cover the most attack paths?), Stackelberg-game formulations (defender chooses mitigations, attacker responds optimally). Most are NP-hard in worst case; production tools use heuristics + approximation algorithms.

**Sensitivity analysis is non-optional.** Per-exploit cost and probability inputs are expert-elicited guesses. A defensible quantitative analysis presents results as ranges over input perturbations of ±50% or 2x. A single-point risk number without sensitivity is precision-theater. Cross-link to `[[reference-attack-trees]]` §10 — the same discipline applies to graphs.

**The quantitative GIGO problem.** Same as attack trees (cross-link to `[[reference-attack-trees]]` §12.2). Cost, probability, and impact inputs are guesses. Sophisticated analysis on garbage inputs produces sophisticated-looking garbage. Sensitivity analysis is the primary mitigation; the secondary mitigation is honest framing — present results as relative rankings of mitigations against each other, not as absolute risk numbers.

---

## §7 — Bayesian attack graphs (BAG)

The Bayesian attack graph variant adds probabilistic dependency structure on top of the basic graph.

**Wang + Singhal + Jajodia and Frigault et al. 2007-2008.** Lingyu Wang (Concordia), Anoop Singhal (NIST), Sushil Jajodia (GMU), and Marcel Frigault (Concordia) developed the Bayesian semantics across several papers including "Measuring the Overall Security of Network Configurations Using Attack Graphs" (DBSec 2007) and Frigault + Wang + Singhal + Jajodia "Measuring network security using dynamic Bayesian network" (QoP 2008) `[unverified specific page numbers]`.

**Bayesian network semantics.** Each state node has a conditional probability table (CPT) that specifies P(state | parent states). The CPT encodes how exploit success depends on prior attacker capabilities. Unlike the independence-product approach in §6, the CPT can encode correlated exploit success — if two exploits target the same vendor's vulnerability class, their success probabilities are correlated.

**Inference.** Standard Bayesian-network inference algorithms (variable elimination, junction-tree, loopy belief propagation, MCMC) compute marginal probabilities P(reach goal | observations). Observations might include: "we patched CVE-X on host Y," "we observed an alert indicating exploit Z was attempted," "we deployed mitigation M." The inference produces updated risk estimates after observations.

**Dynamic Bayesian attack graphs.** Time-evolving variant. The graph is unrolled over time slices; nodes at time t depend on nodes at time t-1. Captures patching cycles, attacker dwell time, defender response. Useful for forecasting and for retrospective incident-reconstruction reasoning.

**Use cases.**

- **Probabilistic risk assessment.** Compute P(specific high-impact compromise within N days) given current configuration.
- **Sensitivity analysis (the load-bearing use).** Compute ∂P(compromise)/∂(per-CVE probability) to identify which CVE matters most to the overall risk. Tells the defender where patching has the biggest marginal impact.
- **Mitigation prioritization.** Compute the expected risk reduction from each candidate mitigation; rank by expected reduction.
- **Continuous risk monitoring.** Update the Bayesian network as configuration drifts; track risk over time.

**Tooling — academic, sparse, no production stack.** Academic implementations use SamIam (UCLA), Hugin (commercial Bayesian-network tool), GENIE (University of Pittsburgh) `[unverified specific institutional affiliations and current availability]`. There is no widely-deployed production Bayesian-attack-graph tool. The MulVAL Bayesian-extensions and academic GMU + Concordia tooling are research-grade.

**Limitations.**

- **CPT elicitation is harder than point-estimate elicitation.** Subject-matter experts can guess "70% probability of success"; they struggle with full conditional probability tables.
- **Inference scaling.** Exact inference is exponential worst-case; approximate inference adds another layer of calibration uncertainty.
- **Independence-vs-dependence calibration is poor.** Real-world correlation structure between exploits is rarely known; defaulting to independence is wrong but defaulting to "everything depends on everything" is intractable.

**Where Bayesian attack graphs earn their complexity.** When the defender needs to compute "given that we observed alert A, how much does P(compromise) increase?" or "given that we patched CVE-X, how much does P(compromise) decrease?" — these are Bayesian-update questions that the static path-probability approach in §6 cannot answer.

**Worked-example fragment.** A simple BAG over the §3 example. Node S5 (read access to production DB) has parent state S4. The CPT for S5 given S4: P(S5 | S4) = 0.7 if exploit E3 succeeded; P(S5 | ¬S4) = 0.05 (some side-channel residual risk). Conditional on observing an alert that fires on E3-style port-scans (alert A with detection probability 0.8 given E3), P(E3 | A) is updated via Bayes' rule; cascading through to P(S5 | A) updates the overall compromise probability. The mechanics are standard Bayesian-network inference; the load-bearing operational discipline is keeping CPTs current and honest about their elicitation provenance.

---

## §8 — Markov decision processes and game-theoretic extensions

Beyond Bayesian probability, attack-graph analysis can be cast as sequential decision-making under uncertainty.

**MDP formulation.** Model attacker progression as a Markov Decision Process: states are attacker-capability tuples, actions are exploit attempts, transition probabilities encode exploit success, rewards encode attacker utility (negative cost + positive goal-reach reward + negative detection-risk). Solve for the attacker's optimal policy via value iteration, policy iteration, or reinforcement learning. The optimal policy is the attacker's best strategy under cost-rational + probability-aware assumptions.

**POMDP — partial observability.** In reality, the attacker does not have full visibility of system state. Model as Partially Observable MDP (POMDP): the attacker observes outcomes of exploit attempts but does not directly see system configuration. POMDP-optimal attacker strategies are more realistic than MDP-optimal but computationally harder.

**Stackelberg game — defender moves first.** The defender chooses a mitigation strategy (which subset of exploits to patch, which detections to deploy); the attacker observes the defender's strategy and best-responds. The defender's optimal strategy is a Stackelberg-equilibrium solution. Cross-link to `[[reference-game-theory-mechanism-design-security]]` for the broader game-theoretic discipline.

**Computational complexity — PSPACE-hard worst case.** MDPs over realistic attack graphs are PSPACE-hard in the worst case. POMDPs are undecidable in general. Production approximations use bounded-horizon search (only consider paths of length ≤ k), Monte Carlo Tree Search (anchored in AlphaZero-style approaches `[unverified` direct deployment to attack-graph analysis), or reinforcement learning with deep function approximation.

**Academic centers.** Branislav Bošanský and others publish on MDP/POMDP/Stackelberg formulations over attack graphs `[unverified specific paper attributions]`. The Game Theory and Security workshop series (GameSec, founded 2010) is the canonical venue. Production deployment is sparse — most operational tools stop at unweighted DAG.

**When MDP/POMDP/Stackelberg formulations earn their complexity.** Adversarial reinforcement learning research (academic); Moving Target Defense policy optimization (when defender strategy is dynamic — rotate keys, shuffle configs, deploy decoys); cyber-insurance pricing (when the insurer needs attacker-optimal-behavior risk estimates). For day-to-day defender planning, MDP overhead is rarely worth it. Use the simpler frameworks in §6 and §7.

---

## §9 — Real-world adoption and case studies

Where attack graphs actually run in production.

**NIST SP 800-30 Rev. 1 (Guide for Conducting Risk Assessments, September 2012)** references graph-based analysis techniques (e.g., attack tree analysis) as one way to conduct more rigorous analysis. NIST does not mandate attack graphs but legitimizes them.

**MIT Lincoln Laboratory NetSPA work.** The MIT Lincoln Labs NetSPA system (Ingols + Lippmann + Piwowarski 2006) generates multiple-prerequisite attack graphs.

**GMU CSIS Cauldron.** Jajodia's George Mason CSIS produced TVA and its commercialized successor Cauldron.

**Skybox and RedSeal — enterprise network vendors.** Skybox built a commercial network-attack-graph + ASM platform combining firewall-policy, vulnerability data, and network topology (Skybox ceased operations in February 2025). RedSeal Networks built an adjacent network-mapping platform.

**Continuous-attack-emulation vendors.** AttackIQ, SafeBreach, Cymulate use attack-graph reasoning to chain attack-technique tests into multi-step scenarios. Output is "you are vulnerable to this attack chain" rather than "you are vulnerable to this CVE."

**Cloud-IAM attack graphs — the most active production area.** Cloud-IAM permission graphs are the natural attack-graph substrate in 2024-2026.

- **AWS IAM Access Analyzer** produces public and cross-account access findings via automated reasoning (Zelkova, an SMT-based policy analysis engine).
- **Wiz, Orca Security, Lightspin** (acquired by Cisco, 2023), CrowdStrike Falcon Cloud Security, Sysdig, Lacework — all CNAPP vendors that compute cloud-IAM attack graphs as part of their product.
- **PMapper** (NCC Group) — open-source AWS permission-graph generator + Neo4j-based analysis.
- **Cloudsplaining** (Salesforce) — IAM-policy linter that surfaces permission-graph anti-patterns.

**Capital One 2019 post-incident analysis** (cross-link to `[[reference-cloud-iam]]`). The Capital One breach involved a multi-step IAM-permission chain: SSRF on a misconfigured WAF instance allowed retrieval of EC2-instance-role credentials, which had `s3:GetObject` on multiple buckets including the customer-data bucket. Post-incident analysis revealed this as a textbook attack-graph chain that would have been visible in a permission-graph tool had one been deployed. The Capital One case has been used as motivation for the cloud-IAM-attack-graph product category.

**Kubernetes attack graphs.** Pod-to-pod reachability + service-account permissions + admission-control-policy traversal. Tools: kube-hunter, kubectl-who-can, kubescape, Wiz / Orca / Sysdig / Aqua / Falco-rule corpus (cross-link to `[[reference-falco-tetragon-runtime-detection]]`). Cisco Hypershield + Panoptica (post-Isovalent acquisition, 2024) marketed cluster-attack-graph reasoning + automated mitigation `[unverified specific Hypershield feature set as of 2026]`.

**MITRE Engenuity Center for Threat-Informed Defense.** Produces attack-graph-aligned threat-modeling outputs at the ATT&CK technique level. The "Attack Flow" specification (Center for Threat-Informed Defense, 2022; v2.0 released October 2022) defines an attack-graph format built as a STIX 2.1 extension.

---

## §10 — Attack graphs vs attack trees — comparative analysis

The two techniques are complements; the choice between them is principled.

**Structural difference.** A tree has one root, every node has exactly one parent. A graph has multiple sources (initial states), multiple sinks (goal states), and a node can have many parents. The tree models a single objective with branching decomposition; the graph models multiple objectives and multiple footholds with state-space convergence.

**Authoring effort.** Attack trees are hand-authored over weeks to months — the act of authoring is the value, forcing explicit enumeration of attacker alternatives. Attack graphs are auto-generated from inputs (network topology, vulnerability scan results, IAM policy, container topology) — the auto-generation is the value, producing exhaustive analysis no human would author by hand. Hand-authored graphs are rare; auto-generated trees are rare.

**Scale.** Typical attack tree: 20-200 nodes (human-reviewable). Typical attack graph: 1,000-100,000 nodes (exceeds visual analysis; requires aggregation per §5).

**Composition.** Attack trees can be extracted from attack graphs by backward-slicing from a goal node. The slice can be re-presented as a tree (duplicating convergence) or as a sub-graph (preserving convergence). Conversely, attack trees can be combined into attack graphs by identifying shared sub-states and merging on those nodes.

**When to use which — operational guidance.**

- **Attack trees:** tabletop exercises, training scenarios, stakeholder workshops, red-team objective planning, high-impact attacker goals where hand-curated quality matters more than completeness.
- **Attack graphs:** systemic posture analysis across networks or cloud environments, cloud-IAM audit, Kubernetes cluster analysis, continuous monitoring as configuration drifts, quantitative risk computation over the full attack surface.
- **Both:** high-value goal in a complex environment. Graph for completeness; extract sub-trees for stakeholder communication; tree-form for tabletop, graph-form for automated reasoning.

**Quantitative analysis differences.** Both support cost / probability / risk computation. Trees use propagation rules (OR-min, AND-sum). Graphs use shortest-path and graph-traversal algorithms. Bayesian semantics (§7) is more natural over graphs (DAGs are also Bayesian-network structures) than over trees. MDP/POMDP/Stackelberg (§8) is more natural over graphs.

**Honest framing — both share fundamental limitations.** Both rely on expert-elicited cost/probability inputs (GIGO). Both assume linear attacker behavior when reality is opportunistic. Both can become performative without driving mitigations. Cross-link `[[reference-attack-trees]]` §12.

---

## §11 — 2024-2026 currency

The state of practice as of 2026.

**Cloud-IAM attack graphs are the dominant production substrate.** The CNAPP (Cloud-Native Application Protection Platform) vendor category — Wiz, Orca, Sysdig, Lacework, Palo Alto Prisma Cloud, CrowdStrike Falcon Cloud Security — compute cloud-IAM permission graphs as a core product feature. The pattern: ingest AWS / Azure / GCP IAM configuration → build permission graph → identify multi-hop privilege-escalation paths → surface as findings. This category did not exist in 2018; it is mainstream in 2026 `[unverified` specific 2026 market share figures).

**Kubernetes and microservice attack graphs.** Mesh-policy + pod-network-policy + service-account-permission graphs are emerging as a sub-category. Cilium ClusterMesh (cross-link to `[[reference-cilium-cluster-mesh]]`) and Cisco Hypershield + Panoptica push automated cluster-attack-graph reasoning. Production maturity is younger than the cloud-IAM case `[unverified` relative maturity claim).

**AI-augmented attack graph generation.** LLM-assisted exploit-rule generation, path enumeration, and explanation are research-grade as of 2026. Pattern: feed the LLM a network configuration; ask for likely attack paths; the LLM produces plausible-looking output. The output is not yet trustworthy for unsupervised use (LLM regresses on novelty — same failure mode as in `[[reference-threat-modeling-discipline]]` §12 and `[[reference-attack-trees]]` §12.7).

**Adversarial-AI attack graphs.** A novel application: model AI-agent tool-call paths as attack graph nodes. Initial state is "attacker controls untrusted input that reaches the agent's context"; exploit nodes are tool-call invocations; goal states are exfiltration or destructive actions. Cross-link to `[[reference-ai-agent-session-management]]` §9 — the EchoLeak, ShadowLeak, CurXecute, Comment-and-Control, and Clinejection incidents are amenable to attack-graph reconstruction. This application is research-grade in 2026.

**MITRE Engenuity Attack Flow.** Attack-graph format built as a STIX 2.1 extension; v2.0 published October 2022. Adoption is uneven; format mature enough for cross-vendor interoperation but tooling is sparse.

**OpenC2 and ATT&CK-aligned automation.** OASIS OpenC2 is a standardized command language for orchestrating mitigations. Combined with ATT&CK techniques, OpenC2 enables attack-graph-driven mitigation orchestration: identify the path, deploy mitigations along it. Production adoption is early `[unverified 2026 adoption breadth]`.

**Game-theoretic and reinforcement-learning research.** The academic frontier includes MDP/POMDP/RL formulations (§8) and adversarial training of attacker policies. DARPA programs including AI Cyber Challenge (AIxCC, 2025) (cross-link to `[[reference-ai-red-team-operator-playbook]]`) push toward automated offensive and defensive reasoning over attack graphs `[unverified specific program scope as of 2026]`.

---

## §12 — Honest failure modes

Load-bearing. Read these before claiming "we do attack-graph analysis."

**1. Graphs blow up exponentially in worst case.** Model-checking-based generation (§4) is exponential in attacker-state. Without monotonicity (Ammann + Wijesekera + Kaushik 2002), generation is intractable beyond ~tens of hosts. Even with monotonicity (MulVAL Datalog), the output graph can have thousands of nodes for moderately complex networks. Polynomial generation does not mean polynomial-sized output.

**2. Visual analysis breaks down at scale.** Hundreds of nodes is the practical ceiling for human visual analysis. Aggregation (Noel + Jajodia 2004), filtering by attacker goal, and personalization (§5) are required for any human consumption of large graphs. Without aggregation, the "wall of arrows" diagram has zero analytic value. A pretty graph is not analysis.

**3. Quantitative GIGO.** Same as attack trees (cross-link to `[[reference-attack-trees]]` §12.2). Per-exploit cost and probability inputs are expert-elicited guesses. Sophisticated analysis on garbage inputs produces sophisticated-looking garbage. Sensitivity analysis is the primary mitigation; presenting results as ranges and as relative rankings is the secondary mitigation.

**4. Static analysis is stale fast.** Networks and cloud configurations change daily. An attack graph computed weekly is out of date within hours in a dynamic environment. Cloud-IAM graphs can drift in minutes (someone creates a role; someone modifies a policy). Continuous-monitoring posture requires re-generation on every configuration change; few production deployments achieve this cadence.

**5. Generation depends on accurate input.** Network topology, vulnerability scan results, service connectivity, and access-control configuration must be accurate. Production tools struggle with:

- **Cloud-dynamic environments** — pods, lambdas, and serverless containers that come up and down within minutes.
- **Microservice meshes** — mesh policies as effective network topology are difficult to model.
- **Identity federations** — cross-account, cross-cloud, federated IdP chains produce permission paths that single-account-scanning tools miss.

**6. MDP and Bayesian variants add academic depth but production tools are sparse.** Most operational attack-graph tools stop at unweighted DAG with basic shortest-path. Bayesian and MDP analysis is research-grade. Defenders who claim "we do Bayesian risk analysis" should be asked to produce the CPTs.

**7. No standardized format.** STIX has attack-graph extensions (MITRE Engenuity Attack Flow) but adoption is uneven. Vendor formats are proprietary. Cross-tool integration is poor. Defenders cannot easily compose graphs from multiple tools.

**8. Attack graphs frame "what attacker could do" not "what attacker will do."** Real attackers pick paths opportunistically. They discover vulnerabilities serendipitously and pursue them rather than enumerating and executing the full graph. The attack graph is a defender's planning aid; it does not predict attacker behavior. Cross-link to `[[reference-attack-trees]]` §12.10 — the same finding for trees.

**9. Cloud-IAM attack graphs face the "shadow admin" problem.** Indirect permission paths via `iam:PassRole` chains, `sts:AssumeRole` hops, resource-policy grants, and cross-account trust relationships produce permission paths that direct-grant scanning misses. Production tooling catches direct paths and one-hop indirect paths; 2-3-hop indirect paths and chained-federation paths are frequently missed. The Capital One 2019 case is the canonical example of a 2-hop path that was visible in retrospect but not in the deployed scanning at the time.

**10. LLM-augmented graph generation regresses on novel exploits.** Same finding as threat modeling and attack trees. LLMs trained on the public CVE corpus reproduce known exploit patterns and miss novel ones. AI-augmented attack-graph generation is best used in a three-pass workflow: LLM enumerates breadth, human reviewer catches novel exploits, human prioritizes by risk-rating. Cross-link to `[[reference-threat-modeling-discipline]]` §12.

**11. Defender-side optimization is NP-hard in general.** The minimum-cost-mitigation problem (which subset of patches minimizes attacker success?) is NP-hard. Production tools use heuristics and approximation. Optimal solutions are computable for small subgraphs; "the tool says this is the optimal mitigation set" should be interpreted as "the tool's heuristic prefers this set."

**12. "We did attack-graph analysis" defense.** Same failure mode as the parent disciplines. Producing a graph and a report does not constitute risk reduction unless the report drives mitigations and the mitigations are deployed and tested. Cross-link to `[[reference-misuse-abuse-case-modeling]]` §12.8 and `[[reference-cast-causal-analysis-stamp]]` §12.6 — the performative-methodology failure recurs across every threat-modeling and risk-analysis technique.

---

## §13 — Cross-link cluster

- `[[reference-attack-trees]]` — the parent technique; hand-authored, narrative branching enumeration. This doc's most important sibling.
- `[[reference-threat-modeling-discipline]]` — STRIDE / PASTA / LINDDUN parent methodology; attack graphs slot into Stage 6 of PASTA.
- `[[reference-misuse-abuse-case-modeling]]` — narrative attacker-story technique; complements graphs for stakeholder communication.
- `[[reference-cloud-iam]]` — IAM permission graphs are the dominant production attack-graph substrate as of 2026.
- `[[reference-container-k8s-security]]` — Kubernetes pod / service-account / network-policy graphs.
- `[[reference-service-mesh-security]]` — mesh-policy + identity graphs.
- `[[reference-multi-cluster-istio-topologies]]` — cross-cluster attack graph topologies.
- `[[reference-cilium-cluster-mesh]]` — eBPF-native multi-cluster attack-graph substrate.
- `[[reference-zero-trust-workload-identity]]` — workload-identity edges in microservice attack graphs.
- `[[reference-cicd-supply-chain]]` — build-pipeline attack graphs; supply-chain variant.
- `[[reference-supply-chain-provenance]]` — SLSA / sigstore / in-toto inputs to supply-chain attack graphs.
- `[[reference-vr-methodology]]` — variant analysis as the bug-finding sibling of graph-driven path analysis.
- `[[reference-code-review-expertise]]` — review-time complement to design-time graph analysis.
- `[[reference-game-theory-mechanism-design-security]]` — Stackelberg / MDP / POMDP attacker-defender game-theoretic formulations.
- `[[reference-detection-engineering]]` — detections placed along attack-graph edges; coverage analysis.
- `[[reference-falco-tetragon-runtime-detection]]` — runtime detection coverage over Kubernetes attack-graph edges.
- `[[reference-ai-agent-session-management]]` — agent-tool-call paths as attack-graph nodes; 2024-2026 frontier application.
- `[[reference-cast-causal-analysis-stamp]]` — post-incident analysis sibling; attack-graph traversal as forensic reconstruction.

---

## §14 — Operational checklist

Use this before claiming "we have attack-graph analysis."

1. **Define initial states and goal states explicitly.** Specify external networks, credentials, footholds. Goal states must be testable yes/no determinations.
2. **Match generation technique to scale.** Model-checking for small high-value subsystems; MulVAL Datalog for enterprise networks; vendor CNAPP for cloud-IAM; cluster tooling for Kubernetes.
3. **Verify input fidelity at generation time.** Re-generate on configuration change; do not trust a graph computed last week.
4. **Aggregate and filter for human review.** Raw graphs beyond ~100 nodes are unreadable. Aggregate by host group, exploit class, attacker goal; filter by capability tier.
5. **Run sensitivity analysis.** Perturb cost and probability inputs by ±50% or 2x. If conclusions change, the analysis is not robust.
6. **Present results as relative rankings, not absolute risk numbers.** "Mitigation A reduces attacker paths to goal X by 60% relative to no mitigation" is defensible. "Risk is 0.073" is precision-theater.
7. **Cross-check with attack trees and misuse cases.** Hand-author 3-5 attack trees for high-value goals; check they appear as sub-graphs of the auto-generated graph. Discrepancies are findings.
8. **Drive mitigations from the analysis.** Each report includes specific recommendations, owners, deadlines. Track implementation.
9. **Re-generate on cadence.** Weekly minimum for cloud-IAM; on-deploy for production network and cluster topology. Cadence below configuration-change rate is stale.
10. **Audit for "shadow admin" patterns by hand.** Cloud-IAM tools miss 2-3-hop indirect permission paths. Periodically audit `iam:PassRole` chains and federated trust paths. Capital One 2019 is the lesson.
11. **Do not claim Bayesian or MDP analysis without producing CPTs or policy.** Most production tools stop at unweighted DAG.
12. **Honest framing in the report.** State input assumptions, sensitivity ranges, generation limitations, and the "what attacker could do, not will do" caveat.

---

End. Read §12 before claiming "we do attack-graph analysis." Cross-link to `[[reference-attack-trees]]` for the parent technique.
