# Attack Trees — Expertise

Operational handbook for attack trees as a threat-modeling and red-team planning technique. Third leg of the threat-modeling triangle alongside `[[reference-threat-modeling-discipline]]` (the parent methodology) and `[[reference-misuse-abuse-case-modeling]]` (the narrative-enumeration technique). Use this doc when enumerating the branching alternatives an attacker has at each step of a multi-step attack and when annotating those alternatives with cost, probability, skill, time, or detection-risk attributes.

Audience: AI agents, security architects, threat modelers, red-team strategists. Imperative voice. Skip the diagram theater; structured text and version-controlled trees beat slide-deck graphics.

---

## §1 — What this is and why it exists

An **attack tree** is a hierarchical, branching enumeration of the ways an attacker can achieve a goal. The root is the attacker's top-level objective ("Steal company financials," "Disable authentication," "Exfiltrate training data from the production model"). Children of a node represent ways to achieve the parent. Leaves are atomic attacks the attacker can attempt without further decomposition. Branches connect via AND-semantics (all children required) or OR-semantics (any child suffices). Annotations on leaves and propagation rules up the tree turn the diagram into a quantitative model of attacker choice.

Attack trees occupy a specific slot in the threat-modeling toolkit:
- **STRIDE** is a **coverage** technique: enumerates threats per data-flow element. Asks "what could go wrong at each interface?"
- **Misuse cases** are a **narrative** technique: end-to-end attacker scenarios. Asks "how does the attacker traverse the system?"
- **Attack trees** are a **branching-enumeration** technique: alternative paths the attacker has at each step. Asks "given the attacker's goal, what alternatives exist, and how do they compare on cost, probability, skill, and detection risk?"

The structural insight that motivates attack trees: a real attacker does not follow a single path. The attacker chooses among alternatives based on what is cheap, what they have skill for, what is likely to succeed, and what is likely to be detected. A linear narrative (one misuse case basic flow) hides that choice. A flat list of threats (STRIDE output) hides the dependencies between threats. The attack tree makes the choice and the dependencies first-class.

Run STRIDE for breadth across all elements. Write misuse cases for the headline attacker stories. Build attack trees for the high-impact attacker goals where you need to reason about alternatives, costs, and where to invest defenses. The three techniques are complements, not substitutes. Cross-link to `[[reference-threat-modeling-discipline]]` for the parent methodology and `[[reference-misuse-abuse-case-modeling]]` for the narrative technique.

This doc covers notation (§3), worked examples (§4), quantitative analysis (§5), attack-defense trees (§6), tooling (§7), tree-as-code patterns (§8), integration with sibling methodologies (§9), best practices and limitations on quantitative analysis (§10), real-world adoption (§11), and honest failure modes (§12). Read §12 before claiming "we do attack-tree analysis."

---

## §2 — Origin and canonical references

Attack trees have a longer pre-history than the canonical citation suggests, but the canonical citation is unambiguous.

**Schneier — the canonical popularization.** Bruce Schneier, "Attack Trees," *Dr. Dobb's Journal*, December 1999. The paper that named the technique and gave it the goal-as-root, sub-goals-as-children, leaves-as-concrete-attacks structure every subsequent treatment inherits. Expanded in *Secrets and Lies: Digital Security in a Networked World* (Wiley, 2000), chapter 21. The canonical "Open a safe" worked example (§4) and the OR-min / AND-sum cost propagation rule already appear in the *Dr. Dobb's* article. Read the *Dr. Dobb's* article first; it is short and operational.

**Sandia — the pre-Schneier engineering tradition.** Cynthia Phillips, Laura Painton Swiler, "A graph-based system for network-vulnerability analysis," *Proceedings of the New Security Paradigms Workshop* 1998. Predates Schneier's *Dr. Dobb's* paper; developed attack-tree-style network-vulnerability graphs in a defense-engineering context. Schneier popularized; the engineering roots are older.

**Mauw and Oostdijk — formal semantics.** Sjouke Mauw, Martijn Oostdijk, "Foundations of Attack Trees," *ICISC 2005*, LNCS 3935, pp. 186-198, Springer 2006. First rigorous formalization of attack-tree semantics as a propositional logic over leaf-attack labels. Established when two trees are equivalent, when one attack subsumes another, and what a propagated attribute formally means. Read this when defending "our cost model is well-defined."

**Kordy and the attack-defense-tree extension.** Barbara Kordy, Sjouke Mauw, Saša Radomirović, Patrick Schweitzer, "Foundations of Attack-Defense Trees," *FAST 2010*, LNCS 6561, pp. 80-95, Springer 2011; extended journal treatment in "Attack-Defense Trees," *Journal of Logic and Computation* 24(1): 55-87, 2014. Formalized interleaving of defender nodes with attacker nodes, established propagation rules for defended trees, and implemented ADTool — the Java-based open-source tool developed at the University of Luxembourg (§7).

**Jhawar et al. — sequential AND.** Ravi Jhawar, Barbara Kordy, Sjouke Mauw, Saša Radomirović, Rolando Trujillo-Rasua, "Attack Trees with Sequential Conjunction," *IFIP SEC 2015*, IFIP AICT 455, pp. 339-353. Extended the notation with the **SAND** (sequential-AND) operator. Classical AND means "all children required" without ordering; SAND adds "in this order." SAND matters when step ordering is load-bearing (compromise perimeter before pivoting, exfil staging before exfil transport).

**Arnold, Hermanns, Pulungan, Stoelinga — quantitative analysis.** Florian Arnold, Holger Hermanns, Reza Pulungan, Mariëlle Stoelinga, "Time-Dependent Analysis of Attacks," *POST 2014*, pp. 285-305. Annotated each leaf with a time-to-success probability distribution and propagated it up the tree via acyclic phase-type distributions; this line of work underwrites the propagation rules in §5.

**Operational corpus.** NATO Research and Technology Organisation Technical Report RTO-TR-IST-049 (Improving Common Security Risk Analysis, September 2008) documents operational attack-tree use in defense. The EU FP7 TREsPASS project (2012-2016) developed attack-tree tooling for socio-technical-system threat modeling. NIST SP 800-30 Rev. 1 (Guide for Conducting Risk Assessments, September 2012) references attack trees as one of the risk-analysis techniques.

**Tooling and DSL contributors.** Christian Schneider authored **Threagile**, a YAML-based threat modeling tool, first released in 2020. Izar Tarandach co-leads **pytm** (OWASP), a Python-DSL threat modeling tool. Both are referenced in the parent doc `[[reference-threat-modeling-discipline]]` and detailed in §7 below.

---

## §3 — The attack-tree notation

The notation is small. Five primitives carry the entire technique.

**Root node — the attacker's goal.** A natural-language statement of what the attacker is trying to achieve. Examples: "Steal company financials," "Disable authentication on the production tenant," "Exfiltrate training data from the production model," "Recover the private key from the HSM." The root must be specific enough to evaluate (you must be able to say "yes, the attacker achieved this" or "no, they did not"). "Compromise the system" is too vague; "Read the contents of `/etc/shadow` on the production bastion" is specific.

**Children — sub-goals or alternative paths.** Each child of a node represents either a sub-step toward the parent (AND-decomposition) or an alternative way to achieve the parent (OR-decomposition). Children are themselves nodes — they may have their own children. The recursion terminates at leaves.

**OR-nodes — default semantics.** If a node has multiple children, the default semantics are OR: any one child achieving its goal is sufficient for the parent to be achieved. OR-nodes are drawn without any connecting arc between children. They model the attacker's choice among alternatives.

**AND-nodes — all children required.** If the parent goal requires *all* children to succeed, the children are drawn with a curved arc connecting them (or annotated with `AND` text). AND-nodes model attacker workflows where multiple steps must succeed jointly. Example: "Eavesdrop on a phone call" is an AND of "Establish position to overhear" + "Get the target to state the secret out loud."

**SAND-nodes — sequential AND.** Some attacks require children to succeed *in a specific order*. SAND-nodes (Jhawar et al. 2015, §2) carry the AND semantics plus an ordering constraint. Drawn with a directed arc or numbered children. Example: "Compromise the production database" is a SAND of "Establish foothold on the bastion" → "Pivot to the database VPC" → "Exploit DB credential" → "Exfil DB rows." Each step must succeed before the next is attempted.

**Leaves — atomic attacks.** Leaves are nodes with no children. They represent attacks the attacker can attempt as single operations — no further decomposition is useful for the modeling exercise. Atomicity is relative to the model's purpose; a "Phish credentials" leaf in a high-level enterprise attack tree might be a 50-node sub-tree in a phishing-specific attack tree.

**Attribute annotations.** Leaves carry annotations that quantitative analysis (§5) propagates up the tree. Common attributes: **cost** (dollar cost to the attacker), **probability** (probability of success), **skill** (skill level required: script-kiddie / proficient / expert / nation-state), **time** (wall-clock time required), **detection risk** (probability the attack is detected). Annotations are typically tuples — `(cost: $5K, P: 0.7, skill: proficient, time: 2 days, detection: 0.2)`.

**Diagrammatic conventions.** Boxes are rectangles for attacker nodes. In attack-defense trees (§6), defender nodes are drawn as rounded rectangles or in a contrasting color. AND-arcs are curved lines connecting children near the parent. SAND uses directed arrows or numbered labels. Most production teams skip the diagram and work in structured text (YAML / JSON / DSL) under version control (§8). Diagrams are useful for stakeholder workshops; structured text is necessary for review, diff, and tool-driven analysis.

**Text-form notation.** A compact text form: each line is a node; indentation indicates parent-child; a prefix marker indicates AND / SAND / OR. Example:

```
ROOT: Open the safe
  OR:
    - Pick the lock                     [cost: $200, P: 0.4, skill: proficient]
    - Learn the combination
      OR:
        - Find written combination      [cost: $50, P: 0.2, skill: script-kiddie]
        - Get combination from owner
          OR:
            - Threaten                  [cost: $0, P: 0.6, skill: any, risk: high]
            - Blackmail                 [cost: $1K, P: 0.3, skill: proficient]
            - Bribe                     [cost: $10K, P: 0.7, skill: proficient]
            - Eavesdrop
              AND:
                - Establish position    [cost: $500, P: 0.8]
                - Get owner to state    [cost: $2K, P: 0.3]
    - Cut open safe                     [cost: $5K, P: 0.9, skill: expert, time: hours]
    - Install improperly                [cost: $0, P: 0.05, skill: opportunistic]
```

The text form lives in version control, renders to a diagram on demand, and supports diff-friendly review.

---

## §4 — Worked example: Schneier's "Open a safe"

Schneier's "Open a safe" example from *Secrets and Lies* is the canonical training example. Walk it because it makes every subsequent technique concrete.

**Root goal.** Open the safe.

**Top-level alternatives (OR).**
1. Pick the lock.
2. Learn the combination.
3. Cut open the safe.
4. Install the safe improperly (so it is openable trivially when delivered).

The attacker wins if any of these succeeds. Default OR.

**"Learn the combination" decomposes (OR).**
- Find a written record of the combination (sticky note on the safe, written in a notebook, stored in a file).
- Get the combination from the safe owner.

**"Get the combination from the safe owner" decomposes (OR).**
- Threaten the owner (coercion).
- Blackmail the owner (leverage).
- Eavesdrop on the owner.
- Bribe the owner.

**"Eavesdrop" decomposes (AND).** Schneier's example uses this branch to introduce AND-semantics.
- Establish a position to overhear the owner.
- Get the owner to state the combination out loud (in a context where the attacker is positioned to hear).

Both must succeed for "Eavesdrop" to succeed. Just establishing a position is useless if the owner never states the combination; just getting them to say it is useless if the attacker is not positioned to hear.

**Leaf annotation.** Annotate each leaf with cost (USD), probability of success (0.0-1.0), and skill required. Example annotations from §3.

**Cost propagation up the tree.**
- For OR-nodes, `cost(parent) = min(cost(children))` — the rational attacker picks the cheapest child.
- For AND-nodes, `cost(parent) = sum(cost(children))` — all children must be paid for.
- For SAND-nodes (if used here), same as AND for cost; ordering does not change the sum.

Walk the safe example:
- Eavesdrop AND: cost = $500 + $2K = $2.5K.
- Get combination from owner OR: min($0, $1K, $10K, $2.5K) = $0 (Threaten).
- Learn combination OR: min($50, $0) = $0.
- Top-level OR: min($200, $0, $5K, $0) = $0.

The cheapest paths are "Threaten the owner" and "Install the safe improperly" (both $0 leaf cost). The model immediately says: if you want to defend a safe, do not over-invest in better lock-picking resistance. Defend against social-engineering and against the supply-chain installation step. The model surfaces the defense priority by surfacing the cheapest attacker paths.

**Probability propagation up the tree.**
- OR-node, attacker can retry across children: `P(parent) = 1 - product(1 - P(child))`. If any child has P=1.0, parent is 1.0.
- AND-node, all children must succeed: `P(parent) = product(P(child))`.
- If the attacker can only attempt one path (mutual exclusivity for some reason), OR-node behaves differently — typically `P(parent) = max(P(child))` for the strategy of picking the best single path.

Walk the safe example for probability (using §3 annotations):
- Eavesdrop AND: 0.8 × 0.3 = 0.24.
- Get combination from owner OR: 1 - (1-0.6)(1-0.3)(1-0.7)(1-0.24) = 1 - 0.4 × 0.7 × 0.3 × 0.76 = 1 - 0.064 = 0.94.
- Learn combination OR: 1 - (1-0.2)(1-0.94) = 1 - 0.8 × 0.06 = 0.952.
- Top-level OR: 1 - (1-0.4)(1-0.952)(1-0.9)(1-0.05) = 1 - 0.6 × 0.048 × 0.1 × 0.95 = 1 - 0.00274 = 0.997.

The safe is opened by a determined attacker with probability ~99.7% across all paths. The probability propagation makes the headline conclusion concrete: a safe is not a permanent defense; it is a delay.

**Combining cost and probability — expected cost.** Rational attacker minimizes expected cost = `cost / P(success)`. For each leaf, compute this and rank. In the safe example, Threaten at ($0, 0.6) has expected cost $0; Install improperly at ($0, 0.05) has expected cost $0; Picking the lock at ($200, 0.4) has expected cost $500. The model identifies the rational-attacker-preferred paths.

**Reading the propagation back to defense priorities.** The safe model is pedagogical; the mechanical conclusion is operational:
- Lower P(Threaten): guard rotations, owner training, panic buttons.
- Raise cost(Install-improperly): supply-chain integrity at install, post-install verification.
- Both higher-leverage than further lock-quality investment.

The quantitative output is the lever to argue this in a budget conversation; the qualitative observation alone is easy to wave away.

**Detection-risk annotation extension.** Add detection-risk per leaf — probability the attempted attack is detected:
- Threaten: high detection-risk (owner reports).
- Install-improperly: very low (attacker never interacts with deployed safe).

The detection-risk view inverts the priority ranking: Install-improperly is most attractive to a stealth-focused attacker. An opportunistic burglar prefers Threaten despite detection risk; an APT-class attacker prefers Install-improperly because stealth is load-bearing. Per-attacker-class trees (§10) operationalize this.

---

## §5 — Quantitative analysis on attack trees

Quantitative analysis turns the tree from a brainstorming aid into a decision-support tool. The math is straightforward; the inputs are the hard part (§10).

**Multi-attribute propagation.** Each node carries a tuple of attribute values. Define propagation rules per attribute:

| Attribute | OR-node rule | AND-node rule |
|-----------|--------------|---------------|
| Monetary cost | `min(children)` | `sum(children)` |
| Time (wall-clock) | `min(children)` | `sum(children)` if sequential, `max(children)` if parallel |
| Probability of success | `1 - prod(1 - p_i)` | `prod(p_i)` |
| Skill required | `min(children)` | `max(children)` |
| Detection risk | `min(children)` | `1 - prod(1 - d_i)` |

The rules are not arbitrary. OR-cost uses min because the attacker picks the cheapest branch. AND-cost uses sum because all branches must be funded. OR-probability uses the complement-of-product because any branch succeeding gives parent success. OR-detection uses min because the attacker picks the stealthiest branch. AND-detection uses complement-of-product because any branch detection counts. Verify the rules against the semantics of each attribute before applying.

**Pareto-optimal attack paths.** Attacker decisions are multi-attribute; a single-attribute optimum (lowest cost) may be unattractive on another attribute (highest detection risk). A strategy is **Pareto-dominated** if another strategy is at least as good on every attribute and strictly better on at least one. The Pareto-front is the set of non-dominated strategies — typically 3-7. Defend against the whole front, not against a single "most likely" path.

**Decision-theoretic analysis.** Frame the interaction as a game (cross-link `[[reference-game-theory-mechanism-design-security]]`):
- Attacker minimizes expected loss = `sum(action costs) + P(failure) × consequence(failure)`.
- Defender minimizes max-loss across attacker strategies, subject to a defense budget.
- Solve via minimax (pure strategies) or mixed-strategy equilibrium (when randomization helps the defender).

Mathematics is well-developed; the practical limitation is input grounding (§10).

**Cost-bounded reachability.** For attacker budget $B, prune branches whose minimum cost exceeds $B. Reachable-set is the defender's worry list under that attacker class:
- Script-kiddie: $100.
- Bug-bounty hunter: $10K.
- Criminal organization: $1M.
- Nation-state: $100M+.

**Time-bounded reachability.** Same analysis with time replacing cost. Useful for incident-response: given the attacker has 4 hours before the next alert sweep, which root goals are reachable?

**Sensitivity analysis.** Vary input estimates by 2x-5x in each direction. Conclusions that flip under reasonable variation are fragile; conclusions that hold are robust. Report sensitivity ranges, not point estimates. A recommendation depending on P=0.4 rather than P=0.5 is fragile; one that holds for P in [0.2, 0.8] is operationally usable.

**Honest limit on quantitative analysis — GIGO.** Cost, probability, time, and detection-risk estimates for novel attacker actions are expert-elicited guesses. No public ground-truth corpus exists for "cost of a 0-day Chromium V8 type-confusion in 2026" or "P(credential harvest) against hardened FIDO2." Output is precisely as good as input estimates. Garbage-in-garbage-out is the dominant failure mode. See §10 for mitigations.

---

## §6 — Attack-defense trees

The attacker is not playing solo. The defender takes actions that change attacker cost, probability, time, and detection risk. **Attack-defense trees (ADT)** interleave defender nodes with attacker nodes to model this interaction.

**Notation.** Each attacker node may have an attached defender node — a defense action that, if implemented, invalidates the attacker action or modifies its attributes. Defender nodes themselves may be decomposed via AND / OR. Defender nodes may have attached attacker sub-nodes representing counter-counter (the attacker bypasses the defense), and so on, alternating across rounds.

**Worked example — defended safe.**
- Attacker action: Pick the lock. Cost $200, P=0.4.
- Defender action attached to "Pick the lock": Install a relocker (a secondary lock that triggers on tampering). Cost to defender: $2K (one-time). Effect on attacker: P drops from 0.4 to 0.05.
- Attacker counter-counter to "Install relocker": Use a borescope to position the relocker bypass tool before picking. Cost to attacker: additional $5K, raises total picking cost to $5.2K.

The ADT model captures the back-and-forth. The defender can compute: "spending $2K on a relocker reduces attacker P from 0.4 to 0.05" — that is a return-on-investment calculation the defender can use to prioritize.

**Propagation in ADTs.** Attribute propagation extends to handle defender nodes — defender cost is the defender's total spend; attacker cost is increased by any active defender countermeasures; probability is modified by the defenses present. The Kordy et al. 2014 *Journal of Logic and Computation* paper establishes the formal propagation rules.

**ADTool — the canonical implementation.** ADTool is a Java-based open-source visual and analytical tool, developed by Barbara Kordy, Piotr Kordy, Sjouke Mauw, and Patrick Schweitzer at the University of Luxembourg (SnT). It supports drawing attack-defense trees, defining attributes per node, and running propagation analyses. ADTool is research-grade — useful for academic work and small-scale practitioner exercises; production teams find it heavy and roll their own (§7, §8).

**When to use ADT vs plain attack tree.** ADT doubles the modeling work — every attacker node may now have a defender counterpart, and counter-counter loops add even more nodes. Use ADT when (a) the defender has a meaningful menu of counter-actions, (b) the cost-benefit of specific defenses is the question, and (c) the model will not exceed ~50 nodes per side (above that, maintainability collapses, §12). For most threat-model exercises, a plain attack tree plus a separate mitigation-tracking spreadsheet is operationally simpler and equally informative.

---

## §7 — Tooling landscape

No dominant production tool. The landscape is academic research tools, commercial niche tools, and team-built custom solutions.

**ADTool (academic OSS).** Java Swing application from Kordy et al. (University of Luxembourg). Free download, open source. Strengths: formal-semantics-aligned, supports all standard operators (AND / OR / SAND / counter-defense). Weaknesses: aging UI, single-author tree models, no first-class version control, no API for CI integration. Use for academic exercises and proof-of-concept work.

**SecurITree (Amenaza Technologies, commercial).** Canadian vendor; widely used in defense and critical-infrastructure consulting. Supports attack trees with attribute propagation. Strengths: production-grade UI, vendor support, defense-industry references. Weaknesses: commercial license, proprietary file format, slow adoption outside defense consulting.

**AttackTree+ (Isograph, commercial).** UK vendor; safety-engineering heritage. Fault-tree-style notation extended for security. Strengths: integrates with safety-engineering practice (ISO 26262, IEC 61508), useful when security and safety analyses share a model. Weaknesses: safety-engineering interface assumptions feel awkward for pure-security use cases.

**Isograph FaultTree+.** Sibling product to AttackTree+, focused on classical fault-tree analysis. Mentioned for context: fault trees and attack trees share notation lineage but differ in semantics (fault trees model random component failures with statistical independence; attack trees model intentional adversarial choice).

**Microsoft Threat Modeling Tool (TMT).** Free Microsoft tool focused on STRIDE-on-DFD. Does not natively support attack trees, but the threat-list output from TMT can seed attack-tree branches.

**OWASP Threat Dragon.** OWASP-maintained open-source web/desktop threat modeling tool. Misuse-case-style threat enumeration on DFDs; not natively attack trees. Useful as a complement, not a replacement.

**NetworkX + custom Python.** The dominant approach in academic and practitioner-research work. The `networkx` Python library handles the graph; custom propagation rules are 200-500 lines of Python; visualization via Graphviz or D3. Strengths: full control over model semantics, integrates with notebooks and data-science workflows. Weaknesses: every team rolls its own; no standard schema; not stakeholder-facing.

**Threagile — YAML-based threat modeling.** Christian Schneider's tool. Define the architecture in YAML; Threagile generates a risk list, data-flow diagram, and data-asset diagram. First public release August 2020. Strengths: tree-as-code workflow (§8), version-controlled, CI-integrable. Weaknesses: opinionated about the YAML schema, learning curve, limited tree-customization beyond Threagile's built-in templates.

**pytm — Python-DSL threat modeling.** Izar Tarandach's tool. Define the model in Python; pytm generates DFDs, sequence diagrams, and threat lists. Strengths: Python-native, fits engineering workflows, scriptable. Weaknesses: less polished output than Threagile, smaller community.

**LLM-augmented attack-tree generation.** STRIDE-GPT (Matt Adams, 2023+) focuses on STRIDE and since v0.2 also generates attack trees as Mermaid diagrams from application descriptions. The LLM-generation regression-on-novelty failure mode (`[[reference-threat-modeling-discipline]]` §12, `[[reference-misuse-abuse-case-modeling]]` §12) applies identically: LLMs propose conventional branches well, miss novel ones systematically. Use for draft branch enumeration; require human review and explicit novelty-seeking prompts.

---

## §8 — Attack-tree-as-code

The tree-as-code movement parallels threat-modeling-as-code. The attack tree lives in the repository as structured text (YAML, JSON, or a DSL); tooling generates diagrams, runs propagation analysis, and gates CI on tree-coverage rules. The pattern matches the doctrine established in `[[reference-threat-modeling-discipline]]` §10 for the broader threat-model artifact.

**Example YAML schema** (suggested, not a standard):

```yaml
goal: "Steal training data from production model"
type: OR
children:
  - goal: "Direct database access"
    type: SAND
    children:
      - leaf: "Compromise CI/CD credential"
        attrs: { cost: 5000, p_success: 0.3, skill: proficient, time_days: 5 }
      - leaf: "Pivot to data-warehouse subnet"
        attrs: { cost: 1000, p_success: 0.6, skill: proficient, time_days: 2 }
      - leaf: "Read training-data S3 bucket"
        attrs: { cost: 0, p_success: 0.9, skill: any, time_days: 0 }
  - goal: "Membership inference"
    leaf: true
    attrs: { cost: 200, p_success: 0.4, skill: ml-research, time_days: 30 }
  - goal: "Model stealing"
    leaf: true
    attrs: { cost: 50000, p_success: 0.6, skill: ml-research, time_days: 60 }
  - goal: "Gradient inversion (federated training only)"
    leaf: true
    attrs: { cost: 10000, p_success: 0.2, skill: ml-research, time_days: 90 }
```

The YAML is version-controlled. A custom propagator (Python + NetworkX) reads it and computes attribute propagation. A Graphviz back-end renders the tree to PNG for stakeholder review. CI runs the propagator on every architecture-change PR and flags trees whose minimum-cost-path drops below a threshold (regression in defense posture).

**The "checked-in attack tree" pattern.** The attack tree lives alongside the architecture documentation. When a feature changes the architecture, the PR includes a tree update. The tree is reviewed in the same pull request. Tree updates are merge-blocked until the security reviewer confirms the new tree captures the architecture change. Cross-link to `[[reference-misuse-abuse-case-modeling]]` §9 for the analogous misuse-case-as-code pattern.

**Threagile as a tree-as-code platform.** Threagile's YAML schema includes asset definitions, communication links, trust boundaries, and produces a risk-categorized threat list. Combined with a Threagile-output post-processor, the tree-as-code workflow integrates naturally. Threagile is the closest existing tool to a turn-key tree-as-code platform; for fully customized models, pytm + custom propagation is more flexible.

**Failure mode — DSL drift.** Custom YAML schemas evolve. Trees written six months ago against schema v1 do not validate against schema v3. Pin the schema version in the YAML; provide a migration tool when bumping schemas; or accept that trees age out and rewrite them at major releases.

---

## §9 — Integration with sibling methodologies

Attack trees are not the only threat-modeling artifact. Use them in combination with the sibling techniques.

**Attack trees + STRIDE.** For each STRIDE threat against an element, build an attack tree showing alternative paths. STRIDE gives breadth ("every element has these six threats"); the tree gives depth for high-impact threats. Pairing: STRIDE produces 50-200 threats for a typical system; attack-tree the top 10-15 by impact; leave the rest as STRIDE-only entries with shorter mitigation notes.

**Attack trees + misuse cases.** A misuse case basic flow is one path through an attack tree; alternate flows are other branches. The techniques are duals: misuse cases narrate, attack trees enumerate. Use both — misuse cases for narrative impact, attack trees for prioritization. Cross-link `[[reference-misuse-abuse-case-modeling]]` §6.

**Attack trees + MITRE ATT&CK.** ATT&CK techniques are leaf-level enumerations of attacker behavior in the wild. Label tree leaves with ATT&CK technique IDs (`T1078 Valid Accounts`, `T1190 Exploit Public-Facing Application`, `T1110 Brute Force`). Compatible with the ATT&CK-driven detection-engineering workflow (cross-link `[[reference-detection-engineering]]`). Defender asks: "for every leaf, do I have a detection?" Unmapped leaves are detection gaps.

**Attack trees + PASTA.** PASTA Stage 6 (Attack Modeling) explicitly uses attack trees as one of its artifact options. The PASTA workflow feeds the architecture model into the attack-tree exercise; the tree output feeds Stage 7 (Risk and Impact Analysis). For PASTA-adopting teams, attack trees are the canonical Stage-6 artifact.

**Attack trees + LINDDUN.** LINDDUN enumerates privacy threats (linking, identifying, non-repudiation, detecting, disclosure, unawareness, non-compliance). Privacy attack trees decompose privacy-related attacker goals ("re-identify users in the published dataset") into branches that correspond to LINDDUN threat categories. Useful when privacy is a first-class concern; see `[[reference-privacy-engineering]]`.

**Attack trees + bug-hunting first-principles.** The Kurt-doctrine bug-hunting workflow (cross-link to `[[reference-bug-hunting-first-principles]]`) is operationally a depth-first traversal of an attack tree — the bug-hunter picks the highest-priority root goal, explores branches, and prunes based on observed defenses. Attack trees give the bug-hunter a planning structure; the hotspot × information-access matrix gives the priority ordering on branches.

**Attack trees + red-team operator playbook.** Red-team engagements use attack trees to track "what we tried" and "what we did not try." Cross-link to `[[reference-ai-red-team-operator-playbook]]` for the operator's perspective. The 7-gate finding-quality filter applies to attack-tree-derived findings the same way it applies to free-form findings.

---

## §10 — Quantitative analysis in practice — best practices and limitations

The math in §5 is the easy part. The hard part is the inputs.

**Cost estimates are guesses.** "How much does it cost to phish a credential from a Fortune 500 employee in 2026?" No public answer exists. Threat-intel firms (Mandiant, Recorded Future), bug-bounty payouts, dark-web pricing, and academic surveys give bounds, not point estimates. Expert-elicit from multiple sources; use ranges.

**Probability estimates are guesses.** "P(credential-stuffing succeeds against hardened FIDO2)?" Empirical data in red-team reports and CTI feeds is fragmentary and stale. Estimates require expert calibration.

**Skill estimates are categorical.** Treat skill as discrete (script-kiddie / proficient / expert / nation-state), not continuous. "Cheapest path requires expert skill — does our threat model include expert-skill attackers?" If yes, defend; if no, accept residual risk.

**Sensitivity analysis is non-optional.** Vary every input by ±50% or 2x. Conclusions that hold are robust; conclusions that flip are fragile. Communicate robust conclusions as recommendations; communicate fragile ones with "if our estimates are right..." caveats.

**Delphi method for expert elicitation.** Each expert estimates independently; spread is shown to all; they re-estimate; iterate to convergence (or documented disagreement). Reduces anchoring bias and groupthink. Useful with 3-5 internal experts.

**Pareto-front over single-path.** Communicate the Pareto-front (3-7 strategies), not a single "most likely" attack. Stakeholders intuit the attacker has choices; showing the front respects that intuition and surfaces defense leverage points across the front.

**Counterfactual analysis.** For each high-priority path, ask: "what would make this path unattractive?" That is the defense leverage point. If "Phish credentials" has cost $5K, P=0.7, and FIDO2 drops P to 0.05, FIDO2 buys a 14x reduction in that path's expected value. Counterfactual reasoning makes the tree actionable.

**Updating with new threat intel.** Threat intel feeds (Mandiant, CrowdStrike, MITRE-ATT&CK updates) publish new attacker capabilities regularly. When a new capability lowers cost or raises P of a leaf, update the tree. Cross-link `[[reference-threat-intel-methodology]]`. Quarterly review is the operational rhythm.

**Per-attacker-class trees.** A single tree with shared cost annotations averages across attacker classes; the average is misleading. Build per-class trees (script-kiddie / criminal / nation-state). Costs differ by orders of magnitude across classes; per-class trees show which classes are in-scope for each defense investment.

**The headline practical rule.** Quantitative attack-tree analysis is precisely as good as the inputs. If you cannot defend the inputs to a skeptical reviewer, you cannot defend the outputs. Treat the tree as a structured-reasoning artifact with quantitative annotations, not as a precise predictive model.

---

## §11 — Real-world adoption and case studies

Attack trees have been used operationally for ~25 years. The adoption corpus is uneven — strong in defense and critical-infrastructure, weaker in commercial software.

**NIST SP 800-30 Rev. 1 (Sep 2012)** cites attack tree analysis for adversarial threats as an example of a graph-based analysis technique, alongside functional dependency network analysis and fault tree analysis (§2.3.3, fn. 32). The NIST endorsement makes attack trees compliance-acceptable for US federal risk assessments.

**Sandia, Booz Allen, MITRE — consulting practice.** Defense-engineering consultancies use attack trees in client engagements regularly. Public Sandia papers (Phillips and Swiler, late 1990s) predate Schneier's popularization (§2).

**Critical-infrastructure / ICS modeling.** Stuxnet has been retrospectively modeled as a multi-stage attack tree (compromise engineering workstation → propagate via removable media → reach PLC programming environment → reload modified ladder logic → cause centrifuge over-speed). Triton / TRISIS similarly. The ICS/OT threat-modeling community (Joe Slowik, Robert M. Lee, Dragos analysts) uses attack-tree-style decomposition. Cross-link to `[[reference-ics-ot-security]]`.

**AI-system attack trees — emerging 2024-2026 application.** Attacker goals on AI systems decompose interestingly:
- "Exfiltrate training data from the production model" → membership inference (`[[reference-adversarial-ml-model-security]]`), model stealing, gradient inversion (FL only; `[[reference-federated-learning-security]]`), direct exfil via training-data-storage compromise.
- "Cause the agent to take an unsafe action" → prompt-injection-via-input, prompt-injection-via-tool-output, tool-poisoning, supply-chain compromise of the model.

Cross-link to `[[reference-llm-agent-security]]`. AI attack trees are an active research frontier; expect formal corpora to mature 2026-2028.

**Bug-bounty and red-team frameworks.** Modern red-team engagements use attack trees to organize "what we tried" / "what we did not try" / "what the team should try next." The tree is a living artifact during the engagement and a deliverable at the end. Cross-link to `[[reference-ai-red-team-operator-playbook]]` for the operator's playbook. Bug-bounty programs increasingly publish attack-tree-style scoping documents to communicate priority areas to researchers.

**Financial-services threat modeling.** Banks and payment processors use attack-tree analysis for high-value scenarios:
- Wire-fraud.
- ATM cash-out.
- Card-not-present fraud.

High impact + adversarial attackers + well-defined scope makes attack trees a natural fit. Public references are scarce because the trees are proprietary `[unverified specific bank-level practice]`.

**Where adoption is weak.** Most commercial software engineering teams do not use attack trees. The combination of (a) tool immaturity, (b) cost of expert-input elicitation, (c) maintenance burden, and (d) the existence of cheaper alternatives (STRIDE on DFDs, misuse cases, ATT&CK technique lists) means attack trees remain a specialist technique used by threat-modeling consultancies and dedicated security teams rather than line engineering teams. The threat-modeling-as-code movement (§8) is the most plausible path to broader adoption.

**Worked example — AI-agent training-data exfil attack tree.** Concrete walk-through of an emerging 2026 application.

Root: Exfiltrate training data from the production model.

Top-level (OR):
1. Direct exfil via training-data-storage compromise (SAND of: gain CI/CD foothold → pivot to data-warehouse → read training-data bucket).
2. Membership inference via query API.
3. Model stealing via query API + extraction attack.
4. Gradient inversion (only if federated training is in use).
5. Insider exfil (employee with legitimate data access).

Annotations (illustrative, not ground truth):
- Direct exfil: SAND-sum cost ~$10K, joint P ~0.15, skill: proficient, time: ~10 days, detection: medium.
- Membership inference: cost ~$500 (query budget), P ~0.4, skill: ML-research, time: ~30 days, detection: low.
- Model stealing: cost ~$50K (query budget), P ~0.6, skill: ML-research, time: ~60 days, detection: low.
- Gradient inversion: cost ~$10K, P ~0.2, skill: ML-research, time: ~90 days, detection: very low.
- Insider exfil: cost ~$0 (recruitment cost varies wildly), P ~0.1, skill: any, time: variable, detection: medium.

OR-min cost: $0 (insider), but insider P is low; expected-cost rankings differ from minimum-cost rankings. Membership inference has best expected cost ($500 / 0.4 = $1.25K). The model surfaces defense priorities:
- (a) Query-API rate limits and DP noise: raise cost / lower P of membership inference.
- (b) FL byzantine-robust aggregation (cross-link to `[[reference-federated-learning-security]]` §3-§6).
- (c) Insider-threat program.
- (d) CI/CD hardening: highest joint cost path but lowest detection — preferred by hardened attackers if other branches are defended.

The exercise produces ranked defense priorities: query-API monitoring + DP noise; FL byzantine-robust aggregation; insider-threat controls; CI/CD hardening. The tree is the mechanism that produced the priorities.

---

## §12 — Honest failure modes

Read this before claiming "we do attack-tree analysis." Every failure mode below has been observed in practice; several have been observed in the same engagement.

**Combinatorial explosion.** A real system has hundreds of attacker goals and thousands of branches. Modeling everything produces an unreadable, unmaintainable artifact. Operational discipline: pick 5-10 high-impact attacker goals; build trees for those; revisit quarterly. Resist the urge to model everything.

**GIGO from ungrounded estimates.** Cost, probability, time, and detection-risk inputs are expert-elicited guesses. Quantitative analysis is precisely as good as the inputs and no better. Sensitivity analysis (§10) is non-optional. Teams that publish single-point quantitative conclusions without sensitivity ranges are publishing precision-theater.

**Attack-defense trees double the complexity.** The ADT extension is mathematically elegant and operationally heavy. A 50-attacker-node tree plus 50 defender nodes plus counter-counter loops produces an artifact no human can review. In practice, most production teams use plain attack trees plus a separate mitigation-tracking spreadsheet — simpler, equally informative, lower maintenance burden.

**AND-OR semantics oversimplify attacker choice.** Real attackers play mixed strategies and adapt to defender responses. The tree models static decomposition; the attacker picks one path. Misses the actual game-theoretic interaction (attacker observes defenses, picks cheapest unobstructed path). Cross-link `[[reference-game-theory-mechanism-design-security]]`.

**Trees imply linear plans; reality is opportunistic.** Attackers often discover vulnerabilities serendipitously (exposed S3, forgotten admin endpoint, leaked GitHub credential) and pursue them. They do not enumerate trees and execute leaves systematically. Trees are defender planning aids, not attacker playbooks. Trees also cannot represent shared sub-states (the same intermediate compromise feeding multiple goal nodes) without duplication; see `[[attack_graphs]]` for the DAG-topology generalization that handles convergence — multiple incoming and outgoing edges per state — plus the Ammann+Wijesekera CCS 2002 monotonicity property that makes scalable generation tractable (Datalog MulVAL realization). Use the attack-tree shape when a single attacker-goal decomposition is the question; promote to graphs when the question is "what state-space can the attacker reach across the system as a whole."

**Tooling is research-grade.** ADTool academic; SecurITree commercial-niche. No dominant production tool. Most teams roll their own (NetworkX + custom Python + YAML). Tooling immaturity is a real adoption blocker.

**The "neat diagram, no action" anti-pattern.** A beautifully rendered tree in a slide deck; no backlog items derived. Six months later, stale and unused. Same failure as misuse cases without mitigations (`[[reference-misuse-abuse-case-modeling]]` §12 "misuse cases without mitigations = theater"). The tree exists to produce defense priorities; if no backlog items emerge, the exercise failed.

**LLM-augmented generation regresses on novelty.** Same finding as parent + sibling docs. LLMs propose conventional branches well — phishing, SQLi, XSS — and miss novel branches systematically. Use for draft enumeration with explicit novelty-seeking prompts; require human review.

**Stale trees mislead.** Architecture changes; tree does not. Wrong tree is worse than no tree because it gives false confidence. Quarterly review minimum; tree-as-code (§8) with CI gating ideal.

**Cost estimates assume cooperative-attacker accounting.** Nation-state "cost" is not the same object as script-kiddie "cost." Nation-state has a fixed cyber-ops budget; individual leaf cost is marginal. Script-kiddie has near-zero budget; any $1K leaf is unreachable. Per-attacker-class trees (§10) address this.

**The "expert with strong opinions" problem.** A single expert dominates tree construction; the team accepts the framing because no one else has thought about it. Mitigations: Delphi elicitation, multi-expert review, sensitivity analysis. Operationally expensive; teams skip; bias creeps back.

**Trees defended outside scope.** "We have an attack tree" used to wave away other threat-modeling activity. The tree is not a STRIDE substitute; it covers different territory (branching vs element enumeration). Run both. Cross-link `[[reference-threat-modeling-discipline]]` §3.

**The "unknown unknown" objection.** The tree only enumerates branches the team thought of; it cannot enumerate branches no one imagined. True. Mitigation: structured novelty-seeking (red-team adversarial-design-review, external review, threat-intel monitoring). The tree is a reasoning aid against known and plausible threats; not a guarantee against the unknown.

**Concluding rule.** Build attack trees for 5-10 high-impact goals. Annotate with ranges, not points. Run sensitivity analysis. Produce backlog items, not slide decks. Revisit quarterly. Acknowledge the limitations to stakeholders. Use the tree as a planning aid alongside STRIDE, misuse cases, ATT&CK, and the other techniques. The tree is not a model of the attacker's mind; it is a structured artifact for the defender's prioritization.

---

## §13 — Cross-link cluster

- `[[reference-threat-modeling-discipline]]` — parent design-time methodology. STRIDE, PASTA, LINDDUN, threat-modeling-as-code, Manifesto.
- `[[attack_graphs]]` — sibling DAG-topology generalization. Multi-source / multi-sink state-space modeling; Ammann+Wijesekera CCS 2002 monotonicity property + MulVAL Datalog realization (Ou+Govindavajhala+Appel 2005); Bayesian attack graphs (Frigault+Wang+Singhal+Jajodia 2008); cloud-IAM attack graphs (Wiz/Orca/Lightspin). Use trees for single-attacker-goal decomposition; use graphs when shared sub-states / convergence matter.
- `[[reference-misuse-abuse-case-modeling]]` — sibling narrative-enumeration technique. Misuse cases, abuse cases, security use cases.
- `[[reference-code-review-expertise]]` — review-time complement. Click-count severity, auth-homogeneity, candidate-point auditing.
- `[[reference-vulnerability-research-methodology]]` — research-time complement. Four canonical methods, surface enumeration, triage.
- `[[reference-bug-hunting-first-principles]]` — Kurt's prioritization doctrine for runtime/research-time bug-hunting; depth-first traversal aligns with attack-tree branch exploration.
- `[[reference-ai-red-team-operator-playbook]]` — engagement-level operator playbook; attack trees as "what we tried / did not try" tracking.
- `[[reference-adversarial-ml-model-security]]` — Biggio ML threat taxonomy; AI-system attack-tree leaves.
- `[[reference-federated-learning-security]]` — gradient inversion and FL-specific attack-tree leaves.
- `[[reference-game-theory-mechanism-design-security]]` — formal game-theoretic treatment of attacker-defender interaction.
- `[[reference-cicd-supply-chain]]` — supply-chain attack-tree branches; GHA pwn_request and tag-mutation.
- `[[reference-distributed-authz]]` — authz attack-tree decomposition; CWE-287/306/308/862/863.
- `[[reference-detection-engineering]]` — ATT&CK technique mapping to leaves; detection coverage from tree analysis.
- `[[reference-threat-intel-methodology]]` — input source for cost/probability annotation updates.
- `[[reference-privacy-engineering]]` — LINDDUN-aligned privacy attack trees.
- `[[reference-ics-ot-security]]` — Stuxnet / Triton retrospective attack-tree modeling.

---

## §14 — Operational checklist

Twelve items for a security architect / threat modeler running an attack-tree exercise.

1. **Pick the right number of root goals.** 5-10 attacker goals per system. More than 15 is over-scope; fewer than 3 is under-scope.
2. **State the root precisely.** "Open the safe" is too vague; "Read the contents of `/etc/shadow` on the production bastion as a non-root user" is precise. Precision lets you say when the attacker has won.
3. **Build the tree top-down.** Start at the root; decompose into 3-7 children per level; stop at leaves the team can annotate without further decomposition.
4. **Use AND, OR, SAND deliberately.** Default is OR. Use AND when all children are required jointly. Use SAND when order matters.
5. **Annotate leaves with attribute ranges, not points.** `(cost: $1K-10K, P: 0.3-0.7, skill: proficient)` not `(cost: $5K, P: 0.5)`.
6. **Propagate up the tree.** Apply OR-min / AND-sum for cost and time; complement-of-product for OR-probability; max for AND-skill.
7. **Run sensitivity analysis.** Vary every input by 2x in each direction. Report which conclusions are robust.
8. **Identify the Pareto-front.** 3-7 strategies non-dominated on the multi-attribute analysis. Defend against the front, not against one path.
9. **Map leaves to ATT&CK techniques.** Compatibility with detection-engineering (`[[reference-detection-engineering]]`).
10. **Produce backlog items.** For each high-priority leaf or branch, file a concrete defense backlog item with a tree-cross-reference. The exercise output is the backlog, not the diagram.
11. **Version-control the tree.** YAML / JSON / DSL under git; CI gating on architecture-change PRs.
12. **Schedule quarterly review.** Architecture drifts. Threat intel updates. The tree must drift with it or it lies.

Done. Build trees for the goals that matter. Annotate honestly. Produce action. Revisit.
