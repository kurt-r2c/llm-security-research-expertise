# How Kurt thinks about security bugs — a model

A reflective synthesis of Kurt Boberg's documented bug-hunting doctrine, drawn from
`bug_hunting_first_principles_expertise.md`, `code_review_expertise.md`, the
severity/triage/reachability specs, and the steelman discipline that runs across all of it.

Two views:

1. **The hunt** — how a candidate becomes a defensible finding.
2. **Triage / severity** — how a finding's weight is decided.

---

## 1. The hunt

```mermaid
flowchart TD
    START([New target]) --> DOES["What does this app <i>do</i>?<br/>(purpose, domain, users,<br/>data model, trust boundaries)"]
    DOES --> VALUE{"What's worth<br/>stealing here?"}
    VALUE -->|dollar-anchored| ASSET["Identify high-value assets<br/>(creds, PII, money, RCE,<br/>cross-tenant data)"]

    ASSET --> SURFACE["Map attack surface<br/>= hotspots × information access"]

    subgraph RANK["The ranking matrix — done BEFORE opening an editor"]
        direction LR
        H["Hotspots<br/>(auth, deser, parsing,<br/>file I/O, shell, IPC)"]
        I["Information access<br/>(what can the<br/>attacker see/control?)"]
        H --- I
        I --> HYP["Ranked bug-hypothesis list"]
    end
    SURFACE --> RANK

    HYP --> GREP["Grep-first per language<br/>(footguns: the dangerous<br/>primitive for THIS stack)"]
    GREP --> CANDIDATE([Candidate point])

    CANDIDATE --> REACH{"Is it actually<br/>reachable?"}
    REACH -->|no / can't prove| PARK["Park it — unproven<br/>≠ a finding"]
    REACH -->|yes, with evidence| SEV

    subgraph SEV["Severity = click-count × blast radius"]
        direction TB
        CLICKS["How many steps<br/>to exploit?"]
        BLAST["How far does it reach?<br/>(one user → whole tenant<br/>→ whole platform)"]
    end

    SEV --> ECON{"Attacker economics:<br/>does attacker pay<br/>&lt;1/1000× defender cost?"}
    ECON -->|no| RELIABILITY["Reframe as reliability,<br/>not security"]
    ECON -->|yes| STEEL

    subgraph STEEL["Steelman / falsify"]
        direction TB
        FLIP["State the flip-conditions:<br/>what would make this<br/>NOT a bug?"]
        REFUTE["Try to refute it<br/>before believing it"]
    end

    STEEL --> PROMOTE{"Can N-click be<br/>promoted to 0-click?<br/>(agentic / chained)"}
    PROMOTE -->|yes| ESCALATE["Escalate severity +<br/>blast radius"]
    PROMOTE -->|no| FINDING
    ESCALATE --> FINDING([Defensible, ranked finding<br/>≥95% precision bar])

    PARK -.->|new info changes reachability| REACH
    FINDING -.->|variant analysis:<br/>where else does this shape live?| SURFACE

    classDef gate fill:#2d3748,stroke:#90cdf4,color:#fff;
    classDef artifact fill:#1a365d,stroke:#63b3ed,color:#fff;
    class VALUE,REACH,ECON,PROMOTE gate;
    class HYP,CANDIDATE,FINDING artifact;
```

### What's most distinctively Kurt here

- **Rank before you read.** The hotspot × information-access matrix produces a hypothesis
  list *before* the editor opens — the center of gravity is upstream of any code.
- **Reachability is a hard gate, not a footnote.** Unproven reachability parks the finding
  rather than silently downgrading it.
- **Severity is mechanical** — click-count × blast radius — not eyeballed. The
  **N-click → 0-click promotion test** is first-class (Clinejection / CurXecute shape).
- **Attacker economics is a filter, not flavor text** — the <1/1000× asymmetry threshold
  decides whether something is a *security* bug or a *reliability* bug.
- **Steelman runs as refutation**, with explicit flip-conditions, before belief.
- The dashed loops — **variant analysis** and **reachability re-entry** — make it a hunt,
  not a checklist.

---

## 2. Triage / severity — how a finding's weight is decided

```mermaid
flowchart TD
    F([Candidate finding]) --> R{"Reachable<br/>with evidence?"}
    R -->|no| DROP["Drop / park<br/>(not a finding yet)"]
    R -->|trusted-service-only<br/>input| CTX["Context downgrade<br/>(internal-only, not attacker-facing)"]
    R -->|attacker-controlled<br/>input| CC

    subgraph CC["Click-count: steps to exploit"]
        direction TB
        Z["0-click<br/>(no interaction)"]
        O["1-click<br/>(one victim action)"]
        N["N-click<br/>(chain / multi-step)"]
    end

    CC --> BR

    subgraph BR["Blast radius"]
        direction TB
        SELF["Self / single account"]
        TEN["Tenant / org"]
        PLAT["Platform / all tenants"]
    end

    BR --> MATRIX{"click-count × blast radius<br/>severity matrix"}

    MATRIX -->|0-click × platform| CRIT["CRITICAL<br/>(RCE, cross-tenant,<br/>auth bypass at scale)"]
    MATRIX -->|low clicks × tenant| HIGH["HIGH"]
    MATRIX -->|interaction-gated<br/>or self-scoped| MED["MEDIUM"]
    MATRIX -->|defense-in-depth<br/>only| LOW["LOW"]

    CRIT --> PROMO{"Promotion check:<br/>can clicks be removed<br/>or radius widened?"}
    HIGH --> PROMO
    MED --> PROMO
    PROMO -->|yes| BUMP["Bump up a tier<br/>(re-enter matrix)"]
    PROMO -->|no| ECONFILT

    BUMP -.-> MATRIX

    ECONFILT{"Attacker economics<br/>+ steelman survives?"}
    ECONFILT -->|asymmetry holds<br/>& can't refute| SHIP([Severity locked +<br/>defensible rationale])
    ECONFILT -->|attacker cost ≥ payoff| REL["Reliability bug,<br/>not security"]
    ECONFILT -->|refuted| DROP

    classDef gate fill:#2d3748,stroke:#90cdf4,color:#fff;
    classDef crit fill:#742a2a,stroke:#fc8181,color:#fff;
    classDef out fill:#1a365d,stroke:#63b3ed,color:#fff;
    class R,MATRIX,PROMO,ECONFILT gate;
    class CRIT crit;
    class SHIP out;
```

### The triage thesis

Severity isn't a vibe — it's the **product of two measurable axes** (click-count ×
blast radius), passed through a **promotion check** (can you remove clicks or widen
radius?) and two **honesty gates** (attacker-economics asymmetry and steelman
survival). A finding only locks its severity once it has survived refutation and the
economics actually favor the attacker. Everything else is reframed (reliability),
context-downgraded (trusted-service-only), or dropped.

---

*Anchors: `bug_hunting_first_principles_expertise.md` (hotspot × info-access matrix,
DoS asymmetry threshold, agentic N-click → 0-click promotion, per-language grep-first),
`code_review_expertise.md` (click-count severity, auth-homogeneity), `SEVERITY_DEFINITION.md`
(blast-radius tiers), `FINDING_ACTIONABILITY_TRIAGE.md` (reachability/context/trusted-service),
`REACHABILITY_VERIFICATION.md` (evidence bar), `steelman_doctrine_expertise.md`
(flip-conditions, refutation-first).*
