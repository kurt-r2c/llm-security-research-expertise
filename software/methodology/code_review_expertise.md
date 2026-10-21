# Staff-Level Secure Code Review Guiding Principles
## Synthesized from Mark Dowd, Justin Schuh, John McDonald, Eoin Keary, and Michał Zalewski

> **Researchers:**
> - **Mark Dowd** — Co-author *The Art of Software Security Assessment* (Addison-Wesley, 2006);
>   former Principal Security Architect, McAfee Avert Labs; X-Force / IBM ISS research; founder of
>   Azimuth Security (now part of L3Harris). Disclosed sendmail, Microsoft Exchange, OpenSSH,
>   and Internet Explorer vulnerabilities. Known for fluent, line-by-line auditing of C/C++ daemons and his
>   "candidate point auditing" methodology.
> - **Justin Schuh** — Co-author *The Art of Software Security Assessment*; Engineering Director on
>   Google Chrome Trust & Safety (as of 2020) and a member of the Chrome team for more than a decade.
> - **John McDonald** — Co-author *The Art of Software Security Assessment*; former senior
>   security researcher at IBM ISS X-Force; director and founder of Azimuth Security.
> - **Eoin Keary** — Originator and past project leader of the *OWASP Code Review Guide*;
>   founder/CEO, edgescan, and founder, BCC Risk Advisory (Dublin). Former OWASP Global Board member.
> - **Michał Zalewski** (lcamtuf) — Author *The Tangled Web* (No Starch, 2011) and *Silence on
>   the Wire*; creator of `afl` / `american fuzzy lop`; former Director of Information Security
>   Engineering, Google. Browser-bug archaeology (XSS family taxonomy), content-sniffing /
>   MIME-confusion research, the `p0f` passive fingerprinter.
>
> **Sources:** *The Art of Software Security Assessment* (TAOSSA, Addison-Wesley 2006);
> *Software Security: Building Security In* (McGraw, 2006) for the touchpoints framing;
> OWASP Code Review Guide v2.0 (2017); OWASP Cheat Sheet Series; *The Tangled Web* (Zalewski,
> 2011); CWE Top 25 + MITRE; Black Hat / CanSecWest / Recon archives; Azimuth Security and
> Trail of Bits research blogs; CVE/NVD archives; edgescan annual vulnerability statistics
> reports. **2024-2026 additions:** DARPA AI Cyber Challenge final report and finalist
> system architectures (Team Atlanta, Trail of Bits Buttercup, Theori); GitHub Copilot
> Code Review GA documentation; CodeRabbit / Endor Labs / Snyk DeepCode product
> disclosures; Semgrep Pro Engine + Assistant release notes; Trail of Bits CodeQL
> publications and `mrva` multi-repo variant analysis tooling; OWASP pytm + Threat
> Dragon (Threat-Modeling-as-Code); Hugging Face safetensors audit; arXiv literature
> on LLM-generated-code vulnerability rates (Jan 2024 - Apr 2025); CVE-2025-53773
> (Copilot RCE), CVE-2025-54135 (CurXecute / Cursor MCP RCE), CVE-2025-32711 (EchoLeak
> / Microsoft 365 Copilot exfil). The doc now treats *the reviewer* and *the reviewed
> code* as both potentially-AI-generated and audits accordingly.

---

## 1. Core Philosophy

### Code review is the audit of trust transitions, not of statements

The novice reads code top-to-bottom; the auditor reads code as a graph of trust transitions.
Every line that consumes data carries an implicit claim about where the data came from and
what shape it has. Most vulnerabilities are not "wrong code" — they are correct code executed
under inputs the author did not anticipate. The code review's job is to discover the inputs
the author did not anticipate, and to evaluate whether the code's defenses survive them.

This frame changes what we look for. We do not look for "bad function names." We look for
boundaries where data crosses from a less-trusted region to a more-trusted region without
the structural guarantees of the destination being enforced. Every such boundary is a
**candidate point** in TAOSSA's terminology — a point where a hypothesis can be formed and
tested. The auditor's value is in choosing which candidate points to investigate; a thorough
audit of every line of a 200KLOC codebase is neither possible nor useful.

### The attacker's cost is the only relevant metric

Severity is not a property of code; severity is a property of *attack paths*. A buffer
overflow in a function only reachable by an authenticated administrator who must paste in
an attacker-supplied URL is a different vulnerability from the same overflow in a public
unauthenticated endpoint, even though the lines of code are identical. **The principle is
load-bearing: zero-click is always worse than one-click is always worse than n-click**, and
unauthenticated is always worse than low-privilege is always worse than high-privilege.

The auditor's first analysis after finding a candidate point is not "is this exploitable?"
but "what is the precondition stack?" — every condition the attacker must satisfy to reach
this line. The precondition stack is the cost; the impact is the payout. The two together
are the trade an attacker would make.

### Symptoms recur; root causes generalize

When you find a bug, do not stop at the bug. Ask: what was the **structural reason** the
author wrote it this way? Was it a missing helper that a peer code site uses? Was it a
language idiom that bites the same author in three other files? Was it an architectural
gap where the framework provides no safe primitive for the operation? The structural
answer tells you where to find the rest of the class. One bug is an incident; ten of the
same shape is a finding worth shipping.

This is why we read code we have already audited again, after building a mental model of
what the author got wrong. The second pass catches the variants of the first-pass bug;
the third pass catches the higher-order pattern.

### Process discipline is non-optional

Code review is the easiest security practice to do badly. Reading code is fluent for
engineers; *auditing* code is the discipline of slowing down enough to ask, at every line
that consumes data: where did this data come from, what shape does it claim, and what
shape is it actually allowed to have. The OWASP Code Review Guide v2's central
contribution is the operational scaffolding around this — application context (purpose,
language, frameworks, deployment), threat model (who is the attacker, what is the asset),
risk-weighted file selection (do not start at `main()`; start at the highest-risk
endpoint).

A code review without a threat model is pattern-matching. A threat model without code
review is wishful thinking. The two are co-load-bearing.

---

## 2. Code Review as Candidate-Point Methodology

### The TAOSSA frame: hypothesis-driven auditing

Dowd, Schuh, and McDonald formalize what the best auditors do informally. A candidate
point is a location in the code where the auditor hypothesizes a vulnerability could
exist; the audit is the verification or falsification of the hypothesis. This is the
scientific method applied to code.

Three classes of candidate points dominate real-world findings:

1. **Boundary points** — every function that consumes input from across a trust boundary
   (HTTP handlers, deserializers, file readers, IPC endpoints, DB rows, environment
   variables, command-line arguments). These are the obvious ones. Static analysis tools
   identify them mechanically.
2. **Trust-elevation points** — every function that assigns or escalates the privileges of
   data. The classic case is a function that takes a user-supplied string and writes it
   into a structure that downstream code treats as trusted. CWE-501 (Trust Boundary
   Violation) is the formal name.
3. **Composition points** — every function that combines data from multiple sources and
   passes the composite to a sink. Composition is where injection vulnerabilities live:
   SQL string built from user input + safe constant, shell command built from user input
   + binary path, path built from base directory + user input. The composite is more
   dangerous than either ingredient alone.

The auditor's productivity is set by the **ratio of candidate points to true findings**.
A naïve audit treats every input function as a candidate point and explores each one fully;
real-world auditors pre-filter using heuristics from the architecture (what frameworks does
this app use, what is its sanitization posture, which subsystems handle untrusted data).
This is why design review and code review are co-essential — design tells you which
candidate points are worth your time.

### Code understanding before code auditing

OWASP CRG v2's first methodological rule: if you do not know what the code is **meant** to
do, you cannot tell whether it is secure. Half of a useful code-review session is consumed
by reading enough of the codebase to know what each function is supposed to do. The other
half is finding the gaps between intent and implementation.

Practical signal: an auditor who immediately starts grepping for `eval`, `exec`,
`Runtime.getRuntime`, `system(`, etc., is doing pattern-matching, not code review.
Pattern-matching catches the obvious; the subtle bugs live in the gap between what the
author intended a function to do and what it actually does when called with a
non-anticipated input.

### Tools as multipliers, not substitutes

Static analysis (Semgrep, CodeQL, Coverity), taint tracers (Pysa),
fuzzers (afl, libFuzzer, honggfuzz), and LSP-aware IDE navigation collectively let a single
auditor cover orders of magnitude more code than was possible in 2006. But every tool's
output is candidate points, not findings. The tool tells you where to look; the auditor
tells you whether the candidate point is real.

The corollary: an auditor who ships every Semgrep finding as a true positive is not doing
the auditor's job. Every candidate point must clear three gates: (1) is the dataflow
plausible, (2) is the precondition stack realistic, (3) does the structural fix point at a
real engineering problem. Findings that fail any of the three are noise the auditor owes
the engineering team to filter out.

### The 2024-2026 SAST landscape and where AI-first entrants fit

The tooling that backs candidate-point auditing matured substantially between 2024 and
2026, and the shape of *what is mechanizable* shifted. The auditor who is anchored on
the 2017-era picture (Semgrep CE + CodeQL + Coverity + maybe Pysa) is now operating
without three load-bearing primitives that the rest of the field has adopted.

- **Cross-file / cross-function dataflow at scale.** Semgrep's Pro Engine moved
  inter-procedural taint analysis out of "research project" into "default expectation."
  The publicly-cited numbers — 25% fewer false positives, 2.5x more true positives over
  the OSS engine on the same rules — represent the structural shift: a finding that
  would have been "unreachable / FP" on local analysis is now "reachable through three
  service boundaries" on cross-file analysis ([Semgrep AppSec Platform vs CE](https://semgrep.dev/products/semgrep-vs-ce/)).
  The 2025 Fall release reports up to 3x faster scans on large monorepos
  ([Fall Release 2025](https://semgrep.dev/blog/2025/semgrep-community-edition-fall-release-2025/)),
  meaning whole-repo audit-time analyses that used to be batch jobs now fit in a CI step.
  Snyk Code (DeepCode AI) covers similar ground with a hybrid symbolic / generative
  pipeline trained on 25M+ dataflow cases across 19+ languages and claims 85%-accurate
  autofixes ([DeepCode AI](https://snyk.io/platform/deepcode-ai/)).
- **AI-assisted triage as a first-class layer on top of static analysis.** Semgrep
  Assistant's deployed numbers — 96% internal-researcher agreement, 95% end-user
  agreement on auto-triage, ~20% finding-reduction immediately rising to ~40% after
  a week, across 250,000+ findings at 45+ enterprises — are the strongest publicly-
  audited evidence that "LLM-as-FP-filter" is operationally tractable when constrained
  by deterministic SAST output. The architectural pattern is important: Assistant
  *never auto-closes findings*; it hides filtered ones for bulk triage. The
  deterministic engine remains the source of truth; the LLM is a triage assistant,
  not the analysis itself ([Semgrep Assistant 2025](https://semgrep.dev/blog/2025/announcing-ai-noise-filtering-and-triage-memories/)).
- **AI-first entrants that flip the architecture.** Endor Labs' AI Security Code
  Review (2025, $93M Series B in April 2025) reverses the SAST-first ordering:
  three coordinated AI agents (developer / architect / security) categorize every
  PR by its architectural impact (unauthenticated endpoint, authentication-flow
  modification, PII surface change, TLS config change, etc.) rather than scanning
  for rule patterns ([Endor Labs AI Security Code Review](https://www.endorlabs.com/learn/introducing-ai-security-code-review)).
  This is design-review-as-code, deployed against every PR. The trade-off is the
  inverse of SAST: design-flaw recall over signature-match precision. The auditor's
  reaction should be that **rule-based SAST + AI-design-review are complementary**,
  not competing — the former catches the C-fault-pattern; the latter catches the
  architectural drift the rules cannot encode.
- **Multi-repo variant analysis at corpus scale.** GitHub's CodeQL Multi-Repository
  Variant Analysis (MRVA) and Trail of Bits' `mrva` terminal tool (December 2025
  release) let a single auditor run a custom CodeQL query against thousands of
  pre-built databases in one shot. GitHub's Security Lab has used MRVA to find
  Android advisories affecting 10M+ apps; the corpus-scale variant hunt is no
  longer a research-team-only capability ([Multi-repository variant analysis](https://github.blog/security/vulnerability-research/multi-repository-variant-analysis-a-powerful-new-way-to-perform-security-research-across-github/),
  [Introducing mrva (Trail of Bits, Dec 2025)](https://blog.trailofbits.com/2025/12/11/introducing-mrva-a-terminal-first-approach-to-codeql-multi-repo-variant-analysis/)).
- **IaC and config-as-code review consolidated.** `tfsec` was absorbed by Trivy
  in 2023; Terrascan was archived by Tenable on
  2025-11-20. Checkov (Palo Alto / Prisma Cloud) and Trivy now own the IaC scanning
  tier; Checkov ships 1,000+ policies including graph-based cross-resource checks
  ([env0: Best IaC Security Scan Tools 2026](https://www.env0.com/blog/best-iac-scan-tool)).
  IaC, Dockerfile, and Kubernetes manifests are now part of the audit scope by
  default, not "infra-team's problem."

The corollary: an auditor who in 2026 still operates without cross-file taint, without
an LLM triage layer, and without a corpus-scale variant tool, is leaving 80% of their
mechanizable productivity on the floor. The audit is still the auditor's job; the
candidate-point generation, false-positive filtering, and variant hunt are now
*tooled*, not artisanal.

### LLM-as-reviewer: tradeoffs and blind-spot patterns

GitHub Copilot Code Review went GA on 2025-04-04
([GitHub Copilot Code Review GA](https://github.blog/changelog/2025-04-04-copilot-code-review-now-generally-available/));
1M+ developers used it within a month. CodeRabbit (a code-review-specific product)
ran on 2M+ repositories and processed 13M+ PRs
([CodeRabbit 2025 Year-End](https://www.coderabbit.ai/blog/2025-the-year-of-the-ai-dev-tool-tech-stack)).
Anthropic's Claude Code (via the `/review` skill family) is the daily-driver review
tool inside Semgrep's research org and many of the AI-first AppSec startups. The
"LLM as code reviewer" is not a 2026 prediction; it is the 2025 baseline.

The auditor working alongside an LLM reviewer must understand its specific
blind-spot patterns:

1. **LLMs review the diff, not the codebase.** Almost every LLM reviewer operates
   on the PR diff and a bounded window of surrounding context. They miss the
   class of bugs where the diff is locally correct but globally wrong —
   the new handler whose authorization-check sibling is in a file the LLM did
   not read; the refactored validator that now bypasses a constraint
   enforced in a different module. **The auditor's job in the LLM-augmented
   review pipeline is the codebase-wide context the LLM cannot afford to
   load.**
2. **LLMs over-flag style and under-flag semantics.** Empirically, LLM
   reviewers reliably catch naming, formatting, missing-null-check, missing-
   error-handling, and obvious-string-concatenation patterns. They reliably
   miss authorization gaps, multi-step state-machine violations,
   cross-trust-boundary identity assumptions, and TOCTOU. The auditor who
   inherits an LLM-pre-reviewed PR should focus exclusively on the
   semantic-and-architectural tier and *not* spend cycles on the patterns
   the LLM already covered.
3. **LLMs hallucinate fixes.** Suggested patches that look right but
   subtly change behavior are common. Endor Labs, citing academic studies,
   reports that over 40% of AI-generated code solutions contain security flaws
   ([Endor Labs: most common AI-generated code vulnerabilities](https://www.endorlabs.com/learn/the-most-common-security-vulnerabilities-in-ai-generated-code)).
   The same hallucination tax applies to LLM-suggested fixes. Treat every
   LLM patch as untrusted input — review the suggested code, do not
   commit it on the LLM's say-so.
4. **LLMs cannot reason about preconditions they were not told about.**
   The click-count discipline (Section 4) is invisible to an LLM that
   only sees code. The auditor must enrich the LLM's context with the
   threat-model artifacts (Section 11) or the LLM will rank a one-click
   FP higher than a zero-click TP.

### DARPA AIxCC: what autonomous review systems achieved in 2025

The DARPA AI Cyber Challenge (AIxCC) final, held at DEF CON 33 in August 2025,
is the strongest public benchmark for autonomous-AI-driven code review and
patching. The numbers
([DARPA AIxCC final results](https://www.darpa.mil/news/2025/aixcc-results),
[Team Atlanta wins](https://www.gatech.edu/news/2025/08/11/georgia-tech-makes-history-wins-darpa-challenge)):

- 86% of synthetic vulnerabilities discovered (up from 37% at semifinals).
- 68% of discovered vulnerabilities patched (up from 25% at semifinals).
- **18 real (non-synthetic) zero-day vulnerabilities** discovered during
  the final and responsibly disclosed: 6 in C codebases, 12 in Java
  codebases.
- All seven finalist Cyber Reasoning Systems were released as OSI-licensed
  open source.

The architectural pattern that won (Team Atlanta, Buttercup-style — multi-agent,
LLM-augmented fuzzing + static-analysis ensemble) is now the public reference
for what a 2026-era autonomous reviewer looks like. Trail of Bits' Buttercup
(2nd place, $3M) augments libFuzzer and Jazzer with LLM-generated test cases,
integrates tree-sitter and code-query systems for static analysis, separates
detection / patching / validation into specialized agents, and achieved >90%
accuracy with 100,000+ LLM calls per system
([Trail of Bits Buttercup post-mortem](https://blog.trailofbits.com/2025/08/09/trail-of-bits-buttercup-wins-2nd-place-in-aixcc-challenge/)).

The implication for the human auditor: the bar for "what a tool can do without
a human" rose by ~2x in 2025. The auditor's value is correspondingly higher
on the work that *did not* clear the 86%/68% bar — the semantic, architectural,
and threat-model-dependent findings that still require a human to articulate.

See also: `software/methodology/fuzzing_discipline_expertise.md` for the
fuzzing-side discipline (corpus design, harness construction, coverage
feedback) that pairs with LLM-augmented review; the Buttercup architecture
is the canonical "fuzzer + reviewer + patcher" composition.

---

## 3. Trust Boundaries and Taint Flow

### Where the boundaries actually live

CWE-501 defines a trust boundary as a region of program execution where the trust level
on one side differs from the trust level on the other. The lexical statement of a trust
boundary is easy; the audit-relevant question is *where in the running program the
transition actually happens*. In a Spring MVC app, the trust boundary is not the
`@RestController` annotation — it is the moment the HTTP request body is parsed into a
Java object via `@RequestBody`. In a Django app, it is the moment a `request.POST.get()`
call returns into a non-`@csrf_exempt` view function.

The implication: the auditor must read the framework's binding layer, not just the
application code. A user-controllable parameter that the framework parses, validates, and
binds to a typed model is fundamentally different from one the application unpacks with
its own parser. The framework's parser is part of the trust boundary's structural defense.

### Validation must happen on the trusted side

A common code-review false positive: the auditor finds a SQL injection sink, traces the
input back through the frontend (which validates), the API gateway (which validates), and
the application layer (which does not validate but passes the result to the sink). The
naïve conclusion is "the sink is OK because three upstream layers validated." This is
wrong. **Validation that happens on the untrusted side of the boundary cannot be relied
upon.** Any attacker who can reach the application directly (via the internal network, a
bypassed gateway, a different client) skips the validation.

This is the canonical defense-in-depth argument, and the canonical reason it matters:
the validation must happen on the **server-side trusted boundary**, not at any earlier
client-side point. Validation on the boundary closest to the sink is the only validation
that survives architectural change.

### Taint flow is a model, not a guarantee

Static taint analysis is the auditor's best friend and worst enemy. The friend: it shows
you, for every sink in the codebase, the set of source-to-sink paths that exist in the
control flow graph. The enemy: it does not know whether each path is *reachable* under
realistic application state, and it does not know whether the path's data is *attacker-
controllable* in practice.

The auditor's job is to evaluate each tainted path the tool emits against three questions:
(1) is the source actually attacker-influenced, (2) does the path's intermediate code
preserve the attacker's influence, (3) does the sink actually do what the analysis claims
when fed the attacker's value. Tainting is hypothesis-generation; the auditor is the
falsification step.

A finding that the auditor cannot falsify is a true positive. A finding the auditor can
falsify (often: "this source is actually a session token from the database, not user
input") should be marked-and-moved-on, with the falsification annotated for the reviewer.

---

## 4. The Attacker's Cost Model: Click-Count and Pre-Conditions

### Click-count ordering is the load-bearing severity axis

**Zero-click is always worse than one-click is always worse than n-click.** This ordering
dominates every other severity dimension when held constant. A buffer overflow in a server
that processes traffic from any unauthenticated remote source (zero-click) is qualitatively
different from the same overflow in a client-side file parser that requires the victim to
double-click a file (one-click) or in a privileged-command pipeline that requires the
victim to copy-paste an attacker-supplied command (n-click).

The reason this ordering is load-bearing: each click is an opportunity for the victim to
withhold consent or for the system to insert a friction step (warning, sandbox, prompt,
SmartScreen). Zero-click eliminates the victim's agency entirely. One-click forces the
attacker to construct a lure; n-click forces the attacker to construct a sustained social
engineering scenario. The defender's mitigation surface increases monotonically with click
count.

CVSS encodes a coarser version of this (`UI:N` vs `UI:R`), but the binary "required vs
none" undersells the gradient. In code review, the right resolution is the full ladder:

| Tier | Definition | Example |
|---|---|---|
| Zero-click pre-auth | Reachable from the network with no prior authentication | Heartbleed; Log4Shell on a public endpoint; ProxyShell |
| Zero-click post-auth (low priv) | Reachable by any authenticated user, no interaction | IDOR on `/api/orders/<id>` |
| Zero-click post-auth (admin) | Reachable only by admin/operator, no interaction | Privileged backend deserialization |
| One-click pre-auth | Reachable when victim clicks attacker-supplied URL/file | Stored XSS triggered on view; document parser RCE |
| One-click post-auth | Same, but victim must already be authenticated | CSRF-style state changes; OAuth callback abuse |
| N-click | Victim must perform two or more deliberate steps | Copy-paste-then-execute; multi-stage social engineering |

### Pre-conditions compound multiplicatively, not additively

When evaluating a candidate point, list the preconditions the attacker must satisfy:
network reachability, authentication tier, authorization tier, knowledge of internal
identifiers, ability to trigger a specific application state, ability to win a race
window. Each is an independent probability of attacker success; the joint exploitability
is their product, not their sum.

This is why an apparent "high severity" finding gated behind three independent
preconditions can be lower priority than an apparent "medium" finding with no
preconditions. The auditor must articulate the precondition stack explicitly in every
finding write-up — handwaving the preconditions is the most common reason engineering
discounts security findings.

### Defense-in-depth shifts the curve, not the asymptote

Mitigations (input validation, output encoding, sandbox, capability dropping) reduce the
exploitability for a fixed bug, but they do not change the attacker's preference ordering.
A zero-click bug behind two layers of mitigation is still an attacker's first pick over a
one-click bug behind one layer. The auditor evaluating a mitigation should ask: does this
mitigation move the bug down a click tier, or does it just narrow the exploit window?
Only the former changes the severity tier.

---

## 5. Authentication and Authorization Code Review

### Heterogeneous auth behavior in a single control abstraction is always suspicious

**The principle:** in any single control abstraction (API controller, DAO, service class,
RPC handler, GraphQL resolver, message-queue consumer), every code path should make the
same auth assumptions and enforce the same auth controls. When some methods of a
controller require authentication and others do not, when some methods of a DAO scope by
the requesting user's tenant and others do not, when some queue consumers validate the
sender's identity and others trust the queue, the heterogeneity is itself a finding.

The reasons it is suspicious:

1. **Drift between code paths is the canonical authorization-bug origin.** Authors who
   write three methods on a controller and remember to add `@PreAuthorize` to two of them
   are almost certainly accidentally omitting it on the third. The omission is rarely
   intentional.
2. **Reviewers cannot pattern-match heterogeneous controllers.** The mental model "this
   controller requires auth" gets violated invisibly; the auditor reading a code review
   misses the omission because the surrounding context primes them to assume uniformity.
3. **Refactor safety breaks down.** When a developer changes the auth posture of "this
   controller" later, they will edit the methods they remember; they will miss the
   methods they did not realize were exceptions. The bug propagates forward in time.

The audit operationalization:

- For every API controller class, enumerate every public/handler method and the auth
  decorator/check applied to each. If the set is not uniform, that is a finding to
  investigate, regardless of whether the heterogeneity is intentional.
- For every DAO/repository class, enumerate every query method and whether it scopes by
  tenant/owner. Heterogeneity here is almost always a missing-authz bug (CWE-862) waiting
  to surface.
- For every message-queue / event consumer, enumerate which handlers validate sender
  identity. A consumer class where 4 of 5 handlers `verify_signature(message)` and the
  5th does not is a candidate point worth deep investigation.

The defense pattern is to **lift auth controls to the abstraction's entry boundary**:
controller-level `@PreAuthorize` rather than per-method, repository-level row-security
policies rather than per-method `.where(tenant=current_tenant)`, queue-level message
authentication via middleware rather than per-handler `verify()`. When the auth check
lives at the abstraction boundary, drift across methods becomes structurally impossible.

### Authentication vs. authorization: a distinction the codebase often blurs

Authentication answers "who is this." Authorization answers "is this who allowed to do
that." Code review consistently finds authentication checks substituting for authorization
checks: handlers that verify "is this request signed" but not "is this signer allowed to
perform this operation on this resource."

The grep pattern: any handler that takes a resource ID as a parameter and accesses the
resource without an authorization check that ties the resource to the authenticated
identity is a CWE-639 / CWE-862 candidate. Examples:

```python
# Authentication present, authorization missing — CWE-862 / CWE-639
@app.route("/orders/<id>")
@login_required               # authentication
def get_order(id):
    return Order.query.get(id)  # NO scope-by-user — IDOR
```

The fix pattern is structural: scope the query at the data layer (`request.user.orders.get(id)`)
so the authorization is enforced by the query itself, not by a pre-check the developer
might omit on the next handler. Per the TAOSSA candidate-point methodology, query-layer
scoping eliminates the candidate point entirely; pre-check authorization just relocates it.

### Session and JWT review

Every session/JWT handling site is a candidate point because session forgery, replay,
algorithm-confusion, and expiration handling are independent bug classes that all hide in
the same code. Specific patterns to investigate:

- **Algorithm-confusion** in JWT verification (`alg=none`, `alg=HS256` with an RSA public
  key) — CWE-1390. Grep for `jwt.decode(...)` calls without an explicit
  `algorithms=["RS256"]` parameter.
- **Predictable session tokens** (sequential, timestamp-derived, low-entropy) — CWE-330.
  Any custom token generator that does not use `secrets.token_urlsafe()` /
  `crypto.randomBytes()` / `java.security.SecureRandom` is suspect.
- **Session fixation** — the authenticated user's session ID survives across the
  pre-auth-to-post-auth transition.

### Privileged-route classification

For each `@admin_required` / `@PreAuthorize("hasRole('ADMIN')")` annotation, ask: what
defines "admin"? Is the role assignment auditable? Can a low-privilege user trigger any
side-effect that promotes them? CWE-269 (Improper Privilege Management) lives here.

---

## 6. Input Validation and Format-String Discipline

### Format strings almost always have a better approach

**The principle:** any code that constructs a format string from a non-literal source, or
that takes a "format string" as an external parameter, should be rewritten. Format strings
were invented before parameterization and structured logging existed; in modern codebases
they are a smell that the author reached for the wrong primitive.

The classical CWE-134 case is well-known:

```c
/* Bad — attacker controls the format string */
printf(user_input);

/* Good — format string is a literal */
printf("%s", user_input);
```

But the smell extends far beyond C `printf`. Modern manifestations:

- **`String.format()` with user input as the format argument** (Java) — `String.format(userTemplate, args)`
  enables arbitrary-length output.
- **f-strings constructed from user input** (Python 3) — `eval(f"{user}")` is the obvious
  case; less obvious is `logger.info(f"User {user_input} did X")` where `user_input` contains
  printf-style escapes that some logging backends still honor.
- **Logger format strings** (Python `%`-style, Log4j, slf4j) — Log4Shell (CVE-2021-44228)
  is the canonical case where the logger's format string handling was itself a sink. The
  general lesson: do not let the logging library evaluate user-controllable substrings.
- **Template injection** — Jinja2 `{{ }}`, ERB `<%= %>`, Thymeleaf `th:utext`, Razor
  `@Raw()`. The format-string family extends to every templating engine that compiles
  user-controllable text as code. CWE-1336.
- **i18n format strings** — `gettext`-style `_("hello %(name)s") % {"name": user}` is
  safer than f-string interpolation, but localized translations are themselves a trust
  boundary; a translator can inject a format specifier that the runtime honors.

The better approach is almost always one of:

1. **Structured logging** with key-value pairs, not format strings. `logger.info("user_action",
   user=user_input, action=action)` gives the logger a typed, parseable record without ever
   substituting into a format string.
2. **Parameterized output** — `printf("%s", x)`, `String.format("%s", x)`, prepared
   statements for SQL, parameterized queries for everything.
3. **Allowlist of format specifiers** when an external format string is genuinely
   required (e.g., a date-format string from a user preference) — parse the format string
   and reject any specifier outside an explicit allowlist.

The grep heuristic: every `printf(` / `String.format(` / `logger.info(f"` / `eval(f"`
where the first argument is not a string literal is a candidate point. Most will be
benign (constants assembled at startup); the rare exceptions are the bug.

### Input validation: allowlist over denylist, structural over syntactic

Denylist validation ("reject inputs containing `<script>`") fails to every novel encoding
the author did not anticipate. Allowlist validation ("accept only `[a-zA-Z0-9_-]{1,32}`")
fails closed when the author missed a legitimate character class, which is recoverable.
Prefer allowlist universally.

Structural validation (parse the input into a typed object, reject inputs that do not
parse) is stronger than syntactic validation (regex match). A JSON parser that produces a
typed object eliminates entire vulnerability classes (truncation, injection of unexpected
keys, unicode normalization differences). A regex match against the raw string does not.

The corollary for code review: any input handler that does its own ad-hoc string parsing
(splitting on commas, regex-extracting fields, hand-rolling URL parsing) is a candidate
point. Modern languages and frameworks provide structured parsers for every standard
format; ad-hoc parsing exists because the author did not know better, and the result is
almost always a bug.

### Unicode, encoding, and the canonicalization gap

Best-fit unicode mapping, overlong UTF-8 sequences, double-encoded URLs, mixed-encoding
inputs (Latin-1 + UTF-8 in the same buffer), and surrogate-pair attacks are recurring
sources of validation bypasses. Zalewski's *The Tangled Web* catalogs the browser-side
manifestations; the same primitives appear in every input handler.

The audit heuristic: any normalization that happens **after** validation is a bug. If the
code validates `username` and then later calls `username.normalize("NFKC")`, an attacker
can submit a non-canonical form that passes validation and canonicalizes to a different
string downstream. Normalize first, then validate. CWE-176, CWE-179.

---

## 7. File System and Path-Handling Discipline

### Absolute path handling is always suspicious

**The principle:** any code that constructs, accepts, or operates on an absolute path —
whether by literal string, by configuration value, by user input, or by environment
variable — is a candidate point. Absolute paths bypass directory-scoping defenses
mechanically. A function that takes an arbitrary path and reads it is, definitionally, a
file-read-anywhere primitive; the only question is whether the attacker can reach the
function and whether the path is attacker-influenced.

The reasons it is suspicious even when the source looks innocuous:

1. **Configuration values are user-influenced in modern deployments.** A config file
   reading `data_path = /var/data` looks safe until you find the code path that
   reassigns it from an environment variable, a CLI flag, a tenant config, or a feature-
   flag service. Any of those flips the path from operator-controlled to attacker-
   controlled.
2. **Symlinks invert directory containment.** Even when the code carefully prepends a
   base directory, `os.path.join("/var/data", user_input)` reduces to `user_input` when
   `user_input` starts with `/`. CWE-23 / CWE-36.
3. **Absolute paths often skip canonicalization.** Code paths that handle "absolute"
   paths frequently assume the absolute path is already canonical and skip the
   `realpath()` step; this is the variant where the attacker submits
   `/var/data/../../etc/passwd` and gets a server-side absolute path through the
   "absolute paths are trusted" branch.
4. **Cross-platform path semantics differ.** Windows treats `C:relative` and
   `\\?\C:\path` differently from POSIX; Java's `Paths.get()` and Python's `pathlib`
   have edge cases around UNC, drive-relative, and reserved-name paths. The defense that
   works on Linux often does not on Windows.

The audit operationalization:

- Grep for `os.path.isabs(`, `Path.isAbsolute(`, `path.IsAbs(`, `Path.IsPathRooted(` and
  trace every call site. If the code branches on absolute-vs-relative, it is admitting it
  knows the two cases differ — examine the absolute branch first.
- Grep for `open(`, `fs.readFile`, `File.ReadAllText`, `ioutil.ReadFile` and trace the
  path argument backwards. Any non-literal path is a candidate point; any path that
  could be absolute is high-priority.
- Inspect every configuration loader for path-typed fields. Confirm whether the loader
  normalizes paths against a known root; if not, the configuration is a trust boundary
  the auditor must treat as untrusted.

### Paths with user inputs must be resolved and verified against proper targeting

**The principle:** when user input contributes any segment of a path that the application
will subsequently access, the constructed path must be **resolved to its canonical form**
(symlinks dereferenced, `..` collapsed, drive/UNC normalization applied) and the resolved
path must be **verified to lie within the intended target directory**, before any
filesystem operation against the path. Both steps are required; neither alone suffices.

The defensive recipe, applied for every language:

**Python:**
```python
from pathlib import Path

def safe_open(base_dir: Path, user_input: str) -> Path:
    target = (base_dir / user_input).resolve()
    base = base_dir.resolve()
    if not target.is_relative_to(base):    # Python 3.9+
        raise PermissionError("path escape")
    return target
```

**Java:**
```java
Path base = baseDir.toRealPath();             // canonicalize base
Path target = base.resolve(userInput).toRealPath();
if (!target.startsWith(base)) {
    throw new SecurityException("path escape");
}
```

**Go:**
```go
absBase, _ := filepath.Abs(base)
target := filepath.Join(absBase, userInput)
absTarget, _ := filepath.EvalSymlinks(target)
rel, err := filepath.Rel(absBase, absTarget)
if err != nil || strings.HasPrefix(rel, "..") {
    return errors.New("path escape")
}
```

**Node.js:**
```javascript
const base = path.resolve(baseDir);
const target = fs.realpathSync(path.resolve(base, userInput));
if (!target.startsWith(base + path.sep)) {
    throw new Error("path escape");
}
```

Three failure modes to grep for:

1. **`os.path.join` without `realpath`** — `os.path.join("/var/data", user_input)` does
   not collapse `..` and does not dereference symlinks. CWE-22.
2. **String concatenation instead of `resolve`/`realpath`** — `base + "/" + user_input`
   skips the canonicalization step entirely.
3. **Prefix check on the non-resolved path** — `target.startsWith(base)` against the
   string before `realpath` lets `/var/data/../../etc/passwd` slip through because the
   string starts with `/var/data` until the OS resolves it.

The two-step structure (resolve THEN verify) is the only correct shape. Either step alone
is bypassable. The combined shape, applied at the boundary, eliminates CWE-22 as a class
for the function.

### TOCTOU between path checks and file operations

Even with correct resolve-and-verify, the attacker can race between the verification and
the open: replace the verified path with a symlink to a sensitive file in the microsecond
window. The structural defense is `openat()` with `O_NOFOLLOW` (POSIX) or `CreateFile`
with `FILE_FLAG_OPEN_REPARSE_POINT` (Windows) — operate on the file descriptor of the
verified path, not on the path string. CWE-367.

This is why path-based file APIs are inherently more dangerous than fd-based APIs. In
code review, flag any sensitive-file operation that uses path-strings across the
check-and-use sequence; the resolve-verify recipe protects against directory escape but
not against TOCTOU.

---

## 8. Serialization and Type Handling Discipline

### Serialization with type handling is always suspicious

**The principle:** any serialization configuration that includes type information in the
serialized stream — Jackson's `enableDefaultTyping()` / `@JsonTypeInfo(use=Id.CLASS)`,
.NET's `TypeNameHandling.All`, PyYAML's `yaml.load()` (without `SafeLoader`), Pickle, Java
`ObjectInputStream`, PHP `unserialize()`, Ruby `Marshal.load()`, fastjson 1.x's
`autoType` — is a candidate point with a very high prior of being CVE-grade. Polymorphic
deserialization is **Property-Oriented Programming** (Frohoff's framing): the attacker
does not inject code, they construct a gadget chain through existing library methods that
collectively achieve arbitrary execution.

The reasons polymorphic-deserialization sinks are uniquely dangerous:

1. **The dangerous primitive is the deserializer itself, not the data.** Input
   validation does not fix the bug; the bug is the willingness to instantiate
   attacker-named classes. Filtering byte patterns or class names is a denylist defense
   against an open-ended class universe (the entire classpath/assemblies/installed
   modules).
2. **Gadgets exist independent of the application.** Jackson's `c3p0`,
   `logback.core.db.DriverManagerConnectionSource`, `tomcat-dbcp.BasicDataSource`; .NET's
   `ObjectDataProvider`, `PSObject`, `ResourceDictionary`; Java native's
   `CommonsCollections1-7`, `Spring1-2`, `Hibernate1-2`. Every dependency the application
   pulls in expands the gadget surface. An auditor cannot enumerate gadgets exhaustively;
   the only safe posture is to never instantiate attacker-named classes.
3. **Default-deny via allowlist is the only structural defense.** JEP 290's
   `ObjectInputFilter`, Jackson's `BasicPolymorphicTypeValidator` with an explicit
   subtype allowlist, .NET's `SerializationBinder` with class-name allowlisting, fastjson's
   `safemode`. Anything less than an explicit, exhaustive allowlist of permitted types is
   a future CVE waiting to be reported. Allowlists must be the boundary; denylists fail
   open against the next-disclosed gadget.

The grep heuristics:

- **Java**: `ObjectInputStream`, `XMLDecoder`, `XStream` (pre-`1.4.18` defaults),
  Jackson `enableDefaultTyping()` or `@JsonTypeInfo(use=Id.CLASS)`, SnakeYAML
  `new Yaml()` without `SafeConstructor`.
- **.NET**: `BinaryFormatter`, `SoapFormatter`, `NetDataContractSerializer`,
  `LosFormatter`, `ObjectStateFormatter`, `JavaScriptSerializer` with
  `SimpleTypeResolver`, `JsonConvert.DeserializeObject` with `TypeNameHandling != None`.
- **Python**: `pickle.loads`, `cPickle.loads`, `yaml.load` (without `SafeLoader`),
  `marshal.loads`, `shelve.open`.
- **PHP**: `unserialize`, `__wakeup`/`__destruct` magic methods on attacker-reachable
  classes.
- **Ruby**: `Marshal.load`, `YAML.load` (unsafe before Psych 4 / Ruby 3.1), `YAML.unsafe_load`,
  `Oj.load(_, mode: :object)`.
- **JS/TS**: `eval`, `Function(`, `vm.runInThisContext`, but more subtly any custom
  reviver function in `JSON.parse(_, reviver)` that instantiates classes from type
  hints.

### The audit operationalization

For every serialization sink the auditor identifies, three questions:

1. **Is the input fully trusted?** Reading a serialized object from disk that the
   application itself wrote, with no opportunity for an attacker to modify the disk
   contents, is fundamentally different from reading a serialized object from a network
   socket. The trust boundary determines the urgency, not the existence of the call.
2. **Is the type domain bounded?** If the application uses a specific, finite set of
   types (e.g., `User`, `Order`, `Payment` and their subtypes), the auditor must verify
   that the deserializer is configured to accept only those types and rejects all others
   by default. The allowlist is the only structural defense.
3. **What is the upgrade path?** The application's dependency tree determines the gadget
   surface today; a `pom.xml` update tomorrow can introduce a new gadget. The audit
   should flag deserialization sinks as "ongoing maintenance burden" findings, not
   one-shot fixes, and recommend either elimination or migration to a non-polymorphic
   format (Protobuf, FlatBuffers, JSON with explicit DTOs).

### Migration patterns

When the application *cannot* eliminate polymorphic deserialization:

- **Replace with constructor-based binding** — Jackson's
  `@JsonCreator` + `@JsonProperty`, .NET's typed `JsonSerializerOptions`, Python's
  Pydantic `model_validate()` over `pickle.loads`.
- **Switch to a serialization format that does not support type metadata** — Protobuf,
  FlatBuffers, MessagePack with strict typing. The format itself prevents the bug class.
- **Apply the JEP 290 / `ObjectInputFilter` / `SerializationBinder` allowlist** where
  the format cannot be changed. Watch for the recurring failure
  modes — allowlists that accept "abstract parent classes" of gadget chains, allowlists
  applied per-call instead of globally, allowlists that omit the deserialization-time
  side effects (`@JsonAlias`, `@JsonAnySetter`).

The auditor's red flag is any deserialization sink where the defensive code is a denylist
or a "reject obviously bad classes" check. That is a CVE-2021 / CVE-2022 / CVE-2023
waiting to happen — the bypass exists; it has not been disclosed yet.

### Pickle and ML-model deserialization is the same bug class with a worse blast radius

The single fastest-growing deserialization sink in 2024-2026 is the ML-model
loader. PyTorch's `torch.load`, scikit-learn's `joblib.load`, HuggingFace's
`from_pretrained` (which delegates to `pickle.load` for non-safetensors weights),
and TensorFlow's older `tf.keras.models.load_model` all run pickle by default (`torch.load` only
before PyTorch 2.6, which flipped `weights_only` to `True`; `weights_only=False`
restores full unpickling),
and the model artifact is treated by developers as data when it is, structurally,
code ([HuggingFace Pickle Scanning docs](https://huggingface.co/docs/hub/en/security-pickle)).

JFrog's 2024 disclosure of malicious models on HuggingFace
([JFrog: malicious HuggingFace models with silent backdoor](https://jfrog.com/blog/data-scientists-targeted-by-malicious-hugging-face-ml-models-with-silent-backdoor/))
demonstrated the working class. HuggingFace's `safetensors` format — externally audited by Trail of Bits
(commissioned by HuggingFace with EleutherAI and Stability AI) and confirmed
to have no critical RCE-enabling flaws — gives the codebase a structural
out. The audit posture:

1. **Any `torch.load`, `joblib.load`, `pickle.load` on a model artifact from
   any non-locally-produced source is CVE-grade pending evidence to the
   contrary.** "We got it from HuggingFace" is not a trust statement; the
   HuggingFace registry pickle-scans uploads but does not verify
   absence-of-malice.
2. **Migrate to `safetensors` wherever the framework supports it.** The
   format stores weights only and has no executable codepath; the entire
   bug class is eliminated structurally ([safetensors security audit](https://huggingface.co/blog/safetensors-security-audit)).
3. **For `from_pretrained` calls, pass `use_safetensors=True` explicitly**
   and fail closed if the artifact lacks a safetensors variant. The library
   default is to fall back to pickle silently.
4. **For ML pipelines that must accept arbitrary user-supplied models
   (Kaggle-style competition platforms, model-serving SaaS), sandbox
   the loader.** Container isolation, gVisor, or running the loader in a
   subprocess with `seccomp-bpf` syscall filtering are the only postures
   that survive a malicious model.

This pattern cross-references heavily with
`software/ai-ml-security/adversarial_ml_model_security_expertise.md` — that
doc covers the model-content security tier (poisoned weights, backdoored
training data, adversarial inputs); the code-review tier covered here is the
loader-side trust boundary. Both apply to every ML-loading PR.

---

## 9. Reviewing AI-Generated Code (2024-2026 Class)

### The prompt-to-PR review challenge

Between mid-2024 and 2026, the canonical question "where did this code come
from?" stopped having a single answer. A substantial fraction of code in modern
codebases is now written by Cursor, Claude Code, GitHub Copilot, Windsurf, or
similar tooling, sometimes with human review and sometimes pasted directly.
Endor Labs reports that **over 40% of AI-generated code solutions contain
security flaws** ([Endor Labs: most common AI-generated code vulnerabilities](https://www.endorlabs.com/learn/the-most-common-security-vulnerabilities-in-ai-generated-code)).

The reviewer's job in this environment is structurally different than in 2017.
The author of the code is not necessarily the human in the PR; the human in
the PR may not have read every line they are submitting. The reviewer is
**both the security reviewer and the code's first careful reader.**

### Bug-class patterns specifically common in AI-generated code

The literature converges on a small set of CWE classes that LLM-assisted
codegen produces at substantially higher rates than human-only codegen:

1. **Missing input sanitization (CWE-20)** — the single most common defect
   class. LLMs reliably produce the working code path and reliably omit
   the validation step. Recipe: any AI-generated handler that accepts
   user input should be triaged for "what does the trained validation
   look like for this framework, and is it present?"
2. **Hardcoded credentials (CWE-259/798)** — LLMs trained on public
   codebases recapitulate the public-codebase pattern of inline secrets
   and example API keys. Grep every AI-generated diff for high-entropy
   strings.
3. **SQL injection via string-concatenated queries (CWE-89)** — LLMs
   produce both correct ORM patterns and incorrect string-concat patterns
   depending on prompt phrasing. The same model can produce both on
   adjacent lines.
4. **Command injection via `os.system(f"...")` / `subprocess(shell=True)`
   (CWE-78)** — LLMs reach for `shell=True` more frequently than human
   authors. The `subprocess.run([...])` array form is structurally safer
   but more verbose, so the LLM picks the unsafe form.
5. **Buffer overflows in C/C++ generated code (CWE-120/787)** —
   particularly common when the LLM produces `strcpy`, `sprintf`, or
   manual buffer arithmetic. C codegen from current-generation LLMs
   remains weak; auditors should treat AI-generated C as
   particularly-untrusted.
6. **Cryptographic misuse (CWE-327, CWE-329, CWE-780)** — ECB mode,
   static IVs, MD5/SHA-1 for security, hand-rolled crypto. LLMs over-
   produce the deprecated patterns because the training data contains
   them.
7. **Hallucinated package imports (CWE-829)** — up to 44.7% of package
   references in some models point to non-existent packages
   ([LLM Generated Code Security (Emergent Mind)](https://www.emergentmind.com/topics/security-of-llm-generated-code)).
   The slop-squatting attack vector: an attacker pre-registers the
   hallucinated package name and ships a backdoor. Cross-reference
   `software/supply-chain/supply_chain_provenance_expertise.md`
   for the broader supply-chain dimension.

The reviewer's grep heuristic for AI-generated code is the union of every
"first-pass red flag" in Section 10 PLUS hallucinated-import checks via
`pip-audit`, `npm audit`, or equivalent against the actual installed
package set.

### The "Rules File Backdoor" and prompt-injection-as-bug-introduction

A novel 2025 class: attackers inject malicious instructions into AI-coding-
tool configuration files (`.cursor/rules`, `.github/copilot-instructions.md`,
project README files) that LLMs read during context-gathering. The LLM
then introduces subtle vulnerabilities at the attacker's direction without
the human author seeing the malicious instruction
([Pillar Security: Rules File Backdoor](https://www.pillar.security/blog/new-vulnerability-in-github-copilot-and-cursor-how-hackers-can-weaponize-code-agents)).

This bug class is novel in three ways:

1. **The "input" the LLM is processing is the codebase itself**, including
   files the author considered prose / config / docs.
2. **The vulnerability is introduced by the LLM, not by the attacker
   directly.** Attribution is to the developer, not the attacker; the
   developer becomes a confused-deputy in the attacker's chain.
3. **No existing CWE cleanly captures it.** The closest is CWE-829
   (inclusion of untrusted source); the operational pattern is closer to
   CWE-94 (code injection) at the meta-tooling layer.

The reviewer's defense:

- **Audit all `.cursor/rules/`, `.github/copilot-instructions.md`,
  `CLAUDE.md`, `AGENTS.md`, and similar config-files for malicious
  instructions before AI-assisted edits.** These files are now part of
  the trust boundary.
- **Pin the AI tool's allowed-tools / permission posture explicitly**
  in checked-in config so a malicious instruction cannot escalate the
  tool's capabilities (e.g., `BYPASS` permission modes inside agentic
  workflows should require deliberate review — this is a real anti-pattern
  seen in production AI-review tooling, where a bypass flag on the
  permission mode silently widened the tool's own write access, not just
  a hypothetical).
- **Cross-link to `software/ai-ml-security/llm_agent_security_expertise.md`**
  for the agent-side defense; that doc covers the runtime tier
  (sandboxing, capability scoping, MCP server review) that complements
  the code-review tier covered here.

### Recent high-impact CVEs in AI-coding-tool ecosystems

The 2025 CVE record establishes that AI-coding-tools are themselves attack
surface, not just attack vectors:

- **CVE-2025-53773** — GitHub Copilot RCE via prompt injection; Copilot
  modified its own environment to escalate privileges and execute code
  on the developer machine ([Embrace The Red writeup](https://embracethered.com/blog/posts/2025/github-copilot-remote-code-execution-via-prompt-injection/)).
- **CVE-2025-54135 (CurXecute)** — Cursor MCP RCE; indirect prompt
  injection through MCP server config triggered zero-click RCE via
  externally-hosted prompts, fixed in Cursor 1.3 ([Aim Security CurXecute](https://www.aim.security/post/when-public-prompts-turn-into-local-shells-rce-in-cursor-via-mcp-auto-start)).
- **CVE-2025-32711 (EchoLeak)** — Microsoft 365 Copilot prompt-injection
  to data-exfiltration ([HackTheBox EchoLeak writeup](https://www.hackthebox.com/blog/cve-2025-32711-echoleak-copilot-vulnerability)).

The reviewer auditing an AI-tool integration into a codebase (an MCP server,
a Copilot Workspace integration, a Cursor extension, a Claude Code
custom skill) is reviewing CVE-grade attack surface. The classes:

1. **External-content ingestion** that flows into the LLM context window
   — README content, GitHub Issues, Slack messages, search results —
   is the prompt-injection entry point. Every such ingestion is a
   trust boundary as serious as a deserialization sink.
2. **MCP server tool definitions** that grant the LLM the ability to
   execute commands, read arbitrary files, or fetch arbitrary URLs are
   privilege grants. The 2025 disclosure pattern is that LLM clients
   under-restrict tools by default; the codebase-side defense is
   explicit allowed-tools lists in checked-in config.
3. **Auto-start hooks** in AI tools (auto-MCP-connect on workspace
   load, auto-rule-apply on file open) are the click-count-zero
   attack vector. Treat any auto-start AI integration the same way
   you would treat any pre-auth network endpoint.

### The reviewer-amplification compound

When AI coding tools become the development front-line, the reviewer's
workload changes shape. Code volume increases (LLMs produce more code,
faster); per-line scrutiny decreases (humans triage faster than they
audit). The compound — more code, less per-line attention — is exactly
the regime where the candidate-point methodology (Section 2) becomes
*more* valuable, not less. The reviewer who tries to read every AI-
generated line is overwhelmed; the reviewer who anchors on candidate
points and uses AI triage (Section 2's Semgrep Assistant pattern) to
filter noise is operating at the right cognitive level.

The general principle: **AI codegen and AI code review must grow in
balance**. A team that ships 5x the code via LLMs but reviews at
human-only rates ships 5x the bugs. A team that reviews via LLM but
generates by human reverts to 2017's productivity. The pair, balanced,
is the 2026 baseline.

---

## 10. The Code Review Triage Checklist

### First-pass red flags (high prior of true positive)

These patterns warrant immediate investigation regardless of context. They are the
"name the bug class" candidate points:

| Pattern | CWE | Why |
|---|---|---|
| `eval` / `exec` / `Function(` / `vm.runInContext` over user input | CWE-94 | Code execution |
| `system(` / `exec(` / `Runtime.exec` / `subprocess(shell=True)` | CWE-78 | Command injection |
| SQL string-concatenation / `.raw` / `.text` ORM escape hatches | CWE-89 | SQL injection |
| `pickle.loads` / `ObjectInputStream` / `BinaryFormatter` / `unserialize` on untrusted bytes | CWE-502 | Deserialization RCE |
| `printf(user)` / `String.format(user, ...)` / format string from non-literal | CWE-134 | Format string |
| `os.path.join(base, user)` without `realpath` + prefix check | CWE-22 | Path traversal |
| `open(user_path)` where path could be absolute | CWE-22, CWE-73 | Arbitrary file read/write |
| `MessageDigest.getInstance("MD5"/"SHA1")` for password/integrity | CWE-328 | Weak hash |
| `Random` / `Math.random()` for security tokens | CWE-330 | Predictable token |
| `jwt.decode` without `algorithms=` argument | CWE-1390 | Algorithm confusion |
| `verify=False` / `rejectUnauthorized: false` / `TrustAllCerts` | CWE-295 | TLS bypass |
| `http://` URL for credential/token transmission | CWE-319 | Cleartext transmission |
| Auth decorators missing from some methods of a controller | CWE-862 | Missing authorization |
| Custom XML parser without `disable_external_entities` | CWE-611 | XXE |

### Second-pass structural flags (medium prior of true positive)

These require more code-context to confirm but should be enumerated:

- Single-tenant queries that do not scope by tenant (CWE-862, multi-tenant data leak).
- Authorization checks done in middleware/decorators rather than at the data layer
  (CWE-639, missing-authz on a single forgotten handler).
- File operations that follow a check-then-use pattern (CWE-367, TOCTOU).
- Cryptographic operations using ECB mode, static IVs, or hardcoded keys (CWE-329,
  CWE-321, CWE-798).
- Cookie / session config without `Secure`, `HttpOnly`, `SameSite=Strict`/`Lax`
  (CWE-1004, CWE-352).
- Error handlers that return stack traces, file paths, or internal hostnames to clients
  (CWE-209).
- Race-condition-prone patterns: lock-free counters used for security decisions,
  non-atomic read-modify-write on credit/balance fields (CWE-362, CWE-367).

### Third-pass design flags (lower prior, higher impact)

These often require architecture review rather than line-by-line code review:

- A subsystem that owns its own auth/authz logic rather than deferring to a shared
  authorization service (CWE-285).
- A multi-step state machine that does not enforce a strict transition graph (CWE-841,
  CWE-840).
- Cross-component trust assumptions: service A "trusts" the data service B passes
  without revalidation (CWE-501).
- Logging that includes sensitive data: passwords, tokens, PII, customer code (CWE-532).
- Dependency-update process that does not pin to immutable references or apply cooldown
  periods (CWE-1357, CWE-1395).

---

## 11. Anti-Patterns and Common Pitfalls

### Anti-patterns the auditor should learn to recognize

**The "defensive parameter" anti-pattern.** A function takes a `validate: bool = True`
parameter that, when set to `False`, skips its validation. Every caller eventually sets
it to `False` "because performance." The audit posture: a security-relevant parameter
should not be optional, and an "unsafe" variant should be a different function with a
name like `_unsafe_internal_only` that grep can find.

**The "TODO: add auth check" anti-pattern.** A comment promising future hardening. Search
every codebase for `TODO`, `FIXME`, `XXX`, `HACK`, `WORKAROUND`, `INSECURE`, `TEMP`.
Half of all medium-severity findings live in code that was already known to be incomplete.

**The "this is internal so we don't need to check" anti-pattern.** Internal endpoints,
admin tools, debug consoles. Every "internal" assumption breaks the day someone exposes
the endpoint to a partner integration, a cloud-service mesh, or a copilot agent. The
auditor should treat internal/external as a hardening tier, not a vulnerability
exemption.

**The "we sanitize earlier in the pipeline" anti-pattern.** Validation in middleware,
gateway, or frontend that is treated as substituting for sink-side validation. Always
verify at the sink; the upstream layer can be bypassed, removed in a refactor, or
inconsistent across endpoints.

**The "the client validates this" anti-pattern.** Any reasoning about client-side
validation as a security defense. The client is the attacker.

**The "obscure encoding" anti-pattern.** Custom encoding/decoding routines that the
author wrote because the standard library "doesn't fit the use case." The standard
library's encoders/decoders have been audited and fuzzed; the custom variant has not.
Find the use-case constraint and use a standard codec.

### Common review pitfalls

- **Over-reliance on grep.** Grep finds the patterns you expect; the bug is in the
  pattern you did not expect. Use grep as the first cut; follow up with reading the code.
- **Stopping at the first bug.** When you find one missing-authz handler, do not ship
  the finding and move on. Audit the surrounding controller — odds are good there are
  more.
- **Failing to articulate the precondition stack.** Every finding the auditor ships
  should name the precondition stack explicitly. "Reachable from the public internet, no
  authentication required, no rate limit observed" is a finding. "SQL injection in
  `get_order`" is a starting point.
- **Treating "best practice violations" as findings.** A weak hash for non-security data
  (file deduplication, cache key) is not a finding. The auditor's currency is genuine
  attacker leverage; spending it on policy violations costs credibility with engineering.
- **Ignoring the rate-of-change.** A function that handles user input and has been
  edited 18 times in the last quarter has a different bug prior than the same function
  untouched for three years. Recent churn is risk. `git log -p --since=3.months.ago`
  per file is part of the audit.

---

## 12. Threat Modeling, Variant Analysis, and IaC Review as Code-Adjacent Disciplines

### Threat-Modeling-as-Code: pytm and Threat Dragon

Threat modeling moved decisively into the codebase between 2017 and 2026. OWASP
pytm (a Python library that expresses processes, dataflows, and trust boundaries
as code) and OWASP Threat Dragon (visual, browser-based, supporting STRIDE /
LINDDUN / CIA / DIE / PLOT4ai) are now the two dominant tools, with Threat Dragon
able to import the CycloneDX TM-BOM (Threat Model Bill of Materials)
format ([OWASP pytm](https://owasp.org/www-project-pytm/),
[OWASP Threat Dragon](https://owasp.org/www-project-threat-dragon/)).

The auditor's leverage: when the threat model itself is committed to the
repository (as a `tm.py` file for pytm, or a `tm.json` for Threat Dragon), the
audit can be **diffed against the code**. A PR that adds a new HTTP endpoint
but does not update the threat model leaves the boundary's auth requirements
unstated; the auditor's grep pattern is "find every PR that touches a route
without touching the threat model." This is variant-analysis applied to design:
find the design-doc-drift pattern instead of the code-bug pattern.

For pytm specifically, the audit recipe:

1. **Every Boundary instance in `tm.py` corresponds to a code-level trust
   transition.** When the audit finds a candidate point (Section 2), confirm
   the corresponding Boundary exists. If it doesn't, the bug is either a
   missing boundary in the model or a missing trust-transition control in
   the code; both are findings.
2. **Every Dataflow has a `protocol` field and `isEncrypted` /
   `authenticatesDestination` controls.** A Dataflow in the model that claims
   `controls.authenticatesDestination=True`
   while the code lacks an auth check is a model-vs-code drift finding —
   the model is now lying.
3. **Run `tm.py --dfd` in CI** to produce the dataflow diagram and check it
   in. The diff against the previous commit shows the structural change
   each PR makes; a PR that visibly adds an unboundaried dataflow gets
   automatic reviewer attention.

### Variant analysis as a first-class auditor discipline

Section 1's "symptoms recur; root causes generalize" framing matured in
2024-2026 into an institutional discipline. GitHub Security Lab's MRVA
combined with Trail of Bits' `mrva` terminal tool gives any auditor the
ability to take a single bug and search for variants across up to 1,000 repositories'
pre-built CodeQL databases without needing build infrastructure
([Trail of Bits codeql-queries](https://github.com/trailofbits/codeql-queries),
[Multi-repository variant analysis blog](https://github.blog/security/vulnerability-research/multi-repository-variant-analysis-a-powerful-new-way-to-perform-security-research-across-github/)).

The operationalization the discipline now expects:

1. **Every shipped finding has a CodeQL query attached** as the variant
   search artifact, even when the original finding was discovered by
   reading code. The query is the *durable* expression of the bug class;
   the finding is just the first instance.
2. **The query gets run against the corpus** (multi-repo or
   org-wide) before the finding ships. If 12 other handlers in the codebase
   have the same bug shape, the finding's title is the bug class, not the
   specific handler.
3. **The query is committed to the repository's security tier**
   so the CI catches
   regressions. The auditor's investment in writing the query pays
   forward into every future PR.

Trail of Bits' public CodeQL query repository (covering misused
cryptography, insecure file permissions, string-method bugs) is the model
for what a 2026 auditor's personal query library looks like; the queries
are the artifact, not the audit-PDF.

### IaC, Dockerfile, and config-as-code review

Half of the security boundaries in a modern stack live in YAML, HCL,
Dockerfile, or JSON, not in application code. The 2024-2026 audit must
include:

- **Terraform / Pulumi / Bicep / CloudFormation** for IaaS resources.
  Checkov (1,000+ policies, graph-based, Palo Alto) and Trivy (the
  `tfsec`-successor, covering Terraform / CloudFormation / ARM / Helm)
  are the production tooling
  ([Trivy / tfsec migration guide](https://github.com/aquasecurity/tfsec/blob/master/tfsec-to-trivy-migration-guide.md)).
  The audit pattern: every IAM-policy resource, every public-bucket
  resource, every NetworkSecurityGroup is a candidate point.
- **Dockerfile** — `USER root`, missing `--no-install-recommends`,
  shell-form `RUN` with variable expansion (the IaC-tier
  command-injection), `ADD <url>` for downloads, hardcoded credentials
  in build args. The audit posture: Dockerfile is application code with
  full filesystem and network capability; treat it as such.
- **Kubernetes manifests** — `securityContext.runAsUser: 0` or missing `runAsNonRoot: true`,
  `privileged: true`, `hostNetwork: true`, missing NetworkPolicies,
  missing RBAC boundaries. The audit posture: every cluster object is
  a privilege grant.
- **GitHub Actions / GitLab CI / CircleCI configs** — `pull_request_target`
  with untrusted PR content, `${{ }}` expansion of attacker-controlled
  values into shell, missing `permissions:` block on the workflow,
  unpinned actions. The supply-chain-tier expertise lives in
  `software/supply-chain/supply_chain_provenance_expertise.md`
  and `software/detection-ir/detection_engineering_expertise.md`;
  the code-review tier treats every CI config as production code.

The combined principle: **the audit's scope is every artifact the
production runtime depends on**, not just the application sources. A
"clean" application code audit that misses a Dockerfile with hardcoded
AWS credentials is a failed audit.

### Supply-chain provenance and the SLSA review tier

The 2024-2026 consolidation: SLSA (Supply-chain Levels for Software
Artifacts) recommends in-toto attestations as the provenance vehicle, and
SLSA's progression to higher levels mandates two-party code review as
a structural control ([SLSA spec](https://slsa.dev/),
[SLSA + in-toto](https://slsa.dev/blog/2023/05/in-toto-and-slsa)).
The reviewer's leverage: the code-review act itself becomes a signed
attestation; SLSA Source Level 4 requires two trusted people to review
every change. The auditor's role expands from "find bugs in
this PR" to "every PR must clear the review gate that the SLSA
attestation will sign over."

GitHub's 2024-2025 introduction of artifact attestations and SBOM
generation in Actions ([InfoQ: Provenance Tools Becoming Standard](https://www.infoq.com/news/2025/08/provenance/))
means the auditor can verify, post-hoc, *which workflow and commit built which
artifact* — and trace back-compromises to the review gate that
admitted them. This is the operational tie between code review and
incident response; cross-link to
`software/supply-chain/supply_chain_provenance_expertise.md` for
the broader pipeline tier.

---

## 13. Operating Model

### When to do code review vs. design review

Design review is upstream and asks: does the architecture make the bug class possible at
all? Code review is downstream and asks: did the implementation realize the architecture
correctly? The two are complementary, not redundant.

When the architecture has a structural defense (e.g., row-level security at the database
ensures every query is tenant-scoped), code review can stop checking for tenant scoping
per query. When the architecture lacks the structural defense, code review must check
every query.

The implication for staff-level work: when you find that a code review keeps turning up
the same bug class, the right output is sometimes "the architecture is wrong here." A
review where every authorization check is hand-written is a review whose deliverable
should be "move authorization to a framework," not "fix the 47 handlers we found."

### Output discipline

A code review finding is a triple: (precondition stack, vulnerability shape, structural
fix). The precondition stack tells the consumer how worried to be. The vulnerability
shape tells them what to look for elsewhere. The structural fix tells them what to
change.

A finding that is just "line 47 has SQL injection" is below the bar. The same finding
written as "(public unauth endpoint, no rate limit) + (string-concatenated SQL across
the entire `UserRepository`) + (migrate to parameterized queries via
`SimpleJdbcInsert` framework)" is shippable.

### When to stop

Auditing has diminishing returns. The first 20% of audit time finds 80% of the
findings; the next 60% finds the 20% that requires understanding the system's full
state machine and concurrent behavior; the last 20% finds vanishingly few findings and
risks degrading into pattern-matching.

The signal that the audit is done: you stop finding new structural classes of bugs.
You may still find instances of classes you already cataloged, but no new genus.
Document the catalog, ship the findings, and budget the next audit for the structural
fixes to land before you re-audit.

### Working with engineering

The auditor's relationship to engineering is adversarial-collaborative: the auditor's
job is to find bugs the engineers missed; the engineers' job is to fix them. The
relationship works when the auditor takes seriously that engineers have context the
audit lacks, and when engineers take seriously that the audit has perspective the
in-tree work lacks.

The single most important auditor habit: when an engineer says "that's not actually a
bug because X," listen. Either X is real and the finding is a false positive (mark it
falsified and move on, gratefully) or X is the engineer's misunderstanding and the
conversation surfaces the real bug. Either way, the conversation is the point. An
auditor who fights every triage decision wastes engineering capacity and stops getting
invited back.

### Closing — what staff-level looks like

A staff-level code reviewer is not measured by the count of findings shipped. They are
measured by the structural fixes that land because of their findings, the bug classes
that stop happening because the architecture changed, and the audit cycles that get
shorter because the codebase has fewer hand-rolled validators and more framework
guarantees.

The work is, at root, the discipline of asking — at every line, in every commit, on
every architectural diagram — *what would an attacker do with this?* The answer is
sometimes "nothing"; the auditor's value is in the cases where the answer is "more than
the author realized."

---

### Cross-references to companion expertise documents

The 2024-2026 deepening pulls in several adjacent disciplines that did not have
companion docs at the original-authoring time. The integrated audit posture now
expects the reviewer to traverse these as needed:

| Companion doc | When to cross-link from a code-review finding |
|---|---|
| `llm_agent_security_expertise.md` | Agent-runtime defenses, MCP server review, allowed-tools scoping; pair with Section 9 |
| `adversarial_ml_model_security_expertise.md` | Pickle / `torch.load` / `from_pretrained` boundary findings; pair with Section 8 |
| `agentic_web_capabilities_expertise.md` | Capability scoping for AI-driven web automation; pair with Section 9 |
| `supply_chain_provenance_expertise.md` | SLSA + in-toto attestation tier; pair with Section 12 |
| `fuzzing_discipline_expertise.md` | Buttercup-style fuzzer + reviewer + patcher composition; pair with Section 2 |
| `detection_engineering_expertise.md` | Runtime-detection signals for review-tier findings; pair with Sections 5 + 12 |
| `steelman_doctrine_expertise.md` | Champion / Foil / Adjudicator procedure for adversarial review of audit findings; the doctrine's Variant B (artifact ship-vs-send-back) is the operating shape for code-review verdicts |

The code review itself is a steelman of the developer's work: the auditor is
the Foil, the developer is the Champion, the merge decision is the Adjudicator.
The discipline is identical; this doc is the substantive content the Foil
brings to the round.

---

*Last reviewed: 2026-05-13. Maintained against TAOSSA (2006), OWASP Code Review
Guide v2.0 (2017), the 2024-2026 AI-assisted code review literature (DARPA AIxCC
finals; arXiv 2412.15004, 2504.20612, 2507.02976, 2509.22040; CodeRabbit /
GitHub / Endor Labs / Semgrep / Snyk product disclosures), and the cumulative
body of CWE / NVD / CanSecWest / Black Hat code-review literature through
May 2026.*
