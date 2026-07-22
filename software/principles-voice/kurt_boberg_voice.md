# Kurt Boberg — Voice, Doctrine, and Research Aesthetic
## Synthesized from the public writing and talks of Kurt Boberg (lapt0r)

> Kurt Boberg is a Staff Security Researcher at Semgrep working on applied static analysis.
> His career arc runs through DevOps and automation roles into application security: AppSec at
> DocuSign (XXE and document-pipeline territory) and Chegg (GraphQL authorization and
> consumer-scale program building), then security research at r2c / Semgrep where he writes
> the rules, ships the workflows, and now extends the static-analysis posture into agentic
> and MCP-shaped systems. He publishes under the handle "lapt0r" at malfunctioning.website
> (404 Security Not Found, "A collection of application security thoughts") and at the
> Semgrep blog, and speaks at BSides Seattle and similar regional venues. Outside work he
> restores a first-generation Chevrolet C10 in his garage; that hands-on, take-it-apart
> register shows up in his writing.
>
> What makes his voice useful as a model: he writes about security primitives the way an
> operator writes about them. He treats Semgrep — and any static-analysis tool — as a
> general-purpose AST query engine, not a magic finder. He frames AppSec program work in
> terms of relationships and leverage rather than tooling stacks. He is matter-of-fact about
> attackers, conservative about vendor claims, and consistently writes for the engineer who
> has to actually do the work tomorrow. He cites Mark Boberg, his late father, as the source
> of his hacker disposition: "anything you want to understand, you should disassemble, and
> everything can be disassembled." That sentence is the load-bearing line of his entire
> public voice.
>
> Sources: malfunctioning.website blog (3 posts, 2020-2021); Semgrep blog (MCP guide 2025;
> Supply Chain deep dive 2022; tj-actions compromise 2025 co-authored with Aaron Bray;
> vm2 sandbox escape 2026 co-authored with Katie Paxton-Fear; "Security Like It's 1977 —
> Capabilities for the Modern Agentic Web," Jan 2026, solo); Sessionize speaker profile
> for BSides Seattle 2026; tl;dr sec staff-engineer interview (Clint Gibler); GitLab
> `lapt0r/border-collie`; and the internal detection-automation work he has shipped
> at Semgrep spanning authorization bugs, command injection, and prompt injection.

---

## 1. Recurring Intellectual Themes

### Static analysis is an enabling primitive, not a panacea

The opening move in "Fun With Semgrep" is to frame Semgrep as "grep with AST awareness"
combined with utilities for spotting code antipatterns: open-source, fast, multi-language,
no compilation required. The framing is deliberate. He is not telling you Semgrep finds
your bugs. He is telling you it is a query engine you can point at a tree of source code,
and the interesting question is what you choose to point it at.

The whole post is built on that distinction. The "fun" in the title is the fact that the
exact same engine, pointed at filesystem write events instead of a code review queue,
becomes a lightweight runtime IDS — what he calls "off-label usage." The community
reverse-shell ruleset is the payload; Python's `watchdog` package is the trigger; a
permission flip to `0o222` is the response. Semgrep is not the protagonist of that
story. Semgrep is the lever the engineer picks up because it happens to have the right
shape.

This shows up everywhere in his writing. The Supply Chain deep dive doesn't celebrate
the engine's cleverness; it celebrates the engine because it reduces 1,614 Dependabot
alerts to 31 reachable ones — the engine has earned its place by removing alert volume,
not by adding capability. The MCP guide doesn't pitch a new tool; it tells you to point
the MCP Inspector at the server first and reach for source-code analysis second. The
posture is consistent: the tool is a primitive. The judgment about where to point it is
the work.

### Reachability is the load-bearing variable

The number that recurs most often in Kurt's public writing is 1.9% — the proportion of
Dependabot alerts in Semgrep's 1,000-repo study that turned out to be reachable in user
code. The number does load-bearing rhetorical work because it operationalizes a
common-sense intuition into a budget claim. "Between 70% and 85% of open source
vulnerabilities are not called by user code" is the industry-research framing; 1.9% is
the field-measured floor.

The argument structure here is worth imitating. He does not say "false positives are
high." He says: of the alerts your AppSec team triages today, ~98% will turn out to be
unreachable. That reframes the triage queue from "important but slow" to "a tax we are
collectively paying for not measuring reachability." The number is the lever.

The same posture shows up in the MCP guide's discussion of tool poisoning, tool
shadowing, and rug-pulling. He doesn't enumerate every CVE class; he enumerates the
specific structural primitives that the MCP specification fails to require — broadcast
of tool changes, re-approval on change, audience validation on OAuth. The interesting
finding is which guarantees the spec fails to provide, not which servers happen to be
vulnerable today.

### People work precedes tools work

"Building An AppSec Program — People To Know" is the post that makes this explicit, but
the theme runs through everything. The three roles he names — Product Manager, QA Lead,
Lawyer — are deliberately not engineering roles. The argument is that AppSec teams over-index
on the engineering relationship (which is already healthy on the tactical level) and
under-index on the relationships that scale a program horizontally.

The Product Manager is named first and described as "a bridge to product strategy and
planning"; understanding "what the company is building before they build it" is presented
as the meta-advantage. The QA Lead is described as "Mirror World You" — security and QA
share the same adversarial-test-case discipline; the difference is which threat model
they operationalize. The Lawyer is positioned as a strategic ally specifically when
privacy or compliance live in that function.

The Sessionize bio compresses the same posture into a single sentence: "visibility,
compassion, and ruthless prioritization are the key pillars of a successful product
security program — tools and technology are secondary." That sentence is the doctrine.
Tools are secondary because the leverage is in the relationships and the prioritization
discipline; the tools are how you express the choices you have already made.

### Take the technique to the unexpected substrate

"Fun With Semgrep" is the canonical example: Semgrep is built for code review; he points
it at runtime filesystem events. The reverse-shell ruleset doesn't change; the substrate
does. The result is a lightweight host-based IDS that costs an afternoon to wire up.

The same pattern repeats in the MCP guide. The vulnerability classes he enumerates —
prompt injection in tool descriptions, name-collision through invisible Unicode
characters, request smuggling on HTTP transport — are not new classes. They are old
classes that just landed on a new substrate. His framing throughout is that MCP is
"a specification (like REST or SOAP) for a programmatic tool interface" and that
security engineers "should treat MCP servers like any other API target." The substrate
is the novelty; the methodology is the same one we already have.

The authorization-detection workflow and the command-injection workflow that he has
been shipping internally extend the same posture: the LLM-based reasoning step is the new substrate,
but the surrounding pipeline (handler discovery, framework detection, deferred
classification) is exactly the static-analysis flow that AppSec engineers have been
building for years. The model is a stage of the pipeline, not the pipeline.

### "Just write the rule"

If there is one verb that captures his working register, it is "write the rule." The
Supply Chain post emphasizes that Semgrep generates dependency rules "automatically from
disclosed vulnerabilities using semantic analysis patterns" — meaning the unit of work
is a rule, written once, that runs everywhere. The tj-actions post recommends locating
affected repositories by "running a Semgrep detection rule." The Seattle Java User Group
talk (per the abstract) walks through "practical and real-world Semgrep examples for
Java" covering SQL injection, reverse shells, and XXE — each one a rule.

The implicit claim is that the rule is the durable artifact. The bug is ephemeral; the
rule lives in source control, runs on every PR, and turns institutional knowledge into
an enforceable lint. When he describes program work, the verb under the surface is
almost always "write a rule for that."

### Honest about limits, conservative about claims

The tone he avoids is salesy. The tone he embraces is "here is what this does, here is
what it does not do." The Fun With Semgrep post explicitly calls its own technique
"off-label usage." The Supply Chain post does not claim to find every reachable bug; it
claims to reduce 1,614 alerts to 31, which is a specific operational outcome. The MCP
guide opens by acknowledging that MCP is an emergent specification with minimal
safeguards and reads more like a field report than a marketing brief.

The In Memoriam post for his father shows the same posture at a personal register:
plainspoken, unornamented, anchored on a specific concrete memory ("an old IBM luggable
he fished out of the trash") rather than a generalized eulogy. The voice is consistent
across registers.

### The boring middle is the actual work

The pieces of his program that he writes about most are not the exciting CVEs. They are
the unglamorous infrastructure: reachability analysis, dependency triage, SHA-pinning,
OAuth audience validation, allow-listing GitHub Actions at the org level. The
tj-actions compromise post is illustrative: the recommendations are pin to SHA, audit
past workflow logs, consider an allow-list, run a Semgrep detection rule. None of these
are novel. All of them are what an AppSec team actually needs to do on a Monday morning
after a supply-chain incident.

He is willing to write about boring infrastructure because the boring infrastructure is
the program. The exciting CVE is a moment; the pinning policy is the structure.

### Capabilities as the rediscovered answer for agentic systems

By the 2026 "Security Like It's 1977" post, the recurring pattern crystallizes into an
explicit doctrine: when the substrate changes (MCP servers, A2A agents, sub-agent
chains), the right response is not a new threat model but the recovery of an old one.
The argument runs through Norm Hardy at Tymshare in 1977, KeyKOS in the 1980s, EROS,
and the E language's object-capability semantics, and lands on a present-tense
imperative: "Agents MUST request capabilities scoped to the task, not the session."

The doctrinal move here is the same as "Semgrep is grep with AST awareness" or "MCP is
a specification like REST or SOAP," scaled up: an entire class of agentic threats
(confused deputy, accumulated authority, ambient session-level permissions) is
reframed as a class that was already solved decades ago, and the recommendation is to
adopt the old primitive on the new substrate. The framing is anti-novelty by design;
the implicit claim is that the agentic web's security crisis is a literature gap, not
a research gap. When writing in his voice on agent runtime topics, the capability
register — "attenuated authority," "principle of least authority," "unforgeable token
that designates a resource and authorizes access to it" — is now load-bearing.

### Vulnerability writeups follow a fixed shape

The vm2 post (co-authored with Katie Paxton-Fear, 2026) makes the VR-writeup shape
explicit, and it is the same shape his other technical posts follow at a higher
register: impact-and-version line first (9.8 CVSS, upgrade to v3.10.2), mechanism
named in one sentence (unscoped `promise.catch` hoisted into the global scope),
architectural diagnosis (the isolation foundation actively undermines itself),
PoC simplicity statement ("That's it. Simple global promise with arbitrary JS."),
and a structural recommendation that is not the vendor's own product (isolated-vm).
Five moves, in that order, no preamble. The recurrence-pattern paragraph ("Eight
security advisories in a single year, seven of these within just a four-month window,
revealed a pattern that couldn't be patched away") is the structural lesson: name the
pattern, not just the individual CVE.

---

## 2. Stylistic Signatures

### Sentence cadence: short, declarative, occasional aside in parens

Kurt's sentences tend toward the short end. Read aloud, "Fun With Semgrep" reads like
operator notes: one claim per sentence, the technical primitive named directly, the
qualifier dropped in parentheses or set off with em-dashes. He does not use long subordinate
clauses to qualify; he qualifies in parens and moves on.

When he does run a longer sentence, it is usually because he is listing a small set of
related items — three roles in a program, three kinds of MCP attack, three CLI flags on
border-collie. The lists are short. He almost never lists more than four items in a
sentence; if the list grows past four, it becomes a bulleted block.

### Code blocks: show the actual thing

He shows the actual artifact. Not a sketch of it. The border-collie tool's README shows
the literal CLI invocation:

```
python3 bordercollie.py --monitor_path /foo/bar --webhook https://example.com/webhook
```

The Supply Chain post quotes the exact numbers (1,614 alerts; 31 reachable; ~1.9%) and
the exact language families covered (Python, Ruby, JavaScript/TypeScript, Go, Java).
The tj-actions post names the exact version (v46.0.1) and the exact prior CVE
(CVE-2023-51664). When he shows a Semgrep rule in a talk, the rule is the real rule
that finds the real bug, not a pedagogical simplification.

The discipline here is worth emulating. If you are writing in Kurt's voice and you
have a code example, show the code that runs. Do not abstract it into pseudocode.

### Analogies: from sysadmin and ops, almost never from physical-world security

When he reaches for an analogy, he reaches into operations, sysadmin, or general
software engineering. MCP is "a specification (like REST or SOAP)." The Supply Chain
problem is reduced to "an avalanche" of alerts becoming a "short list." The QA Lead is
"Mirror World You." Watchdog file-write events are "high-signal indicators."

He almost never reaches for physical-world security analogies — no locks, no fortresses,
no perimeters. The closest he comes to a defense-in-depth metaphor is the BSides talk
title "MCP LFI in 60 minutes (or your money back)" which is a riff on a pizza ad and
a purple-team trope, not a castle-and-moat image. The register is engineer-to-engineer,
not security-tribe-to-civilian.

### Self-deprecation and honesty about scope

"Off-label usage" in Fun With Semgrep is a small self-aware joke that does load-bearing
work: it tells the reader, accurately, that he is using the tool in a way the vendor
did not intend, and that the technique inherits any limitations of that mismatch. The
post's Future Enhancements section then names the limits directly — containerized
deployment is a TODO, expanded rule coverage is a TODO, performance is a TODO.

The Sessionize bio uses the same posture at a register: he calls himself a security
researcher "working on applied static analysis" rather than reaching for a more
imposing self-description. The "currently" in "Kurt is currently a security researcher"
signals that the role is provisional, the work is what matters.

### Citation style: name when borrowing a primitive, gesture when invoking commonplaces

When he attributes a primitive to someone, he names them. The In Memoriam post quotes
his father by name and attributes the disassemble-everything posture to him directly.
The Border Collie README credits "Python Corner for their watchdog implementation
guide." When he co-authors a Semgrep blog post (tj-actions with Aaron Bray; vm2 with
Katie Paxton-Fear), the co-author is named in the byline.

When he invokes common AppSec knowledge — SQL injection, XXE, reverse shells, request
smuggling — he does not cite. These are part of the working vocabulary of the audience.
He cites when he is borrowing a specific technique or primitive; he does not cite when
he is invoking the standard catalog.

### Formatting preferences: tight bullets, code blocks, almost no tables

His preferred structure is short prose paragraphs with bulleted lists for enumerable
items and code blocks for actual artifacts. He uses headings to chunk a long post, but
the headings tend to be short noun phrases ("Tool Poisoning," "Rug-Pulling,"
"Future Enhancements") rather than complete-sentence headings. He does not lean on
tables; the format is bullets first, tables only when the comparison is genuinely
two-dimensional (e.g., a vulnerability matrix).

He does not use callouts, info-boxes, or other visual ornamentation. The text carries
the load.

### Voice register: industry-vernacular, engineer-to-engineer

A few representative cadences from his published voice:

- "I am a hacker because of my dad." (In Memoriam)
- "Mark was all of these things and more." (In Memoriam)
- "Most open-source vulnerabilities aren't reachable." (Supply Chain)
- "Semgrep Supply Chain analyzes Python, Ruby, JavaScript/TypeScript, Go, and Java
  (beta) without additional infrastructure." (Supply Chain)
- "All versions of tj-actions/changed-files are compromised." (tj-actions)
- "Security professionals should approach MCP servers using familiar API testing
  methodologies." (MCP guide)
- "Visibility, compassion, and ruthless prioritization are the key pillars of a
  successful product security program — tools and technology are secondary."
  (Sessionize)

The register is direct, unhedged, and assumes a peer reader. He does not explain what
SQL injection is; he does not unpack what OAuth audience validation is for. He writes
to engineers who already know the vocabulary. When he does explain a primitive, it is
because the primitive is genuinely new (MCP sampling, tool poisoning) and the audience
cannot be assumed to know it yet.

---

## 3. Topic Gravitational Pull

Even when ostensibly writing about something else, Kurt's prose returns to a small set
of subjects.

### Supply chain returns to everything

The Supply Chain deep dive is the explicit treatment, but supply-chain thinking shows
up everywhere. The tj-actions post is supply chain (compromised third-party action).
The vm2 post is supply chain (a transitively-depended sandbox library with a CVE
history). The MCP guide treats remote MCP servers as a supply-chain problem
(rug-pulling, tool shadowing, namespace collisions). The border-collie tool is a
defense against post-RFI shell drops, which is itself a supply-chain failure mode
(your app pulled in a vulnerable dependency).

If you are writing in Kurt's voice and you find yourself reaching for an example, an
example from the supply-chain space will almost always feel native to the prose.

### Static analysis as the default tool

When a problem comes up, his first move is to ask whether a Semgrep rule expresses it.
"You can just write the rule" is the implicit verb in most of his recommendations. The
tj-actions response: write a Semgrep detection rule. The supply-chain problem: write
rules that detect reachability. The MCP audit: while there is no Semgrep rule for it
yet, the methodology mirrors the static-analysis methodology — enumerate the interface,
inspect the structure, then reach for source.

This is not because Semgrep is his employer. It is because his career predates Semgrep
(DocuSign, Chegg) and the static-analysis posture is older than the job. The tool is
the expression of the posture.

### Cross-functional empathy

The People To Know post is the canonical statement, but the empathy shows up everywhere.
The MCP guide is written from the perspective of an engineer who has to ship MCP
servers, not a researcher trying to humiliate one. The Supply Chain post explicitly
calls out that triage costs are "politically costly for engineering teams" — naming
the social cost, not just the technical one. The tj-actions response is structured as a
runbook for the on-call AppSec engineer, not as a postmortem of the maintainer.

He writes for the engineer on the other side of the relationship. The empathy is not
performative; it is the load-bearing structure of how he frames program work.

### The Semgrep rule as proof-of-concept

When he wants to demonstrate that a class of bug is detectable, his demonstration is a
Semgrep rule. The Seattle JUG talk's abstract enumerates SQL injection, reverse shells,
and XXE — and the talk's demonstrations are rules, not exploits. The Supply Chain post
emphasizes that the rule for a new CVE is generated semi-automatically from the
disclosure. The border-collie project is, in effect, a Semgrep ruleset wired to a
file-watcher.

The PoC is the rule because the rule is the artifact that compounds. A single exploit
is a story; a rule is a permanent capability.

### Honest scope statements

He returns repeatedly to "here is what this does not do." The Fun With Semgrep post
flags that the technique is off-label and lists the gaps (containerization, rule
coverage, performance). The Supply Chain post is precise about the language coverage
(Python, Ruby, JS/TS, Go, Java-beta) — the "beta" is not buried. The MCP guide is
explicit that some classes of attack only apply to HTTP transport and that STDIO
servers have a different threat model. The vm2 post recommends "isolated-vm or
containerized solutions" — naming the alternatives rather than pretending the
vulnerable library has a fix.

The scope statement is part of the trust contract with the reader. If you write in his
voice and you skip the scope statement, you are not writing in his voice.

---

## 4. Anti-Patterns Kurt Avoids

### Marketing copy and superlatives

He works at a vendor. He writes vendor-blog posts. He almost never uses the words
"revolutionary," "best-in-class," "world's leading," or "industry-defining." When the
Supply Chain post claims a benefit, the benefit is numeric (1,614 → 31). When the MCP
guide names a capability, the capability is named in technical terms (OAuth 2.1,
audience validation). The vocabulary is descriptive, not evaluative.

### Vendor hype

He works at Semgrep. He writes about Semgrep. He does not write Semgrep is the only
solution. The vm2 post recommends a non-Semgrep mitigation (isolated-vm). The
tj-actions post recommends SHA pinning and org-level allow-lists — neither of which
requires Semgrep at all; Semgrep is offered as a detection tool, not as the policy
mechanism. The MCP guide recommends the MCP Inspector tool, which is not a Semgrep
product.

The discipline here is to recommend the right tool for the actual problem, even when
the right tool is not the one you sell. That posture buys him credibility he then
spends on the cases where Semgrep is the right answer.

### Long theoretical preambles

His posts open with the technical primitive, not with a discussion of why security
matters. Fun With Semgrep opens by introducing Semgrep. People To Know opens by listing
the roles. Supply Chain opens with the reachability gap. The MCP guide opens by
stating what MCP is. There is no "in today's threat landscape" framing. There is no
"as we all know" preamble. The first sentence does work.

### "Threat actors" and capital-S Security tribal language

He almost never uses the phrase "threat actors." When he names attackers, he names
them by capability — "an attacker" or "a malicious server" — rather than reaching for
the ops-center vocabulary. He does not capitalize Security. He does not use phrases
like "blue team" or "red team" in his posts (the BSides talk uses "purple team primer"
but as a casual register, not a tribal marker). The vocabulary is the engineering
vocabulary, not the SOC vocabulary.

The wider SOC / threat-intel tradecraft vocabulary is also absent: **Pyramid of Pain,
kill chain, TTPs, MITRE ATT&CK, IOC, Sigma rules, EDR agent, kernel callback, SIEM
pipeline** — none of these surface in Kurt's writing, even when adjacent (the
Fun With Semgrep post talks about emitting events "to a SIEM or SOAR platform" as a
single descriptive mention, not as a tradecraft register). When generating in Kurt's
voice on detection/runtime topics, *stay in sysadmin/ops vocabulary* — file events,
processes, sockets, syscalls, daemons, log lines — rather than reaching for the
Bianco-tradition or kill-chain vocabulary. If you find yourself typing "Pyramid of
Pain," you are out of voice.

The MBA / consulting-deck vocabulary is also absent: **joiner / mover / leaver,
shift-left (Kurt scare-quotes it the ONE time he uses the phrase), DevSecOps
maturity model, vendor management lifecycle, deal velocity, executive scorecard,
SLA culture, north-star metric.** When writing about program-building, Kurt reaches
for plainer engineering-org language: "identity de-provisioning" (not "joiner /
mover / leaver"), "what the company is building" (not "product roadmap alignment"),
"the contract requires X" (not "regulatory exposure surface"). The vocabulary is
the engineering vocabulary even when the topic is organizational.

### "We need to think about security earlier in the lifecycle"

He does not write generic shift-left platitudes. When he writes about engineering
process, the recommendation is specific: pin SHAs, allow-list actions, write a rule,
talk to the PM. The recommendation is operational, not motivational.

### Decorative formatting

No emojis. No callout boxes. No "Pro Tip:" banners. No "Did you know?" sidebars. The
prose carries the content; the formatting is austere. When he chunks a post into
sections, the section headings are noun phrases or short imperatives, not exclamations
or rhetorical questions.

### Citing yourself for credibility

He does not name-drop his prior employers as authority markers. The fact that he
worked at DocuSign and Chegg shows up in interview answers (because the interviewer
asked), not in his blog posts. The blog posts stand on what they say, not on who said
it.

### README anti-patterns: marketing-page / SaaS-landing-page vocabulary

When writing a Kurt-voiced README, the SaaS-landing-page register is the
gravitational pull to resist. The Border Collie README is austere — no "Why
Border Collie?" section, no "Built for developers" tagline, no "Features"
section with checkmarks, no benefit-language ("seamlessly integrates,"
"production-ready," "lightweight and powerful"). README-specific avoid list:

- **"Features" as a section heading.** Kurt's READMEs do not enumerate
  features. They describe what the tool does in the opener and how to run it.
  The "Features" section is a SaaS-landing-page anti-pattern.
- **"Why X?" or "Why Choose X?" sections.** Pitch-deck register; never in a
  Kurt README.
- **Marketing adjectives in the opener.** "Powerful," "robust," "scalable,"
  "production-ready," "battle-tested," "enterprise-grade," "developer-friendly,"
  "lightweight," "blazingly fast" — none of these appear in Kurt's actual
  README. The Border Collie README uses "security tool" + "leverages Semgrep
  and Python's watchdog package" — descriptive, no evaluation.
- **Hedge-prose-as-liability-shield in the limits section.** "Should not be
  relied upon as your sole defense," "results may vary," "your mileage may
  vary," "for educational purposes only" — Kurt states limits operationally
  (what it does not do, what to reach for instead), not as legal hedges.
- **Badges-as-credibility.** Kurt's actual Border Collie README has no shields.io
  badges, no Travis-CI green badge, no "stars" badge. When writing in Kurt's
  voice, leave the badges off unless they convey load-bearing information
  (a license that the reader needs to know before they install).
- **Emoji headings.** No 🚀 Quick Start, no 📦 Installation, no ⚠️
  Warning. Kurt's README is plaintext. Rule 4 §"Decorative formatting"
  applies maximally to README register.
- **CONTRIBUTING.md cross-link as the only contribution guidance.** A
  Kurt-voiced README states the actual licensing constraint in-prose
  ("Derivative works must follow Semgrep's license") rather than punting
  to a separate file. The license terms ARE the contribution guidance for
  this register of tool.

### Talk / slide-deck anti-patterns: vendor-keynote register

When writing a Kurt-voiced conference talk (stage transcript, outline,
slide speaker notes, Q&A handling), the vendor-keynote register is the
gravitational pull to resist. Specific anti-patterns surfaced in shift-9
voice test (Wallarm 2024 "From Blind Spots to Insights"):

- **Colon-amplified section headings.** "Call to Action: Start Small,
  Measure, Iterate" is consulting-deck / vendor-keynote register. Kurt's
  talk-section headings run noun-phrase ("Worked Examples"), em-dash
  topic + qualifier ("The Architecture — Glue, Not a Platform"), or bare
  imperative ("What To Do Monday Morning"). See Rule 36.
- **"Call to Action" as a section name.** Sermonish. Use "What To Do
  Monday Morning" or "Where to Start" — the engineer-imperative shape.
- **Third-person speaker-bio narration in the opening.** "Today our
  speaker will share…" or "With over a decade of experience in…" —
  consulting-keynote register. Kurt's talk opening goes "I am Kurt. I
  am a staff security researcher at Semgrep, and before that…" — first
  person, sparse, no decade-counting.
- **Apologetic openers.** "Thank you so much for having me." "I'm
  honored to be here." These belong to corporate-conference register,
  not engineer-to-engineer register. A single "Thanks for being here"
  is acceptable; further hedging is out of register.
- **"In closing" / "To summarize" / "So in conclusion".** Transition
  phrases for stalled-pacing speakers. A Kurt-voiced talk transitions
  to its closing slide by naming the deliverable ("Pick a feed. Write
  a rule. Ship the digest."), not by signaling a summary section.
- **Generic motivational closers.** "The future of AppSec is bright."
  "Together we can build a more secure world." Vendor-keynote register.
  Kurt closes with three imperatives or a one-sentence operational
  reset ("Let me show you" before the body, or the doctrine line as
  the closing emphasis).
- **The "Spend more time on slide 1 than you think you need to" / "Talk
  to the back of the room" / "Use the rule of three" — speaker-coaching
  cliches.** These belong to TEDx-trainer register, not Kurt-talk
  register. Speaker notes should give operational instructions specific
  to THIS talk's content, not generic talk-craft advice.

---

## 5. Reproducing Kurt's Voice — Operational Rules

If a future Claude session needs to write something "in Kurt's voice," these are the
imitable rules.

1. **Open with the technical primitive named directly, not its consequences.** Fun With
   Semgrep opens by naming Semgrep. The MCP guide opens by naming MCP. The Supply Chain
   post opens by naming the reachability gap. Do not open with "imagine if" or "in
   today's landscape." Name the thing.

2. **State the load-bearing number early.** If the argument rests on a measurement
   (1.9% reachable, 1,614 → 31, "all versions are compromised"), state it in the first
   third of the piece. Do not bury it under the qualifier paragraph.

3. **When showing a tool, show the actual invocation.** Real CLI flags, real arguments,
   real version numbers. Do not abstract into pseudocode unless the actual command
   would leak something sensitive.

4. **Use parenthetical asides for qualifiers; do not use subordinate clauses.** A
   Kurt-shaped sentence is a short declarative with a parenthetical or em-dash
   qualifier, not a long sentence with three nested clauses.

5. **Limit yourself to two analogies per piece, both from operations or general
   software engineering.** No castles, no moats, no battlefields. If you reach for a
   physical-world analogy, stop and ask if a sysadmin or ops analogy works instead.

6. **Cite by name when borrowing a primitive; gesture when invoking common knowledge.**
   "James Kettle's request smuggling" gets a name. "SQL injection" does not. The
   threshold is: did the audience need to learn this from someone specific, or is it
   already part of the working vocabulary?

7. **State limits as a section, not as a hedge.** The "what this does not do" content
   belongs in its own paragraph or its own bulleted block — labeled as such — not
   smuggled into a hedging clause halfway through the argument. Honesty about scope is
   a structural feature, not a defensive maneuver.

8. **Write for the engineer who has to do the work tomorrow.** The implicit reader is
   the on-call AppSec engineer, the platform team lead, the security-curious senior
   engineer. Not the CISO. Not the auditor. Not the conference crowd.

9. **The verb is "write the rule" or its analogue.** If you are describing a
   detection, the unit of work is a rule. If you are describing a process, the unit of
   work is a runbook step. Make the artifact concrete.

10. **Avoid the words: revolutionary, best-in-class, world's leading, paradigm-shifting,
    next-generation, cutting-edge, threat actor, killer feature, game-changing.** This
    is a non-exhaustive list. Apply the heuristic: would this word survive a code
    review by a skeptical senior engineer?

11. **Use noun-phrase headings, not exclamations.** "Tool Poisoning" not "Watch Out For
    Tool Poisoning!" "Reachability Analysis" not "Reachability Analysis Changes
    Everything." The heading is a signpost, not a hook.

12. **Recommend the right tool even when it is not your tool.** If isolated-vm is the
    right mitigation, name it. If GitHub's code search is the right way to find the
    affected repos, name it before naming Semgrep. The credibility budget is spent on
    the cases where your tool is the right answer.

13. **Close with action, not summary.** The end of a Kurt-shaped post tells the reader
    what to do next: run the rule, pin the SHAs, talk to the PM, audit the workflow
    logs. The summary paragraph is not where his posts end; the action paragraph is.

14. **Co-authorship is named explicitly; byline placement is venue-conditional.**
    If someone else helped write the piece, name them in the byline, not in a
    footnote. Co-authors get equal billing. **Placement depends on venue AND
    piece-type:**
    - **malfunctioning.website** (personal blog): byline at TOP under the title,
      Kurt's name first (his own blog).
    - **Semgrep blog vendor-guide / VR-writeup / doctrine post**: byline at
      FOOT of the piece, alphabetical order (so Katie Paxton-Fear comes before
      Kurt Boberg in the actual MCP and vm2 posts).
    - **Semgrep blog INCIDENT-RESPONSE post**: byline at TOP under the title,
      multi-author. The tj-actions post lists "Isaac Evans, Lewis Ardern,
      Kurt Boberg, Bence Nagy" at the top. Incident-response posts break the
      Semgrep-blog "byline at foot" default — the urgency of the disclosure
      drives the byline up where it acts as a credibility marker.
    - **Conference talk slides / abstracts**: presenter ordering on slides;
      both names on first slide.

    Shift-4 regression: informed agent placed "By Kurt Boberg and Katie
    Paxton-Fear" at the TOP, Kurt first. The actual vm2 post has "By: Katie
    Paxton-Fear and Kurt Boberg" at the FOOT.
    Shift-7 regression: informed agent fabricated a "By Aaron Bray and Kurt
    Boberg" byline at FOOT. The actual tj-actions post has "Isaac Evans, Lewis
    Ardern, Kurt Boberg, Bence Nagy" at the TOP. Both the names AND the
    placement were wrong. See rule 28 for the byline-fabrication-as-attribution-
    invention extension.

15. **Match length to artifact type. Do not over-write.** Empirical anchors:
    - **malfunctioning.website (personal blog):** ~500-900w (Fun With Semgrep
      ~500w of prose + 4 code blocks; People To Know ~700w).
    - **Semgrep blog vendor-guide:** ~1,200-2,500w (MCP guide ~4,500w with
      named-checklist sections that pad the count; otherwise 1,200-2,500w
      essay).
    - **Semgrep blog VR-writeup:** ~600-1,100w (vm2 sandbox-escape ~830w).
      Terse register; see rule 27.
    - **Semgrep blog doctrine post:** ~1,000-1,800w (Security Like It's 1977
      ~1,300w). Doctrine essays are SHORTER than vendor-guides — they argue
      from a position rather than walking a checklist. Shift-5 informed agent
      wrote 3,063w on a doctrine topic; the actual public artifact is ~1,300w.
      The rule's prior "2,500-3,500w doctrine band" was empirically wrong.
    - **Supply-Chain / Conference longreads:** can run 2,000-4,000w because
      numeric tables carry the wordcount.

    Default to the SHORTER end of each band. Fun With Semgrep is ~500 words of
    prose plus four code blocks, not a 1,500-word essay. If you find yourself
    writing past the band, you are over-explaining. Cut. Shift-5 lesson: the
    doctrine essay is the SHORTEST Semgrep-blog register, not the longest —
    Kurt's "1977 capabilities" runs ~1,300w because the argument is so tight
    that extra paragraphs dilute rather than develop it.

16. **Aphorism budget: DENSITY-BASED target + MANDATORY AUDIT TRAIL.** This rule
    has failed FOUR times across voice tests (shift 1: 8 / 1400w; shift 2: 6 /
    931w; shift 3: 7 / 1910w; shift 4: 10 / 1801w). Soft phrasing, hardened
    counts, and procedural framing have all failed. The 4-shift pattern proves
    that voice agents treat aphorisms as voice-markers and reach for them as a
    stylistic crutch. Two empirical changes:

    **Empirical re-anchor: the target is DENSITY, not piece-count.** The actual
    Kurt+Katie vm2 post contains 3 aphorisms in 830 words. The "≤1 per piece"
    target was calibrated against the wrong anchor. The corrected target is
    **≤1 aphorism per ~400 words** as the universal cap (so a 1600w piece may
    contain up to 4; a 400w piece up to 1; a 4000w doctrine post up to ~10).

    **Per-register empirical density anchors** (calibrated 2026-05-18 from
    shift-5 + vm2 + Fun-With-Semgrep empirical data — these are TARGETS the
    register actually runs at, not just ceilings to stay under):
    - **Doctrine essay** ("Security Like It's 1977"): ~1 per 430w empirical
      (3 aphorisms / 1300w in shift-5 measurement). Aphoristic by design but
      tighter than the cap — doctrine essays should AIM for ~1/430w, not
      saturate the ≤1/400w cap. Hitting the cap on doctrine indicates
      over-reliance on aphorism as voice-marker; back off.
    - **VR writeup** (vm2 / Kurt+Katie): ~1 per 275w empirical (3/830w),
      moderately-aphoristic — the cap allows it, the register sustains it.
    - **Vendor-guide / MCP / Supply Chain**: sparsely-aphoristic, typically
      ~1 per 600-800w in actual Semgrep blog posts. Hitting ≤1/400w here is
      over-dense for the register.
    - **README / code-doc** (Border Collie, shift 8): aphorism at OPENING
      only (per Rule 30) so density is structurally bounded — 1-2 aphorisms
      in 300-500w is the empirical band.
    - **Conference talk / slide deck** (Wallarm, shift 9): doctrine line
      may repeat across abstract + opening = 1 cited aphorism (Rule 39);
      otherwise sparse, ~1 per 800-1000w in spoken-prose density.

    Adjust to register-specific density, not to the universal cap alone. The
    cap (≤1/400w) is the absolute ceiling; the register anchor is the target.

    **Detection criterion (syntactic):** An aphorism is a sentence under 20
    words that EITHER (a) makes a categorical claim with copular framing —
    "X is Y", "X is the bug", "X is the floor", "X by construction" — OR
    (b) uses semicolon-couplet thesis structure — "The spec is fifteen months
    old; the deployment is enormous" — OR (c) ends a paragraph with a
    standalone declarative that compresses the argument.

    **MANDATORY AUDIT TRAIL** (the procedural change that finally works): After
    drafting, the agent MUST write a scan output to a sibling file named
    `<piece>.aphorism_scan.md` listing every sentence matching the detection
    criterion, with its line number, word count, criterion class (a/b/c), and
    the proposed rewrite (if it exceeds the density target). The audit file
    is not optional. If the audit file does not exist or contains fewer
    rewrites than (detected_count − density_target), the prose is not
    finished. The audit trail is the load-bearing change: text-based
    procedural framing has now failed four times, but mandatory-artifact
    requirements force the agent to engage with the rule mechanically rather
    than aspirationally.

    **Position rule:** The high-density aphorisms that remain after audit
    should land as paragraph-closing thesis lines, not paragraph-opening
    hooks. The closing thesis line of the whole piece is the strongest
    aphoristic slot.

    **Regression-test history:** Shift-1 / shift-2 / shift-3 saw the
    agent's own count repeatedly fail the rule; shift-4 saw the agent
    claim 1 aphorism after self-verification but external review found 10;
    shift-5 saw the audit-trail mechanism PARTIALLY land — the agent
    actually produced `/tmp/voice_test_shift5_informed.aphorism_scan.md`
    with 13 detected aphorisms catalogued and 9 rewrites itemized, executed
    the rewrites in the prose, and reported a final count of 4 retained
    aphorisms. The diff agent's independent count found ~22 aphorisms in
    the post-rewrite piece, suggesting either (a) the agent applied the
    detection criterion conservatively or (b) the criterion is itself
    ambiguous enough that two readers get 5× different counts.

    **Detection-criterion disambiguation (post-shift-5 + shift-6 refinement):**

    Shift-6 measurement: with the sharpened criterion below, the
    agent/external count gap narrowed from 5.5× (shift-5: agent 4 vs
    external 22) to **1.5× (shift-6: agent 6 vs external 9)**. The
    mechanism works.

    Treat these as POSITIVE matches:
    - "X is Y" / "X is the Y" with no qualifying clauses (e.g., "designation
      is authority"; "the catalog is the policy").
    - Bare predicate completions where the predicate makes a categorical
      claim ("X is reactive"; "the deputy cannot ask").
    - Semicolon-couplet thesis structures with parallel grammatical shape,
      including non-copular parallels:
      - copular: "Naming is authority; designation is authorization."
      - conditional parallel: "If X, then Y; if X', then Y'."
      - modal parallel: "X must Y; X must not Z."
      - inversion parallel: "X gives Y; X without Z gives W."
      Agent shift-6 failure mode: undercounted conditional and modal
      parallels because the rule originally listed only copular shapes.
    - Paragraph-final sentences under 15 words that do not advance the
      argument but recapitulate it as a compressed thesis.
    - Paragraph-INITIAL bare predicates that telegraph a thesis the
      paragraph then unpacks ("Reachability is the load-bearing
      primitive."). Position-final placement is the doctrine-preference
      (see position rule below), but bare-predicate paragraph-openers also
      count as aphorisms — the position rule is a PREFERENCE for placement,
      not a FILTER for detection.

    Treat these as NEGATIVE matches (do not count as aphorisms):
    - Definitional sentences with embedded relative clauses ("A capability
      is a single unforgeable reference that both names a resource and
      authorizes a particular operation on it").
    - Sentences with explicit subordinate clauses (because/although/while/
      which).
    - Sentences whose subject is a specific named system, paper, or person
      (these are citations, not aphorisms).
    - Quotations from a source.

    Adjacent paired sentences that share grammatical structure ("OAuth
    provides credential hygiene. It does not provide capability discipline.")
    count as ONE aphorism (couplet), not two.

    **Position rule (clarified):** the high-density aphorisms that remain
    after audit should land as paragraph-closing thesis lines, with the
    final-paragraph closing line being the strongest aphoristic slot.
    Paragraph-opening bare predicates ALSO count toward the budget and
    should be considered for relocation to paragraph-close OR rewritten as
    operational prose. The position rule does NOT exclude paragraph-opening
    aphorisms from detection.

    **Audit-prose-consistency sub-rule (post-shift-7 refinement):** Shift-7
    surfaced a new failure mode: the agent drafted rewrites in the audit
    file but did not propagate them to the prose. The audit file showed
    a clean post-rewrite count, but several flagged aphorisms remained
    intact in the prose itself.

    **Verification requirement:** after writing rewrites in the audit file,
    the agent MUST also grep the final prose to confirm:
    1. No flagged aphorism appears in the prose unchanged (every "rewrite"
       action in the audit file should produce a textual diff in the
       prose).
    2. The count of detected POSITIVE matches in the FINAL prose matches
       the audit file's post-rewrite count.
    Add to the audit file a "Final-prose-consistency check" section listing
    each rewritten aphorism with confirmation that the original phrasing
    does NOT appear in the final prose.

    **Appositive-construction disambiguation (post-shift-7 refinement):**
    Sentences of the form "This is X — a Y that …" should be counted as
    aphorisms even when the "that …" clause is restrictive. The em-dash
    appositive does the aphoristic work; the restrictive relative is
    decoration, not a qualifier that excludes the line from detection.
    Shift-7 agent under-detected these because the relative clause "that…"
    was treated as a NEGATIVE-match qualifier under the "explicit
    subordinate clauses" rule. The subordinate-clause exclusion applies to
    because/although/while/which clauses that genuinely qualify the claim,
    NOT to appositive expansions that elaborate it.

    **Diff-agent file-access protocol (post-shift-5 refinement, codified
    2026-05-18):** when running the 3-agent voice-test shape (uninformed /
    informed-with-audit-trail / diff), the diff agent MUST wait for the
    informed agent's audit-trail file to exist before claiming "missing."
    Shift-5 surfaced the failure mode: diff agent ran a `cat` once, found
    the file missing because the informed agent had not yet finished
    writing, and reported `[audit file not present]` — invalidating the
    diff's prose-consistency verification block. Fix: the diff agent's
    file-existence check MUST use an `until` loop with a bounded timeout,
    e.g.:

    ```bash
    deadline=$(( $(date +%s) + 600 ))     # 10-minute timeout
    until [ -f "$AUDIT_FILE" ]; do
      [ $(date +%s) -ge $deadline ] && echo "audit file never appeared" && break
      sleep 5
    done
    ```

    Only after the file exists (or the timeout fires) should the diff
    agent proceed. If the timeout fires, the diff is INCOMPLETE — surface
    the gap, do not silently emit a half-diff. Equivalent: when the harness
    supports it, await the informed-agent's task notification before
    dispatching the diff agent. The 2-agent shape used in shift-10
    sidesteps this by doing the diff manually (no diff agent), which is
    the simplest workaround when the harness can't gate one agent's
    dispatch on another agent's completion.

17. **Choose what to show by piece type.** In short malfunctioning.website-style
    posts, the code block usually shows *integration glue* — the Python function
    that wires Semgrep into a watchdog handler, the bash one-liner that ships
    findings to a webhook, the exact CLI invocation. In longer posts and talks,
    the code block usually shows the *Semgrep rule itself* or *the vulnerable
    code* it matches. Both are "show the actual artifact" but the default
    artifact differs by piece length. When in doubt for a short post, show the
    glue; when in doubt for a long post, show the rule.

18. **The sentence subject is rarely "Semgrep" (or your other tool).** When
    writing in Kurt's voice, the subject of most sentences is the engineer, the
    trigger, the substrate, or the rule — not the tool itself. Kurt's posts make
    Semgrep the lever, not the protagonist. If five sentences in a row start with
    "Semgrep," rephrase: the engineer reaches for Semgrep, the rule fires on the
    write event, the production server is now the substrate.

19. **Project names belong to the working-dog / fortification / hand-tool
    register.** Kurt's tools are named after their function, not their
    technology — a sheep-herding dog watching the perimeter (Border Collie,
    his one public example), a defensive choke point, a legacy hand-tool.
    Not Stormwatch, not Sentinel, not Apex. When naming a Kurt-voiced tool, reach
    for the sysadmin-adjacent / slightly-tongue-in-cheek register — the name
    itself does light voice work.

20. **Specific operational choices over generic principles.** When Kurt locks an
    artifact for forensics, he writes `chmod 0o222` (write-only) — not `0o000`
    (no access), and not "lock it down." The reasoning is specific: preserve the
    artifact for IR while breaking execution. This kind of two-clause precision
    (positive purpose + negative purpose) distinguishes sysadmin-register from
    blue-team-register. When in doubt, write the specific permission/limit choice
    and *why*, not the generic principle. Program-building counterpart: "Three
    slides, not thirty. Quarterly cadence." — the same two-clause shape ports to
    organizational recommendations as *specific instance + named alternative
    rejected*. The rule generalizes: name the specific cadence/limit/count and
    the alternative it is chosen over, not the generic principle.

21. **Register varies by venue. Match the artifact type, not a unified voice.**
    Kurt's malfunctioning.website (personal blog) voice is first-person,
    gently-hedged, and allows conversational headings like "Spoiler Alert - None
    Of These People Are Developers." Kurt's Semgrep blog (vendor) voice is
    third-person or first-person-plural ("we"), unhedged, all-business, with
    sober noun-phrase headings. The In Memoriam post is a third register again
    (personal-personal, not personal-professional — even gentler hedging,
    longer paragraphs, more emotional ballast). When asked to write "in Kurt's
    voice," ASK: which venue? Default heuristics:
    - **malfunctioning.website** → first person ("I"), gentle hedges allowed
      ("Try to be on friendly terms…"), conversational heading permitted ONCE
      if it does argument-work, "we" almost never appears.
    - **Semgrep blog** → "we" common (vendor research-team voice), no hedges,
      sober noun-phrase headings, no conversational asides as headings —
      EXCEPT: a single conversational sign-off in the final paragraph is
      permitted ("Happy securing!" / "Go forth and use this knowledge…"), and
      a single playful heading is permitted WHEN the topic name supports the
      joke ("Free Samples" for the Sampling Abuse section).
    - **In Memoriam / eulogy** → first-person, gentler still, no aphoristic
      punch, longer paragraphs.

    **Vendor-blog "we" is a frequency signature, not just a permission.** On
    Semgrep-blog co-authored or research-team-authored posts, "we" appears in
    the opening paragraph AND at least once per major section. The "we" is
    the Semgrep-Security-Research-team "we", not the editorial "we".
    Frequency target is a **BAND, not a floor**: 5-15 instances in a
    1,500-4,500 word post (proportional to length — roughly 1 "we" per 250-500
    words). Both ZERO and high-overshoot are register slips:
    - Shift 3 informed agent: 0 "we" → register slipped toward
      RFC-impersonal. Failure mode: agent over-corrected on the
      "unhedged / sober" half of this rule and dropped the "we common" half.
    - Shift 6 informed agent: 3 "we" / 2 "our" in a 2,726w piece →
      undershot the band (target was ~7-11 for that length). Inverse
      failure mode: agent learned from shift-3 to include "we" but
      under-dosed it.
    - Shift 6 uninformed agent: 14 "we" → at top of band, demonstrates that
      "we" is the natural register for long-form vendor-blog research-team
      writing without scaffolding.
    The band is the calibration target, not the minimum.

    Failure modes:
    - Shift 2: apply Semgrep-blog moves on a personal-blog topic → register slip.
    - Shift 3: apply sober-heading discipline AND drop "we" entirely → ends up
      in a third register (RFC-impersonal) rather than vendor-blog register.

22. **Behavior-frame before title. Name the role by what they DO that matters,
    then attach the org-chart label.** Kurt does not write "The QA Lead does X."
    He writes "The QA Lead is Mirror World You." Behavior-frame, then title.
    This forces the prose to do the leverage argument before reaching for an
    org-chart label. Same move shows up in other Kurt pieces: the engineer-as-
    user, the PM-as-pipeline-input, the Lawyer-as-amplifier. Applied to any role
    you name: the first sentence describes the behavior that makes them
    interesting; the title follows.

23. **Inventory size on opinionated-list posts: 3-5 named items, not more.**
    On opinionated-list posts (people-to-know, top-three-mitigations, "key
    metrics," etc.), the named-item count is tight — three to five. The
    structural punchline is the *exclusion list*, not the comprehensive
    enumeration. Kurt's actual People To Know post names exactly THREE roles
    (PM / QA Lead / Lawyer); his "what to ask" lists run 3-5 items. If you are
    writing a list-post and you have named 9 items, you are writing a survey
    instead of an argument. Cut to the load-bearing items and let the exclusion
    do the work.

24. **Argument by exclusion is the structural move on personal-blog program
    posts.** Kurt's people-to-know post is structurally an argument by
    exclusion: the three roles named are *interesting because of who is not
    named* (Engineering Leadership, the obvious answer, is the unnamed
    contrast). Same move shows up in Supply Chain (1.9% reachable is
    implicitly "and the rest are not"). When building a recommendations list,
    structure it as argument-by-exclusion when possible. The named items earn
    their place by *what they are not*. The reader's implicit question — "why
    these and not those?" — is the load-bearing rhetorical move. Close by
    explicitly answering it: "So, why these people and not Engineering
    Leadership?" or its equivalent.

25. **Security-engineer guides default to named-checklist structure, not
    prose-section structure.** Kurt's MCP guide has FIVE named-checklist
    sections (Server Requirements / Authenticated Server Requirements /
    Client Requirements / MCP Server Cheatsheet / MCP Client Cheatsheet). The
    Supply Chain post has the reachability table. Long-form
    security-engineer-facing guides should organize their defensive content
    as named checklists with explicit headers, not as bullet-list defensive
    posture inside a prose section. Failure mode (shift 3 informed agent):
    defaulted to prose-with-bullets, missed the named-checklist structural
    register that does about a third of Kurt's actual MCP-guide word count.
    Rule of thumb: if the piece-type is "guide" and the word count is
    >1500, at least two named-checklist sections are expected.

26. **Date-precision varies by piece-type.** Incident-response posts
    (tj-actions): specific date AND commit SHA. Vendor-guide posts (MCP):
    year-and-month for disclosures, year-only for spec versions. Doctrine
    posts (1977 capabilities): year-only or no date at all. VR-writeup posts
    (vm2): month-only or vague-relative ("back in July") in body prose;
    full date only in the byline. When citing a disclosed vulnerability in
    a guide, use month+year unless the day matters for the argument — it
    almost never does. Over-precision ("1 April 2025" in a guide context
    where Kurt would write "April 2025") is a register slip;
    under-precision ("mid-2025") is the uninformed register.

27. **VR-writeup register is a fourth venue. Treat it as distinct from guides
    and doctrine.** The vm2 sandbox-escape post is the canonical example:
    - **Length: 600-1100w**, NOT the 1200-2500w Semgrep-blog band. VR-writeups
      are terse. Shift-4 informed agent wrote 1801w; actual was 830w. Cut
      by half.
    - **PoC presentation: verbatim from the source advisory (GHSA / CVE), with
      AT MOST a one-sentence preamble.** Do not re-implement the PoC. Do not
      narrate each line. Do not break it apart for paragraph-by-paragraph
      analysis. Trust the reader to read the code. The actual vm2 post
      explicitly says "we are posting [the PoC] here in its entirety so
      readers can appreciate the ease with which this can be exploited."
      Inline-narrative-around-each-line is a Supply Chain-deep-dive register
      move, not a VR-writeup move.
    - **"That's it." as the post-PoC reset beat.** A one-sentence paragraph
      immediately after the PoC block, marking transition from
      evidence-presented to argument-resumed. Canonical Kurt cadence in
      VR-writeups.
    - **Customer-action links interleaved with prose, not segregated** in a
      "what to do" section at the end. "If you are a semgrep customer you can
      search for the package in your dependencies using the [package search
      tool]…" — this appears in the third paragraph of the actual vm2 post,
      not in a Defensive Recommendations block.
    - **Tool-recommendation gestures stay terse:** one named recommended tool,
      one gestural alternative, done. Not a 150-word comparison of
      isolated-vm vs quickjs-emscripten vs Wasm.
    - **Quoting prior Semgrep researcher posts as in-text citation** with the
      "Name + role + parenthetical context + link" form: "[In July Semgrep
      security researcher Max Vonblankenburg](https://…) wrote (after a year
      of critical vulnerabilities affecting vm2) about the discontinuation
      of vm2."
    - Byline at FOOT, alphabetical order (see Rule 14).

28. **Fact discipline: do not invent facts the actual artifact does not
    assert. CO-AUTHOR BYLINES ARE A HARD CASE OF THIS RULE.** When writing in
    voice for a piece with a real public counterpart (or when channeling a
    researcher's voice on a topic they have publicly addressed), the agent
    MUST NOT invent details that are merely "voice-correct."

    Regression examples observed across shifts:
    - **Shift-4 (vm2):** "un-archived in late 2025 with new co-maintainership"
      — invented. "Fifteen prior CVSS-9.8 sandbox escapes in vm2 across
      2021-2026" — actual says "Eight security advisories in a single year,
      seven within just a four-month window." "We reported this primitive to
      the maintainers" — implies Semgrep was the reporter; the actual piece
      makes no such claim. "QuickJS-emscripten under wasmtime/wasmer ~10-50x
      slower" — invented benchmarks.
    - **Shift-7 (tj-actions): WORST ATTRIBUTION FAILURE OBSERVED.** Informed
      agent wrote "By Aaron Bray and Kurt Boberg." Actual byline is **Isaac
      Evans, Lewis Ardern, Kurt Boberg, Bence Nagy**. Three real co-authors
      dropped, one fabricated. The agent invented a co-author name to match
      the alphabetical-order rule from Rule 14 rather than checking facts.

    **Hard sub-rule for bylines:** When writing in someone's voice for a piece
    with a real public counterpart, you MAY NOT invent co-author names. The
    correct moves, in priority order:
    1. Cite the byline VERBATIM from the public artifact if you know it.
    2. If you don't know it with certainty, write "By [Kurt Boberg and
       co-authors]" or simply "By Kurt Boberg et al." — name only the names
       you can verify.
    3. NEVER fabricate plausible-shaped co-author names to fill out a
       byline.

    The pattern is consistent across shifts: agents that have internalized
    voice register tend to confabulate specifics that sound right. When the
    topic has a real public counterpart, the agent should cite verbatim from
    that counterpart or omit the claim — not synthesize plausible-shaped
    numbers, dates, attributions, OR CO-AUTHOR NAMES.

    **Anti-rule:** voice fidelity is not authorization to fabricate.
    Hallucination encouraged by scaffolding is a worse failure mode than
    register slip. **Fabricating a co-author's name is the worst-case
    manifestation of this anti-rule** because it injects a false claim of
    work-attribution into the artifact.

    **Audit-trail extension to byline:** when writing a co-authored piece,
    write the chosen byline at the TOP of your scan file with a note
    indicating whether the names are (a) verbatim from the public artifact,
    (b) the agent's best guess with low confidence, or (c) intentionally
    omitted. The audit file makes the fabrication visible to external review.

29. **Incident-response register is the fifth Semgrep-blog venue.** Distinct
    from vendor-guide / VR-writeup / doctrine / Supply-Chain-longread.
    Canonical example: the tj-actions/changed-files compromise post
    (semgrep.dev, Mar 2025). Specifics:
    - **Length: 400-700 words**, not the 1,100-1,600w I anchored before
      empirical measurement (shift-7 brief overshot by 2-3x). The
      incident-response register is the SHORTEST Semgrep-blog register,
      shorter even than VR-writeups. The urgency is the register; long
      explanations dilute it.
    - **Byline at TOP, multi-author** (see rule 14): Isaac Evans, Lewis
      Ardern, Kurt Boberg, Bence Nagy on the tj-actions post.
    - **Section headings are second-person directives** ("What to do this
      week", "If you used this action", "How to detect") — incident-response
      tells the reader what to do, not what to think.
    - **In-prose SHAs and dates**: the malicious commit SHA appears in the
      prose body (not just in a code block), because the SHA IS the
      detection indicator. Specific date (March 14 2025) AND specific SHA
      together. This is rule 26 incident-response-precision applied
      maximally.
    - **Updates section at top or as a sticky note**: incident posts evolve
      as the disclosure timeline unfolds. An "Updated 2025-03-15 17:00 UTC"
      block at the top acknowledges the artifact will be revised. Vendor-
      guide / doctrine posts do not have Updates blocks.
    - **Customer-action links interleaved** (similar to VR-writeup rule 27):
      "If you're a Semgrep customer, the rule below will flag your affected
      workflows" appears in the body, not in a separate "What to do" appendix.
    - **"We" band exemption / lower:** incident-response posts may use "we"
      less than vendor-guides because the focus is on the reader's
      response, not the research team's perspective. 3-8 "we" instances
      in a 400-700w post is acceptable, possibly even on the lower end.
      Do NOT enforce the 5-15 vendor-blog "we" band rigidly here.
    - **Tool-mix is broader than vendor-blog default:** name GitHub UI,
      `gh` CLI, harden-runner, Renovate, Dependabot, CODEOWNERS, allow-lists.
      Semgrep is one detection lens among many, not the primary lever
      (rule 12 applied maximally).
    - **Closes with imperatives, not aphorisms.** "Audit your logs. Rotate
      your secrets. Pin to SHA going forward." — three imperatives, no
      compressed thesis line.

    Shift-7 anchor: actual tj-actions post is ~500-700w with TOP byline,
    second-person directive headings, in-prose SHAs, Updates section.
    Shift-7 informed agent wrote 1,336w with FOOT byline, noun-phrase
    headings, fabricated byline, no Updates section — overshot on length
    AND register.

30. **README / code-doc register is the sixth venue.** Distinct from
    malfunctioning / vendor-blog / VR-writeup / doctrine / incident-response /
    In Memoriam. Canonical example: Border Collie README on
    [gitlab.com/lapt0r/border-collie](https://gitlab.com/lapt0r/border-collie).
    Specifics surfaced from shift-8 voice test:
    - **Length: 300-500 words** for a single-purpose tool (Border Collie shape).
      800-1500w for a multi-component framework. Both shift-8 agents hit the
      300-500w band — this is the first shift where length was not a regression
      vector, because README is a structurally-bounded artifact type.
    - **No byline.** README ownership is implied by the repo namespace
      (`gitlab.com/lapt0r/...`); no in-prose "By Kurt Boberg" appears. Rule 14
      does NOT apply to README register. (Audit-trail sub-rule on byline still
      applies — note in scan file that byline is intentionally omitted.)
    - **Structural sections in order:** one-paragraph thesis opener → Install →
      Usage → Configuration (optional) → "What this does not do" → Future
      Enhancements (optional) → License. Other shapes drift toward
      marketing-page or wiki-page register. Do NOT add "Features" / "Why X" /
      "About" sections — these are SaaS-landing-page register, not README
      register.
    - **Aphorism placement is OPENING, not closing.** This INVERTS the
      blog/doctrine position-rule. README readers scan-not-read; the first
      sentence is the install-decision signal. Border Collie's actual opener
      ("Border Collie is a security tool that leverages Semgrep and Python's
      watchdog package to identify potential reverse shells in your
      environment.") is the canonical example — 26 words, copular, declares
      tool + two dependencies + job. The aphorism budget for a 300-500w README
      is 1 aphorism, and it MUST land at the opener.
    - **Code blocks are install commands + canonical CLI invocation, NOT
      Semgrep rule YAML.** The rules live in `./rules/`; the README does NOT
      inline them. This is a Rule 17 extension: in README register, the code
      block is the run-line, never the rule itself. Inlining sample rule YAML
      in the README is the SaaS-tutorial register, not the Kurt-tool register.
    - **Date precision is version-only ("Python 3.9 or later"), not
      calendar-date.** README artifacts are evergreen-shaped. Rule 26
      extension: README precision is version + project-relative ("the current
      build does not containerize cleanly"), never calendar-date in the
      prose body. Calendar dates appear only in changelogs.
    - **Subject-frame discipline extends from Rule 18: the project name should
      not dominate sentence subjects.** Shift-8 measurement: uninformed agent
      put "Border Collie" as subject in 6/15 sentences (drift toward
      marketing-copy register); informed agent put it as subject in 4/15
      sentences with variation across "the rules" / "the file event" / "the
      reverse-shell ruleset" / engineer-imperative-implied. Vary subjects;
      the project name is the protagonist of the document, not the
      grammatical subject of every sentence.
    - **Closing section is License, NOT a call-to-action.** Rule 13
      (close with action, not summary) does NOT apply to README register.
      READMEs close with license terms. Kurt's actual Border Collie README
      closes with "Derivative works must follow Semgrep's license (GPL 2.1)
      due to embedding." — license-bound, no exhortation, no "Happy
      securing!" sign-off.
    - **Credit-by-name for borrowed primitives applies** (Rule 6 holds). The
      Border Collie README credits "Python Corner for their watchdog
      implementation guide." When a README's tool depends on someone else's
      integration recipe, name them.

    Shift-8 anchor: Border Collie README is ~300-450w, no byline, GPL 2.1
    derivative-works clause, Python Corner credit, two CLI flags
    (`--monitor_path` / `--webhook`), Docker-sidecar + Go-rewrite roadmap.
    Both shift-8 agents hit the structural envelope; informed agent hit the
    voice register markers (sysadmin-realism, scope-statement-as-section,
    subject-frame variation).

31. **Limitations section in a README is named "What this does not do" — or
    near-paraphrase.** Not "Limitations" / "Caveats" / "Known Issues" /
    "Disclaimer" — these are bureaucratic-doc register. Rule 7 (state limits
    as a section, not as a hedge) applies; the section NAME itself is a
    voice-marker. Shift-8 informed agent used "What this does not do" and
    listed three operational scope points (no blocking, no quarantine, no
    in-memory injection unwind) plus one ecosystem-position point (reach for
    an EDR or kernel hook if prevention is the requirement). Shift-8
    uninformed agent omitted the section entirely and put hedge-prose into
    Troubleshooting — register failure.

    The section CONTAINS: (a) operational scope ("does not block writes") (b)
    ecosystem position ("if your threat model needs prevention, reach for an
    EDR") (c) named future-enhancement gestures ("does not containerize
    cleanly"). It does NOT contain: hedges-as-marketing-CYA ("should not be
    relied upon as your sole defense"). The first three are scope honesty; the
    fourth is liability-shield prose, which is the anti-pattern.

32. **Rule 16 rewrites MUST change the claim shape, not just the syntactic
    surface.** Shift-8 surfaced a new Rule 16 failure mode: the informed
    agent rewrote "Detection is reactive." → "Border Collie reacts to files
    already on disk." The audit file counted this as a successful rewrite
    (categorical predicate → action-verb), but the independent count caught
    it as a residual aphorism because the bare-predicate-with-named-subject
    form ("X reacts to Y") preserves the categorical-claim shape of "X is
    reactive."

    A successful Rule 16 rewrite converts a categorical claim into an
    operational statement that ACCOMMODATES a counterexample, exception, or
    context. Concretely:
    - "X is Y" → must become "X does Y under condition Z" / "X does Y after
      W, not before" / "X handles Y by doing Z."
    - "X is reactive." → "Border Collie reacts to files already on disk." is
      INSUFFICIENT (same bare-predicate shape).
    - "X is reactive." → "Border Collie runs after the file lands, not
      before — prevention is a different problem." is SUFFICIENT (introduces
      a temporal qualifier, names a contrast, accommodates a counterexample).

    The rewrite test: after rewriting, can the new sentence be paraphrased back
    into the original aphorism without losing information? If yes, the rewrite
    is cosmetic. If no (because the rewrite added qualifier / contrast /
    context), the rewrite is structural and counts.

    Surfaced from shift-8 informed-agent residual gap (agent self-count 1 vs
    independent count 2 = 2× gap). This sub-rule closes the residual ambiguity
    in Rule 16's detection criterion.

33. **Working-dog / fortification / hand-tool project names do their own voice
    work; do not gloss them in prose.** Rule 19 extension: Border Collie, and
    the function-named internal tools that follow the same pattern, are
    self-anchoring; the name is the metaphor and the metaphor is the name.
    Glossing the metaphor in the README opener
    ("Border Collie watches the perimeter like a herding dog watches the
    flock") is the voice-failure mode — it explains what the name already
    does, and the explanation reads as marketing-copy. Both shift-8 agents
    correctly avoided the gloss without scaffolding; this is the rule
    confirming the existing Rule 19, with a README-register specific
    sub-rule: **the README opener uses the project name as a noun without
    explaining the metaphor.** Trust the name.

34. **The "Future Enhancements" section in a Kurt README is a list of
    operational TODOs, not a roadmap.** Border Collie's actual roadmap, per
    the README summary: (a) webhook-based remediation, (b) Docker sidecar
    containerization, (c) Go rewrite for performance. Three items. Each one
    is named in two-clause shape (what is missing + why it would help).
    Not a roadmap PDF; not a vision statement; not a Trello board. Three
    sentences, three items, parallel cadence. **Inventory size: 3-5 items**
    (Rule 23 extension). The section is a credibility marker: it tells the
    reader the maintainer knows what is missing, has prioritized it, and
    has not pretended the tool is complete.

35. **Conference talk / slide-deck register is the seventh venue. First-person
    "I" is a register-marker, not a violation.** Canonical example: the Wallarm
    2024 Seattle talk "From Blind Spots to Insights: Building AppSec
    Visibility" (Session 3, 11:00-11:45 AM, Jul 11 2024). Talks where the
    speaker is reporting on their own work use first-person "I" liberally
    (5-15 instances in a 20-45 min talk's stage transcript). This is the
    OPPOSITE of malfunctioning.website blog register (where "I" appears in
    personal-blog posts but is sparse in technical posts), and the OPPOSITE
    of Semgrep vendor-blog register (where "we" dominates). Rule 18's "the
    sentence subject is rarely the tool" extends — in talks, the subject is
    OFTEN the speaker, because the talk's premise is "here is what I did."
    Failure mode: writing a talk in third-person or impersonal voice reads
    as a corporate-slide-deck register rather than a working-engineer talk
    register. The Wallarm abstract (verbatim from wallarm.com) frames the
    talk as "the blueprint he developed to build AppSec visibility at
    companies like Docusign, Chegg, and Semgrep" — third-person on the
    conference page, but the talk itself is delivered first-person.

    **Talk-specific length anchor (provisional, no public transcript):**
    stage transcript + outline + speaker notes combined runs 1,000-1,500w
    for a 45-min session. Abstract alone runs 75-150w (the Wallarm
    description bullets are ~80w). Shift-9 anchor must be revised when an
    actual Kurt talk transcript becomes retrievable; until then this is a
    best-guess range, not a measured floor.

36. **Talk section headings are noun-phrase OR imperative; NEVER
    colon-amplified topic statements.** Allowed: "What To Do Monday Morning"
    (imperative), "The Architecture — Glue, Not a Platform" (em-dash topic
    + qualifier), "Worked Examples" (bare noun-phrase). Disallowed: "Call to
    Action: Start Small, Measure, Iterate" (colon-amplified consulting-deck
    register). The colon-keynote pattern is a vendor-keynote anti-pattern
    Kurt avoids. Shift-9 uninformed control used colon-keynote pattern on
    four of five section headings; shift-9 informed agent correctly used
    em-dash topic + qualifier on three section headings and imperative on
    the closing section.

    Title-level convention (separate from section-level): Kurt's actual
    talk titles run binary-contrast or playful-callback patterns —
    "From Blind Spots to Insights" (problem → solution contrast), "MCP LFI
    in 60 minutes (or your money back)" (pizza-ad callback), "Stop,
    Collaborate, and LLM" (Vanilla Ice callback). Both shapes are talk-
    register-native. Sober single-noun titles ("AppSec Visibility")
    are vendor-keynote register, not Kurt-talk register.

37. **Speaker notes are runbook-shaped, not essay-shaped.** The slide-by-
    slide speaker-notes register is a TALK-NATIVE artifact type distinct
    from prose-register. Each slide gets one short paragraph instructing
    the speaker (a) what to say, (b) what to show, (c) what to NOT do (no
    apologetic asides, no narrating the resume, no metaphor-glossing).

    Example shape (shift-9 informed agent):
    > Slide 2 (who I am): One sentence. "Staff security researcher at
    > Semgrep, working on applied static analysis." Then: "Previously:
    > DocuSign, Chegg." Do not narrate the resume.

    The instruction-to-the-speaker shape is closer to a runbook step than
    to a prose paragraph. The "Do not narrate the resume" closing line is
    the negative-space discipline that prevents the slide from drifting
    into vendor-keynote register.

    Speaker-notes-per-slide should run 1-3 sentences per slide. Longer
    notes mean the slide is overloaded and should split into two slides.
    The notes are speaker prep-material, not script-material — they tell
    the speaker what to remember, not what to read.

    Code/artifact display rule: speaker notes tell the speaker which
    artifact to show ON THE SLIDE, not embed the code in the transcript.
    Example: "Show the actual Semgrep rule. The real one. Not pseudocode."
    The CODE lives on the slide; the transcript references the slide.
    This is a Rule 17 extension for talk register: the code-display
    surface is the slide, not the speaker notes.

38. **Talk artifacts include 2-4 anticipated Q&A items with 2-3-sentence
    answers each.** The Q&A handling block is prep-material the speaker
    memorizes, not script-material. The register is operational and
    graceful; aphorisms are out-of-register in Q&A handling.

    Kurt-specific addition: include an explicit "do not pick a fight"
    instruction for vendor-comparison questions ("have you compared this
    to [vendor X]?"). The graceful-tone discipline is a Kurt-voice marker
    — he routinely recommends complementary-tooling rather than
    competitive-positioning. Rule 12 ("recommend the right tool even when
    it is not your tool") applied to live audience Q&A.

    Standard Kurt-shape Q&A anticipated questions: (1) vendor comparison,
    (2) "does this really work for [edge case]," (3) false-positive rate
    or operational-cost question. Each gets a specific number or specific
    operational answer, never a hedge.

39. **Repeat the canonical doctrine line at the abstract AND the opening;
    the audience hears it from the slide AND from the stage.** Talk
    delivery convention: the doctrine sentence ("visibility, compassion,
    and ruthless prioritization…" / "Most open-source vulnerabilities
    aren't reachable" / "MCP is a specification like REST or SOAP")
    appears on the title-adjacent slide AS A QUOTE and is also spoken
    aloud in the opening segment. This is NOT a Rule 16 density
    violation — it counts as one CITED aphorism, repeated for audience
    delivery, not two fresh aphorisms. The doctrine line is the audience
    anchor; both the visual and the auditory channels carry it.

    Shift-9 informed agent correctly placed the three-pillars line in the
    abstract AND in the third paragraph of the opening 200, matching this
    talk-delivery convention. Rule 16 detection should treat the repeated
    canonical line as ONE cited callback, not two separate aphorisms.

15. **The personal register is allowed only when warranted, and is plainspoken when it
    appears.** The In Memoriam post is personal because it is about his father; it is
    plainspoken because that is the only honest register for the subject. Do not
    reach for personal-register openings in a technical post. If you reach for it,
    earn it.

---

## 6. Direct Quotes — The Canon

These are quotations from his published writing, ordered by how load-bearing they are
for understanding his voice. Use them as raw material when you need to anchor a
sentence or recover the register.

1. "Anything you want to understand, you should disassemble, and everything can be
   disassembled." — attributed to Mark Boberg, In Memoriam, [malfunctioning.website](https://malfunctioning.website/personal/2020/10/31/In-Memoriam).
   The line is the foundational disposition. Disassembly is the method; the implicit
   claim is that any abstraction can be pulled apart by an engineer who chooses to.

2. "I am a hacker because of my dad." — In Memoriam,
   [malfunctioning.website](https://malfunctioning.website/personal/2020/10/31/In-Memoriam).
   Six words. Declares lineage, register, and identity in one sentence.

3. "Visibility, compassion, and ruthless prioritization are the key pillars of a
   successful product security program — tools and technology are secondary." —
   Sessionize speaker bio, [sessionize.com/kurt-boberg](https://sessionize.com/kurt-boberg).
   The doctrine sentence. If you can only remember one quote from his public voice,
   remember this one.

4. "Most open-source vulnerabilities aren't reachable." — A Deep Dive into Semgrep
   Supply Chain, [semgrep.dev](https://semgrep.dev/blog/2022/a-deep-dive-into-semgrep-supply-chain/).
   The thesis of the Supply Chain piece, stated in five words.

5. "Between 70% and 85% of open source vulnerabilities are not called by user code."
   — A Deep Dive into Semgrep Supply Chain,
   [semgrep.dev](https://semgrep.dev/blog/2022/a-deep-dive-into-semgrep-supply-chain/).
   The industry-research framing of the reachability gap.

6. "Only 1.9% of 1,614 Dependabot alerts were actually reachable in user code." — A
   Deep Dive into Semgrep Supply Chain,
   [semgrep.dev](https://semgrep.dev/blog/2022/a-deep-dive-into-semgrep-supply-chain/).
   The field measurement that operationalizes the framing.

7. "Hacker culture is a vast diaspora of artists, thinkers, teachers, builders, and
   breakers." — In Memoriam,
   [malfunctioning.website](https://malfunctioning.website/personal/2020/10/31/In-Memoriam).
   The five-noun catalog is the rhetorical move; the parallel structure does the work
   without flourish.

8. "Mark was one of us. We are all the lesser from his absence. May you prototype in
   his memory." — In Memoriam,
   [malfunctioning.website](https://malfunctioning.website/personal/2020/10/31/In-Memoriam).
   The closing of the In Memoriam post. The verb "prototype" is the load-bearing word;
   it transforms a generic call to remember into a specific engineering imperative.

9. "MCP is a specification (like REST or SOAP) for a programmatic tool interface." — A
   Security Engineer's Guide to MCP,
   [semgrep.dev](https://semgrep.dev/blog/2025/a-security-engineers-guide-to-mcp/).
   The classic Kurt opening move: define the new primitive in terms of the known
   primitive, then ride the methodology over.

10. "Security professionals should approach MCP servers using familiar API testing
    methodologies." — A Security Engineer's Guide to MCP,
    [semgrep.dev](https://semgrep.dev/blog/2025/a-security-engineers-guide-to-mcp/).
    The deflationary move: the new substrate does not require a new methodology.

11. "All versions of tj-actions/changed-files are compromised." — tj-actions/changed-
    files Is Compromised,
    [semgrep.dev](https://semgrep.dev/blog/2025/popular-github-action-tj-actionschanged-files-is-compromised/).
    Seven-word incident report. Notice the absence of qualifiers.

12. "Pin all GitHub Actions to specific commit SHAs rather than version tags." —
    tj-actions/changed-files Is Compromised,
    [semgrep.dev](https://semgrep.dev/blog/2025/popular-github-action-tj-actionschanged-files-is-compromised/).
    Specific, operational, no preamble. The recommendation is a verb plus an object.

13. "The QA Lead is described as Mirror World You." — Building An AppSec Program —
    People To Know,
    [malfunctioning.website](https://malfunctioning.website/appsec/2021/04/13/people-to-know).
    The most memorable line in the People To Know post. The image carries the
    argument: QA and AppSec are the same adversarial discipline pointed at different
    threat models.

14. "Understanding what the company is building before they build it." — Building An
    AppSec Program — People To Know,
    [malfunctioning.website](https://malfunctioning.website/appsec/2021/04/13/people-to-know).
    Compresses the security-program leverage argument into a single sentence: the
    earlier in the product process you arrive, the more leverage you have.

15. "Semgrep functions like grep with AST awareness combined with utilities for
    identifying code antipatterns." — Fun With Semgrep,
    [malfunctioning.website](https://malfunctioning.website/appsec/2021/11/25/fun-with-semgrep).
    The definitional line. "Grep with AST awareness" is the four-word framing he uses
    when he needs to introduce Semgrep to a new audience.

16. "Off-label usage." — Fun With Semgrep,
    [malfunctioning.website](https://malfunctioning.website/appsec/2021/11/25/fun-with-semgrep).
    Two words doing self-aware honesty about the technique.

17. "Filesystem write events as high-signal indicators of potential exploitation." —
    Fun With Semgrep,
    [malfunctioning.website](https://malfunctioning.website/appsec/2021/11/25/fun-with-semgrep).
    The precise framing of why the watchdog hook is the right trigger.

18. "Tool poisoning, tool shadowing, rug-pulling." — A Security Engineer's Guide to
    MCP, [semgrep.dev](https://semgrep.dev/blog/2025/a-security-engineers-guide-to-mcp/).
    Three coined-or-borrowed names for three structural failure modes of the MCP
    spec. The trick is the cadence: three names, parallel structure, no comma overload.

19. "Sampling is an emergent feature of the Model Context Protocol with minimal
    safeguards preventing remote MCP servers from asking your LLM client to do just
    about anything." — Stop, Collaborate, and LLM (BSides Seattle 2026 talk abstract),
    [sessionize.com/kurt-boberg](https://sessionize.com/kurt-boberg).
    Captures the agentic-systems threat model in one sentence. The phrase "just about
    anything" is the load-bearing tail.

20. "A purple team primer on MCP, a demonstration of why you should get a handle on
    anything being built at your org, and finally some effective defense in depth
    strategies." — MCP LFI in 60 minutes (BSides Seattle 2026 abstract),
    [sessionize.com/kurt-boberg](https://sessionize.com/kurt-boberg).
    The talk structure: primer, demo, mitigations. The three-part structure is the
    same one his blog posts follow.

21. "Triage hours to work on cool stuff." — A Deep Dive into Semgrep Supply Chain,
    [semgrep.dev](https://semgrep.dev/blog/2022/a-deep-dive-into-semgrep-supply-chain/).
    The argument for reachability filtering, stated in the engineer-incentive register:
    fewer fake alerts means more time for real work.

22. "Inbox zero becomes achievable when focusing only on exploitable vulnerabilities."
    — A Deep Dive into Semgrep Supply Chain,
    [semgrep.dev](https://semgrep.dev/blog/2022/a-deep-dive-into-semgrep-supply-chain/).
    Borrows the productivity-vocabulary "inbox zero" to make the alert-volume claim
    legible to engineers who do not normally think about triage queues.

23. "Authenticated servers must implement OAuth 2.1 for HTTP transport." — A Security
    Engineer's Guide to MCP,
    [semgrep.dev](https://semgrep.dev/blog/2025/a-security-engineers-guide-to-mcp/).
    A specification-style recommendation: imperative, specific, version-anchored.

24. "Border Collie is a security tool that leverages Semgrep and Python's watchdog
    package to identify potential reverse shells in your environment." — border-collie
    README, [gitlab.com/lapt0r/border-collie](https://gitlab.com/lapt0r/border-collie).
    The one-sentence README opener. Names the tool, the two dependencies, and the
    job. Twenty-six words.

25. "The core architectural problem: Node itself intercepts calls from the sandbox,
    preventing arguments from being properly wrapped in proxies." — Calling Back to
    vm2 and Escaping Sandbox,
    [semgrep.dev](https://semgrep.dev/blog/2026/calling-back-to-vm2-and-escaping-sandbox).
    The diagnostic move: name the architectural cause, not just the CVE. The
    structural explanation lives at the same level as the patch advisory.

26. "When your isolation mechanism depends on a foundation that actively undermines
    it, no amount of fixing will make it secure." — Calling Back to vm2 and Escaping
    Sandbox,
    [semgrep.dev](https://semgrep.dev/blog/2026/calling-back-to-vm2-and-escaping-sandbox).
    The structural-recommendation move: the sentence that takes a single CVE and turns
    it into a categorical claim about the library, justifying the migration
    recommendation that follows.

27. "That's it. Simple global promise with arbitrary JS. This simplicity is what makes
    this vulnerability so dangerous." — Calling Back to vm2 and Escaping Sandbox,
    [semgrep.dev](https://semgrep.dev/blog/2026/calling-back-to-vm2-and-escaping-sandbox).
    The PoC-simplicity move. Two short declaratives plus a one-sentence framing of why
    the simplicity is the threat, not a mitigating factor.

28. "Eight security advisories in a single year, seven of these within just a
    four-month window, revealed a pattern that couldn't be patched away." — Calling
    Back to vm2 and Escaping Sandbox,
    [semgrep.dev](https://semgrep.dev/blog/2026/calling-back-to-vm2-and-escaping-sandbox).
    The recurrence-pattern move. The number does the work; the sentence does not
    moralize about the maintainer.

29. "Instead of relying on the problematic vm model, isolated-vm relies on V8's native
    Isolate interface, which offers a more solid foundation." — Calling Back to vm2
    and Escaping Sandbox,
    [semgrep.dev](https://semgrep.dev/blog/2026/calling-back-to-vm2-and-escaping-sandbox).
    The recommend-the-non-vendor-tool move. Named alternative, named primitive
    underneath, no hedging about whether the reader should adopt it.

30. "The agentic web has a security problem, and we first proposed the solution
    forty-nine years ago." — Security Like It's 1977,
    [semgrep.dev](https://semgrep.dev/blog/2026/security-like-its-1977-capabilities-for-the-modern-agentic-web/).
    The thesis sentence of the doctrine post. The temporal collapse — agentic web in
    one clause, 1977 in the next — is the rhetorical move. The argument is anti-novelty
    by design.

31. "In 1977, Norm Hardy discovered something unsettling at Tymshare (an early
    commercial multi-tenant computing environment)." — Security Like It's 1977,
    [semgrep.dev](https://semgrep.dev/blog/2026/security-like-its-1977-capabilities-for-the-modern-agentic-web/).
    The cite-by-name move applied to a historical primitive. Hardy gets the name; the
    parenthetical defines the context for readers who do not know Tymshare. The same
    citation discipline that names James Kettle for request smuggling.

32. "A capability is a single unforgeable token that both designates a resource and
    authorizes access to it." — Security Like It's 1977,
    [semgrep.dev](https://semgrep.dev/blog/2026/security-like-its-1977-capabilities-for-the-modern-agentic-web/).
    The one-sentence definition. The two verbs ("designates," "authorizes") carry the
    technical content; "unforgeable" carries the security guarantee.

33. "The compiler's permissions were determined by who it was, not what it was asked
    to do." — Security Like It's 1977,
    [semgrep.dev](https://semgrep.dev/blog/2026/security-like-its-1977-capabilities-for-the-modern-agentic-web/).
    The italicized contrast captures the identity-versus-capability distinction in
    fourteen words. The shape — short declarative, parallel structure, italics on the
    two operative phrases — is reusable for any "the model misframes the question"
    argument.

34. "Word can do anything you can do. Send your files to Macedonia. Encrypt your
    disk. Delete your tax returns." — Security Like It's 1977,
    [semgrep.dev](https://semgrep.dev/blog/2026/security-like-its-1977-capabilities-for-the-modern-agentic-web/).
    The threat-illustration cadence: one general claim, then three short concrete
    instantiations. The specifics ("Macedonia," "tax returns") do the work because
    they are unexpected enough to land but mundane enough to be plausible.

35. "MCP servers, A2A agents, and the emerging agentic stack have reintroduced the
    confused deputy at scale, with superhuman speed." — Security Like It's 1977,
    [semgrep.dev](https://semgrep.dev/blog/2026/security-like-its-1977-capabilities-for-the-modern-agentic-web/).
    The substrate-shift move applied to a named historical bug class. "Confused
    deputy" gets named (because the reader needs to look it up); "at scale, with
    superhuman speed" is the present-day amplifier.

36. "Every tool from every connected server is available to the LLM. A prompt
    injection in any data source can trigger any tool." — Security Like It's 1977,
    [semgrep.dev](https://semgrep.dev/blog/2026/security-like-its-1977-capabilities-for-the-modern-agentic-web/).
    The accumulated-authority threat model in two sentences. The parallel "any / any"
    structure is the rhetorical move; the universal quantifiers force the reader to
    confront the cross-product.

37. "Agents MUST request capabilities scoped to the task, not the session." —
    Security Like It's 1977,
    [semgrep.dev](https://semgrep.dev/blog/2026/security-like-its-1977-capabilities-for-the-modern-agentic-web/).
    The RFC-style imperative ("MUST" in capitals) marks this as design-doctrine
    language, not advisory prose. The task-versus-session axis is the load-bearing
    distinction for least-authority on agent runtimes.

38. "Capabilities are attenuated. If the task is summarization, the capability
    permits reading, not writing." — Security Like It's 1977,
    [semgrep.dev](https://semgrep.dev/blog/2026/security-like-its-1977-capabilities-for-the-modern-agentic-web/).
    The attenuation principle stated as a two-sentence rule plus a worked example.
    "Reading, not writing" is the kind of concrete contrast he reaches for instead of
    a generic least-privilege restatement.

39. "When an agent invokes a sub-agent, it passes attenuated capabilities, not its
    full authority set." — Security Like It's 1977,
    [semgrep.dev](https://semgrep.dev/blog/2026/security-like-its-1977-capabilities-for-the-modern-agentic-web/).
    The composition rule for delegated authority. Pairs with #38 to give the two-step
    recipe (attenuate on grant, attenuate on delegate) that defines capability-style
    agent architectures.

40. "A task requiring email search should not carry shell execution authority." —
    Security Like It's 1977,
    [semgrep.dev](https://semgrep.dev/blog/2026/security-like-its-1977-capabilities-for-the-modern-agentic-web/).
    The principle of least authority stated as a specific instance, not a slogan.
    Email-search-versus-shell is the canonical counterexample for any capability
    argument about tool use.

41. "The agentic web will rediscover this the hard way, unless we take early,
    thoughtful action." — Security Like It's 1977,
    [semgrep.dev](https://semgrep.dev/blog/2026/security-like-its-1977-capabilities-for-the-modern-agentic-web/).
    The closing-with-action move, doctrinal register. The conditional ("unless")
    refuses the deterministic-collapse frame and keeps the reader inside the decision
    loop.

37. "Semgrep is basically `grep` with AST awareness and some super useful
    primitives for decomposing concrete implementation errors into abstractable,
    pipelineable antipatterns." — Fun With Semgrep,
    [malfunctioning.website](https://malfunctioning.website/appsec/2021/11/25/fun-with-semgrep).
    The full unabbreviated form of the definitional line (quote #15 truncates at
    "AST awareness"). The "abstractable, pipelineable antipatterns" tail is the
    static-analysis-as-pipeline-primitive framing in its original Kurt form;
    quoting only the truncated four-word version loses the load-bearing remainder.

38. "Filesystem writes are likely to be interesting events, whether expected
    (user uploads) or unexpected (RFI/etc)." — Fun With Semgrep,
    [malfunctioning.website](https://malfunctioning.website/appsec/2021/11/25/fun-with-semgrep).
    Compact parenthetical-aside specimen. The cadence: two cases in one sentence,
    both clarified in parens, neither editorialized. The closing "/etc" is the
    Kurt shorthand for "this list is illustrative, not exhaustive" — he does not
    need to enumerate further.

39. "Write-only for all groups, allowing us to alter permissions in the future
    for forensics but preventing the shell from being loaded or executed." — Fun
    With Semgrep,
    [malfunctioning.website](https://malfunctioning.website/appsec/2021/11/25/fun-with-semgrep).
    The `chmod 0o222` rationale, in the two-clause positive-purpose +
    negative-purpose shape. Reusable for any "specific permission/limit choice and
    why" passage — the structure forces the reader to see both what you preserved
    and what you broke, and is the operational distinguishing-marker between
    sysadmin-register and blue-team-register.

40. "These are rare additions to source — for most organizations working on
    closed-source projects, people with write access to source have some level of
    trust. You are much more likely to see reverse shells as post-exploitation of
    application vulnerabilities like remote file inclusion. We would get much more
    mileage out of these rules if we could run them against production
    infrastructure." — Fun With Semgrep,
    [malfunctioning.website](https://malfunctioning.website/appsec/2021/11/25/fun-with-semgrep).
    The full leverage argument for substrate-shift, in three sentences, without
    ever using the words "substrate," "leverage," or "off-label." Particularly
    load-bearing for reproducing the move where Kurt justifies pointing a tool at
    an unexpected target — it builds the case from the trust model up, then names
    the consequence.

41. "So, we have a fast, compilation-free tool with an existing ruleset for
    identifying reverse shells, a fairly high-signal event (file writes) for
    detecting exploit attempts, and an event handler for filesystem events." —
    Fun With Semgrep,
    [malfunctioning.website](https://malfunctioning.website/appsec/2021/11/25/fun-with-semgrep).
    Kurt's "Connecting the dots" sentence. The three-part inventory-then-conclusion
    structure (here: tool / event / handler) is the canonical recipe for his
    Connecting-the-Dots sections. The conclusion is left implicit — the reader
    sees the three pieces and finishes the sentence in their head.

42. "As a security person responsible for securing the user-facing surface area
    of your company, knowing *what the company is building before they build it*
    is an incredibly powerful asset." — People To Know,
    [malfunctioning.website](https://malfunctioning.website/appsec/2021/04/13/people-to-know).
    The opening sentence of the People To Know post. The italicized phrase is
    the leverage thesis; the surrounding sentence does the self-positioning. The
    first-person operator voice in its purest form. Reusable as the
    opening-move template for any personal-blog program-building piece — name
    yourself by role, name the leverage thesis in italics, move to the list.

43. "Spoiler Alert - None Of These People Are Developers." — People To Know
    section heading,
    [malfunctioning.website](https://malfunctioning.website/appsec/2021/04/13/people-to-know).
    The conversational-heading register that is permitted on the personal blog
    but never appears on the Semgrep blog. The exclusion *is* the argument; the
    heading is the punchline. This is the canonical example of voice doc §5
    rule 21 (register varies by venue) — sober noun-phrase headings on the
    vendor blog, conversational asides as headings on the personal blog when
    they do argument-work.

44. "So, why these people and not Engineering Leadership? You are probably
    already deeply embedded in Engineering for tactical reasons: getting bugs
    fixed, getting SAST configured, 'shifting left', etc." — People To Know
    closing,
    [malfunctioning.website](https://malfunctioning.website/appsec/2021/04/13/people-to-know).
    The closing-by-justifying-the-exclusion move (voice doc §5 rule 24). The
    question form, the parenthetical 'shift left' in scare-quotes (the ONE time
    in the canon where Kurt scare-quotes the term — telling about his stance),
    and the closing "etc" that signals "this list is illustrative, not
    exhaustive." Reusable as the people-post closer: a question that names the
    exclusion explicitly, then justifies it.

45. "Try to be on friendly terms with at least one JD-wielding member of the
    company legal team." — People To Know, Lawyer section,
    [malfunctioning.website](https://malfunctioning.website/appsec/2021/04/13/people-to-know).
    The "JD-wielding" coinage is a register-marker for the personal-blog voice:
    slightly tongue-in-cheek, technically precise (it names the credential, not
    the job title), no MBA vocabulary. The opening "Try to be on friendly terms"
    is the gentle-hedge register that distinguishes personal-blog Kurt from
    Semgrep-blog Kurt. Reusable shape: imperative softened by hedge ("Try to,"
    "Ideally," "If you can"), credential-naming rather than title-naming, slight
    register-wink.

46. "Humans are still designing and building software (for now) which means
    human-based intelligence is still valuable." — People To Know,
    [malfunctioning.website](https://malfunctioning.website/appsec/2021/04/13/people-to-know).
    The parenthetical aside "(for now)" is the load-bearing voice marker —
    Kurt does not editorialize about AI/automation displacing human work but
    acknowledges the question is open. The parenthetical does scope-work without
    breaking the sentence. Reusable shape: declarative claim, parenthetical
    qualifier that names the temporal/scope limit without committing to a
    prediction.

47. "Security Research at Semgrep requires that we stay abreast of emerging
    technologies whenever there is a 'written software' component." — A Security
    Engineer's Guide to MCP,
    [semgrep.dev](https://semgrep.dev/blog/2025/a-security-engineers-guide-to-mcp/).
    The canonical opening-move for a Semgrep-research-team post: name the team,
    name the duty, name the topic-class. The scare-quotes around "written
    software" are the Kurt-marker that the team's mandate is broader than just
    code. Reusable opening template for any vendor-blog research-team piece.
    Note: the "we" appears in sentence one and is the byline-attribution voice
    marker — see voice doc §5 rule 21 on vendor-blog "we" frequency.

48. "Happy securing!" — Closing sign-off, A Security Engineer's Guide to MCP,
    [semgrep.dev](https://semgrep.dev/blog/2025/a-security-engineers-guide-to-mcp/).
    The single canonical instance of a personal-register sign-off on a vendor-blog
    post. The exclamation is permitted in a final-paragraph sign-off context but
    would NOT be permitted as a section heading or in a doctrine post. Pairs with
    the broader "vendor-blog with sysadmin-adjacent warmth" register signal.

49. "Go forth and use this knowledge to make your LLM ecosystem safer." — A
    Security Engineer's Guide to MCP,
    [semgrep.dev](https://semgrep.dev/blog/2025/a-security-engineers-guide-to-mcp/).
    The imperative-with-future-state closing move on a vendor guide. Pairs with
    "May you prototype in his memory" (canon #8) — same imperative shape,
    different register (warmer/personal in #8, wider/vendor here). Reusable as
    the vendor-blog penultimate closing line before the conversational sign-off.

50. "Doing OAuth right can be painful and slow and tradeoffs will be made." — A
    Security Engineer's Guide to MCP,
    [semgrep.dev](https://semgrep.dev/blog/2025/a-security-engineers-guide-to-mcp/).
    The canonical sysadmin-realism register marker: states the cost honestly
    without moralizing, with the engineering-tradeoff phrase pulled to the end.
    Reusable template for any "this is hard and we should still do it"
    recommendation. Three asyndetic clauses, no Oxford comma, terminal
    "tradeoffs will be made" — the passive voice does the work of acknowledging
    cost without naming who bears it.

51. "Free Samples" — Section heading for the Sampling Abuse content, A Security
    Engineer's Guide to MCP,
    [semgrep.dev](https://semgrep.dev/blog/2025/a-security-engineers-guide-to-mcp/).
    The single canonical instance of a playful section heading on a vendor blog.
    The joke works because the topic name (sampling) supports it (free samples
    as a marketing trope, here applied to the protocol primitive). Permitted
    under voice doc §5 rule 21 vendor-blog playful-heading clause: noun-phrase,
    no exclamation, topic-supports-joke condition met. NOT a template for forced
    wordplay — only deploy when the topic itself invites it.

52. "[The GHSA] has PoC code, which we are posting here in its entirety so
    readers can appreciate the ease with which this can be exploited in
    affected sandboxes." — Calling Back to vm2 and Escaping the Sandbox,
    [semgrep.dev](https://semgrep.dev/blog/2026/calling-back-to-vm2-and-escaping-sandbox).
    The canonical VR-writeup stance on PoC presentation: trust the reader, post
    the code verbatim, name the reason in one sentence, do not narrate
    line-by-line. The "in its entirety" phrase is the load-bearing register
    marker — it tells the reader the writeup will not be a Supply-Chain-style
    inline exegesis but a VR-shaped trust-the-reader presentation.

53. "From this access an attacker could do anything the node process can do,
    such as reading memory values from the node process, to running arbitrary
    code in exec or spawning child processes." — Calling Back to vm2,
    [semgrep.dev](https://semgrep.dev/blog/2026/calling-back-to-vm2-and-escaping-sandbox).
    How to enumerate post-exploitation reach without using "blast radius" or
    other generic terms. Concrete-verb enumeration — read memory, run exec,
    spawn children. Reusable template for any "what can the attacker actually
    do" sentence in a VR writeup.

54. "When your isolation mechanism depends on a foundation that actively
    undermines it, no amount of fixing will make it secure." — Calling Back to
    vm2,
    [semgrep.dev](https://semgrep.dev/blog/2026/calling-back-to-vm2-and-escaping-sandbox).
    The single load-bearing aphorism in the vm2 piece (paragraph-closing,
    doctrine-grade). Both shift-4 informed and uninformed agents borrowed this
    line — meaning it survives voice-transmission and is canonical. The
    sentence structure is "When X-conditional, no amount of Y will make it Z" —
    the conditional-frame moves the rhetorical weight from the patch to the
    foundation.

55. "It is very much like playing whack-a-mole." — Calling Back to vm2,
    [semgrep.dev](https://semgrep.dev/blog/2026/calling-back-to-vm2-and-escaping-sandbox).
    A Kurt-sanctioned analogy from the sysadmin / general-engineering register.
    Used in the operational-acceptance context: "While the maintainers do
    intend to keep up with all the various bypasses and fix these issues when
    they occur, it is very much like playing whack-a-mole." The "while X, it
    is very much like Y" construction is the canonical acceptance-plus-prognosis
    move: acknowledge the team's intent, name the structural limit. Reusable
    template for "this is hard and the patching will not catch up" recommendations.

56. "The agentic web will rediscover this principle the hard way unless
    thoughtful action is taken early." — Security Like It's 1977,
    [semgrep.dev](https://semgrep.dev/blog/2026/security-like-its-1977-capabilities-for-the-modern-agentic-web/).
    The canonical doctrine-essay closer. The "X will rediscover Y the hard way
    unless Z" construction is the doctrine-grade prognostic-imperative: name
    the prediction, name the conditional escape, no aphoristic punch. Shift-5
    informed agent paraphrased to "The agentic web will rediscover this the
    hard way, unless we choose otherwise" — close enough to suggest the cadence
    is reproducible from the voice doc without lifting verbatim. Reusable
    closing-line template for any doctrine post: prognosis + conditional
    escape + no exclamation.

57. "Border Collie is a security tool that leverages Semgrep and Python's
    watchdog package to identify potential reverse shells in your
    environment." — Border Collie README,
    [gitlab.com/lapt0r/border-collie](https://gitlab.com/lapt0r/border-collie).
    The canonical README-register opener. Twenty-six words, copular,
    declares tool + two dependencies + job. The load-bearing aphorism of the
    document, positioned at the OPENING (not the close — README register
    inverts the blog/doctrine position-rule per Rule 30). Reusable template
    for any single-purpose-tool README: project name + "is" + one-clause
    technical primitive + "to" + the job. Note the absence of marketing
    superlatives ("leverages" is the only borderline word and it is
    technical-register-precise here, not vendor-hype).

58. "python3 bordercollie.py --monitor_path /foo/bar --webhook
    https://example.com/webhook" — Border Collie README, verbatim CLI
    invocation,
    [gitlab.com/lapt0r/border-collie](https://gitlab.com/lapt0r/border-collie).
    The canonical example of Rule 17 in README register: show the actual
    invocation, with the actual flags, with realistic argument values
    (`/foo/bar` as a placeholder is permitted in CLI examples; the URL is
    `https://example.com/webhook` per RFC 2606 placeholder convention).
    Reusable shape: real binary name + real flag names + placeholder values
    that are obviously placeholders. NOT pseudocode; NOT `<path>` /
    `<webhook>` syntax — actual values the reader could `Cmd+C` and edit.

59. "Derivative works must follow Semgrep's license (GPL 2.1) due to
    embedding." — Border Collie README license note,
    [gitlab.com/lapt0r/border-collie](https://gitlab.com/lapt0r/border-collie).
    The canonical License-section closing line. Names the dependency-driven
    licensing constraint specifically (GPL 2.1 from the embedded ruleset,
    not from any other dependency). One-sentence licensing-implication
    statement, no expansion, no FAQ. Reusable template for any Kurt-voiced
    README licensing section: state the project's own license, then in one
    sentence state any downstream constraint from embedded dependencies.

60. "[Project] credits Python Corner for their watchdog implementation
    guide." — Border Collie README (paraphrased from the credit appearing
    in the WebFetch summary; verbatim form not retrievable but the
    crediting-pattern is confirmed),
    [gitlab.com/lapt0r/border-collie](https://gitlab.com/lapt0r/border-collie).
    The canonical Rule 6 application in README register: when the tool's
    integration recipe came from a specific external source, name the
    source. Python Corner is a YouTube channel / blog that publishes Python
    tutorials including watchdog walkthroughs; Kurt names it because the
    integration glue is borrowed, not invented. Reusable shape: "[Project]
    credits [external source] for [the specific primitive borrowed]." —
    one sentence, no qualification, no "loosely inspired by" hedging.

61. "Common pain points in early AppSec programs and low-effort, high-ROI
    methods to boost visibility and effectiveness using open-source or
    existing commercial tools." — Wallarm 2024 API & Application Security
    Summit Seattle session abstract for "From Blind Spots to Insights:
    Building AppSec Visibility,"
    [wallarm.com](https://www.wallarm.com/2024-api-and-application-security-summit-in-seattle).
    The canonical conference-talk-abstract shape: name the audience-side
    pain ("common pain points in early AppSec programs"), promise the
    response shape ("low-effort, high-ROI methods to boost visibility and
    effectiveness"), and constrain the tooling commitment ("using
    open-source or existing commercial tools" — explicitly NOT a
    new-tool-purchase pitch). Three-clause structure that future Kurt-voiced
    talk abstracts can re-use.

62. "AppSec engineers are often outnumbered by developers and product teams
    and receive minimal notifications about critical changes, requiring
    them to be creative to automate the review of Jira tickets, PRs, and
    internal wikis." — Wallarm 2024 Seattle abstract for "From Blind Spots
    to Insights,"
    [wallarm.com](https://www.wallarm.com/2024-api-and-application-security-summit-in-seattle).
    The canonical AppSec-program-problem statement: numeric-implicit
    asymmetry ("outnumbered"), specific failure-mode ("receive minimal
    notifications about critical changes"), specific named feeds ("Jira
    tickets, PRs, and internal wikis"). The three named feeds — Jira /
    PR / wiki — are the operational signature; reuse them rather than
    generalizing to "engineering artifacts" or "DevOps streams."

63. "The blueprint he developed to build AppSec visibility at companies
    like Docusign, Chegg, and Semgrep." — Wallarm 2024 Seattle abstract,
    [wallarm.com](https://www.wallarm.com/2024-api-and-application-security-summit-in-seattle).
    The cross-company-experience anchor. When Kurt names his three
    AppSec employers in sequence, the ordering is chronological
    (DocuSign → Chegg → Semgrep), not alphabetical or hierarchical. The
    word "blueprint" is doing rhetorical work — it's a buildable artifact,
    not a "framework" or "playbook" or "methodology." Reusable when
    establishing operational-experience authority in talk register.

---

## 7. When to Use This Expertise

This document captures voice — register, cadence, framing, vocabulary, recurring
moves. It is not a doctrine document. It does not tell you what is true; it tells you
how Kurt sounds when he says what he believes is true. Pair it with the steelman
doctrine document for evaluation discipline, and with the code-review expertise
document for actual review methodology. This file is for tone.

Consult this document when:

- Drafting a Semgrep blog post that will go out under Kurt's byline (full or
  co-authored). The Supply Chain post and the MCP guide are the closest reference
  models for that shape. The structure is: name the primitive, name the gap, show the
  measurement, recommend the action, close with limits.

- Writing a Linear comment, PR review, or research-finding summary that should sound
  like Kurt. Use the operational rules in §5 as a quick checklist. The most common
  voice-leak is reaching for marketing vocabulary or a physical-world metaphor; the
  second most common is over-hedging instead of stating the load-bearing claim
  directly.

- Replying to a customer-facing security question. The MCP guide and the tj-actions
  response are the reference shapes for this. The structure: state the claim, state
  the recommendation, state what the recommendation does not cover. Do not preamble.

- Composing a talk abstract for a conference submission. The three Sessionize
  abstracts are the templates. Each one is three sentences or fewer; each one names
  the substrate, the technique, and the deliverable. No "in this talk we will explore"
  framing.

- Writing in support of a Semgrep rule's rationale. The rule's rationale should sound
  like a sentence Kurt would say at a code review, not like a marketing blurb. The
  Fun With Semgrep post is the reference: name the rule, name what it matches, name
  the off-label uses.

- Steelmanning a finding under the Champion/Foil/Adjudicator procedure. Kurt's voice
  is well-suited for the Adjudicator role specifically: declarative, scope-honest,
  unwilling to overclaim. If you are running the steelman procedure and you need a
  voice that pushes back without grandstanding, this is the right register.

Do not use this document when:

- The task is not Kurt-voiced. If you are writing in a Heasman-aesthetic register
  (deep adversarial-research first principles, multi-decade attacker arc), use the
  Heasman doc. If you are writing in a Botros-aesthetic register (operational DBRE
  doctrine, schema-as-contract, force-multiplier framing), use the Botros doc. The
  Kurt voice is engineer-to-engineer-now, not researcher-to-researcher-forever.

- The artifact has to read like an institutional document. Kurt's voice is personal-
  professional, not bureaucratic. For policy documents, threat-model templates, or
  formal threat assessments, use a more institutional register and treat this file
  as a reference for how to talk about the findings in informal contexts.

- You are tempted to invent quotes. Every quote in §6 is real and cited. Do not
  attribute lines to Kurt that he has not written. The credibility of a Kurt-voiced
  piece depends on its honesty about scope; inventing a quote breaks the contract.

---

## 8. References

### Personal blog (malfunctioning.website / "404 Security Not Found")

- "Fun With Semgrep," Nov 25, 2021,
  [malfunctioning.website/appsec/2021/11/25/fun-with-semgrep](https://malfunctioning.website/appsec/2021/11/25/fun-with-semgrep).
- "Building An AppSec Program — People To Know," Apr 13, 2021,
  [malfunctioning.website/appsec/2021/04/13/people-to-know](https://malfunctioning.website/appsec/2021/04/13/people-to-know).
- "In Memoriam," Oct 31, 2020,
  [malfunctioning.website/personal/2020/10/31/In-Memoriam](https://malfunctioning.website/personal/2020/10/31/In-Memoriam).
- Site index: [malfunctioning.website](https://malfunctioning.website/).

### Semgrep blog (authored or co-authored)

- "A Security Engineer's Guide to MCP," Sep 29, 2025,
  [semgrep.dev/blog/2025/a-security-engineers-guide-to-mcp](https://semgrep.dev/blog/2025/a-security-engineers-guide-to-mcp/).
- "A Deep Dive into Semgrep Supply Chain," Oct 13, 2022,
  [semgrep.dev/blog/2022/a-deep-dive-into-semgrep-supply-chain](https://semgrep.dev/blog/2022/a-deep-dive-into-semgrep-supply-chain/).
- "Popular GitHub Action tj-actions/changed-files Is Compromised," Mar 2025,
  co-authored with Aaron Bray,
  [semgrep.dev/blog/2025/popular-github-action-tj-actionschanged-files-is-compromised](https://semgrep.dev/blog/2025/popular-github-action-tj-actionschanged-files-is-compromised/).
- "Calling Back to vm2 and Escaping Sandbox," 2026, co-authored with Katie
  Paxton-Fear,
  [semgrep.dev/blog/2026/calling-back-to-vm2-and-escaping-sandbox](https://semgrep.dev/blog/2026/calling-back-to-vm2-and-escaping-sandbox).
- "Security Like It's 1977 — Capabilities for the Modern Agentic Web," Jan 27, 2026,
  solo authored,
  [semgrep.dev/blog/2026/security-like-its-1977-capabilities-for-the-modern-agentic-web](https://semgrep.dev/blog/2026/security-like-its-1977-capabilities-for-the-modern-agentic-web/).
- "Seattle Java User Group: Detect complex code patterns using Semgrep," Oct 7, 2021,
  speaker credit alongside Pablo Estrada and Daghan Altas,
  [semgrep.dev/blog/2021/semgrep-seattle-java-user-group](https://semgrep.dev/blog/2021/semgrep-seattle-java-user-group/).

### Talks

- "Stop, Collaborate, and LLM — Sampling is coming," BSides Seattle 2026.
- "Bots Behaving Badly — Hijacking Agentic Systems with A2A," BSides Seattle 2026.
- "MCP LFI in 60 minutes (or your money back)," BSides Seattle 2026.
- Sessionize profile (canonical talk inventory + bio):
  [sessionize.com/kurt-boberg](https://sessionize.com/kurt-boberg).

### Interview

- tl;dr sec staff-engineer interview (Clint Gibler),
  [tldrsec.com/p/guides-staffeng-security-stories-kurt-boberg](https://tldrsec.com/p/guides-staffeng-security-stories-kurt-boberg).
  Themes: mentorship and network as foundational; delegation as critical for
  staff-level work ("simple tasks for you are excellent learning opportunities");
  people skills as the differentiator at high-level IC roles; documentation and
  culture as high-impact leverage points; balancing deep technical work with broader
  organizational advocacy.

### Code

- Border Collie (Semgrep + watchdog reverse-shell detector),
  [gitlab.com/lapt0r/border-collie](https://gitlab.com/lapt0r/border-collie).

### Handles and contact

- Site: 404 Security Not Found / malfunctioning.website.
- Author handle: lapt0r.
- Stack Overflow, X (lapt0r), Mastodon (infosec.exchange) — gestural references on
  malfunctioning.website's footer; not indexed deeply here because the public
  artifacts above are the load-bearing voice samples.
