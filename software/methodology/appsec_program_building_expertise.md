# Building an AppSec Program — People, Visibility, and Leverage
## Synthesized from Kurt Boberg, Rami McCarthy, Clint Gibler, Ryan McGeehan, Rich Smith, Phil Venables, Jeremiah Grossman, Tanya Janca, Caroline Wong, and Justine Bone

> **Researchers:**
> - **Kurt Boberg** (anchor) — Staff Security Researcher at Semgrep, formerly AppSec at
>   Chegg and DocuSign. Author of "Building An AppSec Program — People To Know"
>   (malfunctioning.website, 13 Apr 2021), the canonical short-form statement of his
>   people-first program-building thesis. Interviewee in tl;dr sec's *Staff-Eng Security
>   Stories* series. Speaker on "From Blind Spots to Insights: Building AppSec Visibility"
>   at the Wallarm 2024 API and Application Security Summit in Seattle, presenting the
>   blueprint he built across DocuSign, Chegg, and Semgrep. Credited with CVE-2019-0228
>   (Apache PDFBox XXE) from his DocuSign era. Panelist on BSidesSF 2023's "Level Up Your
>   Career" alongside Rami McCarthy, Lea Snyder, and Hasnain Lakhani. Publishes under the
>   handle `lapt0r`.
> - **Rami McCarthy** — Cloud and AppSec engineer; contributor to tl;dr sec; author at
>   `ramimac.me` ("High Signal Security"). Conducted the *Staff-Eng Security Stories*
>   interview with Kurt. His own writing covers AppSec program scaling, paved roads,
>   secure defaults, "How to Say 'No' Well," and a fwd:cloudsec EU talk distilling
>   program-building, vulnerability and asset management, IAM, detection, and deployment.
>   Co-author of an extension to Scott Piper's *AWS Security Maturity Roadmap*.
>   Co-panelist with Kurt at BSidesSF 2023.
> - **Clint Gibler** — Head of Security Research at r2c (Semgrep); previously Research
>   Director at NCC Group. Ph.D. in Computer Science (UC Davis). Founder and maintainer of
>   the tl;dr sec newsletter, which is the de facto weekly reading list for AppSec
>   practitioners. Author of "Lessons Learned from the DevSecOps Trenches" (AppSec
>   California 2019) and "What I Learned Watching All 44 AppSec Cali 2019 Talks." Speaker
>   at BlackHat USA, AppSec USA/EU/Cali, BSidesSF, DevSecCon Seattle/London/Tel
>   Aviv/Singapore. Kurt's manager at Semgrep.
> - **Ryan McGeehan** (`magoo`) — Former Director of Security Incident Response at
>   Facebook; Director of Security at Coinbase (joined April 2014 to build the program
>   from scratch); founder/advisor at HackerOne. Maintains *Starting Up Security*
>   (`scrty.io`, `magoo.medium.com`) — a curated set of essays aimed at new leadership
>   building new security teams. Recent focus is quantitative risk measurement aimed at
>   making forecasting and estimation practical for engineers.
> - **Rich Smith** — Head of Duo Labs (now part of Cisco); formerly Director of Security
>   at Etsy; co-founder of Icelandic red-team startup Syndis. Co-author of *Agile
>   Application Security: Enabling Security in a Continuous Delivery Pipeline* (O'Reilly,
>   with Laura Bell, Michael Brunton-Spall, and Jim Bird). His Etsy-era talks crystallize
>   three operating principles: **Enabling** (help engineers do what they want to do, but
>   securely); **Transparent** (give people the context for your actions and bring them
>   along); **Blameless** (treat failures as learning opportunities via postmortem).
> - **Phil Venables** — Strategic security advisor at Google Cloud and Google Cloud's
>   first CISO (joined 2020); prior to Google, 25+ years as CISO at Goldman Sachs,
>   Deutsche Bank, Standard Chartered, and Barclays. Director on the boards of HackerOne,
>   Interos, and NIST's Information Security and Privacy Advisory Board. His personal
>   blog (`philvenables.com`) is the most-cited contemporary source on running a security
>   *program* (rather than a security *technology*) and on the economics and governance
>   of the CISO function — "from artisanal to industrial," "shift down not left," "fire
>   stations to flywheels."
> - **Jeremiah Grossman** — Founder of WhiteHat Security (2001); former information
>   security officer at Yahoo! Co-founder of the Web Application Security Consortium
>   (WASC). Currently at Root Evidence; previously Chief of Security Strategy at
>   SentinelOne. One of the earliest commercial advocates for "build an actual
>   application security program" rather than treating AppSec as a one-off audit. Vocal
>   about vendor accountability — keynoted AppSec California on the theme of requiring
>   vendor guarantees.
> - **Tanya Janca** (`SheHacksPurple`) — Founder of We Hack Purple; now Head of Education
>   and Community at Semgrep (We Hack Purple merged with Semgrep in August 2023). OWASP
>   Lifetime Distinguished Member; OWASP Hacker of the Year. Author of *Alice and Bob
>   Learn Application Security* (Wiley, 2020) and *Alice and Bob Learn Secure Coding*.
>   Her arc is the canonical example of building an AppSec training program as a
>   product: accessible curricula, an active community, public office hours, and a
>   measurable certification track.
> - **Caroline Wong** — Chief Strategy Officer at Cobalt; author of *Security Metrics: A
>   Beginner's Guide* (McGraw-Hill, 2012; inducted into the Cybersecurity Canon Hall of
>   Fame in 2022) and *The PtaaS Book*. Host of the *Humans of InfoSec* podcast. Her
>   work is the standing reference for "which numbers actually mean something in an
>   AppSec program, and which are vanity metrics that drive bad behavior."
> - **Justine Bone** — Former CEO of MedSec; former Global CISO at Dow Jones (News Corp).
>   Began her career as a vulnerability researcher at ISS X-Force after training with the
>   NSA. Now Executive Director of the Crypto ISAC and on HP Inc.'s Security Advisory
>   Board. Provides the model for the CISO arc that evolves from internal-only
>   responsibility to a public, industry-shaping role.
>
> Sources: Kurt Boberg, "Building An AppSec Program — People To Know,"
> malfunctioning.website (13 Apr 2021); Rami McCarthy interview, "Staff-Eng Security
> Stories: Kurt Boberg," tl;dr sec; Wallarm Seattle 2024 Summit session page; BSidesSF
> 2023 panel video and schedule; tl;dr sec archives; Rich Smith, *Crafting an Effective
> Security Organization* (InfoQ); Phil Venables blog; Ryan McGeehan, *Starting Up
> Security* on `scrty.io` and Medium; Cobalt blog and Caroline Wong's *Security Metrics*;
> Tanya Janca's `tanyajanca.com` and We Hack Purple / Semgrep Academy course catalog;
> Justine Bone, BlackHat *Fast Chat* and Dark Reading column; NVD, OSS-Security archives,
> and Apache PDFBox JIRA for CVE-2019-0228.

---

## 0. Why this doctrine exists

There are two kinds of AppSec work that get conflated. The first is **finding
vulnerabilities** — variant analysis, code review, fuzzing, red-team exercises, rule
authoring. That work has a deep technical literature anchored on books like *The
Shellcoder's Handbook*, *The Web Application Hacker's Handbook*, *The Tangled Web*, and
the synthesis docs in this same directory ([[reference-vr-methodology]],
[[reference-code-review-expertise]], [[reference-john-heasman]], the per-class deep dives
on deserialization, SSRF, prototype pollution, template injection, and so on). The second
is **building the program inside which that work happens** — the org chart, the
relationships, the visibility plumbing, the metrics, the budget cycle, the hiring plan,
the way you talk about a vulnerability to a director of engineering whose OKRs do not
include "fix security debt this quarter." This doctrine covers the second kind.

The reason it deserves a doctrine at all is that the second kind is the *gating
constraint* on the first. Finding a high-impact vulnerability that no one fixes is not
security work; it is journalism. Reading code beautifully and producing a flawless
write-up that the engineering org ignores is theatre. The leverage point of an AppSec
program is the engineering organization's willingness to act on what the security team
finds. Trust earned at the org level is the substrate; tools, scanners, rule sets, and
findings are deposits made into that substrate. A program that has not built the
substrate is a program that runs scanners no one acts on.

Kurt's "People To Know" post is the load-bearing short-form statement of this thesis. He
opens by stating it plainly: "An AppSec program is a function of the engineering
organization's trust in the security team. Buy the trust before you buy the scanner."
Everything else in this doctrine flows from there.

This document is the program-side counterpart to
[[reference-vr-methodology]] (which is about *finding bugs*). It mirrors the format of
[[reference-john-heasman]] (synthesized doctrine from one anchor figure) and of
[[reference-steelman-doctrine]] (Champion / Foil / Adjudicator procedural discipline).
Where those are about *what you do at your desk*, this one is about *how the desk
exists in the org*.

The constraints on doctrine are tighter than on technique catalogs. A technique catalog
can be wrong about a single technique and remain useful as a reference. A doctrine that
is internally inconsistent or that prescribes a workflow with hidden dependencies fails
silently — the practitioner adopts a frame that does not survive contact with their first
real program-building engagement, and they do not find out until the relationship with
engineering has already broken. So this doctrine is conservative. It draws only from
practitioners with publicly attributable program-building track records. It flags every
prescription with the condition under which it inverts.

---

## 1. Kurt's "People To Know" thesis — stakeholders before tooling

### The post

Kurt published "Building An AppSec Program — People To Know" on
malfunctioning.website on 13 April 2021. It is short — three named roles plus a
deliberately-omitted fourth — and it remains the single most-cited primary source for his
program-building voice. The full URL:
`https://malfunctioning.website/appsec/2021/04/13/people-to-know`.

The post's framing argument is that AppSec engineering is well-served by existing
DevSecOps literature on the engineering side of the org chart — pipelines, scanners,
gates, paved roads — and that the *under-covered* lever is the set of stakeholders
*outside* engineering whose buy-in turns a security recommendation into an actual change
in production behavior. He puts it bluntly: "There are lots of DevSecOps resources out
there tackling the Engineering side of things." The omission is deliberate. The post is
about everyone else.

### The three roles he names

**1. Product Manager.** Kurt's framing: "knowing *what the company is building before
they build it* is an incredibly powerful asset." Product managers hold the roadmap. They
know what is coming in two quarters before engineering writes the first line of code.
An AppSec engineer who has a working relationship with the PMs in each product area is
not surprised by the launch of a feature that introduces an entire new authorization
boundary, a new payment integration, or a new data-residency obligation. They are
consulted during the design phase, when the cost of changing a decision is small. They
write threat models against the spec, not the deployed system.

The inversion: an AppSec engineer who only sees code at PR review is reactive by
construction. The PR is a fait accompli — the engineer has already invested in the
design, the design is the easiest defensible thing to ship, and security feedback is a
cost imposed on a finished product. Get the relationship with the PM, and security
feedback is an input to the design, not a tax on it.

The practical engagement: every product area should have at least one PM whom the AppSec
team has worked with on a non-controversial review. The first engagement should be cheap
and friendly — sit in on a roadmap review, offer to threat-model an upcoming feature, ask
what they wish security would help with. The relationship is the deliverable.

**2. QA Lead.** Kurt calls the QA Lead "Mirror World You." The framing is exact:
security testing and quality testing share more than ninety percent of their machinery.
Both run the application in test environments. Both write regression suites that catch
classes of issue post-fix. Both maintain coverage dashboards. Both have to negotiate with
engineering for time on the CI pipeline. The QA function is the closest organizational
analog to an AppSec function that already exists in most engineering orgs.

The leverage: rather than build a parallel security testing apparatus, *fold security
checks into the existing QA pipeline*. The DAST scan, the dependency check, the secret
scan, the authorization-coverage test — these can run in the QA suite if the QA Lead has
agreed they belong there. The cost to engineering is incremental; the cost to security
to build a parallel pipeline is enormous. The QA Lead has organizational currency that
security frequently does not; co-opting their infrastructure trades on that currency.

The inversion: the QA team and the AppSec team are competing for the same engineering
attention if they do not coordinate. A security scanner that fails a build and a QA
suite that fails the same build look the same to the engineer who has to triage at 5pm
on a Friday. If the two teams have not aligned on signal quality, severity thresholds,
and ownership of false positives, engineering treats both as noise.

**3. Lawyer.** Kurt's quote: lawyers have "the same mandate you do: protect the
company." The framing is that the legal team is the only other internal function whose
job description is functionally identical to security's. They both think about risk in
the form of "what would happen if this went wrong, who would be liable, and what is the
plausible blast radius." The vocabulary differs — legal speaks in terms of contracts,
regulatory exposure, and tort liability; security speaks in terms of CVSS, blast radius,
and attacker capability — but the underlying decision-making structure is the same. Both
functions are advisory to the business and both must persuade rather than command.

The leverage: when the AppSec team has a finding that requires executive intervention,
legal is the natural co-signer. A privacy-relevant data exposure that engineering wants
to defer becomes legally actionable once the GC has signed on. A vendor risk concern
about a third-party dependency lands harder if the contract team has flagged the same
vendor for indemnification weakness. The two functions reinforce each other; in
isolation they are weaker than in combination.

The inversion: legal can be a blocker rather than an ally if the relationship is not
established. Legal's first instinct on hearing "we found a vulnerability" can be to slow
disclosure, prevent public commentary, and limit liability through silence. An AppSec
team that has not previously worked with legal will discover this at the worst possible
moment — during an incident — and learn that the two functions' priorities are not
aligned in the absence of relationship-building.

### What's missing — deliberately

The post does not name engineering leadership. Kurt notes this is intentional:
"Engineering is already the focus of every DevSecOps resource." The omission is the
thesis statement. Tooling-first AppSec programs are essentially programs that build
relationships with engineering and call it a program. The under-covered work is
*everywhere else in the org chart.*

It is worth holding this thesis up against the steelman counter. The strongest version of
the counter is: engineering is, in fact, where the code is; if you do not have
engineering trust you have nothing, regardless of how well you know the PMs. Kurt's
implicit answer is that engineering trust is *necessary but not sufficient*, and the
*marginal* work — the work that moves a program from "we have some Semgrep rules" to "we
catch authorization regressions before they ship" — is the work done with the
non-engineering stakeholders. The relationship with engineering must exist as the
substrate. The post is about the layer on top.

### The org chart as attack surface

There is an implicit framing in the post that becomes explicit in Kurt's later work:
**the org chart is itself an attack surface**, in the sense that the set of people who
must say "yes" for security to ship a control is the gating constraint on what gets
shipped. If the AppSec team has no relationship with the PM who owns the auth boundary,
the auth boundary will be designed without security input. If the AppSec team has no
relationship with the QA Lead, the security regression tests will not exist in the place
where regressions are caught. If the AppSec team has no relationship with legal,
disclosure decisions will be made by the most risk-averse party in the room without
input from the most knowledgeable.

This frame ports directly into the per-stakeholder catalog in Section 4. The question
to ask of any AppSec program is not "what scanners do we run" but "for each stakeholder
whose decision affects security posture, who on the security team is the relationship
owner, what is the cadence of contact, and what is the joint deliverable?"

---

## 2. The Kurt arc as case study — DocuSign → Chegg → Semgrep

### The shape of the arc

The three jobs are not interchangeable AppSec roles. Each is a distinct stage in a
career arc that maps onto a maturity ladder for AppSec program builders. They are worth
walking through in sequence because the doctrine that emerges from Kurt's writing is the
synthesis of the three.

**DocuSign — AppSec engineering and external research.** Kurt's DocuSign tenure spans
the period in which he is credited with CVE-2019-0228, the Apache PDFBox XXE
vulnerability ("Kurt Boberg of DocuSign reported a possible XML External Entity (XXE)
attack" — Apache advisory, openwall oss-security, 12 Apr 2019). The CVE is a blind XXE
in the FDF (Forms Data Format) parser when processing crafted XFDF — a CVSS 9.8 issue
in a widely-deployed Java PDF library. Reporting a high-severity CVE in an open-source
dependency that your employer uses is a particular kind of program-building work: it
turns the AppSec engineer into an upstream contributor, builds reputational currency
with the open-source community, and creates a forcing function for internal patching
because the vulnerability is now publicly tracked.

The doctrinal lesson: at the early stage of an AppSec engineer's career, the leverage
move is technical depth that produces externally-verifiable artifacts. CVEs, blog
posts, conference talks, open-source contributions. These do double duty — they sharpen
the engineer's technical posture and they build the personal brand that makes
program-building easier at the next job.

**Chegg — program building at consumer scale.** Kurt's Chegg work is the source of the
most-quoted line in his tl;dr sec interview: he "strongly advocated for authorization
considerations early in the design process which led to a launch with basically zero
authorization issues in a collection of services notorious for broken access control."
The collection of services in question is the GraphQL migration he describes as
affecting "a ~400 person engineering organization." The deliverable was a "batteries
included authorization scheme for GraphQL" — a programmatic, library-level abstraction
that made it structurally hard for engineers to ship a GraphQL resolver without
authorization checks.

The doctrinal lesson: program-building leverage is *structural*, not enforcement-based.
A program that catches authorization bugs in code review scales linearly with reviewer
attention; a program that prevents them at the framework layer scales with engineering
adoption. The Chegg work is a "paved road" pattern (a phrase that recurs throughout
Rami McCarthy's tl;dr sec writing): build the secure default into the path of least
resistance. Engineers do not need to remember to add authorization if the framework
adds it for them. The job becomes maintaining the framework and reviewing the few
deviations rather than reviewing every change for the absence of a check.

This is also the era in which Kurt tried engineering management and decided against it.
His quote in the tl;dr sec interview: "I briefly tried engineering management. I enjoy
mentoring but I do not find the active, consistent work of managing engaging and
frankly, I was not a very good people manager." The decision to stay on the IC track at
staff is itself a program-building decision — see Section 5.

**Semgrep / r2c — staff research and tooling.** The current era. Kurt is Staff Security
Researcher building the tooling that makes the previous era's leverage move accessible
to others. The "batteries included authorization scheme for GraphQL" at Chegg required
a 400-person engineering organization and a senior IC who could persuade the platform
team to adopt it. Semgrep is the externalization of that move: a tool that lets any
security engineer at any company author the equivalent rule, run it across their
codebase, and get the leverage without needing organizational buy-in for a new
framework.

The Semgrep blog post "A Security Engineer's Guide to MCP" (29 Sep 2025) extends the
posture into agentic systems — see Section 11 on variant analysis. The throughline is
that Kurt's program-building work *productizes* — the rules, the workflows, the
playbooks become artifacts that other AppSec engineers can adopt at zero marginal cost.

### What changed between jobs

Read against itself, the arc reveals three transitions:

1. **DocuSign → Chegg:** From individual-contributor technical depth to programmatic
   leverage. The DocuSign CVE was a one-off. The Chegg GraphQL authorization scheme
   was a system. The transition required learning to write code that other engineers
   would adopt, not code that solved a single problem.
2. **Chegg → Semgrep:** From organization-specific tooling to portable tooling. The
   Chegg framework only worked at Chegg. The Semgrep rules work everywhere there is
   Semgrep. The transition required learning to abstract the specific to the general
   without losing the precision that made the specific useful.
3. **Throughout:** Increasing scope of audience. DocuSign's audience was internal
   engineering plus the Apache PDFBox maintainers. Chegg's audience was 400 internal
   engineers. Semgrep's audience is every AppSec engineer who reads tl;dr sec. The
   leverage scales with audience.

The doctrinal lesson is that the staff-IC AppSec arc is a sequence of audience
expansions. Each transition adds an audience that the previous role did not reach, and
the work output shifts to match — from CVEs and PRs (audience: engineering peers and
upstream maintainers) to internal frameworks (audience: the entire internal engineering
org) to portable tools and rules (audience: the global AppSec community).

---

## 3. Visibility — the precondition to leverage

### Kurt's Wallarm 2024 thesis

The session abstract for "From Blind Spots to Insights: Building AppSec Visibility" at
the Wallarm 2024 API and Application Security Summit in Seattle reads:

> Kurt addresses common pain points in early AppSec programs and discusses
> low-effort, high-ROI methods to boost visibility and effectiveness using
> open-source or existing commercial tools. He explains that AppSec engineers,
> often outnumbered by developers and product teams, receive minimal
> notifications about critical changes and must be creative to automate the
> review of Jira tickets, PRs, and internal wikis.

The title is the thesis: **from blind spots to insights**. You cannot fix what you
cannot see; you cannot prioritize what you cannot count; you cannot defend a budget for
what you cannot quantify. Visibility is the precondition to every other leverage move
the AppSec team makes. A program that begins by buying a SAST tool but cannot answer
"what services do we have, in what languages, talking to what data stores, exposed
to what networks, with what authentication, by what teams" is a program that buys
findings it cannot prioritize.

Kurt's framing in the abstract is sharper than the standard "asset inventory" trope.
The under-covered visibility surface, in his telling, is *the work product of the
engineering organization itself*: Jira tickets, pull requests, internal wikis, design
docs, RFC streams, post-mortems. These are the artifacts that describe what the
organization is *doing*, as distinct from the assets that describe what it *has*. The
security team that has automated review of these artifacts can identify a security-
relevant decision at the moment it is proposed — before the design ships, before the PR
merges, before the on-call gets paged. The team that has not automated this review is
relying on engineering to remember to consult security, which is the failure mode the
"People To Know" post is fundamentally about.

### The maturity progression

A useful framing borrowed from Rami McCarthy's and Scott Piper's maturity-roadmap
writing: visibility maturity progresses in four steps.

**Step 1: You know what you have.** Asset inventory. Service catalog. Dependency graph.
Endpoint catalog. Identity inventory. Repository inventory. Cloud account inventory.
The deliverable is a list, machine-readable, with an owner field for every entry.

**Step 2: You know what changes.** Change-monitoring instrumentation. Every new service,
every new endpoint, every new dependency, every new identity, every new repository
triggers a security-team-visible event. The deliverable is a feed that the security
team monitors, with a noise floor low enough that humans can attend to it.

**Step 3: You know what matters.** Risk prioritization on top of the inventory. Internet-
facing vs internal. Data-classified-as-sensitive vs non-sensitive. Compliance-scoped vs
non-scoped. Production vs staging. The deliverable is a triage rubric that tells you,
given a new event from Step 2, whether the security team should engage now, this week,
or this quarter.

**Step 4: You know what is happening.** Real-time security-relevant signal: detections,
findings, anomaly alerts, customer reports, regulator inquiries, threat intelligence.
The deliverable is the integrated picture — assets + change + risk + signal — that lets
a CISO answer "how is the program doing this quarter" with evidence.

Steps 1 and 2 are the visibility foundation. Steps 3 and 4 are the leverage layer.
Programs that start at Step 3 — buying a SIEM, a detection-engineering platform, a
threat-intel feed — without having completed Steps 1 and 2 produce findings the team
cannot ground in business context, and the findings are ignored. The order matters.

### The "show one dashboard" exercise

A useful gut-check Kurt has used in talks (paraphrased from the Wallarm session
description and the doctrinal posture in his writing): if the CEO asked "what is our
security posture, in one number," what would the number be, and how would you defend
it?

Most AppSec leaders cannot answer. They have many numbers — open vulnerabilities, mean
time to fix, scanner coverage percentage, training completion rate, dependency-update
SLA compliance — and the numbers do not aggregate to a single answer. This is correct;
security posture is not a scalar. But the *inability to construct any meaningful
aggregate* is a red flag. It indicates that the team does not have the underlying
visibility plumbing to roll up its measurements into an executive-facing summary.

The dashboard exercise is a useful forcing function. Try to design the one dashboard.
The data you wish you had but do not is your visibility backlog. The numbers you have
but do not trust are your data-quality backlog. The numbers you trust but cannot
defend to a non-technical audience are your *communication* backlog (see Section 8).

### Concrete visibility surfaces

The standard list. Each surface should have an owner, a refresh cadence, and a
documented authoritative source.

- **Vulnerability inventory.** SAST, SCA, DAST, container scan, IaC scan. Deduplicated.
  Triaged. Owned by team.
- **Dependency graph.** Direct and transitive. Per-service. Per-language. Source of
  truth: lockfiles, manifests, SBOMs.
- **Authorization coverage.** For each route / endpoint / GraphQL field, is there an
  authorization check? What kind? Who owns the check? Cross-link to
  [[reference-distributed-authz]] for the per-pattern detail.
- **Secrets inventory.** What secrets exist, where do they live, who owns rotation,
  when was the last rotation, what is the blast radius if one leaks?
- **Network egress.** Per service, where does outbound traffic go? Which destinations
  are policy-allowed, which are anomalous?
- **IAM trust policies.** Cloud identity trust relationships. Cross-account roles.
  Federated identity providers. SSO config. MFA coverage.
- **Build chain.** Cross-link to [[reference-cicd-supply-chain]]. CI pipelines, runner
  inventory, artifact signing, lockfile cooldowns, GitHub Actions pinning.
- **Engineering work-product feeds.** Per Kurt's Wallarm talk: Jira tickets, PRs,
  internal wikis, design docs. Automated review.

Each surface, on its own, is a project. The program-building decision is the *order* in
which the team builds them. Heuristic: start with the surface where you have the
weakest current intuition. The thing you do not know is the thing you cannot defend.

Cross-link: [[reference-cicd-supply-chain]] for build-chain visibility;
[[reference-distributed-authz]] for authorization coverage; [[reference-vr-methodology]]
§7 for triage discipline applied to the resulting findings.

---

## 4. Stakeholder roles to map

This section is the long-form catalog implied by Kurt's "People To Know" post. The post
names three roles. This section names the full set the AppSec team should map. For each
role: what they own, what they need from security, what they can give security, and a
concrete first engagement.

### Engineering leadership (VP Engineering, Eng Director, Eng Manager)

**They own.** The engineering organization's roadmap, headcount, on-call rotation, code-
review culture, and operational reliability targets. They have direct authority over
whether security findings get fixed.

**They need from security.** Predictable, low-friction security input that does not
slow shipping velocity. Clear severity assessments they can stand behind in
roadmap discussions. Defensible answers to board-level questions about security
posture in the engineering org.

**They can give security.** Engineering time. Headcount. Buy-in for paved-road
investments. Air cover when a security finding requires a hard conversation with a
product owner.

**First engagement.** Offer to take fifteen minutes per month on the eng-leadership
staff meeting to talk through one trend, one decision, and one ask. Show up with the
work done. Do not use the time as a complaint channel.

### Platform / Infrastructure team

**They own.** The shared infrastructure on top of which product engineering ships:
CI/CD, container orchestration, cloud accounts, internal libraries, observability
stack, identity infrastructure.

**They need from security.** Security-validated paved roads they can encourage product
teams to adopt. Threat models for new platform offerings. Reviews of platform
architecture decisions before commitment.

**They can give security.** The single highest-leverage relationship in the entire org.
A platform team that ships a secure-by-default authentication library, a secure-by-
default secret-management interface, a secure-by-default deployment pipeline turns
security from an enforcement function into a structural property of the platform.
Cross-link to Kurt's Chegg "batteries included authorization scheme" — that was a
platform-team partnership at heart.

**First engagement.** Pair with platform on the design of one shared component. Treat
the platform team as a peer, not a customer. They are the lever; you are the fulcrum.

### Product Management

(See Section 1 for the long version. Summary repeated here for catalog completeness.)

**They own.** The product roadmap. Customer-facing feature decisions.

**They need from security.** Early threat modeling. Clarity on customer-facing security
claims they can make in marketing materials.

**They can give security.** Roadmap visibility two quarters out. Air cover when a
security review changes the design of a feature.

**First engagement.** Threat-model an upcoming feature jointly. Make it a one-page
output, not a thirty-page document.

### Legal / Privacy / Compliance

(See Section 1 for the long version. Summary repeated here.)

**They own.** Regulatory exposure, customer contract negotiation, breach disclosure
posture, vendor risk acceptance.

**They need from security.** Technical translation of compliance obligations into
engineering controls. Evidence packages for auditor engagements.

**They can give security.** Executive air cover during incident response. Co-signature
on board-level risk acceptance. Vendor leverage in renegotiation.

**First engagement.** Co-author the security section of the next customer security
questionnaire response. Build the working relationship before the next incident.

### Operations / SRE

**They own.** Production reliability. On-call rotation. Incident response operational
mechanics. Capacity planning. SLO/SLI posture.

**They need from security.** Detections that fire on real attacker activity, not on
benign operations. Runbooks for security-relevant alerts. Joint participation in
incident response.

**They can give security.** Production telemetry. Existing alerting infrastructure.
Existing incident response culture. SREs are usually the closest organizational analog
to security in terms of operational discipline.

**First engagement.** Co-own one detection. SRE owns the alert plumbing; security owns
the rule logic. Build the joint runbook together.

### Human Resources

**They own.** Hiring pipeline. Employee lifecycle. Background checks. Offboarding.
Training compliance. Code of conduct enforcement.

**They need from security.** Joiner / mover / leaver process for identity. Insider
risk indicators. Defensible answers to legally-sensitive personnel security questions.

**They can give security.** The single most underrated lever for offboarding. An HR
function that integrates cleanly with identity provisioning prevents the
"contractor still has prod access six months after their contract ended" failure
mode that shows up in every breach retrospective.

**First engagement.** Map the joiner / mover / leaver process end to end. Identify the
gaps where identity de-provisioning lags behind HR status changes. Fix one gap.

### Finance

**They own.** Budget cycle. Vendor procurement. Capital expense vs operating expense
classification. ROI calculations.

**They need from security.** Defensible justifications for tooling spend. Risk-
adjusted forecasts they can pin in the budget conversation. Vendor consolidation
opportunities.

**They can give security.** Budget. Vendor negotiation leverage. Air cover during the
annual planning cycle. A finance partner who understands the program's leverage
points fights for security budget when the security team is not in the room.

**First engagement.** Walk the finance partner through one specific tooling decision.
What problem, what alternatives, what was decided, what risk was accepted. Make the
finance partner literate enough to defend the line item.

### Sales / Sales Engineering

**They own.** The customer-facing security narrative during the deal cycle. Security
questionnaire response. Customer reference calls. Public commitments made during sales
motions.

**They need from security.** Fast, accurate responses to customer security questions.
Reusable templates for common questionnaires (SIG, CAIQ, custom enterprise variants).
Subject-matter-expert participation in late-stage deals.

**They can give security.** Visibility into what enterprise customers are asking for.
This visibility is the closest thing the security team has to a market signal — the
features that prospects are demanding are the controls the broader industry will be
demanding within 18 months.

**First engagement.** Build a security-questionnaire response library. Take one
customer call as the SME. Use the call to surface the gaps between what the company
claims and what the company can defend.

### Customer Success / Support

**They own.** Customer-facing communications during incidents. Customer-facing
security advisories. Customer escalation paths.

**They need from security.** Pre-written, pre-approved customer communications for
predictable security scenarios. Authoritative answers to customer-reported security
issues. Triage of customer-submitted vulnerability reports.

**They can give security.** Front-line visibility into customer security concerns.
Customer support tickets are an under-mined source of vulnerability reports — many
real findings come in via support before they come in via a bug bounty program.

**First engagement.** Set up a triage path for security-relevant support tickets.
Train the support team to recognize the signal. Close the loop on the first one.

### Marketing

**They own.** External-facing communications. Conference attendance. Blog post
calendar. Public commitments about security posture.

**They need from security.** Technical accuracy on security-relevant marketing copy.
Defensible content for blog posts about the program. Conference attendance and
speaker support.

**They can give security.** A platform. A blog. A conference budget. Marketing is the
program's external megaphone — a security program that publishes is a program that
recruits, retains, and earns industry credibility.

**First engagement.** Co-author one blog post. Make it technical. Make the marketing
partner the editor, not the author. Establish the editorial relationship before the
incident communication.

### Executive leadership (CEO, COO, CFO, board)

**They own.** Risk acceptance at the company level. Final budget authority. External-
facing commitments. Regulatory and legal exposure.

**They need from security.** Briefings in language they can repeat. Defensible
quantification of risk in terms they care about — revenue impact, customer impact,
regulatory exposure, competitive positioning. A single, trusted partner in the
security organization.

**They can give security.** Strategic direction. Budget approval. Air cover during
the hard conversations. The CEO-CISO relationship is the single most consequential
program-building lever; everything else flows downhill from it.

**First engagement.** Build the quarterly briefing rhythm. Show up with three slides,
not thirty. Use the time to flag emerging risks, not to report on operational metrics.

### Security Champions embedded in product teams

**They own.** Inside-the-team advocacy for security. First-pass review of PRs in their
team's repo for security concerns. Translation of security-team requests into the
team's internal language.

**They need from security.** Training, tooling access, and time to do the role. Recognition
from their own management chain. A direct line to the central security team.

**They can give security.** Reach. A central security team of three cannot review every
PR in a 400-person engineering organization. A champions program with one champion per
team can. The scaling factor is the program's most-cited leverage move after paved roads.

**First engagement.** Pilot the program with three teams whose engineering managers are
already supportive. Define the role narrowly. Measure adoption before scaling.

### Pattern: who is your relationship owner

For each role above, the AppSec team should be able to name *the specific person* on
the security side who owns the relationship, *the specific person* on the
counterpart side who is the relationship partner, the cadence of contact, and the
joint deliverables in flight. If any of these are blank, the relationship is implicit,
which means it does not exist when an incident pressure-tests it.

---

## 5. The DocuSign → Chegg → Semgrep career arc as doctrine

### IC track vs management track

Kurt's tl;dr sec interview is unambiguous on the decision: "I briefly tried engineering
management. I enjoy mentoring but I do not find the active, consistent work of
managing engaging and frankly, I was not a very good people manager." The decision to
stay on the staff-IC track is itself a program-building decision with consequences for
the kinds of work the practitioner can do.

The staff-IC AppSec track optimizes for **technical leverage at scale through
authored artifacts**: rules, frameworks, libraries, blog posts, tools, talks. The role
is not free of management overhead — staff ICs run informal mentor cohorts, drive
multi-team initiatives, and influence headcount and budget — but the primary
deliverable is technical work that other engineers consume.

The management track optimizes for **organizational leverage through team
construction**: hiring, performance management, prioritization, executive
communication. The primary deliverable is the team itself; the team's output is the
secondary deliverable.

Both tracks are valid. The choice is not about which is "more senior" — Kurt is staff-
IC at the same nominal seniority as a security engineering manager would be — but
about which form of leverage matches the practitioner's energy and preference.
Mismatched choices burn practitioners out. Someone who likes building tools and finds
performance reviews draining should not become a manager; someone who likes coaching
and finds long heads-down rule-authoring sessions draining should not stay IC.

The doctrinal lesson: **make the choice deliberately, and revisit it every two years**.
The career arc that produces a great staff IC at year five may produce a great
manager at year ten if the practitioner's preferences shift.

### When to switch companies

Kurt's arc shows two company transitions in roughly eight years. The tl;dr sec
interview frames the network-and-mentorship side ("Hands down the most important
contributor to achieving a Staff title was my network and peer/mentor group") but the
companion question — *when* to switch — is doctrinally important.

The framing is **leverage caps**. Every AppSec role has a ceiling determined by the
intersection of (a) the engineering organization's size and complexity, (b) the
maturity of the existing program, and (c) the practitioner's authority within the org.
A role hits its leverage cap when the practitioner can no longer move the program
forward without taking on work that does not match their track preference (an IC
who needs to become a manager to keep growing; a manager who needs to become a VP).

Signs a role is approaching its leverage cap:

- The interesting problems are repeats of problems the practitioner has already solved
  elsewhere.
- The blockers are increasingly organizational rather than technical.
- The practitioner's calendar is dominated by meetings that re-litigate prior decisions.
- The practitioner's external output (blog posts, talks, OSS contributions) has slowed
  because internal work has consumed the discretionary time.

Signs to stay despite hitting a leverage cap:

- The practitioner's primary motivation is the current team and the work being shipped,
  not the personal growth curve.
- The next external role would require relocation, equity loss, or other costs the
  practitioner does not want to absorb.
- The current company is in a phase (acquisition, IPO, major product launch) where
  continuity has organizational value.

Both can be correct. The point is to **make the decision deliberately**, and to
recognize that companies have leverage caps independent of the practitioner's
personal trajectory.

### The first 90 days at a new AppSec role

A useful applied exercise. Use Kurt's framing — people first, visibility second,
tooling third — to construct the 90-day plan.

**Days 1-30: stakeholder mapping.** Identify every role from Section 4. Schedule a
30-minute introductory meeting with at least one counterpart in each. The deliverable
is a working stakeholder map and a sense of which relationships are pre-existing,
which are missing, and which are antagonistic.

**Days 31-60: visibility audit.** Walk through the surfaces in Section 3. For each,
determine the current state: who owns it, what the data quality is, whether it is
trusted by leadership. Identify the two surfaces with the highest gap between
"importance" and "current maturity." Propose remediation for those two.

**Days 61-90: one quick win.** Pick a single, scoped, ship-by-day-90 deliverable
that demonstrates the AppSec function's value to a specific stakeholder. Examples: a
threat model for one upcoming feature, an authorization-coverage report for one
service, a paved-road component for one shared infrastructure team, a tabletop
exercise with one product team. The win is the program's introduction to the org —
make it memorable and credible.

Anti-pattern: the new AppSec hire who spends the first 90 days running scanners and
producing CSV exports of findings nobody acts on. Findings are not a program. The
relationships and the credibility that converts findings to fixes are the program.

### Narrow specialty vs broad program — the staff-IC tradeoff

A staff-IC AppSec practitioner faces a recurring tension: deepen specialization
(become the org's authority on, say, authentication-protocol design or sandbox escape
analysis) versus broaden program ownership (cover a wider set of program functions
less deeply). Kurt's arc favors broad: each successive role broadened the audience and
the program scope.

The countervailing argument: specialized expertise is the form of credibility that
makes broad-program work possible. The Chegg GraphQL authorization framework worked
in part because Kurt could speak with authority about authorization at the protocol
and library level. A practitioner who is broadly literate but not deeply expert in
anything has less leverage with the engineering teams than one who is deeply expert
in one or two domains and broadly literate elsewhere.

The synthesis: **maintain one deep specialty, refresh it every two-to-three years
when the practitioner's primary focus shifts, and use the specialty as the
credibility anchor for the broader program work**. The arc of expertise rotates
through specialties (deserialization → SSRF → MCP → agentic systems), but at any
given time the practitioner is the org's authority on one. The breadth shows up
through the broader program work; the depth shows up through the public artifacts
produced in the current specialty.

---

## 6. Buying decisions — when to make vs buy

### The category map

Modern AppSec has many tooling categories. The ones worth naming, in approximate
order of how often they show up in a program-building conversation:

- **SAST** (Static Application Security Testing) — Semgrep, CodeQL, Checkmarx,
  Fortify, Veracode, SonarQube.
- **SCA** (Software Composition Analysis) — Snyk, Dependabot, Mend, Sonatype,
  GitLab/GitHub native, Semgrep Supply Chain.
- **DAST** (Dynamic Application Security Testing) — Burp Suite Enterprise, Invicti,
  ZAP at scale.
- **IAST** (Interactive Application Security Testing) — Contrast, Seeker.
- **RASP** (Runtime Application Self-Protection) — Imperva, Contrast.
- **ASPM** (Application Security Posture Management) — the aggregator category;
  ArmorCode, Apiiro, OX Security, ZeroPath, plus offerings from existing vendors.
- **AVMS** (Application Vulnerability Management Systems) — Brinqa, Vulcan,
  Kenna/Qualys VMDR.
- **EDR** / **XDR** (endpoint, extended detection and response) — CrowdStrike,
  SentinelOne, Microsoft Defender. AppSec-adjacent.
- **CSPM** / **CIEM** (Cloud Security Posture Management / Cloud Infrastructure
  Entitlement Management) — Wiz, Orca, Lacework, Prisma Cloud.

The temptation in a new AppSec role is to map every category onto a vendor and buy
one of each. The temptation is wrong.

### "Every category has a vendor; not every category has leverage"

The framing: the existence of a category and the existence of a vendor selling into
the category do not imply the existence of a leverage point in the program. Some
categories are mature enough that purchase is the right move (SCA — running dependency
checks by hand does not scale). Some categories are immature enough that purchase
is destructive (an ASPM aggregator without input data quality just aggregates noise).
Some categories overlap with adjacent infrastructure the platform team already
owns (DAST overlaps with QA's regression infrastructure; the QA Lead has more
context than the security team about how to fold it in).

The buying decision for each category should answer four questions:

1. **What is the leverage point?** If we bought this tool, what specific decisions
   would change? Whose work would the tool replace, augment, or improve?
2. **Who owns the data?** Tools generate findings. Findings have owners. If we cannot
   name the team that will triage the tool's output, the tool will become noise.
3. **What is the integration cost?** Tools are expensive to integrate, not to buy.
   The buy-list price is a fraction of the total cost. Engineering time to integrate,
   pipeline impact, false-positive triage, and ongoing tuning costs dominate.
4. **What is the alternative?** Is there a paved-road investment that would solve
   the problem structurally rather than detect it? An authorization library that
   makes the bug class impossible to write is more valuable than a SAST rule that
   catches the bug after it is written. A secrets-management platform that prevents
   committing secrets is more valuable than a secret scanner that finds them post-
   facto.

### When to write your own rules vs buy a scanner with rules baked in

This is the doctrinal core of the make-vs-buy question for SAST in particular, and
it is the Kurt-Semgrep self-coherent argument. The argument runs:

- SAST tooling that ships with a fixed rule set assumes the vendor's threat model
  matches the consumer's. It rarely does.
- The most-valuable SAST findings are program-specific: authorization patterns local
  to the codebase, API-specific misuse, internal library invariants. A scanner that
  ships with a generic rule set cannot find these.
- Therefore: the leverage point in SAST is the ability to *author rules* at the
  speed of the program's evolution, not the size of the vendor's pre-built rule set.
- Semgrep is the productization of that insight: a rule engine that an AppSec
  engineer can use to express the program's local invariants and run them at scale.
- Therefore: an AppSec program with a Semgrep-shaped tool and a practitioner who
  can write rules outperforms a program with a black-box scanner and the same
  practitioner.

The self-coherence is intentional. Kurt's program-building work at Chegg (the
authorization framework) became Semgrep rules at the next job; the rule-authoring
expertise that made the Chegg work valuable is the same expertise that makes the
Semgrep era productive. The Semgrep-blog post on MCP security extends the pattern:
the MCP security cheat-sheet is a Semgrep-shaped artifact — a set of detections an
engineer can run, audit, and modify, not a vendor's opaque verdict.

The argument has a steelman counter worth naming: an early-stage AppSec team without
the bandwidth to author rules benefits from a turn-key scanner with a comprehensive
default rule set. The bandwidth argument is real. The synthesis is to **buy the
turn-key scanner for the program's first year while building the rule-authoring
capability, and migrate to authored rules as the team's capacity grows**. The
end-state is authored; the start-state is bought.

---

## 7. Communicating with engineers

### The engineering empathy thesis

Restated: AppSec ships through engineers, not around them. Every security control
that lands in production was implemented by an engineer who wrote, reviewed, tested,
and deployed the code. An AppSec function that does not have the engineers' trust
ships nothing. An AppSec function that has it ships at the engineering org's
shipping cadence.

The thesis is uncontroversial in statement. The hard work is the operationalization:
what does it look like, day to day, to be the security partner the engineering team
*wants* to work with rather than the one they tolerate?

Rich Smith's Etsy-era framing — Enabling, Transparent, Blameless — is the most
crisp operational doctrine. Apply it at the level of the individual PR comment, the
individual Jira ticket, the individual incident retrospective.

### What "CVSS 9.8" is wrong as an opening

The opening "you need to fix this CVSS 9.8 finding" is wrong for three reasons. First,
CVSS is a vendor-facing scoring rubric, not an organizational risk statement. A CVSS
9.8 in a non-internet-facing component with no sensitive data has lower organizational
risk than a CVSS 6.5 in an internet-facing service that gates customer access. The
engineer correctly knows this, and the security partner who leads with CVSS is
signaling that they have not done the contextualization work.

Second, "you need to fix" is a command. Engineering does not respond well to commands
from outside its chain of command. The framing creates the antagonistic relationship
the rest of the program-building work is trying to avoid.

Third, "you need to fix this" without a clear path to "fixed" is an unresolvable
ticket. Engineers do not enjoy unresolvable tickets. The security partner who opens
with a finding and does not specify the conditions under which the finding is closed
is asking for tickets that linger and erode trust.

The replacement opening: "We saw the following pattern in <service>. Here is why
we're concerned in this context. Here is what 'fixed' would look like, with two
options of varying engineering cost. We're happy to pair on the implementation."
Three components: contextualized concern, defined success condition, explicit offer
to share work.

### What the engineer's day looks like

Concrete exercise: spend a full day shadowing one engineer in each of the three
largest engineering teams. Sit through their stand-up, their PR reviews, their
on-call check-in, their afternoon focused work, their end-of-day handoff. Take notes.

The output is a working model of what fraction of the engineer's day is consumable by
external requests, what kinds of requests they treat as high-priority, what kinds
they treat as background noise, and what the failure modes of their day look like
(too many meetings, fragmented context, on-call fatigue, last-minute scope changes).

The model converts directly into program design. If the engineering org's primary
failure mode is fragmentation, the security team's tickets should be batched and
delivered weekly rather than as a continuous stream of small interruptions. If
on-call rotation is the engineer's most-protected time, the security team should
avoid filing tickets that page on-call engineers unless the issue genuinely
requires pager-level response.

This work is rarely done. Doing it is itself a relationship-building exercise — the
engineer feels seen, the security team learns the day-shape, and the resulting
program design is calibrated to the actual operational reality.

### PR comment tone

A working pattern, adapted from Rich Smith's Etsy doctrine and Kurt's own
PR-comment practice:

- **Lead with the observation, not the verdict.** "I noticed the input is taken from
  query string and passed unsanitized to the database query." Engineer reads the
  observation, sees the bug independently, and arrives at the same conclusion.
- **Name the bug class, not the CVSS.** "This is SQL injection." Names are
  memorable, technical, and accurate. CVSS is forgettable.
- **Provide the fix, with rationale.** "Recommended fix: use the parameterized
  query API at line N. The library handles escaping at the driver level so we
  don't need to think about quoting." Show the answer.
- **Specify the close condition.** "Closing this when the parameterized query
  is in place and the existing test cases pass." The engineer knows when they are
  done.
- **Open the door.** "Happy to pair on this if it's helpful." The offer is rarely
  taken; the existence of the offer changes the relationship.
- **No marketing copy. No superlatives.** No "critical." No "urgent." No fire
  emoji. The severity of the finding is communicated by its existence, not by
  the prose.

### The "no-blocker AppSec" principle

A program should rarely block deployments. The default posture is *advise and
prioritize*, not *block and gatekeep*. The exceptions are rare and worth
enumerating:

- Active exploitation of the deployed artifact.
- A regression that re-introduces a previously-fixed critical bug.
- Compliance-mandated controls that have an external auditor consequence.

Outside the exceptions, blocking is destructive. It builds resentment, it bypasses
the program's actual leverage point (engineering's voluntary adoption of secure
patterns), and it creates the political conditions in which security is treated
as a tax rather than a partner.

When security must block — in the rare cases — the block must come with a clear
unblocking path. "We can't ship this until X is in place, and X is achievable by
end of day with the following steps" is workable. "We can't ship this until we
review it" is not. The unblocking path is the engineering org's social contract
with the security team; honor it.

---

## 8. Communicating with executives

### Risk register language

The executive register is risk-register language. The vocabulary: *likelihood*,
*impact*, *residual risk*, *risk owner*, *risk acceptance*, *mitigation*,
*compensating control*. The unit of communication is the risk-register entry —
a short statement of the risk, its likelihood and impact, its owner, the
mitigations in place, the residual exposure, and any pending decisions.

Every program decision should map to a risk-register entry. The annual budget
ask is the aggregated mitigation cost for the residual-risk picture the
register paints. The hiring plan is the staffing required to deliver the
mitigations. The tooling decisions are the line items in the mitigation budget.

The executive-facing CISO or staff researcher who can walk through the risk
register, point to the entries that have improved over the year, point to the
entries that have not, and connect the improvements to specific program
investments has a defensible budget story. The one who cannot is asking for
budget on vibes.

Phil Venables' blog is the standing reference for this register. His framing
of "shift down, not left" — pushing security responsibility down to the
platform layer rather than left into earlier development phases — is the kind
of executive-friendly framing that translates technical work into governance
language. The CISO talking to a board about "shifting down" is asking for
investment in the platform team. The CISO talking to a board about "shifting
left" is asking for behavior change in engineering. The former is a one-time
investment with structural payoff; the latter is a continuous program. Both
are valid. The framing changes what investment looks like.

### Annual budget cycle

The annual budget cycle is a recurring forcing function. The work to do it
well happens across the year, not in the two weeks before the budget is due.

**Q1: surface emerging needs.** Identify the program gaps that will require new
investment in the coming year. Validate the gaps with the relevant stakeholders.
Document the cost of inaction in risk-register terms.

**Q2: pilot the case studies.** For each major ask in the coming budget,
construct a defensible pilot or proof-point. "We need to invest in <X>" lands
harder when accompanied by "and here is the pilot we ran in Q2 showing the
impact."

**Q3: write the ask.** Translate the pilots and risk-register entries into the
specific budget request. Include the trade-off framing — "with this investment
we expect to move <metric>; without it we expect <residual risk> to remain
unchanged or worsen."

**Q4: defend the ask.** Walk it through executive review. Adjust on the basis
of feedback. Lock the final budget.

Programs that surface a brand-new ask in Q4 fail. Programs that have spent the
year building the case land their asks.

### The "I want to hire one more person" pitch

A specific case worth treating. The hiring ask is the most common AppSec
budget request and the most often poorly-framed.

The wrong framing: "we are understaffed and need more headcount."
"Understaffed" is undefined relative to what; the executive does not know
how to evaluate the claim.

The right framing: a three-part structure.

1. **What is the work this person would do.** Specific deliverables, in
   priority order. "This person owns the platform-team paved-road
   partnership and is responsible for the authorization, secrets, and CI
   integration roadmap."
2. **What is the cost of not doing the work.** Risk-register entries that
   remain unmitigated. Specific platform investments that lag. Specific
   customer or regulatory exposure that persists.
3. **Why is now the right time.** The forcing function — a customer commitment,
   a compliance deadline, an executive risk decision — that makes this the
   year rather than next.

Hire approvals come from executives who can defend the decision to *their*
audiences (the board, the CEO, the CFO). Give them the three-part story they
need to defend it.

### The incident-response narrative

Every program has incidents. The defining moment of a program's executive
relationship is the post-incident conversation.

The wrong posture: defend the program. "We did everything we reasonably
could." Defensive postures preserve the existing program but do not improve
it.

The right posture: **own what the program missed**. "Here is what happened.
Here is what we did. Here is what we should have detected earlier, and the
specific program investment that would have detected it. We are proposing
the following changes." The defensive frame protects the past program; the
ownership frame proposes the future one. Executives respect the latter.

The pattern is consistent with Rich Smith's "Blameless" principle, scaled
to the executive level: the postmortem is about the system, not the
individuals, and the system improvement is the deliverable.

Cross-link: [[reference-steelman-doctrine]] §1 (Variant D — operational
go/no-go) for the procedural shape of incident-response decisions made
under time pressure; the Champion / Foil / Adjudicator structure ports
directly onto incident-response decision discipline.

---

## 9. Measuring an AppSec program

### The metrics vs vanity numbers distinction

Caroline Wong's *Security Metrics: A Beginner's Guide* (McGraw-Hill, 2012;
Cybersecurity Canon Hall of Fame, 2022) is the standing reference. Her
operative distinction: **a metric is a number that supports a decision; a
vanity number is one that looks impressive but does not change behavior**.

A program drowning in vanity numbers has dashboards that grow but no
decisions that improve. A program with a sparse set of decision-supporting
metrics has fewer numbers but tighter coupling between measurement and
action.

The test: for each number on the program's dashboard, ask "what decision
does this number support, and what value of this number would change that
decision?" If the answer is unclear, the number is a vanity metric.

### What to measure

Defensible candidates, each with the decision it supports:

- **Vulnerability inventory size + trend.** Supports the decision: "are we
  fixing faster than we are finding?" Watch the trend, not the absolute
  number; the absolute is sensitive to detection coverage.
- **Time-to-fix by severity.** Supports the decision: "is our triage
  rubric matching engineering's actual prioritization?" Severity classes
  that consistently take longer than the SLA need either re-classification
  or a new partnership conversation.
- **Security-champion engagement.** Supports the decision: "is the
  champions program healthy?" Active champions per team, attendance at
  champion office hours, champion-initiated reviews.
- **Tooling adoption.** Supports the decision: "are our paved roads
  being used?" The percentage of services using the secure-by-default
  authentication library, the percentage of CI pipelines on the hardened
  template, the percentage of repos with the security pre-commit hook.
- **Incident counts + MTTR (mean time to recover).** Supports the
  decision: "is our operational posture improving?" Watch both — counts
  decreasing while MTTR rises is a different signal than counts
  increasing while MTTR drops.
- **Customer security-questionnaire response time.** Supports the
  decision: "is our sales-security partnership functioning?" Slow
  responses cost deals; the metric is a direct revenue lever.

Each metric should have an owner, a refresh cadence, and a documented
calculation methodology. The methodology matters more than the number — a
metric whose definition shifts quarter over quarter cannot show a trend.

### What NOT to measure

Caroline Wong's standing list of antipatterns:

- **Tickets closed without a quality bar.** "We closed 1,200 tickets" is
  meaningless if half of them were closed as "won't fix" with no
  follow-up.
- **Training hours without retention.** "Our engineers completed 2,000
  hours of security training" tells you nothing if you cannot show the
  training changed behavior. Test the retention. Show the post-training
  reduction in the bug class the training targeted.
- **Scanner findings without false-positive rate.** "Our SAST scanner
  found 8,000 issues" is a number that looks impressive and changes
  nothing. The decision-supporting number is "of the findings flagged
  this quarter, what percentage were real, and what percentage of the
  real ones were fixed?"

### Goodhart's law

The standing caveat. Goodhart's law: "when a measure becomes a target, it
ceases to be a good measure." The corollary for AppSec: any metric you
publish becomes a target the program optimizes against, and the
optimization may or may not align with the actual goal.

Operational examples:
- Publishing "open vulnerabilities" as a target metric optimizes for
  closing tickets — sometimes by re-classifying findings into a different
  tracking system, sometimes by accepting risk that should have been
  fixed.
- Publishing "training completion rate" as a target metric optimizes for
  completion, not for learning.
- Publishing "mean time to fix" as a target metric optimizes for the
  mean — which can be improved by closing easy issues fast while leaving
  hard issues to age.

The defense is to **publish ratios and trends rather than absolute
numbers**, and to publish two opposing metrics simultaneously so that
gaming one degrades the other. "Time-to-fix" alone is gameable; "time-to-
fix paired with finding quality" is harder to game because closing low-
quality findings fast lowers both numbers in opposite directions.

Cross-link: [[reference-vr-methodology]] §7 (triage and prioritization)
for the analogous discussion in the vulnerability-research register.

---

## 10. Common program failure modes

A catalog of how AppSec programs go wrong. For each: how to detect it, how
to recover. The list is canonical — every program has touched some of these
at some point, and the consistency of the failure modes is what makes them
useful as diagnostic categories.

### Tool-driven program

**Symptom.** The program is identified by the tools it owns. "We have
Snyk, Semgrep, Wiz, and CrowdStrike" is the elevator pitch. The findings
those tools generate are not consistently triaged; no one on the team can
state with confidence what fraction of the findings are real and what
fraction are noise.

**How to detect.** Ask the team to walk through one randomly-chosen
week's findings end to end. If they cannot tell you, for any given
finding, whether it was real, whether it was fixed, and who owned the
fix, the program is tool-driven.

**How to recover.** Stop adding tools. Pick one. Build the end-to-end
triage and fix process around it. Demonstrate that the process produces
fixed bugs. Add the next tool only when the existing one is operating at
high signal.

### Compliance-driven program

**Symptom.** The program's deliverables are auditor-facing artifacts — a
SOC 2 report, an ISO 27001 certification, a PCI DSS attestation — and
the work is structured around the audit calendar. Security improvements
that do not show up on a control matrix are deprioritized.

**How to detect.** Ask the team what the program would do differently if
the audits did not exist. If the answer is "very little," the program is
compliance-driven.

**How to recover.** Treat compliance as a downstream artifact of a real
security program, not as the program itself. Build the security
posture that the compliance frameworks describe; the artifacts then
follow naturally. The reframe is identical to the engineering teams'
relationship with code quality: write good code, the linter passes;
write code to satisfy the linter, the code quality stagnates.

### Hero-driven program

**Symptom.** One senior practitioner carries the program. Their personal
relationships, their domain expertise, their on-call response are the
program's connective tissue. The bus factor is one.

**How to detect.** Ask what happens if the hero takes a six-week
sabbatical. If the answer involves emergency hires or program freeze,
the program is hero-driven.

**How to recover.** Document the relationships explicitly (Section 4).
Document the runbooks. Build the second person's authority deliberately
— let them own meetings the hero would normally own, let them be the
first responder to incidents the hero would normally take. The
transition is slow because the hero has to *cede* visibility, which
runs counter to the social rewards they have been receiving. Provide
new social rewards (mentorship recognition, external speaking
opportunities) for the cession.

### Isolation

**Symptom.** The security team has no engineering trust. Their PRs are
ignored. Their tickets sit. Their meetings are skipped. Their findings
are batched into a "security debt" backlog that no one prioritizes.

**How to detect.** Ask the engineering managers to rate their working
relationship with the security team on a 1-10 scale. The numbers will
not lie; if the average is below 6, the team is isolated.

**How to recover.** Start with the relationship rebuild before any new
technical work. Identify the most-supportive engineering manager.
Build the working relationship there first. Use the success of that
relationship as the proof point for the others. The technical work
follows the trust, not the other way around.

### Over-extension

**Symptom.** The program tries to cover everything — SAST, SCA, DAST,
detection engineering, IR, GRC, security awareness, customer-facing
security — and covers nothing well. The team is constantly behind on
every commitment.

**How to detect.** Ask the team what they would *stop* doing if they
could. If the list is long and the items are non-trivial, the program
is over-extended.

**How to recover.** Pick three priorities for the year. Defend them
to leadership. Explicitly de-scope the rest, with documented risk
acceptance. The reduction in scope is the precondition for execution
quality.

### The "10x security engineer trap"

**Symptom.** One senior practitioner ships disproportionately more
than the rest of the team. The org rewards them, the practitioner
takes on more, the rest of the team disengages because their work is
invisible relative to the hero's. The bus factor is again one — and
the rest of the team's career growth stalls.

**How to detect.** Compare individual output to team output over a
quarter. If the hero's contribution accounts for more than half of
the team's measurable output, the trap is in effect.

**How to recover.** Distinct from the hero-driven program recovery
because the cause is different. Here the hero is high-performing and
the team is *under-performing relative to capacity*. The intervention
is to scope the hero's role to high-leverage work only and explicitly
hand off the medium-leverage work to the rest of the team, with the
recognition system rewarding completion at all levels rather than only
exceptional output.

### Detection patterns common to all failure modes

A useful meta-pattern: the failure modes share a small set of root
causes. Insufficient stakeholder mapping (Section 4) produces isolation
and tool-driven programs. Insufficient prioritization (Section 9)
produces over-extension. Insufficient succession planning produces
hero-driven and 10x-trap dynamics. Insufficient framing of executive
communication (Section 8) produces compliance-driven programs.

The remediation always starts at the relational layer, not at the
technical one. A program that buys a new scanner to fix an isolation
problem has bought a scanner; the isolation persists.

---

## 11. Variant analysis — under-explored corners

### AppSec for AI / agentic systems

The current frontier. Kurt's MCP guide (Semgrep blog, 29 Sep 2025) is the
canonical short-form Semgrep-flavored treatment. The thesis: agentic systems
add new attack surfaces that the standard AppSec rubric does not anticipate.
Tool poisoning, line jumping, tool shadowing, rug-pull semantics, prompt
injection at scale.

The program implications are real. The AppSec function in a company that
deploys agentic systems internally or ships them to customers needs to:

- Inventory MCP-shaped tools and their permission grants.
- Threat-model agentic decision boundaries (which tool calls are
  reversible, which are not).
- Detect prompt injection in incoming content streams.
- Audit agent-mediated authorization (the agent acting on behalf of a
  user must not exceed the user's permission grants).
- Plan for incident response in scenarios where the attacker has prompt-
  injection capability on customer-facing surfaces.

The doctrine is mature enough to extend. The threat model has the same
shape as classical AppSec — input is untrusted, output must be
contextualized, authorization must be checked — but the medium is
natural-language input flowing through an LLM rather than HTTP requests
flowing through a parser. The program-building moves carry over: paved
roads (a hardened agent framework with secure-by-default tool grants),
visibility (logging tool calls with the natural-language input that
preceded them), stakeholder mapping (product, legal, and platform all
have stakes in agentic decisions).

Cross-link: [[reference-agentic-web-capabilities]] for the capability
model of agentic web actions; [[reference-llm-agent-security]] for the
per-class detail on prompt injection, tool poisoning, output handling,
and authorization-at-the-tool-call boundary.

### AppSec at acquisition

A company that is acquired or that acquires another faces a discrete
AppSec workload that the steady-state program is not staffed for. The
acquirer must (a) due-diligence the target's security posture, (b)
integrate the target's identity and access systems, (c) inherit the
target's compliance commitments, and (d) absorb the target's
vulnerability backlog. The target faces the reverse problem from the
opposite side.

The program-building move is to have a documented M&A playbook *before*
the deal closes. The playbook is short — a checklist of the artifacts
the acquirer needs from the target, the integration milestones for
identity and access, the timeline for harmonizing vulnerability-
management policies, and the communication plan for the merged
organization. The playbook is rarely needed; when it is needed, it
saves months.

### AppSec at remote-first companies

The post-COVID norm. The program implications are subtle but real:

- The stakeholder relationships (Section 4) must be cultivated through
  written channels and short video meetings rather than hallway
  conversations. The relationship-building cadence is slower.
- The visibility surfaces (Section 3) must include the remote-work
  infrastructure: VPN, BYOD posture, home-office network exposure,
  cloud-IDE security posture, asynchronous-collaboration tools (Slack,
  Notion, Linear, Loom) and the data they hold.
- The training programs (Tanya Janca's domain) must be asynchronous-
  first. Live training does not scale to a globally-distributed
  workforce on consistent quality.

The program doctrine is not different in kind from in-person AppSec.
The execution is more deliberate because the implicit information flow
of an in-person office does not exist.

### AppSec for fully-managed-service products

If the product *is* a managed service — Semgrep is one example; so are
Auth0, Cloudflare, Stripe, Datadog, Snowflake — then *your customers'
security is your product*. The standard AppSec function is supplemented
by:

- A customer-facing security posture (audit reports, penetration test
  summaries, threat model documents) that is consumable by the
  customers' security teams.
- A vulnerability-disclosure program scaled for customer reports.
- Customer-facing incident communications.
- A product security review process that treats security-relevant
  product decisions with the same rigor as feature decisions.

The internal AppSec function in this context is much closer to a
product function than to a back-office function. The deliverables are
shipped to customers, not just internally.

### AppSec for open-source maintenance

If the company maintains an open-source codebase (Semgrep's own corpus
is the relevant example), the AppSec function must handle:

- Coordinated vulnerability disclosure from external researchers.
- A public security advisory cadence.
- Supply-chain security for the project's own dependencies.
- Code-signing and reproducible-build infrastructure.
- Community-facing communication about security decisions.

The program doctrine pulls in elements from upstream-maintainer culture —
the Apache Software Foundation's security committee, GitHub's security
advisory infrastructure, OpenSSF's working groups — that are not
typically part of a closed-source AppSec function. The synthesis is to
treat the OSS-maintenance security function as a peer to the internal
AppSec function, with explicit handoffs between the two.

Cross-link: [[reference-cicd-supply-chain]] for the build-chain
specifics that apply to both closed-source and OSS workloads.

---

## 12. References

### Primary sources — Kurt Boberg

- **"Building An AppSec Program — People To Know,"** Kurt Boberg,
  malfunctioning.website, 13 Apr 2021.
  https://malfunctioning.website/appsec/2021/04/13/people-to-know
- **"Staff-Eng Security Stories: Kurt Boberg,"** Rami McCarthy
  (interviewer), tl;dr sec.
  https://tldrsec.com/p/guides-staffeng-security-stories-kurt-boberg
- **"From Blind Spots to Insights: Building AppSec Visibility,"**
  Kurt Boberg, Wallarm 2024 API and Application Security Summit in
  Seattle.
  https://www.wallarm.com/2024-api-and-application-security-summit-in-seattle
- **"A Security Engineer's Guide to MCP,"** Kurt Boberg, Semgrep blog,
  29 Sep 2025.
  https://semgrep.dev/blog/2025/a-security-engineers-guide-to-mcp/
- **CVE-2019-0228** — Apache PDFBox XXE in FDF parser. Reported by Kurt
  Boberg of DocuSign.
  https://nvd.nist.gov/vuln/detail/CVE-2019-0228 ;
  https://issues.apache.org/jira/browse/PDFBOX-4505 ;
  https://www.openwall.com/lists/oss-security/2019/04/12/1
- **BSidesSF 2023 — "Level Up Your Career: A Panel on Staff+ Engineering"**
  with Rami McCarthy, Lea Snyder, Hasnain Lakhani, and Kurt Boberg.
  https://www.youtube.com/watch?v=OJyFP14tgjk ;
  https://bsidessf2023.sched.com/type/Panel

### Primary sources — Rami McCarthy

- **High Signal Security** — Rami's personal blog.
  https://ramimac.me/
- **tl;dr sec** — newsletter and archive; Rami contributes regularly
  and conducted the Kurt Boberg interview.
  https://tldrsec.com/
- **"How to Say 'No' Well"** and related AppSec-program writing on
  tl;dr sec and ramimac.me.

### Primary sources — Clint Gibler

- **tl;dr sec newsletter archive.** Founder/maintainer; the de facto
  weekly AppSec reading list.
  https://tldrsec.com/
- **"Lessons Learned from the DevSecOps Trenches,"** AppSec California
  2019 transcript.
  https://tldrsec.com/p/blog-transcript-appsec-cali-2019-lessons-learned-from-the-devsecops-trenches
- **"What I Learned Watching All 44 AppSec Cali 2019 Talks,"** Clint
  Gibler.
  https://tldrsec.com/p/appsec-cali-2019

### Primary sources — Ryan McGeehan (`magoo`)

- **Starting Up Security** — `scrty.io` (collection) and
  `magoo.medium.com` (blog).
  https://scrty.io/ ; https://magoo.medium.com
- **"Starting Up Security: From Scratch."**
  https://magoo.medium.com/starting-up-security-from-scratch-6f9a41199a65
- **"Lessons learned in risk measurement."**
  https://magoo.medium.com/lessons-learned-in-risk-measurement-c33b4de0f72e
- **"Quantifying your unknown risks."**
  https://magoo.medium.com/quantifying-your-unknown-risks-4ff51df65e0a

### Primary sources — Rich Smith

- **Agile Application Security: Enabling Security in a Continuous
  Delivery Pipeline,** Laura Bell, Michael Brunton-Spall, Rich Smith,
  and Jim Bird (O'Reilly, 2017).
- **"Crafting an Effective Security Organization,"** Rich Smith
  (InfoQ presentation, Etsy-era).
  https://www.infoq.com/presentations/security-etsy/
- **"Rich Smith on redefining success for security teams and managing
  security culture,"** O'Reilly.
  https://www.oreilly.com/content/rich-smith-on-redefining-success-for-security-teams-and-managing-security-culture/

### Primary sources — Phil Venables

- **Personal blog.**
  https://www.philvenables.com/ ; https://blog.google/authors/phil-venables/
- **"Shift Down Not Left,"** Phil Venables, summarized in tl;dr sec
  RSAC 2025 coverage.
  https://tldrsec.com/p/phil-venables-rsac-2025
- **Google Cloud CISO Perspectives** column.
  https://cloud.google.com/blog/products/identity-security/cloud-ciso-perspectives-phil-venables-on-ciso-2-0-and-the-ciso-factory
- **Wikipedia entry** for biographical and career-arc reference.
  https://en.wikipedia.org/wiki/Phil_Venables_(computer_scientist)

### Primary sources — Jeremiah Grossman

- **Blog.** https://blog.jeremiahgrossman.com/
- **Personal site.** https://www.jeremiahgrossman.com/
- **AppSec California keynotes** — vendor accountability and program
  advocacy.
- **WhiteHat Security history** (1999-2018).

### Primary sources — Tanya Janca (SheHacksPurple)

- **`tanyajanca.com`** — personal site, blog, book listings.
  https://tanyajanca.com/
- **SheHacksPurple training and YouTube channel.**
  https://shehackspurple.ca/ ; https://www.youtube.com/shehackspurple
- ***Alice and Bob Learn Application Security*** (Wiley, 2020).
- ***Alice and Bob Learn Secure Coding*** (Wiley, more recent).
- **We Hack Purple → Semgrep merger announcement** (Aug 2023).

### Primary sources — Caroline Wong

- ***Security Metrics: A Beginner's Guide*** (McGraw-Hill, 2012;
  Cybersecurity Canon Hall of Fame, 2022).
- ***The PtaaS Book.***
- **Cobalt blog: Rethinking Application Security.**
  https://www.cobalt.io/blog/author/caroline-wong
- **"Effective AppSec Metrics,"** Caroline Wong (OWASP SF, Apr 2017).
  https://www.youtube.com/watch?v=dY8IuQ8rUd4
- **Humans of InfoSec podcast.**

### Primary sources — Justine Bone

- **BlackHat "Fast Chat" with Justine Bone, June 2020.**
  https://www.blackhat.com/latestintel/06242020-fast-chat-justine-bone.html
- **Dark Reading author page.**
  https://www.darkreading.com/author/justine-bone
- **MedSec / Crypto ISAC public materials.**

### Secondary sources and adjacent literature

- **Scott Piper, *AWS Security Maturity Roadmap.*** The standing
  reference for cloud-security program maturity; the framing
  ports cleanly into the AppSec-program context.
- **NCC Group, Bishop Fox, Rhino Security Labs program-building
  blog series.** Public-facing program-building literature from the
  major AppSec consultancies.
- **OWASP SAMM (Software Assurance Maturity Model).**
  https://owaspsamm.org/ — the canonical formal model.
- **BSIMM (Building Security In Maturity Model).**
  https://www.bsimm.com/ — Synopsys's empirical benchmark of
  observed practices across hundreds of programs.
- **Google's *Building Secure and Reliable Systems*** (O'Reilly,
  2020). The Google-internal program-building doctrine, made
  external.
- **OpenSSF working groups.** Open-source program-building
  doctrine, especially for the supply-chain-adjacent work.
- **Adam Shostack, *Threat Modeling: Designing for Security***
  (Wiley, 2014). The standing reference on threat modeling, which
  is the program-building activity that most directly connects
  PM-stakeholder work to engineering deliverables.

### Cross-references within this expertise corpus

- **[[reference-john-heasman]]** —
  `software/principles-voice/john_heasman_appsec_principles.md` —
  the adversarial-AppSec counterpart doctrine; covers the technical-
  depth side of staff-IC AppSec work.
- **[[reference-steelman-doctrine]]** —
  `software/methodology/steelman_doctrine_expertise.md` — the
  Champion / Foil / Adjudicator procedural discipline; ports onto
  executive-communication and budget-defense work.
- **[[reference-vr-methodology]]** —
  `software/methodology/vulnerability_research_methodology_expertise.md`
  — the methodology counterpart for the vulnerability-finding work
  that an AppSec program enables.
- **[[reference-code-review-expertise]]** —
  `software/methodology/code_review_expertise.md` — the
  technical-depth counterpart for PR-review work; the prose-tone
  guidance in Section 7 ports onto code-review tone.
- **[[reference-agentic-web-capabilities]]** —
  `software/ai-ml-security/agentic_web_capabilities_expertise.md`
  — the capability model for agentic-system AppSec (Section 11).
- **[[reference-llm-agent-security]]** —
  `software/ai-ml-security/llm_agent_security_expertise.md` — the
  per-class detail for LLM-agent threats; pairs with the MCP-era
  program doctrine.
- **[[reference-cicd-supply-chain]]** —
  `software/supply-chain/cicd_supply_chain_expertise.md` — the
  build-chain visibility surface (Section 3) and the OSS-maintenance
  variant (Section 11).
- **[[reference-distributed-authz]]** —
  `software/appsec-web/distributed_authz_expertise.md` — the
  authorization-coverage visibility surface (Section 3) and the
  Chegg "batteries included authorization scheme" case study
  (Section 2).

---

## Closing posture

This doctrine is not original to Kurt. Every section draws from a literature that
predates him — Phil Venables on governance, Rich Smith on engineering culture, Ryan
McGeehan on starting up security, Caroline Wong on metrics, Tanya Janca on training,
Jeremiah Grossman on the entire commercial AppSec category. What Kurt's "People To
Know" post and his tl;dr sec interview and his Wallarm visibility talk add is the
synthesis at the staff-IC level: the framing of program-building as a sequence of
relationship investments and visibility plumbing, layered under the technical work,
with the audience expansion as the load-bearing career arc.

The synthesis is useful because the staff-IC AppSec role is under-documented. Most
program-building writing comes from CISOs and managers — practitioners whose work is
constructed at the team and budget level. Kurt's contribution is the *staff-IC*
view: how a technical individual contributor, who has chosen not to manage, builds
program-level leverage through the artifacts they author and the relationships they
maintain. The doctrine in this doc is that view, broadened to incorporate the
literature.

A practitioner using this doctrine should not treat it as a script. The order of
operations differs at each company, the stakeholders that matter most differ, the
metrics that move differ. Use the doctrine as the *frame* — the question is
always "for this org, in this phase, what is the leverage point?" — and let the
specifics emerge from the practitioner's reading of the org. Kurt's post is one
hundred sentences long. The frame is the deliverable. The execution is local.

The final discipline: when the program-building work succeeds, the security
function disappears into the engineering organization's structural posture. The
authorization framework is just how authorization works. The paved road is just
how services are built. The visibility plumbing is just how the program knows what
is happening. The leverage move that started as a security investment becomes,
over time, an engineering invariant. That is the goal. A program is mature when
its mature deliverables are no longer attributed to the security team.
