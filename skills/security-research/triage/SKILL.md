# Findings Triage

Apply this skill after running domain audit skills. Downgrade or close findings
that fail any of the following checks. Stop at the first failure — do not
continue to subsequent checks once a disposition is determined.

---

## Pre-Scan: Corpus Exclusion

Run this gate once per repository before any scanning. Exclude the repository
entirely (generate no findings) if any signal below is present.

**Deliberately vulnerable applications — exclude when any one holds:**
- README or top-level doc contains (case-insensitive): "intentionally
  vulnerable", "deliberately insecure", "vulnerable by design", "do not deploy
  to production", "for educational/training/learning/practice purposes only",
  or "this application is insecure"
- Repository name/description identifies it as DVWA, WebGoat, OWASP Juice
  Shop, Mutillidae, VulnHub, Metasploitable, HacMe, WrongSecrets, BadStore,
  or any name containing "vulnerable", "vuln-lab", "hackme", "pwnable", or
  "intentionally-insecure" as a descriptor of the app itself
- CTF markers: `challenge/`, `challenges/`, `ctf/`, `levels/`, or `flags/`
  directory at root; presence of `flag.txt` or `flag{...}` token; `.ctfrc`,
  `ctf.yaml`, or HackTheBox/TryHackMe/PicoCTF deployment metadata
- Pervasive in-code annotations `# VULNERABLE:`, `// VULNERABLE:`, or
  `// NOTE: intentionally insecure` across multiple source files

Do not exclude on topic tags alone (`security`, `pentest`, `ctf`). Security
tools and defensive libraries that discuss vulnerabilities are not excluded.

**Content-free / marketing repositories — exclude when all three hold:**
1. Zero files with programming-language extensions (`.py`, `.js`, `.ts`,
   `.go`, `.java`, `.rb`, `.php`, `.cs`, `.rs`, `.c`, `.cpp`, `.swift`,
   `.kt`, `.scala`, `.sh`, etc.). Config files count only when they implement
   auditable logic (CI/CD pipelines, IaC, policy rules) — not bare metadata.
2. More than 90% of files (excluding `.git/` and hidden dotfiles) are
   Markdown, plain text, images, PDFs, or standard boilerplate.
3. README describes a hosted SaaS/API with no link to the implementation.

When conditions 1 and 2 hold but 3 does not, flag for human review rather
than silently excluding.

---

## Severity Reference

Severity reflects worst-case realistic impact given stated attacker
preconditions. It is not a measure of likelihood or remediation effort.

| Level | Impact ceiling | Precondition ceiling |
|---|---|---|
| CRITICAL | Total/near-total compromise: unauthenticated RCE, arbitrary auth bypass for any user, full primary data store exfiltration, persistent supply-chain backdoor | Unauthenticated, or authentication freely and anonymously obtainable |
| HIGH | Significant capability gain: privilege escalation, cross-user data access, exploitable stored injection, session hijacking of other users, service-wide DoS at negligible cost | Authenticated low-privilege, or network-adjacent without prior host compromise |
| MEDIUM | Bounded impact: non-actionable info disclosure, self-scope access control bypass, session-scoped DoS, rarely-triggering stored injection, defense-in-depth gap with demonstrated primary vuln | Authenticated with meaningful access controls, specific network position, or prior low-severity compromise |
| LOW | Hardening gap or self-affecting condition: missing defensive control with no demonstrated primary vuln, self-XSS, self-IDOR, non-actionable info disclosure, findings whose prerequisite already implies more severe compromise (discard entirely, do not retain at LOW) | Any |

**Tie-breakers (adjacent levels):** prefer lower level when preconditions are
complex or unlikely; prefer lower level when impact is confined to the
attacker's own context; prefer higher level when impact is persistent
(credential theft, data exfiltration, backdoor).

---

## Actionability Checks (apply in order, stop at first failure)

### Step 0: Plain-Language Restatement

Before applying any check, restate the finding in plain language by answering
all four questions below. If any question cannot be answered concretely, the
finding is a false positive by definition — close it and document which question
failed.

- **(a) Attacker identity and access:** Who is the attacker, and what access do
  they hold at the moment of the attack? (e.g., "an unauthenticated external user",
  "an authenticated user with the `viewer` role", "a maintainer of a forked repo")
- **(b) Specific action:** What exact action does the attacker perform? Name the
  HTTP method, endpoint, parameter, payload, or sequence of steps.
- **(c) Trigger:** What causes the vulnerability to execute? Name the URL,
  parameter, event, or condition that detonates the finding.
- **(d) Capability gained:** What specific capability does the attacker gain that
  they did not have before? (e.g., "read any user's password hash", "execute
  arbitrary shell commands as the web process user", "forge a valid session token
  for another user")

Proceed to Check 1 only after all four are answered.

### Check 1: Implication

State the attacker's preconditions and the action the finding enables. Downgrade
to MEDIUM or LOW if the action is already implied by the preconditions without
needing this finding.

- If local shell access is the precondition, reading config files is already
  implied — not HIGH.
- If an authenticated admin already has unrestricted SQL access via a built-in
  query console, SQL injection in an adjacent form adds no marginal capability.

### Check 2: Plausibility

Downgrade if the preconditions require the attacker to already control the
target system. Preconditions must be achievable by a realistic remote or
authenticated-but-low-privilege attacker.

### Check 3: Network Reachability

Downgrade to MEDIUM if the endpoint binds only to loopback (127.0.0.1 / ::1),
a RFC-1918 address with no proxy or load balancer exposure, or a
cluster-internal DNS name (e.g. `svc.cluster.local`) with no external ingress
— unless a concrete external path is demonstrated (SSRF chain, misconfigured
ingress, publicly-routable secondary interface, or DNS rebinding per below).

**DNS rebinding carve-out — retain at HIGH when all four hold:**
1. The service is HTTP (not raw TCP, gRPC without HTTP/1.1 framing, SSH)
2. The service does not enforce Host header validation
3. A browser-capable runtime (browser, Electron, VS Code extension host,
   embedded Chromium) runs on the same host as the loopback-bound service
4. An external attacker can cause that browser-capable client to visit an
   attacker-controlled page (phishing link, malicious ad, prompt-injected URL)

If the service enforces strict Host header validation, condition 2 fails and
the downgrade applies normally.

Verify claimed reachability using Shodan (see Reachability Verification
section). A confirmed Shodan hit retains HIGH. No hit supports the MEDIUM
downgrade when no other concrete path exists.

### Check 4: Relevance

Downgrade if the action does not matter in this application's context.
Exfiltrating a public dataset is not interesting. Crashing a non-critical
background job with no user-visible impact is not HIGH.

### Check 5: Defense-in-Depth

Downgrade missing defensive controls (CSP, HSTS, X-Frame-Options, weak CORS)
to MEDIUM unless a concrete, exploitable primary vulnerability exists in the
same context that the missing control would have mitigated.

**CORS carve-out — do not apply this downgrade when either holds:**
- (a) The configuration reflects the request Origin and sets
  `Access-Control-Allow-Credentials: true`, enabling cross-origin reads of
  authenticated API responses
- (b) The same reflected-origin plus Allow-Credentials enables credentialed
  cross-origin state mutation against an API that lacks a CSRF token or other
  origin-independent secret — for any state-mutating HTTP method (POST, PUT,
  PATCH, DELETE, or API-defined state-changing methods)

Evaluate CORS on its own merits when either carve-out applies.

### Check 6: Detonation Control

For stored/second-order injection (stored XSS, second-order SQLi, stored
template injection), downgrade to MEDIUM if the attacker cannot cause
detonation without relying on an independent privileged action that is not
part of any regular, predictable workflow.

Retain at HIGH only when at least one holds:
- (i) The application detonates automatically (e.g. admin dashboard loads all
  pending records on each page view)
- (ii) The attacker can cause a legitimate user to perform the triggering
  action (e.g. by sending a link)
- (iii) The application processes stored payloads via a routine scheduled
  automated job
- (iv) The triggering action is part of a recurring human workflow with a
  predictable time window (daily review, next-business-day processing, weekly
  audit) making eventual detonation near-certain

### Check 7: Authenticated-Admin Equivalent Access

For injection findings (command, SQL, template, code) in interfaces that
require admin/operator/superuser role, downgrade if the role already possesses
at least as permissive access to the same specific resource through an
explicit, documented, legitimate mechanism.

Scope constraints:
- "Same resource" means the same database (not same server), same API
  namespace, same filesystem path. An admin with SELECT on `production_db`
  does not have equivalent access to `audit_logs_db` on the same server.
- Partial access does not satisfy this check: a read-only console does not
  cover write-escalating injection.
- Do not apply to horizontal escalation: admin A reading admin B's data is a
  boundary violation even when both hold nominally equivalent roles.

### Check 8: Information-Disclosure Actionability

Downgrade information-disclosure findings unless the disclosed content directly
enables a specific attack the attacker could not carry out without it.

- Credentials, session tokens, API keys, private keys, PII, or internal
  topology enabling a demonstrated SSRF/lateral-movement path: retain at
  severity of the enabled attack.
- Version strings and technology fingerprints: downgrade to LOW or MEDIUM
  unless the specific version has a known, publicly-available, remotely
  exploitable CVE applicable to this deployment. "Could help research
  vulnerabilities" is not sufficient.
- Stack traces and internal file paths: downgrade to LOW unless content
  reveals credentials, tokens, or specific internal endpoint information that
  concretely enables a documented follow-on attack.
- **Combination disclosure**: when a single response leaks multiple pieces
  individually below threshold that together form a coherent exploit chain,
  evaluate the combination at the severity of the attack it enables. Document
  the chaining reasoning explicitly.

### Check 9: Availability

Distinguish scope and attacker cost for DoS and resource-exhaustion findings.

- Session-scoped DoS (harms only the attacker's own session or quota): MEDIUM
  or LOW regardless of privilege level.
- Service-wide DoS at unauthenticated or negligible-cost position: HIGH.
- Service-wide DoS requiring meaningful authentication: downgrade to MEDIUM
  unless a single request triggers disproportionate resource consumption
  (quadratic regex, unbounded recursion, thousands of downstream operations)
  or a small bounded sequence of requests achieves service-wide impact without
  sustained flooding — in both cases, authentication is not a meaningful
  mitigating factor and finding retains HIGH.
- Partial-scope DoS (specific other user's session, not full service): MEDIUM.
- DoS on non-critical background services: apply the relevance check to
  confirm taking the service offline has meaningful operational impact.

### Check 10: Self-Affecting Only

Downgrade if the only demonstrated impact affects the attacker's own session,
data, or account.

- Self-XSS (fires only in attacker's own browser, no path to other users): LOW.
- IDOR that only exposes the attacker's own data: not HIGH — confirm the
  finding is exploitable to access another user's data.
- Deleting own account, revoking own tokens, corrupting own settings: not HIGH.
- Exception: if a self-affecting action cascades to harm other users or the
  service (deleting a shared resource, corrupting a global cache), this check
  does not apply.

### Check 11: Cryptographic Weakness Actionability

Require a statement of what specific attack the weakness enables in this
deployment before scoring HIGH.

**Prerequisite-severity check — discard entirely (do not retain at LOW) when:**
the stated prerequisite for exploiting the finding is itself more severe than
the finding's claimed impact. If breaking the underlying primitive would
already grant a catastrophic capability, the specific finding adds nothing.

Identify the attack class: collision, preimage, length extension, decryption,
key recovery, timing oracle. Do not score HIGH on "MD5 is deprecated" alone.

- MD5 for password hashing: HIGH (preimage/dictionary attacks bypass auth).
- MD5 for non-secret, non-security-relevant cache keys: LOW.
- SHA-1 for TLS certificates: MEDIUM (SHAttered demonstrated, compute
  significant; note as downgrade factor, not elimination).
- Non-constant-time comparison of attacker-supplied secrets: HIGH when the
  endpoint is not rate-limited globally at a level that makes the required
  oracle requests impractical. Per-IP and per-user limits are trivially
  bypassed by distributing requests.

### Check 12: Race-Condition Exploitability

Confirm the race window is realistically exploitable before scoring HIGH.

- Evaluate exploitability in production context (concurrency, load, latency),
  not only in low-traffic lab. A narrow lab window may be wide in production.
- Verify that no production-specific serialization closes the window:
  distributed locks (Redis SET NX, Zookeeper, DB advisory locks), idempotency
  keys enforced at DB level, queue-based serialization, DB unique constraints.
  If such a mechanism is correctly applied to the racy path, downgrade to LOW
  or document as staging-only.
- For HIGH to be justified, the race must lead to a HIGH-impact outcome.
  A race whose worst-case impact is MEDIUM is MEDIUM regardless of
  exploitability.
- Document: estimated race window, conditions under which it is triggerable,
  and why the impact justifies HIGH.

---

### Check 13: CRITICAL Finding Challenge (apply only to CRITICAL severity)

Before finalising a CRITICAL verdict, answer all five adversarial questions. If
any question cannot be answered affirmatively, downgrade to HIGH pending further
investigation and document which question was not satisfied.

1. **No-prior-knowledge trigger:** Can the attacker trigger the vulnerability
   without any system knowledge or access beyond the stated precondition? (e.g.,
   no need to enumerate internal IDs, guess a token, or chain a separate
   unrelated finding)
2. **No practical upstream barrier:** Is there no rate-limit, WAF, input
   validation, or sandbox upstream that makes exploitation impractical even though
   the code path is reachable? Per-IP and per-user rate limits are insufficient
   barriers — they are trivially distributed.
3. **Confirmed external reachability:** Is the vulnerable code path reachable from
   an unauthenticated or low-privilege external request — not just theoretically
   reachable but confirmed via network reachability check (triage Check 3)?
4. **Single-finding impact:** Does the claimed CRITICAL impact require only this
   finding, or must additional unrelated vulnerabilities be chained to reach the
   CRITICAL impact ceiling? If chaining is required, score at the severity of the
   weakest link.
5. **Identified minimal proof-of-concept:** Has a concrete, minimal request or
   payload been identified (HTTP method, endpoint, parameter, payload) that would
   produce the claimed CRITICAL impact against a representative deployment?

---

## Domain-Specific Downgrade Rules

### Fail-Open Findings

Apply when reviewing findings framed as "attacker corrupts file X → security
check Y fails open" (covers ERROR_HANDLING, ACCESS_CONTROL_ENFORCEMENT,
SSRF_PREVENTION, AUDIT_LOGGING specs).

**Downgrade to LOW (or close) when:** the corruption path requires arbitrary
write capability in the application's data directory. An attacker who can
write arbitrary files can rewrite config, replace binaries, or alter any other
state — the specific fail-open path is irrelevant noise.

**Retain at MEDIUM only when a specific, bounded corruption path exists that
does not imply total prior compromise:**
- The file is world-writable (itself a separate finding)
- A specific non-privileged code path can produce a truncated or malformed
  write without crashing (e.g. partial write on SIGKILL mid-flush)
- A dependency or plugin with write access to the data directory but without
  execution privilege could produce the corrupt state

When retaining at MEDIUM, document the specific precondition explicitly; do
not assert a generic "storage corruption → fail-open" claim.

### Config Mutation in Interpreted Languages

Apply when reviewing findings about configuration tampering in Python, Ruby,
JavaScript/Node.js, PHP, Perl, or any other interpreted language (covers
DEFAULT_CREDENTIALS, ACCESS_CONTROL_ENFORCEMENT, ERROR_HANDLING,
SECURITY_REQUIREMENTS specs).

**Downgrade to LOW and close when:** the assumed attack path is local
arbitrary file write. In interpreted runtimes, any process that can overwrite
a `.py`, `.rb`, `.js`, or `.php` file can inject arbitrary logic at the next
import or require — arbitrary file write is already RCE. The config mutation
finding adds no information.

**Retain at original severity only when:** a specific, remote path to alter
config values exists without requiring local file write — a documented CVE in
a config parser, an API endpoint or database-backed config store that accepts
user-controlled writes, or an authenticated administrative interface with
insufficient access control. Document that path explicitly.

For compiled languages (Go, Rust, C, C++, Java, C#), config mutation may be
meaningfully distinct from RCE; evaluate normally.

### Trusted Service Failures

Apply when reviewing findings about malicious or unexpected data returned by
trusted external services (covers DATA_TRANSPORT, DATA_MODEL, SSRF_PREVENTION,
TEMPLATE_INJECTION, DESERIALIZATION_SAFETY specs).

**Close or downgrade to LOW when:** the application sends validated, benign
input to a trusted external service (OAuth provider, payment processor,
internal microservice, third-party API) and the threat model requires the
service to return malicious output. The failure belongs to the remote service,
not the application under test.

**Retain at appropriate severity when:**
- The application transmits user-controlled data to the service without
  validation, and that data could influence the service's response harmfully.
  Frame as an input validation or injection failure in the application, not a
  trust assumption failure.
- The application uses a trusted service's response in a security-sensitive
  way without output validation (redirect targets, template rendering, command
  arguments, deserialization). Retain and attribute to the specific
  output-handling weakness (SSRF, template injection, deserialization).

### Dependency CVEs

Apply a three-step gate before assigning final severity to any CVE or
hardcoded-credential finding.

**Step 1 — Code-path reachability:**
- Identify the specific vulnerable function or behaviour from the CVE
  description, NVD advisory, or patch diff.
- Determine whether the application calls that API at all, and if so, whether
  the call is reachable from attacker-controlled input.
- Verdicts:
  - Vulnerable function not called: close the finding. Document which function
    is vulnerable and confirm it is absent from the call graph.
  - Called with static or operator-controlled input only: downgrade to LOW.
  - Called with attacker-controlled input in authenticated context: retain at
    severity constrained by the authentication precondition per
    SEVERITY_DEFINITION levels.
  - Called with attacker-controlled input in unauthenticated context: retain
    at full CVE severity mapped to SEVERITY_DEFINITION (not raw CVSS score).
- Apply the same reachability check to transitive dependencies.

**Step 2 — Runtime vs development scope:**
- dev/test-only dependencies (npm devDependencies, Cargo dev-dependencies,
  CI-only installs): downgrade to LOW unless the dev environment itself
  handles production secrets or deploys to production.
- Build-time only (webpack plugins, build compilers, linters that do not ship
  to production): close the finding. Exception: build-time code injection
  that modifies the output artifact retains HIGH.
- Bundled but unused features (optional module requiring explicit activation,
  not activated): treat as unreachable per Step 1.

**Step 3 — Credential validity (for secret/credential findings):**
- Verify using the credential's native read-only mechanism (e.g. `GET /v1/user`
  for API keys; read-only DB connection for database credentials). Do not
  perform write operations, destructive queries, or state-modifying actions.
- If verification would cause visible side effects or is out of scope, document
  the reason and treat the credential as potentially active.
- Active credential confirmed: retain at severity based on what the credential
  grants, mapped to SEVERITY_DEFINITION.
- Inactive credential confirmed (401 or confirmed rotated): close the finding.
  Retain as LOW hygiene note — credential is inactive but hardcoding practice
  persists.
- Credentials in git history: if the repository is or was ever publicly
  accessible, treat the exposure window as indefinite regardless of when the
  commit was made. Active credentials in history retain full severity.
  Confirmed-inactive credentials in history close with a LOW note recommending
  history scrubbing.

**CVSS adjustment:** do not use CVSS score as a direct severity assignment.
Apply deployment-specific adjustments before mapping to SEVERITY_DEFINITION:
- AV:N assumes internet-reachability — apply network reachability check if
  the component is not directly internet-facing.
- PR:N assumes unauthenticated access — if the endpoint requires authentication
  in this deployment, adjust precondition accordingly.
- S:C (scope changed) requires confirming the scope applies — a container CVE
  with S:C may have limited actual scope if the container has no host mounts
  and runs as non-root.

---

## Reachability Verification Procedure

Use this procedure when the network reachability check (Check 3) is the
deciding factor for severity.

**Do not submit loopback (127.0.0.1 / ::1) or RFC-1918 addresses to Shodan.**
For those, evaluate only via SSRF chains, ingress misconfigurations, and the
DNS rebinding carve-out above.

### Shodan Passive Lookup

```
shodan host <public-ip>
# or: https://shodan.io/host/<ip>
```

Interpret results:
- **Confirmed hit** (relevant port open, banner matches identified service):
  retain at current severity. Record port, banner excerpt, and last-seen date
  in the finding.
- **No hit**: treat as supporting — but not conclusive — evidence for a
  downgrade. Shodan coverage is incomplete; "not found" means "not confirmed
  exposed", not "confirmed unexposed". Apply the MEDIUM downgrade when no
  other concrete reachability path exists.

**Default ports by service class:**

| Service class | Default ports |
|---|---|
| Key-value stores | Redis 6379, Memcached 11211 |
| Document / search databases | Elasticsearch 9200, MongoDB 27017, Cassandra 9042 |
| Relational databases | PostgreSQL 5432, MySQL 3306, MSSQL 1433 |
| Orchestration / control planes | Kubernetes API 6443, etcd 2379/2380, Docker API 2375/2376 |
| Admin / management panels | Common alternates: 8080, 8443, 9090, 9091, 9100 |
| Message brokers | Kafka 9092, RabbitMQ 5672 (AMQP) / 15672 (management), NATS 4222 |

### Masscan Active Confirmation

Run only with explicit written authorisation covering the target IP range.
Record the authorisation reference (document title, date, scope clause)
alongside the result.

```
masscan <ip-or-range> -p<port> --rate 1000
```

Interpret results:
- **Port confirmed open**: retain at HIGH. Record invocation, target,
  timestamp, and result.
- **Port confirmed closed or filtered**: downgrade to MEDIUM. Note that
  firewall rules may differ between assessment and attacker timing.

---

## Fast-Path Index

Use this table to identify which checks are most likely to be dispositive.
Apply the first check first and stop if it produces a disposition. The full
check set above remains authoritative; this table is a navigation aid only.

| Finding category | First check | Second check | Third check |
|---|---|---|---|
| Injection — SQL, command, template, code | Implication / plausibility | Network reachability (Shodan if applicable) | Authenticated-admin equivalent-access |
| Access control — IDOR, broken auth, missing authz | Implication | Self-affecting-only | Network reachability |
| Stored / second-order injection — stored XSS, second-order SQLi | Detonation-control | Network reachability | Self-affecting-only |
| Information disclosure — errors, stack traces, version strings | Information-disclosure actionability (incl. combination) | Relevance | Defense-in-depth |
| Denial of service — resource exhaustion, crash, loop | Availability (scope + amplification) | Self-affecting-only | Relevance |
| Cryptographic weakness — weak primitive, deprecated algorithm | Prerequisite-severity | Crypto actionability (attack class + use case) | Timing oracle rate-limit (if applicable) |
| Race condition / TOCTOU | Race-condition exploitability | Production serialization check | Impact ceiling |
| Defense-in-depth — missing headers, CSP, HSTS | Defense-in-depth (primary vuln required) | Relevance | — |
| CORS misconfiguration | Defense-in-depth (access control carve-out applies) | Reflected-origin + Allow-Credentials check | CSRF token presence |
| Network-exposed unauthenticated service | Network reachability | Shodan / masscan verification | Implication |
| Prompt injection (LLM agents) | Injection surface (direct vs indirect) | Tool capability assessment | Human-in-the-loop gate |
| Dependency CVE | Code-path reachability | Runtime vs dev scope | CVSS adjustment to deployment context |
| Secret / credential exposure | Credential validity (active vs rotated) | Access scope of credential | History exposure |

---

## Validation Tier

Assign a Validation Tier to each retained HIGH or CRITICAL finding to help
remediation teams sequence verification work. Add a `Validation Tier:` field to
the finding in the audit report.

| Tier | Validation effort | Typical conditions |
|---|---|---|
| 0 | < 15 minutes — single request or code review confirms | Reflected injection with clear taint path, hardcoded credential, missing header |
| 1 | 15–60 minutes — multi-step setup, account creation, specific application state | Stored XSS requiring write then read, IDOR requiring two accounts, race condition in staging |
| 2 | > 1 hour — timing-sensitive, infrastructure-dependent, or chained exploit | Race condition under production concurrency, SSRF requiring DNS rebinding, supply-chain injection requiring compromised upstream |

**Assign Tier 0** when: a single HTTP request demonstrates the vulnerability (curl
command shows the difference between vulnerable and safe response) or a single code
review confirms the control is absent.

**Assign Tier 1** when: the validator needs to create accounts, populate database
state, or execute a multi-step flow to confirm the finding — but all steps are
achievable in a standard development or staging environment.

**Assign Tier 2** when: confirmation requires specific infrastructure conditions
(production traffic load, DNS rebinding timing, upstream service compromise), or
the exploit chain spans multiple vulnerabilities that must be validated together.

Use lower tier when uncertain. Tier assignment does not change severity.
