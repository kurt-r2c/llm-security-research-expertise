# Business Logic Security Audit

Audit the codebase for business logic vulnerabilities: state-machine bypass, missing
rate limiting, and absent re-authentication on privilege-changing operations.

---

## Quick Scope

- Multi-step workflows: checkout, fund transfer, account deletion, role/permission change,
  password reset, subscription upgrade/downgrade, refund, order cancellation
- Sensitive endpoints: login, registration, payment, transfer, withdrawal, invite, verify
- State-progression code: session flags, status columns, workflow/saga orchestrators,
  step-index checks, FSM transition guards
- Rate-limiting middleware and decorator usage on all HTTP handlers
- Re-authentication gates preceding privilege-escalating or destructive actions

---

## Check 1: Step-Ordering Enforcement — Sequence bypass

**Find:** Multi-step flows where later steps do not validate that earlier steps completed.
Search for:
- Route/controller handlers named with words like `confirm`, `complete`, `finalize`,
  `checkout`, `verify`, `approve`, `activate` that accept a token or ID without first
  querying a status/state field on the associated record.
- State fields (columns, session keys, cache keys) that guard step ordering — then trace
  whether every handler for step N checks that the step N-1 state is set before proceeding.
- Direct jumps: URLs or API paths that accept `step=N` or `stage=N` query parameters
  without server-side validation of prior steps.

**Evaluate:** Confirm the finding is real by checking whether the handler reads a
persisted state value before proceeding. If the handler reconstructs all required
preconditions from the request alone (no DB/session read), flag it. If state is
read but not checked against a required predecessor value, flag it.

**Severity:** HIGH if skipping the step allows a financial transaction, privilege grant,
or account takeover to complete; MEDIUM if skipping results in data inconsistency
without direct financial or privilege impact; LOW if only cosmetic or UI-visible state
is affected.

**Common false positives:** Idempotent confirmation endpoints (e.g., email-link verify
that tolerates re-clicks) are not a bypass if the underlying record state is still
validated. Wizard UIs that save partial state are not a finding if the final submission
validates all prior steps server-side.

---

## Check 2: Missing Rate Limiting — Brute-force and enumeration

**Find:** Run Semgrep with the `logic_business` ruleset:

```
semgrep --config security-research/rules/business_logic_security \
  --include="*.py,*.go,*.java,*.js,*.ts,*.cs,*.rb,*.php,*.kt" \
  <target-path>
```

Supplement with a manual search for route/handler definitions on paths matching:
`login`, `password-reset`, `forgot-password`, `register`, `payment`, `transfer`,
`withdraw`, `invite`, `verify`, `otp`, `pin`, `code` — then check whether a
rate-limiting middleware, decorator, or annotation is applied at the route level or
in a wrapping middleware chain.

**Evaluate:** A finding is confirmed if:
1. The endpoint accepts repeated identical requests with no throttle.
2. No framework-level rate limiter (e.g., `@limiter.limit`, `ratelimit.Middleware`,
   `Throttle`, `ThrottleRequests`, `express-rate-limit`, `rack-attack`) is visible
   on the route or in its enclosing middleware stack.
3. No reverse-proxy or gateway rate limit is documented in config files (nginx,
   Caddy, AWS API Gateway, Cloudflare rules).

Do not flag an endpoint if rate limiting is applied at the infrastructure layer and
that config is present in the repository.

**Severity:** HIGH if the endpoint is a login, OTP/PIN check, or password-reset
trigger (credential brute-force or account enumeration); MEDIUM if the endpoint is
registration, invite, or payment (abuse/spam risk); LOW if the endpoint returns
only public read data with no account impact.

**Common false positives:** Internal-only routes (bound to localhost or protected by
mTLS/VPN at the infra layer with evidence in config). Admin-only endpoints where
admin access is already tightly controlled.

---

## Check 3: Absent Re-authentication Gate — Privilege-changing operations

**Find:** Locate handlers that perform any of the following without requiring the user
to re-enter credentials or confirm identity immediately before the action:
- Email or phone number change
- Password change (initiated from within an authenticated session, not via reset link)
- MFA enrollment or removal
- Role or permission assignment/revocation
- Payment method addition or deletion
- Account deletion or deactivation
- Transfer of ownership or admin rights

Search for controller or service functions whose names contain `change`, `update`,
`delete`, `remove`, `transfer`, `assign`, `revoke`, `promote`, `demote` and that
operate on `user`, `account`, `role`, `permission`, `email`, `phone`, or `password`.
Check whether a `confirm_password`, `require_password`, `sudo`, or equivalent
re-auth check appears in the same function or a decorator/middleware applied to it.

**Evaluate:** A finding is confirmed if the handler executes the privilege-changing
action while relying solely on the existing session cookie/token with no re-auth
check in the request lifetime. A CSRF token does not constitute re-authentication.

**Severity:** HIGH if the action enables account takeover (email/phone/password
change, MFA removal); HIGH if the action grants elevated privileges or transfers
ownership; MEDIUM if the action is destructive but limited to the user's own data
(account delete, payment method removal) without account-takeover potential.

**Common false positives:** Password-reset flows triggered by a one-time email link
(the link itself is the re-auth factor). Admin consoles where the administrator must
re-authenticate at session start and the session TTL is short (< 15 minutes).

---

## Check 4: Parallel / Race-Condition Bypass — Double-spend and duplicate execution

**Find:** Identify operations that read a balance, quota, or inventory count, then
write an updated value without holding a database-level lock or using an atomic
compare-and-swap. Look for patterns like:

- `SELECT ... WHERE id = ?` followed later by `UPDATE ... SET balance = balance - ?`
  without `SELECT ... FOR UPDATE` or equivalent advisory lock.
- Application-level checks (`if user.balance >= amount`) followed by a non-atomic
  debit without a DB transaction that serialises the check and the write.
- Idempotency keys or request deduplication absent on payment or transfer endpoints.

**Evaluate:** A finding is confirmed if concurrent identical requests can both pass the
check and both execute the write, resulting in a balance going negative, a coupon
being applied twice, or a resource quota being exceeded. Assess whether the
framework's ORM default isolation level prevents phantom reads in practice.

**Severity:** HIGH if the race produces a financial loss (negative balance, duplicate
charge reversal, over-redemption of a discount); MEDIUM if the race causes quota
over-usage or duplicate resource creation without direct financial impact; LOW if
the window is milliseconds and the operation is idempotent in effect.

**Common false positives:** Operations protected by database-level unique constraints
or serialisable transaction isolation (confirm the isolation level). Queued
operations processed by a single-threaded worker (confirm queue semantics).

---

## Check 5: Workflow State Exposure — Client-controlled state

**Find:** Locate places where the workflow step, role, price, or quantity is read
from client-supplied input (query string, request body, hidden form field, JWT
claim not verified server-side) rather than from a server-side authoritative source.

Search for:
- `request.params.step`, `req.body.price`, `request.POST['amount']`,
  `params[:role]`, or equivalent patterns used to drive business-critical logic
  without a server-side allowlist or re-derivation.
- JWT payloads decoded without signature verification before using role/permission
  claims.
- Price or discount values passed from a frontend cart that are used as-is without
  re-fetching from the product catalogue.

**Evaluate:** A finding is confirmed if the client-supplied value is used to determine
what action is taken or what price is charged, with no server-side re-derivation
from a trusted data source.

**Severity:** HIGH if the attacker can set their own price (purchase at $0 or
arbitrary discount), grant themselves elevated roles, or skip required steps by
manipulating the parameter; MEDIUM if the manipulation causes incorrect application
behaviour that requires additional steps to exploit; LOW if the only outcome is
cosmetic or self-affecting.

**Common false positives:** Pagination cursors, display preferences, and non-security-
relevant UI state passed from the client. Server-side code that reads the client
value but immediately re-validates it against a database record before use.

---

## Rationalizations to Reject

Do not accept these justifications for skipping or downgrading a business-logic
finding without completing the full evidence chain:

- **"The race window is too narrow to exploit"** must be evaluated under production
  concurrency, not lab conditions — a window that is sub-millisecond in a
  single-process dev environment may be reliably exploitable under production load
  with concurrent requests.
- **"Only affects the attacker's own balance"** requires the self-affecting check
  to be applied — confirm there is no cascading effect on platform accounting,
  shared quotas, or other users before closing on self-affecting grounds.
- **"The UI prevents skipping this step"** is not a server-side control — verify
  that server-side state validation enforces step ordering independently of any
  client-side flow or UI constraint.
- **"The ORM prevents double-writes"** must be confirmed at the transaction
  isolation level — default isolation in most ORMs does not prevent phantom reads;
  verify `SELECT ... FOR UPDATE`, advisory locks, or DB unique constraints are
  in place.

## Output Format

For each confirmed finding:

- **[BIZ-N]** · SEVERITY · Title
- **Location:** `file:line`
- **Evidence:** quoted code showing the logic gap
- **Impact:** what the attacker achieves by exploiting the logic error
- **Fix:** specific remediation

**File-handoff (when `$OUTPUT_FILE` is set):** Write all findings to the path in
`$OUTPUT_FILE` and return only the following stub to the orchestrator:

```
{
  "domain": "BIZ",
  "output_file": "<$OUTPUT_FILE value>",
  "raw_counts": {"CRITICAL": N, "HIGH": N, "MEDIUM": N, "LOW": N},
  "status": "complete"
}
```

If `$OUTPUT_FILE` is not set, write findings to stdout as usual.

---

## Triage Gate

Before reporting any HIGH or CRITICAL finding, apply the fast-path checks from
`../triage/SKILL.md`. For business logic findings, pay special attention to:

- **Implication/plausibility:** the attacker must be able to reach the logic gap
  (authenticated user, correct role, correct application state).
- **Relevance:** the outcome must be meaningful — not just a self-affecting anomaly.
- **Self-affecting-only:** if only the attacker's own data, balance, or quota is
  affected and no other user or the platform bears the loss, downgrade severity.
- **Race-condition exploitability:** evaluate whether the race window is reachable
  under real production concurrency; a theoretical window with a sub-millisecond
  frame and serialisable isolation is LOW.
