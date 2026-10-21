# Authentication & Authorization Security Audit

Audit the codebase for 7 auth/session vulnerability classes: session token
entropy and lifecycle, default and hardcoded credentials, session fixation,
authorization model (client-supplied identity claims), access control
enforcement (missing checks, path traversal, forced browsing), and open
redirect.

Use a two-pass approach for every check: first an LLM-native read of the
relevant code, then a Semgrep pass using the rule sets named in each check.
Reconcile the two sets of findings before reporting.

---

## Quick Scope

- Authentication entry points: login handlers, OAuth callbacks, API key
  validators, SSO consumers.
- Session middleware: token generation, cookie configuration, logout handlers,
  privilege-escalation code paths.
- Configuration files: `.env`, `application.yml`, `config.json`, `settings.py`,
  `appsettings.json`, Docker / Compose files, Helm values, Kubernetes Secrets.
- Route definitions and middleware chains: Express/Koa/Gin/Rails/Django/Spring
  router files, `routes/`, `controllers/`, `handlers/`, `middleware/`.
- Authorization helpers: `can()`, `isAllowed()`, `hasRole()`, `authorize()`,
  `checkPermission()`, guard decorators, CASL/Pundit/OPA policy files.
- Resource handlers that serve files, database rows, or admin actions.

---

## Pre-Pass: Route and Middleware Map

Before running any auth check, produce a Route and Middleware Map for the
codebase. Checks 5 (Authorization Model) and 6 (Access Control Enforcement)
reference this map rather than re-discovering routes from scratch, improving
both coverage and efficiency on large codebases.

**Step 1 — Enumerate all routes.** Locate every route definition:
- HTTP: decorator-based (`@app.route`, `@router.get`, `router.HandleFunc`),
  config-based (`routes.rb`, `urls.py`), controller annotations (`@GetMapping`)
- gRPC service definitions, GraphQL resolver registrations, WebSocket upgrade
  paths, message consumers, scheduled job handlers

For each route record: HTTP method, path pattern, handler name, `file:line`.

**Step 2 — Map middleware chains.** For each route, determine the full middleware
sequence applied: global framework middleware, router-group middleware, and
handler-level decorators or guards. Note which middleware performs authentication
or authorization versus non-auth concerns (logging, rate-limiting, CORS).

**Step 3 — Flag unprotected routes.** Identify routes where no auth middleware
appears in the chain. Exclude routes that are intentionally public by design
(login page, health check, static assets, registration endpoint). Mark the
remainder as candidate findings for Check 6.

Record results in a compact map carried forward into all subsequent checks:

```
Route Map:
- POST /api/admin/users  → AdminController.createUser  [auth, requireAdmin]
- GET  /api/status       → HealthController.status     [none — intentionally public]
- PUT  /api/profile      → UserController.update       [auth — no authorization check ⚠]
```

Do not begin Check 1 until this map is complete.

---

## Check 1: Session Token Entropy — Weak or insecure RNG

**Find:** Locate every site that generates a session identifier or bearer token.
Search for `session.secret`, `token =`, `generateToken`, `randomBytes`,
`uuid()`, `Math.random()`, `rand()`, and framework-specific session-creation
APIs. Run Semgrep with the `auth_session` rule set.

**Evaluate:** Determine the entropy source and output size.
- Flag if the RNG is not cryptographically secure (`Math.random`, `rand()`,
  `random.random()`, `srand`-seeded PRNG).
- Flag if the output is fewer than 128 bits of randomness (e.g., a 16-hex-char
  token is only 64 bits; a UUIDv4 without additional entropy is borderline).
- Flag if the secret used to sign JWTs or sessions is a short literal string.

**Severity:** HIGH if a weak RNG or sub-128-bit token reaches production;
MEDIUM if a sufficiently entropic token is truncated or encoded in a way that
reduces effective entropy; LOW if the concern is theoretical with no clear
attack path.

**Common false positives:** Test helpers that deliberately use `Math.random`
for non-security identifiers (e.g., correlation IDs, UI animation keys). Verify
the value never enters an auth path.

---

## Check 2: Session Lifecycle — Missing invalidation on logout and privilege change

**Find:** Trace every logout handler and every code path that elevates
privileges (password change, MFA verification, role assignment). Look for
`session.destroy()`, `req.session.regenerate()`, `invalidate()`,
`token.revoke()`, or framework-equivalent calls. Also search for their absence:
handlers that return a success response without calling any of those.

**Evaluate:**
- Flag if a logout handler clears client-side state (cookie deletion, redirect)
  but does not invalidate the server-side session record.
- Flag if a privilege-escalation path does not rotate the session token before
  returning the elevated session. An attacker who observed the low-privilege
  token retains access.
- Flag if token revocation lists or session stores lack the capability to
  invalidate a specific token (e.g., stateless JWT-only with no block list and
  a long expiry > 24 h).

**Severity:** HIGH if logout does not invalidate server-side state; HIGH if
privilege escalation does not rotate the token; MEDIUM if JWT expiry exceeds 24
hours with no revocation mechanism.

**Common false positives:** Stateless APIs that are intentionally sessionless
(every request carries a short-lived signed credential). Confirm there is no
server-side session before closing.

---

## Check 3: Session Fixation — Client-supplied session identifier accepted pre-auth

**Find:** Identify every authentication flow entry point. Check whether the
application reads a session identifier from the request (cookie, query param,
`Authorization` header) before the user is authenticated and continues to use
that same identifier after successful authentication.

Search for patterns where the session ID is read from the request early in the
flow and `session.regenerate()` / `session.save()` / `generate_csrf_token()` is
not called immediately after credential verification. Run Semgrep with the
`auth_session` rule set.

**Evaluate:**
- Flag if the pre-auth session ID is preserved post-auth without regeneration.
- Flag if the application explicitly accepts a `?session_id=` query parameter
  and binds it to the new authenticated session.

**Severity:** HIGH if an attacker can plant a known session ID before the victim
authenticates and then use that ID to access the victim's account.

**Common false positives:** OAuth `state` parameters are intentionally
round-tripped but are not session identifiers. CSRF tokens bound to pre-auth
sessions are not fixation vectors on their own.

---

## Check 4: Default and Hardcoded Credentials — Literals in source or config

**Find:** Locate all credential initialization sites and configuration files.
Search for:
- Literal password assignments: `password = "`, `passwd =`, `secret =`,
  `api_key =`, `token =` followed by a quoted string.
- Well-known default strings: `admin`, `password`, `root`, `changeme`,
  `secret`, `1234`, `letmein`.
- Fallback chains: `os.getenv("DB_PASS") or "hardcoded"`,
  `ENV.fetch("SECRET", "default_secret")`.
- Credentials embedded in connection strings, DSN URIs, or JDBC URLs.
Run Semgrep with the `config_credentials` rule set.

**Evaluate:**
- Flag hardcoded literals that are not placeholders (i.e., the value is a real
  credential, not `<YOUR_KEY_HERE>` or `TODO`).
- Flag fallback chains where the default resolves to a usable credential even
  when the environment variable is absent.
- Flag Compose / Helm / Kubernetes files that set well-known default passwords
  without requiring an override.

**Severity:** HIGH if the credential grants access to production data or
infrastructure; HIGH if the fallback is silently active when an env var is
unset; MEDIUM if the credential is only present in development/test configs that
are not deployed to production (confirm deployment pipeline before downgrading).

**Common false positives:** Placeholder strings in README examples, commented-
out code, and `.env.example` files. Verify the file is actually loaded at
runtime before flagging.

---

## Check 5: Authorization Model — Client-supplied identity or role claims

**Find:** Trace every authorization decision from its data source to its
decision logic. Search for authorization checks that read from:
- Request headers: `X-User-Id`, `X-Role`, `X-Admin`, custom identity headers.
- Cookie values read directly: `req.cookies.role`, `request.COOKIES["admin"]`.
- Query parameters: `?isAdmin=true`, `?userId=<id>`.
- JWT claims decoded without signature verification (e.g., base64-only decode).

Run Semgrep with the `access_authz` rule set. Cross-reference all API endpoint
definitions — including internal (`/internal/`, `/admin/`, `/_/`) routes — to
confirm each has an identified authorization check.

**Evaluate:**
- Flag any authorization check that trusts a header or parameter the client
  controls without verifying a server-side signature or looking up the claim in
  a server-side store.
- Flag horizontal privilege escalation: handlers that accept a resource ID from
  the request body or path and return the resource without confirming the
  authenticated user owns or is authorized for that ID.
- Flag admin or internal endpoints with no authorization check at all.
- Trace the client-supplied value from its read site to the conditional that gates
  the privileged action. Flag only if the value reaches the gating conditional
  without passing through a server-side store lookup or signature verification. Do
  not flag if the value is only logged, forwarded to a monitoring service, or used
  in a non-security-relevant field (e.g., display name, UI preference).
- For horizontal privilege escalation candidates: confirm the resource ID from the
  request is used without first joining to an ownership table or confirming the
  authenticated user's association to that resource ID in the database.

**Severity:** HIGH if the check reads an unsigned client-supplied role claim
and uses it to gate privileged actions; HIGH if a horizontal escalation path
allows access to another user's data; HIGH if an admin endpoint has no check;
MEDIUM if the check is present but incomplete (e.g., confirms authentication
but not authorization level).

**Common false positives:** Trusted-service patterns where the header is set by
an upstream reverse proxy under operator control and the endpoint is not exposed
to the public internet — apply `../triage/SKILL.md` network reachability check
before downgrading.

---

## Check 6: Access Control Enforcement — Missing checks, path traversal, forced browsing

**Find:** Enumerate all route handlers and middleware chains. For each handler
that returns data or performs a state-mutating action, locate the access control
check that precedes it. Search for:
- Handlers with no preceding `authorize()`, guard decorator, middleware call, or
  explicit permission check.
- File-serving routes that concatenate user input into a file path without
  normalization: `path.join(baseDir, req.params.file)`,
  `File.open(params[:path])`, `open(base + user_input)`.
- Path traversal sequences accepted by the application: `../`, `%2e%2e%2f`,
  `..%2f`, `%2e%2e/` in any file-serving or template-loading route.

Run Semgrep with the `access_control` rule set. Cross-reference against the
handler list from Check 5.

**Evaluate:**
- Flag handlers that have no access control check at all (forced browsing).
- Flag file paths constructed from user input without `realpath`/`os.path.abspath`
  normalization followed by a base-directory containment check.
- Flag access control checks that read a client-supplied parameter
  (`isAdmin=true` in a request body) without server-side verification.

**Severity:** HIGH if a missing check exposes another user's data or allows
privilege escalation; HIGH if path traversal can read files outside the web
root; MEDIUM if a non-sensitive handler lacks a check (e.g., returns only
public metadata); LOW if the check is redundant with an upstream gateway that
reliably enforces the same rule.

**Common false positives:** Public endpoints (login page, static assets, health
checks) are intentionally open. Confirm the route is genuinely unprotected by
design before flagging its absence of an access control check.

---

## Check 7: Open Redirect — Unvalidated redirect targets

**Find:** Every location where the application performs an HTTP redirect using a
URL or path derived from user-supplied input. Search for:

- **OAuth `redirect_uri`:** `redirect_uri` parameter accepted and used without
  exact-match comparison against a registered allowlist. Also check for partial
  matching (prefix-only, regex-without-anchors) or encoding bypass susceptibility
  (`%2F`, `%40`, double-encoding).
- **Post-login redirect:** `next=`, `return_to=`, `redirect=`, `goto=`,
  `destination=`, `url=` parameters that are read and used in a redirect response
  after authentication without same-origin or allowlist validation.
- **Logout redirect:** Similar parameters on logout handlers that redirect to an
  arbitrary external URL.
- **URL parsing confusion:** Values like `//evil.com`, `javascript:`, `data:`,
  `\\/evil.com`, or `///evil.com` that pass naive slash-prefix or hostname checks.

Run Semgrep with the `auth_session` rule set and cross-reference all redirect
call sites (`redirect()`, `Response.Redirect()`, `res.redirect()`, `header('Location: ...')`,
`HttpResponseRedirect(...)`, etc.).

**Evaluate:**
- Confirm the redirect target is at least partially user-controlled (request param,
  header, or cookie value).
- Check whether a same-origin enforcement or allowlist check is applied before the
  redirect executes. A same-origin check must verify both the scheme and the host
  (`urllib.parse.urlparse(target).netloc == request.host` style), not merely check
  for a leading `/`.
- For OAuth `redirect_uri`: exact allowlist match is the only acceptable control;
  prefix matching is exploitable (`https://allowed.com.evil.com`).
- For `javascript:` URIs: a client-side redirect (e.g., `window.location`) to one is a DOM XSS vector.

**Severity:**
- **HIGH**: OAuth `redirect_uri` not validated against an exact allowlist — enables
  authorization code or token theft via open redirect chained with the OAuth flow.
- **MEDIUM**: Post-login redirect to an attacker-supplied URL without allowlist
  validation — enables phishing with the application's trusted domain in the
  referrer.
- **LOW**: Logout redirect to an arbitrary URL with no sensitive token in the URL
  and no OAuth flow involvement.

**Common false positives:** Redirects to a URL that is assembled entirely from
server-side constants or configuration values not influenced by the request;
redirects that enforce a strict same-origin check correctly (scheme + host match);
OAuth flows where `redirect_uri` is hardcoded in the client configuration and never
read from the request.

---

## Rationalizations to Reject

Do not accept these justifications for skipping or downgrading an auth finding
without completing the full evidence chain:

- **"The framework handles sessions"** does not mean this specific authentication
  flow is safe — verify the framework is correctly configured and that this code
  path uses the framework's session API rather than a custom bypass.
- **"Admin-only endpoint"** does not eliminate injection or privilege-escalation
  risk unless triage Check 7 confirms the admin role already possesses at least
  as permissive access to the same resource through an explicit documented mechanism.
- **"Short-lived token"** does not substitute for server-side invalidation on
  logout — token expiry and session revocation are distinct controls; a token
  valid for 15 minutes after logout is still exploitable.
- **"The login page is rate-limited"** does not cover all credential-verification
  paths — confirm every endpoint that checks a credential (API key, OTP, magic
  link) has its own rate-limit control.

---

## Output Format

For each confirmed finding:

- **[AUTH-N]** · SEVERITY · Title
- **Location:** `file:line`
- **Evidence:** quoted code or config showing the gap
- **Impact:** what the attacker gains
- **Fix:** specific remediation

Number findings sequentially within this audit (AUTH-1, AUTH-2, …).

**File-handoff (when `$OUTPUT_FILE` is set):** Write all findings to the path in
`$OUTPUT_FILE` and return only the following stub to the orchestrator:

```
{
  "domain": "AUTH",
  "output_file": "<$OUTPUT_FILE value>",
  "raw_counts": {"CRITICAL": N, "HIGH": N, "MEDIUM": N, "LOW": N},
  "status": "complete"
}
```

If `$OUTPUT_FILE` is not set, write findings to stdout as usual.

---

## Triage Gate

Before reporting any HIGH or CRITICAL finding, apply the fast-path checks from
`../triage/SKILL.md`. For auth findings the most dispositive checks are:
implication/plausibility (does the precondition actually hold in this
codebase?), network reachability (for exposed admin endpoints), and
self-affecting-only (for IDOR / horizontal escalation findings where the
attacker can only reach their own resources).
