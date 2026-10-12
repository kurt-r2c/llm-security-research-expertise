# Output Hardening & Security Requirements Audit

Audit the codebase for 5 output and configuration hardening gaps: error disclosure,
fail-open error handling, missing or misconfigured security headers, undocumented
security requirements, and unvalidated external data model fields.

---

## Quick Scope

- HTTP middleware and response-construction files (routers, controllers, filter chains)
- Exception/error handler registrations (global handlers, middleware, catch-all routes)
- Framework configuration files (settings.py, application.properties, web.config,
  config/environments/*.rb, app.config, *.env, docker-compose.yml)
- Data model definitions: ORM models, structs, DTOs, schema files, proto definitions
- Authentication and authorisation code paths (login, token validation, permission checks)
- `catch` / `except` / `rescue` / `defer`-with-recover blocks anywhere in auth or
  transaction code
- Security documentation: threat models, ADRs, README security sections, test suites
  that assert security controls
- Run `semgrep --config rules/config_errors`, `rules/resilience_errors`,
  `rules/config_headers`, `rules/logic_requirements`, and `rules/data_model` to
  establish the deterministic baseline; use LLM-native review to extend coverage.

---

## Check 1: Error Disclosure — Stack traces and internals in responses

**Find:** Locate every exception handler, error middleware, and response serialisation
path where exception data or diagnostic information may reach the client. Look for:

- Exception objects or their `.Message` / `.StackTrace` / `.toString()` serialised
  directly into response bodies or JSON error payloads
- File paths (absolute or relative) written into client-visible error fields
- SQL query text or ORM diagnostic strings echoed back to the caller
- Framework debug payloads: Django `DEBUG = True` responses, Rails detailed exception
  pages, Spring `server.error.include-stacktrace=always`, Express `err.stack` in
  `res.json()`
- Verbose error flags active in any environment other than development
  (`debug: true`, `ASPNETCORE_ENVIRONMENT=Development` in production configs,
  `display_errors = On` in php.ini)

**Evaluate:** Apply a two-pass approach.

Pass 1 — enumerate all sites where exception objects or their properties flow into
response construction. Note every handler, middleware registration, and
serialisation helper.

Pass 2 — for each site, determine whether raw exception data (stack frame, file path,
SQL text, class name) is written to the response, OR whether the framework's debug
mode renders a diagnostic page. If yes, it is a finding. If the handler logs
internally and returns a generic message, it is not.

**Severity:** HIGH if stack traces, file paths, or SQL text are written to responses
in a production or production-equivalent environment; MEDIUM if the same behaviour
occurs only when a debug flag is enabled and that flag is not set in production
configs; LOW if only a generic error code or user-facing message is disclosed without
implementation detail.

**Common false positives:** Logging statements that write stack traces to log files
(not responses); developer-mode error pages that are explicitly gated on an
environment variable set only locally; client-side error messages that contain
user-supplied input echoed back for UX purposes (evaluate those under injection
specs instead).

---

## Check 2: Fail-Open Error Handling — Security checks bypassed on exception

**Find:** Enumerate all `catch`, `except`, `rescue`, and `recover` blocks in
authentication, authorisation, and transaction code. Look for handlers that:

- Return a success response or a truthy/zero-error value after catching an exception
  from a security gate (token validation, permission check, signature verification)
- Execute a `continue`, `next`, `return true`, `return null`, or equivalent that
  bypasses a pending security check when an error is caught
- Swallow exceptions silently (`catch (Exception e) {}`, `except: pass`,
  `rescue => _e; nil`) where the surrounding code would otherwise deny access
- Use `finally` or `defer` to release locks, tokens, or connection state
  conditionally in a way that leaves shared state inconsistent on the error path

**Evaluate:** Apply a two-pass approach.

Pass 1 — list every catch/except/rescue/recover block in auth, permission, and
transaction paths; record what action the handler takes (return value, next call,
state mutation).

Pass 2 — for each handler, answer: does an exception on the security check cause the
caller to proceed as if the check passed? Does the finally/defer block leave a lock
released or a session open that should be closed? If yes to either, flag it.

**Severity:** HIGH if an exception causes a security gate to pass (authentication or
authorisation bypass, or a transaction to commit in a partially-applied state); MEDIUM
if the exception is swallowed silently in a security-adjacent path but the immediate
control flow still denies access (defence-in-depth gap); LOW if the swallowed
exception is in non-security code or the finally block only affects logging.

**Common false positives:** Catch blocks that re-throw or wrap and re-raise; handlers
that return a structured error response (HTTP 500, error DTO) rather than success;
finally blocks that unconditionally close resources regardless of exception state.

---

## Check 3: Security Headers — Missing or disclosing HTTP response headers

**Find:** Identify all locations where HTTP responses are constructed or middleware is
configured. Look for:

- Response construction sites that do not set `Content-Security-Policy`,
  `Strict-Transport-Security`, `X-Frame-Options`, or `X-Content-Type-Options`
- `Access-Control-Allow-Origin` set to `*` combined with
  `Access-Control-Allow-Credentials: true`; or an endpoint that reflects the
  request `Origin` header directly into `Access-Control-Allow-Origin` without
  validating against an allowlist
- Middleware or server configuration that adds `Server`, `X-Powered-By`, or
  `X-AspNet-Version` headers disclosing technology stack details
- `Content-Security-Policy` directives that include `unsafe-inline` or `unsafe-eval`
  without a nonce or hash value
- Framework defaults that emit disclosing headers and are not suppressed
  (Express `x-powered-by`, ASP.NET `X-AspNet-Version`, Apache/nginx `Server` with
  version tokens)

**Evaluate:** Apply a two-pass approach.

Pass 1 — enumerate every middleware registration, filter, or response-builder that
sets or suppresses headers; note which security headers are present and which are
absent at each site.

Pass 2 — cross-reference each response site against the required header list:
`Content-Security-Policy`, `Strict-Transport-Security`, `X-Frame-Options`,
`X-Content-Type-Options`. Flag any site that omits a required header, adds a
disclosing header, or sets an unsafe CSP directive without a nonce or hash.

**Severity:** MEDIUM for missing required headers (defence-in-depth; escalate to HIGH
only if a concrete primary vulnerability is demonstrated that the header would
mitigate, e.g. a confirmed XSS with no CSP); MEDIUM for disclosing headers
(`Server`, `X-Powered-By`) unless a specific disclosed version has an unpatched CVE,
in which case HIGH; HIGH for `unsafe-inline` or `unsafe-eval` in CSP without a nonce
or hash if the application also has user-controlled output in the same page.

**CORS severity:** `Access-Control-Allow-Origin: *` alone is LOW per the
defence-in-depth rule in `../triage/SKILL.md` Check 5. Escalate to MEDIUM or
HIGH only when the CORS carve-out conditions apply: reflected-origin +
`Allow-Credentials: true` enables credentialed cross-origin reads (MEDIUM) or
credentialed state-mutating requests against an API without a CSRF token (HIGH).

**Common false positives:** Headers set in a reverse-proxy or CDN layer not visible in
source (note the gap but do not rate as HIGH without confirmation the proxy is
absent); non-browser API endpoints that are legitimately header-minimal; test or
health-check endpoints intentionally excluded from security middleware.

---

## Check 4: Security Requirements Coverage — Features without documented controls

**Find:** Enumerate all features that handle sensitive data or perform privileged
operations. For each feature, verify:

- A documented security requirement exists (threat model entry, ADR security section,
  inline security comment, test asserting the control, or design doc)
- The requirement has a traceable implementation control: a test case, configuration
  entry, or code construct that enforces it
- Threat model coverage is present; if a feature processes PII, handles payments, or
  escalates privileges, flag absence of a threat model entry

Also look for:

- Routes or handlers marked `admin`, `privileged`, `internal`, or `sudo` with no
  corresponding security test
- Auth and permission checks with no associated negative test (i.e. a test that
  verifies access is denied)
- Sensitive-data fields (passwords, tokens, PII) with no documented retention or
  encryption requirement

**Evaluate:** Apply a two-pass approach.

Pass 1 — build a feature inventory: list every handler, service method, or background
job that operates on sensitive data or elevated privilege. Check each for an
associated requirement document or annotation.

Pass 2 — cross-reference with Semgrep `logic_requirements` findings to surface
implementation control gaps and missing threat model entries. Flag features that have
no requirement and no corresponding negative/security test.

**Severity:** HIGH if a privileged or PII-handling feature has no security requirement
and no implementation control (the gap is unmitigated); MEDIUM if requirements exist
but lack traceability to a specific implementation control; LOW if the gap is
documentation-only and implementation controls are clearly present in code.

**Common false positives:** Utility functions (logging helpers, formatters) that
incidentally touch sensitive fields but do not control access; test infrastructure
code; commented-out or feature-flagged code paths that are not reachable in
production.

---

## Check 5: Data Model Validation — External fields used without validation

**Find:** Identify all data model entities, structs, DTOs, and schema types that
accept external input. Look for:

- Struct or object instantiation that populates fields directly from raw external
  data (request body, query parameters, HTTP headers, webhook payloads, message queue
  messages) without validation or schema enforcement before use
- Deserialisation or unmarshalling operations (`json.Unmarshal`, `ObjectMapper.readValue`,
  `pickle.loads`, `YAML.load`, `xmltodict.parse`) where the source is not
  authenticated or the result is used without sanitisation
- Fields that lack type constraints, range checks, or allow-list validation when
  populated from external sources
- Mass-assignment patterns (`Object.assign(model, req.body)`,
  `update_attributes(params)`, `bind(request)`) that allow callers to set
  security-sensitive fields (roles, permissions, account IDs)

**Evaluate:** Apply a two-pass approach.

Pass 1 — for each entity or struct field populated from an external source, trace
whether input validation or schema enforcement is applied before the value is used
downstream. If not, flag it.

Pass 2 — for each deserialisation operation, verify the source is authenticated and
the result is not used before sanitisation. If either condition is absent, flag it.

**Severity:** HIGH if a mass-assignment or unauthenticated deserialisation pattern
allows a caller to set security-sensitive fields (roles, flags, IDs); HIGH if
deserialisation uses an unsafe mechanism (`pickle`, `yaml.load` with `Loader=Loader`)
on unauthenticated input; MEDIUM if validation is missing on non-privileged fields
that could cause data integrity issues; LOW if the only missing constraint is a
non-security format check (e.g. string length on a display name).

**Common false positives:** Internal service-to-service calls where the caller is
authenticated and trusted at the transport layer; configuration file deserialisation
loaded at startup from a path controlled by the operator (not the user); test fixtures
and seed data loaders.

---

## Rationalizations to Reject

Do not accept these justifications for skipping or downgrading an output-hardening
finding without completing the full evidence chain:

- **"Missing header is only defence-in-depth"** is not a rationalization to skip
  the CORS carve-out check — evaluate whether the reflected-origin +
  `Allow-Credentials: true` combination applies before applying the
  defence-in-depth downgrade.
- **"Debug mode is off in prod"** must be confirmed from actual production
  configuration files or deployment manifests — the presence of `DEBUG = False`
  in source is not sufficient if an environment variable can override it at
  runtime.
- **"The endpoint only returns non-sensitive data"** requires verifying what the
  endpoint actually returns, not what its name or documentation claims — read the
  handler code and any shared response serialiser before accepting this.
- **"The CSP is set by the reverse proxy"** must be confirmed in repository config
  — do not close a missing-CSP finding without evidence the proxy configuration
  is present and deployed.

## Output Format

For each confirmed finding:

- **[OUT-N]** · SEVERITY · Title
- **Location:** `file:line`
- **Evidence:** quoted code or config snippet
- **Impact:** what the disclosure, bypass, or missing control enables
- **Fix:** specific remediation step

Number findings sequentially across all checks (OUT-1, OUT-2, ...).

**File-handoff (when `$OUTPUT_FILE` is set):** Write all findings to the path in
`$OUTPUT_FILE` and return only the following stub to the orchestrator:

```
{
  "domain": "OUT",
  "output_file": "<$OUTPUT_FILE value>",
  "raw_counts": {"CRITICAL": N, "HIGH": N, "MEDIUM": N, "LOW": N},
  "status": "complete"
}
```

If `$OUTPUT_FILE` is not set, write findings to stdout as usual.

---

## Triage Gate

Before reporting any HIGH or CRITICAL finding, apply the fast-path checks from
`../triage/SKILL.md`. For output hardening findings the most dispositive checks are:

- **Defence-in-depth:** missing headers are MEDIUM unless a primary vulnerability is
  demonstrated that the header directly mitigates.
- **Information-disclosure actionability:** stack traces and version strings must have
  a demonstrated follow-on attack (specific CVE, credential extraction path) to rate
  HIGH.
- **Fail-open:** confirm the exception path causes the security gate to pass, not
  merely to log or return an error; silent swallowing in a non-security path is MEDIUM
  at most.
- **Authenticated-admin equivalent access:** if an attacker must already have
  admin-equivalent access to reach the misconfigured endpoint or feature, downgrade
  accordingly.
