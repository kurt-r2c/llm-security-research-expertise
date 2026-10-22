# Observability Security Audit

Audit the codebase for 6 logging and audit-trail security gaps: missing
authentication event logging, missing access-control denial logging, suppressed
log errors, secrets in log messages, log injection via user-controlled input,
and log destinations writable by the application process.

---

## Quick Scope

- Authentication and session management code (`login`, `logout`, `authenticate`,
  `authorize`, `session`, `token`, `credential` in file names or directories).
- Middleware and request-interceptor files (`middleware/`, `interceptor/`,
  `filter/`, `guard/`).
- Log initialisation and configuration files (`logger`, `logging`, `log4`,
  `winston`, `pino`, `logback`, `serilog`, `zap`, `zerolog`).
- HTTP handler and controller files that act on sensitive resources.
- Infrastructure config files that specify log file paths or destinations.

---

## Pass 1: LLM-Native Discovery

Trace all authentication and authorisation code paths. For each site, note:

1. Does a login attempt (success or failure) emit a structured log entry?
2. Does an access-control denial emit a log entry with user identity, resource
   identifier, and timestamp?
3. Does a mutation of a sensitive resource (password change, role assignment,
   secret rotation) emit a log entry?
4. Are any log calls wrapped in `try/catch` (or equivalent) in a way that could
   silently suppress the entry on error?
5. Does any log message include a password, session token, API key, or other
   secret?

Enumerate all log write sites. For each site, trace data flow from request input
to the log message, identifying direct string concatenation or interpolation of
user-controlled values and any structured-logging fields populated directly from
request input.

Note all log file paths configured by the application.

---

## Pass 2: Semgrep Confirmation

Run the Semgrep rulesets against the files identified in Pass 1:

```
semgrep --config rules/observability_audit   <files>
semgrep --config rules/observability_integrity <files>
```

Reconcile tool output with the Pass 1 findings. Flag items found by either
pass; do not discard LLM findings that the tool missed.

---

## Check 1: Authentication Events — Missing Log on Success or Failure

**Find:** Authentication code paths (login handlers, token validation, OAuth
callbacks, API-key verification) that return a success or failure response
without calling a log function.

**Evaluate:** Confirm the code path is reachable and that no upstream middleware
unconditionally logs all authentication outcomes before the handler runs. A
finding is real if at least one outcome (success or failure) produces no
structured log entry containing user identity and timestamp.

**Severity:** HIGH if both success and failure are unlogged; MEDIUM if only one
outcome is unlogged.

**Common false positives:** Framework-level audit middleware that logs every
request before the handler executes; test stubs and mock authenticators.

---

## Check 2: Access-Control Denials — Missing Denial Log

**Find:** Permission-check sites (`authorize`, `hasPermission`, `can`, `isAllowed`,
`assertRole`, and equivalents) that return or throw a denial without logging.

**Evaluate:** Confirm the denial branch is reachable and that no surrounding
middleware logs the denial. A finding is real if the denial path does not emit a
log entry containing user identity, resource identifier, and timestamp.

**Severity:** HIGH if denials on sensitive resources (admin endpoints, payment
flows, data export) are unlogged; MEDIUM for denials on lower-sensitivity paths.

**Common false positives:** Framework-supplied 403 handlers that include an
audit log call internally; rate-limit rejections handled by dedicated middleware
that logs separately.

---

## Check 3: Suppressed Log Errors

**Find:** Log calls inside `try/catch` (Java/JS/C#/PHP), `rescue` (Ruby),
`except` (Python), or equivalent, where the `catch` block swallows the
exception without re-emitting it to a secondary sink.

**Evaluate:** Confirm the catch block does not re-throw, call a fallback logger,
or write to stderr/stdout. A finding is real if the log call can silently fail
with no observable signal.

**Severity:** MEDIUM for all confirmed instances; raise to HIGH if the silenced
log call is the sole record of an authentication or security-relevant event.

**Common false positives:** Catch blocks that call a fallback sink (e.g., write
to stderr or a dead-letter queue); intentional best-effort logging in
non-security paths documented as such.

---

## Check 4: Secrets in Log Messages

**Find:** Log calls whose message or structured fields include variables or
literals matching: `password`, `passwd`, `secret`, `token`, `api_key`, `apikey`,
`credential`, `auth`, `bearer`, `private_key`, `ssn`, `credit_card`, `cvv`.

**Evaluate:** Confirm the variable or field name reflects actual secret content
rather than a redacted placeholder or a label string (e.g., logging the field
name `"password"` as a string literal to describe what was changed, not its
value). A finding is real if the log statement passes the secret value itself.

**Severity:** HIGH if the secret is a session token, API key, or private
credential; MEDIUM if the secret is a password hash rather than plaintext (still
a risk but lower immediate impact).

**Common false positives:** Log statements that record the field name as a string
("password field updated") without including the value; redaction wrappers that
replace the value before logging (`redact(password)`).

---

## Check 5: Log Injection via User-Controlled Input

**Find:** Log calls that concatenate or interpolate user-controlled request
values (query parameters, headers, body fields, path segments, usernames) into
the log message string without sanitisation. Look for newline characters
(`\n`, `\r`, `%0a`, `%0d`) passing unescaped, and ANSI escape sequences
in the same data flow.

Also identify structured-logging fields populated directly from request input
without type enforcement (e.g., a JSON field set to `req.body.level` that
controls the log level).

**Evaluate:** Confirm the value flows from an untrusted source to the log call
without normalisation. A finding is real if an attacker can inject newlines to
forge additional log lines or inject ANSI sequences to corrupt terminal log
viewers, or control structured fields that affect log routing or severity.

**Severity:** HIGH if the injection enables forging of other users' audit entries
or suppression of log lines; MEDIUM if the injection produces garbled or
misleading entries without full line forgery.

**Common false positives:** Logging libraries that automatically escape newlines
and ANSI codes before writing (verify in library documentation); log calls that
pass user input only to a field with a scalar type enforced by the library schema.

---

## Check 6: Log Destinations Writable by the Application Process

**Find:** Log file paths configured in the application (log4j properties,
logback XML, winston transports, pino destinations, serilog sinks, custom open
calls) that point to locations writable by the same OS user that runs the
application process.

**Evaluate:** Determine whether the path is under a directory the application
process owns or has write permission to (e.g., the application working directory,
`/tmp`, a user home directory). A finding is real if the process can open the
log file for writing and also has no append-only enforcement (e.g., Linux
`O_APPEND` with a chattr `+a` flag, or a remote syslog destination the process
cannot reach directly).

**Severity:** MEDIUM for writable local paths with no append-only protection;
LOW if the log destination is a remote syslog or SIEM the process cannot modify
directly.

**Common false positives:** Containerised applications where the writable log
path is expected and logs are forwarded to an immutable external sink before the
container can be tampered with; read-only root filesystems with a dedicated
writable volume for logs that is separately backed up.

---

## Rationalizations to Reject

Do not accept these justifications for skipping or downgrading an observability
finding without completing the full evidence chain:

- **"Logs are internal so secrets in logs don't matter"** requires verifying log
  access controls before downgrading — confirm no developer workstation, CI
  system, log-aggregation service, or monitoring tool with broader access can
  read the log output.
- **"The log is only for debugging and never reaches prod"** must be confirmed by
  deployment configuration, not by convention or developer intent — check whether
  the logger is initialised and called in production code paths.
- **"Framework-level logging captures everything"** must be verified — confirm the
  framework middleware fires before the handler for all authentication paths,
  including error paths and early-return branches that might bypass the middleware.
- **"The secret is masked in the log"** requires reading the masking implementation
  — confirm the masking function covers all representations of the secret (raw,
  base64-encoded, URL-encoded) and is applied before the log call, not after.

---

## Output Format

For each confirmed finding:

- **[OBS-N]** · SEVERITY · Title
- **Location:** `file:line`
- **Evidence:** quoted code or config
- **Impact:** what the gap enables (evasion of detection, tampered evidence,
  forged audit trail, secret exposure, etc.)
- **Fix:** specific remediation (e.g., add structured log call with user identity
  and resource fields; strip newlines from user input before logging; move log
  file to append-only destination)

**File-handoff (when `$OUTPUT_FILE` is set):** Write all findings to the path in
`$OUTPUT_FILE` and return only the following stub to the orchestrator:

```
{
  "domain": "OBS",
  "output_file": "<$OUTPUT_FILE value>",
  "raw_counts": {"CRITICAL": N, "HIGH": N, "MEDIUM": N, "LOW": N},
  "status": "complete"
}
```

If `$OUTPUT_FILE` is not set, write findings to stdout as usual.

---

## Triage Gate

Before reporting any HIGH or CRITICAL finding, apply the fast-path checks from
`../triage/SKILL.md`. For observability findings the most dispositive checks are:

- **Relevance:** missing logging on a non-critical, unauthenticated, or
  read-only path is LOW — it reduces forensic capability but creates no
  exploitable risk on its own.
- **Defense-in-depth:** a logging gap alone does not constitute an exploitable
  vulnerability; report it at MEDIUM unless a concrete attack chain depends on
  the absence of the log (e.g., log suppression that conceals an ongoing
  intrusion from a real-time alerting system).
