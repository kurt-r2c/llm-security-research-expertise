# Infrastructure Security Audit

Audit the codebase for 5 infrastructure-level vulnerability classes: Server-Side
Request Forgery (SSRF), Resource Exhaustion (DoS), Unsafe Deserialization,
CORS misconfiguration, and file upload security.

---

## Quick Scope

- HTTP client call sites: `requests`, `urllib`, `httpx`, `fetch`, `axios`, `curl`,
  `HttpClient`, `RestTemplate`, `OkHttp`, `net/http`, `Faraday`, `open-uri`
- File upload handlers: multipart form endpoints, streaming body readers, S3 put paths
- Loops and recursive functions whose bounds derive from request parameters or
  external data
- External I/O without timeout: database queries, cache reads, third-party API calls
- Deserialization call sites: `pickle.loads`, `marshal.loads`, `yaml.load`,
  `json.loads` on raw network bytes, Java `ObjectInputStream`, Ruby `Marshal.load`,
  PHP `unserialize`, .NET `BinaryFormatter`/`NetDataContractSerializer`
- ORM hydration paths, IPC message consumers, cache-read-then-hydrate patterns

---

## Check 1: SSRF — Outbound request URL constructed from user input

**Find:** Every call site that constructs or dispatches an outbound HTTP or DNS
request. Trace the URL argument back to its source. Flag any path where:

- A URL or hostname is derived from a request parameter, header, body field, or
  database value without passing through an allowlist before the network call.
- Redirect-following is enabled (the default for most clients) and no post-redirect
  URL re-validation is performed.
- The target could resolve to RFC-1918 space (10.x, 172.16-31.x, 192.168.x),
  loopback (127.x, `::1`), or cloud metadata endpoints (`169.254.169.254`,
  `fd00::/8`).

Use Semgrep `access_ssrf` rules for a deterministic first pass, then walk the call
graph manually for indirect sources (e.g. URL stored in DB, fetched at request time).

**Evaluate:**

1. Is the URL value user-controlled, or is it a hardcoded constant / config value
   loaded at startup by an operator?
2. Is there an allowlist (exact hostnames or CIDR blocks) applied *before* the
   network call, not after?
3. Does the client follow redirects? If yes, is the redirected URL also allowlist-
   checked?
4. Can a DNS rebinding attack bypass a pre-resolution IP check?

Flag only call sites where user control can reach the network without a validated
allowlist on the final resolved address.

**Severity:** HIGH if the target can reach internal services, metadata endpoints, or
cloud credentials; MEDIUM if the target is network-reachable but restricted to
external hosts with no demonstrated internal path; LOW if URL is operator-configured
at deploy time with no runtime user influence.

**Common false positives:**

- Webhook delivery to a caller-supplied URL where the application documents that
  operators are responsible for allowlist configuration.
- Health-check pings to hardcoded internal endpoints where the URL is not user-
  influenced at runtime.
- Proxy pass-through where the upstream address is set in infrastructure config, not
  request parameters.

---

## Check 2: Resource Exhaustion — Unbounded allocation driven by user input

**Find:** Every request handler, file-upload endpoint, recursive function, and
external I/O call site. For each, determine whether a user-controlled value sets
or influences the bound on the resource consumed.

Use Semgrep `resilience_resources` rules for a deterministic first pass, then
manually inspect:

- File upload handlers: look for missing `max_length`, `MAX_CONTENT_LENGTH`,
  `Content-Length` ceiling, or file-count cap.
- Loops: look for `while`, `for`, and recursive calls whose termination condition
  or iteration count derives from a request field or response body without a
  hard ceiling.
- Memory allocation: look for `bytearray(n)`, `bytes(n)`, `Buffer.alloc(n)`,
  `make([]byte, n)` where `n` traces to user input.
- External calls: look for database queries, cache reads, and third-party API
  calls missing explicit `timeout`, `deadline`, `context.WithTimeout`, or a
  circuit-breaker wrapper (`hystrix`, `resilience4j`, `pybreaker`, `gobreaker`).

**Evaluate:**

1. Does the allocation size, iteration count, or recursion depth have a hard
   upper bound enforced before the resource is consumed?
2. For uploads: is there both a per-file size limit and a per-request file-count
   limit?
3. For external calls: does every call path have an explicit timeout that fires
   at a bounded wall-clock duration, or a circuit breaker that opens after a
   threshold of failures?
4. Is exhaustion scoped to the requesting session only, or does it degrade shared
   infrastructure?

**Severity:** HIGH if a single unauthenticated request can exhaust a shared resource
(memory, file descriptors, thread pool, external quota) causing service-wide
degradation; MEDIUM if the path requires authentication or the impact is session-
scoped; LOW if the allocation is bounded in practice by an upstream reverse-proxy
limit (document which limit and its value).

**Common false positives:**

- Streaming response bodies read in fixed-size chunks regardless of `Content-Length`.
- Upload size limits enforced by a reverse proxy or CDN where that configuration is
  verified and documented.
- Recursion on internal data structures (AST traversal, filesystem walk) where the
  depth is bounded by file-system or grammar limits, not user input.
- Timeouts set to a large-but-finite value (e.g. 300 s) for legitimately long-
  running jobs — flag only `0` / "no timeout" or genuinely unbounded values.

---

## Check 3: Unsafe Deserialization — Arbitrary object instantiation from untrusted data

**Find:** Every deserialization call site, including indirect ones. Use Semgrep
`data_deserialization` rules for a deterministic first pass, then manually trace:

- **Python:** `pickle.loads`, `pickle.load`, `marshal.loads`, `marshal.load`,
  `yaml.load(data)` without an explicit `Loader=yaml.SafeLoader` argument,
  `shelve.open` reading from a network-writable path.
- **Java:** `ObjectInputStream.readObject`, `XMLDecoder.readObject`,
  `XStream` without a whitelist, `Kryo` without class registration,
  `Jackson` with default typing enabled (`enableDefaultTyping`).
- **Ruby:** `Marshal.load` on untrusted input, `YAML.load` on Psych < 4 (Ruby < 3.1, where it is unsafe by default), or
  `YAML.unsafe_load` (not `YAML.safe_load`).
- **PHP:** `unserialize()` on user-supplied strings.
- **.NET:** `BinaryFormatter`, `NetDataContractSerializer`,
  `SoapFormatter`, `LosFormatter` on untrusted streams.
- **Indirect sites:** ORM hydration from cache (Redis/Memcached binary protocol),
  IPC consumers deserializing message payloads, session stores that pickle objects.

For each site, trace the data source: does untrusted user input (request body,
header, cookie, URL parameter, uploaded file, message-queue payload) reach the
deserializer without schema validation that constrains the set of instantiatable
types?

**Evaluate:**

1. Does the format permit arbitrary object instantiation (pickle, marshal, Java
   native, Ruby Marshal, PHP unserialize, .NET BinaryFormatter)? If yes and the
   input is untrusted, this is a direct flag regardless of claimed "internal-only"
   routing — verify that claim.
2. For YAML: is `yaml.safe_load` (Python), `YAML.safe_load` (Ruby), or an
   equivalent safe-loader class used consistently? Any bare `yaml.load(data)`
   without an explicit safe Loader is a flag.
3. For JSON: `json.loads` is generally safe for object instantiation; flag only
   if the result is passed to `eval`, `exec`, or a secondary deserializer.
4. Is the data source truly internal (same-process constant, operator-controlled
   config file loaded at startup)? If yes, severity is lower.

**Severity:** HIGH if an arbitrary-object-instantiation format is applied to any
data originating outside the process boundary (network, filesystem path writable
by non-privileged users, message queue); MEDIUM if the format is type-safe but
schema validation is absent or incomplete, permitting unexpected type coercion;
LOW if the deserializer operates on data that is operator-configured at deploy
time and not reachable at runtime by end users.

**Common false positives:**

- `pickle` used exclusively for inter-process communication between two processes
  running as the same trusted user with no network exposure — confirm no network
  socket bridges the pickle stream.
- `yaml.safe_load` call sites (the safe variant is not a finding).
- JSON deserialization into typed structs/dataclasses where no secondary dynamic
  dispatch occurs.
- ORM model hydration from a database that the application itself writes — flag
  only if an attacker can inject arbitrary bytes into that store via a separate
  vulnerability (document the dependency chain).

---

## Check 4: CORS Misconfiguration — Permissive cross-origin access

**Find:** Every location where `Access-Control-Allow-Origin` and related CORS
response headers are configured. Look for:

- **Reflected-origin:** Code that reads `req.headers.origin` (or equivalent) and
  echoes it directly into `Access-Control-Allow-Origin` without validating against
  an explicit allowlist of trusted origins.
- **Wildcard + credentials:** Configuration that sets both
  `Access-Control-Allow-Origin: *` and `Access-Control-Allow-Credentials: true`.
  (Most browsers reject this combination, but some framework defaults or middleware
  misconfigurations produce it.)
- **Dev-domain leakage:** Allowlists that include `localhost`, `127.0.0.1`,
  `*.local`, `*.dev`, or other development-only origins in a production configuration.
- **Overly broad pre-flight:** `Access-Control-Allow-Methods: *` or inclusion of
  `DELETE`, `PUT`, `PATCH` when only `GET` and `POST` are needed, combined with
  `Allow-Credentials: true`.

Use Semgrep `access_ssrf` rules as a supplementary pass, then manually inspect
CORS middleware configuration, API gateway settings, and per-handler header assignments.

**Evaluate:**

1. **Reflected-origin + Allow-Credentials:** Determine whether an attacker-controlled
   origin would be reflected. This enables credentialed cross-origin reads of API
   responses and, if the API lacks CSRF tokens, credentialed state mutation. Confirm
   the endpoint requires cookies or `Authorization` headers (i.e., credentials are
   relevant to the request).
2. **Dev origins in production:** Verify which environment the configuration is active
   in. A `localhost` entry in a production config is a finding; in a dev-only config
   that is never deployed, it is not.
3. **Wildcard-only (no credentials):** Apply the defence-in-depth check from
   `../triage/SKILL.md` Check 5. Wildcard CORS without credentials is LOW unless a
   concrete primary vulnerability exists that the CORS policy expands.
4. **Pre-flight permissiveness:** Flag only when `Allow-Credentials: true` is combined
   with broad method allowlists against state-mutating endpoints.

**Severity (per `../triage/SKILL.md` Check 5 CORS carve-out):**
- **HIGH**: reflected-origin + `Allow-Credentials: true` + state-mutating API without
  CSRF token — enables credentialed cross-origin state mutation.
- **MEDIUM**: reflected-origin + `Allow-Credentials: true` + read-only API — enables
  credentialed cross-origin data reads.
- **MEDIUM**: dev origin (`localhost`, `*.local`) included in a production allowlist.
- **LOW**: `Access-Control-Allow-Origin: *` without credentials — defence-in-depth gap.

**Common false positives:** Public APIs intentionally serving any origin (CDN assets,
public data APIs) with no credentialed access — `*` without credentials is by design.
CORS headers set only in a reverse proxy or CDN layer that is not in source — note
the gap but do not rate HIGH without confirmation the proxy config is absent.

---

## Check 5: File Upload Security — Web shell, path traversal, and zip slip

**Find:** Every endpoint that accepts file uploads (multipart form, streaming body,
base64-encoded field). The Quick Scope already lists file upload handlers; this check
provides the detailed evaluation criteria.

Look for:

- **Web shell upload:** File stored under a web-accessible path with no content-type
  or extension validation — an attacker can upload `shell.php`, `shell.aspx`, or
  `shell.jsp` and request it directly.
- **Magic-bytes bypass:** Extension is checked (allowlist of `.jpg`, `.png`, etc.)
  but the actual file content is not verified independently. An attacker can rename
  `shell.php` to `shell.jpg`.
- **Filename path traversal:** The `Content-Disposition` `filename` parameter is used
  in a path construction (`os.path.join(upload_dir, filename)`) without normalization
  or stripping of path separators — enables writing outside the intended upload
  directory with `../` sequences.
- **Zip slip:** `tarfile.TarFile.extractall()` (Python, before the 3.14 `filter='data'` default), `ZipInputStream` (Java),
  `Archive::Zip` (Ruby), or equivalent archive extraction without verifying that each
  entry's resolved path stays within the target directory. Enables arbitrary write via
  `../../etc/cron.d/malicious`.

**Evaluate:**

1. **Web shell:** Confirm the file is stored in a web-served directory (or symlinked
   to one) AND that no server-side script execution is disabled for that path (e.g.,
   nginx `location` block with `deny` for script execution). If the file is stored
   outside the web root or execution is disabled, downgrade to MEDIUM.
2. **Magic-bytes bypass:** Confirm the server checks only the `Content-Type` header
   or file extension, not actual file content (e.g., `file --mime-type` output or a
   library like `python-magic`). If content is independently verified, close this
   check.
3. **Path traversal:** Verify whether `os.path.realpath()` / `os.path.abspath()` or
   equivalent is called on the resolved path followed by a base-directory containment
   check (`resolved.startswith(upload_dir)`). Both steps are required; `basename()`
   alone is insufficient.
4. **Zip slip:** Verify each archive entry's resolved destination path is checked
   against the target directory before extraction. `tarfile` `extractall()` without path
   iteration or `filter='data'` is always a finding when the archive source is user-supplied.

**Severity:**
- **HIGH**: web shell upload to a web-accessible directory with script execution
  enabled (RCE); zip slip enabling arbitrary file write to a sensitive path
  (`/etc/`, application config, cron directory).
- **MEDIUM**: magic-bytes bypass with no clear execution path (file stored but not
  executable by the server); path traversal limited to the application's own data
  directory with no demonstrated privilege escalation.
- **LOW**: filename sanitization gap that allows special characters in filenames but
  cannot escape the upload directory.

**Common false positives:** Uploads processed in a sandboxed environment (Lambda,
Cloud Run, separate container) with no persistent filesystem and no web-serving of
uploaded files — confirm the storage and serving architecture before flagging.
Upload endpoints that immediately stream to object storage (S3, GCS) without local
disk writes — object storage does not serve scripts, so web-shell risk is absent.

---

## Rationalizations to Reject

Do not accept these justifications for skipping or downgrading an infrastructure
finding without completing the full evidence chain:

- **"Internal-only service"** requires network reachability verification before
  downgrading — run the Shodan lookup from triage Check 3, review ingress
  configuration, and check for SSRF chains before accepting a claim of internal
  isolation.
- **"Authenticated"** does not mean safe if authentication is weak, bypassable,
  or if the finding enables capability gain beyond what the authenticated role
  already possesses — apply triage Check 7 before downgrading on authentication
  grounds.
- **"SSRF target is external-only"** must be confirmed post-redirect — HTTP
  clients that follow redirects may reach RFC-1918 or metadata addresses after
  an initial external target; verify redirect-following behaviour.
- **"Upload size is limited by the reverse proxy"** requires confirming that
  configuration is present in the repository and enforced before the application
  handler — do not accept this claim without evidence in config files.

---

## Output Format

For each confirmed finding:

- **[INF-N]** · SEVERITY · Title
- **Location:** `file:line`
- **Evidence:** quoted code snippet showing the vulnerable call
- **Impact:** what the attacker achieves (e.g. "read EC2 instance credentials via
  metadata endpoint", "exhaust thread pool with a single request", "achieve RCE via
  pickle gadget chain")
- **Fix:** specific remediation (allowlist enforcement point, timeout value, safe
  loader substitution, etc.)

Number findings sequentially: INF-1, INF-2, … across all check categories.

**File-handoff (when `$OUTPUT_FILE` is set):** Write all findings to the path in
`$OUTPUT_FILE` and return only the following stub to the orchestrator:

```
{
  "domain": "INF",
  "output_file": "<$OUTPUT_FILE value>",
  "raw_counts": {"CRITICAL": N, "HIGH": N, "MEDIUM": N, "LOW": N},
  "status": "complete"
}
```

If `$OUTPUT_FILE` is not set, write findings to stdout as usual.

---

## Triage Gate

Before reporting any HIGH or CRITICAL finding, apply the fast-path checks from
`../triage/SKILL.md`. For infrastructure findings the most dispositive checks are:
network reachability (SSRF target reachability), availability scope (session vs
service-wide for DoS), and the trusted-service rule (SSRF to a service that enforces
its own auth may be lower severity).
