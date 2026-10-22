# SSRF Detection

Detect Server-Side Request Forgery vulnerabilities: outbound HTTP or DNS requests
whose target URL, host, or authority component derives from user-controlled input
without passing through a pre-call allowlist.

**Precision mandate:** Flag only findings where both conditions are unambiguously
established — (1) the URL or host value is user-controlled, and (2) no validated
allowlist is enforced before the network call is dispatched. When either condition
is uncertain, do not flag. Miss indeterminate cases rather than generate noise.

---

## Quick Scope

**HTTP client sinks — locate these call sites first:**

- **Python:** `requests.*`, `httpx.*` (sync/async client or session), `aiohttp.ClientSession.*`,
  `urllib.request.urlopen`, `urllib3.PoolManager().request`, `http.client.HTTP[S]Connection`
- **JavaScript/Node.js:** `fetch`, `axios.*`, `http.get`/`http.request`,
  `https.get`/`https.request`, `got`, `node-fetch`, `superagent.*`, `undici.*`
- **Java:** `new URL(…).openConnection()`, `RestTemplate.*`, `WebClient…uri(`,
  `HttpRequest.newBuilder().uri(`, `OkHttpClient…execute`, `CloseableHttpClient…execute`
- **Go:** `http.Get`, `http.Post`, `http.NewRequest`, `client.Do`, `http.DefaultClient`
- **Ruby:** `Net::HTTP.*`, `URI.open`, `open(` (open-uri), `Faraday.*`, `Typhoeus.*`,
  `HTTParty.*`, `RestClient.*`
- **PHP:** `curl_setopt($ch, CURLOPT_URL`, `curl_exec`, `file_get_contents($url`,
  `fopen($url`, `$client->*` (PSR-18), `Http::*` (Laravel), `HttpClient::create()->request` (Symfony)
- **C#:** `HttpClient.*Async`, `new HttpRequestMessage(`, `WebClient.*`,
  `WebRequest.Create`, `RestSharp.*`

**User-controlled sources — trace these to sinks:**

- Query params, body fields, headers, path params, cookies (`request.args.get(`,
  `req.body.*`, `req.headers[`, `req.params.*`, `req.cookies[`, and framework
  equivalents: `@RequestParam`, `@PathVariable`, `c.Query(`, `ctx.query.*`)
- JWT / OIDC claim fields — especially `picture`, `jku`, `x5u`, `iss` —
  attacker-controlled when the token is forged or claims are read before signature
  verification
- Forwarded host headers: `HTTP_X_FORWARDED_HOST`, Django `request.get_host()`
  with `USE_X_FORWARDED_HOST=True`, `req.headers['x-forwarded-host']`
- GraphQL resolver arguments: `args.url`, `args.target`, URL-typed named params
- WebSocket message fields: `JSON.parse(data).url`, `ws.on('message', …)` URL fields
- Redirect `Location` headers used as re-fetch targets (attacker-controlled when
  the initial request reaches an attacker's server)

**Allowlist / validation patterns that close a finding:**

Comparison must use **strict set membership** (`==`, `in`, `Set.contains`,
`Array.includes`). Substring, suffix, prefix, regex, or glob checks do NOT
close — all are bypassable via subdomain injection or URL decoration. Verify
no allowlist entry contains wildcard characters.

Accepted closing patterns (must be enforced BEFORE the network call):
- Exact hostname set membership: `if host not in ALLOWED_HOSTS:`, `if (!WHITELIST.has(parsed.hostname))`
- URL parse + **`.hostname`** comparison (not `.netloc` — that includes port/userinfo)
- Full-string anchored regex equivalent to exact equality (e.g., Java `String.matches("http://fixed\\.url")`)
- Scheme restriction AND hostname strict set membership together
- CIDR-based network-layer egress (not domain-name-only; config in-repo; covers
  decimal/hex/IPv6 IP forms)

**Residual risk:** Hostname allowlists permitting attacker-owned external domains are
vulnerable to DNS rebinding. Recommend IP-resolution validation post-allowlist for
high-risk deployments.

**Do not flag:**

- URL is a literal, env var, or startup config (not per-request). If an admin API
  can modify the backing value, rate MEDIUM rather than closing.
- URL has hardcoded scheme+host; only the path is user-controlled → path traversal
  risk, not SSRF (note it and close).
- Webhook URL registered exclusively by admin/operator users — verify from code,
  not documentation.
- Health-check pings to hardcoded internal endpoints.
- Applications whose **documented primary purpose** is user-configured HTTP requests
  (workflow automation, webhook engines, self-hosted search proxies) → output
  `[DEPLOY-REC]` instead of findings (see Output Format).

---

## Check 1: Direct URL Injection

**Find:** HTTP sink's URL argument traces directly to a user-controlled source with
no intervening transformation that fixes the host or scheme.

```python
# Python
url = request.args.get('url')
requests.get(url)                      # direct query param → sink
avatar_url = oidc_claims.get('picture')
requests.get(avatar_url)               # JWT claim source
```
```java
// Java
String url = request.getParameter("url");
new URL(url).openConnection();                         // stdlib
restTemplate.getForObject(url, String.class);          // RestTemplate
String jku = decodedJWT.getHeaderClaim("jku").asString();
new JwkProviderBuilder(new URL(jku)).build();           // jku SSRF during JWT verify
```

**Evaluate:**
1. Trace the URL variable to a request param, body, header, cookie, JWT claim, or
   WebSocket payload. If it terminates at a literal, env var, or startup config, close.
2. Confirm no allowlist gate between source and sink (strict set membership only;
   scheme-only checks do not close).
3. Confirm the URL controls the host, not only a path segment of a hardcoded base URL.

**Severity:** HIGH — no allowlist, no meaningful auth barrier. MEDIUM — requires auth,
or response is not returned to the caller (blind SSRF). Skip below MEDIUM.

**FPs:** env var URLs, startup config, hardcoded-host URLs with user-controlled path only.

---

## Check 2: URL Assembly

**Find:** URL passed to HTTP sink assembled by concatenation or interpolation where
the user-controlled value occupies the **host** or **scheme** position.

```python
# Python
url = f"http://{user_host}/api/data"
url = "http://" + request.args.get('host') + "/endpoint"
```
```js
// JavaScript
const url = `http://${req.body.server}/api`;
```

**Evaluate:**
1. Identify which URL component the user value occupies. Flag if host or scheme;
   close if only path or query of a hardcoded base URL.
2. Check for pre-call strict-set-membership host validation. Scheme-only check does
   not close (host can still target RFC-1918 or metadata).
3. Subdomain template `f"https://{tenant}.app.example.com/"`: flag unless `tenant`
   passes a server-side allowlist before assembly.

**Severity / FPs:** Same matrix as Check 1. FPs: user controls only path/query.

---

## Check 3: Redirect Following

**Applies when:** the initial URL is user-controlled (Check 1 or 2) AND the client
follows redirects without re-validating the redirected URL.

Most clients follow redirects by default: `requests`, `fetch`, `axios`,
Java `HttpURLConnection` (same-protocol), `RestTemplate`, Go `http.Client`,
C# `HttpClient`. Exceptions that do NOT follow by default: Ruby `Net::HTTP`,
PHP cURL. Disable with `allow_redirects=False` / `follow_redirects=False` /
`maxRedirects: 0` / custom `CheckRedirect` returning `http.ErrUseLastResponse`.

**BYPASS-10 — manual re-fetch:** Flag when `allow_redirects=False` is set but code
reads `response.headers['Location']` and re-fetches that URL without re-running the
allowlist check. The `Location` value is attacker-controlled when the initial
request reaches an attacker's server.

```python
r = requests.get(url, allow_redirects=False)
if r.is_redirect:
    r = requests.get(r.headers['Location'])   # no allowlist re-check — flag
```

**Evaluate:**
1. Confirm initial URL is user-controlled.
2. Confirm redirect following is not disabled.
3. Confirm no post-redirect URL re-validation.
4. Go `CheckRedirect`: depth-only limit does NOT close — requires unconditional
   `http.ErrUseLastResponse` or per-hop allowlist check on `req.URL.Host`.

**Severity:** HIGH when redirect can reach metadata endpoints or RFC-1918 services.

---

## Check 4: Indirect SSRF — stored URL fetched later

**Find:** (1) user input stored as a URL or webhook endpoint; (2) that value later
retrieved and used as an HTTP target without re-validation at fetch time.

Storage includes: DB tables, event bus / message queue, RSS/feed item URLs, job
queues, agent config columns, workflow parameters. Key property: URL written by
user input, read by a fetch operation without re-running an allowlist check.

**Multi-hop severity:**
- Two-hop (user stores → system fetches): HIGH if both steps are low-privilege.
- Three-hop (user stores → admin reviews without technical allowlist → system
  fetches automatically): MEDIUM — procedural gate only.
- Event-bus chain (user-configured feed URL → fetcher emits item URLs → downstream
  HTTP-fetch node uses those URLs without host validation): flag downstream node.

JWT claims flowing directly from token to HTTP call in the same request lifecycle
are Check 1, not Check 4 — there is no storage step.

**Evaluate:**
1. Storage step accepts user-supplied URL content (not an ID that maps server-side).
2. Fetch step uses stored URL without re-running an allowlist check.
3. Both steps reachable by attacker. Admin-only storage + automated fetch: MEDIUM.

**FPs:** stored URL re-validated at fetch time; only path stored with hardcoded base.

---

## Rationalizations to Reject

- **"Authenticated endpoint"** → MEDIUM, not closed.
- **"URL is validated"** → demand strict parsed-hostname set membership. Scheme-only,
  suffix, prefix, or regex checks do not close.
- **"Only external hosts reachable"** → invalid if client follows redirects; external
  target can redirect to `169.254.169.254`.
- **"Internal firewall blocks it"** → accept only if CIDR-based, evidenced by in-repo
  config, and pre-DNS-resolution. Otherwise, document as mitigating factor only.
- **"Response not returned"** → blind SSRF still enables port scanning and metadata
  timing inference. Retain at MEDIUM.
- **"Can't trace the source"** → if uncertain, do not flag.
- **"Check 7 (admin equivalent)"** → does NOT close SSRF to metadata/RFC-1918 outside
  admin scope. Retain at MEDIUM. Exception: apply triage Check 1 (Implication) if
  the admin role demonstrably implies OS-level server access (SSH, container exec).

---

## Output Format

For each confirmed finding:

- **[SSRF-N]** · SEVERITY · Title
- **Location:** `file:line`
- **Evidence:** quoted code snippet showing the sink and where the URL originates
- **Trace:** `source:line → sink:line` (required for HIGH findings; omit for MEDIUM)
- **Redirect risk:** yes or no (Check 1 and 2 findings only)
- **Impact:** what the attacker achieves (internal probing, metadata credential theft,
  blind port scan, SSRF-to-RCE via internal service, etc.)
- **Fix:** parse URL, extract `.hostname` (not `.netloc`), validate against a strict
  allowlist before the HTTP call; re-validate after each redirect hop if following
  redirects; consider resolving hostname to IP and blocking RFC-1918/loopback/link-local.

Number findings SSRF-1, SSRF-2, … Consolidate findings sharing the same root cause
(same unvalidated source → same shared component → multiple sinks) into one finding
with an "Affected locations" list. Keep separate only when severity, fix, or access
controls differ.

**DEPLOY-REC:** For apps whose primary purpose is user-configured HTTP calls, emit
instead of SSRF-N findings:
```
[DEPLOY-REC] · Network Egress Controls Required
Enforce egress rules blocking RFC-1918, loopback (127.0.0.0/8, ::1), link-local
(169.254.0.0/16, fe80::/10), and cloud metadata endpoints at the
firewall/security-group level.
```

**File handoff:** If `$OUTPUT_FILE` is set, write findings there and return only
`{"domain":"SSRF","output_file":"<path>","raw_counts":{"HIGH":N,"MEDIUM":N},"status":"complete"}`
to the orchestrator. Otherwise write to stdout.

---

## Triage Gate

Before reporting any HIGH finding:

1. **Step 0 (Plain-Language Restatement)** from `../triage/SKILL.md`: answer who,
   what action, what trigger, what capability gained. If any is unanswerable, close.
2. **Check 2 (Plausibility):** Confirm the URL source is genuinely attacker-reachable
   without prior system compromise.
3. **Check 3 (Network Reachability):** For MEDIUM findings asserting no internal path
   exists, apply the Shodan procedure to the host's public IP if determinable.
4. **Check 7 (Authenticated-Admin):** Does NOT close SSRF to metadata/RFC-1918 outside
   admin scope — retain at MEDIUM. Exception: triage Check 1 (Implication) if admin
   role demonstrably implies OS-level server access.
5. **Trusted Service Failures** from `../triage/SKILL.md`: if the threat requires an
   allowlisted external service to behave maliciously, downgrade or close.

SSRF to an internal service with its own authentication may warrant MEDIUM downgrade —
evaluate whether that auth provides meaningful protection against unauthenticated RFC-1918
calls.
