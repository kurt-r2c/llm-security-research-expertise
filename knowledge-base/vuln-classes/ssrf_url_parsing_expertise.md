# SSRF, Open Redirect, and URL Parser Differentials — Primitives and Defenses
## Synthesized from Orange Tsai, James Kettle, Frans Rosén, Nick Frichette, Mark Yason, Daniel Stenberg, Sam Sanoop, and Kurt Boberg

> **Researchers:**
> - **Orange Tsai** (@orange_8361) — DEVCORE Principal Security Researcher; Black Hat USA 2017
>   "A New Era of SSRF: Exploiting URL Parsers in Trending Programming Languages." The canonical
>   taxonomy of URL parser differentials: validator-parser vs fetcher-parser divergence, IPv6
>   zone identifier ambiguity, hex/octal/decimal IP normalization, the `http://attacker.com#@victim/`
>   class. Author of multiple GitHub Enterprise SSRF-to-RCE chains (2017).
> - **James Kettle** (@albinowax) — Director of Research, PortSwigger. Black Hat USA 2017 "Cracking
>   the Lens: Targeting HTTP's Hidden Attack-Surface." Pioneered the SSRF-via-routing-fabric
>   class: reverse proxy header injection, host-header SSRF, the
>   Collaborator-Everywhere methodology for at-scale blind SSRF discovery. Earned $33,000 in
>   bounties demonstrating the technique.
> - **Frans Rosén** (@fransrosen) — Detectify Security Advisor; long-running
>   bug-bounty practitioner ranked #2 on HackerOne's all-time hall of fame. Frequent Detectify
>   Labs author on SaaS-context SSRF.
> - **Nick Frichette** (@frichette_n) — Staff Security Researcher, Datadog; creator and primary
>   maintainer of Hacking the Cloud. The de-facto reference for AWS exploitation primitives
>   reachable through SSRF: IMDS credential theft, Lambda IAM-role pivot, ECS task metadata,
>   IMDSv2 hop-limit hardening and bypass classes.
> - **Mark Vincent Yason** — Independent security researcher, formerly IBM X-Force Advanced
>   Research; Black Hat Asia 2014 "Diving Into IE 10's Enhanced Protected Mode Sandbox," Black Hat USA 2015
>   "Understanding the Attack Surface and Attack Resilience of Project Spartan's New EdgeHTML
>   Rendering Engine."
> - **Daniel Stenberg** (@bagder) — curl maintainer (since 1996); author of the "everything-curl"
>   reference and the URL-interop position paper ("My URL Isn't Your URL," 2016 →
>   "The URL Interop Situation," ongoing). Documented the irreconcilable gap between RFC 3986
>   and the WHATWG URL Living Standard; landed the libcurl URL parser API in 2018 so applications
>   can stop mixing parsers.
> - **Kurt Boberg** (@kurt-r2c) — Staff Security Researcher, Semgrep; previously r2c. Three
>   publicly-credited CVEs in this cluster: CVE-2022-24794 (Auth0 express-openid-connect open
>   redirect via Express `req.originalUrl` double-slash), CVE-2022-0235 (node-fetch secure-header
>   forwarding across cross-origin redirects, fixed in 2.6.7 / 3.1.1), GHSA-gf8q-jrpm-jvxq
>   (node-forge `forge.util.parseUrl` regex-based URL parser, removed in 1.0.0 in favor of
>   WHATWG URL).
>
> Sources: Black Hat 2017 papers (Tsai, Kettle); blackhat.com/docs/us-17/; labs.detectify.com;
> hackingthe.cloud; daniel.haxx.se; everything.curl.dev; snyk.io/blog; GitHub Security Advisory
> Database (GHSA-7p99-3798-f85c, GHSA-r683-j2x4-v87g, GHSA-gf8q-jrpm-jvxq); NVD; RFC 3986; RFC
> 6749; RFC 7230; RFC 9700; WHATWG URL Living Standard.

---

## 1. The Trust Boundary — Why URLs Are Universally Misparsed

### Three specifications, none of them aligned

A URL is a small string. In every codebase you read, that string crosses an API boundary
between something that **parses** the URL (validator, router, authorizer) and something that
**dereferences** it (HTTP client, redirect emitter, SAML responder). If the two operations
disagree about what the bytes mean, the application has a vulnerability.

This disagreement is endemic because three incompatible specifications coexist in production:

1. **RFC 3986** (January 2005) — "URI: Generic Syntax." The IETF ABNF grammar. curl, libcurl,
   Java `java.net.URI`, Go `net/url`, Python `urllib.parse`, Ruby `URI` all aim at RFC 3986
   compliance with varying fidelity.
2. **RFC 7230** (June 2014) — "HTTP/1.1: Message Syntax and Routing." Defines an HTTP-specific
   `request-target` syntax that differs from RFC 3986 on absolute vs origin-form, userinfo
   handling, and `Host:` header semantics.
3. **WHATWG URL Living Standard** (2012-present, continuously revised) — Browser-aligned, owned
   by WHATWG. Explicitly diverges from RFC 3986 to model what browsers do (backslashes as
   separators, whitespace stripping, scheme-relative URLs, `data:`/`blob:` handling). Used by
   modern browsers, Node `new URL()`, and the Ada URL parser library.

curl's [URL syntax documentation](https://curl.se/docs/url-syntax.html):
"The WHATWG URL spec was written later, is incompatible with the RFC 3986 and changes over
time… it is considered a security risk to mix different implementations and assume the same
behavior."

For staff-level review purposes: **any time a codebase performs URL validation and URL fetching
with two different parser implementations, you have a parser-differential SSRF or open-redirect
candidate.** The bug is not in either parser; it's that both parsers exist in the same data flow.

### The userinfo ambiguity

The RFC 3986 grammar for the authority component is:

```
authority   = [ userinfo "@" ] host [ ":" port ]
userinfo    = *( unreserved / pct-encoded / sub-delims / ":" )
```

This allows `https://user:pass@example.com/`. The `host` is `example.com`. The `userinfo` is
`user:pass`. So far, every parser agrees.

Orange Tsai's seminal observation in "A New Era of SSRF" is what happens at the **boundaries**
of this grammar. Consider these strings:

| String | RFC 3986 host | Some parsers see host as | Some parsers fetch |
|---|---|---|---|
| `http://victim.com#@attacker.com/` | `victim.com` | `attacker.com` (Python urllib before the 2017 bpo-30500 fix) | varies |
| `http://attacker.com#@victim.com/` | `attacker.com` | `victim.com` (some Ruby parsers) | varies |
| `http://victim.com\@attacker.com/` | `victim.com\` (invalid) | `attacker.com` (backslash read as a userinfo character; WHATWG treats `\` as `/` and sees `victim.com`) | varies |
| `http://[::1]:80@attacker.com/` | Invalid (`[`/`]` not allowed in userinfo) | `attacker.com` (parser misreads IPv6 bracket) | varies |
| `http://user@victim.com@attacker.com/` | Implementation-defined | first or second hostname | varies |

Tsai demonstrated each of these against built-in URL libraries in Python, PHP, Perl, Ruby, Java,
JavaScript, Wget, and curl, producing divergent parses across pairs. The exploit is the
divergence itself — pick the pair (validator-parser, fetcher-parser) where the validator says
"safe external host" but the fetcher dereferences "internal host."

### The host portion is not one thing

`host` in RFC 3986 is the union of `IP-literal` (bracketed IPv6/IPvFuture), `IPv4address`, and
`reg-name` (DNS-style names). Parser-specific edges relevant to SSRF defense:

- **IPv6 zone identifiers** (`fe80::1%eth0`): RFC 6874 percent-encodes as `%25eth0`. Validators
  that strip zone IDs before checking link-local blocklists vs those that don't diverge.
- **IPv4-in-IPv6** (`::ffff:127.0.0.1` ↔ `::ffff:7f00:1`): loopback in IPv6 form.
- **Hex/octal/decimal IPv4** (`0x7f000001`, `017700000001`, `2130706433` for `127.0.0.1`):
  POSIX `inet_aton(3)` accepts all four notations and mixed forms. URL parsers normalize one
  form; socket-level fetchers accept what the kernel accepts.
- **DNS resolution side-effects**: a forward-DNS check is TOCTOU vs the fetch's re-resolution.
  See section 6 for DNS rebinding.
- **IDNA**: validators that don't IDNA-normalize while fetchers do (or vice versa) see
  different hosts.

### Path normalization disagreements

`/a/../b` vs `/b` vs `/a/%2e%2e/b` vs `/a/.%2e/b` vs `/a%2f..%2fb`: RFC 3986 §5.2 defines a
canonical path-merging algorithm, but very few real parsers implement it identically.
Reverse proxies, application routers, validators, and origin servers each do their own
normalization, and the gaps between them produce SSRF and authorization bypasses. James Kettle's
"Cracking the Lens" exploited this class extensively against reverse proxies and CDNs.

For open-redirect purposes (section 4), the relevant gap is between the **validator** that
checks if a redirect target is a relative path and the **fetcher/responder** that interprets
the path. `//attacker.com/` is a relative path under one reading and a protocol-relative URL
under another.

### Scheme registration and pseudo-schemes

URI schemes are open-ended. Validators that allowlist `http`/`https` must still constrain what
the fetcher accepts: `data:` (inline content with JS in HTML form), `javascript:` (XSS),
`blob:` (same-origin blob references), `file:` (local-file read via SSRF), `gopher:` (raw TCP
send-anything — the universal SSRF-to-Redis pivot; curl 7.65.2 dropped it from the default redirect protocols),
`ftp:`/`tftp:`/`dict:`/`ldap:`/`imap:`/`smtp:` (libcurl defaults), `chrome://`/`intent:` (mobile
WebView intent-redirect). Defensive principle: **scheme allowlist, not blocklist**, applied at
the validator AND reaffirmed at the fetcher (`CURLOPT_PROTOCOLS_STR`, per-call
`protocols=['https']`, SDK-level scheme allowlists).

---

## 2. SSRF — The Canonical Attack

### Pattern: attacker controls where the server fetches

Every SSRF reduces to the same shape. A code path on the server fetches a URL. Some portion of
that URL is influenced by user input. The application's network position — typically inside a
VPC, on a private subnet, or with IAM credentials attached to the instance role — is fundamentally
more privileged than the attacker's. The attacker reaches inside the perimeter by inducing the
server to make the request.

```python
# The canonical sink (any language, any HTTP client):
url = request.get_json()["webhook_url"]   # attacker-controlled source
requests.get(url)                          # privileged fetch
```

This is the architecture. The vulnerability is the architecture. Patching the parser, blocklisting
the destination, adding regex validation — these are defenses against specific exploitation
techniques, not against the underlying class.

### Three canonical substrates

~90% of high-impact SSRF lives in three patterns:

**1. Webhook receivers.** User-configured URLs for outbound notification (Slack/Stripe/GitHub
style). The URL is user input; the fetch is privileged.

**2. Image/preview fetchers.** OG-cards, thumbnails, avatar URLs, "import from URL" features,
HTML-to-PDF generators that fetch by URL.

**3. Federated identity** (OIDC, SAML, SCIM). OIDC discovery
(`<issuer>/.well-known/openid-configuration`), SAML metadata, SCIM resource URLs. The URL is
"trusted" in the threat model because the tenant admin chose it — but tenant admins are
malicious in multi-tenant SaaS.

Other recurring substrates: PDF-to-HTML converters (Gotenberg/wkhtmltopdf class), agent/LLM
tool execution (section 9), serverless URL-argument invocation, "fetch this asset to my CDN"
APIs.

### Cloud-metadata SSRF: the canonical chain

The highest-impact SSRF target is the cloud provider's instance metadata service:

| Cloud | Endpoint | Auth | Reward |
|---|---|---|---|
| AWS | `169.254.169.254/latest/meta-data/iam/security-credentials/<role>` | IMDSv1: none; IMDSv2: PUT token, hop-limit 1 | IAM role credentials |
| GCP | `metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token` | `Metadata-Flavor: Google` | SA OAuth2 token |
| Azure | `169.254.169.254/metadata/identity/oauth2/token` | `Metadata: true` | Managed-identity token |
| Oracle | `169.254.169.254/opc/v2/instance/` | `Authorization: Bearer Oracle` | Instance principal creds |
| DigitalOcean | `169.254.169.254/metadata/v1.json` | None | Droplet metadata (no IAM) |

AWS IMDS is canonical because the resulting credentials are short-lived but fully
fungible once exfiltrated. Frichette's
[Hacking the Cloud](https://hackingthe.cloud/aws/exploitation/ec2-metadata-ssrf/) is the
authoritative reference.

**IMDSv1 vs IMDSv2.** IMDSv1 (GET-without-headers) is exploitable by any HTTP-URL SSRF. IMDSv2
(2019) requires PUT-to-get-token-then-GET-with-token plus 1-hop default response TTL. SSRF
primitives rarely permit arbitrary headers AND PUT method, and the 1-hop limit drops requests
proxied through internal services. IMDSv2 is not default for pre-2019 instances.

### DNS rebinding for SSRF — TOCTOU between validation and fetch

The defensive pattern most applications reach for is: resolve the URL's hostname to an IP,
check the IP against a blocklist (private ranges, loopback, link-local), and proceed if it's
public. This pattern is **always** vulnerable to DNS rebinding.

The attack:

```
1. Attacker registers attacker.com with a DNS server they control.
2. Attacker configures attacker.com to return:
   - First response: TTL=0, A record 203.0.113.42 (public)
   - Subsequent response: TTL=0, A record 169.254.169.254 (IMDS)
3. Application resolves attacker.com → 203.0.113.42 → validator passes (public IP).
4. Application's HTTP client re-resolves attacker.com for the fetch → 169.254.169.254 → IMDS hit.
```

The window is the gap between validation-resolution and fetch-resolution. In Node.js, Go,
Python, and most stdlib HTTP clients, the two operations are independent DNS lookups by default.
The defense is **DNS pinning**: resolve once, validate the resolved IP, then pass the resolved
IP directly to the HTTP client (with the original hostname only as `Host:` header for SNI/vhost
routing). See section 8.

The DNS rebinding class is enjoying a 2024–2026 renaissance against LLM tool-execution
endpoints. Multiple advisories in the last 12 months — Craft CMS (CVE-2026-27127),
langchain-openai (GHSA-r7w7-9xr2-qq2r), Postiz (GHSA-f7jj-p389-4w45), WeKnora
(GHSA-h6gw-8f77-mmmp), Gotenberg (CVE-2026-42592) — all document the same bug:
`isSafeURL(url)` performs DNS lookup #1, `fetch(url)` performs DNS lookup #2, attacker times
the rebind. Cross-link to `dns_network_infrastructure.md` for DNS rebinding mechanics in
general.

### file:// scheme — the silent SSRF subclass

When a fetcher supports `file://` and the validator accepts any scheme, the attacker reads
arbitrary local files. `file:///etc/passwd` is the canonical probe. Subclasses worth flagging
in review:

- **libcurl-based clients** support `file://` by default. Disable via
  `--proto =https` or `CURLOPT_PROTOCOLS_STR`.
- **Java's `URL.openConnection()`** supports `file://`, `jar:file://`, `ftp://`. The `jar:file:`
  scheme is particularly nasty because it implies reading + parsing an archive — historically
  exploitable through ZIP path traversal.
- **PHP wrappers** (`php://filter`, `php://memory`, `expect://`, `phar://`) extend the surface
  further. `phar://` deserialization is its own CVE class (Sam Thomas's
  "It's a PHP Unserialization Vulnerability Jim, but Not as We Know It," Black Hat USA 2018).

### gopher:// and the protocol-pivot subclass

`gopher://` is the universal SSRF-to-arbitrary-protocol primitive. The format
`gopher://target:port/_<URL-encoded raw bytes>` tells curl-class clients to send raw bytes to
the target. With Redis (6379), memcached (11211), MySQL (3306), SMTP (25), or FastCGI (9000)
colocated, SSRF becomes arbitrary protocol interaction. Redis is canonical because it defaults
to no auth and supports `CONFIG SET dir`/`dbfilename`/`SAVE` for cron-file writes. Gopherus
(Tarunkant Gupta, 2018) automates payload generation for Redis, memcached, MySQL,
PostgreSQL, FastCGI, SMTP, and Zabbix. CVE-2022-0543 (Redis Lua sandbox escape) extends this
to a single-shot RCE primitive on Debian/Ubuntu-packaged Redis. Cross-link to
`dns_network_infrastructure.md` and `container_k8s_security.md`.

---

## 3. URL Parser Differentials — Orange Tsai's Seminal Taxonomy

### The validator-parser vs fetcher-parser frame

Tsai's foundational insight is methodological: the vulnerability lives in the **gap** between
two URL operations. Ask: which library parses the URL during validation? Which parses it during
dereference? If the answers differ, every byte where they disagree is exploitation surface.

Common pairs in production:

| Validator | Fetcher | Known divergences |
|---|---|---|
| Python `urlparse` | `requests`/urllib3 | bracket-mismatch IPv6, RFC-3986 deviations |
| Node `new URL(x).hostname` | `http.request({hostname})` | IPv4-mapped IPv6 normalization |
| Python `urlparse` | curl subprocess | Tsai's classic divergence pair |
| Ruby `URI.parse` | `Net::HTTP.get` | `userinfo@host@host` forms |
| Java `java.net.URL` | `URLConnection.openConnection` | bracket-less IPv6 |
| Custom regex validator | Any fetcher | Regex never models the full grammar — always a candidate |

### The taxonomy of parser divergences (from "A New Era of SSRF")

Grouped by category:

**1. Userinfo confusion.** `http://victim.com#@attacker.com/` (fragment-as-userinfo —
parsers that miss the `#` see different hosts); `http://attacker.com\@victim.com/`
(backslash-as-separator — WHATWG normalizes to `/`, RFC 3986 doesn't);
`http://google.com:@attacker.com/` (empty-password userinfo).

**2. IPv6 zone-ID parsing.** `http://[::1%25eth0]/` (RFC 6874 percent-encoded);
`http://[::1]:80@attacker.com/` (bracketed IPv6 in userinfo position).

**3. IPv4 numeric normalization.** `http://0x7f000001/` (hex), `http://2130706433/` (decimal),
`http://017700000001/` (octal), `http://127.1/` (truncated — `inet_aton` 1/2/3/4-component
forms), `http://127.0.0.1.nip.io/` (wildcard DNS). Validators matching `^127\.0\.0\.1$` miss
all five.

**4. IPv4-in-IPv6.** `http://[::ffff:127.0.0.1]/` ↔ `http://[::ffff:7f00:1]/` — same address,
different string. Node's WHATWG parser normalizes one direction; validators checking literal
string form miss the normalized form.

**5. Scheme-relative confusion.** `//attacker.com/` (scheme-relative — becomes
`https://attacker.com/` if validator only checks `^/`); `/\attacker.com/` (backslash-then-slash
normalized to `//` in WHATWG).

**6. Whitespace and tab stripping.** `http://attacker.com\t/` — WHATWG strips ASCII whitespace
and control chars; RFC 3986 parsers may treat the tab as a parse error or include it in the host.

### Kurt Boberg's node-forge URL parser CVE (GHSA-gf8q-jrpm-jvxq)

This vulnerability sits squarely in the Tsai taxonomy. node-forge `forge.util.parseUrl` is (was)
a regex-based URL parser used internally by node-forge's TLS and HTTP-utility paths. The regex
modeled a subset of the URL grammar but missed enough corner cases that the parsed `host`,
`path`, and `scheme` fields could be made to disagree with what a fetcher would actually
dereference if given the same URL.

The advisory (GHSA-gf8q-jrpm-jvxq) is intentionally vague about the specific malformed inputs —
the maintainer's correct response was to **remove the API in 1.0.0** rather than patch it,
because URL parsing via regex is permanently broken. The recommended migration is to the
WHATWG URL Standard API (`new URL()` in modern Node), which has the virtue of being a single
well-defined implementation shared with the broader ecosystem.

This is the right architectural fix and aligns with Stenberg's principle: **applications that
use libcurl should use the libcurl URL API**, not their own parser. Applications that use
WHATWG URLs at the fetch layer should use WHATWG URLs at the validation layer too. Don't mix.

### The Python urllib vs urllib3 vs requests divergence

The canonical multi-parser pitfall: code uses `urllib.parse.urlparse(url).hostname` for a
blocklist check, then passes the unmodified `url` to `requests.get(url)`. Three parsers see
this URL — `urlparse` (RFC 3986), urllib3 (drives requests), and `socket.getaddrinfo` (name
resolution). Divergences with CVE history: bpo-30500 (Tsai-reported fix to
urllib host splitting for `http://127.0.0.1#@host.com/`); `urlparse(url).hostname` does no DNS, but `requests.get(url)` does — the
blocklist doesn't catch `http://my-private-dns-name/` that resolves private.

Defense: parse with strict parser → resolve hostname → check resolved IP → pass the resolved
IP (not the hostname) to the HTTP client. See section 8.

### The Node WHATWG URL vs legacy `url.parse` divergence

Node ships two URL parsers. `url.parse(input)` is the legacy parser (deprecated in Node 11, reclassified as
Legacy in 14.17/15.13, application-deprecated in Node 24, but still widely used). `new URL(input)` is the WHATWG parser. They give different answers for
many inputs:

| Input | `url.parse(x).hostname` | `new URL(x).hostname` |
|---|---|---|
| `http://[::ffff:127.0.0.1]/` | `::ffff:127.0.0.1` | `[::ffff:7f00:1]` |
| `http://EXAMPLE.com/` | `example.com` | `example.com` |
| `http://example.com:80/` | `example.com` | `example.com` (port stripped from `hostname`) |

Codebases that mix the two — validator using `url.parse`, fetcher using `fetch()` (which uses
WHATWG) — are differentially exploitable. Cross-link to `code_review_expertise.md`'s
"User-input paths must be resolved AND verified" heuristic: the same logic applies to URLs.

---

## 4. Open Redirect — The Easy Cousin

### Why "low severity" is wrong for open redirect

Open redirect is conventionally rated low/medium because the immediate impact is "the user
lands on attacker.com" — a phishing primitive. The framing is wrong in three contexts:

**1. Token theft in OAuth flows.** Any OAuth/OIDC flow issuing an authorization code or access
token to a `redirect_uri` is full account takeover if `redirect_uri` is controllable. RFC 9700
mandates exact-match validation specifically to close this.

**2. Bearer-token leakage on redirect.** When the HTTP client follows an open redirect to
attacker-controlled host without stripping credentials, you have the node-fetch class
(section 5). Open redirect is the trigger; header-forwarding is the payload.

**3. Trust transfer.** Modern phishing kits (Modlishka/EvilGinx-class 2023+) leverage open
redirects to present continuations of legitimate flows, defeating MFA via real-time relay.

Treat open redirect as **MEDIUM at minimum** in flows crossing an authentication boundary, and
as **HIGH** when the affected URL is OAuth `redirect_uri`, SAML `Destination`/`ACS URL`, or any
auth callback. Cross-link to `code_review_expertise.md` for click-count severity reasoning.

### Kurt Boberg's CVE-2022-24794 — express-openid-connect (Auth0)

GHSA-7p99-3798-f85c, fixed in 2.7.2. The post-login middleware did `res.redirect(req.originalUrl)`.
For a request to `http://example.com//google.com`, Express sets
`req.originalUrl = "//google.com"`. The browser interprets the redirect to `//google.com` as
scheme-relative — post-login, the user lands on attacker-controlled `google.com`.

Structural bug: the middleware trusted `req.originalUrl` as a path, but Express preserves
double-slash forms that the browser interprets as scheme-relative URLs. Validator (implicit,
"it's a path because Express said so") and fetcher (browser following `Location:`) disagree
about what `//google.com` means. Fix normalizes the path before reuse. The fix sits in the
middleware that consumes Express's output — middleware is responsible for re-validating any
string it intends to use in a security-sensitive context. Cross-link to `http_web_security.md`
and `distributed_authz_expertise.md`.

### OAuth redirect_uri validation — exact match or no match

RFC 9700 §2.1 (BCP for OAuth 2.0 Security, January 2025) is unambiguous: "When comparing
client redirection URIs against pre-registered URIs, authorization servers MUST utilize exact
string matching except for port numbers in localhost redirection URIs of native apps." RFC
6749 §3.1.2 (2012) was permissive and produced a decade of bypass CVEs against major IdPs;
9700 codified the lesson.

Failure modes that exact-match defends against: prefix match
(`https://app.example.com.attacker.com/` matches `startswith("https://app.example.com")`),
wildcard/regex match (`https://*.example.com/` registered, subdomain takeover or misparse),
path-suffix match (`https://app.example.com/callback/../redirect?to=attacker.com`), fragment
or query inconsistency between registration and runtime check.

Right design: register full URLs at app-registration time; reject everything else at runtime.

### Relative-URL and scheme-relative open redirect

A `Location:` value of `//attacker.com/` is interpreted by browsers as scheme-relative — the
browser keeps the current scheme and replaces the host. Many validators check
`if value.startswith("/")` and accept anything that does, missing `//attacker.com` entirely.
Kurt's CVE-2022-24794 is exactly this at a different layer. Related: `/\attacker.com/` is
normalized by Chromium to `//attacker.com/` per WHATWG's "special scheme" backslash rule.

Defense recipe for redirect targets: parse with a strict parser; if a scheme is present, it
must be `http`/`https`; if a netloc is present, it must be in the allowed-hosts set; if no
netloc, the path must start with single-slash AND not with `//`, `\\`, `/\`, or `\/`. Even
better: don't accept absolute redirect targets at all — accept a registered identifier
(`{"return_to": "dashboard"}`) and map server-side to a known URL.

### SAML RelayState — open-redirect-by-design

In SAML 2.0, `RelayState` is an opaque parameter the SP sends to the IdP at auth time and the
IdP echoes back. The intent: SP-encoded post-auth destination (deep link or session
identifier). Many SAML implementations treat `RelayState` as a URL and redirect to it after
assertion validation — open redirect by default unless the SP applies an allowlist (see
directus GHSA-3573-4c68-g8cc). Same applies to OIDC `state` when misused as a return-URL slot,
or any "callback completion URL" mechanism. Rule: never treat an opaque token as a URL without
revalidation, even when the protocol allows it.

### Target=_blank and noopener

Hyperlinks rendered with `target="_blank"` historically retained a `window.opener` reference
allowing the linked page to navigate the original tab — the "reverse tabnabbing" attack.
Modern browsers (Chromium 88+, Firefox 79+, Safari 12.1+) default to `rel="noopener"` for
`target="_blank"`, but server-rendered HTML with attacker-controlled link URLs remains an
open-redirect-adjacent vector requiring an allowlist.

---

## 5. Header-Forwarding Attacks

### Kurt Boberg's CVE-2022-0235 — node-fetch

GHSA-r683-j2x4-v87g, affecting `node-fetch` <2.6.7 and 3.0.0–3.1.0: on a cross-origin 3xx
redirect, `node-fetch` re-issued the request with `Authorization`, `WWW-Authenticate`,
`Cookie`, and `Cookie2` preserved. An application making an authenticated outbound fetch with
a Bearer token to a user-supplied URL leaks the token if the URL redirects to attacker-
controlled host — combine with any SSRF substrate (webhook, image, OIDC discovery) for
end-to-end credential theft. The fix in 2.6.7/3.1.1 strips the listed headers when origin
changes (curl pattern: `--location-trusted` / `CURLOPT_UNRESTRICTED_AUTH` opt-in). CWE-173/200/601, CVSSv3 8.8 HIGH.
Reporter: kurt-r2c (Kurt Boberg, then at r2c).

### ### The header-forwarding class generalizes

HTTP clients make divergent decisions about what to forward across redirects:

| Library | Behavior |
|---|---|
| `libcurl` | Strips `Authorization` cross-host since 7.10.4; `--location-trusted` / `CURLOPT_UNRESTRICTED_AUTH` opt-in |
| `Python requests` | Strips cross-host; CVE-2018-18074 (Authorization sent on same-host https→http redirect) |
| `Python urllib3` | Strips since 1.23; CVE-2018-20060 (Authorization kept on cross-origin redirect) |
| `node-fetch` | Did NOT strip pre-CVE-2022-0235; now strips since 2.6.7/3.1.1 |
| `Go net/http` | Strips since Go 1.8 (2017) |
| `Java HttpURLConnection`, OkHttp, Apache HttpClient | Implementation-defined |

The class extends to non-`Authorization` credentials: `Cookie`/`Cookie2` (most non-browser
clients don't strip cross-origin), `Proxy-Authorization` (should never leave the proxy hop —
CVE history shows it sometimes did), custom auth headers (`X-API-Key`, `X-Auth-Token`,
vendor-specific tokens — almost universally **not** stripped because the client can't infer
which headers are credential-bearing).

Posture: **disable automatic redirect-following** in any code path that sends credentials.
Handle redirects manually with explicit per-redirect credential-stripping and a max-redirect
count. Cross-link to `http_web_security.md` for the broader HTTP-client hardening checklist.

### Worked example — webhook receiver with bearer token

A common SaaS pattern: an integration accepts a webhook URL and signs outbound requests with
a tenant-specific Bearer token via `fetch(webhookUrl, {headers: {Authorization: "Bearer ..."}})`.
If `fetch` is pre-fix node-fetch 3.0.0 and the tenant configures their webhook URL as
`https://my-redirector.example.com/`, the redirector returns `302 Location: https://attacker.com/`.
The HTTP client follows the redirect, sending the Bearer token to `attacker.com`.

The structural defense, even on patched clients: set `redirect: "manual"`, examine the
`Location:` header, re-issue without the credential if the origin changed, and enforce a max
redirect count. For sensitive webhook deliveries, prefer **payload signing instead of bearer
auth**: HMAC-SHA256 over the request body with a tenant-shared secret. The signature is
verifiable post-redirect but not reusable.

### Cookie forwarding to redirect

When a session cookie is `HttpOnly` but the HTTP client follows redirects with the cookie
attached, the redirected destination receives the cookie — bypassing the `HttpOnly` flag's
intent (which protects against JS-readable theft, not server-side exfiltration). Non-browser
HTTP clients (Selenium, Playwright, server-to-server fetchers) typically respect cookies
cross-origin unless explicitly told otherwise. Any internal-tool fetcher handling authenticated
state via cookies is an SSRF-amplified credential-theft candidate if redirects are followed.

---

## 6. Modern SSRF Chains

### SSRF → IMDS → IAM credentials → AWS pivot

End-to-end: SSRF (webhook / image-import / OIDC issuer URL) → attacker submits
`http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>` → server
fetches IMDS → response is JSON with `AccessKeyId`/`SecretAccessKey`/`Token` → attacker
exfils (response-reflection, image-format abuse, gopher/DNS OOB) → attacker runs `aws s3 ls`
etc with short-lived credentials. The role's IAM policy determines blast radius. ECS task
roles, Lambda execution roles, and EC2 instance profiles commonly hold `s3:GetObject`,
`dynamodb:*`, `secretsmanager:GetSecretValue`, or `sts:AssumeRole` — each a pivot.
Cross-account `sts:AssumeRole` is the canonical lateral-movement path in mature AWS estates.

### SSRF → internal Kubernetes API

Kubernetes pods reach `https://kubernetes.default.svc:443` (kube-apiserver), other pods
(`<service-name>.<namespace>.svc.cluster.local`), `169.254.169.254` (cloud metadata if not
blocked), and `<node-ip>:10250` (kubelet, if firewall is lax). The apiserver path uses the
service-account token at `/var/run/secrets/kubernetes.io/serviceaccount/token` — SSRF with a
`file://` primitive plus apiserver access gives full pod-API permissions, which commonly include
`get`/`list`/`watch` on `pods`/`secrets`/`configmaps` in the namespace. Cross-link to
`container_k8s_security.md`.

### SSRF → OAuth token exchange

When an SSRF-exploitable endpoint shares an origin with an OAuth callback, the attacker can
chain: SSRF triggers a request to the OAuth `redirect_uri`, the `redirect_uri` receives an
authorization code, the SSRF response reflects the code to the attacker. The result is an
unauthenticated cross-application token theft.

This requires same-origin between the SSRF and the OAuth callback, which is more common than
you'd expect in monolithic applications where every feature lives on `app.example.com` and the
SSO callback is also there.

### SSRF → cache poisoning

If the SSRF result is cached and served to subsequent users (CDN image-resize, preview
generators, asset proxies), the attacker poisons the cache with attacker-controlled content:
JS served as HTML with hours-long TTL, binary content interpreted as another type (XSS via SVG,
RCE via vulnerable ImageMagick), or `Set-Cookie` respected by the cache layer for session
fixation.

### SSRF in serverless

Lambda functions
that perform user-controlled HTTP fetches without restricting the destination are the same
SSRF class as EC2, with the same IAM blast radius. The rule is:
**any serverless function performing URL fetches is an SSRF candidate**, with severity equal
to the managed-identity blast radius.

---

## 7. Detection — Static Analysis Lens

### Sink catalog

The first list every SSRF / open-redirect detection rule needs is the language-specific HTTP
sink catalog. The shape is consistent across languages:

| Language | Sinks |
|---|---|
| Python | `requests.{get,post,put,patch,delete,head,request}`, `urllib.request.urlopen`, `httpx.{get,post,...}`, `aiohttp.ClientSession.{get,post,...}`, `pycurl.Curl.setopt(CURLOPT_URL, ...)` |
| JavaScript / Node | `fetch`, `axios.{get,post,...}`, `node-fetch`, `got`, `superagent`, `http.{get,request}`, `https.{get,request}`, `XMLHttpRequest.open` |
| Java | `URL.openConnection`, `URL.openStream`, `HttpClient.send`, `HttpClient.sendAsync`, `OkHttpClient.newCall`, Apache HttpClient `HttpClient.execute`, JAX-RS `Client.target` |
| Go | `http.Get`, `http.Post`, `http.NewRequest`, `(*http.Client).Do`, `(*http.Client).Get`, `(*http.Client).Post` |
| Ruby | `Net::HTTP.{get,post,start}`, `Net::HTTP::Get.new`, `HTTParty.{get,post,...}`, `Faraday.new`, `RestClient.{get,post,...}`, `open-uri`'s `URI.open` |
| PHP | `curl_setopt(..., CURLOPT_URL, ...)`, `file_get_contents`, `fopen`, `fsockopen`, `stream_socket_client`, `GuzzleHttp\Client::request` |
| C# / .NET | `HttpClient.{GetAsync,PostAsync,SendAsync}`, `WebRequest.Create`, `WebClient.DownloadString`, `RestClient.Execute` |
| Rust | `reqwest::Client::{get,post,...}`, `hyper::Client::get`, `surf::get` |

The sink catalog is necessary but not sufficient. The rule also needs source identification:
where does the URL string come from?

### Source enrichment

Sources: direct request reads (`request.params["url"]`, `req.body.target`,
`request.headers["x-fetch-url"]`), user-influenced DB rows (`tenant.webhook_url`), env-var
sources in serverless-misconfig contexts, and URL string concatenation
(`f"https://{user_input}.example.com/path"`). The string-concat pattern is an SSRF candidate
even when validators catch canonical forms — the attacker controls a portion that may be the
host or scheme.

### The validator-fetcher gap as a static-analysis target

A staff-level rule for parser-differential bugs needs to identify code paths where:

1. URL `U` is parsed by parser `P1` and a property of the parse (host, scheme, port) is
   validated.
2. The same URL `U` (the original string, not a re-emitted form) is later passed to a sink that
   parses with `P2`.

The structural signal is: `urlparse(url).hostname` (or equivalent) is checked, and `url` (the
unmodified string) is then passed to `requests.get(url)`. The right pattern is
`fetch_target = urlparse(url).hostname` followed by `requests.get(scheme + "://" + fetch_target + path)`
— rebuild the URL from the parsed components rather than trusting the original string.

Semgrep shape (illustrative): match `urlparse($URL).hostname` validation followed by passing
the unmodified `$URL` to an HTTP-client sink. For open-redirect detection, match
`res.redirect($REQ.params.$_)`, `res.redirect($REQ.body.$_)`, `res.redirect($REQ.originalUrl)`
without an intervening allowlist check. The `req.originalUrl` rule catches the
express-openid-connect CVE-2022-24794 class directly.

### Allowlist vs blocklist — the durable-defense distinction

Any blocklist-based SSRF defense is bypassable. The recurring pattern in CVEs:

- Blocklist matches `127.0.0.1` → attacker uses `127.1`, `0x7f000001`, `::1`, `::ffff:127.0.0.1`
- Blocklist matches `169.254.169.254` → attacker uses `169.254.169.254.nip.io`,
  `[::ffff:a9fe:a9fe]`, `2852039166` (decimal)
- Blocklist matches `localhost` → attacker uses `0.0.0.0`, `[::]`, the local network IP

The rule for review: **flag any SSRF defense that operates as a blocklist**. The defender's
correct move is an allowlist of permitted destination hosts, applied at the resolved-IP level
after DNS resolution.

Cross-link to the [Semgrep rule-writing docs](https://semgrep.dev/docs/writing-rules/overview) for the broader rule-precision discipline and to
`code_review_expertise.md` for the click-count severity heuristic that should drive open-
redirect ratings.

### Detection of the header-forwarding class

This class is harder to detect statically because it depends on the HTTP client's version and
configuration. A practical rule shape:

```yaml
- id: node-fetch-vulnerable-version
  message: |
    node-fetch <2.6.7 or 3.0.0-3.1.0 forwards Authorization/Cookie headers across cross-origin
    redirects (CVE-2022-0235). Upgrade or disable automatic redirects when sending credentials.
  pattern: |
    $X = require("node-fetch")
  paths:
    include:
      - "package.json"
  metadata:
    require: "node-fetch >= 2.6.7 || >= 3.1.1"
```

For runtime-configurable redirect behavior, flag any `fetch`/`axios`/`requests` call that
sends an `Authorization` header without `redirect: "manual"` (or library equivalent). The
credential leaks on cross-origin redirect.

---

## 8. Defensive Patterns

### Allowlist of destination hosts

The only durable SSRF defense is an explicit allowlist of permitted destination hosts at the
fetcher layer, applied after DNS resolution. Recipe: parse the URL, reject non-HTTPS scheme,
reject hostnames not in the allowlist, resolve the hostname yourself, reject non-public
resolved IPs, then connect to the resolved IP with the original hostname as `Host:` header
for SNI/vhost. Use `httpx`'s custom-transport or urllib3's `HTTPSConnectionPool(assert_hostname=...)`
to validate the cert against the original hostname while connecting to the pinned IP.

The pure-allowlist approach is right when the application has a small, well-defined set of
outbound destinations. When the application's purpose is to fetch arbitrary user-supplied URLs
(image preview, webhook receiver, federated identity), combine the allowlist with network-layer
defenses (next item).

### Network-layer egress filtering

The defense of last resort is to make SSRF physically impossible at the network layer. Common
implementations:

- **VPC egress rules** (AWS Security Groups, GCP firewall rules) that deny outbound traffic
  to private CIDR ranges (10/8, 172.16/12, 192.168/16, 169.254/16, 127/8). Applied at the
  subnet or VPC level so individual application bugs can't bypass.
- **Egress proxy** that all outbound HTTP must pass through. The proxy enforces the allowlist
  and adds audit logging. Examples: Smokescreen (Stripe), Squid with destination ACLs, Envoy
  with HTTP filters. Tenant-aware proxies enforce per-tenant allowlists.
- **CNI policies** in Kubernetes that deny pod-to-pod traffic except via service mesh, with
  policy on the service mesh.

The IMDS-specific defense is **IMDSv2 with hop limit 1**. Set on every EC2 instance at launch
time via:

```bash
aws ec2 modify-instance-metadata-options \
  --instance-id $ID \
  --http-tokens required \
  --http-put-response-hop-limit 1 \
  --http-endpoint enabled
```

With `http-tokens required`, IMDSv1 is disabled — only IMDSv2 (PUT-token-then-GET) works. With
`hop-limit 1`, the response doesn't traverse any internal proxy or container network boundary.
The combination defeats nearly all SSRF-to-IMDS exploitation, with the residual risk being
SSRF primitives that can issue PUT requests with custom headers (rare in practice).

### Strip dangerous headers on cross-host redirect

Rule: **disable automatic redirect-following in any code path that sends credentials**. If
you must follow redirects, handle them manually — set `allow_redirects=False` (Python requests)
or `redirect: "manual"` (fetch / axios), inspect the `Location:`, validate the next URL, re-issue
without the credential. For OAuth/OIDC callbacks, RFC 9700 requires exact-match `redirect_uri`
validation — implement as string-equality on the registered URL set, not regex or prefix match.

### Webhook receivers — domain allowlist or signed-only

When the application's purpose is fetching user-supplied URLs (the inherent SSRF substrate),
the realistic defenses are:

1. **Tenant-level domain allowlist.** Each tenant pre-registers the set of destination domains.
   The fetcher rejects URLs outside the set. Pairs well with network-layer egress filtering.
2. **Signed-payload-only mode.** Instead of fetching the user-supplied URL, the application
   sends a signed payload that the user retrieves from their own infrastructure. Eliminates
   SSRF by inverting the data flow: the application is the source, the user is the destination.
3. **Proxy-only mode.** All outbound webhook traffic passes through a dedicated egress proxy
   (Smokescreen-style) that enforces the allowlist independently of the application code.
   Adds defense-in-depth.

For OIDC discovery and SAML metadata fetching, the equivalent is **tenant-level configured
issuer / metadata URLs** with an exact-match policy. Once configured, the URL is fixed; the
SSRF surface reduces to the configuration-time check (which is typically administrator-only).

### Cross-link checklist for code review

1. Is the URL user-influenced (anywhere in its history)?
2. Is the validator parser the same as the fetcher parser? (If no — parser-differential surface.)
3. Is the destination check on the resolved IP (post-DNS) or on the hostname string (pre-DNS)?
   Pre-DNS is DNS-rebindable.
4. Is the destination check an allowlist or a blocklist? Blocklists are bypassable.
5. Does the HTTP client follow redirects automatically? If yes, are credentials stripped?
6. Does the HTTP client support `gopher://`, `file://`, `dict://`? Disable unused schemes.
7. Is the response visible to the attacker (body, status, timing)?
8. Does the request traverse VPC IMDS-blocking egress rules?
9. Is IMDSv2 enforced with hop-limit 1?
10. For redirect responses: is the redirect URL validated against an allowlist before emission?
11. For OAuth/OIDC: is `redirect_uri` exact-match against pre-registered URLs?
12. For SAML: is `RelayState` validated against an allowlist?
13. Is the URL re-emitted from parsed components, or trusted as a string?
14. Are user-supplied headers reflected into outbound requests (header-injection-to-SSRF)?
15. Does the application log the fetch destination for audit?

Cross-link to `code_review_expertise.md` "User-input paths must be resolved AND verified" —
the same two-step rule applies to URLs as to filesystem paths.

---

## 9. Variant Analysis — Under-Explored

### SSRF via DNS rebinding in mobile SDKs

Mobile SDKs (feature-flag, telemetry, A/B-testing) that fetch configuration from a DNS-resolved
hostname at startup and re-resolve on each subsequent request are DNS-rebindable. The attack:
the SDK trusts the initial response to determine its endpoint; the attacker times a rebind so
the first response (configuration) comes from a benign IP but subsequent requests resolve to
attacker-controlled IPs. Combined with older Android TLS weaknesses or missing cert pinning,
the attacker achieves persistent MITM on the app's API traffic. Defense: pin the resolved IP
at first contact for the session, or pre-build the permitted-endpoint list into the SDK.

### SSRF via WebRTC TURN/STUN and push-notification gateways

WebRTC's NAT-traversal stack uses TURN/STUN servers configured per-peer. If an application
accepts user-supplied TURN configuration, the server-side WebRTC stack will contact the TURN
server — classic SSRF substrate. Server-side gateways (Jitsi, Janus, mediasoup) inherit this.

FCM, APNS, and webhook-style push gateways similarly accept URLs that the gateway will contact
when a notification is delivered. The SSRF is **deferred** — the request happens asynchronously
in response to a push event, sometimes hours after URL configuration. Detection from logs is
harder because the request doesn't correlate to a recent user action.

### SSRF in AI / agent tool execution

The fastest-growing SSRF substrate in 2025–2026 is LLM agent tool execution. The pattern:

1. An agent has a `fetch_url(url)` tool registered for retrieval / web-browsing tasks.
2. The agent receives an instruction (from a user, from a system prompt, or from a previously-
   fetched page via prompt injection) that includes a URL.
3. The agent calls `fetch_url(<adversarially-chosen URL>)`.

Substrates:

- **Retrieval-augmented generation (RAG)** pipelines that fetch user-cited URLs.
- **Browse / Computer-use tools** that take URLs from prompts.
- **MCP servers** that expose `fetch`/`http_get`/`search` tools to a hosting agent.
- **Image-input pipelines** where an image URL is fetched and processed by a vision model.

The langchain-openai DNS-rebinding
advisory (GHSA-r7w7-9xr2-qq2r) is an instance of this class. The defense pattern is the
same as for any SSRF: allowlist destinations, pin DNS resolution, network-layer egress filtering
for IMDS protection. But the **threat model is novel** because the URL is chosen by the agent
based on its training and current context, not by a directly-attributable user request.

Particularly nasty: **second-order prompt injection** that uses a fetched page to instruct the
agent to fetch a second URL. The attacker controls page A. The agent fetches page A. Page A
contains text instructing the agent to fetch `http://169.254.169.254/latest/meta-data/...`.
The agent obliges. Result: IMDS exfil via an LLM as the SSRF primitive.

Cross-link to `llm_agent_security_expertise.md` (when written) for the broader agent-runtime
threat model. For now, treat any `fetch_url` tool in an agent as an SSRF candidate of severity
equal to the agent's network position and IAM authority.

### Open redirect via "soft" auth flows

Passwordless email links, magic-link auth, and SMS-OTP flows often include a `redirect_to`
parameter encoded in the link. The intent is to send the user to the page they originally
wanted; the bug is the same as in OAuth callbacks if the redirect target isn't allowlisted.
The exposure surface is large because magic-link emails are frequently the user's only
authentication touchpoint, and an attacker who can manipulate the redirect target intercepts
the post-auth session.

Recommended defense: encode the intended destination as a server-side identifier
(`{"return_to": "session:abc123"}`) and map it server-side, never trusting the URL form.

### URL parser differentials in service meshes

Service mesh proxies (Envoy, Linkerd, Istio's data plane) parse URLs for routing decisions.
The application's HTTP client parses the same URL for the actual request. If the service mesh
sees `http://a/b` but the upstream sees `http://a/c` because of path-normalization differences,
the mesh's authorization rules apply to the wrong destination. James Kettle's research on
reverse-proxy parser differentials (2019–2023) catalogues many such bugs.

For staff-level review of service-mesh configurations, treat **any path-based authorization
rule** as a candidate for parser-differential bypass against the upstream. The defense is to
do authorization at the upstream (where the actual destination is known), not at the mesh
(where the path string is interpreted independently). Cross-link to
`distributed_authz_expertise.md` for the broader authorization-placement discussion.

---

## 10. References

### Primary research

- Orange Tsai, "A New Era of SSRF: Exploiting URL Parsers in Trending Programming Languages,"
  Black Hat USA 2017.
  [PDF](https://blackhat.com/docs/us-17/thursday/us-17-Tsai-A-New-Era-Of-SSRF-Exploiting-URL-Parser-In-Trending-Programming-Languages.pdf)
- James Kettle, "Cracking the Lens: Targeting HTTP's Hidden Attack-Surface," Black Hat USA 2017.
  [PDF](https://blackhat.com/docs/us-17/wednesday/us-17-Kettle-Cracking-The-Lens-Exploiting-HTTPs-Hidden-Attack-Surface.pdf)
  | [PortSwigger writeup](https://portswigger.net/research/cracking-the-lens-targeting-https-hidden-attack-surface)
- Frans Rosén research index, Detectify Labs.
  [labs.detectify.com/tag/frans-rosen/](https://labs.detectify.com/tag/frans-rosen/)
- Nick Frichette, "Steal EC2 Metadata Credentials via SSRF," Hacking the Cloud.
  [hackingthe.cloud/aws/exploitation/ec2-metadata-ssrf/](https://hackingthe.cloud/aws/exploitation/ec2-metadata-ssrf/)
- Mark Vincent Yason research index, IBM Security Intelligence.
  [securityintelligence.com/author/mark-yason/](https://securityintelligence.com/author/mark-yason/)
- Daniel Stenberg, "My URL Isn't Your URL," 2016.
  [daniel.haxx.se/blog/2016/05/11/my-url-isnt-your-url/](https://daniel.haxx.se/blog/2016/05/11/my-url-isnt-your-url/)
- Daniel Stenberg, "The URL Interop Situation."
  [daniel.haxx.se/docs/URL-interop.html](https://daniel.haxx.se/docs/URL-interop.html)
- Snyk Security Research Team and Claroty Team82, "URL confusion vulnerabilities in the wild: Exploring parser inconsistencies,"
  Snyk Blog. [snyk.io/blog/url-confusion-vulnerabilities/](https://snyk.io/blog/url-confusion-vulnerabilities/)

### Standards

- RFC 3986 — "Uniform Resource Identifier (URI): Generic Syntax."
  [datatracker.ietf.org/doc/html/rfc3986](https://datatracker.ietf.org/doc/html/rfc3986)
- RFC 6749 — "The OAuth 2.0 Authorization Framework."
  [datatracker.ietf.org/doc/html/rfc6749](https://datatracker.ietf.org/doc/html/rfc6749)
- RFC 6874 — "Representing IPv6 Zone Identifiers in Address Literals and Uniform Resource
  Identifiers." [datatracker.ietf.org/doc/html/rfc6874](https://datatracker.ietf.org/doc/html/rfc6874)
- RFC 7230 — "Hypertext Transfer Protocol (HTTP/1.1): Message Syntax and Routing."
  [datatracker.ietf.org/doc/html/rfc7230](https://datatracker.ietf.org/doc/html/rfc7230)
- RFC 9700 — "Best Current Practice for OAuth 2.0 Security."
  [datatracker.ietf.org/doc/rfc9700/](https://datatracker.ietf.org/doc/rfc9700/)
- WHATWG URL Living Standard. [url.spec.whatwg.org](https://url.spec.whatwg.org/)

### CVEs and advisories in this cluster

- CVE-2022-24794 — express-openid-connect open redirect (Auth0).
  [GHSA-7p99-3798-f85c](https://github.com/auth0/express-openid-connect/security/advisories/GHSA-7p99-3798-f85c)
  | [NVD](https://nvd.nist.gov/vuln/detail/cve-2022-24794)
  | [Auth0 security bulletin](https://auth0.com/docs/secure/security-guidance/security-bulletins/cve-2022-24794)
- CVE-2022-0235 — node-fetch forwards secure headers to untrusted sites.
  [GHSA-r683-j2x4-v87g](https://github.com/advisories/GHSA-r683-j2x4-v87g)
  | [NVD](https://nvd.nist.gov/vuln/detail/cve-2022-0235)
  | [Red Hat security advisory](https://access.redhat.com/security/cve/cve-2022-0235)
- GHSA-gf8q-jrpm-jvxq — URL parsing in node-forge could lead to undesired behavior.
  [GHSA-gf8q-jrpm-jvxq](https://github.com/digitalbazaar/forge/security/advisories/GHSA-gf8q-jrpm-jvxq)

### Tooling

- Gopherus — SSRF-to-arbitrary-protocol payload generator.
  [github.com/tarunkant/Gopherus](https://github.com/tarunkant/Gopherus)
- Assetnote, "A Glossary of Blind SSRF Chains," 2021.
  [blog.assetnote.io/2021/01/13/blind-ssrf-chains/](https://blog.assetnote.io/2021/01/13/blind-ssrf-chains/)
  | [github.com/assetnote/blind-ssrf-chains](https://github.com/assetnote/blind-ssrf-chains)
- Smokescreen (Stripe) — outbound egress proxy with SSRF protection.
  [github.com/stripe/smokescreen](https://github.com/stripe/smokescreen)
- OWASP SSRF Prevention Cheat Sheet.
  [cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)

### AWS IMDS

- AWS, "Use the Instance Metadata Service to access instance metadata."
  [docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html)
- AWS Security Blog, "Get the full benefits of IMDSv2 and disable IMDSv1 across your AWS
  infrastructure." [aws.amazon.com/blogs/security/get-the-full-benefits-of-imdsv2-and-disable-imdsv1-across-your-aws-infrastructure/](https://aws.amazon.com/blogs/security/get-the-full-benefits-of-imdsv2-and-disable-imdsv1-across-your-aws-infrastructure/)

### Related expertise docs in this collection

- `knowledge-base/networking/dns_network_infrastructure.md` — DNS rebinding, BGP, network
  position.
- `knowledge-base/appsec-web/http_web_security.md` — HTTP semantics, CORS, redirect handling.
- `knowledge-base/appsec-web/distributed_authz_expertise.md` — OAuth, OIDC, SAML authorization
  models and the placement of authz checks.
- `knowledge-base/ai-ml-security/llm_agent_security_expertise.md` — agent runtimes and tool-execution
  threat model.
- `knowledge-base/methodology/code_review_expertise.md` — secure-code-review heuristics for
  candidate-point auditing, click-count severity, and the "resolve then verify" path-handling
  recipe.
  and corpus discipline for SSRF/open-redirect rules.
