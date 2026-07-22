# HTTP Request Smuggling — Primitives, Variants, and Defenses
## Synthesized from Chaim Linhart, Amit Klein, Ronen Heyes, Watchfire Research, James Kettle, Bishop Fox, Daniel Stenberg, PortSwigger Research, and the OWASP HTTP working group

> **Researchers:**
> - **Chaim Linhart, Amit Klein, Ronen Heyes, Steve Orrin** — Authors of "HTTP Request Smuggling" (Watchfire, June 2005, https://www.cgisecurity.com/lib/HTTP-Request-Smuggling.pdf). The canonical first systematic treatment of the class. Documented CL/TE disagreement against Apache, IIS, WebLogic, SunONE, and proxy chains commonly deployed at the time. Predated by Klein's own 2004 work on HTTP Response Splitting (Sanctum / Watchfire), which seeded the framing of HTTP as a state-machine that two endpoints can disagree about.
> - **James Kettle (@albinowax)** — Head of Research, PortSwigger. Re-popularized the class with "HTTP Desync Attacks: Request Smuggling, Reborn" (Black Hat USA 2019, https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn). Followed by "HTTP/2: The Sequel is Always Worse" (Black Hat USA 2021, https://portswigger.net/research/http2), "Browser Powered Desync Attacks: A New Frontier in HTTP Request Smuggling" (Black Hat USA 2022, https://portswigger.net/research/browser-powered-desync-attacks), and "Smashing the State Machine: The True Potential of Web Race Conditions" (Black Hat USA 2023, https://portswigger.net/research/smashing-the-state-machine). The 2019-2023 sequence is the canonical modern corpus; Kettle's PoCs against Slack, PayPal, GitHub, and Atlassian during the talks moved the class from "theoretical" to "every CDN ships variants of this."
> - **Bishop Fox** — Authors of h2cSmuggler (Jake Miller, https://bishopfox.com/blog/h2c-smuggling-request and https://github.com/BishopFox/h2csmuggler, 2020). Documented HTTP/2-cleartext upgrade smuggling through HTTP/1.1 proxies; the canonical reference for h2c-upgrade abuse.
> - **Daniel Stenberg (@bagder)** — curl maintainer; ongoing documentation of the gap between RFC 7230's request-target grammar and what HTTP libraries actually accept. The framing of HTTP as "a protocol with one specification and dozens of inconsistent implementations" runs through curl's bug tracker.
> - **PortSwigger Research / Web Security Academy** — Maintains a labbed taxonomy of HRS shapes (https://portswigger.net/web-security/request-smuggling) and the HTTP Request Smuggler Burp extension. The Web Security Academy lab corpus is the practical reference for the four classical shapes plus the HTTP/2 variants.
> - **OWASP HTTP Desync Working Group** — Maintainers of the OWASP HTTP Request Smuggling cheat sheet and the Web Security Testing Guide entries that translate Kettle's research into auditor-facing checklists.
>
> Sources: cgisecurity.com (Watchfire 2005 paper); portswigger.net/research (Kettle BHUSA 2019/2021/2022/2023); bishopfox.com/blog (h2cSmuggler); github.com/BishopFox/h2csmuggler; daniel.haxx.se; everything.curl.dev; RFC 7230; RFC 9112 (HTTP/1.1); RFC 9113 (HTTP/2); RFC 9114 (HTTP/3); NVD; GitHub Advisory Database; OWASP Web Security Testing Guide v4.

---

## 1. What HTTP request smuggling is

Two HTTP servers in a chain disagree about where one request ends and the next begins. The disagreement creates a "smuggled" request the front-end thinks belongs to victim N+1 and the back-end thinks belongs to attacker N+0 — or vice versa. The mismatch is the primitive; everything else is exploitation.

The mismatch arises because HTTP/1.1 specifies two independent ways to delimit a message body — `Content-Length` and `Transfer-Encoding: chunked` — and the spec's tie-breaking rules are unevenly implemented. When the front-end and back-end honor different headers, or honor the same header with different parsing rules, a single TCP byte stream gets split at two different places. Whatever bytes one server thinks are "next request" and the other thinks are "body of the current request" become a smuggled message.

Connection reuse is the precondition. If every request opened a new TCP+TLS connection, the mismatch would be harmless: each request boundary would equal the connection boundary. The reason HRS matters is that modern stacks pool back-end connections for performance, and the smuggled bytes end up at the head of the next pooled-connection client's request — which is some other user.

---

## 2. The 1999 → 2005 origin and why it stayed alive

The class predates the Watchfire paper by several years. Chaim Linhart's earlier work and a 1999 "double Content-Length" PoC circulated on the web-application-security mailing lists; the techniques were folklore before they were a paper. Linhart, Klein, Heyes, and Steve Orrin's June 2005 Watchfire white paper "HTTP Request Smuggling" (https://www.cgisecurity.com/lib/HTTP-Request-Smuggling.pdf) was the first systematic treatment — it cataloged the CL/CL, CL/TE, and TE/CL shapes against the major HTTP servers of the day (Apache, IIS, SunONE, WebLogic) and the major caching proxies (Squid, Tinyproxy).

The class went quiet for roughly a decade. Vendors patched the obvious shapes; auditors moved on. HRS surfaced occasionally in single advisories but stopped being framed as a live class.

James Kettle's "HTTP Desync Attacks: Request Smuggling, Reborn" (Black Hat USA 2019) re-popularized HRS by showing it was still exploitable against production stacks at PayPal, Slack, the Red Hat customer portal, and others. Kettle's framing made HRS legible to a generation of researchers who hadn't read the 2005 paper: he reframed the bug as a desync between a state-machine the front-end runs and one the back-end runs, and showed that the state-machine gap had grown with HTTP/2 rather than shrunk.

The reason the class survives twenty-five years: every CDN, every load balancer, every WAF, and every origin server has its own RFC interpretation, and the RFC itself is ambiguous on edge cases. RFC 7230 §3.3.3 says a request with both Content-Length and Transfer-Encoding should treat Content-Length as if it were not present (effectively: prefer TE). RFC 9112 §6.3 says the same. Real implementations split. RFC 7230 §3.2.4 explicitly bans whitespace between header name and colon ("No whitespace is allowed between the header field-name and colon") — but several long-deployed parsers accept it. The grammar is precise enough to score on Wireshark; it's not precise enough to force every implementer to the same byte-level behavior.

The structural reason HRS persists is that HTTP/1.1 is a textual protocol parsed by hand-written code in a dozen different languages by a dozen different teams, none of which share a test corpus. Every variant of "what is a valid header line?" lives somewhere in production.

---

## 3. Classical HRS shapes (HTTP/1.1)

Each shape names the front-end behavior first, then the back-end behavior. `CL.TE` means front-end uses `Content-Length`, back-end uses `Transfer-Encoding`.

### 3.1. CL.TE — front-end CL, back-end TE

The front-end honors `Content-Length`. The back-end honors `Transfer-Encoding: chunked` and ignores `Content-Length` once TE is present (per RFC 7230 §3.3.3, the correct behavior).

```
POST / HTTP/1.1
Host: victim.example
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

Front-end reads 13 bytes (`0\r\n\r\nSMUGGLED`), forwards them as the body of one request, and considers the connection ready for the next request. Back-end reads `Transfer-Encoding: chunked`, sees the `0\r\n\r\n` chunk terminator, considers the body done after byte 5, and treats the remaining bytes (`SMUGGLED`) as the start of the next request on the pooled connection.

Canonical pairing observed in the field: Cloudflare and similar CDNs in front of origins that aggressively prefer TE (older nginx + chunked-aware modules; Apache 2.4.x in some configs).

### 3.2. TE.CL — front-end TE, back-end CL

The front-end honors `Transfer-Encoding: chunked`. The back-end honors `Content-Length` and either silently ignores TE or rejects it.

```
POST / HTTP/1.1
Host: victim.example
Content-Length: 3
Transfer-Encoding: chunked

8
SMUGGLED
0

```

Front-end reads chunked encoding: an 8-byte chunk containing `SMUGGLED`, then `0\r\n\r\n` to terminate. Forwards everything. Back-end reads 3 bytes (`8\r\n`), considers the body done, and treats the rest of the buffer (starting at `SMUGGLED`) as the next request.

Canonical pairing in the field: older HAProxy → Apache or → IIS configurations where the front-end stripped or honored TE but the back-end did not. Modern HAProxy has hardened against this since 2.x, with several CVEs in the 2.0-2.4 series tracking the regression set.

### 3.3. TE.TE — both honor TE, but one is obfuscated

Both servers can parse `Transfer-Encoding: chunked`. The attacker sends an obfuscated variant; one server normalizes and honors the obfuscation, the other server doesn't see it as TE at all and falls back to Content-Length.

Obfuscation variants observed in the field (Kettle 2019 catalog plus Web Security Academy lab variants):

```
Transfer-Encoding: xchunked
Transfer-Encoding : chunked        (note the space before the colon)
Transfer-Encoding: chunked\r\n
Transfer-Encoding:[tab]chunked
Transfer-encoding: chunked         (case variant)
TRANSFER-ENCODING: chunked
Transfer-Encoding
 chunked                            (continuation line)
Transfer-Encoding: chunked, identity
Transfer-Encoding: identity, chunked
X: X\r\nTransfer-Encoding: chunked
Transfer-Encoding​: chunked   (zero-width Unicode in header name)
```

Each variant has a known pairing: some servers honor `chunked, identity` as "use chunked, identity is a discarded codec," others reject the multi-token form outright. The catalog is the attack surface — every obfuscation that any server accepts becomes a candidate TE.TE primitive against a paired server that doesn't accept it.

### 3.4. CL.CL — duplicate Content-Length

```
POST / HTTP/1.1
Host: victim.example
Content-Length: 8
Content-Length: 7

12345678
```

RFC 7230 §3.3.3 says duplicate `Content-Length` headers with different values must be rejected (HTTP 400). Plenty of stacks pick the first value, plenty pick the last, plenty concatenate, and plenty proceed without raising. The disagreement between "first" and "last" parsers across a chain produces a 1-byte (or more) desync, which is enough to smuggle a short prefix into the next request — typically the start of a request line.

CL.CL is the simplest shape to fuzz for; it's also the most likely to be caught by a properly-configured front-end. Treat it as the canary: if a stack accepts duplicate `Content-Length`, every other obfuscation is probably also viable.

---

## 4. HTTP/2 desync attacks (Kettle BHUSA 2021/2022)

The load-bearing modern update. Kettle's two papers — "HTTP/2: The Sequel is Always Worse" (BHUSA 2021, https://portswigger.net/research/http2) and "Browser Powered Desync Attacks" (BHUSA 2022, https://portswigger.net/research/browser-powered-desync-attacks) — established that HTTP/2 doesn't fix HRS, it just changes the boundary where the desync lives. The desync moves from "two HTTP/1.1 parsers disagreeing" to "an HTTP/2-to-HTTP/1.1 downgrade emitting an HTTP/1.1 request that an HTTP/1.1 parser then desyncs on."

The reason this matters: almost every production stack still terminates HTTP/2 at the edge and speaks HTTP/1.1 to the back-end. HTTP/2-to-HTTP/1.1 downgrade is the dominant deployment shape in 2026. Every downgrade is a HRS opportunity.

### 4.1. H2.CL

HTTP/2 has a `content-length` pseudoheader. The front-end translates the HTTP/2 request to HTTP/1.1 by emitting a `Content-Length` header with the value the attacker supplied — even if the actual body length after H2-to-H1 translation is different. The back-end honors the translated `Content-Length`; any bytes past it become the next request.

The attacker can ship a body of 100 bytes in HTTP/2 while declaring `content-length: 5` in the pseudoheader. The H2 front-end forwards `Content-Length: 5\r\n\r\n<100-byte-body>` to the back-end; the back-end reads 5 bytes and treats the remaining 95 as the next request.

### 4.2. H2.TE

Same shape but the smuggled body relies on a `transfer-encoding: chunked` header surviving the H2-to-H1 downgrade. Per RFC 9113 §8.1.1, HTTP/2 forbids `Transfer-Encoding` as a connection-level header and forbids `chunked` as a value — but plenty of HTTP/2 front-ends pass it through unmolested to the back-end, where it activates chunked parsing.

### 4.3. CL.0

Front-end honors `Content-Length`. Back-end treats the body as zero-length for some reason — most often because the request method is one the back-end's router ignores bodies for (typically GET or HEAD), or because the back-end strips Content-Length before parsing. The body bytes the front-end forwarded land at the head of the connection and get parsed as the next request.

```
GET / HTTP/1.1
Host: victim.example
Content-Length: 50

GET /admin HTTP/1.1
X: Y
```

The classical version uses POST; CL.0 is the GET/HEAD variant where back-ends that route to body-less handlers discard the body entirely.

### 4.4. TE.0

Analogous: front-end honors chunked, back-end treats the body as zero-length. The chunked-encoded body bytes land at the head of the next request.

### 4.5. h2cSmuggler

Bishop Fox's 2020 contribution (Jake Miller, https://bishopfox.com/blog/h2c-smuggling-request, tool at https://github.com/BishopFox/h2csmuggler). HTTP/2 cleartext (h2c) upgrade is the RFC 7540 §3.2 mechanism for negotiating HTTP/2 over an existing HTTP/1.1 connection via:

```
GET / HTTP/1.1
Host: victim.example
Connection: Upgrade, HTTP2-Settings
Upgrade: h2c
HTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA
```

If the front-end forwards these headers to the back-end without stripping the `Upgrade` and `HTTP2-Settings` headers, the back-end may accept the upgrade and begin parsing the rest of the socket as HTTP/2 frames. The attacker now has a direct HTTP/2 tunnel to the back-end through the front-end's auth boundary. Every HTTP/2 frame the attacker sends bypasses the front-end's HTTP-level filtering — including auth header injection, host-header rewriting, and path-based access control.

The defense is trivial in principle: front-end strips `Connection`, `Upgrade`, and `HTTP2-Settings` from forwarded headers, or refuses to honor h2c upgrade against the back-end. In practice, plenty of reverse proxies in 2020-2024 didn't strip these (the h2cSmuggler README has a tested-target list).

### 4.6. HTTP/3 — same class, different transport

HTTP/3 (RFC 9114) runs over QUIC and inherits the HTTP/2 framing model. The HRS-relevant question is not "can H3 frames be smuggled?" — they cannot, because the QUIC framing is unambiguous — but "what happens when an H3 front-end downgrades to H1 to talk to back-ends?" The answer is the same as H2: every downgrade re-introduces the HTTP/1.1 parser as the load-bearing boundary, and every header that survives the downgrade is a candidate smuggling vector. As of 2026, H3-to-H1 downgrade is not as deeply audited as H2-to-H1; expect the next wave of disclosures to live here.

---

## 5. The single-packet attack

Kettle's "Smashing the State Machine: The True Potential of Web Race Conditions" (Black Hat USA 2023, https://portswigger.net/research/smashing-the-state-machine) is not strictly HRS, but it uses the HTTP/2 framing primitives that the HRS toolchain already ships, and it lives in the same `Turbo Intruder` workflow.

The single-packet attack uses HTTP/2 to pack N requests into a single TCP packet, defeating server-side rate limits and race-condition defenses that rely on serial request arrival. The mechanism: open an HTTP/2 connection; warm the connection up with a harmless first request so TLS handshake and TCP slow-start are amortized; then send N HEADERS frames simultaneously, all flushed as a single TCP segment. The server sees all N requests within microseconds of each other, defeating the "request 2 must observe request 1's side effects" assumption that powers most race-condition defenses.

Connection warmup is the load-bearing detail. Without warmup, TCP slow-start staggers the requests across multiple segments and the attack degrades to N-1 race conditions. With warmup, the requests arrive synchronized at L7.

The defense pattern is the same as for filesystem TOCTOU: per-request idempotency tokens, server-side request-level locks, optimistic concurrency control at the application layer. Cross-link `[[reference-race-conditions-concurrency]]` for the broader race-condition taxonomy; HRS and single-packet are siblings in that doc.

---

## 6. Browser-powered desync

Kettle's "Browser Powered Desync Attacks: A New Frontier in HTTP Request Smuggling" (BHUSA 2022, https://portswigger.net/research/browser-powered-desync-attacks) is the headline class change of the 2020s. Pre-2022, exploiting HRS required attacker control of either a TLS-terminating front-end (rare) or a TCP-level position adjacent to the victim's session (rare). Browser-powered desync removes both requirements: the attacker uses a malicious page to force the victim's BROWSER to send a desync-shaped request to the victim's origin, polluting the victim's connection pool.

The mechanism in outline:

1. Victim visits attacker-controlled page `evil.example`.
2. The page issues a `fetch()` to `victim.example` with a body crafted to trigger CL.0 or H2.CL on victim.example's stack.
3. The victim's browser establishes a connection to victim.example, sends the request, and pools the connection per HTTP/2 connection-reuse rules.
4. The victim's browser then issues normal requests to victim.example (perhaps the user clicks a link). Those requests are smuggled-into by the leftover bytes from step 2.

The attacker doesn't need network position. The attacker needs to convince the victim to load attacker JS, which is the precondition for half of all web attacks anyway. HRS is now an XSS-precursor class: client-side prompt-inject the browser into pool-poisoning, then ride the pollution for whatever the front-end's auth boundary protects.

Cross-link `[[reference-http-web-security]]` — browser fetch semantics, CORS interaction with pooled connections, and the connection-reuse rules that determine which fetch calls share a TCP stream live in that doc.

---

## 7. Front-end / back-end pair catalog

Practical reference. Treat any row marked `[unverified specific advisory]` as "this pairing is plausible per architectural analysis, but I do not have a specific CVE I can anchor to" — go look at the vendor's advisory feed before treating the row as fact.

| Front-end | Back-end | Known shape(s) | Observed CVE / disclosure | Mitigation status |
|---|---|---|---|---|
| Cloudflare | Any-origin | H2.CL, H2.TE pre-2021 | Kettle BHUSA 2019 demos against Cloudflare-fronted properties; Cloudflare blog acknowledges hardening | Cloudflare strips ambiguous CL+TE since 2019; H2 downgrade hardened progressively 2020-2024 |
| AWS ALB | Any-origin | CL.TE, H2.CL pre-2021 | Multiple HackerOne disclosures against AWS-ALB-fronted properties; specific CVE attribution `[unverified specific advisory]` | ALB rejects ambiguous CL+TE since ~2020; HTTP/2-to-HTTP/1.1 hardening per AWS HTTP/2 announcements |
| AWS CloudFront | Any-origin | CL.TE, H2.CL | `[unverified specific advisory]` | CloudFront rejects ambiguous CL+TE per AWS docs |
| Azure Front Door | Any-origin | H2.CL, H2.TE | `[unverified specific advisory]` | Azure published HTTP/2 desync mitigations 2022 |
| Google Cloud Load Balancer | Any-origin | CL.TE, H2.CL | `[unverified specific advisory]` | GCLB rejects ambiguous CL+TE per Google docs |
| nginx (1.x) | Apache | CL.TE | Documented in Watchfire 2005 paper for the era's versions | Modern nginx (1.18+) and Apache 2.4 reject ambiguous CL+TE |
| nginx | uWSGI | CL.TE, CL.0 | Various GitHub issues against specific uWSGI versions; specific CVE `[unverified specific advisory]` | uWSGI versions post-2.0.20 reject ambiguous CL+TE; check version |
| HAProxy | Backend | TE.CL, integer-overflow CL parsing | CVE-2021-40346 (HTX header parser integer overflow → HRS, fixed in 2.0.25 / 2.2.17 / 2.3.14 / 2.4.4) | Patched in stated versions; older HAProxy 2.0-2.3 vulnerable |
| Akamai | Any-origin | Various; Kettle 2019/2021 demos | Kettle BHUSA 2019 against Akamai-fronted properties; specific public CVE attribution `[unverified specific advisory]` | Akamai published HRS hardening per their security advisories feed |
| Fastly | Any-origin | CL.TE, H2.CL pre-2021 | `[unverified specific advisory]` | Fastly hardened progressively 2019-2022 per their security blog |
| Imperva | Any | TE.TE obfuscation bypass class | `[unverified specific advisory]` | WAF parser-differential risk; treat WAF as compensating control |
| F5 BIG-IP | Any | CL.TE, TE.TE | F5 K-series advisories; specific CVE attribution `[unverified specific advisory]` | Check F5 security advisories feed for current version's status |
| Varnish | Any | CL.TE, TE.TE | Varnish GitHub issues for specific releases | Patched in modern Varnish 6.x+ versions |
| Envoy | Backend | H2.CL, H2.TE | CVE-2019-9512 (HTTP/2 Ping Flood) and related H2-framing CVEs; specific HRS CVE attribution `[unverified specific advisory]` | Envoy hardens H2 frame parsing per CVE feed; check version |
| Istio sidecar | Backend | Inherits Envoy | See Envoy | See Envoy |
| Kong | Backend | CL.TE | `[unverified specific advisory]` | Check Kong security advisories per release |
| Tyk | Backend | CL.TE | `[unverified specific advisory]` | Check Tyk security advisories per release |
| Apigee | Any | CL.TE, H2.CL | `[unverified specific advisory]` | Check Apigee security advisories per release |

Two operational rules from the table:

1. **The "ambiguous CL+TE rejection" defense is widely deployed at the CDN tier but still incomplete at long-tail origin stacks.** Treat the CDN's hardening as a *first* line, not the only line.
2. **Every HTTP/2-to-HTTP/1.1 downgrade is a candidate.** If a row in the table has a CDN doing H2 termination and an origin speaking H1, that pairing is a candidate H2.CL / H2.TE target regardless of what the CDN's published hardening claims.

PortSwigger's Web Security Academy maintains a more current and lab-verified version of this kind of table at `https://portswigger.net/web-security/request-smuggling` — defer to it over this one when current accuracy matters.

---

## 8. Exploitation primitives — what you do once you have the desync

The desync is the primitive. What it buys you depends on what you smuggle.

### 8.1. Authentication bypass

The smuggled request lands at the head of some other user's pooled connection. The back-end sees the smuggled request *plus* the victim's HTTP headers, including their `Cookie:` and `Authorization:` headers, appended at the position the back-end is expecting headers. The attacker chooses the request body; the victim's session inherits the request.

Concretely: smuggle a `GET /admin HTTP/1.1\r\nX:` prefix; the back-end consumes the victim's next request as the continuation of the X header, finds the victim's `Cookie:` line, treats the cookie as authentication for `/admin`. The privileged-user-as-victim case is the one that pays out — admin users have privileged cookies, and the attacker only needs one of them to land on the pooled connection.

This is the textbook HRS-to-admin pattern. Kettle's BHUSA 2019 demos against PayPal, Slack, and the Red Hat customer portal were variants of this primitive.

### 8.2. Cache poisoning

The front-end caches the response to the smuggled request and serves it to other users. If the smuggled request was `GET /` with a host header pointing at `evil.example` (whose server returns attacker HTML), the cached entry for `/` now serves attacker HTML to every user on the cache shard.

Cross-link `[[reference-cicd-supply-chain]]` §2.7 for the Cacheract pattern — the analogous primitive on GitHub Actions caches, where a poisoned cache entry compromises downstream pipelines. Different cache, same shape: control a cache write, control all subsequent reads.

The defense at the cache layer is to scope the cache key by `Host:` plus a per-host secret, not just by path. Many CDN configurations do this; some don't.

### 8.3. Web cache deception

Omer Gil's BHUSA 2017 paper "Web Cache Deception Attack" (https://omergil.blogspot.com/2017/02/web-cache-deception-attack.html) is the canonical anchor for the class. Append `;.css` or `/x.css` or `.jpg` to a path that returns sensitive content; the CDN sees a static-asset extension and caches the response; the application sees the unmodified path and returns the sensitive content. Cached entry now contains the victim's data, retrievable by URL.

Web cache deception is separate from HRS but composable with it: a smuggled request can request `/users/me;.css`, the back-end returns the requesting user's profile, the cache stores it under the static-asset cache key, the attacker fetches it. The smuggle lets the attacker control the victim cookie that hits the back-end; the cache-deception trick lets the attacker control where the response gets stored. Together they're a victim-data exfil chain.

### 8.4. XSS via response queue desync

The smuggled request returns attacker-controlled HTML/JS. The back-end writes the response to the pooled connection; the front-end forwards it to the next client on that connection — who is the victim. The victim's browser sees attacker JS in response to a URL the victim itself requested, with the victim's cookies attached. This is XSS without an XSS sink in the application.

Often the most reliable HRS-to-RCE-in-the-browser path on modern stacks. The Web Security Academy lab "Exploiting HTTP request smuggling to deliver reflected XSS" walks the variant in detail.

### 8.5. Internal endpoint reach

The smuggled request bypasses the front-end's auth boundary. The back-end receives a request the front-end would normally have blocked: `/admin`, `/_internal`, `/debug`, `/metrics`, the actuator endpoints in Spring Boot, `/server-status` on Apache, `/nginx_status` on nginx. The front-end's blocklist is enforced at the front-end; smuggling routes around it.

This is the most common practical payoff on internal-network-attached stacks: the auditor doesn't need to find a vulnerability in the admin endpoint, only to reach it.

### 8.6. Cross-origin SSRF promotion

Smuggle a request with a `Host:` header pointing to internal infrastructure (`Host: internal.corp`, `Host: localhost:8080`, `Host: 169.254.169.254`). The back-end routes by Host header to the internal service. If the front-end normally rewrites or constrains Host, the smuggle bypasses that constraint.

Cross-link `[[reference-ssrf-url-parsing]]` — the SSRF primitives catalogued there (cloud metadata, DNS rebinding, gopher pivot) all become reachable via HRS-driven Host injection on stacks that route by Host header.

---

## 9. Header obfuscation grammar — the parser-differential surface

This is where new HRS variants are born. Every obfuscation is a candidate primitive; every server has its own set of obfuscations it accepts or rejects; every mismatch between two paired servers' acceptance sets is a candidate desync.

### 9.1. Whitespace in header names

```
Transfer-Encoding : chunked          (space before colon — RFC 7230 §3.2.4 bans this)
Transfer- Encoding: chunked          (space in the header name itself)
Transfer-Encoding:[tab]chunked       (tab between colon and value — allowed)
[space]Transfer-Encoding: chunked    (leading space on header line — banned, but parsed by some)
```

RFC 7230 §3.2.4: "No whitespace is allowed between the header field-name and colon… A server MUST reject any received request message that contains whitespace between a header field-name and colon with a response code of 400 (Bad Request)." Plenty of implementations don't.

### 9.2. Case variants

```
Transfer-Encoding: chunked
transfer-encoding: chunked
TRANSFER-ENCODING: chunked
Transfer-encoding: chunked
TrAnSfEr-EnCoDiNg: chunked
```

HTTP/1.1 header names are case-insensitive per RFC 7230 §3.2 ("Each header field consists of a case-insensitive field name"). Every conformant parser normalizes case. Non-conformant parsers — including some pre-canonicalizing WAFs that match against exact strings — do not. Case-folding mismatch between front-end and back-end is rare but observed.

### 9.3. Continuation lines (obsolete folding)

RFC 7230 §3.2.4 deprecates header continuation: "A server that receives an obs-fold in a request message that is not within a message/http container MUST… reply with a 400 (Bad Request)." Some parsers still accept it:

```
Transfer-Encoding:
 chunked
```

If one server in the chain accepts the continuation and the other doesn't, the obfuscated TE is honored by one side and ignored by the other.

### 9.4. Duplicate headers with different values

```
Content-Length: 5
Content-Length: 10
```

RFC 7230 §3.3.3 demands rejection. Real implementations split: some take first, some take last, some concatenate as `5, 10` and try to parse, some reject. The defense pattern is "if a server's behavior on duplicate CL is configurable, the configuration choice is part of the attack surface."

### 9.5. Invalid characters in chunk size

```
0\r\nX:Y\r\n\r\n            (correctly formed terminator)
0\n\r\nX:Y\r\n\r\n          (LF instead of CRLF in chunk terminator)
00\r\n\r\n                   (leading zeros on chunk size — allowed by RFC but unevenly parsed)
0;extension=ignored\r\n\r\n  (chunk extension — allowed by RFC but sometimes mis-parsed)
0a\r\n... (10 bytes)         (hex chunk size — required by RFC, but some parsers accept decimal)
```

Chunk-extension parsing is a fertile area for desync; the RFC allows the extension grammar but most implementations don't exercise it, so extension content can carry trailing bytes that one parser ignores and the other doesn't.

### 9.6. Implicit-zero header values

```
Transfer-Encoding:                   (empty value)
Content-Length:                      (empty value)
Content-Length: 0
Transfer-Encoding: chunked,
```

Empty TE values get treated as "no chunked encoding present" by some servers and as "TE header is present with no value, fall back to default codec" by others. The trailing-comma variant invokes the codec-list parsing path, which some implementations handle as "chunked plus an empty codec slot."

### 9.7. Pseudoheader-vs-regular-header mismatch (HTTP/2)

HTTP/2 has `:authority` (the canonical host) and may also have a regular `Host:` header. RFC 9113 §8.3.1 says these must match; many implementations don't enforce. The H2 front-end may forward both unchanged to the back-end, where the back-end's routing uses one and the back-end's logging uses the other. The smuggle: set `:authority: victim.example`, set `Host: internal.corp`, observe which the back-end routes by.

This is also a load-bearing HTTP/2 SSRF primitive — the front-end's host-allowlist sees `victim.example`; the back-end's router sees `internal.corp`.

### 9.8. Trailing-header smuggling

HTTP/1.1 chunked encoding supports trailers — headers that appear after the body, terminated by an empty line:

```
POST / HTTP/1.1
Host: victim.example
Transfer-Encoding: chunked
Trailer: X-Smuggled

5
hello
0
X-Smuggled: smuggled-value

```

If the front-end accepts trailers and forwards them as regular headers, and the back-end re-parses the trailer-as-header on the next request boundary, the trailer content can become a request prefix. Less common in production than CL.TE / TE.CL, but the surface exists.

Cross-link `[[reference-xml-parser-differential]]` — the analogous parser-differential class in XML, where attacker bytes are interpreted differently by signature-verifier and consumer; same structural bug, different protocol. Also `[[reference-ssrf-url-parsing]]` — URL parser differentials are the URL-format sibling of header-format differentials.

---

## 10. Detection

Multiple layers, each with a known failure profile.

### 10.1. Static (Semgrep / linter) rules

HRS is fundamentally a runtime state-machine bug. Static rules catch the obvious shapes — application code emitting double `Content-Length`, application code copying header values without canonicalizing, application code that proxies requests without stripping `Transfer-Encoding`.

Concrete rule shapes that work statically:

```yaml
# Flag application code that sets Content-Length without checking for TE
rules:
  - id: double-content-length-write
    patterns:
      - pattern-either:
          - pattern: response.set_header("Content-Length", $X)
          - pattern: response.headers["Content-Length"] = $X
      - pattern-not-inside: |
          if not response.headers.get("Transfer-Encoding"):
              ...
    message: Content-Length is being set unconditionally; if Transfer-Encoding is also present, the back-end may treat one as the canonical body delimiter.
    severity: WARNING

# Flag reverse-proxy code that forwards Upgrade: h2c without stripping
  - id: h2c-upgrade-not-stripped
    patterns:
      - pattern-either:
          - pattern: proxy.forward_request($REQ)
          - pattern: $CLIENT.send($REQ)
      - pattern-not-inside: |
          $REQ.headers.pop("Upgrade", None)
          $REQ.headers.pop("HTTP2-Settings", None)
    message: Forwarding Upgrade header without stripping enables h2cSmuggler-class attacks.
    severity: WARNING
```

These rules catch only the obvious config-level cases. Most HRS lives below the application code, in the reverse-proxy or load-balancer configuration; static analysis of YAML / nginx.conf / haproxy.cfg is the higher-leverage surface. Auditors should run dedicated parsers over those config files looking for `proxy_pass` directives without `proxy_set_header Connection ""`, `proxy_http_version 1.1` settings, and similar reverse-proxy-config patterns.

### 10.2. Active fuzz testing

The practical detection path. Tools:

- **HTTP Request Smuggler** (Burp extension, https://portswigger.net/bappstore/aaaa60ef945341e8a450217a54a11646) — PortSwigger's official tool; runs the full TE.TE / CL.TE / TE.CL / CL.CL probe set plus H2.CL / H2.TE / CL.0. Includes Kettle's `smuggle-probe` and `smuggle-attack` workflows.
- **smuggler** (defparam, https://github.com/defparam/smuggler) — Python CLI tool with a YAML mutation grammar for header obfuscations. Faster than the Burp extension for at-scale corpus testing.
- **h2cSmuggler** (Bishop Fox, https://github.com/BishopFox/h2csmuggler) — Specifically for the h2c-upgrade variant.
- **Turbo Intruder** (PortSwigger, https://github.com/PortSwigger/turbo-intruder) — Kettle's high-rate HTTP fuzzer; the single-packet-attack workflow lives here. Not strictly HRS, but the same primitives.
- **`http-request-smuggling-cracker`** and similar second-tier tools — `[unverified specific advisory]` on quality; defer to PortSwigger / Bishop Fox tooling for production audits.

Typical detection workflow on a new target:

```bash
# 1. Identify the front-end and back-end
curl -v -k -X POST https://target/ \
  -H 'Transfer-Encoding: chunked' \
  -H 'Content-Length: 4' \
  --data-binary $'1\r\nZ\r\n0\r\n\r\n'
# Look at response timing and status — front-ends differ on how they handle ambiguous CL+TE.

# 2. Run the canonical probe set
python3 smuggler.py -u https://target -m POST

# 3. If the target speaks HTTP/2, run the H2 probes
# (HTTP Request Smuggler Burp extension is the easier path for this)
```

The audit-discipline rule: **never run smuggling probes against production without explicit authorization.** Successful probes write smuggled requests into the connection pool, which pollutes other users' sessions. PortSwigger's tools include a "probe" mode that detects desyncs without exploiting them — use that mode first, escalate to "attack" mode only with authorization.

### 10.3. WAF detection signatures

WAFs detect HRS via heuristics: dual `Content-Length` and `Transfer-Encoding`, obfuscated TE (case variants, whitespace variants, continuation lines), unexpected pseudoheaders in HTTP/2, unusual chunk-extension content.

Known bypass class: the WAF/back-end parser differential. The WAF pre-canonicalizes headers and matches against its rules; if the WAF's canonicalization differs from the back-end's canonicalization, attacker can craft an obfuscation the WAF normalizes away ("nothing suspicious here") that the back-end parses literally ("oh, you wanted chunked encoding"). This is a meta-HRS — the WAF itself becomes the front-end half of a CL.TE pair, and the back-end is the original back-end.

Treat WAF detection as defense-in-depth detection, not the security boundary. The boundary is "the back-end and front-end agree on request parsing," not "the WAF rejects known signatures."

### 10.4. Runtime telemetry

Flag connections with anomalous request-boundary patterns: connections where the front-end's request count diverges from the back-end's request count, connections where the back-end logs a request the front-end didn't proxy, connections where two requests in a short window have unusual header sets (e.g., the second request has no Host header because the smuggled prefix consumed it).

The hard part is volume. HRS-shape requests look superficially normal to L7 logs — they're well-formed HTTP/1.1, they have plausible methods and paths, they fit existing log schemas. The signal lives in cross-correlating front-end logs (Cloudflare logs, ALB access logs) with back-end logs (origin access logs) and flagging mismatches. Most organizations don't ingest both into the same SIEM at the granularity needed for this correlation.

Cross-link `[[reference-detection-engineering]]` §10 for the detection-rule corpus pattern — every rule needs a known FP profile, especially HRS-detection rules. The FP profile of HRS detection at L7 logs is dominated by load-balancer connection-reset events and client-side TCP-RST races, which produce log-volume divergence indistinguishable from a successful smuggle.

---

## 11. Mitigation hierarchy — what defenders actually do

In order of structural strength.

### 11.1. HTTP/2 end-to-end

The strongest structural defense. If the back-end speaks HTTP/2 natively and the front-end forwards HTTP/2 frames without translating to HTTP/1.1, there is no HTTP/1.1 parser in the chain to desync. H2.CL and H2.TE go away because the H2→H1 downgrade window is gone.

The adoption gap as of 2026: H2-to-H1 termination is still the default in most production stacks. Internal services rarely speak H2; back-end frameworks (Rails, Django, Express, Spring Boot defaults) often do not have first-class H2 server support. Adoption is improving but slow.

Practical: even where end-to-end H2 is feasible, audit the transition carefully. A misconfigured H2-back-end that falls back to H1 on parse errors re-introduces the downgrade. Verify with explicit traffic capture.

### 11.2. Reject ambiguous CL+TE

Front-end rejects with HTTP 400 any request that contains both `Content-Length` and `Transfer-Encoding`. RFC 9112 §6.1 codifies this as the recommended behavior for security-conscious deployments. Cloudflare, AWS ALB, AWS CloudFront, GCLB, Azure Front Door all do this by 2024 for canonical obfuscations.

The gap is the long tail of obfuscation grammar (§9). Every obfuscation variant a server doesn't recognize as TE is an opening for "the obfuscated TE is silently dropped; the CL is honored; the back-end honors the same obfuscation as TE; CL.TE desync." Hardening means recognizing all obfuscations, not just the canonical form.

Concrete: nginx 1.18+ rejects whitespace-before-colon per RFC 9112 by default. Apache 2.4 has `HttpProtocolOptions Strict` (default since 2.4.55). HAProxy has `option http-buffer-request` and `option httplog`. Verify each by version.

### 11.3. Per-connection request limit + force-close on parse anomaly

If the front-end forces connection close after every parse anomaly — including any 400-class response — pool pollution becomes impossible. The smuggled bytes are still in the pool, but the pool entry is torn down before they can be served to another user.

Performance cost: connection-reuse is load-bearing for TLS amortization. Closing connections aggressively means more handshakes, more CPU, higher latency. The defense is correct but expensive.

A weaker variant: limit pool reuse to N requests per connection (typical N: 100). Reduces the blast radius without eliminating it.

### 11.4. Idempotency tokens at the application layer

Make smuggled requests fail server-side validation even if the parse succeeds. Every state-changing endpoint requires a token bound to the requesting user's session; smuggled requests carry the victim's session, but the attacker doesn't know the victim's token. The smuggled request reaches the back-end but rejects on token mismatch.

This is defense-in-depth, not a primary mitigation. The state-changing endpoint surface is large; coverage is uneven; token validation is easy to bypass at the application layer.

### 11.5. WAF as compensating control

WAFs catch known HRS signatures. Useful for fielding zero-days against the canonical shapes. Fragile against new obfuscation grammar — every new obfuscation in §9 that the WAF doesn't recognize is a WAF bypass.

The disciplined position: WAF for known shapes, parser hardening for the rest. Do not treat the WAF as the security boundary; treat it as alerting infrastructure.

### 11.6. Out of scope for this section

What this section does NOT cover:

- HTTP/2 frame-level fuzzing (RAPID-RESET CVE-2023-44487, Continuation Flood CVE-2024-27983 class). These are HTTP/2 DoS, not HRS — different bug class, different mitigations. Reference: Cloudflare and Google's joint disclosure of CVE-2023-44487 (October 2023).
- TLS-level desync attacks (e.g., session-resumption desync). These exist but live below the HTTP layer.
- Specific WAF-rule syntax. Different WAFs have different rule grammars; the relevant vendor docs change quarterly.

---

## 12. Incident corpus

Real-world exploitations, chronological where dates are public. Each entry cites the primary source only. The `[unverified specific advisory]` marker is liberally applied to date-specific or CVE-specific claims I cannot anchor without speculation — go to the vendor's advisory feed before treating these as canonical.

### 12.1. Watchfire 2005 demo set

Linhart, Klein, Heyes, Orrin's June 2005 paper cataloged working HRS against Apache, IIS, SunONE, WebLogic, Squid, and Tinyproxy of the era. The paper demonstrated cache poisoning of a Squid proxy, credential disclosure via response splitting, and authentication bypass via CL.CL on a SunONE / Apache pair. This is the canonical first systematic disclosure; the techniques have aged but the framing is unchanged. Source: https://www.cgisecurity.com/lib/HTTP-Request-Smuggling.pdf.

### 12.2. PortSwigger BHUSA 2019 demo: PayPal, Slack, Red Hat

James Kettle's "HTTP Desync Attacks: Request Smuggling, Reborn" (https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn) demonstrated working HRS against PayPal, Slack, and the Red Hat customer portal during the conference talk. The PayPal exploit reached login pages of other users; the Slack exploit reached privileged channels; the Red Hat exploit reached internal endpoints. All were CL.TE or TE.CL against AWS-fronted infrastructure of the era. Bug bounty payouts were significant per HackerOne's published disclosures.

Specific CVE attribution for these disclosures: `[unverified specific advisory]`. Treat the Kettle talk + the HackerOne reports as the primary source.

### 12.3. HAProxy CVE-2021-40346

Integer overflow in HAProxy's HTX header parser leading to HRS via crafted header lengths. Disclosed by JFrog Security Research in August 2021 (https://jfrog.com/blog/critical-vulnerability-in-haproxy-cve-2021-40346-integer-overflow-enables-http-smuggling/). Affected HAProxy 2.0 through 2.4 series; fixed in 2.0.25 / 2.2.17 / 2.3.14 / 2.4.4. The HTX bug is a textbook example of integer-overflow-as-parser-corruption: the header parser's length tracking wraps, and the wrapped value lets the attacker land a smuggled prefix where a longer header should have been. CVSS 8.6 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:N) per NVD.

### 12.4. Apache mod_proxy CVE-2021-33193, CVE-2021-40438

CVE-2021-33193 — Apache HTTP Server 2.4.x request splitting via crafted Transfer-Encoding header that the mod_proxy module forwarded literally to back-ends. Fixed in 2.4.49. Apache advisory at https://httpd.apache.org/security/vulnerabilities_24.html.

CVE-2021-40438 — mod_proxy SSRF reachable via crafted `uri-path` argument. Not strictly HRS but in the same advisory cluster and demonstrative of how mod_proxy's parsing surface accumulated bugs in that release cycle. Fixed in 2.4.49.

Source: Apache HTTP Server security advisories archive.

### 12.5. PortSwigger BHUSA 2021 demo: HTTP/2 desync against multiple targets

Kettle's "HTTP/2: The Sequel is Always Worse" (https://portswigger.net/research/http2) demonstrated H2.CL / H2.TE against several major CDNs and websites. Targets named in the paper and follow-up disclosures included Atlassian, Netflix, and Imperva — `[unverified specific advisory]` on the per-target CVE assignments; the paper itself is the primary source. The headline finding: HTTP/2-to-HTTP/1.1 downgrade re-introduces every HTTP/1.1 parser bug class, including ones the front-end didn't have when running pure H2.

### 12.6. Bishop Fox h2cSmuggler disclosures (2020)

Jake Miller's August 2020 h2cSmuggler blog post and tool release (https://bishopfox.com/blog/h2c-smuggling-request) included a tested-target list with reproducer commands. The reproducers ran against multiple production targets at the time of release; specific vendor advisory attributions are in the blog post's referenced disclosures.

### 12.7. PortSwigger BHUSA 2022 demo: browser-powered desync

Kettle's "Browser Powered Desync Attacks: A New Frontier in HTTP Request Smuggling" (https://portswigger.net/research/browser-powered-desync-attacks) demonstrated CL.0 against Amazon AWS console (the demo specifically named in the talk) plus several other targets. The class change here is structural: HRS no longer requires attacker control of a TLS-terminating proxy; the attacker's website is sufficient. Specific bounty attributions for the demonstrated targets are in the PortSwigger disclosure-acknowledgment archive.

### 12.8. GitLab HRS series 2020-2022

Multiple HRS-class issues affecting GitLab Pages and the GitLab application server were disclosed via the GitLab security advisories feed between 2020 and 2022. Specific CVE numbers and dates: `[unverified specific advisory]` without re-checking GitLab's advisory archive. The GitLab security advisories index at https://about.gitlab.com/releases/categories/releases/ is the source of truth.

### 12.9. Akamai 2024, Cloudflare 2024 HRS-related disclosures

There are multiple 2024 CDN-side HRS-related advisories and security blog posts but the specific CVE assignments and dates are `[unverified specific advisory]` without re-checking each vendor's advisory feed. Treat each vendor's security blog as the canonical reference.

### 12.10. PortSwigger BHUSA 2023: single-packet attack

Kettle's "Smashing the State Machine: The True Potential of Web Race Conditions" demonstrated single-packet race conditions against several major targets, including a $7,000 payout from a target the talk references. The headline structural claim: HTTP/2 framing makes server-side rate-limit and idempotency defenses against race conditions structurally weaker than they look at HTTP/1.1.

---

## 13. Cross-link cluster

This doc is the HRS-specific anchor. Related expertise:

- `[[reference-http-web-security]]` (file: `~/ai/expertise/software/http_web_security.md`) — Broader HTTP semantics, CORS, CSP, session management, the prerequisite protocol layer this doc assumes. Read this first if you don't yet know what `Transfer-Encoding: chunked` is.
- `[[reference-ssrf-url-parsing]]` — URL parser differentials are HRS's siblings. Same structural bug (two parsers disagreeing on the same byte string), different protocol surface.
- `[[reference-xml-parser-differential]]` — The protocol-differential class in XML. The xmldom multi-root CVE and the SAML XSW class are the XML-shaped HRS.
- `[[reference-race-conditions-concurrency]]` — The single-packet attack and HTTP/2 race conditions live here. HRS and race conditions are technically separate bug classes but share the HTTP/2 framing primitives.
- `[[reference-cicd-supply-chain]]` §2.7 — Cache poisoning at the GitHub Actions build cache; the analogous primitive to HRS-driven web cache poisoning. Same shape, different cache.
- `[[reference-detection-engineering]]` §10 — Detection-rule corpus pattern, including the FP-economics framing every HRS detection rule needs.
- `[[reference-code-review-expertise]]` — Auditing reverse-proxy configs for HRS-prone setups. The click-count severity framing applies: a single misconfigured `proxy_pass` is one click to exploit; an end-to-end H2 stack is multiple clicks away from desync.
- `[[reference-fuzzing-discipline]]` — HRS variant discovery via HTTP fuzzers. PortSwigger's HTTP Request Smuggler, defparam's smuggler, and the BHUSA toolchain are the practical HRS-fuzzing reference; the broader fuzzing methodology is in this expertise doc.
- `[[reference-vr-methodology]]` — HRS as a variant-analysis surface against new CDN releases. Every CDN release note is a hypothesis-generation surface; the variant-analysis methodology in vr-methodology applies directly.
- `[[reference-bug-hunting-first-principles]]` — The first-principles lens for HRS auditing: start with parser asymmetry, work outward. Hotspot is "boundary between two HTTP parsers in the same data flow."
