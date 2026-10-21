# HTTP and Web Security: Guiding Principles and Staff-Level Expertise

> Synthesized from the public research output of James Kettle (Director of Research, PortSwigger)
> and PortSwigger collaborators: Gareth Heyes, Martin Doyhenard, Zakhar Fedotkin.
> Auxiliary anchors: Bartek Nowotarski (CONTINUATION Flood, CVE-2024-27316 class), RyotaK / Flatt
> Security (first-sequence-sync extension to single-packet attack), Omer Gil (Web Cache Deception),
> Microsoft MSRC (postMessage anti-patterns, August 2025).
> Covers talks and papers from Black Hat USA/Europe, DEF CON, AppSec, 44CON, Nullcon, RomHack
> (2013–2025), plus 2024-2026 follow-on disclosures.
>
> **Cross-references:** Sibling expertise docs that did not exist when this guide was first drafted —
> `ssrf_url_parsing_expertise.md` (URL parser discrepancy class; covers SSRF-side primitives that
> overlap with cache-deception and host-header attack chains), `race_conditions_concurrency_expertise.md`
> (single-packet attack + first-sequence-sync details and broader concurrency literature),
> `webrtc_realtime_comms_expertise.md` (WebRTC/DTLS adjacency to QUIC and WebSocket research).

---

## I. Researcher Profiles

### James Kettle (@albinowax)
Director of Research at PortSwigger (makers of Burp Suite). Personal site: skeletonscribe.net / jameskettle.com.

His research arc follows a consistent pattern: find an unexploited or systematically underexplored vulnerability class, build tooling to scale discovery, demonstrate real-world impact at high-value targets, publish methodology and tool, then move to the next class. Each paper introduces a formal detection/exploitation methodology, not just individual bugs.

**Research progression (chronological):**
1. 2013 — Host header attacks and OAST (Burp Collaborator precursor)
2. 2015 — Server-Side Template Injection (SSTI)
3. 2016 — Backslash Powered Scanning (differential injection scanning)
4. 2016 — CORS misconfigurations (systematic exploitation of bitcoin exchanges)
5. 2017 — Hidden attack surface via reverse proxies / Collaborator Everywhere
6. 2018 — Web cache poisoning (unkeyed inputs methodology)
7. 2019 — HTTP Desync / request smuggling (CL.TE, TE.CL revival)
8. 2020 — Web cache entanglement (fat GET, parameter cloaking, normalization)
9. 2021 — HTTP/2 downgrade attacks (H2.CL, H2.TE, H2.X, request tunnelling)
10. 2022 — Browser-powered desync (CL.0, client-side desync, pause-based desync)
11. 2023 — Race conditions / single-packet attack
12. 2024 — Web timing attacks that actually work (200μs precision)
13. 2025 — HTTP/1.1 Must Die (0.CL, Expect-based desync, double-desync, RQP); BHUSA 2025 + DEF CON 33, paper at portswigger.net/research/http1-must-die

**Auxiliary contemporaries (non-PortSwigger but in-class):**
- **Bartek Nowotarski** — HTTP/2 CONTINUATION Flood, disclosed to CERT/CC in January 2024, advisory at https://nowotarski.info/http2-continuation-flood-technical-details/. The class spans CVE-2024-27316 (Apache httpd), CVE-2024-27983 (Node.js), CVE-2024-28182 (nghttp2), CVE-2024-24549 (Tomcat), CVE-2024-31309 (Apache Traffic Server), CVE-2024-27919 + CVE-2024-30255 (Envoy), CVE-2023-45288 (Go net/http), CVE-2024-2653 (amphp/http), CVE-2024-2758 (Tempesta FW), plus a Rust `h2` advisory (Snyk: https://snyk.io/blog/exploiting-http-2-continuation-frames-dos-attacks/).
- **RyotaK (Flatt Security)** — "Beyond the Limit: first-sequence-sync" extension (2024-08-02) to Kettle's single-packet attack, raising payload ceiling from ~1500 B to ~65535 B and request count from ~30 to ~10000 (https://flatt.tech/research/posts/beyond-the-limit-expanding-single-packet-race-condition-with-first-sequence-sync/).
- **Paolo Arnolfo, Guillermo Gregorio, Francesco Mariani** — independent TE.0 discovery against Google Cloud Load Balancer (~$8,500), incorporated into Kettle's 2025 framework.
- **Akamai Security Research Team** — CVE-2025-32094 writeup (https://www.akamai.com/blog/security/cve-2025-32094-http-request-smuggling) and CVE-2025-54142 (OPTIONS + body desync, https://www.akamai.com/blog/security-research/advisory-cve-2025-54142-http-request-smuggling-via-options-body).

### Gareth Heyes
Security Researcher at PortSwigger. Author of *JavaScript for Hackers* and the PortSwigger XSS Cheat Sheet. Research areas: AngularJS sandbox escapes, prototype pollution, CSS exfiltration, email parser exploitation. Created DOM Invader (browser-integrated PP detection), Hackvertor (encoding transformation BApp), Taborator.

### Martin Doyhenard
Security Researcher at PortSwigger. Specializes in HTTP server exploitation and URL parsing discrepancy attacks. Primary author of "Gotta Cache 'Em All" (Black Hat USA 2024) — URL parsing discrepancies for both web cache poisoning and web cache deception. Also researched SAP IPC exploitation (affecting 200,000+ companies). Conferences: Black Hat USA, DEF CON, RSA, EkoParty, Hack in The Box, Troopers.

### Zakhar Fedotkin
Security Researcher at PortSwigger. Specializes in source code analysis, image processing library vulnerabilities, HTTP clients/frameworks. Research: cookie sandwich technique (HttpOnly bypass via RFC2109 legacy parsing), WAF bypass via `$Version` phantom cookie, SAML authentication bypasses, `__Host`/`__Secure` prefix bypasses, WebSocket Turbo Intruder, VS Code ASCII exploitation.

---

## II. Core Research: HTTP Request Smuggling

### The Fundamental Problem

HTTP/1.1 persistent connections (keep-alive) create a stateful socket between servers. RFC 7230 §3.3.3 says: if both `Content-Length` and `Transfer-Encoding` are present, TE overrides CL. But many servers don't enforce this, and chained proxy architectures parse these headers differently — creating ambiguity about where one request ends and another begins.

HTTP/1.1 has a **fatal architectural flaw**: request boundaries are consistently ambiguous in any chained proxy system. The only structural fix is HTTP/2 end-to-end (binary framing with built-in length, no CL/TE ambiguity).

### Classic HTTP/1.1 Variants (2019 Research)

**CL.TE:**
- Front-end uses `Content-Length` → forwards N bytes.
- Back-end uses `Transfer-Encoding: chunked` → reads body as chunked.
- Attacker sends a small `Content-Length` that covers only the chunk header + `0\r\n\r\n` terminator. Back-end treats the trailing bytes as the start of the next request.
- Detection: CL.TE timeout — send request designed to cause back-end to hang waiting for next chunk.

**TE.CL:**
- Front-end uses `Transfer-Encoding` → reads full chunked body.
- Back-end uses `Content-Length` → reads only N bytes; rest becomes next request prefix.
- Detection: TE.CL timeout — send chunked request where back-end will wait for data to match its Content-Length.

**TE.TE (obfuscation):**
Both servers support TE; attacker makes TE visible to one but not the other:
- `Transfer-Encoding: xchunked`
- `Transfer-Encoding : chunked` (space before colon)
- Tab characters in the header name or value
- Line-wrapped TE value (obsolete folding)
- `Transfer-Encoding: \x00chunked` (null byte prefix)
- `Transfer-Encoding: identity\r\nTransfer-Encoding: chunked` (chained values)

Named bounty highlights: PayPal $18,900 + $20,000 (TE:chunked filter bypass + Akamai line-wrap bypass); Trello (auth cookie theft); F5 BIG-IP advisory K50375550.

### HTTP/2 Downgrade Attacks (2021 Research)

HTTP/2 uses binary framing with built-in stream length — no CL/TE ambiguity by design. But when a front-end speaks HTTP/2 to clients and downgrades to HTTP/1.1 for the backend, it must synthesize CL or TE headers. RFC 9113 prohibits connection-specific headers (TE, Transfer-Encoding, Connection) in HTTP/2 — but many servers accept them anyway.

**H2.CL:** Front-end ignores injected `Content-Length` in HTTP/2 request during downgrade. Attacker injects CL that mismatches actual body length. Back-end reads only N bytes, leaving remainder as next request prefix.
- CVE-2021-21295: Netflix/Netty. $20,000 bounty.

**H2.TE:** HTTP/2 requests shouldn't have `Transfer-Encoding` (RFC-prohibited). AWS ALB accepted it anyway. Enabled H2.TE desync against any backend behind an AWS ALB.
- Verizon identity portal: $7,000. Verizon AOL accounts: $10,000.

**H2.TE via header injection:** CRLF (`\r\n`) embedded in HTTP/2 header values injects headers during HTTP/1.1 downgrade.
- Netlify CDN + Firefox start page: $4,000.

**H2.X via request splitting:** Double line-breaks terminate headers prematurely during downgrade.
- Atlassian Jira: response queue poisoning — users received others' auth tokens. $15,000 (triple max bounty).

**H2.TE via header name injection:** Colons in HTTP/2 header names inject `transfer-encoding: chunked` as a separate header.

**H2.TE via request line injection:** Pseudo-headers like `:method` inject complete HTTP/1.1 request lines.

**Request tunnelling:** Front-end creates a new connection per request. Attacker tunnels a complete HTTP request inside the first. HEAD method trick for blind tunnelling: HEAD response over-reads by Content-Length, leaking the tunnelled response. Used to discover internal headers via Param Miner.

CVE-2021-33193: Apache mod_proxy — spaces in `:method` pseudo-header inject request line.

Turbo Intruder HTTP/2 stack character mappings: `^` → `\r`, `~` → `\n`, `` ` `` → `:`. Enables malformed request construction that Burp's normal inspector blocks.

### Browser-Powered Desync (2022 Research)

**CL.0 desync:** Back-end ignores `Content-Length` entirely on specific endpoints (static files, redirect handlers). Attacker exploits browser connection reuse — browser keeps a pooled connection alive, sends second request through it, back-end treats second request's body as next request prefix.
- IIS reserved filenames (`/con`, `/nul`) act as early-response gadgets: server sends response before reading full request body.

**Client-Side Desync (CSD):** Targets browser connection pools, not server-to-server connections. Victim visits attacker page. Attacker page makes `fetch()` with `mode: 'no-cors', credentials: 'include'` to victim site — poisons victim's browser connection pool. Works against single-server sites (no proxy needed).
- Verisign.com: CSD via POST to `/%2f`.
- Capital One: via Akamai redirect CL.0.

**Pause-Based Desync:** Send partial HTTP request → pause → server timeout leaves connection open → resumed data treated as new request.
- Varnish: 15-second timeout. CVE-2022-23959.
- Apache httpd: CVE-2022-22720 (patched March 2022).
- Can be triggered MITM-style without decryption via TCP packet delay (tc-NetEm, ~90% success rate).

**H2.0:** HTTP/2 requests without `Content-Length` cause confusion on downgrade. AWS ALB added `TE: chunked` without modifying body.

**Connection state attacks:**
- First-request validation: WAF/proxy whitelists only the first request on a connection; subsequent requests go unchecked.
- First-request routing: proxy routes all subsequent requests to the backend that handled the first request, regardless of path.

**Stacked HEAD attacks:** Multiple HTTP responses using HEAD requests with crafted headers → inject malicious JavaScript into response queue.

### HTTP/1.1 Must Die — The Endgame (2025 Research)

Four length interpretation methods now in play: `CL` | `TE` | `0` (implicit-zero) | `H2` (built-in). Every combination of these at front-end vs. back-end is a potential desync.

**0.CL desync:** Front-end doesn't recognize `Content-Length`; treats request as zero-length. Back-end uses CL to read a body that the front-end already consumed or ignored.

**Expect-based desync:**
- `0.CL via Expect:` — bare `Expect:` header triggers early response from some servers.
- `0.CL via obfuscated Expect:` — `Expect: y 100-continue` (malformed value) triggers different parsing.
- `CL.0 via Expect:` — expect triggers a response before body is consumed.

**Double-desync:** First request creates 0.CL desync; the poisoned connection then converts the second request into a CL.0 desync. Two-stage amplification.

**TE.0:** Front-end uses `Transfer-Encoding`; back-end treats request as zero-length. Independently discovered by Paolo Arnolfo, Guillermo Gregorio, Francesco Mariani against Google Cloud ($8,500 bounty). Incorporated into Kettle's 2025 framework.

Affected infrastructure (2025): Akamai (CVE-2025-32094 — OPTIONS + obsolete line folding, $9,000); Cloudflare (24M+ exposed websites, $7,000); Netlify (no bounty; out of scope); T-Mobile ($12,000); GitLab ($7,000); LastPass via Akamai ($5,000). Total across all bounty hunters: $350,000+ including $221,000 from 74 Akamai-related reports.

**V-H vs H-V parser-discrepancy taxonomy (2025 primitive vocabulary).** Kettle's HTTP Request Smuggler v3.0 reframes detection around two primitives rather than the legacy CL/TE matrix:

- **Visible-Hidden (V-H):** a header is visible to the front-end but hidden from the back-end. Bypasses front-end security checks that the back-end never re-evaluates. Maps to classic CL.0 / 0.CL gadgets where the front-end honored a length the back-end ignored.
- **Hidden-Visible (H-V):** a header is hidden from the front-end but visible to the back-end. The back-end reads a body length the front-end never accounted for; trailing bytes become the prefix of the next request. AWS ALB's HTTP/2 → HTTP/1.1 downgrade adding `Transfer-Encoding: chunked` against an IIS back-end is the canonical H-V chain.

The H-V / V-H reframing is load-bearing for 2025-era hunting: the methodology is "find any pair of systems that disagree about a header's presence," not "find CL+TE confusion." See https://portswigger.net/blog/http-1-1-must-die-what-this-means-for-bug-bounty-hunters for the v3.0 tool retrospective. New companion BApp **HTTP Hacker** surfaces parser mismatches directly rather than chaining them to canned exploits.

**CVE-2025-32094 mechanics in detail.** Akamai's own writeup (https://www.akamai.com/blog/security/cve-2025-32094-http-request-smuggling) confirms the trigger: an `OPTIONS *` request with `Expect: 100-continue` and a header value continued across lines using obsolete RFC 7230 §3.2.4 line folding. Akamai's front-end accepted the folded header; the back-end parsed the folded continuation as the start of a smuggled request. Time to full remediation: 65 days from disclosure. The closely-related CVE-2025-54142 ("OPTIONS + body") extended the same Akamai parser quirk; advisory at https://www.akamai.com/blog/security-research/advisory-cve-2025-54142-http-request-smuggling-via-options-body.

**HAProxy HTTP/3 desync (CVE-2026-33555).** A 2026 demonstration that HTTP/3 is not immune: a single zero-byte QUIC packet desynchronizes HAProxy's backend connection pool, smuggling HTTP/1.1 requests across unrelated users — even across distinct frontend protocols (HTTP/2-client → HTTP/1.1-backend leakage via the shared pool). HAProxy forwards a request with a `Content-Length` that doesn't match the actual body size; the back-end's early response drains the pending body off the TCP socket and consumes bytes belonging to the next request. PoC at https://github.com/r3verii/CVE-2026-33555. This confirms Kettle's thesis from a different angle: even moving frontend to HTTP/3, if the backend hop is HTTP/1.1, the desync class persists.

**HTTP/2 CONTINUATION Flood (CVE-2024-27316 class).** Discovered by Bartek Nowotarski and disclosed to CERT/CC in January 2024. A HEADERS frame followed by an unbounded sequence of `CONTINUATION` frames without the `END_HEADERS` flag — many HTTP/2 implementations buffer or process each frame's HPACK-decoded headers even after exceeding configured header-list limits, producing OOM crashes from a **single TCP connection or a handful of frames**. Critically: attack traffic is not visible in HTTP access logs because access-log writes happen on request completion, and no CONTINUATION-flood request ever completes. This is an observability gap — defenders cannot trivially identify the source IP from standard logs. Class spans `httpd`, Node.js, Tomcat, Apache Traffic Server, Envoy, Go net/http, nghttp2, amphp/http, Tempesta FW, and the Rust `h2` crate (CVE list in researcher-profile section above). Mitigation: enforce a hard cap on cumulative HPACK-decoded header octets per stream and on CONTINUATION-frame count per HEADERS frame.

### Specific Proxy/CDN Behavior Reference

| System | Observed Behavior |
|--------|-------------------|
| Akamai (pre-2019) | Front-end didn't support chunked TE → CL.TE device |
| Akamai (CVE-2025-32094) | OPTIONS + `Expect: 100-continue` + obsolete line folding → request splitting |
| AWS ALB | Added `Transfer-Encoding: chunked` on HTTP/2 downgrade without modifying body (H2.0) |
| Varnish | 15-second timeout on partial requests (pause-based desync, CVE-2022-23959) |
| Apache httpd | Pause-based desync on server-generated redirects (CVE-2022-22720) |
| Apache mod_proxy | Spaces in `:method` → request line injection (CVE-2021-33193) |
| HAProxy | Vertical tab normalization failure (fixed v2.0.6); integer overflow CVE-2021-40346 (JFrog) |
| Cloudflare | WAF checks only first duplicate header for cache key; normalizes many smuggling attempts |
| Fastly | Normalizes most smuggling; port exclusion from cache key exploitable |
| nginx | Cache key URL-decoding normalization discrepancy (`%3f` → `?`) |
| IIS | Reserved filenames (`/con`, `/nul`) as early-response gadgets for 0.CL |
| F5 BIG-IP | Desync advisory K50375550 (2019) |
| Cisco ASA WebVPN | CL.0 on most endpoints (CVE-2022-20713, deprecated — no fix) |
| Pulse Secure VPN | CL.0 on static files |
| Netlify | H2.TE via header injection; also affected by Firefox update poisoning; 2025 RQP via Expect leaks internal deployment IDs |
| Akamai (CVE-2025-54142) | OPTIONS + body desync (companion to CVE-2025-32094) |
| HAProxy (CVE-2026-33555) | HTTP/3 zero-byte QUIC packet → cross-protocol backend pool desync |
| LSQUIC / LiteSpeed (CVE-2025-54939) | Pre-handshake QUIC memory leak via coalesced packets with invalid DCID; bypasses post-handshake QUIC flow controls |
| Google Cloud Load Balancer | TE.0 desync, independently discovered, ~$8,500 (Arnolfo / Gregorio / Mariani 2024) |

---

## II-B. Core Research: HTTP/2 and HTTP/3 Frame-Level Denial-of-Service

### Rapid Reset (CVE-2023-44487, October 2023)

Reference baseline for the HTTP/2 frame-DoS class. Attacker opens a stream (HEADERS frame), then immediately cancels it (RST_STREAM). The cancelled stream frees the stream slot at the framing layer, allowing the attacker to re-open another stream within the same connection. Server-side request-handling state (URL parsing, routing, downstream calls) often outlives the framing-layer cancellation, so a single connection can drive request work at rates far above the configured `SETTINGS_MAX_CONCURRENT_STREAMS`. Observed in the wild at 398 million RPS against Google (https://blog.cloudflare.com/zero-day-rapid-reset-http2-record-breaking-attack/). Mitigations: cap the rate of RST_STREAM frames per connection; drop streams that emit RST_STREAM without ever sending data; close the connection on threshold exceedance.

### CONTINUATION Flood (CVE-2024-27316 class, April 2024)

Discovery: Bartek Nowotarski, disclosed to CERT/CC in January 2024. Mechanism summarized in section II above. Two structural properties make this class worse than Rapid Reset:

1. **Single connection, sometimes single stream** — Rapid Reset needs many streams; CONTINUATION Flood needs only one stream with an unbounded CONTINUATION frame sequence. The DoS budget is set by frames-per-stream, not streams-per-connection.
2. **Invisible to access logs** — HTTP access-log infrastructure writes on request completion. A flood request never completes, so the source IP and User-Agent never reach the log. Standard nginx / Apache / IIS / cloud-load-balancer log pipelines all miss the traffic. Detect via H2 frame counters (`nghttp2`'s `--continuation-frame-limit` style metrics) or via stream-lifetime histograms exported by the server's HTTP/2 stack.

Cross-implementation patch summary: each affected stack landed a per-stream cumulative-header-size cap and (most) a per-HEADERS CONTINUATION-count cap.

### QUIC-LEAK (CVE-2025-54939, August 2025)

Imperva discovery (https://www.imperva.com/blog/quic-leak-cve-2025-54939-new-high-risk-pre-handshake-remote-denial-of-service-in-lsquic-quic-implementation/). LSQUIC's packet-parsing logic counts invalid coalesced QUIC Initial packets (those with malformed Destination Connection IDs) against amplification limits, but does not free their `packet_in` structures. Memory leaks accumulate per malformed packet until OOM. The vulnerability sits **pre-handshake**, so the post-handshake QUIC connection limits, stream controls, and flow regulation never engage.

Affected downstreams: LiteSpeed Web Server (~14% of all websites, ~34% of HTTP/3-enabled sites per Imperva), OpenLiteSpeed, every product that vendors LSQUIC. Fixed LiteSpeed v6.3.4 / OpenLiteSpeed v1.8.4. Disclosure: 2025-07-15. Patch: 2025-07-18. Public advisory: 2025-08-18.

**Generalizable lesson:** QUIC's pre-handshake surface is an "ungoverned territory" — any state machine that allocates per-packet structures before a session exists must bound those allocations with no expectation of help from later flow controls. This applies to every QUIC implementation, not just LSQUIC.

---

## III. Core Research: Web Cache Poisoning

### Foundational Methodology (2018)

The cache poisoning threat model: caches store responses keyed on a subset of request attributes. Inputs forwarded to the backend but excluded from the cache key are "unkeyed." If the backend reflects an unkeyed input in its response, the attacker can poison the cached response for every user requesting that URL.

**Attack workflow:**
1. Identify candidate unkeyed inputs (use Param Miner — 50,000+ wordlist + harvested terms).
2. Inject payload into unkeyed input; verify backend reflects it in response.
3. Confirm caching via response headers (`Age`, `X-Cache`, `CF-Cache-Status`).
4. Attack: trigger caching of the malicious response.
5. Safe testing: always use cache-buster parameter during research to avoid real poisoning.

**Common unkeyed headers (empirically confirmed):**
- `X-Forwarded-Host` — most widely abused; controls `request.host` in many frameworks.
- `X-Forwarded-Server` — similar host override.
- `X-Forwarded-Scheme` — controls URL scheme in generated responses.
- `X-Original-URL`, `X-Rewrite-URL` — path override in Symfony/Zend (CVE-2018-14773, ZF2018-01, SA-CORE-2018-005).
- `translate`, `bucket`, `path_info` — custom headers in specific frameworks.

Named targets: Mozilla SHIELD (X-Forwarded-Host → Firefox recipe-fetch hijacked, tens of millions of users, $1,000 bounty); Drupal (two-stage nested cache poisoning, internal + external cache); Pinterest (JavaScript redirect hijacking).

### Web Cache Entanglement (2020)

**Unkeyed query parameters:** Some sites exclude the entire query string from cache keys (for "clean" caching). If a parameter in the excluded query string is reflected by the backend, attacker injects XSS payload in that parameter.

**Fat GET technique:** Some frameworks (Rails, etc.) accept `GET` requests with request bodies. Caches treat GET as bodyless and ignore the body when constructing the cache key. Body parameters can override query parameters. Attacker injects via body; cache key unchanged; all users see the injected response.
- GitHub: $10,000 bounty.
- Zendesk + Rails + Cloudflare: Fat GET combo.

**Cache parameter cloaking:** Regex-based cache key rules exclude specific parameters (e.g., `utm_source`). Alternate delimiters can sneak additional parameters inside the "excluded" parameter as far as the cache regex is concerned:
- `;` in Rails (matrix variable syntax)
- `$` characters
- Encoded `?` (`%3f`) in cases where origin decodes but cache does not

**Cache key normalization discrepancy:** Cache normalizes URLs before applying rules; backend normalizes after. Example: nginx decodes `%3f` → `?` while constructing cache key, matching an update URL pattern. Mozilla Firefox update pipeline poisoned via this discrepancy.

### URL Parsing Discrepancy Attacks (Doyhenard, 2024)

Martin Doyhenard's "Gotta Cache 'Em All" extended cache poisoning and cache deception via origin server delimiter behaviors not recognized by CDN caches:

- **Spring (Java):** Semicolons (`;`) for matrix variables — `path;param=value` routes to `path` on origin, but cache stores key including `;param=value`.
- **Rails (Ruby):** Dots (`.`) for formatter extensions — `resource.json` routes to `resource` on origin.
- **OpenLiteSpeed:** Null bytes (`%00`) truncate path.
- **Nginx with rewrite rules:** Newlines (`%0a`) in path.

Most CDNs only recognize `?` as a query delimiter. Attacker crafts URL using origin-specific delimiters to make cache and origin disagree about what's being requested.

**Static extension exploitation:** `dollar sign` delimiter on origin + `?` on proxy → cache stores dynamic content as `.js` or `.css` file.

**Static directory attacks:** Encoded dot-segments (`%2e%2e`) bypass cache rules matching `/static`, `/assets`, `/wp-content` — origin normalizes and serves dynamic content; cache stores it as static.

CDNs tested: Cloudflare, Akamai, CloudFront, Google Cloud CDN, Azure CDN, Imperva, Fastly.

### Doyhenard's Three Named Primitives (BHUSA 2024 / DEF CON 32)

Doyhenard's published paper at https://portswigger.net/research/gotta-cache-em-all crystallizes the URL parsing-discrepancy class into three named attack categories:

1. **Arbitrary Web Cache Deception:** Force storage of dynamic responses by exploiting static-extension or static-directory cache rules. The cache thinks it stored `/MyAccount.css`; the origin served `/MyAccount` (user-specific PII). Any subsequent unauthenticated request to `/MyAccount.css` retrieves the cached PII.
2. **Arbitrary Web Cache Poisoning:** Modify cache keys via origin-specific delimiters so that a benign cache entry (e.g., the home page) is replaced with content from a different endpoint (e.g., an open redirect). Particularly effective against Microsoft Azure per the BHUSA writeup.
3. **Cache-What-Where:** Chain a normally-unexploitable primitive (open redirect, weak reflected XSS, JSON injection) with cache poisoning to upgrade severity to full-site compromise. Caches turn one-shot reflected bugs into persistent stored bugs against every cache-hitting user.

**Real-corpus targets disclosed:** Nginx-Cloudflare path-normalization disagreement enabling Static Path Deception; Apache-CloudFront equivalent (CloudFront normalizes before cache-rule evaluation by default); Microsoft Azure Cloud (cache-key confusion via `#`-delimited fragments). Burp Scanner now ships a web-cache-deception detector built from this research; PortSwigger's Web Security Academy added matching labs.

### Web Cache Deception Lineage (Omer Gil, 2017 → 2024 Methodology Work)

Original disclosure: Omer Gil 2017 (http://omergil.blogspot.com/2017/02/web-cache-deception-attack.html), targeting PayPal. Academic follow-up (Mirheidari et al., USENIX Security 2020 / 2022) studied 340 high-profile sites from the Alexa Top 5K (2020) and detected 1188 vulnerable sites in the Alexa Top 10K (2022). Filippo Berto's CLOSER 2024 paper (https://air.unimi.it/retrieve/7df93d97-538a-4df6-9355-7625561e0416/CLOSER_2024_36_CR%20(1).pdf) formalized a methodology for WCD vulnerability discovery, including encoded-delimiter probes (`%2f`, `%3b`, `%23`) and origin-server fingerprinting. Doyhenard's 2024 work is the natural successor — it generalizes WCD to URL-parsing-discrepancy class and ships actionable origin-specific delimiter taxonomies.

### DOM-Based Cache Poisoning

Attacker poisons a response containing JavaScript that reads from `location`, `document.referrer`, or similar and loads external resources. When users receive the poisoned cached response, their browsers execute the JS and load attacker-controlled scripts. Does not require reflected XSS in headers — only requires the JavaScript to use URL fragments or parameters from the cached response.

### Cache Poisoning for DoS

Single request can cache a redirect or error response for all users hitting a target URL. A cacheable 403 is an unintentional DoS vector. Kettle documented responsible disclosure: always use cache-buster parameter so PoC doesn't poison production; inform the vendor that the PoC was safe.

### Cloudflare Cache Poisoning Bypass (Post-2018)

Cloudflare deployed two defenses after the 2018 research:
1. WAF rule blocking XSS chars in `X-Forwarded-Host`.
2. Added `X-Forwarded-Host` to the cache key.

Bypass: Cloudflare only checks the *first* instance of duplicate headers for the cache key. Submit two `X-Forwarded-Host` headers — first is benign (excluded from cache key per Cloudflare optimization), second is malicious (concatenated by the backend). Cache serves poisoned response; WAF never inspects second instance.

---

## IV. Core Research: Web Timing Attacks (2024)

### The Problem with Timing Attacks

Prior to Kettle's 2024 work, timing attacks were considered impractical for remote exploitation. The research reduced the minimum detectable differential from 30,000μs to **200μs**.

### Single-Packet HTTP/2 Timing

Send two HTTP/2 requests in a single TCP packet. Both arrive at the server simultaneously; server processes them concurrently. Response arrival order and differential reveal processing time. Eliminates TCP round-trip jitter from the measurement.

### Dual-Packet Synchronization

PING frames force OS coalescing of header frames. Eliminates the "sticky request-order problem" (first request gets a head-start in processing) which biases all prior timing measurements. Steps:
1. Send PING frame + header frames for both requests in one packet.
2. OS coalesces into single segment.
3. Both requests start processing simultaneously.
4. Measure response differential.

### Bottom-Quartile Measurement

Compare the bottom quartile of 30 measurements to filter server-side noise (GC pauses, thread scheduling, I/O variance). The minimum reflects the true processing time; noise inflates but never deflates the measurement.

### DNS Caching Detection

Requests with domain names in headers detect DNS lookups via timing. Absence of DNS lookup = domain cached = system is querying it regularly (reveals hidden reverse proxies and internal routing).

**Overlong DNS label:** 64-octet labels are invalid per RFC and prevent the lookup attempt — useful as a negative control.

### Applications

- **Blind injection detection:** Different code paths (e.g., valid vs. invalid SQL) produce different timing signatures at 200μs precision.
- **Hidden reverse proxy discovery:** Hundreds of previously invisible proxies found, exposing tens of thousands of domains behind them.
- **WAF detection:** WAF processing adds measurable latency.
- **IP spoofing detection:** 375 vulnerable domains found among 30,000 test sites — servers trusting `X-Forwarded-For` without verification show timing differentials based on IP-based logic.
- **SonarQube behind firewall-blocked route:** Timing revealed existence of internal service before any content was returned.

### Four Vulnerability Categories Named in the 2024 Paper

The Black Hat USA 2024 paper at https://i.blackhat.com/BH-US-24/Presentations/US-24-Kettle-Listen-to-the-whispers-web-timing-attacks-that-actually-work.pdf formalizes the techniques into four attack categories that are now the canonical vocabulary:

1. **Masked misconfigurations.** Server responds identically (e.g., generic 404) regardless of input but parsing cost differs. Timing reveals hidden behavior: presence of a `commonconfig` header expecting JSON, presence of an undocumented internal-only feature flag, presence of an auth bypass on a specific path.
2. **Blind data-structure injection.** Inject malformed JSON / XML / GraphQL into a parameter; if the server delegates parsing to a more expensive logger or trace-emitter on parse failure, the timing diff signals a reachable parser. Confirmed against blind SQLi at ~8ms cost differential (162ms vs 170ms with quote injection).
3. **Hidden routes to forbidden areas.** Reverse-proxy front-end routes requests differently based on path / header content. Two requests differing only in `X-Forwarded-For` IP value — server with timing-sensitive geolocation lookup leaks the lookup. The 2024 study found 375 vulnerable domains among 30,000 tested.
4. **Invisible attack surface.** DNS-cache-presence detection (request causes DNS lookup → timing spikes; subsequent request hits cache → spike disappears). Reveals which domains a backend regularly queries → reveals hidden reverse proxies, analytics endpoints, observability targets. Overlong DNS labels (64+ octet) act as a negative control: invalid per RFC 1035 §2.3.4, so no lookup is ever attempted regardless of cache state.

### Tooling Notes

- **`h2spacex`** — open-source HTTP/2 framework; per the paper, Kettle was working with its developer to integrate the technique.
- **Param Miner** — extended with timing-mode analysis: compares the bottom quartile of 30 measurements per set.
- **Methodology core (carry-forward):** disable `TCP_NODELAY`; send a sacrificial PING frame followed by both header frames; withhold final data bytes; wait 100ms; release. The OS coalesces the trailing fragments into a single TCP segment, so both requests cross the network at the same instant. Compare bottom-quartile of 30 measurements per request, not the mean.

---

## V. Core Research: Race Conditions (2023)

### Beyond Limit Overruns

Classic race condition attacks target limit checks (e.g., coupon redemption before counter increments). Kettle's 2023 research identified richer attack classes:

**Sub-state attacks:** A single HTTP request transitions through multiple fleeting hidden states during processing. Between state A (validated) and state B (committed), the object is in an intermediate state that another concurrent request can observe or corrupt.

**Multi-endpoint collisions:** Race simultaneous operations across different endpoints that share state. Classic example: email verification token processing racing against email address change — use old token with new address.

**Partial construction attacks:** Objects are created in multi-step processes. The insecure intermediate state (created but not fully initialized) is exploitable.

**Deferred collisions:** Backend uses batched processing. Requests don't need to be synchronized in real-time — they collide when the batch runs.

### Single-Packet Attack

Prior best technique: "last-byte sync" — hold final byte of all requests, release simultaneously. Median spread ~4ms (standard deviation 3ms) over the network.

**Single-packet attack:** 4–10x improvement. Uses HTTP/2 multiplexing:
1. Send 20–30 requests, each withholding its final fragment.
2. Wait for network stabilization (connection state quiet).
3. Release all final fragments simultaneously → OS coalesces into a single TCP packet.
4. Server processes all requests starting from one network event.
5. Achieves 20–30 requests within a <1ms window (measurably works Melbourne→Dublin).

Turbo Intruder implementation: `Engine.BURP2`, `concurrentConnections=1`, gate-based synchronization.

CVE-2022-4037: GitLab email confirmation token misdirecting via Devise framework — medium severity, patched January 2023.

### First-Sequence-Sync Extension (RyotaK, 2024)

The original single-packet attack was bounded by Ethernet MTU (~1500 bytes), capping payload at roughly 20-30 small concurrent requests. RyotaK's "Beyond the Limit: Expanding single-packet race condition with first sequence sync" (https://flatt.tech/research/posts/beyond-the-limit-expanding-single-packet-race-condition-with-first-sequence-sync/, 2024-08-02) lifts the cap to the TCP window limit (~65,535 bytes, ~10,000 small requests) by combining two mechanisms:

1. **IP fragmentation:** a large TCP payload is split into multiple IP fragments. The server's NIC/kernel reassembles before delivering to userspace.
2. **TCP sequence-number reordering:** the attacker sends every fragment **except** the one with the lowest sequence number first. The kernel buffers the out-of-order fragments and waits. When the lowest-sequence fragment arrives last, the entire payload is committed to userspace in a single delivery — and userspace sees all requests at the same instant.

**Throughput observed:** ~10,000 synchronized requests in ~166 ms. Newly exploitable: rate-limited one-time-token brute-force endpoints (1000+ attempts in a race window vs prior ~10), bulk-redemption races, batch processing windows that were too narrow for the 1500 B variant.

**Implementation:** RyotaK published a proof-of-concept repository; Burp Suite/Caido integration was listed as future work. Cross-link to `race_conditions_concurrency_expertise.md` for the broader concurrency literature including non-HTTP single-packet variants and the TOCTOU adjacency.

---

## VI. Core Research: Server-Side Template Injection (2015)

SSTI occurs when user input is embedded into a template that is then evaluated by the template engine. Distinct from XSS because the payload executes server-side.

### Detection Decision Tree

Language-differentiating payloads reveal engine identity:
- `{{7*'7'}}` → `49` = Twig; `7777777` = Jinja2
- `${7*7}` → `49` = Smarty or FreeMarker
- `<%= 7*7 %>` = ERB (Ruby)

If the application reflects `49` or `7777777`, template injection is confirmed.

### Exploitation Chains

- **FreeMarker (Java):** `${freemarker.template.utility.Execute?new()("id")}` — uses the `Execute` class which runs system commands.
- **Velocity (Java):** Use the `$class` ClassTool helper (`inspect`/`type`) to reach `java.lang.Runtime` via reflection.
- **Smarty (PHP):** Secure mode bypass via `Smarty_Internal_Write_File::writeFile()` (fixed v3.1.24).
- **Twig (PHP, sandboxed):** `displayBlock()` method for sandbox escape (fixed v1.20.0).
- **Jade/Node.js:** `root.process.mainModule.require('child_process').exec('id')`.

Real-world cases confirmed: Alfresco CMS (low-privilege stored SSTI chain), XWiki Enterprise (low-privilege RCE via Velocity).

---

## VII. Core Research: Scanning and Detection Methodology

### Backslash Powered Scanning (2016)

Alternative to signature-based scanning. Core insight: instead of sending known-bad payloads and looking for known-bad responses, send *differential probes* and classify responses:
1. Send two distinct probes with different injection characters (including backslash).
2. Classify response differential: boring (no change) / interesting (structural change) / vulnerable (error or execution).
3. Follow up on interesting/vulnerable with targeted probes.

Benefits: finds both known injection classes and unknown ones; tiny network footprint; WAF evasion (no signature to match). Extended at NorthSec 2017 to auto-escalate HTTP parameter pollution and JSON injection to RCE.

### Out-of-Band Application Security Testing (OAST)

Introduced via 44CON 2015 ("Hunting Asynchronous Vulnerabilities"). The technique: inject payloads that trigger *outbound* requests (DNS, HTTP) to an attacker-controlled server (Burp Collaborator). If the Collaborator receives a callback, injection succeeded — even if the application response gives no indication.

**Why DNS callbacks specifically:** DNS is rarely filtered even in hardened environments; many injection payloads can trigger DNS lookups; DNS reveals the vulnerable server's identity even when the HTTP response is blocked.

OAST payload targets:
- Blind SQL injection (MS SQL `xp_dirtree`, Oracle XML+XXE chain, PostgreSQL `COPY TO`)
- Blind XSS (stored, fires when admin views report)
- Second-order injection (fires when a batch job processes stored data)
- XXE with multi-vector XML payloads (XXE/XInclude/schema location all in one document)
- SSRF via URL parameters

Burp Collaborator is the production tool built from this research.

### Cracking the Lens: Hidden Attack Surface (2017)

Methodology for testing systems invisible in normal testing: reverse proxies, load balancers, backend analytics systems.

**Technique:** Exploit-induced callbacks via Burp Collaborator. Send malformed requests that trigger outbound DNS/HTTP from the proxy layer, revealing its existence and identity. Scaled with ZMap/ZGrab across tens of thousands of IPs.

Specific techniques:
1. Invalid `Host` header → callbacks from intermediary proxy (found 27 DoD servers/ISPs).
2. Request-line URL overriding `Host` header.
3. Ambiguous URL parsing: `Host: target.net:80@attacker.net`.
4. Authority-component abuse: `GET @attacker.net/ HTTP/1.1`.
5. Pre-emptive caching abuse: reflected XSS makes the proxy fetch and cache an attacker-chosen internal URL.

Notable finds: Yahoo Traffic Server exposing load balancer admin panels ($15k + $5k); BT CleanFeed (covert HTTP interception proxy; port 443 left alone); METROTEL Colombia (DNS poisoning + HTTPS interception).

---

## VIII. Core Research: CORS Misconfigurations (2016)

Systematically attacked bitcoin exchanges and high-value bug bounty targets.

### High-Severity Patterns

**Origin reflection with credentials:**
`Access-Control-Allow-Origin: [reflected Origin]` + `Access-Control-Allow-Credentials: true`
Attacker controls origin → reads cross-origin credentialed responses → steals API keys, session tokens.

**Subdomain whitelist prefix bypass:**
Whitelist checking `btc.net` prefix accepts `btc.net.evil.net` if string-prefix checked rather than parsed as origin triple.

**Null origin:**
`Access-Control-Allow-Origin: null` + credentials. Sandboxed iframes generate null origin. Attacker uses sandboxed iframe to make credentialed cross-origin requests.

**Regex bypass:**
`^https://.*\.example\.com$` bypassed by `https://attacker.example.com.evil.com` if not anchored correctly.

**Safari backtick tolerance (historical):**
`http://example.com\`.attacker.net/` treated as subdomain of example.com by Safari.

**Missing `Vary: Origin`:**
CORS responses without this header can be cached and served to all origins — potentially serving credentialed responses to unauthenticated users if combined with cache poisoning.

### CORS + Cache Poisoning Combination

If a CORS-enabled response is cached without `Vary: Origin`, an attacker can poison the cache with a credentialed CORS response from one origin and have it served to others. This elevates CORS misconfigurations from "requires victim interaction" to "passive attack."

---

## IX. Collaborator Research: AngularJS Sandbox Escapes (Heyes, 2015–2017)

AngularJS client-side templates evaluate expressions in a "sandbox" — the sandbox attempts to block access to `window`, `document`, and `Function`. Heyes systematically broke every sandbox version.

### Version-Specific Escapes

- **v1.2.24–1.2.26:** `getOwnPropertyDescriptor`/`defineProperty` to reach `Function` constructor via array notation.
- **v1.2.27–1.3.20:** `{}.")));alert(1)//"` — semicolon duplication via non-alphanumeric property parsing breaks context.
- **v1.4.0–1.4.5:** `__lookupGetter__` + `event.target` → `document.defaultView` → `window.location`.
- **v1.4.5–1.5.8:** `charAt=[].join` breaks parser character validation; then `orderBy:'x=alert(1)'`.
- **v1.6.0:** Angular removed the sandbox entirely as unfixable.

Key insight: Client-side template injection in AngularJS (`{{expression}}` in `ng-app` scope) is effectively XSS. Any user-controlled content that lands in an AngularJS template context is exploitable regardless of HTML escaping, because the AngularJS expression evaluator is invoked *after* HTML parsing.

### Prototype Pollution (Heyes, 2022–2023)

**DOM-based prototype pollution:** Attacker pollutes `Object.prototype` via URL fragment parsing, `document.cookie`, or other sources. Third-party libraries and browser APIs that read properties from objects without `hasOwnProperty` checks inherit the attacker's values.

Gadgets found in: Google Analytics (`hitCallback` → `setTimeout` sink); Google Tag Manager (`sequence` eval sink, `event_callback` setTimeout sink); Adobe DTM (`cspNonce`/`bodyHiddenStyle` innerHTML, `trackingServerSecure` script.src); browser `fetch()` and `localStorage`/`sessionStorage` APIs.

**Server-side prototype pollution:**
Non-destructive detection methods (safe for production):
- JSON spaces alteration: pollute `JSON.stringify` spaces property → observe space changes in response.
- Exposed CORS headers manipulation.
- HTTP response status code changes.
- OPTIONS method modification.
- `NODE_OPTIONS` inspection flag via OAST.

Destructive (avoid on live): `constructor` modification, encoding property changes.

Vulnerable frameworks: Lodash `merge()`, Express configs, body-parser, qs library, Kibana (RCE).

### Blind CSS Exfiltration (Heyes, 2023)

Technique: exfiltrate data from unknown pages using only CSS — no JavaScript, bypasses JavaScript CSP restrictions.

Mechanism:
- CSS attribute selectors (`input[value^="a"]`) + background image URL → request fires if attribute starts with "a".
- Leak character-by-character by iterating through all characters.
- `:has()` selector: match parent elements by child attributes regardless of page structure — eliminates need to know page structure in advance.
- Multiple CSS backgrounds per element: assign multiple URL variables to `<html>` background → unlimited requests in single payload.

Extractable without JavaScript: input names/values, textarea attributes, form action URLs, anchor destinations.

### Email Parser Exploitation (Heyes, 2024)

Email parsers in security-sensitive contexts (email-based domain verification, invitation systems) use various RFCs and legacy standards. Discrepancies between parsers enable access control bypass.

**Techniques:**
- **Unicode overflow:** PHP `chr()` truncates to 8 bits — `String.fromCodePoint(0x100 + 0x40)` → `@` sign. Inject `@` into local part of email to create fake second `@`.
- **Encoded-word (RFC2047):** Q-encoding (`=?charset?Q?data?=`) and B-encoding (base64) in email addresses. Some parsers decode; others don't.
- **Malformed Punycode:** IDN encoding with nonstandard input — `xn--0049` → comma → splits email domain.
- **UUCP path:** `!`-separated routing (ancient protocol, still parsed by some libraries).
- **Percent hack:** `collab%psres.net@example.com` routes to `collab@psres.net` in Postfix 3.6.4.

**CVE-2024-21725 (Joomla):** Malformed Punycode → `<style>` tag injection → CSS injection → CSRF token exfiltration → PHP RCE via template modification.

**GitHub/Zendesk:** Ruby Mail Gem encoded-word parsing bypass for domain verification (both fixed May 9, 2024).

**GitLab:** Domain-restricted registration bypass (fixed April 25, 2024).

---

## IX-B. Client-Side Web Platform Hardening (2024-2026)

### postMessage Security: event.source vs event.origin (Microsoft MSRC, August 2025)

Microsoft's MSRC team published "postMessaged and Compromised" (https://www.microsoft.com/en-us/msrc/blog/2025/08/postmessaged-and-compromised) cataloguing high-impact postMessage vulnerabilities in Teams apps. The headline anti-pattern is well-known but persistently re-introduced:

**Anti-pattern:** Validating `event.source` (the `Window` reference) instead of `event.origin` (the URL triple).

**Why it fails:** An attacker page can embed the target application as an iframe, then mutate the iframe's `src` to attacker-controlled content. The parent application keeps a reference to that `Window` and checks `event.source === iframeRef.contentWindow`. The check passes — but the content inside that iframe is now attacker-controlled. `event.origin` is the only field that the browser cryptographically ties to the sender's actual origin and that the attacker cannot forge.

**Microsoft's findings (2025):**
- **Power Virtual Agents (Microsoft Copilot Studio)** — 0-click XSS during a Teams meeting (no user interaction required).
- **Teams FileBrowser** — 1-click XSS via deep link.
Both were tied to `isFullTrust: true` plus overly broad `validDomains` lists (`*.sharepoint.com`, `*.powerapps.com`).

**Defenses MSRC recommends:**
- Validate `event.origin` against a strict allowlist; never use wildcard `targetOrigin` in `postMessage(msg, '*')` when sending tokens.
- Drop `isFullTrust: true` except for the narrowest necessary cases.
- Enforce `Content-Security-Policy: frame-ancestors <origins>` and an explicit `frame-src` directive.
- Audit `validDomains` regularly; remove unused subdomains.

**Companion 2025 research:** Google CTF 2025 "Postviewer v5²" combined a client-side iframe-lifecycle race condition with a predictable `Math.random()` salt to break SafeContentFrame's salted origin isolation; @terjanq's writeup at https://gist.github.com/terjanq/e66c2843b5b73aa48405b72f4751d5f8 details the chain.

### Cross-Origin Isolation (COOP + COEP) — Post-Spectre Hardening

The web platform's response to Spectre (2018) was to disable `SharedArrayBuffer`, `performance.measureUserAgentSpecificMemory()`, and high-resolution timers across all browsers. These features are now re-enabled only in **cross-origin-isolated** documents — those that opt in via two response headers:

```
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Embedder-Policy: require-corp
```

Reference: https://web.dev/articles/coop-coep.

- **COOP `same-origin`:** Severs the `window.opener` relationship to cross-origin documents. Prevents tab-nabbing and process-sharing with attacker windows.
- **COEP `require-corp`:** Every cross-origin sub-resource (images, scripts, fonts) must explicitly opt-in to being embedded via a `Cross-Origin-Resource-Policy: cross-origin` header, or via CORS for fetch responses.
- **COEP `credentialless` (Chrome 96+):** Loads cross-origin resources without credentials, removing the need for upstream third-parties to add CORP headers. Tradeoff: third-party iframes don't see user cookies. Reference: https://developer.chrome.com/blog/coep-credentialless-origin-trial.

**Why this matters for HTTP security:** Pages that need `SharedArrayBuffer` (WebAssembly threading, video processing, ML inference in-browser) MUST be cross-origin-isolated, which significantly tightens the broader cross-origin attack surface as a side effect. Auditors should expect every page that uses WASM threads or fine-grained timing to ship COOP+COEP — if it doesn't, the page is using something else (e.g., shimmed APIs) and merits a closer look.

### Strict CSP (nonce + strict-dynamic) — Current Best Practice

Per OWASP CSP Cheat Sheet and Google's web.dev guide (https://web.dev/articles/strict-csp), the modern XSS-defense CSP shape is:

```
Content-Security-Policy:
  script-src 'nonce-{RANDOM}' 'strict-dynamic';
  object-src 'none';
  base-uri 'none';
  require-trusted-types-for 'script';
```

Rationale:
- **`nonce-{RANDOM}`** — server emits a fresh, unguessable nonce per response; only `<script>` tags carrying the matching `nonce` attribute execute.
- **`'strict-dynamic'`** — extends the nonce's trust to scripts dynamically loaded by nonce-trusted scripts (`document.createElement('script')`). Eliminates the brittleness of allowlisting CDNs / hashes for transitively-loaded scripts.
- **`object-src 'none'`** — blocks Flash/Java/etc plugin XSS chains that pre-CSP allowlist policies forgot.
- **`base-uri 'none'`** — blocks `<base>` injection from rewriting relative-URL script sources.
- **`require-trusted-types-for 'script'`** — forces every DOM XSS sink (`innerHTML`, `eval`, `Function`) to receive a Trusted Type, which is the only path to systematically eliminating DOM XSS at runtime.

For **statically-cached HTML** where per-response nonces can't be minted, fall back to **hash-based CSP** (`'sha256-...'`) combined with `'strict-dynamic'`.

**WebAssembly + CSP:** Per MDN, `default-src` / `script-src` without explicit `wasm-unsafe-eval` blocks `WebAssembly.compileStreaming()`. If a page legitimately needs WASM, add `'wasm-unsafe-eval'` and consider whether the WASM module itself needs subresource-integrity protection.

### Cross-Site WebSocket Hijacking (CSWSH) — 2025 State of Play

Include Security 2025 retrospective (https://blog.includesecurity.com/2025/04/cross-site-websocket-hijacking-exploitation-in-2025/) covers what's changed since the classic Christian Schneider 2013 writeup:

**What broke (defender wins):**
- Chrome / Edge default `SameSite=Lax` for cookies (since 2020) — WebSocket handshakes are not top-level GET navigations, so Lax-defaulted auth cookies are not sent cross-origin. The classic PoC fails by default.
- Firefox "Total Cookie Protection" (2022+) partitions cookies per top-level site, neutralizing cross-origin WebSocket exploitation even with `SameSite=None`.

**What still works:**
- Servers that explicitly set `SameSite=None` cookies (often required for legitimate cross-origin SSO flows) remain exposed in Chrome/Edge when third-party-cookie blocking is off.
- Private-IP targets (internal services, IoT, intranet) are NOT protected by Private Network Access — the PNA spec requires CORS preflight, and WebSocket handshakes do not preflight. PNA's WebSocket support remains incomplete as of 2025.
- GraphQL-over-WebSocket APIs (`graphql-ws`, `subscriptions-transport-ws`) are a common 2025 finding because backend `Origin` checks lag behind the GraphQL feature work.

**Defense (the immutable list):**
- Validate `Origin` header in the WebSocket handshake against a server-side allowlist. RFC 6455 makes this the server's responsibility; many frameworks ship without it.
- Embed CSRF tokens in `Sec-WebSocket-Protocol` (arbitrary headers can't be set on a browser WebSocket handshake, but the `WebSocket()` constructor's subprotocol list populates this one).
- Require the first message after handshake to be an authentication frame; reject the connection if the first frame is not a valid auth message.

### WebSocket Smuggling

WebSocket smuggling exploits proxy/backend disagreement on whether a WebSocket upgrade succeeded. If the proxy thinks the upgrade succeeded but the backend thinks it didn't (or vice versa), the proxy keeps the TCP socket open in raw-bytes mode while the backend continues HTTP/1.1 parsing — the attacker injects HTTP requests through what the proxy treats as opaque WebSocket frames. Surfaces in chained CDN architectures where the front-end and back-end have differing WebSocket-handshake-validity criteria (header capitalization, `Upgrade` value parsing, `Sec-WebSocket-Version` enforcement). Mitigation: enforce strict WebSocket-handshake validation at the proxy layer; on any handshake mismatch, close the underlying TCP connection rather than fall back to bidirectional bytes.

### HTTP/2 and HTTP/3 Connection Coalescing — Application-Layer Risk

Browser-side connection coalescing (Mozilla bug 1420777, Chrome equivalent) allows reuse of a single HTTP/2 connection for requests to multiple hostnames if:
1. The hostnames resolve to the same IP address, AND
2. The server's TLS certificate covers both hostnames (CN, SAN, or wildcard).

Habets 2024 writeup (https://blog.habets.se/2024/10/Connection-Coalescing-breaks-the-internet.html) details the failure mode: TLS handshake establishes via SNI for `a.example.com`, but subsequent HTTP requests on the same connection set `Host: b.example.com`. The server, which may have a different security posture for `b.example.com` (stricter mTLS, IP allowlists, different WAF rules), still receives the request because the TCP+TLS layer doesn't re-validate SNI against the Host header.

**Kettle's HTTP/3 contamination thesis** (https://portswigger.net/research/http-3-connection-contamination): HTTP/3 explicitly removes the same-IP requirement for coalescing (RFC 9114 §3.3). Any wildcard or multi-SAN certificate becomes a coalescing magnet without requiring DNS-level alignment. A compromised sibling host with a wildcard cert can intercept requests intended for any other domain on that cert — **without MITM** — by manipulating DNS for clients within range. Cloudflare's ORIGIN frame writeup (https://blog.cloudflare.com/connection-coalescing-with-origin-frames-fewer-dns-queries-fewer-connections/) covers RFC 8336's ORIGIN frame, an explicit server signal that coalescing is available regardless of DNS.

**Defensive minimum (server-side):**
- Reject any request on a connection where the `Host` header doesn't match what the SNI claimed. Respond with HTTP 421 Misdirected Request (RFC 7540 §9.1.2). Note: many clients still handle 421 poorly; the structural fix is per-host TCP/QUIC connections, which contradicts the performance reason coalescing exists.
- Avoid wildcard certificates for hosts with materially different security postures. Use distinct certs per sensitivity tier.
- Be aware that connection coalescing is a **first-request routing** problem in disguise; any reverse-proxy that routes-by-first-request will misroute coalesced requests by definition.

---

## X. Collaborator Research: Cookie Sandwich Technique (Fedotkin, 2025)

### Mechanism

Apache Tomcat (v8.5.x, 9.0.x, 10.0.x) switches from RFC6265 → RFC2109 legacy parsing mode when a `$Version=1` cookie is present. In RFC2109 mode, quoted strings are treated as a single cookie value.

**Attack construction:**
```javascript
document.cookie = '$Version=1;';
document.cookie = 'param1="start';
document.cookie = 'param2=end"';
```

Server receives `$Version=1; param1="start; HttpOnlyCookie=SECRET; param2=end"` — the HttpOnly cookie is embedded inside the quoted string value of `param1`, making it readable via `document.cookie`.

**Prerequisites:** XSS on the domain + a reflection point + CORS with credentials + HttpOnly cookie on an accessible subdomain.

**Why Chrome specifically:** Chrome doesn't natively support `$Version=1` legacy cookies, so an attacker with XSS can create it via JavaScript without overriding existing browser behavior.

### Phantom $Version Cookie for WAF Bypass

The same `$Version=1` mechanism triggers RFC2109 legacy parsing in Apache Tomcat-based backends. By injecting `$Version=1`, the attacker can hide payloads inside quoted (or octal-escaped) strings that the backend decodes but the WAF does not, bypassing signature matching (demonstrated against AWS WAF).

Also researched: `oncontentvisibilityautostatechange` event handler for AWS WAF bypass — an event handler so obscure that AWS WAF's signature list didn't include it.

---

## X-B. AI-Generated HTTP Handlers: Empirical Security Posture (2025-2026)

Five distinct 2025/2026 studies converge on a single uncomfortable finding: LLMs default to insecure HTTP-handler implementations unless the prompt explicitly signals "security matters."

**George Mason University, "Guiding AI to Fix Its Own Flaws"** (https://arxiv.org/html/2506.23034v1) — all eight models tested (including GPT-4o, GPT-3.5-turbo, CodeLlama, StarCoder2, DeepSeek-Coder-V2-Lite) generated vulnerable code under vanilla prompts. Augmenting the prompt with self-generated vulnerability hints meaningfully reduced insecure output.

**Backslash Security 2025 evaluation** (https://www.backslash.security/press-releases/backslash-security-reveals-in-new-research-that-gpt-4-1-other-popular-llms-generate-insecure-code-unless-explicitly-prompted) — GPT-4.1 and peers consistently emit code vulnerable to XSS, SQL injection, command injection, and CSRF when prompted without security framing.

**Springer 2025 "Hidden Risks of LLM-Generated Web Application Code"** (https://arxiv.org/pdf/2504.20612, https://link.springer.com/chapter/10.1007/978-3-032-13714-2_3) — focused specifically on **authentication, session management, and HTTP security headers**. None of the five tested LLMs (ChatGPT, DeepSeek, Claude, Gemini, Grok) emitted any of the checked headers (CSP, HSTS, X-Frame-Options, Referrer-Policy, Permissions-Policy). DeepSeek and Claude omitted `Secure`, `HttpOnly`, and `SameSite` cookie flags; Claude also lacked session-fixation protection.

**Netizen 2026 industry retrospective** (https://blog.netizen.net/2026/05/07/what-security-teams-are-seeing-in-ai-generated-code/) — citing Veracode research, about 45% of AI-generated code contained security flaws across more than 100 LLMs and 80 coding tasks.

### Concrete HTTP Anti-Patterns Observed

- **Reflective `Access-Control-Allow-Origin: <Origin>`** with `Access-Control-Allow-Credentials: true` — the same misconfig Kettle exploited at scale in 2016 is the default LLM emission for "add CORS to my API."
- **Host-header trust** — LLM-generated password-reset flows that construct the reset URL from `request.host` without validation. Direct host-header poisoning primitive.
- **Missing `Vary: Origin` / `Vary: Accept-Encoding`** in cached responses — invites the cache-poisoning class.
- **Bare `eval` and `dangerouslySetInnerHTML`** in React boilerplate — The Hacker News reports this React pattern was exploited in over 200 documented attacks in 2024, and that `dangerouslySetInnerHTML` near a payment iframe lets attackers inject hidden iframes (https://thehackernews.com/2025/09/iframe-security-exposed-blind-spot.html).
- **Hard-coded session secrets / static JWT signing keys**
- **WebSocket `Origin` not validated** — `socket.on('connection', ws => {...})` patterns omit the handshake-`Origin` check almost universally.
- **`postMessage` with `targetOrigin: '*'`** — when an LLM is asked to add cross-iframe communication, the wildcard is the default emission.

### Defender's Operating Model

1. **Treat LLM-emitted HTTP code as "draft-quality"** by default. The security review burden is now front-loaded onto the human reviewer or onto a separate security-checking pass.
2. **Prompt with explicit security context.** "Generate a CORS handler that allowlists exactly these origins, validates against the allowlist, and emits `Vary: Origin`" is dramatically better than "add CORS."
3. **Scan the output.** Semgrep / CodeQL / Snyk / Backslash all have rule packs that catch the typical LLM-emitted HTTP anti-patterns. Integrate into the same review loop as the LLM authoring.
4. **Distrust generated test suites.** LLMs that emit insecure handlers also emit tests that don't exercise the security boundary (e.g., no Origin-spoofing test for the CORS handler).

This is a forward-pointing section: the empirical record will keep moving. The two structural patterns — LLM defaults insecure, explicit prompting partially fixes — are likely to persist into 2026-2027 absent a step-change in pretraining-data hygiene or RLHF security-aware fine-tuning.

---

## XI. HTTP Protocol Fundamentals — Security Perspective

### Version Security Differences

**HTTP/1.0 vs HTTP/1.1:**
- HTTP/1.1 adds persistent connections (`Connection: keep-alive` default) — creates stateful socket, enables request smuggling.
- HTTP/1.1 adds chunked transfer encoding — source of CL/TE ambiguity.
- HTTP/1.0 closes after each request — no desync risk.

**HTTP/1.1 vs HTTP/2:**
- HTTP/2: binary framing, stream multiplexing over single TCP, HPACK header compression.
- HTTP/2 eliminates response splitting (binary framing prevents CRLF injection in headers).
- HTTP/2 prohibits connection-specific headers (TE, Transfer-Encoding, Connection) per RFC 9113 — but many servers accept them anyway.
- HTTP/2 downgrade reintroduces all HTTP/1.1 desync risks plus new ones (H2.CL, H2.TE, H2.X).
- HPACK: static dict of 61 common headers + dynamic dict + Huffman encoding. Mitigates (but does not completely prevent) CRIME-style attacks by forcing guesses to match an entire header field value; no known attack against its static Huffman encoding.

**HTTP/2 vs HTTP/3:**
- HTTP/3 uses QUIC (UDP-based, TLS 1.3 integrated) instead of TCP.
- HTTP/3 eliminates TCP head-of-line blocking.
- HTTP/3 removes IP-match requirement for connection coalescing → dramatically expands HTTP/3 connection contamination attack surface.

### Hop-by-Hop Headers

Headers consumed by the next proxy and not forwarded: `Connection`, `Keep-Alive`, `Proxy-Authenticate`, `Proxy-Authorization`, `TE`, `Trailer`, `Transfer-Encoding`, `Upgrade`.

**Attack technique:** Add arbitrary headers to the `Connection` header field — this marks them as hop-by-hop. A WAF that checks `Authorization` will strip it; the backend never sees the check was requested. Used to strip security headers at intermediary layers without the backend knowing.

### Chunked Transfer Encoding Specification

Format: `<hex-size>\r\n<data>\r\n` ... `0\r\n\r\n` (terminator). Optional trailer headers between `0\r\n` and final `\r\n`. Chunk extensions allowed: `<hex-size>;<ext>=<value>` — some servers parse extensions differently (obfuscation vector). Obfuscation variants: `xchunked`, null-byte prefix, space before colon, tab in name, line-wrap (obsolete folding).

### Host Header Semantics

RFC 7230: exactly one `Host` header required per request. Used for virtual hosting. Attack vectors:
- Password reset link construction using untrusted `Host` value.
- Cache key determination (controlled by attacker → cache poisoning).
- Redirect generation.
- SSRF via backend routing rules.
- Absolute URI in request line overrides `Host` header on RFC-compliant servers.

Duplicate `Host` headers: RFC 7230 requires a 400; Varnish (since 2014) and current nginx reject them. Parsers that instead pick different values create inconsistency exploitable for smuggling past WAFs.

### SOP (Same-Origin Policy) Reference

Origin = `{scheme, host, port}` triple. Two resources are same-origin only if all three match exactly.

**What SOP blocks:**
- Cross-origin script reading DOM or fetch response content.
- Cross-origin AJAX response reading.
- Cross-origin `localStorage`/`sessionStorage` access.

**What SOP allows (cannot block without breaking the web):**
- `<img>`, `<video>`, `<script>`, `<link>` loading (content unreadable by JS).
- `<form>` submissions (CSRF exploits this; SameSite cookies are the primary mitigation).
- `window.location` writing (not reading).

**SOP exceptions:**
- `postMessage()` — safe cross-origin channel.
- `document.domain` relaxation — deprecated in modern browsers, TLDs blocked.
- Cookies accessible across subdomains unless `__Host-` or `__Secure-` prefix used.

---

## XII. Tooling Reference

### Param Miner
**GitHub:** PortSwigger/param-miner

Discovers hidden, unlinked HTTP parameters (headers, cookies, query parameters).
- Built-in wordlist + harvests additional terms from in-scope traffic.
- Binary search approach: tests up to 65,000 names per request efficiently.
- Compares responses with/without candidate parameter using BPS diff logic.
- Post-2021: extended to guess internal header names via HTTP/2 request tunnelling.
- Post-2024: extended with timing analysis for hidden proxy discovery.

Primary uses: web cache poisoning (unkeyed input discovery), hidden API parameter discovery, internal header discovery, hidden reverse proxy detection.

### HTTP Request Smuggler
**GitHub:** PortSwigger/http-request-smuggler

Automates detection of CL.TE, TE.CL, TE.TE variants via timeout-based probing. Updated for 2021 HTTP/2 research: H2.CL, H2.TE, tunnelling, HEAD method detection for blind tunnelling, Param Miner integration. Now integrated into Burp Suite's core scanner.

### Turbo Intruder
**GitHub:** PortSwigger/turbo-intruder

Custom HTTP stack built from scratch for speed. Max observed ~30,000 RPS to a remote server. Flat memory enables billion-request multi-day attacks. Configured via Python scripts.
- Added single-packet attack: `Engine.BURP2`, `concurrentConnections=1`, gate-based synchronization.
- Custom HTTP/2 stack: character mappings `^` → `\r`, `~` → `\n`, `` ` `` → `:` for malformed request construction.
- Can run headless via CLI.

### ActiveScan++
**GitHub:** PortSwigger/active-scan-plus-plus

Extended Burp active/passive scanner detecting: Host header attacks and password reset poisoning, cache poisoning indicators, SSTI, blind code injection (EL, Ruby `open()`, Perl `open()`), DNS rebinding, XML injection. Minimal network overhead.

### Backslash Powered Scanner
**GitHub:** PortSwigger/backslash-powered-scanner

Differential injection scanner. Phase 1: two distinct probes with different injection characters. Phase 2: classify response differential (boring/interesting/vulnerable). Phase 3: targeted follow-up. Finds known and unknown injection classes without WAF-triggering signatures.

### Collaborator Everywhere (v1 and v2)
Injects Burp Collaborator payloads into all HTTP headers and URL parameters of in-scope traffic. Detects out-of-band callbacks indicating SSRF, blind injection, and hidden proxy behavior. V2 by Compass Security with improved UI.

### DOM Invader (Heyes)
Browser-integrated tool in Burp Suite for client-side prototype pollution detection and DOM XSS source/sink tracing.

### h2spacex
Open-source HTTP/2 timing tool for dual-packet synchronization attacks. Released alongside 2024 timing attack research.

---

## XIII. CVE Index

| CVE | Vulnerability | System | Bounty | Year |
|-----|---------------|--------|--------|------|
| CVE-2018-14773 | X-Original-URL unkeyed header | Symfony | — | 2018 |
| ZF2018-01 | X-Original-URL unkeyed header | Zend Framework | — | 2018 |
| SA-CORE-2018-005 | X-Original-URL/X-Rewrite-URL unkeyed | Drupal | — | 2018 |
| CVE-2019-16276 | Request smuggling | Golang net/http | — | 2019 |
| K50375550 | HTTP desync | F5 BIG-IP | — | 2019 |
| CVE-2021-21295 | H2.CL desync | Netflix/Netty | $20,000 | 2021 |
| CVE-2021-33193 | `:method` spaces → request line injection | Apache mod_proxy | — | 2021 |
| K97045220 | HTTP/2 request smuggling | F5 BIG-IP | — | 2021 |
| CVE-2022-20713 | CL.0 desync (most endpoints) | Cisco ASA WebVPN | — | 2022 |
| CVE-2022-22720 | Pause-based desync | Apache httpd | — | 2022 |
| CVE-2022-23959 | Pause desync | Varnish | — | 2022 |
| CVE-2022-4037 | Email token misdirecting | GitLab / Devise | — | 2022/23 |
| CVE-2024-21725 | Email parser → CSS injection → RCE | Joomla | — | 2024 |
| CVE-2023-44487 | HTTP/2 Rapid Reset DDoS | Multi-vendor (398M RPS observed) | — | 2023 |
| CVE-2024-27316 | HTTP/2 CONTINUATION Flood | Apache httpd | — | 2024 |
| CVE-2024-27983 | HTTP/2 CONTINUATION Flood | Node.js | — | 2024 |
| CVE-2024-28182 | HTTP/2 CONTINUATION Flood | nghttp2 | — | 2024 |
| CVE-2024-24549 | HTTP/2 CONTINUATION Flood | Apache Tomcat | — | 2024 |
| CVE-2024-31309 | HTTP/2 CONTINUATION Flood | Apache Traffic Server | — | 2024 |
| CVE-2024-27919 | HTTP/2 CONTINUATION Flood | Envoy | — | 2024 |
| CVE-2024-30255 | HTTP/2 CONTINUATION Flood | Envoy | — | 2024 |
| CVE-2023-45288 | HTTP/2 CONTINUATION Flood | Go net/http | — | 2024 |
| CVE-2024-2653 | HTTP/2 CONTINUATION Flood | amphp/http | — | 2024 |
| CVE-2024-2758 | HTTP/2 CONTINUATION Flood | Tempesta FW | — | 2024 |
| CVE-2024-26135 | Cross-Site WebSocket Hijacking | MeshCentral | — | 2024 |
| CVE-2024-10956 | Cross-Site WebSocket Hijacking | gpt_academic | — | 2024 |
| CVE-2025-32094 | OPTIONS + obsolete line folding desync | Akamai | $9,000 | 2025 |
| CVE-2025-54142 | OPTIONS + body desync | Akamai | — | 2025 |
| CVE-2025-54939 | QUIC-LEAK pre-handshake memory leak | LSQUIC / LiteSpeed | — | 2025 |
| CVE-2026-33555 | Standalone QUIC FIN → HTTP/3-to-HTTP/1 desync | HAProxy HTTP/3 | — | 2026 |

---

## XIV. What Distinguishes Staff-Level Expertise

### Thinking in Systems, Not Vulnerabilities

Kettle does not hunt individual bugs. He identifies *vulnerability classes* that are systematically underexplored, builds tooling to scale discovery, and demonstrates the class is real through high-impact real-world targets. Every paper includes a methodology that others can replicate.

The progression from "web cache poisoning exists" → "here is a systematic methodology for finding it in any application" → "here is a tool that automates discovery" → "here are specific targets across six CDNs" is the pattern. This is the difference between a bug hunter and a researcher.

### Protocol-Level Thinking

Staff-level HTTP security means understanding the protocol at the RFC level, not just the application level:
- RFC 7230 §3.3.3 is the root cause of every request smuggling variant.
- RFC 9113's prohibition on connection-specific headers in HTTP/2 is the root cause of every H2 downgrade attack.
- RFC6265 vs RFC2109 legacy parsing is the root cause of the cookie sandwich attack.

When you understand the RFC, you can predict where new variants will appear before they're found.

### Differential Thinking

The Backslash Powered Scanner philosophy extends to everything: send two inputs, measure the difference. This applies to timing attacks (send two requests, measure differential), cache poisoning (send request with and without candidate header, compare responses), prototype pollution detection (send polluted and unpolluted, observe JSON space changes). Differential analysis finds vulnerabilities that signature-based approaches miss.

### Chained Infrastructure Is the Attack Surface

Modern web architectures have multiple layers: CDN → WAF → Load Balancer → Application Server → Backend Services. Each transition is an opportunity for protocol interpretation disagreement. The attack surface is not "the application" but "every point where two systems must agree on what a request means."

This perspective explains why: a vulnerability in Cloudflare exposes 24 million websites; a CL.0 gadget on a static-file endpoint compromises dynamic endpoints; a first-request routing rule in a proxy makes an entire backend population exploitable.

### Severity Is About Impact, Not Score

Kettle has repeatedly reframed "unexploitable" or "low severity" vulnerabilities as critical:
- Web cache poisoning was considered theoretical before 2018.
- HTTP header injection was rated moderate; Kettle demonstrated it enables response queue poisoning (users get each other's responses).
- Timing attacks were considered impractical beyond LAN; reduced to 200μs differential at intercontinental distances.
- CORS misconfigurations on non-sensitive APIs enabled credential theft because API keys from one endpoint can be used on others.

The staff-level skill is not just exploiting the vulnerability — it's finding the chain that makes a low-severity finding critical.

### Safe Research Practice

Kettle introduced the cache-buster technique specifically so researchers can test cache poisoning without poisoning production. The "responsible DoS" framing acknowledges that a single proof-of-concept request can affect millions of users. For his 2025 desync research, his bounty share was doubled by PortSwigger and donated to charity.

For desync research: always verify findings in a controlled environment before triggering in production; use Burp's built-in smuggling scanner which includes safeguards against accidentally poisoning victim connections.

---

## XV. Defense Principles

### Against Request Smuggling

1. **Prefer HTTP/2 end-to-end.** HTTP/1.1 has an unfixable ambiguity in chained architectures. The only structural solution is HTTP/2 throughout, eliminating the CL/TE parsing problem.
2. **Normalize before forwarding.** If HTTP/1.1 is required, the front-end proxy must normalize requests before passing to backend — reject ambiguous CL+TE combinations; strip or reject connection-specific headers in HTTP/2.
3. **Reject requests with both CL and TE.** Per RFC 7230, servers *should* reject or log these as potential smuggling. Most don't. Enable this check explicitly.
4. **Do not trust `Connection: keep-alive` connections across security domains.** Each connection boundary (WAF → backend) should be treated as a new connection.
5. **Avoid first-request routing and first-request-only validation patterns.** These are exploitable by definition when any desync exists upstream.

### Against Cache Poisoning

1. **Audit unkeyed inputs.** Run Param Miner against every production endpoint. Any header reflected in a cacheable response without being in the cache key is a poisoning risk.
2. **Include `Vary` headers correctly.** `Vary: Origin` on CORS responses; `Vary: Accept-Encoding` where applicable. Missing `Vary` enables cross-user cache serving.
3. **Disable Fat GET on caching tiers.** Frameworks that accept GET bodies should either disable the behavior or ensure the cache key includes the body.
4. **Audit CDN delimiter handling.** Test with `;`, `.`, `%00`, `%0a`, `%2f`, `%5c` in paths against your specific origin stack. What the CDN and origin disagree about can be exploited.
5. **Do not reflect request headers into cached responses.** If `X-Forwarded-Host` is needed for generating URLs, do so in a way that is either validated against a whitelist or excluded from cacheable responses.

### Against CORS Misconfigurations

1. **Never reflect the `Origin` header into `Access-Control-Allow-Origin`.** Maintain an explicit allowlist.
2. **Parse origins as triples, not strings.** Prefix/suffix matching is broken.
3. **Never whitelist null.** Sandboxed iframes generate null origin.
4. **Always emit `Vary: Origin`** on CORS responses. Prevents cache serving cross-origin credentialed responses.
5. **Do not combine `Access-Control-Allow-Credentials: true` with wildcard or reflected origin.** This is universally exploitable.

### Against SSTI

1. **Never pass user input directly to a template engine for evaluation.** Render templates with user data as *variables*, not as template source.
2. **Use the latest version of your template engine.** Sandbox escapes exist in all historical versions of AngularJS, Twig, Smarty, Freemarker.
3. **Treat SSTI as equivalent to RCE.** Every server-side template engine provides access to the underlying runtime.

### Against Prototype Pollution

1. **Use `Object.create(null)` for dictionaries.** Objects without prototype chain cannot be polluted.
2. **Use `Object.freeze(Object.prototype)`** in Node.js applications. Prevents runtime pollution.
3. **Sanitize property names before using them as keys.** Block `__proto__`, `constructor`, `prototype`.
4. **Audit Lodash `merge()` and similar deep-merge utilities.** They are the most common gadget entry points.
5. **Use `hasOwnProperty()` checks** before reading properties from user-controlled objects.

### Against Timing Attacks

1. **Use constant-time comparison for secrets.** `crypto.timingSafeEqual()` (Node.js), `hmac.compare_digest()` (Python), `hash_equals()` (PHP).
2. **Rate-limit and add jitter to authentication endpoints.** Measurement requires many samples; rate limiting increases the cost.
3. **Be aware that 200μs differentials are now measurable remotely.** Any code-path difference that processes a secret can leak via timing.

### Against Race Conditions

1. **Use database-level atomic operations.** `UPDATE ... WHERE condition AND status = 'pending'` returning affected row count is safer than read-check-write.
2. **Idempotency keys on sensitive operations.** Prevents duplicate processing even if same request arrives twice.
3. **Model state machines explicitly.** If a resource transitions through states, ensure no state is exploitable by concurrent access.
4. **Use single-packet attack in pen testing.** Traditional limit-overrun testing with 2 concurrent requests misses sub-millisecond race windows.
5. **Use first-sequence-sync mode for high-payload races.** RyotaK's extension lifts the test budget from ~30 to ~10000 concurrent requests; if your endpoint is rate-limited at the 100-1000 attempts/window threshold, the 1500 B variant will miss the race window.

### Against HTTP/2 and HTTP/3 Frame-Level DoS

1. **Cap per-stream cumulative HPACK-decoded header bytes.** Reject the stream with `RST_STREAM` on overflow.
2. **Cap CONTINUATION frames per HEADERS frame.** Close the connection if exceeded.
3. **Cap RST_STREAM rate per connection.** Mitigation for Rapid Reset (CVE-2023-44487); cloud-load-balancer defaults vary, audit yours.
4. **Bound pre-handshake QUIC allocations.** Per RFC 9000 §8.1 amplification limits, but also explicitly free `packet_in` structures regardless of amplification accounting. CVE-2025-54939 is the cautionary case.
5. **Export HTTP/2 frame-level telemetry.** Standard HTTP access logs miss CONTINUATION-flood traffic because requests never complete. Stream-lifetime histograms, frame-count counters, and per-connection bytes-without-completion metrics are the only reliable signal.

### Against Connection Coalescing Misrouting

1. **Reject SNI/Host-header mismatches.** If a request's `Host` doesn't match the SNI presented at TLS handshake, respond with HTTP 421 Misdirected Request. Note: client 421 handling is uneven, but rejecting is structurally correct.
2. **Use per-host certificates for materially-different security postures.** Wildcard certs are coalescing magnets; if `admin.example.com` has stricter mTLS than `www.example.com`, they should not share a cert.
3. **Avoid first-request routing.** Reverse-proxy routing by first-request-only is exploitable by definition under coalescing.
4. **Watch HTTP/3 specifically.** RFC 9114 removed the same-IP requirement; the coalescing attack surface is larger than HTTP/2's. Cloudflare's ORIGIN frame helps, but adoption is partial.

### Against postMessage Exploitation

1. **Always validate `event.origin`, never `event.source`.** The `Window` reference is forgeable via iframe `src` mutation; the origin URL triple is not.
2. **Use a strict allowlist for `event.origin`.** Wildcards (`*.example.com`) are exploitable when any sub-domain is compromised or in a wildcard cert's chain.
3. **Never `postMessage(msg, '*')`** when the message carries credentials, tokens, or PII. Always specify the explicit target origin.
4. **Audit `validDomains` regularly** in framework-level configs (Microsoft Teams app manifests, Atlassian Connect, Salesforce iframe SDKs). Remove unused subdomains.

### Against Cross-Site WebSocket Hijacking

1. **Validate the `Origin` header in the WebSocket handshake server-side.** RFC 6455 explicitly makes this the server's responsibility.
2. **Embed CSRF tokens in `Sec-WebSocket-Protocol`** — the subprotocol header is set from the client constructor and cannot be forged from a cross-origin attacker page without an XSS prerequisite.
3. **Require an authentication frame as the first message.** If the first frame is not a valid auth message, close the socket.
4. **Be aware that `SameSite=None` cookies on WebSocket routes are an attractive target.** Audit any service that ships them; verify the Origin check is present on every handshake handler.
5. **Don't rely on Private Network Access** to protect intranet WebSocket services. PNA's WebSocket coverage is incomplete.

### Against Strict CSP Regression

1. **Use nonce + strict-dynamic for HTML pages with server-side rendering.** Hash-based CSP for static SPA shells.
2. **Set `object-src 'none'` and `base-uri 'none'`** — these are no-cost wins that block historical bypass classes.
3. **Add `require-trusted-types-for 'script'`** to systematically eliminate DOM XSS sinks. Pair with the Trusted Types polyfill for older browsers.
4. **Deploy in `Content-Security-Policy-Report-Only` first.** Collect violations for a week before enforcing.
5. **Audit `wasm-unsafe-eval` usage.** If your app uses WASM, the directive is required; if not, omit it.

---

*Sources: James Kettle research at portswigger.net/research, jameskettle.com, skeletonscribe.net; Black Hat conference papers 2015–2025; PortSwigger Research blog (Gareth Heyes, Martin Doyhenard, Zakhar Fedotkin); infocondb.org/presenter/james-kettle-albinowax; PortSwigger Top 10 Web Hacking Techniques 2023–2024. 2024-2026 currency updates anchored on: Bartek Nowotarski's CONTINUATION Flood advisory (CERT/CC 2024); RyotaK's first-sequence-sync writeup (Flatt Security, 2024); Akamai's CVE-2025-32094 and CVE-2025-54142 advisories; Imperva's QUIC-LEAK (CVE-2025-54939) disclosure; Microsoft MSRC "postMessaged and Compromised" (2025); HAProxy CVE-2026-33555 PoC; Include Security 2025 CSWSH retrospective; GMU / Backslash / Springer / Netizen 2025-2026 studies on LLM-emitted insecure HTTP code.*

*Currency note: this document was extended on 2026-05-13 with material from the 2024-2026 web-security research record. Sections II-B (HTTP/2+HTTP/3 frame DoS), IX-B (client-side platform hardening), and X-B (AI-generated HTTP code) are net-new since the original draft. Sections II, III, IV, and V have been extended with primary-source-cited 2024-2025 follow-on research.*
