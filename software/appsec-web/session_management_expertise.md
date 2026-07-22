# Session Management as a Discipline
## What happens after authentication: cookies, tokens, refresh rotation, revocation, and the long tail of post-auth bugs

> **Primary researchers and teams cited in this document:**
>
> - **Mitja Kolšek** (ACROS Security, Slovenia). Authored the 2002 "Session Fixation
>   Vulnerability in Web-based Applications" whitepaper that named and characterized the
>   class; the canonical primary source for the bug class that still ships in 2026.
>   https://www.acrossecurity.com/papers/session_fixation.pdf
> - **Sam Curry** (independent; previously Yuga Labs). 2022-2023 OAuth bug-bounty corpus —
>   Apple, GM/Mercedes/BMW/Hyundai car-API account takeovers, the "Web Hackers vs. The Auto
>   Industry" program. Practitioner archive for missing-state, redirect-uri-wildcard, and
>   session-binding bugs. https://samcurry.net/
> - **Frans Rosén** (Detectify Labs). Long-running OAuth and SSO bug-bounty corpus from
>   ~2014 forward, including the 2016 Slack OAuth account-takeover. The redirect-uri
>   validation-bypass taxonomy in §11 is downstream of Rosén's "One Token to rule them all."
>   https://labs.detectify.com/
> - **Aaron Parecki** (Senior Security Architect, Okta). Co-author of the OAuth 2.1 draft
>   with Dick Hardt and Torsten Lodderstedt; author of "OAuth 2.0 Simplified"; maintainer
>   of oauth.net. https://aaronparecki.com/oauth/
> - **Justin Richer** (Bespoke Engineering). OAuth WG long-time contributor; co-author of
>   RFC 6749 and RFC 7662; author of "OAuth 2 in Action"; GNAP chair (RFC 9635).
>   https://justin.richer.org/
> - **Dick Hardt** (Hellō; formerly Salesforce/Microsoft). Editor of RFC 6749 (October 2012).
>   The deliberate "framework, not protocol" framing in §1 is Hardt's discipline call —
>   OAuth leaves session-binding semantics to the deployment, and most of §11's bugs are
>   downstream of that.
> - **Brian Campbell** (Ping Identity). Co-author of RFC 9449 (DPoP, September 2023
>   [unverified date]) and RFC 8705 (mTLS-bound tokens, February 2020). Most-cited author
>   on sender-constrained tokens.
> - **Mike Jones** (Self-Issued Consulting, formerly Microsoft). Co-author of RFC 7519
>   (JWT), editor of JOSE WG output (JWS/JWE/JWK), W3C WebAuthn co-editor.
>   https://self-issued.info/
> - **Adam Barth** (Google, formerly UC Berkeley). Author of RFC 6265 (April 2011) — the
>   modern cookie spec — and the 2008 "Robust Defenses for Cross-Site Request Forgery"
>   paper with Collin Jackson and John Mitchell. RFC 6265bis is the working-group descendant.
>   https://datatracker.ietf.org/doc/html/rfc6265
> - **Eric Rescorla** (Mozilla CTO; RTFM Inc.). Author of RFC 8446 (TLS 1.3); continuous
>   commentary on cookie/transport/session-binding interaction. https://educatedguesswork.org/
> - **Daniel Stenberg** (curl maintainer). Authoritative voice on real-world cookie-handling
>   quirks across HTTP clients. https://daniel.haxx.se/blog/
> - **Filippo Valsorda** (independent; formerly Cloudflare crypto-engineering). Commentary
>   on token-binding and the "sender-constrained tokens are the right answer but nobody
>   ships them" thread. https://filippo.io/
> - **Emil Lundberg** (Yubico). WebAuthn implementation lead; session-adjacent commentary
>   on step-up authentication. Cross-ref `webauthn_fido2_passkeys_expertise.md`.
> - **Daniel Fett** (Authlete; formerly University of Stuttgart). Co-author of RFC 9700
>   (OAuth Security BCP, January 2025 [unverified date]); Fett-Küsters-Schmitz 2016 CCS
>   formal analysis drove the BCP into existence.
> - **Kelly Lum** (1981-2021; formerly Tumblr / Spotify AppSec). Conference-talk archive
>   from 2014-2019 (BSides NYC, AppSec USA); cited for the cookie-tossing / subdomain-set
>   anti-pattern catalog.
>
> Sources: RFC 6265 (Barth, April 2011); RFC 6265bis (active draft); RFC 6749 (Hardt et al.,
> October 2012); RFC 7519 (Jones-Bradley-Sakimura, May 2015); RFC 8252 (OAuth for Native Apps,
> Denniss-Bradley, October 2017); RFC 8705 (Campbell et al., mTLS-Bound Tokens, February
> 2020); RFC 9449 (Campbell et al., DPoP, September 2023 [unverified date]); RFC 9700 (Fett-
> Lodderstedt-Bradley-Labunets, OAuth Security BCP, January 2025 [unverified date]); OWASP
> Application Security Verification Standard (ASVS) V3 Session Management; OWASP Session
> Management Cheat Sheet; OWASP Top 10 2021 A07 (Identification and Authentication Failures);
> Kolšek 2002 (Session Fixation); Barth-Jackson-Mitchell 2008 (Robust CSRF Defenses); Sam
> Curry / Frans Rosén OAuth bug-bounty archives. This document is the consolidated treatment
> of post-authentication session-state security that previously lived as fragments in
> `saml_federation_expertise.md` §JWT-anti-patterns and `distributed_authz_expertise.md`
> §OAuth threat model.

---

## 1. Why this doc exists — the maintenance discipline between authentication and authorization

Three sibling documents cover the adjacent concerns. `saml_federation_expertise.md` and
`webauthn_fido2_passkeys_expertise.md` cover **authentication** — the moment of identity
binding. `distributed_authz_expertise.md` covers **authorization** — the per-request
decision of whether a bound principal can perform a given action. This document covers
**session management** — the maintenance of the bound identity-to-principal mapping across
requests, transports, devices, and time. Distinct from `secrets_management_discipline_expertise.md`,
which covers long-lived service / API secrets; sessions are short-lived, user-bound,
revocable.

Define a session precisely. **A session is a bearer-style credential that represents a
previously-authenticated principal, with associated lifetime, scope, and revocation
semantics.** The credential may be a server-side opaque identifier indexing a Redis-backed
store, a self-contained signed token (JWT-as-session), an OAuth access token, or a hybrid.
Possession of the credential proves the bearer is the authenticated principal, subject to
the constraints encoded in the session metadata.

OWASP Top 10 2021 ranks "Identification and Authentication Failures" (A07) at the top of
the catalog, and the bulk of that category is session-management bugs: session fixation,
missing logout-revocation, weak session-ID entropy, missing `HttpOnly`, missing `SameSite`,
JWT-without-revocation, refresh-token theft, cookie-tossing across subdomains, OAuth
missing-state, redirect-uri wildcards. This is the most-frequent web-app bug class in
2025-2026 and is the discipline most-frequently delegated to a framework default the
engineer never reads.

---

## 2. OWASP ASVS V3 Session Management as the canonical anchor

OWASP Application Security Verification Standard V3 ("Session Management") is the
structural scaffolding for this domain. Chapter V3 is divided into seven subsections, each
of which corresponds to a real bug class the field has paid for in incidents:

- **V3.1 Fundamental Session Management Requirements.** Sessions must be unique across
  users and not be guessable. The system must not disclose session tokens through URL
  parameters, log files, or error messages. Sessions must always be generated server-side.
- **V3.2 Session Binding Requirements.** Sessions must be issued only after authentication
  completes. Session tokens must be cryptographically strong (≥64 bits effective entropy,
  CSPRNG-sourced; 128 bits is the modern recommendation). Sessions must be invalidated when
  the user authenticates with a different identity or steps up.
- **V3.3 Session Logout and Timeout Requirements.** Idle timeout and absolute timeout are
  both required. Logout must invalidate sessions both client-side (clear the cookie) and
  server-side (remove the index entry or add to denylist).
- **V3.4 Cookie-based Session Management.** `Secure`, `HttpOnly`, `SameSite` (Lax or
  Strict), domain restriction. `__Host-` or `__Secure-` prefixes where applicable.
- **V3.5 Token-based Session Management.** JWT or opaque-token-based sessions must validate
  signature, expiry, audience, issuer; revocation strategy must exist.
- **V3.6 Federated Re-authentication.** SAML / OIDC sessions must respect issuer-side
  termination signals; step-up authentication must reset the session-binding state.
- **V3.7 Defense in Depth.** Re-authenticate for sensitive actions; bind sessions to TLS
  channels where possible; rotate session IDs on privilege boundary crossings.

Use V3.x chapter numbers as the structural scaffolding when writing requirements or audit
checklists. The ASVS is the closest thing the field has to a normative session-management
standard; OWASP Session Management Cheat Sheet is the practitioner-friendly companion.

---

## 3. Cookie security primitives

The HTTP cookie remains the dominant session-transport primitive on the web. Get the cookie
flags right and most of §11's incident corpus is closed off; get them wrong and you ship a
post-auth account-takeover. RFC 6265 (Barth, April 2011) defines the spec; RFC 6265bis is
the active refresh adding `SameSite`, prefixes, and `__Host-` semantics.

### 3.1 The flag inventory

- **`Secure`**. Cookie transmitted only over HTTPS. The minimum bar in 2026; browsers
  reject `SameSite=None` without `Secure`.
- **`HttpOnly`**. Cookie not accessible via `document.cookie`. The most-important defense
  against XSS-based session theft. With `HttpOnly`, XSS is bounded by the script's
  execution context; without it, the attacker exfiltrates the cookie and uses it from
  their own infrastructure for weeks.
- **`SameSite`**: `Strict` / `Lax` / `None`. Controls cross-site cookie attachment.
  `Strict` excludes the cookie from any cross-site context; `Lax` includes it on top-level
  GET navigation (the modern default); `None` requires `Secure`. Chrome's 2020 default-to-
  Lax rollout shifted the CSRF threat model: in 2025-2026, CSRF is largely a story of
  same-site-context attacks (subdomain XSS, sibling-app session sharing) rather than the
  classic third-party-forges-POST pattern from the 2000s.
- **`__Host-` and `__Secure-` prefixes** (RFC 6265bis). `__Host-` requires `Secure`, no
  `Domain` attribute (so origin-bound, not registrable-domain-bound), and `Path=/`.
  `__Secure-` requires `Secure` and HTTPS at set-time. **`__Host-` is the most-overlooked
  defensive primitive in modern session management** — closes the cookie-tossing class
  (can't be set by a subdomain) and the network-attacker-injection class (can't be set
  over HTTP). Adopt it.
- **`Path`**. Defense-in-depth-only; same-origin policy makes `Path` mostly useless as a
  security boundary.
- **`Domain`**. Causes the cookie to be sent to all subdomains. The canonical anti-pattern:
  `Domain=example.com` on a session cookie for `app.example.com` leaks the cookie to
  `marketing.example.com`, `blog.example.com`, and every third-party-vendor-run subdomain.
  Omit `Domain`; the cookie defaults to the origin that set it.

### 3.2 Cookie-tossing and cookie-bombing

The Cookie-Tossing attack: adversary with control over a subdomain (e.g., they uploaded a
file to `user-content.example.com` and chained it to XSS, or `marketing.example.com` was
operated by a third-party vendor that got compromised) sets a cookie with `Domain=example.com`
and a `Path` that takes precedence over the legitimate cookie. Browsers send both cookies,
and which one wins depends on the application's parsing. This is the underlying primitive
behind a long tail of CSRF-via-subdomain-takeover bugs in the 2015-2020 corpus; the `__Host-`
prefix is the structural defense.

The Cookie-Bomb DoS: adversary sets enough oversized cookies for a domain that the victim's
subsequent requests exceed the server's header size limit, causing 400-level errors until
the user manually clears cookies. Real impact in pre-2020 deployments; mitigated by cookie
size limits (~4KB per cookie, ~50 cookies per domain per browser-imposed quota).

### 3.3 Partitioned cookies / CHIPS

Chrome's CHIPS (Cookies Having Independent Partitioned State) rollout in 2024 [unverified
exact date] adds the `Partitioned` cookie attribute, keying the cookie by top-level site
in addition to its own domain. Primarily a third-party-iframe privacy story; interacts
with session management when your app is iframed by a third party. Cross-link
`privacy_preserving_advertising_expertise.md`.

---

## 4. Server-side session management

The classic pattern, and the one that should be your default unless you have a specific
reason to do otherwise.

### 4.1 Opaque session ID + server-side state

The server generates a high-entropy random identifier (≥128 bits CSPRNG, Base64URL-encoded
into ~22 characters), stores session state indexed by that identifier in a server-side
store (Redis, Memcached, encrypted database, in-memory), and ships the identifier to the
client in a session cookie. Subsequent requests carry the cookie; the server looks up the
state and processes the request.

Why opaque-and-server-side is the default. Revocation is trivial (`DEL session:<id>` in
Redis). State updates are trivial (you control the row). Token confidentiality is preserved
(the cookie carries no business data). The cost is one round-trip to the session store per
request, which Redis handles in sub-millisecond latencies for the load profile of every
non-Google-scale deployment.

### 4.2 Per-session metadata to store

At minimum: **principal ID**; **`iat`** (issued-at); **`exp`** (absolute expiry);
**`last_active_at`** (idle-timeout); **`auth_method`** (password / MFA / WebAuthn / SSO —
step-up policies depend on this; a password-only session should not perform actions policy
requires MFA for); **`source_ip` and `user_agent_fingerprint`** (anomaly detection;
privacy trade-off — constrain retention because these become re-identification primitives
if retained beyond the session); **`device_id`** if device-bound credentials are in use
(Apple Managed Device Attestation, Android Play Integrity).

### 4.3 Session fixation

Mitja Kolšek's 2002 paper named this class. The attack: if your application accepts a
session identifier from the client *before* authentication and continues using that same
identifier *after* authentication, an attacker can pre-position a session ID (set the cookie
in the victim's browser via a same-site script, a `Set-Cookie` HTTP header from a malicious
sibling subdomain, or a URL-embedded session-ID parameter on older frameworks), wait for the
victim to authenticate, and then use the pre-positioned identifier to access the
authenticated session.

**Mitigation: always regenerate the session ID on authentication.** This is the canonical
defense and is the default behavior of every modern framework. Audit for it anyway —
custom session-management code written before ~2010 routinely fails to regenerate, and
"helpful" middleware that exposes a `req.session` object before authentication completes is
a common foot-gun. In Django: `request.session.cycle_key()`. In Rails: `reset_session`. In
Express + `express-session`: `req.session.regenerate(...)`. In ASP.NET: the framework
abandons and creates new identifiers on `AuthenticationManager.SignIn`. Confirm your
framework does this and ship a regression test that the post-auth session ID differs from
the pre-auth one.

### 4.4 Idle timeout and absolute timeout

Both are required. OWASP recommends 15-30 minutes idle / 4-8 hours absolute for sensitive
applications; banking applications use 5-10 minutes idle. The idle timeout limits the
exposure window if a session credential is stolen and the legitimate user has stepped away
from the device; the absolute timeout limits the lifetime of any session credential
regardless of activity, bounding the damage from a long-running compromised session.

Per-user customization is reasonable for stepped-up sensitivity contexts: a user who has
just authenticated to a banking app's "wire transfer" surface should have a shorter session
than the same user reading their account balance. Implement this as a session-tier or
auth-context-class on the session metadata, not as a separate session per surface.

### 4.5 Session revocation

The lookup primitive is the principal ID. Index sessions by principal so you can revoke all
of them on a single event: password change ("log me out everywhere"), administrative kill
("disable this user"), compromise detection ("this principal's refresh token was reused
after rotation; revoke everything"). A common bug in production systems is that the
"sessions" table is indexed by session ID only — there is no way to enumerate sessions for
a principal without a full table scan. Fix this at design time.

Logout must invalidate sessions at both ends. Clear the client cookie (the
`Set-Cookie: session=; Max-Age=0` line). Remove the server-side state. Do not rely on
client-side cookie deletion alone — a session credential captured by an attacker before
logout remains usable against the server until the server-side state expires unless the
server-side state is removed.

---

## 5. JWT-based session management

The most-common 2020-2026 anti-pattern this document catalogs: "we use JWT, so we're
stateless." JWT-as-session-token is operationally attractive because it allows the server
to validate the token without a database lookup, but **the revocation problem is unsolved
without adding a stateful component**, which negates the operational benefit. "Stateful
JWT" is a contradiction in terms.

### 5.1 JWT structure and the JOSE family

A JWT is a Base64URL-encoded triple `header.payload.signature`. The header carries `alg`
and `kid`. The payload carries claims; relevant for sessions: `sub` (principal), `iat`,
`exp`, `aud`, `iss`, `jti` (JWT ID, for revocation denylists). JWS signs without encryption
(anyone can read the payload); JWE encrypts but adds complexity most apps don't need. For
sessions, JWS-with-EdDSA-or-ES256 is the default; HS256 is acceptable for single-issuer-
single-verifier deployments with well-managed shared secrets; RS256 remains common but is
implicated in the key-confusion attacks below.

### 5.2 JWT anti-patterns

The full bestiary lives in `saml_federation_expertise.md` §JWT-anti-patterns; the
session-management-relevant subset:

- **`alg: none`** (CVE-2015-9235 and later). A JWT with `{"alg":"none"}` claims to be
  unsigned; a vulnerable library accepts it as valid. Mitigation: never accept `alg: none`;
  pin allowed algorithms in your validation configuration.
- **Algorithm confusion (HS256 / RS256)**. A vulnerable library uses the same key-loading
  code path for both symmetric and asymmetric verification. Attacker switches the `alg`
  header from `RS256` to `HS256` and signs the token with the *public* key (which is
  publicly known) interpreted as the HMAC symmetric secret. Mitigation: pin allowed
  algorithms per-key, not per-token.
- **Attacker-controlled `kid`**. The `kid` header tells the verifier which key to use.
  If the verifier resolves `kid` against a database or file path without validation, an
  attacker can pivot to a key under their control (file traversal, SQL injection,
  attacker-uploaded public key). Mitigation: `kid` lookup must be in a closed set of
  pre-configured keys.
- **Missing `aud` validation**. A token issued by your auth server for service A is
  accepted by service B because service B doesn't check the `aud` claim. Token meant for
  the password-reset surface accepted by the wire-transfer surface; the cross-surface
  privilege escalation pattern. Mitigation: always validate `aud` against the expected
  audience for *this* service.
- **Missing `exp` validation**. A library accepts a token whose `exp` is in the past, or
  fails to validate `exp` because the library API requires a separate `verify_exp=True`
  flag and the engineer didn't set it. Mitigation: pin `verify_exp=True` and add a test.
- **Attacker-controlled `jku`**. The `jku` header is a URL to a JWK Set. If the verifier
  fetches the JWK Set from an attacker-controlled `jku`, the attacker provides their own
  signing key. Mitigation: `jku` must be in a pre-configured allowlist of trusted issuers.

### 5.3 Refresh-token rotation (OAuth 2.1)

The OAuth 2.1 default: every refresh-token use issues a new refresh token and invalidates
the old. If the application sees the old refresh token used again, that is a compromise
indicator — revoke the entire grant.

Threat model: if an attacker steals a refresh token (XSS, mobile malware, MITM, social
engineering) and uses it to mint an access token, either the legitimate client uses its
refresh token first and the attacker's stolen token is invalid, or the attacker uses the
token first and the legitimate client's next refresh attempt triggers reuse-detection. In
both cases the grant is revoked and the principal re-authenticates.

Implement reuse detection by storing a refresh-token family identifier server-side and
tracking the sequence number; reject any refresh that is not for the most-recent token in
the family. RFC 6749 §10.4, RFC 6819 (Threat Model), and RFC 9700 (BCP, January 2025
[unverified date]) all reference this pattern.

### 5.4 Token binding — DPoP and mTLS

The structural defense against bearer-token theft is to bind the token to a key the legitimate
client holds. Two specs:

- **DPoP (Demonstrating Proof of Possession), RFC 9449** (September 2023 [unverified date]).
  The client generates an asymmetric key pair, sends the public key in the access-token request
  binding it to the token, and demonstrates possession on every API call by signing a
  request-specific JWT with the private key. A stolen access token is useless to the
  attacker without the private key.
- **mTLS-bound access tokens, RFC 8705** (February 2020). The client authenticates the TLS
  channel with a client certificate; the auth server binds the access token to the cert's
  thumbprint. A stolen access token presented over a different TLS channel is rejected.

Adoption is rare in 2026. Most production OAuth deployments still issue bearer tokens that
work for the attacker if stolen. DPoP is gaining traction in the GNAP and FAPI (Financial
API) communities; mTLS-bound tokens are deployed in banking-grade FAPI deployments.

---

## 6. Storage decisions in SPA, mobile, and native clients

### 6.1 The localStorage vs httpOnly cookie debate

- **localStorage**: XSS-readable (any script on your origin reads it); immune to CSRF;
  no automatic transport (SPA must attach to fetch/XHR).
- **httpOnly cookie**: not JS-readable; automatic transport; CSRF-vulnerable without
  `SameSite` and / or a CSRF token.

**Operational truth: XSS is more common than CSRF in modern apps.** `SameSite=Lax` +
`HttpOnly` + a CSRF token for state-changing operations is the recommended default. XSS
that reads `document.cookie` is the dominant session-theft mechanism in 2024-2026 incident
reports; tokens in localStorage give that XSS a credential that survives reload and
device-wipe-via-exfiltrate-and-replay. OWASP Cheat Sheets ("Session Management," "HTML5
Security," "JSON Web Token for Java") all settled on httpOnly-cookie-plus-CSRF-token by ~2022.

### 6.2 Mobile clients

Android: Android Keystore for refresh-token storage. Avoid `SharedPreferences` (even
`EncryptedSharedPreferences`) for high-value tokens; Keystore offers hardware-backed key
protection on devices with secure-element support.

iOS: Keychain for refresh-token storage. Avoid `NSUserDefaults`. Use accessibility flags
(`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`) to constrain reachability.

Cross-platform: tokens must not be written to logs, crash reports, or analytics SDKs.
Audit the third-party SDK list — analytics/crash-reporting SDKs are recurring leak channels.

### 6.3 The BFF (Backend for Frontend) pattern

Emerged ~2020 as the modern SPA + OAuth recommendation: browser holds an opaque session
cookie issued by your BFF; the BFF holds the actual OAuth refresh tokens server-side. The
SPA never sees an access or refresh token. XSS in the SPA can no longer exfiltrate OAuth
credentials — only a session cookie bound to the BFF's origin and `HttpOnly`. Available
out of the box in Duende IdentityServer's BFF library, Curity Token Handler, ory-oathkeeper.
If your SPA talks to multiple downstream OAuth APIs, adopt BFF; the alternative is
XSS = OAuth-token-theft.

### 6.4 Native / desktop apps

RFC 8252 (OAuth for Native Apps, October 2017). Use the system browser
(ASWebAuthenticationSession on iOS, Custom Tabs on Android, default browser on desktop)
for the authorization flow, with PKCE. Do not embed a WebView; an embedded WebView is
under the host app's control and undermines the system-browser trust boundary. Store
tokens in the OS credential store (macOS Keychain, Windows Credential Manager,
libsecret/kwallet on Linux). No plaintext config files.

---

## 7. OAuth 2.1 Security Best Current Practice

The OAuth WG consolidated a decade of OAuth 2.0 deployment experience into the OAuth 2.1
draft (`draft-ietf-oauth-v2-1`, Parecki / Hardt / Lodderstedt) and RFC 9700 (BCP 240, "Best
Current Practice for OAuth 2.0 Security," January 2025 [unverified date]). The
session-management-relevant requirements:

- **PKCE mandatory for all OAuth flows**, not just public clients. PKCE (RFC 7636) binds
  the authorization request to the token request via a cryptographic verifier the attacker
  cannot guess; closes the authorization-code-interception class of attacks.
- **Implicit grant deprecated**. The implicit grant returned access tokens in the URL
  fragment, exposing them to browser history, server logs, and referer headers. Replaced
  by authorization-code-with-PKCE.
- **Resource Owner Password Credentials (ROPC) grant deprecated**. The ROPC grant required
  the client to handle the user's password, defeating the entire point of OAuth as a
  delegation framework.
- **Exact-match `redirect_uri`** required. No wildcards, no prefix matching, no pattern
  matching. The redirect-uri-validation-bypass class (§11) closes only when the auth
  server compares the request's `redirect_uri` byte-for-byte against the registered URI.
- **Refresh-token rotation default** (§5.3 above).
- **Token binding via DPoP or mTLS for high-security flows.**
- **OAuth client authentication via `private_key_jwt` or `tls_client_auth`** preferred
  over `client_secret_basic`. Symmetric client secrets are credential-store risks; key-
  based client authentication scales better and is auditable.

Audit your auth server's policy against this list. RFC 9700 §2 is the consolidated
checklist.

---

## 8. Single sign-on and session propagation

The hardest problem in session management is propagating session state — especially
revocation — across the SSO trust boundary.

### 8.1 SAML SSO session model

In SAML SSO, the IdP and the SP each maintain independent sessions. The IdP session
represents "user is logged in to the identity provider"; each SP session represents "user
has authenticated to *this* service via the IdP." The two sessions have independent
lifetimes; killing the IdP session does not automatically kill the SP session.

SAML Single Logout (SLO) is the protocol mechanism for propagating logout from one party
to all others, but SLO is widely broken in production: SPs frequently don't implement the
back-channel notification correctly, or the SLO request is sent only to SPs the user has
recently visited, or the IdP doesn't track which SPs the user has authenticated to. The
practical result in 2026 is that "logging out at the SSO portal" often leaves authenticated
sessions alive at downstream services.

### 8.2 OIDC session management

OpenID Connect supplements OAuth with three logout patterns:

- **RP-Initiated Logout**: the relying party (your app) redirects the user to the OP's
  end-session endpoint, which the OP uses to clear the OP-side session and (optionally)
  notify other RPs.
- **Front-Channel Logout**: the OP returns an HTML page containing iframes pointing to
  each RP's logout URL; the user's browser loads each iframe, and each RP clears its
  session. Fragile: depends on the browser loading all iframes successfully.
- **Back-Channel Logout**: the OP sends a logout token (a signed JWT) to each RP's
  back-channel logout endpoint. The most-reliable mechanism but requires per-RP
  back-channel registration and is least-widely-deployed.

In practice, "logout at the IdP propagates everywhere" is mostly aspirational. Survey:
when a principal initiates logout at one app, what state changes at the IdP vs at other
RPs? In most deployments only the IdP session and the originating RP session are
terminated. **After password change at the IdP, sessions at all RPs should be revoked;
verify your implementation actually does this.** It rarely does without explicit work.

---

## 9. Cross-site request forgery (CSRF)

The CSRF threat model: an attacker-controlled site causes the victim's browser to issue
cross-site authenticated requests against the target. The victim's session cookie is
automatically attached by the browser; the target processes the request as if the
authenticated user initiated it.

### 9.1 The modern defenses

- **`SameSite=Lax` / `SameSite=Strict`** as the structural defense. Modern browsers default
  to `Lax` (as of the Chrome rollout in 2020). On a Lax-defaulted cookie, the cookie is
  not attached to cross-site POST / DELETE / fetch requests; only top-level GET navigation
  triggers attachment. The classic "form auto-submitted from attacker.com" attack is closed
  by the browser default.
- **CSRF tokens** (Synchronizer Token Pattern, Barth-Jackson-Mitchell 2008). Server issues
  a per-session random token; client must echo it in a hidden form field or custom request
  header on state-changing requests. Defense-in-depth on top of SameSite for state-changing
  operations, particularly in apps that need to support legacy clients without SameSite.
- **Custom request headers + CORS preflight**. Browsers prevent cross-site code from
  setting custom headers without a CORS preflight; an API that requires a custom header
  (`X-CSRF-Token`, `X-Requested-With`) on state-changing operations gets CSRF protection
  via the browser's CORS enforcement. Used by Angular and many SPA frameworks.
- **Double-submit cookie pattern**. Server issues a cookie containing a random value; the
  client must also include the same value in a header. An attacker cannot read the cookie
  due to same-origin policy, so cannot forge the header. Stateless and useful for apps
  that don't have server-side session state to bind the CSRF token to.
- **Cookie-to-header pattern**. Implicit in frameworks like Angular and Django: the
  framework sets a cookie containing a CSRF token, and the SPA's HTTP client copies the
  cookie value into a header on outgoing requests.

### 9.2 OAuth-specific CSRF

The OAuth `state` parameter is the CSRF defense *for the OAuth flow itself*. The client
generates a random `state` value, includes it in the authorization request, and verifies
that the auth server returns the same `state` in the callback. Without `state`, an attacker
can initiate an OAuth flow, capture the resulting authorization code, and substitute it into
the victim's callback — the victim's account becomes linked to the attacker's identity.
Egor Homakov's 2012 "Most Common OAuth2 Vulnerability" post is the canonical primary source.
The `state` parameter must be cryptographically random and bound to user-agent state (e.g.,
stored in a session cookie, then compared on callback). Missing `state` = OAuth account
takeover.

---

## 10. Cross-site scripting (XSS) impact on sessions

XSS on a session-bearing origin compromises the session unless cookies are `HttpOnly`. If
tokens live in localStorage, XSS exfiltrates them directly. If tokens are in `HttpOnly`
cookies, XSS cannot read them but can still perform actions in the victim's session via
the XSS payload — the attacker is constrained to the XSS execution context (which may
already be sufficient for the attacker's goals, but at least the credential doesn't leave
the browser).

Defenses:

- **CSP (Content Security Policy)** as defense-in-depth. A strict CSP (`script-src 'self'`
  + nonce-based inline scripts) raises the bar for XSS exploitation. CSP is not a primary
  XSS defense — primary defenses are output encoding and Trusted Types — but it constrains
  exfiltration channels.
- **Trusted Types** (Chrome, behind a CSP directive). Forces DOM sinks (`innerHTML`,
  `document.write`, `setTimeout` with string-callbacks) to accept only specifically-typed
  values produced by a Trusted Types policy. Closes the DOM-XSS class structurally where
  deployed.
- **Subresource Integrity (SRI)** on third-party scripts. SRI ensures a script's content
  matches a pinned hash, defending against compromised CDNs.

Cross-link to `prototype_pollution_expertise.md` for prototype-pollution gadgets that
escalate to XSS in JavaScript frameworks.

---

## 11. Session-related attack classes and incident corpus

- **Session fixation** (Kolšek 2002). Pre-position a session ID, wait for the victim to
  authenticate, use the pre-positioned session. Mitigation in §4.3.
- **Session hijacking via XSS.** `HttpOnly` is the defense for cookie-based sessions;
  don't store tokens in localStorage.
- **Session prediction.** Weak entropy in session IDs lets the attacker guess valid
  identifiers. Modern frameworks (Spring Session, Django, Rails, ASP.NET Core,
  express-session) use CSPRNG-derived ≥128-bit identifiers by default. Legacy PHP
  `session_id()` configurations using `mt_rand()` or weak entropy sources could produce
  predictable IDs prior to PHP 7; audit `session.entropy_*` on PHP deployments.
- **Cookie-tossing and cookie-bombing.** Adversary on a subdomain sets a cookie scoped to
  the parent domain; depending on parsing, the adversary's cookie may take precedence.
  The `__Host-` prefix is the structural defense.
- **Refresh-token theft and the Storm-0558 class.** Microsoft May 2023: an attacker
  obtained a Microsoft consumer signing key and forged Exchange Online and Outlook.com
  access tokens — including for *enterprise* customers, because of a token-validation
  bug accepting the consumer key for enterprise tokens. The canonical "token-signing key
  is the keys to the kingdom" story. Key-management discipline (HSM-backed signing,
  rotation, scope-restricted keys) is part of session management.
- **Pass-the-cookie attacks.** Lapsus$ (2022-2023) and the Snowflake-customer-tenant
  compromises (mid-2024) demonstrated this at scale. Credential-stealer malware extracts
  session cookies from the browser profile (Chromium's `Cookies` SQLite store, decrypted
  with the OS-bound DPAPI / Keychain key) and exfiltrates them. The attacker imports the
  cookies and proceeds as the authenticated user. **MFA was bypassed not by attacking MFA
  but by stealing the post-MFA session cookie.** Defenses: short session lifetimes,
  sender-constrained tokens, continuous risk evaluation, device-bound credentials.
  CrowdStrike's 2024 infostealer-driven SaaS reporting is the public primary source.
- **OAuth redirect-uri wildcard / pattern-matching** (Sam Curry et al.). Auth servers
  that pattern-match `redirect_uri` (regex, prefix, suffix, "starts with") allow
  attackers to register a redirect URI that satisfies the pattern, capture the
  authorization code, and link the victim's account. Still shipped in production at auto
  OEM auth servers as recently as 2023. Exact-match `redirect_uri` is the OAuth 2.1
  structural defense.
- **OAuth missing-state** (Egor Homakov, 2012). `state` binds the OAuth callback to the
  user agent that initiated the flow. Missing `state` = account-takeover via CSRF on the
  callback. Modern OAuth libraries handle `state` by default; custom code routinely omits it.

---

## 12. Modern defense patterns

### 12.1 Sender-constrained tokens

DPoP and mTLS-bound tokens are the structural defense against bearer-token theft. Token
theft alone is insufficient because the attacker also needs the private key. Adoption is
rare; in FAPI and GNAP deployments DPoP is standard.

### 12.2 Continuous session re-validation and risk-based monitoring

Okta ThreatInsight, Microsoft Entra ID Identity Protection ("risky sign-in"), Google's
account-protection risk engine, and Cloudflare Access all implement continuous session
risk evaluation: a session that started benign may become risky if the device fingerprint
changes, the source IP geolocates to a new country, the user-agent class changes, or the
behavior pattern departs from baseline. The system response is step-up authentication or
session termination. Cross-link to `zero_trust_workload_identity_expertise.md` for the
broader continuous-authn framing.

### 12.3 Device-bound credentials

Apple Managed Device Attestation (ManagedAppAttestation, iOS 16+), Android Play Integrity
API, Google Pixel StrongBox, Microsoft Device Health Attestation, Apple Touch ID/Face ID.
The session credential is bound to a hardware-backed key that the device cannot exfiltrate.
The attacker steals the cookie but cannot use it from their own machine because the
hardware-bound proof-of-possession check fails. Production deployment is concentrated in
banking and high-security enterprise contexts; gradually expanding into consumer SaaS.

### 12.4 Passkey-backed re-authentication

For sensitive actions (changing email, initiating a wire transfer, accessing admin
controls), trigger a WebAuthn re-authentication step. The user proves possession of their
passkey for the specific action; the session is upgraded to a higher auth context class
for a short window. Cross-link to `webauthn_fido2_passkeys_expertise.md`.

### 12.5 Short-lived access tokens + refresh-token rotation

The OAuth 2.1 default pattern. Access tokens expire in minutes (5-15 minutes is typical);
refresh tokens rotate on every use and are revoked on reuse detection. Token theft has a
short useful lifetime and any attempt to extend it via the refresh token triggers
revocation.

---

## 13. 2024-2026 currency

- **RFC 9700** (OAuth Security BCP, BCP 240, January 2025 [unverified exact date]).
  Authoritative checklist for OAuth security operators.
- **RFC 9449** (DPoP, September 2023 [unverified exact date]). The sender-constrained-token
  spec the modern OAuth ecosystem converged on.
- **OAuth 2.1 draft** (`draft-ietf-oauth-v2-1`). Not yet finalized RFC as of early 2026.
- **Chrome CHIPS partitioned cookies** rollout in 2024. Cross-link
  `privacy_preserving_advertising_expertise.md`.
- **OAuth library CVEs.** Spring Authorization Server, Keycloak (incl. CVE-2022-1245),
  Node OAuth-server libraries shipped session-management-relevant CVEs across 2023-2025.
- **Storm-0558** (Microsoft, May-July 2023). Token-signing-key compromise; canonical
  "the signing key is the keys to the kingdom" case study.
- **Snowflake mid-2024.** Credential-stuffing initial access + session-cookie extraction
  as secondary lateral movement; multiple downstream-tenant compromises (AT&T,
  Ticketmaster, Santander, per press). Mandiant's reporting is the primary source. Lesson:
  MFA at the IdP doesn't protect downstreams that accept long-lived session credentials.
- **AI-agent session story (emerging).** Claude Code, Cursor, ChatGPT Operator, Anthropic
  Computer Use, MCP-tool-using agents increasingly hold OAuth refresh tokens or session
  cookies on behalf of users. Token theft from the agent = session theft. The discipline
  is in its infancy. Cross-link `ai_orchestration_harnessing_expertise.md` and
  `ai_incident_response_playbook_expertise.md`.

---

## 14. Honest failure modes — load-bearing

The single most-important section. The discipline lives or dies by which of these is
present in your deployment.

- **JWT-as-session-token without revocation strategy is the most-common 2020-2026 mistake.**
  Engineers adopt JWT for stateless verification, don't think about revocation, and ship
  a system where compromised tokens are usable until expiry. Then they add a denylist when
  an incident forces it — at which point the system is stateful and the operational
  benefit is gone. Either start opaque-server-side, or start JWT + denylist + short
  access-token lifetimes + refresh-token rotation.
- **localStorage tokens get exfiltrated by XSS.** Don't put session tokens there. "We'll
  just prevent XSS" is operationally weak; the cost of `HttpOnly` cookies is zero.
- **`SameSite=None` without `Secure`** is rejected by modern browsers, but legacy code
  paths still attempt the combination and the cookie silently doesn't get set. Audit.
- **Missing exact-match `redirect_uri`.** Wildcard / regex / prefix matching on
  `redirect_uri` is the single most-paid-out OAuth bug class from 2022 onward.
- **Federated logout is mostly broken.** SLO, OIDC RP-Initiated Logout, front-channel
  logout, back-channel logout are all partial coverage. After password change at the IdP,
  sessions at all RPs should be revoked; verify your implementation actually does this.
- **Long-lived refresh tokens with no rotation** are equivalent to long-lived static API
  keys. Adopt rotation; OAuth 2.1 default is rotation-on-use with reuse detection.
- **Session-fixation bugs persist in legacy frameworks.** Audit
  session-ID-regenerate-on-auth in every framework you touch.
- **MFA-bypass via session cookie theft** is the dominant post-2023 attack pattern.
  Lapsus$, Storm-0558, Snowflake all demonstrated MFA bypass not by attacking the MFA
  step but by stealing the post-MFA session credential.
- **"Idle timeout disabled because users complain"** is operational pressure eroding
  session security. Quantify the risk explicitly; align with business risk tolerance.
- **OAuth `state` parameter missing or not bound to user-agent state.** CSRF on the OAuth
  callback equals account-linking attack. Modern libraries handle `state` by default;
  custom code routinely omits it.
- **Token binding (DPoP / mTLS) adoption is rare.** Most production apps still issue
  bearer tokens that work for the attacker if stolen. Adopting DPoP / mTLS is the single
  most-impactful structural defense available in 2026 and is on few teams' roadmaps.
- **"Logout" that only clears the cookie client-side leaves server-side state alive.**
  Verify the server-side session record is destroyed on logout.
- **Cookie `Domain=example.com` on session cookies leaks the session to every subdomain.**
  Omit `Domain` or use the `__Host-` prefix.

---

## 15. Cross-link cluster

- `saml_federation_expertise.md` — federation-protocol authentication (the upstream act);
  JWT anti-patterns full bestiary.
- `webauthn_fido2_passkeys_expertise.md` — authenticator-side perspective; passkey-backed
  step-up authentication.
- `distributed_authz_expertise.md` — per-request authorization decisions; complement to
  this doc's session-state framing.
- `secrets_management_discipline_expertise.md` — long-lived service / API secrets; sibling
  but distinct from short-lived user-bound sessions.
- `zero_trust_workload_identity_expertise.md` — continuous authn evaluation and risk-based
  session monitoring framing.
- `dfir_methodology_expertise.md` — IR for session-credential compromises; pass-the-cookie
  forensics.
- `ai_assisted_coding_tool_security_expertise.md` — AI-agent credential handling.
- `ai_incident_response_playbook_expertise.md` — IR for AI-agent token theft.
- `prototype_pollution_expertise.md` — XSS gadget chains relevant to session theft.
- `cicd_supply_chain_expertise.md` — session-credential leakage via CI/CD logs and
  artifact exfiltration.
- `http_request_smuggling_expertise.md` — request smuggling as a session-confusion
  primitive (smuggled request inherits another principal's session).
- `threat_modeling_discipline_expertise.md` — session-management requirements in threat
  models.
- `privacy_preserving_advertising_expertise.md` — partitioned cookies / CHIPS context.
- `anti_fraud_abuse_engineering_expertise.md` — session-based abuse signals; account-
  takeover detection.

---

## 16. Operational checklist — adopt this before shipping a session-bearing system

The single-page audit you should run before any production system handles authenticated
sessions:

1. Session cookies have `Secure`, `HttpOnly`, `SameSite=Lax` (or `Strict`). No exceptions.
2. Session cookies use the `__Host-` prefix where origin-scoped and path-`/`-scoped.
3. Session IDs are ≥128 bits CSPRNG-sourced.
4. Session ID is regenerated on authentication; ship a regression test.
5. Idle timeout (15-30 min) and absolute timeout (4-8 hr) are both configured.
6. Logout invalidates server-side session state in addition to clearing the client cookie.
7. Sessions are indexed by principal ID so revocation-by-principal is fast.
8. If JWT-as-session: revocation strategy documented; denylist or short-TTL+refresh-rotation
   in place; `alg`/`aud`/`exp`/`iss` pinned; `kid` and `jku` allowlisted.
9. If OAuth: PKCE on all flows; exact-match `redirect_uri`; refresh-token rotation with
   reuse detection; `state` on every authorization request.
10. CSRF token or `SameSite=Strict` on state-changing endpoints.
11. CSP (`script-src 'self'` + nonce-based) and Trusted Types deployed where supported.
12. Sender-constrained tokens (DPoP or mTLS) considered for high-value flows.
13. Federated logout tested: trigger logout at the IdP and verify termination at downstream
    RPs. If it doesn't work (it usually doesn't), document the gap and add a compensating
    control (e.g., short SP-session absolute lifetimes).
14. MFA-bypass-via-cookie-theft tested: confirm step-up to high-value actions requires
    re-authentication, not possession of an MFA-backed session cookie.
15. Session-credential leakage audited: tokens not in logs, analytics SDKs, URLs, error
    messages, or referer headers.

The discipline is unglamorous. The failures are catastrophic. Run the checklist.
