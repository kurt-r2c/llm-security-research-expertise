# SAML, OIDC Federation, and Identity Protocol Security
## Synthesized from the SSO Research Corpus, OAuth Working Group Output, and the JWT Bug Bestiary

> **Primary researchers and teams:**
>
> - **Juraj Somorovsky** (Ruhr-University Bochum; now Professor at
>   Paderborn University). Lead author of "On Breaking SAML: Be Whoever You Want to Be"
>   (USENIX Security 2012), the canonical XML Signature Wrapping (XSW) paper that surveyed 14
>   major SAML frameworks and found 11 vulnerable, including Salesforce, Shibboleth, and IBM
>   XS40. Ongoing research at the JWT, JSON-JWS, and TLS state-machine intersection (the WS-
>   Attacks corpus).
>   https://www.usenix.org/conference/usenixsecurity12/technical-sessions/presentation/somorovsky
> - **Jörg Schwenk** (Ruhr-University Bochum, Chair for Network and Data Security). Somorovsky's
>   doctoral advisor and a co-author on "On Breaking SAML." Long-running SSO research lineage
>   including OAuth 2.0 formal analysis, TLS-state-machine attacks, and the SSO multi-factor
>   threat model. The Bochum group is the academic centre of gravity for protocol-level SSO
>   vulnerability research.
> - **Daniel Fett** (Authlete; formerly University of Stuttgart). Co-author of RFC 9700 ("Best
>   Current Practice for OAuth 2.0 Security," BCP 240, January 2025) with Torsten Lodderstedt,
>   John Bradley, and Andrey Labunets. Author of "A Comprehensive Formal Security Analysis of
>   OAuth 2.0" (CCS 2016) — the formal-analysis-derived attack catalog that drove the BCP
>   into existence.
>   https://datatracker.ietf.org/doc/rfc9700/
>   https://publ.sec.uni-stuttgart.de/fettkuestersschmitz-ccs-2016.pdf
> - **Mike Jones** (Self-Issued Consulting; formerly Microsoft Identity Standards Architect).
>   Co-author of RFC 7519 (JSON Web Token) with John Bradley and Nat Sakimura; editor of the
>   JOSE working group output (JWS, JWE, JWK); editor of multiple OpenID Connect Core
>   specifications; W3C WebAuthn co-editor; FIDO 2.0 spec contributor. Maintains the long-
>   running self-issued.info blog as the canonical primary source for spec rationale and
>   interop notes. https://self-issued.info/
> - **Brock Allen** and **Dominick Baier** (Duende Software, formerly IdentityServer). Co-authors
>   of the IdentityServer (now Duende IdentityServer) OpenID Connect and OAuth 2.x implementation
>   for ASP.NET, in continuous development since 2009. The practitioner-side counterweight to
>   the academic SSO literature: their leastprivilege.com and brockallen.com blogs document
>   the implementation reality of every spec gotcha catalogued below.
>   https://leastprivilege.com/  https://brockallen.com/
> - **Vittorio Bertocci** (died 2023; formerly Auth0 Principal Architect, Microsoft Azure AD
>   team). Author of "Modern Authentication with Azure Active Directory
>   for Web Applications" (Microsoft Press) and host of the "Identity, Unlocked" podcast. The
>   most-cited practitioner voice for explaining OAuth/OIDC at the level engineers actually
>   build against. The OAuth JWT-profile access-token spec (RFC 9068) is his work; his
>   cloudidentity.com archive is essential reading.
> - **Egor Homakov** (independent researcher; later Sakurity). Pre-2015 OAuth corpus: the
>   2012 "Most Common OAuth2 Vulnerability" post (missing-state CSRF), the 2013 Facebook
>   OAuth-to-XSS chain with Andrey Labunets (Hack In The Box Amsterdam), and the GitHub
>   `mass_assignment` discovery. Homakov's blog is the historical archive of OAuth attack
>   primitives that the 2025 BCP corpus eventually canonicalized.
>   http://homakov.blogspot.com/
> - **Aaron Parecki** (Director of Identity Standards, Okta). Maintainer of oauth.net; co-author of
>   the OAuth 2.1 draft (`draft-parecki-oauth-v2-1`) with Dick Hardt and Torsten Lodderstedt;
>   author of "OAuth 2.0 Simplified" (the de facto practitioner introduction). The standards-
>   side counterpart to Bertocci's implementation-side writing.
>   https://aaronparecki.com/oauth/
> - **Kelby Ludwig** (Senior Application Security Engineer, Duo Security / Cisco). Discoverer
>   of the 2018 SAML XML comment injection vulnerability affecting Duo Network Gateway,
>   OneLogin, Clever, OmniAuth, and Shibboleth. The "insert seven characters to bypass SAML
>   authentication" finding that hardened text-node handling in every Python lxml / Ruby
>   REXML-based SAML library.
>   https://duo.com/blog/duo-finds-saml-vulnerabilities-affecting-multiple-implementations
> - **Bhavuk Jain** (independent researcher). 2020 Sign-In With Apple zero-day: an attacker
>   could request a JWT for any email address and have Apple's public key validate it as
>   genuine. $100,000 Apple Security Bounty payout. The canonical worked example of "OIDC
>   identity-provider issuance bug → total account takeover" in the consumer-grade SSO
>   corpus. https://bhavukjain.com/blog/2020/05/30/zeroday-signin-with-apple/
> - **Dirk-jan Mollema** (Outsider Security; formerly Fox-IT). The Entra ID / Azure AD
>   offensive research lineage: pass-the-PRT (Primary Refresh Token), Temporary Access Pass
>   abuse, ROADtools / roadtx tooling, the cross-tenant guest-to-admin escalation chain.
>   The single most-cited practitioner on Entra-specific federation attacks.
>   https://dirkjanm.io/
> - **Lewis Ardern** (Staff Security Researcher, Semgrep; formerly Synopsys/Cigital security
>   consultant). JavaScript and web-app domain expert
>   driving Semgrep's JWT and OIDC ruleset development; cross-cited in the GraphQL and
>   prototype-pollution expertise docs in this directory for adjacent web-stack work.
>   https://github.com/LewisArdern
> - **Kurt Boberg (`kurt-r2c`)** — Semgrep staff researcher. Two relevant CVEs in the
>   federation corpus: **CVE-2022-1245** (Keycloak token-exchange privilege escalation; CVSS
>   9.8) — missing authorization in the OAuth2 token-exchange grant let any client redeem
>   tokens for any target client_id; **CVE-2022-24901** (parse-server Apple Game Center
>   certificate-URL validation bypass; CVSS 7.5) — weak SSRF-style URL validation in an
>   OIDC-flavored identity-binding flow.
>   https://github.com/advisories/GHSA-75p6-52g3-rqc8
>   https://github.com/advisories/GHSA-qf8x-vqjv-92gr
>
> Sources: USENIX Security 2012 (Somorovsky XSW); RFC 9700 (OAuth Security BCP); RFC 7519
> (JWT); CCS 2016 (Fett-Kuesters-Schmitz formal analysis); Duo Labs 2018 disclosure; Bhavuk
> Jain's Sign-In With Apple writeup; Mollema's dirkjanm.io archive; the OASIS SAML 2.0 Core
> spec; OpenID Connect Core 1.0; the Auth0 / Snyk JWT-attack corpus; Kurt Boberg's GHSA
> advisories cited inline. This document is the consolidated treatment of federation-protocol
> security that previously lived as fragments in `distributed_authz_expertise.md` §6 (OAuth/
> OIDC threat model) and `xml_parser_differential_expertise.md` §4 (SAML XSW).

---

## 1. The federated-identity threat model

### Why federation exists

Three drivers: **SSO** (one login, N service providers; removes per-app password
databases from breach radius), **audit centralization** (one log to subpoena,
one MFA enforcement point), **B2B/B2C tenant isolation** (multi-tenant SaaS
delegates identity to each customer's IdP; platform never sees passwords). The
2002 SAML 1.0 → 2005 SAML 2.0 → OIDC 2014 lineage tracks these.

### The three trust boundaries

Every federated protocol — SAML, OIDC, WS-Federation — instantiates the same three-party
trust model. Bugs cluster at the boundaries:

```
                       +----------------+
                       |   User-Agent   |
                       |  (browser/app) |
                       +-------+--------+
                               |
              (1) AuthN request   |   (4) Token / Assertion
                               v
        +----------------+       +----------------+
        |    Identity    |<----->|    Service     |
        |   Provider     |  (3)  |    Provider    |
        |     (IdP)      | back- |      (SP)      |
        +----------------+ chan  +----------------+
                                  ^
                                  | (2) Federation metadata
                                  |     (SAML metadata.xml /
                                  |      OIDC discovery doc)
```

Five attacked message-paths: **(1) User → IdP** (phishing, MFA bypass — out of
scope but every downstream depends on IdP not being compromised), **(2) IdP
metadata → SP** (metadata-poisoning via unsigned/HTTP fetch), **(3) IdP ↔ SP
backchannel** (token-exchange, JWKS fetching — Kurt's CVE-2022-1245 lives here),
**(4) IdP → Browser → SP** (SAML Response / OIDC ID Token relay — XSW corpus,
Sign-In With Apple, most public CVEs), **(5) SP-to-API token usage** (bearer
replay, audience confusion — RFC 6750 corpus).

### Why federation INCREASES attack surface

Federation concentrates risk:

- **IdP compromise = total compromise** across all federated services. 0ktapus
  2022 and Midnight Blizzard 2024 are the public exemplars.
- **Backwards-compatibility tax**: WS-Fed, SAML 1.1, Implicit Flow, `alg:none` —
  permanent attack surfaces.
- **Trust-chain opacity**: SP code rarely logs enough to forensicate a forged
  assertion. Signature valid, audience right, timestamp fresh.
- **Incentive misalignment**: IdP team optimizes uptime; SP team optimizes
  time-to-market; neither owns the joint threat model. Same "shared
  responsibility" pattern as cloud IAM (`cloud_iam_expertise.md` §1).

### The Federation Authority Lifecycle

Federation is a long-running cryptographic state machine. Required: initial
trust establishment (signing-cert pin or discovery URL), key rotation
(quarterly with overlap windows), metadata refresh (many SPs hard-code at
deployment), revocation (SAML has no standard mechanism; OIDC relies on JWKS
cache TTLs), tear-down (refresh-token revocation is a frequent gap). Auth0
post-mortems and Okta 2022/2023 incidents are mostly lifecycle-hygiene
failures, not crypto breaks. See `cloud_iam_expertise.md` §9.

Cross-link: parent treatment of authentication patterns and CWE mapping lives in
`distributed_authz_expertise.md` §1 (AuthN vs AuthZ vs Identity Binding) and §6
(OAuth/OIDC threat model). This document is the depth-first sibling.

---

## 2. SAML protocol in depth

### The three-party trust model

SAML 2.0 (OASIS 2005) standardized the SSO model the industry had been hand-rolling
since the late 1990s. Three parties, three message-types, two principal bindings.

The three parties:

- **User-Agent**: the browser (or, in the web-services SAML profile, a SOAP client).
- **Service Provider (SP)**: the application being accessed.
- **Identity Provider (IdP)**: the authority that authenticates the user.

The flow (HTTP-POST binding, the dominant deployment in 2025):

```
1. User → SP: "Show me /protected".
2. SP → User: HTTP 302 to IdP with SAMLRequest (AuthnRequest message)
              + RelayState.
3. User → IdP: AuthnRequest. IdP runs its login dance (password + MFA, OIDC, etc.).
4. IdP → User: HTML form, auto-submitted to SP's ACS URL, carrying:
                 - SAMLResponse (base64 of XML document)
                 - RelayState
5. User → SP: POST to /acs?SAMLResponse=…&RelayState=…
6. SP: Parse SAMLResponse, verify XML signature, extract Assertion,
       check Issuer / Audience / NotBefore / NotOnOrAfter / SessionIndex,
       map subject NameID to local user, set session cookie, redirect to RelayState.
```

Step 6 is where the entire attack surface lives. Every XSW paper, every comment-
injection bug, every audience-confusion CVE has its root in step 6.

### SAML message types

- **AuthnRequest**: SP-initiated SSO request. Mostly procedural; the only attack-
  relevant fields are `ForceAuthn`, `IsPassive`, and the requested NameIDFormat.
- **Response**: top-level message wrapping zero or more Assertions. May be signed
  (`SignatureValue` over the Response element) and/or carry signed Assertions inside.
- **Assertion**: the actual identity claim. Contains a Subject (NameID), Conditions
  (NotBefore, NotOnOrAfter, AudienceRestriction), AuthnStatement (when/how the user
  authenticated), and optionally AttributeStatement.
- **LogoutRequest** / **LogoutResponse**: the Single Logout (SLO) flow. Frequently
  unimplemented or broken; rarely security-critical in well-architected deployments.

### XML Digital Signature in assertions

`<ds:Signature>` embedded in the signed element. Attack-relevant fields:
`<ds:Reference URI="#id-of-thing">` (URI fragment names element by `ID` —
**this indirection is the entire reason XSW exists**: verifier resolves URI;
processor traverses tree; when they disagree, attacker wins);
`<ds:Transforms>` (C14N + optional XPath transforms; `enveloped-signature`
mandatory for self-descendant signatures); `<ds:DigestValue>` (SHA-1 deprecated
but still seen, SHA-256 normal); `<ds:SignatureValue>` (RSA-SHA1/SHA-256 over
SignedInfo).

### Bindings

**HTTP-POST** (form-auto-submit with base64 SAMLResponse; dominant for browser
SSO; frontchannel), **HTTP-Redirect** (query-string DEFLATE-compressed; used
for AuthnRequests), **HTTP-Artifact** (artifact ID on frontchannel,
dereferenced via backchannel SOAP; more secure but rare), **SOAP binding**
(web-services style for IWSF and attribute queries).

### SAML metadata

`metadata.xml` describes IdP endpoints, signing certs, NameIDFormats, binding
preferences. SP must trust it — cryptographic root of the federation.
Unsigned/HTTP metadata fetch enables MITM hostile-key substitution.
Hardening: pin signing certificate at deployment; HTTPS with strict cert
validation; require signed metadata (`<ds:Signature>` on the `EntityDescriptor`); local cache with
conservative TTLs.

### Common SAML libraries

`shibboleth-sp` (C++; long XSW patch history), `simplesamlphp` (PHP/Drupal SSO;
XSW CVEs through 2014), `ruby-saml` and `python3-saml` (OneLogin; 2018
comment-injection), `python-saml` / `pysaml2` (Saleor, Django),
`com.onelogin.saml` / `Spring SAML` (Java), `passport-saml` (Node), `sustainsys/saml2`
(.NET). **Almost every SAML library accepted unsigned messages by default at
some point** — the hardening curve was driven by XSW disclosures. Defaults are
mostly sane in 2025, but configuration overrides and library forks regress
frequently.

### "SAML is XML; XML is hostile"

Every SAML attack except audience-confusion reduces to XML-parser hostility.
Comment injection (text-node handling), namespace confusion (namespace
inheritance), canonicalization differentials (C14N divergence). See
`xml_parser_differential_expertise.md` §4.

---

## 3. XML Signature Wrapping — the canonical SAML attack

The Somorovsky 2012 USENIX paper classified XSW attacks against SAML messages by
signing type and by where the evil assertion, original assertion, and signature
sit in the tree. The root cause is universal across implementations: the
XML-Signature spec defines verification as "look up the element by ID and check
its digest"; SAML response processing defines extraction as "walk the tree looking
for an Assertion element by name." When these two operations resolve to different
elements, the attacker wins.

### The two-parser primitive

A SAML response carries an Assertion that contains a `<ds:Signature>` block. The
`<ds:Reference URI="#assertion-1234">` says "I sign the element whose `ID` attribute
is `assertion-1234`." The verifier:

1. Locates the element with `ID="assertion-1234"`.
2. Canonicalizes it.
3. Computes its SHA-256 digest.
4. Compares the digest to `<ds:DigestValue>`.
5. If equal, verifies the signature is genuine via RSA.

The processor — the code that turns "we have a valid Assertion" into "we have a
logged-in user" — then locates the Assertion to use. Most processors do something
like `response.getElementsByTagName("Assertion")[0]` or an XPath equivalent. The
attacker's job is to construct a document where these two operations resolve to
different Assertion elements: the verifier checks a benign element (the original
signed assertion); the processor uses a malicious element (inserted by the
attacker).

### The 8 attack shapes

SAML Raider's XSW1-XSW8 naming (per NetSPI; full XML samples and library
matrix live in `xml_parser_differential_expertise.md` §4):

1. **XSW1** (Response): unsigned clone of the Response added after the existing
   signature.
2. **XSW2** (Response): unsigned clone of the Response added before the existing
   signature.
3. **XSW3** (Assertion): unsigned clone of the Assertion added before the
   existing Assertion.
4. **XSW4** (Assertion): unsigned clone of the Assertion added after the
   existing Assertion.
5. **XSW5** (Assertion): a value in the signed Assertion is changed, and a copy
   of the original Assertion with its signature removed is added at the end of
   the message.
6. **XSW6** (Assertion): as XSW5, but the copy is added after the original
   signature.
7. **XSW7** (Assertion): an `Extensions` block carrying a cloned, unsigned
   Assertion.
8. **XSW8** (Assertion): an `Object` block carrying a copy of the original
   Assertion with its signature removed.

### Worked example: shibboleth XSW patch lineage

Two waves of defenses: 2011 (CVE-2011-1411 OpenSAML/IdP XSW fix;
canonicalization pipeline rewritten so verified element = processed element;
processor walks only the validated subtree) and 2018 (CVE-2018-0489
comment-injection fix). Defensive pattern: **after `Signature.verify()`, hand
the caller a reference to the verified subtree only.** Never let app code
re-traverse the original document for "the Assertion." Codified in `xmlsec-c`,
`xml-security-java`, and modern SAML libraries.

### CVE-2022-39353 as a SAML-relevant primitive

Kurt's CVE-2022-39353 against `@xmldom/xmldom` is the JS-ecosystem multi-root
primitive. `xmldom` accepted multi-root documents without raising;
downstream signature verification that processed only the first root could be
tricked into validating different content. Any Node.js SAML library using
`@xmldom/xmldom` — including some `passport-saml` deployments — inherited XSW.
https://github.com/advisories/GHSA-crh6-fp67-6883

---

## 4. SAML implementation-bug corpus

Beyond the XSW shape taxonomy, SAML has a long tail of bug classes.

### Comment injection (Duo Labs 2018, Kelby Ludwig)

SAML responses identify the user in `<NameID>`. XML processors universally
collapse adjacent text nodes — except some don't. Attack: insert an XML comment:

```xml
<NameID>alice<!---->@evil.com</NameID>
```

Signed canonical form (C14N strips comments) is `alice@evil.com` — what got
signed. The processor splits on the comment and returns `alice` as the first
text node, handing the wrong user to the application.

Affected (Duo Labs 2018): Duo Network Gateway, OneLogin (`python-saml`, `ruby-
saml`), Clever (`saml2-js`), OmniAuth, Shibboleth. Fix: concatenate all text-node
children of NameID before use; ignore intervening comments. Root cause: every
library used the host language's stock XML parser (lxml, REXML, xmldom), none
of which document text-node handling in a way that would alert a SAML
implementer.

### Namespace confusion

Attacker redefines a namespace prefix so verifier and processor disagree about
which elements are in the SAML namespace. Example:
`<saml:Assertion xmlns:saml="http://attacker.com">`. Verifier that doesn't track
namespace URIs sees an Assertion; processor with correct namespace tracking
ignores it.

Defense: C14N must emit the namespace URI (not just prefix) into the canonical
form. Spec-mandated; legacy implementations don't always comply.

### Canonicalization differentials

C14N (1.0, 1.1, Exclusive) has multiple variants. Library combinations of
`<ds:Transforms>` are combinatorially complex; partial-support libraries can
diverge in whitespace and namespace-prefix handling between sign and verify —
either DoS (verify fails) or, worst case, verify-success on content the IdP
didn't intend.

Defense: pin canonicalization at deployment; reject unexpected
`<ds:CanonicalizationMethod>`.

### Padding-oracle on encrypted assertions

XML-Enc with AES-CBC/PKCS#7 is padding-oracle vulnerable when the SP returns
distinguishable errors. Kupser-Mainka-Schwenk-Somorovsky "How to Break XML Encryption —
Automatically" (WOOT 2015) found new problems in four of five analyzed Web
Service implementations, including IBM DataPower and Apache CXF.

Defense: AES-GCM or authenticated modes; avoid XML-Enc CBC.

### Replay attacks

If SP doesn't track recently-consumed Assertion IDs, captured Assertions replay
within the validity window. Many libraries leave replay-prevention to the
application and the app forgets.

Defense: bounded seen-set with TTL = max Assertion lifetime.

### Audience-restriction bypass

`<AudienceRestriction><Audience>` names the intended SP. SPs that don't validate
their own entity ID appears in Audience accept Assertions intended for other
SPs federated to the same IdP — a cross-tenant auth bypass in multi-tenant SaaS.

Defense: explicit SP entity ID config; strict Audience match; reject missing
Audience.

### NotBefore / NotOnOrAfter abuse

Two failure modes: clock skew (legitimate assertions rejected) and skipped
validation (old captured Assertions replay indefinitely).

Defense: validate Conditions with 60-300s clock-skew tolerance; fail closed if
Conditions missing.

### Sign-In With Apple (Bhavuk Jain, 2020)

Apple's SSO is OIDC with SAML-flavored ergonomics. The 2020 zero-day: an
attacker requested a JWT for any email address; Apple's signing key validated
it. Apple's authorization server honored the `email` claim as user-controlled
input without verifying against the authenticated user. $100K Apple Security
Bounty. Fix: bind issued JWT `email` to the authenticated user at issuance.

Structural lesson: **federation depends on the IdP not issuing tokens for
principals it hasn't authenticated.** No SP-side hardening protects against
IdP-side claim-binding failures.

---

## 5. OIDC in depth

OIDC 1.0 (OpenID Foundation, 2014) is OAuth 2.0 plus an ID Token. Where SAML
carried identity in a signed XML Assertion, OIDC carries it in a signed JWT.
JSON-everywhere with HTTP-form encoding on redirect endpoints.

### The four flows

1. **Authorization Code + PKCE** (RFC 7636). Dominant in 2025.
   ```
   SP → User: 302 to IdP /authorize?response_type=code&client_id=…&code_challenge=…
   IdP → User: 302 to SP /callback?code=…&state=…
   SP → IdP: POST /token with code + code_verifier  (backchannel)
   IdP → SP: { access_token, id_token, refresh_token }
   ```
   PKCE binds authorization to token request; mitigates cross-origin code injection.
2. **Implicit Flow**: deprecated by RFC 9700. Returns tokens in URL fragment;
   leakage via referer/history/JS-context mixing.
3. **Hybrid Flow**: code + ID token in redirect; immediate ID-token validation
   + later code exchange. Complex validation (`c_hash`, `at_hash`); frequent
   source of gaps.
4. **Client Credentials Flow**: service-to-service; no user. Attack surface:
   confused-deputy between user/service contexts.

### ID Token vs Access Token

Both JWTs with `iss`/`aud`/`exp`/`iat`. ID Token's `aud` is the SP's client_id
(used for session establishment, not API calls; 5-15 min lifetime). Access
Token's `aud` is the resource server (used as bearer in API calls, not for
SP session). **The single most common OIDC bug**: SP accepts an Access Token
where an ID Token was expected. Without `token_type`/`aud` validation, an Access
Token from the same IdP for a different resource server logs the user in.

### The `nonce` claim

Binds the ID Token to a specific authorization request. SP generates random
`nonce`, session-stores, sends in AuthnRequest; IdP echoes into ID Token; SP
validates match. Defeats replay across sessions and SPs. Quick-start OIDC
tutorials frequently omit this validation; production inherits the gap.

### Discovery and JWKS

`/.well-known/openid-configuration` describes endpoints, algorithms, scopes,
and `jwks_uri`. JWKS serves current public signing keys (fetched on startup
and on `kid` mismatch). JWKS endpoint is the cryptographic root; compromising
it = compromising the federation.

Defense: pin discovery/JWKS URLs at deployment (no user-input IdP choice);
HTTPS strict cert validation; bounded TTL cache with rate-limited kid-mismatch
refresh (prevents kid-flooding DoS); vetted OIDC client library — don't roll
your own.

Cross-link: parent OAuth/OIDC threat model at lower depth in
`distributed_authz_expertise.md` §6.

---

## 6. JWT-specific attacks — the dominant OIDC-era class

JWTs are the on-the-wire identity-token format that powers OIDC, much of OAuth
post-2014, and most API authentication. The format is `header.payload.signature`,
three base64url-encoded parts. Each part is an attack surface.

### alg=none acceptance

RFC 7519/7515 define `none` as a valid algorithm for contexts where transport
guarantees integrity. The attack: send `{"alg":"none"}`, no signature, arbitrary
claims. RFC 8725 (JWT BCP, 2020) mandates that verifiers maintain an algorithm
allowlist excluding `none`. As of 2025 this remains the most-cited JWT bug.

Defense: never accept `none`. Use libraries that require the verifier to specify
the algorithm (`jose@4+`, `pyjwt@2+`, `jjwt` with explicit algorithm).

### Key confusion — RS256 → HS256

The JWT header carries the algorithm; the verifier looks up a key from its store.
A polymorphic verifier accepts `{"alg":"HS256"}` and uses the IdP's RSA public
key as the HMAC secret. The public key is published via JWKS; HMAC-SHA256 accepts
any byte string as a key; the verifier computes HMAC-SHA256 with the public-key
bytes and the attacker's signature matches.

Disclosure: Tim McLean, Auth0 2015 ("Critical vulnerabilities in JSON Web Token
libraries"). Still appears in code that calls `jwt.decode(token, key)` without
specifying the expected algorithm.

Defense: `jwt.verify(token, key, { algorithms: ["RS256"] })` — never trust the
JWT header's algorithm claim.

### kid path traversal and SQL injection

The `kid` (key ID) header tells the verifier which key to look up. Libraries
sometimes use it as a filename (`read_key("./keys/" + kid + ".pem")`); attacker
sends `kid: "../../../../dev/null"`, points verifier at an empty key, signs with
the empty key, wins. Variant: SQL injection when `kid` is a database lookup.

Defense: treat `kid` as opaque; whitelist against an enum.

### jku / x5u abuse

The `jku` (JWKS URL) and `x5u` (X.509 URL) header fields can carry a URL pointing
to verification keys. Attack: set `jku: "https://attacker.com/jwks.json"`,
publish attacker keys, sign with matching private key.

Defense: ignore `jku` and `x5u`; look up keys by `iss` against configured
discovery URLs.

### typ / cty / JWS-JWE confusion

`typ` and `cty` header fields are descriptive but libraries sometimes dispatch
on them. JWS (3 parts) vs JWE (5 parts) auto-detection is an attack surface:
CVE-2022-3102 (jwcrypto) let an attacker substitute a JWE encrypted with the
signature-validation public key for a signed JWS; CVE-2023-51774 (json-jwt) is
a sign/encryption confusion bypass.

Defense: pin `typ` and `cty`; use type-specific APIs; don't auto-detect.

### Signature stripping at proxy layers

Downstream services in microservice architectures often receive JWTs from an
upstream gateway that has already verified them. Services parse JWT claims but
skip re-verification. A direct request to the downstream service (bypassing
gateway) is then trusted without integrity checks.

Defense: every consumer verifies the signature. Use service-mesh mTLS to ensure
downstream services only receive traffic from the gateway. Defense in depth.

### kty: dir and Sign-In With Apple

The `dir` algorithm in JWE allows direct symmetric encryption without key
wrapping. Custom JWT issuance with symmetric keys derived from low-entropy input
(session IDs, etc.) is trivially crackable. Structurally related to the Bhavuk
Jain Sign-In With Apple bug: IdP issuing tokens with attacker-derivable key
material.

Defense: HSM/KMS-managed signing keys; never derive keys from request inputs.

### Egor Homakov's pre-2015 corpus

Homakov's 2012-2014 blog established the OAuth attack patterns RFC 9700 later
canonicalized: missing-state CSRF (2012), Facebook OAuth-to-XSS with Andrey
Labunets (HITB 2013), redirect_uri / response_type chaining. These primitives
reappear in JWT-era OIDC implementations with new framing.

---

## 7. OAuth-specific flaws — the RFC 9700 corpus

The OAuth 2.0 Security BCP (RFC 9700, January 2025) is the canonical catalog of
OAuth-protocol-level vulnerabilities — Daniel Fett's formal analysis plus a
decade of OAuth Working Group field experience.

### redirect_uri loose matching

The single most-exploited OAuth class. IdP validation of `redirect_uri` that
uses substring, suffix, or wildcard matching lets an attacker have codes sent to
attacker-controlled URLs:

- `redirect_uri=https://app.example.com.attacker.com/callback` (suffix-match
  bypass).
- `redirect_uri=https://app.example.com/callback?foo=https://attacker.com`
  (query-normalization differential).
- `redirect_uri=https://app.example.com/callback#https://attacker.com` (fragment-
  handling differential).

Fundamentally a URL-parser differential. Cross-link:
`ssrf_url_parsing_expertise.md` §4. Defense: strict-equality byte-comparison
against a pre-registered allowlist; no wildcards. RFC 9700 §4.1.

### state parameter omission

`state` binds the authorization request to the browser session. Without it,
the attacker initiates a flow in their browser, captures the authorization
code, then tricks the victim's browser into visiting the SP's callback with the
attacker's code. The victim is logged in as the attacker; subsequent victim
actions modify the attacker's account. CSRF on the OAuth flow (Homakov 2012).

Defense: random `state` per request, session-bound, validated on callback.

### PKCE downgrade

PKCE (RFC 7636) binds the authorization code to a client-generated secret.
Optional PKCE plus an IdP that accepts requests without `code_challenge` lets
the attacker strip it. Defense: PKCE-required at the IdP for every client.
RFC 9700 requires PKCE for public clients and recommends it for confidential
clients.

### Refresh token theft and binding

Refresh tokens are long-lived; capture = indefinite access-token minting. RFC
9700 requires refresh tokens for public clients to be sender-constrained or
rotated; with rotation, every use mints a new refresh token and invalidates the
old. Rotation enables replay-detection — double-use means leak or lost response;
either way, invalidate the token family.

Defense: rotate on use; detect family-level replay; bind refresh tokens to
client_id and original transaction.

### Cross-org consent (confused deputy)

A multi-org OAuth app (GitHub App, Slack App) installed in Org A receives a
token. If the IdP doesn't bind tokens to specific tenant/org IDs, the app's
runtime can use that token to access Org B.

Defense: tenant_id as a token claim, validated by the resource server on every
request.

### Authorization Code injection

Variant of state-omission. Attacker captures a legitimate code (leaky referer,
misconfigured SP) and injects into a victim's callback. Without PKCE+state, the
SP exchanges the attacker's code for an attacker-identity session. RFC 9700 §4.5
covers this attack.

Defense: PKCE + state, both mandatory.

### Hybrid Flow validation gaps

Hybrid Flow returns code + ID token in the redirect. Client must validate
signature, `nonce`, `c_hash` (left-most half of the code's hash under the ID Token
`alg`), and `at_hash` (same, over the access token, if applicable). Each is independent and fail-silent; `c_hash` is the
most-skipped because tutorials gloss it.

Defense: vetted OIDC client library; don't hand-roll Hybrid flow.

### Implicit Flow token leakage

Returns tokens in URL fragment (`#access_token=…`). Leakage paths: browser
history, referer headers, extensions, DOM JS, URL cache. RFC 9700 says
clients SHOULD NOT use Implicit Flow.

### Client Credentials in user-context endpoints

Client Credentials Flow mints tokens for the client itself (no user). User-
context endpoints that accept these tokens and treat client_id as "the user"
have a privilege bug. Defense: service-context endpoints reject tokens with
`sub`; user-context endpoints require `sub`. Validate `aud`.

### The Fett-Kuesters-Schmitz formal-analysis result

The 2016 CCS paper formally modeled OAuth 2.0 and surfaced four attacks, among
them the 307 Redirect Attack and the IdP Mix-Up Attack. Mix-up: a multi-IdP client can be confused about which IdP the
user authenticated against, enabling token swapping across IdPs. Defense:
`iss` in authorization responses (RFC 9207), one of the mix-up defenses
RFC 9700 requires for clients that use more than one authorization server. Many pre-2025
implementations lack it.

---

## 8. SCIM and provisioning protocol attack surface

SCIM (RFC 7644) is the user-provisioning protocol complementing SAML/OIDC: IdP
push-provisions users into the SP via `/scim/v2/Users` and `/scim/v2/Groups`,
with bearer-token auth. Bug classes:

- **Long-lived bearer token compromise.** Token leakage (logging, telemetry,
  repo, env-var exposure) lets the attacker provision arbitrary users —
  including admins.
- **Tenant scoping.** Multi-tenant SaaS that uses bearer token alone (not
  tenant_id) lets a compromised tenant-A token cross-provision into tenant B.
- **Attribute mass-assignment.** No whitelist on settable attributes; IdP sets
  `is_admin=true` or similar privileged fields.
- **Filter injection.** Naive `/Users?filter=…` implementations pass filter
  strings to SQL/NoSQL queries.
- **Provisioning replay.** `PATCH`/`PUT` non-idempotency leaves accounts in
  stale states on replay.

Pattern: SCIM treated as "internal,"
gets less scrutiny, harbors bugs obvious on public endpoints.

Defense: per-tenant SCIM endpoints or mandatory tenant_id token claim;
attribute allowlist (deny-by-default on role assignments); rate-limit;
quarterly token rotation.

---

## 9. Microsoft Entra ID / Azure AD specifics

Entra ID (formerly Azure AD) is the dominant enterprise IdP in 2025. Its
federation surface is much broader than vanilla OIDC: WS-Federation, ADFS, B2B
Guest, B2C Consumer, Conditional Access, app registrations, service principals,
managed identities — each its own attack surface.

### B2B Guest and B2C Consumer

B2B Guest: users from a home tenant invited into a resource tenant; auth
happens at home tenant; resource tenant honors home-tenant MFA assertions. A
compromised home tenant can authenticate Guest users into resource tenants
without re-MFA. B2C Consumer: separate tenant model for consumer-facing apps;
social federation (Google, Facebook, Apple); attack surface around local-vs-
federated-account confusion and JS injection in custom sign-up flows.

### Conditional Access bypass

CA evaluates signals (user, app, device, location, risk) and produces access
decisions. Bypasses:

- **Policy gaps**: legacy apps (Office ProPlus, IMAP, POP3) often don't honor CA.
- **Token replay across CA boundaries**: low-risk-issued token replayed from
  high-risk context when the resource server doesn't re-evaluate CA at use time.
- **Device-trust forgery**: compromise of Intune attestation forges compliance.
- **Service-principal bypass**: CA applies to user accounts; service
  principals are covered only by CA for workload identities (single-tenant
  SPs, Workload Identities Premium); an uncovered compromised SP calls
  protected APIs without CA.

Mollema's PRT research is the dominant CA-bypass path (next).

### Pass-the-PRT

The Primary Refresh Token is device-bound and gates all token issuance for the
device. Stored in LSASS on Windows. Mollema's research:

1. Local admin extracts PRT + decryption keys from LSASS.
2. ROADtools / roadtx mints access tokens for any Entra-connected resource.
3. IdP cannot distinguish these from legitimate device-issued tokens.
4. PRT-minted tokens carry the original device-trust claim, satisfying
   "require compliant device" CA policies.

The most-impactful Entra attack path (2020-2023). Defense: TPM-attested key
material; revoke PRTs on device-compromise; monitor anomalous source networks.

### App registration vs service principal confusion

App registration is the global app definition (client_id, redirect URIs,
permissions); service principal is the tenant-local instantiation. Permission
scopes on the app registration are inherited by all service principals. A
multi-tenant app requesting `Mail.Read` gets it in every tenant that installs
it; runtime logic that isn't tenant-scoped enables cross-tenant pivot.

### WS-Federation and ADFS legacy

WS-Fed (SAML 1.1 predecessor for Windows) carries all SAML attack surface plus
`wreply` URL-validation bugs and `wctx` CSRF. ADFS is the on-prem IdP for AD
environments pre-Entra; "Golden SAML" (CyberArk Labs, 2017) extracts the ADFS
signing key to mint arbitrary assertions. PKINIT abuse via compromised ADCS
mints user certificates that pivot to ADFS tokens. The 2023 Storm-0558
incident used a stolen Microsoft Account (MSA) consumer signing key to forge
Azure AD (Entra) tokens. Defenses: HSM for
signing keys; migrate WS-Fed to OIDC.

### Cross-tenant access (XTA)

Default-allow XTA accepts Guest invitations from any tenant; a malicious tenant
can invite Guest users into a resource tenant. Trust-chain laundering: A trusts
B, B is compromised, attacker uses B as pivot into A.

Cross-link: enterprise IAM treatment in `cloud_iam_expertise.md` §4.

---

## 10. SSO-vendor-specific attack surface

- **Okta**: 2022 LAPSUS$ (third-party support laptop
  compromise pivoting to support tooling); 2022 0ktapus / 2023 Scatter Spider
  (help-desk social engineering at Okta customers, MFA reset, federation
  bypass).
- **OneLogin**: 2017 secrets-environment compromise (customer tokens stolen);
  long XSW history in `ruby-saml`/`python-saml`; comment-injection (Duo Labs
  2018).
- **Ping Identity / PingFederate**: SAML-heavy enterprise default; CVE corpus
  dominated by configuration footguns.
- **Auth0**: large free-tier configuration surface; Rules/Hooks are full-app
  JS-execution surfaces with several account-takeover findings; acquired by
  Okta 2021.
- **Keycloak**: open-source Java IdP from RedHat; default for self-hosted SSO;
  CVE cluster around OAuth2 token-exchange (Kurt's CVE-2022-1245 in this
  lineage — token-exchange spans multiple trust boundaries and is hard to
  authorize correctly). Cross-link: `distributed_authz_expertise.md` §3.
- **Newer entrants**: Stytch (passwordless/FIDO2 defaults; narrower but
  less-battle-tested); WorkOS (SSO-as-a-service; workos.com/blog "Fun with SAML SSO
  vulnerabilities and footguns" essential reading); AWS Cognito (heavy customization
  surface; misconfiguration tail — public sign-up, weak password policies,
  exposed user pools).

---

## 11. Detection — static and runtime

### Static (Semgrep)

**SAML:**
- Unsigned-assertion acceptance: SAML library calls with
  `validate_signature=False`. FP on test fixtures; scope to non-test files.
- Missing Audience check: response parsing without subsequent audience
  comparison. Often distributed across functions; workflow-level taint
  (`parse_saml_response` → `set_session_user` without audience check) is more
  accurate than syntactic match.
- XSW-vulnerable parsers: `defusedxml` with `forbid_entities=False`,
  `lxml.etree.XMLParser(huge_tree=True)`, DOM parsers without ID uniqueness.
  Cross-link: `xml_parser_differential_expertise.md` §8.

**OIDC/JWT:**
- `alg=none` acceptance: JWT verification without explicit algorithm allowlist.
  FP on libraries with secure defaults (`jose@4+`).
- RS256/HS256 confusion: `jwt.decode(token, public_key)` without algorithm
  specification. Targets legacy code.
- Hardcoded JWT secrets: short low-entropy string literals reaching JWT signing
  in non-test paths.
- JKU/X5U trust: verification flows steered by `jku`/`x5u` header.
- redirect_uri laxity: substring/wildcard matching in client-side validation.

**SCIM:**
- Mass-assignment: `PATCH` handlers copying request attributes without
  allowlist.
- Filter injection: SCIM filter params reaching SQL/NoSQL query builders.

### Runtime

- Anomalous `iss`/`aud`: first-seen issuer/audience combinations.
- Algorithm anomalies: `alg` mismatched against IdP's JWKS.
- `kid` anomalies: `kid` not in any published JWKS.
- Stale assertion replay: `NotOnOrAfter`/`exp` just past expiration.
- Auth source anomalies: IP/geography mismatches against historical baseline.
- Velocity anomalies: same user from geographically-distant locations within
  seconds (impossible-travel).

Cross-link: `detection_engineering_expertise.md` §6;
`cloud_iam_expertise.md` §9.

---

## 12. Defensive patterns

### SAML

- Enforce signed assertions; reject responses without a valid signature.
- Validate `<AudienceRestriction>` strictly against the SP's entity ID.
- Validate `<Conditions>` `NotBefore` and `NotOnOrAfter` with a small
  clock-skew tolerance (60-300 seconds).
- Use a hardened XML parser: disable external entities, disable DTD
  processing, fail on multiple root elements. Cross-link:
  `xml_parser_differential_expertise.md` §8.
- Maintain a replay-prevention set: reject Assertions whose ID was
  recently seen.
- Enforce `InResponseTo`: an SP-initiated SSO Response must carry the
  AuthnRequest's ID; reject Responses that don't match.
- Refresh metadata over HTTPS with strict certificate validation.
- Cache JWKS / signing certificates with bounded TTLs; refresh
  proactively.

### OIDC

- Validate `iss`: the issuer must match the configured IdP.
- Validate `aud`: the audience must include the SP's client_id.
- Validate `nonce`: ID tokens received via the redirect must echo the
  nonce stored in the user's session.
- Validate `iat` and `exp`: with small clock-skew tolerance.
- Validate `token_type`: don't accept Access Tokens where ID Tokens are
  expected.
- Use a vetted OIDC client library; don't hand-roll discovery, JWKS, or
  ID token validation.
- Pin discovery URLs at deployment time.

### JWT

- Maintain an algorithm allowlist; **never** accept `none`.
- Use libraries with explicit-algorithm APIs: `jose@4+`, `pyjwt@2+`,
  `jjwt`.
- Treat `kid` as opaque; whitelist against known IDs.
- Ignore `jku` and `x5u` unless explicitly allowlisted.
- Use proper key management (HSM, KMS) for signing keys.
- Re-verify signatures in every consumer; don't rely on "the gateway
  already verified."

### OAuth flows

- Mandate PKCE for every flow, every client type.
- Strict-equality redirect_uri allowlist; no wildcards, no substring
  match.
- Mandate `state` parameter; bind to user session.
- Validate `iss` parameter in authorization responses (RFC 9207).
- Rotate refresh tokens on use; detect family-level replay; invalidate
  aggressively.
- Don't accept Client Credentials tokens in user-context endpoints.
- Don't accept Implicit Flow tokens; refuse `response_type=token` in
  modern clients.

### Federation hygiene

- Rotate signing keys quarterly. Maintain a key-rollover runbook with
  overlap windows.
- Refresh IdP metadata at least daily.
- Maintain an inventory of federated SPs; review quarterly for
  decommissioned apps that still have active federation trust.
- Pin signing certificates at deployment time when SP supports it;
  monitor for IdP-side key rotation that requires SP-side updates.
- Maintain an "in case of IdP compromise" runbook: how to fail-closed
  the federation, force re-authentication of all active sessions,
  invalidate all refresh tokens.
- Treat SCIM tokens, IdP signing private keys, and OAuth client
  secrets as Tier-0 secrets in the secret-rotation policy.

### Code review checklist

1. SAML signature verification returns reference to verified subtree (not
   re-traversal of original document)?
2. `<AudienceRestriction>` validated against SP's specific entity ID?
3. SAML Assertion IDs added to replay-prevention set?
4. `NotBefore`/`NotOnOrAfter` validated with bounded clock skew?
5. JWT signatures verified with explicit algorithm allowlist?
6. JWT `iss`/`aud` validated against expected IdP/SP?
7. OIDC `nonce` validated against session-stored value?
8. ID Token / Access Token distinguished by `aud` and `token_type`?
9. OAuth `redirect_uri` validated by strict equality (no wildcards)?
10. `state` parameter generated, transmitted, validated?
11. PKCE used for every authorization code flow?
12. Refresh tokens rotated on use with replay-detection?
13. SCIM endpoints scoped to per-tenant authentication?
14. SCIM-settable attributes allowlisted (deny-by-default on role)?
15. XML parser hardened (no external entities, no DTD, single root)?

Cross-link: `code_review_expertise.md` §9.

---

## 13. Variant analysis — under-explored areas

### SCIM provisioning at scale

Cross-tenant SCIM (§8) is structurally similar to the broader multi-tenant
AuthZ problem. Few SaaS vendors test SCIM at cross-tenant boundaries; few have
detection rules for "SCIM token used to create users in a different tenant than
issuance." Under-tested attack surface.

### Federated identity for AI agents

The 2025-2026 LLM-agent rise asks: how does an agent prove user authority?
Two patterns: **ambient OAuth tokens** (agent holds user's refresh token —
hard to scope, revoke, audit) and **capability tokens** (narrow, time-bound,
explicit scope per operation). OIDC assumes user is present and consenting at
authentication; agents break this assumption. Cross-link:
`llm_agent_security_expertise.md`, `agentic_web_capabilities_expertise.md` §5.

### Mobile-specific OIDC flows

Device Code grant (RFC 8628) and Authorization Code + PKCE in native apps:
custom URL schemes (`com.example.app://callback`) can be claimed by other apps
on the device; "client secret" in a native binary isn't secret (RFC 8252
mandates PKCE, treats native as public clients); Universal Links / App Links
provide cryptographic proof of app ownership but many integrations don't use
them.

### Browser-based wallet federation

Sign-In With Ethereum (SIWE; ERC-4361) and DID/Verifiable Credentials shift
federation boundaries: wallet is the IdP, user controls signing key, SP
verifies a signed login challenge instead of redirecting to centralized IdP.
Early-stage attack surfaces — SIWE has had message-replay and chain-confusion
bugs. Forward-looking threat model.

### Cross-cloud federation

AWS IAM, GCP IAM, and Entra federate via OIDC trust. The bug class:
misconfigured trust policies with permissive principal-claim validation. AWS's
"GitHub Actions to AWS via OIDC" trust-policy misconfigurations let arbitrary
repository owners assume privileged roles. Cross-link:
`cloud_iam_expertise.md` §7.

### "Your IdP is your single point of compromise"

Storm-0558 demonstrated maximum impact: a single stolen
signing key minted tokens for arbitrary tenants for weeks before detection.
The structural defense isn't "harden more" (Microsoft was at the top of the
curve); it's diversification: dual-IdP architectures (require valid assertions
from two IdPs for critical apps), pinned signing certificates (SP consent
required for IdP key rotation), token-binding (RFC 8471, bind tokens to TLS
channel keys), SP-side circuit-breakers (fail-closed without IdP cooperation).
Almost no one implements dual-IdP — cost is real (operational complexity, UX
friction), benefit narrow (only for IdP-side crypto compromise). For the 99%
whose threat model isn't "nation-state targeting Microsoft," practical defense
is operational hygiene (§12) + IdP-side incident monitoring. Cross-link:
`appsec_program_building_expertise.md` §11.

---

## 14. References

### Canonical specifications

- **OASIS SAML 2.0 Core** (March 2005). The protocol specification.
  https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
- **OASIS SAML 2.0 Profiles**. The Web Browser SSO Profile and HTTP
  Bindings. https://docs.oasis-open.org/security/saml/v2.0/saml-profiles-2.0-os.pdf
- **RFC 7519 — JSON Web Token (JWT)**. Mike Jones et al., May 2015.
  https://datatracker.ietf.org/doc/rfc7519/
- **RFC 7515 — JSON Web Signature (JWS)**. https://datatracker.ietf.org/doc/rfc7515/
- **RFC 7516 — JSON Web Encryption (JWE)**. https://datatracker.ietf.org/doc/rfc7516/
- **RFC 8725 — JWT Best Current Practices**. https://datatracker.ietf.org/doc/rfc8725/
- **RFC 6749 — The OAuth 2.0 Authorization Framework**. https://datatracker.ietf.org/doc/rfc6749/
- **RFC 7636 — Proof Key for Code Exchange (PKCE)**. https://datatracker.ietf.org/doc/rfc7636/
- **RFC 8414 — OAuth 2.0 Authorization Server Metadata**. https://datatracker.ietf.org/doc/rfc8414/
- **RFC 9068 — JWT Profile for OAuth 2.0 Access Tokens**. Vittorio Bertocci.
  https://datatracker.ietf.org/doc/rfc9068/
- **RFC 9207 — OAuth 2.0 Authorization Server Issuer Identification**.
  https://datatracker.ietf.org/doc/rfc9207/
- **RFC 9700 — Best Current Practice for OAuth 2.0 Security (BCP 240)**.
  Fett, Lodderstedt, Bradley, Labunets. January 2025.
  https://datatracker.ietf.org/doc/rfc9700/
- **OpenID Connect Core 1.0**. https://openid.net/specs/openid-connect-core-1_0.html
- **OpenID Connect Discovery 1.0**. https://openid.net/specs/openid-connect-discovery-1_0.html
- **RFC 7644 — SCIM Protocol**. https://datatracker.ietf.org/doc/rfc7644/

### Foundational research

- Somorovsky, Mayer, Schwenk, Kampmann, Jensen. **"On Breaking SAML: Be
  Whoever You Want to Be."** USENIX Security 2012.
  https://www.usenix.org/system/files/conference/usenixsecurity12/sec12-final91.pdf
- Fett, Kuesters, Schmitz. **"A Comprehensive Formal Security Analysis
  of OAuth 2.0."** CCS 2016.
  https://publ.sec.uni-stuttgart.de/fettkuestersschmitz-ccs-2016.pdf
- Kupser, Mainka, Schwenk, Somorovsky. **"How to Break XML Encryption
  — Automatically."** USENIX WOOT 2015.
  https://www.usenix.org/system/files/conference/woot15/woot15-paper-kupser.pdf
- McLean, Tim. **"Critical vulnerabilities in JSON Web Token libraries."**
  Auth0, 2015. https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/

### Vulnerability disclosures

- Duo Labs / Kelby Ludwig. **"Duo Finds SAML Vulnerabilities Affecting
  Multiple Implementations."** 2018.
  https://duo.com/blog/duo-finds-saml-vulnerabilities-affecting-multiple-implementations
- Jain, Bhavuk. **"Zero-day in Sign in with Apple."** 2020.
  https://bhavukjain.com/blog/2020/05/30/zeroday-signin-with-apple/
- CyberArk Labs. **"Golden SAML: Newly Discovered Attack Technique
  Forges Authentication to Cloud Apps."** 2017.
  https://www.cyberark.com/resources/threat-research-blog/golden-saml-newly-discovered-attack-technique-forges-authentication-to-cloud-apps
- **CVE-2022-1245** — Keycloak token-exchange privilege escalation.
  https://github.com/advisories/GHSA-75p6-52g3-rqc8
- **CVE-2022-24901** — parse-server Apple Game Center cert-URL bypass.
  https://github.com/advisories/GHSA-qf8x-vqjv-92gr
- **CVE-2022-39353** — @xmldom/xmldom multi-root XSW primitive.
  https://github.com/advisories/GHSA-crh6-fp67-6883

### Microsoft Entra ID research

- Mollema, Dirk-jan. **"Phishing for Primary Refresh Tokens and Windows
  Hello keys."** https://dirkjanm.io/phishing-for-microsoft-entra-primary-refresh-tokens/
- Mollema, Dirk-jan. **"Lateral movement and on-prem NT hash dumping
  with Microsoft Entra Temporary Access Passes."**
  https://dirkjanm.io/lateral-movement-and-hash-dumping-with-temporary-access-passes-microsoft-entra/
- Mollema, Dirk-jan. **ROADtools.**
  https://github.com/dirkjanm/roadtools
- Microsoft. **"Midnight Blizzard: Guidance for responders on
  nation-state attack."** 2024.
  https://www.microsoft.com/en-us/security/blog/2024/01/25/midnight-blizzard-guidance-for-responders-on-nation-state-attack/

### Practitioner writing

- Bertocci, Vittorio. **"Identity, Unlocked."** Podcast archive.
  https://identityunlocked.auth0.com/
- Bertocci, Vittorio. **cloudidentity.com archive.**
  https://www.cloudidentity.com/
- Baier, Dominick. **leastprivilege.com.** https://leastprivilege.com/
- Allen, Brock. **brockallen.com.** https://brockallen.com/
- Jones, Mike. **self-issued.info.** https://self-issued.info/
- Parecki, Aaron. **OAuth 2.0 Simplified.**
  https://aaronparecki.com/oauth-2-simplified/
- Parecki, Aaron. **oauth.net.** https://oauth.net/
- Homakov, Egor. **"The Most Common OAuth2 Vulnerability."** 2012.
  http://homakov.blogspot.com/2012/07/saferweb-most-common-oauth2.html
- Homakov, Egor, and Labunets, Andrey. **"OAuth 2.0 and the Road to
  XSS: attacking Facebook Platform."** HITB Amsterdam 2013.
  https://conference.hitb.org/hitbsecconf2013ams/materials/D2T1%20-%20Andrey%20Labunets%20and%20Egor%20Homakov%20-%20OAuth%202.0%20and%20the%20Road%20to%20XSS.pdf
- WorkOS Engineering. **"Fun with SAML SSO vulnerabilities and
  footguns."** https://workos.com/blog/fun-with-saml-sso-vulnerabilities-and-footguns

### Cross-references in this directory

- `distributed_authz_expertise.md` — parent treatment of AuthN/AuthZ
  failure modes; AI-assisted authz-detection workflow lane.
- `xml_parser_differential_expertise.md` §4 — XSW depth treatment;
  §8 — Defensive Parser Configurations.
- `cryptography_expertise.md` — RSA signature algorithms; HMAC vs
  asymmetric signing; key management.
- `ssrf_url_parsing_expertise.md` §4 — URL-parser-differential
  primitive underlying redirect_uri laxity.
- `cloud_iam_expertise.md` §4 — Identity Provider Patterns;
  §7 — Cross-Cloud Trust Policies; §9 — Logging and Audit Hygiene.
- `detection_engineering_expertise.md` §6 — Authentication Anomaly
  Detection.
- `appsec_program_building_expertise.md` §9 — Incident Response;
  §11 — Building Federation Resilience.
- `agentic_web_capabilities_expertise.md` §5 — Capability-Based
  Delegation as an alternative to ambient OIDC tokens.
- `llm_agent_security_expertise.md` — federation for AI agents.
- `code_review_expertise.md` §9 — Auth-Centric Review Patterns.
