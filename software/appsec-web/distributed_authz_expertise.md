# AuthZ in Distributed Systems — Patterns, Bugs, and Detection
## Synthesized from Zanzibar, OPA, OWASP API, and the Practitioner Corpus

> **Primary researchers and teams:**
>
> - **Lea Kissner** — co-author of the Google Zanzibar paper; former Google Global Lead, Privacy
>   Technology; former Twitter CISO and Head of Privacy Engineering; former Lacework CISO; PhD
>   cryptography, CMU.
> - **Ruoming Pang, Ramon Cáceres, Mike Burrows, Zhifeng Chen, Pratik Dave, Nathan Germer,
>   Alexander Golynski, Kevin Graney, Nina Kang, Jeffrey L. Korn, Abhishek Parmar, Christina D.
>   Richards, Mengzhi Wang** — the Google Zanzibar paper authors (USENIX ATC 2019). Burrows
>   carries the Chubby, BigTable, and Dapper legacy; the team's combined CV is essentially the
>   distributed-systems primitives layer underneath every Google service that does access checks.
> - **Tim Hinrichs, Torin Sandall, Teemu Koponen** — co-creators of Open Policy Agent (Styra,
>   2016). Hinrichs (CTO, Styra; PhD Stanford; co-founder OpenStack Congress) and Sandall (VP of
>   Open Source, Styra) drove OPA from inception through CNCF graduation. OPA is the
>   canonical declarative policy engine in the Kubernetes admission controller path and the
>   reference example for "policy as code" in cloud-native authorization.
> - **Paulo Silva, Erez Yalon, Inon Shkedy** — co-leads of the OWASP API Security Top 10 2023.
>   The 2023 edition canonicalized the **BOLA / BFLA / BOPLA** taxonomy (Broken Object Level
>   Authorization, Broken Function Level Authorization, Broken Object Property Level
>   Authorization), which is now the dominant API-AuthZ bug vocabulary in product security
>   triage.
> - **Björn Kimminich** — creator and project lead of OWASP Juice Shop (with Jannik
>   Hollenbach). The Juice Shop's "Broken Access Control" challenge family is the pedagogical
>   reference corpus for IDOR, BFLA, and role-string-compare bugs.
> - **Daniel Fett, Torsten Lodderstedt, John Bradley, Andrey Labunets** — IETF OAuth Working
>   Group authors of RFC 9700 ("Best Current Practice for OAuth 2.0 Security," January 2025)
>   and its predecessor `draft-ietf-oauth-security-topics`. The canonical statement of the
>   OAuth threat model and the attacks the protocol layer must defend against.
> - **Kurt Boberg (`kurt-r2c`)** — Semgrep staff researcher; five publicly-credited AuthN/AuthZ
>   CVEs covering the exact failure-mode bestiary this document codifies:
>   - CVE-2020-13957 (Apache Solr, CVSS 9.8) — auth-bypass on ConfigSet upload via
>     UPLOAD+CREATE action composition. https://github.com/advisories/GHSA-3c7p-vv5r-cmr5
>   - CVE-2022-1245 (Keycloak, CVSS 9.8) — privilege escalation in the OAuth2 token-exchange
>     grant; missing authorization let any client redeem tokens for any target client_id.
>     https://github.com/advisories/GHSA-75p6-52g3-rqc8
>   - CVE-2022-1332 (Mattermost, CVSS 4.3) — improper privilege management in custom admin
>     roles; restricted-role admins could read server logs and config.json contents.
>     https://github.com/advisories/GHSA-qggc-pj29-j27m
>   - CVE-2022-3294 (Kubernetes, CVSS 8.8) — node address validation bypass in kube-apiserver
>     proxy; authenticated requests could reach the API server's private network.
>     https://github.com/advisories/GHSA-jh36-q97c-9928
>   - CVE-2022-24901 (parse-server, CVSS 7.5) — weak validation of the Apple Game Center
>     certificate URL allowed authentication bypass and DoS.
>     https://github.com/advisories/GHSA-qf8x-vqjv-92gr
>
> These five CVEs hit five different products, five different protocols, and five different
> failure modes. This document is the synthesis of those failure modes plus the broader
> distributed-AuthZ literature, written to drive a static-analysis authz-detection workflow.
>
> Sources: USENIX ATC 2019 (Zanzibar paper); GHSA advisories cited inline; OWASP API Top 10
> 2023; RFC 9700; OPA documentation; Authzed SpiceDB documentation; OpenFGA project docs.

---

## 1. AuthN vs AuthZ vs Identity Binding

### The three-step chain

Every request that touches a sensitive resource has to answer three questions, in order:

1. **AuthN — Who are you?** Prove the principal identity claimed by the request. Outputs an
   authenticated principal (a user ID, a service account, a token claim set).
2. **AuthZ — What can you do?** Decide whether that principal is permitted to perform the
   requested operation against the requested resource. Outputs a permit/deny decision.
3. **Identity binding — Bind the action to the actor.** Execute the operation under the
   authenticated identity, so that downstream audit, ownership tagging, and follow-on AuthZ
   checks all reference the correct principal.

These three steps are routinely conflated in bug reports, CWE labels, and production code —
the root cause of most failure modes in this document. Common conflations:

- **AuthN-as-AuthZ.** Handler checks "is the user logged in" and treats that as permission.
  BOLA / IDOR primitive: the request's `resource_id` is never checked for ownership.
- **AuthZ-without-binding.** Handler authorizes principal A to perform operation X, then
  executes under a service identity. Audit attributes the action to the service. TOCTOU on
  the resource handle: entry-decorator validates ID X belongs to A, body operates on ID Y.
- **Binding without AuthZ.** System tags "user A did this" but never asks whether A was
  allowed. Common in admin tools that audit-but-don't-gate.

### CWE mapping

This detection lane is organized around six CWEs in this cluster. The mapping below
is the canonical one the per-CWE detection prompts encode:

| CWE | Name | What it means | Typical primitive |
|---|---|---|---|
| 287 | Improper Authentication | AuthN check exists but is broken: token validator skips signature, credential equality check is type-confused, identity-provider response is trusted without verification | JWT `alg:none`, SAML signature wrap, OAuth confused-deputy, Apple Game Center cert-URL bypass (CVE-2022-24901) |
| 306 | Missing Authentication for Critical Function | No AuthN check at all on a sensitive endpoint. Public actuator. Public admin route. Public data export | Spring Boot `/actuator/env` unauth, Solr ConfigSet API unauth (CVE-2020-13957), unauth GraphQL mutation |
| 308 | Use of Single-factor Authentication | The endpoint is sensitive enough that a single factor (password, API key, token) is insufficient; MFA / re-auth required | Password-only on `/admin/delete-tenant`, no re-auth on email change, single-token reset flow |
| 862 | Missing Authorization | AuthN succeeded but no AuthZ check is performed. The principal is known; the question "are they allowed to do this on THIS resource" is never asked | IDOR (`/users/123/orders/456` returns A's order to B), missing tenant filter, public read on private bucket |
| 863 | Incorrect Authorization | AuthZ check exists but is wrong. The check passes when it should not | Role-string compare with type-coercion (`role == "admin"` matches `["admin"]` via JS coercion), client-controlled tenant ID, TOCTOU between entry-decorator and body, capability-confusion in custom RBAC (CVE-2022-1332 Mattermost) |
| 1390 | Weak Authentication | AuthN exists but the credential primitive is weak: cleartext transport, hardcoded secret, weak hash, shared static API key, broken signature compare, secret in URL | Basic auth without TLS, HMAC verified with `==` instead of constant-time, JWT signed with `HS256` and a known-weak key |

This mapping is **load-bearing for triage**. A "missing authz" finding under CWE-862 is
treated very differently from an "incorrect authz" finding under CWE-863 — the first
indicates a structural omission (likely entire endpoint class is unprotected), the second
indicates a logic bug in a check that is present (likely a regression introduced when the
check was modified). Cross-reference to `code_review_expertise.md` §3 ("click-count
severity"): missing-authz is typically zero-click (any authenticated user can exploit);
incorrect-authz is typically one-click (authenticated user with some specific attribute can
exploit).

### Detection taxonomy

A static-analysis authz-detection workflow can organize detection for these CWEs into
per-CWE pattern buckets, each further broken into named detection patterns:

- CWE-308 (single-factor) — patterns such as NoReauthPrivileged, PasswordOnlyPrivileged,
  SingleTokenReset, StaticCredPrivileged
- CWE-306 (missing AuthN) — patterns such as PublicActuator, PublicAdminRoute,
  PublicDataExport, UnauthMutation
- CWE-862 (missing AuthZ) — patterns such as IdorObject, BulkScopeLeak, MutationNoAuthz,
  TenantBypass
- CWE-863 (incorrect AuthZ) — patterns such as ClientControlledRole, ClientControlledTenant,
  IdentityObjectCompare, RoleStringCompare, ToctouAuthz

These are detection units. The bugs they detect are the practical realization of the
failure modes catalogued in §3 and §4 below.

---

## 2. The Trust-Boundary Topology in Distributed Systems

### The layered authorization stack

Modern distributed systems do authorization at five layers, each with a distinct failure
mode:

| Layer | Examples | Dominant failure mode |
|---|---|---|
| Edge / API gateway | Kong, AWS API GW, Envoy, NGINX `auth_request`, Apigee | "Trust the upstream header" — backends reachable via alternate paths (kubelet API, internal admin tools, debug ports) forge the gateway-injected `X-User-Id` |
| Service mesh | Istio, Linkerd, Consul Connect | Mesh proves service identity (mTLS/SPIFFE), not user identity. User identity propagation in-band (JWT, session) can be stripped on retry or skipped in async paths |
| Sidecar AuthZ | OPA + Envoy ext_authz, OAuth2-proxy, SpiceDB middleware | Sidecar makes coarse decision ("user A can call POST /orders/:id"); backend then writes to any order ID user supplies because resource-level scope wasn't in sidecar input |
| In-application AuthZ | Spring Security, Django middleware, Rails Pundit, ASP.NET filters, Flask `before_request`, Express chains | Decorator validates caller's role/session; body operates on different resource ID from request body (TOCTOU; CWE-863 ToctouAuthz pattern) |
| Database-layer AuthZ | PostgreSQL RLS, MongoDB field-level, BigQuery RLS, Snowflake masking | RLS policy depends on session variable that connection pool must reset on checkout; pool reuse leaks tenant A's policy context into tenant B's query (see `silvia_botros_dba_principles.md`) |

### The "auth-once at edge" vs "auth-at-every-hop" tradeoff

The central architectural decision in distributed AuthZ. One position: authorization should be a **single, consistent decision** made once, with the
result propagated to every component that needs to know. The alternative — every service
re-asks the question — is operationally expensive, inconsistent (different services may have
different views of the policy graph), and impossible to make uniformly fast.

The counter-argument: any component that trusts an upstream decision is one
upstream-compromise away from being trivially exploitable. The "trust the upstream header"
anti-pattern is a direct consequence of the auth-once-at-edge architecture.

The synthesis in practice is **defense-in-depth on AuthZ specifically**: the edge does
gross-grain authorization (is this caller authenticated, is the path allowed for this role
class), the backend re-checks fine-grained authorization (does this caller own this specific
resource, is this specific tenant scope valid for this caller). Both checks must succeed.
The backend cannot trust the edge for resource-level decisions; the edge cannot make
resource-level decisions because it doesn't have the data.

---

## 3. AuthN Bugs — Primitives and Corpus

This section catalogues failure modes in step 1 of the chain (prove identity). CWE-287
(Improper Authentication), CWE-306 (Missing Authentication for Critical Function), and
CWE-1390 (Weak Authentication) cluster here.

### Token-exchange privilege escalation (CVE-2022-1245)

The Keycloak token-exchange grant (RFC 8693) lets a client redeem one OAuth token for
another — typically for delegation where service A calls service B on behalf of user U with
a token scoped for B but bound to U's identity. Kurt's CVE-2022-1245: the endpoint
validated that the requesting client held a valid token and that the target `client_id`
existed, but **did not check whether the requester was authorized to exchange for the
target**. Any client holding a valid token could redeem it for a token bound to any other
registered client.

Structural lesson: **token-exchange grants are an authorization decision, not just an
authentication operation.** Same applies to SAML attribute mapping (the IdP must be
authorized to assert each attribute the SP uses for AuthZ), OIDC dynamic client
registration (any unauthenticated party that can register a client is in the trust
boundary), and JWT issuer trust expansion (multiple issuers means any can mint for any
subject).

Detection sketch (CWE-287 ClientTrustedIdentity): handler that calls `exchange_token(
target_client_id)` or `assertion_from_idp.subject` without checking the caller's authority
to act for that target.

### Apple Game Center / parse-server (CVE-2022-24901)

Apple Game Center: the server fetches Apple's signing certificate from a URL Apple supplies
in the player identity assertion, then verifies the assertion against that certificate. The
pre-fix parse-server code accepted the certificate URL **from the client-supplied
assertion** with only weak validation of that URL, allowing authentication bypass.

Structural lesson: **trust chain anchored to server-controlled value, not client-supplied.**
Federation must pin IdP discovery to a server-side allowlist, not extract from request
data. Same pattern: SAML metadata URL from assertion's IssuerID, OIDC `iss` self-selection
for JWKS endpoint, OAuth dynamic client registration with arbitrary `redirect_uri` schemes,
JWT verification trusting the header's `alg`.

Detection sketch (CWE-287 ClientTrustedIdentity, CustomSessionShape): identity-verification
path where a URL, JWKS endpoint, IdP, or signing key is selected from request data without
a server-side allowlist gate.

### Missing AuthN on admin endpoints (CVE-2020-13957)

Apache Solr's ConfigSet API: ConfigSets contain Velocity templates and arbitrary Java
classes that Solr executes — upload-with-RCE is the obvious endpoint. The pre-fix code
blocked dangerous features in ConfigSets uploaded via the API without authentication, but the
check could be circumvented by combining the `UPLOAD` and `CREATE` actions → unauth RCE.

Structural lesson: **authentication enforced at the operation level, not the endpoint
level.** Two operations on the same endpoint with different effects cannot share an
auth gate that protects only one. This is the CWE-306 PublicAdminRoute detection pattern:
any administrative route (writes config, creates resources, modifies users, executes
operator-reserved code paths) requires an explicit check at the operation level, not a
generic "authenticated-routes-only" middleware that may not match.

### JWT validation footguns (cross-link to `cryptography_expertise.md`)

Top JWT vulnerabilities, with their detection-pattern mapping:

| Bug | Mechanism | Detection pattern |
|---|---|---|
| `alg:none` | Verifier accepts unsigned tokens | CWE-287 CustomSessionShape |
| HS256/RS256 confusion | RS256-configured verifier accepts HS256 signed with the public key | CWE-287 CustomSessionShape |
| `kid` path traversal / SQLi | `kid` header used as filesystem path or SQL parameter | CWE-287 CustomSessionShape |
| Issuer trust expansion | Verifier accepts tokens from any registered IdP | CWE-287 ClientTrustedIdentity |
| JKU/X5U URL injection | JWT header's JKU/X5U points to attacker JWK Set | CWE-287 ClientTrustedIdentity |

The cryptographic substrate is in `cryptography_expertise.md`. The authorization-impact
substrate is here.

### SAML and OAuth — protocol-layer summary

**SAML signature bypass** families: XML Signature Wrapping (signed element moved, unsigned
copy substituted in its place), comment-truncation in NameID, DOCTYPE/XXE injection,
canonicalization mismatches between signer (exclusive) and verifier (inclusive). Impact is
always AuthZ — attacker claims any identity the SP trusts the IdP to assert.

**OAuth/OIDC** canonical attacks per RFC 9700 §4: authorization code injection, missing
`state` (CSRF on authorize endpoint), mix-up attack across IdPs, access-token redirect via
Referer/logs, PKCE downgrade, refresh-token theft +
rotation evasion. The cross-cutting failure mode — "trusting a client-supplied value during
identity assertion" — is the dominant primitive across all of them.

---

## 4. AuthZ Bugs — Primitives and Corpus

This section catalogues failure modes in step 2 of the chain (decide if permitted).
CWE-862 (Missing Authorization) and CWE-863 (Incorrect Authorization) cluster here, with
overlap into CWE-306 (which is technically AuthN but is functionally an AuthZ failure when
the missing check is on a privileged route).

### Path-based bypasses in reverse proxies (CVE-2022-3294)

Kurt's CVE-2022-3294: kube-apiserver supports node-proxying — clients reach kubelet
endpoints through the API server, which validates the proxying address for Nodes. The
bypass: a bug in kube-apiserver let a user who can modify Node objects and send proxy
requests to them bypass this validation → authenticated requests destined for Nodes reach
the API server's private network.

Structural lesson: **validation-against-mutable-data is not validation.** If the allowlist
itself is editable by the attacker, it's a UX feature, not a security control. Path-
normalization bugs in reverse proxies are the same family: NGINX/Envoy/HAProxy normalize
one way, backend Spring/Django/Express normalize differently, and the difference is the
attacker's escape route. Mirheidari et al.'s "Cached and Confused: Web Cache Deception in the Wild" (USENIX
Security 2020), which frames web cache deception as path confusion, is the canonical
research line.

Detection (cross-cuts CWE-863 and CWE-22): handler proxies to a backend address selected
from request data via validation-against-stored-state where the stored state is writable by
non-admin actors.

### Capability-confusion in role models (CVE-2022-1332)

Kurt's CVE-2022-1332 in Mattermost: an API failed to properly protect permissions, so
authenticated members with a restricted custom admin role could bypass those restrictions
and view the server logs and the server config.json contents.

Structural lesson: **role composition is a security boundary.** Custom role models that let
admins combine permissions must enumerate the combinations or impose a closure rule.
Capability inflation via composition is the same failure mode as the K8s RBAC
privilege-escalation paths (`container_k8s_security.md` §4) — individually-harmless
permissions compose into cluster-admin.

### BOLA / IDOR / BFLA / BOPLA — OWASP API Top 10

**BOLA** (Broken Object Level Authorization) is the dominant API-AuthZ bug. Pattern:
`@requires_login` decorator + handler that trusts login implies access:

```python
@app.route("/orders/<int:order_id>")
@requires_login
def get_order(order_id):
    return Order.objects.get(id=order_id).to_json()  # any user reads any order
```

**BFLA** (Broken Function Level Authorization) is the same bug at function level: a
non-admin reaches an admin-only endpoint because authentication is mistaken for
authorization. **BOPLA** (Broken Object Property Level Authorization, new in 2023): a user
reads/writes object properties they shouldn't — e.g., `PATCH /users/me` accepting arbitrary
fields including `is_admin: true`.

CWE-862 family detection patterns:

- **IdorObject** — handler takes resource ID from request and uses it directly in a query
  without joining against the caller's principal.
- **BulkScopeLeak** — list endpoint returns multiple resources without principal-scope
  filtering.
- **MutationNoAuthz** — write/delete endpoint with the IdorObject pattern.

Canonical defensive pattern is to scope queries through the authenticated principal:

```python
Order.objects.get(id=order_id)                    # Vulnerable
request.user.orders.get(id=order_id)              # Safe (data-layer-scoped)
```

The second form enforces ownership structurally at the query layer. Detection prompts for
this pattern family **do not emit findings** for data-layer-scoped queries.

### Tenant isolation failures

The "client-controlled tenant ID" pattern:

```python
tenant_id = request.args.get("tenant_id")              # Vulnerable
return Data.objects.filter(tenant=tenant_id).all()
```

Tenant binding must come from the authenticated principal (`tenant_id = request.user
.tenant_id`), never request payload. The CWE-863 ClientControlledTenant pattern targets
exactly this. Subtler form: **URL-keyed vs token-keyed tenant binding** — the URL contains
the tenant ID and the auth token also contains a tenant ID, and the code reads from the URL
without comparing to the token's claim.

### Resource-scoped vs operation-scoped AuthZ

"Can X perform Y" (operation-scoped) vs "Can X perform Y on resource Z" (resource-scoped) is
the defining axis. RBAC encodes operation-scoped (`can_delete_user`); ABAC and ReBAC encode
resource-scoped (`can_delete_user(target=user_z)`). Bug class: an operation-scoped check
applied where resource-scoped is needed — "can the caller delete users" returns yes; the
handler doesn't ask "can the caller delete THIS user." This is the failure mode behind most
K8s RBAC escalations (`container_k8s_security.md` §4) — individual verbs are
operation-scoped, resource-scoping via `Resources`/`ResourceNames` is often omitted.

### Role-string compare anti-pattern (CWE-863)

The CWE-863 RoleStringCompare detection pattern targets a specific implementation:

```javascript
// Vulnerable: type coercion
if (user.role == "admin") { ... }

// Vulnerable: substring match
if (user.role.includes("admin")) { ... }   // "non-admin" matches

// Vulnerable: array-vs-string confusion
if (user.roles == "admin") { ... }   // ["admin"] coerces to "admin"

// Vulnerable: case-insensitive accidental
if (user.role.toLowerCase() == "admin") { ... }   // user can set role to "Admin"
```

The defensive pattern: structured role comparison via a typed enum, with a strict equality
or set-membership test. In TypeScript: `user.roles.includes(Role.ADMIN)` where `Role` is an
enum and `user.roles` is a typed array. In Python: `Role.ADMIN in user.roles` with `Role` as
an `Enum`. In Java: `user.getRoles().contains(Role.ADMIN)` with `Role` as an enum.

The bug pattern's signal is **string equality on role/permission identifiers**. The fix is
to type the identifier.

### TOCTOU on AuthZ check

The CWE-863 ToctouAuthz detection pattern targets the time-of-check-to-time-of-use pattern in
authorization: the entry-decorator validates resource ID X belongs to the caller, the body
operates on resource ID Y from a different source.

```python
@requires_owns_order(order_id=request.GET["order_id"])
def update_order():
    order_id = request.POST["order_id"]   # different source!
    Order.objects.filter(id=order_id).update(...)
```

The decorator validates the GET parameter. The body operates on the POST parameter. An
attacker sends `?order_id=their_order&order_id=victim_order` (one in GET, one in POST), the
decorator passes (validates GET), the body writes to the POST value.

Detection signal: handler with an authorization decorator that takes a specific resource
identifier, where the body reads a resource identifier from a different request source.

### Capability inflation via UNION

A subtler form of incorrect AuthZ: a query that joins or unions tables with different access
policies inherits the broadest policy. PostgreSQL RLS catches this on direct table access
but not on views; MongoDB aggregation pipelines with `$lookup` are particularly vulnerable.

```sql
-- TableA has RLS by tenant. TableB does not.
SELECT * FROM tableA JOIN tableB ON ...
-- RLS applies to tableA. tableB rows leak across tenants.
```

The fix is policy parity: every table touched in a multi-tenant query must have its own RLS
policy or be wrapped in a tenant-filtering view.

---

## 5. Zanzibar and the Relationship-Tuple Model

### The 2019 paper synopsis

Pang et al., "Zanzibar: Google's Consistent, Global Authorization System," USENIX ATC 2019.
The paper describes the authorization system that backs Google Drive, Calendar, YouTube,
Cloud, Photos, and Maps. The contribution is not a new theory — it's a working,
planetary-scale implementation of a relationship-based access control (ReBAC) model with
operational properties (consistency, latency, throughput) that no prior system had achieved.

URL: https://www.usenix.org/conference/atc19/presentation/pang

### Relationship tuples

The data model is brutally simple. Every authorization fact is a tuple of the form:

```
<namespace>:<object>#<relation>@<user>
```

Examples:

- `doc:report123#viewer@user:alice` — Alice can view document 123
- `doc:report123#owner@user:bob` — Bob owns document 123
- `group:engineers#member@user:alice` — Alice is a member of group engineers
- `doc:report123#viewer@group:engineers#member` — every member of group engineers can view
  document 123

The last form is the **userset** — a tuple where the user field is not a user but another
set of users defined by a relation. This is what makes the model compositional: groups can
contain groups, ownership can imply viewership, project-membership can imply
folder-membership.

### Userset rewrites and the expand algorithm

The schema (in the Zanzibar configuration language) defines **rewrites**: rules that say
"the set of users with relation X on object O includes the set with relation Y." Example:

```
namespace doc:
  relation owner
  relation editor: owner   # owners are editors
  relation viewer: editor + parent->viewer   # editors are viewers, and viewers of parent folder are viewers
```

To answer "can Alice view doc 123" the system:

1. Look up `doc:123#viewer@user:alice` directly → if found, allow
2. Look up `doc:123#editor@user:alice` (per rewrite) → if found, allow
3. Look up `doc:123#owner@user:alice` (per chained rewrite) → if found, allow
4. Look up parent: `folder:F1#viewer@user:alice` (per parent rewrite) → if found, allow
5. Otherwise deny

This is how a **Check** request is evaluated. The structural property: every authorization decision is
the answer to a graph reachability query in the relationship graph.

### Consistency: ZedTokens and the "new enemy" problem

The "new enemy" problem (Pang et al. §2.2): a user U is removed from a group G; immediately
after, a document D's permissions are changed to grant access to G; U should not be able to
read D after the change, but if the system reads from a stale snapshot, U might see the
group-grant decision before seeing the group-removal.

Zanzibar's solution: every write returns a **zookie** (an opaque token encoding a timestamp). A subsequent
check that wants strong consistency with respect to the write passes the zookie; the
system guarantees the check sees the world at or after that point. Without a zookie, the
check is allowed to use a snapshot — much faster, less consistent.

This is the defining operational property of Zanzibar-style systems: **consistency is
configurable per request.** Critical operations (revocations, security-sensitive denies) use
strong consistency; common reads use snapshot consistency for performance.

### Adoption, limits, and the hybrid argument

Production implementations: AuthZed/SpiceDB (schema-faithful), OpenFGA (Auth0/Okta-flavored),
Permify (YAML-schema-friendly), Google Cloud IAM internals. The argument for ReBAC over RBAC: real authorization questions are
relationship questions — "Can X edit D" depends on whether X owns D, is in a group that owns
D, or is in a project that owns the folder containing D. RBAC's flat role-permission pairs
cannot express the graph; ReBAC encodes it directly.

Known limits: **schema rigidity**; **bulk operations** (`LookupResources` —
"every document Alice can view" — is much more expensive than `CheckPermission`);
**consistency-snapshot tradeoff** (ZedTokens pin a snapshot but force fresh-enough replica
reads with tail-latency cost). For most applications the right answer is a hybrid: ReBAC
for the relationship graph (group/project membership, ownership transitivity), OPA-style
policy-as-code at the edge for cross-cutting concerns (rate-limiting, request-shape
validation, simple role checks).

---

## 6. OAuth/OIDC Threat Model

RFC 9700 (January 2025) codifies the OAuth 2.0 Best Current Practice. Each canonical attack
has a specific code-level signal that static analysis can detect. The summary below pairs
each attack with its detection signal.

URL: https://datatracker.ietf.org/doc/rfc9700/

### `redirect_uri` bypass

The authorization server redirects the user back to a `redirect_uri` after consent. Without
strict allowlist validation, an attacker registers a `redirect_uri` pointing at
attacker-controlled infrastructure; the authorization code lands at the attacker.
Pre-RFC-9700 footguns: substring match (`https://victim.com.attacker.com/`), wildcard
subdomains, open redirector on the registered host, path-prefix match extended to a
victim-side open redirector.

The RFC 9700 mandate: **exact string match**, no substring, no wildcard, no path-prefix.
Detection: any OAuth server code that compares `redirect_uri` with anything other than `==`
on the full string.

### `state` / `nonce` and PKCE

The `state` parameter is the OAuth-layer CSRF token; without it, an attacker can initiate a
flow and trick a victim into completing it — binding attacker's account to victim's session.
The `nonce` parameter (OIDC) is bound into the ID token to prevent replay.

PKCE (RFC 7636) binds the authorization code to a client-chosen secret. PKCE-downgrade: a
client that supports PKCE but lets the server fall back to non-PKCE is vulnerable to
authorization code interception. Detection: code that initiates an OAuth flow without
per-request `state`, or doesn't validate `state` on callback; client code that sets
`code_challenge` but doesn't verify the server honored it.

### Refresh token theft, scope creep, confused-deputy

**Refresh tokens** are long-lived. RFC 9700 requires refresh tokens for public clients to be
sender-constrained or use refresh token rotation; with rotation, every
refresh issues a new token and invalidates the old; reuse triggers family-wide
invalidation.

**Scope creep**: a new endpoint is added without updating the scope-to-endpoint mapping;
or a scope is granted broadly during onboarding and never tightened. Static analysis can
flag endpoints reachable from a path scoped by a `*` permission.

**Confused-deputy** (cross-org OAuth): a GitHub OAuth app granted `read:org` for one org
used to read other orgs because the scope is bound to the app's identity rather than the
user-grant context. Detection: resource-server code that authorizes based on OAuth
`client_id` (app identity) rather than the bound user-grant scopes.

### Apple Sign-In / Google OAuth credential confusion

Apple Sign-In ID tokens may carry `email_verified` false (Apple may not verify email addresses for Sign in with Apple at Work & School users).
An attacker registers Apple ID with `victim@gmail.com`; a relying party that accepts
either Apple or Google ID tokens for the same account, and uses email as the cross-IdP
identifier, lets the attacker sign in as the victim. This is **CVE-2022-24901 at the
protocol layer**: trusting an IdP for an attribute the IdP doesn't actually validate. Fix:
pin federation to (IdP, subject) pairs, not (email).

---

## 7. Distributed-Systems AuthZ Anti-Patterns

A consolidated reference of the patterns a static-analysis authz-detection workflow targets
and the code-review pass should flag. Each entry: pattern → failure → defense → detection
pattern (where applicable).

| Anti-pattern | Failure mode | Defense | Detection pattern |
|---|---|---|---|
| **Auth at the edge only** (gateway terminates AuthN; internal services trust `X-Forwarded-User`) | Any path that reaches a service without going through the gateway forges the header | Every service re-validates the principal at its boundary; gateway decision is supplementary, not substitutive | — |
| **Trust the upstream header** (`X-User-Id`, `X-User-Role`, `X-Tenant-Id` from proxy) | Any backend reachable via an alternate path sees the same headers and trusts them | Cryptographically bound tokens (JWT, SPIFFE, signed headers); validate the binding, not the header value | — |
| **Role string compare** (`if (user.role == "admin")`) | Type coercion, substring match, case sensitivity, list-vs-scalar confusion | Typed enum / set membership; `user.has_perm("X")` not role-name string equality | CWE-863 RoleStringCompare |
| **TOCTOU on auth check** (decorator validates X, body operates on Y) | Decorator satisfied with one value; body writes to another | AuthZ check in the body, against the ID as used; or pass the resolved resource, not the ID | CWE-863 ToctouAuthz |
| **Client-controlled tenant** (tenant ID from request body/URL/query used as tenant filter) | Any authenticated user reads any tenant | Tenant binding from authenticated principal (token claim, session attribute), never request payload | CWE-863 ClientControlledTenant |
| **Capability inflation via UNION** (DB query joins/unions tables with different access policies) | Broader policy applies to joined rows | Every table in a multi-tenant query has its own tenant filter; wrap RLS-less tables in tenant-filtering views | — |
| **Authentication-as-authorization** (`@requires_login` on a per-user resource; no ownership check) | BOLA / IDOR — any authenticated user accesses any resource | Scoped query (`request.user.orders.get(id=...)`); or explicit ownership check in body | CWE-862 IdorObject |
| **Public-by-omission** (handler missing auth decorator entirely) | Anyone, including unauthenticated, can access | Default-deny middleware: handlers without explicit policy match → 403 | CWE-306 family |
| **Hardcoded auth secret** (API key/JWT secret/basic-auth credential in source) | Source / config access yields the credential | Secret manager (Vault, AWS Secrets Manager); secret never in source | CWE-287 HardcodedAuthSecret |
| **Basic auth without TLS** (HTTP Basic on non-HTTPS) | Credentials in cleartext, trivially intercepted | TLS mandatory; basic auth deprecated in favor of token-based AuthN | CWE-1390 BasicWithoutTls |
| **Client-trusted identity** (handler accepts user ID from request as the operation actor) | Anyone with the endpoint can impersonate anyone | Impersonation endpoints require admin-only gate + cryptographically-bound delegation token | CWE-287 ClientTrustedIdentity |

---

## 8. Detection / Rule-Authoring Patterns

This section turns the §3/§4 failure-mode catalogue into static-analysis rules. The
patterns here drive rule-authoring for authz-detection more broadly.

### The candidate-point pattern + auth-homogeneity heuristic

From `code_review_expertise.md` §2: every route handler is a candidate point. The audit
triple for each handler: (1) does it take a resource ID from request, (2) is that ID used
in a storage-layer query, (3) is there an explicit check that the principal is allowed to
operate on that specific resource? Yes-yes-no is a candidate finding. This is the
systematic implementation of the CWE-862 detection pattern.

From `code_review_expertise.md` §3, the **auth-homogeneity heuristic**: in N handlers, if
90% have `@requires_auth` and 3 don't, audit those 3. Either intentionally public (then
most-reviewed code in the service) or forgotten (then top finding). A discovery pass can
build the handler inventory + parent_chain (decorators, middleware, framework defaults)
across Django, Flask, FastAPI, Express, NestJS, Spring. Detection prompts then operate on
the inventory + parent_chain to identify where the auth signal is missing.

### Source enrichment + data-layer-scoped queries

A dataflow taint tracer traces: request entry (`request.GET/POST`, URL params, JSON body)
→ storage call (ORM `get(id=...)`, raw SQL, NoSQL query) → response serialization. Taint
flow from request to query (when query is resource-ID lookup) is the BOLA signal. Taint
flow from request to filter (`.filter(tenant=...)`) is the ClientControlledTenant signal.

Cardinal rule the CWE-862 detection prompt encodes: **do not emit findings for
data-layer-scoped queries.**

```python
Order.objects.get(id=request.GET["order_id"])                   # Vulnerable — emit
request.user.orders.get(id=request.GET["order_id"])             # Safe — do NOT emit
Order.objects.filter(user=request.user).get(id=...)             # Safe — do NOT emit
```

### Typed-flag scoring + cross-pattern deferral

A robust implementation encodes detection in two layers: per-CWE **detection prompts**
(reasoning-model analysis with cardinal rules per bucket) and per-CWE **finding models**
(structured types with a `compute_severity` step driven by typed flags: `sensitive_route`,
`auth_present`, `mitigation_present`). The LLM emits flags + evidence + reasoning; a
deterministic function maps flags to severity. The LLM never emits `severity` directly —
the "let the LLM reason, let the code score" discipline.

Detection patterns with overlapping surfaces require discipline: each pattern's prompt
should carry a `DEFER` block listing peer patterns it should not duplicate. The
cross-pattern DEFER graph should be pinned by a regression test enumerating the expected
bidirectional pairs; test failures force deliberate review on pattern additions or DEFER
edits.

---

## 9. Defensive Patterns

The catalogue below maps each failure mode to its structural defense. The defenses
compose — a system using all of them has defense-in-depth on AuthZ specifically, not just
generic defense-in-depth.

### Centralized policy decision point (PDP)

OPA, AuthZed/SpiceDB, OpenFGA, Permify — externalize the authorization decision. Application
code is a policy enforcement point (PEP) that calls the PDP with a structured query
(`{actor: user_X, action: read, resource: doc_123}`) and acts on the boolean answer.

Strengths: policy reviewable/testable in isolation; policy changes don't require app
redeployment; cross-service consistency; audit trail. Tradeoffs: latency tax (OPA-sidecar
mitigates), operational burden, schema-evolution coordination across PDP and PEPs.

### Zanzibar-style relationship tuples

For applications where authorization questions are fundamentally relationship questions
(group-membership, project-membership, ownership transitivity), the ReBAC model in §5 is the
structural answer. SpiceDB, OpenFGA, Permify, Authzed Cloud. Pattern: every fact a tuple,
every check a graph query, consistency per-request configurable via ZedTokens.

### Capability-bearing tokens, resource-scoped policies, audit

**Capability tokens** (macaroons, JWT-with-fine-grained-claims, sigstore attestations) are
the opposite of ambient authority — every action requires a token that explicitly grants
the capability. No ambient authority means no confused-deputy by construction; delegation is
explicit (mint a derived macaroon); revocation is structural (rotate issuing key). Tradeoff:
token size grows with capability count, bearer-compromise grants capability.

**Resource-scoped policies** express every decision as `(actor, action, resource)`, not
`(actor, action)`. If the policy function literally cannot be called without a resource,
BOLA cannot happen by omission.

**Audit every authorization decision**: every prod AuthZ check emits an
event with actor, action, resource, decision, policy-rule. This is forensic ground truth
and the feedstock for anomaly detection. Audit logs must be off-cluster, append-only,
immutable (cross-link `container_k8s_security.md` §8).

### TOCTOU-safe authorization

Three structural defenses, in order of strength:

1. **Re-check at write time.** The decorator is advisory; the write path re-validates
   ownership before persisting.
2. **Resolve, don't trust.** Every ID the body uses goes through `resolve(actor, id)` that
   returns the resource only if it's in actor scope, `None` otherwise. The body operates on
   the resolved resource.
3. **Pass the resource, not the ID.** The decorator looks up the resource and passes it to
   the body. The body cannot operate on a different resource because it doesn't have a
   different ID to dereference.

### Forbid-by-default middleware

The middleware chain has a final terminal handler that returns 403 for any request not
explicitly authorized by a prior handler. Django: a `RequireExplicitAuthorization`
middleware checks for a marker attribute on the resolved view (set by `@requires_auth` /
`@requires_perm` decorators); absence → 403. Spring:
`HttpSecurity.authorizeHttpRequests(authz -> authz.anyRequest().denyAll())` as the default,
with explicit `permitAll`/`authenticated`/`hasRole` per pattern.

### Code review checklist (15 items)

When reviewing a service's AuthZ posture:

1. Every handler has an explicit authentication check (decorator, middleware, framework
   policy). No handler is "accidentally public."
2. Every handler that takes a resource ID does an ownership check on that resource,
   either via scoped query or explicit check.
3. Every handler that takes a tenant ID either ignores the request value and uses the
   token's tenant claim, or validates the request value matches the token.
4. Role comparisons are typed (enum, set membership), not string equality.
5. Authorization decorators and handler bodies operate on the same source for resource
   IDs.
6. Multi-step operations don't drop authorization state between steps.
7. Authentication tokens are short-lived; refresh-token rotation is implemented with
   replay detection.
8. Federation trust is pinned to (IdP, subject) pairs, not (email).
9. JWT verification configuration is pinned to specific algorithms; `alg:none` and
   HS/RS confusion are blocked.
10. SAML signature verification uses canonicalization that matches the signer's
    canonicalization.
11. The redirect_uri allowlist for OAuth is exact-match, not substring / wildcard /
    path-prefix.
12. CSRF tokens (`state`) are mandatory on authorization endpoints.
13. PKCE is required for all OAuth public clients; the server doesn't downgrade.
14. Authorization decisions are logged with actor + action + resource + decision +
    policy-rule.
15. The authentication / authorization configuration is reviewed when the service
    surface changes, not only at initial design time.

---

## 10. Variant Analysis — Under-Explored

The patterns above cover the majority of the public corpus. The following areas have less
mature defensive guidance and are where staff-level research has the highest leverage.

### AuthZ in gRPC streaming and WebSocket

Both protocols establish a long-lived connection with authentication at connection-open and
no per-message authentication primitive. Bug pattern: the authorization decision at
open-time is for the stream's purpose, not for each individual message. A gRPC stream
opened for "user X's notifications" can be coerced mid-stream to fetch user Y's
notifications if the per-message handler trusts the connection-level identity. A
WebSocket-upgrade request authorizes the connection; subsequent frames bypass HTTP-layer
middleware entirely.

Defense: per-message authorization with the stream-level identity bound by the server (not
the client) into each message; or the connection-level identity is strictly scoped to a
single resource (the connection is "read-only on stream X"; any other operation requires a
new connection).

### AuthZ in event-driven architectures and CDC pipelines

Kafka, NATS, AWS SNS/SQS, Pub/Sub: publisher and consumer have separate authorization
contexts. Per-topic ACLs are often not configured granularly; a service authorized to
publish to T1 can also publish to T2 if the ACL is cluster-wide. The deeper pattern: Kafka
message payloads often carry user identity ("user X did Y"); consumers acting on that
identity must verify the claim is signed by the producing service, or any producer with
topic-write access can impersonate any user.

CDC (Debezium, Maxwell, AWS DMS) reads the WAL with `REPLICATION` role — intrinsically
cross-tenant, bypassing application-layer RLS. Row events for tenant A end up on Kafka
topics that consumers subscribe to without tenant filtering. Defense: re-apply tenant
scoping at the consumer / sink level; the WAL is cross-tenant by design.

### AuthZ in GraphQL resolvers

GraphQL exposes a typed graph. AuthZ in REST is per-endpoint; in GraphQL it's per-field,
because a single query can traverse many fields across many types. Bug pattern: an AuthZ
check at the operation level but not at the field level. `{ user(id: "me") { friends {
email } } }` checks that the caller can see their own user, then recursively returns
friends' fields without checking per-field permissions.

Defense: field-level resolvers each call the PDP with the specific (actor, action,
resource) tuple. GraphQL Shield and SpiceDB's
relationship-tuple model support this. Every resolver declares its authorization
requirement; resolvers without an explicit declaration are denied by default.

### AuthZ for AI/agent contexts and vector databases

The new failure surface: an AI agent acts on behalf of a user but holds its own service
identity. The structural defense is **tool-calling under delegated authority by default**:
the user's identity is bound to every tool call; the agent's identity is reserved for
agent-internal operations (memory writes, planning state) and treated as a low-privilege
service identity. Prompt-injection-induced privilege escalation is the dominant failure
mode — if a tool runs under the agent's identity, the agent's identity defines the blast
radius. Cross-link `expertise/software/llm_agent_security_expertise.md`.

**Vector databases** (Pinecone, Weaviate, Milvus, Chroma) support per-namespace indices but
allow cross-namespace search if the namespace is parameterized. "Client-controlled
namespace" is the ClientControlledTenant anti-pattern translated to vector search. Defense:
namespace binding from the authenticated principal; metadata filters on every query
restricting to the caller's tenant.

---

## 11. References

### Kurt Boberg CVEs

- CVE-2020-13957 (Apache Solr): https://github.com/advisories/GHSA-3c7p-vv5r-cmr5
- CVE-2022-1245 (Keycloak): https://github.com/advisories/GHSA-75p6-52g3-rqc8
- CVE-2022-1332 (Mattermost): https://github.com/advisories/GHSA-qggc-pj29-j27m
- CVE-2022-3294 (Kubernetes): https://github.com/advisories/GHSA-jh36-q97c-9928
- CVE-2022-24901 (parse-server): https://github.com/advisories/GHSA-qf8x-vqjv-92gr

### Zanzibar / ReBAC

- Pang et al., "Zanzibar: Google's Consistent, Global Authorization System," USENIX ATC
  2019: https://www.usenix.org/conference/atc19/presentation/pang
- Authzed SpiceDB: https://authzed.com/spicedb
- AuthZed's annotated Zanzibar paper: https://authzed.com/zanzibar
- OpenFGA (Auth0/Okta): https://github.com/openfga/openfga
- Permify: https://github.com/Permify/permify

### Open Policy Agent

- OPA project: https://www.openpolicyagent.org/
- OPA documentation: https://www.openpolicyagent.org/docs/latest/

### OAuth / OIDC

- RFC 9700 — Best Current Practice for OAuth 2.0 Security: https://datatracker.ietf.org/doc/rfc9700/
- RFC 6749 — OAuth 2.0 Authorization Framework: https://datatracker.ietf.org/doc/html/rfc6749
- RFC 6819 — OAuth 2.0 Threat Model and Security Considerations: https://datatracker.ietf.org/doc/html/rfc6819
- RFC 7636 — PKCE: https://datatracker.ietf.org/doc/html/rfc7636
- RFC 8693 — OAuth 2.0 Token Exchange: https://datatracker.ietf.org/doc/html/rfc8693
- OpenID Connect Core 1.0: https://openid.net/specs/openid-connect-core-1_0.html

### OWASP

- OWASP API Security Top 10 (2023): https://owasp.org/API-Security/editions/2023/en/0x00-header/
- OWASP API1:2023 BOLA: https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/
- OWASP API3:2023 BOPLA: https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/
- OWASP API5:2023 BFLA: https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/
- OWASP Juice Shop: https://owasp.org/www-project-juice-shop/

### CWE Definitions

- CWE-287 Improper Authentication: https://cwe.mitre.org/data/definitions/287.html
- CWE-306 Missing Authentication for Critical Function: https://cwe.mitre.org/data/definitions/306.html
- CWE-308 Use of Single-factor Authentication: https://cwe.mitre.org/data/definitions/308.html
- CWE-862 Missing Authorization: https://cwe.mitre.org/data/definitions/862.html
- CWE-863 Incorrect Authorization: https://cwe.mitre.org/data/definitions/863.html
- CWE-1390 Weak Authentication: https://cwe.mitre.org/data/definitions/1390.html

### Related documents

- `software/methodology/code_review_expertise.md` — candidate-point auditing,
  auth-homogeneity heuristic, click-count severity
- `software/crypto-trust/cryptography_expertise.md` — JWT algorithm confusion, SAML
  signature wrapping, TLS/mTLS substrate
- `software/cloud-containers/container_k8s_security.md` — K8s RBAC permission graphs,
  nodes/proxy as cluster-admin, kubelet API bypass
- `software/appsec-web/http_web_security.md` — HTTP auth headers, cookie scoping,
  CSRF, session management
- `software/ai-ml-security/llm_agent_security_expertise.md` — agent identity, delegated
  tool calls, prompt-injection blast radius

---

## 12. Summary: What Defines Staff-Level Distributed AuthZ

1. **AuthN, AuthZ, and identity binding are three distinct steps.** Conflating them is the
   root cause of most failure modes; triage must disambiguate before any defense is
   meaningful.

2. **The trust topology has at least five layers** (edge, mesh, sidecar, application,
   database). Defense-in-depth on AuthZ specifically means re-checking at every layer that
   has the data; trusting upstream for resource-level decisions is always wrong.

3. **BOLA is the dominant API-AuthZ bug.** Every handler that takes a resource ID and
   doesn't scope the query through the authenticated principal is a candidate. The
   data-layer-scoped pattern (`request.user.orders.get(id=...)`) is the structural defense
   and the detection invariant.

4. **Role-string-compare is the dominant CWE-863 pattern.** Type the role identifier; use
   enum/set membership, not string equality. Every project-grown RBAC system accumulates
   these footguns.

5. **Client-controlled tenant ID is the dominant tenant-isolation failure.** Tenant binding
   from authenticated principal, never request payload. The token's tenant claim is the
   only trustworthy tenant source.

6. **OAuth has a canonical threat model (RFC 9700).** Exact-string `redirect_uri` match,
   mandatory PKCE, refresh-token rotation with replay detection, `state`/`nonce` on every
   authorization flow. Implementations that relax any of these are inherently exploitable.

7. **Zanzibar-style ReBAC is becoming dominant for fine-grained authorization.**
   Relationship tuples, userset rewrites, configurable consistency via ZedTokens. For
   applications where authorization questions are relationship questions, this is the
   structural answer.

8. **A static-analysis authz-detection workflow is the applied form of this expertise.**
   Per-CWE detection prompts across the four CWE buckets (308, 306, 862, 863) encode the
   cardinal rules from this document. Severity is computed deterministically from
   LLM-emitted typed flags, not from LLM-emitted severity words — the canonical "let the
   LLM reason, let the code score" discipline.

9. **Federation trust must be anchored server-side.** IdP discovery endpoint, signing key
   URL, issuer identifier — all from server-side allowlist, never request payload.
   CVE-2022-24901 (parse-server / Apple Game Center) is the reference.

10. **Capability composition in custom RBAC is a security boundary.** Custom admin roles
    that combine permissions must either enumerate the combinations or impose a closure
    rule. CVE-2022-1332 (Mattermost) is the reference.

11. **Token-exchange is an authorization decision.** OAuth token exchange, SAML attribute
    mapping, JWT cross-trust — any redemption needs explicit authorization, not just
    requester authentication. CVE-2022-1245 (Keycloak) is the reference.

12. **Missing-AuthN on admin endpoints is the highest-severity, lowest-complexity failure
    mode.** CVE-2020-13957 (Solr ConfigSet) is the reference. Every administrative
    operation has an explicit check at the operation level, not endpoint-level middleware
    that may not match.

13. **Path-based authorization bypasses in reverse proxies are systemic.** Validation
    against mutable data is not validation. CVE-2022-3294 (Kubernetes node proxy) is the
    reference.

14. **Variant analysis** — gRPC streaming, WebSocket, event-driven, CDC, GraphQL, AI
    agents, and vector databases all instantiate the same long-lived-identity vs.
    per-message-authorization pattern. These are the next frontiers.

15. **Detection discipline = defensive discipline.** Every pattern in §9 maps to a
    detection signal in §8. Defensive and offensive code review are the same activity from
    different chairs (`steelman_doctrine_expertise.md`).
