# GraphQL and API Security — Primitives, Authorization, and Defenses
## Synthesized from the OWASP API Security Top 10, the GraphQL attack-surface literature, and operator practice at Chegg / Semgrep

> **Primary researchers, working groups, and operators:**
>
> - **Dolev Farhi** — Distinguished Security Engineer at Palo Alto Networks; co-author
>   of *Black Hat GraphQL: Attacking Next Generation APIs* (No Starch Press, 2023, ISBN
>   978-1-7185-0284-0) with Nick Aleks; author of the companion vulnerable-target lab
>   `dvga` (Damn Vulnerable GraphQL Application) and the `graphql-cop` and `graphw00f`
>   reconnaissance tools. Farhi's body of work is the canonical practitioner reference for
>   offensive GraphQL: schema enumeration via introspection, alias-batching DoS,
>   field-suggestion fingerprinting, persisted-query bypass, and resolver-layer injection.
> - **Nick Aleks** — Senior Director of Security at Wealthsimple; founder of ASEC.IO;
>   co-author of *Black Hat GraphQL* (2023). His half of the book covers the
>   application-architecture side: schema design under attack, persisted-query gateways, and
>   field-level authorization patterns.
> - **Paulo Silva, Erez Yalon, Inon Shkedy** — co-leads of the OWASP API Security Top 10
>   2023 (Silva is project lead; Yalon is VP of Security Research at Checkmarx and founder
>   of DEF CON AppSec Village; Shkedy is Head of Security Research at Traceable). The 2023
>   edition canonicalized the **BOLA / BFLA / BOPLA** taxonomy, which is now the dominant
>   API-AuthZ bug vocabulary in product-security triage.
> - **Aleksei Tiurin** — Senior Security Researcher at Acunetix / Invicti since 2018. Long
>   author byline on Acunetix's web-security blog covering cache-poisoning DoS, reverse-proxy
>   attacks, SSTI in Thymeleaf, and JS deserialization.
> - **Frans Rosén** — Security advisor at Detectify; one of the highest-paid HackerOne
>   bounty hunters of the 2017–2022 era. Canonical writeups: "Hacking Slack using
>   postMessage and WebSocket-reconnect to steal your precious token" (2017), "postMessage
>   XSS on a million sites," "Account hijacking using 'dirty dancing' in sign-in OAuth-flows."
>   His writeups establish that API-layer bugs compose with browser-layer bugs into full
>   account takeover.
> - **James Kettle, Gareth Heyes, Martin Doyhenard** (PortSwigger) — Director of Research
>   and collaborators behind the Web Security Academy GraphQL labs. Their contribution is
>   the systematic methodology for finding GraphQL endpoints (via `__schema`,
>   suggested-field error oracles, alias-batching detection) and the broader HTTP-layer
>   primitives (request smuggling, cache poisoning, CORS abuse) that compose with
>   GraphQL-specific bugs. See `knowledge-base/appsec-web/http_web_security.md`.
> - **Kurt Boberg (`kurt-r2c`)** — Staff Security Researcher at Semgrep; previously AppSec
>   at DocuSign and Chegg. The Chegg work is the load-bearing operator credential for this
>   document. Per the tl;dr sec staff-engineer interview with Clint Gibler:
>
>   > "I got a ~400 person engineering organization to adopt a 'batteries included'
>   > authorization scheme for GraphQL. Authorization is not part of the original
>   > specification and missing or broken access control is a recurring problem with many
>   > early adopters of GraphQL. The target organization had a collection of services
>   > notorious for broken access control. I strongly advocated for authorization
>   > considerations early in the design process which lead to a launch with basically zero
>   > authorization issues." — *tl;dr sec, "Kurt Boberg - Staff Security Researcher at r2c"*
>
>   Publicly credited (with yoshmidev) on CVE-2022-24901 (parse-server). See
>   `knowledge-base/appsec-web/distributed_authz_expertise.md` for per-CVE writeups.
>
> Sources: OWASP API Security Top 10 2023; *Black Hat GraphQL* (No Starch, 2023); Apollo
> GraphQL documentation; GraphQL specification (graphql.org); PortSwigger Web Security
> Academy GraphQL labs; Detectify Labs writeups; Acunetix Web Security Zone (Tiurin's
> author archive); Checkmarx blog on GraphQL batching attacks; tl;dr sec interview with
> Kurt Boberg.

---

## 1. GraphQL's structural attack surface

### What makes GraphQL different from REST

GraphQL was published by Facebook in 2015 and standardized by the GraphQL Foundation in
2018. The single design decision that drives most of its security surface is that **the
client specifies the shape of the response**. A REST endpoint at `GET /users/123` returns
whatever the server defines. A GraphQL endpoint at `POST /graphql` accepts a query document
that names fields, traverses relationships, possibly aliasing the same field multiple times
with different arguments.

This shifts several invariants REST defenses assume:

- **One endpoint, many operations.** WAF rules, rate limiters, and audit log analyzers that
  key on `(method, path)` see every GraphQL request as the same operation. Operation name,
  fields touched, and arguments are all in the body. Defenses that don't parse the body see
  noise.
- **The schema is the API.** REST publishes its surface through routes; GraphQL publishes
  through the schema, which the server itself hands to anyone who asks via `__schema`.
  Introspection is by-spec, not an accident.
- **The client controls cost.** A single document can request hundreds of fields, follow
  relationship chains to arbitrary depth, and use aliases to multiply identical expensive
  fields. Every server-side cost-control mechanism is opt-in.
- **Authorization is not in the spec.** The load-bearing observation in Kurt's tl;dr sec
  interview: missing or broken access control is the recurring failure mode in early
  adopters because the spec gives a query language and a type system but says nothing
  about who can resolve a field with a given argument. Every working deployment grows its
  own authorization layer.

### Introspection as the first-stage recon primitive

The introspection query is the canonical reconnaissance starting point. The spec-defined
query:

```graphql
query FullSchema {
  __schema {
    types { name kind fields { name args { name type { name } } type { name } } }
    queryType { name }
    mutationType { name }
  }
}
```

returns the entire schema in one request. Most servers ship with introspection enabled by
default; Apollo Server's official guidance is to disable it in production via
`introspection: false` gated on `NODE_ENV`. Even with introspection disabled, fallbacks
exist:

- **Field-suggestion error oracles.** Most servers (Apollo, graphql-java, HotChocolate)
  emit `Did you mean "..."` for misspelled fields, revealing the closest valid field by
  Levenshtein distance. `graphql-cop` and `graphw00f` automate iterative rebuild.
- **Tooling fingerprints.** `graphw00f` matches behavior to 37 frameworks by observing how
  each handles malformed queries, alias depth, and reserved characters. Knowing the
  framework narrows exploit surface — different alias-cap defaults, cost models, unauth
  introspection posture.
- **Documentation leakage.** Public-facing playgrounds (`/graphql-playground`, `/graphiql`,
  Apollo Studio Sandbox) often run on the same host and leak schema through their own UI.

### The single-endpoint trust-model failure

REST puts each operation at a separate route; per-route middleware fans out naturally.
GraphQL puts everything at one route; per-resolver fan-out is the developer's
responsibility. Three failure modes follow:

1. **Middleware on `POST /graphql` is a no-op for authorization.** Authentication runs once
   per request regardless of fields resolved or mutations fired. Permission to read `User`
   must run on every resolver that returns a `User`.
2. **Endpoint rate-limiting is meaningless.** A single request can trigger thousands of
   resolver calls. 100 req/min on `POST /graphql` does not bound database load.
3. **Path-matching WAF rules see every payload as identical.** Schema-aware WAFs (Apollo
   Router, Hasura, AWS AppSync) handle this; generic CDN WAFs do not.

### Aliases as IDOR amplifier

GraphQL aliases let the same field appear multiple times in one document with different
arguments:

```graphql
query EnumerateUsers {
  u1: user(id: "1") { email phoneNumber salary }
  u2: user(id: "2") { email phoneNumber salary }
  u3: user(id: "3") { email phoneNumber salary }
}
```

If `user(id:)` lacks BOLA enforcement, one request returns N users' PII. The HTTP-layer
rate limiter sees one request; the audit log sees one query; the database sees N queries.
The same primitive amplifies authentication: `login(email:, password:)` called under 1,000
aliases in one request is a credential-stuffing amplifier that bypasses per-request rate
limits. Checkmarx's "Didn't Notice Your Rate Limiting" walks through the OTP brute-force
variant.

### Variable-quote evasion in WAFs

The same query expressed three ways — inline literal, inline string, variable-extracted —
moves the payload from query string to variables JSON. A WAF rule grepping for
`transferFunds.*victim` catches inline forms but not the variable form where the query
references `$t` and `t` lives in `variables`. Schema-aware defenses substitute variables
before matching; generic WAFs don't.

### Mutation vs Query: auth distinction often unenforced

The spec says mutations are sequenced and queries are parallelizable. It does not say
mutations require authentication and queries don't — that's developer convention. A
resolver called from both `Query.user` and `Mutation.updateUser` duplicates the check; a
schema refactor adding `Subscription.userUpdates` forgets it. Treat operation type as a
hint, not as a permission.

---

## 2. BOLA / IDOR in GraphQL

### The canonical failure: resolver lacks actor↔resource binding

OWASP API1:2023. A resolver accepts a resource identifier as an argument and returns the
resource without verifying the authenticated principal can access *that specific instance*:

```javascript
// Vulnerable resolver — auth-as-AuthZ
const resolvers = {
  Query: {
    order: async (parent, { id }, context) => {
      if (!context.user) throw new AuthenticationError("Login required");
      return Order.findById(id);   // BOLA: any logged-in user reads any order
    }
  }
};
```

The check verifies authentication and confuses it with authorization. The detection
invariant — codified as a `MissingAuthz` (CWE-862) / `IncorrectAuthz` (CWE-863)
static-analysis detection pattern — is the absence of a query path from `args.id` to a
scoping clause through the authenticated principal. The structural fix is data-layer
scoping:

```javascript
// Safe — tenant and ownership bound at the query layer
return Order.findOne({ _id: id, userId: context.user.id });
```

Same pattern as `knowledge-base/appsec-web/distributed_authz_expertise.md` §4: instead of
"fetch X, then check X.owner == user," the lookup is "fetch X where X.owner == user." Null
result means null response — no oracle distinguishes "doesn't exist" from "exists but
forbidden."

### Kurt's "batteries-included authorization scheme" at Chegg

From the tl;dr sec interview:

> "I got a ~400 person engineering organization to adopt a 'batteries included'
> authorization scheme for GraphQL. Authorization is not part of the original specification
> and missing or broken access control is a recurring problem with many early adopters of
> GraphQL. The target organization had a collection of services notorious for broken access
> control. I strongly advocated for authorization considerations early in the design
> process which lead to a launch with basically zero authorization issues."

The interview doesn't publish implementation details; the design shape can be inferred from
constraints and contemporaneous patterns. What the framing tells us:

- **"Batteries included" means default-safe.** A developer who writes a new resolver gets
  an authz check whether they remembered to ask or not. The cheap implementation: a
  middleware layer or resolver decorator that wraps every resolver and applies a default-deny
  policy.
- **"Adopt at 400-person scale" means it survives 400 developers' judgment.** The check
  cannot be optional or opt-in per-resolver. It cannot require remembering the right
  helper. Install once at schema-construction; apply everywhere.
- **"Notorious for broken access control" means the prior baseline failed empirically.**
  Per-resolver-its-own-check had failed. The fix had to remove per-resolver cognitive
  burden, not add to it.
- **"Launch with basically zero authorization issues" means the design held under
  testing.** The launch criterion was a finding-rate floor, not a feature checkbox.

Three architectural patterns match these constraints (all documented by 2018–2020):

1. **Schema-level middleware intercepting every resolver.** Built with `makeExecutableSchema`
   from `graphql-tools` or Apollo Server plugins; a visitor wraps every field in every type
   with an authz check before delegating to the original resolver. `graphql-shield`
   implements this declaratively.
2. **Directive-based authorization.** Fields annotated with `@requireRole(role: "admin")`
   or `@requirePermission(...)`; a schema visitor at construction wraps every annotated
   resolver. Hasura and PostGraphile use a variant driven by row-level security rather than
   directives.
3. **DataLoader-bound principal context.** Resolvers fetch through DataLoaders constructed
   once per request with principal identity baked in; the batch function applies tenant
   scoping unconditionally. Developers can't bypass because there's no other way to fetch
   data — the raw model isn't exported.

Kurt's framing most naturally maps to option 1 or a 1+3 hybrid: dev writes resolver,
framework wraps it, wrapper runs authz check sourced from parent type and principal
session, data layer's loaders are pre-scoped. The interview's lesson is structural rather
than implementation-specific: **the authz boundary belongs at schema construction, not in
each resolver's body**.

### The cardinality problem at 400-person scale

A schema with 100 types × 8 fields = 800 fields, each a potential authz decision point. At
~50 → ~400 engineers in 18 months, per-resolver checks become structurally unmaintainable:

- No central audit point; reviewers can't examine 800 places.
- Code review can't enforce consistency; teams write checks differently.
- New resolvers default to broken; default-broken at scale means broken in practice.

Schema-level middleware inverts the default: new resolvers are wrapped automatically; the
developer must actively opt out (which becomes a code-review red flag), not actively opt in.

### The DataLoader + auth-check + caching tension

GraphQL servers commonly use DataLoader to coalesce N+1 queries. Authz interacts with three
loader properties:

- **Batching:** if the authz check is per-ID, the batch function applies it per-ID inside
  the batch.
- **Caching:** within one request, `id -> object` is cached. But two fields under different
  parent types loading `User(42)` may have different authz requirements
  (`Order.customer` vs `AdminPanel.userList`).
- **Cross-request leakage:** module-level loader (instead of per-request) leaks
  authz-passed objects between users — a GraphQL+DataLoader-specific cross-tenant bug.

Defensive rule: **DataLoader instances live in `context`, constructed per-request, with
principal identity baked into the closure**. Loaders never become module-level singletons.
Authz checks live one layer up so the loader stays a pure data-fetching primitive.

### Field-level BFLA: object readable, field on it isn't

OWASP API3:2023 — BOPLA. Reading `User` is fine; reading `User.salary` should be gated.
GraphQL makes this observable through aliases:

```graphql
query SalaryEnum {
  u1: user(id: "1") { salary }
  u2: user(id: "2") { salary }
}
```

If `User.salary` lacks its own check (caller is user, manager, or HR admin), the query
reveals everyone's salary. Fix: per-field resolvers, not default field projection from the
parent. Schema-construction-time middleware that wraps every field applies the check at the
right level; bespoke per-resolver code commonly forgets.

Cross-link `distributed_authz_expertise.md` §4 for the distributed-systems BOLA / BFLA /
BOPLA framing.

---

## 3. Authorization patterns at scale

### Pattern A: per-resolver imperative check (the don't-do-this baseline)

Every resolver opens with `if (!can(context.user, "read", parent))` then fetches. Works for
10 resolvers; fails at 100+ for the cardinality reasons in §2. The pattern Kurt's Chegg
work explicitly replaced.

### Pattern B: directive-based declarative authorization

Fields annotated in SDL:

```graphql
type User {
  email: String! @auth(requires: [SELF, ADMIN])
  salary: Int @auth(requires: [SELF, MANAGER, HR_ADMIN])
}
type Mutation {
  deleteUser(id: ID!): Boolean @auth(requires: [ADMIN])
}
```

Schema visitor at construction wraps every annotated resolver. Apollo Server supports this
via `SchemaDirectiveVisitor` (v2; built-in support removed in v3 in favor of `mapSchema` from
`@graphql-tools/utils`). Declarative form is auditable — grep `@auth` and see protected
fields. Risk: **silent permissive default** — fields without `@auth` are unprotected.

Defenses:

- **Default-deny visitor** wraps every resolver; unannotated fields get an explicit
  "fail-closed" wrapper.
- **CI lint** blocking unannotated fields on PRs that add to `type Query`/`type Mutation`.
- **Schema diff in CI** (`graphql-inspector`, Apollo `rover graph check`) flags unannotated
  fields as breaking changes.

### Pattern C: graphql-shield (rules-as-code)

`graphql-shield` implements an authz middleware with composable rule functions:

```javascript
const isAuthenticated = rule()((p, a, ctx) => !!ctx.user);
const isOrderOwner = rule()(async (p, a, ctx) => {
  const o = await Order.findById(p?.id || a.id);
  return o?.userId === ctx.user.id;
});

const permissions = shield({
  Query: {
    "*": isAuthenticated,
    order: and(isAuthenticated, or(isOrderOwner, isAdmin)),
  },
  Mutation: { "*": isAuthenticated, deleteUser: and(isAuthenticated, isAdmin) }
}, { fallbackRule: deny, fallbackError: "Not authorized." });
```

`Query: { "*": isAuthenticated }` is the "batteries included" floor; `fallbackRule: deny`
ensures missing rules fail closed. Risks: rule composition gets baroque; rules that issue
extra DB queries multiply load; per-request caching can produce wrong answers when rule
inputs change mid-request.

### Pattern D: Hasura / PostGraphile / row-level security

Database-to-GraphQL bridges push authz into the database. GraphQL translates queries to
SQL; SQL executes with the session's role; database enforces RLS:

```sql
CREATE POLICY order_owner_read ON orders FOR SELECT
  USING (user_id = current_setting('app.current_user_id')::uuid);
```

The GraphQL server sets `app.current_user_id` per request. Footguns:

- **`current_setting` is per-session, not per-statement.** Pooled connections that forget
  to reset between requests serve under the wrong principal. Fix: pgbouncer in transaction
  pooling mode plus `SET LOCAL`.
- **Admin paths bypass RLS.** `SUPERUSER` connections or `BYPASSRLS` roles (analytics,
  migrations, admin tools) are unconstrained. The BYPASSRLS catalog is the catalog of
  who can leak data.
- **Performance.** Policies become `WHERE` clauses on every query. Indexes that don't
  include policy filter columns produce sequential scans.

### Pattern E: persisted-query allowlist (deny-everything-not-allowed)

Apollo's GraphOS persisted queries: clients pre-register operations at build time; the
production runtime accepts only hashed references. Apollo markets it explicitly as a
security feature.

1. Build pipeline extracts every operation; uploads to the persisted-query list (PQL) with
   SHA-256 hash.
2. Client sends `{ extensions: { persistedQuery: { sha256Hash: "..." } } }`.
3. Server in safelist mode looks up the hash; executes if found; rejects
   `PERSISTED_QUERY_NOT_IN_LIST` if not — no fallback to arbitrary queries.

This is the strongest discoverability hardening: attacker without build-pipeline access
cannot run arbitrary queries. Introspection moot. Alias batching moot (every operation is
platform-approved). Field-suggestion oracle moot.

Tradeoffs: doesn't work for third-party API consumers (Shopify, GitHub Public API);
requires build-pipeline integration; mobile apps need migration plans for in-flight client
versions; variables are still attacker-controlled (BOLA via variable manipulation
unchanged).

### Pattern F: Kurt's Chegg shape (informed inference)

Combining §2 constraints with the patterns above, the most likely shape:

1. **Schema-construction-time middleware wrapping every resolver.** Custom visitor or
   `graphql-shield` with `fallbackRule: deny`. New resolvers inherit a default-deny floor.
2. **Central policy registry listing every (type, field, action) tuple and the rule.**
   Adding a resolver without a policy entry is a CI-blocking error. The policy file is the
   auditable authz surface.
3. **DataLoader instances per-request with principal baked in.** No direct model access;
   loaders enforce tenant scope by construction.
4. **Persisted queries on top, eventually.** Second-stage hardening once resolver-layer is
   solid.

Kurt's emphasis is that the **early-design-phase advocacy** is load-bearing. Retrofitting
authz onto a schema where every resolver was written without it is a one-by-one audit of
every field. Building with the wrapper from the start means team velocity points at adding
features instead of plugging gaps.

---

## 4. Query complexity attacks (the DoS class)

### Deeply nested queries

Schemas with bidirectional relationships admit arbitrary depth:

```graphql
query Deep {
  user(id: "1") { friends { friends { friends { friends { id } } } } }
}
```

100 friends/user × 8 levels = `10^16` relationships. Even with short-circuiting, request
parsing and validation are server-side work. The DoS is structural.

Defenses, cheap to expensive:

- **Maximum depth limit.** `graphql-depth-limit` (npm), Apollo Server's `validationRules`,
  graphql-java's `MaxQueryDepthInstrumentation`. Reasonable: 8–12 for consumer apps, 15–20
  for admin tools.
- **Query complexity / cost analysis.** Each field assigned a static or dynamic cost;
  document total walked and capped. `graphql-query-complexity` (npm), Hasura's analyzer,
  GitHub's published v4 cost model.
- **Operation-count caps within one request.** Require `operationName` when multiple named
  operations exist; cap to 1 per request.
- **Persisted queries.** Make deep-nesting moot — only platform-approved operations run.

### Aliases as alias-DoS amplifier

```graphql
query Amplify {
  a1: expensiveField(arg: "x") { ... }
  a2: expensiveField(arg: "x") { ... }
  # ... up to N (often 10,000+)
}
```

Each alias triggers an independent resolver call. Invicti's `GraphQL Alias Overloading
Allowed` detection flags this. Defense: alias-count cap (graphql-armor
defaults to 15); field-count cap; cost analysis counting each alias separately.

### Fragment recursion (where allowed)

The spec forbids fragment-spread cycles, direct or indirect. Mutual recursion through indirection
(`A → B → A`) is a known weakness in some implementations. Defense: current parser version plus depth limit.

### Field-name suggestion as side-channel DoS

`Did you mean ...` computes Levenshtein distance against every schema field. For 1000-field
schemas and long misspelled names, computation is O(schema × len(query)). Repeated long
random probes amplify load. graphql-armor's "block-field-suggestions" plugin disables suggestions
in production both as a recon-oracle close (§6) and to remove this side-channel.

Cross-link `redos_algorithmic_dos_expertise.md` §7 for the broader algorithmic-DoS framing.

---

## 5. Injection in resolver paths

GraphQL is "just a transport." Every classical injection class — SQLi, NoSQLi, OS command,
path traversal, SSRF, template injection, LDAP, XPath — applies to a resolver that
concatenates an argument into a backend query.

### SQL injection

```javascript
const resolvers = {
  Query: {
    productsByCategory: (p, { category }) =>
      db.query(`SELECT * FROM products WHERE category = '${category}'`)
  }
};
```

`String!` constrains to non-null string; `'; DROP TABLE products; --` is still a valid
string. Fix: parameterized queries, identical to REST. Detection: pattern-match on string
concatenation into query functions; SQL-injection detection rules apply to resolver bodies
the same way as Express handlers.

### NoSQL injection (Mongo operator injection)

```javascript
// Vulnerable — filter is JSON, parsed straight into Mongo
const resolvers = { Query: { user: (p, { filter }) => User.findOne(filter) } };
// Attacker: { filter: { username: "admin", password: { "$ne": null } } }
```

If the schema accepts a `JSON` scalar and the resolver passes it through, attacker
controls operator selection. Fix: constrain to primitive scalars; structured filters as
typed `FilterInput` with named fields and operators.

### Path injection

```javascript
const resolvers = {
  Query: { document: (p, { id }) => fs.readFile(`/documents/${id}.pdf`) }
};
// Attacker: id = "../../../../etc/passwd "
```

Cross-link `code_review_expertise.md` §5 for the canonical "resolve AND verify" recipe.

### Template injection in resolvers

Resolvers that compile user-supplied strings as templates (Handlebars, Jinja2 via Python
resolvers, FreeMarker via Java resolvers) inherit full SSTI surface. Cross-link
`template_code_injection_expertise.md`.

### SSRF in resolver paths

Resolvers that fetch user-supplied URLs (webhook registration, URL preview, image-by-URL,
OAuth-callback) inherit full SSRF surface. The variable-quoting issue from §1 makes
detection harder for path-based WAFs. Cross-link `ssrf_url_parsing_expertise.md`.

### The framing

Every injection rule that targets REST handlers should be ported to match resolver shapes
(`(parent, args, context, info) => ...`). Authz-focused detection workflows and
injection-focused detection workflows are typically separate lanes; both should expand to
cover resolver bodies as first-class targets.

---

## 6. Introspection and schema-leakage attacks

### `__schema` as recon oracle

Covered in §1; restating in threat-model framing: in production, **introspection is a
recon oracle equivalent to publishing API documentation to attackers**. Cost-benefit for
keeping it on:

- *Benefit:* dev tooling (Playground, Apollo Studio, GraphiQL) works without schema upload.
- *Cost:* attackers enumerate every type, field, argument, return type, plus every
  internal-only mutation added "just for the admin panel."

For non-public APIs, default off in production. Apollo's documentation makes this explicit.
Environment-variable gating preserves local DX:

```javascript
new ApolloServer({
  typeDefs, resolvers,
  introspection: process.env.NODE_ENV !== "production",
});
```

Equivalent in graphql-java (`Instrumentation`), HotChocolate (`AllowIntrospection(false)`),
Sangria, gqlgen. Disabling introspection is necessary but not sufficient — the
field-suggestion oracle still leaks types. Combine with graphql-armor's `block-field-suggestions`
plugin.

### Schema diffing as CI gate

Schema changes are observable via introspection or field-suggestion oracle. New mutation
behind a feature flag is discoverable when it appears in the schema. Defensive practice:
schema-as-code in version control plus `graphql-inspector` or Apollo `rover graph check` in
CI. Diffs adding fields are reviewed for authz coverage before merging. CI catches "new
field without `@auth` annotation" and "new mutation without persisted-query list entry."

### Errors leak schema

```json
{ "errors": [{ "message": "Cannot query field 'salary' on type 'User'. Did you mean 'salaryBand'?",
  "extensions": { "stacktrace": ["at User.resolveType (...)", "..."] } }] }
```

Reveals: type `User` has `salaryBand`; validation codepath; potentially file paths via
stack trace. Production hardening: strip stack traces (Apollo `formatError`), strip field
suggestions (graphql-armor), generic error codes, log full detail server-side with
correlation ID.

Cross-link `vulnerability_research_methodology_expertise.md` for the surface enumeration
discipline applied to GraphQL.

---

## 7. REST API security — the older sibling

GraphQL inherits REST's failure modes plus a few amplifiers (aliasing, introspection,
single-endpoint trust, query complexity). The OWASP API Security Top 10 2023 is the
canonical taxonomy for both. The 2019 → 2023 deltas: BOPLA (consolidating Excessive Data
Exposure and Mass Assignment); Unsafe Consumption of APIs (API10); rename of Lack of
Resources & Rate Limiting to Unrestricted Resource Consumption (API4).

### API1:2023 — Broken Object Level Authorization (BOLA / IDOR)

Dominant API-AuthZ bug. Every handler accepting an object ID without principal-scoped
lookup is a candidate. REST: `GET /api/orders/{id}` returning any order when handler does
`Order.findById(id)`. GraphQL: same shape at resolver level (§2). Cross-link
`distributed_authz_expertise.md` §4.

### API2:2023 — Broken Authentication

Token validators skipping signatures; password resets that don't invalidate prior tokens;
refresh tokens that don't rotate; OAuth flows skipping `state`/`nonce`. CVE-2022-1245
(Keycloak, Kurt's CVE): privilege escalation in OAuth2 token-exchange; missing
authorization let any client redeem tokens for any target `client_id`. Cross-link
`distributed_authz_expertise.md` §6 for the RFC 9700 OAuth threat model.

### API3:2023 — Broken Object Property Level Authorization (BOPLA)

Reading the object is fine; reading a property isn't. Consolidates:

- **Excessive data exposure (2019 API3):** endpoint returns `User` with `salary`,
  `internal_notes` even for low-privilege callers.
- **Mass assignment (2019 API6):** endpoint accepts `User` body and writes every field;
  client elevates to `role: "admin"`.

REST: explicit DTOs naming readable / writable fields per role; never accept `req.body`
into `Model.update(...)` without allowlist. GraphQL: per-field resolvers with per-field
authz checks (§3 Pattern B).

### API4:2023 — Unrestricted Resource Consumption

Missing rate limits, missing query cost analysis, lack of pagination caps, unbounded
uploads, unbounded WebSocket connections, lack of per-tenant quota. Cross-link §4 and
`redos_algorithmic_dos_expertise.md`.

### API5:2023 — Broken Function Level Authorization (BFLA)

Principal authorized for the object but not for the function. `DELETE /api/users/{id}`
reachable by any authenticated user; ownership passes because `current_user.id == {id}`;
the function should be admin-only. Or `POST /api/users/{id}/promote-to-admin` — guessable
URL, auth check is "is logged in" not "is admin," self-promotion follows. Detection: every
state-changing route operating on a resource needs a function-level check distinct from
the ownership check.

### API7:2023 — Server-Side Request Forgery (SSRF)

Webhook registration, image-by-URL, OAuth callback URLs, document-fetch-by-URL, AI-agent
tool integrations. Capital One 2019 was SSRF via an internal WAF misconfiguration on a
metadata-service-adjacent endpoint. Cross-link `ssrf_url_parsing_expertise.md`.

### API8:2023 — Security Misconfiguration

Default credentials, verbose errors, missing/permissive CORS, default ports left open,
dev tooling exposed in production (GraphiQL, Playground, Swagger UI with editable
Try-It-Now), missing TLS, reachable debug endpoints. Cross-link `http_web_security.md` §IV.

### API6:2023 — Unrestricted Access to Sensitive Business Flows

New in 2023 as distinct from rate limiting because per-IP defenses fail against
distributed credential stuffing. Mitigation: device fingerprinting; bot management
(Cloudflare, Akamai, Datadome); per-account anomaly detection; CAPTCHA on suspicious
inflows; MFA on high-risk logins.

### API9:2023 — Improper Inventory Management

You can't secure an API you don't know exists. Shadow APIs: dev/test on same DNS as
production; old API versions still serving traffic after v2 launch; partner APIs added
without security review. Defense: spec-driven dev (OpenAPI / GraphQL SDL as truth), API
gateway as choke point, network-level external enumeration, ASM tooling for external view.

### API10:2023 — Unsafe Consumption of APIs

New in 2023. Risk: consuming **other APIs** in service-to-service mesh without the same
hygiene applied to inbound requests. Trusting third-party webhook payload as authenticated
user data; chained downstream API with inconsistent types; SSRF in your service's outbound
calls because downstream response shape isn't validated. Mitigation: treat downstream
responses with same skepticism as upstream requests; validate types; enforce timeout /
retry; never trust upstream identity claims without re-verification.

---

## 8. Authentication patterns and pitfalls

### API keys

Three failure modes:

- **Long-lived keys without rotation.** Key issued at signup still valid five years later;
  disclosure is permanent.
- **Keys scoped to all-of-API.** One key per customer = blast radius = customer's entire
  data.
- **Keys in query strings.** `?api_key=...` ends up in access logs, CDN logs, browser
  referer headers, URL-history sync services. RFC 9700 forbids this for bearer tokens; same
  logic for API keys.

Defenses: rotation cadence (90-day for high-value, immediate on disclosure); per-endpoint
or per-scope keys; transport via `Authorization: Bearer` header; per-key audit log.

### JWT bearer tokens

Well-known failure modes:

- **`alg: none`** — validator accepts unsigned tokens. Fix: hardcode expected algorithm.
- **Algorithm confusion.** Validator reads `alg` from header; attacker sends `alg: HS256`
  with public key as HMAC secret; validation passes.
- **`kid` path traversal.** Validator concatenates `kid` into a file path; `kid:
  ../../etc/passwd` reads arbitrary files. Worse: `kid` as SQL lookup → SQLi.
- **Expired-token replay.** `exp` claim in the future or validator doesn't check `exp`.

Cross-link `cryptography_expertise.md` for JWS/JWE landscape; `distributed_authz_expertise.md`
§6 for OAuth/OIDC threat model.

### OAuth 2.0 / OIDC

Two patterns:

- **Authorization-code with PKCE** (RFC 7636) for first-party client → API. Redirect to
  IdP; user authenticates; code returned via redirect; client exchanges code for tokens.
  PKCE binds the code to the client instance via per-request code verifier.
- **Client credentials grant** for service-to-service. Backend authenticates to IdP with
  own credentials; receives access token; uses token against API.

Failure modes in RFC 9700: redirect-URI manipulation, code injection across clients,
refresh-token theft without rotation, token replay across audiences, mix-up attacks
against multi-IdP clients, `state` omission (CSRF on OAuth flow), `nonce` omission for
OIDC ID tokens.

### mTLS for service-to-service

Replaces bearer tokens with X.509 client certs at TLS layer. Credential bound to network
connection (no replay across connections); presented automatically by TLS stack (no
token-in-header bugs); revocation via CRL/OCSP. Cost: certificate lifecycle is non-trivial.
SPIFFE/SPIRE standardizes service-identity certs; service meshes (Istio, Linkerd)
automate at sidecar layer. For cloud-native, mTLS-by-default at the mesh layer is the
right baseline.

### Refresh-token lifecycle

- **Non-rotating refresh tokens.** Token issued at first login valid six months later;
  theft gives permanent access. Fix: rotation — every redemption issues new token,
  invalidates old. RFC 9700 requires rotation or sender-constraining for public clients.
- **Refresh-token replay without detection.** Attacker steals token, uses once; legitimate
  client also uses. Detection: redeemed-then-redeemed-again chain → all tokens in chain
  invalidated; user forced to re-auth.
- **Cross-client refresh token theft.** Token issued to client A presented by client B.
  Token endpoint binds to `client_id` and rejects mismatched redemption.

### Tokens in URLs (still happens, still bad)

Why it persists: magic-link login (`?token=...`), API key as query param (easier
onboarding), OAuth implicit grant with `#access_token=...` in fragment. Mitigations:
exchange magic-link tokens for session cookie at first hop and redirect to token-free URL;
API keys in `Authorization` header; OAuth via authorization-code with PKCE (implicit grant
deprecated by OAuth Security BCP).

---

## 9. Rate limiting and abuse prevention

### Per-user vs per-IP vs per-endpoint

- **Per-IP.** Cheap, effective against amateur scraping. Defeated by residential proxy
  networks (Bright Data, Smartproxy). Per-IP rate limit is per-IP-per-window — doesn't
  slow credential-stuffing with 1M rotating IPs.
- **Per-user.** Effective against logged-in abuse; useless pre-auth (login, signup,
  password-reset).
- **Per-endpoint.** Blunt; fine for static cost limits but doesn't distinguish high vs
  low-value calls.
- **Per-account-or-fingerprint.** Layered. Account lockouts after N failures; device
  fingerprinting; ASN reputation (datacenter vs residential).

Defensive stack: per-endpoint floor (DoS prevention) + per-account ceiling (abuse) +
per-fingerprint anomaly (ATO) + CAPTCHA on suspicious inflows.

### Why simple rate limits don't stop credential stuffing

Credential stuffing is population-level, not per-user. Attacker has breached (email,
password) pairs; tries each pair against one account. Per-account lockout (5 failed
attempts) never fires — each account sees exactly one attempt. What helps: aggregate-level
detection (high failure rate, unusual fingerprint distribution), aggregate throttling,
CAPTCHA, MFA on high-risk logins. OWASP Credential Stuffing Prevention cheat sheet
documents the canonical defenses.

### The expensive-operation tax

For rare-by-design operations (account creation, password reset, OTP request), force a
cost that scales with abuse:

- **CAPTCHA.** Free, well-tooled (reCAPTCHA, hCaptcha, Turnstile). Slows but doesn't stop
  motivated attackers.
- **Proof-of-work.** Client computes hash with target prefix; server verifies in
  microseconds; client took seconds-to-minutes. Hashcash-style.
- **Delay.** Server-side sleep on failed login (500ms). Legitimate users feel it once;
  brute-force hits a soft parallelism cap.
- **Cost in dollars.** Twilio per SMS, Stripe per tokenize. Abuse economically irrational
  beyond break-even.

### Anomaly scoring

Salt Security / Traceable / Wallarm class: ingest full request stream; per-account /
per-endpoint baselines; alert on deviations (unusual access pattern, geographic outlier,
sequence deviation — user who never exported data suddenly exports 10x). First-party
defenders: structured access logs in a data lake; daily/weekly per-account rollups;
alerts on volume increases or new-endpoint use.

### Tokens-per-second budgets

Each request consumes tokens from a per-account budget; budgets refill at configurable
rate (token-bucket / leaky-bucket). Different operations cost different tokens (search = 1,
export = 100). GitHub's v4 GraphQL "Resource limitations" doc codifies this; AWS API
Gateway and Apigee ship the primitive natively. Cost-weighted (cheap calls don't crowd
out expensive); budget gives a soft ceiling on damage from account compromise.

Cross-link `redos_algorithmic_dos_expertise.md` §7 for the algorithmic-DoS framing.

---

## 10. API inventory and discovery

### The shadow-API problem

Real consumer-scale APIs accumulate undocumented surface:

- v1, v2, v3 — and v1 still serves traffic (deprecation ignored; old mobile apps depend on
  the old endpoint).
- Dev/test endpoints exposed (same load balancer; no auth on `api-dev.example.com`).
- Partner integrations added by business teams without security review.
- Internal microservices exposed to the internet by accident (Helm `internal-only` value
  not set; ingress routes externally).

API9:2023 codifies: the top-line failure is not knowing what you have.

### OpenAPI / GraphQL SDL as source of truth

Spec-driven development: spec is truth; implementation is generated from or validated
against it. Discovery becomes a property of the spec.

- **REST:** OpenAPI 3.1 (formerly Swagger); codegen (`openapi-generator`); runtime
  validation (`express-openapi-validator`, FastAPI). CI gate: drift detection.
- **GraphQL:** Schema-first SDL with `graphql-inspector` or `rover graph check`.
  Persisted-queries list as second-layer truth for what queries run.
- **Service mesh:** Istio `VirtualService` lists every routable endpoint; network policy
  audits report unauthorized exposure.

### API gateway as choke point

Single ingress for external traffic. Enforces: authentication (reject unauth before
service); schema validation (parse against registered schema; reject malformed); rate
limiting (per-account/per-endpoint before service); audit logging (principal + endpoint +
response code).

### "If you can't list it, you can't secure it"

Visibility precedes defense. An appsec program without an authoritative inventory defends
a strict subset of what's exposed. The list of "all our APIs" is the prerequisite for
every follow-on defense. Cross-link `code_review_expertise.md` §3 — asymmetric attention,
publicly-reachable entry points first.

---

## 11. Detection — static analysis lens

### GraphQL detection patterns

A static-analysis authz-detection workflow generalizes to GraphQL via the same authz-CWE
bestiary with resolver-specific patterns:

- **Resolver-without-auth-check.** Functions matching `(parent, args, context, info) => ...`
  that don't reference `context.user` or auth helpers. A CWE-862 `MissingAuthz` detection
  pattern's parent-chain enrichment applies: resolvers declared inside `withAuth(...)` HOCs
  or registered via `@requireAuth`-decorated bindings pass; bare resolvers fail.
- **Introspection enabled in production.** `ApolloServer({ introspection: true })` not
  gated on `NODE_ENV`. MEDIUM severity; investigation cost low.
- **Raw query construction in resolvers.** String concatenation/interpolation into
  `db.query(...)`, `Model.findOne(...)`, `mongoose...find(...)`. Injection-focused
  detection lanes scoped to resolver function bodies.
- **Persisted-query allowlist enforcement.** Every `ApolloServer` instance with
  `persistedQueries` configured AND safelist-only routing. Misconfigured safelist falling
  back to arbitrary queries is a regression from no safelist (false sense of security).
- **Missing depth/complexity limit configuration.** `ApolloServer` instantiations whose
  `validationRules` lack `depthLimit(...)` or `createComplexityLimitRule(...)`.
  MEDIUM absence.

### REST detection patterns

OWASP API Top 10 maps to Semgrep rule families:

- **BOLA (API1):** route handlers where path captures ID and handler does `findById(id)`
  without `userId`/`tenant_id` filter.
- **BFLA (API5):** state-changing endpoints (`POST/PUT/DELETE`) whose handlers lack
  function-level authz checks. Heuristic: `app.delete(...)` or `app.post(...)` on
  `/admin/...` or `/api/internal/...` routes without role/permission references.
- **BOPLA (API3) — mass assignment:** `Model.update(req.body)` or `Object.assign(model,
  req.body)` without writable-field allowlist.
- **API6 (SSRF):** cross-link `ssrf_url_parsing_expertise.md` for the URL-parser
  discrepancy detection lane; pattern adapts to resolvers.
- **API4 (Resource consumption):** endpoints without rate-limiting middleware (heuristic:
  no `express-rate-limit`, `bottleneck`, or framework-equivalent in scope).

### OWASP API Top 10 to CWE mapping

The six authz/authn CWEs (287, 306, 308, 862, 863, 1390) map to API1 (BOLA → 862/863), API2
(Broken Auth → 287/1390), API5 (BFLA → 862/863). The detection lane for GraphQL is the
same lane applied to a JavaScript/TypeScript/Python resolver corpus. Cross-link
`vulnerability_research_methodology_expertise.md` §2 for variant-analysis framing.

---

## 12. Defensive patterns

### Auth-first architecture

Default for every resolver, route, operation: deny. Explicit allow is the precondition for
execution. Schema-construction-time middleware (§3 Pattern F) installs this as the
structural default.

### Persisted queries

Highest-leverage hardening for first-party GraphQL. Build pipeline extracts every
operation; production server accepts only registered operations by hash.
Discoverability collapses; attacker surface = "queries you wrote." Layer on top of
resolver-level authz, not as replacement.

### Per-field BFLA checks

Object-level authz necessary but not sufficient. Sensitive fields (`User.salary`,
`Order.fullCreditCard`, `Document.internalNotes`) get their own per-field resolvers with
their own checks.

### Schema-as-code with explicit auth annotations

`@auth` / `@requireRole` / `@requirePermission` directives become the readable surface of
the authz policy. Grep `@auth`; see protected fields. CI gate: "no new field merges
without `@auth` or explicit `@public` exemption."

### API gateway as choke point

Every external request enters through the gateway: authentication, schema validation, rate
limiting, audit logging. Application server trusts gateway auth headers but enforces
authorization itself.

### Per-endpoint logging and audit trail

Every request logged with: authenticated principal, endpoint / operation name, field set
(for GraphQL — fields the operation requested), arguments (sensitive values redacted),
response code, response size, processing time. Precondition for ATO detection and forensic
response.

### Code-review checklist for API and GraphQL changes

Adapted from `code_review_expertise.md`'s candidate-point methodology:

1. Every new resolver has an explicit authz check (directive, shield rule, or inline).
2. Every new mutation has a corresponding persisted-query list entry (if PQ adopted).
3. Every resolver taking `id` routes lookup through the principal (`Model.findOne({
   _id: args.id, userId: context.user.id })`, not `Model.findById(args.id)`).
4. Every sensitive-field resolver has its own per-field check (default field projection is
   a smell for `salary`, `email`, `phoneNumber`, `taxId`, `internalNotes`).
5. No raw query construction in resolver bodies (ORMs or parameterized queries).
6. No `JSON` / arbitrary-object scalars on user-controlled input (typed `FilterInput` with
   named fields).
7. DataLoader instances per-request with principal baked in; never module-level.
8. Introspection disabled in production (`NODE_ENV`-gated).
9. Field-suggestion errors disabled in production (graphql-armor).
10. Depth limit (10) and complexity limit (1000) explicit in server constructor.
11. Alias-count cap (default 15) configured.
12. Rate limits per-account and per-endpoint; tokens-per-second budget on expensive ops.
13. Error messages stripped of stack traces and schema-revealing detail.
14. CORS configured restrictively (`*` is never the answer in production).
15. Mutations touching finance/auth/authz state have CSRF protection or sameOrigin policy.

---

## 13. Variant analysis — under-explored surfaces

### gRPC streaming authorization

gRPC supports unary, server-streaming, client-streaming, bidi-streaming RPCs. Streaming
RPCs hold long-lived connections; authorization context captured at stream-start applies
to every message. Failure modes:

- **Token expiry mid-stream.** Token valid at start; expires; stream keeps serving. Fix:
  per-message re-check (expensive) or stream-lifetime cap (cheap, may interrupt valid
  long-running operations).
- **Permission changes mid-stream.** Permissions revoked (suspension, demotion); stream
  keeps serving.
- **Cross-stream tenancy bleed.** Two streams from different tenants sharing in-memory
  cache or DataLoader at service layer (module-level singleton). One tenant's data leaks.
  Fix: per-stream context; no module-level state.

### WebSocket subprotocol authorization

GraphQL subscriptions over WebSocket (`graphql-ws`, `subscriptions-transport-ws`) carry
auth context in the connection-init payload, not per-message headers. Failure modes:

- **Connection-init replay.** Attacker captures init payload; replays from different
  origin. Fix: bind connection to originating session; reject mismatched re-binds.
- **Permission changes between pushes.** Subscription's authz check runs only at
  subscribe-time, not push-time. Changes don't take effect.
- **CORS doesn't apply to WebSockets.** Cross-origin upgrades succeed without origin check
  unless server explicitly verifies `Origin` at upgrade time. Common gap.

### tRPC end-to-end-typed APIs

TypeScript-typed RPC; wire is HTTP/JSON; security model = HTTP plus stronger typing.
Procedure middleware chain is canonical authz placement:

```typescript
const authedProcedure = t.procedure.use(async ({ ctx, next }) => {
  if (!ctx.user) throw new TRPCError({ code: "UNAUTHORIZED" });
  return next({ ctx: { ...ctx, user: ctx.user } });
});
const adminProcedure = authedProcedure.use(async ({ ctx, next }) => {
  if (ctx.user.role !== "admin") throw new TRPCError({ code: "FORBIDDEN" });
  return next();
});
```

Same composition discipline as graphql-shield rule chains. Risk: forgetting the
`authedProcedure` prefix and writing bare `t.procedure.query(...)` for what should be
protected. CI lint: every procedure starts from `authedProcedure` or `publicProcedure`;
bare `t.procedure` forbidden.

### AI agent API consumption

An LLM agent calls your API with credentials delegated by the user. Tool-call carries
either the user's token (delegation right) or the agent's service token (delegation wrong
— see `distributed_authz_expertise.md` §10). API has to:

- Distinguish human vs agent calls (separate `client_id` at OAuth layer or custom header);
  audit trail needs the distinction.
- Apply different rate limits and abuse signals; agent traffic is qualitatively different.
- Re-verify sensitive operations (irreversible deletes, fund transfers, data exports)
  with human-in-the-loop regardless of auth state.

Cross-link `llm_agent_security_expertise.md` and `agentic_web_capabilities_expertise.md`.

### AsyncAPI for event-driven APIs

AsyncAPI is OpenAPI-equivalent for message-driven APIs (Kafka, RabbitMQ, NATS, MQTT). The
discovery problem from §10 applies: topics are reachable infrastructure; authorization is
broker-level ACLs vs HTTP-layer; audit trail is message-level. Treat events as APIs; apply
the same inventory discipline.

### Internal-only API exposed externally

Classic misconfiguration: service intended cluster-internal exposed externally. Causes:
Kubernetes Service `LoadBalancer` when dev meant `ClusterIP`; security group with
`0.0.0.0/0` in addition to internal CIDR; ingress controller catching internal-only
hostname. Cross-link `cicd_supply_chain_expertise.md` and `container_k8s_security.md`.

---

## 14. References

### Primary sources — GraphQL security

- *Black Hat GraphQL: Attacking Next Generation APIs* — Nick Aleks, Dolev Farhi (No Starch
  Press, 2023). ISBN 978-1-7185-0284-0. https://nostarch.com/black-hat-graphql
- *Damn Vulnerable GraphQL Application (DVGA)*: https://github.com/dolevf/Damn-Vulnerable-GraphQL-Application
- *graphw00f* (framework fingerprinting): https://github.com/dolevf/graphw00f
- *graphql-cop* (audit tool): https://github.com/dolevf/graphql-cop
- GraphQL specification (October 2021): https://spec.graphql.org/October2021/
- Apollo GraphQL documentation: https://www.apollographql.com/docs/
- "Why You Should Disable GraphQL Introspection in Production":
  https://www.apollographql.com/blog/why-you-should-disable-graphql-introspection-in-production
- "Secure your GraphQL platform by safelisting known queries":
  https://www.apollographql.com/blog/secure-your-graphql-platform-by-safelisting-known-queries
- "Safelisting with Persisted Queries":
  https://www.apollographql.com/docs/graphos/routing/security/persisted-queries
- PortSwigger Web Security Academy GraphQL labs:
  https://portswigger.net/web-security/graphql

### Primary sources — OWASP API Security

- OWASP API Security Top 10 2023: https://owasp.org/API-Security/editions/2023/en/0x00-header/
- API1:2023 BOLA: https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/
- API3:2023 BOPLA: https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/
- API5:2023 BFLA: https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/
- API6:2023 SSRF: https://owasp.org/API-Security/editions/2023/en/0xa6-server-side-request-forgery/
- OWASP API Security Project: https://owasp.org/www-project-api-security/
- OWASP GraphQL Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html
- OWASP Credential Stuffing Prevention: https://cheatsheetseries.owasp.org/cheatsheets/Credential_Stuffing_Prevention_Cheat_Sheet.html

### Tooling and libraries

- graphql-shield: https://github.com/maticzav/graphql-shield
- graphql-armor: https://escape.tech/graphql-armor/
- graphql-query-complexity: https://github.com/slicknode/graphql-query-complexity
- graphql-depth-limit: https://github.com/stems/graphql-depth-limit
- graphql-inspector: https://github.com/kamilkisiela/graphql-inspector
- Hasura: https://hasura.io/
- PostGraphile: https://www.graphile.org/postgraphile/
- Apollo Router: https://www.apollographql.com/docs/router/

### Practitioner writeups

- Kurt Boberg, "Staff Eng Security Stories" (Clint Gibler, tl;dr sec):
  https://tldrsec.com/p/guides-staffeng-security-stories-kurt-boberg
- Frans Rosén, "Hacking Slack using postMessage and WebSocket-reconnect":
  https://labs.detectify.com/writeups/hacking-slack-using-postmessage-and-websocket-reconnect-to-steal-your-precious-token/
- Frans Rosén, "Account hijacking using 'dirty dancing' in sign-in OAuth-flows":
  https://labs.detectify.com/writeups/account-hijacking-using-dirty-dancing-in-sign-in-oauth-flows/
- "Didn't Notice Your Rate Limiting: GraphQL Batching Attack" (Checkmarx):
  https://checkmarx.com/blog/didnt-notice-your-rate-limiting-graphql-batching-attack/
- "GraphQL Alias Overloading Allowed" (Invicti):
  https://www.invicti.com/web-application-vulnerabilities/graphql-alias-overloading-allowed-potential-denial-of-service-vulnerability
- "Avoid GraphQL Denial of Service attacks through batching and aliasing" (Escape):
  https://escape.tech/blog/graphql-batch-attacks-cause-dos/
- Aleksei Tiurin's Acunetix author archive:
  https://www.acunetix.com/blog/author/alekseitiurin/

### Standards and RFCs

- RFC 9700 — OAuth 2.0 Security BCP: https://datatracker.ietf.org/doc/rfc9700/
- RFC 7636 — PKCE: https://datatracker.ietf.org/doc/html/rfc7636
- RFC 8693 — OAuth 2.0 Token Exchange: https://datatracker.ietf.org/doc/html/rfc8693
- OpenID Connect Core 1.0: https://openid.net/specs/openid-connect-core-1_0.html
- OpenAPI 3.1: https://spec.openapis.org/oas/v3.1.0
- AsyncAPI: https://www.asyncapi.com/

### Internal cross-references

- `knowledge-base/appsec-web/distributed_authz_expertise.md` — Zanzibar, OAuth threat
  model, BOLA/BFLA/BOPLA primitives, authz CWE mapping.
- `knowledge-base/appsec-web/http_web_security.md` — HTTP request smuggling, web cache
  poisoning, CORS. The transport-layer surface GraphQL inherits.
- `knowledge-base/methodology/code_review_expertise.md` — candidate-point auditing,
  auth-homogeneity, click-count severity, format-string/path heuristics.
- `knowledge-base/vuln-classes/template_code_injection_expertise.md` — Jinja2/Handlebars/
  FreeMarker SSTI. Resolver-layer template injection (§5).
- `knowledge-base/vuln-classes/ssrf_url_parsing_expertise.md` — URL-parser discrepancies,
  IMDS blocking. Resolver-layer SSRF (§5, §7).
- `knowledge-base/vuln-classes/redos_algorithmic_dos_expertise.md` — algorithmic-DoS,
  token-bucket budgets, worst-case bounding. GraphQL complexity (§4, §9).
- `knowledge-base/crypto-trust/cryptography_expertise.md` — JWT algorithm confusion,
  JWS/JWE, TLS/mTLS. AuthN credentials (§8).
- `knowledge-base/ai-ml-security/llm_agent_security_expertise.md` — LLM agent runtime,
  delegated authority. AI-agent API consumption (§13).
- `knowledge-base/supply-chain/cicd_supply_chain_expertise.md` — pipeline hygiene,
  internal-only-exposed misconfiguration. Inventory failure (§10).
- `knowledge-base/methodology/vulnerability_research_methodology_expertise.md` — surface
  enumeration, variant analysis, finding-rate floors. GraphQL discovery discipline (§6, §11).

---

## 15. Summary: what defines staff-level GraphQL and API security

1. **GraphQL inherits REST's failure modes and amplifies a few.** Every injection class
   applies underneath. Amplifiers: introspection, aliases, single-endpoint trust model,
   absence of authz primitives in the spec.

2. **The schema-construction layer is where authz belongs.** Per-resolver imperative
   checks don't scale past ~100 resolvers and don't survive at 400-person engineering
   scale. Kurt's Chegg framing — "batteries included" — means default-deny installed at
   schema construction; every resolver inherits automatically.

3. **Persisted queries are the strongest discoverability hardening.** For first-party
   deployments, the production server accepts only platform-approved operations by hash.
   Layered on top of resolver-level authz, not as replacement.

4. **The OWASP API Top 10 (2023) is the canonical taxonomy.** BOLA, BFLA, BOPLA, SSRF,
   Unrestricted Resource Consumption account for the bulk of API findings in 2023–2026
   corpora. Map detection rules to these categories.

5. **Introspection off in production is non-negotiable for non-public APIs.** Combined
   with field-suggestion suppression, depth/complexity limits, alias caps. Default
   posture for every major framework.

6. **DataLoader instances are per-request with principal baked in.** Module-level loaders
   leak across tenants; per-request loaders with closure-captured identity don't.

7. **Inventory precedes defense.** Shadow-API problem is the precondition for every
   downstream gap. OpenAPI/SDL as truth, API gateway as choke point, schema diffing in CI.

8. **Authentication and authorization are distinct.** Most public bugs cluster at
   AuthN-as-AuthZ conflation — "logged in" treated as "permitted." The six authz/authn
   CWEs (287/306/308/862/863/1390) cover the distinct failure modes.

9. **The AI-agent API surface is the next frontier.** Tokens delegated by users to agents;
   agent-originated traffic distinguishable from human; per-operation re-auth on sensitive
   actions. Cross-link the agent-runtime expertise.

10. **Static analysis applies to GraphQL the same way as REST.** Authz-detection and
    injection-detection workflows both generalize to resolver bodies. Patterns are the
    same; only syntactic shapes differ.
