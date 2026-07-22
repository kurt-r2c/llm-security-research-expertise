# GNAP (RFC 9635) — Grant Negotiation and Authorization Protocol

Specialization sibling to `session_management_expertise.md` §7 (OAuth 2.1 RFC 9700 BCP) and `ai_agent_session_management_expertise.md` §7 (OAuth-for-AI-agents). GNAP is the IETF-finalized OAuth successor designed for fine-grained, multi-party, non-browser, sender-constrained authorization. This doc is for the AppSec / IdP / API-platform engineer evaluating GNAP for high-security flows or designing GNAP-compatible services.

## 1. Why this doc exists

OAuth 2.x grants are coarse-grained (scope is a string), client-driven (the client asks; the AS approves or denies), and structurally assume a browser-mediated authorization step. GNAP — *Grant Negotiation and Authorization Protocol*, RFC 9635 `[unverified specific publication month, finalized late 2024]` — generalizes the model: per-action authorization, negotiable between Resource Server (RS), Authorization Server (AS), Resource Owner (RO), and Client; sender-constrained tokens by default; non-browser interactions as first-class; asynchronous and polling-friendly flows.

The structural insight is that GNAP is OAuth designed for the world OAuth was not designed for — multi-party APIs, IoT, AI agents, and high-assurance financial flows. Treat GNAP as the protocol you reach for when OAuth 2.1 + DPoP + PAR + JAR stops being expressive enough, not as a drop-in upgrade. Almost no team needs GNAP today; the teams that need it tend to be banks, healthcare data brokers, and people building AI-agent runtimes with real authorization stakes.

## 2. Origin and canonical references

- **RFC 9635 — *Grant Negotiation and Authorization Protocol*** `[unverified specific month, finalized late 2024]`. The core IETF specification.
- **Justin Richer** — GNAP Working Group co-chair, primary protocol author, and the operator-historian of the OAuth-to-GNAP arc. Author of *OAuth 2 in Action* (Manning 2017) with Antonio Sanso. His pre-WG draft, **the XYZ proposal** (~2019-2020 `[unverified date]`), is the informal "OAuth 3" exploration that the IETF GNAP WG was chartered to formalize.
- **Aaron Parecki** — OAuth + GNAP commentator, author of oauth.com, IETF participant. Practitioner-side documentation anchor.
- **Fabien Imbault** — GNAP WG contributor; protocol-design and implementation reviews `[unverified specific role]`.
- **Tony Nadalin** — IETF veteran (Microsoft alumnus), GNAP WG contributor `[unverified specific role]`.
- **Daniel Fett** — OAuth 2.1 BCP (RFC 9700) author, GNAP WG reviewer, formal security analysis lineage (TLS 1.3 formal verification, OAuth FAPI security analyses).
- **Hannes Tschofenig** — IETF area director-adjacent, RATS chair, GNAP WG participant `[unverified]`.
- **Brian Campbell** — Ping Identity, **DPoP RFC 9449** author, OAuth long-time contributor. DPoP is the sender-constraining primitive GNAP defaults to.
- **Mike Jones** — JWT / OIDC primary author; adjacent IETF identity work. Cross-cutting reference for token formats.
- **Filip Skokan** — Auth0 / Okta engineer, author of widely-used `node-openid-client` and `node-oidc-provider` libraries. Library-author voice on the migration cost.

Adjacent IETF specs referenced by GNAP:

- **RFC 9449 — *OAuth 2.0 Demonstrating Proof of Possession (DPoP)*** (Brian Campbell et al. `[unverified specific year]`).
- **RFC 8705 — *Mutual-TLS Client Authentication and Certificate-Bound Access Tokens*** (mTLS-bound tokens).
- **RFC 8707 — *Resource Indicators for OAuth 2.0*** (audience binding — adopted by MCP 2025-11-25 spec update).
- **RFC 9700 — *OAuth 2.0 Security Best Current Practice*** (May 2024 `[unverified]`).
- **RFC 9711 — *EAT (Entity Attestation Token)*** — adjacent token format for sender-constrained tokens with hardware-attestation evidence; integrates with GNAP for high-assurance flows.
- **Supplementary GNAP documents** including *GNAP Resource Server Connections* (RFC TBD `[unverified status]`) which specifies AS-to-RS interaction.

Track this set; GNAP is RFC 9635 plus a small constellation of supporting drafts, not a monolithic spec.

## 3. GNAP vs OAuth 2.1 — the structural differences

The single most useful framing: OAuth 2.1 is a *grant protocol*; GNAP is a *negotiation protocol*. The differences fall out of that.

1. **Fine-grained per-action authorization.** OAuth scope is a string. GNAP requests describe specific actions on specific resources with specific constraints — a JSON object with `access` arrays containing `type`, `actions`, `locations`, `datatypes`, `identifier`, and similar fields. The AS evaluates the structured request and may issue a token authorizing exactly that or counter-offer.
2. **Multi-party negotiation.** OAuth assumes the AS speaks for the RS. GNAP separates RS, AS, RO, and Client as distinct participants. The RS can register intent and capabilities with the AS, the AS can issue RS-aware tokens, and the RO is treated as a participant whose interaction surface is negotiable.
3. **Negotiation is real.** The AS can return *less authority than requested*, with explanations, or counter-propose constraints (shorter TTL, narrower audience, additional binding). OAuth is take-or-leave. GNAP's response can be `access_token`, `continue`, `interact`, or partial combinations.
4. **Sender-constrained tokens by default.** GNAP tokens are DPoP-bound or mTLS-bound. Bearer-token theft alone is insufficient; the attacker also needs the key. This is the single largest practical security improvement over OAuth 2.1's default bearer-token semantics. Cross-link to `[[reference-session-management]]` §12 (sender-constrained tokens rare in production).
5. **Non-browser-first.** OAuth assumes browser redirects. GNAP supports redirect, push (app-to-app deep link), URI scheme, display (show a code to the user), and `finish` callbacks as composable interaction methods. CLI, IoT, AI agent, and headless flows are first-class.
6. **Asynchronous and polling.** GNAP supports "request now, get the response later" without the ad-hoc OAuth Device Authorization Grant (RFC 8628) workaround. The continuation URI is the protocol primitive.
7. **Continuation API.** A single grant has a continuation URI that the client uses to update, query, rotate, or cancel. OAuth's refresh-token mechanism is a special case of this.

If your situation doesn't need at least three of those properties, you don't need GNAP.

## 4. The GNAP message model

A GNAP exchange has four shapes you must understand to read the spec:

- **Grant request.** Client sends a JSON object to the AS describing what it wants: `access_token` (the requested access — array of resource descriptors), `client` (key material, identifier), `interact` (how the RO can interact, if needed), `subject` (which subject identifier formats are acceptable), `user` (user assertion if known), `capabilities` (negotiation hints).
- **Grant response.** AS returns access token(s), continuation URI (for further operations on this grant), interaction info (where to send the user, if needed), subject info, and any counter-offers.
- **Continuation API.** Subsequent operations on the grant — update the request, poll for completion, rotate the token, revoke — go through the continuation URI with a continuation access token issued in the initial response.
- **Interaction methods.** Composable: `redirect` (browser-style), `push` (AS pushes notification to client), `finish` (callback after RO interacts), `user_code` (display code), `app` (URI scheme). Multiple methods may be offered; client picks one.

The subject identifier is more flexible than OAuth's `sub` claim. GNAP supports multiple identifier formats — opaque, email, phone, account URI, decentralized identifier — and lets the client request which formats are acceptable. This matters for cross-domain flows where the OAuth-style single-`sub` model breaks.

## 5. Access token format and binding

GNAP access tokens are **bound by default**. The protocol assumes DPoP (RFC 9449) or mTLS (RFC 8705) sender-constraining. Issuing a bearer token in GNAP is possible but requires explicit choice; the operational expectation is bound.

Practical consequences:

- **Token theft alone is insufficient.** Steal a DPoP-bound token; without the corresponding private key, replay against an RS fails the proof check. This collapses the "session cookie theft as MFA bypass" attack pattern that dominates 2023-2026 incidents (Lapsus$ / Storm-0558 / Snowflake; cross-link `[[reference-session-management]]` §11).
- **Introspection is built in.** The AS exposes introspection capability without the OAuth-style separate `/introspect` endpoint convention.
- **Token rotation via continuation.** The continuation API lets the client request a fresh token, rotate the binding key, or update the access description. Refresh tokens become optional rather than a distinct grant type.
- **Multiple-access-token issuance.** A single grant can yield multiple tokens — one per RS, or one per action class. The client requests; the AS issues `access_token` as either a single object or an array of named tokens.

The binding requirement is also GNAP's largest operational lift. DPoP requires per-client keypair management; mTLS requires per-client certificate PKI. If your client population is a handful of internal services, this is straightforward. If your client population is millions of consumer apps, this is a real infrastructure project. The honest version is in §13.

## 6. Resource Server (RS) connections

The OAuth assumption that AS-RS coupling is informal — AS issues opaque token; RS introspects when curious — breaks in multi-RS, fine-grained scenarios. GNAP addresses this with a separate spec, *GNAP Resource Server Connections* (RFC TBD `[unverified status]`), that defines:

- **RS-to-AS registration.** RS announces what kinds of resources it serves and what kinds of access descriptions it accepts.
- **AS-to-RS policy push.** The AS can push authorization decisions to the RS without per-request introspection round-trips.
- **RS-aware token issuance.** The AS issues tokens scoped to specific RS instances rather than a generic audience string.

This piece is the most operationally important and the least mature. Production GNAP deployments need it; the standardization is still finalizing as of 2026 `[unverified]`. Build with caution and plan to track the RFC.

## 7. GNAP for AI agents

The AI-agent fit is the single most-discussed application of GNAP outside FAPI. The structural argument:

- **AI agents are non-browser clients with per-action authorization needs.** GNAP's per-action granularity and non-browser-first design fit better than OAuth 2.1's redirect-based grants.
- **Just-in-time delegation.** GNAP's continuation API supports "agent requests permission for action X, RO approves via push or app, AS issues short-lived bound token for that specific action." OAuth's refresh + scope-rescoping flow can approximate this with effort; GNAP does it natively.
- **Sender-constrained agent tokens.** A DPoP-bound or mTLS-bound agent token raises the bar for attacker post-compromise. Steal the token from agent logs; without the key, replay fails. Cross-link `[[reference-ai-agent-session-management]]` §12.10 (token binding adoption rare).
- **MCP authorization (Anthropic 2025-11-25 spec update).** Brought MCP onto OAuth 2.1 + RFC 8707 audience-binding + PKCE-S256 + token-passthrough prohibition. GNAP is the natural next step for MCP-class delegation; the 2025-11-25 update did not adopt GNAP and probably won't for a generation.
- **The four agent-session shapes from `[[reference-ai-agent-session-management]]` §2** (agent-as-user-proxy via OBO / agent-with-its-own-identity / browser-cookie inheritance / productivity-app inheritance) all benefit from GNAP-style fine-grained per-action binding, though browser-cookie inheritance (Computer Use, Operator, Mariner) inherits the user's existing OAuth grants rather than negotiating fresh GNAP grants.

GNAP is the protocol AI-agent runtimes will eventually want. They mostly don't have it yet.

## 8. FAPI 2.0 + GNAP alignment

The Financial-grade API working group at the OpenID Foundation produces the **FAPI 2.0 Baseline** and **FAPI 2.0 Advanced** profiles, built on OAuth 2.1 with mandatory DPoP-or-mTLS, **PAR (Pushed Authorization Requests, RFC 9126)**, and **JAR (JWT-Secured Authorization Requests, RFC 9101)**. The structural overlap with GNAP is large: both require sender-constrained tokens, both want first-class server-to-server authorization-request transport, both support fine-grained access.

The coordination story `[unverified specific status]`:

- The OpenID Foundation FAPI WG has discussed GNAP alignment for the next FAPI generation.
- GNAP subsumes many FAPI 2.0 features natively (PAR is an OAuth retrofit; GNAP grant requests are PAR-shaped by default).
- Banking-sector adoption of FAPI 2.0 is concentrated in UK Open Banking, EU PSD2 (with national variations), Brazil Open Banking, and Australia Consumer Data Right.
- GNAP adoption in banking is research-grade as of 2026.

A bank evaluating GNAP today should treat it as a 2027-2028 migration target, not a current rollout option. FAPI 2.0 is the production move; GNAP is the trajectory.

## 9. Implementation status as of 2026

The honest picture:

- **Reference implementations.** Academic and proof-of-concept libraries exist (GNAP-AS reference server, various Node/Python/Go client libraries `[unverified specific library names]`). None have the production-grade security-audit + maintenance track record of mature OAuth libraries.
- **OAuth-to-GNAP migration.** Non-trivial. Different message model (JSON object vs form-encoded), different token format (bound vs bearer-default), different client library surface area. Coexistence is possible but each protocol carries its own ops.
- **Cloud-provider IdP support.** AWS Cognito, Azure Entra ID, GCP Identity Platform all primarily on OAuth 2.1 + OIDC. No public GNAP support announcements as of 2026 `[unverified]`.
- **Commercial IdP support.** Okta / Auth0, Microsoft Entra, Keycloak, Ory Hydra, ForgeRock — all OAuth 2.1 + OIDC primary. GNAP is on roadmaps to varying degrees but not GA.
- **Library availability.** Filip Skokan's `node-oidc-provider` ecosystem is the gold standard for OAuth/OIDC; equivalent GNAP libraries are research-grade. Python `authlib` and Go `golang.org/x/oauth2` similarly OAuth-first.
- **Spec readiness.** RFC 9635 is finalized; RS Connections and several supporting drafts are still in progress `[unverified]`.

The pragmatic position for 2026 is "track the standard, don't deploy yet" unless you have specific multi-party / AI-agent / fine-grained-delegation needs that OAuth 2.1 + DPoP + PAR + RFC 8707 cannot express.

## 10. Use cases where GNAP wins over OAuth 2.1

The wins are concentrated in a narrow set of high-assurance or fine-grained scenarios:

- **High-security financial flows.** Per-transaction authorization bound to specific account, amount, recipient — expressed in the grant request, enforced by the AS, propagated to the RS. OAuth's scope-string model cannot express "transfer $X from account A to account B before time T" without per-transaction grant ceremony that GNAP makes native.
- **AI-agent delegation.** Per-tool-call authorization with sender-constrained tokens. The user approves an agent action (or class of actions); the AS issues a bound token scoped to that action; the agent uses it once or for a tight window. OAuth approximates this with custom scope strings + refresh patterns; GNAP does it cleanly.
- **IoT device authorization.** Non-browser, polling-friendly, capability-negotiable. The device asks for permission to publish to a topic; the AS issues a bound token; the device polls the continuation URI for updates.
- **Multi-RS scenarios.** Single grant covering multiple downstream APIs with per-RS scoping. The user grants once; the AS issues multiple per-RS tokens. OAuth requires multiple grants or aggregator-style designs.
- **Healthcare data sharing.** Patient-controlled fine-grained release-of-information (HL7 SMART on FHIR has OAuth profiles; GNAP could express patient consent at the per-data-element level).
- **High-assurance government identity.** eIDAS 2.0 / EUDI Wallet scenarios where the verifier requests specific claims and the wallet negotiates disclosure are GNAP-shaped, though the OIDC4VC family currently dominates.

If your scenario is "user clicks Sign In With Google on a web app," GNAP is the wrong tool.

## 11. GNAP anti-patterns and adoption hesitations

- **Don't pick GNAP for browser-based web apps.** OAuth 2.1 + PKCE + DPoP is mature, library-supported, and sufficient. Picking GNAP for a SaaS web app is signaling, not engineering.
- **Don't pick GNAP without DPoP-or-mTLS infrastructure.** Sender-constrained tokens require per-client key infrastructure. If you can't operate that, GNAP's biggest security win is unavailable to you.
- **Don't migrate OAuth 2.1 to GNAP for novelty.** The operational complexity is real and the security delta over OAuth 2.1 + RFC 9700 BCP + DPoP + PAR + RFC 8707 audience-binding is narrower than headlines suggest.
- **Don't ship a GNAP-only API in 2026.** Library support is insufficient. Offer OAuth 2.1 as well, or wait.
- **Don't write a custom GNAP server.** The spec is large and the security review surface is large. Wait for mature implementations.
- **Don't treat "negotiation" as the killer feature.** Most clients don't know how to negotiate intelligently. The fine-grained authorization and sender-constrained-by-default properties carry the practical weight.

The wait-for-vendor-support pattern is the right call for ~99% of teams in 2026.

## 12. 2024-2026 currency

- **RFC 9635 finalized late 2024** `[unverified specific month]`.
- **RFC 9700 OAuth 2.0 Security BCP May 2024** `[unverified]` — codifies OAuth 2.1 hardening and positions GNAP as the post-OAuth-2.1 trajectory.
- **MCP Anthropic 2025-11-25 spec update** — adopted OAuth 2.1 + RFC 8707 audience-binding + PKCE-S256, prohibited token-passthrough. Did not adopt GNAP. Most likely a multi-year delay before GNAP enters the MCP picture.
- **Apple PCC, Anthropic Computer Use, OpenAI Operator, Google Project Mariner** — AI-agent products that would benefit from GNAP-style fine-grained delegation. Adoption pending; all currently use OAuth 2.1 + bespoke authorization layering.
- **EU AI Act + agent-transparency requirements `[unverified specific provisions]`** — direction of regulation favors fine-grained auditable authorization, which aligns with GNAP's audit-trail and per-action grant model.
- **NIST SP 800-63-4 publication** `[unverified date]` — adjacent identity-assurance updates referencing modern authorization protocols.
- **FAPI 2.0 advanced profiles** — production deployments in UK / EU / Brazil / Australia banking through 2026. GNAP alignment discussions ongoing in the OIDF FAPI WG.

The standard is settled; the ecosystem is not.

## 13. Honest failure modes — load-bearing

1. **Adoption is research-grade in 2026.** Most production teams should not pick GNAP yet. The exceptions are narrow: a bank evaluating FAPI 3.0 successor profiles, an AI-agent platform with fine-grained-delegation security stakes, a government identity service exploring per-claim disclosure. Everyone else should wait for major IdP vendor support — Okta, Auth0, Microsoft Entra, Keycloak, Ory — before committing.
2. **Migration from OAuth 2.1 is non-trivial.** Different message model, different token format, different client libraries, different debugging surface. Coexistence is possible — many APIs will speak both for years — but each protocol carries its own ops cost.
3. **GNAP's flexibility is also its complexity.** OAuth 2.1 has roughly five grant types and a small canonical vocabulary. GNAP can express orders of magnitude more combinations of access descriptions, interaction methods, subject formats, and token bindings. Each combination is a potential interop point. Expect the production-deployed subset to be much narrower than the spec.
4. **Sender-constrained tokens require per-client key infrastructure.** DPoP keys must be generated, stored, rotated, and recovered. mTLS requires per-client certificate PKI. For server-to-server flows this is operationally tractable; for millions of consumer apps it is a real infrastructure project. Many teams will end up issuing bearer GNAP tokens to avoid the infrastructure lift, which negates the primary security advantage.
5. **The "negotiation" aspect is rarely exercised in practice.** Clients don't know how to negotiate intelligently. Most GNAP flows in production will resemble OAuth 2.1 grants because clients ask for what they want and the AS either issues it or refuses. Expect the rich counter-offer semantics to be used by sophisticated clients only.
6. **AS-to-RS protocols are evolving separately.** RFC TBD on RS Connections is the missing piece. Production deployments with multiple RS need it. Until it stabilizes, AS-RS coupling is bespoke per deployment, which undermines GNAP's portability story.
7. **Library quality is uneven.** Reference implementations exist. Production-grade libraries with security-audit track records and active maintenance commitments are sparse. Treat any GNAP library you adopt as a load-bearing dependency that needs in-house security review.
8. **OAuth 2.1 will dominate for years.** Even with GNAP available, OAuth 2.1 + RFC 9700 BCP + DPoP + PAR + JAR + RFC 8707 is "good enough" for the vast majority of authorization scenarios. The pressure to migrate will come from specific high-assurance domains, not from across-the-board OAuth replacement.
9. **The "wait for universal adoption" trap.** Teams that wait for OAuth-2.1-style ubiquity may be waiting indefinitely. GNAP may settle into niche use — FAPI successor profiles, AI-agent delegation runtimes, healthcare consent infrastructures — rather than becoming the universal next-generation OAuth. Planning should be "evaluate GNAP for specific use cases" rather than "wait for GNAP to replace OAuth."
10. **Spec drift across supporting documents.** RFC 9635 is the core, but the operationally complete GNAP picture includes RS Connections, additional interaction-method documents, and clarifying drafts. Track the WG's document set, not just the core RFC.
11. **The "we use GNAP" defense as theater.** As with every protocol upgrade, deploying GNAP without DPoP/mTLS infrastructure, without rigorous AS-RS coupling, and without scrutinizing access-request shapes produces no real security improvement over a well-configured OAuth 2.1 + DPoP deployment. Protocol choice does not substitute for authorization-architecture discipline. Cross-link `[[reference-threat-modeling-discipline]]` §15(e) "we threat-modeled it" defense.
12. **AI-agent fit is theoretical until MCP-equivalent specs adopt it.** GNAP's structural fit for AI agents is real, but adoption requires either MCP or an equivalent agent-protocol layer to mandate or recommend it. The 2025-11-25 MCP spec landed on OAuth 2.1; GNAP entry is a multi-year proposition.

## 14. Cross-link cluster

- `[[reference-session-management]]` — OAuth 2.1 §7 background; sender-constrained tokens §12 honest failure mode (rare adoption); cookie-theft-as-MFA-bypass §14.8 attack pattern that GNAP binding structurally addresses.
- `[[reference-ai-agent-session-management]]` — §7 OAuth-for-AI-agents; §3 MCP credential storage and the 2025-11-25 OAuth 2.1 adoption; §10 defense-in-depth where GNAP would sit.
- `[[reference-saml_federation]]` — adjacent federation protocol; GNAP is OAuth-lineage, SAML is the alternative federation lineage.
- `[[reference-zero-trust-workload-identity]]` — §4 workload identity (SPIFFE/SPIRE), §6 PDP/PEP architecture; GNAP fits the workload-identity story for non-SPIFFE flows.
- `[[reference-ciam-consumer-identity]]` — CIAM scenarios where GNAP could replace OAuth for fine-grained consumer-controlled disclosure.
- `[[reference-webauthn-fido2-passkeys]]` — passkey-as-primary-authentication composes with GNAP-as-authorization for high-assurance flows.
- `[[reference-secrets-management-discipline]]` — §8 OIDC trusted publishing; analogous workload-identity-federation primitives; GNAP grants are operationally adjacent to short-lived OIDC-issued credentials.
- `[[reference-cicd-supply-chain]]` — CI/CD OIDC short-lived credentials; GNAP could express finer per-job authorization.
- `[[reference-ai-assisted-coding-tool-security]]` — AI-tool authorization surface; GNAP would address the per-action authorization gap.
- `[[reference-llm-agent-security]]` — agent authorization primitives.
- `[[reference-threat-modeling-discipline]]` — §15(e) "we threat-modeled it" defense; protocol choice is not authorization architecture.
- `[[reference-hardware-attestation-chains]]` — RFC 9711 EAT integration; GNAP can carry attestation evidence in sender-constrained binding.
- `[[reference-distributed-authz]]` — Zanzibar / relationship-tuple authorization; GNAP is the protocol-layer counterpart for grant-time authorization.

## 15. Operational checklist for evaluating GNAP

Use this before committing to a GNAP project:

1. Identify the specific OAuth 2.1 limitation you are hitting. Write it down.
2. Verify OAuth 2.1 + DPoP + PAR + JAR + RFC 8707 audience-binding does not address it.
3. Confirm you have DPoP-or-mTLS infrastructure or can build it.
4. Identify production-grade GNAP library candidates and read their security-audit history.
5. Plan for OAuth 2.1 coexistence; GNAP-only is not viable in 2026.
6. Define your AS-RS coupling strategy; track RFC TBD on RS Connections.
7. Pilot on a non-critical surface; do not migrate the primary auth flow first.
8. Threat-model the access-request shapes you intend to support; the per-action descriptors are a new attack surface.
9. Plan key rotation, key recovery, and lost-key user-experience for DPoP-bound tokens.
10. Set a 12-18 month re-evaluation point; the ecosystem is moving.

If you cannot complete this checklist, defer GNAP. The OAuth 2.1 + DPoP + PAR + JAR baseline is the right place to live in 2026.
