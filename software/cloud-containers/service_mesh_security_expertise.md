# Service Mesh Security Expertise

Operator-grade reference for the **data-plane enforcement layer** sitting between L4 network reachability and L7 application code. Imperative voice; audience is a staff security engineer auditing or operating a service mesh in production, and Claude on future shifts working in that surface.

## 1. Why this doc exists

Three sibling docs ring this one, and getting the boundaries right is load-bearing:

- `[[reference-zero-trust-workload-identity]]` is **WHO** — what cryptographic identity a workload presents (SPIFFE ID, k8s ServiceAccount-bound token, cert subject). Identity issuance + verification.
- `[[reference-container-k8s-security]]` is **WHERE** policy is configured — the k8s API surface where NetworkPolicy, AuthorizationPolicy, and CRDs live.
- **This doc is HOW** packets are actually enforced — the data plane. Whether that's an Envoy sidecar, a Rust ztunnel, an eBPF program in the kernel, or a library linked into the application process.

Service mesh is the layer that handles **identity-bound mTLS + observability + traffic management + authorization** as cross-cutting infrastructure rather than per-service code. It is security infrastructure first; the "developer convenience" framing (canary deploys, traffic shifting) is a happy second-order effect.

Get this distinction right: the workload identity story tells you *what cert this workload may present*. The service mesh tells you *whether the packet carrying that cert is allowed to land*. Both have to be correct; either alone is necessary-not-sufficient.

This doc is operational. If you want the protocol-formalism treatment of mTLS, read `[[reference-cryptography]]`. If you want the OPA/Cedar policy-language treatment, read `[[reference-distributed-authz]]`. Here you get architecture, CVE patterns, and what to harden.

## 2. The architectural taxonomy

There are three architectural shapes. Pick the wrong one and the trade-offs compound for the lifetime of the deployment.

### 2.1 Sidecar mesh

Inject a userspace proxy (typically Envoy) into every pod. Application traffic is transparently captured (iptables redirect or eBPF) into the sidecar; the sidecar terminates mTLS, evaluates authorization, emits telemetry, then forwards to the application loopback.

**Examples:** Istio sidecar mode (the original and still most-deployed), Linkerd2 (Rust `linkerd2-proxy`), Consul Connect sidecar.

**Pros:** per-workload process isolation. A compromised sidecar compromises one pod, not a node. Granular policy scoping. Familiar Linux process boundaries.

**Cons:** every pod pays the resource overhead — typical Envoy sidecar is 30-80MB RSS at idle, climbing with config size; at 1000 pods that is 30-80 GB of sidecar overhead alone. Control plane must push config to N proxies, which is an O(N) scaling problem (xDS Δ-push helps but does not eliminate). Sidecar lifecycle is a real operational burden: startup ordering races, shutdown drain semantics, version skew with the control plane.

### 2.2 Sidecar-less / ambient mesh

Move the proxy off the per-pod path. Either share a node-level proxy across all workloads on the node (Istio Ambient) or push enforcement into the kernel via eBPF (Cilium Service Mesh).

**Istio Ambient Mesh:** ztunnel (Rust-written, L4-only, handles mTLS termination + identity) runs as a per-node DaemonSet. Optional waypoint proxy (Envoy-based, L7) handles per-tenant L7 policy. Reached GA in late 2024 `[unverified specific date]`.

**Cilium Service Mesh:** eBPF programs in the Linux kernel enforce L4 policy + mTLS; an embedded Envoy handles L7 features.

**Pros:** dramatically lower per-pod overhead. No sidecar startup ordering. Application doesn't see the proxy hop in `netstat`.

**Cons:** **shared-process attack surface.** The ztunnel handling traffic for tenant A and tenant B is one process on the node. Bug in ztunnel = cross-tenant compromise within node. This is genuinely new in 2024-2026 and the trust model differs from the per-pod sidecar story. Reason about it explicitly; don't assume "service mesh good, ambient mesh more-good."

### 2.3 Library mesh

Link the mesh client into the application process. No proxy hop.

**Examples:** Finagle (Twitter, the original library mesh, Scala/JVM). gRPC-go xDS client (gRPC integrates xDS natively; the application binary is the proxy).

**Pros:** no proxy hop, no resource overhead per pod, native L7 visibility into the protocol.

**Cons:** language-specific. A polyglot fleet pays the integration cost N times. No transparent injection — the application must be rebuilt to participate. Less common outside of monoglot organizations.

The library mesh shape is underused outside of large monoglot shops; for the staff-engineer audit perspective, treat it as an outlier and focus the threat model on sidecar + ambient.

## 3. Istio

The most-deployed service mesh in production.

### 3.1 Origin

Joint project of Google + IBM + Lyft, announced May 2017. Architectural lineage from Google's internal infrastructure (load-balancer mesh) and Lyft's Envoy. Lin Sun (IBM, then Tetrate) and Louis Ryan (Google) drove the early design alongside Eric Brewer (Google, of CAP-theorem fame). Donated to CNCF September 2022 after a long governance dispute.

### 3.2 Architecture

- **istiod** — consolidated control plane (since 1.5). Previously split into Pilot (config push), Citadel (cert issuance), Galley (config validation), Mixer (telemetry, now deprecated and removed).
- **Envoy sidecars** — data plane in sidecar mode. Configured via xDS over gRPC.
- **CNI plugin** (optional, recommended) — replaces the legacy iptables-redirect init-container with a CNI-based traffic capture. The init-container approach was a privileged container that became its own CVE class.
- **Citadel-merged-into-istiod** — SPIFFE-format certs issued to every workload; default 24h cert lifetime.

### 3.3 Istio Ambient Mesh

The 2024 architectural shift, championed publicly by Christian Posta (Solo.io) and John Howard (Google, Istio):

- **ztunnel** — Rust-written L4 proxy, runs as DaemonSet, one per node. Handles HBONE (HTTP-Based Overlay Network Encapsulation, an HTTP/2 CONNECT tunnel that carries the mTLS handshake). Identity-aware at L4 but does not parse L7.
- **waypoint proxy** — Envoy-based, opt-in, per-namespace or per-service-account. Handles L7 authorization, traffic management, complex routing. Sits on the node-to-node path when L7 policy is required.

The security trade-off is explicit and new: ztunnel handles traffic for every workload on its node in one process. Memory-safety language choice (Rust) is a deliberate hedge against the historical Envoy CVE pattern, but does not eliminate logic bugs that cross tenants.

### 3.4 Authorization primitives

- **AuthorizationPolicy** — allow/deny rules on source (principal, namespace, IP), destination (operation, paths, methods), and conditions (headers, JWT claims). The primary k8s-native authz CRD.
- **PeerAuthentication** — mTLS mode per workload/namespace: `DISABLE`, `PERMISSIVE` (accept both mTLS and plaintext), `STRICT` (mTLS only). Configures how the proxy treats incoming connections.
- **RequestAuthentication** — JWT validation at the data plane. Verifies signature, claims, audience; results feed into AuthorizationPolicy conditions.

The precedence rules are operationally non-obvious. AuthorizationPolicy evaluation: DENY rules first; then if any ALLOW rule matches, allow; if any ALLOW rules exist for the workload but none match, deny by default. Workload-with-no-ALLOW-rules has default ALLOW. This last clause is a footgun — adding the first ALLOW rule flips the default for that workload from allow-all to deny-by-default.

### 3.5 CVE corpus

- **CVE-2024-9026** — Envoy access-log truncation under certain conditions; observability bypass. Patched in Istio 1.22.4 / 1.23.1.
- **CVE-2024-3727** — `containerd` image-tag-validation in the init container path; supply-chain class.
- **CVE-2023-44487** — HTTP/2 Rapid Reset; cross-vendor (Envoy, nginx, HAProxy, every HTTP/2 implementation). Disclosed Oct 2023 by Cloudflare, Google, AWS jointly. Mesh impact: every Envoy-based proxy required emergency patching.
- **CVE-2022-23635** — Istiod denial-of-service via crafted JWT during RequestAuthentication processing.
- **CVE-2022-21679** — auth-policy bypass class.
- **CVE-2021-39156** — AuthorizationPolicy bypass via path-normalization confusion. Path `/admin/../public` could match an ALLOW for `/public` while landing on `/admin`. The fix forced normalization before policy evaluation.

The 2021-2024 CVE lineage shows the same shape repeatedly: a discrepancy between what the proxy parses (for policy matching) and what the application sees (after URL-decode, normalize, or strip). Audit any custom EnvoyFilter that touches headers or paths with this discrepancy in mind.

### 3.6 Operational footguns

- **PERMISSIVE mTLS as a migration mode.** Intended for the weeks-long migration window where some workloads have sidecars and some don't. Operations teams leave it there for years. PERMISSIVE means *the mesh accepts plaintext from anyone who claims to be in the cluster*. The migration is not complete until every namespace is STRICT.
- **Wildcard hosts in VirtualService.** A VirtualService binding `hosts: ["*"]` to a Gateway catches more than the operator expects, including health-check probes and metric scrapers.
- **EnvoyFilter as a sharp tool.** EnvoyFilter writes raw Envoy config into the data plane. Mis-ordered filters bypass authz; mis-typed config crashes proxies cluster-wide on push.

## 4. Linkerd

The "do less, do it safely" mesh.

### 4.1 Origin

William Morgan and Oliver Gould, founders of Buoyant, shipped Linkerd 1.x on Twitter's Finagle (Scala/JVM). Linkerd 1.x is deprecated. Linkerd2 (announced 2018, renamed back to "Linkerd" for marketing) is a complete rewrite: Go control plane, **Rust data plane** (`linkerd2-proxy`).

### 4.2 Rust data plane as security differentiator

This is the load-bearing security claim. The 2020-2024 CVE corpus for service mesh data planes is dominated by Envoy (C++): HTTP/2 parsing bugs, integer overflows in filter chains, header-handling crashes, use-after-free in connection lifecycle. A memory-safe data plane in Rust does not eliminate logic bugs but cuts the most-common CVE class.

Linkerd's published CVE count is dramatically lower than Istio's in the 2020-2024 window `[unverified specific count]`. Some of this is feature-surface ("Istio does more things") but the data-plane language choice is real. If your threat model centers data-plane memory corruption, Linkerd has an honest claim.

### 4.3 Architecture

Lightweight by design. Fewer CRDs, fewer config surfaces, less to misconfigure. The proxy is opinionated: HTTP/1, HTTP/2, gRPC, opaque TCP. No filter chain like Envoy; no scripting extension; no WASM filters. This is intentional and is the security marketing.

### 4.4 Authorization primitives

- **Server** — declares a port + protocol on a workload as policy-managed.
- **ServerAuthorization** — declares which clients (by mesh identity or network policy) may reach a Server.
- **MeshTLSAuthentication** — mTLS-identity-based authn primitive.
- **NetworkAuthentication** — network-CIDR-based authn primitive (for unmeshed clients).

The CRD shape is more granular than Istio's AuthorizationPolicy but the operational ceiling is lower — there is less rope to hang yourself with.

### 4.5 What Linkerd doesn't do

Worth saying explicitly: Linkerd does not do general L7 traffic management at the level Istio does. No EnvoyFilter, no WASM, no ext_authz at the proxy level (it can be configured but is less idiomatic). If you need a full L7 policy engine integrated into the data plane, Istio is the answer; if you want a minimal correct mTLS + authz mesh, Linkerd is.

## 5. Envoy as the substrate

Matt Klein (Lyft, 2016) created Envoy. CNCF Graduated 2018. Every major mesh except Linkerd uses Envoy as the data plane. Envoy's security posture is therefore the substrate security posture of most production meshes.

### 5.1 Why everyone uses Envoy

- **xDS** — the Discovery Service protocol (LDS, RDS, CDS, EDS, SDS) is the standard config-push mechanism. Istio, Consul, Cilium, and Kong all speak xDS.
- **Protocol coverage** — gRPC, HTTP/1.1, HTTP/2, HTTP/3 (QUIC) native. WebSocket. TCP. UDP.
- **Filter chain extension model** — chained L4 and L7 filters with well-defined ordering.
- **Production-hardened** — Lyft, Google, Apple, Reddit, Stripe, every major CDN.

### 5.2 Envoy CVE history is your mesh's CVE history

When Envoy patches, every Envoy-based mesh has to roll. The cadence is high: Envoy ships security advisories roughly monthly. Selected high-impact:

- **CVE-2023-44487** (HTTP/2 Rapid Reset) — cross-vendor; the most consequential single CVE for service mesh in the last three years.
- **CVE-2024-32974 / CVE-2024-32975 / CVE-2024-32976** — multi-CVE Envoy security release May 2024 `[unverified specific batch attribution]`.
- **CVE-2022-29225 / -29226 / -29227 / -29228** — multi-CVE DoS class (decoding errors, hash-table collisions, oversized headers).
- **CVE-2020-25018** — auth bypass via uppercase Host header; classic case-normalization discrepancy.

### 5.3 xDS as attack surface

The xDS server (Istiod, Consul control plane, Cilium operator, Kong Gateway control plane) is the highest-trust path in the mesh. Compromise of the xDS server = ability to push arbitrary config to every proxy = own every proxy in the mesh.

Harden the control plane like an HSM. Specifically:

- mTLS for xDS itself, with a separate trust anchor from data-plane mTLS.
- ServiceAccount-bound tokens for xDS client authentication (not long-lived service-account tokens).
- Audit logging on every config push.
- Pin the control plane image SHA; the supply chain on the control plane image is the supply chain for the whole mesh.

### 5.4 Filter chain ordering

Envoy filters run in declared order. A misordered chain — e.g., applying `ext_authz` *after* `lua` script execution that has already mutated the request — can produce authorization decisions on data the application never sees. Audit filter chains by reading the effective config (`/config_dump`), not the input YAML; mesh control planes mutate filter chains in non-obvious ways.

The canonical correct filter chain ordering for L7 HTTP traffic:

1. **Network filters** — `envoy.filters.network.tls_inspector` (peek at TLS without terminating), `envoy.filters.network.http_connection_manager`.
2. **HTTP filters in order:** `envoy.filters.http.cors` → `envoy.filters.http.jwt_authn` → `envoy.filters.http.rbac` → `envoy.filters.http.ext_authz` → custom Lua / WASM → `envoy.filters.http.router`.

`jwt_authn` before `ext_authz` so external authz sees a verified JWT. RBAC before ext_authz so cheap deny decisions short-circuit expensive external policy calls. Lua / WASM filters last (before the router) so that any header mutations they perform happen *after* the authz decision, not before — otherwise a Lua filter that strips `Authorization` headers will bypass downstream JWT validation.

### 5.5 WASM filters as an extension model and a risk surface

Envoy supports WASM-based filters (Proxy-Wasm spec) for custom data-plane logic without rebuilding Envoy. The security trade-off: WASM modules ship outside the Envoy CVE/patch cycle. A vulnerable WASM filter is the operator's problem to maintain.

Treat WASM filters like any other untrusted code: supply-chain attest the binary, pin SHA, sandboxing limits are Envoy-version-dependent. Cross-link to `[[reference-webassembly-security]]` for the Wasm runtime threat model.

## 6. Consul Connect (HashiCorp)

Armon Dadgar and Mitchell Hashimoto (HashiCorp). Consul started as service discovery + KV store; Connect added the mTLS + service-to-service primitive.

### 6.1 Architecture

- **Sidecar mode (Envoy)** — same shape as Istio sidecar.
- **Native (lib-based) mode** — Go applications can link the Consul SDK and skip the sidecar.
- **Multi-DC + multi-cloud federation** — the differentiator. Consul federates across data centers and cloud providers natively, with WAN gossip.
- **Consul as discovery + KV + connection-secrets** — one component does service discovery, distributed config, and Connect.

### 6.2 Authorization

- **Intentions** — source service + destination service + allow/deny. Simpler than AuthorizationPolicy; no path/header/JWT conditions at the Intention level (those live in higher-level configs).
- **Service Defaults / Proxy Defaults** — global config knobs.

### 6.3 ACLs as the load-bearing primitive

Consul's ACL system is the operational center of gravity, distinct from Istio's CRD-driven model. Tokens carry policies; policies grant permissions on resource prefixes; node-tokens are separate from service-tokens. The historical Consul incident pattern is **default-allow ACLs in production** — the `acl.default_policy = "allow"` setting that ships in development quickstarts and persists into production. With default-allow, any agent that reaches the Consul gossip port has read access to the service catalog and KV store.

The operational hardening posture:

- `acl.default_policy = "deny"` in every non-quickstart environment.
- ACL tokens scoped to specific service identities, not bearer tokens shared across services.
- Bootstrap token (the first token, generated at `consul acl bootstrap`) stored as a one-time credential, not a long-lived operational secret.
- Gossip encryption key rotated on a schedule.

### 6.4 CVE corpus

HashiCorp's Consul CVE history is `[unverified specific recent CVEs]`; the high-impact pattern has historically been ACL token leakage, gossip-protocol denial-of-service, and Envoy proxy CVEs propagating through Connect (since Connect uses Envoy). Consul's data-plane CVE surface is therefore inherited from Envoy — same patch cadence considerations as §5.2.

### 6.5 Federation as both a feature and a threat surface

WAN federation across data centers is the Consul differentiator. The threat surface: WAN-federated clusters share a trust domain via cross-signing; compromise of one DC's CA compromises the cross-signed trust into other DCs. Treat the WAN-federation CA as a higher-trust artifact than per-DC CAs.

## 7. Cilium Service Mesh + eBPF data plane

Thomas Graf and Daniel Borkmann (Isovalent, ~2016) created Cilium. CNCF Graduated 2023. Acquired by Cisco April 2024. Liz Rice (Isovalent, previously Aqua Security) is the most-visible public face.

### 7.1 eBPF as data plane

The architectural bet: push packet enforcement into the Linux kernel via eBPF programs. No sidecar process; the kernel itself is the data plane. CNI (container networking) and service mesh in one binary.

**Tetragon** is the runtime detection sibling — eBPF programs that observe syscalls, file access, network connections — cross-link to `[[reference-container-runtime-escape]]` §11.

### 7.2 Trust model shift

The trust boundary moves into the kernel. eBPF programs run with kernel privileges; bugs in the eBPF verifier or in unsafe-helpers expose the host. The eBPF program supply chain is now load-bearing:

- Signed eBPF programs (BPF signing, in development through 2024-2026).
- Kernel BTF (BPF Type Format) for ABI stability across kernel versions.
- Kernel-version compatibility constraints; eBPF programs targeting kernel 6.x do not run on RHEL 8's 4.18.

### 7.3 L7 limitations

eBPF can parse simple L7 protocols (HTTP/1, DNS) in-kernel but complex L7 features (gRPC frame parsing, JWT validation, intricate routing) still delegate to a userspace Envoy. Cilium's "service mesh" in practice is eBPF L4 + Envoy L7. The eBPF claim is real for L4 + identity but not for full L7 policy.

### 7.4 Cilium Network Policy

- **CiliumNetworkPolicy** — extends k8s NetworkPolicy with L7 rules (HTTP method, path, header conditions).
- **CiliumClusterwideNetworkPolicy** — cluster-scoped variant.

Audit gotcha: a CiliumNetworkPolicy at L7 only applies if the relevant traffic is being proxied through the Cilium Envoy; pure eBPF L4 enforcement skips L7 inspection. The "Did this policy actually apply?" question requires checking enforcement mode.

### 7.5 Hubble as the observability layer

Hubble is the Cilium-native observability stack — built on the same eBPF programs, surfaces flow logs, drops, policy decisions, and DNS resolutions in real time. From a security perspective, Hubble's value is that it sees *every* connection on the node, including connections that bypass the userspace proxy. This is observability into the eBPF L4 enforcement path that does not exist for sidecar meshes.

The trade-off: Hubble's relay component aggregates flows across nodes; the relay's network exposure and authentication posture become security-relevant. Treat Hubble Relay like any other cluster-wide telemetry aggregator: mTLS, AuthN required, no exposed ingress.

### 7.6 WireGuard transport-encryption option

Cilium supports WireGuard as a transparent transport-encryption layer between nodes, distinct from mesh-level mTLS. WireGuard handles node-to-node encryption at the kernel level; mTLS still handles workload identity. This is double-encryption (WireGuard outer, mTLS inner) for high-assurance deployments — accept the modest CPU cost; the defense-in-depth is real for hostile-network threat models.

## 8. Kubernetes Gateway API (replacing Ingress)

Kubernetes Gateway API reached GA in K8s 1.29 (December 2023). The Ingress resource is now legacy.

### 8.1 Resource model

Three CRD kinds at the core:

- **GatewayClass** — analogous to StorageClass. Declares an implementation (NGINX, Envoy Gateway, Cilium Gateway, Contour, Kong, Traefik).
- **Gateway** — an instance of a GatewayClass. Listeners on ports, TLS config, hostname binding.
- **HTTPRoute** (+ **TCPRoute**, **GRPCRoute**, **TLSRoute**) — route definitions, attached to Gateway listeners.

The role-separation is intentional: cluster operators manage GatewayClass + Gateway; application teams own HTTPRoutes for their namespaces. This is a security improvement over Ingress, which conflated infrastructure and application concerns in one resource.

### 8.2 Per-controller security posture differs

Gateway API implementations vary widely:

- **NGINX Gateway Fabric** — the new NGINX Gateway API implementation (distinct from NGINX Ingress Controller).
- **Envoy Gateway** — CNCF-incubating, Envoy-native.
- **Contour** — Bitnami/VMware, Envoy-based.
- **Kong Gateway** — Kong's commercial offering.
- **Cilium Gateway** — eBPF + Envoy.
- **Traefik** — Go-native.
- **Istio Gateway (via Gateway API)** — Istio supports both its own Gateway CRD and the upstream Gateway API.

Each has its own default TLS posture, default header sanitization, CVE patch cadence, and idiosyncratic annotation/extension behavior. Treat the choice of GatewayClass as a security decision, not a developer-tooling decision.

### 8.3 NGINX Ingress Controller as the cautionary anchor

The legacy NGINX Ingress Controller (`ingress-nginx`, the most-deployed K8s ingress controller historically) has the worst CVE history of any mesh-adjacent component.

**IngressNightmare** (Wiz Research, March 2025): CVE-2025-1974, CVE-2025-1097, CVE-2025-1098, CVE-2025-1973. Wiz reported approximately 30% of all k8s clusters reachable from the internet had vulnerable NGINX Ingress controllers at disclosure `[unverified exact percentage]`.

The pattern of the bug is general: the controller code parses Ingress annotations into NGINX config blocks via Go-template substitution. Untrusted Ingress annotations get rendered into nginx config. Annotation-injection → arbitrary nginx directives → full control-plane RCE because the controller has cluster-admin-ish privileges to read Secrets across namespaces.

This is the bug pattern to watch for in *every* ingress/gateway controller: any code path that takes user-supplied annotations and renders them into a config language has the same shape, with the same fix (treat annotations as data, not code).

## 9. mTLS + identity binding

### 9.1 Two distinct claims

Conflate these and you lose:

- **(a) mTLS encrypts traffic and verifies cert chains.** Achievable with a self-signed CA, distributed certs, and mTLS-required listeners. Defeats passive eavesdropping. Does not defeat a workload that legitimately holds a cert but should not be talking to this destination.
- **(b) The cert subject is bound to a verified workload identity** (SPIFFE ID, k8s ServiceAccount). Requires the full workload-identity story from `[[reference-zero-trust-workload-identity]]`: short-lived cert issuance, identity-attesting issuance flow, no offline cert generation.

A service mesh that claims "mTLS everywhere" without claim (b) provides defense-in-depth against network sniffing but does not provide authorization. The cert is just a TLS handshake artifact; the authorization decision must reference the workload identity.

### 9.2 Cert rotation

- **Istio Citadel-in-istiod** — default 24h cert lifetime; rotation via SDS (Secret Discovery Service, an xDS variant).
- **Linkerd** — default 24h workload cert, root CA 365d; `linkerd identity` is the issuer.
- **Consul Connect** — default 72h leaf cert.

The principle: cert lifetime should be ≤ the TLS session-resumption ticket lifetime, so that revocation propagates within roughly one cert generation. A 7-day cert with no revocation list means a stolen cert is usable for 7 days regardless of any revocation action.

### 9.3 Trust domain federation

SPIFFE Federation across meshes is the federation primitive: each trust domain publishes a SPIFFE Trust Bundle, and federated meshes verify the other's bundle. Multi-cluster Istio offers two shapes:

- **Shared root CA across clusters** — simpler, but cluster compromise compromises the root CA.
- **Federation mode (per-cluster CA, federated trust bundles)** — operationally harder, but cluster compromise is bounded.

The federation-mode shape is the correct default for multi-cluster deployments. Avoid sharing a root CA across non-production and production environments — see §14.10.

## 10. Authorization at the mesh

### 10.1 Layered authorization

Defense-in-depth across three layers:

- **L4 NetworkPolicy (k8s native)** — IP/port reachability. Coarse; doesn't see TLS-encrypted payload.
- **L7 service mesh authz** — Istio AuthorizationPolicy, Linkerd ServerAuthorization, Consul Intentions, Cilium CiliumNetworkPolicy. Operates on identity (cert subject) + L7 fields (method, path, headers, JWT claims).
- **Application-level authz** — the business-logic authorization the application itself performs. Should be assumed-present; the mesh doesn't know what "user can read their own document but not someone else's" means.

Each layer has its own failure mode. Don't conflate them or assume one substitutes for another.

### 10.2 ext_authz integration

Envoy's `ext_authz` filter externalizes the authz decision to a PDP (policy decision point), typically:

- **OPA** (Open Policy Agent) — Rego policy language.
- **Cedar** — AWS's policy language.
- **Custom gRPC service** — author your own.

Cross-link to `[[reference-zero-trust-workload-identity]]` §6 (PDP/PEP) and `[[reference-distributed-authz]]` for the policy-language treatment.

### 10.3 The "authorize on the wrong field" failure

The most-common service-mesh authz failure: authorize on a synthesizable HTTP header instead of a cryptographically-verified identity.

A request enters via an ingress gateway that strips and re-sets the `X-User-Id` header from JWT claims. A downstream policy authorizes on `X-User-Id`. An attacker who can reach the destination service through any path that doesn't go through that gateway can set `X-User-Id` themselves, because the destination service is trusting an HTTP header instead of a cert subject or a cryptographically-verified JWT.

**Authorize on the cert subject (SPIFFE ID, or Istio's `source.principal`) for service-to-service. Authorize on JWT claims, verified at the destination, for end-user identity.** HTTP headers set by upstream proxies are advisory; they are not authentication.

## 11. Observability + supply chain

### 11.1 Observability as security signal

Every mesh emits per-connection logs: source identity, destination, mTLS verification result, authorization decision, latency, response code. This is the security telemetry corpus for the mesh. Cross-link to `[[reference-detection-engineering]]` §10 (OpenTelemetry semantic conventions for service-to-service traffic).

Absence of telemetry is absence of visibility. Mesh deployments that disable access logging to save log-storage cost give up the only authoritative record of what crossed the data plane. Sample if you must, but don't disable.

The mesh-specific fields to ingest into the SIEM and to write detections against:

- **source.principal / destination.principal** — the SPIFFE-format identity. Detect unexpected pairs; detect new principals appearing.
- **connection.mtls** — boolean; the alert here is "false in a STRICT namespace."
- **response_flags** — Envoy emits short codes (`UAEX` external authz denial, `RBAC` denied by RBAC filter, `URX` upstream retry exhausted). These are the highest-signal alerts.
- **request.headers and request.path** — for the L7 detection layer.
- **upstream.cluster** — where the proxy ultimately routed; useful for routing-audit detections.

### 11.2 Distributed tracing as security context

W3C TraceContext propagation through the mesh means every request gets a span. From a security perspective, traces give you cross-service request reconstruction: a single user-facing request that touched 12 services is one trace with 12 spans. Detection rules can hunt across whole request paths rather than per-hop.

Trace propagation also leaks information — a leaked TraceContext header can be used by an attacker who has reached one service to correlate their requests with a victim's session. Sanitize TraceContext at the ingress gateway when crossing trust boundaries.

### 11.3 xDS server as supply chain

Restated from §5.3 because it's the load-bearing point: the xDS server is the highest-trust path in the mesh. Treat it as a HSM-equivalent component.

- Pin the control-plane container image by SHA-256 digest, not tag.
- Verify image signatures (cosign + Sigstore Fulcio) — cross-link to `[[reference-supply-chain-provenance]]`.
- Audit every config-push event.
- Network-isolate the control plane from workload traffic.

### 11.4 eBPF program supply chain (for Cilium-class)

The eBPF program loaded into the kernel is the data plane. Its provenance matters:

- Kernel BTF for ABI stability — load-bearing for production.
- Signed eBPF (`bpf_sig`, in-tree work) — the maturing supply-chain primitive.
- Kernel-version compatibility — verify before rolling.

### 11.5 Sidecar image supply chain

In sidecar meshes, every pod pulls the proxy image. Compromise of the proxy image = compromise of every pod. Pin image SHAs in the mesh control plane configuration (Istio's `image: <hash>` rather than `image: <tag>`).

The mesh control plane typically *also* injects the sidecar image via mutating admission webhook (Istio's sidecar-injector, Linkerd's proxy-injector). The admission webhook is itself a control-plane component with cluster-wide pod-mutation authority. Treat the injector webhook like the xDS server: pinned image, audit-logged, restricted egress, mTLS to its own webhook endpoint.

## 12. 2024-2026 currency

What changed recently and what matters operationally:

- **Istio Ambient Mesh GA, late 2024** `[unverified specific date]` — shifts the trust boundary from per-pod sidecar to node-level ztunnel. New attack surface, new threat model. If you are evaluating Ambient, re-read §2.2 and §3.3.
- **HTTP/2 Rapid Reset cross-vendor patch (CVE-2023-44487, Oct 2023)** — every Envoy-based mesh patched. The episode demonstrated the operational reality: when Envoy patches a critical CVE, every downstream mesh ships an emergency release within days.
- **IngressNightmare (Wiz Research, March 2025)** — CVE-2025-1974 et al.; NGINX Ingress Controller; ~30% of internet-reachable k8s clusters affected `[unverified specific percentage]`. The single highest-impact mesh-adjacent incident of 2025.
- **Kubernetes Gateway API GA in K8s 1.29 (Dec 2023)** — Ingress is now legacy. Multi-controller surface expands the audit footprint.
- **Cilium 1.16+ Gateway API + Service Mesh** — eBPF mesh maturing; Cisco acquisition of Isovalent (April 2024) accelerated this.
- **Policy-as-CRD convergence across Istio + Linkerd + Cilium** — the operational pattern is stabilizing: declarative policy CRDs reviewed in pull requests, applied via GitOps. Cross-link to `[[reference-cicd-supply-chain]]`.
- **mTLS adoption in serverless (Knative, AWS Lambda mTLS for VPC endpoints, Cloud Run service-to-service mTLS)** — the workload-identity story is following the mesh out of k8s into managed serverless. Cross-link to `[[reference-zero-trust-workload-identity]]` §10.

## 13. Real-incident corpus

The incidents to know:

### 13.1 IngressNightmare (March 2025)

**CVE-2025-1974, CVE-2025-1097, CVE-2025-1098, CVE-2025-1973.** Reported by Wiz Research. NGINX Ingress Controller (`ingress-nginx`). Annotation-injection in `nginx-snippets-annotations` and related fields rendered untrusted user input into nginx config, yielding RCE on the ingress controller pod. Because the ingress controller has cluster-wide Secret read access, the blast radius is *every secret in the cluster*.

**Lesson:** any controller that templates user-supplied annotations into a config DSL has this bug latent. Audit the controller's annotation handling code path. Disable snippet annotations by default if not needed.

### 13.2 HTTP/2 Rapid Reset (October 2023)

**CVE-2023-44487.** Cloudflare, Google, AWS joint disclosure. Attacker abuses HTTP/2 stream-reset to force the server to allocate-then-free per-stream state at unbounded rate, exhausting CPU. Affected every HTTP/2 implementation: Envoy, nginx, HAProxy, Apache, Go net/http, .NET, Node.

**Mesh impact:** every Envoy-based mesh shipped emergency patches within 5-7 days. The episode is the canonical example of "Envoy CVE = my-mesh CVE."

### 13.3 Istio AuthorizationPolicy bypass class

**CVE-2021-39156** — path-normalization discrepancy: `/admin/../public` matched an ALLOW for `/public` while landing on `/admin`.
**CVE-2022-23635** — Istiod DoS via crafted JWT during RequestAuthentication.
**CVE-2024-9026** — Envoy access-log truncation; observability bypass.

The pattern: any discrepancy between what the proxy parses for policy and what the application sees becomes a bypass primitive. Path normalization, header case, JWT validation, all share this shape.

### 13.4 NSA-CISA Service Mesh and Kubernetes guidance

**NSA-CISA Kubernetes Hardening Guide** (Aug 2021, v1.2 Aug 2022); follow-up service-mesh-specific guidance `[unverified specific 2023-2024 update date]`. Federal-mandate baselines for service mesh deployment in regulated environments. Treat as a checklist, not a ceiling.

### 13.5 Sysdig / Wiz / Aqua cloud-native threat reports

Annual reports surface the mesh-related findings in the wild: misconfigured AuthorizationPolicies, PERMISSIVE mTLS lingering for years, public-internet-exposed istiod, ingress controllers with known CVEs in the wild `[unverified specific 2024-2025 stat]`.

### 13.6 Istiod-exposed-to-internet pattern

A recurring finding in cloud-native posture-management scans: istiod (or the equivalent Linkerd / Consul control plane) reachable from the public internet via mis-scoped LoadBalancer service, mis-scoped Gateway, or naked NodePort. The control plane is supposed to be cluster-internal-only; the moment it's reachable, every CVE in the control plane is exploitable from anywhere.

Posture audit: enumerate every Service of type LoadBalancer in the cluster; cross-reference against the control-plane namespace. If istiod's xDS port is reachable from the internet, treat as a P0.

### 13.7 The Envoy header-handling lineage

Quietly load-bearing: Envoy has shipped multiple header-handling CVEs over 2020-2024 that share a shape — case sensitivity, header injection via newline, header duplication semantics. CVE-2020-25018 (uppercase Host bypass), and several CVE-2021/CVE-2022 entries in the same family. The fix pattern is canonicalization-before-policy, and audit teams should treat any custom header-mutating filter as in-scope for the same class of bug.

Cross-link to `[[reference-http-request-smuggling]]` — the request-smuggling primitive surface and the header-mutation surface overlap considerably at the mesh-proxy layer.

## 14. Honest failure modes — load-bearing section

This is the section to re-read every time you audit a mesh. Mesh adoption is in a happy-path-marketing era; the failure modes below are what actually goes wrong.

### 14.1 "We have a service mesh" ≠ zero trust

The mesh provides primitives: mTLS, AuthorizationPolicy CRDs, observability hooks. If you do not write the policies, you have mTLS-encrypted plaintext-equivalent traffic. The marketing diagram shows zero trust; the production cluster has mTLS-and-allow-all.

Audit posture: count AuthorizationPolicy / Server / Intention objects in the cluster. If the count is suspiciously low relative to service count, you have mTLS without authorization.

### 14.2 PERMISSIVE mTLS as long-lived migration mode

The single most-common operational anti-pattern in Istio deployments. PERMISSIVE was designed for the multi-week migration window where some workloads are meshed and some aren't. It becomes permanent.

PERMISSIVE means *plaintext traffic from unmeshed sources is accepted*. The mesh is not enforcing identity; it is offering identity to those who ask. Get to STRICT, in production, in every namespace. If you cannot, you do not have a mesh-enforced identity story.

### 14.3 Authorize on HTTP headers ≠ authorize on identity

Reiterated from §10.3 because it shows up in incident reviews repeatedly. HTTP headers are set by whatever in the request path chose to set them. The mesh's job is to bind requests to cryptographically-verified identities; using identity is the whole reason to deploy a mesh.

### 14.4 xDS-server compromise = mesh-wide compromise

Reiterated from §11.2. The control plane is the highest-trust component. Treat istiod / Consul control plane / Cilium operator / Linkerd control plane as security-critical infrastructure. Monitor it, isolate it, audit-log it, pin its image SHA.

### 14.5 Sidecar memory overhead is real

A 50-80MB Envoy sidecar × 1000 pods is 50-80 GB of sidecar overhead. At scale this is significant cost. Operator pushback against mesh adoption is sometimes rooted in legitimate operational concern, not security ignorance. Ambient meshes (ztunnel) and library meshes (gRPC xDS) reduce this but shift the trust boundary.

Plan capacity. Budget for the sidecar. If your platform team won't fund the overhead, you will get partial mesh adoption, which means PERMISSIVE forever (§14.2).

### 14.6 Ambient mesh tenant isolation is new

Per-pod sidecars provided process-level isolation: a bug in one sidecar compromises that pod, not the node. Node-level ztunnel shares a process boundary across every tenant on the node. The trust model changed in 2024.

The Rust language choice for ztunnel is a deliberate hedge; it does not eliminate logic bugs that cross tenants. Reason about your isolation requirements explicitly before adopting Ambient for multi-tenant workloads.

### 14.7 CVE patch cadence on the data plane is high

Envoy ships security advisories on a roughly monthly cadence. "Deploy mesh once, leave it" is a vulnerable mesh. Operational hygiene:

- Pin the proxy image SHA to a recent build.
- Have a rolling update process for sidecars that completes within days of a Critical CVE.
- For ambient meshes, the ztunnel DaemonSet rolling update is on-node-restart-equivalent; plan for it.

### 14.8 Ingress controllers are the soft underbelly

NGINX Ingress Controller has been the most-deployed K8s ingress controller and has the worst CVE history of any mesh-adjacent component. IngressNightmare (§13.1) was not the first NGINX Ingress controller CVE class and will not be the last.

If you can move to a Gateway API implementation with a smaller attack surface (Envoy Gateway, Cilium Gateway, Contour), the migration is a security win independent of the feature story.

### 14.9 eBPF-based meshes shift the trust boundary into the kernel

A bug in an eBPF program plus a verifier limitation equals node compromise. The eBPF verifier is robust but not infallible — verifier bypasses have shipped (`[unverified specific CVE-XXXX-YYYY]`). Cross-link to `[[reference-linux-kernel-exploitation]]` for the kernel-side threat model.

eBPF program supply chain (signing, BTF compatibility) is the new substrate to harden. Treat the eBPF program loader as security-critical.

### 14.10 mTLS-with-self-signed-anchor anti-pattern

A self-signed root CA generated once at install time, shared across non-production and production, never rotated. The "we have mTLS" claim is technically true; the security claim is hollow.

Operate the mesh root CA with the same discipline as a PKI root: hardware HSM if possible, offline root with online intermediates, rotation discipline, separate trust domains for production and non-production. Cross-link to `[[reference-secrets-management-discipline]]` §9 and `[[reference-cryptography]]` §11 for key-management discipline.

### 14.11 Mesh + WAF + L4 firewall = layered, not redundant

Each layer catches different things. The WAF parses HTTP and looks for attack signatures; the mesh authorizes on identity; the L4 firewall enforces network reachability. Don't fold one into another. The mesh is not a WAF (despite some marketing); the WAF is not a mesh; both are necessary in defense-in-depth posture.

## 15. Cross-link cluster

This doc lives inside the sibling-doc ring:

- `[[reference-zero-trust-workload-identity]]` — WHO; the identity issued to a workload that the mesh enforces.
- `[[reference-container-k8s-security]]` — WHERE; the k8s API surface where mesh policies are configured.
- `[[reference-container-runtime-escape]]` — the container-boundary attack surface beneath the mesh.
- `[[reference-cloud-iam]]` — IAM for the cloud account hosting the cluster; mesh CRDs cannot enforce against IAM-level take-over.
- `[[reference-secrets-management-discipline]]` — root CA + cert key custody for the mesh PKI.
- `[[reference-detection-engineering]]` — turning mesh telemetry into detection rules; OpenTelemetry semantic conventions.
- `[[reference-linux-kernel-exploitation]]` — eBPF data-plane threat model; verifier escapes.
- `[[reference-cicd-supply-chain]]` — GitOps for mesh policy; pull-request review of AuthorizationPolicy CRDs.
- `[[reference-threat-modeling-discipline]]` — the mesh is a control; threat-model what it does and does not mitigate.
- `[[reference-distributed-authz]]` — OPA/Cedar policy languages used at the mesh via ext_authz.
- `[[reference-dns-network-infrastructure]]` — network-layer concerns beneath the mesh.
- `[[reference-http-request-smuggling]]` — request-smuggling primitives that bypass mesh authz parsers.
- `[[reference-cryptography]]` — TLS protocol, cert chain validation, PKI.
- `[[reference-confidential-computing]]` — mesh-in-TEE deployments for hostile-substrate threat models.
- `[[reference-supply-chain-provenance]]` — cosign + Sigstore for mesh control-plane image attestation.

## 16. Operator checklist

For the staff-security-engineer audit of a mesh deployment, run this list:

1. Identify the data-plane shape: sidecar / ambient / eBPF / library. Trust model differs per shape (§2, §14.6, §14.9).
2. Confirm STRICT mTLS in every production namespace. If PERMISSIVE, get to STRICT (§14.2).
3. Count AuthorizationPolicy / Server / Intention objects relative to service count. Low count = mTLS without authz (§14.1).
4. Verify authorization is on cert subject / SPIFFE ID / verified JWT — not on synthesizable HTTP headers (§10.3, §14.3).
5. Audit the xDS server: image SHA pinned, signed image, network-isolated, audit-logged (§5.3, §11.2, §14.4).
6. Audit the mesh root CA: HSM-backed if possible, separate per environment, rotation discipline (§9, §14.10).
7. Verify ingress / Gateway API controller is patched: IngressNightmare, current Envoy CVEs (§8.3, §13.1, §14.8).
8. Confirm sidecar / proxy image is pinned by SHA and on a recent Envoy build (§5.2, §11.4, §14.7).
9. Confirm telemetry (access logs, mTLS verification logs, authorization decision logs) is flowing into the SIEM (§11.1).
10. For Ambient deployments: reason explicitly about ztunnel tenant isolation; the trust boundary moved (§14.6).
11. For eBPF-based meshes: verify eBPF program provenance, kernel version compatibility (§7, §11.3, §14.9).
12. Review the migration history: PERMISSIVE windows, recent CVE patch cadence, control-plane upgrade history. Long-stale config is vulnerable config.
