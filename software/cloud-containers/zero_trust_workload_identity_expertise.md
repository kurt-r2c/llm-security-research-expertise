# Zero Trust + Workload Identity Expertise

Operational reference for staff-security-engineer work on Zero Trust architecture (ZTA) and workload-identity systems. Sibling to `cloud_iam_expertise.md` (which covers identity policy / role / cross-account) and `dns_network_infrastructure.md` (which covers network-layer concerns at the IP/DNS/BGP/CDN layer). This doc fills the gap between them: how to enforce policy at every hop when there is no trusted network perimeter, and how workloads (services, agents, jobs) authenticate as first-class principals.

Audience: Claude itself on future shifts, plus a staff security engineer doing real ZT architecture work in a product context. Imperative voice. Vendor-pitch register prohibited.

---

## 1. Why this doc exists

The corpus has 97 docs. `cloud_iam_expertise.md` answers "who can do what" — IAM principals, policies, roles, cross-account trust. `dns_network_infrastructure.md` answers "how packets flow" — DNS, BGP, CDN, DDoS. Neither answers the load-bearing modern question: how do you enforce identity-driven access policy at every hop when the corporate network, the cluster network, and the cloud-VPC network are all assumed hostile?

That is Zero Trust. The substrate underneath it is workload identity: every service, every container, every agent, every batch job is a named principal with a cryptographic identity, and every connection is authenticated and authorized continuously against dynamic policy.

"Zero Trust" is simultaneously a doctrine (NIST SP 800-207, BeyondCorp, Kindervag's original Forrester paper) and a product-category buzzword (every ZTNA vendor's marketing page). The substance and the marketing diverged hard around 2021. Treat any claim of "Zero Trust" with the same scrutiny you would apply to "AI-powered" or "blockchain-secured": read for the seven NIST tenets, the workload-identity substrate, and the policy decision/enforcement separation. If those three pieces are present, the claim is real. If only one is present, it is marketing.

The shift this doc traces is castle-and-moat (perimeter firewall, flat trusted internal network, VPN for remote) → identity-everywhere (every request authenticated, every authorization decision contextual, no network location confers trust). The castle-and-moat model survived from the 1990s through the 2010s on the assumption that the inside of the corporate network was trustworthy. SolarWinds (§11) ended that assumption empirically.

---

## 2. Doctrinal anchors

### 2.1 NIST SP 800-207 (Aug 2020)

The canonical reference. Authors: Scott Rose, Oliver Borchert, Stu Mitchell, Sean Connelly (NIST + CISA collaboration). 7 tenets (covered in §3). 4 deployment variants:

1. **Device-agent / gateway-based** — endpoint agent enforces policy with a gateway PEP at the resource. Closest to traditional VPN-replacement ZTNA.
2. **Enclave-based** — resources grouped into protected enclaves; PEP sits at the enclave boundary.
3. **Resource-portal-based** — application-layer broker (identity-aware proxy / IAP); the resource is published through a portal that does authn/authz before proxying.
4. **Device-application-sandboxing** — workloads run inside a sandboxed runtime on a managed device that enforces policy locally.

**NIST SP 800-207A (Sept 2023)** extends to multi-cloud / multi-network ZTA, addressing the practical gap where ZT principles must span AWS + GCP + Azure + on-prem with different identity substrates. Authors: Ramaswamy Chandramouli and Zack Butcher. This is the document to reach for when designing federated ZT across more than one cloud.

### 2.2 BeyondCorp (Google, 2014-2019)

Six-paper USENIX `;login:` series. Origin paper: Rory Ward and Betsy Beyer, "BeyondCorp: A New Approach to Enterprise Security" (`;login:` Vol 39 No 6, Dec 2014). Follow-on papers (Beyer / Spear / Saltonstall / Cittadini / Janosko / Escobedo) extended through 2016-2018 covering design-to-deployment, the access-proxy architecture, migration, user experience, and fleet health.

The load-bearing insight: Google's response to Operation Aurora (2009) was not to harden the perimeter further, but to assume the corporate network was already compromised and to require every internal-resource access to be authenticated against device + user identity with no implicit network trust. The "no internal network" formulation is BeyondCorp's contribution.

Tiered-trust model: each device is assigned a trust tier based on posture (managed, patched, encrypted, EDR-installed). Each resource is assigned a minimum trust tier. Access requires that the requesting device meet or exceed the resource's tier. This is the conceptual ancestor of every modern "conditional access" product.

### 2.3 John Kindervag (Forrester, 2010)

Term originator. Forrester report, 2010: "No More Chewy Centers: Introducing The Zero Trust Model Of Information Security." Kindervag's framing predates BeyondCorp publication and was independently arrived at by Google. Both share the observation that the trusted-interior model was an artifact of 1990s network economics and had become a liability by 2010.

Kindervag later moved to Palo Alto Networks (Field CTO), then ON2IT, and then Illumio (Chief Evangelist) — much of the microsegmentation discourse traces back to his Forrester period.

### 2.4 US Federal mandate stack

- **Executive Order 14028** (May 12, 2021), "Improving the Nation's Cybersecurity." §3 directs federal agencies toward Zero Trust architecture.
- **OMB M-22-09** (Jan 26, 2022), "Moving the U.S. Government Toward Zero Trust Cybersecurity Principles." Sets specific FY24 milestones across 5 pillars (identity, devices, networks, applications and workloads, data).
- **CISA Zero Trust Maturity Model v2.0** (April 2023). Replaces the v1.0 draft. Defines four maturity stages (Traditional / Initial / Advanced / Optimal) across 5 pillars + 3 cross-cutting capabilities (visibility and analytics, automation and orchestration, governance).
- **DOD Zero Trust Reference Architecture v2.0** (July 2022) and **DOD Zero Trust Strategy** (Oct 2022). DOD ZT Strategy: 45 capabilities and 152 activities across 7 pillars.

Read these as binding for federal/DIB work and as influential-but-non-binding for commercial deployments. The CISA ZTMM is the cleanest English-language operational ladder.

---

## 3. The 7 NIST tenets

Each tenet has a concrete failure mode when violated. Treat the failure modes as red-team targets — they are where ZT deployments crack.

1. **All data sources and computing services are considered resources.** Operational gloss: an S3 bucket, a managed DB, a SaaS app, a printer, an IoT sensor, and an AI agent are all "resources" requiring identity-driven access decisions. **Failure mode:** treating SaaS APIs as outside-the-ZT-perimeter and granting them implicit trust via IP allowlists. This is how Okta sub-processor compromises propagate (§11).

2. **All communication is secured regardless of network location.** mTLS or equivalent at every hop, including intra-VPC, intra-namespace, intra-pod. **Failure mode:** "internal traffic doesn't need TLS" — the Capital One SSRF-to-IMDS chain works partly because intra-VPC was implicitly trusted (§11).

3. **Access to individual enterprise resources is granted on a per-session basis.** No long-lived perimeter session blanket-authorizes downstream resource access. **Failure mode:** classic VPN — once on the corporate network, lateral movement is unrestricted. SolarWinds (§11).

4. **Access to resources is determined by dynamic policy.** Policy considers user identity + device posture + behavioral analytics + threat-intel signal + time-of-day + geolocation. **Failure mode:** static IP-allowlist as the entire access decision. Useful as a defense layer; insufficient as the decision.

5. **The enterprise monitors and measures the integrity and security posture of all owned and associated assets.** Continuous EDR / patch-level / configuration-drift telemetry. **Failure mode:** trust an asset at first authentication and not re-evaluate; an EDR alert mid-session does not revoke access.

6. **All resource authentication and authorization are dynamic and strictly enforced before access is allowed.** Per-request authz, not per-session-and-cached. **Failure mode:** JWT issued at sign-in with a 24-hour lifetime that does not check revocation, posture changes, or risk-score updates.

7. **The enterprise collects as much information as possible about the current state of assets, network infrastructure, and communications.** Visibility is a precondition for ZT — you cannot enforce policy on traffic you cannot see. **Failure mode:** encrypted-everywhere with no decryption / inspection capability and no service-mesh visibility — the org becomes blind to its own east-west traffic.

If a vendor pitches ZT without describing how they instrument all seven, ask which they actually do.

---

## 4. Workload identity — the substrate

Workload identity is what makes ZT mechanically possible. Without a cryptographic identity bound to every workload, "every connection is authenticated" reduces to "every connection has a TLS cert" — which says nothing about who the workload is.

### 4.1 SPIFFE / SPIRE (CNCF graduated)

**SPIFFE** (Secure Production Identity Framework For Everyone) is the spec; **SPIRE** is the reference implementation. CNCF graduated 2022. Originated by Joe Beda in 2016; Scytale (acquired by HPE in 2020) was a founding contributor. Evan Gilman + Doug Barth co-authored *Zero Trust Networks* (O'Reilly, 2017) — the practitioner-grade book on the underlying concept.

**SPIFFE ID** — URI-format `spiffe://<trust-domain>/<path>`. Example: `spiffe://prod.example.com/ns/payments/sa/billing-service`. The trust domain is a federation boundary; the path is workload-scoped (typically encoding namespace + service account + workload).

**SVID** (SPIFFE Verifiable Identity Document) — two forms:
- **X.509-SVID** — short-lived X.509 certificate (default 1 hour) with the SPIFFE ID in the URI SAN. Used for mTLS.
- **JWT-SVID** — JWT with the SPIFFE ID in the `sub` claim. Used for application-layer authn against APIs that consume bearer tokens.

**Trust bundles** — the set of CA certs / JWK signing keys for a trust domain. Distributed via Workload API to every workload that needs to validate peers.

**SPIRE Server + Agent + Workload API:**
- **Server** — runs the CA, stores registration entries, issues SVIDs.
- **Agent** — runs on every node, performs node attestation against the Server, then attests workloads on its node.
- **Workload API** — Unix-domain-socket API the workload calls to fetch its own SVID and the trust bundle. The workload does not hold long-lived credentials; the Agent issues a fresh SVID before the previous one expires.

**Node attestation plugins:** `k8s_psat` (Kubernetes projected service-account token), `aws_iid` (EC2 Instance Identity Document), `azure_msi` (Azure Managed Service Identity), `gcp_iit` (GCP Instance Identity Token), `tpm_devid` (TPM-based device identity), `join_token` (one-time bootstrap for ad-hoc workloads).

**Workload attestation plugins:** `k8s` (pod-spec matching), `docker` (container labels), `unix` (uid/gid/binary-path), `systemd` (unit name).

**Federation** — multiple trust domains federate by exchanging trust bundles via SPIFFE Trust Domain Federation API. This is how `spiffe://prod.aws.example.com` and `spiffe://prod.gcp.example.com` workloads can mTLS to each other without sharing a CA.

Production users (documented in SPIFFE/CNCF case studies): Bloomberg, ByteDance, Pinterest, Anthem (now Elevance Health).

### 4.2 Service-mesh mTLS

The mesh is the most common place workload identity actually gets enforced in production today.

- **Istio** — Lin Sun (Solo.io, formerly IBM), Louis Ryan (Solo.io, formerly Google), Sven Mawson (Google). Sidecar Envoy proxy injected per pod; control plane (Istiod) issues SPIFFE-compatible identities via the secret discovery service (SDS). mTLS-by-default within the mesh.
- **Linkerd** — Buoyant. William Morgan (CEO), Oliver Gould (CTO, ex-Twitter). The original service mesh (Linkerd 1.x was Scala; Linkerd 2.x rewrote in Rust as the `linkerd2-proxy` micro-proxy). Identity issued via Kubernetes ServiceAccount projected tokens; mTLS-by-default.
- **Consul Connect** — HashiCorp. Armon Dadgar (cofounder, CTO). Sidecar-Envoy model; SPIFFE-compatible identities.
- **Cilium Service Mesh** — Isovalent (acquired by Cisco, 2024). Thomas Graf (CTO). eBPF-based, sidecarless. Cross-link to `[[reference-linux-kernel-exploitation]]` §3 for the eBPF substrate.
- **Istio Ambient Mesh** (GA 2024) — Christian Posta (Solo.io, ex-Red Hat), John Howard (Solo.io, formerly Google). Sidecarless Istio; node-level ztunnel handles L4 + mTLS, optional waypoint proxies handle L7. Reduces sidecar memory overhead at the cost of weaker per-pod isolation.

The sidecar-vs-sidecarless tradeoff: sidecar gives per-pod isolation (a compromised sidecar in one pod cannot directly observe another pod's traffic); sidecarless gives lower overhead and simpler operations at the cost of node-level blast radius. For high-security workloads (PCI, HIPAA, FedRAMP-High), sidecar is the conservative choice.

### 4.3 Cloud-native workload identity

- **AWS IAM Roles Anywhere** (GA July 2022) — IAM credentials issued via X.509 client certificates to non-EC2 workloads. The CA can be ACM Private CA or external. Bridges on-prem and AWS-resident IAM.
- **GCP Workload Identity Federation** — exchanges external OIDC / SAML tokens for short-lived GCP service-account credentials via STS. The pattern that makes GitHub Actions OIDC → GCP authentication work without long-lived service-account keys.
- **Azure Workload Identity** (formerly AAD Pod Identity, deprecated Oct 2022). Uses Kubernetes ServiceAccount projected tokens + OIDC discovery; federated to an Azure AD application registration.
- **Kubernetes ServiceAccount projected token + OIDC discovery** — every Kubernetes cluster ≥1.21 can expose an OIDC discovery endpoint (`/.well-known/openid-configuration`) signing JWTs for projected ServiceAccount tokens. Cloud providers consume these as a federated identity source. This is the OIDC trusted-publishing primitive that `cicd_supply_chain_expertise.md` §7 references and that PyPI / npm trusted publishing depends on.

The OIDC trusted-publishing pattern is load-bearing for modern ZT CI/CD: the CI runner authenticates as a workload via OIDC, exchanges that for short-lived cloud credentials, performs the deploy, and never holds a long-lived key. Any architecture that still uses long-lived AWS access keys in CI/CD is one disclosure incident away from a SolarWinds-shape problem.

---

## 5. ZTNA vendor landscape

Zero Trust Network Access (ZTNA) is the vendor product category. The Gartner definition (2019) emphasized endpoint-initiated and service-initiated variants; in practice the market split along the lines below.

### 5.1 Cloud-broker style

- **Zscaler ZPA** (Zscaler Private Access) — Jay Chaudhry (founder, CEO). Cloud-broker model; client agent + cloud edge + connector inside the customer environment. Resources are never exposed inbound.
- **Cloudflare Access** (part of Cloudflare One) — Matthew Prince (cofounder, CEO), John Graham-Cumming (CTO until 2025, now on the board). Identity-aware proxy at Cloudflare edge; integrates with Cloudflare Tunnel (formerly Argo Tunnel) for outbound-only resource connectivity.
- **Palo Alto Prisma Access** — formerly GlobalProtect Cloud Service. Nir Zuk (founder, CTO).
- **Cisco Duo Network Gateway + Cisco Secure Access** — Cisco's ZT push post Duo acquisition (2018).
- **Netskope Private Access** — Sanjay Beri (founder, CEO).
- **Check Point Harmony Connect** — Check Point Software.

### 5.2 Endpoint-VPN-as-mesh

- **Tailscale** — Avery Pennarun (cofounder, CEO), David Crawshaw (cofounder, formerly Go team at Google), Brad Fitzpatrick (formerly Go team / LiveJournal). WireGuard underneath; coordination server brokers connections; identity from external IdP (Google / GitHub / Microsoft / Okta). Tailnet-wide ACLs as policy.
- **Twingate** — Tony Huie (CEO), Alex Marshall.
- **Nebula** — open-sourced by Slack (2019). Identity-aware overlay mesh with embedded certificate-based authn.
- **ZeroTier** — Adam Ierymenko. Older project (2014+); overlay network with rule-based access.

### 5.3 OSS / self-hosted

- **Pomerium** — Bobby DeSimone (founder, CEO). Identity-aware proxy; integrates with OPA-style policy.
- **HashiCorp Boundary** — HashiCorp. Session-broker model; the user never receives target credentials directly.
- **Teleport** — Gravitational (now Teleport). Ev Kontsevoy (CEO). Bastion + identity-aware proxy for SSH / Kubernetes / DB / web app access; certificate-based authn with short-lived issuance.
- **OpenZiti** — NetFoundry. Open-source zero-trust overlay; bring-your-own-identity-provider.
- **ngrok** — Alan Shreve (founder). Originally a tunneling tool; pivoted toward ZT framing 2022+.

### 5.4 Specialty

- **StrongDM** — Justin McCarthy. Audit-first, just-in-time database / SSH / Kubernetes access broker.
- **Banyan Security** — acquired by SonicWall (Dec 2023).
- **Appgate SDP** — single-packet authorization (SPA) variant of ZTNA; the resource is invisible (no TCP handshake) until the client proves identity via a UDP single-packet token. SDP roots trace to the Cloud Security Alliance specification, ca. 2014.

### 5.5 How to read the vendor pitches

Three diagnostic questions:

1. **Where does the PDP run?** Vendor-cloud (Zscaler/Cloudflare/Netskope), customer-cloud-tenant (Pomerium/Teleport/Boundary), or fully on-prem (some Appgate deployments)? Vendor-cloud PDP means the vendor sees every authz decision your workforce makes. That is a sub-processor relationship requiring its own threat model.
2. **What is the workload identity substrate?** SPIFFE-compatible? Cloud-IAM-native? Vendor-proprietary? Vendor-proprietary substrates are vendor-lock-in dressed as ZT.
3. **What is the failure mode if the broker is down?** Fail-closed (no access until broker recovers) is the security-correct choice; fail-open is the availability-driven choice that defeats ZT during the only window an attacker cares about.

---

## 6. Policy decision / enforcement architecture

ZT inherits the XACML 4-component policy architecture, which survived its source spec by decades because the decomposition is correct.

- **PDP** (Policy Decision Point) — evaluates policy against request + context, returns permit/deny.
- **PEP** (Policy Enforcement Point) — intercepts the request, calls PDP, enforces the decision.
- **PIP** (Policy Information Point) — supplies attributes (user identity, device posture, time-of-day, threat-intel feed) the PDP needs for the decision.
- **PAP** (Policy Administration Point) — authors and distributes policy.

In modern ZT deployments:

- **PEP placement options:** network edge (cloud broker, identity-aware proxy), sidecar proxy (Envoy / linkerd-proxy), endpoint agent (Tailscale / Zscaler client), L7 reverse proxy (nginx + ext_authz, Envoy + ext_authz), cloud-IAM resource policy (effectively a PEP at the resource itself).
- **PIP examples:** SCIM-provisioned user attributes from Okta / Entra; EDR posture from CrowdStrike / SentinelOne; risk score from Okta ThreatInsight / Microsoft Identity Protection; threat-intel feed from a TIP.

### 6.1 Open Policy Agent (OPA) — Styra

CNCF graduated. Tim Hinrichs (cofounder, CTO of Styra), Teemu Koponen (Styra, formerly VMware NSX), Torin Sandall. Rego language — declarative, datalog-inspired. Used as PDP across Kubernetes admission (Gatekeeper), Envoy ext_authz, Terraform (Conftest), microservice authz, and CICD policy. The dominant general-purpose PDP.

Common deployment topology: OPA as sidecar to each service, with policies bundled and pushed by OPAL or Styra DAS. The service calls OPA over loopback for each authz decision.

### 6.2 Cedar — AWS

Open-sourced May 2023 from AWS Verified Permissions. Designed for formal verification of policies — the language is intentionally restricted so policies can be analyzed for equivalence, redundancy, and "does policy A subsume policy B." Authoring team includes Mike Hicks, Aaron Eline, Emina Torlak.

Cedar's structural choice: separating principal / action / resource as first-class concepts (vs OPA Rego which is general-purpose datalog). The tradeoff is less expressiveness in exchange for stronger analysis guarantees.

### 6.3 Topaz — Aserto

Open Source. Omri Gazitt (CEO Aserto, formerly HP / Puppet / Microsoft). Combines OPA's policy engine with the Google Zanzibar relationship-tuple model for fine-grained authorization (ReBAC). Useful where the authz question is "does user U have relation R to resource X" rather than "does user U match attribute predicate P."

### 6.4 AuthZed SpiceDB

Zanzibar-faithful implementation. Cross-link to `[[reference-distributed-authz]]` for the deeper Zanzibar treatment. The relevant point for ZT: when the access decision depends on graph relationships (user → group → project → resource with inherited permissions), Zanzibar-shaped PDPs scale where attribute-based predicates do not.

### 6.5 Operational PDP discipline

- **Latency budget** — PDP calls sit on the request path. Budget single-digit milliseconds. OPA-as-sidecar (loopback) makes this cheap; OPA-as-remote-service makes this expensive and creates an availability dependency.
- **Decision caching** — cache permit decisions briefly (seconds) with explicit invalidation on policy / posture change. Do not cache deny — they are usually transient (step-up auth pending) and caching them is a UX failure.
- **Decision logging** — every PDP decision is an audit event. Pipe to SIEM. Detection engineering (cross-link `[[reference-detection-engineering]]`) depends on this telemetry being structured and complete.
- **Policy testing** — Rego, Cedar, and SpiceDB all have unit-test frameworks. Use them. ZT policies that nobody tests will be wrong, and you will discover this during an incident.

### 6.6 Policy authoring discipline

Policy-as-code inherits all the discipline of code-as-code, plus some that is specific to security-critical declarative configuration.

- **Default-deny.** The base policy is deny. Allow rules are explicit. The reverse (default-allow with explicit deny) produces miss-by-omission failures: a new resource or a new action that nobody wrote a deny for is allowed by default. Default-deny inverts the failure mode to over-restrictive (the new resource breaks until policy is written), which is the safe direction.
- **Layered policies — coarse before fine.** Tenant isolation at the outermost layer, role-based controls in the middle, attribute-based and risk-based controls at the innermost. A request blocked at the tenant boundary should never reach the fine-grained PDP. This bounds the blast radius of a bug in the fine-grained layer.
- **Policy review as code review.** Every policy change goes through the same review process as code: two-person review for sensitive policies, CODEOWNERS for security-critical paths, signed commits, audit-log retention. Policy bugs are security bugs.
- **Diff testing.** Before merging a policy change, evaluate the old and new policy against a corpus of historical requests (sampled from PDP logs) and surface diffs. Any request whose decision changes is either an intended fix or an unintended regression. This catches "we tightened policy X but accidentally also broke unrelated service Y" before the deploy.
- **Policy versioning + rollback.** Policies are versioned artifacts. Rollback is a one-command operation. PDPs that load policy from a bundle store should support pinned-version operation; PDPs that pull from main-branch HEAD will eventually deploy a bad policy at the wrong moment.
- **Emergency-access controls (break-glass).** The PDP MUST support break-glass identities that bypass normal policy with full audit trail and time-limited validity. The break-glass mechanism is itself a high-value attack target — protect it with hardware tokens, two-person controls, and immediate notification to a security-on-call channel. Without break-glass, ZT becomes a operational-availability risk: a policy bug locks out the responders who need to fix it.
- **Authorization decisions are append-only history.** Never delete PDP decision logs. The "did Alice access X on day Y" question must be answerable for compliance and incident windows that often span years. SOX / PCI / HIPAA / SOC 2 audits all expect this.

The single most-load-bearing discipline in this list is **diff testing against historical traffic before deploying policy changes.** It is the difference between policy-as-code-shaped-like-real-code and policy-as-code-shaped-like-config-that-might-break-prod-at-3am.

---

## 7. Continuous authentication + posture

ZT tenet 5 ("monitor and measure security posture") requires continuous signal collection from the workforce endpoint fleet and from workload runtimes.

### 7.1 Device posture

Endpoint compliance signals consumed by the PDP:

- **Managed-device check** — MDM enrollment (Jamf, Intune, Workspace ONE).
- **EDR-installed check** — CrowdStrike Falcon, SentinelOne, Microsoft Defender for Endpoint, Sophos Intercept X.
- **Disk encryption** — FileVault (macOS), BitLocker (Windows), LUKS (Linux).
- **Patch-level** — OS build + recent-CVE patch status.
- **EDR-health** — agent running, telemetry flowing, not tampered.

Vendor implementations:

- **CrowdStrike Falcon Identity** — surfaces device-trust scores into IdP decisions.
- **Okta Device Trust** — Okta consumes device signals from CrowdStrike / Jamf / Intune / Workspace ONE / Sophos as PIP inputs.
- **Microsoft Conditional Access + Intune compliance** — the Entra ID side of the same picture; Intune evaluates compliance, Conditional Access uses compliance as a sign-in policy attribute.
- **Jamf Trust** — Jamf's bundled ZT capability for macOS / iOS fleets.

### 7.2 User behavior / session risk

- **Okta ThreatInsight** — Okta-side reputational/IP/behavior signals.
- **Microsoft Entra ID Identity Protection** — risky-sign-in and risky-user detection; feeds into Conditional Access.
- **Google Risk Engine** — Google Workspace adaptive auth.
- **CrowdStrike Falcon Identity Threat Detection** — anomalous authn pattern detection.

The PDP consumes risk score as a PIP attribute and triggers step-up (re-MFA, passkey re-auth, device-attestation challenge) or denial when the score crosses thresholds.

### 7.3 Hardware attestation

The strongest device-posture signal is cryptographic — the device proves what it is using hardware-backed keys.

- **Windows Attestation** — TPM 2.0 + Windows Hello for Business; the TPM attests boot state and Windows configures Conditional Access on the result.
- **Apple Managed Device Attestation** (2022+ for iOS 16; macOS 14 Sonoma) — Secure Enclave-backed device identity; MDM platforms request attestations for use as authn factors. The attestation chains to Apple's CA.
- **Android Play Integrity API** + **hardware-backed key attestation** — StrongBox-backed (Titan M / Titan M2) attestation on supported Pixel devices.
- **Apple iCloud Private Relay** / **Anonymous Cloud Tokens** — adjacent privacy-preserving attestation primitives.

Cross-link to `[[reference-confidential-computing]]` for the broader attestation framing across TEEs / Apple Private Cloud Compute / NVIDIA H100 Confidential Computing.

---

## 8. Microsegmentation / data-plane enforcement

Microsegmentation is ZT's east-west story. Where ZTNA brokers handle north-south (user-to-resource) traffic, microsegmentation handles service-to-service.

### 8.1 Service-mesh as microseg

- **Istio AuthorizationPolicy** — `apiVersion: security.istio.io/v1beta1, kind: AuthorizationPolicy`. Allow/Deny by source principal (SPIFFE ID), namespace, method, path. The mesh's PEP is the Envoy sidecar.
- **Linkerd Server + ServerAuthorization** — Linkerd's analogous CRDs; ServerAuthorization references identities by Kubernetes ServiceAccount.
- **Consul intentions** — `intention create web db` allows `web` workload to talk to `db`; default-deny is configurable. SPIFFE-compatible identity underneath.

### 8.2 Cloud-native

- **AWS VPC Lattice** (GA March 2023) — application-layer routing + authz across VPCs / accounts / regions with SigV4 + IAM auth at the lattice layer. The cloud-native answer to "I have 50 microservices across 20 accounts and I do not want to peer 200 VPCs."
- **GCP Service Mesh** (Anthos / Cloud Service Mesh) + Workload Identity — GCP's managed Istio with managed control plane and tight Workload Identity Federation integration.
- **Azure Private Link** + Private Endpoint — network-level service isolation; weaker than identity-aware microseg but useful for shared-services patterns.

### 8.3 Identity-aware proxy at the edge

- **Google Identity-Aware Proxy (IAP)** — GCP-native; protects HTTPS load balancers and SSH-via-IAP-TCP. The reference implementation of the BeyondCorp resource-portal variant.
- **Cloudflare Access** — Cloudflare-edge IAP, configurable per hostname / per application.
- **AWS Verified Access** (GA April 2023) — AWS-native IAP with Cedar policy integration.

### 8.4 eBPF / Cilium-based

- **Cilium Service Mesh** — Isovalent / Cisco. Network policy enforcement in the kernel via eBPF; service mesh layered on top without sidecars.
- **Tetragon** — Isovalent. eBPF-based L7 enforcement and observability; can enforce policy on syscall / file / network operations.
- **Calico Cloud / Tigera** — competing eBPF-based network policy with enterprise tooling.

The eBPF microseg story is operationally compelling (no sidecar overhead, kernel-level enforcement) but inherits eBPF's threat model. Cross-link `[[reference-linux-kernel-exploitation]]` §3 (eBPF attack surface) before deploying eBPF-based PEPs as the primary enforcement layer for sensitive workloads.

---

## 9. Identity federation + trust domains

Multi-cluster, multi-cloud, multi-org. ZT does not stop at the organizational boundary, and the federation patterns are load-bearing for any real deployment.

- **SPIFFE Federation** — exchange trust bundles across trust domains. Workloads in `spiffe://prod.example.com/` can mTLS to `spiffe://partner.acme.com/` if both sides have ingested each other's trust bundles.
- **OIDC chains (trusted publishing pattern)** — GitHub Actions OIDC issues a JWT, cloud-IAM (AWS STS AssumeRoleWithWebIdentity / GCP STS / Azure Federated Credentials) validates the JWT against GitHub's OIDC discovery endpoint and issues short-lived cloud credentials. This is the dominant supply-chain ZT pattern as of 2024-2026. PyPI Trusted Publishing and npm Trusted Publishers are the package-registry side of the same primitive. Cross-link `[[reference-cicd-supply-chain]]` §7.
- **External identity sources via SAML / OIDC / SCIM** — workforce identity flows in from Okta / Entra / Google Workspace / Auth0 / Ping. SCIM provisioning syncs user / group lifecycle. Cross-link `[[reference-saml-federation]]` for the auth-protocol depth.
- **Customer-facing workload identity (CIAM)** — Auth0, Okta CIAM (Customer Identity), Stytch, Clerk, Frontegg. Distinct from workforce ZT both in scale (10⁶-10⁸ users vs 10³-10⁵ employees) and in threat model (account-takeover dominant vs lateral-movement dominant). A workforce ZT product does not automatically address CIAM, and the substitution failure mode here is common.

The federation hard problem is policy translation across trust domains. SPIFFE federation gives you cryptographic identity exchange; it does not give you "what is `partner:engineering` group allowed to do in my system." That mapping is policy and lives in your PDP.

---

## 10. 2024-2026 currency

Major developments since the 2020-2022 standardization wave. Confirm specific dates against primary sources before citing in published work — many are date-sensitive.

- **NIST SP 800-207A** (September 2023) — multi-cloud / multi-network ZTA. The companion document to 800-207 that addresses the practical multi-cloud gap.
- **CISA Zero Trust Maturity Model v2.0** (April 2023) — supersedes the v1.0 draft. Four maturity stages × five pillars.
- **DOD Zero Trust Strategy** (Nov 2022) + **DOD ZT Reference Architecture v2.0** (July 2022). DOD ZT Portfolio Management Office stood up post-strategy.
- **OMB M-24-15** (July 2024) — FedRAMP modernization; not strictly ZT but ZT-adjacent in cloud-resource authorization.
- **EU NIS2 Directive** — transposition deadline Oct 17 2024. ZT-shaped controls implicit in Article 21 cybersecurity risk-management measures. Member-state transposition has been uneven [unverified specific transposition status as of 2026 — confirm before citing].
- **OpenID Federation 1.0** — approved as a Final Specification in February 2026; addresses B2B federated identity at scale, relevant for workforce-of-workforces ZT (e.g., government agency federations).
- **AI-agent ZT** — AI agents are workloads with API capabilities. They need SPIFFE IDs, scoped IAM, audit telemetry, and policy enforcement at every tool call. Cross-link `[[reference-ai-orchestration-harnessing]]` §5 (8-concern harness design) for the agent-runtime side. Most ZT deployments as of mid-2026 do not yet treat AI agents as first-class workloads — they live under shared service-account credentials. This is the single biggest ZT gap in current production deployments. The shape of the corrective: (a) each agent invocation gets a SPIFFE ID encoding agent name + version + invoking human; (b) tool calls go through PEPs that evaluate agent identity, invoking human identity, and the requested tool against a PDP; (c) audit logs structure so agent actions and human actions are distinguishable; (d) MCP-allowlists become policy artifacts under the same review and rollback discipline as any other policy.
- **Vendor M&A and ZT-buzzword-creep** — Cisco acquired Isovalent (2024). HashiCorp acquired by IBM (announced April 2024, closed February 2025). Banyan acquired by SonicWall (closed December 2023, announced January 2024). SonicWall acquired by Francisco Partners and Elliott Management (private 2016, from Dell). VMware NSX → Broadcom integration ongoing. The market is consolidating around hyperscaler-bundled ZT (AWS Verified Access, Azure Conditional Access + Defender, GCP BeyondCorp Enterprise) plus three or four major independents (Zscaler, Cloudflare, Palo Alto, Cisco).

---

## 11. Real-incident corpus

The structural ZT argument is best made through real incidents where the absence of ZT controls produced the impact.

### 11.1 SolarWinds (2020)

Russia-attributed (SVR / APT29 / Cozy Bear). SUNBURST trojanized SolarWinds Orion build pipeline, distributed via legitimate update channel to ~18,000 Orion customers. ~100 organizations confirmed targeted exploitation post-implant. Impact dominated by lateral movement on flat trusted internal networks — once SUNBURST established C2 and the operator landed on a victim's network, traditional segmentation did not stop the operator from reaching email, source code, SAML signing keys (the Golden SAML attack on ADFS), and cross-tenant cloud resources.

**ZT counter-argument:** in a ZT posture, the implant on the Orion server would still be a problem, but lateral movement to other services would require per-resource authn against a PDP that considers device posture, workload identity, and behavioral anomaly. A SolarWinds-shape implant cannot trivially mint SAML tokens for arbitrary identities if the SAML signing keys are HSM-backed and SAML issuance is gated by a PDP. This is roughly the model OMB M-22-09 codifies.

Primary sources: Mandiant (FireEye at the time) UNC2452 reporting (Dec 2020), Microsoft MSTIC NOBELIUM reporting, CISA AA20-352A.

### 11.2 Microsoft Midnight Blizzard (2024)

Russia-attributed (APT29 / NOBELIUM-successor designation). Initial access via password-spray against a legacy non-production tenant; lateral movement via OAuth application abuse to reach Microsoft corporate email including senior leadership. Disclosed January 19, 2024.

The notable ZT lesson: Microsoft is one of the most-resourced organizations on the planet for ZT, and they still had a legacy non-prod tenant with weaker controls that allowed initial access; OAuth app abuse then provided the lateral movement. Confirms that ZT is a property of every component (legacy systems included), not a property of the new shiny components.

Cross-reference: CSRB (Cyber Safety Review Board) report *Review of the Summer 2023 Microsoft Exchange Online Intrusion* (April 2024; covers Storm-0558, with Midnight Blizzard outside its scope).

### 11.3 Okta sub-processor breaches (2022-2023)

- **Lapsus$ Sitel breach (Jan 2022)** — third-party support engineer access to Okta tenant administration via Sitel's compromised workstation.
- **Okta support case file breach (Oct 2023)** — attacker accessed HAR files uploaded to Okta support; HAR files contained session tokens; cross-tenant token theft followed.

**ZT lesson:** identity-provider compromise is the apex failure mode for identity-everywhere architectures. If your PDP's PIP for user identity is Okta, and Okta is compromised, the PDP is compromised by extension. The mitigations are (a) defense-in-depth (require device posture + behavioral anomaly, not just IdP assertion); (b) phishing-resistant authn (passkeys / WebAuthn, cross-link `[[reference-webauthn-fido2-passkeys]]`); (c) sub-processor diligence and incident-readiness.

### 11.4 Snowflake customer-account compromises (2024)

UNC5537 (Mandiant designation). Credential-stuffing against ~165 Snowflake customer tenants, attacker-controlled credentials sourced from years of InfoStealer logs. The Snowflake tenants compromised had no MFA enforced and no IP-allowlisting. Notable downstream: Ticketmaster, AT&T (~110M call-record metadata), Advance Auto Parts, Neiman Marcus, Santander.

**ZT lesson:** passwords-without-second-factor are ZT-incompatible. The control failure was not on Snowflake — Snowflake offers MFA, IP allowlisting, and federated SSO — it was that customer tenant admins did not configure them. ZT requires the tenant operator to actually configure the controls, and shared-responsibility-model SaaS makes this a recurring failure mode.

### 11.5 Capital One (2019)

Paige Thompson. Misconfigured WAF (ModSecurity) on AWS that permitted SSRF; attacker reached EC2 IMDSv1 metadata endpoint, retrieved IAM role credentials, used them to list and exfiltrate S3 buckets — ~100M individuals' data. Convicted June 2022.

**ZT lesson:** intra-VPC was implicitly trusted. IMDSv1 had no authentication and no PEP between the workload and the metadata service. IMDSv2 (released later that year) introduced session tokens that defeat the basic SSRF chain. The structural fix is "no implicit trust on intra-VPC traffic" — both at the metadata layer and at the S3 access layer. Cross-link `[[reference-cloud-iam]]` Capital One anatomy and `[[reference-ssrf-url-parsing]]`.

### 11.6 CDK Global (June 2024)

Ransomware against CDK's dealer-management SaaS. ~15,000 auto dealerships affected; weeks of outage. Reported actor: BlackSuit (rebrand of Royal / Conti lineage) [unverified attribution].

**ZT lesson:** dealer-to-CDK trust was implicit. Once CDK's environment was compromised, dealers had no PEP between their environment and CDK's pushed updates / data flows. ZT-microseg argument: even trusted SaaS relationships should have policy enforcement on the data flows in both directions, especially for SaaS that pushes content back to customer environments.

### 11.7 MOVEit Transfer mass exploitation (May-June 2023)

CL0P ransomware operator exploited CVE-2023-34362 (SQLi → arbitrary file read / RCE in Progress Software's MOVEit Transfer managed file transfer product). Impact: 2,600+ confirmed victim organizations, ~94M affected individuals across downstream organizations (estimates vary; Emsisoft tracking). Notable downstream: US Department of Energy, Shell, BBC, British Airways, Maximus, Welltok.

**ZT lesson:** the MOVEit Transfer pattern is "trusted file-transfer appliance with broad network connectivity, sitting between organizations." Once compromised, the appliance becomes a pivot to every customer whose data transits it. The ZT counter-argument: data-in-transit between organizations should be encrypted at the data layer (PGP / age / hybrid PKI) with no trust placed in the transit appliance. Customers who applied data-layer encryption pre-transit limited blast radius to traffic metadata; customers who relied on MOVEit's TLS-and-trust-the-appliance model lost the cleartext data.

### 11.8 LastPass (2022)

Two-stage compromise: August 2022 initial access (source code + technical docs from dev environment), then August-October 2022 second incident where the attacker used credentials from the first incident to reach customer vault backups in an AWS S3 bucket. Backups were encrypted but contained vault metadata (URLs, usernames) in cleartext and the encrypted-vault blobs were encrypted under user-derived keys with iteration counts that varied widely (some accounts had as few as 5,000 PBKDF2 iterations against the documented default).

**ZT lesson:** the attack succeeded because credentials from environment A (dev) provided access to environment B (production backup storage) without re-authentication, posture re-check, or behavioral-anomaly detection on the cross-environment access. ZT tenet 6 (per-request authn/authz) was violated structurally — long-lived AWS credentials allowed the second. The corrective is short-lived federated credentials with continuous validation, not long-lived AWS access keys.

The secondary lesson is about the encryption-not-being-uniform problem: a ZT property of "encrypted at rest" is meaningless if the key-derivation parameters vary across user accounts. Vault encryption was technically present; the cryptographic strength was unevenly applied, and the legacy accounts (sub-100,000 iterations) became practically brute-forceable for high-value targets.

### 11.9 GitHub-OAuth-app token theft (April 2022)

Attacker compromised OAuth tokens issued to two third-party integrators (Heroku and Travis CI) and used them to clone private repositories from dozens of GitHub customers including npm. The OAuth scopes granted were broad ("read all repositories the user can read"); the GitHub side could not distinguish "user opened the IDE" from "attacker is now using the user's OAuth token."

**ZT lesson:** OAuth scopes-without-time-bound are not ZT-compatible. Long-lived OAuth tokens with broad scopes are equivalent to long-lived passwords for the purposes of compromise. The corrective is OIDC short-lived federated tokens (the trusted-publishing pattern), narrow OAuth scopes, per-installation tokens, and detection-engineering on OAuth API usage patterns (volume / geolocation / off-hours).

---

## 12. Tooling stack — operational

Per-engagement, the question is which subset to reach for. The matrix below is conservative for security-critical workloads.

**In-cluster service-to-service:**
- SPIRE for workload identity.
- Istio or Linkerd for mTLS + AuthorizationPolicy.
- OPA or Cedar as PDP for application-layer authz beyond what the mesh expresses.
- Cilium NetworkPolicy + Tetragon for L3-L7 network policy.

**SMB / mid-market endpoint-to-resource:**
- Tailscale or Twingate for VPN-replacement.
- IdP (Okta / Entra / Google Workspace) for user identity.
- Endpoint MDM (Jamf / Intune) for device posture.
- Hardware passkeys (YubiKey 5 / Apple passkeys / Google Titan) for phishing-resistant authn.

**Enterprise workforce broker:**
- Zscaler ZPA or Cloudflare Access or Palo Alto Prisma Access or Cisco Secure Access.
- IdP federation + CrowdStrike Falcon Identity or Okta Device Trust for posture PIP.
- HashiCorp Boundary or Teleport for privileged-session brokering.

**Policy:**
- OPA for general-purpose attribute-based policy.
- Cedar where formal-verification of policy equivalence matters.
- SpiceDB or Topaz where relationship-based authz dominates the question shape.

**Compliance / control-mapping:**
- CIS Critical Security Controls IG1/IG2/IG3 alignment.
- NIST SP 800-53 control families AC-3 (access enforcement), AC-4 (information flow), IA-2 (identification and authentication), SC-7 (boundary protection).
- CISA ZTMM v2.0 self-assessment.

Detection telemetry from every PEP and PDP into a SIEM (Splunk / Sumo Logic / Chronicle / Sentinel / Panther). Cross-link `[[reference-detection-engineering]]`. Without telemetry, ZT is theater.

### 12.1 Per-engagement decision tree

The question of which subset to deploy depends on size, regulatory regime, and existing identity-provider posture.

- **Greenfield startup, <50 employees, no compliance regime yet.** Tailscale + Okta-or-Google-Workspace + hardware passkeys + the cloud provider's native workload identity (GCP Workload Identity Federation or IAM Roles Anywhere). Skip the broker layer entirely; the user-to-resource path is the IdP-authenticated Tailscale connection plus the cloud provider's IAM. Add service-mesh mTLS when service count crosses ~10 services.
- **Growth-stage product company, 50-500 employees, SOC 2 Type 2.** IdP federation (Okta or Entra ID), MDM (Jamf or Intune), EDR (CrowdStrike or SentinelOne), Cloudflare Access or Zscaler ZPA for workforce broker, SPIFFE/SPIRE + Istio or Linkerd for in-cluster, OPA for application authz, Teleport or Boundary for privileged sessions. The SOC 2 audit will land on PDP audit-log completeness and on access-review evidence — get those right early.
- **Large enterprise, regulated (FINRA / HIPAA / FedRAMP-Moderate or higher).** Same as growth-stage plus: hardware-attested device posture (TPM / Secure Enclave), Cedar or formal-verified policy for high-sensitivity controls, segregation-of-duties (the operator who writes policy is not the operator who approves policy is not the operator who reviews audit logs), HSM-backed signing keys for SAML and OIDC issuers, multi-region PDP availability, break-glass with two-person rule.
- **Federal civilian agency.** OMB M-22-09 milestones, CISA ZTMM v2.0 self-assessment evidence, FedRAMP-authorized ZT components, FICAM-compliant identity. The shortcut here is to start from the CISA ZTMM and pick controls by pillar; do not invent a custom maturity model.
- **DOD or DIB.** DOD ZT Reference Architecture v2.0 + DOD ZT Strategy + the specific Component (Service / Combatant Command / DOD Agency) implementation guide. NIST 800-171 / CMMC 2.0 overlay. Hardware-attested device identity is table stakes; CAC / PIV integration is required.

### 12.2 Migration sequencing

The standard sequence for migrating from castle-and-moat to ZT, in order of impact-per-effort:

1. **Workforce phishing-resistant MFA.** Hardware passkeys for all workforce accounts. Single highest-impact control. Cross-link `[[reference-webauthn-fido2-passkeys]]`.
2. **Identity-provider consolidation.** One IdP, not three. The PIP gets a single source of user-identity truth.
3. **Privileged-access broker.** Teleport / Boundary / StrongDM for SSH / database / Kubernetes access. Eliminates standing access; introduces session-broker audit trail.
4. **MDM + EDR everywhere.** Posture signal must exist before posture-based policy can.
5. **VPN replacement.** Workforce ZTNA broker for application access. Order this after MDM + EDR because the broker is consuming MDM + EDR signals.
6. **Service-mesh + workload identity.** SPIRE + Istio or Linkerd for east-west. This is the longest-tail item operationally.
7. **PDP centralization.** OPA / Cedar / SpiceDB-shaped policy engine integrated across PEPs.
8. **Continuous risk-based authz.** Risk-score-driven step-up and revocation. Requires steps 1-7 to be in place.

Organizations attempting this in different order (e.g., service-mesh-first without IdP consolidation) typically produce shelfware. The discipline is to put the user-identity primitive before the workload-identity primitive, and to put posture before posture-aware policy.

---

## 13. Anti-patterns + honest failure modes

Load-bearing section. The ZT marketing industry has produced a deep catalog of plausible-but-wrong deployments.

### 13.1 ZTNA-vendor-lock-in as ZT

Replacing one perimeter (the corporate firewall) with one vendor's broker (Zscaler / Cloudflare / Netskope) is not zero trust. It is a different perimeter, with the same single-point-of-trust failure mode and a new sub-processor dependency. If your ZT strategy is "buy ZTNA from Vendor X and we are done," the strategy is a procurement strategy, not a security architecture.

### 13.2 "We use mTLS" ≠ ZT

mTLS proves cryptographic identity at connection establishment. It does not authorize the request. A mesh with mTLS-everywhere and `AuthorizationPolicy: allow-all` is encrypting its trust-by-default, not enforcing identity-aware policy. Audit AuthorizationPolicy presence and content, not just mTLS-enabled status.

### 13.3 OPA-as-everything

OPA is general-purpose, which makes it tempting to route every policy decision through it. The failure modes:

- **PDP latency** — OPA-as-remote-service adds RTT to every authz check. Mitigation: OPA sidecar with cached bundle, not central OPA.
- **PDP availability** — if every authz call requires a live OPA, OPA outages produce request outages.
- **Policy sprawl** — Rego that nobody owns drifts into untested correctness debt. Treat policy as code, including review and unit tests.

For relationship-shaped questions, reach for SpiceDB / Topaz over OPA. For policy-equivalence-shaped questions, reach for Cedar.

### 13.4 Workload-identity-as-static-creds

SPIFFE IDs that never rotate are not SPIFFE. Kubernetes ServiceAccount tokens with no expiration (the pre-1.21 default) are not workload identity. Any long-lived credential in a CI/CD pipeline is one disclosure event away from a SolarWinds-shape problem.

The discipline: SVIDs ≤ 1 hour, ServiceAccount tokens projected with `expirationSeconds`, IAM credentials from STS with 15-minute - 12-hour lifetimes, no long-lived AWS access keys in source control or in CI environment variables.

### 13.5 Device-trust-by-AD-join

Joining a domain ≠ device is compliant. The 2019-era control "device must be domain-joined" provides a weak posture signal (the device exists in AD) but says nothing about patch level, EDR health, disk encryption, or whether the device is currently compromised. Device trust requires continuous posture telemetry, not membership in a directory.

### 13.6 The "Zero Trust journey" excuse

Multi-year ZT roadmaps that never materialize specific controls. CISA ZTMM v2.0 exists specifically to break this — it provides a maturity ladder you can be measured against. If an organization cannot place itself at a specific stage on the ZTMM for each pillar with evidence, the "journey" is rhetoric.

The corrective: pick one pillar (typically Identity), pick one stage gap (typically Initial → Advanced), pick three controls to close the gap, ship them in a quarter. Repeat. ZT roadmaps that span more than 18 months without intermediate measurable milestones are program-management failures masquerading as strategy.

### 13.7 AI-agent identity blindness

Most ZT deployments as of 2026 do not treat AI agents (Claude Code, Cursor agent mode, GitHub Copilot Workspace, Devin) as first-class workloads with their own SPIFFE IDs / IAM roles / audit telemetry. Agents inherit the workforce user's identity, which collapses the audit trail ("did Kurt do this or did Claude do this in Kurt's session?") and bypasses per-workload posture (the agent does not have a managed-device check; the human's laptop does).

The structural fix: AI agents get scoped workload identities. Tool calls go through PEPs that check the agent identity + the human's identity + the tool's authorization scope. Audit logs distinguish agent vs human actor. Cross-link `[[reference-ai-assisted-coding-tool-security]]` §13 (Semgrep AI-tool policy) and `[[reference-ai-orchestration-harnessing]]` §5 (8-concern harness design).

### 13.8 Visibility gap on east-west

If you cannot see service-to-service traffic, you cannot enforce policy on it. The mesh provides this visibility; the mesh-less environment does not. Many large enterprises have ZTNA at north-south but flat L3 inside the cluster — the east-west attack surface is the modern equivalent of the flat-trusted-internal-network problem ZT was supposed to solve.

### 13.9 Posture-without-signal-quality

Device-compliance signals that are not adversarially-validated are weak. EDR telemetry that an attacker on the device can suppress is not posture; it is the absence of evidence. Cross-link `[[reference-dfir-methodology]]` for the EDR-tampering question and `[[reference-detection-engineering]]` for the detection-as-code response.

### 13.10 ZT-for-employees-only

CIAM ZT is a separate problem from workforce ZT. Workforce controls (managed devices, EDR, MDM) do not apply to your customers. The customer-identity ZT story is webauthn + risk-based step-up + bot detection + behavioral analytics — overlapping primitives, very different deployment shape. Cross-link `[[reference-anti-fraud-abuse-engineering]]` for the customer-identity-meets-abuse-engineering view.

---

## 14. Cross-link cluster

- `[[reference-cloud-iam]]` — IAM policy / cross-account trust / Capital One anatomy. The "who can do what" half of the ZT story.
- `[[reference-dns-network-infrastructure]]` — network-layer concerns. The packet-level adjacency to ZT enforcement.
- `[[reference-distributed-authz]]` — Zanzibar / SpiceDB / fine-grained authz. The relationship-graph PDP shape.
- `[[reference-saml-federation]]` — SAML XSW / OIDC / OAuth RFC 9700. The federation-protocol depth ZT depends on.
- `[[reference-cicd-supply-chain]]` — OIDC trusted publishing / GHA pwn_request / SLSA. The CI/CD half of workload identity in deployment pipelines.
- `[[reference-ai-assisted-coding-tool-security]]` — IDE-AI tool threat surface. The AI-agent-as-workload identity gap.
- `[[reference-ai-orchestration-harnessing]]` — agent harness 8-concern design. The runtime side of agent identity.
- `[[reference-confidential-computing]]` — TEE attestation. The hardware-attestation substrate for ZT device posture.
- `[[reference-linux-kernel-exploitation]]` — eBPF substrate. The threat model under Cilium / Tetragon ZT enforcement.
- `[[reference-dfir-methodology]]` — IR lifecycle. The detection-and-response half of ZT (tenets 5 and 7 are visibility tenets).
- `[[reference-detection-engineering]]` — Sigma / Sentinel / SIEM. The detection-as-code response to ZT telemetry.
- `[[reference-threat-modeling-discipline]]` — STRIDE / kill-chain / attack-tree. The structured-analysis frame for designing ZT controls.
- `[[reference-webauthn-fido2-passkeys]]` — phishing-resistant authn primitive. The user-identity primitive every modern ZT deployment depends on.
- `[[reference-anti-fraud-abuse-engineering]]` — adversary economics and abuse engineering. The CIAM ZT counterpart to workforce ZT.

---

## Honest failure modes of this doc

- **Vendor landscape (§5) ages fast.** The cloud-broker / endpoint-VPN-as-mesh / OSS split is structurally durable, but specific vendor names, acquisitions, and product rebrandings shift quarterly. Treat §5 as a snapshot, not a reference.
- **NIST 800-207A multi-cloud detail (§2.1) is shallow.** A multi-cloud ZT engagement would need to consult 800-207A directly and trace it against the specific CSPs in scope. This doc gestures at the framing but does not catalog the multi-cloud control mappings.
- **CIAM ZT (§9, §13.10) is gestured at but not developed.** Customer-identity ZT deserves its own doc — the threat model, the bot-vs-human signal stack, the account-takeover dominant failure mode, and the regulatory overlay (PSD2 SCA, FIDO2 in financial services) are large enough to warrant separate treatment. Flagged as a gap.
- **Posture-signal-quality (§13.9) is under-developed.** The EDR-suppression / agent-tampering question deserves its own treatment as a sibling to detection-engineering. Out of scope here.
- **AI-agent ZT (§10, §13.7) is the most-current and least-mature topic in the doc.** The pattern of "agents-get-workload-identity" is structurally correct but production-rare as of 2026. Expect this section to require revision within 12 months as production deployments mature.
- **Service-mesh deep-dive is shallow.** Istio Ambient vs sidecar tradeoffs deserve their own treatment, as do the Linkerd2-proxy Rust-implementation security properties. A "service-mesh-security expertise" sibling doc is the obvious extension.
- **Hardware-attestation chain depth is thin.** §7.3 names the primitives but does not walk the attestation chain end-to-end (TPM EK → AIK → platform attestation → IdP). A separate doc on attestation chains across TPM / Apple Secure Enclave / Android StrongBox / NVIDIA H100 would slot under the confidential-computing sibling cluster.
- **No diff-tested PDP authoring example.** §6.6 names diff-testing as load-bearing but does not show the operational shape (request-corpus capture, replay harness, expected-diff workflow). A worked example would strengthen the section but expands scope beyond doc-target.
