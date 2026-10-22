# Docker Desktop and VM-Isolated Dev-Container Escape — Expertise

Audience: Claude when auditing developer-workstation container tooling; the developer-tooling security engineer building enterprise policy; the AppSec engineer triaging "Docker Desktop CVE" tickets; the IT-security lead deciding between Docker Desktop, Rancher Desktop, Podman Desktop, Lima/Colima, OrbStack, or WSL2 at fleet scale. Imperative voice. Cross-link `[[reference-container-runtime-escape]]` for the Linux-runtime (runc/leaky-vessels/cgroup) view; this is the **VM-isolated dev-tooling sibling**. Cross-link `[[reference-container-k8s-security]]` for orchestrator policy; `[[reference-macos-apple-security]]` for the macOS host platform; `[[reference-linux-kernel-exploitation]]` for the Linux guest kernel inside the VM.

## 1. Why this doc exists

Server-side container security is the runc / containerd / cgroup / kernel-namespace story (`[[reference-container-runtime-escape]]`). Desktop container tooling on macOS and Windows is a different story. Macs and Windows hosts cannot run Linux containers natively. Every Mac and Windows container tool runs a **Linux virtual machine** under the hood and ships containers inside that VM.

The attack surface that produces is not one boundary but four:

- **Surface A: container → VM-guest.** The runc-class problem. Identical to the server-side story. Escape into the Linux VM as root inside the VM. Does not yet compromise the host.
- **Surface B: VM-guest → host.** The hypervisor boundary. Cross from inside the Linux VM out to macOS or Windows. Rare, catastrophic, and platform-specific (HyperKit, Apple Virtualization.framework, Hyper-V, WHPX).
- **Surface C: host-side daemon / UI / privileged helper.** The desktop application itself runs with elevated host privileges. A vulnerability in Docker Desktop's macOS privileged helper, Windows service, web UI, or update channel is a direct host RCE that **does not require containers at all**.
- **Surface D: credential exfil via host filesystem access.** Even without a VM escape, a container with a broad bind mount can read credentials, browser cookies, SSH keys, kubeconfigs, and cloud SDK material directly off the host.

The structural insight that governs the rest of the doc: **a developer workstation is the keys to many kingdoms.** Cloud credentials for every account the developer touches. Source-control credentials for every repo. SaaS session cookies for every internal tool. SSH keys for every server. A compromise of the container tool on a developer's machine is not a contained event; it is a chain across the developer's entire authorization graph. Treat dev-container tooling as a high-value target, not a productivity utility.

This doc owns the gap between the server-side runtime-escape corpus and the macOS/Windows host platform. It does not re-cover Pod Security Standards (see container-k8s), runc CVEs (see container-runtime-escape), or macOS-internal sandbox details beyond TCC interactions (see macos-apple-security).

## 2. The desktop-container tooling landscape

A short census of what developers run, because the threat model differs per tool.

**Docker Desktop.** Docker Inc. The most-deployed. Subscription required for orgs over a size threshold since 2021. macOS implementation has migrated across HyperKit (BSD-licensed xhyve fork by Docker engineers) → Apple Virtualization.framework (vz) as the default backend on Apple Silicon. Windows implementation runs either WSL2 (recommended, since 2020) or Hyper-V VM (legacy). Ships a Linux VM running containerd and dockerd, a host-side desktop app (Electron), a privileged helper service, an extension marketplace, and a Kubernetes single-node distribution. The biggest single attack surface in this doc.

**Rancher Desktop.** SUSE (Sheng Liang founded Rancher Labs; SUSE acquired 2020). OSS. Kubernetes-first — ships k3s rather than a custom k8s. Backed by Lima on macOS and Linux, WSL2 on Windows. Smaller host-side surface than Docker Desktop; no proprietary extension marketplace; CRD-style configuration.

**Podman Desktop.** Red Hat. OSS. The Podman engine is daemonless on Linux (runs containers via fork-exec rather than a long-lived daemon). On macOS and Windows, ships a Linux VM under libkrun (current default) or Apple Virtualization.framework (applehv) on macOS, QEMU in older releases, and WSL2 on Windows. Marketed around rootless containers and OpenShift compatibility. Daniel Walsh (Red Hat container-tools lead) drove the daemonless and rootless design.

**Lima.** OSS, macOS-specific. Maintained primarily by Akihiro Suda (NTT; also rootless-containers maintainer). Provides a generic Linux VM on macOS — uses QEMU or Apple Virtualization.framework. Doesn't ship a container engine itself; provides the substrate. Backs Colima and Rancher Desktop on Mac.

**Colima.** OSS Mac-specific. Lightweight Docker + Kubernetes runtime built on Lima. Popular among teams that want Docker Desktop's Docker CLI compatibility but don't want the Docker Desktop license or host-side daemon attack surface.

**OrbStack.** Commercial, Mac-only. Marketed on low resource consumption and fast startup. Ships its own VM implementation on Apple Virtualization.framework. Smaller team than Docker Inc; vendor-trust model accordingly.

**WSL2.** Microsoft. Windows Subsystem for Linux 2. A Hyper-V-managed Linux VM that hosts user-installed Linux distributions. Strictly not a container tool; in practice used as one and as the backend for Docker Desktop and Rancher Desktop on Windows.

**k3d / kind.** Kubernetes-in-Docker. These run a k8s control plane and nodes as containers inside an existing Docker daemon. Their attack surface is governed by the underlying Docker engine; they themselves add a thin orchestration layer. The relevant subtlety: a k3d / kind cluster runs the Kubernetes control plane as containers with permissions sufficient to manage other containers. A compromise of the control-plane container can pivot to other workloads on the same Docker engine.

**Telepresence, Devspace, Skaffold, devcontainers.** Orchestrators on top of the above tools. Telepresence runs a sidecar in a remote cluster and routes traffic to local containers — the inverse direction of Surface D (production credentials and traffic flow into developer workstations). Treat these tools' configuration as production-grade.

What this doc does NOT cover: server-side Kubernetes distributions, server-side container runtimes (containerd, cri-o, runc on Linux servers), Linux desktop with native dockerd (no VM involved — same threat model as a Linux server with developer accounts).

## 3. The four attack-surface model

The model the rest of the doc operates on. Read this once; refer back to it when looking at any CVE in §4 or §5.

### Surface A: container → VM-guest

Identical to `[[reference-container-runtime-escape]]`.

A malicious container escapes runc / containerd inside the VM via runc CVE-2019-5736, leaky-vessels CVE-2024-21626 / CVE-2024-23651, OverlayFS CVE-2023-0386, cgroup release_agent CVE-2022-0492, etc.

Lands as root inside the Linux VM. Has access to other containers on the VM, the dockerd socket, and the VM's filesystem.

This is exactly the runc-class problem, repackaged.

Mitigations are the same: keep runc current, prefer rootless mode where supported, drop CAP_SYS_ADMIN, restrict seccomp profile, prefer user-namespace mappings.

**A escape alone does not compromise the host.** The attacker is now root in a Linux VM that the host runs as an unprivileged hypervisor guest.

To reach the host, the attacker must either find a Surface B bug or find a Surface D footgun (bind-mounted credentials, etc).

Snyk's leaky-vessels research (Rory McNamara, January 2024) demonstrated a coordinated multi-CVE chain across runc, BuildKit, and Moby. The chain is in scope as Surface A inside Docker Desktop. The vendor advisories for leaky-vessels include patched Docker Desktop versions — track the patch level on the developer fleet.

### Surface B: VM-guest → host

The hypervisor boundary.

On macOS, Apple Virtualization.framework (vz, since macOS 11 Big Sur) or the older HyperKit.

On Windows, Hyper-V (also used by WSL2).

Crossing this boundary requires a hypervisor or virtualization-framework bug.

These bugs are rare in absolute count but high-impact when they land. Hyper-V has a public CVE history (`[unverified specific advisory]` for each); Apple's Virtualization.framework has a smaller public CVE corpus, partly because it's newer and partly because Apple discloses vulnerabilities less systematically than Microsoft. HyperKit is BSD-derived and has its own CVE trail.

Real-world precedent for hypervisor escape: VMware Workstation Pwn2Own chains (multiple years); QEMU device-emulation escapes (CVE-2019-14378, CVE-2020-14364 — affects Linux-on-Mac via QEMU-backed Lima).

The Apple Virtualization.framework attack surface is less public but is structurally similar to other Type-1.5 hypervisors.

Felix Wilhelm's virtualization research (Hyper-V at ERNW in 2014; a KVM guest-to-host escape at Project Zero in 2021) is a useful priors-anchor for the class. The boundary is not impervious; it is moderately well-defended and rarely studied at the depth a serious attacker would invest in.

### Surface C: host-side daemon, UI, privileged helper

The Docker Desktop app on macOS runs as the user, but spawns a privileged helper (historically `com.docker.vmnetd` or `com.docker.socket`) installed via SMJobBless / SMAppService, running as root.

On Windows, equivalent privileged service runs under SYSTEM.

The privileged helper exists to perform host operations the unprivileged UI cannot: install network filters, manipulate launchd / Windows services, write under `/Library/PrivilegedHelperTools` or `C:\Program Files`, etc.

Any vulnerability in the privileged helper's IPC, command parsing, or authentication is a local privilege escalation to host root or SYSTEM.

Web-UI surface: Docker Desktop ships an Electron-based dashboard. XSS, CSRF, SSRF, or RCE in the dashboard means an attacker who lands a browser-side primitive (malicious image preview, malicious extension page, ingress page over a localhost socket) reaches container-management privileges and, via container-management, host access.

Update channel: every desktop container tool auto-updates. A compromise of the vendor's update key or signing infrastructure is mass simultaneous compromise of every installation. See `[[reference-cicd-supply-chain]]` for the general pattern; SolarWinds is the canonical reference.

Extension marketplaces: Docker Desktop Extensions (since 2022) and (to a lesser extent) other tools allow third-party extensions to install with elevated privileges, contributing UI panels, mounting volumes, spawning containers. Same threat model as VS Code extensions or browser extensions: vendor vetting is the only meaningful control, and vendor vetting is uneven.

### Surface D: credential exfil via host filesystem

A container with a bind mount that includes credential paths exfils credentials without escaping anything.

`docker run -v ~:/host` is the obvious case.

`docker run -v ~/.aws:/root/.aws` is the deliberate case that developers do constantly to pass cloud credentials into containers.

`docker run -v /:/host` is the apocalyptic case that examples on the internet still occasionally suggest.

Even more insidious: a container with `~/.config` mounted reads browser cookies (Chrome stores under `~/Library/Application Support/Google/Chrome` on macOS, `~/.config/google-chrome` on Linux).

Browser session cookies on macOS are encrypted by Chrome with a key in the Keychain — but the unprivileged user can decrypt them themselves, and the running browser has decrypted them into shared memory or temporary state.

SaaS session cookie exfil is the lowest-friction lateral-movement primitive in the modern enterprise. Cross-link `[[reference-session-management]]` §11 (session-fixation and session-exfil).

Surface D is the most common, lowest-skill, and most-overlooked attack class in this doc.

It requires no CVE, no novel research; it requires only that a developer was once persuaded to `docker run` an attacker-supplied image with broad bind mounts.

Defense is policy: enforce minimum-bind discipline.

## 4. CVE corpus — VM-to-host escapes

The Surface B and adjacent corpus. Stay current with the vendor advisories; the list below is point-in-time.

The structural lesson: privileged helpers must do four things to be safe. Authenticate the calling client cryptographically (codesign-anchor on macOS, signature check on Windows). Validate every argument against an allow-list of paths / commands. Use safe syscalls (no `system()`, no shell-out) for the work. Log every request to a tamper-evident audit log. Few privileged helpers do all four; most do two.

**Docker Desktop CVE-2024-8695.** Remote code execution via a malicious extension's crafted description or changelog; fixed in Docker Desktop 4.34.2. Separately, the installer-as-attack-surface pattern is a recurring class: installers run as root or SYSTEM, write files into protected paths, and execute scripts as part of the install process. If a low-privileged user can influence what the installer reads or writes, the install path is the privilege-escalation primitive.

**Docker Desktop CVE-2023-0625.** RCE via a crafted extension description or changelog in Docker Desktop before 4.12.0.

**WSL2 / Hyper-V CVE history.** WSL2 runs in Hyper-V; Hyper-V vulnerabilities affect WSL2 as a structural consequence. Hyper-V CVE-2024-38080 (elevation of privilege, CVSS 7.8, exploited in the wild per CISA KEV, July 2024). The interesting subtlety: WSL2 distros are mounted with broad permission, which means a WSL2-distro compromise can reach Windows credentials without breaching Hyper-V at all. The Surface D problem in WSL2 form.

Microsoft's Hyper-V security team has been one of the more transparent hypervisor groups about its CVE pipeline. Patch Tuesday cycles frequently include Hyper-V advisories that map onto VMBus, VID.sys, vmswitch.sys, and the WinHvr.sys layers. Track these advisories specifically for the words "guest-to-host" or "root partition." See cross-link `[[reference-windows-kernel-exploitation]]` for the broader Hyper-V exploitation context.

**HyperKit history.** Docker Desktop on Intel Macs ran HyperKit (BSD-licensed xhyve fork). HyperKit has had its own CVE trail, including QEMU-derived device-emulation bugs. On Apple Silicon, Docker Desktop migrated to Apple Virtualization.framework; HyperKit is being phased out.

**Apple Virtualization.framework.** Used by Docker Desktop (Apple Silicon), Lima, Colima, Rancher Desktop, OrbStack. Newer code; smaller public CVE corpus. Treat as a single shared dependency: a Virtualization.framework bug affects every macOS desktop container tool simultaneously. `[unverified specific CVE references]`.

**QEMU device-emulation escapes.** Lima and Podman Desktop have used QEMU as an alternative backend. QEMU device-emulation CVEs (CVE-2019-14378 SLiRP, CVE-2020-14364 USB emulation) are real escapes from the Linux guest to the QEMU process on the host. If QEMU runs as the user (not root), the escape gains user-level host privileges; combined with a Surface D primitive, this is full host compromise.

## 5. CVE corpus — host-side daemon and UI

The Surface C corpus. Tracking this is harder because some vendors disclose under generic LPE language without naming the IPC or daemon directly.

**Docker Desktop privileged helper (`com.docker.vmnetd` historically, now consolidated into the broader privileged-service path on macOS).** Runs as root. Communication with the unprivileged UI is over a Unix domain socket. The historic attack pattern: unauthenticated or weakly-authenticated requests over the socket allow command injection or arbitrary file writes as root. Mitigation: privileged helper authenticates the calling client (e.g., XPC peer validation, codesign-anchor checks) and validates every argument before invoking shell or kernel paths.

**Docker Desktop Electron dashboard.** Electron apps have a long history of XSS-to-RCE via nodeIntegration misconfiguration, contextIsolation oversights, and Webview2 surface on Windows. The dashboard handles image-detail pages, extension-marketplace listings, log-viewer panes, container-build outputs — any of which can include attacker-controlled strings (image names, container logs containing ANSI / HTML, extension descriptions). Treat the dashboard as a browser-class target. Docker Desktop UI advisories include CVE-2023-0626 (RCE via query parameters in the message-box route, fixed in 4.12.0) and CVE-2024-8695 (RCE via a crafted extension description or changelog, fixed in 4.34.2).

**Update mechanism.** Docker Desktop, Rancher Desktop, Podman Desktop, OrbStack each implement auto-update. The update channel is over HTTPS to a vendor-controlled endpoint, with code signing verification on the downloaded artifact. The trust anchor is the vendor's signing key and (on macOS) the Apple Developer ID code signature. Compromise of the vendor's signing infrastructure is a one-shot fleet compromise. SolarWinds 2020 demonstrated the upstream variant; CodeCov 2021 demonstrated the lower-friction variant.

**Docker Desktop Extensions (since 2022).** Third-party extensions install with elevated container-management privileges and can mount volumes from the host, spawn privileged containers, present arbitrary UI inside the dashboard. The vetting model is vendor curation — Docker Inc reviews submitted extensions, but the depth of that review is not publicly auditable. Treat extensions as one would treat unsigned VS Code extensions or browser extensions: install only from named vendors with established security postures.

**MCP-server-as-Docker-extension.** Emerging 2024-2026 surface. Docker has published MCP server integrations exposing Docker-Desktop control to AI agents. The combination is: AI agent (Claude Code, Cursor, Cline) speaking MCP to a Docker-Desktop-resident MCP server that controls container lifecycle. Prompt-injection into the agent's context becomes container-spawn-with-attacker-controlled-image-and-mounts. Cross-link `[[reference-ai-assisted-coding-tool-security]]` §6 (MCP threat model) and `[[reference-ai-agent-session-management]]`.

## 6. Credential exposure on developer workstations

Surface D in detail. The list of sensitive material on a typical developer workstation is longer than developers usually appreciate.

**Docker `config.json`** (`~/.docker/config.json`). Stores registry credentials, sometimes base64-encoded username:password pairs to ECR / GHCR / Docker Hub / GAR / internal registries. A container with `~/.docker/` bind-mounted (a pattern some CI emulation scripts use) reads these.

**AWS credentials via bind mount.** `docker run -v ~/.aws:/root/.aws <image>` is the documented pattern for passing AWS credentials into containers. It exposes the credential file (and any SSO cache) to whatever runs inside the container. Cross-link `[[reference-cloud-iam]]` for the AWS-side blast radius of leaked credentials. Mitigation: use IAM Roles Anywhere / OIDC federation for ephemeral credentials in containers; do not bind-mount long-lived credentials.

**Kubeconfig.** `~/.kube/config` contains cluster credentials (client certificates or tokens) for every cluster the developer has accessed. A container with the kubeconfig mounted reaches every cluster. The aggregation problem is severe: developers commonly hold credentials for 5-50 clusters simultaneously.

**Cloud SDK caches.** `~/.config/gcloud`, `~/.azure`, `~/.oci`. Each holds refresh tokens, application default credentials, or service-account keys. Same exfil pattern.

**SSH keys.** `~/.ssh/id_*`, `~/.ssh/authorized_keys`, `~/.ssh/known_hosts`. SSH private keys often unencrypted in practice (passphrase-less, or unlocked into ssh-agent). Reaching `id_rsa` is the most common credential-exfil event in this list because SSH keys are routinely passphrase-less.

**Git credentials.** `~/.git-credentials`, `~/.gitconfig`, `~/.config/gh/hosts.yml`. GitHub CLI stores OAuth tokens that can be used for `gh api`-equivalent access to every repo the developer has access to.

**Browser session cookies.** Chrome on macOS: `~/Library/Application Support/Google/Chrome/Default/Cookies`. SQLite database; values are encrypted but the encryption key is in Keychain accessible to the user. Firefox `~/Library/Application Support/Firefox/Profiles/*/cookies.sqlite`. On Linux, the equivalent paths under `~/.config`. Chrome's macOS encryption uses Keychain-stored key derived from the user account; an unprivileged process under the developer's UID can request the key with `security find-generic-password -wa "Chrome"` (newer macOS versions prompt for the user's password first). A container with bind-mount of `~/Library/Application Support` reads the cookies file; pairing with the Keychain access is harder, but the running Chrome's process memory contains the decrypted cookies (and many SaaS sessions use long-lived tokens that survive past cookie encryption). Cross-link `[[reference-session-management]]` for the session-takeover blast-radius downstream.

The browser-cookie exfil is the highest-leverage Surface D primitive. A typical developer is signed into AWS Console, Google Workspace, GitHub, GitLab, Snowflake, Datadog, PagerDuty, Slack, Notion, Linear, Salesforce, internal SSO portals, and a long tail of vendor-specific dashboards. Each session cookie is a credential. SaaS session cookies frequently bypass MFA prompts on subsequent re-auth (sliding session windows). A single exfil event is a multi-SaaS lateral chain.

**`.env` files in project directories.** Bind-mounting a project for development (`-v $(pwd):/app`) exposes any `.env` (or `.env.local`, `.envrc`) in that tree. Cross-link `[[reference-secrets-management-discipline]]` for prevention discipline.

**1Password CLI / Bitwarden CLI session tokens.** If the developer has unlocked a password vault and a CLI session is cached on disk, a container reading the cache file can exfil the vault unlock state.

**Aggregation.** Treat this list as a single attack: any container with `-v ~:/host` or `-v /:/host` exfils the full set in seconds. The compromise blast-radius is "developer's full digital identity," not "one container."

**Defense.** Default-deny bind mounts of the credential paths above. Docker Desktop Business's `admin-settings.json` and Rancher Desktop's preferences both support path-restricted file sharing. Treat the developer's home directory as untrusted from a container's perspective; pass credentials via ephemeral tokens, OIDC federation, IAM Roles Anywhere, GitHub OIDC for CI tokens, short-lived `aws sts assume-role` outputs piped via stdin, never long-lived files mounted in. Educate developers on the difference between "this works" and "this works safely" — the canonical README example `docker run -v ~/.aws:/root/.aws` is the wrong default.

## 7. WSL2-specific considerations

WSL2 is Hyper-V-managed Linux VMs hosting user Linux distributions. Microsoft markets it as a development environment, not a container tool, but in practice it is the substrate for Docker Desktop and Rancher Desktop on Windows, and developers use it directly.

**WSL2 distro → Windows host crossing.** The Hyper-V boundary is the only structural defense. Hyper-V CVEs that break the root-partition / guest-partition isolation affect WSL2 as a side effect. CVE history is non-trivial (e.g., CVE-2024-38080, a Hyper-V elevation of privilege). Treat WSL2 distro compromise as roughly equivalent to "untrusted Linux VM with broad host filesystem access via the `/mnt/c/`-style automount."

**Automount of Windows drives.** WSL2 by default mounts the Windows C: drive at `/mnt/c`. A compromised WSL2 distro reads the entire Windows filesystem under the user's privileges — including browser profiles, SSH keys, git credentials.

**Enterprise visibility gap.** Many enterprise EDR products instrument the Windows kernel and user-mode but have weaker telemetry inside WSL2 distros. A WSL2 distro can therefore run reconnaissance, lateral movement, and exfiltration with substantially less endpoint visibility than equivalent Windows-native activity. IT-security policies frequently underweight this gap.

**Interop sockets and named pipes.** WSL2 exposes Windows-side named pipes and Unix sockets across the boundary. `wsl.exe`-resident processes can talk to Windows-side services. The interop layer has had its own CVE pipeline historically. Treat any cross-boundary IPC as untrusted and audit the named pipes a WSL2 distro can reach.

**Mirrored mode networking and 9P/Plan9 share semantics.** WSL2's filesystem sharing between Windows and Linux uses the 9P protocol over Hyper-V VSock. Performance and correctness issues have surfaced in the share path historically; security-relevant issues are rarer but plausible. Newer WSL2 versions (`networkingMode=mirrored`) change the network model and the implications for host firewall rules.

## 8. macOS-specific considerations

Apple's host platform has its own constraints that interact with container tooling.

**Virtualization.framework (vz) since macOS 11.** Apple's first-party VM framework. Replaces HyperKit. Used by Docker Desktop (Apple Silicon), Rancher Desktop, Lima, Colima, OrbStack. Virtualization.framework is a `[unverified specific architecture detail]` Type-1.5 hypervisor with Apple-controlled implementation. Cross-link `[[reference-confidential-computing]]` for the trusted-execution parallel; vz is not a TEE but shares some isolation goals.

**TCC (Transparency, Consent, Control).** macOS gates access to certain resources (Camera, Microphone, Documents, Desktop, Downloads, Contacts, Calendars, Photos) behind user-consent prompts. Container tools that need broad filesystem access (Docker Desktop offering `-v ~:/host` style mounts) request TCC grants at install time. Once granted, **the VM's host-side mount-bridging code has access broader than any normal sandboxed macOS app**. This is the structural reason a malicious container with the right bind mounts can read user data that TCC-respecting apps cannot.

**Code signing and notarization.** Docker Desktop, Rancher Desktop, OrbStack ship as notarized macOS apps. The privileged helper is signed and installed via SMJobBless / SMAppService. The integrity of the install rests on Apple Developer ID notarization plus the vendor's private signing key. A compromise of either chain is fleet-wide.

**Universal-binary architecture.** Docker Desktop ships separate code paths for Intel Macs (HyperKit-backed historically) and Apple Silicon (Virtualization.framework-backed). The Intel path is being deprecated; security maintenance is uneven across the two. Treat older Intel-Mac installations as higher-risk.

**Endpoint Security framework (ES).** Apple's EDR API. Provides telemetry on process spawn, file open, network connection, code-signing events. EDR products built on ES can detect anomalous Docker Desktop child processes but have limited visibility inside the Linux VM. The blind spot below the hypervisor boundary is a structural EDR limitation, not a product gap.

**Rosetta 2 and architecture emulation.** Apple Silicon Macs can run Intel containers via Rosetta 2 emulation when configured via Docker Desktop's "Use Rosetta for x86_64/amd64 emulation" toggle. Rosetta-translated container code runs through Apple's translation layer, which has its own security properties; bugs in Rosetta would surface as a guest-side anomaly affecting only containers that opted into Rosetta emulation. Treat Rosetta as a new translation layer with its own attack surface, not as transparent.

**SIP and System Integrity Protection interactions.** Docker Desktop installs files into protected paths and registers system extensions. SIP-bypass disclosures in macOS occasionally interact with desktop container tools — an SIP-bypass plus a Docker Desktop privileged-helper bug is a compound primitive that can write to paths that should be immutable.

## 9. Enterprise policy and management

What an IT-security or AppSec lead can actually do to harden the developer fleet.

**Docker Desktop Business tier.** Centralized configuration, integrated Image Access Management, image signing enforcement, Settings Management via the `admin-settings.json` mechanism (locks down dangerous settings like privileged-container support, host-network sharing, file-sharing paths). The trade-off: one more vendor relationship with a non-zero cost; some teams choose the OSS alternatives explicitly to avoid the dependency.

**Disable Docker Desktop entirely, prefer Colima or Lima.** Some security-conscious teams move developers to Colima / Lima / Podman to avoid the Docker Desktop daemon and extension marketplace attack surface. Trade-off: less polish, more setup work, no centralized vendor support, but a smaller host-side attack surface.

**Restrict bind-mount paths.** Docker Desktop Business and Rancher Desktop both expose configuration that restricts which host paths can be bind-mounted into containers. Enforce that `~/.aws`, `~/.ssh`, `~/.docker`, `~/.kube`, `~/Library/Application Support` (macOS) and the Windows User profile root are never bind-mountable by default; require explicit grant on a per-project basis.

**Rootless container mode.** Podman supports rootless containers natively (each container runs under the developer's UID inside a user namespace, never as VM-root). Docker rootless mode exists but is less polished on Docker Desktop. Rootless is structurally the right default — every other defense in this section is a workaround for the absence of rootless.

**MDM-controlled deployment.** Jamf (macOS) and Intune (Windows) push consistent versions of Docker Desktop / Rancher Desktop and consistent config (disable insecure registries, lock extensions, enforce update channel). MDM enforcement is the only realistic way to bound the long-tail of misconfiguration on a fleet of hundreds.

**Update channel pinning and lag.** Production-grade IT security pins desktop container tools to a vetted version (one or two releases behind current), then forces an update once the new version has been deployed elsewhere for a cooldown period. This trades the latest CVE fixes for protection against a poisoned-update event. The trade-off is real; pick a side deliberately.

**CI/CD-friendly alternatives.** Developers using `docker buildx` in CI rather than local Docker Desktop reduce per-workstation attack surface. Pair with Buildkit's reproducible-build features. Encourage devcontainer.json + GitHub Codespaces / GitPod / Coder where appropriate so that the container substrate is a remote service rather than the local workstation.

**Extension allow-listing.** Docker Desktop Business permits administrators to allow-list extensions. Default-deny is the right posture; permit only named vendors with demonstrated security review.

**Vulnerability scanning of pulled images.** Docker Desktop Business includes Docker Scout integration; Snyk, Trivy, and Grype operate as separate tools developers can wire into their workflows. None of them prevent malicious-image pulls in real time; they surface after-the-fact CVE inventories. Treat as a useful inventory tool, not a defense.

**Egress proxy for the VM.** Some shops route all VM egress through a corporate proxy with TLS interception. The proxy can deny egress to known-bad destinations, log all container egress, and surface attempts at credential exfil. The trade-off: TLS interception itself is a security event (the proxy holds plaintext for every connection) and developers complain when it breaks tools that pin their own roots-of-trust.

**Devcontainer.json + Codespaces / GitPod / Coder.** Move the container substrate off the workstation entirely. The developer's machine becomes a thin client. The Surface A and B and D problems migrate to a managed remote service with centralized telemetry and short-lived workspaces. Trade-off: latency, offline-work blockers, cost. Worth considering for high-risk roles (developers with production access, security engineers, infrastructure engineers).

## 10. Detection patterns

Endpoint telemetry on macOS and Windows can see most of Surfaces C and D and parts of Surface B; container-internal events on Surface A are mostly invisible to host EDR.

**macOS Endpoint Security framework.** Process-exec, file-open, code-signing events. Useful detection points:

- Children of `Docker.app` or `Docker Desktop` that spawn unexpected binaries on the host (anything outside the small known set of helpers).
- Privileged helper IPC invocations that produce shell child processes (`/bin/sh -c` under the helper).
- Code-signing failures or anchor mismatches on Docker Desktop binaries — early warning of tampered or downgraded installation.

**Windows Event Tracing (ETW) + Security Auditing.** Sysmon Event ID 1 (process create), Event ID 11 (file create), Event ID 22 (DNS query), Event ID 25 (process image change). Detection points:

- `Docker Desktop.exe` or `wsl.exe` spawning unexpected children.
- WSL2 distros writing to or reading from `\\wsl$\<distro>\..\Windows\...` paths that suggest Windows-credential access from inside Linux.
- DPAPI access from the WSL2 service context.

**Unusual bind-mount operations.** Docker / containerd emit log events for bind-mount creation. A SIEM rule that flags bind mounts of `/`, `~`, `~/.ssh`, `~/.aws`, `~/.docker`, `~/.kube`, `~/Library/Application Support`, `C:\Users\<user>\.aws`, etc. catches most Surface D events.

**Network egress from VM to unusual destinations.** The VM's egress flows through a host-managed virtual interface. Host-level network telemetry can see the destination IPs and DNS names. Egress to webhook.site, requestbin, ngrok subdomains, paste services, attacker-controlled cloud IPs is anomalous from a developer container. Cross-link `[[reference-falco-tetragon-runtime-detection]]` §10 for the Linux-side runtime detection of the same anomalies inside the VM.

**Browser cookie file reads from container context.** Anomalous: `bash` inside a container reading `Cookies.sqlite`. Detectable on Linux runtime by Falco / Tetragon if instrumented inside the VM; detectable on host EDR only if the bind mount surfaces the read as a host file-open from the dockerd process.

**Privileged helper request volume and source.** Spike in privileged-helper IPC requests, or requests from unexpected client codesign anchors, is a signature of an exploit attempt against the helper.

**Limitations.** Runtime detection on developer workstations is structurally weaker than on servers: workstations are noisier, EDR coverage inside Linux VMs is rare, the volume of legitimate container activity overwhelms anomaly detection. Treat detection as a useful supplement to policy, not a replacement.

**Detection rules worth shipping in any EDR / SIEM environment with desktop container tooling:**

- Process-create where parent is `Docker Desktop.app/Contents/MacOS/Docker Desktop` and child is anything outside the small allow-list of expected helpers and frameworks.
- File-open of `~/.aws/credentials`, `~/.ssh/id_rsa`, `~/.kube/config`, `~/.git-credentials`, browser `Cookies` SQLite databases where the opening process is a container-tooling component or descendant.
- Privileged helper IPC where the calling client codesign anchor is not the expected Docker / Rancher / Podman / OrbStack vendor anchor.
- Network egress from the VM virtual interface to known credential-exfil destinations (webhook.site, requestbin.com, ngrok subdomains, paste services). Maintain an updated allow-list of legitimate developer-tooling destinations and deny by exception.
- `docker run` invocations whose bind-mount arguments include `/`, `~`, `~/.ssh`, `~/.aws`, `~/.docker`, `~/.kube`, `~/Library/Application Support`, `C:\Users\<user>\.aws`. This rule alerts on most accidental misconfigurations and on most malicious activity.

## 11. 2024-2026 currency

The platform is moving; record the state of play so future-Claude can re-orient.

**Docker Desktop subscription model.** Mature. Docker Inc requires a paid license for orgs above a size threshold since 2021; Docker Desktop Business since 2022 has matured into an enterprise SKU with admin-settings.json, image-access management, and centralized policy. Many enterprises are now Docker-Desktop-Business customers; the centralized policy surface is a meaningful security gain.

**Podman Desktop GA progress.** GA since 2023; 1.x line stable. Adoption growing in security-conscious shops because of rootless-by-default and daemonless architecture. Red Hat's investment is substantial.

**Apple Silicon native support across all tools.** Apple Silicon Macs are dominant in developer fleets at most modern shops since ~2023. Every desktop container tool ships Apple Silicon native; HyperKit on Intel is being deprecated. Surface A and B threat models on Intel and Apple Silicon Macs differ in implementation (HyperKit vs Virtualization.framework) but converge in the modern fleet.

**WSL2 stable but Hyper-V CVE class continues.** WSL2 is GA and stable. Hyper-V continues to ship CVEs at a steady cadence — boundary not broken, but tested.

**MCP + Docker Extension intersection.** Docker has published MCP server integrations and there is a marketplace of Docker-resident MCP servers as of 2025. Combined with AI-IDE clients (Claude Code, Cursor, Cline) speaking MCP, the prompt-injection-to-container-spawn pipeline is a new attack class. Cross-link `[[reference-ai-assisted-coding-tool-security]]` and `[[reference-ai-agent-session-management]]`.

**AI-IDE container spawn.** Cursor, Continue, Cline, Claude Code can all spawn containers via Docker Desktop / Podman Desktop. A prompt-injection in the AI-IDE's context (via a malicious file, README, dependency README, indirect injection) can drive the IDE to `docker run -v /:/host attacker/image`. The blast radius is the Surface D problem at the speed and frequency of AI agent action. Treat AI-IDE container-spawn permissions like sudo permissions: scope tightly, default-deny mounts, audit logs.

**Confidential containers / Kata-on-the-desktop.** Largely server-side as of writing; not yet a developer-workstation default. Watch the Kata Containers and Confidential Containers projects (`[[reference-confidential-computing]]`) for any move into desktop tooling.

## 12. Honest failure modes — load-bearing

Where the doc's defenses fail in practice. Internalize this section.

**Dev workstation is the keys to many kingdoms.** §6 is the single most-important fact in this doc.

Cloud credentials for every account the developer touches, source-control credentials for every repo, SaaS session cookies for every internal tool, SSH keys for every server — all on one machine.

A container-tool compromise is not a contained event. Cross-link `[[reference-secrets-management-discipline]]`.

**Host-side daemon is the highest-trust component.** Docker Desktop's privileged helper has more attack surface than the VM itself.

Audit the privileged helper like a kernel module.

Track Docker / Rancher / Podman release notes for helper-related advisories specifically.

**VM boundary is rarely breached but catastrophic when it is.** Hypervisor CVEs are rare in absolute count.

The impact is total when they land: container → VM → host, no further mitigation.

Mitigation is patching speed and update-channel hygiene.

**Browser cookie exfil is the most-overlooked attack class.** §6 again.

A bind-mounted home directory plus a malicious image reads `Cookies.sqlite` and exfiltrates SaaS sessions in seconds.

EDR rarely detects this because the host file-open looks like normal Docker Desktop bind-mount activity.

The blast radius is SaaS account takeover for every app the developer has signed into in the last cookie-lifetime window.

**Docker Extension marketplace is a supply-chain surface.** Extensions run with elevated privileges; vendor vetting is opaque.

Treat as one would treat unsigned browser extensions: default-deny, allow only named vendors.

The MCP-as-extension pattern (§5) compounds this.

**Auto-update channels are mass-compromise vectors.** Compromise of a vendor's signing infrastructure is one-shot fleet compromise.

Mitigation: pin to a vetted version with a cooldown window before adopting updates.

Trade-off: short window of exposure to the most recent CVEs. Pick a side deliberately and document it.

**WSL2 boundary on Windows is structurally similar to other VM boundaries** — but enterprise visibility inside the WSL2 distro is much lower than on the Windows host side.

Admins frequently underweight WSL2 in policy.

**macOS Virtualization.framework adoption hides per-vendor implementation issues behind a shared dependency.** A Virtualization.framework bug affects every Mac desktop container tool simultaneously.

Apple discloses these less systematically than Microsoft discloses Hyper-V bugs; the visibility into shared-framework CVE risk is lower than the actual risk warrants.

**OSS alternatives shift but don't eliminate attack surface.** Lima, Colima, Podman avoid Docker Desktop's daemon and extension marketplace, but introduce their own privileged components, their own update channels, their own VM substrate.

Rootless modes are not universally available and not universally configured.

The migration is sometimes a wash from a security perspective, sometimes a real gain — it depends on which surfaces matter most in the threat model.

**AI-IDE integration adds prompt-injection-driven container spawn.** Cline, Cursor, Claude Code, Continue all spawn containers via Docker Desktop / Podman as part of their tool repertoire.

A prompt-injection in the AI's context becomes a `docker run` with attacker-controlled image and mount paths.

The Surface D problem at AI-agent speed and frequency. Treat AI-IDE container-spawn permissions like sudo: scope, default-deny mounts, audit.

Cross-link `[[reference-ai-assisted-coding-tool-security]]` §6, `[[reference-ai-agent-session-management]]`.

**Threat-model omission.** Many AppSec programs threat-model production container infrastructure and ignore developer workstations entirely. The blast radius of a dev workstation compromise is frequently larger than that of a single production container. Bring dev workstations into the threat model. Cross-link `[[reference-threat-modeling-discipline]]`.

**EDR blind spot inside the VM.** The Surface A class (container-to-VM-guest escape) is invisible to host EDR almost by definition: every event happens inside the Linux VM's kernel and userspace, and host EDR instruments macOS or Windows, not the Linux guest. Falco / Tetragon inside the VM closes this gap on paper but is rarely deployed on developer workstations; the configuration burden is too high. The practical effect: Surface A escapes are detected (if at all) by their second-order Surface B / Surface D effects on the host.

**The OOB-update window.** When a Docker Desktop / Rancher Desktop / Podman Desktop CVE is announced, the gap between announcement and fleet patch is typically days-to-weeks on managed fleets and longer on unmanaged ones. Attackers who can identify developer-workstation IPs (via reverse-DNS, browser fingerprinting on internal portals, or exposed dev-tunnel endpoints) can target the window. MDM-forced updates close the window faster but introduce the auto-update risk above. There is no clean answer — pick a side and document it.

## 13. Cross-link cluster

Sibling docs in the corpus that anchor or extend this one.

- `[[reference-container-runtime-escape]]` — the runc / leaky-vessels / cgroup-escape corpus on Linux. Surface A is identical there.
- `[[reference-container-k8s-security]]` — Kubernetes orchestrator policy, Pod Security Standards, admission control.
- `[[reference-linux-kernel-exploitation]]` — Linux kernel inside the VM. Any in-VM kernel CVE is in scope.
- `[[reference-macos-apple-security]]` — macOS host platform. TCC, code signing, Endpoint Security framework, Network Extensions.
- `[[reference-active-directory-windows-security]]` — Windows host platform and AD-joined considerations. WSL2 + DPAPI + Credential Manager interop.
- `[[reference-confidential-computing]]` — TEE and VM-isolated trusted execution parallel. Virtualization.framework is not a TEE but the design discipline overlaps.
- `[[reference-secrets-management-discipline]]` — credential storage discipline on developer workstations.
- `[[reference-session-management]]` — SaaS session-cookie exfil blast radius downstream of Surface D.
- `[[reference-cicd-supply-chain]]` — auto-update channel compromise and signing-key supply chain.
- `[[reference-falco-tetragon-runtime-detection]]` — runtime detection inside the Linux VM.
- `[[reference-ai-assisted-coding-tool-security]]` — AI-IDE threat model that includes Docker / MCP integration.
- `[[reference-ai-agent-session-management]]` — AI-agent permission scoping for tool actions including container spawn.
- `[[reference-threat-modeling-discipline]]` — bringing developer workstations into the threat model.
- `[[reference-cloud-iam]]` — AWS / Entra / GCP blast radius downstream of leaked credentials from §6.

End of doc.
