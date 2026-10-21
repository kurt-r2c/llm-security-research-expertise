# Staff-Level Container and Kubernetes Security Guiding Principles
## Synthesized from Ian Coldwater, Brad Geesaman, and Collaborators

> **Primary researchers:**
> - **Ian Coldwater** (@IanColdwater) — Senior Principal Security Architect at Docker; Kubernetes
>   SIG Security co-chair; CNCF Top Ambassador 2020. "Container escape artist." Focuses on what
>   default Kubernetes configurations look like to an attacker.
> - **Brad Geesaman** (@bradgeesaman) — Ghost Security; previously Darkbit co-founder (acquired
>   by Aqua Security). Pioneered GKE-specific attack research; discoverer of CVE-2020-15157
>   (ContainerDrip).
>
> **Collaborators (co-presenters or co-authors with the above):**
> - **Duffie Cooley** (@mauilion) — Field CTO at Isovalent/Cisco; SIG-Honk; co-presenter Black
>   Hat 2019, KubeCon NA 2021
> - **Rory McCune** (@raesene) — Senior Security Researcher at Datadog; CIS Docker and Kubernetes
>   Benchmark author; prolific practitioner, 50+ talks
> - **Liz Rice** (@lizrice) — Chief Open Source Officer at Isovalent; "Containers from Scratch";
>   O'Reilly books on container security and eBPF; Tetragon lead
> - **Andrew Martin** (@sublimino) — CEO of ControlPlane; *Hacking Kubernetes* (O'Reilly); kubesec
> - **Tabitha Sable** (@TabbySable) — Kubernetes SIG Security co-chair; co-presenter KubeCon EU 2021
>
> This group is informally known as **SIG-Honk**. The four (Coldwater,
> Geesaman, Cooley, McCune) appear together across multiple talks.
>
> Sources: KubeCon/Black Hat/DEF CON schedules and slides; GitHub CVE advisories; raesene.github.io
> blog; bgeesaman.github.io; mbechler.github.io; Speaker Deck; NVD; CIS; O'Reilly.
>
> **2024-2026 contributors added in subsequent revisions:**
> - **Wiz Research Team** (Nir Ohfeld, Ronen Shustin, Sagi Tzadik, Hillai Ben-Sasson) — IngressNightmare disclosure (CVE-2025-1097/1098/1974/24513/24514), arguably the highest-impact Kubernetes disclosure cluster since CVE-2018-1002105.
> - **Rory McNamara** (Snyk Security Labs) — Leaky Vessels cluster (CVE-2024-21626 runc + 3 BuildKit CVEs), 2024-01-31.
> - **Liz Rice + Isovalent / Cilium team** — Tetragon eBPF in-kernel enforcement; *Learning eBPF* (O'Reilly 2023).
> - **Chainguard / Wolfi team** (Dan Lorenc, Kim Lewandowski, Adolfo García Veytia and others) — continuously rebuilt distroless images as a productized hardening primitive.
>
> Cross-references to companion expertise docs: [`cloud_iam_expertise.md`](./cloud_iam_expertise.md),
> [`supply_chain_provenance_expertise.md`](./supply_chain_provenance_expertise.md),
> [`confidential_computing_expertise.md`](./confidential_computing_expertise.md),
> [`adversarial_ml_model_security_expertise.md`](./adversarial_ml_model_security_expertise.md),
> [`llm_agent_security_expertise.md`](./llm_agent_security_expertise.md),
> [`detection_engineering_expertise.md`](./detection_engineering_expertise.md),
> [`cicd_supply_chain_expertise.md`](./cicd_supply_chain_expertise.md).

---

## 1. Core Philosophy

### Think like the attacker first — then build defenses that matter

The defining contribution of this research community is relentless attacker-perspective framing
applied to production Kubernetes defaults. Ian Coldwater's central question — "what does an
attacker see when they look at your cluster?" — is the right starting point for any security
assessment. The answer is almost never the CVE your scanner found. It is the combination of
defaults, misconfigurations, and RBAC grants that chain into cluster-admin access via paths no
scanner models.

The lesson of Brad Geesaman's KubeCon 2017 talk
still holds: most Kubernetes compromises do not require a zero-day. They use unvetted images, no
network policy, cleartext secrets in environment variables, and anonymous API server access — all
defaults or common configurations.

### Features are weapons

From Ian Coldwater's KubeCon 2019 keynote: Kubernetes features designed for legitimate use are
frequently the best attack primitives. Ephemeral containers enable post-compromise persistence
without modifying a pod spec in a way that triggers alerts. The Dynamic Audit Sink feature lets
you filter your own activity from audit logs. Validating webhooks, intended to enforce policy, can
intercept and mutate all pod creation. The `nodes/proxy` RBAC permission, used for legitimate
monitoring, provides kubelet API access that bypasses audit logging entirely.

Security policy must account for the attacker who can use every feature in your cluster, not
only the features classified as "dangerous."

### Defense-in-depth: no single control is reliable

From the "Malicious Compliance" talk (Coldwater, Geesaman, Cooley, McCune, KubeCon EU 2023):
container vulnerability scanners — Trivy, Grype, Docker Scan, Docker Scout — can all be bypassed
by intelligent adversaries using techniques that require no CVEs and no zero-days. Image scanning
is a **policy control**, not a security boundary. Any single control can be evaded; defense
requires overlapping layers.

### Threat model first — everything else follows

From Brad Geesaman's KubeCon 2017 and Ian Coldwater's persistent framing: the questions that
matter before any hardening decision:
- What are you protecting?
- Who are you protecting it from?
- What is the blast radius if a workload is compromised?
- What does lateral movement look like in your cluster?
- Where do your audit logs go, and can a cluster-admin delete them?

Without a threat model, hardening decisions are guesswork. With one, they are prioritized.

---

## 2. Container Primitives: What Isolation Actually Is

### A container is a Linux process — nothing more

From Liz Rice's "Containers from Scratch" (DockerCon, GOTO Chicago 2018, and many others): a
container is a Linux process with its view of the world limited through three kernel mechanisms.
Understanding these mechanisms is the foundation for understanding every container escape.

**Namespaces — what you can see:**

| Namespace | `CLONE_NEW*` flag | Isolates |
|-----------|------------------|---------|
| UTS | `CLONE_NEWUTS` | Hostname, domain name |
| PID | `CLONE_NEWPID` | Process tree |
| Mount | `CLONE_NEWNS` | Filesystem view (mount points) |
| Network | `CLONE_NEWNET` | Network interfaces, routing, iptables |
| User | `CLONE_NEWUSER` | UID/GID mappings (allows fake root) |
| IPC | `CLONE_NEWIPC` | System V IPC, POSIX message queues |
| Cgroup | `CLONE_NEWCGROUP` | Cgroup root |

A container starts as a normal process calling `clone(2)` with namespace flags. The isolation is
real but it is entirely kernel-enforced — any kernel bug or misconfiguration that lets a process
cross a namespace boundary breaks all container isolation.

**Cgroups — what you can use:**
Control the resource consumption of a process group: CPU time, memory, block I/O, network
bandwidth, process count. Controlled via the cgroup filesystem at `/sys/fs/cgroup/`. Container
runtimes set these limits at container start; they are not a security boundary in the same sense
as namespaces (they prevent resource exhaustion, not access).

**chroot / pivot_root:**
Sets the filesystem root boundary. A container's root filesystem is a directory tree on the host
that appears as `/` inside the container. Combined with a mount namespace, this provides
filesystem isolation — but only as strong as the mount namespace.

### Linux capabilities: the real privilege model inside containers

Linux capabilities decompose root privileges into discrete units. Containers, by default, run
with a restricted set. The most dangerous capabilities:

**`CAP_SYS_ADMIN`:** The "root of capabilities." Enables mount operations,
`nsenter` into other namespaces, setting hostname, filesystem quotas. Granting
`CAP_SYS_ADMIN` to a container is effectively granting root on the host with extra steps.
kubesec (Andrew Martin) flags this as the highest-risk finding in manifest analysis.

**`CAP_NET_ADMIN`:** Configure network interfaces, iptables, routing tables. In a shared network
namespace (hostNetwork), enables network attacks against other pods and host services.

**`CAP_NET_RAW`:** Raw packet access. Enables ARP spoofing, packet capture, ICMP attacks against
the pod network.

**`CAP_SYS_PTRACE`:** Attach a debugger to processes in other namespaces — effectively
cross-namespace process injection if combined with shared PID namespace.

The security context field `allowPrivilegeEscalation: false` sets the `no_new_privs` prctl flag,
preventing the container from gaining new capabilities via setuid binaries. This should always
be set in Restricted pod security profiles.

### seccomp: syscall filtering

seccomp (Secure Computing Mode) filters system calls via a BPF program. Docker and containerd
apply a default seccomp profile that disables around 44 of 300+ syscalls including the most dangerous:
`ptrace`, `kexec_load`, `open_by_handle_at`, `bpf` (partially), `perf_event_open`. Kubernetes
did not apply the Docker default seccomp profile by default until `SeccompDefault`
(alpha kubelet feature gate in k8s 1.22, stable in 1.27) — before that, all pods ran with no seccomp unless
explicitly configured.

PSS Restricted level requires `seccompProfile.type: RuntimeDefault` or `Localhost`.

### AppArmor and SELinux: mandatory access control

AppArmor (Ubuntu/Debian) and SELinux (RHEL/CentOS/Fedora) are LSMs (Linux Security Modules)
that apply mandatory access control on top of DAC (discretionary — ownership/permissions).
Containers can apply AppArmor profiles that restrict which files can be written, which syscalls
invoked, what network operations are allowed — independent of the capabilities granted.

The default Docker AppArmor profile blocks key escape paths (`mount`, `pivot_root`, some
procfs/sysfs writes). Kubernetes workloads without an explicit AppArmor profile run unconfined
unless the node's container runtime applies one by default.

---

## 3. Container Escape Techniques

### Privileged container: direct host access

`securityContext.privileged: true` does not put the container in the host's namespaces (that is
what `hostNetwork`/`hostPID`/`hostIPC` do), but it runs with all capabilities, with access to all host
devices. A privileged container can:
- Mount host `/` via `mount /dev/sda1 /mnt`
- Load kernel modules
- Use `nsenter` to enter any other namespace on the host
- Access any device in `/dev`

This is the most direct container escape. Any workload requiring `privileged: true` should be
treated as a host-level access grant.

### nsenter: namespace traversal from a privileged container

With `CAP_SYS_ADMIN` and `hostPID: true` (or from a privileged container):
```bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```
This enters the init process's (PID 1) namespaces — effectively exiting the container and running
in the host context. Demonstrated by Coldwater/Cooley at Black Hat 2019.

### hostPath volume: the filesystem escape that doesn't look like an escape

Mounting the host filesystem into a container via `hostPath`:
```yaml
volumes:
- name: host-root
  hostPath:
    path: /
volumeMounts:
- name: host-root
  mountPath: /host
```
The container gets read/write access to the entire host filesystem. From there: read etcd data
directly (if accessible), read kubelet credentials, read other pods' secrets, write to host
init scripts for persistence.

Critically: many organizations block `hostPath` with admission policies but miss the subPath
symlink bypass (CVE-2021-25741).

### Docker socket: the backdoor that ships by default

Mounting `/var/run/docker.sock` into a container grants full Docker API access:
```yaml
volumes:
- name: docker-sock
  hostPath:
    path: /var/run/docker.sock
```
From inside: `docker run --rm -v /:/host --privileged ubuntu chroot /host bash` — full host
root. The Docker socket is equivalent to a root shell on the host.

### CVE-2021-25741: subPath symlink exchange (CVSS 8.8)

Reported by Fabricio Voznika and Mark Wolters of Google; the advisory thanks Coldwater, Geesaman,
Cooley, and McCune for related research. A container with a subPath volume mount can
create a symlink inside the subPath directory. On subsequent container creation or kubelet
reconciliation, the symlink is followed during mount setup → the container gains access to host
filesystem paths outside the declared volume.

**Why this matters beyond the CVE:** This bypasses explicit `hostPath` restrictions. An
organization that explicitly denies `hostPath` mounts via admission control is unprotected,
because subPath achieves equivalent host filesystem access without the `hostPath` configuration
field. Security policy that blocks only the obvious mechanism is incomplete.

Affected: k8s ≤v1.21.4, ≤v1.20.10, ≤v1.19.14, v1.22.0-v1.22.1.
Interim mitigation: disable the `VolumeSubpath` feature gate on kubelet and kube-apiserver.

### CVE-2021-30465: runc mount race condition (CVSS 8.5)

Discovered by Etienne Champetier (champtar). runc before 1.0.0-rc95: when a
pod starts multiple containers concurrently, an attacker controlling one container can race to
swap a volume mount destination symlink. The next container's mount setup follows the new symlink
→ the mount lands at the host filesystem path the symlink points to → container escape.

Requires: ability to create pods with specific mount configurations. Fix: runc 1.0.0-rc95.

### CVE-2024-21626 / Leaky Vessels: runc WORKDIR breakout (CVSS 8.6)

Discovered by Rory McNamara of Snyk Security Labs (disclosed 2024-01-31, alongside three
BuildKit CVEs in the same Leaky Vessels cluster: CVE-2024-23651 mount-cache race,
CVE-2024-23652 build-teardown arbitrary delete, CVE-2024-23653 GRPC privilege check). The
runc vulnerability is an order-of-operations container breakout: leaked file descriptors
pointing into the host filesystem namespace are inherited by a `runc exec`-spawned process,
which can then use `WORKDIR` to land in the host filesystem at process start. A malicious
image (or a malicious Dockerfile run through `docker build`) can escape to host root with
no additional privileges and no host-side misconfiguration.

Fixes: runc 1.1.12, BuildKit 0.12.5, Moby/Docker engines that bundle the patched runc. Snyk
released `leaky-vessels-static-detector` (Dockerfile static analysis) and
`leaky-vessels-runtime-detector` (eBPF runtime) as companion tooling. The CVE cluster also
re-emphasized that **image build infrastructure is in scope for container escape research**,
not only image-runtime infrastructure — anyone who can submit a malicious Dockerfile to a
shared BuildKit instance has the same blast radius as anyone running a malicious image.
Sources: [Snyk Labs Leaky Vessels overview](https://labs.snyk.io/resources/leaky-vessels-docker-runc-container-breakout-vulnerabilities/);
[Snyk Labs CVE-2024-21626 deep dive](https://labs.snyk.io/resources/cve-2024-21626-runc-process-cwd-container-breakout/);
[Wiz deep dive on Leaky Vessels](https://www.wiz.io/blog/leaky-vessels-container-escape-vulnerabilities).

### CVE-2020-15257: containerd-shim abstract socket (CVSS 5.2)

Discovered by NCC Group. containerd-shim exposes
its management API over an abstract namespace Unix domain socket. Abstract sockets are accessible
from the root network namespace without any filesystem path or permission check. Any container
with `hostNetwork: true` (or in the same network namespace as the host) can connect to the shim
API and execute commands on the host as root.

Fix: containerd v1.4.3/v1.3.9 switched to file-based Unix sockets with appropriate permissions.
**Lesson:** Abstract Unix sockets are accessible from host network namespace — they are not
filesystem-isolated the way named sockets are. Any container sharing the host network namespace
can reach them.

---

## 4. Kubernetes Attack Paths

### CVE-2018-1002105: privilege escalation via proxied upgrade requests (CVSS 9.8)

Analyzed and taught by Ian Coldwater (KubeCon EU 2019). Root cause: incorrect error handling of
proxied upgrade requests in kube-apiserver. Attack:

1. Craft a request to establish a connection through kube-apiserver to a backend (aggregated API
   server or kubelet)
2. The connection persists after the API server fails to properly handle the upgrade error
3. Attacker sends arbitrary requests authenticated with the API server's own TLS credentials

Two exploitation paths:
- Via `pod exec`/`attach`/`portforward` → kubelet API → list all pods, exec commands on any pod
- Via any aggregated API endpoint → unauthenticated users can trigger backend escalation

**Critical property:** Unauthorized requests appear in audit logs as legitimate proxied API server
traffic. No anomalous authentication event. Detection via audit logging was blind.

### IngressNightmare (CVE-2025-1974 et al.): unauthenticated cluster takeover via the admission webhook

Disclosed 2025-03-24 by Nir Ohfeld, Ronen Shustin, Sagi Tzadik, and Hillai Ben-Sasson at Wiz
Research. A five-CVE cluster in ingress-nginx
(CVE-2025-1097 `auth-tls-match-cn`, CVE-2025-1098 `mirror-target` / `mirror-host`,
CVE-2025-1974 master RCE at CVSS 9.8, CVE-2025-24513 path traversal,
CVE-2025-24514 `auth-url`). The chain:

1. The ingress-nginx ValidatingAdmissionWebhook listens on port 8443 inside the cluster pod
   network with **no authentication on the admission endpoint by default**.
2. Any attacker with pod-network reachability sends an `AdmissionReview` containing an
   Ingress object with malicious annotations — no RBAC `create` on Ingress required, because
   the webhook validates payloads regardless of caller identity.
3. The admission controller writes the rendered nginx configuration to a temp file and
   shells out to `nginx -t` to validate. Crafted annotations inject arbitrary nginx
   directives, in particular `ssl_engine` which loads an attacker-controlled shared library
   that the attacker stages by sending a large request body that NGINX buffers to a temp file,
   referenced via `/proc/<pid>/fd/<n>`.
4. `nginx -t` loads and executes the shared library as the ingress-nginx ServiceAccount,
   which has cluster-wide secret read access by default → instant cluster takeover.

Wiz scanned the public internet and found ~6,500 clusters exposing the admission webhook
publicly, including Fortune 500 environments; their telemetry indicates ~43% of audited cloud
environments ran a vulnerable ingress-nginx. Fixed in ingress-nginx v1.12.1 and v1.11.5.
Interim mitigation: disable the ValidatingWebhookConfiguration
(`helm upgrade ... --set controller.admissionWebhooks.enabled=false`) or NetworkPolicy-isolate
the webhook so only kube-apiserver can reach it.

**Why this matters beyond the CVE:** Two structural lessons. First, admission webhooks are
**privileged code-execution surfaces** that often run with cluster-admin or near-equivalent
permissions; their authentication posture is rarely audited. Second, an admission controller
that shells out to a config-parser like `nginx -t` to validate input is effectively running
attacker-controlled commands during validation — the validation step itself is the sink.
Any admission webhook that writes user-controlled data to disk and then exec's a tool to
parse it has the same shape of vulnerability latent.

Sources:
[Kubernetes project blog 2025-03-24](https://kubernetes.io/blog/2025/03/24/ingress-nginx-cve-2025-1974/);
[Wiz Research disclosure](https://www.wiz.io/blog/ingress-nginx-kubernetes-vulnerabilities);
[Datadog Security Labs overview + detection](https://securitylabs.datadoghq.com/articles/ingress-nightmare-vulnerabilities-overview-and-remediation/).

### RBAC: the permission graph is the attack surface

RBAC is the primary Kubernetes authorization mechanism — and its misconfiguration is the most
common path from low-privilege workload to cluster-admin. Key principles:

**`nodes/proxy` is cluster-admin without the label** (McCune + Iain Smart, NCC Group):
`get` and `create` on `nodes/proxy` allows proxying connections through kube-apiserver to
the kubelet API on any node. The kubelet API (port 10250) can exec commands in any pod on that
node. This path:
- Bypasses Kubernetes audit logging entirely (requests go kubelet → not API server audit)
- Bypasses all admission controllers
- Bypasses network policies (traffic routes through API server)
- Is widely granted unknowingly in monitoring and management tooling

Any account with `nodes/proxy` get+create effectively has cluster-admin access with a significantly
smaller audit footprint.

**RBAC privilege escalation paths (documented):**
- `cluster-admin` binding (obvious)
- `create` on `pods` + `hostPath` / `privileged` allowed → container escape → host access
- `create` on `serviceaccounts/token` → create long-lived tokens for privileged SAs
- `update` on `clusterrolebindings` → add yourself to cluster-admin
- `create` on `validatingwebhookconfigurations` → intercept and mutate all API requests
- `create` on `daemonsets` in kube-system → run privileged pod on every node
- `create` on `pods/exec` in privileged namespace → exec into privileged pod
- `get` on `secrets` in any namespace containing cluster-admin tokens → credential theft
- Certificate Signing Request API + `approve` verb → sign arbitrary client certificates

**Token enumeration (TOKEN_BRUTEFORCE in KubeHound model):**
An account with `get` but not `list` on secrets cannot enumerate secret names via the list API,
but can construct names from known patterns (e.g., `<serviceaccount-name>-token-<random>`) and
fetch them individually. This lets low-privilege accounts enumerate service account tokens by
brute-forcing name patterns.

### The Kubernetes CA: the "golden ticket" with no revocation

The cluster CA private key is the master credential. If compromised:
- Forge arbitrary client certificates with any CN (username) and O (group)
- Map to any RBAC identity in the cluster
- **Kubernetes has no certificate revocation** (no CRL, no OCSP)
- Only remediation: full CA rotation across the entire cluster — a disruptive operation
- CA certificates have 10-year validity by default → forged access persists for a decade

Exposure paths: CA key committed to git, accessible via hostPath mount from control plane node,
found on internet-exposed API servers. Managed Kubernetes (GKE, EKS, AKS) mitigates this by
keeping CA keys inaccessible to users — a major security argument for managed k8s.

### kubelet: the node-level authority that bypasses everything

The kubelet API (port 10250) accepts direct requests to:
- `POST /run/{namespace}/{pod}/{container}` — execute commands in a container
- `GET /logs/{path}` — read node filesystem logs
- `GET /pods` — list all pods on the node

If authenticated kubelet requests are not required (`--anonymous-auth=true` or
`--authorization-mode=AlwaysAllow`, common in older clusters), any network-accessible kubelet is
fully exploitable without credentials.

Even with authentication required, reaching the kubelet via `nodes/proxy` bypasses audit logging
as documented above.

### etcd: the database that stores all secrets

etcd stores all Kubernetes state including all Secrets. An attacker with etcd access (direct or
via TLS certificates from a compromised control plane node) has:
- All Kubernetes Secrets in plaintext (if encryption at rest is not enabled)
- All service account tokens
- All RBAC policies
- All pod specs — including environment variables containing credentials

Ian Coldwater and Duffie Cooley's Black Hat 2019 demo: mount host `/` from a pod → read etcd
data files directly → extract cluster-admin credentials. Defense: etcd encryption at rest
(`--encryption-provider-config`), restrict network access to etcd to control plane nodes only,
audit etcd access separately from Kubernetes API access.

### The shadow API server: persistence with no logs, no RBAC, no admission control

From "Advanced Persistence Threats" (Coldwater + Geesaman, RSA 2020 / KubeCon EU 2020):

If an attacker gains access to a node running the API server (via container escape from a
co-located pod), they can:
1. Read etcd TLS certificates from the filesystem
2. Have network access to etcd (same node or pod CIDR)
3. Deploy a secondary, attacker-controlled kube-apiserver that talks directly to etcd
4. The shadow API server has: **no RBAC** (it's the attacker's apiserver), **no audit logging**,
   **no admission control** ("no security policy, no logs, no crime")
5. The shadow apiserver is invisible to existing monitoring — it's not in the cluster's resource
   inventory

This is the most powerful persistence technique in the entire research body. Detection requires
monitoring for: unexpected apiserver processes on control plane nodes, unexpected connections to
etcd from non-control-plane processes, and network traffic patterns to the etcd port.

### Audit log manipulation: covering tracks at cluster scale

Also from "Advanced Persistence Threats":

**Audit log bypass via annotation padding:**
Pad a pod spec's `annotations` field with large amounts of junk data → if audit truncation is enabled (it is
off by default), the Kubernetes API server truncates audit log entries at a byte limit → all data after the annotation is dropped from the
audit record → pod spec details (including malicious container images, capabilities, mounts)
are hidden from the audit log.

**Dynamic audit sink modification:**
The `DynamicAuditing=true` feature gate (available in older Kubernetes versions) allowed
runtime modification of audit sink configurations. An attacker with cluster-admin could
modify the audit policy to filter their own activity — preventing it from being logged entirely.

**Implication for defenders:** Audit log integrity cannot be assumed if the cluster itself stores
audit configuration. Audit logs must be shipped to an **off-cluster, immutable backend** (S3 with
object lock, a SIEM, a dedicated log service) before they can be trusted.

### Validating webhooks: turning a security control into an attack vector

From "Advanced Persistence Threats":

Validating webhooks are intended to enforce policy by intercepting API requests. An attacker
with permissions to create `ValidatingWebhookConfigurations` can deploy a malicious webhook that:
- Intercepts all pod creation requests cluster-wide
- Exfiltrates pod specs (containing environment variables, mounted secret references, image names)
- Denies legitimate pods to cause disruption
- If it's a MutatingWebhookConfiguration: injects malicious containers into all new pods

Webhook configuration requires high privileges. Defense: restrict `ValidatingWebhookConfiguration`
and `MutatingWebhookConfiguration` create/update to cluster-admin only; monitor changes to webhook
configurations as a high-priority event.

---

## 5. Persistence Techniques

### C2BERNETES: using Kubernetes as C2 infrastructure

From "Advanced Persistence Threats": K3s (single binary, ~40MB) can be deployed inside a
compromised cluster as covert C2 infrastructure. It creates a single outbound TLS connection
that blends with legitimate cluster traffic. The attacker's C2 channel rides inside the cluster's
own network fabric, making it difficult to distinguish from normal Kubernetes API traffic.

### Phantom credentials: forged certificates that last a decade

From Rory McCune's persistence research: once a CA key is obtained, an attacker generates a
forged client certificate with a chosen identity, stores it externally, and uses it for ongoing
access. Since Kubernetes has no certificate revocation:
- The forged certificate remains valid until the CA is rotated
- CA rotation is a disruptive cluster-wide operation that many operators avoid
- Default CA certificate validity is 10 years
- Detection: robust audit log retention matching the certificate lifetime, and monitoring for
  unknown client certificate CNs in API server authentication logs

### Static containers and CRI-O/containerd direct API

Containers created directly via the container runtime API (containerd gRPC, CRI-O API) without
going through the Kubernetes API server are invisible to `kubectl get pods`. They do not appear
in any Kubernetes resource listing because they have no corresponding Pod object in etcd.

Techniques:
- Static pods (placed in `/etc/kubernetes/manifests/`) are managed by kubelet directly and may
  not appear in all management tooling depending on the cluster's configuration
- Creating containers via `ctr` (containerd CLI) or `crictl` bypasses the API server, admission
  control, audit logging, and RBAC entirely

Detection: monitor at the container runtime level (Tetragon, Falco with CRI hooks), not only
at the Kubernetes API level.

### Kubelet API direct traffic: bypassing the entire API server stack

Direct traffic to the kubelet API bypasses:
- Kubernetes audit logging (kubelet has its own logging, often not aggregated)
- Admission controllers
- Network policies (network policy is applied at the CNI level, not the kubelet level)

This is a persistence/lateral-movement technique for
attackers who have cluster-level privileges but want to minimize their audit footprint.

---

## 6. Cloud-Provider-Specific Attack Paths and Workload Identity Evolution

### 6a. GCP/GKE-Specific Attack Paths (Brad Geesaman / Darkbit)

### The kube-env metadata attack chain

The GCP instance metadata API (`http://metadata.google.internal/computeMetadata/v1/`) is
accessible from pods on GKE nodes without authentication by default (unless Metadata Concealment
or Workload Identity is enabled).

The `kube-env` attribute contains bootstrap certificates and keys that allow nodes to issue
Certificate Signing Requests for any hostname in the cluster. Brad Geesaman's `kube-env-stealer`
tool automates:

1. Read `kube-env` from metadata API
2. Extract bootstrap certificate and private key
3. Generate valid kubelet TLS certificates for **every node in the cluster** (the bootstrap cert
   is not node-specific — it can create certs for any node identity)
4. Impersonate each kubelet to the API server
5. kubelet credentials allow reading Secrets for pods scheduled on that node
6. Enumerate all nodes, collect all Secrets accessible to any kubelet
7. Find a Secret containing a privileged service account token → cluster-admin

This attack requires only the ability to create a pod (or `compute.instances.get` IAM permission
plus network access). Mitigation: enable Workload Identity (replaces node service account with
pod-level service account) or enable Metadata Concealment.

### ContainerDrip (CVE-2020-15157): credential theft at image pull time

Discovered by Brad Geesaman. containerd versions before 1.2.14 process "foreign layers" in OCI
image manifests — layers that specify an arbitrary download URL (a legitimate OCI feature for
distributing large layers from CDNs). When pulling an image with a foreign layer URL pointing to
an attacker-controlled server, containerd sends its full authentication credentials — including
the GCP service account token from the instance metadata — in the HTTP Authorization header to
that URL if the server returns HTTP 401 with appropriate registry challenge headers.

**Trigger:** A simple pull of the malicious image via containerd's default resolver (cri-containerd,
`ctr`); Docker, which does not use that resolver, is not affected. No code executes on the victim.

**GKE severity amplification:** The default GKE node service account is the Compute Engine
default service account with Project Editor permissions. Stolen token → attacker has cloud-level
Project Editor access to the entire GCP project, including all GCS buckets, GCE instances,
BigQuery datasets, and IAM manipulation capabilities.

Won fifth place in Google's 2020 GCP VRP Prize.

### 6b. Workload identity evolution 2024-2026: federation replaces impersonation

Cross-cloud the workload-identity stack moved from "pod ServiceAccount impersonates a cloud
service account" (an indirection layer that required a trust-policy round-trip) toward
direct federation of the Kubernetes ServiceAccount identity into the cloud IAM trust graph.
See [`cloud_iam_expertise.md`](./cloud_iam_expertise.md) for the IAM-side companion.

**GKE — Workload Identity → Workload Identity Federation for GKE (2024 rename).**
The feature was renamed in 2024 and rolled out a simplified configuration model: IAM
policies can now directly bind to Kubernetes principal identifiers
(`principal://iam.googleapis.com/projects/.../subject/ns/<ns>/sa/<sa>` for a specific SA;
`principalSet://...` for namespace-wide or cluster-wide groups). The Google service account
indirection is no longer required. The GKE metadata server still mediates token issuance on
each node; the federation step happens at IAM time, not at pod startup. Setup shrank from
six steps to three.
Source: [Google Cloud — Workload Identity Federation for GKE concepts](https://docs.cloud.google.com/kubernetes-engine/docs/concepts/workload-identity);
[Google Cloud blog announcement](https://cloud.google.com/blog/products/identity-security/make-iam-for-gke-easier-to-use-with-workload-identity-federation).

**EKS — IRSA → EKS Pod Identity (2023 GA, broadly adopted 2024-2025).**
IRSA used per-cluster OIDC providers and per-role trust policies referencing the cluster's
OIDC issuer. EKS Pod Identity (released re:Invent 2023, now the AWS-recommended pattern for
new clusters) introduces a per-node DaemonSet (the Pod Identity Agent) that intercepts SDK
credential requests at the local IMDS-style endpoint. The trust policy is single-principal:
`pods.eks.amazonaws.com`. The SA→role mapping is an EKS API association
(`eks:CreatePodIdentityAssociation`), not an annotation on the ServiceAccount. Cross-cluster
reuse becomes trivial: one IAM role's trust policy is valid for any EKS cluster in the
account that creates an association. IRSA still works; AWS has not deprecated it.
Source: [AWS EKS Pod Identity documentation](https://docs.aws.amazon.com/eks/latest/userguide/pod-identities.html).

**AKS — AKS Workload Identity (Entra ID + federated credentials, GA 2023).**
AKS Workload Identity uses Entra ID federated credentials, where the federation issuer is
the AKS cluster's OIDC issuer URL. A managed identity or app-registration trusts a specific
`(issuer, subject, audience)` tuple where subject is the Kubernetes ServiceAccount. Replaces
the deprecated pod-managed-identity / aad-pod-identity addon.

**Common security implication across all three:** in the federation model, the cluster's
OIDC issuer URL becomes a load-bearing trust anchor. If the OIDC issuer JWKS is reachable
by an attacker who can also influence the cluster's ServiceAccount-token issuance (e.g., a
malicious admission webhook or a compromised control plane), the attacker can mint tokens
that the cloud IAM trust graph accepts. Defense: treat the OIDC issuer JWKS endpoint as
control-plane material (don't expose it more broadly than necessary) and monitor for
unexpected federated-credential additions in the cloud audit log — the cloud-side IAM
control plane is where federation attacks become visible, not the cluster-side audit log.

---

## 7. Supply Chain and Image Security

### Scanner evasion: five techniques that work today

From "Malicious Compliance" (SIG-Honk, KubeCon EU 2023) and Rory McCune's blog (April 2023).
All five techniques bypass Trivy, Grype, Docker Scan, Docker Scout simultaneously:

1. **OS release file modification:** Overwrite `/etc/os-release` with a different OS name/version.
   Scanners query the OS vulnerability database based on this file → wrong CVE set queried →
   OS-level CVEs missed.

2. **Package metadata deletion:** Remove APK/dpkg/rpm metadata files (e.g., `/var/lib/dpkg/info/`,
   `/lib/apk/db/`). Scanners cannot identify installed packages → package-level CVEs missed.

3. **Dependency file symlink:** Replace language package manifests (requirements.txt, go.sum,
   package-lock.json) with symlinks to empty files or `/dev/null`. Scanners cannot resolve the
   dependency graph → library CVEs missed.

4. **UPX binary packing:** Compress all binaries with UPX. Defeats signature-based detection
   and binary analysis in many scanner implementations.

5. **Runtime tarball extraction** (Rory McCune's technique — the most powerful):
   Build `FROM scratch`. Embed a statically compiled Go binary (CGO_ENABLED=0) + UPX-packed.
   The binary contains a compressed tarball of a full vulnerable OS and its binaries. At
   container start, the binary decompresses the tarball to a writable path and executes from it.
   Static scanners see an empty image with one UPX-packed binary — zero findings. All
   vulnerabilities only materialize at runtime.

**Implication:** Admission policies that gate on scanner results can be bypassed by any
image builder who knows these techniques. Admission-time scanning is a necessary control for
catching unintentional vulnerabilities, but it is not a security boundary against a motivated
attacker building the image. Runtime security (Tetragon, Falco) is required as a complementary
layer.

### The metadata API as an image pull attack vector

CVE-2020-15157 (ContainerDrip) demonstrates that the image pull process itself is an attack
surface. Any step in the image pull chain that makes network requests with credentials is
potentially exploitable:
- Foreign layer resolution (ContainerDrip)
- Registry mirror misconfiguration
- Image manifest signature verification with callback to attacker-controlled OCSP/AIA (analogous
  to Bechler's X.509 AIA JNDI injection)

Images pulled from untrusted registries or from registries where the manifest can be influenced
by an attacker should be treated with the same caution as executing untrusted code.

### sigstore / cosign / Rekor: signing and verification at admission time

By 2024-2025 the sigstore stack (cosign for signing, Rekor for transparency-log inclusion,
Fulcio for keyless certificate issuance) is the de facto open standard for container image
signing. The verification step lands in two places:

- **Admission-time verification via sigstore Policy Controller** (CNCF) — `ClusterImagePolicy`
  CRDs gate pod admission on verified signatures + attestations; supports keyless (Fulcio
  OIDC), key-pinned, and key-ref-based trust. Cross-link to
  [`supply_chain_provenance_expertise.md`](./supply_chain_provenance_expertise.md) for the
  attestation-format discussion (in-toto, SLSA Provenance, SPDX SBOM, CycloneDX).
- **Admission-time verification via Kyverno's `verifyImages` rule** — Kyverno integrates
  sigstore verification directly into its policy engine; same signature + attestation model,
  CEL-based policy expression for richer matching logic. Kyverno 1.16 (November 2025) added
  namespaced `NamespacedImageValidatingPolicy` for tenant-scoped image-signing policies and
  service-edge enforcement via the Kyverno Authz Server.
Source: [Kyverno 1.16 release announcement](https://kyverno.io/blog/2025/11/10/announcing-kyverno-release-1.16/);
[sigstore Policy Controller documentation](https://docs.sigstore.dev/policy-controller/overview/).

**SLSA L3 in 2025:** the GitHub OIDC + cosign keyless + Rekor transparency-log path makes
SLSA L3 build provenance practically achievable for any project on GitHub Actions or
Buildkite. The provenance attestation is signed at build time with an ephemeral Fulcio
certificate scoped to the workflow identity (`https://github.com/<org>/<repo>/.github/workflows/<wf>.yml@<ref>`);
the entry is logged to Rekor; admission-time verification consults Rekor to confirm
inclusion. The 2025 maturation point is that this is **the** baseline rather than the
aspirational target — open-source projects ship SLSA L3 provenance by default in
GitHub-hosted runners. See [`supply_chain_provenance_expertise.md`](./supply_chain_provenance_expertise.md)
and [`cicd_supply_chain_expertise.md`](./cicd_supply_chain_expertise.md) for the build-side
treatment.

### Chainguard Images / Wolfi: distroless as a product, not a Dockerfile pattern

The original "distroless" images (Google) shipped language-runtime + minimal base only, no
shell, no package manager. Chainguard's contribution starting 2022 and crystallized through
2024-2025 is to extend that minimal-base philosophy with **continuously rebuilt, CVE-curated
images** based on the Wolfi un-distro (apk-format packages, glibc, no traditional `/etc`
configuration apparatus). Key 2024-2025 developments:

- Chainguard publishes >1,000 distroless-style images, claiming ~54,000 remediated CVEs
  cumulatively. Adopters include Anduril, Canva, Snowflake, Wiz, and (per their published
  case study) Elastic — Elastic's 8.16+ Stack containers ship a Chainguard variant with
  a lower CVE count than previous versions.
- Multi-layer image format (May 2025) — shared base layers across the catalog improve cache
  reuse and reduce per-image effective size.
- Wolfi-base remains free and openly accessible; the curated images and SLA are the
  commercial product.
Source: [Chainguard Images overview](https://edu.chainguard.dev/chainguard/chainguard-images/overview/);
[Chainguard 1,000-image milestone](https://www.chainguard.dev/unchained/milestone-1-000-secure-container-images-and-over-100-work-years-saved).

**Implication for hardening:** the Section 9 "use distroless" recommendation now has a
three-option ladder rather than a single choice — `FROM scratch` (Go/Rust static binaries),
Google Distroless (most language runtimes), Chainguard Images / Wolfi (broadest coverage
with active CVE remediation). The trade-off remains the same: minimization shrinks the
post-RCE toolchain available to an attacker, but the image's CVE posture is only as good as
the rebuild cadence. Chainguard's product is that cadence.

---

## 8. Runtime Security and Observability

### eBPF: the correct layer for container security telemetry

From Liz Rice's Tetragon work and *Learning eBPF* (O'Reilly, 2023):

eBPF programs attach to kernel hooks and execute in response to kernel events — system calls,
kprobes, tracepoints. For container security, this means:
- **Visibility before security mechanisms run:** an eBPF program attached to `execve` sees every
  process execution in every container on the node before any userspace tool can
- **No performance hot path:** eBPF programs run in the kernel, avoiding userspace round-trips
- **In-kernel filtering and policy enforcement:** eBPF can **block** events (return error codes)
  without syscall interception overhead — this is prevention, not just detection
- **Tamper resistance:** container processes cannot disable the eBPF programs that monitor them
  (they run in the kernel, outside any container namespace)

Tetragon specifically:
- Tracks process lineage across container boundaries (detects namespace escapes)
- Detects capability escalation in real time
- Blocks specific file access, network connections, or privilege use at kernel level
- Generates forensic events with process + binary + user + syscall + target information

### Audit logs: the minimum viable telemetry, but only if shipped off-cluster

Kubernetes audit logs record API server activity: who made what request, to what resource, with
what response. This is the primary visibility layer for:
- Unusual RBAC enumeration (listing secrets, listing ClusterRoleBindings)
- New webhook configurations (potential interceptor install)
- Unusual pod specs (hostPath, privileged, sensitive capabilities)
- API calls at unusual times or from unusual service accounts
- Token requests for high-privilege service accounts

**Critical constraint from "Advanced Persistence Threats":** audit logs stored in the cluster
can be manipulated by a cluster-admin attacker (audit sink modification, annotation padding
truncation). Audit logs must be shipped to an off-cluster, append-only backend as they are
generated. An attacker who can modify the audit configuration after compromising the cluster
invalidates all logs captured after that point.

**Minimum viable audit policy:** log at Request level for `secrets`, `configmaps`,
`clusterrolebindings`, `webhookconfigurations`; at Metadata level for all other resource
modifications; at None for read-only operations on non-sensitive resources to manage volume.

### KubeHound: graph-based attack path analysis

KubeHound (Datadog Security Labs) models the Kubernetes cluster as an attack graph using
JanusGraph. It ingests Kubernetes API data and computes all attack paths from a given starting
node (e.g., a compromised pod) to a target (e.g., cluster-admin). It models 25+ attack
techniques including TOKEN_BRUTEFORCE and SHARE_PS_NAMESPACE.

The graph model reveals multi-hop attack paths that linear policy review misses: a pod with
`get` on configmaps in namespace A + `create` on pods in namespace B + a privileged service
account in namespace B = cluster-admin, through a chain of three individually-unremarkable
permissions.

### eBPF runtime-security stack maturation 2024-2026: Tetragon vs Falco vs Tracee

The eBPF runtime stack has consolidated around three production-grade tools, each with a
distinct posture. See [`detection_engineering_expertise.md`](./detection_engineering_expertise.md)
for the broader eBPF observability story.

| Tool | Author | Primary mode | Strength | Overhead |
|------|--------|--------------|----------|----------|
| **Tetragon** | Isovalent / Cilium (Liz Rice) | Detection + in-kernel enforcement | Kernel-level kill/block before syscall completes; namespace-escape detection via process-lineage tracking | ~6.5 mCPU (SciTePress 2025 test; lowest) |
| **Falco** | Sysdig / CNCF | Detection (userspace rules engine over eBPF or kernel-module events) | Mature rules library; long-running CNCF graduated project | ~431 mCPU (same test; highest) |
| **Tracee** | Aqua Security | Detection + forensic event stream | Strong forensic-event detail; behavior-signature engine | Balanced |

Tetragon's distinguishing capability is **in-kernel prevention** — eBPF programs return
error codes from kernel hooks before the syscall completes, so the malicious operation is
blocked rather than logged-and-investigated. Falco remains the production-default for
detection-only deployments because its rules library is the most mature and the operational
pattern (alert → SIEM → SOAR) fits existing detection-engineering workflows. A common
production pattern by 2025 is **both** — Falco for detection breadth, Tetragon for
enforcement on a curated set of high-confidence rules. Sources:
[Cilium Tetragon project](https://github.com/cilium/tetragon);
[comparative analysis paper, SciTePress 2025](https://www.scitepress.org/Papers/2025/142727/142727.pdf).

**The five-technique scanner-evasion finding from Section 7 maps directly onto eBPF
detection.** Runtime tarball extraction (McCune technique #5) produces a clean static image
that materializes a vulnerable rootfs at runtime; an eBPF agent attached to `execve` sees
the decompression and the subsequent exec from a writable temp path. Static scanning cannot
catch this image; eBPF runtime detection can.

### Service mesh data-plane evolution 2024-2025: Istio Ambient + Cilium Service Mesh

The 2024-2025 service-mesh inflection point was the shift from per-pod sidecars to
shared-node data-plane components. Key milestones:

- **Istio Ambient Mode** reached GA in Istio 1.24 (November 2024) after 26 months of
  development. Two-tier architecture: `ztunnel` is an L4 per-node proxy enforcing mTLS,
  network policy, and identity; `Waypoint` proxies are optional L7 (namespace-scoped) for
  traffic policy and HTTP authorization. ztunnel cuts per-pod overhead by an Istio-reported
  ~90% in some deployments. The sidecar-injection model remains supported; the 2025
  roadmap focuses on multi-cluster ambient (Alpha in Istio 1.27, August 2025).
  Source: [Istio Ambient GA announcement](https://istio.io/latest/blog/2024/ambient-reaches-ga/);
  [Istio 2025-2026 roadmap](https://istio.io/latest/blog/2025/roadmap/).
- **Cilium Service Mesh + Tetragon** — Cilium's mesh implementation uses the Cilium CNI's
  existing eBPF data plane for L4 (no separate proxy process) and a per-node Envoy for L7,
  pairing naturally with Tetragon for runtime visibility into mesh traffic. Same shared-node
  architecture as Istio Ambient; different implementation lineage.
- **Linkerd 2.x** continues the lightweight sidecar (`linkerd-proxy` written in Rust) and
  has not adopted the ambient model; remains the lower-operational-overhead choice for
  workloads that accept the sidecar pattern.

**Security implication of the sidecar → ambient shift:** the sidecar model put mTLS
enforcement inside each pod's network namespace, which had the property that a pod could
not bypass its own sidecar (egress traffic had to traverse the sidecar's iptables rules).
The ambient model moves enforcement to the node ztunnel; pods route through it via per-pod
iptables. The exit path from a compromised pod is the same in both models, but the ztunnel
runs as a node-scoped privileged component, so a ztunnel compromise has node-wide blast
radius rather than pod-scoped. This is a different threat model, not a worse one — node-scoped
components are easier to monitor and patch than thousands of sidecars.

---

## 9. Hardening Principles

### Pod Security Standards: the replacement for PodSecurityPolicy

PodSecurityPolicy (PSP) was deprecated in k8s 1.21 and removed in k8s 1.25. Its replacement is
Pod Security Admission (PSA).

PSA enforces at the namespace level via the `pod-security.kubernetes.io/` label set. Three
levels:

**Privileged:** No restrictions. For system components that genuinely need it.

**Baseline:** Prevents known privilege escalation techniques:
- No `privileged: true`
- No `hostPID`, `hostIPC`, `hostNetwork`
- No `hostPath` volumes
- No dangerous capabilities (beyond the default set)
- No host port binding
- Limited seccomp profiles (RuntimeDefault or defined)

**Restricted:** Security best practice for most workloads:
- All Baseline restrictions plus:
- Must run as non-root (`runAsNonRoot: true`)
- Must not run as root user (`runAsUser` ≠ 0)
- Read-only root filesystem strongly encouraged
- seccomp profile required (RuntimeDefault or Localhost)
- Only `NET_BIND_SERVICE` capability permitted from the default set; all others dropped
- No privilege escalation

Three modes per level: `enforce` (block), `audit` (log to API server audit), `warn` (return
warning to kubectl). Warn and audit first, then enforce — this is the migration path from
uncontrolled to Restricted.

### RBAC: minimum viable rights per workload

From the Kubernetes RBAC Good Practice Guide (official k8s documentation):

- **Avoid `cluster-admin` ServiceAccounts.** Most workloads need namespace-scoped permissions
  at most. `cluster-admin` should be reserved for cluster management components.
- **Never wildcard verbs or resources** (`* on *`). Always enumerate specific verbs and
  resources needed.
- **Treat `nodes/proxy` as cluster-admin.** It provides equivalent access via the kubelet API
  with a smaller audit footprint.
- **Avoid `get/list/watch` on secrets cluster-wide.** Namespace-scoped secret access should be
  scoped to exactly the secrets the workload needs.
- **Use projected service account tokens** (k8s 1.22+) with bounded TTL and audience binding,
  instead of long-lived tokens in Secret objects.
- **Audit ClusterRoleBindings regularly.** Every `cluster-admin` binding is a blast radius event
  if that identity is compromised.

### Network policy: the segmentation control Kubernetes does not apply by default

Kubernetes does not apply any network policy by default — all pods can communicate with all
pods across all namespaces. A compromised workload has unrestricted network access to:
- Every other pod in the cluster
- The kubelet API on every node
- The Kubernetes API server
- The cloud metadata API

A default-deny NetworkPolicy per namespace with explicit allow rules for required communication
is the correct baseline. This requires a CNI that enforces NetworkPolicy (Calico, Cilium, Weave).

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny
spec:
  podSelector: {}
  policyTypes: [Ingress, Egress]
```

Apply this to every namespace, then add explicit allow rules for required traffic.

### Secrets management: environment variables are the wrong answer

From Brad Geesaman's KubeCon 2017 and multiple subsequent works: secrets stored as environment
variables in pod specs are:
- Visible in `kubectl describe pod` to anyone with `get` on pods
- Logged in some audit log configurations
- Accessible to any container in the pod via `/proc/1/environ`
- Stored in the pod spec in etcd (plaintext unless encryption at rest is enabled)

Preferred patterns:
1. **Projected secret volumes with short-lived tokens** — mounted as files, with file permissions
   set appropriately, not visible in pod spec descriptions
2. **External secrets managers** (Vault, AWS Secrets Manager, GCP Secret Manager) with the
   CSI secrets driver — secrets never stored in etcd at all
3. **Workload Identity** (GKE) / **IRSA** (EKS) — no credentials stored in the cluster; identity
   asserted via OIDC token exchange

### etcd encryption at rest: required, not optional

etcd stores all Kubernetes Secrets in plaintext by default. `--encryption-provider-config` on
kube-apiserver enables encryption. All managed Kubernetes providers (GKE, EKS, AKS) support
customer-managed key encryption for etcd.

Without encryption at rest: any attacker with access to the etcd data directory (via hostPath
from a co-located pod, or from a compromised control plane node) reads all Secrets verbatim.

### Image hardening: minimize the attack surface in the image

- **Distroless or scratch-based images:** Remove shell, package manager, and system utilities.
  An attacker who achieves RCE in a distroless container cannot easily install tools or move
  laterally using the OS toolchain.
- **Non-root user:** `USER 65534` in Dockerfile. Combine with `runAsNonRoot: true` in the
  security context. Most privilege escalation paths require starting as root.
- **Read-only root filesystem:** `readOnlyRootFilesystem: true`. Forces all writes to explicitly
  mounted volumes. Prevents runtime modification of application binaries.
- **Pinned digests, not tags:** Image tags are mutable. `registry/image@sha256:<digest>` is
  immutable. Pinning to a tag means a registry compromise or image replacement can silently
  deploy different code.
- **Minimal capabilities:** Drop all capabilities, add back only what is required:
  ```yaml
  capabilities:
    drop: [ALL]
    add: [NET_BIND_SERVICE]
  ```

---

## 9b. AI/ML Workloads and Confidential Containers

The 2024-2026 surge in production LLM and ML inference on Kubernetes opened a new attack
surface that the original SIG-Honk corpus did not anticipate. Cross-link to
[`adversarial_ml_model_security_expertise.md`](./adversarial_ml_model_security_expertise.md)
for the model-level treatment and [`llm_agent_security_expertise.md`](./llm_agent_security_expertise.md)
for the agent-level treatment; this section covers the Kubernetes-specific surface.

### KServe / Triton / Seldon: model-serving control planes as attack targets

KServe (CNCF Incubating, v0.15 in 2025) is the dominant Kubernetes-native
model-serving abstraction. Its `InferenceService` CRD orchestrates Deployment, Service,
HPA, and (optionally) Knative resources around a backing runtime — Triton, vLLM, TGI, or a
custom predictor. Security-relevant properties:

- **The runtime pod runs untrusted model weights.** A model loaded from Hugging Face or an
  artifact registry can contain a pickle-trojan (PyTorch checkpoints), a `__reduce__`
  payload in a numpy archive, or a malicious custom op in a TensorFlow SavedModel.
  Deploy-time scanning of the model artifact (Protect AI, Hugging Face's own scanners) is
  a necessary admission control.
- **Model-serving pods often run with broad credentials** (S3, GCS, object-store reads).
  Combined with the pickle-execution attack surface, a compromised model deserialization
  becomes a credential-theft pivot. The pod's cloud workload identity (IRSA / Pod Identity /
  WIF) becomes the post-compromise lateral path.
- Treat the KServe controller and any custom transformer/predictor as
  privileged code-execution surfaces, not as managed inference plumbing.
Source: [KServe GitHub releases](https://github.com/kserve/kserve/releases).

### Confidential Containers (CoCo): per-pod TEE for tenant isolation

Confidential Containers, a CNCF Sandbox project, encapsulates each pod inside a Trusted
Execution Environment (Intel TDX, AMD SEV-SNP, IBM SEL on Z/LinuxONE). Memory contents and
register state are encrypted from the host kernel's perspective; attestation evidence
verifies the TEE state at boot before workload secrets are released. Production status as
of 2025:

- OpenShift sandboxed containers 1.10.0 is GA on Azure for both Intel TDX and AMD SEV-SNP.
- Azure Confidential Containers on AKS is in preview.
- IBM Z / LinuxONE support via Secure Execution for Linux is in tech preview.
- Bare-metal and other-cloud support is in active development.

**Threat model addressed:** CoCo defends against a malicious or compromised host kernel,
hypervisor, or cloud-provider operator — the workload's plaintext memory is not visible to
any party outside the TEE. It does **not** defend against an attacker who compromises the
workload from within (a pickle-trojan in a model artifact still executes inside the TEE
boundary). Cross-link to [`confidential_computing_expertise.md`](./confidential_computing_expertise.md)
§6 for the GPU and accelerator-sharing isolation story (NVIDIA H100 confidential compute,
MIG partitioning, time-sharing semantics).
Source: [Red Hat Confidential Containers overview](https://www.redhat.com/en/blog/learn-about-confidential-containers);
[CNCF Confidential Containers project page](https://www.cncf.io/projects/confidential-containers/).

### GPU sharing and the multi-tenant model-serving attack surface

NVIDIA's MIG (Multi-Instance GPU, A100/H100) partitions a single physical GPU into up to 7
hardware-isolated instances each with dedicated SM, memory, and L2 cache. Time-sharing
(default on consumer-class GPUs) does not provide cross-tenant isolation — GPU state
including HBM contents can leak via timing channels and memory-residue reads. For
multi-tenant model serving:

- **MIG-partitioned isolation** is the strong control. Each pod gets a hardware-isolated
  GPU instance.
- **Time-shared / MPS** is shared infrastructure with no security boundary; comparable to
  giving two workloads access to the same `/dev/sda`.
- **GPU device-plugin RBAC** is often overlooked — pods with `claim` access to a GPU
  resource type may obtain `/dev/nvidia*` access that bypasses the partitioning intent.

For the broader GPU and accelerator-sharing treatment, see
[`confidential_computing_expertise.md`](./confidential_computing_expertise.md) §6.

---

## 10. Tooling Reference

| Tool | Author | Purpose | Technical Notes |
|------|--------|---------|----------------|
| **kube-env-stealer** | Brad Geesaman | GKE bootstrap credential theft | Reads kube-env metadata → generates kubelet certs for all nodes → extracts all Secrets |
| **mkit** | Darkbit (Geesaman/Larsen) | Managed k8s security config assessment | GKE, EKS, AKS; archived |
| **k8s-mirror** | Darkbit | Offline cluster review | Mirrors cluster to in-memory apiserver+etcd in Docker; no credentials needed for review |
| **OpenCSPM** | Darkbit | Cloud Security Posture Management | JanusGraph-based; cross-references GCP IAM + k8s RBAC for relationship analysis |
| **malicious-compliance** | Brad Geesaman | Scanner evasion PoC | Five evasion technique image variants from KubeCon EU 2023 |
| **kubesec** | Andrew Martin / ControlPlane | Manifest risk scoring | Scores pod specs 0–100; checks privileged, hostPID, capabilities, allowPrivilegeEscalation |
| **kube_security_lab** | Rory McCune | Attack/defense practice labs | Ansible + kind; spin up clusters with specific vulnerable configurations |
| **eathar** | Rory McCune | Kubernetes security assessment | Go-based; checks workload configs and RBAC |
| **teisteanas** | Rory McCune | CSR-based kubeconfig creation | Demonstrates certificate-based identity escalation |
| **k8s_ssrf_portscanner** | Rory McCune | API server SSRF demonstration | Uses webhook configs to port-scan from the API server's network position |
| **container-security-site** | Rory McCune | Knowledge aggregation | Container/k8s attack technique and tool reference |
| **securekubernetes** | Geesaman/Mesta/Sable/Benjamin | CTF-style tutorial | KubeCon 2019 guided attack/defense tutorial; full materials at securekubernetes.com |
| **Tetragon** | Isovalent (Liz Rice) | eBPF runtime security | Prevention + forensic observability; kernel-level enforcement; CNCF project |
| **kube-hunter** | Aqua (Rice oversight) | K8s penetration testing | Passive + active modes; network/in-cluster scan; probes kubelet, etcd, API server |
| **kube-bench** | Aqua (Rice oversight) | CIS Benchmark assessment | Automated check of CIS Kubernetes Benchmark controls |
| **KubeHound** | Datadog Security Labs | Graph-based attack path analysis | JanusGraph; 25+ attack techniques; identifies multi-hop privilege escalation paths |
| **Falco** | Sysdig / CNCF graduated | eBPF runtime detection | Mature rules library; userspace rules engine over kernel events; detection-only by default |
| **Tracee** | Aqua Security | eBPF runtime detection + forensic events | Behavior-signature engine; rich forensic event detail; balanced overhead |
| **leaky-vessels-static-detector / runtime-detector** | Snyk Labs (Rory McNamara) | Leaky Vessels CVE detection | Dockerfile static analysis + eBPF runtime detection for CVE-2024-21626 cluster |
| **sigstore Policy Controller** | sigstore / CNCF | Image-signature admission control | ClusterImagePolicy CRD; verifies cosign signatures + attestations at admission time |
| **Kyverno** | Nirmata / CNCF | Policy-as-code admission control | CEL-based; image signature verification; ValidatingAdmissionPolicy generation; 1.16 added namespaced policies + service-edge enforcement |

---

## 11. CVE Reference

| CVE | CVSS | Component | Discoverers (from this group) | Mechanism |
|-----|------|-----------|------------------------------|-----------|
| CVE-2018-1002105 | 9.8 | kube-apiserver | Analyzed/taught by Coldwater | Proxied upgrade request → persistent connection → backend auth bypass |
| CVE-2019-11253 | 7.5 | kube-apiserver | Geesaman, McCune | YAML anchor recursion → Billion Laughs memory exhaustion DoS |
| CVE-2020-15157 "ContainerDrip" | 6.1 (higher in GKE) | containerd | Geesaman | Foreign layer manifest → credential theft at image pull time |
| CVE-2020-15257 "Abstract Shimmer" | 5.2 | containerd-shim | NCC Group; taught by Sable | Abstract Unix socket → host network containers access shim API → host escape |
| CVE-2021-25741 | 8.8 | kubelet | Fabricio Voznika, Mark Wolters (Google); built on research by Coldwater, Cooley, Geesaman, McCune | subPath symlink exchange → host filesystem access, bypasses hostPath restrictions |
| CVE-2021-30465 | 8.5 | runc | champtar (original); SIG-Honk k8s PoC | Mount destination symlink race → container escape |
| CVE-2024-21626 "Leaky Vessels" | 8.6 | runc | Rory McNamara (Snyk Labs) | Leaked fd + WORKDIR → process spawns with cwd in host filesystem namespace |
| CVE-2024-23651/52/53 | 8.7-10.0 | BuildKit | Rory McNamara (Snyk Labs) | Mount-cache race / build-teardown arbitrary delete / GRPC privilege check — companion CVEs to CVE-2024-21626 |
| CVE-2025-1974 "IngressNightmare" | 9.8 | ingress-nginx | Ohfeld, Shustin, Tzadik, Ben-Sasson (Wiz) | Unauthenticated pod-network reach to admission webhook → nginx config injection → ssl_engine library load → cluster takeover via ingress-nginx SA secret access |
| CVE-2025-1097 / 1098 / 24513 / 24514 | 4.8-8.8 | ingress-nginx | Wiz Research | Admission-webhook annotation-injection variants in `auth-tls-match-cn`, `mirror-target`, path traversal, `auth-url` |

---

## 12. Summary: What Defines Staff-Level Container and Kubernetes Security

1. **Attacker-perspective threat modeling before any hardening decision.** The question is not
   "what CIS Benchmark checks are we passing?" It is "what can an attacker do from a compromised
   pod in this cluster, and how many hops does it take to reach cluster-admin?"

2. **The cluster is a flat network by default.** Without NetworkPolicy, all pods can reach all
   pods, all nodes, and the cloud metadata API. The blast radius of any compromised workload is
   the entire cluster plus the cloud account.

3. **RBAC permissions compose into attack paths.** Individual RBAC grants that appear harmless
   combine into privilege escalation chains. `nodes/proxy` is cluster-admin without the label.
   The CSR API is a certificate forge. Webhook configuration create is an interceptor install.
   Model the permission graph, not just individual bindings.

4. **No certificate revocation means forged credentials last forever.** A compromised CA key or
   an intentionally forged client certificate persists until the CA is rotated. Treat the CA
   private key with HSM-level security. Monitor for unknown certificate CNs in API server auth logs.

5. **Audit logs are only valuable if they're off-cluster and immutable.** A cluster-admin
   attacker can modify audit configuration and
   delete log storage within the cluster. Audit logs that stay in the cluster can be manipulated.

6. **Scanners are policy controls, not security boundaries.** Any image builder who knows five
   documented techniques can produce an image with critical vulnerabilities that all major
   scanners report as clean. Runtime security (eBPF, Tetragon, Falco) is required alongside
   admission-time scanning.

7. **Managed Kubernetes solves the CA key problem and little else.** GKE, EKS, and AKS keep
   CA keys inaccessible and manage etcd security. They do not fix RBAC misconfigurations,
   network policy gaps, insecure pod specs, or cloud metadata exposure (unless Workload Identity
   is enabled). The GKE kube-env attack (Geesaman) requires only the ability to create a pod.

8. **The persistence endgame is the shadow API server.** Once an attacker can run a pod on a
   control plane node, they can deploy an apiserver with no audit logging, no RBAC, and no
   admission control, fed directly from etcd. Detection requires monitoring outside the cluster's
   own audit subsystem — at the network and host process level.

9. **Admission webhooks are privileged code-execution surfaces.** IngressNightmare
   (CVE-2025-1974) demonstrated that an unauthenticated admission webhook reachable on the
   pod network can yield cluster takeover with no RBAC and no exec primitive. Any admission
   webhook that writes user-controlled data to disk and then exec's a parser (`nginx -t`,
   `yaml-validate`, custom shell helpers) has the same shape of vulnerability latent. Audit
   admission webhooks for authentication posture, network reachability, and parser-shellout
   patterns.

10. **Build infrastructure is in scope for container escape research.** Leaky Vessels
    (CVE-2024-23651/52/53) extended the runc/containerd CVE corpus into BuildKit. Anyone who
    can submit a malicious Dockerfile to a shared BuildKit instance has the same escape
    surface as anyone running a malicious image. CI build clusters need the same hardening
    posture as production runtime clusters.

11. **eBPF moves runtime security from "policy" to "boundary."** Tetragon's in-kernel
    enforcement model blocks malicious operations at kernel-hook return time, not after
    detection-and-alert. The Section 7 scanner-evasion techniques (which bypass static
    image analysis) are visible at runtime via eBPF observation of the actual `execve` and
    file-mutation events. Pair static scanning with eBPF runtime as overlapping layers.

12. **Workload identity federation is the new credential model.** EKS IAM Roles for Service Accounts (IRSA), GKE
    Workload Identity Federation, and AKS Workload Identity replace impersonation chains with
    direct OIDC-federated trust. The cluster's OIDC issuer JWKS endpoint becomes load-bearing
    cloud-IAM trust infrastructure; monitor it accordingly. See
    [`cloud_iam_expertise.md`](./cloud_iam_expertise.md).
