# Container Runtime Escape — Expertise

Audience: Claude when auditing container-isolation choices or hunting container-escape primitives, and the staff security engineer reading over Claude's shoulder. Imperative voice. Real CVE numbers. Cross-link `[[reference-container-k8s-security]]` for the platform-policy view and `[[reference-linux-kernel-exploitation]]` for the kernel-side view; this doc is the runtime-layer sibling.

## 1. Why this doc exists

Container security splits cleanly into three layers, each with its own attack surface and its own primary-source corpus:

- **Kernel exploitation** — privilege escalation inside the Linux kernel. Covered in `[[reference-linux-kernel-exploitation]]`. Slab heap-spray, eBPF, io_uring, KASLR/SMEP/SMAP/KPTI. Lives below the container.
- **Container runtime** — the namespace + cgroup + capability + seccomp + MAC envelope that runc / containerd / cri-o build around a process. This is THIS doc. Lives at the OS↔workload boundary.
- **Kubernetes / orchestrator** — RBAC, admission control, Pod Security Standards, network policy, service mesh, CSI. Covered in `[[reference-container-k8s-security]]`. Lives above the container.

A container escape is exactly one of two things. Either (a) a kernel bug that crosses a namespace boundary (CVE-2022-0492 release_agent; CVE-2023-0386 OverlayFS) — in which case it shows up in BOTH the kernel-exploitation corpus AND the container-escape corpus — or (b) a runtime-tooling bug that mishandles the namespace setup itself (CVE-2019-5736 runc; CVE-2024-21626 leaky-vessels). The first class is mitigated by patching the kernel; the second by patching runc / containerd / BuildKit.

State the structural insight plainly: **runc and the OCI runtime family are not a security boundary against malicious workloads. They are an isolation convenience.** Containers share the host kernel. Every container on a node depends on every other container's good behavior plus zero in-tree Linux kernel bugs. If the workload is hostile, the runtime tier matters more than any seccomp profile — see §10 (isolation tier survey) for gVisor / Kata / Firecracker / Sysbox.

This doc does not re-cover Pod Security Standards, NetworkPolicy, or admission controllers — `[[reference-container-k8s-security]]` owns those. It does not re-cover kernel-side exploitation primitives — `[[reference-linux-kernel-exploitation]]` owns those. It owns the gap between them.

## 2. The isolation primitives runc uses

A container is six-to-eight Linux namespaces, one or more cgroups, a capability mask, a seccomp filter, and a MAC label. Understand each primitive on its own terms before reading §3-§9.

### 2.1 Linux namespaces

The Linux kernel exposes eight namespace types as of Linux 5.6+:

- **PID namespace** — process-tree isolation. Inside, the container's init is PID 1. Escape primitive: a process in the host PID namespace can `kill -9` any PID; a process in a container can't see host PIDs. Relevant CVE class: PID-namespace re-entry bugs via `setns(2)`.
- **NET namespace** — network-stack isolation. Each container gets its own interfaces, routing tables, iptables/nftables tables. Escape primitive: `--net=host` opts out entirely; CAP_NET_ADMIN inside lets you reach the host's veth pair from the container side.
- **UTS namespace** — hostname + domainname isolation. Mostly cosmetic; not a security boundary on its own.
- **IPC namespace** — System V IPC + POSIX message queues. Modest isolation.
- **MNT namespace** — filesystem-mount isolation. The big one. Most container escapes manipulate mounts. Escape primitives: bind-mount-from-host, `pivot_root` mishandling, `/proc` re-mount, `propagation=shared` slips.
- **USER namespace** — user-ID + group-ID + capability isolation. The pivot of the rootless-container story. Inside, the container's "root" (UID 0) maps to an unprivileged UID on the host (commonly 100000+). This is the single primitive that most reliably converts "container root" into "host nobody" — IF the runtime configures it correctly. Many production deployments do NOT use user namespaces.
- **TIME namespace** (Linux 5.6+) — boot-time + monotonic-clock isolation. Mostly cosmetic.
- **CGROUP namespace** — cgroup-hierarchy view isolation. Hides the host's cgroup paths.

A container escape that "breaks namespaces" almost always means breaks the MNT namespace or breaks the USER namespace.

### 2.2 cgroups v1 vs v2

cgroups (control groups) enforce resource limits (CPU, memory, IO, PIDs) and gate certain kernel features (freezer, device whitelist, release_agent).

**cgroups v1** is the legacy hierarchy. Each controller (cpu, memory, devices, freezer, etc.) had its own mount point and its own quirks. The historically dangerous primitive: `release_agent`. Writing a path into `release_agent` and arranging for a process in the cgroup to exit while `notify_on_release` was set caused the kernel to invoke that path as a userspace helper — **as root, in the host's user namespace**. See §7 for the CVE-2022-0492 walk-through.

**cgroups v2** (default since ~Linux 5.8 in many distros, Fedora 31+ first) unifies the hierarchy and removes `release_agent` as a writable userspace helper interface. v2 is structurally less escape-prone. As of 2024, most modern distros ship v2-default; some legacy clusters still run v1.

When auditing a container, check `mount | grep cgroup` from inside. If you see v1 controllers mounted writable, the release_agent class of bug is in scope; if v2 only, it isn't.

### 2.3 Linux capabilities

POSIX capabilities partition root's omnipotence into ~40 individual privileges. Docker's default capability set is a subset of ~14 retained capabilities:

CAP_CHOWN, CAP_DAC_OVERRIDE, CAP_FSETID, CAP_FOWNER, CAP_MKNOD, CAP_NET_RAW, CAP_SETGID, CAP_SETUID, CAP_SETFCAP, CAP_SETPCAP, CAP_NET_BIND_SERVICE, CAP_SYS_CHROOT, CAP_KILL, CAP_AUDIT_WRITE.

The capabilities Docker drops by default — the ones you must NOT add back without a fight:

- **CAP_SYS_ADMIN** — "near root." Lets you mount filesystems, call `setns(2)`, manipulate namespaces, modify many sysfs/procfs entries. The single most dangerous capability to grant; ~30+ escape primitives reach through CAP_SYS_ADMIN.
- **CAP_SYS_MODULE** — load kernel modules. Trivial host root if granted.
- **CAP_SYS_PTRACE** — `ptrace(2)` arbitrary processes (host PIDs if PID namespace is shared).
- **CAP_NET_ADMIN** — manipulate network configuration. Routing-table rewrites, iptables/nftables manipulation, raw sockets in places you shouldn't have them.
- **CAP_DAC_READ_SEARCH** — bypass file-read DAC checks. Useful for filesystem-escape primitives.
- **CAP_SYS_BOOT, CAP_SYS_TIME, CAP_AUDIT_CONTROL, CAP_MAC_OVERRIDE, CAP_MAC_ADMIN, CAP_BLOCK_SUSPEND, CAP_SYSLOG, CAP_WAKE_ALARM** — assorted host-only privileges.

`docker run --privileged` is equivalent to: drop no capabilities + grant all devices + disable seccomp + disable AppArmor + disable SELinux confinement. Production code paths must not run privileged containers; if you see one, treat it as a finding.

### 2.4 seccomp-bpf profiles

seccomp-bpf attaches a BPF filter to the syscall entry path. The filter returns ALLOW / KILL / TRAP / ERRNO per syscall. Linux exposes ~330+ syscalls; Docker's default seccomp profile blocks ~44 of them — the ones with no legitimate userspace use OR with known escape primitives:

`mount`, `umount2`, `pivot_root`, `kexec_*`, `init_module`, `delete_module`, `bpf` (partially), `setns`, `unshare` (partially), `keyctl`, `add_key`, `request_key`, `acct`, `clock_settime`, `clock_adjtime`, `nfsservctl`, `vmsplice`, `process_vm_readv` / `process_vm_writev` (partially), and others.

`docker run --security-opt seccomp=unconfined` removes the filter entirely. Treat this as equivalent to `--privileged` for threat-model purposes; an unconfined seccomp profile re-exposes most of the historically dangerous syscalls.

The seccomp default profile is configurable per OCI spec; podman, cri-o, containerd each ship their own variants. Audit the actual filter in production with `grep Seccomp /proc/<pid>/status` (value `2` = filter active).

### 2.5 MAC: AppArmor / SELinux

Linux ships two mandatory access control frameworks:

- **AppArmor** (Debian/Ubuntu default) — path-based profiles. Docker ships a default profile `docker-default` that restricts mounts, writes to `/proc/sys/*`, writes to `/sys/*`. Containers can opt out with `--security-opt apparmor=unconfined`.
- **SELinux** (RHEL/CentOS/Fedora default) — label-based MAC. Docker labels container processes `container_t` (or `svirt_lxc_net_t` in older Red Hat lineage); the policy restricts what `container_t` can access on the host. Disabled with `--security-opt label=disable`.

MAC complements (does not replace) capabilities + seccomp. A `--privileged` container without `--security-opt apparmor=unconfined` is still partially MAC-confined; in practice MAC profiles catch a handful of known-bad mount paths but don't enumerate the universe of escape primitives.

### 2.6 no-new-privileges flag

`--security-opt no-new-privileges` sets the `PR_SET_NO_NEW_PRIVS` prctl. Once set, the process and its descendants can never gain new privileges via setuid binaries, file capabilities, or LSM transitions. Cheap and high-value; enable everywhere a workload doesn't depend on setuid binaries internally.

### 2.7 read-only root filesystem

`docker run --read-only` mounts the container's root filesystem read-only. Defense in depth: many post-exploitation actions (dropping a payload, modifying init scripts, persisting) require writes to `/`. Combined with explicit `--tmpfs /tmp` and `--volume ...:rw` for the few paths the workload actually needs writable, you get a meaningful narrowing of the post-escape attack surface.

## 3. Classic escape primitives (pre-2019)

These are the patterns that should never appear in production. They keep appearing in production. Treat them as findings, not as exotic edge cases.

### 3.1 `--privileged` containers

`docker run --privileged` is the canonical anti-pattern. The container gets:

- All capabilities (not just Docker's default 14)
- All device nodes mounted (including `/dev/sda*`, `/dev/mem`, `/dev/kmem` on older kernels)
- seccomp disabled
- AppArmor / SELinux confinement disabled
- Cgroup device whitelist permitted-all

From a privileged container, host filesystem mount is one syscall:

```
mount /dev/sda1 /mnt && chroot /mnt sh
```

Or via kernel module load (CAP_SYS_MODULE present):

```
insmod /payload.ko
```

Or via direct kernel memory write (`/dev/mem`, `/dev/kmem` on kernels that still expose them).

If you find a `--privileged` container in production, the question isn't "is this exploitable" — it's "what's the workload's risk tolerance and why is this still running."

### 3.2 Docker socket mounted into container

`-v /var/run/docker.sock:/var/run/docker.sock` is the single most common "I needed CI to build images" misconfiguration. The Docker socket is an unauthenticated control plane for the Docker daemon (which itself runs as root on the host). Any container with the socket mounted can:

```
docker run --privileged --pid=host --net=host \
  -v /:/host alpine \
  chroot /host sh
```

This is host root in one command. Or, equivalently, `docker run` an `nsenter` payload into the host PID 1:

```
docker run --privileged --pid=host alpine \
  nsenter -t 1 -m -u -n -i sh
```

Variants of this primitive apply to any container-control socket exposed: containerd's grpc socket, cri-o's socket, podman's user socket. Treat the socket as "host root in a Unix domain endpoint."

The defender posture: never mount the daemon socket into a container. If a workload needs to build images, use a rootless builder (BuildKit rootless, Kaniko, Buildah rootless) that does not require daemon access.

### 3.3 CAP_SYS_ADMIN + mount escape primitives

A container with CAP_SYS_ADMIN granted (NOT --privileged, just the capability) gets enough mount/unmount/setns power to break out via a half-dozen primitives. The flagship technique: create a fresh mount namespace with `unshare -m`, then `pivot_root` your way out of the container's view via a bind-mount that escapes the chroot.

CAP_SYS_ADMIN alone — without user-namespace remapping — was the standard escape lever from ~2015 through 2020. The defense: drop CAP_SYS_ADMIN unless the workload absolutely needs it, and if it does, run inside a user-namespace remap so "container root" can't actually exercise CAP_SYS_ADMIN against the host's init user namespace.

### 3.4 cgroup v1 release_agent (CVE-2022-0492 anchor)

See §7 for the full walk-through. Short form: a container with the cgroup v1 hierarchy writable and the right (default) capability set could trigger host code execution via `release_agent`. The bug predates 2022 — the primitive was known to red teams for years — but Yuval Avrahami and Yiqi Sun at Palo Alto Unit 42 wrote the canonical analysis that landed as CVE-2022-0492 and the kernel patch shortly after.

## 4. runc CVE-2019-5736 — the canonical escape

This is the bug every container-security person knows. Understand it cold.

**Primary anchors:** Adam Iwaniuk and Borys Popławski (Dragon Sector CTF team) discovered it. Aleksa Sarai (SUSE / runc maintainer) coordinated the disclosure and patch across runc, containerd, Docker, podman, cri-o, and LXC.

**Disclosure:** February 11, 2019.

**The bug:** When you ran `docker exec` (or `runc exec`) into a running container, the host's `runc` binary was invoked. Pre-patch, runc opened `/proc/self/exe` and re-execed itself into the container's namespaces. The path `/proc/self/exe` resolved to the runc binary on the host filesystem — but inside the container's mount namespace, that path was still walkable through to the underlying file. A malicious container could:

1. Wait for the host to spawn `runc exec`.
2. The host's runc opens `/proc/self/exe` inside the container's mount namespace.
3. The container had replaced its own `/proc/self/exe` (via a clever pinning of the runc inode through file descriptor manipulation, using `O_PATH` and `/proc/<pid>/exe` reopens) with attacker-controlled bytes.
4. The host kernel `execve`d those bytes — as host root, outside the container.

**The fix:** runc was hardened to use a `memfd_create(2)` copy of itself before re-execing. The exec path now reads runc's bytes into an in-memory file descriptor that the container cannot reach, then execs from that. Released as runc 1.0.0-rc6 / Docker 18.09.2 / containerd 1.2.4.

**Patch trail:** runc PR `opencontainers/runc#1670`, with concurrent patches in containerd `containerd/containerd#3007`, Docker `moby/moby#38731`, podman/libpod, and cri-o. The CVE was scored CVSS 8.6.

**Detection in the wild:** Several reports of post-disclosure exploitation in cryptomining campaigns. Cetus group attribution is `[unverified specific advisory]`.

**Why it matters as a teaching case:** runc was doing the "right" thing — re-execing itself into the container — and the bug was in a primitive (`/proc/self/exe`) that nobody had previously thought about as crossing a trust boundary. This is the template for the leaky-vessels family five years later: runtime tooling doing privileged setup, with a primitive that leaks across the host↔container boundary in a way nobody had reviewed.

## 5. leaky-vessels (CVE-2024-21626 and family)

**Primary anchor:** Rory McNamara, Snyk Security Labs. Disclosed January 31, 2024. Coordinated with Aleksa Sarai for runc patches and Docker BuildKit maintainers for the BuildKit triplet.

Four CVEs together; Snyk branded the cluster "leaky-vessels":

### 5.1 CVE-2024-21626 — runc WORKDIR escape

CVSS 8.6.

**The bug:** runc accepts a `WORKDIR` setting from the OCI spec, then `chdir`s into it as part of container setup. Pre-patch, runc resolved `WORKDIR` via the container's mount-namespace view AFTER some file descriptors to host directories were already open (held by runc for legitimate setup). An attacker setting `WORKDIR=/proc/self/fd/<n>` — where `<n>` was a file descriptor that runc had opened pointing into a HOST directory — caused the container's process to start with its working directory set to a host directory outside the container's root.

The container could then walk via relative paths (`../../../../etc/shadow`) into the host filesystem and read/write host files as host root.

**The fix:** runc 1.1.12 (and the 1.0.x backport) audits file descriptors more aggressively before container setup completes and validates that WORKDIR resolves inside the container root.

**Why it slipped past review for years:** runc holds host-side FDs for legitimate setup. `WORKDIR` was thought of as a workload-controlled string, not as a primitive that could re-enter the FD table. The class of bug is "trusted runtime holding privileged FDs while accepting attacker-controlled paths that include `/proc/self/fd/`."

### 5.2 CVE-2024-23651 — BuildKit mount cache TOCTOU

CVSS 8.7. Affects BuildKit (the Docker build subsystem) versions <0.12.5.

**The bug:** BuildKit's build cache uses mounts. A malicious Dockerfile with a `RUN --mount=type=cache,...` directive could race the mount setup — TOCTOU between BuildKit's filesystem state check and the mount syscall — to redirect the cache mount onto an attacker-controlled path. Net effect: arbitrary file read/write on the host during build time.

**The fix:** BuildKit 0.12.5 holds the cache directory under an additional lock + verifies the resolved inode before performing the mount.

### 5.3 CVE-2024-23652 — BuildKit symlink-following cleanup

CVSS 9.1 (the highest of the cluster). BuildKit <0.12.5.

**The bug:** BuildKit's cache-mount cleanup followed symlinks as root. A malicious Dockerfile could plant a symlink during build that pointed to a host path. When BuildKit cleaned up the cache mount, it followed the symlink and deleted (or rewrote) the target host file — as host root.

**The fix:** BuildKit 0.12.5 uses `openat2(RESOLVE_NO_SYMLINKS)` and explicit lstat/unlink chains for cleanup paths.

This is a "TOCTOU + symlink" classic; cross-link `[[reference-race-conditions-concurrency]]` §filesystem-races and `[[reference-linux-kernel-exploitation]]` §filesystem-primitives.

### 5.4 CVE-2024-23653 — BuildKit interactive containers

CVSS 7.8. BuildKit <0.12.5.

**The bug:** BuildKit's interactive mode (`docker buildx ... --build-arg BUILDKIT_INLINE_CACHE=1` with interactive commands) allowed the workload to write outside the container root through an internal RPC mechanism. The interactive shell had inappropriate access to BuildKit's host-side filesystem APIs.

**The fix:** BuildKit 0.12.5 restricts the interactive RPC surface to paths inside the container root.

### 5.5 Why "leaky-vessels" as a class

All four CVEs share a shape: **the runtime tooling itself performs privileged setup operations while holding privileged file descriptors or mount handles, and those handles leak across the host↔container boundary in ways the threat model didn't account for.** The vulnerability is not in the workload, not in seccomp, not in a kernel namespace primitive — it's in the trusted code path that wires the container together.

This is a different bug shape from CVE-2019-5736 (which was a re-exec primitive). It's the same META shape — runtime trusted code mishandling its own privileged state — and the lesson is the same: trusted runtime code that holds privileged handles must treat workload-controlled inputs as untrusted with extreme prejudice.

No publicly-documented in-the-wild exploitation of leaky-vessels as of disclosure; Snyk's reporting noted "wide attack surface but no confirmed exploitation" `[unverified ongoing telemetry]`.

## 6. Docker Desktop CVE-2025-0750 / CVE-2025-0751

`[unverified specific dates]` — these CVE identifiers are reported as 2025 Docker Desktop host-escape advisories from the VM-isolated Docker Desktop product on macOS and Windows. The structural note worth retaining is:

Docker Desktop on macOS and Windows runs containers inside a Linux VM (HyperKit / Hyper-V / WSL2 backend), not directly on the host kernel. "Container escape" in the Docker Desktop context means **VM → host crossing**, not container → VM. The threat model is closer to a hypervisor escape than a runc escape; cross-link `[[reference-confidential-computing]]` §VM-escape-vectors.

Verify the specific 2025 advisories against Docker's security bulletins before citing in a finding. Until verified, treat these CVE numbers as `[unverified]`.

## 7. cgroup release_agent — CVE-2022-0492

**Primary anchors:** Yiqi Sun and Yuval Avrahami, Palo Alto Networks Unit 42. Disclosed February 4, 2022.

**The bug:** Under cgroups v1, the `release_agent` mechanism allowed a process with CAP_SYS_ADMIN in the cgroup hierarchy's owning user namespace to set a userspace helper path. When the last process in a cgroup exited and `notify_on_release` was set, the kernel invoked the `release_agent` binary as root in the **init user namespace** — bypassing whatever user-namespace remap the container was using.

The pre-2022 check was: "does the calling process have CAP_SYS_ADMIN in init_user_ns?" An unprivileged container with the default Docker capability set didn't have CAP_SYS_ADMIN in init_user_ns. But — and this is the bug — the check was insufficient for one specific path: when a container with no user-namespace remap (the default for most production deployments at the time) had the cgroup v1 filesystem mounted writable, a process inside could write to `release_agent` AND `notify_on_release` AND fork a process that exited, triggering host code execution as root.

The bypass worked because Docker's default container, without user-namespace remap, runs the workload's UID 0 as the host's UID 0. The capability check passed because the calling process's effective capabilities included CAP_SYS_ADMIN in the init namespace — even though the container's threat model assumed it didn't.

**The Unit 42 walk-through PoC:**

```sh
# Inside an unprivileged Docker container without user-ns remap,
# default capabilities, default seccomp profile, default AppArmor.

# Mount a fresh cgroup v1 RDMA hierarchy (most-used CVE PoC path).
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp
mkdir /tmp/cgrp/x

# Enable notify_on_release on the new cgroup.
echo 1 > /tmp/cgrp/x/notify_on_release

# Compute the container's path on the host filesystem (overlayfs upper).
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)

# Write a payload to the container that the host will exec as root.
echo "$host_path/cmd" > /tmp/cgrp/release_agent
echo '#!/bin/sh' > /cmd
echo 'cat /etc/shadow > /host_shadow' >> /cmd
chmod +x /cmd

# Trigger the release by adding our PID to the cgroup, then exiting.
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
# Host root just exec'd /cmd in init_user_ns.
```

**The kernel patch:** the CAP_SYS_ADMIN check on `release_agent` writes was strengthened to require the capability against the user namespace **owning the cgroup**, not just the init user namespace. Containers with user-namespace remap fail the check; containers without remap also fail because writing to a cgroup v1 hierarchy from a non-init user namespace now requires CAP_SYS_ADMIN against that namespace.

**The mitigation in the field:** cgroups v2 doesn't have `release_agent` as a writable path. Moving to cgroups v2 eliminates this class of bug entirely. Most modern distros (Fedora 31+, RHEL 9+, Ubuntu 22.04+) default to v2; some legacy clusters and some Docker installs still ship v1.

**Why this matters as a teaching case:** the bug wasn't in runc, wasn't in containerd, wasn't in seccomp. It was in a kernel mechanism that pre-dated user namespaces by years and never had its security model audited against the modern container threat model. The same class — "kernel feature that pre-dates namespaces, never audited for namespace crossing" — applies to several other primitives still in the tree (keyrings, BPF cgroup attach, perf events, the trace_uprobe surface).

## 8. Project Zero and the research lineage

Felix Wilhelm at Google Project Zero published several runc and container-runtime analyses across 2018-2022 — including a notable `runc` namespace setup analysis that surfaced a class of bugs in the privileged-FD-leak space that later became leaky-vessels.

The broader research stream:

- **Brad Spengler** (grsecurity) — kernel hardening lineage. The PaX/grsecurity heritage informed many of the modern Linux mitigations (USERCOPY hardening, KERNEXEC, RAP-style CFI ancestors) that make container escapes harder. grsecurity's commercial kernel patches include namespace-hardening that mainline Linux still doesn't ship by default.
- **Aleksa Sarai** (SUSE / opencontainers / runc co-maintainer) — primary author of runc's modern security model. Wrote the post-CVE-2019-5736 hardening, the `RESOLVE_BENEATH` and `openat2(2)` integrations, and several rootless-container plumbing pieces. If runc has a single "security architect," it's Sarai.
- **Liz Rice** (Aqua Security → Isovalent, now Chief Open Source Officer) — author of *Container Security* (O'Reilly, 2020). The canonical introductory book. Liz also champions eBPF-based runtime detection (Tetragon).
- **Yossi Naar and Daniel Sagi** (Aqua Security) — research on container escape primitives and runtime detection bypasses.
- **Loris Degioanni** (Sysdig founder) — original Falco architect. The eBPF runtime detection model that catches container escape syscall patterns at runtime.
- **The Twistlock → Palo Alto Unit 42 stream** — Yuval Avrahami and Yiqi Sun's CVE-2022-0492 walk-through is the canonical write-up. Twistlock (acquired by Palo Alto in 2019) maintained the deepest container-escape research output of any vendor through ~2022.

The lesson from reading this lineage: container escape research is a small field. Six-to-ten researchers produce the bulk of the public corpus. If you're hunting a container escape primitive and you haven't read all six of those names' recent posts, you're missing prior art.

## 9. OverlayFS as a container-escape primitive

OverlayFS (the union filesystem that backs most container image storage) has a recurring class of bugs around how it handles two-layer file ownership when user namespaces are involved.

### 9.1 CVE-2023-0386 — OverlayFS uid/gid mapping bypass

**Primary anchor:** Xingyuan Mo (IceSword Lab). Disclosed January 2023.

**The bug:** OverlayFS's copy-up operation (when a process in an upper layer writes to a file that lives in the lower layer, OverlayFS copies the file to the upper layer) handled SUID bits in a way that allowed UID/GID smuggling across user-namespace boundaries. A user in an unprivileged user namespace could create a SUID-root file in an OverlayFS upper layer; when copied up, the SUID bit was preserved in a way that — when executed from a different mount namespace — granted host root.

Local privilege escalation from any unprivileged user-namespace-using context, including default rootless containers.

**The fix:** Linux 6.2+ kernel patch hardening copy-up to strip SUID/SGID bits when the operation crosses user-namespace boundaries.

### 9.2 CVE-2023-2640 and CVE-2023-32629 — "GameOver(lay)" lineage

Ubuntu-specific patches to OverlayFS that diverged from upstream introduced a different SUID-via-overlay primitive. Ubuntu's customized OverlayFS (the patches that backported user-namespace support into older kernels) had a different uid/gid handling path that allowed a SUID binary in an overlay upper to be executed with cross-namespace privileges.

These are Ubuntu-kernel-specific CVEs (Wiz's "GameOver(lay)" branding). Cross-link `[[reference-linux-kernel-exploitation]]` §distro-specific-patches for why downstream-only kernel patches recur as escape primitives.

### 9.3 The general pattern

OverlayFS is a layered filesystem where file ownership and mode bits cross between layers during copy-up. Every CVE in this class is a variant of: "the copy-up didn't sanitize SUID/SGID/capability-xattr bits in some specific edge case, and a user in a low-privileged context could smuggle those bits across into a context where they grant elevated privilege."

The defender posture: distroless base images don't ship SUID binaries; if your base image has no SUID binaries, the OverlayFS SUID-smuggling primitives have nothing to smuggle. Cross-link `[[reference-supply-chain-provenance]]` §minimal-base-images.

## 10. Isolation-tier survey — what runs harder than runc

When the workload is hostile (multi-tenant SaaS, customer-supplied code execution, browser-rendered untrusted content), runc is not sufficient. The following tiers exist, each with its own trade-offs.

### 10.1 gVisor (Google, 2018+)

**Primary anchors:** Adin Scannell, Andrei Vagin, Hanieh Hashemi (Google).

**Architecture:** gVisor's Sentry component is a user-space kernel-syscall interceptor written in Go. The container runs against Sentry's reimplementation of ~250 Linux syscalls instead of against the host kernel directly. Sentry mediates everything; only a handful of syscalls reach the host kernel (and those go through a heavily-restricted seccomp filter on Sentry itself).

**OCI shim:** `runsc` (gVisor's OCI runtime), drop-in replacement for runc.

**Performance:** ~5-15% overhead on syscall-heavy workloads; ~negligible on CPU-bound workloads. Network performance with the `netstack` backend is meaningfully slower than host-network; the alternative `host` backend trades isolation for performance.

**Attack surface:** Sentry itself. ~250 syscalls of Go code that intercepts and reimplements Linux syscall behavior. Bugs in Sentry are escape candidates, and several have been found (`[unverified specific CVE list]` — gVisor has a security bulletin page; check `github.com/google/gvisor/security/advisories` for the current list). The structural advantage: the attack surface is ~250 Go syscalls (smaller, simpler, less code) instead of ~330+ C syscalls in the Linux kernel (larger, more complex, more code).

**Where it's deployed:** Google Cloud Run (entire workload tier runs under gVisor `[unverified scope]`), App Engine, parts of Google internal multi-tenant infrastructure. AWS does not use gVisor (AWS uses Firecracker — see §10.3).

**When to choose gVisor over runc:** when the workload may execute untrusted code (PaaS, CI/CD untrusted-tenant builds, browser sandboxing, language-runtime sandbox like a Notebook).

**When NOT to choose gVisor:** when the workload is performance-sensitive on syscalls (databases, JIT-heavy runtimes), or when it depends on Linux kernel features Sentry doesn't reimplement (some BPF flavors, some namespace operations, some less-common ioctls).

### 10.2 Kata Containers (Intel + Hyper.sh lineage → OpenStack Foundation → CNCF)

**Primary anchors:** Eric Ernst, Samuel Ortiz, Wei Liu (across Intel + Hyper.sh + Red Hat).

**Architecture:** each container (or pod) runs inside its own lightweight VM. The default VMM is QEMU with a minimal Linux kernel; alternative VMMs include Firecracker and cloud-hypervisor. Filesystem sharing is via VirtIO-FS (or 9p in older versions). The container does NOT share the host kernel.

**Isolation:** strong. A kernel bug in the guest kernel is a guest-kernel-only bug; it doesn't compromise the host. A QEMU escape (CVE-2019-14378 PCNET, CVE-2020-29130 SLiRP, et al.) crosses into the host, but the host attack surface is QEMU's exposed device emulators, not the full Linux kernel.

**Performance:** start time ~250ms-500ms (slower than runc's ~50ms). Steady-state syscall performance ~equal to runc for most workloads. Memory overhead per pod ~30-100MB for the VM.

**Real CVEs:** CVE-2020-2023, CVE-2020-2024, CVE-2020-2025 — Kata host-escape lineage from 2020. Even Kata isn't bulletproof; the strong-isolation tier still has its own bug class around the VMM↔host RPC surface.

**When to choose Kata:** when the workload must run untrusted code AND must use kernel features gVisor doesn't reimplement (custom BPF, specialized network stacks, kernel modules the workload requires).

**Where it's deployed:** RHEL (sandboxed-container preview), parts of Alibaba Cloud, parts of Azure (Confidential Containers built on Kata).

### 10.3 Firecracker (AWS, 2018+)

**Primary anchors:** Diana Carroll, Andra Paraschiv, Alexandru Agache (AWS).

**Architecture:** ~50KB Rust VMM, KVM-based. No PCI, no USB, no most-device-emulators. Bootstraps a minimal Linux guest in ~125ms. Designed from the ground up for "microVM density" — running thousands of microVMs per host.

**AWS usage:** AWS Lambda runs on Firecracker (since 2018). AWS Fargate (the serverless ECS/EKS substrate) moved to Firecracker in 2019. AWS App Runner uses Firecracker. The substrate is hardened against Spectre / Meltdown / L1TF / MDS class side-channels via configuration (per-tenant CPU pinning, SMT disabled in some configurations) `[unverified specific configuration details]`.

**Attack surface:** the Rust VMM itself, plus VirtIO device emulators (block, net, vsock). Smaller than QEMU by ~two orders of magnitude in code size.

**Side-channel research:** AWS publishes very limited threat-model documentation. There is `[unverified specific advisory]` on Spectre-on-Firecracker primitives publicly documented as of 2026; AWS treats the Firecracker threat model as commercially sensitive. The independent research community has not produced a public Firecracker escape as of writing.

**When to choose Firecracker:** when running on AWS, multi-tenant serverless workloads. Firecracker is not a drop-in replacement for runc in your own cluster unless you're operating at AWS-scale and willing to build the operational tooling around it. firecracker-containerd (and Kata-on-Firecracker) make it more accessible.

### 10.4 Sysbox (Nestybox → Docker, 2019+)

**Primary anchor:** Cesar Talledo (Nestybox founder, now at Docker since the acquisition).

**Architecture:** "system container" runtime. Runs systemd, Docker-in-Docker, Kubernetes-in-Docker, etc. *safely without* `--privileged`. Uses user-namespace remap + procfs/sysfs virtualization to make the inner systemd / inner Docker think it has the privileges it expects, while actually running as an unprivileged user on the host.

**When to choose Sysbox:** when you need to run "system-like" workloads (Docker-in-Docker for CI runners, Kubernetes-in-Docker for testing, full systemd-based VM-style workloads) inside a container without the host-takeover risk of `--privileged`.

**Where it's deployed:** primarily as a developer/CI workload runtime. Less commonly in production data planes.

### 10.5 Container-as-microVM hybrids and confidential containers

- **cloud-hypervisor** (Intel + Microsoft + Cloudflare). Rust VMM, similar in spirit to Firecracker but with more device support. Backs some Azure Confidential Computing workloads.
- **Confidential Containers (CoCo)** — CNCF Sandbox project that combines Kata + AMD SEV-SNP / Intel TDX / IBM Secure Execution for hardware-attested confidential workloads. Cross-link `[[reference-confidential-computing]]` §confidential-VMs-and-containers.
- **Azure Confidential Containers (GA 2023 for AKS)**, **GCP Confidential GKE Nodes (AMD SEV / Intel TDX)**, **AWS Nitro Enclaves** (different model — enclave attached to an EC2 instance, not a container per se). `[unverified specific GA dates]`.

## 11. Hardening discipline (defender side)

When you can't change the runtime tier (you're stuck on runc), stack defense in depth. The checklist:

### 11.1 Capability minimization

```
docker run --cap-drop=ALL --cap-add=NET_BIND_SERVICE ...
```

Drop everything; add back exactly what the workload needs. For most workloads, NET_BIND_SERVICE (binding to <1024 ports) is the only capability needed. Web apps that don't bind <1024 ports don't even need that.

### 11.2 seccomp tightening beyond Docker default

The Docker default profile is "permissive enough to run most workloads." Tighter profiles ship with specific workload knowledge:

- **docker/labs/security/seccomp/seccomp-profiles** (legacy reference)
- **Anchore Grype seccomp** workload-specific profiles
- **Custom profile** generated from `strace -c <workload>` + manual review

Common workloads don't need ~150 of the ~330 syscalls. Profile your workload; restrict the syscall surface.

### 11.3 Read-only root filesystem

```
docker run --read-only --tmpfs /tmp --tmpfs /run ...
```

Workloads that write to `/var/log/...`: mount that path as a named volume, not as part of the read-only root.

### 11.4 User-namespace remap

Either Docker daemon `userns-remap` (in `/etc/docker/daemon.json`):

```
{"userns-remap": "default"}
```

Or rootless runtime entirely — rootless Podman, rootless containerd, rootless Docker. Rootless eliminates the entire class of "container root → host root" via missing-namespace-remap.

### 11.5 no-new-privileges + dropped setuid

```
docker run --security-opt no-new-privileges ...
```

Pair with distroless or scratch base images that ship no SUID binaries.

### 11.6 MAC profiles

Use the default AppArmor or SELinux profile. Don't disable with `--security-opt apparmor=unconfined` or `--security-opt label=disable` unless you have a specific reason and have documented the threat model trade-off.

### 11.7 Pod Security Standards (k8s)

If you're on Kubernetes, use the "Restricted" Pod Security Standard at the namespace level. This enforces:

- `runAsNonRoot: true`
- `allowPrivilegeEscalation: false`
- `readOnlyRootFilesystem: true`
- `capabilities.drop: [ALL]`
- `seccompProfile.type: RuntimeDefault`
- No privileged containers, no host networking, no hostPath mounts.

Cross-link `[[reference-container-k8s-security]]` §pod-security-standards.

### 11.8 Runtime detection (eBPF)

- **Falco** (CNCF Graduated 2024) — Sysdig's runtime detection engine. Watches syscalls via eBPF; matches against rules for known escape primitives (suspicious `mount`, suspicious `setns`, write to `/proc/sys/kernel/core_pattern`, write to release_agent paths, etc.).
- **Tetragon** (Isovalent / Cilium) — eBPF-based observability + enforcement. Can KILL processes on policy violation in real time.
- **Tracee** (Aqua Security) — eBPF tracing engine with a rule library focused on container security events.

Cross-link `[[reference-detection-engineering]]` for the broader detection-as-code methodology and `[[reference-linux-kernel-exploitation]]` §eBPF for the substrate.

The honest framing: runtime detection catches *known* primitive patterns. Novel primitives — including any future runc / containerd / BuildKit CVE — won't show up in Falco rules until someone writes the rule. Detection lags exploitation.

## 12. 2024-2026 currency

State of the art as of mid-2026:

**leaky-vessels (Jan 2024)** as the canonical recent corpus event. Every container security team should know the four CVEs cold. Patches landed quickly (runc 1.1.12, BuildKit 0.12.5); the ecosystem migrated within ~3 months. No publicly documented in-the-wild exploitation as of writing `[unverified ongoing telemetry]`.

**xz-utils backdoor (CVE-2024-3094)** — surfaced March 2024. Showed that supply-chain compromise of a build-time dependency can bridge into container-image-poisoning. The xz-utils tarball-injected backdoor would have shipped in container images built from any base layer that included liblzma. Cross-link `[[reference-supply-chain-provenance]]` §image-provenance + `[[reference-cicd-supply-chain]]` §build-time-dependencies.

**Rootless containers reaching production parity** — rootless Podman has matched root-podman for the bulk of workloads since ~2022. Rootless Docker (`dockerd-rootless`) is still maturing; some networking modes and some volume drivers don't work. Fedora 39+ defaults to rootless Podman for the user; many Linux distros have followed. The structural win: rootless containers run inside a user namespace by default, eliminating CVE-2022-0492 class bugs.

**eBPF-based runtime detection maturing** — Falco graduated CNCF in 2024. Tetragon is GA from Isovalent. Tracee is Aqua-stewarded. The "default-deny syscall list per workload" pattern (CO-RE eBPF, per-workload BPF policy) is reaching production at the hyperscalers and at security-forward end users.

**Wasm-as-container-alternative** — WasmEdge, wasmtime-containerd-shim, Spin (Fermyon). Different threat model: instead of a Linux process in a namespace, you run a WebAssembly module against a host-provided syscall surface. The threat model resembles a programming-language sandbox more than a Linux container; cross-link `[[reference-webassembly-security]]` §WASI and §Bytecode-Alliance-security-WG. Wasm-as-container is in production at Cloudflare Workers, Fastly Compute@Edge, and increasingly at GKE (containerd-wasm-shims).

**Confidential containers GA on cloud:**
- Azure Confidential Containers on AKS (AMD SEV-SNP), GA ~2023.
- GCP Confidential GKE Nodes (AMD SEV / Intel TDX), GA 2023-2024 `[unverified specific GA dates]`.
- AWS doesn't offer "confidential containers" per se; AWS Nitro Enclaves is the closest analog and has a different programming model.

**Cloud Native Computing Foundation security WG output:** ongoing work on supply-chain SBOM for container images, in-toto attestations for image builds, sigstore for image signing. Cross-link `[[reference-supply-chain-provenance]]`.

## 13. Real-incident corpus

The container-escape incident corpus is smaller than you'd expect. Most "container breach" headlines are misconfiguration (exposed Docker socket, exposed Kubernetes API) rather than escape via a primitive. The genuine escape corpus:

### 13.1 Tesla Kubernetes 2018

**Anchor:** RedLock (now Palo Alto) Cloud Security Intelligence team disclosed February 2018.

Tesla had an internet-exposed Kubernetes dashboard with no authentication. Attackers deployed a cryptominer pod and exfil'd AWS S3 credentials from the cluster's service-account secrets. Not strictly a container ESCAPE — the dashboard misconfiguration gave attackers pod-create privileges, and the pod-create privilege gave them everything else. Listed here because it's the canonical "container security misconfiguration as material security failure" anchor, and because the lesson (Kubernetes API is the front door, lock it) applies broadly.

### 13.2 TeamTNT (2020-2021)

**Anchors:** Aqua Security, Trend Micro, Cado Security reporting across 2020-2021.

Long-running campaign by the TeamTNT cluster (likely German-speaking, possibly individual actor) that targeted exposed Docker daemon sockets on the internet. Modus operandi:

1. Scan for `:2375/tcp` open (unauthenticated Docker API).
2. Deploy a cryptominer container with `--privileged --pid=host --net=host`.
3. From inside, mount the host filesystem and harvest AWS / GCP / Azure metadata credentials.
4. Pivot into cloud APIs, deploy more miners, exfil credentials, repeat.

Multiple variants: Hildegard, Kinsing, WatchDog, Doki. The "container malware family" pattern of cryptomining-via-misconfigured-runtime continues into 2026 with new branding (`[unverified specific 2024-2026 attribution]`).

### 13.3 Doki / Ngrok-Miner / Kinsing / Hildegard

Specific malware families that exploited Docker socket exposure and unprivileged container misconfigurations. Each used a slightly different persistence mechanism (DGA-based C2 in Doki, Java SSRF + Kinsing kdevtmpfsi in Kinsing, multi-stage Hildegard). Cross-link `[[reference-threat-intel-methodology]]` for tracking these families as a campaign.

### 13.4 runc CVE-2019-5736 in-the-wild

Post-disclosure (Feb 2019), several reports of crypto-mining campaigns weaponizing the bug. Specific attribution to a Cetus group is `[unverified specific advisory]`. The structural lesson: when a runtime-tooling escape is disclosed publicly, weaponization in cryptomining campaigns follows within weeks-to-months.

### 13.5 leaky-vessels (Jan 2024)

No publicly documented in-the-wild exploitation as of disclosure or in the ~24 months since `[unverified ongoing telemetry]`. Snyk's own reporting framed it as "high-impact, broad-attack-surface, no confirmed exploitation observed."

The honest reading: container-escape primitives that REQUIRE the attacker to control the workload (i.e., the attacker needs to ship a malicious container image into the target environment) are weaponized against multi-tenant SaaS hosts, build-pipeline CI runners (where the attacker controls a PR), and PaaS workloads — not against single-tenant production deployments where the operator controls all the workloads.

## 14. Honest failure modes — load-bearing

This section is where the doc earns its keep. Each item is something a defender or a builder may believe and be wrong about.

### 14.1 runc is not a security boundary

State this baldly: **runc, containerd, cri-o, and the OCI runtime family are not security boundaries against malicious workloads.** They are isolation conveniences. They depend on the Linux kernel's namespace + cgroup + capability + seccomp + MAC primitives being bug-free, AND on the runtime tooling not leaking privileged FDs / mounts / paths across the boundary during setup.

The kernel is not bug-free (see `[[reference-linux-kernel-exploitation]]`). The runtime tooling leaks privileged state periodically (see §4, §5). Therefore: if the workload may be hostile, runc is not enough. Move to gVisor / Kata / Firecracker.

### 14.2 "--privileged is fine for trusted workloads" is the wrong framing

"Trusted workloads" is not a static category. A trusted workload's dependency chain — its base image, its language runtime, its package manager, its CI pipeline, its developers' laptops — is the actual attack surface. Supply-chain compromise of a dependency (cross-link `[[reference-cicd-supply-chain]]` and `[[reference-supply-chain-provenance]]`) converts a "trusted" workload into a hostile one with no notice.

The xz-utils backdoor (CVE-2024-3094) demonstrated this concretely: a trusted SSH daemon's trusted compression library was backdoored upstream. Container images built from base layers that included liblzma would have shipped the backdoor. If those containers ran `--privileged`, the backdoor had host root.

If you can't say "this workload's full dependency chain — including transitive dependencies, language runtime, base image, build tools — is exhaustively verified" with a straight face, don't run it `--privileged`.

### 14.3 Rootless ≠ escape-proof

User namespaces eliminate a wide class of bugs (CVE-2022-0492 release_agent, most CAP_SYS_ADMIN-based escapes). But a bug in the user-namespace plumbing itself (CVE-2023-0386 OverlayFS uid/gid mapping) escalates a rootless container directly to host root. User-namespace bugs are rarer than other classes — but they exist, they're impactful when they hit, and "rootless" is not a silver bullet.

### 14.4 Detection lags exploitation

Falco / Tetragon / Tracee catch *known* primitive patterns. Each detection rule encodes a known escape signature: writes to release_agent, suspicious mount syscalls, writes to /proc/sys/kernel/core_pattern, etc. **Novel escape primitives have no detection rule until someone writes one.** Time-to-rule for a public CVE is usually days to weeks; for a private 0-day, indefinite.

This is the same dynamic as in `[[reference-detection-engineering]]` §detection-rule-coverage: detection follows research, and research follows incidents. Plan for the window between novel-primitive-emergence and rule-deployment to be measured in weeks.

### 14.5 Cloud-provider managed-runtime opacity

When you run a workload on EKS / GKE / AKS / Fargate / Cloud Run, you mostly don't know what container runtime is underneath. Defaults change without notice. Examples that have shifted at various points:

- AWS Fargate runs on Firecracker since 2019.
- AWS EKS Auto Mode (introduced 2024) uses Bottlerocket as the node OS, with containerd as the runtime.
- GCP Cloud Run runs containers under gVisor `[unverified scope]`. GKE node pools run containerd by default.
- Azure AKS runs containerd by default; Confidential Containers on AKS run on Kata + AMD SEV-SNP.

The structural problem: customers often don't know what isolation tier they're paying for. Ask your cloud provider; treat the answer as your operational threat model.

### 14.6 "We use gVisor" can be a false comfort

gVisor is opt-in per-workload (per-pod in Kubernetes via `runtimeClassName: gvisor`). Most production gVisor deployments cover the "untrusted tenant" workload path only. The platform team's containers — the metrics agent, the log collector, the secrets-injection sidecar, the service mesh proxy — almost always still run on runc.

Verify gVisor coverage by asking: "what fraction of pods in the cluster have `runtimeClassName: gvisor`?" If the answer is "the customer-workload namespace," then the platform pods are unprotected. An escape in a platform pod compromises the host.

### 14.7 Kernel-shared model is the elephant in the room

All runc-class runtimes share the host kernel with all containers on the node. A single in-tree Linux kernel CVE (eBPF, io_uring, netfilter, namespace plumbing, OverlayFS, filesystem driver) = escape primitive for every container on every node running an affected kernel.

The Linux kernel ships dozens of CVEs per year (cross-link `[[reference-linux-kernel-exploitation]]` §CVE-cadence). Not all are exploitable from a container — but a non-trivial fraction are. Patching the host kernel is the dominant control. The patch-to-deploy time matters: clusters that patch host kernels in days are meaningfully more secure than clusters that patch in months.

### 14.8 Build-time vs runtime is a fuzzy boundary

leaky-vessels reminded the field: the *build* tooling (BuildKit) is privileged trusted code that runs on the host. A malicious Dockerfile (in a PR to your repo, in a third-party action, in a base image) can exploit build-time CVEs in BuildKit to compromise the build host — without ever running a container at runtime.

This matters for CI runners that build images. The "container runtime" attack surface includes the build pipeline, not just `docker run`. Cross-link `[[reference-cicd-supply-chain]]` §self-hosted-runners and `[[reference-supply-chain-provenance]]` §build-time-integrity.

## 15. Cross-link cluster

Related sibling docs in this corpus:

- `[[reference-container-k8s-security]]` — Kubernetes orchestrator security, Pod Security Standards, RBAC, admission controllers, NetworkPolicy. The "layer above" this doc.
- `[[reference-linux-kernel-exploitation]]` — kernel exploitation primitives, modern mitigations (KASLR/SMEP/SMAP/KPTI/CET-IBT), slab heap-spray, eBPF/io_uring/netfilter attack surfaces, kernelCTF + Project Zero corpus. The "layer below" this doc.
- `[[reference-cloud-iam]]` — once an attacker has escaped a container, the typical next move is enumerating cloud credentials from IMDS / workload-identity tokens. AWS / GCP / Azure IAM threat model.
- `[[reference-cicd-supply-chain]]` — build-pipeline compromise as a path to container-image poisoning; self-hosted runners as escape surface.
- `[[reference-supply-chain-provenance]]` — SLSA / sigstore / SBOM / VEX. Provenance of base images; verification of build integrity.
- `[[reference-detection-engineering]]` — Falco / Tetragon / Tracee runtime detection; sigma + behavioral rules. Detection-as-code methodology.
- `[[reference-confidential-computing]]` — confidential containers, AMD SEV-SNP / Intel TDX / IBM SE / NVIDIA H100 CC. The strongest isolation tier (TEE-attested guest).
- `[[reference-webassembly-security]]` — Wasm as container alternative; WASI host-import surface; capability-based security model.
- `[[reference-race-conditions-concurrency]]` — TOCTOU primitives (relevant for CVE-2024-23651, CVE-2024-23652, OverlayFS race bugs).
- `[[reference-dfir-methodology]]` — container forensics, ephemeral-evidence collection, the "container is gone before you can image it" problem.
- `[[reference-code-review-expertise]]` — when auditing a runtime / build tool for the next leaky-vessels-class bug, the candidate-point auditing methodology applies.
- `[[reference-threat-intel-methodology]]` — tracking container-malware families (TeamTNT, Kinsing, Hildegard) as campaigns.
- `[[reference-shell-injection-expertise]]` — `release_agent` and entrypoint-shell bugs as classes; CWE-78/88/150 taxonomy applies to container escape via shell-injection in entrypoint scripts.
- `[[reference-secrets-management-discipline]]` — the post-escape attacker's next move is harvesting cloud credentials from `/var/run/secrets/...`, IMDS, mounted secret volumes. Defend the secret surface.

## 16. Operational checklist

For the staff security engineer auditing a container-based deployment:

1. **List the runtime.** runc / containerd-runtime / cri-o / runsc / kata-runtime / Firecracker. If the answer is "I don't know," start there.
2. **Check for `--privileged` containers.** `docker ps --format '{{.Names}}\t{{.Command}}' | xargs ...` or in Kubernetes, `kubectl get pods -A -o json | jq '.items[] | select(.spec.containers[]?.securityContext.privileged == true)'`. Treat any hit as a finding.
3. **Check for mounted daemon sockets.** Search for `/var/run/docker.sock`, `/var/run/containerd/containerd.sock`, `/var/run/crio/crio.sock` in volume specs. Treat any hit as a finding.
4. **Verify capability minimization.** Workloads should drop ALL and add back individually. `securityContext.capabilities.drop: [ALL]` in k8s.
5. **Verify seccomp profile.** `RuntimeDefault` minimum; ideally a workload-specific profile.
6. **Verify user-namespace remap.** `userns-remap` in Docker, `runAsNonRoot` + `runAsUser >= 1000` in k8s.
7. **Verify `no-new-privileges`** and read-only root filesystem.
8. **Verify host kernel patch level.** A container escape via a kernel CVE matters only if the kernel is vulnerable; track kernel CVE patch cadence as a primary metric.
9. **Verify runtime tier matches workload trust level.** Untrusted multi-tenant workloads → gVisor / Kata / Firecracker. "Trusted" single-tenant workloads → runc is acceptable IF the dependency chain is verified end to end.
10. **Verify runtime-detection coverage.** Falco / Tetragon / Tracee installed; rules current; alerts routed.
11. **Verify build-pipeline isolation.** BuildKit running rootless; build runners not sharing trust with production runtime.
12. **Verify image-provenance.** Base images signed (sigstore / cosign); SBOM published; VEX statements for known-not-affected CVEs.

A clean answer to all twelve items doesn't make you escape-proof — see §14 — but the absence of any one item is a discrete finding.

---

**Document discipline.** This is an operational doc, not a tutorial. CVE numbers are real where verified. `[unverified]` flags mark items where the specific date, version, or attribution wasn't ground-checkable in the authoring window — verify against primary sources before citing in a finding. The corpus of container-escape researchers is small; the names in §8 are the load-bearing prior art for almost every bug class in this doc.
