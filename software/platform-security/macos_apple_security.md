# macOS and Apple Security: Guiding Principles and Staff-Level Expertise

> Synthesized from the public research output of Patrick Wardle (Objective-See Foundation / DoubleYou,
> formerly NSA / Synack / Jamf), Csaba Fitzl ("theevilbit"), Cedric Owens, Jaron Bradley (Jamf Threat Labs),
> Howard Oakley (The Eclectic Light Company), and Thomas Reed (Malwarebytes).
> Side-channel and microarchitectural research from Daniel Genkin (Georgia Tech), Yuval Yarom (Ruhr
> Universität Bochum), Christopher W. Fletcher (UC Berkeley), Boru Chen (UIUC), Jason Kim (Georgia Tech),
> the MIT CSAIL CAP group (PACMAN, 2022), and Kaspersky GReAT (Operation Triangulation, 2023–2024).
> Covers talks and papers from DEF CON (DC22–DC33), Black Hat USA (2015–2022), ShmooCon, Virus Bulletin,
> Objective by the Sea (v1.0–v6.0, 2018–2023), USENIX Security and IEEE S&P (2024–2025).
>
> Cross-references:
> - `mobile_security_expertise.md` — iOS/iPadOS adjacency, BLASTPASS, NSO Pegasus
> - `hardware_side_channels_expertise.md` — Apple Silicon DMP/LAP/LVP, PAC, Spectre family
> - `confidential_computing_expertise.md` — Apple Private Cloud Compute, attestation models
> - `cloud_iam_expertise.md` — Entra-as-MDM-source, federated device enrollment
> - `detection_engineering_expertise.md` — XProtect Yara, ESF telemetry, Mac-specific Sigma
> - `linux_kernel_exploitation_expertise.md` — KIP/PAC parallels in Linux ARM64 kernel

---

## I. Researcher Profiles

### Patrick Wardle
Founder of the Objective-See Foundation; co-founder of DoubleYou (2024, with Mikhail Sosonkin, ex-Apple).
Previously: NSA, Synack (Director of Research), Digita Security (founder, acquired by Jamf 2019),
Jamf (Principal Security Researcher 2019–2021).

**DEF CON presence:** 17 confirmed talks across DC22 (2014) through DC33 (2025).

**Full DEF CON talk list:**

| Year | Talk |
|------|------|
| DC22 (2014) | Optical Surgery; Implanting a DropCam (w/ Colby Moore) |
| DC23 (2015) | Stick That In Your (root)Pipe & Smoke It |
| DC23 (2015) | 'DLL Hijacking' on OS X? #@%& Yeah! |
| DC24 (2016) | I've got 99 Problems, but Little Snitch ain't one |
| DC25 (2017) | Death By 1000 Installers; on macOS, it's all broken! |
| DC25 (2017) | Offensive Malware Analysis: Dissecting OSX/FruitFly via a Custom C&C Server |
| DC26 (2018) | Fire & Ice: Making and Breaking macOS Firewalls |
| DC26 (2018) | The Mouse is Mightier than the Sword |
| DC27 (2019) | Harnessing Weapons of Mac Destruction |
| DC28 (2020) | Office Drama on macOS |
| DC29 (2021) | Bundles of Joy: Breaking macOS via Subverted Applications Bundles |
| DC30 (2022) | Déjà Vu: Uncovering Stolen Algorithms in Commercial Products (w/ Tom McGuire) |
| DC30 (2022) | You're Rooted (CVE-2022-28756 Zoom privesc) |
| DC31 (2023) | Demystifying (& Bypassing) macOS's Background Task Management |
| DC31 (2023) | Nothing but Net: Leveraging macOS's Networking Frameworks to Heuristically Detect Malware |
| DC33 (2025) | Binary Facades: Reversing Approaches to Extract Embedded Scripts in Compiled macOS Malware |
| DC33 (2025) | Mastering Apple's Endpoint Security for Advanced macOS Malware Detection |

**Black Hat USA:** 2015 (Writing Bad @$$ Malware for OS X), 2017 (FruitFly C&C), 2018 (macOS Firewalls),
2020 (Office Drama), 2021 (Arm'd and Dangerous — arm64/M1 malware), 2022 (Algorithm theft in commercial products).

**Book:** *The Art of Mac Malware*, Vol. 1 (No Starch Press, 2022) — free at taomm.org.
Vol. 2 (detection-focused) available in chapter PDFs at taomm.org/vol2/pdfs/.

**Key co-presenters:** Jaron Bradley and Cedric Owens (OBTS v4.0 CVE-2021-30657); Runa Sandvik (US spy agency
macOS implants); Tom McGuire (algorithm theft); Colby Moore / Synack (DropCam implant).

### Csaba Fitzl ("theevilbit")
Security researcher; macOS course instructor at Offensive Security (EXP-312); later Kandji.
Primary research: TCC bypass techniques, macOS privilege escalation, XPC exploitation.
Known for: "Beyond the Good Ol' LaunchAgents" blog series (30+ macOS persistence mechanisms cataloged);
"20+ Ways to Bypass Your macOS Privacy Mechanisms" (Black Hat USA 2021, EU 2022, Asia 2024, with Wojciech Regula).
CVEs: CVE-2020-9771, CVE-2021-1784, CVE-2021-30782 (all TCC bypass).

### Jaron Bradley
Director of Jamf Threat Labs. Background in IR, threat hunting, APT investigation. Blog: themittenmac.com.
Key analyses: DazzleSpy (2022), Shlayer/CVE-2021-30657 (2021, first to detect in wild at Jamf Protect),
RustBucket and KandyKorn (2023, BlueNoroff/Lazarus), Flutter-obfuscated DPRK malware (2024).

### Cedric Owens
Independent researcher. Discovered CVE-2021-30657 (Gatekeeper bypass, exploited by Shlayer in the wild before patch).
Author of ESF implementation guides on Medium. Co-presenter with Wardle and Bradley at OBTS v4.0.

### Howard Oakley (The Eclectic Light Company — eclecticlight.co)
macOS internals documentarian. Produces the most technically accurate public documentation of macOS internal
mechanisms that Apple does not formally document (quarantine xattr, codesigning, AMFI, XProtect Remediator,
Secure Boot). Security researchers including Wardle reference eclecticlight.co for ground truth before building
exploits or detections.

### Thomas Reed (Malwarebytes)
Director of Mac and Mobile Threat Intelligence. First to publicly document FruitFly (January 2017).
Tracked Shlayer ecosystem 2018–2021. Co-discovered Silver Sparrow (February 2021). Annual Mac Threat Reports.

---

## II. macOS Security Architecture

### Gatekeeper

Prevents execution of unsigned or untrusted software downloaded from the internet.

**Mechanism:**
1. Downloading via Safari, Chrome, Mail, etc. sets `com.apple.quarantine` extended attribute (xattr) on the file.
   Value encodes: download URL, agent bundle ID, timestamp, quarantine flags.
2. On first launch of a quarantined app, `syspolicyd` (Gatekeeper) checks:
   - Code signature validity (Developer ID certificate against Apple root CA).
   - Notarization ticket (from Apple's notarization service; checked via OCSP or embedded stapled ticket).
   - Hardened runtime requirements (required for notarized apps since 2019).
3. Failure → block with user dialog.

**Critical xattr caveat:** `curl`, `scp`, USB drives, and many archive utilities do NOT set the quarantine xattr.
Files delivered via these paths bypass Gatekeeper entirely — no signature check, no notarization check.

**Notarization:** Apple scans for known malware and hardened runtime compliance before issuing a ticket.
Apple can revoke tickets reactively (has done so for Shlayer samples). XProtect Remediator (macOS 12.3+)
handles autonomous background remediation; MRT retired April 2022.

**Hardened Runtime** (required for notarization): Restricts `DYLD_INSERT_LIBRARIES` injection; prevents
unsigned code injection into process address space. Weakening entitlements:
- `com.apple.security.cs.allow-dyld-environment-variables` — re-enables DYLD injection
- `com.apple.security.cs.disable-library-validation` — allows unsigned dylib injection
- `com.apple.security.cs.allow-unsigned-executable-memory` — allows unsigned JIT code

**Bypass techniques (historical CVEs):**

| CVE | Year | Mechanism |
|-----|------|-----------|
| CVE-2021-30657 | 2021 | Script-based app bundle with no `Info.plist` — `syspolicyd` skipped all checks. Exploited by Shlayer before patch. Discovered by Cedric Owens. |
| CVE-2021-30853 | 2021 | Empty shebang line (`#!/ `) — macOS fell back to `/bin/sh`, bypassing Gatekeeper. Discovered by Gordon Long. |
| Notarization bypass | 2020 | Shlayer was inadvertently notarized by Apple — first documented notarized malware. |
| Archive extraction | pre-2020 | Many archive utilities did not propagate quarantine xattr to extracted contents. |

macOS Sequoia (2024): Apple tightened Gatekeeper for unnotarized apps; unnotarized apps now require explicit
user bypass in System Settings > Privacy & Security (cannot be opened by double-click alone).

---

### SIP (System Integrity Protection)

Introduced OS X 10.11 El Capitan (2015). Prevents modification of OS-owned paths and SIP-protected processes.

**Protected filesystem paths:** `/System`, `/usr` (except `/usr/local`), `/sbin`, `/bin`, `/private/var/db/`.

**Protected runtime behaviors:** Prevents debugger attachment to SIP-protected processes (`loginwindow`, `launchd`,
`tccd`); prevents unsigned KEXT loading; prevents modification of protected processes' memory.

**NOT protected:** `/Library`, `/Applications`, `~/Library`, user home directories, `/usr/local`.

**SIP bypass CVE history:**

| CVE | Year | Mechanism | Discoverer |
|-----|------|-----------|------------|
| CVE-2021-30892 "Shrootless" | 2021 | `system_installd` carries `com.apple.rootless.install.heritable` entitlement; child processes (bash/perl) inherit SIP bypass via malicious post-install script in Apple-signed `.pkg` | Microsoft |
| CVE-2022-22583 | 2022 | PackageKit → writes to SIP-protected paths via crafted installer package | Ron Hass (Perception Point), Mickey Jin (Trend Micro) |
| CVE-2022-26712 | 2022 | PackageKit `SystemShoveService.xpc` holds `com.apple.rootless.install` and accepts file-shove requests from any caller → file moves past SIP. PoC fit in a single tweet. | Mickey Jin |
| CVE-2023-32369 "Migraine" | 2023 | `systemmigrationd` same `heritable` entitlement pattern as CVE-2021-30892; requires root | Microsoft |
| CVE-2024-44243 | 2024 | `storagekitd` (`heritable` entitlement) launches a root-planted file-system bundle from `/Library/Filesystems`; enables loading third-party kernel extensions | Microsoft |

**Core bypass pattern:** Apple-signed daemons with `com.apple.rootless.install.heritable` spawn child processes
(interpreters, shell scripts) that inherit the SIP bypass privilege. Finding such daemons and triggering them
via attacker-controlled input is the dominant modern SIP bypass methodology.

---

### TCC (Transparency, Consent, and Control)

Gate access to privacy-sensitive resources: camera, microphone, screen recording, full disk access, contacts,
calendar, photos, location, accessibility (synthetic UI control), input monitoring.

**Database locations:**
- User-level: `~/Library/Application Support/com.apple.TCC/TCC.db` (SQLite)
- System-level: `/Library/Application Support/com.apple.TCC/TCC.db` (SIP-protected, root-writable)
- Managed by `tccd` daemon.

**Key service identifier strings (kTCCService\*):**
- `kTCCServiceCamera` / `kTCCServiceMicrophone` — hardware access
- `kTCCServiceScreenCapture` — screen recording
- `kTCCServiceSystemPolicyAllFiles` — Full Disk Access (FDA); bypasses most filesystem restrictions
- `kTCCServiceAccessibility` — synthetic click injection; UI automation
- `kTCCServiceListenEvent` — input monitoring (keylogger channel)
- `kTCCServiceAddressBook` / `kTCCServiceCalendar` / `kTCCServicePhotos` / `kTCCServiceLocation`

**Dangerous entitlements:**
- `com.apple.private.tcc.allow` — Apple-internal; grants TCC permissions without user prompt.
  Used by: Terminal, Finder, Spotlight Importer host. Any app inheriting context from these inherits their grants.

**TCC bypass technique taxonomy:**

| Technique | Mechanism | Representative CVE(s) |
|-----------|-----------|----------------------|
| Direct database injection | Write to TCC.db via sqlite3. Requires SIP bypass (user DB) or root (system DB). Pre-SIP was trivial. | Pre-2015 |
| Dylib injection into TCC-entitled app | Inject malicious dylib into app with TCC grants → inherit grants in same process context. | Telegram abuse case (2020) |
| AppleScript injection into entitled app | AppleScript executed within context of app with TCC grants (e.g., Finder) → inherits grants. | Multiple |
| NFSHomeDirectory manipulation | Change user home dir via `dscl` → `tccd` reads TCC.db from attacker-controlled path. | CVE-2020-27937, CVE-2021-30970 |
| Mount over TCC directory | Mount crafted volume over `~/Library/Application Support/com.apple.TCC/` → replace TCC.db. | CVE-2021-1784 |
| AppTranslocation abuse | Confuse `tccd` about app bundle identity via translocation path. | CVE-2021-30782 |
| APFS snapshot mounting | Mount snapshot over TCC-protected path to expose older, attacker-modified TCC.db. | CVE-2020-9771 |
| Synthetic click injection | Use pre-existing `kTCCServiceAccessibility` grant to click "Allow" on TCC dialogs via CGEventPost. | Wardle DC26 2018 |
| Parent process TCC inheritance | Fork from TCC-permitted process; child inherits parent's access context. | — |
| PPPC profile abuse | Malicious `.mobileconfig` MDM profile silently grants TCC permissions to attacker-controlled apps. | Requires initial admin access |

**PPPC at scale:** Enterprise MDM (`com.apple.TCC.configuration-profile-policy` payload) can pre-approve TCC
permissions across all managed Macs. Requires User Approved MDM or DEP/ABM enrollment. Attack surface: a
social-engineered admin installing a malicious `.mobileconfig` grants arbitrary TCC permissions silently.

---

### XProtect and XProtect Remediator

**XProtect:** YARA-based signature database. Location:
`/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Resources/XProtect.yara`.
Checked by Gatekeeper on first launch of quarantined files; also scanned by `XProtect.app` on file open.
Silent background updates; historically checked daily.

**XProtect Remediator (XPR, macOS 12.3+, March 2022):**
- Replaced MRT (Malware Removal Tool, last updated April 2022).
- Autonomous background scanner; runs ~every 6 hours during low-activity periods.
- Modular plugin architecture: separate `.bundle` per malware family, at
  `/Library/Apple/System/Library/CoreServices/XProtect.app/Contents/MacOS/`.
- Autonomous remediation (quarantine/removal) without user interaction.
- Update cadence: ~every 2 weeks via silent system update; can be pushed rapidly for zero-days.
- **Limitation:** Signature-based; new malware families routinely fly under XProtect for months.

**XProtect Behavior Service (macOS 13 Ventura+):** Third XProtect component (alongside the YARA-based
scanner and Remediator). Behavior-based; observes process activity for known-malicious patterns.
(macOS 13 Ventura introduced the ESF surfacing of XProtect Remediator events.)

**Sequoia 15.2 delivery overhaul (December 2024):** Apple discontinued `softwareupdated`-based
XProtect delivery in favor of an undocumented iCloud-direct service that activates approximately
daily. The XProtect bundle moved from
`/Library/Apple/System/Library/CoreServices/` to `/private/var/protected/xprotect`. A new
`xprotect` CLI tool (`sudo xprotect update --prerelease`) provides limited manual control. Third-party
update-helper utilities (SilentKnight) can no longer push XProtect updates on Sequoia 15.2+. Source:
[Eclectic Light Company — XProtect has changed again in macOS Sequoia 15.2](https://eclecticlight.co/2024/12/19/xprotect-has-changed-again-in-macos-sequoia-15-2/).

**Sequoia Gatekeeper hardening:**

- `spctl --master-disable` removed. Gatekeeper can no longer be disabled at the CLI; the
  longstanding malware-installer technique of `spctl` disable is dead.
- Finder right-click "Open" Gatekeeper override removed. The historical adware delivery technique
  ("right-click, choose Open" social engineering) is dead.
- Unverified app first-run requires explicit Privacy & Security pane visit.
- ESF surfaces the Gatekeeper user-override event for centralized telemetry. Source:
  [SentinelOne — macOS Sequoia: What's New in Privacy and Security](https://www.sentinelone.com/blog/macos-sequoia-whats-new-in-privacy-and-security-for-enterprise/).

Cross-link: `detection_engineering_expertise.md` for Mac-specific Sigma rules covering XProtect
Remediator events, Behavior Service detections, and Gatekeeper-override telemetry.

---

### AMFI (Apple Mobile File Integrity)

Kernel-level enforcement of code signature validation for all executables.

**Components:**
- `AppleMobileFileIntegrity.kext` — kernel extension (MAC framework hooks in XNU)
- `amfid` — user-space daemon at `/usr/libexec/amfid`; communicates with kernel over Mach port
  `HOST_AMFID_PORT` (special port 18); handles trust cache lookups and OCSP checks.

**Flow:** AMFI.kext intercepts Mach-O loading via `vnode_check_signature`; hashes executable pages
against embedded LC_CODE_SIGNATURE blob. Mismatch → task terminated. Policy decisions deferred to `amfid`.

**Key codesign flags:**
- `CS_ENFORCEMENT` — code signing enforced
- `CS_REQUIRE_LV` — Library Validation: only Apple-signed or same-team-ID dylibs may load
- `CS_HARD` — don't load invalid pages
- `CS_KILL` — process killed on any signature violation

---

### Endpoint Security Framework (ESF)

Introduced macOS 10.15 Catalina (2019). Replaced OpenBSM/kauth kext-based monitoring.
Pure user-space API consumed by security tools via System Extension.

**Required entitlement:** `com.apple.developer.endpoint-security.client` (restricted; must be requested from Apple).

**Event model:**

| Class | Description | Usage |
|-------|-------------|-------|
| AUTH | Kernel suspends operation; client must respond allow/deny before deadline. Can block. | `ES_EVENT_TYPE_AUTH_EXEC`, `ES_EVENT_TYPE_AUTH_OPEN` |
| NOTIFY | Informational; no response required. Cannot block. | `ES_EVENT_TYPE_NOTIFY_EXEC`, `ES_EVENT_TYPE_NOTIFY_CREATE` |

**Key event types (partial, ~100+ total):**
- `ES_EVENT_TYPE_AUTH_EXEC` — intercept/block process execution (EDRs use this to block malware)
- `ES_EVENT_TYPE_NOTIFY_EXEC` — observe all process launches: PID, path, args, UID, signing info, PPID
- `ES_EVENT_TYPE_NOTIFY_CREATE` / `NOTIFY_WRITE` / `NOTIFY_RENAME` / `NOTIFY_UNLINK` — filesystem events
- `ES_EVENT_TYPE_NOTIFY_MOUNT` — volume mounts (relevant to TCC bypass monitoring)
- `ES_EVENT_TYPE_NOTIFY_MPROTECT` — memory protection changes
- `ES_EVENT_TYPE_NOTIFY_SIGNAL` — signals sent to processes

**Objective-See uses ESF for:** BlockBlock (persistence file events), ProcessMonitor (NOTIFY_EXEC),
FileMonitor (CREATE/WRITE/RENAME). LuLu uses Network Extension (separate framework).
Commercial EDRs (SentinelOne, CrowdStrike, Jamf Protect) consume ESF for all process/file telemetry.

**ESF maturation (2024–2026):** The "kext is dead" framing is now operationally complete.

- Apple's
  [Deprecated Kernel Extensions and System Extension Alternatives](https://developer.apple.com/support/kernel-extensions/)
  page lists every IO family with its DriverKit replacement: IOAudioFamily → AudioDriverKit (deprecated
  in Monterey 12.3), IOUSBFamily → USBDriverKit, IONetworkingFamily → NetworkingDriverKit, IOHIDFamily →
  HIDDriverKit, IOSCSIParallelFamily → SCSIControllerDriverKit, IOPCIFamily → PCIDriverKit.
- Third-party KEXTs on Apple Silicon require Reduced Security mode + user reboot + per-KEXT approval.
  In practice no enterprise EDR ships KEXTs in 2025; EDR vendors who held out (e.g., legacy
  CrowdStrike Falcon prior to 6.31) migrated to ESF System Extensions.
- ESF event coverage now includes Gatekeeper-bypass observability: starting macOS 15 Sequoia,
  `ES_EVENT_TYPE_NOTIFY_GATEKEEPER_USER_OVERRIDE` fires when a user opens an unverified app via System
  Settings > Privacy & Security (the new mandatory bypass path). EDRs can centrally log every user
  Gatekeeper override. Source:
  [SentinelOne — macOS Sequoia: What's New in Privacy and Security](https://www.sentinelone.com/blog/macos-sequoia-whats-new-in-privacy-and-security-for-enterprise/).
- XProtect Remediator detections now surface as ESF events (since macOS 13 Ventura), letting EDRs
  attribute Apple's autonomous remediation actions in the same telemetry stream as third-party
  defenses.

**Notable post-2023 ESF research (Wardle DC33 / "Mastering Apple's Endpoint Security for Advanced
macOS Malware Detection"):** ESF's `NOTIFY_AUTHENTICATION`, `NOTIFY_BTM_LAUNCH_ITEM_ADD`, and
`NOTIFY_OD_*` (Open Directory) events extend behavioral detection into the persistence-install and
account-modification paths that previously required kext-level hooks or polling. The full event
taxonomy now exceeds 130 event types and is the highest-fidelity user-mode behavioral signal
available on any operating system.

---

### Background Task Management (BTM) — macOS 13 Ventura+

Apple's user-facing alert system for new background item installations. Shows new LaunchAgents, LoginItems,
and SMAppService-registered items in System Settings > General > Login Items & Extensions.

**Components:** `BTMDaemon`, `BackgroundTaskManagementAgent`, `sfltool` CLI, `SMAppService` API.

**Wardle's 2023 research (DEF CON 31):** Found BTM initial implementation "done so poorly that any malware
that's somewhat sophisticated can trivially bypass the monitoring":
1. **Race condition/sleep abuse:** SIGSTOP the relevant process during the BTM notification window — no root required.
2. **Kernel communication bug:** Exploit BTMDaemon kernel communication flaw; persist without notification — no root required.
3. **Root-level bypass:** Additional technique requiring root; still bypasses BTM alerting.

**Impact:** New LaunchAgent plist drops can avoid triggering user-visible BTM notifications on macOS 13,
undermining Apple's primary persistence detection improvement.

---

### Apple Silicon Security Architecture

**Secure Enclave (SEP):**
- Isolated security subsystem present on all Apple SoCs (A7+, M1+).
- Operations never leave SEP: biometric template processing (Touch ID, Face ID), key generation/storage,
  AES/ECC cryptographic operations.
- Device UID: AES-256 key fused into chip at manufacture, inaccessible to Application Processor, used to
  derive per-device keys.
- sepOS: its own operating system with private Boot ROM and encrypted memory.

**Boot chain (Apple Silicon):**
1. Boot ROM (immutable, chip-burned) → verifies LLB
2. LLB (Low Level Bootloader, from NAND) → verifies iBoot, loads **LocalPolicy** (SEP-signed)
3. iBoot → verifies XNU kernel + kernel collections
4. Kernel → Kernel Integrity Protection (KIP) activates

**LocalPolicy:** Image4-format file signed by the device's own SEP (not Apple). Per-machine; contains
OS hash, security level, anti-replay nonce hash. Changes require authentication in recoveryOS (admin password).

Security levels:
- **Full Security:** Only most-recently-known-legitimate macOS version can boot.
- **Reduced Security:** Allows older macOS and third-party KEXTs with user approval.
- **Permissive Security:** No signature enforcement.

**Pointer Authentication Codes (PAC) — ARMv8.3-A:**
- Five 128-bit signing keys (APIAKEY, APIBKEY, APDAKEY, APDBKEY, APGAKEY).
- `PACIA`/`PACIB` embed cryptographic signature in unused top bits of 64-bit code pointers.
- `AUTIA`/`AUTIB` verify signature before use; invalid pointer → fault on dereference.
- Signing context includes pointer address + context value (e.g., stack pointer) — prevents relocation.
- **PACMAN attack (MIT, 2022):** Speculative execution side-channel on M1 — guessing valid PAC values via
  timing without triggering auth fault. Reduces PAC from hard cryptographic barrier to time-bounded guessing.
  Mitigated in subsequent Apple SoC revisions.
- **Purpose:** Mitigates ROP/JOP attacks that overwrite return addresses or function pointers.

**Kernel Integrity Protection (KIP):**
- Hardware memory controller configured during boot to deny writes to kernel text + read-only data regions.
- Hardware-level enforcement — not bypassable via kernel exploits modifying page tables.

**Impact on attackers:**

| Attack Class | Intel Mac | Apple Silicon M-series |
|---|---|---|
| Kernel shellcode injection | Feasible | Near-impossible (hardware KIP) |
| Kernel ROP/JOP | Common | Much harder (PAC) |
| Kernel data-only attacks | Possible | Primary remaining kernel vector |
| User-space exploitation | Common | Still effective (weaker PAC in user space) |
| KEXT-based rootkits | Feasible older macOS | Prevented in Full Security mode |

**Net assessment:** On Apple Silicon in Full Security mode, kernel exploitation is among the hardest in the
industry. Post-exploit tradecraft has shifted to user-space: privilege escalation via LaunchServices bugs,
TCC bypasses, SIP bypasses via entitlement-inheriting daemons, and social engineering. Nation-state actors
exploit user-space chains (MacMa, DazzleSpy: WebKit + XNU LPE) rather than standalone kernel exploits.

---

### Apple Silicon Microarchitectural Side-Channels (2022–2025)

Cross-link: `hardware_side_channels_expertise.md` (DMP, LAP, LVP, transient-execution taxonomy).

Apple Silicon's aggressive predictive hardware (data-memory-dependent prefetcher, load address predictor,
load value predictor) has produced a sustained series of side-channel disclosures from the Genkin–Yarom
collaboration and the MIT CSAIL CAP group. Each is unpatchable in microcode; mitigations are
software-level (constant-time hardening, DIT bit, browser SOP changes, Lockdown Mode toggles).

**PACMAN (Ravichandran, Na, Lang, Yan — MIT CSAIL, ISCA 2022):**
- Speculative-execution side-channel that distinguishes valid from invalid PAC values without triggering
  an authentication fault. Reduces PAC's 16-bit signature space from cryptographic to time-bounded
  brute-force per gadget.
- Confirmed on Apple M1; ARM subsequently confirmed nine PA-enabled cores share the underlying
  weakness. Source: [pacmanattack.com](https://pacmanattack.com/),
  [MIT CSAIL paper PDF](https://cap.csail.mit.edu/sites/default/files/research-pdfs/PACMAN-%20Attacking%20ARM%20Pointer%20Authentication%20with%20Speculative%20Execution.pdf).
- Mitigation directions explored in follow-ons: invisible-speculation (InvisiSpec, SafeSpec, Delay-on-Miss)
  and information-flow tracking (STT, NDA, Dolma). None are deployed in production silicon yet.

**GoFetch (Chen et al. — UIUC + UT Austin + GT + UCB + UW + CMU, USENIX Security 2024):**
- Authors: Boru Chen (UIUC), Yingchen Wang (UT Austin), Pradyumna Shome (Georgia Tech), Christopher W.
  Fletcher (UC Berkeley), David Kohlbrenner (Washington), Riccardo Paccagnella (CMU), Daniel Genkin
  (Georgia Tech). Source: [gofetch.fail](https://gofetch.fail/).
- Exploits the data-memory-dependent prefetcher (DMP) on Apple M-series. DMP speculatively dereferences
  values in cache that "look like" pointers — including cryptographic key material — leaking activation
  through cache-timing side-channel. Violates the constant-time programming contract at the
  microarchitectural level.
- Demonstrated end-to-end key extraction against OpenSSL Diffie-Hellman, Go RSA, CRYSTALS-Kyber, and
  CRYSTALS-Dilithium implementations on M1. M2/M3 share the vulnerable DMP behavior. Disclosed to Apple
  December 2023; public 21 March 2024.
- **Mitigation:** On M3, set the DIT bit (`PSTATE.DIT`) per-thread to force data-independent timing and
  disable DMP for that execution context. On M1/M2 the relevant control bit is `SYS_APL_HID11_EL1[30]`
  but macOS does not expose it; full mitigation requires
  algorithmic blinding/masking by the crypto library.

**iLeakage (Kim, van Schaik, Genkin, Yarom — ACM CCS 2023):**
- First Spectre-class transient-execution attack against Apple Silicon's Safari WebKit. A malicious
  webpage in one renderer reads cross-origin secrets from another renderer via a cache-timing gadget
  that does not require a high-resolution timer (uses race-condition primitives compatible with
  `performance.now()` clamping).
- Demonstrated Gmail inbox recovery and extraction of LastPass-autofilled credentials in Safari.
  Affects all A-series and M-series from 2020 onward. Source: [ileakage.com](https://ileakage.com/).
- **Mitigation:** Fixed in Safari 17.2 (iOS 17.2 / macOS 14.2). Lockdown Mode disables JIT in WebKit, eliminating the speculative gadget surface.

**SLAP (Kim, Genkin, Yarom — IEEE S&P 2025):**
- Exploits the Load Address Predictor (LAP) on Apple M2/A15+. LAP speculatively prefetches based on
  predicted next-load address; on misprediction the CPU performs computation on out-of-bounds data under
  speculative execution before squashing. Attacker recovers leaked computation via cache side-channel.
- Demonstrated recovery of email content and browsing behavior in Safari. Disclosed
  to Apple 24 May 2024; public January 2025. Source: [predictors.fail](https://predictors.fail/).

**FLOP (Kim, Chuang, Genkin, Yarom — USENIX Security 2025):**
- Exploits the Load Value Predictor (LVP) introduced on Apple M3/A17+. LVP guesses the data value a
  load will return before the cache responds; on misprediction the CPU performs arbitrary computation
  on incorrect values under speculative execution.
- Demonstrated recovery of location history, calendar events, and credit card data from cross-origin
  browser state. Disclosed 3 September 2024.

**Operation Triangulation hardware bypass (Kaspersky GReAT, 27 December 2023):**
- The four-CVE chain (CVE-2023-32434 XNU integer overflow, CVE-2023-38606 GPU MMIO bypass,
  CVE-2023-32435 Safari RCE, CVE-2023-41990 undocumented ADJUST TrueType instruction) used
  *undocumented* MMIO registers at physical addresses `0x206040000`, `0x206140008`, `0x206150020` on
  Apple A12–A16 to bypass Page Protection Layer (PPL) — the hardware mitigation Apple introduced to
  prevent kernel-write-after-LPE on iOS.
- The bypass writes attacker-controlled `(data, address, hash)` triples to GPU coprocessor registers;
  a custom Hamming-code hash was the only "authentication." Source: [Securelist last hardware mystery
  writeup](https://securelist.com/operation-triangulation-the-last-hardware-mystery/111669/).
- **Implication:** PPL was the load-bearing iOS kernel-integrity primitive 2020–2022. A hardware
  bypass through undocumented SoC features demonstrates that even hardware-enforced memory protection
  is only as strong as the auditability of the silicon. The "how did they find this?" question — whether
  via reverse engineering, leaked internal documentation, or a possible supply-chain channel — remains
  open. Apple has since replaced PPL with SPTM (Secure Page Table Monitor) on A15-or-later and
  M2-or-later SoCs.

**Net assessment:** Apple Silicon's microarchitectural attack surface is now the most-researched in any
production silicon family outside Intel. Five distinct disclosure-coordinated papers in three years
(PACMAN 2022, iLeakage 2023, GoFetch 2024, SLAP+FLOP 2025) from overlapping author groups indicates
sustained academic focus. None are remotely-triggerable without a JavaScript or local-code vector;
they raise the cost ceiling but do not invalidate Apple Silicon's overall security posture. The strongest
practical defense for high-risk users remains Lockdown Mode (disables WebKit JIT, removing the
speculative-execution gadget surface in browsers).

---

### Apple Private Cloud Compute (PCC, 2024–2025)

Cross-link: `confidential_computing_expertise.md` §7 (verifiable transparency, attestation).

Announced 10 June 2024 at WWDC. PCC is Apple's server-side AI inference platform for Apple Intelligence
requests too large to run on-device. Architecturally novel: the security claim is *verifiable transparency*
rather than just confidential computing.

**Security model claims (Apple Security Research blog, 10 June 2024 + 24 October 2024):**

1. **Stateless processing.** No request data, derived state, or logs are retained beyond the inference
   call. Memory is encrypted with per-boot ephemeral keys; nothing persists.
2. **Enforceable guarantees via attestation.** Each PCC node attests its software stack to client devices
   before the request is sent. Clients refuse to send data to a node whose attestation doesn't match a
   transparency-logged build.
3. **No privileged runtime access.** Apple's operators cannot read user data — the operational tooling
   path is designed to be incapable of producing decrypted user-data access.
4. **Non-targetability.** A device cannot be steered to a specific compromised node; node selection is
   randomized within the attested fleet.
5. **Verifiable transparency.** Every production PCC software build is published to a transparency log
   (Merkle-tree-anchored); the bundle of binaries that run in production is the *same* bundle researchers
   can download, run in a Virtual Research Environment, and audit.

**Researcher resources (24 October 2024 expansion):**

- **PCC Virtual Research Environment (VRE):** Runs PCC node software in a macOS Sequoia 15.1 virtualized
  environment on a Mac with Apple Silicon + 16 GB+ unified memory. Researchers can inspect releases,
  download binaries, verify transparency-log consistency, and execute inference locally.
- **Source code:** Limited-use license at [github.com/apple/security-pcc](https://github.com/apple/security-pcc).
  Components published include `CloudAttestation` (node attestation construction/validation), `Thimble`
  (device-side transparency enforcement), `splunkloggingd` (logging filter preventing accidental
  disclosure), and `srd_tools` (VRE tooling).
- **Bounty program:** Maximum reward $1,000,000 for arbitrary code execution compromising request data;
  $250,000 for access to request data outside the trust boundary; $150,000 for attack on request data from a
  privileged network position; $100,000 for unattested code execution; $50,000 for accidental data disclosure
  from a deployment or configuration issue. Source:
  [security.apple.com/blog/pcc-security-research](https://security.apple.com/blog/pcc-security-research/).

**Independent analysis:**

- **Trail of Bits (14 June 2024, "PCC: Bold step forward, not without flaws"):** Praised the
  non-ML security architecture as exceptional but noted that ML workloads still require decryption
  inside the enclave because homomorphic encryption is not viable at LLM-scale latency. Audit
  difficulty: the custom-everything stack (Apple-designed SoC, Apple-built hypervisor, Apple-published
  cryptography) requires deep silicon-and-firmware expertise outside most security firm bench depth.
  Source: [blog.trailofbits.com/2024/06/14/pcc-bold-step-forward-not-without-flaws/](https://blog.trailofbits.com/2024/06/14/pcc-bold-step-forward-not-without-flaws/).

**Assessment:** PCC sets a new high-water mark for *commodity-cloud confidential AI inference*. The
verifiable-transparency primitive is rare in production and stronger than the AWS Nitro / Azure
Confidential Computing baseline (which attest hardware but do not require client-side attestation-policy
enforcement before sending data). The MVP-vs-Mature gap is in ML-side defenses against prompt
injection, training-data extraction, and model-output side channels — independent of PCC's
infrastructure claims.

---

## III. Objective-See Tool Suite

### LuLu — Outbound Network Firewall

**Architecture:** System Extension (user-mode NEFilterDataProvider). Intercepts all outgoing TCP/UDP at
socket layer. For new connections: check rule DB → if no rule, suspend connection → alert user (process name,
PID, path, destination IP/hostname, port, codesigning status, VirusTotal) → user allows/blocks → rule persisted.

**Historical caveat:** macOS Big Sur introduced `ContentFilterExclusionList` — Apple-signed processes
(iCloud, App Store, Maps) bypassed all third-party network filters. Wardle documented and publicized this;
Apple removed the list in later releases.

**GitHub:** github.com/objective-see/LuLu

### BlockBlock — Persistence Monitor

**Architecture:** Two-process XPC design — privileged LaunchDaemon (root) + Login Item (user session UI).
Daemon consumes ESF to monitor persistence-related file creation/modification events. On detection: XPC
message to Login Item → user alert (process name, PID, path, code signing, VirusTotal, process ancestry tree).
User actions: Allow (permanent rule) / Block (removes the file) / Temporary allow.

**Locations monitored:** `~/Library/LaunchAgents/`, `/Library/LaunchAgents/`, `/Library/LaunchDaemons/`,
Login Items, Browser extensions (Safari/Chrome/Firefox), KEXTs, System Extensions, Cron jobs.

**GitHub:** github.com/objective-see/BlockBlock

### KnockKnock — Persistent Item Scanner

Point-in-time scanner (analogous to Autoruns on Windows). Enumerates all persistence locations; shows
code signing status, hash, VirusTotal lookup for each. Filters Apple-signed items by default.
Additional scanned locations: shell rc files (`~/.zshrc`, `~/.bash_profile`), Spotlight Importers.

**GitHub:** github.com/objective-see/KnockKnock

### OverSight — Camera/Microphone Monitor

Monitors CoreMediaIO/AVFoundation for video sessions; monitors coreaudiod via Mach messaging for mic
activation. **Key capability:** Detects piggybacking processes — if a second untrusted process joins an
already-active legitimate camera session (FaceTime is active; malware starts reading same stream), OverSight
identifies the secondary process. macOS's green LED indicates camera-in-use but does not enumerate *which*
processes are reading the stream. OverSight does.

### ReiKey — Keylogger Detector

Listens for Darwin notification `com.apple.coregraphics.eventTapAdded` (`kCGNotifyEventTapAdded`) broadcast
whenever a new CGEventTap is created. CGEventTap (`CGEventTapCreate`) is the dominant macOS keylogging
technique (used in EvilQuest, etc.). On notification: identifies the installing process and alerts.
Also provides on-demand scan of all currently installed event taps.

### ProcessMonitor / FileMonitor (ESF-based)

Both consume the Endpoint Security Framework (require `com.apple.developer.endpoint-security.client` + Full
Disk Access + System Extension approval). ProcessMonitor subscribes to `ES_EVENT_TYPE_NOTIFY_EXEC` (all
process launches: PID, PPID, UID, path, args, signing info). FileMonitor subscribes to CREATE/WRITE/RENAME/
UNLINK/OPEN events. Output: JSON stream. Primary use: dynamic malware analysis.

### RansomWhere? — Generic Ransomware Detector

Monitors file creation events. For newly created files: measure Shannon entropy of contents. If an **untrusted
process** (not Apple-signed, not in baseline whitelist) rapidly creates high-entropy files → alert + offer
termination. **Inherent limit:** 2–3 files may be encrypted before detection; does not detect ransomware
using trusted/signed binaries for encryption.

### DoubleYou (Commercial, 2024)

Co-founded by Patrick Wardle and Mikhail Sosonkin (ex-Apple offensive research). B2B "component catalog"
model — enterprise security vendors license individual detection modules rather than a full product. Modules
cover: untrusted/unnotarized process execution, anomalous DNS (C2 heuristics), persistence installation,
crypto mining behavior, ransomware (file entropy), webcam/microphone access. Commercial evolution of the
behavioral detection approach pioneered in Objective-See.

---

## IV. macOS Persistence Mechanisms — Complete Taxonomy

### Tier 1: Standard (Well-Monitored)

| Mechanism | Path | Privilege | Trigger |
|-----------|------|-----------|---------|
| LaunchAgents (user) | `~/Library/LaunchAgents/*.plist` | User | Login |
| LaunchAgents (system) | `/Library/LaunchAgents/*.plist` | Admin | Login (all users) |
| LaunchDaemons | `/Library/LaunchDaemons/*.plist` | Root | Boot |
| Login Items (legacy) | `SMLoginItemSetEnabled()` | User | Login |
| Login Items (modern) | `SMAppService.register()` | User | Login (BTM-monitored) |

### Tier 2: Code Injection / Dylib-Based

| Mechanism | Notes |
|-----------|-------|
| Dylib hijacking | Place `.dylib` at `@rpath`-resolved path or `LC_LOAD_WEAK_DYLIB` reference. Requires user-writable rpath or weak import. |
| Dylib proxying | Malicious dylib `dlopen()`s the original; presents expected behavior while executing malicious code. Used by APTs. |
| `DYLD_INSERT_LIBRARIES` | Environment variable; blocked by hardened runtime / `CS_REQUIRE_LV`. |
| `Info.plist LSEnvironment` | Add `DYLD_INSERT_LIBRARIES` key to app bundle's `LSEnvironment` plist dict → inject at every app launch. Effective on apps without Library Validation. |

### Tier 3: Scheduled

Cron jobs (`crontab -e`, `/var/at/cron/tabs/`), At jobs (`/var/at/jobs/`), Periodic scripts
(`/etc/periodic/{daily,weekly,monthly}/`). Rarely used by modern macOS malware; monitored by
KnockKnock and BlockBlock.

### Tier 4: Authentication Hooks

| Mechanism | Path | Notes |
|-----------|------|-------|
| AuthorizationPlugin | `/Library/Security/SecurityAgentPlugins/` + entry in `/etc/authorization` | Executes during login/authentication via SecurityAgent/securityd. Can steal cleartext credentials passed between plugins. |
| PAM modules | `/etc/pam.d/` + `/usr/lib/pam/` | PAM stack for authentication; attacker module = keylogger at auth time. |
| Login/Logout hooks (deprecated) | `com.apple.loginwindow.plist` keys `LoginHook`/`LogoutHook` | Deprecated macOS 10.9+; still functional on some versions. |

### Tier 5: Event-Based / Daemon

| Mechanism | Path | Notes |
|-----------|------|-------|
| Emond | `/etc/emond.d/rules/*.plist` | Deprecated but functional through macOS 12. Daemon `/sbin/emond` processes plist rules on system events (startup, auth). |
| XPC service | `Contents/XPCServices/` or `/Library/Application Support/<app>/` | Re-launched on-demand by launchd; survives parent app termination. |

### Tier 6: Browser / Application-Level

Safari extensions (`~/Library/Safari/Extensions/`), Chrome extensions
(`~/Library/Application Support/Google/Chrome/Default/Extensions/`),
Firefox extensions (`~/Library/Application Support/Firefox/Profiles/*/extensions/`),
Spotlight Importers (`/Library/Spotlight/`, `~/Library/Spotlight/`).

### Tier 7: Kernel / Low-Level (Increasingly Restricted)

KEXTs (`/Library/Extensions/`): deprecated macOS 10.15+; require user approval on Intel; blocked on Apple
Silicon without Reduced Security. System Extensions: managed by `systemextensionsd`; require MDM PPPC profile
or user approval; crashes don't kernel-panic.

### Tier 8: MDM / Configuration Profile

`.mobileconfig` profiles: can configure LaunchAgents, Login Items, TCC permissions, CA certificates, VPN.
MDM-provisioned LaunchDaemons pushed to supervised devices. Attack: social-engineer admin into installing
malicious profile → silently grant all TCC permissions to attacker-controlled app.

### Tier 9: Shell Configuration

`~/.zshrc`, `~/.bashrc`, `~/.bash_profile`, `~/.zprofile`, `~/.zshenv` (user).
`/etc/zshrc`, `/etc/zprofile` (system-wide, requires root). KnockKnock v2+ scans these.

---

## V. macOS Malware Landscape

### Threat Actor Breakdown

**Nation-state (China):** Daggerfly (MacMa/CDDS, 2021), WINDSHIFT (WindTail, 2018),
pro-China watering holes (DazzleSpy, 2022). Delivery: watering holes + WebKit 0-days, social engineering.

**Nation-state (DPRK / Lazarus Group):** AppleJeus (2018–ongoing), RustBucket (2023), KandyKorn (2023),
3CX supply chain (2023), Flutter-obfuscated malware (2024). Delivery: trojanized crypto apps, Discord/Telegram
social engineering, supply chain. Motive: cryptocurrency theft, espionage.

**Criminal / financially motivated:** Shlayer (adware dropper, 2018–2021), CookieMiner (crypto theft, 2019),
GMERA (crypto trader Trojans, 2019–2020).

**Individual / mystery:** FruitFly (2017, ~400 victims, Perl, biomedical + ordinary consumer targeting).

---

### Key Malware Families — Technical Reference

**OSX.WindTail (WINDSHIFT, 2018):**
- Delivery: spear-phishing → Safari auto-open ZIP → custom URL scheme trigger (`openurl2622007://`)
- Persistence: `LSSharedFileListInsertItemURL` Login Item
- C2: AES-encrypted PHP endpoints; hardcoded key `æ$&łŁńŚŽ~Ę?|!~<Œ`
- Wardle analysis: VB2019

**OSX.MacMa / CDDS (Daggerfly-linked, 2021):**
- Delivery: watering hole (Hong Kong pro-democracy sites) + CVE-2021-1789 (WebKit RCE, n-day) + CVE-2021-30869 (XNU kernel LPE 0-day, Pangu Lab)
- Persistence: `~/Library/LaunchAgents/com.UserAgent.va.plist`
- C2: custom protocol initialized over TLS
- Capabilities: 24+ commands including screen capture, audio recording, keylogging, file ops, terminal, shell

**OSX.DazzleSpy (2022):**
- Same exploit chain as MacMa (CVE-2021-1789 + CVE-2021-30869)
- Persistence: `~/Library/LaunchAgents/com.apple.softwareupdate.plist` (masquerades as system)
- Analysis: ESET

**Lazarus Group / AppleJeus (2018–ongoing):**
- Delivery: trojanized cryptocurrency trading apps (Celas Trade Pro, JMT Trading, Union Crypto, etc.)
- Persistence: LaunchDaemon (root) or LaunchAgent; malicious update mechanism
- C2: HTTP via `libcurl.4.dylib`; shared infrastructure fingerprint across samples

**RustBucket (BlueNoroff, 2023):**
- Three-stage: AppleScript dropper → Objective-C "functional PDF viewer" (only malicious on specific booby-trapped PDF hash match) → Rust RAT (system profiling, file ops, download/execute, anti-VM)
- Persistence: LaunchAgent plist

**KandyKorn (Lazarus, 2023):**
- Discord social engineering (crypto arbitrage bot lure) → Python ZIP → `Watcher.py` → testSpeed.py / FinderTools (from Google Drive) → SUGARLOADER → HLOADER (Discord.app hijack) → KANDYKORN (memory-resident RAT)
- Persistence: HLOADER replaces/hijacks Discord.app; executes at every Discord launch
- Attribution: Elastic (technique, network-infrastructure and code-signing-certificate overlaps with Lazarus)

**OSX.GMERA (2019–2020):**
- Delivery: trojanized Stockfolio/Kattana trading apps from fake websites
- Also: reverse shell, browser cookie theft, screenshots

**OSX.FruitFly (2017):**
- Wardle registered expiring C2 domains → sinkholed ~400 victims; turned data over to FBI
- Written in Perl (highly unusual); webcam access, screenshots, remote keyboard/mouse control
- Victims: biomedical institutions + ordinary US consumers (Ohio concentration)

**Silver Sparrow (2021):**
- Second known malware natively compiled for Apple Silicon, after GoSearch22 (arm64 universal binary)
- First use of macOS Installer JavaScript API for malicious persistence
- C2: AWS S3 buckets; final payload never delivered; ~30,000 infected Macs, 153 countries
- Co-discovered: Red Canary + Malwarebytes (Reed) + VMware Carbon Black

**OSX.Shlayer (2018–2021):**
- Most prevalent macOS malware 2019–2021 (1-in-10 Macs, Kaspersky)
- Delivery: malvertising (fake Flash update notices)
- 2020: First notarized malware — Apple inadvertently notarized Shlayer; ticket revoked reactively
- 2021: Exploited CVE-2021-30657 (Cedric Owens) as zero-day; Jamf Protect detected exploitation in wild January 9, 2021, before April 2021 patch

**CookieMiner (2019):**
- Browser cookie theft (Binance, Coinbase, Poloniex, etc.) + Chrome saved passwords + iTunes SMS backups
- 2FA bypass: stolen cookies + credentials + SMS codes = authenticated session on crypto exchanges
- Coinminer: XMRig variant mining Koto (Japanese privacy coin)
- Evasion: checks for Little Snitch; halts remote access agent if detected

---

### 2024–2025 Malware Corpus

Wardle's annual review ([objective-see.org/blog/blog_0x7D.html](https://objective-see.org/blog/blog_0x7D.html),
1 January 2025) groups 2024 first-seen families into three classes; infostealers dominated. SentinelOne's
[2024 macOS Malware Review](https://www.sentinelone.com/blog/2024-macos-malware-review-infostealers-backdoors-and-apt-campaigns-targeting-the-enterprise/)
extends the corpus and adds attribution. Cross-corpus, 2024 saw the
[101% quarter-over-quarter increase in macOS infostealers](https://unit42.paloaltonetworks.com/macos-stealers-growing/)
reported by Palo Alto Unit 42.

**Infostealers (the dominant 2024 category):**

| Family | First documented | Key traits | Source |
|---|---|---|---|
| AMOS / Atomic Stealer | mid-2023; mature 2024 | Malvertising via Google Ads + counterfeit Photoshop/Office/Tor; AppleScript password dialog → Keychain dump via Chainbreaker; XOR-obfuscated payload (key `0x91`); Telegram-marketed MaaS at ~$1k/month. Late-2024 variant added persistent backdoor. | [SpyCloud reverse-engineering writeup](https://spycloud.com/blog/reverse-engineering-atomic-macos-stealer/), [Picus dissection](https://www.picussecurity.com/resource/blog/atomic-stealer-amos-macos-threat-analysis) |
| Poseidon | 2024 | AMOS-derived (former AMOS developer "Rodrigo4") with crypto-wallet, Notes, and Bitwarden module additions | Wardle 2024 review |
| Cthulhu | 2024 | Go-based stealer; targets KeyChain, MetaMask, Wasabi wallets | Cado Security |
| Banshee | 2024 | Russian-marketed MaaS; bypassed XProtect for months via string-encryption mirroring Apple's own AV codebase | Check Point Research |
| Cuckoo | 2024 | Delivered via fake music-converter download sites; persistence via LaunchAgent + xattr quarantine strip | Kandji |
| CloudChat | 2024 | Trojanized chat client; credential harvest + clipboard theft | Wardle 2024 review |
| PyStealer | 2024 | Python-implemented; targets browser autofill + crypto extensions | Wardle 2024 review |

**Operational tactics common to the 2024 infostealer cohort:** AppleScript-driven fake password dialogs
mimicking native macOS prompts (the dominant *technique-to-get-keychain-password* path), Chainbreaker
or `security` CLI for keychain decryption post-password-capture, no persistence (one-shot exfil
exit-and-die — assumes re-infection is cheap), Telegram or Tor-hidden-service C2.

**DPRK macOS payload corpus (continuing Lazarus / BlueNoroff activity):**

| Family | Year | Attribution / Cluster | Notes |
|---|---|---|---|
| RustBucket | 2023 (continuing) | BlueNoroff | Three-stage; Objective-C trojan → Rust RAT; selective trigger on booby-trapped PDF SHA hash. ESET, Jamf, Elastic each tracked separate variants. |
| KandyKorn | 2023 (continuing) | Lazarus | Discord-arbitrage-bot lure → SUGARLOADER → HLOADER → KANDYKORN memory-resident RAT. Elastic. |
| ObjCShellz | Q4 2023 / 2024 | BlueNoroff | Lightweight Objective-C reverse-shell payload. Jamf Threat Labs. |
| BeaverTail | 2023; Qt rewrite mid-2024 | DPRK (Contagious Interview cluster, separate from BlueNoroff) | LinkedIn-recruiter social engineering targeting developers; trojanized interview-coding apps. 2024 Qt rewrite produces same source compiling to Windows + macOS. Drops InvisibleFerret Python backdoor; targets 13 crypto wallet extensions. [Unit 42 Contagious Interview](https://unit42.paloaltonetworks.com/north-korean-threat-actors-lure-tech-job-seekers-as-fake-recruiters/), [The Hacker News update July 2024](https://thehackernews.com/2024/07/north-korean-hackers-update-beavertail.html) |
| SpectralBlur | Jan 2024 | DPRK (Greg Lesnewich / Proofpoint disclosure; Wardle analysis) | Cross-platform backdoor sharing code with KANDYKORN; shell, file transfer, configurable C2. |
| ToDoSwift | mid-2024 | BlueNoroff | Swift-language Bitcoin-themed PDF lure delivering second-stage payload. |
| Hidden Risk | Q4 2024 | BlueNoroff | Crypto-themed PDF lure; novel `zshenv` persistence (loaded by every interactive zsh, bypasses BTM since `zshenv` is not a monitored persistence location). SentinelOne. |
| RustyAttr | late 2024 | DPRK-suspected | Stores payload in extended attributes (`xattr`) of decoy files to evade signature scanners and casual binary inspection. |

**Chinese-attributed:**

| Family | Year | Notes |
|---|---|---|
| LightSpy macOS | 2024 | Modular surveillance RAT with APT41-adjacent attribution; ports the iOS LightSpy framework to macOS. Hooks WeChat, audio, keystrokes. Huntress + ThreatFabric. |
| HZ RAT macOS | 2024 | Long-running Windows family acquired a macOS variant in 2024; persistence + targeted exfiltration. Kaspersky. |

**Ransomware (still rare, but no longer absent):**

| Family | Year | Notes |
|---|---|---|
| NotLockBit | 2024 | First macOS ransomware family with native exfiltration *and* encryption (vs. earlier macOS "ransomware" that was either fake or wiper-class). Go-implemented; targets local files and Documents. Trend Micro. |

**Backdoor / loader:**

| Family | Year | Notes |
|---|---|---|
| Activator | 2024 | Distributed via cracked applications; LaunchAgent persistence; loads second-stage tooling. Kaspersky. |
| Zuru | 2024 | LaunchAgent-persistent backdoor delivered via trojanized developer tools (iTerm2 lookalikes, etc.). 2024 variant reported by Jamf Threat Labs. |
| Fake Cloudflare Authenticator | 2024 | Tauri-framework malware deploying VShell agent. Kandji. |

**Trend takeaways:**

1. **Infostealer-as-a-service has reached macOS at scale.** Telegram-channel sales of AMOS, Poseidon,
   Cthulhu, and Banshee turn macOS infostealer attacks from a Lazarus-specialist activity into a
   commodity criminal market. The threat-actor diversity has broadened correspondingly.
2. **The AppleScript-password-dialog technique is the single most-shared 2024 building block.** Any
   2024 detection-engineering posture should baseline-detect `osascript` invocations originating from
   unsigned/non-Apple-team-ID binaries (highest-value ESF heuristic of the year).
3. **DPRK's `zshenv` persistence (Hidden Risk) is the first major BTM bypass since Wardle's DC31
   research.** BTM does not monitor zsh dotfiles; KnockKnock v2 catalogues them but is point-in-time.
   Real-time defenders should add `~/.zshenv`, `~/.zprofile`, `/etc/zshenv` to ESF file-monitor lists.
4. **DPRK groups have completely embraced Rust + Swift.** RustBucket and ToDoSwift
   evidence sustained tooling investment; analysis difficulty has measurably increased (no
   Objective-C symbols, no `objc_msgSend` call graph anchors).

---

## VI. CVE Reference Table

| CVE | Year | Discoverer | Description | Impact |
|-----|------|------------|-------------|--------|
| CVE-2015-1130 | 2015 | Emil Kvarnhammar (TrueSec) | RootPipe — Admin framework privesc in OS X | Root without password |
| CVE-2021-30657 | 2021 | Cedric Owens | Script-based app bundle with no Info.plist bypasses Gatekeeper | Full Gatekeeper bypass; exploited by Shlayer as 0-day |
| CVE-2021-30853 | 2021 | Gordon Long | Empty shebang line → macOS falls back to /bin/sh | Full Gatekeeper bypass |
| CVE-2017-7150 | 2017 | Wardle | Keychain access without master password prompt in High Sierra | Credential extraction |
| CVE-2022-28756 | 2022 | Wardle | Zoom auto-updater root privesc | Root via Zoom |
| CVE-2020-9771 | 2020 | Fitzl | TCC bypass via APFS snapshot mount | TCC bypass |
| CVE-2021-1784 | 2021 | Fitzl | TCC bypass via mount over com.apple.TCC directory | TCC bypass |
| CVE-2021-30782 | 2021 | Fitzl | TCC bypass via AppTranslocation | TCC bypass |
| CVE-2021-30892 "Shrootless" | 2021 | Microsoft | SIP bypass via system_installd inheritable entitlement | SIP bypass |
| CVE-2021-30970 "powerdir" | 2021 | Microsoft / Jonathan Bar Or | TCC bypass via NFSHomeDirectory manipulation | TCC bypass |
| CVE-2022-26712 | 2022 | Mickey Jin | SIP + TCC bypass via PackageKit SystemShoveService (no client check) | SIP + TCC bypass; PoC in one tweet |
| CVE-2023-32369 "Migraine" | 2023 | Microsoft | SIP bypass via systemmigrationd same entitlement pattern | SIP bypass |
| CVE-2021-1789 | 2021 | @S0rryMybad (360 Vulcan Team) | WebKit RCE | Exploited by MacMa/CDDS and DazzleSpy watering holes |
| CVE-2021-30869 | 2021 | Google TAG + Project Zero | XNU kernel LPE 0-day | Exploited in MacMa/CDDS and DazzleSpy chains |
| CVE-2023-32434 | 2023 | Kaspersky GReAT | XNU integer overflow in memory-mapping syscalls | Operation Triangulation chain element |
| CVE-2023-32435 | 2023 | Kaspersky GReAT | Safari arbitrary code execution | Operation Triangulation Safari-stage exploit |
| CVE-2023-38606 | 2023 | Kaspersky GReAT | Undocumented MMIO bypass of PPL via GPU coprocessor registers | Operation Triangulation PPL bypass — hardware-level |
| CVE-2023-41990 | 2023 | Kaspersky GReAT | Undocumented `ADJUST` TrueType font instruction RCE | Operation Triangulation font-handling primitive |
| CVE-2023-41991/41992/41993 | 2023 | Citizen Lab + Google TAG | Intellexa/Predator three-CVE iOS exploit chain | Active commercial mercenary spyware deployment |
| CVE-2024-44243 | 2024 | Microsoft | SIP bypass via kernel-extension loading mechanism | Continuation of inheritable-entitlement pattern |
| CVE-2025-31200 | 2025 | Apple | Sophisticated attack disclosure (CoreAudio) | Exploited in the wild — "extremely sophisticated attack against specific targeted individuals" |
| CVE-2025-31201 | 2025 | Apple | RPAC bypass companion to CVE-2025-31200 | Same in-the-wild attack chain |
| CVE-2025-43529 | 2025 | Google TAG | WebKit emergency-patch zero-day | Active exploitation |
| GoFetch | 2024 | Chen et al. (UIUC + UTA + GT + UCB + UW + CMU) | DMP side-channel key extraction | Microarchitectural; no CVE (architectural) |
| SLAP | 2024/2025 | Kim, Genkin, Yarom | Load Address Predictor speculative-execution leak | M2/A15+; no CVE |
| FLOP | 2024/2025 | Kim, Chuang, Genkin, Yarom | Load Value Predictor speculative-execution leak | M3/A17+; no CVE |

**Note on tracking:** Google Threat Intelligence Group's
[*Hello 0-Days, My Old Friend: A 2024 Zero-Day Exploitation Analysis*](https://cloud.google.com/blog/topics/threat-intelligence/2024-zero-day-trends)
tracked 75 in-the-wild zero-days across vendors in 2024. Apple's share is dominated by WebKit RCE +
XNU LPE pairs deployed against journalists, activists, and dissidents. Lockdown Mode (introduced
iOS 16, hardened in iOS 17 / 18) has — per Apple's own claim and corroborating Citizen Lab analysis —
not been successfully bypassed by mercenary spyware in any documented case since launch. The
[Apple-published Lockdown Mode security documentation](https://support.apple.com/guide/security/lockdown-mode-security-sec2437264f0/web)
catalogs the disabled features: most message attachment types, link previews, JIT in WebKit
(critical against Spectre-class browser exploits), most accessory connections in iOS, FaceTime
incoming-call gating, configuration profile installation, shared albums.

---

### iOS Attack Surface (2024–2026)

Cross-link: `mobile_security_expertise.md` for full iOS coverage.

**Operation Triangulation legacy (Kaspersky GReAT, disclosed June 2023, hardware-bypass detail
published 27 December 2023):**

- The four-CVE chain (CVE-2023-32434 + CVE-2023-38606 + CVE-2023-32435 + CVE-2023-41990) is the most
  technically detailed iOS in-the-wild exploit publicly disclosed to date. Kaspersky obtained all stages
  because Kaspersky's own employees were targeted.
- The undocumented-MMIO PPL bypass (CVE-2023-38606) is the load-bearing primitive: it demonstrates
  that even hardware-enforced memory protection can be bypassed via SoC-coprocessor surfaces that
  Apple itself did not publicly document.
- Apple deprecated PPL in favor of SPTM (Secure Page Table Monitor) on A15 / M2+ silicon. SPTM is
  documented in the [Apple Platform Security Guide](https://support.apple.com/guide/security/welcome/web)
  as the successor mitigation.

**BLASTPASS (Citizen Lab + Apple, September 2023, continuing relevance):**

- CVE-2023-41064 (ImageIO) + CVE-2023-41061 (Wallet) — zero-click iMessage chain delivering NSO
  Pegasus. Patched in iOS 16.6.1.
- Architectural lesson: PassKit content rendering via ImageIO created an attack surface in the
  message-arrival path that bypassed BlastDoor sandboxing introduced for prior NSO chains
  (FORCEDENTRY / KISMET).
- Lockdown Mode's "block most message attachment types" disables exactly this primitive.

**2024–2025 in-the-wild zero-day pattern:**

- Apple disclosed multiple "extremely sophisticated attack against specific targeted individuals"
  emergency patches in 2024 and 2025 (CVE-2025-31200, CVE-2025-31201,
  CVE-2025-43529 family). Reporter mix continues to be dominated by Citizen Lab and Google TAG; an
  increasing share is co-credited with Apple's own Security Engineering and Architecture team.
- Source: [Google Cloud Threat Intelligence — 2024 zero-day trends](https://cloud.google.com/blog/topics/threat-intelligence/2024-zero-day-trends).
- [Intellexa / Predator exploit chains](https://cloud.google.com/blog/topics/threat-intelligence/intellexa-zero-day-exploits-continue)
  continued through 2023–2024, demonstrating that the mercenary-spyware vendor ecosystem persists
  despite NSO sanctions and US Commerce Department Entity List additions.

**iOS 17 / iOS 18 hardening:**

- iOS 17 (2023): iMessage Contact Key Verification general availability (iOS 17.2). Extended Lockdown Mode to additional surfaces; new requirements for cross-app
  permission requests; tightened WebKit JIT exclusion in Lockdown Mode.
- iOS 18 (2024): Apple Intelligence introduced as on-device-first with PCC fall-through;
  expanded passkey adoption.
- iOS 17.3 Stolen Device Protection: requires Face ID/Touch ID for sensitive operations even when
  the passcode is known to the attacker, with a one-hour security delay for high-risk actions
  outside Familiar Locations. Direct hardening against the
  [Joanna Stern–reported pickpocket attack chain](https://www.wsj.com/articles/apple-iphone-security-theft-passcode-data-privacysafety-a4d99cbc).

---

## VII. Enterprise macOS Security (MDM, Jamf)

### MDM Protocol

Apple's MDM protocol communicates via HTTPS. APNs (Apple Push Notification service) used for server-to-device
push commands. Enrollment: DEP (Device Enrollment Program, now ABM — Apple Business Manager) or manual profile.

**MDM capabilities:** Install profiles (restrictions, certificates, VPN, PPPC, WiFi), install/remove apps
(PKG, App Store), lock/wipe/restart, query inventory, deploy LaunchDaemons via profile, enforce FileVault,
enforce password policies.

**DEP MitM attack (Jesse Endahl of Fleetsmith / Max Bélanger of Dropbox, Black Hat USA 2018):** During DEP enrollment, the Mac contacts Apple, then
the MDM server (URL not yet TLS-pinned at this point). Network attacker can intercept the MDM server URL and
serve a malicious MDM configuration. Mitigation: ABM enrollment with pre-assigned MDM profile and server pinning.

### Jamf Pro Attack Surface (Fitzl Research)

The `jamf` binary runs as a root LaunchDaemon and executes policies downloaded from the Jamf server. Research
identified: root-privilege script execution via Jamf Pro policies as an escalation vector; `jamf` binary
accepting commands executable as root.

### Malicious `.mobileconfig` Profiles

Can: install root CA certificates (TLS MitM), configure VPN (traffic interception), deploy LaunchAgents/Daemons,
grant TCC permissions to attacker apps, configure kiosk/restriction modes. Delivered via email, web, AirDrop.
macOS prompts "This profile is unverified" — social engineering overcomes this. Used in nation-state attacks
against journalists and activists (MDM-based iOS spyware, analogous patterns on macOS).

### MDM Ecosystem Attack Surface (2024–2026)

Cross-link: `cloud_iam_expertise.md` (Entra-as-MDM-source, federated enrollment, conditional access).

The macOS enterprise MDM market consolidated and matured in 2024–2026 around three vendors and one
federation pattern:

- **Jamf Pro / Jamf Now / Jamf Protect.** The reference enterprise stack. Largest installed base in
  Apple-heavy enterprises.
- **Kandji.** Cloud-first ABM-tier MDM. Their Threat Research team (Kandji-published research on
  Cuckoo stealer and others) is a credible defensive intelligence source
  in addition to MDM vendor.
- **Microsoft Intune (with Mac support).** Increasingly common in Microsoft 365-centric enterprises;
  uses Entra ID (formerly Azure AD) as user identity source.
- **Mosyle.** Education + SMB-tier Apple MDM; recent enterprise feature parity with Jamf.

**Federation pattern (Entra-as-MDM-source):** In Microsoft-aligned enterprises, the *MDM trust root
is Entra*, not Apple Business Manager. A device user authenticates via Entra → Entra Conditional
Access decides whether enrollment proceeds → ABM bridge passes the device-to-organization binding
to Apple → MDM provisioning flows. Compromise of an Entra Global Admin or a Privileged Authentication
Administrator therefore yields *MDM control of every federated Mac in the tenant*. This is the
modern equivalent of compromising the Jamf Pro admin account: same blast radius, achieved via a
different identity surface. See `cloud_iam_expertise.md` for the Entra side of this analysis.

**Apple Business Manager (ABM) — the post-DEP enrollment trust root:**

- ABM is the 2018 evolution of DEP. Device-to-organization binding is established at hardware-
  reseller channel; devices acquired through Apple's authorized resellers are pre-bound to the
  purchasing organization's ABM tenant.
- Historical DEP MitM concern (Endahl/Dropbox 2018, [Duo Security DEP serial-number weakness 2018](https://duo.com/blog/duo-labs-research-uncovers-apple-dep-authentication-weakness))
  was that Apple's DEP server only required a device serial number to confirm
  enrollment-eligibility, with no per-organization secret. The
  [Threatpost summary](https://threatpost.com/weakness-in-apple-mdm-tool-allows-access-to-sensitive-corporate-info/137737/)
  catalogs the brute-force-by-serial-number attack: predictable serials + small key space + no
  rate limiting = attacker enrolls rogue device into target's MDM and inherits the same
  privileged-endpoint treatment.
- ABM mitigations: MDM-side user-auth-before-enrollment enforcement (admin-configurable but not
  default), Account-Driven User Enrollment for BYOD separation, hardware-bound enrollment via
  device-attestation primitives Apple ships with iOS 16+ / macOS 14+. Most production deployments
  still do not require user-auth-before-enrollment, leaving the historical attack surface
  partially open.

**MDM-as-blast-radius:** Nation-state actors increasingly view
MDM servers as high-value targets because a compromised MDM yields silent, OS-level access to
hundreds-to-thousands of high-value devices.

---

## VIII. *The Art of Mac Malware* — Key Technical Principles

**Book:** Free at taomm.org. Patrick Wardle (No Starch Press, 2022).

### Volume 1: Analysis Methodology

**Static analysis:**
- Mach-O format: fat/universal binaries (multiple arch slices), load commands
  (`LC_SEGMENT_64`, `LC_LOAD_DYLIB`, `LC_CODE_SIGNATURE`, `LC_MAIN`, `LC_RPATH`).
- Codesign inspection: `codesign -dvvv`, `spctl --assess`, entitlement extraction.
- ARM64 assembly for M1 malware (Wardle "Arm'd and Dangerous", BH 2021).
- Tools: Hopper Disassembler, IDA Pro, Ghidra; dynamic instrumentation with LLDB, Frida.

**Dynamic analysis:**
- ProcessMonitor (ES NOTIFY_EXEC) for process tree; FileMonitor (ES file events) for persistence plist drops.
- Network monitoring with LuLu (outbound interception) and Wireshark.
- Isolated VMs (VMware Fusion, Parallels) — note: sophisticated malware performs
  anti-VM checks.

**Three core distinguishing ideas:**

1. **Social engineering >> drive-by.** macOS malware overwhelmingly requires user interaction (open DMG, run
   installer, approve dialog). Gatekeeper makes drive-by exploitation hard without a 0-day. This is why adware
   and PUI ecosystems (Shlayer, Genieo, Pirrit) dominate the Mac threat landscape — they operate within
   user-consent boundaries.

2. **Persistence = detection opportunity.** Every malware family must persist to survive reboots. Monitoring
   persistence locations (LaunchAgents, LoginItems) provides a near-universal detection opportunity regardless
   of the malware's other obfuscation techniques. This is why BlockBlock and KnockKnock are so effective.

3. **Dylib injection as pervasive post-exploitation.** Injecting into trusted processes — especially those with
   TCC grants (Finder, Terminal, Spotlight) — is the standard technique to inherit elevated privileges and evade
   detection. Monitoring for unsigned dylibs loaded into signed processes is a high-signal detection heuristic.

### Volume 2: Detection (ESF-Based)

Building ES clients: subscribing to events, AUTH vs NOTIFY model, responding within deadlines.
Behavioral heuristics: unsigned process execution, anomalous outbound connections, persistence plist creation,
camera/microphone access. Persistence Monitor chapter provides full code walkthrough of BlockBlock-style
ESF implementation.

---

## IX. What Distinguishes Staff-Level macOS Security Expertise

### Follow the Entitlement Chain

Staff-level analysis identifies which process *granted* a TCC permission, not just whether one exists.
`com.apple.private.tcc.allow` on a system process means any exploit of that process inherits all TCC grants.
`com.apple.rootless.install.inheritable` on a daemon means any child process inheriting the environment
bypasses SIP. The entitlement graph is the attack surface.

### Apple Silicon Changes the Kernel Exploitation Calculus

Every historical macOS kernel exploit technique (shellcode injection, KTRR bypass, KEXT-based rootkit) is
significantly harder or eliminated on Apple Silicon + Full Security. Staff-level practitioners know that
this shifts the threat model: the kernel is no longer the easiest path to persistence or privilege escalation.
User-space chains (WebKit → XNU LPE, TCC bypass, SIP-inheriting daemon abuse) are now the dominant
nation-state approach, confirmed by MacMa, DazzleSpy, and DPRK campaigns.

### Gatekeeper Gaps Are Well-Known and Repeatedly Exploited

The notarization check is not a guarantee. Shlayer was notarized. CVE-2021-30657 was exploited in the wild
for months before patch. Staff practitioners understand the boundary conditions: files downloaded via
non-quarantining tools (curl, scp, USB, AirDrop) bypass Gatekeeper entirely. Any security posture that
relies solely on Gatekeeper for code execution control is under-defended.

### The MDM Trust Hierarchy Is Often Weaker Than the TCC Trust Hierarchy

Enterprise Macs are frequently in a state where a PPPC profile has pre-approved broad TCC permissions
for management tools. A malicious MDM profile or a Jamf policy executing as root is more powerful than
any OS security boundary. Staff-level enterprise macOS security is as much about MDM configuration hygiene
as about OS-level mitigations.

### Behavioral Detection Beats Signatures at Scale

XProtect remains signature-based and consistently misses new malware families for months (Silver Sparrow,
KandyKorn, Flutter DPRK malware — all flew under XProtect initially). ESF-based behavioral detection
(monitor persistence locations, unsigned process execution, high-entropy file creation, unexpected outbound
connections) provides detection opportunities that are independent of signature databases. This is the
architectural insight behind the entire Objective-See suite and DoubleYou's commercial approach.

---

## X. Defense Principles

### Persistence-Centric Monitoring
Deploy KnockKnock for one-time baseline; run BlockBlock or equivalent EDR for real-time persistence alerts.
Every macOS malware family establishes persistence — this is the universal detection point.

### TCC Hygiene
Minimize processes with Full Disk Access (`kTCCServiceSystemPolicyAllFiles`). Audit TCC database regularly
(third-party tools). In enterprise: use PPPC profiles to grant only the minimum necessary;
never grant Accessibility (`kTCCServiceAccessibility`) broadly — it enables synthetic click injection.

### SIP Hardening
Keep SIP enabled (verify with `csrutil status`). Never boot in Reduced Security mode without specific need.
Monitor for SIP bypass indicators (unexpected file modifications in protected paths; Apple-signed daemon
spawning unexpected child processes).

### Network Monitoring
LuLu or equivalent: alert on first outbound connection from any new untrusted process. Most malware makes
an outbound call quickly after execution — this is the earliest behavioral detection opportunity in the
kill chain.

### Enterprise MDM
Require DEP/ABM enrollment for all corporate Macs (prevents DEP MitM). Review and minimize PPPC profile
grants quarterly. Audit Jamf Pro policies that execute as root. Block `.mobileconfig` installation from
untrusted sources via MDM restriction.

### Apple Silicon + Full Security
For high-risk environments (journalists, executives, security researchers): operate all Macs in Full Security
mode. Decline any request to enable Reduced Security or install third-party KEXTs. This eliminates the largest
class of kernel-level persistence techniques.

---

*Sources: Patrick Wardle / objective-see.org / taomm.org; Csaba Fitzl / theevilbit.github.io; Howard Oakley /
eclecticlight.co; Jaron Bradley / themittenmac.com; Thomas Reed / Malwarebytes; DEF CON media archives;
Black Hat USA proceedings; OBTS conference archive; Apple Platform Security Guide (2024);
MITRE ATT&CK macOS techniques; ESET, Elastic, Jamf Threat Labs, Unit42 malware analyses.*

*2024–2026 additions: GoFetch (Chen et al., USENIX Security 2024, [gofetch.fail](https://gofetch.fail/));
SLAP/FLOP (Kim et al., IEEE S&P 2025 + USENIX Security 2025, [predictors.fail](https://predictors.fail/));
iLeakage (Kim/van Schaik/Genkin/Yarom, [ileakage.com](https://ileakage.com/)); PACMAN (Ravichandran et al.,
MIT CSAIL, ISCA 2022, [pacmanattack.com](https://pacmanattack.com/)); Apple Private Cloud Compute
(Apple Security Research, [security.apple.com/blog](https://security.apple.com/blog/private-cloud-compute/);
Trail of Bits, [blog.trailofbits.com 2024-06-14](https://blog.trailofbits.com/2024/06/14/pcc-bold-step-forward-not-without-flaws/));
Operation Triangulation (Kaspersky GReAT,
[Securelist hardware mystery](https://securelist.com/operation-triangulation-the-last-hardware-mystery/111669/));
SentinelOne 2024 macOS Malware Review,
[blog](https://www.sentinelone.com/blog/2024-macos-malware-review-infostealers-backdoors-and-apt-campaigns-targeting-the-enterprise/);
Wardle's [Mac Malware of 2024](https://objective-see.org/blog/blog_0x7D.html); Google Threat Intelligence Group
[2024 zero-day trends](https://cloud.google.com/blog/topics/threat-intelligence/2024-zero-day-trends);
Unit 42 [Contagious Interview](https://unit42.paloaltonetworks.com/north-korean-threat-actors-lure-tech-job-seekers-as-fake-recruiters/);
Duo Labs [DEP authentication weakness](https://duo.com/blog/duo-labs-research-uncovers-apple-dep-authentication-weakness);
Apple developer-deprecated-KEXTs page; Eclectic Light Company XProtect Sequoia coverage.*
