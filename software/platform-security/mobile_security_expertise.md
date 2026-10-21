# Mobile Security — iOS and Android Pentest, Exploitation, and Defense

> Synthesized from the public research output of Bill Marczak (Citizen Lab),
> Ian Beer (Google Project Zero), Brandon Azad (formerly Project Zero),
> Adam Donenfeld (formerly Zimperium), "axi0mX" (checkm8),
> Tihmstar (jailbreak / ra1nsn0w), Ole André Vadla Ravnås (Frida / NowSecure),
> Tielei Wang (Pangu Team / MOSEC), Connor Tumbleson (apktool),
> Bernhard Mueller (OWASP MASVS / MASTG lead author),
> Daniel Komaromy (TASZK / Comsecuris baseband research), Bill Demirkapi,
> Patrick Wardle (Objective-See — cited for iOS adjacency),
> Boris Larin / Leonid Bezvershenko / Grigoriy Kucherin (Kaspersky GReAT —
> Operation Triangulation hardware-MMIO reverse engineering), Man Yue Mo
> (GitHub Security Lab — Mali GPU and MTE-era Pixel research), John
> Scott-Railton (Citizen Lab — Paragon Graphite + Pegasus civil-society
> forensics 2024–2025), and the Project Zero Year-In-Review iOS / Android
> 0-day-in-the-wild team.
> Covers Project Zero blog posts (2017–2025), Citizen Lab Pegasus / Predator
> / Triangulation / Paragon Graphite analyses (2016–2025), Amnesty Tech's
> Pegasus forensic methodology, Apple Platform Security Guide (current
> edition) plus the September 2025 Memory Integrity Enforcement and Private
> Cloud Compute architecture publications, Android Security Bulletin
> archive, Frida 17.x documentation, OWASP MASVS v2.1 + MASTG + MASWE
> (2024 reorganization), and the OffensiveCon / hardwear.io / Pwn2Own
> Mobile baseband corpus through Toronto 2024 + Cork 2025.

---

## I. Researcher Profiles

### Bill Marczak (Citizen Lab, University of Toronto)
Senior researcher at The Citizen Lab. Discovered, named, and reverse-
engineered multiple in-the-wild iOS chains used by Pegasus and competing
mercenary spyware — Trident (2016), KISMET (2020),
FORCEDENTRY (2021), BLASTPASS (2023), plus three iOS 15/16 zero-click
chains captured in 2022. Marczak and John Scott-Railton's joint forensic
work on journalists, dissidents, and HRDs is the canonical public source
on in-the-wild mobile chain anatomy. Reference:
[billmarczak.org](https://billmarczak.org/).

### Ian Beer (Google Project Zero)
The most prolific public source on iOS kernel exploitation 2017–2022.
Authored the December 2020 "An iOS zero-click radio proximity exploit
odyssey" — a 30,000-word writeup of a wormable AWDL buffer overflow
that yielded full OTA device compromise with no user interaction. Series
authority on JSC, IOSurface, mach_msg, and iOS ipc. Reference:
[Project Zero](https://projectzero.google/2020/12/an-ios-zero-click-radio-proximity.html).

### Brandon Azad (formerly Project Zero, now Apple)
P0 researcher 2018–2020. Authored oob_timestamp (CVE-2020-3837),
unauthd sandbox escapes, mach voucher / IOSurface primitives, and the
canonical "A survey of recent iOS kernel exploits" (June 2020). At
Apple since 2020. Reference: [github.com/bazad](https://github.com/bazad).

### Adam Donenfeld (formerly Zimperium)
Author of the public ziVA exploit (iOS ≤ 10.3.1, multi-bug chain in
AppleAVEDriver/IOSurface) — one of the first fully chained public iOS
kernel-from-userland exploits with PoC. Reference:
[github.com/doadam/ziVA](https://github.com/doadam/ziVA),
[Zimperium blog](https://zimperium.com/blog/ziva-video-audio-ios-kernel-exploit).

### axi0mX
Author of checkm8 (CVE-2019-8900) — the unfixable USB-DFU SecureROM
exploit for A5–A11 SoCs (iPhone 4S through iPhone X). On-die read-only
mask ROM means no firmware update can patch it; foundation of checkra1n
and most pre-A12 jailbreaks. Reference:
[Apple Wiki checkm8](https://theapplewiki.com/wiki/Checkm8_Exploit),
[CERT VU#941987](https://www.kb.cert.org/vuls/id/941987/).

### Tihmstar
Long-time iOS jailbreak researcher; author of futurerestore, ra1nsn0w,
jbinit, ipwndfu derivative tooling. Most A5–A11 public jailbreaks depend
on his infrastructure. Reference:
[github.com/tihmstar](https://github.com/tihmstar).

### Ole André Vadla Ravnås (NowSecure / Frida Project)
Creator and maintainer of Frida — canonical cross-platform dynamic
instrumentation. Security researcher at NowSecure. Frida is
load-bearing infrastructure for nearly every public mobile-pentest
methodology. Reference: [frida.re](https://frida.re),
[NowSecure Frida](https://www.nowsecure.com/frida/).

### Tielei Wang (Team Pangu)
Member of Pangu Team — the most successful long-running public iOS
jailbreak research group. Co-author of Pangu 9 (first untethered iOS 9
jailbreak) and a sustained corpus of iOS sandbox, IOKit, and XNU
port-type-confusion research. Frequent MOSEC presenter. Reference:
[en.pangu.io](https://en.pangu.io/).

### Connor Tumbleson (iBotPeaches / Source Toad)
Primary maintainer of apktool — canonical Android APK decompilation and
rebuild tool, foundation of patch-and-resign. Reference:
[github.com/iBotPeaches/Apktool](https://github.com/iBotPeaches/Apktool).

### Bernhard Mueller (OWASP MAS / Floating Pragma)
Lead author of OWASP MASVS and MASTG — the de-facto international
standard for mobile-app security controls, adopted by the App Defense
Alliance MASA program (badge shown in Google Play's Data safety section). Mueller primarily wrote the reverse-
engineering chapter. Pwnie Award (Best Research). Reference:
[mas.owasp.org](https://mas.owasp.org/).

### Daniel Komaromy (TASZK / formerly Comsecuris, Qualcomm)
Most prolific public cellular-baseband researcher. Won Mobile Pwn2Own
with a Samsung Shannon chain; co-authored "Breaking Band" (Recon 2016,
with Nico Golde) — canonical public RE of Shannon baseband.
Founder of TASZK Security Labs. Reference:
[comsecuris.com](https://comsecuris.com/),
["Breaking Band" Recon 2016](https://comsecuris.com/slides/recon2016-breaking_band.pdf).

### Bill Demirkapi
Independent researcher; OS-internals + RE work spanning Android,
Windows, embedded supply chain. Published findings on Dell SupportAssist
(LPE+RCE) and exposed-secret discovery via VirusTotal Retrohunt at scale. Reference:
[billdemirkapi.me](https://billdemirkapi.me/).

### Patrick Wardle (Objective-See / DoubleYou)
Cited for iOS adjacency; full profile in `macos_apple_security.md`.
Wardle frames Apple Lockdown Mode in public discourse and covers
iOS-adjacent topics (Endpoint Security, code signing, MDM) at Mac Admins
/ Objective by the Sea.

### Boris Larin / Leonid Bezvershenko / Grigoriy Kucherin (Kaspersky GReAT)
The Operation Triangulation reverse-engineering team. From 2023's initial
disclosure of the iMessage-delivered chain through the 37C3 2023
presentation "Operation Triangulation: What You Get When Attack iPhones
of Researchers," they progressively unraveled four CVE-2023 vulnerabilities
including the CVE-2023-38606 hardware-MMIO PPL bypass via undocumented
GPU coprocessor registers (a Hamming-coded write primitive on A12–A16).
The 37C3 talk is the canonical primary source for the hardware-feature
mystery. Reference:
[Securelist — The last hardware mystery](https://securelist.com/operation-triangulation-the-last-hardware-mystery/111669/),
[Kaspersky 37C3 talk index](https://www.kaspersky.com/blog/triangulation-37c3-talk/50166/).

### Man Yue Mo (GitHub Security Lab)
Most prolific recent public Mali GPU researcher; carried the corpus
forward into the MTE era. Authored "Gaining kernel code execution on
an MTE-enabled Pixel 8" (CVE-2023-6241) — a Mali CSF logic bug that
sidesteps MTE entirely by abusing the GPU as a coprocessor that
operates on physical addresses outside CPU tag-check enforcement.
The general lesson — "at some point, physical addresses will have to
be used directly to access memory" — is now the canonical caveat
against treating MTE as a complete defense. Reference:
[GitHub Blog — MTE Pixel 8](https://github.blog/security/vulnerability-research/gaining-kernel-code-execution-on-an-mte-enabled-pixel-8/).

### John Scott-Railton (Citizen Lab)
Joint lead with Marczak on most public Pegasus / Predator / Paragon
forensic work since 2018. Co-author with Marczak of the June 2025 Paragon Graphite
disclosure (CVE-2025-43200, zero-click via crafted iCloud-Link photo
processing, mitigated in iOS 18.3.1). Reference:
[Citizen Lab — Paragon Graphite](https://citizenlab.ca/research/first-forensic-confirmation-of-paragons-ios-mercenary-spyware-finds-journalists-targeted/),
[Citizen Lab — Jordan Pegasus](https://citizenlab.ca/2024/02/confirming-large-scale-pegasus-surveillance-of-jordan-based-civil-society/).

---

## II. Mobile Threat Model

### 1. Why mobile is different from desktop

Five structural properties:

1. **App-store gatekeeping.** App Store / Play Store impose review,
   code-signing, and post-publication revocation. Attacker work shifts
   to sideloading (Android), legitimate-app supply-chain compromise, or
   OS-level zero-day chains that need no malicious app.
2. **Sandboxing-by-default.** iOS App Sandbox + entitlements; Android
   UID-per-app + SELinux MAC. The desktop "shared filesystem, shared
   user" model does not apply; cross-app lateral movement is itself a
   vulnerability class.
3. **Baseband attack surface.** 5+ independent radios per device
   (cellular, Wi-Fi, BT, NFC, UWB, GPS, sometimes satellite), each its
   own trust domain with its own RTOS, all wirelessly reachable.
4. **App-as-OS-update lifecycle.** Apps update weekly; OS updates lag
   (Android OEM/carrier delays). Attackers ship implants faster than
   defenders patch on Android. Apple's monolithic-OS model pushes
   security patches faster than any general-purpose OS in history.
5. **Ubiquitous biometric auth.** Touch ID, Face ID, Pixel face
   unlock, BiometricPrompt are the de-facto auth surface for payments
   and credential storage. Matchers run in separate secure enclaves
   (SEP, StrongBox/Titan M); app-level integration is frequently
   misconfigured.

### 2. The four primary attack surfaces

| Layer | Attacker entry | Primary defender control |
|---|---|---|
| **App-layer** | malicious app, deep links, IPC, embedded libraries, WebView, pasteboard, document handlers | OWASP MASVS controls, secure SDK hygiene |
| **OS-layer** | kernel syscalls, drivers, IOKit, Binder, mediaserver, image codecs | OS vendor patching, exploit mitigations (PAC, KTRR, SELinux, ASLR, SHA) |
| **Baseband / radio** | cellular RRC, Wi-Fi 802.11 frames, BLE GATT, NFC, AWDL/Wi-Fi Aware | radio firmware updates, isolation from AP, baseband-AP IPC hardening |
| **Cloud-sync layer** | iCloud Backup, Google Drive, KeyChain, BlobStore, FCM/APNs, Find My | account auth, end-to-end encryption, hardware security key |

App-layer is where most general-population attacks live (malicious apps,
phishing, credential theft). OS-layer + baseband is where zero-click
nation-state chains live. Cloud-sync is the persistence / exfil layer for
both.

### 3. Physical access ≠ remote exploit
Physical-access extraction (Cellebrite/GrayKey/MSAB) usually needs a
chained physical exploit (e.g., checkm8 + post-BootROM kernel bug);
defense priorities are full-disk encryption strength, Lockdown Mode,
USB Restricted Mode, quick remote wipe. Remote exploit operates
wirelessly or via messaging; defense priorities are attack-surface
reduction (Lockdown Mode disables JIT, image codecs, attachments).

### 4. The mobile zero-day economy
Mobile zero-days are the highest-priced public vulnerability class.
Remote zero-click iOS chains have been quoted USD $1M–$2.5M+; Zerodium's
2019 list priced Android zero-click full chains ($2.5M) above iOS ($2M).
Principal mercenary-spyware vendors: **NSO Group** (Pegasus —
Trident/KISMET/FORCEDENTRY/BLASTPASS + 2022 trio), **Cytrox /
Intellexa Alliance** (Predator), **Candiru** (DevilsTongue),
**QuaDream** (shut down 2023). Forensic-extraction vendors (physical
threat model): **Cellebrite, MSAB, Magnet Forensics**. Western:
**AzimuthSecurity / L3Harris / Linchpin Labs**. Brokered markets:
**Zerodium** (Western), **Crowdfense** (UAE), Russian/Chinese-sphere
brokers. Targets are consistently journalists, human rights defenders,
dissidents, opposition politicians; the "only used against terrorists"
narrative is not supported by Citizen Lab's case load. Economic
asymmetry: a $2M chain amortizes across hundreds of targets over a
year before patching.

---

## III. iOS Architecture Overview

### 1. The XNU kernel
iOS runs XNU (Mach + BSD + IOKit), shared with macOS and visionOS but
hardened: KEXT loading disabled (DriverKit only), `task_for_pid`
restricted, mach trap surface reduced, large portions of `__TEXT_EXEC`
KTRR-protected. See `macos_apple_security.md` §II for XNU's mach IPC
and BSD policy stack — same primitives apply.

### 2. AMFI and CoreTrust
AppleMobileFileIntegrity (AMFI) enforces code-signing on every execve
and dlopen, rejecting any binary not signed by Apple or by a valid
developer chain. CoreTrust is the lower-level cert-chain validator.
Jailbreaks require AMFI bypass — either a CoreTrust bug (CVE-2022-26766,
CVE-2023-41991 used in 2023 Predator) or a kernel patch.

### 3. Page protection: PAC, KTRR, SPTM/TXM
- **PAC (ARMv8.3, A12+, 2018)** — five secret 128-bit keys; function
  pointers/return addresses get a signature in unused-high-bit padding
  of a 64-bit pointer, verified before use. Defeats naive ROP/JOP;
  bypassable with signing oracles, valid-signature copy/replay, or
  unauthenticated code paths. Reference:
  [Project Zero — Examining Pointer Authentication on the iPhone XS](https://projectzero.google/2019/02/examining-pointer-authentication-on.html).
- **KTRR** — hardware read-only mapping of kernel `__TEXT_EXEC`,
  unchangeable post-lock. Bypass requires pre-lock primitive or
  hypervisor-level write.
- **PPL** (pre-A15) → **SPTM/TXM** (A15+): SPTM runs at a higher
  exception level than the kernel and is the sole modifier of page
  tables; TXM enforces code-exec policy. Even with kernel RWX, the
  attacker cannot remap pages without compromising SPTM/TXM. Reference:
  [Apple — Operating system integrity](https://support.apple.com/guide/security/operating-system-integrity-sec8b776536b/web).
- **Memory Integrity Enforcement (MIE)** (September 9, 2025
  announcement; A19 / A19 Pro and M5 generation onward — iPhone 17 +
  iPhone Air ship-default): Apple's always-on, synchronous-mode memory
  safety stack. Three components: (1) secure typed allocators for
  kernel and userland; (2) **Enhanced Memory Tagging Extension
  (EMTE)** running in synchronous mode (vs. ARM MTE's optional async
  mode that Pixel ships with) — synchronous mode means a tag mismatch
  faults *immediately* rather than within a window, eliminating the
  TOCTOU window that practical Pixel-8 MTE bypasses have exploited;
  (3) **Tag Confidentiality Enforcement (TCE)** — multi-layer
  side-channel and speculative-execution defenses to prevent tag-value
  leakage. Apple explicitly states: "tag values can't influence
  speculative execution in any way" and EMTE requires knowing a
  region's tag to access non-tagged memory from tagged regions. Covers
  the kernel and "over 70 userland processes," prioritizing the
  attack surfaces in third-party messaging / social apps that
  mercenary spyware actually exercises. The stated design horizon is
  half a decade of co-design between silicon and OS. Reference:
  [Apple Security Research — Memory Integrity Enforcement](https://security.apple.com/blog/memory-integrity-enforcement/),
  [Apple Developer — Secure your app with MIE](https://developer.apple.com/videos/play/meet-with-apple/206/).

### 4. Sandbox model
Every iOS process runs in an App Sandbox profile (compiled .sb policy,
TrustedBSD MAC heritage). Entitlements are static capability grants in
the code-signing blob. Validated by AMFI at exec and at mach-port-
rights-transfer. Bypasses are typically sandbox-profile flaws (a
permitted IOKit user-client that yields escape) or entitlement-
validation flaws.

### 5. DriverKit
User-space driver framework replacing kernel extensions. Drivers run as
their own user-level process with IOKit-equivalent APIs over secure
shared memory. Converts kernel-LPE-in-driver bugs into user-LPE +
IPC-escape problems.

### 6. Code-signing chain
At exec: binary CMS blob → developer cert → Apple intermediate CA →
Apple Root CA → AMFI policy → ProvisioningProfile (UDID list / wildcard
/ entitlements) → entitlement vs process-need check → CoreTrust
validation → exec or deny. Historical weaknesses anywhere in this chain
have been exploitable (Janus on Android, `tfp0` on iOS, CoreTrust
bypasses in Pegasus/Predator).

### 7. Secure Enclave (SEP)
Physically separate ARM coprocessor with its own OS (sepOS), RAM, ROM,
and mailbox-based AP communication. Stores keybag/keychain master keys,
biometric templates, Apple Pay tokenization keys, secure-boot root, and
UID (non-exportable per-device key). Most public SEP research is on
A7–A10 era (Tarjei Mandt, Tihmstar); A14+ remains largely opaque. SEP
bugs are catastrophic — full keybag extraction on locked devices.

### 8. Boot chain
SoC reset → BootROM (read-only) → LLB → iBoot → kernel cache (XNU) →
launchd → SpringBoard. Each stage signature-validates the next via a
chain rooted in SoC ROM. checkm8 (CVE-2019-8900) breaks this on A5–A11
at the unupdatable BootROM root — every stage above is replaceable.

---

## IV. iOS Exploitation — The Modern Lineage

### 1. BootROM exploitation: checkm8
[checkm8](https://github.com/axi0mX/ipwndfu) (CVE-2019-8900) is a USB
DFU stack vulnerability in SecureROM of A5–A11 SoCs (iPhone 4S through
iPhone X, plus many iPads/iPods/Apple TVs). RCE at the BootROM trust
level, before any signature check runs. Because BootROM is on-die
read-only mask ROM, no firmware update can patch it — these devices
are permanently exploitable with physical access + DFU.

checkm8 founds checkra1n and most A5–A11 public jailbreaks. It alone
does not bypass keybag encryption — user-data extraction needs the
passcode or a separate SEP bug. A12+ SoCs are not vulnerable; physical-
access threat modeling differs materially across that boundary.

### 2. Kernel exploitation: primitives and patterns
Modern iOS kernel chains stack: **info leak** (kernel-pointer leak to
defeat KASLR — IOKit user-client reads, Mali-style timeline-buffer
analogs), **memory-corruption primitive** (overflow, UAF, type confusion,
double-free), **heap grooming** (`ipc_voucher`, mach ports, OOL
descriptors, IOSurface ports, controlled-size mach messages),
**arbitrary read/write** (typically constructed mach port with controlled
`ip_kobject`), **privesc** (overwrite `proc->p_ucred` or task-port
rights to gain `tfp0` or PAC-resilient equivalent), **cleanup**
(restore state to avoid panic). Canonical reference: Brandon Azad,
"A survey of recent iOS kernel exploits" (Project Zero, June 2020).

### 3. JIT escape from JavaScriptCore
Mobile Safari and JIT-enabled WKWebView host JSC. Lineage: type
confusion / OOB read → addrof+fakeobj → JIT-RWX-region write → renderer
RCE → sandbox escape → kernel chain → root. Cross-link
`browser_js_engine_exploitation_expertise.md` §6 — the JSC taxonomy
applies unchanged, with PAC on A12+ adding the further constraint that
JIT regions themselves are PAC-signed.

### 4. BLASTPASS and Operation Triangulation
**BLASTPASS** (September 2023, Citizen Lab + Apple): CVE-2023-41064
(Image I/O buffer overflow in lossless WebP via crafted PassKit
attachment) + CVE-2023-41061 (Wallet validation bypass). Zero-click
iMessage, patched in iOS 16.6.1. The WebP vuln is the same parser as
libwebp CVE-2023-4863 in Chrome. Reference:
[Project Zero — Blasting Past Webp](https://projectzero.google/2025/03/blasting-past-webp.html).

**Operation Triangulation** (Kaspersky, June 2023; full chain disclosed
at 37C3 December 2023): four-CVE chain, all CVE-2023, all zero-click:

| CVE | Layer | Mechanism |
|---|---|---|
| **CVE-2023-41990** | Initial RCE | Undocumented ADJUST TrueType font instruction (removed by patch; "had existed since the early nineties") triggered via iMessage attachment; multi-stage ROP/JOP through NSExpression/NSPredicate |
| **CVE-2023-32434** | XNU kernel R/W | Integer overflow in `mach_make_memory_entry` / `vm_map` syscalls yielding user-level R/W to entire physical memory |
| **CVE-2023-38606** | PPL bypass | Hardware-MMIO write to undocumented GPU coprocessor registers at `0x206040000`, `0x206140000`, `0x206150000` (data + destination + Hamming-coded hash) — modifies cache-line-resident page-table state below PPL's protection horizon |
| **CVE-2023-32435** | Safari RCE | Safari exploit (reached after the implant launches an invisible Safari process to a verification webpage) used to execute a shellcode |

The CVE-2023-38606 register set belongs to the GFX coprocessor — improper
access raises a "GFX SERROR Exception." Affected SoCs are A12–A16
(the entire PPL generation; A15+ SPTM/TXM models are also affected as
the bypass targets a layer below them). Kaspersky's working hypothesis
is that the feature is a leftover from silicon factory test / debug,
never documented in the device tree. How attackers discovered it
remains publicly unanswered — insider knowledge, leaked documentation,
or extraordinary reverse engineering are the three available
hypotheses. This is the most consequential public iOS chain of the
2020s because it demonstrates: (a) hardware mitigations have
undocumented surface that bypasses them; (b) at the in-the-wild
attacker tier, "undocumented" does not mean "unfindable." References:
[Securelist — The last (hardware) mystery](https://securelist.com/operation-triangulation-the-last-hardware-mystery/111669/),
[Kaspersky 37C3 2023 talk recap](https://www.kaspersky.com/blog/triangulation-37c3-talk/50166/),
[Securelist — Coruna framework follow-on](https://securelist.com/coruna-framework-updated-operation-triangulation-exploit/119228/).

### 5. 1-click vs. 0-click
- **1-click** — user taps a link, opens a message, accepts a call.
  Usually Safari or in-app webview. Higher target-attrition.
- **0-click** — triggers on receipt without interaction. Vectors:
  iMessage attachment preview, AirDrop
  listener (Ian Beer 2020), AWDL/Wi-Fi Aware frames. The gold standard
  for offensive ops — per-target cost is chain-amortized, not
  social-engineering-amortized.

Pegasus/Triangulation chains since 2020 are all 0-click.
The 2024–2025 in-the-wild iOS corpus continued the pattern:

| Year | Chain / Vendor | Lead vuln(s) | Patched in | Disclosure |
|---|---|---|---|---|
| 2024 | Pegasus (NSO) Jordan campaign | (chain undisclosed publicly) | rolling | [Citizen Lab — Jordan](https://citizenlab.ca/2024/02/confirming-large-scale-pegasus-surveillance-of-jordan-based-civil-society/) |
| 2025 | Graphite (Paragon) | **CVE-2025-43200** — logic flaw processing crafted photo/video via iCloud Link in Messages | iOS 18.3.1 (Feb 2025) | [Citizen Lab — Graphite](https://citizenlab.ca/research/first-forensic-confirmation-of-paragons-ios-mercenary-spyware-finds-journalists-targeted/) |

The Paragon Graphite chain is structurally aligned with the FORCEDENTRY
/ BLASTPASS / Triangulation lineage: iMessage-adjacent zero-click on
crafted media. Targets included Italian journalist Ciro Pellegrino and
at least one anonymous European journalist; Apple sent threat
notifications on April 29, 2025; Citizen Lab confirmed via forensic
analysis. The Apple-mitigated-but-undisclosed pattern (CVE-2025-43200
was patched February 10, 2025; publicly disclosed June 11, 2025) is
worth carrying forward as the 2025 attribution-window standard.

### 6. Sandbox escape primitives
After renderer/parser RCE, escape primitives include: **IOKit
user-client misconfig** (a sandbox-permitted class with unsafe
selectors), **XPC service trust** (services accepting unsigned messages
or with weak NSXPC interface validation), **NSXPC interface confusion**
(`setExportedObject` deserialization yielding type confusion),
**launchd / launchctl misuse** (service registration, launch-on-demand
manipulation).

### 7. Pegasus FORCEDENTRY anatomy
Citizen Lab + Project Zero coverage (2021): iMessage receives crafted
PDF with .gif extension → CoreGraphics CGContext handles malformed
JBIG2 stream → JBIG2 bytecode interpreter repurposed via integer
overflow into a small virtual CPU (the "JBIG2 bit-trick computer" Beer
documents) → that computer (registers plus a 64-bit adder and
comparator) searches memory and performs arithmetic to assemble the
chain in place → sandbox escape + kernel + implant. A useful demonstration that constraint-rich primitives can
be Turing-complete with enough work.

### 8. Trident (2016) historical baseline
First widely-documented mercenary-spyware chain: CVE-2016-4655 (kernel
info leak in OSUnserializeBinary), CVE-2016-4656 (kernel UAF privesc),
CVE-2016-4657 (WebKit RCE via Safari). 1-click via SMS link. iOS 9.3.5
shipped alongside Citizen Lab's August 25, 2016 disclosure, 15 days after the August 10 discovery — establishing the public-
disclosure + fast-Apple-patch pattern that has held since.

---

## V. iOS App-Layer Attack Surface

### 1. URL schemes
Custom URL schemes (`yourapp://path?param=value`) are app-registered deep
links. iOS routes `openURL:` to whichever app last registered the
scheme — no enforced uniqueness. Attacks: **scheme hijacking** (malicious
app registers a popular scheme), **parameter injection** (URL params
flowed into webview URLs, SQL queries, or shell paths without
validation), **unauthenticated privileged actions**
(`myapp://transfer?to=alice&amount=100` with no user confirmation).
Mitigation: Universal Links for sensitive actions; treat every URL
parameter as attacker-controlled.

### 2. Universal Links and Associated Domains
The app declares Associated Domains in its entitlement; the domain
hosts `/.well-known/apple-app-site-association` (AASA JSON) listing
handled paths. iOS fetches and verifies at install. Misconfiguration
patterns: AASA missing (fallback to Safari), overly broad path globs
(`/*`), AASA over HTTP or via unverified CDN (MITM-substitutable on
historical apps).

### 3. Pasteboard sniffing
Pre-iOS 14 any foreground app silently read `UIPasteboard.general`.
iOS 14+ added the "pasted from X" indicator — pasteboard remains
readable, just visible. Sensitive classes: 2FA codes, passwords, wallet
addresses (target of "clipper" malware). Defensive: use
`UIPasteboard(name:create:)` with a private name, or `setItems` with
`.localOnly: true` and `.expirationDate`.

### 4. Keychain misuse
iOS Keychain Services provides hardware-backed credential storage with
several accessibility classes:

| Class | When readable |
|---|---|
| `kSecAttrAccessibleAlways` | Always (deprecated, do not use) |
| `kSecAttrAccessibleWhenUnlocked` | Device unlocked |
| `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` | Device unlocked, not backed up |
| `kSecAttrAccessibleAfterFirstUnlock` | After first unlock since boot |
| `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly` | Passcode required, never backed up |

Common anti-patterns: using `kSecAttrAccessibleAlways` for tokens that
only need access during foreground use; storing high-value secrets
without `ThisDeviceOnly` (allowing iCloud Keychain replication and
potentially recoverable via account compromise). Cross-link to
`cryptography_expertise.md` §IV on key storage.

### 5. App Transport Security (ATS) bypass
ATS requires HTTPS with TLS 1.2+ for all network connections by default
since iOS 9. Apps can declare exceptions in `Info.plist`:

```xml
<key>NSAppTransportSecurity</key>
<dict>
  <key>NSAllowsArbitraryLoads</key>
  <true/>
</dict>
```

`NSAllowsArbitraryLoads: true` disables ATS entirely. This is a frequent
finding in MASVS-pentest reports. Variants like
`NSExceptionDomains` with `NSExceptionAllowsInsecureHTTPLoads` for a
single domain are less catastrophic but still concerning.

### 6. Plist parsing
Apps that consume external plist files (XML or binary) can be attacked
via plist parsing differentials — type-confusion between `NSDictionary`
and `NSString`, embedded `NSKeyedArchiver` payloads, or `NSURL` schemes
that trigger app-specific handlers. Cross-link to
`xml_parser_differential_expertise.md` for the canonical plist /
XML parser-differential taxonomy.

Particularly nasty: `NSKeyedUnarchiver` with `unarchiveObject(with:)`
(no class allowlist) on attacker-controlled bytes is roughly equivalent
to Java unsafe deserialization. Apple deprecated this API; use
`unarchivedObject(ofClass:from:)` with an explicit class list.

### 7. WKWebView injection
WKWebView is the modern iOS in-app browser primitive. Attack surfaces:

- **`evaluateJavaScript:`** — passing untrusted strings into JS context
  is direct injection (XSS-equivalent).
- **`WKScriptMessageHandler`** — JS-to-native bridge. Any input from
  the JS side is attacker-controlled if the page loaded is untrusted.
  Validate every parameter; never `eval()` JS-supplied strings on the
  native side.
- **JavaScript bridge promotion** — registering a bridge that exposes
  too many native capabilities (file read, network, intent-equivalent).
- **`UIWebView`** — deprecated; should not exist in 2026-era apps.
  Apps still using UIWebView have a different (worse) bridge model.

Cross-link to `browser_js_engine_exploitation_expertise.md` for renderer-
process exploitation primitives that apply to WKWebView's WebContent
process (same JSC, same renderer codebase as Safari).

### 8. Push Notification abuse
APNs delivery requires an Apple-developer-signed token (modern: JWT
signed by a per-account private key). Key theft yields push impersonation
against every device that has the app installed. Notifications can carry
deep-link URLs that route to the app's URL handler — combine with §1
scheme-hijacking for targeted phishing.

### 9. Background Task abuse
Apps declare background modes (audio, location, VoIP, fetch, processing),
each gated by entitlement and Settings grant. Anti-pattern: declaring
VoIP or `location` to maintain background runtime for non-VoIP /
non-location work, providing a stealthy persistence vector that survives
App Review.

### 10. JIT entitlement abuse
The `dynamic-codesigning` entitlement lets a process map W+X memory.
Only Safari WebContent and a small allowlist of system processes have
it. Frida's "gadget" mode on iOS often piggybacks on JIT entitlement
on jailbroken devices to inject code without resigning.

### 11. Custom keyboards
Third-party `UIInputViewController` apps requesting "Full Access" can
exfiltrate every keystroke. A pentest finding class: apps that accept
sensitive input (passcode, payment) without disabling third-party
keyboards — per field via `isSecureTextEntry`, or app-wide by returning
false from `application(_:shouldAllowExtensionPointIdentifier:)` for the
keyboard extension point.

### 12. iOS sideloading and EU Digital Markets Act regime
iOS 17.4 (March 2024) introduced **EU-only alternative distribution**
in response to the EU **Digital Markets Act**. The regime has three
material attack-surface implications, all of which are
underappreciated in pre-2024 MASVS-derived threat models.

**(a) Alternative marketplaces.** AltStore PAL (the first, April 2024),
Setapp Mobile, Epic Games Store, AltStore Classic-on-PAL, and the
Apple-distributed-but-third-party-curated stores. Each is a separate
trust domain with its own curation policy, takedown latency, and
malware-scan posture. Requirements as published by Apple: EU
geo-presence (no VPN), EU App Store account, iOS 17.4+, and (per
AltStore PAL, until an Epic MegaGrant removed it in 2024) a €1.50/year
subscription covering Apple's Core Technology Fee.

**(b) Notarization, not review.** Apps distributed through alternative
marketplaces or Web Distribution are **notarized** (automated malware
scan + basic functionality check + signed-developer-identity, combining
automated checks with human review) but **not App-Reviewed**: Apple calls
it a baseline review and leaves broader review to each marketplace. The
distinction matters: Notarization catches known malware and obvious
policy violations; it does not catch business-logic abuse,
manipulative monetization, or privacy violations that human App
Review historically gated.

**(c) Three-app sideload cap** on AltStore-tier free distribution
(non-marketplace AltStore Classic personal-signing path retains the
historical limit) limits casual abuse but doesn't apply to apps
distributed through a Notarized marketplace.

The pattern-of-concern for pentests: an EU-only attack surface for
apps that ship a strict App Store version and a relaxed
alternative-marketplace version (different entitlements, different
ATS posture, different deep-link claim sets). Several iOS 26.2-era
expansion announcements (per Apple) extended the alternative-
distribution regime beyond the EU; surface enumeration should not
assume "App Store implies Apple-curated" for any 2025+ build.
Reference:
[Apple Developer — Update on apps distributed in the EU](https://developer.apple.com/support/dma-and-apps-in-the-eu/),
[Apple Newsroom — DMA impacts on EU users (Sep 2025)](https://www.apple.com/newsroom/2025/09/the-digital-markets-acts-impacts-on-eu-users/),
[AltStore PAL FAQ](https://faq.altstore.io/altstore-pal/what-is-altstore-pal).

---

## VI. Android Architecture Overview

### 1. AOSP layers
Apps (Java/Kotlin + ART) → Framework (Activity/Service/ContentProvider/
Broadcast) → Binder IPC + `system_server` (privileged framework
process) → native libs (libc, libbinder, libcrypto, libstagefright/
libmedia) → HAL (vendor-supplied) → Linux kernel + drivers (Mali,
Adreno, MediaTek bsg, etc.). The framework layer is Android-unique:
most app-to-system interaction goes through it via Binder.

### 2. Binder IPC
Kernel-level IPC bus; every cross-process framework call (Activity
launches, service calls, ContentProvider queries) goes via Binder
transactions through `/dev/binder`. SELinux gates this via the
`binder` object class (`call`, `transfer`, `set_context_mgr`,
`impersonate`), isolating vendor and framework traffic. The Binder
driver itself is a recurring CVE source — "Bad Binder" (CVE-2019-2215)
was used in the wild. Reference:
[source.android.com — Use binder IPC](https://source.android.com/docs/core/architecture/hidl/binder-ipc).

### 3. SELinux on Android
Enforcing mode since 5.0 (2014). Monolithic compiled policy; every
domain has a small allowed-rule set; `untrusted_app` is extremely
restricted. Vendor extensions in `device/<vendor>/sepolicy/`. SELinux
is the second-line defense after Linux DAC's UID-per-app, and the
first defense against kernel-driver attack surface (most drivers gated
behind SELinux types).

### 4. Verified Boot (AVB)
Bootloader signature-validates each partition before load. AVB 2.0 is
current; supports rollback protection via tamper-evident chained
version counters. OEM unlock breaks the chain — the conventional path
for ROM modding and root.

### 5. Permission model evolution
Install-time (pre-6) → runtime dangerous (6+) → scoped storage (10+) →
separate background-location grant (11+) → approximate-vs-precise
location + clipboard toast (12+) → opt-in notifications (13+) →
photo-picker + granular screen-record (14+). Edge case: permission
semantics changing across major versions ("user granted v2 X, app
retains in v3 with broader meaning").

### 6. Project Mainline and APEX
Mainline (10+) separates 20+ core system modules (Conscrypt, Media
Codecs, DNS resolver, Permission Controller, NetworkStack) from the OS
image. Modules ship as APEX or APK and update via Play Store —
decoupling critical security components from OEM OTA cadence. APEX
signed by Google, not OEM.

### 7. Google Play Protect
On-device + cloud malware detection. Periodically scans installed apps,
sideloaded APKs at install time, continuously monitors behavior.
Mostly opaque externally; bypass typically requires novel code or
obfuscation targeting the static-signature DB.

### 8. The OEM customization mess
Samsung Knox, Xiaomi MIUI, Huawei EMUI/HarmonyOS, OnePlus OxygenOS
each add custom services (system_server-equivalent), HAL
implementations, SELinux policy, and Settings UIs that may default
weaker. Fertile ground for per-OEM vulnerabilities patched slowly or
never on older devices. Samsung Knox has been a particularly productive
target (multiple TEE/Trustlet vulnerabilities).

---

## VII. Android Exploitation

### 1. Kernel exploitation
Android runs a Linux kernel — the canonical Linux taxonomy applies.
Cross-link `linux_kernel_exploitation_expertise.md` for primitives
(SLAB/SLUB grooming, cred overwrite, eBPF, io_uring). Android-specific:
**vendor drivers are the productive surface** (most in-the-wild chains
exploit Mali, Adreno, Hexagon DSP, MediaTek bsg, or Samsung Exynos —
not core Linux). The **Binder driver** has produced multiple CVEs
(Bad Binder CVE-2019-2215 in the wild, CVE-2023-20938 on 12/13).
**GKI** (Android 12+) requires Google-provided generic kernel with
vendor drivers as loadable modules.

### 2. Mali GPU CVE corpus (Pixel)
The Mali driver on Pixel 6/7/8/9 (Tensor SoC) has yielded a substantial
in-the-wild corpus: **CVE-2022-22706** (read-only imported pages made
host-writable), **CVE-2023-26083** (kernel-pointer leak via timeline
ring buffer in userspace), **CVE-2023-6241** (Mali CSF `kbase_jit_grow`
lock-release TOCTOU on Pixel 8 — the canonical MTE-era exploit;
Man Yue Mo, GitHub Security Lab, 2024), and Jann Horn's 2022 audit found
5 additional exploitable bugs in 3 weeks. Pattern: large, infrequently
audited code with weak memory-management invariants. Reference:
[Project Zero — Mind the Gap](https://projectzero.google/2022/11/mind-the-gap.html),
[Analyzing a Modern In-the-wild Android Exploit](https://projectzero.google//2023/09/analyzing-modern-in-wild-android-exploit.html),
[GitHub Blog — Kernel Code Execution on an MTE-Enabled Pixel 8](https://github.blog/security/vulnerability-research/gaining-kernel-code-execution-on-an-mte-enabled-pixel-8/).

### 2a. Pixel 8/9 MTE production deployment and bypass
Pixel 8 (October 2023) was **the first production handset with ARM
Memory Tagging Extension support**, exposed as a developer option
(opt-in for apps via `android:memtagMode`). Android recommends
**asynchronous** mode for production and synchronous mode for
development — a material delta vs. Apple's iPhone-17
EMTE-synchronous-by-default. The
Pixel 8/9 deployment delivered the long-awaited "production
spatial+temporal heap safety" but Man Yue Mo's CVE-2023-6241 chain
demonstrated within months that **MTE only protects CPU pointer
dereferences** — a coprocessor (Mali GPU, in this case) operating on
physical addresses outside CPU tag-check enforcement remains a viable
bypass. Generalizable lesson: any MTE deployment must extend tag-check
discipline to DMA-capable peripherals (GPU, DSP, NPU, baseband) or
attackers will pivot to them. Reference:
[Project Zero — First handset with MTE on the market](https://projectzero.google/2023/11/first-handset-with-mte-on-market.html),
[Android Developer — MTE NDK guide](https://developer.android.com/ndk/guides/arm-mte),
[AOSP — ARM MTE](https://source.android.com/docs/security/test/memory-safety/arm-mte).

### 3. Qualcomm DSP / Hexagon
Hexagon DSP runs its own OS (QuRT) processing attacker-influenced data
(audio codec, camera ISP). DSP-to-AP escalation productive in the wild.
Cross-link `firmware_embedded_security.md`.

### 4. WebView (Chromium-derived)
Updatable APK (via Google Play) since Android 5.0. Most WebView CVEs are Chromium
renderer/V8 bugs applying unchanged to embedding apps — cross-link
`browser_js_engine_exploitation_expertise.md` §3.

### 5. Stagefright corpus
2015 Zimperium family: integer overflows + parser bugs in
`libstagefright`, exploitable via MMS auto-fetch (zero-click). Pushed
Google to monthly Security Bulletins and to isolate media parsing into
`mediaserver`/`mediacodec` with reduced sandbox. Canonical "parser in
privileged process consuming network bytes" 0-click pattern.

### 6. Pwn2Own Mobile / Tianfu Cup
Mobile Pwn2Own (Tokyo) and Tianfu Cup (Chengdu) are the principal
non-mercenary-spyware public-chain disclosure venues — Pangu,
Fluoroacetate, TASZK. Post-2021 Tianfu output largely unpublicized;
chains believed to flow into Chinese-state offensive use rather than
vendor disclosure. **Pwn2Own Ireland 2024** (Cork) became the new
home of the consumer edition (mobile + IoT targets). Reference:
[ZDI — Pwn2Own coverage](https://www.thezdi.com/blog).

---

## VIII. Android App-Layer Attack Surface

### 1. Intent-based attacks
Three flavors: **explicit** (target named), **implicit** (resolved by
Action+Category+Data URI), **PendingIntent** (wrapped intent fired by
another app under the wrapper's identity — a recurring privesc source).

- **Implicit intent hijacking** — any app matching the filter receives
  sensitive data.
- **Exported activity/service bypass** — `android:exported="true"`
  (default pre-SDK 31 for components with intent filters) lets any app
  launch the component. Android 12 made `exported` explicit.
- **PendingIntent mutability** — pre-2023 mutable PendingIntents could
  be modified before fire (CVE-2020-0188). Apps targeting SDK 31+ must
  specify `FLAG_IMMUTABLE` / `FLAG_MUTABLE`.

### 2. Content Provider misuse
URI-addressed row/file primitive. Vulnerabilities: **SQLi via Provider**
(`query()` concatenating selection-args into raw SQL), **path traversal via `openFile()`** (file URI
handler accepting `../` segments), **GrantUriPermission abuse**
(calling app receives URI permission scoped to a parent that includes
unintended resources).

### 3. Deep links and App Links
Custom-scheme links carry the same hijacking risk as iOS schemes. App
Links (Android's Universal Links equivalent) are verified via Digital
Asset Links JSON at `/.well-known/assetlinks.json`; misconfiguration
patterns parallel iOS AASA. `autoVerify="true"` + DAL mismatch silently
breaks link handling and falls back to browser.

### 4. WebView JS bridge abuse
`addJavascriptInterface(obj, "name")` exposes Java methods to JS.
Pre-Android 4.2, JS could reflect on `obj` to invoke
`getClass().forName(...).getMethod("exec").invoke(...)` → arbitrary
command exec. Android 4.2+ requires `@JavascriptInterface` annotation
per method (blocks the reflection trick), but apps still misuse it to
expose dangerous methods (file read, network, intent fire).
`setAllowFileAccessFromFileURLs(true)` / `UniversalAccessFromFileURLs`
weaken origin policy; `setJavaScriptEnabled(true)` plus attacker-
controlled URLs is equivalent to letting the attacker run JS in your
app.

### 5. KeyStore weaknesses
Backing modes: software-backed (file system, extractable on rooted
devices), TEE-backed (TrustZone, most Snapdragon), StrongBox
(dedicated secure element — Pixel Titan M2, some Samsung). MASVS
requires sensitive keys be TEE or StrongBox. Use
`setUserAuthenticationRequired(true)` +
`setUserAuthenticationParameters(0, AUTH_BIOMETRIC_STRONG)` for
biometric-per-use.

### 6. SharedPreferences without encryption
Default `SharedPreferences` writes plaintext XML to
`/data/data/<pkg>/shared_prefs/` (UID-protected but trivially extracted
via `adb backup` on debuggable apps or on rooted devices). Use
`EncryptedSharedPreferences` (AndroidX Security) for sensitive data.

### 7. Janus signature bypass (CVE-2017-13156)
Pre-2017 APK v1 signature scheme verified content-hash matches manifest
only. The Janus attack prepended a DEX to an APK; ZIP parsing ignored
the prefix while ART loaded it — legitimate-signed APK with attacker
DEX. Fixed in Android 7+ with APK Signature Scheme v2 (full-archive
signature). Apps not enabling v2 remain vulnerable.

### 8. Tapjacking and accessibility-service abuse
**Tapjacking** — malicious overlay draws on top of a sensitive button;
target should set `filterTouchesWhenObscured` (Android 12+ also
blocks touches passing through untrusted overlays from other apps by
default). **Accessibility-service
abuse** — `BIND_ACCESSIBILITY_SERVICE` yields full UI read +
tap/text injection; banking trojans (Anubis, Cerberus, ERMAC) abuse
this for overlay + 2FA exfil. Play Protect flags non-accessibility
abuse but the bypass is mature.

### 9. APK signing scheme history
v1 → v2 → v3 (key rotation) → v4 (incremental delivery, post-2020 Play
Store streaming). Some attacks live in the gap between schemes an OS
version verifies vs. schemes the app declares.

### 10. Banking-trojan corpus (2024–2026)
The 2024–2026 Android banking-trojan corpus continued the
accessibility-service-abuse + overlay + remote-control pattern with
several productive evolutions:

- **Anatsa / TeaBot / Toddler** — long-running dropper-family active
  since 2020; July 2025 campaign distributed via fake "Document Viewer -
  File Reader" app in Google Play, ≈90,000 installs before takedown. Targets
  North American + European banking apps. References:
  [The Hacker News — Anatsa via Google Play 2025](https://thehackernews.com/2025/07/anatsa-android-banking-trojan-hits.html).
- **ToxicPanda** — surfaced October 2024 (Cleafy Labs); evolved from
  the Asian-targeted TgToxic family. By early 2025 the botnet had
  doubled in size (peaking near 4,500 infected devices), with Portugal
  and Spain as the main targets. Adds on-device-fraud (ODF) over
  account-takeover (ATO) — money moves from the *victim's* device
  rather than a separate fraudster-side device, defeating
  device-fingerprint risk gates. Attributed to Chinese-speaking
  threat actor. References:
  [Cleafy — ToxicPanda](https://www.cleafy.com/cleafy-labs/toxicpanda-a-new-banking-trojan-from-asia-hit-europe-and-latam),
  [The Hacker News — ToxicPanda](https://thehackernews.com/2024/11/new-android-banking-malware-toxicpanda.html).
- **SoumniBot** — South Korea-targeted (April 2024); novel evasion
  via **Android manifest obfuscation** (intentionally malformed
  manifest bytes that AOSP parses but most analyzer tooling skips),
  plus search for Korean-banking digital certificates on the device
  for direct credential theft. References:
  [The Hacker News — SoumniBot](https://thehackernews.com/2024/04/new-android-trojan-soumnibot-evades-detection.html).
- **TgToxic** — February 2025 variant added anti-analysis upgrades
  (emulator detection, packer evasion). The parent family of
  ToxicPanda; ongoing.

Three patterns worth flagging for app-team threat models:

1. **Google Play remains a productive delivery channel** despite
   review. The Anatsa droppers ship as innocuous productivity apps
   and download payload post-install — Play Protect catches
   late-stage, not early-stage.
2. **Manifest-parser differential abuse (SoumniBot)** is an
   instance of an Android-malware family weaponizing
   parser surface to evade static analysis. Cross-link
   `xml_parser_differential_expertise.md`.
3. **ODF over ATO** — the financial-fraud pattern has shifted from
   "take over the account from a fraudster device" to "make the
   victim device do the transfer." This defeats device-binding /
   fingerprint-risk-scoring gates and requires server-side
   transaction-pattern detection (impossible-travel, atypical-payee,
   atypical-amount, atypical-velocity).

### 11. AI-app phishing and malicious AI app stores
A 2024–2025 emerging class. Fake "ChatGPT-style" apps surface
periodically on both Play Store and App Store; they collect credentials
or charge subscription on a thin GPT-API frontend, or run an in-app
phishing flow themed around AI-assistant functionality. The pattern
intersects with §1a (Apple Intelligence) and §1b (Gemini Nano) by
attempting to confuse users about what is on-device vs. cloud, and
where the privacy boundary actually lives. No mature MASVS control
addresses this; the closest gate is MASVS-PRIVACY's data-disclosure
controls.

---

## IX. Runtime Instrumentation — Frida and Friends

### 1. Frida architecture
Cross-platform dynamic-instrumentation toolkit (iOS, Android, Windows,
macOS, Linux). Three injection modes: USB (`frida-server` daemon on
rooted/jailbroken device, host over USB), spawn-gated (Frida spawns and
pauses target, attaches, resumes), and gadget (`frida-gadget` statically
linked / dlopen'd into the target — works without root/jailbreak). Core
is **Gum** (C, JIT-driven hot-patching) with a V8/QuickJS scripting
layer. Hooks compile to inline trampolines.

**Frida 17.x** (May 2025+) is a major-version bump after nearly three
years on 16.x; the breaking change is **runtime bridges decoupled
from GumJS** — `frida-objc`, `frida-swift`, and `frida-java-bridge`
ship separately, allowing leaner agents that don't pull every
language-runtime shim. 17.4 (October 2025) added the **`simmy`
backend** for Apple-simulator (CoreSimulator.framework) targets,
giving native spawn/attach against iOS Simulator processes — a
material productivity gain for pre-device pentest iteration. 17.5
(November 2025) added platform-aware compiler externals and
async/await-first Swift bindings. References:
[Frida 17.0.0 release](https://frida.re/news/2025/05/17/frida-17-0-0-released/),
[Frida 17.4.0 release](https://frida.re/news/2025/10/12/frida-17-4-0-released/),
[Frida 17.5.0 release](https://frida.re/news/2025/11/04/frida-17-5-0-released/).

### 2. Hooking patterns
- **Objective-C method swizzling** via IMP-table replacement
  (`ObjC.classes.X["- m"].implementation = ...`).
- **Swift method-table override** via vtable patching; harder for
  whole-module-optimized binaries where devirtualized calls require
  per-call-site trampolines.
- **ART method patching (Android)** by overwriting `ArtMethod`'s
  entry-point pointer.
- **Native function hooks** — inline trampoline at prologue; original
  prologue saved for "call original."

### 3. Objection
[Objection](https://github.com/sensepost/objection) is a pre-built
Frida wrapper with CLI shortcuts for the common mobile-pentest tasks:
heap dumps, class enumeration, SSL pinning bypass, root/jailbreak
detection bypass, KeyStore enumeration, intent inspection.

### 4. r2frida
[r2frida](https://github.com/nowsecure/r2frida) gives radare2's static
UI access to Frida's runtime state — useful for cross-referencing live
hooks with static disassembly.

### 5. Magisk and the root cat-and-mouse
[Magisk](https://github.com/topjohnwu/Magisk) is the de-facto modern
Android root: **systemless** (boot-image patch, no /system mods,
defeats SafetyNet/Play Integrity static checks), **Zygisk**
(namespace-isolated root), and a **DenyList** UI for hiding root from
specific apps. Google Play Integrity ships periodic detection-logic
updates; Magisk ships countermeasures — a continuous arms race the
user usually wins for weeks at a time.

### 6. Frida detection and bypass
Apps detect Frida via `/proc/self/maps` scans for `frida-agent` /
`gum-js-loop` thread names, open-file scan for
`/data/local/tmp/re.frida.server`, port scan for the default 27042,
function-prologue checksum (Frida's trampoline mutates prologue
bytes), and TLS-callback timing anomalies. Bypass: hook the detection
function itself, patch matching strings, rename `frida-server` /
change its port, or use `frida-gadget` injected via custom build.

### 7. Root / jailbreak detection by apps
iOS checks: `/Applications/Cydia.app`, `/private/var/lib/apt`,
`/usr/sbin/sshd`, fork() success (sandboxed apps cannot fork),
writability of `/private/jb_test`, `dlopen("/usr/lib/libsubstrate.dylib")`,
`cydia://` URL handler. Android checks: `/system/bin/su` or `xbin/su`,
Superuser.apk, `test-keys` in build tags, `/system` remount-rw,
busybox. Bypass: Objection's `ios jailbreak disable` /
`android root disable`, Frida hook scripts, SSL Kill Switch 2 (iOS,
Substrate-based detection + pinning bypass).

---

## X. Static Analysis of Mobile Binaries

### 1. iOS: Mach-O reversing
Hopper (GUI, good ObjC/Swift metadata), IDA Pro (industry standard,
AppleSwift type recovery), Ghidra (open source, weaker Swift but
improving), Binary Ninja. iOS apps post-decryption are ARM64 Mach-O.
App Store binaries are FairPlay-encrypted; decryption requires
extraction from a running process on a jailbroken device (`Clutch`,
`frida-ios-dump`, `bagbak`) or re-sign via AltStore.

### 2. Android: APK + native libs
**jadx** (APK → Java source, default first-pass), **apktool** (APK →
smali + resources, rebuild support, foundation of patch-and-resign),
**bytecode-viewer** (multi-decompiler aggregator), **Ghidra/IDA** for
native `.so`. Pipeline: `apktool d` → edit smali → `apktool b` →
`apksigner sign`.

### 3. Code obfuscation analysis
**ProGuard/R8** (Google's default — class/field/method rename),
**DexGuard** (Guardsquare commercial — string + class encryption,
RASP, pinning), **Bangcle/Ijiami/Qihoo** (Chinese packers with
whole-DEX encryption — usually bypassable via `frida-dexdump`). iOS
Swift/ObjC are less obfuscated by convention; high-value iOS targets
use LLVM-Obfuscator-derived passes (CFF, bogus CF, instruction
substitution).

### 4. Native library reversing
Look for **pinned cert hashes** (static byte arrays, x-ref
`SSL_CTX_set_verify`), **hardcoded secrets** (regex `AKIA*`,
`sk_live_*`, `ghp_*`, `xoxb-*`), **JNI bindings**
(`Java_com_<pkg>_<class>_<method>`), **string decryption stubs**
(XOR/RC4/AES on first-reference).

### 5. MOBSF
[Mobile Security Framework](https://mobsf.github.io/Mobile-Security-Framework-MobSF/)
— automated static + dynamic analysis pipeline. Decompiles APK/IPA,
runs rule-based checks (crypto, secrets, ATS, permissions), produces
HTML report. Productivity multiplier for pentest first-pass and CI/CD
gates. Cross-link `vulnerability_research_methodology_expertise.md`
§5.

### 6. Surface enumeration on mobile binaries
Priority order: (1) network endpoints (URL/hostname strings),
(2) hardcoded secrets (entropy + known prefixes), (3) custom URL
schemes / intent-filters, (4) exported components, (5) permissions,
(6) WebView JS bridges, (7) ATS / NetworkSecurityConfig exceptions,
(8) crypto API misuse (ECB, fixed IVs, weak KDFs). Cross-link
`code_review_expertise.md`.

---

## XI. Network-Traffic Interception

### 1. Burp Suite / mitmproxy + mobile certs
Standard setup: install proxy CA on device (iOS: install profile via
Safari + trust in Cert Trust; Android: install as user cert + require
`network-security-config.xml` allowing user certs, or push to system
store on a rooted device), configure proxy in Wi-Fi settings, intercept.
mitmproxy is the open-source/scriptable alternative. Limitations:
pinned apps reject the proxy CA outright; `cleartextTrafficPermitted=
"false"` + pinning resists user-cert injection.

### 2. Frida-based SSL pinning bypass
Canonical mobile-pentest technique. Hook the TLS-validation function
per stack: iOS NSURLSession (`SSLHandshake`, `URLSession:didReceiveChallenge:`),
iOS BoringSSL (`SSL_CTX_set_custom_verify`, `SSL_get_verify_result`),
Android OkHttp (`OkHttpClient$Builder.certificatePinner`,
`CertificatePinner.check`), Android `X509TrustManager`
(`checkServerTrusted`). Universal scripts:
[frida-android-unpinning](https://github.com/httptoolkit/frida-android-unpinning),
[Objection `android sslpinning disable`](https://github.com/sensepost/objection),
[SSL Kill Switch 2](https://github.com/nabla-c0d3/ssl-kill-switch2)
(iOS).

### 3. Certificate pinning defenses (developer side)
Pin to **SPKI public-key hashes** (survives cert rotation when key
stays). Pin to **intermediate CA** for resilience to leaf rotation
(less resilient to CA compromise). **Dynamic pinning** fetches signed
pin manifest on first run. Always ship a **backup pin**. Monitor
**Certificate Transparency** logs server-side. iOS supports declarative
pinning via `NSPinnedDomains` (iOS 14+); Android via
`network-security-config.xml` `<pin-set>`.

### 4. Charles Proxy / Proxyman
GUI-friendly Burp alternatives for mobile traffic capture, aimed at
non-security developers. Same cert-install pattern; same pinning-
bypass limitations.

---

## XII. Baseband and Radio Attack Surface

### 1. Cellular baseband as a separate trust domain
A modern smartphone has at least two CPUs: **AP** (Application
Processor, running iOS/Android) and **BP** (Cellular Baseband
Processor, running its own RTOS — Qualcomm Modem OS, Samsung Shannon,
MediaTek, Intel XMM). BP handles IMSI auth, RRC, NAS, mobility, voice,
SMS, packet data. BP is reachable directly from any cellular base
station, without AP involvement. Baseband RCE compromises BP; AP-BP
interface (or BP DMA on poorly designed SoCs) provides pivot.
Reference:
[Comsecuris — Path of Least Resistance](https://comsecuris.com/blog/posts/path_of_least_resistance/).

### 2. 2G/3G/4G/5G protocol exploitation
**IMSI catchers / Stingrays** impersonate the network for IMSI
collection + encryption downgrade. **2G downgrade attacks** force
4G/5G fallback to A5/0 or A5/1. **TASZK / Komaromy chains** on
Samsung Exynos, MediaTek, Qualcomm documented through hardwear.io
(Basebandheimer 2023) and OffensiveCon trainings (2024/2025). **5G
AKA / N1** has its own surface — weaker than 4G in some specs,
hardened in others.

### 3. "Breaking Band" (Komaromy / Golde, Recon 2016)
Canonical public RE of Samsung Shannon baseband. Established that the
baseband image is loadable, disassemblable (ARM Cortex-R), and
auditable for memory corruption. Won Mobile Pwn2Own with an OTA RCE
against Samsung S6 baseband. Reference:
[comsecuris.com slides](https://comsecuris.com/slides/recon2016-breaking_band.pdf).

### 4. Bluetooth LE attacks
**BlueFrag** (CVE-2020-0022, Android Bluetooth daemon L2CAP RCE),
**BleedingTooth** (CVE-2020-12351, BlueZ kernel RCE), **KNOB**
(CVE-2019-9506, key negotiation forces 1-byte keys), **BIAS** (auth
bypass during reconnection), **BLE GATT misuse** (write characteristics
without auth — canonical "smart lock unlockable in BT range" finding
class).

### 5. Wi-Fi
**FragAttacks** (Vanhoef 2021, frame agg/frag flaws across all Wi-Fi),
**KRACK** (Vanhoef 2017, WPA2 KRA), **WPA2-PSK offline crack**
(handshake capture + brute-force), **Kr00k** (CVE-2019-15126, Broadcom/Cypress
chips encrypt buffered frames with an all-zero key after
disassociation).

### 6. AirDrop / AWDL / Wi-Fi Aware
AirDrop runs over AWDL (Apple Wireless Direct Link). Ian Beer's 2020
"radio proximity exploit odyssey" exploited an AWDL kernel handler
buffer overflow — remote 0-click kernel RCE to anyone in Wi-Fi range.
Wi-Fi Aware is the cross-platform standard analog, also implemented
on Android. Reference:
[projectzero.google — radio proximity exploit](https://projectzero.google/2020/12/an-ios-zero-click-radio-proximity.html).

### 7. The "five radios" reality
Cellular, Wi-Fi, Bluetooth, NFC, UWB, GPS (passive), sometimes
satellite. Each is a distinct trust boundary with its own firmware,
driver, and attack history. Threat modeling that focuses only on
cellular underestimates the surface by ~5×.

---

## XIII. Mobile MASVS / OWASP MAS — The Testing Standard

### 1. MASVS v2 overview
OWASP Mobile Application Security Verification Standard v2 defines the
global control framework. v2.0.0 (April 2023) removed the legacy
verification-level system in favor of **MAS Testing Profiles**; v2.1.0
(January 2024) added the **MASVS-PRIVACY** control group as a response
to converging privacy and security regulatory pressure (EU CRA, US
state privacy laws, sectoral mandates). Lead authors: Bernhard Mueller,
Sven Schleier, Jeroen Willemsen, Carlos Holguera.
Reference:
[mas.owasp.org/MASVS](https://mas.owasp.org/MASVS/),
[MASVS v2.1 release notes](https://mas.owasp.org/news/2024/01/18/masvs-v210-release--masvs-privacy/).

### 2. Seven control groups
| Code | Group | Examples |
|---|---|---|
| **STORAGE** | Sensitive data | Keychain class, EncryptedSharedPreferences, no PII in logs |
| **CRYPTO** | Cryptography | Strong algorithms, no hardcoded keys, hardware-backed |
| **AUTH** | Authentication / session | OAuth2, MFA, biometric integration |
| **NETWORK** | Network communication | TLS 1.2+, cert pinning, no cleartext |
| **PLATFORM** | Platform interaction | IPC, deep links, WebView, paste, sharing |
| **CODE** | Code quality / build | Updated SDKs, no dev settings in prod, signed builds |
| **RESILIENCE** | Anti-RE | Obfuscation, jailbreak/root detection, anti-debug, anti-hook |

### 3. MAS Testing Profiles (post-v2.0 — replaces L1/L2/R)
v2.0+ replaced the three verification levels with **MAS Testing
Profiles** layered on top of the eight control groups. The legacy
levels (L1, L2, L1+R) remain widely used as shorthand in
procurement language and pentest reports, and v2 controls retain
clear lineage; the conceptual map is: L1 ≈ baseline-app profile,
L2 ≈ sensitive-data profile, R ≈ resilience overlay. The mapping is
informal; new programs should adopt the profile vocabulary directly.

### 4. MASTG — the operational playbook (v1.7+)
Mobile Application Security Testing Guide: practical how-to for each
MASVS control. Mueller wrote the reverse-engineering chapter
primarily. Ships with reference test apps (iGoat-Swift iOS,
MASTG-Hacking-Playground Android) for hands-on practice. MASTG
ships per-control test scripts in `.md` + frida-`.js` form, kept
current via the OWASP MAS GitHub. Releases are versioned independently
from MASVS; v1.7+ aligns with MASVS v2.1.

### 4a. MASWE — Mobile App Security Weakness Enumeration (July 2024)
**MASWE** is the third pillar of OWASP MAS, added July 2024. It sits
between MASVS controls (high-level "what") and MASTG tests
(operational "how") with a granular **weakness taxonomy** — analogous
to CWE for mobile, scoped to the MASVS namespace. Each MASWE entry
maps to one or more MASVS controls and to one or more MASTG tests,
giving a stable identifier for cataloguing findings across pentest
engagements. Reference:
[OWASP MASWE](https://mas.owasp.org/MASWE/).

### 5. Applying MASVS in practice
Pull app from store + decrypt → MOBSF + jadx/IDA static pass → Frida
hook NETWORK/CRYPTO/STORAGE/AUTH boundaries → Burp + pinning bypass +
endpoint map → tamper APK/IPA + resign + re-run → test PLATFORM
surface → map findings to MASVS L1/L2 controls.

### 6. Regulatory adoption
**App Defense Alliance MASA** (independent assessment against MASVS
Level 1 controls, surfaced as a badge on Google Play listings)
references MASVS as the underlying standard. Materially different from earlier
educational frameworks like OWASP Mobile Top 10.

---

## XIV. Mobile Zero-Day Economy

### 1. The vendor ecosystem
The principal commercial offensive-spyware vendors targeting mobile:

| Vendor | HQ | Flagship product | Status (2026) |
|---|---|---|---|
| **NSO Group** | Israel | Pegasus | Active; US sanctions list (Entity List 2021); 2024 Jordan campaign + ongoing civil-society targeting documented |
| **Cytrox / Intellexa Alliance** | Greece / Macedonia / Cyprus | Predator | Active; US Treasury sanctions on Intellexa Alliance March 2024; continued operations through 2025 |
| **Candiru / Saito Tech** | Israel | DevilsTongue | Active; US Entity List |
| **Paragon Solutions** | Israel | Graphite | Active; CVE-2025-43200 iOS zero-click confirmed June 2025; targeted European journalists |
| **QuaDream** | Israel | REIGN / KingsPawn | Shut down April 2023 (Citizen Lab disclosure) |
| **Variston IT** | Spain | (Heliconia spyware kit + 0-day brokering) | Shut down February 2024 per multiple reports |
| **Cellebrite** | Israel | UFED + Premium | Active; physical-extraction primarily |
| **MSAB** | Sweden | XRY | Active; physical-extraction |
| **Magnet Forensics** | Canada | GrayKey (merged with Grayshift 2023) | Active; partial iOS 18 access claimed |
| **L3Harris / Linchpin Labs** | Western | (undisclosed) | Active; AzimuthSecurity heritage |

**Paragon Graphite** (added 2025) is the most consequential post-NSO
entrant. Founded by ex-Unit-8200 leadership; the June 2025 Citizen
Lab disclosure (CVE-2025-43200, iCloud-Link photo-processing
zero-click, iOS 18.3.1 patch) is the first public forensic
confirmation. Targets matched the historical Pegasus/Predator
victim profile (journalists, civil society). The chain demonstrates
that the Pegasus/FORCEDENTRY/BLASTPASS lineage of "iMessage-adjacent
zero-click on crafted media" continues to yield productive surface
even with Lockdown Mode and BlastDoor in place; Apple's patch
cadence (Feb 10 patch, June 11 disclosure) is the new attribution
window standard.

**Forensic-tool capabilities (leaked 2024 support documents):**
Cellebrite's April 2024 matrix listed iOS 17.4+ as "In Research" and
no brute-force on powered-off Pixel 6/7/8; GrayKey's November 2024
documents showed only partial access on iOS 18/18.0.1. Cellebrite's
leaked documents also indicated no access to GrapheneOS devices updated
since late 2022 — a useful data point for high-risk-user threat models.

### 2. Cytrox Predator chain corpus
Key references: 2021 — first Citizen Lab disclosure of Predator on a
doubly-Pegasus+Predator-infected iPhone
([Citizen Lab](https://citizenlab.ca/2021/12/pegasus-vs-predator-dissidents-doubly-infected-iphone-reveals-cytrox-mercenary-spyware/));
2023 — Predator Files / Talos technical deep-dive
([Talos](https://blog.talosintelligence.com/mercenary-intellexa-predator/),
[Amnesty](https://securitylab.amnesty.org/latest/2023/10/technical-deep-dive-into-intellexa-alliance-surveillance-products/))
— ALIEN loader + PREDATOR implant architecture; multiple Chrome /
Android (CVE-2021-37973 et al.) and iOS chains throughout 2023.

### 3. Pricing tiers (public-reporting estimates, 2024 update)
Crowdfense's April 2024 acquisition program announcement repriced
the public market upward by 2–3× over its 2019 numbers, reflecting
the rising cost of mitigation-stack-aware chains. Public figures:

| Product | 2019 (Crowdfense) | 2024 (Crowdfense + reporting) |
|---|---|---|
| iOS zero-click full chain | $3M | **$5M–$7M** (and a separate $9M tier for SMS/MMS zero-click) |
| Android zero-click full chain (Pixel-class) | $3M | **$5M** |

Subsequent reporting documented an August 2025 zero-day startup
(Advanced Security Solutions) advertising
up to **$20M for "tools that can hack any smartphone"**, indicating
continued upward pressure on the full-chain tier as Lockdown Mode and
MIE further raise reliable-chain construction cost. PAC (A12),
SPTM/TXM (A15+), MIE/EMTE (A19+), Lockdown Mode each raised iOS
prices; OEM patching cadence, Mainline, GKI, and MTE-on-Pixel each
raised Android prices over the same period. Reference:
[SecurityWeek — Crowdfense $30M program](https://www.securityweek.com/company-offering-30-million-for-android-ios-browser-zero-day-exploits/),
[TechCrunch — Zero-day prices rise as products harden (2024)](https://techcrunch.com/2024/04/06/price-of-zero-day-exploits-rises-as-companies-harden-products-against-hackers/),
[TechCrunch — $20M smartphone-hack offer (Aug 2025)](https://techcrunch.com/2025/08/20/new-zero-day-startup-offers-20-million-for-tools-that-can-hack-any-smartphone/).

### 4. Brokered markets
**Zerodium** (Western, public price list), **Crowdfense** (UAE,
similar model), Chinese-sphere brokers (less visible; Tianfu Cup
outputs believed to flow this way), Russian-sphere brokers. Public-
disclosure paths (Pwn2Own/ZDI, Apple Security Bounty, Android
Security Rewards) compete economically — bounty payouts have risen
materially over the past decade.

### 5. Defensive deterrents
**Apple Lockdown Mode** (iOS 16+, §XV), **Google Advanced
Protection Program** (hardware key + reduced 3rd-party access),
**Apple Threat Notifications** (mercenary-spyware-targeting alert),
**Citizen Lab / Amnesty Tech / Access Now Digital Security Helpline**
(civil society support and forensics).

### 6. The targeting reality
Citizen Lab's case load documents the consistent pattern: journalists,
human rights defenders, opposition politicians, dissidents-in-exile,
their lawyers, their family members. The "only used against
terrorists" narrative is not supported by any public forensic record.

---

## XV. Defensive Patterns

### 1. Don't ship secrets in the binary
Static analysis finds embedded API keys in seconds; any reverse-engineer
has them forever, and rotation requires an app update. Use OAuth2/OIDC
user-auth flows (no app-bound secret), backend-issued short-lived
tokens gated on device attestation (Apple App Attest, Play Integrity
API), or Firebase Remote Config style signed-fetch scoped to user auth.
For per-device secrets, generate at first launch and store in
Keychain/KeyStore.

### 2. Pin certificates, plan for rotation
Pin to SPKI public-key hashes (not full certs). Always ship a backup
pin. Have a documented rotation process; non-rotated pinned apps go
dark when the cert expires.

### 3. KeyChain / KeyStore best practices
- **iOS:** prefer `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`;
  use `kSecAttrAccessControl` with biometric requirement for
  high-value secrets; never use `kSecAttrAccessibleAlways`.
- **Android:** prefer StrongBox (`setIsStrongBoxBacked(true)`) on
  capable devices; require user auth per-use for signing keys;
  `EncryptedSharedPreferences` for preference data.

Cross-link `cryptography_expertise.md` §IV.

### 4. WebView discipline
Disable JavaScript unless required. Disable `file://` access
(`setAllowFileAccess(false)` and friends on Android). Restrict the JS
bridge to a minimum capability surface; annotate every Android bridge
method with `@JavascriptInterface`. Validate WebView URLs against an
allowlist; never `evaluateJavaScript:` with untrusted input.

### 5. Deep-link verification
iOS: Universal Links with strict AASA; avoid custom URL schemes for
sensitive actions. Android: App Links with `autoVerify="true"` and
Digital Asset Links; avoid `exported="true"` unless required. Both:
never treat deep-link parameters as authenticated.

### 6. Runtime integrity ("when not if")
Root/jailbreak/Frida detection raises the bar; it doesn't stop a
determined attacker. The right posture: detect-and-log to backend
with attestation metadata; **server-side enforcement** of every
security-relevant decision; reduce client-side trust; use Play
Integrity / App Attest as the authoritative attestation source.

### 7. Server-side enforcement
Never trust client checks. "If not Premium, hide" on the client is
bypassable; "if not Premium, the backend won't serve" is not.

### 8. Hardening for high-risk users
For journalists, dissidents, executives, high-value targets:

**Apple Lockdown Mode** (iOS 16+, evolution through iOS 18) disables
arbitrary attachment types in Messages (the WebP/JBIG2 lineage),
Safari JIT, configuration profiles, Wi-Fi auto-join, FaceTime from
non-contacts, incoming shared albums. iOS 17 added further
protections; **iOS 18.1 added the
inactivity-reboot timer**, for all devices rather than only Lockdown Mode (after 72 hours locked the device
auto-reboots, returning it to before-first-unlock state where
keybag-protected data is unrecoverable without the passcode — a
direct counter to forensic-tool extraction). Apple's public position
remained through 2026: no Lockdown Mode device has been
compromised by mercenary spyware to date.
[Apple — About Lockdown Mode](https://support.apple.com/en-us/105120),
[AppleInsider — Lockdown Mode 100% protection claim](https://appleinsider.com/articles/26/03/27/apple-claims-a-100-protection-rate-with-iphone-lockdown-mode).

**Stolen Device Protection (SDP, iOS 17.3+)** is a separate, broader-
population control aimed at the "shoulder-surfed passcode + grab and
walk" threat model rather than zero-click spyware. SDP keys
high-impact operations (saved passwords and passkeys, Safari AutoFill
payment methods, Lost Mode disable, erase all content and settings,
new-device setup)
to **biometric-only authentication with no passcode fallback** when
the device is away from Frequent Locations. Sensitive operations
additionally require a **one-hour security delay** plus a second
biometric. The Frequent-Locations dependency means SDP is a *familiar-
location-trust* model, not a strict deny-list; forensic-tool
implications are non-trivial (a tool that re-enters a familiar
location avoids the biometric-only gate). References:
[Apple — About Stolen Device Protection](https://support.apple.com/en-us/120340),
[ElcomSoft — Forensic Implications of SDP](https://blog.elcomsoft.com/2025/03/forensic-implications-of-apples-stolen-device-protection/).

**Google Advanced Protection Program** + hardware security key.
**Android Identity Check** (Android 15+, opt-in, rolled out January 2025) — biometric-only
gate on changing PIN, disabling theft protection, accessing Passkeys
from untrusted locations; the closest Android peer to iOS SDP.

**MVT (Mobile Verification Toolkit)** for periodic backup forensics —
[mvt.re](https://mvt.re/),
[mvt-project/mvt](https://github.com/mvt-project/mvt). Disable
unnecessary radios (BT off when unused; airplane mode in sensitive
environments). Operational separation between sensitive-comms and
personal devices.

### 9. AppSec program integration
Mobile-app security belongs in the broader AppSec program — cross-link
`appsec_program_building_expertise.md` §4. Critical interfaces: build
pipeline integration (MOBSF in CI, pre-merge MASVS gates), SDK
governance (third-party supply-chain — `cicd_supply_chain_expertise.md`),
IR runbook for mobile-app compromise (signing-key rotation, push-cert
rotation, OTA forced update).

### 10. Detection on the defender side
Mobile EDR is constrained by iOS sandbox; Android EDR is more capable.
MDM (Jamf, Intune, Workspace ONE) provides posture for managed devices.
Unmanaged BYOD defenders rely mostly on server-side anomaly detection
(impossible-travel auth, endpoint-call patterns). Cross-link
`detection_engineering_expertise.md`.

### 11. Code-review checklist (mobile-specific, 15 items)
1. URL schemes / deep links validated for params and auth state?
2. Sensitive actions registered as Universal Links / App Links
   (not custom schemes)?
3. JS-bridge methods explicitly allowlisted and
   `@JavascriptInterface`-annotated?
4. JavaScript disabled in WebViews where not required?
5. `file://` and cross-origin access disabled in WebViews?
6. WebView-loaded URLs validated against an allowlist?
7. Keychain/KeyStore items stored at the strongest compatible
   accessibility class?
8. Biometric auth required per-use for high-value crypto keys?
9. ATS / NetworkSecurityConfig enforced (no arbitrary loads,
   no cleartext)?
10. Pinning via SPKI hashes with a rotation plan?
11. Exported Android components explicitly justified;
    `exported` declared on every component?
12. PendingIntents declared `FLAG_IMMUTABLE` unless mutability
    required?
13. ContentProvider query / openFile paths sanitized against SQLi
    and path traversal?
14. Sensitive data excluded from system logs and crash reports?
15. Device-attestation (App Attest / Play Integrity) checks
    server-side, not client-side?

---

## XVI. Variant Analysis — Under-Explored

### 1. Smartphone AI assistant attack surface
Siri, Google Assistant, Bixby, and the new LLM-driven mobile assistants
(Apple Intelligence, Pixel Gemini) introduce a structurally novel
surface: **voice prompt injection** (audio from video/podcast/nearby
device containing assistant-targeted commands), **contextual prompt
injection** (Apple Intelligence reads incoming emails/messages/screen
to summarize and act — malicious content is prompt-injection material),
and **cross-app capability misuse** (assistant-driven calendar/message/
payment actions span a surface larger than any single app's). Largely
unaddressed by MASVS/MASTG as of 2026. Cross-link
`llm_agent_security_expertise.md` for the prompt-injection taxonomy
(recently deepened) and `adversarial_ml_model_security_expertise.md`
for adversarial-input grounding.

### 1a. Apple Intelligence + Private Cloud Compute (PCC) architecture
Apple Intelligence (iOS 18+, announced WWDC 2024, ship-default on
A17 Pro / M-series capable devices) splits inference between **on-
device models** (3B-class, semantic search, response generation) and
**Private Cloud Compute** for queries exceeding on-device capacity.
PCC is the most public-research-friendly Apple cloud service ever
deployed; key technical commitments:

- **Stateless compute** — user data exists only for the request
  lifetime; per-request keys; no persistence post-response.
- **No privileged runtime access** — "no remote shell or interactive
  debugging mechanisms"; production-staff cannot bypass.
- **Non-targetability** — "an attacker should not be able to attempt
  to compromise personal data that belongs to specific, targeted PCC
  users without attempting a broad compromise of the entire PCC
  system." Implemented via OHTTP relay (third-party-operated to hide
  source IP), RSA Blind Signatures for single-use credentials, and
  load-balancer subset returns without device identification.
- **Verifiable transparency** — Apple commits to publishing every
  production binary (OS, applications, sepOS firmware, iBoot
  bootloader in plaintext) to a tamper-proof append-only transparency
  log within 90 days of inclusion.
- **Virtual Research Environment (VRE)** — researcher-friendly tooling
  that boots a minimally-virtualization-modified PCC node on a Mac
  with Apple Silicon.

The Secure Enclave on each PCC node holds the per-request decryption
key; data volume encryption keys are randomized every reboot and not
persisted (cryptographic erasure across restarts). Client-device
attestation chain: device fetches signed list of valid PCC node
certificates → verifies measurement chain → encrypts to that subset
only.

The PCC threat model is roughly: "an attacker who fully compromises
one PCC node can decrypt only that node's small share of inbound
traffic; an attacker who wants to target a specific user must also
defeat the OHTTP relay, the blind-credential system, the load-
balancer subset auditing, the transparency log, and Apple's
attestation chain." Most public-research interest is on the
non-targetability claims; the **load-balancer subset audit** is
the load-bearing primitive most amenable to external verification.
Reference:
[Apple Security Research — Private Cloud Compute (June 2024)](https://security.apple.com/blog/private-cloud-compute/),
[Apple — PCC Security Guide](https://security.apple.com/documentation/private-cloud-compute),
[Apple — PCC security research](https://security.apple.com/blog/pcc-security-research/).

### 1b. Google Gemini Nano on-device LLM (Pixel)
Gemini Nano ships on-device starting Pixel 8 Pro (December 2023) and
Pixel 9 series; cloud-tier Gemini Pro/Ultra serves heavier queries.
The on-device model gates app-side capabilities through **AICore**
(privileged Android service) plus per-app entitlements. Attack
surface contour parallels Apple Intelligence but with a different
trust model: AICore mediates on-device queries; cross-cloud queries
flow through Google's broader ML serving infra (less public-research
exposure than PCC). The on-device cross-app function-calling surface
is the highest-leverage pivot: a Pixel-side prompt-injection through
Gemini that can fire `Send message`, `Create calendar event`, or
`Read screen` is structurally similar to Apple Intelligence's
cross-app surface. Mobile-specific defenses currently rest on
per-capability prompts; defense-in-depth is sparse. Reference:
[Android Developers — AICore](https://developer.android.com/ai/aicore),
[Google AI — Gemini Nano](https://ai.google.dev/gemini-api/docs/models/gemini#gemini-nano).

### 1c. On-device prompt-injection — emerging research surface
The on-device LLM attack-surface intersection with mobile-app sandbox:
(a) Mobile LLMs read app content (Mail, Messages, screen — Apple
Intelligence's "Visual Intelligence"; Pixel's "Circle to Search").
Untrusted content reaches a privileged model. (b) Function/tool
calling maps prompt-induced intents to mobile capabilities. (c)
Memory / context windows persist across sessions on some assistants.
Cross-link `llm_agent_security_expertise.md` (recently deepened
through 2026) and the on-device subset of
`agentic_web_capabilities_expertise.md` for tool-call surface
taxonomy; cross-link `confidential_computing_expertise.md` for the
TEE-equivalent reasoning on what PCC's "non-targetability" actually
buys vs. Intel SGX / AMD SEV-SNP cloud peers.

### 2. AI-generated app outputs
FlutterFlow, Bubble.io for mobile, AppGyver, and AI-driven code
generation (Cursor, Copilot Workspace, Claude Code) ship mobile apps
from natural-language specs with uneven security defaults: permissive
ATS/Network Security Config, over-broad exported/intent-filter posture,
software-backed keystore, rare Universal Links/App Links adoption.
Audit-of-generated-code is a productive emerging niche.

### 3. Foldable devices
Two displays / one device introduce surfaces unaddressed by MASVS:
fold-spanning activities (touch targets vs. visible content on
different surfaces — a "fold-jacking" extension of tap-jacking),
inner-vs-outer state-management bugs (auth prompts on the wrong
display), and posture-detection misclassifications that trigger
unauthorized UI changes.

### 4. AR/VR headset security
Apple Vision Pro (visionOS, XNU lineage — iOS mitigations apply) and
Meta Quest 3 (Android-derived — Android mitigations apply). Novel
surfaces: gaze tracking as biometric + intent channel, hand-tracking
gesture injection (accessibility-service-abuse analog), spatial deep
linking, and inter-user device hygiene (shared headsets). Limited
public exploit corpus as of 2026.

### 5. Wearable security
Apple Watch (watchOS — XNU + AMFI), Pixel Watch (Wear OS — Android),
Garmin/Fitbit. Smaller attack surface (fewer apps, limited cellular
on LTE variants, tight phone coupling) but high-value targets:
payments, health PII, second-factor auth. A compromised paired watch
is a different threat-model dimension than a compromised phone.

### 6. LLM-in-app surface
Apps embedding LLMs (Anthropic/OpenAI/Google/on-device) introduce an
instruction-execution boundary inside the app. Mobile-specific
concerns: on-device fine-tuning incorporating user data (privacy +
extraction-attack surface), tool/function calling mapped to mobile
capabilities (send message, create calendar event, transfer money —
now a prompt-injection-reachable capability surface), and emerging
MCP-equivalent mobile connectors. Cross-link
`llm_agent_security_expertise.md` §III/V/VII.

---

## XVII. References

### Primary research sources

**Citizen Lab** — research index
[citizenlab.ca/category/research/](https://citizenlab.ca/category/research/),
FORCEDENTRY,
[Great iPwn](https://citizenlab.ca/research/the-great-ipwn-journalists-hacked-with-suspected-nso-group-imessage-zero-click-exploit/),
[Pegasus vs Predator (2021)](https://citizenlab.ca/2021/12/pegasus-vs-predator-dissidents-doubly-infected-iphone-reveals-cytrox-mercenary-spyware/),
[Triple Threat 2022 chains](https://citizenlab.ca/2023/04/nso-groups-pegasus-spyware-returns-in-2022/).

**Project Zero** — Ian Beer
[radio proximity (2020)](https://projectzero.google/2020/12/an-ios-zero-click-radio-proximity.html);
Azad
[PAC on iPhone XS (2019)](https://projectzero.google/2019/02/examining-pointer-authentication-on.html);
[iOS kernel exploits survey (2020)](https://projectzero.google/2020/06/a-survey-of-recent-ios-kernel-exploits.html);
[In-the-Wild Chain 3 (2019)](https://googleprojectzero.blogspot.com/2019/08/in-wild-ios-exploit-chain-3.html);
[Blasting Past Webp (2025)](https://projectzero.google/2025/03/blasting-past-webp.html);
[Mind the Gap — Mali (2022)](https://projectzero.google/2022/11/mind-the-gap.html);
[Modern In-the-wild Android Exploit (2023)](https://projectzero.google//2023/09/analyzing-modern-in-wild-android-exploit.html);
[An iOS hacker tries Android (2020)](https://projectzero.google/2020/12/an-ios-hacker-tries-android.html).

**Kaspersky / Securelist** — Operation Triangulation
[The last (hardware) mystery](https://securelist.com/operation-triangulation-the-last-hardware-mystery/111669/),
[Coruna framework (2026)](https://securelist.com/coruna-framework-updated-operation-triangulation-exploit/119228/),
[Kaspersky 37C3 2023 talk recap](https://www.kaspersky.com/blog/triangulation-37c3-talk/50166/).

**Predator / Intellexa** — Talos
[Mercenary mayhem](https://blog.talosintelligence.com/mercenary-intellexa-predator/),
[Intellexa & Cytrox](https://blog.talosintelligence.com/intellexa-and-cytrox-intel-agency-grade-spyware/);
Amnesty Tech
[Predator Files deep-dive](https://securitylab.amnesty.org/latest/2023/10/technical-deep-dive-into-intellexa-alliance-surveillance-products/).

**Paragon Graphite (2025)** — Citizen Lab
[First forensic confirmation of Paragon's iOS spyware (June 2025)](https://citizenlab.ca/research/first-forensic-confirmation-of-paragons-ios-mercenary-spyware-finds-journalists-targeted/),
[Citizen Lab Pegasus index](https://citizenlab.ca/tag/pegasus/),
[Jordan-wide Pegasus campaign (Feb 2024)](https://citizenlab.ca/2024/02/confirming-large-scale-pegasus-surveillance-of-jordan-based-civil-society/).

**MTE / Pixel** —
[Project Zero — First handset with MTE on the market (2023)](https://projectzero.google/2023/11/first-handset-with-mte-on-market.html),
[GitHub Security Lab — Kernel code exec on MTE-enabled Pixel 8 (2024)](https://github.blog/security/vulnerability-research/gaining-kernel-code-execution-on-an-mte-enabled-pixel-8/),
[Android Developers — ARM MTE NDK guide](https://developer.android.com/ndk/guides/arm-mte),
[AOSP — ARM MTE](https://source.android.com/docs/security/test/memory-safety/arm-mte).

**iOS DMA / sideloading regime** —
[Apple Developer — DMA and apps in the EU](https://developer.apple.com/support/dma-and-apps-in-the-eu/),
[Apple Newsroom — DMA impacts on EU users (Sep 2025)](https://www.apple.com/newsroom/2025/09/the-digital-markets-acts-impacts-on-eu-users/),
[AltStore PAL FAQ](https://faq.altstore.io/altstore-pal/what-is-altstore-pal),
[The Apple Wiki — AltStore](https://theapplewiki.com/wiki/AltStore).

**Mobile zero-day economy (2024–2025)** —
[SecurityWeek — Crowdfense $30M program (April 2024)](https://www.securityweek.com/company-offering-30-million-for-android-ios-browser-zero-day-exploits/),
[TechCrunch — Zero-day prices rise (April 2024)](https://techcrunch.com/2024/04/06/price-of-zero-day-exploits-rises-as-companies-harden-products-against-hackers/),
[TechCrunch — $20M smartphone-hack tools (Aug 2025)](https://techcrunch.com/2025/08/20/new-zero-day-startup-offers-20-million-for-tools-that-can-hack-any-smartphone/),
[Group-IB — Patch Me If You Can (Cellebrite leak analysis)](https://www.group-ib.com/blog/patch-me-if-you-can/),
[ElcomSoft — Forensic Implications of SDP](https://blog.elcomsoft.com/2025/03/forensic-implications-of-apples-stolen-device-protection/).

**Android banking trojans (2024–2025)** —
[The Hacker News — Anatsa via Google Play (July 2025)](https://thehackernews.com/2025/07/anatsa-android-banking-trojan-hits.html),
[Cleafy — ToxicPanda technical analysis](https://www.cleafy.com/cleafy-labs/toxicpanda-a-new-banking-trojan-from-asia-hit-europe-and-latam),
[The Hacker News — ToxicPanda (Nov 2024)](https://thehackernews.com/2024/11/new-android-banking-malware-toxicpanda.html),
[The Hacker News — SoumniBot manifest obfuscation (April 2024)](https://thehackernews.com/2024/04/new-android-trojan-soumnibot-evades-detection.html),
[The Hacker News — TgToxic variant evolution (Feb 2025)](https://thehackernews.com/2025/02/new-tgtoxic-banking-trojan-variant.html).

**Apple Platform Security** —
[Platform Security Guide](https://support.apple.com/guide/security/welcome/web),
[OS integrity (PAC/KTRR/SPTM/TXM)](https://support.apple.com/guide/security/operating-system-integrity-sec8b776536b/web),
[Pointer Authentication Codes](https://support.apple.com/guide/security/pointer-authentication-codes-seca5759bf02/web),
[About Lockdown Mode](https://support.apple.com/en-us/105120),
[About Stolen Device Protection](https://support.apple.com/en-us/120340).

**Apple Security Research (2024–2025)** —
[Memory Integrity Enforcement (Sep 2025)](https://security.apple.com/blog/memory-integrity-enforcement/),
[Private Cloud Compute (June 2024)](https://security.apple.com/blog/private-cloud-compute/),
[PCC Security Guide](https://security.apple.com/documentation/private-cloud-compute),
[PCC security research expansion](https://security.apple.com/blog/pcc-security-research/),
[Secure your app with MIE — WWDC/Meet with Apple](https://developer.apple.com/videos/play/meet-with-apple/206/).

**Android source** —
[Binder IPC](https://source.android.com/docs/core/architecture/hidl/binder-ipc),
[Security Bulletin archive](https://source.android.com/docs/security/bulletin).

**checkm8 / ziVA / Frida** —
[ipwndfu](https://github.com/axi0mX/ipwndfu),
[Apple Wiki — checkm8](https://theapplewiki.com/wiki/Checkm8_Exploit),
[CERT VU#941987](https://www.kb.cert.org/vuls/id/941987/);
[doadam/ziVA](https://github.com/doadam/ziVA),
[Zimperium ziVA blog](https://zimperium.com/blog/ziva-video-audio-ios-kernel-exploit);
[frida.re](https://frida.re/),
[NowSecure Frida](https://www.nowsecure.com/frida/),
[Ravnås talks](https://slides.com/oleavr),
[Frida Handbook](https://academy.nowsecure.com/the-frida-handbook),
[Frida 17.0.0 release notes (May 2025)](https://frida.re/news/2025/05/17/frida-17-0-0-released/),
[Frida 17.4.0 — simmy backend for Apple simulator (Oct 2025)](https://frida.re/news/2025/10/12/frida-17-4-0-released/),
[Frida 17.5.0 — Swift overhaul (Nov 2025)](https://frida.re/news/2025/11/04/frida-17-5-0-released/).

**OWASP MAS** —
[mas.owasp.org](https://mas.owasp.org/),
[MASVS](https://mas.owasp.org/MASVS/),
[MASTG](https://mas.owasp.org/MASTG/),
[MASWE — Mobile App Security Weakness Enumeration](https://mas.owasp.org/MASWE/),
[MASVS v2.1.0 release + MASVS-PRIVACY (Jan 2024)](https://mas.owasp.org/news/2024/01/18/masvs-v210-release--masvs-privacy/),
[2024 news archive](https://mas.owasp.org/news/archive/2024/),
[project page](https://owasp.org/www-project-mobile-app-security/).

**Baseband (Komaromy)** —
[comsecuris.com](https://comsecuris.com/),
["Breaking Band" Recon 2016](https://comsecuris.com/slides/recon2016-breaking_band.pdf),
[Path of Least Resistance](https://comsecuris.com/blog/posts/path_of_least_resistance/),
[BH USA 2021 5G baseband OTA RCE (Grassi & Chen, Keen Lab)](https://i.blackhat.com/USA21/Wednesday-Handouts/us-21-Over-The-Air-Baseband-Exploit-Gaining-Remote-Code-Execution-On-5G-Smartphones.pdf),
[Basebandheimer hardwear.io 2023](https://hardwear.io/netherlands-2023/speakers/daniel-komaromy.php).

**MVT / Amnesty Tech** —
[mvt-project/mvt](https://github.com/mvt-project/mvt),
[mvt.re](https://mvt.re/),
[Pegasus forensic methodology](https://www.amnesty.org/en/latest/research/2021/07/forensic-methodology-report-how-to-catch-nso-groups-pegasus/),
[NoviSpy AndroidQF guide (2024)](https://securitylab.amnesty.org/latest/2024/12/tech-guide-detecting-novispy-spyware-with-androidqf-and-the-mobile-verification-toolkit-mvt/).

**Tooling** —
[apktool](https://github.com/iBotPeaches/Apktool),
[jadx](https://github.com/skylot/jadx),
[Objection](https://github.com/sensepost/objection),
[r2frida](https://github.com/nowsecure/r2frida),
[Magisk](https://github.com/topjohnwu/Magisk),
[MOBSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF),
[SSL Kill Switch 2](https://github.com/nabla-c0d3/ssl-kill-switch2),
[frida-android-unpinning](https://github.com/httptoolkit/frida-android-unpinning),
[Pixel GPU Exploit](https://github.com/0x36/Pixel_GPU_Exploit),
[Trigon iOS kernel writeup](https://alfiecg.uk/2025/03/01/Trigon.html).

**Tihmstar / Pangu / Wardle / Demirkapi** —
[Tihmstar](https://github.com/tihmstar),
[ra1nsn0w](https://github.com/tihmstar/ra1nsn0w),
[Pangu](https://en.pangu.io/),
[Objective-See](https://objective-see.org/about.html),
[Mac Admins iOS episode (Apr 2026)](https://podcast.macadmins.org/2026/04/08/episode-456-patrick-wardle-on-ios-security),
[billdemirkapi.me](https://billdemirkapi.me/).

### Cross-references to sibling expertise docs in this repository
- `macos_apple_security.md` — XNU kernel, code signing, AMFI, Objective-See lineage; iOS shares XNU + WebKit (recently deepened with 2024–2026 currency)
- `macos_memory_corruption_investigation.md` — heap-spray + binary-format surgery applicable to iOS Mach-O exploitation
- `linux_kernel_exploitation_expertise.md` — Android kernel = Linux kernel; same primitive taxonomy
- `browser_js_engine_exploitation_expertise.md` — WKWebView (iOS) and WebView (Android) inherit JSC / V8 exploitation
- `xml_parser_differential_expertise.md` — iOS plist parsing, Android XML parsing, SoumniBot Android-manifest-parser obfuscation
- `firmware_embedded_security.md` — baseband + bootloader; SoC firmware threat model
- `cryptography_expertise.md` — Keychain / KeyStore best practices, cert pinning
- `detection_engineering_expertise.md` — mobile telemetry + EDR posture
- `vulnerability_research_methodology_expertise.md` — surface enumeration on mobile binaries
- `llm_agent_security_expertise.md` — assistant prompt injection, LLM-in-app, on-device-AI tool-call surface (recently deepened)
- `adversarial_ml_model_security_expertise.md` — on-device model adversarial input + extraction attack surface (recently deepened)
- `agentic_web_capabilities_expertise.md` — tool-call surface taxonomy applicable to Apple Intelligence + Gemini Nano cross-app capabilities
- `confidential_computing_expertise.md` — TEE-equivalent reasoning for PCC's non-targetability claims vs. SGX / SEV-SNP cloud peers
- `appsec_program_building_expertise.md` — mobile-app team as AppSec stakeholder
- `cicd_supply_chain_expertise.md` — mobile SDK supply chain
- `code_review_expertise.md` — auditor heuristics applied to mobile binaries
