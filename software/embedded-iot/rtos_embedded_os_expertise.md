# Real-Time Operating Systems and Embedded OS Security
## Staff-Level Technical Reference

---

This document is the OS-layer companion to `firmware_embedded_security.md`. The
parent doc covers the hardware substrate — firmware acquisition, bootloader
manipulation, JTAG/SWD, glitching, decap. This one focuses on what runs on top
of that substrate: the kernels, schedulers, protocol stacks, and update
mechanisms that ship inside billions of devices. Both are required reading for
embedded review work; this one assumes the parent's material.

Cross-links: `firmware_embedded_security.md` (parent — hardware substrate);
`linux_kernel_exploitation_expertise.md` (embedded Linux kernel side);
`ics_ot_security_expertise.md` (RTOS in industrial deployments);
`automotive_security_expertise.md` (AUTOSAR Classic = RTOS); `fuzzing_discipline_expertise.md`
(RTOS fuzzing harnesses); `race_conditions_concurrency_expertise.md`
(interrupt-handler races); `supply_chain_provenance_expertise.md` (embedded
SBOM, VEX/CSAF); `detection_engineering_expertise.md` (network-layer detection
for unmanageable endpoints); `llm_agent_security_expertise.md` (agents on
constrained devices).

---

## I. Researcher Profiles

### Ang Cui — Red Balloon Security

Already profiled in `firmware_embedded_security.md` (parent). Cui's relevance to
RTOS work specifically: the Symbiote injection technique demonstrated on Cisco
IOS, Cisco IP phones, and HP LaserJet firmware operates against proprietary
single-address-space embedded OSes without source code or vendor cooperation.
The Stepping P3wns demonstration (DEF CON 21, 2013) showed cross-product RTOS
firmware-worm propagation between Cisco VoIP, Cisco IOS routers, and HP printers
— the canonical proof that one RTOS-class bug cascades into multi-product blast
radius. Thrangrycat (CVE-2019-1649, 2019) targets the FPGA bitstream of Cisco's
Trust Anchor module beneath the RTOS, but the practical exploitation chain
flows through the RTOS layer to deliver the modified bitstream. See parent doc
Section I and Section IV for full Cui treatment.

### Jos Wetzels — Forescout Vedere Labs

Security researcher at Forescout (formerly SecurityMatters, acquired
2018). Co-author of RFC 9267 ("Common
Implementation Anti-Patterns Related to DNS RR Processing") codifying
embedded-DNS lessons from NAME:WRECK. Co-author across all five Project
Memoria phases.

Research arc: embedded TCP/IP stack research → multi-vendor coordinated
disclosure → standards codification → OT product security review →
post-compromise OT lateral movement.

Key disclosures (co-authored with dos Santos, Dashevskyi, Amri):
- **AMNESIA:33** (Dec 2020) — 33 CVEs across uIP / picoTCP / FNET /
  Nut-Net / Contiki uIP.
- **NUMBER:JACK** (Feb 2021) — 9 TCP ISN-generation CVEs.
- **NAME:WRECK** (Apr 2021, with JSOF) — 9 DNS CVEs across FreeBSD,
  Nucleus NET, IPnet, NetX.
- **INFRA:HALT** (Aug 2021, with JFrog) — 14 CVEs in HCC NicheStack.
- **NUCLEUS:13** (Nov 2021) — 13 CVEs in Siemens Nucleus NET (~3 billion
  devices: medical imaging, industrial).
- **OT:ICEFALL** (Jun 2022) — 56 CVEs across 10+ OT vendors (Emerson,
  Honeywell, Motorola, Omron, Yokogawa, JTekt, Bently Nevada, Phoenix
  Contact, Siemens); "insecure by design" classification.

Tools: project-memoria-detector
(github.com/Forescout/project-memoria-detector) — TCP/IP stack
fingerprinting with detection signatures for 16 embedded stacks (uIP/Contiki,
picoTCP, Nut/Net, FNET, Nucleus NET, CycloneTCP, NDKTCPIP, uC/TCP-IP,
MPLAB Harmony Net, NicheStack, FreeBSD, Microsoft ThreadX, CMX TCP/IP,
emNet, Keil TCP/IP, lwIP).

### Daniel dos Santos — Forescout Vedere Labs (Head of Research)

PhD computer science (Trento, formal access control). Head of Research
at Forescout Vedere Labs. 35+ peer-reviewed publications; hundreds of
disclosed CVEs. Speaker at S4, Black Hat, DEF CON, RSA, FIRST.

Research arc: formal access control → all five Project Memoria phases →
OT:ICEFALL (head researcher; quantified that 74% of vulnerable OT
product families carried some form of security certification) →
**Sierra:21** (Dec 2023, 21 CVEs in Sierra Wireless AirLink + TinyXML +
OpenNDS; 86,000+ exposed devices, <10% patched) → solar power
infrastructure risk (2025) → annual "Riskiest Connected Medical Devices"
report.

### Stanislav Dashevskyi — Forescout Vedere Labs (Principal Researcher)

PhD Trento (2017, "Security Assessment of Open Source Third-Parties
Applications"). 100+ disclosed CVEs. Personal site: standash.github.io.
Tools: TestREx (repeatable-exploit framework); co-author
project-memoria-detector.

Key paper: "How Embedded TCP/IP Stacks Breed Critical Vulnerabilities"
(Black Hat EU 2020, with Wetzels and dos Santos) — argues structural
similarity across embedded TCP/IP stacks creates a class-of-bug landscape
that scales better through structural analysis than per-stack auditing.
Co-author all five Project Memoria phases; "A Screening Test for
Disclosed Vulnerabilities in FOSS Components" (IEEE TSE); "Dissecting
Android Cryptocurrency Miners."

### Zachary Cutlip

Worked with NSA since 2003. Senior researcher at Tactical Network
Solutions (TNS). GitHub: github.com/zcutlip.

Tool: **Bowcaster** — Python exploit-dev framework focused on MIPS (which
dominates SOHO routers: Atheros AR7240, Ralink RT3050,
Mediatek MT76xx). Payload encoders, connect-back servers, ROP gadgets,
SQLi-to-MIPS-buffer-overflow bridge.

Key talks: "From SQL Injection to MIPS Overflows: Rooting SOHO Routers"
(Black Hat USA 2012) — established the SOHO router playbook on Netgear
gear; D-Link DSP-W215 +
DIR-815 (2014 Rapid7 update integrated Cutlip's modules into Metasploit);
"Reversing and Exploiting BT CPE Devices" (44CON 2013).

### Brian Gorenc — Trend Micro Zero Day Initiative (VP, Threat Research)

VP of Threat Research at Trend Micro; leads ZDI since 2012. Organizes
and adjudicates Pwn2Own.

**Pwn2Own Miami** (2020+, S4 Conference) — first ICS Pwn2Own track.
Categories: Control Server (Iconics Genesis64, Ignition), OPC UA Server
(Unified Automation, Softing, OPC Foundation .NET Standard), DNP3
Gateway, HMI (AVEVA Edge), Engineering Workstation Software.
**Pwn2Own Automotive** (2024+, Tokyo) — Tesla, EV charging, IVI, often
running embedded Linux or QNX.

ZDI is the primary commercial pipeline for 0-days in proprietary
RTOS-based products (HMIs, PLCs, gateways, medical, infotainment).
Per-CVE advisory model complements Forescout's blog-plus-CVE-block model.

### Yannay Livneh

Researcher at Enigmatos; previously Checkpoint and Israeli national
service. Linux internals, low-level vulns, embedded devices. Published
at PoC||GTFO, CCC, HITCON.

### Ben Seri — Armis Security (VP, Research)

VP of Research at Armis. Lead researcher on URGENT/11 (July 2019, 11
CVEs in VxWorks IPnet TCP/IP, six critical RCE, ~2 billion devices).
Earlier: BlueBorne (Bluetooth RCE on Android/Linux, 2017) — established
the methodology of mass-disclosure of latent platform-level
vulnerabilities via a single shared component. Subsequent analysis
showed IPnet had been inherited from Interpeak (acquired by Wind River
2006); IPnet also shipped in OSE (Enea), INTEGRITY (Green Hills), ThreadX
(Microsoft / Azure RTOS), and others — making URGENT/11 a
shared-supply-chain disclosure crossing RTOS vendor boundaries.

### Microsoft Section 52 (BadAlloc, institutional)

Section 52 (Azure Defender for IoT research). **BadAlloc** (April 2021)
catalogued 25+ CVEs across embedded memory allocators. Affected vendors:
Amazon (FreeRTOS), Apache (NuttX), ARM (mbed OS), BlackBerry (QNX),
Cesanta (Mongoose OS), Google (Cloud IoT Device SDK), Linux Foundation (Zephyr —
earlier versions), Micrium, NXP, RedHat, Samsung Tizen RT, Texas
Instruments, Wind River (VxWorks). Pattern: `malloc(VALUE)` with
attacker-controlled VALUE; integer overflow during size calculation;
small allocation, oversized payload, heap overflow. Canonical
"shared anti-pattern at scale" disclosure.

### Eclipse ThreadX maintainers (institutional)

Microsoft contributed Azure RTOS to Eclipse Foundation November 2023;
transition complete April 2024 (Eclipse ThreadX 6.4.1, MIT). Components:
ThreadX, NetX Duo, FileX, GUIX, USBX, LevelX. October 2024 Eclipse
ThreadX Alliance broadened the steward set. 12 billion devices claim
(Microsoft pre-handover). Institutional shift from proprietary to open
licensing is itself a security event — research moves from
licensed-customer-channel to public issue tracker.

---

## II. Why RTOS Security Is Distinct

### The "real-time" property and its threat model implications

A real-time operating system is one where the correctness of the system
depends not only on the logical result of a computation but also on the time
at which results are produced. Two flavors:

- **Hard real-time** — missing a deadline is a system failure (anti-lock
  braking, pacemaker stimulation pulse, missile guidance loop). Worst-case
  execution time (WCET) is a load-bearing engineering parameter; the system
  cannot tolerate priority inversion, lock contention with unbounded wait,
  or interrupt-storm-induced delay.
- **Soft real-time** — missing a deadline degrades quality but doesn't fail
  the system (audio glitch, frame drop in video conferencing). Most
  consumer IoT devices, despite using RTOS-class kernels, are functionally
  soft real-time.

Threat-model implications:

- **Denial of service is severity-elevated** vs general-purpose OS contexts.
  On a Linux server, DoS is a service degradation. On a hard-real-time
  medical device, "missed control loop iteration" can mean missed pacemaker
  pulse — patient harm. Severity of DoS-class bugs in hard-RT contexts is
  often equivalent to RCE in conventional contexts.
- **WCET arguments support insecure-by-design choices**. RTOS authors
  frequently justify omission of bounds checks, argument validation, and
  authentication gates on the grounds that "the deadline budget can't
  afford the cycles." This is the OT:ICEFALL pattern. The argument is
  almost always wrong — modern Cortex-M MCUs have spare cycles — but it's
  the cultural argument that produced the current installed base.
- **Single fault propagates further**. On a hard-RT system the failure of
  one task can cascade through priority inheritance, deadlock, or watchdog
  reset. There is rarely a recovery primitive (no `systemd restart`); a
  bug that crashes one task often bricks the device until power cycle, and
  bricking a deployed industrial device costs orders of magnitude more than
  bricking a desktop.

### RTOS vs general-purpose OS

| Property | General-purpose OS | RTOS |
|---|---|---|
| MMU | Required | Optional / often absent on Cortex-M0/M3 |
| Address spaces | One per process | One total (single-address-space) is common |
| User/kernel split | Hardware-enforced | Often cooperative (privilege bit not enforced) |
| Scheduling | Best-effort fair | Priority-based, often preemptive, sometimes cooperative |
| Memory protection | Process-level virtual memory | MPU regions (8 or 16 on Cortex-M) at best |
| Driver model | Loadable kernel modules / userspace | Statically linked into kernel image |
| Update mechanism | Package manager + reboot | Whole-image firmware swap |
| TCB size | Millions of LOC (Linux/Windows) | Tens of thousands of LOC (FreeRTOS kernel) |
| Network stack | Linux netdev / Windows TCPIP | Often a separate library (lwIP, FreeRTOS+TCP, Treck, NicheStack) |
| Crypto stack | OS-provided (kTLS, KeyMaster, etc.) | Library-of-choice (mbedTLS, wolfSSL, hand-rolled) |
| Filesystem | Multiple (ext4, NTFS, APFS) | One or two (FAT, LittleFS) |
| Power management | Suspend/hibernate complex | Tickless idle, deep-sleep states |

The implications for review work: a Linux CVE corpus does not transfer cleanly
to an RTOS. Many Linux primitives (UID/GID separation, namespace isolation,
seccomp filtering, AppArmor/SELinux MAC) do not exist on RTOS targets. Many
RTOS-class bugs (single-address-space stack collision, missing MPU
configuration, interrupt-handler reentrancy) do not have direct general-purpose
analogs. Mental model shift: think of RTOS as MS-DOS-with-threads, not as a
small Linux.

### "Code is data, data is code"

Most RTOS deployments place code and data in the same address space, often
the same physical memory if no MMU is present. Without a hardware-enforced
W^X separation, every stack overflow that overwrites a function pointer or
return address is potentially RCE. The Cortex-M MPU can mark RAM regions as
execute-never (XN), but doing so requires positive configuration by the
developer, and many existing FreeRTOS deployments do not configure MPU
regions because the original code shipped pre-MPU. ARMv8-M's split
secure/non-secure worlds (TrustZone-M) and the always-XN attribute on
Cortex-M default memory map provide some baseline protection, but only if
the developer has enabled them.

The deeper problem is firmware update. Even on devices with MPU, the
firmware-update path frequently has elevated privilege to write the program
flash region. A bug in the update parser (bootloader DFU handler, OTA
manifest signature check) can subvert any runtime protection because update
runs before MPU is enforced.

### Cascading blast radius from shared components

One RTOS bug → many products. The Ripple20, URGENT/11, INFRA:HALT,
AMNESIA:33, NAME:WRECK, NUMBER:JACK, NUCLEUS:13, and BadAlloc disclosures
have a common shape: a single TCP/IP stack or memory allocator implementation
is integrated into dozens or hundreds of products by separate vendors who
share no source code, no security contact, and no patch cycle. Patching the
upstream stack does not patch the downstream devices — most of which will
never receive an update at all.

This pattern is structural to the embedded ecosystem and explains why
embedded security research focuses heavily on shared components (TCP/IP
stacks, crypto libraries, allocators) rather than per-product analysis: one
research project produces N device disclosures, not one. The corollary for
defenders: SBOM and VEX/CSAF infrastructure (covered in
`supply_chain_provenance_expertise.md`) is more load-bearing for embedded
devices than for any other deployment class because the upstream patches do
not propagate downstream automatically.

---

## III. The RTOS Landscape

This section catalogs the major RTOSes and embedded OSes. Vendor business
model (open vs proprietary), licensing, target architectures, and current
deployment scope are all relevant to threat model. Excludes general-purpose
Linux distributions (covered in `linux_kernel_exploitation_expertise.md`)
and excludes hypervisors covered elsewhere.

### Zephyr (Linux Foundation, Apache 2.0, 2016)

Modern modular RTOS. Subsystem model: kernel + drivers + subsystems
(Bluetooth, networking, sensor, USB) + boards. Build system: CMake + west +
devicetree (inherited from Linux). Architectures: ARM Cortex-M/A/R, ARC,
RISC-V, Xtensa (ESP32), x86, NIOS-II, SPARC. Strong Bluetooth LE stack,
LwM2M, CoAP, MQTT, OPC UA, EtherCAT subsystems in mainline.

Security posture: active Security Working Group (SWG) and PSIRT (CNA
status). Embargo period up to 90 days (30-day fix + 60-day downstream).
Vulnerability-alerts mailing list seeded with a contact from each project member. Known issue
corpus: Bluetooth LE Mesh OOB writes during provisioning (CVE-2022-1041/1042
plus 2025 GHSA-8wvr-688x-68vr / GHSA-r3j3-c5v7-2ppf), Synopsys CyRC
Defensics LE fuzzing (CVE-2021-3430 through CVE-2021-3435, CVE-2021-3454, CVE-2021-3455, fixed 2.6.0),
multiple IPv6/DHCPv4/DNS parser CVEs. EU CRA workstream documented under
doc/security/standards/cyber-resilience-act.rst.

### FreeRTOS (Amazon, MIT, 2003)

The "RTOS as a library" archetype. ~10K LOC kernel. Cooperative or
preemptive. Tasks, queues, semaphores, mutexes, software timers. No
kernel-side filesystem or network stack — those ship as separate modules
(FreeRTOS+FAT, FreeRTOS+TCP, the latter vulnerable in Zimperium's 2018
CVE-2018-1652x disclosure). ~40 architectures supported. AWS-acquired
2017.

Deployment pathology: easy integration means millions of products ship
with whatever version was current at product-development start, never
updated. AWS FreeRTOS LTS branches (LTS 202012, 202210, 202406) provide
2+ years of security backports but require OEM tracking.

FreeRTOS-MPU port: per-task MPU regions on Cortex-M with MPU; tasks run
unprivileged, kernel privileged. Caveats: 8 or 16 MPU regions limit task
counts; regions must be power-of-two aligned; non-MPU port is the default
that most legacy code uses. TLS integration via mbedTLS or wolfSSL, each
with their own CVE history.

### MicroPython / CircuitPython (MIT)

Python 3 interpreter compiled into MCU flash with mark-sweep GC.
Architectures: Cortex-M, ESP8266/32, RP2040, STM32, RISC-V. Adafruit's
CircuitPython is a hardware-friendlier fork with CIRCUITPY USB-MSC
development drive.

Security posture: limited. No isolation between Python modules; untrusted
Python code can reach interpreter internals. CHERIoT MicroPython
(University of Glasgow) is the research direction for hardware-capability-
based memory safety + library compartmentalization, not yet default
deployment. Threat model: code execution is trivial if attacker delivers
`.py` or `.mpy`. Defense: no REPL on production, sign+verify firmware
including bundled scripts, disable USB-MSC in production.

### RT-Thread (Apache 2.0, China, 2006)

Apache 2.0 RTOS from Shanghai team. Widely deployed in Chinese consumer
and industrial IoT. PSA Certified Level 1 (Cortex-M33 baseline). Modular
like Zephyr; networking, DFS filesystem, LVGL GUI. 2024 hn security
disclosure: CVE-2024-24334/24335 (dfs_v2 heap/buffer overflows),
CVE-2024-25389 (weak random), CVE-2024-25392/25394/25395 (utility-side
OOB). Bog-standard C memory corruption; audit posture catching up.
Procurement / threat-model implications around China-origin codebase plus
opaque downstream hardware supply chain.

### mbed OS (Arm, Apache 2.0, EOL July 2026)

Cortex-M focused, mbed Studio + Keil tooling. Arm halted active
maintenance and CI before EOL date. Community fork mbed CE under
development; Arduino migrating its mbed-based cores to Zephyr. Note: mbed
TLS is a separate project at TrustedFirmware.org and is **not** affected
by mbed OS EOL.

### NuttX (Apache 2.0, ASF top-level since November 2022)

Most "Unix-like" of major RTOSes: fork(), exec(), pipes, signals, message
queues, shell, BSD sockets. Architectures: 8-bit through 64-bit ARM/RISC-V.
Flagship deployment: PX4 Autopilot for drones (Pixhawk hardware). NuttX
provides threading/scheduling/driver/filesystem; PX4 the flight stack.
Smaller research community than Zephyr / FreeRTOS — fewer disclosed CVEs
but also fewer eyes; under-explored research surface. MAVLink protocol
parsing has had reports on the PX4 side.

### VxWorks (Wind River, proprietary, 1987)

Dominant industrial / aerospace / defense RTOS for the previous three
decades. Mars rover Curiosity, Boeing 787 avionics partitions,
BMW iDrive (early gens). 2 billion devices at
peak per Wind River. Wind River independent since 2018 Intel spinout;
Aptiv-acquired 2022.

Security history:
- **URGENT/11 (Armis, 2019)**, CVE-2019-12255 through 12265 in the IPnet
  TCP/IP stack inherited from Interpeak (2006 acquisition). Six critical
  RCE. Stack code unchanged from 2000s-era third-party; escaped scrutiny
  by being inside a proprietary RTOS.
- **Exodus Intelligence (2016)** pre-URGENT/11 disclosure: 3 VxWorks
  vulns (DHCP client/server overflow, DNS client stack overflow); see
  "VxWorks: Execute My Packets" (blog.exodusintel.com).
- **BadAlloc (Microsoft, 2021)**: VxWorks among affected products.

VxWorks 7 (2014+): microkernel option, Real-Time Process (RTP) model with
true MMU-isolated processes, user-mode networking, separation kernel
option for IMA. Material architectural improvement; installed base
dominated by older 6.x where the gain is unavailable. DO-178C DAL-A certified Cert
Platform. Certifications constrain architecture but not implementation
(URGENT/11 was implementation).

### QNX (BlackBerry, proprietary, 1982)

Microkernel architecture — only a small kernel in privileged mode;
drivers, FS, networking, apps run as user-mode processes. IPC via
message passing. Architectural selling point: a driver crash doesn't
kill the kernel, a compromised driver doesn't auto-yield kernel
privilege.

Deployment: automotive infotainment + ADAS (195 million vehicles per
BlackBerry), medical devices (surgical robots, infusion pumps,
pacemakers via QNX OS for Medical / Safety), industrial control,
robotics, heavy machinery, rail. ISO 21434 (Automotive Cybersecurity)
certified.

**BadAlloc CVE-2021-22156**: QNX SDP 6.5.0SP1 and earlier, QNX OS for
Medical 1.1 and earlier, QNX OS for Safety 1.0.1 and earlier vulnerable
to the same allocator integer overflow pattern. CISA issued AA21-229A
because of medical and automotive impact. BlackBerry's initial public
response was guarded and widely criticized; patches eventually
published.

### INTEGRITY (Green Hills) and PikeOS (SYSGO)

High-assurance separation-kernel RTOSes. **INTEGRITY-178B** certified to
Common Criteria EAL6+ High Robustness (2008 NSA certification, highest
commercial-OS evaluation achieved). DO-178C DAL-A for avionics (F-35,
F-22, A380). Toolchain (Green Hills MULTI + GHS compiler) is part of
certification scope. **PikeOS**: separation kernel + hypervisor;
multiple partitions for guest OSes (Linux, Android, RTOS); Airbus,
Embraer, defense, rail. EAL5+ certified.

Certification reality: attests to architecture and process, not
implementation bug-immunity. Both have had disclosed vulnerabilities
(rare, real). Compromise is rare-and-publishable; public examples
sparse because deployments are mostly military and commercial researchers
can't easily acquire targets.

### ThreadX / Azure RTOS / Eclipse ThreadX (MIT since April 2024)

Express Logic origin (Bill Lamie; also original Nucleus author).
Microsoft-acquired 2019 as Azure RTOS. Eclipse Foundation contribution
November 2023; transition complete April 2024 as Eclipse ThreadX 6.4.1
under MIT. Components: ThreadX kernel, NetX Duo (TCP/IP), FileX,
GUIX, USBX, LevelX. 12 billion devices claim (Microsoft pre-handover).
BadAlloc disclosure listed Azure RTOS ThreadX as not-vulnerable in
default configuration (Microsoft discloser AND product owner; the
default-config language matters). Few public kernel-side CVEs to date —
reflects prior commercial channel. Expect CVE volume to rise materially
2025-2027 with public research now possible.

### Other named systems

**embOS** (SEGGER, proprietary, well-engineered, J-Link tooling ecosystem,
limited public CVE history). **Contiki-NG / RIOT-OS / TinyOS**: research-
RTOS lineage; Contiki-NG ships uIP (AMNESIA:33-vulnerable); RIOT-OS LGPL
from Berlin Free University; TinyOS mostly historical now. **TI-RTOS**
(Texas Instruments). **Micrium µC/OS-II/III** (Silicon Labs, open-sourced
2020 under Apache, industrial controls). **CMSIS-RTOS2 RTX5** (Arm
reference). **Nucleus RTOS** (Siemens, NUCLEUS:13-vulnerable). **Apache
Mynewt** (Apache Software Foundation; originally developed by Runtime). **Tock** (research RTOS in
Rust; memory-safety story; OpenSK security keys).

---

## IV. Common RTOS Attack Surface Categories

### TCP/IP stack — the dominant attack surface

The Project Memoria research arc establishes that embedded TCP/IP stacks are
the single most productive attack surface in the RTOS landscape. The
disclosure record:

| Year | Disclosure | CVEs | Stack(s) |
|------|---|---|---|
| 2019 | URGENT/11 (Armis) | 11 | Wind River IPnet (VxWorks 6.5+) |
| 2020 | Ripple20 (JSOF) | 19 | Treck embedded TCP/IP |
| 2020 | AMNESIA:33 (Forescout) | 33 | uIP, picoTCP, FNET, Nut/Net, Contiki-NG uIP |
| 2021 | NUMBER:JACK (Forescout) | 9 | TCP ISN generation across multiple stacks |
| 2021 | NAME:WRECK (Forescout/JSOF) | 9 | FreeBSD, Nucleus NET, IPnet, NetX (DNS) |
| 2021 | INFRA:HALT (Forescout/JFrog) | 14 | NicheStack (HCC Embedded) |
| 2021 | NUCLEUS:13 (Forescout/Medigate) | 13 | Nucleus NET (Siemens) |
| 2021 | BadAlloc (Microsoft Section 52) | 25+ | Cross-stack allocator integer overflow |
| 2023 | Sierra:21 (Forescout) | 21 | Sierra Wireless AirLink + TinyXML + OpenNDS |

Common bug classes in this corpus:

- **Heap overflow in DHCP option parsing** — URGENT/11 CVE-2019-12257 (DHCP Offer/ACK parsing in Ipdhcpc), Zimperium
  FreeRTOS+TCP CVE-2018-16602.
- **DNS message compression pointer abuse** — NAME:WRECK pattern; the RFC
  1035 compression pointer (offset back into the message) was misimplemented
  across multiple stacks, allowing OOB reads, OOB writes, and infinite-loop
  DoS. RFC 9267 codifies the anti-patterns.
- **TCP urgent pointer mishandling** — URGENT/11 CVE-2019-12255 (TCP Urgent
  Pointer = 0 → integer underflow).
- **IPv4 fragment reassembly** — multiple stacks have had fragment-overlap and
  buffer-bound bugs.
- **ICMP/ICMPv6 echo and redirect parsing** — periodic source of OOB reads.
- **TCP Initial Sequence Number predictability** — NUMBER:JACK pattern.
  Per-connection ISNs derived from millisecond timers without
  cryptographic mixing → off-path TCP injection.

For review of any embedded device with a network interface, the TCP/IP
stack should be the first target of attention. Identifying the stack is
itself the first step: project-memoria-detector
(github.com/Forescout/project-memoria-detector) provides fingerprints for
16 embedded stacks based on observable behaviors (malformed ICMP echo
replies and TTL, TCP options in the SYN-ACK, TCP Urgent flag handling,
HTTP/SSH/FTP banners). If the
stack matches a known-vulnerable version, the CVE list is the starting
point. If the stack is unknown, fuzzing the parser is the productive next
step (Section IX).

### Bluetooth stack

BLE has been productive across BLE-enabled RTOSes. Zephyr Bluetooth Mesh
OOB writes (CVE-2022-1041/1042 plus 2025 GHSA-8wvr-688x-68vr,
GHSA-r3j3-c5v7-2ppf) are exploitable pre-authentication during
provisioning from adjacent radio range; provisioning state machines have
large parser surface and subtly stateful key-exchange phases. BlueZ on
embedded Linux has its own corpus that smart speakers / TVs / fitness
trackers inherit and rarely patch.

### USB stack

The most common physical-access surface. USBFuzz (USENIX
Security 2020) found 26 USB-driver bugs across desktop OSes; RTOS-side
stacks (FreeRTOS USB, Zephyr USB, ThreadX USBX, NuttX usbhost) have
received less fuzz attention. Treat USB device classes (HID, MSC, CDC, ACM,
DFU) as exploitable input parsers. See `firmware_embedded_security.md`
for Facedancer specifics.

### Filesystem layer

Reachable via remote-read/write (Samba on embedded Linux, FTP/SFTP on
RTOS, TFTP on PLCs). FatFs (ChaN), FreeRTOS+FAT, ThreadX FileX, LittleFS
(ARM, dominant on modern Cortex-M), and embedded ext have had bounds and
integer bugs. Review surface: long filenames, FAT chain traversal,
journal replay, integer arithmetic on size/cluster count.

### OTA update mechanism

Highest-value target — persistent code-write capability. Bug classes:
missing signature check (HTTPS download without payload signature);
skippable signature check (debug branch left in production, or glitching
the check instruction); downgrade-permitted (no anti-rollback); signing
key compromise (consumer routers, medical devices, multiple OEMs); partial
signature scope (kernel signed but rootfs/config not); TOCTOU between
verify and execute. MCUboot is the widely-used reference implementation
(github.com/mcu-tools/mcuboot); FreeRTOS-OTA covers the AWS-integrated
path.

### HTTP / HTTPS servers

Most embedded devices ship a built-in HTTP server for configuration
(routers, cameras, IoT hubs, ICS engineering interfaces). Hand-rolled or
small libraries (boa, goAhead, miniHTTPd, RomPager). RomPager
"Misfortune Cookie" CVE-2014-9222 affected 12 million home routers across
~200 device models. 2020 F5 BIG-IP TMUI RCE (CVE-2020-5902, exploited by Mirai
variants) is a "server-grade product with embedded-style architecture"
example.

### Crypto stack

mbedTLS, wolfSSL, BearSSL, MatrixSSL, Cyclonecrypto — each with its own
CVE history (mbedTLS X.509/ASN.1 memory-corruption; wolfSSL timing
attacks). Pre-TLS, plenty of embedded crypto is hand-rolled or worse: DES
still ships in some industrial protocols. OT:ICEFALL category "weak
cryptography or broken authentication" called this out specifically.

---

## V. FreeRTOS-Specific Surface

**Single-address-space reality**: dominant deployment is Cortex-M0+/M3/M4
without MMU, often without MPU. Every task has R/W access to every
other task's stack, kernel data structures, and peripheral registers. A
buffer overflow in any task can corrupt kernel state (e.g., ready-task
list pointers) and yield arbitrary control flow when the corrupted task
is next scheduled. Defensive options: FreeRTOS-MPU port (M3+ with MPU,
M4F/M7, M33 with ARMv8-M), TrustZone-M to split security-critical code
(keys, sig verify, session keys) into Secure world, or migrate to a
higher-end MCU with an MMU. Most existing deployments use none of these.

**FreeRTOS+TCP — 2018 Zimperium CVE-2018-1652x disclosure**: multiple OOB
parser bugs (CVE-2018-16524 TCP options info-disclosure, CVE-2018-16599
NBNS OOB, CVE-2018-16600 ARP OOB, CVE-2018-16602 DHCP OOB). Affected AWS
FreeRTOS through 1.3.1, FreeRTOS up to V10.0.1 with FreeRTOS+TCP, and
WITTENSTEIN WHIS Connect. Pattern: parser code adapted from older
references carrying latent OOB patterns; even AWS-backed maintenance
missed them.

**AWS IoT bundle**: MQTT-over-TLS to IoT Core; Greengrass for local-edge.
Surface: device cert key recovery from flash (no secure element →
identity clone); topic-based-authorization misconfiguration (publish/
subscribe to topics that should be device-local); FreeRTOS-side MQTT
parser bugs (malformed broker messages crash device).

**Version-freeze deployment pathology**: identifying FreeRTOS version in
a target firmware image is the first review step. Look for
`tskKERNEL_VERSION_NUMBER` string (preserved by default) or infer from
idle-task structure layout. AWS IoT LTS branches (LTS 202012, 202210,
202406) provide security backports but require active OEM tracking.

---

## VI. Zephyr-Specific Surface

**Subsystem-as-attack-surface model**: kernel + drivers + Bluetooth (LE
host+controller, Mesh, BR/EDR) + Networking (IPv4/6, DHCP, DNS, MQTT,
CoAP, LwM2M, HTTP, Sockets) + Filesystem (FatFs, LittleFS, ext2) + USB
host+device + POSIX subset + Power management + Logging/shell/settings.
Each is an optional-build module. Major toggles: CONFIG_BT, CONFIG_NET,
CONFIG_USB, CONFIG_FILE_SYSTEM. Defensive: minimize enabled subsystems.

**Bluetooth Mesh** is currently the most productive public CVE source.
Mesh provisioning requires a pre-pairing handshake that derives mesh
keys; provisioning-message parser has had multiple OOB-write bugs
(gen_prov_start, gen_prov_cont — see Section IV). State machine reachable
without authentication from any device in radio range during provisioning
window. Factory reset or configuration timeout re-enters provisioning,
extending the window.

**LwM2M / IoT-protocol surface**: OMA LwM2M parser handles registration /
observation / bootstrap (CoAP-encoded TLV). CoAP-over-DTLS authenticates;
CoAP-over-UDP does not. Many deployments use UDP-only for development
then ship the development variant.

**Test-suite-as-fuzz-corpus**: twister test runner has been used as the
starting point for AFL++ fuzzing via Renode. Structural strength vs
FreeRTOS. **Architecture-specific divergence**: ARM/RISC-V/Xtensa/ARC
have different memory models; bugs surface on one arch may not on
another. Multi-architecture fuzzing as release-gate is the mitigation.

---

## VII. VxWorks, INTEGRITY, QNX — Proprietary High-Assurance

### URGENT/11 anatomy

The most-studied embedded-OS network-stack disclosure. Bug pattern
recurs and is worth understanding in detail.

- **CVE-2019-12255** — TCP Urgent Pointer = 0 → integer underflow. URG
  flag with zero pointer → subtraction wraps to ~2^32 → memcpy length.
  Heap-corrupting RCE on VxWorks 6.5–6.9.3.
- **CVE-2019-12257** — Heap overflow in DHCP Offer/ACK parsing
  (Ipdhcpc). Option-length parsed without bounds. Triggerable from any
  rogue DHCP server on the same broadcast domain. Pre-network-config
  attack — fires before device has IP-level filtering.
- **CVE-2019-12258** — TCP connection DoS via malformed TCP options.
- **CVE-2019-12259** — DoS via NULL deref on IGMP parsing.
- **CVE-2019-12260 through 12265** — additional RCE, DoS, info-leak
  variants across TCP, IPv4, IPv6, DHCP.

Three structural observations: (1) IPnet code is Interpeak (2006
acquisition) predating modern coding standards; "old code in trusted
wrapper survives audit by reputation, not by review." (2) Attack surface
is unauthenticated and L2-reachable — rogue DHCP, malformed packet from
any subnet peer. (3) Patch deployment delay is enormous; many fielded
devices will never be patched in their service lifetime.

### VxWorks 7 hardening and the certification reality

VxWorks 7 (2014+) introduced a microkernel option; the Real-Time Process
(RTP) model with MMU-isolated processes dates to VxWorks 6.x. An
RTP-isolated network stack cannot corrupt kernel state directly.

INTEGRITY-178B's 2008 EAL6+ High Robustness certification is real
engineering — separation kernel, strict partitioning, formally-analyzed
small kernel. Disclosed INTEGRITY/PikeOS vulns are rare-and-publishable;
deployment is mostly military so commercial researchers can't easily
acquire targets.

QNX BadAlloc episode (CVE-2021-22156, CISA AA21-229A): calloc() integer
overflow in QNX SDP 6.5.0SP1-, QNX OS for Medical 1.1-, QNX OS for
Safety 1.0.1-. Pattern: QNX microkernel architecture limits kernel-side
blast radius, but allocator bugs still cripple per-process / per-driver
scope. Microkernel-vs-monolithic matters for kernel-state corruption,
not for "this driver process can be made to misbehave."

Forescout's OT:ICEFALL quantified the gap: 74% of vulnerable OT product
families carried some form of security certification. Certifications
attest to architecture and process, not bug-immunity. EAL6+ is meaningful
for the partitioning architecture; it doesn't mean the OEM-side code
built atop the OS (outside certification scope) is bug-free.

---

## VIII. Embedded Linux and Yocto

Embedded Linux is a distinct space from RTOS but shares attack-surface
concerns. The kernel itself is in `linux_kernel_exploitation_expertise.md`;
this section covers embedded-deployment specifics.

**Kernel-version-freeze pathology**: most embedded Linux deployments
freeze kernel at product-development start. Common fielded versions as of
2026: 2.6.x (historical but real), 3.10/3.18 (Allwinner/Mediatek/Broadcom
BSPs), 4.4/4.9/4.14 (LTS, often past LTS EOL), 4.19/5.4/5.10 (modern-IoT
baseline), 5.15/6.1/6.6 (new hardware). Each LTS has 1000+ CVEs over its
lifetime; SUSE notes the kernel CNA issued 4500+ CVEs across 2024-2025. Most aren't
reachable on every embedded build (subsystem-dependent) but any 5+-year-
old embedded Linux device has many open CVEs. Yocto cve-check and
Buildroot pkg-stats scan but don't deploy fixes.

**BusyBox CVE corpus**: dominant userspace toolbox. 2021 disclosure
(CVE-2021-42373 through 42386, Claroty + JFrog) added 14 CVEs across
awk (9), hush (2), ash (1), man (1), lzma/unlzma (1); 10 of 14 possibly
enable RCE. CVE-2022-48174 (ash stack overflow, fixed 1.35+) extended the
corpus. Affected versions span 1.16 to 1.33.1. JFrog + Claroty
estimated 40% of inspected firmware bundles a vulnerable applet.
BusyBox is rarely updated in fielded devices.

**systemd / udev in embedded**: set-top boxes, infotainment, high-end
industrial gateways increasingly use systemd. udev hotplug rules are a
frequently-misconfigured trust boundary (USB-attach-grants-permission
rules exploitable with arbitrary attached USB devices). Smaller
deployments use BusyBox mdev or static device nodes.

**Buildroot vs Yocto**: Buildroot is simpler, single-make-tree, common in
low-end embedded. Yocto/Poky/OpenEmbedded is layered, more complex,
dominates high-end and automotive. Fingerprints distinguish them: libc
choice (uClibc-ng/musl Buildroot vs glibc Yocto by default), init
(BusyBox vs systemd), package shape.

**Zombie-device class**: material fraction of fielded IoT devices have
OEMs out of business or product lines abandoned. No further updates;
CVEs accumulate. Mirai-class botnets target this specifically (default
creds, known CVEs, no patch pipeline). Hundreds of millions of devices
globally. Only viable defense is network-layer (cross-link
`detection_engineering_expertise.md`, `ics_ot_security_expertise.md`).

---

## IX. Cross-Cutting Attack Patterns

### Memory corruption in C-heavy codebases

RTOS code is overwhelmingly C, often C89/C90 dialects, often pre-MISRA-C
in style. Memory-corruption bugs dominate the disclosed CVE corpus:
buffer overflows, integer overflows in size computations, NULL
dereferences, use-after-free in allocator-recycled buffers, double-free
in error paths. Stack-cookie / canaries are available on Cortex-M GCC
(`-fstack-protector-strong`) and increasingly on by default in modern
toolchains, but legacy builds often disable them for code-size reasons.
W^X via MPU XN is similarly available-but-often-not-enabled.

### Unauthenticated firmware update

Already covered in Section IV. This is the highest-value bug class
because successful exploitation yields persistent code execution and
typically pivots to other devices via lateral movement.

### Hardcoded credentials in firmware images

The Mirai pattern: default Telnet credentials, hardcoded support
passwords, hardcoded service-mode passwords. The OT:ICEFALL category
"weak cryptography or broken authentication schemes" includes
hardcoded-key disclosures. Tools: binwalk + strings + entropy analysis
to locate keys and hashes in extracted firmware images (see parent doc
Section III on firmware analysis).

### Weak crypto

DES still ships in deployed RTOS code paths. RC4 still appears in some
legacy SSL/TLS implementations on embedded. SHA-1 collision-resistance
is broken but SHA-1-as-signature-of-firmware-image is still used in
deployed bootloaders. ECDSA implementations with predictable nonces
(constant-K bug) have been disclosed in multiple embedded TLS stacks.

### Buffer overflows in protocol parsers

The Ripple20 / URGENT/11 / NUCLEUS:13 corpus is dominantly this class.
Pattern: protocol parser reads a length field from the wire, allocates
or sizes a buffer based on the length, and either (a) trusts the
length without bounds-checking against the actual remaining packet, or
(b) computes the allocation size with arithmetic that wraps. Either
shape yields heap or stack corruption.

### Stack collision / overflow in single-address-space deployments

When task stacks are adjacent in RAM with no guard pages (common on
small Cortex-M without MPU), a task that recurses too deep, allocates a
large local buffer, or has a runaway memcpy can overflow into the
adjacent task's stack. The runtime corruption is hard to debug because
it manifests as the adjacent task misbehaving later. Defensive: enable
stack-overflow checking in FreeRTOS (`configCHECK_FOR_STACK_OVERFLOW = 2`),
which fills the bottom of each task stack with a known pattern and
checks at context switch; enable MPU with per-task stack guard regions
where possible.

### Race conditions in interrupt handlers

Embedded code has more interrupt-handler surface than general-purpose
code. Races between interrupt context and task context, between two
interrupt handlers, or between interrupt and DMA, are common bug
sources. Patterns to look for: non-atomic update of multi-byte fields
shared between ISR and task (read-modify-write on a 16-bit field on an
8-bit MCU); critical sections that disable interrupts but leak the
critical state via shared globals; double-buffering schemes where the
producer side and consumer side disagree about ownership boundaries.
Cross-link to `race_conditions_concurrency_expertise.md`.

### Cooperative scheduling bugs

Some RTOS configurations use cooperative scheduling (FreeRTOS without
preemption, NuttX in some modes). Cooperative schedulers eliminate
ISR-context races within task code but introduce a different bug class:
a task that yields infrequently can starve higher-priority tasks of
CPU, including any task that handles watchdog kicks or safety
interlocks. A bug that increases yield latency in one task can DoS the
whole system.

---

## X. Fuzzing RTOS Code

Cross-link to `fuzzing_discipline_expertise.md` §6 for broader fuzzing
context. RTOS-specific challenges and approaches:

**syzkaller adaptation**: syzkaller targets POSIX syscall surfaces;
RTOSes don't expose syscall APIs (function calls in single-address-space
FreeRTOS, supervisor-call in MPU/RTP). **Rtkaller** (Wingtecher Lab,
EMSOFT 2021) is a state-aware kernel fuzzer for RTOS — automatic task
initialization + coverage-guided task mutation. Achieves 26.1% / 22.0%
more branch coverage than syzkaller / Moonshine in 24 hours. Public but
limited adoption; porting work required per target.

**Renode + AFL++ emulation-based fuzzing** (Antmicro, 2023): Renode
executes unmodified binaries, hooks each block to fill an AFL coverage
map in shared memory, signals crash conditions to AFL++ via configurable
exit triggers (default: jump to address 0). Strengths: unmodified
production binaries, multi-architecture support, peripheral-level
fuzzing (UART, SPI, I2C, network adapters emulated). Limitations:
approximate peripheral fidelity, DMA semantics may differ from
hardware, timing-sensitive bugs may not reproduce, hardware-glitching
bugs not emulated. Renode supports Zephyr, seL4, ThreadX, NuttX,
Linux.

**"Fuzz the parser, not the whole device"**: the productive approach
for TCP/IP stack research. Extract parser code, compile as Linux
userland with libFuzzer/AFL++ harness, fuzz at native speed. Translation requires
understanding external dependencies (heap, network buffer API,
byte-order macros) and stubbing safely. Per-stack effort, linear
payoff.

**Hardware-in-the-loop (HITL) with Boofuzz** (Sulley successor): serial,
Ethernet, IP-layer, UDP-broadcast support; drives real device via
wire, monitors via target reset. Claroty Team82's OPC UA fuzzer is
Boofuzz-based. HITL is right when emulation fidelity is insufficient
or device is proprietary; low throughput; non-crashing internal-state
corruption is hard to detect without instrumentation.

**Coverage-guided differential fuzzing**: run identical input against
two implementations of the same protocol (FreeBSD TCP/IP vs lwIP, or
IPnet vs Treck); divergences are usually a bug in one.

---

## XI. Defensive RTOS Patterns

### Enable MPU on Cortex-M when possible

Recommended baseline regions (8 or 16 MPU region limit constrains task
count + layout): kernel data in privileged-only region; task stacks
each in own region with adjacent-region access denied (catches stack
overflow into neighbors); code flash execute-only; RAM XN (no execute);
peripheral access gated per-task.

### TrustZone-M for ARMv8-M (M23, M33, M35P, M55, M85)

Split application Secure / Non-Secure. Place cryptographic operations,
key storage, signature verification, attestation, secrets in Secure
world. Cross-world calls via NSC (Non-Secure-Callable) veneers. **Trusted
Firmware-M** (TF-M) is the reference Secure-world implementation —
attestation, key store, PSA Crypto API.

### Memory-safety language adoption

Rust on embedded growing rapidly. embedded-hal traits, RTIC (Real-Time
Interrupt-driven Concurrency, rtic.rs) for Cortex-M with static
priorities, compile-time shared-resource tracking, deadlock-free
guarantee, zero-cost abstractions. **Tock** (tockos.org) is a research
RTOS in Rust used in OpenSK security keys — proves memory-safe RTOS
production-deployable in security-critical contexts. Realistic
horizon: 5-10 years for material market share via gradual C-to-Rust
migration with FFI.

**CHERIoT-MCU** (Microsoft Research) — hardware-enforced
capability-based memory safety for IoT MCUs. CHERIoT MicroPython
(University of Glasgow) demonstrates Python interpreters hardenable
via hardware capability enforcement. Worth tracking; hardware support
emerging.

### Sign and verify all firmware updates

Requirements: asymmetric signature (ECDSA P-256 / Ed25519); signing key
in HSM (OEM) + secure element (device verify root); signature covers
entire image (bootloader, kernel, application, resources, config — not
just kernel); anti-rollback via monotonic version numbers enforced at
install; bootloader itself signature-checked by ROM or eFUSE-pinned key.
**MCUboot** (github.com/mcu-tools/mcuboot) is the widely-used reference
implementation; Zephyr integrates it. FreeRTOS-OTA covers the AWS path.

### Disable unused services, replace ancient stacks, patch promptly

Every compiled-in subsystem is surface (CONFIG_BT, CONFIG_USB, CONFIG_NET,
CONFIG_SHELL, CONFIG_LOGGING). If on a Project-Memoria-affected stack
(Treck, uIP, picoTCP, FNET, NicheStack, Nucleus NET, IPnet), migrate to
modern lwIP 2.x or Zephyr networking; recurring CVE-patching cost on a
legacy stack is higher than migration cost over service life. The
"physical access required" excuse is wrong for network-facing RTOS
devices since most disclosed CVEs are remote. Subscribe to vendor advisory
feeds (Zephyr PSIRT, FreeRTOS, Wind River, Forescout, ZDI); track LTS
branches; maintain a build pipeline that can produce a re-flashed image
within days of a CVE disclosure.

### Static analysis on protocol parsers

Coverity, CodeQL, Semgrep catch buffer-bound mismatches, integer-overflow
in size computations, NULL derefs. MISRA-C compliance eliminates some
dangerous constructs. Combine static analysis + fuzz + manual review on
parsers for the high-yield audit recipe.

### Code review checklist (10-item baseline)

For an RTOS-based product review, check these items first:

1. **Network stack identification** — what TCP/IP stack ships? Is it
   Project-Memoria-affected? Is the version patched?
2. **MPU/TrustZone-M enablement** — is the MPU configured? Are tasks
   isolated? Is XN enabled on RAM?
3. **Firmware update path** — is the OTA update signed? Is the entire
   image covered? Anti-rollback enforced?
4. **Bootloader trust root** — what verifies the bootloader? ROM?
   eFUSE? Hardware secure element?
5. **Default credentials** — are there hardcoded credentials in the
   firmware image? (binwalk + strings + entropy).
6. **Service surface** — what protocols are listening? (nmap from
   adjacent network).
7. **Bluetooth provisioning window** — if Bluetooth is enabled, when
   is the device in provisioning mode? How is it re-entered?
8. **USB device classes** — if USB is enabled, what classes are
   exposed? Can attacker-controlled USB devices be attached?
9. **Crypto stack version** — what mbedTLS / wolfSSL version? Is it
   current? Are weak ciphers disabled?
10. **CVE corpus on each shared component** — for every identifiable
    library, run the version against CVE lookup; track which CVEs
    apply.

---

## XII. IoT Device Disclosure and Coordination

**CISA / ICS-CERT process**: primary US-government coordination body for
ICS/OT embedded device vulnerabilities. Researchers submit to vendor +
CISA simultaneously (or CISA first if vendor unresponsive). CISA
coordinates multi-vendor disclosure for shared-component bugs (e.g.,
AMNESIA:33 across many downstream vendors), publishes ICSA-YY-NNN-NN
advisories. Embargo typically 90+ days.

**Forescout multi-vendor model** (Project Memoria template): identify
shared component → research the upstream → coordinate patches with
maintainer → build vendor list from licensee records + fingerprinting →
coordinate with CISA → publish advisory + report + detection tooling.
Memoria conclusion: 81 of 422 potentially affected vendors published
advisories (19.2%). Structural gap between upstream patching and
downstream disclosure remains unsolved.

**The "no vendor security contact" reality**: many small/medium OEMs
have no published contact despite ISO/IEC 30111 and 29147 requiring one.
Escalation: security@vendor → contact@vendor → LinkedIn engineering
leadership → CERT/CC mediation. CERT/CC coordinates when vendor
unresponsive.

**Bug bounty coverage gaps**: Wind River, BlackBerry, Microsoft, Eclipse
Foundation, Linux Foundation have varying program maturity. Mid-market
embedded vendors (Allwinner, Rockchip, Mediatek, TI) generally don't —
researcher incentives mismatched with highest-volume surface.

**CSAF / VEX for embedded SBOMs**: CycloneDX is dominant SBOM format with
IoT/ICS/embedded support. CSAF is dominant advisory format. VEX provides
per-vuln per-product status (Not Affected / Affected / Fixed / Under
Investigation) — four implementations: CSAF, CycloneDX, SPDX, OpenVEX.
SBOM+VEX is more load-bearing for embedded than any other deployment
class because the upstream CVE landscape vastly exceeds per-device
exposure. EU CRA is the regulatory mover (Zephyr's CRA workstream
documented under doc/security/standards/cyber-resilience-act.rst).
Cross-link `supply_chain_provenance_expertise.md`.

---

## XIII. Detection at the IoT/RTOS Edge

**"You can't run an EDR on a Cortex-M0"**: EDR agents need megabytes of
RAM and writable storage; neither exists on FreeRTOS in 32KB SRAM.
Standard EDR is structurally inapplicable to most of the RTOS surface.

**Network-layer-only detection** is the practical posture for
unmanageable RTOS endpoints: flow-level baseline (destinations, protocols,
volumes, packet sizes — deviation is the primary signal); protocol-level
DPI (Modbus function-code anomalies, S7, DNP3 manipulations); asset
visibility (Forescout, Armis, Claroty, Nozomi, Dragos all sell
passive-observation + behavioral-baseline platforms); TLS fingerprinting
(JA3/JA4 identifies device firmware versions, anomaly when device
suddenly initiates TLS to unknown servers). Cross-link
`detection_engineering_expertise.md` §6 / §9; `ics_ot_security_expertise.md`
§7.

---

## XIV. Variant Analysis — Under-Explored Surface

**AI agents on RTOS (TinyML-with-tool-use)**: TinyML inference on
Cortex-M (uTensor, TensorFlow Lite Micro, CMSIS-NN) moving toward
agents that can call functions on the device. Threat dimensions: (a)
tool-call as RCE primitive — if model calls shell/exec/write-flash,
prompt-injection via sensor data becomes device takeover; (b)
memory-safety of inference frameworks — TFLM and similar are C code
processing untrusted weights and tensors. Genuinely under-explored as
of 2026. Cross-link `llm_agent_security_expertise.md`.

**Quantum-resistant crypto on RTOS**: NIST PQC (FIPS 203/204/205,
finalized 2024) adapting to RTOS. Resource constraints: Kyber-768
public key 1184 bytes vs ECDSA-P256 64 bytes — embedded with 32KB
flash budgets can't accommodate both. SPHINCS+ (stateless hash-based)
is more RTOS-friendly than Dilithium for some signature use cases.

**WebAssembly on MCUs**: Wasm3, WAMR, WasmEdge target MCU-class
hardware. WebAssembly provides memory-safe execution sandbox by design
(module can't reach outside linear memory, function pointers
validated, host functions explicitly imported). Defense argument: run
untrusted code in Wasm sandbox on RTOS; treat module as application
surface, host RTOS as TCB. Caveats: ~50KB runtime baseline,
host-function calls are integration points, sandbox-escape bugs in
runtime cross from Wasm to host.

**Multi-core RTOS (AMP vs SMP)**: RP2040 dual-M0+, NXP i.MX RT1170
M7+M4, ESP32-S3 LX7+LX7+ULP. AMP — different OS per core, IPC via
shared memory + interrupts; kernel isolation enforced by core
separation but shared peripherals (flash, USB, network) need
coordination. SMP — single OS instance spans cores (FreeRTOS SMP, mainline V11.0.0 2023,
Zephyr SMP); shared kernel state across cores creates more
race-condition surface.

**Programmable logic + RTOS hybrids**: Xilinx Versal / Zynq UltraScale+
combine Cortex-A (Linux) + FPGA fabric + Cortex-R (RTOS) on one die.
Cross-die DMA from FPGA to R-side memory bypasses OS-level isolation.
Bitstream injection, shared-power side-channel. Cross-link to
parent doc Section IV (Thrangrycat / FPGA bitstream).

**Edge AI accelerator security (TPU / NPU on RTOS)**: Google Edge TPU,
Hailo, Mythic, Synaptics, Kneron — driver interfaces (DMA, shared
memory, control-plane registers) are new attack surface; loaded models
are input parsers (proprietary binary formats per vendor) with limited
public research. Productive area for 2026-2030.

---

## XV. References

### Researchers and disclosures

- Jos Wetzels (Forescout Vedere Labs): https://datatracker.ietf.org/person/jos.wetzels@forescout.com
- Daniel dos Santos (Forescout Vedere Labs): https://www.forescout.com/research-labs/
- Stanislav Dashevskyi: https://standash.github.io/
- Zachary Cutlip: https://github.com/zcutlip
- Brian Gorenc (ZDI): https://www.thezdi.com/
- Yannay Livneh: https://www.enigmatos.com/advisors/yannay-livneh/

### Disclosures and CVE blocks

- URGENT/11 (Armis, 2019): https://www.armis.com/research/urgent-11/
- Ripple20 (JSOF, 2020): https://www.jsof-tech.com/disclosures/ripple20/
- AMNESIA:33 (Forescout, 2020): https://www.forescout.com/blog/amnesia33-forescout-research-labs-finds-33-new-vulnerabilities-in-open-source-tcp-ip-stacks/
- NUMBER:JACK (Forescout, 2021): https://www.forescout.com/blog/numberjack-forescout-research-labs-finds-nine-isn-generation-vulnerabilities-affecting-tcpip-stacks/
- NAME:WRECK (Forescout/JSOF, 2021): https://www.forescout.com/research-labs/namewreck/
- INFRA:HALT (Forescout/JFrog, 2021): https://www.forescout.com/research-labs/infra-halt/
- NUCLEUS:13 (Forescout/Medigate, 2021): https://www.forescout.com/research-labs/nucleus-13/
- OT:ICEFALL (Forescout, 2022): https://www.forescout.com/research-labs/ot-icefall/
- Sierra:21 (Forescout, 2023): https://www.forescout.com/research-labs/sierra21/
- Project Memoria overview: https://www.forescout.com/research-labs/project-memoria/
- project-memoria-detector tool: https://github.com/Forescout/project-memoria-detector
- BadAlloc (Microsoft Section 52, 2021): https://msrc-blog.microsoft.com/2021/04/29/badalloc-memory-allocation-vulnerabilities-could-affect-wide-range-of-iot-and-ot-devices-in-industrial-medical-and-enterprise-networks/
- CISA AA21-229A (BadAlloc/QNX): https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-229a
- Zimperium FreeRTOS+TCP disclosure (2018): https://zimperium.com/blog/freertos-tcpip-stack-vulnerabilities-details
- Exodus Intelligence VxWorks (2016): https://blog.exodusintel.com/2016/08/09/vxworks-execute-my-packets/
- BusyBox disclosure (Claroty/JFrog 2021): https://jfrog.com/blog/unboxing-busybox-14-new-vulnerabilities-uncovered-by-claroty-and-jfrog/
- RFC 9267 (DNS RR processing anti-patterns): https://datatracker.ietf.org/doc/html/rfc9267

### RTOS project documentation

- Zephyr Project security: https://zephyrproject.org/security/
- Zephyr vulnerability reporting: https://docs.zephyrproject.org/latest/security/reporting.html
- Zephyr GitHub Security Advisories: https://github.com/zephyrproject-rtos/zephyr/security/advisories
- FreeRTOS MPU support: https://www.freertos.org/Security/04-FreeRTOS-MPU-memory-protection-unit
- FreeRTOS security: https://www.freertos.org/Documentation/04-Demos/02-Security
- NuttX (Apache project): https://nuttx.apache.org/
- PX4 / NuttX: https://github.com/PX4/NuttX
- Eclipse ThreadX: https://threadx.io/
- Eclipse ThreadX GitHub: https://github.com/eclipse-threadx
- VxWorks (Wind River): https://www.windriver.com/products/vxworks
- QNX (BlackBerry): https://blackberry.qnx.com/
- INTEGRITY (Green Hills): https://www.ghs.com/products/rtos/integrity.html
- PikeOS (SYSGO): https://www.sysgo.com/pikeos
- RT-Thread: https://www.rt-thread.io/
- MicroPython: https://micropython.org/
- CircuitPython: https://circuitpython.org/

### Tools and frameworks

- Renode (Antmicro): https://renode.io/
- Renode GitHub: https://github.com/renode/renode
- AFL++ + Renode + Zephyr: https://antmicro.com/blog/2023/10/fuzzing-zephyr-with-afl-renode
- Boofuzz: https://github.com/jtpereyda/boofuzz
- MCUboot: https://github.com/mcu-tools/mcuboot
- Bowcaster: https://github.com/zcutlip/bowcaster
- Rtkaller (EMSOFT 2021): http://www.wingtecher.com/themes/WingTecherResearch/assets/papers/emsoft21.pdf
- RTIC (Rust): https://rtic.rs/
- Tock (Rust): https://tockos.org/
- WAMR (WebAssembly Micro Runtime): https://github.com/bytecodealliance/wasm-micro-runtime
- Wasm3: https://github.com/wasm3/wasm3
- WasmEdge: https://github.com/WasmEdge/WasmEdge

### Standards and frameworks

- PSA Certified: https://www.psacertified.org/
- ARM TrustZone for Cortex-M: https://www.arm.com/technologies/trustzone-for-cortex-m
- Common Criteria EAL levels: https://www.commoncriteriaportal.org/
- CSAF (OASIS): https://www.oasis-open.org/standards/#csafv2.0
- CycloneDX SBOM: https://cyclonedx.org/
- OpenVEX: https://github.com/openvex
- IoT Security Foundation SBOM whitepaper: https://www.iotsecurityfoundation.org/wp-content/uploads/2023/02/RELEASE-2022-02-19-IoTSF-SBOM-whitepaper-v1-1-0.pdf
- FIRST.org Consolidated SBOM/VEX Framework: https://www.first.org/standards/frameworks/psirts/Consolidated-SBOM-VEX-Operational-Framework.pdf
- EU Cyber Resilience Act / Zephyr compliance: https://docs.zephyrproject.org/latest/security/standards/cyber-resilience-act.html

### Buildroot, Yocto, embedded Linux

- Yocto Project Security: https://wiki.yoctoproject.org/wiki/Security
- Yocto CVE management: https://www.thegoodpenguin.co.uk/blog/yocto-security-hardening-cve/
- BusyBox: https://busybox.net/
