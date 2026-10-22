# Digital Forensics and Incident Response — Methodology, Tools, and Cloud-Era Discipline
## Synthesized from Brian Carrier, Eoghan Casey, Andrew Case, Michael Hale Ligh, Jamie Levy, AAron Walters, Hal Pomeranz, Sarah Edwards, Heather Mahalik Barnhart, Lenny Zeltser, Lesley Carhart, Richard Bejtlich, Chris Sanders, Ryan McGeehan, and the MITRE Engenuity Center for Threat-Informed Defense

> **Researchers:**
> - **Brian Carrier** (Ph.D., Purdue; formerly Basis Technology; founder of Sleuth Kit
>   Labs and Cyber Triage) — Author of *File System Forensic Analysis* (Addison-Wesley,
>   2005), the canonical text on FAT, NTFS, ext, and UFS forensic analysis. Maintainer
>   of The Sleuth Kit (TSK) and Autopsy, the dominant open-source disk-forensics
>   tooling.
> - **Eoghan Casey** (Ph.D.; Professor of Digital Forensic Science, Ecole des Sciences
>   Criminelles, Université de Lausanne) — Author of *Digital Evidence and Computer
>   Crime: Forensic Science, Computers, and the Internet* (Academic Press, 3rd ed.
>   2011), the foundational graduate textbook in digital forensics. Editor-in-Chief of
>   *Forensic Science International: Digital Investigation* since 2004. Previously
>   Chief Scientist at the Defense Cyber Crime Center (DC3).
> - **Andrew Case, Michael Hale Ligh, Jamie Levy, AAron Walters** — Co-authors of
>   *The Art of Memory Forensics: Detecting Malware and Threats in Windows, Linux, and
>   Mac Memory* (Wiley, 2014) and core developers of Volatility. Walters is founder
>   and lead developer of Volatility and President of the Volatility Foundation; Case
>   is Director of Research at Volexity. The
>   Volatility 3 framework (Python 3, modular plugins) is the dominant open-source
>   memory-forensics tooling for Windows, Linux, and macOS.
> - **Hal Pomeranz** (Principal Consultant, Deer Run Associates; SANS Faculty Fellow)
>   — Linux/Unix forensics specialist; author of ext3/ext4 recovery tooling and
>   primary instructor for SANS SEC506 *Securing Linux/Unix*. Long-running SANS DFIR
>   blog contributor; *Command Line Kung Fu* co-author. The reference voice on
>   practical Linux artifact discovery (`auditd`, journald, ext4 carving).
> - **Sarah Edwards** (SANS Faculty Fellow; mac4n6.com) — Author and instructor of
>   SANS FOR518 *Mac and iOS Forensic Analysis and Incident Response*, the first
>   non-vendor Apple-platform forensics course. Creator of APOLLO (Apple Pattern of
>   Life Lazy Output'er), the open-source toolkit decoding macOS/iOS pattern-of-life
>   SQLite artifacts (KnowledgeC, biome, locationd, Spotlight).
> - **Heather Mahalik Barnhart** (Senior Director, Community Engagement, Cellebrite;
>   SANS DFIR Curriculum Lead; Faculty Fellow) — Co-author and primary instructor of
>   SANS FOR585 *Smartphone Forensic Analysis In-Depth*; co-author of *Practical
>   Mobile Forensics* (Packt). Twenty-plus years of mobile-device investigation
>   experience; "Earn the Tool" doctrine — operate the device, then the tool, then
>   trust the output.
> - **Lenny Zeltser** (CISO, Axonius; SANS Faculty Fellow) — Founder and primary
>   maintainer of REMnux, the Linux distribution for malware analysis (hundreds of tools).
>   Author of SANS FOR610 *Reverse-Engineering Malware*. Practitioner voice on
>   static/dynamic analysis pipelines and on scaling security programs.
> - **Lesley Carhart** (Director of Incident Response — North America, Dragos) —
>   ICS/OT incident-response practitioner. Maintains *tisiphone.net*; DEF CON Hacker
>   of the Year; SANS Difference Maker. Distinguishes commodity-malware IR on OT
>   networks from targeted ICS intrusions — methodologically different problems.
>   Public writing on IR psychology and the junior-analyst pipeline is widely cited.
> - **Richard Bejtlich** (formerly TaoSecurity, GE-CIRT, Mandiant CSO, FireEye Chief
>   Security Strategist; currently Corelight advisor) — Author of *The Tao of Network
>   Security Monitoring* (2004) and *The Practice of Network Security Monitoring*
>   (No Starch, 2013). Architected NSM doctrine — detect, contain, respond, with
>   full-content network data as evidentiary ground truth. Built and ran the 40-member
>   GE Computer Incident Response Team.
> - **Chris Sanders** (founder, Applied Network Defense) — Co-author with Jason Smith
>   of *Applied Network Security Monitoring: Collection, Detection, and Analysis*
>   (Syngress, 2014); author of *Practical Packet Analysis* (multiple editions, No
>   Starch). Practitioner voice on accessible NSM training and on analyst-facing
>   evidence-reading tradecraft.
> - **Ryan McGeehan** (*@magoo*; scrty.io; formerly Director of Security Incident Response, Facebook;
>   founding security at Coinbase) — *Starting Up Security* essays codify IR for
>   small / early-stage teams. *An Incident Response Plan for Startups*, *Security
>   Breach 101*, and the annual *Learning from a Year of Security Breaches* essays
>   are standard reading on small-team breach comms and operational discipline.
> - **MITRE Engenuity Center for Threat-Informed Defense (CTID)** — Authors of the
>   Adversary Emulation Library and the ATT&CK Workbench; the Cyber Analytics
>   Repository (CAR) is a MITRE project. CAR formalizes detection analytics as ATT&CK-mapped pseudocode; the
>   bridge between ATT&CK as taxonomy and CAR/Sigma as detection IR.
>
> **Sources:** Carrier, *File System Forensic Analysis* (2005); Casey, *Digital
> Evidence and Computer Crime* (3rd ed., 2011); Case, Hale Ligh, Levy, Walters,
> *The Art of Memory Forensics* (2014); Bejtlich, *The Practice of Network Security
> Monitoring* (2013); Sanders & Smith, *Applied Network Security Monitoring* (2014);
> Mahalik et al., *Practical Mobile Forensics*; NIST SP 800-61 Rev. 2 (Aug 2012,
> withdrawn) and Rev. 3 (Apr 2025); RFC 3227 (2002); Volatility 3
> (`volatility3.readthedocs.io`); The Sleuth Kit / Autopsy; Plaso / log2timeline;
> Amnesty Tech *Forensic Methodology Report* (2021) and MVT; Citizen Lab Pegasus
> archive; MITRE ATT&CK / D3FEND / ATLAS / CAR; AWS / GCP / Azure forensic
> documentation; SANS DFIR poster corpus and FOR500/508/518/526/572/585/610 course
> materials; *tisiphone.net*; *Starting Up Security* on Medium and scrty.io.
> Additional 2024-2026 currency sources: Mandiant UNC5537 disclosure (Jun 2024);
> Microsoft MSRC Midnight Blizzard posts (Jan + Mar 2024) and CISA ED 24-02;
> CrowdStrike Channel File 291 RCA (Aug 2024); Synnovis / NHS Qilin coverage
> (Jun 2024-Nov 2025); Change Healthcare ALPHV/BlackCat coverage and
> Congressional testimony (Feb-May 2024); CDK Global BlackSuit coverage (Jun-Jul
> 2024); SEC Form 8-K Item 1.05 final rule (Dec 2023) and Gerding staff statement
> (May 2024); EU CRA Regulation 2024/2847 and Commission CRA reporting guidance
> (effective Sep 11 2026); OCSF schema and Linux Foundation governance
> transition (Nov 2024); FoxIO JA4+ specification and `ja4db.com` community
> database; Elcomsoft + Cellebrite + HaystackID Stolen Device Protection
> analyses (iOS 17.3, Jan 2024 → 2025); Kaspersky GReAT shutdown.log
> methodology (Jan 2024).

---

## 1. The IR Lifecycle

### NIST SP 800-61 and the SANS six-phase model

The dominant lifecycle in operational use is the SANS six-phase model — Preparation,
Identification, Containment, Eradication, Recovery, Lessons Learned — which compresses
the four-phase NIST SP 800-61 Rev. 2 lifecycle into a sequence that maps to runbook
structure. NIST SP 800-61 Rev. 3 (April 2025) restructured the framework around the
NIST Cybersecurity Framework 2.0 Functions (Govern, Identify, Protect, Detect,
Respond, Recover), shifting IR from a standalone discipline into a risk-management
overlay. Most teams continue to operate the six-phase model day-to-day because it has
runbook resolution; the CSF-aligned framing is the program-level lens. The two are
isomorphic — Preparation maps to Govern+Identify+Protect, Identification to Detect,
Containment+Eradication+Recovery to Respond+Recover, Lessons Learned to the feedback
loop.

### NIST SP 800-61 Rev. 3 — what actually changed (April 2025)

Rev. 3 is the first overhaul of SP 800-61 since the Rev. 2 publication in August
2012 — a 13-year gap covering the entire cloud, container, and EDR/XDR generations
plus the rise of ransomware-as-an-industry. Rev. 3 explicitly *withdraws* the rigid
four-phase lifecycle model from Rev. 2 (Preparation → Detection & Analysis →
Containment, Eradication, Recovery → Post-Incident Activity) and replaces it with a
mapping of incident-response activities to the six CSF 2.0 Functions: Govern,
Identify, Protect, Detect, Respond, Recover. In this mapping, Govern + Identify + Protect cover ongoing
preparation work; Detect surfaces incidents; Respond + Recover handle the active
event; the cycle is continuous, not phased. NIST published Rev. 3 as a CSF 2.0
Community Profile rather than a procedural handbook — operational details that were
in Rev. 2 prose are now in CSF 2.0 subcategory mappings, with implementation
examples called out separately. Operational implication for IR teams: keep
runbook-resolution SANS-six-phase models for tactical use; align program governance
documentation to the Rev. 3 / CSF 2.0 axis (auditors and regulators will start
asking for the mapping). Source:
[NIST CSRC SP 800-61 Rev. 3 (final)](https://csrc.nist.gov/pubs/sp/800/61/r3/final);
[NIST news release on Rev. 3](https://www.nist.gov/news-events/news/2025/04/nist-revises-sp-800-61-incident-response-recommendations-and-considerations);
[NIST SP 800-61r3 PDF](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r3.pdf).

### Preparation is the highest-leverage phase

Every retrospective on a botched IR identifies preparation gaps as load-bearing. The
team that has never rehearsed cannot containerize an investigation in the first hour;
the team that has rehearsed three scenarios in tabletop has muscle memory for the
fourth, novel one. Preparation deliverables:

1. Named on-call structure with explicit handoff protocol. Who pages whom; who
   declares; who decides scope. Carhart repeatedly notes the time-to-decision in the
   first hour is the dominant variable.
2. A logging baseline that survives the incident. Logs the attacker can mutate are
   not evidence. Pre-establish remote shipping with attestation; pre-establish
   immutable cloud audit-log retention.
3. Pre-staged forensic capability — memory-acquisition binaries signed and approved,
   disk-imaging hardware on hand, forensic workstations isolated and validated.
4. Pre-built playbooks for the top-N scenarios — ransomware, credential compromise,
   BEC, supply-chain, insider, ICS intrusion (if applicable). Each has explicit
   decision gates and named roles.
5. Tabletop cadence — quarterly minimum for established programs; monthly for new
   teams or post-incident.
6. Pre-approved communications templates — customer, regulator, internal. The first
   hour is not the time to draft a breach disclosure.
7. Pre-signed vendor IR retainers — forensic firms, breach coaches, PR, legal.

McGeehan's startup-IR-plan essay is the most-cited primer for small teams; Mandiant's
*M-Trends* annual reports are the most-cited mature-program reference. Both converge:
the first hour reveals every gap in preparation that calm times tolerated.

### Casey's investigative process

Casey's *Digital Evidence and Computer Crime* frames the digital forensic
investigation as a structured scientific process: hypothesis → evidence collection →
hypothesis revision → final report. The framing imposes falsifiability. The analyst
who states "this is ransomware" early commits to an explanation; the disciplined
analyst states "leading hypothesis is ransomware with evidence X, Y, Z; the
alternatives that remain plausible are insider data destruction and supply-chain
wiper" and lets evidence collection adjudicate. The cross-link to the steelman
doctrine is direct (`steelman_doctrine_expertise.md`, Variant C — research-style
hypothesis adjudication is structurally identical).

### Decision speed under uncertainty

IR is decision-making under partial information. The data the analyst has is always
less than the data the analyst wants; waiting for completeness isn't an option.
Framing that helps:

- What decision am I being asked to make right now? Containment yes/no. Customer
  comms yes/no. Plane-grounding yes/no.
- What's the cost of being wrong in each direction? False-positive containment
  (operational disruption); false-negative (continued attacker access).
- What evidence would flip the decision? If collectable within the window, collect.
  If not, decide with what you have, document residual uncertainty.

The mature practitioner is calibrated; the novice oscillates between premature
certainty and analysis paralysis. Carhart's "trust the process; the data is what the
data is" is the operational mantra.

### Cross-links

Identification is fed by detection (cross-link
`detection_engineering_expertise.md` §6 — runtime detection signals are identification
triggers). Preparation is fed by threat intelligence
(`threat_intel_methodology_expertise.md` §10 — strategic and operational intel inform
which scenarios to prepare for). The post-incident phase feeds back into both (§11,
§13) — what an incident teaches becomes detection content and intel reporting.

---

## 2. Evidence Handling and Chain of Custody

### What counts as admissible — and when it matters

Most corporate IR work never reaches a courtroom. Chain-of-custody matters anyway:
the team that handles evidence sloppily during the routine incident handles it
sloppily during the non-routine one — the one that does end up at trial, in a
regulator inquiry, or in a civil suit. Casey's stance is the standard — treat all
evidence as if it will be litigated. The marginal cost of doing it right is small;
the cost of botching the case that matters is large.

Admissibility standards vary by jurisdiction. In the US, *Daubert v. Merrell Dow
Pharmaceuticals* (1993) governs expert testimony — testimony must be based on a
methodology that is testable, peer-reviewed, has a known error rate, and is generally
accepted. In the EU, ENFSI (European Network of Forensic Science Institutes)
guidelines establish the equivalent. The cross-jurisdictional doctrine is the same:
documented methodology, reproducible results, qualified analyst, intact custody.

### Order of volatility (RFC 3227)

RFC 3227 (IETF, February 2002) established the canonical order of volatility. From
most to least volatile: (1) registers, cache (microseconds); (2) routing table, ARP
cache, process table, kernel statistics, memory contents (seconds to hours, lost on
reboot); (3) temporary filesystems; (4) disk; (5) remote logging and monitoring data;
(6) physical configuration, network topology; (7) archival media. The doctrine:
collect in descending volatility. Reboot before capturing memory and the memory is
gone. Image the disk before extracting `netstat` and the network state is
approximate, not authoritative. RFC 3227 also stipulates that collection methods
must be transparent, reproducible, and minimize decision-making during collection —
write the procedure ahead of time; execute under pressure.

### Write-blockers and disk imaging

Physical write-blockers (Tableau, WiebeTech, CRU) interpose between the suspect
drive and the forensic workstation, electrically preventing writes. Software
write-blockers (`HKLM\SYSTEM\CurrentControlSet\Control\StorageDevicePolicies`,
`blockdev --setro`) are second choice; hardware is standard. Imaging tools producing
bit-for-bit forensic images: `dd`, `dcfldd` (DoD-extended with on-the-fly hashing),
`dc3dd` (DC3-maintained fork), `ewfacquire` (libewf, EnCase E01), FTK Imager
(AccessData), Guymager (Linux GUI), `aff4imager` (next-gen, supports compression and
signing).

Acquire at the physical-disk level (the entire block device), not partition or
filesystem. Hash before, hash after, hash on every analysis copy. Standard practice
as of May 2026 is SHA-256 — MD5 has been deprecated for evidentiary purposes since
the early 2010s due to collision feasibility; SHA-1 also flagged. Cross-link
`cryptography_expertise.md`.

### Hash-based integrity proofs

The integrity proof is the hash, captured at acquisition, propagated through every
copy, validated at presentation. Three capture points: source-media hash (computed
against the original, sometimes skipped on running systems and documented), image
hash (the primary evidentiary artifact), working-copy hash (every working copy
validates against the image hash before analysis). The "hashes match" proof is
reproducible; chain-of-custody documentation pins which analyst hashed which artifact
at what time on what hardware.

### The forensic clean-room

The forensic workstation is itself evidence. Standard practice: isolated network
(air-gapped or dedicated VLAN with no external routing — malware analysis on a
workstation that calls home is malpractice); validated tool baseline (analyst can
demonstrate reproducible results on test data; SWGDE — Scientific Working Group on
Digital Evidence — tool-validation guidance is the reference); read-only mounts on
every analysis (`mount -o ro`, `losetup -r`); signed reports (analyst signature on
findings; cryptographic signature on digital deliverables for inter-agency exchange).

### Sub-zero-trust: evidence is suspect until validated

The mature practitioner treats all evidence as suspect until cross-validated. Reasons:

1. Attackers tamper with evidence — log scrubbing, timestomping, in-memory rootkit
   hiding. The forensic image is *current state*, not necessarily *true state*.
2. Tools have bugs — TSK has had carving false positives; Volatility plugins have
   had Windows-version-specific defects; EnCase has had documented timestamp parsing
   issues. Cross-validation across tools is standard.
3. Time is unreliable — clocks drift, NTP can be lied to, timestomp tools overwrite
   NTFS standard-information timestamps. Cross-validate against $MFT $FileName
   attributes (less commonly timestomped), against centrally-collected logs, against
   external corroboration.
4. Memory snapshots are non-atomic — a memory dump of a 32 GB system takes seconds
   to minutes; processes run during the dump. Page-tearing artifacts are normal.

Cross-link `cryptography_expertise.md` (signing primitives, certificate-chain
validation for in-toto-style provenance).

---

## 3. Memory Forensics — The Volatile-Evidence Layer

### Why memory matters

Disk forensics shows what was; memory forensics shows what is. The attacker's
in-memory state — injected DLLs, hollowed processes, unlinked kernel threads, decoded
strings, network sockets, credentials — exists nowhere else. The shift to fileless
malware over the 2010s (PowerShell-only, .NET-reflective, in-memory commodity
loaders like Cobalt Strike) moved the evidentiary center of gravity from disk to
memory. Modern IR without memory forensics is missing half the attacker.

### Volatility — the canonical framework

Volatility (`volatilityfoundation.org`) is the dominant open-source memory-forensics
framework. Volatility 3 (2.x branch as of May 2026, Python 3, modular plugin
architecture, ISF — Intermediate Symbol Format — for OS-version handling) superseded
Volatility 2 (Python 2, profile-based) in 2025. Layered architecture: memory layers
handle address-space translation, symbol tables provide OS-specific structures,
plugins query and present. Canonical plugins:

- **Process listing** — `windows.pslist`, `windows.psscan`, `linux.pslist`,
  `mac.pslist`. `psscan` uses pool-tag scanning to detect unlinked / hidden
  processes that `pslist` (walks `_EPROCESS` doubly-linked list) misses.
- **DLL / SO walking** — `windows.dlllist`, `linux.proc.Maps`. Reveals injected
  libraries.
- **Network** — `windows.netscan`, `linux.sockstat`, `mac.netstat`.
- **Injection detection** — `windows.malfind` (executable private memory regions),
  `windows.hollowprocesses` (process hollowing), `windows.ldrmodules` (PEB module-list mismatches).
- **Registry** — `windows.registry.printkey`, `windows.registry.hivelist`.
- **Credentials** — `windows.hashdump` (NTLM), `windows.lsadump` (LSA secrets),
  `windows.cachedump` (cached domain creds). Mimikatz-in-memory artifact patterns
  (specific RWX regions in `lsass.exe`) are detectable.
- **Timeline** — `timeliner` produces a memory-resident event CSV.

### Memory acquisition

By platform:

- **Windows: WinPmem** (Velocidex, originally Google Rekall, `winpmem.velocidex.com`)
  — RAW output (the AFF4 imager is yet to be updated to the new driver); kernel
  driver with three independent physical-memory reading methods. F-Response and FTK Imager are commercial
  alternatives.
- **Linux: AVML** (Microsoft, `github.com/microsoft/avml`) — Rust binary, statically
  linked, single-binary deployable. Uses `/proc/kcore`, `/dev/crash`, or `/dev/mem`.
  LiME is the older LKM-based approach; requires kernel-version-matched module
  compilation.
- **macOS: osxpmem** — historical Intel-Mac tool. Acquisition on Apple Silicon (M1
  through M4) is materially harder — the hypervisor enforces memory isolation; no
  kernel extension can DMA the kernel address space. Practical guidance as of May
  2026: full-system memory acquisition on Apple Silicon requires hardware-assisted
  approaches not routinely available to incident responders.

### The Apple Silicon memory-forensic ceiling (2024-2026 status)

As of mid-2026, Volatility 3 macOS support has *not* reached parity with Windows /
Linux on Apple Silicon. The
[Volatility 3 macOS tutorial](https://volatility3.readthedocs.io/en/latest/getting-started-mac-tutorial.html)
states that "As of the Volatility 3 parity release, macOS analysis support is no
longer actively maintained";
practical analysis tops out at older macOS versions on Intel hardware. The Volatility
Foundation's
[Official Parity Release announcement](https://volatilityfoundation.org/announcing-the-official-parity-release-of-volatility-3/)
covered Windows and Linux; it states that "Volatility 3 does not support macOS."
Operational implication for IR teams investigating Apple Silicon endpoints:

1. **Pre-deployment third-party drivers via MDM** are the only practical
   acquisition path. Enterprise managed devices can enroll a vendor (Volexity
   Surge Collect, etc.) via MDM-distributed signed
   kernel extension or system extension; consent + entitlement happens
   pre-incident. Unmanaged or BYOD Apple Silicon devices are effectively memory-
   forensic dark.
2. **Volatility 3 Intel-Mac coverage** is no longer actively maintained as of
   the parity release. macOS Sonoma (14.x, 2023), Sequoia (15.x, 2024), and the
   2025/2026 successor are increasingly off-bench.
3. **Lateral compensation:** unified-log forensics (`log show --predicate` on the
   host; sysdiagnose for offline analysis), endpoint-agent in-memory scan output
   (Defender for Endpoint, CrowdStrike Falcon for Mac, SentinelOne), and APFS
   snapshot forensics fill the gap unevenly. Cross-link `macos_apple_security.md`
   for Apple Silicon platform internals and EndpointSecurity framework forensic
   surface.

The Apple-Silicon memory-forensic gap is the largest *structural* (not tactical)
limitation in the open-source memory-forensic stack as of May 2026.

The acquisition window matters operationally. Reboot the host and the memory is
gone. Capture memory first, network state second, disk last. The reboot-on-suspicion
reflex is a well-documented IR antipattern.

### Volatility profile / symbol-table requirements

Volatility 2 used profiles (pre-built parsing rules per kernel version). Volatility 3
uses ISF — JSON-serialized symbol tables generated from kernel debug symbols (PDB
for Windows, kernel DWARF for Linux/macOS). The Foundation distributes pre-built
tables for major Windows builds; Linux and macOS often require per-kernel table
construction locally. `dwarf2json` and `pdbconv` generate ISF from debug symbols.
Operational implication: an obscure kernel build can stall analysis until a symbol
table exists. Maintain a corpus of symbol tables for kernels in your environment —
preparation work, not response work.

### Code-injection detection patterns

- **Reflective DLL injection** — DLL mapped into private RWX memory. `malfind` flags
  via VAD enumeration of PAGE_EXECUTE_READWRITE regions with no backing file.
- **Process hollowing** — legitimate process started suspended, original image
  unmapped, attacker payload mapped. `windows.hollowprocesses` detects.
- **IAT hooking** — function pointers redirected. `windows.modules` plus manual IAT
  inspection.
- **Inline patching** — function-prologue bytes overwritten with `JMP <hook>`.
  Compare in-memory code bytes against on-disk DLL bytes.
- **PEB walking anomalies** — `InLoadOrderModuleList`, `InMemoryOrderModuleList`,
  `InInitializationOrderModuleList` unlinked or modified one at a time. `ldrmodules`
  cross-references all three.
- **APC injection** — `QueueUserAPC` schedules attacker code in a target thread
  context. APC-queue inspection.

### Rootkit and persistence detection

Kernel rootkits hide from running-system enumeration. Memory forensics defeats most
via pool-tag scanning: the rootkit hides from the OS API but the underlying pool
allocations remain detectable.

- **SSDT hooking** — `windows.callbacks`, `windows.ssdt`.
- **IRP major-function hooking** — driver dispatch tables modified.
- **DKOM (Direct Kernel Object Manipulation)** — `_EPROCESS` unlinked from
  `ActiveProcessLinks` while pool allocation persists. `psscan` finds it.
- **Bootkit / bootloader rootkits** — less common since Secure Boot adoption.
  Cross-link `firmware_embedded_security.md`.

### Credential-dumping artifacts

Mimikatz-and-derivatives leave characteristic `lsass.exe` patterns. Volatility's
`windows.hashdump`, `windows.lsadump`, `windows.cachedump` extract NTLM hashes, LSA
secrets, and cached domain credentials. Detecting mimikatz *use* via memory
forensics requires looking for residual artifacts — specific decrypted material in
unusual memory regions, specific code-injection patterns, specific RWX allocations.
The detection-engineering pivot is direct: Sysmon EID 10 LSASS access logging is the
preventive-detection layer (`detection_engineering_expertise.md` §3); memory
forensics is post-hoc validation.

### Reboot-loses-everything

Memory is gone after reboot. Implications: pre-incident, deploy agents
(CrowdStrike, SentinelOne, Defender, Carbon Black) that retain memory-derived
artifacts via continuous in-memory scanning. During incident, prohibit reboot until
memory captured. Post-incident, train operations and helpdesk never to reboot a
suspected-compromise system without IR sign-off.

Cross-link `linux_kernel_exploitation_expertise.md` and
`macos_memory_corruption_investigation.md` — the offensive side, what the attacker
puts into memory that the forensic analyst then extracts.

---

## 4. Disk Forensics

### The Sleuth Kit and Autopsy

Brian Carrier's The Sleuth Kit (TSK; `sleuthkit.org`) is the canonical open-source
disk-forensics library. Command-line tools (`fls`, `ils`, `mmls`, `fsstat`, `istat`,
`icat`, `blkstat`, `blkcat`, `tsk_recover`) implement file-system-level analysis
across NTFS, ext, FAT, exFAT, HFS+, ISO9660, UFS, YAFFS. Autopsy (`autopsy.com`) is
the GUI with case management, timeline visualization, keyword search, hash-set
matching, and a Python ingest-module plugin architecture. Carrier's *File System
Forensic Analysis* (2005) and its five-layer file-system model (file system,
content, metadata, file name, application) remain the analytical scaffold.

### File-system specifics

| File System | Platforms | Forensic Anchors |
|-------------|-----------|------------------|
| NTFS        | Windows   | `$MFT`, `$LogFile`, `$UsnJrnl:$J`, `$Boot`, `$Bitmap`, `$Secure` |
| ext2/3/4    | Linux     | superblock, group descriptors, inode tables, journal (jbd2) |
| FAT12/16/32 | Embedded, removable | FAT chains, directory entries, deleted-entry markers |
| exFAT       | Removable, SD | FAT-derived; explicit metadata, no journaling |
| HFS+        | macOS legacy | catalog file, extents overflow, attributes file |
| APFS        | macOS / iOS | object map, snapshot trees, encrypted volumes; copy-on-write |
| ReFS        | Windows Server | integrity streams; copy-on-write |
| ZFS / Btrfs | Linux / BSD | copy-on-write; snapshot history; pool-level structures |

For NTFS the `$MFT` is the forensic centerpiece: every file has an entry, deleted
files leave un-allocated entries that retain metadata until overwritten, and the
`$STANDARD_INFORMATION` / `$FILE_NAME` attributes hold timestamps that timestomp
tools target asymmetrically (cross-validate). `$UsnJrnl:$J` records file-system
change events for a configurable retention window — high-value for activity-window
reconstruction. `$LogFile` (NTFS journal) is even higher-resolution but harder to
parse.

### Allocated, unallocated, slack

- **Allocated** — reachable via current file-system metadata.
- **Unallocated** — clusters not currently assigned; may contain deleted-file
  content until overwritten. Carving target.
- **Slack space** — within an allocated cluster, bytes between EOF and end-of-cluster.
  May contain remnants from previously-resident files.
- **MFT slack** — for NTFS, bytes within an MFT entry beyond declared attribute data.

A forensic image preserves all four. Analysis tools (TSK, EnCase, FTK, X-Ways)
expose each to query and carving.

### Timeline construction

The forensic timeline is the unified chronology of every dateable event on the
system. Plaso / log2timeline (`plaso.readthedocs.io`) is the canonical timeline-
building toolchain — a Python framework parsing 100+ artifact types (file-system
metadata, registry hives, browser history, Windows event logs, macOS unified logs,
syslog, prefetch, shellbags, jumplists, LNK files) and emitting a unified CSV or
SQLite database for `psort`, Timesketch (`timesketch.org`, Google), Splunk, or
Excel. Discipline:

1. Image first, then timeline. Never timeline a running system.
2. Use all timestamp sources, not just file-system. $MFT $STANDARD_INFORMATION and
   $FILE_NAME both. Registry last-write. Event log records. Browser history.
3. Normalize to UTC. The single most common timeline error is timezone confusion.
4. Pivot on anomalies. A burst of activity in a typically-quiet window. `lsass.exe`
   access from a non-privileged process. A scheduled-task creation at 3:47 AM local.
5. Cross-validate with external sources — network logs, authentication logs, EDR.

### Carving

Carving recovers files from raw bytes without filesystem metadata. Tools: `scalpel`
(signature-based header/footer pair matching); `foremost` (DoD-derived, also
signature-based); PhotoRec / TestDisk (`cgsecurity.org`; high recall on JPEG, PNG,
DOCX, PDF, MP4); `bulk_extractor` (Simson Garfinkel; extracts strings, emails,
URLs, credit-card patterns; high recall, low precision). Carving is approximate —
the recovered file is a candidate; validate via header inspection, content
cohesion, metadata cross-reference. False positives are common.

### The anti-forensics arms race

- **Timestomping** — modify timestamps. Mitigation: cross-validate
  $STANDARD_INFORMATION vs $FILE_NAME; cross-validate external sources.
- **Secure-erase** — multi-pass overwriting. Mitigation: limited; depends on
  implementation correctness.
- **Encrypted containers** — VeraCrypt, BitLocker, FileVault, LUKS. Mitigation:
  capture credentials in memory before container locks; cooperative decryption;
  legal compulsion in some jurisdictions.
- **Anti-forensic tooling** — Eraser, BleachBit, CCleaner secure-delete. Tools leave
  use-traces (registry entries, prefetch, `$LogFile` entries).
- **Living-off-the-land binaries (LOLBins)** — attacker uses native OS tools
  (PowerShell, WMIC, certutil, bitsadmin) to avoid dropping detectable malware.
  Mitigation: memory forensics, command-line auditing (Sysmon EID 1, PowerShell
  ScriptBlock 4104).
- **Full-disk encryption with attacker-controlled key** — emerging ransomware.
  Mitigation: backups (cross-link `cryptography_expertise.md`).

The arms race is asymmetric — defense is structural (logging, attestation,
immutable copies) more than tactical.

---

## 5. Log Forensics

### Everything is logs

Modern systems generate logs at every layer: kernel, syscalls, network, application,
identity, cloud control plane. Effective IR depends on correlating across all of
them. The dominant challenge is volume — terabytes per day in enterprise environments
— and the practitioner's discipline is *query, don't grep*.

Log sources by layer (full treatment in `detection_engineering_expertise.md` §2):
endpoint (Windows Event Log Security/System/Application plus Microsoft-Windows-*
providers, Linux auditd / journald / syslog, macOS unified log, Sysmon cross-
platform, EDR telemetry from CrowdStrike / SentinelOne / Defender / Carbon Black);
network (Zeek connection logs, NetFlow / sFlow / IPFIX, firewall, DNS query logs,
proxy); identity (Active Directory event logs 4624/4625/4768/4769/4776/4672, Entra
ID sign-in and audit logs, Okta logs, Google Workspace admin audit); cloud (AWS
CloudTrail, VPC Flow Logs, S3 access; GCP Cloud Audit Logs, VPC Flow Logs; Azure
Activity Log, Diagnostic Logs); application (web-server access, API, DB audit,
custom); containers (kube-apiserver audit, etcd audit, container runtime, pod
logs).

### Log normalization

Normalization standards: **Sigma** (`sigmahq.io`; open-standard for detection rules
and log-format mapping; the detection-engineering source of truth); **CEF**
(ArcSight / HPE-originated); **LEEF** (IBM QRadar); **CIM** (Splunk); **OCSF** (Open
Cybersecurity Schema Framework — emerging vendor-neutral schema from Splunk, AWS,
others); **ECS** (Elastic Common Schema). Practitioner pattern: ingest native, parse
to normalized schema at the SIEM, query against normalized fields. Inconsistent
field names across sources is the dominant operational tax.

### Modern log-forensics workbenches

ELK / Elastic Stack (Elasticsearch, Logstash, Kibana, Beats; Elastic Security as the
SIEM/XDR layer); OpenSearch (AWS-originated fork, Linux Foundation-governed since 2024); Splunk (dominant commercial
enterprise SIEM); Microsoft Sentinel (cloud-native, Azure-hosted, KQL); Google
Chronicle (cloud-native, high-volume); Devo, Sumo Logic, Datadog Security, Panther,
Hunters; Timesketch (investigation-specific timeline analysis beside the SIEM). DFIR
engagements typically use the customer's SIEM if mature, augmented with a
case-specific Timesketch or Elastic for investigation-window deep work.

### Retention vs storage cost

Standard tiering: hot (queryable in seconds, 30 to 90 days); warm (queryable in
minutes, 90 days to 1 year); cold / archive (queryable in hours, 1 to 7 years; S3
Glacier, GCS Coldline, Azure Archive). Compliance overlay sets minimums (PCI-DSS 1
year; HIPAA up to 6 years per jurisdiction; SOC 2 typically 1 year). IR overlay
sets practical minimums based on attacker dwell time — median has compressed from
200+ days (M-Trends 2013) to a 10–11-day global median, ~5 days when the adversary
notifies (notably ransomware) (M-Trends 2024/2025); espionage still ran 122 days
(M-Trends 2026), but the team needs enough history to investigate a
discovered intrusion that started months earlier. Hot 90 days, warm 1 year is a
reasonable default for mid-size environments.

### Log tampering detection

Defenses: centralized log shipping with attestation (logs leave the host via a
signed channel; tampering on the host is detected by absence on the central store);
append-only stores (S3 Object Lock, immutable tiers — cross-link
`cloud_iam_expertise.md`); cryptographic log signing per entry; HSM-attested log
streams (higher-assurance, cross-link `cryptography_expertise.md`); log-tampering
detection rules (Windows Security EID 1102 security log cleared, auditd anomalies, log-source
gaps).

### Cloud audit-log forensics

AWS CloudTrail (control-plane API logging; required to be on; multi-region;
organization-wide; with S3 Object Lock for immutability; Management events
standard, Data events high-volume selective); VPC Flow Logs (network-flow capture);
GuardDuty findings; Security Hub aggregation; AWS Config (configuration change
history). GCP Cloud Audit Logs (Admin Activity always on with ~400-day retention,
Data Access off by default — enable per-service, System Event); Security Command
Center. Azure Activity Log (~90-day default), Microsoft Defender XDR, Sentinel.

Cross-link `detection_engineering_expertise.md` (log-based detection content).

---

## 6. Network Forensics and NSM

### Bejtlich's NSM doctrine

Bejtlich's *Tao of NSM* (2004) and *Practice of NSM* (2013) established NSM as a
discipline: collect network data continuously, retain enough to investigate, detect
to identify incidents, contain to limit damage, respond to resolve. NSM's central
claim is that the network is the most-trustworthy evidence layer — endpoints can be
compromised and lie, but the network is the substrate over which the attacker's
tools actually communicate.

NSM data hierarchy: full-content data (every packet; high fidelity, high storage);
session / flow data (5-tuple, byte counts, duration, timing; lower cost, adequate
signal for most investigations); transaction data (application-layer events — DNS,
HTTP, TLS handshakes; mid-cost, Zeek's primary output); alert data (IDS/IPS hits;
lowest cost); statistical data (aggregations and baselines). The mature program
tiers retention: full-content for days to weeks, flow / transaction for months,
statistical / alert effectively forever.

### Tools

**Wireshark** (packet analyzer; hundreds of dissectors); **tcpdump / tshark**
(command-line); **Zeek** (formerly Bro, `zeek.org`; open-source network analysis
producing structured conn.log, http.log, dns.log, ssl.log, files.log, x509.log; NSM
standard); **Suricata** (`suricata.io`; open-source IDS/IPS/NSM with rule-based
detection and protocol parsing; often paired with Zeek); **Arkime** (formerly
Moloch, `arkime.com`; full-packet-capture indexer with searchable session metadata
— the PCAP-at-scale standard); **NetworkMiner** (passive content extraction);
**NfDump / SiLK** (NetFlow / IPFIX analysis at scale); **stenographer** (Google;
fast PCAP capture-and-store).

### Full PCAP vs flow vs metadata

A 10 Gbps link at 50% utilization produces ~50 TB/day of packet data. Full PCAP
retention beyond days requires substantial infrastructure. Flow / metadata (Zeek
conn.log, NetFlow v9, IPFIX) is two to three orders of magnitude smaller and
retains the signal needed for most investigations — which hosts talked, when, how
much, in what protocol — but not what was said. Mature programs do both, tiered.

### TLS-blind era

By 2020 ~95% of internet traffic was TLS-encrypted; the share continues to rise.
NSM dependent on content inspection is increasingly TLS-blind. Compensating shifts:

1. **Metadata-only NSM.** TLS handshake metadata (SNI, cert fingerprints) is still
   visible. JA3 / JA4 / JA4S TLS-stack fingerprinting (cross-link
   `detection_engineering_expertise.md` §2 and `threat_intel_methodology_expertise.md`
   §3) identifies the *client* by TLS-library characteristics — different malware
   families and operator toolchains have characteristic JA4 hashes.
2. **Endpoint visibility.** EDR/XDR sees process-level activity before TLS; the
   network blind spot is partially compensated.
3. **TLS interception** on outbound proxy. Increasingly difficult (HSTS, cert
   pinning, ECH, browser pinning) and legally / ethically constrained.
4. **DNS as residual content channel.** DNS queries reveal destinations before TLS;
   DNS-over-HTTPS and DNS-over-TLS reduce this. Cross-link
   `dns_network_infrastructure.md`.

### JA3 / JA4 fingerprinting

JA3 (John Althouse, Salesforce, 2017) hashes TLS Client Hello fields (cipher
suites, extensions, elliptic curves, point formats). JA4 (FoxIO, 2023) refines the
format. JA3S / JA4S do the same for Server Hello. The fingerprint identifies the
TLS library / version / configuration — not the user, not the host, but the tool.
Detection use: known-bad fingerprint list with outbound-connection alerts. DFIR
use: retro-pivot — a network log shows JA4 = X, what's been seen using that
fingerprint? Cross-link `threat_intel_methodology_expertise.md` §3.

### The JA4+ family (2023-2026 expansion)

By mid-2026 the [JA4+ suite (FoxIO)](https://github.com/FoxIO-LLC/ja4) has expanded
well beyond the original Client Hello fingerprint into a family of complementary
fingerprints covering the entire encrypted-connection surface. Members include:

- **JA4** — TLS Client Hello (the original).
- **JA4S** — TLS Server Hello. Pairing JA4 + JA4S "going from merely identifying
  underlying libraries of a client to identifying the client or malware family"
  ([FoxIO blog](https://blog.foxio.io/ja4+-network-fingerprinting)).
- **JA4H** — HTTP client request fingerprint. Useful on TLS-terminating proxies,
  WAFs, and load balancers where TLS is decrypted.
- **JA4X** — X.509 certificate fingerprint; identifies certificate-authoring
  toolchains (e.g., self-signed C2-server signatures).
- **JA4L / JA4LS** — TLS handshake latency / server latency; geographic/topology
  proxy.
- **JA4SSH** — SSH client / server fingerprint.
- **JA4T / JA4TS / JA4TScan** — TCP-level fingerprinting (window size, options
  order) — operating-system-level fingerprint that survives TLS encryption
  because it operates below the TLS layer.

All JA4+ fingerprints use an `a_b_c` format so analysts can pivot on partial
matches (`ab`, `ac`, or `c` alone). The community-maintained
[JA4+ database (`ja4db.com`)](https://ja4db.com/) tracks known associations
between fingerprints and applications, malware families, certificate authorities,
libraries, and operating systems. Tooling integrations: Cloudflare ships JA4 +
JA4H in its analytics platform
([Cloudflare blog Aug 2024](https://blog.cloudflare.com/ja4-signals/)); Google
Cloud Threat Intelligence integrates JA4
([GCTI deep dive](https://security.googlecloudcommunity.com/community-blog-42/ja4-fingerprinting-in-gti-deep-dive-6043));
TheHive integrates JA4+ via observable enrichment
([StrangeBee blog](https://strangebee.com/blog/ja4-fingerprinting-now-available-in-thehive/)).
Suricata ships upstream JA4 for TLS and QUIC (since 7.0.6, off by default), but
FoxIO lists its JA4+ support as under development; Zeek support comes from
FoxIO's own JA4+ package. JA4+ is broadly available in
commercial NDR / NSM products. License caveat: FoxIO License 1.1 is permissive
for academic and internal-business use; not permissive for monetization without
license.

For the DFIR practitioner in the TLS-encrypted era, JA4+ is the most-important
new fingerprinting addition since JA3 — it extends pivot capability to layers
below TLS (TCP-stack via JA4T), above TLS (HTTP via JA4H), and into certificate
infrastructure (JA4X) — partially restoring the metadata-only NSM workflow on
encrypted-traffic networks.

### DNS forensics

Artifact sources: internal DNS query logs (debug / analytical logging on Windows DNS,
`querylog yes` / `rndc querylog on` on BIND, Pi-hole / Unbound on small networks); passive DNS (Farsight,
Microsoft Defender TI, DomainTools, SecurityTrails, Validin — third-party corpora
for historical resolution); DNS-over-HTTPS / DNS-over-TLS endpoints (when clients
bypass internal DNS, visibility moves to network-flow metadata only). Patterns: DGA
detection via lexical analysis; long-TXT-record exfiltration; fast-flux
infrastructure; sinkholed-domain beaconing.

### In-network MITM vs endpoint-only

The architectural debate is in-line TLS-interception inspection (visibility win,
complexity and security cost) vs endpoint visibility (lower overhead, no TLS
termination). The trend since ~2020 is endpoint-first — EDR / XDR for process-level
visibility, networking restricted to metadata. In-network inspection still wins in
high-security regulated environments, ICS/OT networks where endpoint deployment is
constrained, and deep-packet-inspection-mandate compliance scenarios.

---

## 7. Cloud Forensics — The New Discipline

### Why cloud is structurally different

On-prem forensics has a substrate: physical hosts, disks, RAM. Cloud forensics works
on a substrate the investigator does not own:

1. **Ephemeral resources.** A Lambda function ran, emitted a log line, was destroyed.
   No host to image.
2. **Shared-tenancy.** Hypervisor and underlying infrastructure are vendor-
   controlled; no visibility below the workload boundary.
3. **Vendor-controlled hypervisor.** Memory acquisition of the underlying VM is
   impossible from the customer side. EC2 / Compute Engine / Azure VM memory is
   reachable only via guest-OS tools (WinPmem, AVML) while the instance is running.
4. **Log-as-only-evidence.** Ephemeral workload → cloud audit log is the only
   persistent record. If the log wasn't enabled, the evidence doesn't exist.

The implication: cloud IR depends on customer preparation, far more than on-prem.
The forensic capability is determined by which logs were turned on before the
incident, not by what tools the responder brings.

### The four data classes for cloud IR

1. **Control plane** — API calls; who created/modified/deleted what. CloudTrail,
   Cloud Audit Logs, Activity Log.
2. **Data plane** — resource-internal activity. S3 access logs, VPC Flow Logs, RDS
   audit logs, blob access logs.
3. **Runtime** — workload-internal. EC2 in-OS logs, container logs, Lambda execution
   logs.
4. **Identity** — authentication events. IAM, Entra ID, Okta, SSO IDP.

Typical investigation pivots across all four: identity event (sign-in from unusual
location) → control plane (signed-in principal created new IAM role) → data plane
(new role accessed S3 buckets) → runtime (role assumed by EC2 instance that
exfiltrated data).

### AWS-specific

**CloudTrail** — required for IR; enable in every region; aggregate to a central
account with S3 Object Lock; CloudTrail Lake for queryable investigation. **VPC
Flow Logs** at VPC, subnet, or ENI granularity. **GuardDuty** managed threat
detection. **Security Hub** findings aggregation. **AWS Config** configuration-
change history. **Athena over CloudTrail** is the dominant IR-query pattern.
**Detective** is the graph-based pivot tool. **AWS Security Incident Response
Guide** covers role isolation, instance isolation, EBS snapshot acquisition,
forensic-account architecture. EBS snapshot acquisition is the AWS disk-imaging
path: snapshot the volume → copy to a forensic account → attach to a forensic
instance. API-driven; scriptable as a containment + acquisition step.

### GCP-specific

**Cloud Audit Logs** — Admin Activity (on by default, ~400-day retention), Data
Access (off by default — enable per-service), System Event. **VPC Flow Logs** for
GCE network flow. **Security Command Center** with Premium-tier managed threat
detection (Event Threat Detection, Container Threat Detection). **Cloud Logging**
unified substrate; export to Pub/Sub, BigQuery, GCS. **Persistent disk snapshots**
for disk acquisition.

### Azure-specific

**Activity Log** subscription-level control-plane log; ~90-day default; export to
Log Analytics or storage. **Microsoft Defender XDR / Sentinel** as the XDR+SIEM
stack — Sentinel is the KQL analytical layer. **Microsoft Entra ID** (formerly
Azure AD) sign-in logs, audit logs, risk detections — the identity-forensics anchor
for Microsoft-environment investigations. **Azure Disk snapshots** for disk
acquisition.

### Containers and Kubernetes

The forensic substrate is layered: **kube-apiserver audit log** (every API call;
control-plane forensic anchor; configurable audit policy controls verbosity);
**etcd audit** (less commonly enabled, high-value if so); **container runtime logs**
(containerd, CRI-O); **pod logs** (application stdout/stderr; shipped to log
aggregator); **Falco runtime events** (`falco.org`, CNCF runtime-security project;
syscall-level patterns); **CNI flow logs** (Cilium, Calico, AWS VPC CNI). The IR
challenge — container forensic acquisition is structurally different: no disk to
image (writable layer overlayed on image), no persistent memory beyond runtime.
Snapshot the writable layer via `crictl` / `nerdctl`, capture process memory while
running, then preserve. The window is short. Cross-link `container_k8s_security.md`.

### The customer-must-enable-logs problem

A common cloud-IR opening pattern: IR firm arrives, asks for CloudTrail history
covering the suspected window, learns CloudTrail was off or scoped to a subset of
regions. Forensic capability cap is fixed at the moment of intrusion — preparation,
not response. The repeated recommendation: enable comprehensive audit logging in
every cloud account before any incident, with immutable storage, centralized
aggregation, and a tested query interface. Cross-link `cloud_iam_expertise.md` §9
detection patterns, §11 forensic-logging architecture.

### Multi-cloud forensic standardization — OCSF (2022-2026)

The
[Open Cybersecurity Schema Framework (OCSF)](https://ocsf.io/) — launched in
August 2022 with 18 founding organizations led by AWS and Splunk and transitioned to Linux
Foundation governance in November 2024 — is the dominant emerging vendor-
agnostic schema for security telemetry. OCSF defines normalized event classes
across categories including System Activity, Findings, Identity & Access
Management, Network Activity, Discovery, and Application Activity, with
extensible attributes per event. At its November 2024 move to the Linux Foundation the project
reported 900+ contributors and ~200 participating organizations.

Forensic-relevance: OCSF is the canonical schema for
[AWS Security Lake](https://docs.aws.amazon.com/security-lake/latest/userguide/open-cybersecurity-schema-framework.html),
which aggregates CloudTrail, VPC Flow, Route 53 query logs, EKS audit logs, and
arbitrary partner sources into Parquet/columnar format in S3 for cross-vendor
investigation via Athena, Spark, or partner-tool engines. Google Chronicle,
Splunk Enterprise Security, Microsoft Sentinel, CrowdStrike Falcon LogScale,
Datadog Cloud SIEM, and others support OCSF ingestion or output. The 2024-2026
maturity arc moved OCSF from "vendor PR press-release standard" to "operational
multi-cloud / multi-vendor query substrate." For DFIR teams the practical
implication: cross-vendor pivots (CloudTrail finding → CrowdStrike EDR
correlation → Splunk identity-log query) can run against a normalized schema
rather than per-source schema gymnastics. Cross-link `cloud_iam_expertise.md`
§11 (federated-identity log architecture) and
`detection_engineering_expertise.md` §2 (Sigma/normalized-schema detection
content).

---

## 8. Malware Analysis — The IR Sub-Discipline

### Static vs dynamic

**Static** — examine the artifact without running it. File-type identification,
string extraction, import-table walking, decompilation. Fast, safe, partial.
Defeats most runtime evasion; defeated by packing / obfuscation. **Dynamic** — run
in an instrumented environment and observe. Slow, dangerous, complete. Defeats most
static evasion; defeated by sandbox-aware checks. Mature workflow combines both —
static triage to characterize and prioritize, dynamic detonation to extract
behavior, iterative loop until understood.

### Static analysis tools

File identification (`file`, `binwalk`, TrID, PEiD); strings (`strings`, FLOSS for
obfuscated strings); PE / ELF / Mach-O parsing (`pe-tree`, `pefile`, `readelf`,
`otool`, `lief`); decompilation (IDA Pro / IDA Home / IDA Free, Hex-Rays
commercial; Ghidra NSA open-source 2019 release, comparable to IDA; Binary Ninja
Vector 35; radare2 / Cutter; Hopper Mac-first); macros and scripts (`oletools`
suite — oleid, olevba, oledump for Office; `pdfid` / `pdfparser` for PDFs;
PowerShell / VBA / JavaScript decoders); **YARA** (pattern-matching engine; de-facto
malware-classification IR, `virustotal.github.io/yara`); **capa** (Mandiant FLARE,
`github.com/mandiant/capa`; maps binary capabilities to ATT&CK techniques).

### Dynamic analysis tools and sandboxes

**CAPE Sandbox** (`github.com/kevoreilly/CAPEv2`; open-source malware-config and
payload-extraction sandbox); **Cuckoo** (legacy, mostly superseded by CAPE);
**Joe Sandbox** (commercial; Windows / macOS / Android / iOS); **Hatching Triage**
(Recorded Future-owned; commercial high-volume); **VMRay** (commercial,
hypervisor-level); **any.run** (interactive cloud sandbox); **Hybrid Analysis**
(CrowdStrike community corpus); live-system observation (Wireshark, Procmon,
Process Hacker / System Informer); network emulation for sandboxed analysis
(INetSim, FakeNet-NG); **Frida** (`frida.re`; dynamic instrumentation, cross-link
`mobile_security_expertise.md` §8).

### REMnux and FLARE-VM

**REMnux** (Lenny Zeltser; `remnux.org`) — Linux malware-analysis distribution with
200+ pre-installed tools spanning static analysis, dynamic analysis, network
emulation, document examination, memory forensics, and AI-assisted analysis. The
canonical Linux-side malware-analyst workbench. **FLARE-VM** (Mandiant FLARE;
`github.com/mandiant/flare-vm`) — Windows-side equivalent. PowerShell installer
converts a Windows VM into a malware-analysis workstation with IDA, Ghidra, x64dbg,
PE-bear, Process Hacker, etc. The two-VM workflow (Windows FLARE-VM for detonation
+ Linux REMnux for triage, networked in a private analysis subnet) is the standard
lab shape.

### Unpacker / obfuscator arms race

Malware author's evasion: packers (UPX, Themida, VMProtect, Enigma, Obsidium,
custom); obfuscators (ConfuserEx .NET, Allatori Java, JSObfuscator; string
encryption, control-flow flattening, API call obfuscation); anti-debug
(`IsDebuggerPresent`, `CheckRemoteDebuggerPresent`, hardware breakpoints, timing
checks, PEB.BeingDebugged); anti-VM (CPUID, MAC address ranges, Registry keys,
driver-list inspection, timing); anti-sandbox (user-interaction requirements,
file-system reconnaissance, sleep-based delays past the sandbox window); anti-
analysis tooling (detect IDA / Ghidra / x64dbg processes).

Analyst countermeasures: hardware-assisted debugging (Intel VT-x, AMD-V, ARM EL2
hypervisor stubs); transparent debugger plugins (Scylla, ScyllaHide); specialized
sandboxes that defeat common anti-VM (VMRay, Joe Sandbox).

### IDA / Ghidra / Binary Ninja

IDA Pro is the two-decade industry standard; IDA Home / IDA Free for lower-budget
use. Ghidra is the NSA open-source equivalent (2019 release; free; comparable in
many dimensions). Binary Ninja (Vector 35) has Python-first scripting and modern
UX. radare2 / Cutter is the open-source command-line-first alternative. Hopper is
the Mac-first option. Choice is largely familiarity; the mature analyst is
comfortable in two and uses what fits the binary.

### YARA rule authoring

YARA rules comprise strings (literal, hex with wildcards, regex) and a Boolean
condition. Ship as text; engines (YARA library, VirusTotal Livehunt, ClamAV, EDR
products) execute against artifacts. IR use: triage (new artifact → run against
in-house corpus → identify family); hunt (suspect TTP → write rule → run across
file corpus or memory images); detection (ship to EDR / network sensor / file-
server scanner); attribution (family-specific YARA enables family-to-actor
mapping). Authoring discipline: high-specificity, test against a large benign
corpus, version-control rules, document false-positive rate. Cross-link
`threat_intel_methodology_expertise.md` §6.

### The "what does this malware do" question, rigorously

Mature malware-analysis output is structured behavior characterization, not prose:

- **Persistence** — registry run keys, services, scheduled tasks, WMI event
  subscriptions, COM hijacks, signed-binary proxy chains. ATT&CK Tactic Persistence
  (TA0003).
- **Network** — C2 protocols, beaconing intervals, jitter, dead-drop resolvers,
  DGAs. Tactic C2 (TA0011).
- **Lateral movement** — credential dumping, hash-grabbing, remote execution. Tactic
  Lateral Movement (TA0008).
- **Discovery** — domain enumeration, process listing, browser-history theft. Tactic
  Discovery (TA0007).
- **Data targeting** — document grabbers, keyloggers, screenshot capture, credential
  stealers.
- **Evasion** — AMSI bypass, ETW patching, anti-debug, packing.

Output maps to MITRE ATT&CK; intel writeups consume it for campaign characterization
(`threat_intel_methodology_expertise.md` §2); detection engineering consumes it for
hunt content (`detection_engineering_expertise.md` §3).

---

## 9. Mobile Forensics

### The Mahalik lineage

SANS FOR585 *Smartphone Forensic Analysis In-Depth* is the canonical mobile-forensics
course; *Practical Mobile Forensics* (Mahalik, Tamma, Bommisetty, Packt) is the
most-cited practitioner reference. Three structural differences from PC forensics:

1. **Closed ecosystems.** iOS and Android both restrict direct device access; the
   forensic substrate is mediated by the OS or by vendor partnership.
2. **Encryption pervasive.** Apple Data Protection and Android File-Based Encryption
   mean device-at-rest is encrypted; user passcode or BFU/AFU (Before First Unlock /
   After First Unlock) state determines what's readable.
3. **Cloud-resident data.** Significant portions of user data live in cloud-backup
   substrates (iCloud, Google Backup) rather than on-device — and cloud acquisition
   requires user credentials or legal compulsion.

### Commercial tooling

**Cellebrite UFED / Inseyets / Premium** (industry standard; logical, file-system,
and physical acquisition where supported; Inseyets is the successor suite combining UFED and
Premium extraction with Physical Analyzer decoding). **Magnet AXIOM** (cross-domain forensic platform with strong mobile, plus
computer and cloud). **Oxygen Forensic Detective** (Russian-origin; LE and
enterprise; mobile + cloud + IoT). **MSAB XRY** (European, LE-focused).
**Elcomsoft** (offline backup analysis, password recovery, cloud acquisition). The
commercial corpus is well-funded because of the LE-investigation market;
exploitation targeting new iOS / Android versions is continuous.

### iOS forensics

iTunes-style backup (logical extraction; user-readable files plus configuration;
encryption optional — if on, requires backup password). Full-file-system extraction
(requires bypass of Data Protection; achievable on unlocked / passcode-known
devices via Cellebrite / GrayKey / Elcomsoft; newer iOS-version support depends on
continuous vendor exploitation work). Keychain access (per-app credential storage;
protected by Data Protection classes — AfterFirstUnlock, WhenUnlocked, etc.).
iCloud backup analysis (requires Apple ID credentials; cloud-resident data via
Elcomsoft or Cellebrite Cloud). **APOLLO** (Sarah Edwards) for pattern-of-life
decoding from iOS SQLite artifacts — KnowledgeC, biome, locationd, Health, Photos
— the "what did the user do when" layer beyond message contents.

### Android forensics

ADB backup (logical, user-readable subset, often disabled or limited by app).
Physical extraction (requires root or boot-loader unlock; destructive of data-at-
rest encryption in many cases). JTAG / chip-off (hardware-level; legacy for
unrooted / damaged devices). Cloud-backup analysis (Google Backup, Samsung Cloud,
vendor-specific; cloud acquisition with credentials or legal compulsion). App-
specific artifact analysis (WhatsApp, Signal, Telegram, Wickr — each has
characteristic on-device storage that the forensic toolchain parses).

### Pegasus and MVT

NSO Group's Pegasus is the highest-profile commercial-grade mobile spyware.
Amnesty Tech's *Forensic Methodology Report* (July 2021), with Citizen Lab,
published IOC methodology and released **MVT** (Mobile Verification Toolkit;
`mvt.re`, `github.com/mvt-project/mvt`) — open-source forensic detection of
Pegasus and similar mercenary-spyware traces on iOS and Android. MVT operation:
acquire backup (or full file-system dump where available) → run MVT against the
artifact with a STIX2 IOC bundle → MVT parses dozens of artifact types (DataUsage,
network logs, manifest cache, Safari history, Webkit cache) and matches against the bundle → report on matched indicators and
timeline. The methodology is the model for civil-society-facing forensic work:
open-source tooling, public IOC publication, signed-evidence chains, named-victim
consent, named operators.

### Citizen Lab methodology

The Citizen Lab (`citizenlab.ca`; cross-link
`threat_intel_methodology_expertise.md` §4) operates the highest-rigor public
mobile-forensic research. Stack: recruit suspected victims via civil-society
networks → acquire forensic backups with informed consent → run MVT plus custom
pipelines → confirm via Apple-Threat-Notifications cross-reference where applicable
→ publish with named victims (consent-attested), named operators (attributed via
infrastructure intel), full evidence chains → cross-publish with Amnesty Tech and
partners. The 2021 Pegasus Project (Forbidden Stories + Amnesty Tech, with Citizen Lab peer review)
is the canonical civil-society-targeted-spyware forensic investigation; cross-link
`mobile_security_expertise.md` §13.

### The cloud-backup gap

A common finding: data gone from the device may persist on cloud-backup; data on
the cloud may not be on the device. Both directions matter. iCloud and Google
Backup retention windows are configurable but typically weeks-to-months; explicit
user-deletion may or may not propagate cloud-side. Mature mobile IR collects both
device-side and cloud-side, then reconciles.

### iOS Stolen Device Protection — the iOS 17.3+ forensic complication

Apple introduced **Stolen Device Protection (SDP)** in iOS 17.3 (January 2024)
and expanded it through subsequent updates. When enabled, SDP requires biometric
authentication (Face ID or Touch ID, no passcode fallback) for sensitive actions
including accessing stored passwords, accessing credit cards, and changing Apple
Account settings; when the device is *away from familiar locations* (home, work),
SDP additionally imposes a *one-hour security delay* on critical changes (Apple
Account password reset, removing Face ID/Touch ID enrolled biometrics, disabling
Find My, etc.), with a second biometric check required at the end of the delay.

Forensic implications, per
[Elcomsoft analysis (March 2025)](https://blog.elcomsoft.com/2025/03/forensic-implications-of-apples-stolen-device-protection/),
[ADF analysis](https://www.adfsolutions.com/adf-blog/ios-stolen-device-protection-a-game-changer-for-users-and-a-challenge-for-law-enforcement),
and [Cellebrite advisory](https://cellebrite.com/en/blog/ios-stolen-device-protection/):

1. **Passcode-known acquisition is no longer sufficient** for many sensitive
   artifact classes. Even with the device unlocked and the passcode in hand,
   biometric authentication is required away from familiar locations. Consent-
   based acquisition by law-enforcement at a non-residential location (booking
   room, lab) hits SDP biometric gates.
2. **The one-hour security delay** affects every workflow that would normally
   reset a credential to gain broader access — Apple ID password reset for iCloud
   acquisition, removing FRP, etc. The delay is enforced at the device level and
   cannot be bypassed.
3. **Workaround** — perform consensual acquisition at the suspect's residence /
   other trusted geographic location, or temporarily disable SDP before
   transport. Both require pre-incident or arrest-scene cooperation that is often
   unavailable.
4. **Legal compulsion** of biometric authentication remains jurisdictionally
   varied. Fifth-Amendment doctrine on passcode compulsion (Doe v. US and successor cases) does not translate cleanly to biometric
   compulsion; the federal-circuit split as of 2025 has not resolved cleanly.
5. **Commercial-tool support** — Cellebrite Premium, Magnet AXIOM, GrayKey, and
   Elcomsoft have advisory documentation on SDP impact; Cellebrite reports SDP
   blocks iTunes-protocol (Advanced Logical) extraction without the owner's
   biometrics but does not affect Inseyets UFED full-file-system extraction when
   the passcode is known.

The Stolen Device Protection regime is the most-significant tightening of
mobile-forensic access since the introduction of File-Based Encryption / Data
Protection. Mobile forensic IR work on Apple Silicon iPhones must account for it
explicitly in scoping; iCloud-backup acquisition with credential reset is no
longer a same-day option.

### MVT updates — Shutdown.log methodology (2024)

The
[Kaspersky GReAT methodology disclosure (January 2024)](https://securelist.com/shutdown-log-lightweight-ios-malware-detection-method/111734/)
identified `Shutdown.log` (per-reboot log inside sysdiagnose archives, under
`system_logs.logarchive/Extra`)
as a previously-unexplored forensic artifact that retains Pegasus / Reign /
Predator infection evidence even when other artifacts are sanitized. The
discovery: spyware processes that fail to terminate during user-initiated shutdown
get logged with their path — `/private/var/db/...` paths appeared across the
infections reviewed (Predator used `/private/var/tmp/`). Kaspersky released
standalone Python scripts to extract and parse it; MVT's `check-sysdiagnose`
ships no built-in sysdiagnose modules. Operational note: shutdown.log requires the user to have
rebooted the device at least once during the infection window. Cross-link
`mobile_security_expertise.md` §13 for the broader Pegasus / Predator forensic
literature.

---

## 10. Incident Response Playbooks

### The first-hour runbook

The first hour is the most important and most error-prone. A mature playbook covers:
declaration criteria (what set of observed conditions triggers declaration; who has
authority; what's the on-call paging structure); IC (Incident Commander) appointment
(one person in charge of decisions — not "the team"; one human with explicit
shift-change handoff); comms-channel establishment (dedicated, secure, evidence-
tracked; out-of-band if primary may be compromised); initial scope characterization
(provisional, revised as evidence accrues); containment-decision gate (cut access
now with operational disruption, or instrument and watch with continued exposure;
IC owns the call); evidence-preservation kickoff (memory, log freezes, snapshots
before any cleanup); comms drafting (internal, customer, regulator templates pulled
and customized).

### Roles

- **Incident Commander (IC).** Makes decisions, holds the timeline, owns
  communications routing. Often a security leader; can be any senior with experience.
- **Communications Lead.** Drafts and routes external and internal messaging; works
  with PR / legal / regulator-comms; stands up customer notification.
- **Technical Investigation Lead.** Owns forensic acquisition, log analysis, IOC
  development; coordinates with SOC, EDR vendor, threat-intel team.
- **Containment Lead.** Owns network isolation, account revocation, system shutdown,
  credential rotation; coordinates with IT and engineering.
- **Legal Counsel.** Privilege protection, breach-notification timing, regulator
  liaison; often outside firm — coordinate retainer in advance.
- **Customer Comms Lead.** Customer-facing notifications, support triage, customer-
  success coordination.
- **Executive Sponsor.** CISO / CEO / Board; kept informed; major decisions
  (operational disruption, public disclosure, ransom decisions).
- **Scribe.** Maintains the incident timeline; often rotated; always present. The
  timeline is the source of truth for postmortem and any legal proceedings.

ICS/OT incident response adds the **Safety Officer** (ensures investigation doesn't
compromise process safety) and the **Process Engineer** (interprets OT-system
behavior alongside cybersecurity investigation).

### McGeehan's Starting-Up-Security tradition

For small / early-stage teams without dedicated IR staff, the core advice:

1. Have a plan, in writing, before you need it. Even a one-pager.
2. Pre-establish relationships — legal, IR firm, breach-coach, PR. The 2 AM call
   from an unknown number is not the time to start cold-calling.
3. Don't trust your own systems. During an incident, assume any system the attacker
   could reach is compromised. Out-of-band comms.
4. Capture before you cleanup. Memory, logs, snapshots — preserve, then act.
5. Communicate honestly, soon, with specifics. The breach that becomes a
   reputational crisis is rarely the breach itself; it's the comms.
6. Postmortem honestly. No blame; full causal chain; structural improvements.

### The Carhart ICS-IR doctrine

The gap between commodity IR and ICS IR: OT systems often cannot be safely shut
down — containment is constrained by process-safety considerations. Communications
with field-site engineering staff is essential — the IR team doesn't understand the
process; the process engineers don't understand the IT investigation. OT telemetry
is often unrecoverable — ICS networks may not have central logging; PLCs and HMIs
may not retain forensic artifacts. The "patch and continue" reflex is unsafe — OT
systems run on schedules driven by physical process; emergency patching is rarely
an option; compensating controls are. Cross-link `firmware_embedded_security.md`.

Cross-link `appsec_program_building_expertise.md` §7 (engineering empathy for SOC
analysts; the IR role consumes outputs from the application-security program); and
`threat_intel_methodology_expertise.md` §10 (intel feeds preparation; IR feeds
intel).

---

## 11. Post-Incident Discipline

### The blameless postmortem

The blameless-postmortem doctrine — Etsy / Google SRE tradition, codified in *Site
Reliability Engineering* (Beyer et al., 2016) — extended to IR: when something goes
wrong, the response is to fix the system, not punish the human. Structural argument:
humans operating under pressure with incomplete information make defensible
decisions that turn out wrong. Punishing those decisions disincentivizes the very
behavior — early escalation, candid timeline narration — that the next incident
depends on.

Postmortem structure: incident summary (what happened, what was the impact, when
did it start / stop / get contained); detailed timeline (every event with
timestamp; source of truth); causal analysis (why did each event happen; what
conditions allowed it); what went well (detection, containment, communication;
catalog so the program doubles down); what went poorly (delays, thrash, confusion);
action items (specific, owned, time-bound — each has a name and a date); lessons
learned (higher-level reflections). The discipline: action items must be tracked
to completion. The postmortem that produces 30 action items of which 3 ship within
a year is not a postmortem; it's a venting session.

### Root-cause analysis

"5 Whys" (Toyota Production System) iteratively interrogates causal chains. Five
iterations typically reach organizational/structural root causes rather than
proximate ones. Fishbone (Ishikawa) is a visual complement; causal-chain diagrams
more rigorous still. The contemporary critique (John Allspaw, *STELLA Report*
(Stella Working Group, 2017), Sidney Dekker) — "root cause" is a misnomer; complex
systems have *contributing factors*, not a single root. The investigation that
names one root and stops misses the system-of-causes context. The mature retro
identifies the contributing-factor network and the structural defenses that would
reduce future incident likelihood.

### Dissemination

Patterns: all-hands write-up (what happened, what we learned, what we're doing);
engineering-team deep-dive (detailed technical retrospective); executive briefing
(business impact, strategic implications); customer-facing write-up (if customers
were affected, what they need to know); industry sharing (sector ISACs, CISA,
FIRST; TLP-tagged; cross-link `threat_intel_methodology_expertise.md` §9). Public
postmortems — Cloudflare, GitHub, Stripe — set a high bar for transparency and
have become recruiting and trust-building assets. Counter-pattern: companies that
publish nothing learn nothing publicly and forfeit reputational benefit and
contribution to the field.

### Patch the system, not the person

Every action item must address a structural change, not a behavioral one. "Train
people to be more careful" is not an action item. "Add a guardrail that prevents
the unsafe action" is. Reasons: training decays (knowledge of safe practice fades;
next-cohort employees may not have received it); pressure overrides training
(under stress people fall back to habit; if habit is unsafe, training doesn't
help); systems are checkable ("do we have the guardrail" is auditable; "are people
following the training" is not).

### Did the IR work?

Measurement of IR effectiveness is genuinely hard. Useful proxies: MTTD (Mean Time
To Detect — adversary dwell time before detection); MTTC (detection to
containment); MTTR (detection to full resolution); detection coverage (what
fraction of simulated attacker techniques would have been detected — purple-team
exercises, cross-link `detection_engineering_expertise.md` §10); postmortem-action
completion rate; customer-impact metrics (SLA breaches, customer-trust survey
results, churn). Avoid "incident count" — it confounds detection quality (you find
more) with attack volume (more attacks) with defense quality (fewer attacks
succeed).

### Customer comms — when, how, what

Constrained by legal obligation (jurisdiction-specific — see §12), contractual
obligation (customer contracts often impose 24-72 hour windows for B2B SaaS), and
reputational consideration (the cover-up that gets discovered is worse than the
incident). Principle: tell customers the truth, as soon as you have it, in language
they can act on. Avoid weasel language ("some
users may have been affected" when you know which), burying the lede, apologizing
without specifics, talking about the attacker in heroic terms ("sophisticated
nation-state actor" often means "phishing email landed").

---

## 12. Legal and Compliance Overlay

### GDPR 72-hour breach notification

Under GDPR Article 33, controllers must notify the supervisory authority of a
personal-data breach within 72 hours of becoming aware of it, "unless the personal data breach is
unlikely to result in a risk to the rights and freedoms of natural persons."
Article 34 imposes data-subject notification when high-risk. The 72-hour clock is
from *awareness* — not breach occurrence. The IR program's internal awareness-
determination process is the load-bearing operational question. Late notification
has been enforced (multi-million-euro fines).

### US state breach notification

Every US state has a breach-notification law. The SEC adopted federal rules in July
2023 requiring public-company disclosure of material cybersecurity incidents on
Form 8-K within four business days. State laws vary on threshold (encrypted data,
harm thresholds), notification timing (typically 30 to 60 days from discovery,
some narrower), and content. California's CCPA and other state data-protection laws
add layers. A US-multistate-active company has dozens of notification obligations
triggered by a single breach. Legal counsel runs the matrix; IR supplies facts.

### SEC Form 8-K Item 1.05 — the four-business-day clock

The SEC cyber-incident disclosure rule took effect on December 18, 2023 (smaller
reporting companies June 15, 2024). The trigger is the *materiality determination*
— not the breach itself, not detection, not initial investigation conclusion. Once
a public-company registrant determines a cybersecurity incident is material under
Form 8-K Item 1.05, the disclosure clock runs four business days. The disclosure
must cover the "material aspects of the nature, scope, and timing of the
incident, and the material impact or reasonably likely material
impact" — explicitly including financial-condition and operating-results impact.
SEC staff (Director Erik Gerding, May 2024) clarified that Item 1.05 disclosures
are reserved for incidents *determined* material; voluntarily-disclosed incidents
of undetermined materiality should be filed under Item 8.01 instead, with an
Item 1.05 follow-up if and when materiality is established. Operational
implications for IR teams at public companies:

1. The materiality-determination process is itself the load-bearing operational
   question — who decides, with what criteria, at what trigger. The four-day clock
   does not start until the determination, so the determination process timing
   matters legally.
2. The IR investigation must produce material-impact estimates in actionable
   timeframes — financial, operational, reputational — typically with counsel and
   finance/CFO function in the loop.
3. The disclosed-then-amended pattern is explicit and acceptable — initial Item
   1.05 with material-aspects summary, follow-up amendments as scope sharpens.
4. Cross-jurisdictional interplay is real: an incident triggering SEC Item 1.05 in
   the US likely also triggers GDPR 72-hour, NIS2 24/72/30-day, and state
   breach-notification clocks; legal counsel runs the multi-clock matrix.

Source:
[SEC Item 1.05 final rule (Dec 2023)](https://www.sec.gov/files/rules/final/2023/33-11216.pdf);
[SEC Gerding statement on Item 1.05 (May 2024)](https://www.sec.gov/newsroom/speeches-statements/gerding-cybersecurity-incidents-05212024);
[KPMG SEC cyber-disclosure summary 2024](https://kpmg.com/us/en/frv/reference-library/2024/sec-finalizes-cybersecurity-rules.html).

### EU Cyber Resilience Act Article 14 — 24h/72h/14-day clocks effective Sep 11 2026

The EU Cyber Resilience Act (Regulation (EU) 2024/2847) entered into force in
December 2024; the Article 14 reporting obligations apply from **September 11,
2026**. Article 14 imposes the tightest cyber-reporting cadence in any major
regulatory regime to date. Three nested clocks apply to product manufacturers
("manufacturers of products with digital elements") on becoming aware of either an
*actively exploited vulnerability* or a *severe incident* impacting the product's
security:

1. **24 hours** — *early warning notification* to the CSIRT of the member state of
   main establishment and simultaneously to ENISA (the EU cybersecurity agency).
2. **72 hours** — *vulnerability or incident notification* with general technical
   detail; for actively-exploited vulnerabilities, any corrective or mitigating
   measures taken.
3. **14 days after corrective/mitigating measure available** — *final report* for
   actively-exploited vulnerabilities. *One month after the 72-hour notification*
   for severe incidents.

Notification flows via the *ENISA Single Reporting Platform* (SRP). The scope is
substantially broader than NIS2 (which targets sectors) — CRA targets *products*,
so any product manufacturer placing digital-element products on the EU market
falls under its reporting obligations regardless of sector. Operational
implications for IR teams supporting EU-market products:

- The 24-hour clock fires on *awareness*, not on confirmed exploitation —
  cautious-disclosure posture during early investigation collides with the
  reporting timeline.
- Active-exploitation disclosure becomes adversary intelligence; ENISA SRP and
  CSIRT handling discipline matters. Manufacturers cannot withhold simply because
  patch availability lags.
- The final-report deadlines are short by historical standards; postmortem-grade
  evidence assembly must run in parallel with response, not after.

Source:
[European Commission CRA reporting page](https://digital-strategy.ec.europa.eu/en/policies/cra-reporting);
[Article 14 text (european-cyber-resilience-act.com)](https://www.european-cyber-resilience-act.com/Cyber_Resilience_Act_Article_14.html);
[White & Case CRA compliance alert](https://www.whitecase.com/insight-alert/cyber-resilience-act-clock-ticking-compliance).

### HIPAA, PCI-DSS, sectoral

HIPAA Breach Notification Rule (45 CFR §164.400–414): covered entities notify
affected individuals within 60 days; HHS within 60 days for larger breaches (>500
individuals) or annually for smaller. PCI-DSS Requirement 12.10 mandates an IR plan
covering breach notification, root-cause analysis, and remediation; the PCI
Forensic Investigator (PFI) program is a qualified-investigator requirement that
fires on cardholder-data compromise. NYDFS Part 500 (NY financial services): 72-hour
breach notification. CISA reporting (CIRCIA, 2022): 72-hour reporting for critical-
infrastructure entities; final rule expected ~2026. NIS2 (EU): 24-hour early
warning, 72-hour formal notification, one-month final report. Singapore PDPA,
Australia Privacy Act, Brazil LGPD, India DPDP Act each have similar regimes with
varying details.

### Lawyers in the loop

Most IR engagements run with legal counsel from the first hour. Reasons:
privilege protection (attorney-client communications may be protected from
disclosure; retain-counsel-first patterns — Kovel arrangements, in-house counsel
direction — are standard); notification-clock management (every jurisdiction has
its own clock); regulator liaison (when notification is required, counsel often
handles interaction); litigation hold (preservation obligations beyond IR's own).
The IR-counsel interaction can be frustrating to technical responders; operational
reality is that company exposure is largely defined by legal posture during IR.

### Chain-of-custody for legal admissibility

When evidence may end up in court, chain-of-custody documentation must: name every
person who handled the evidence with timestamps; record every transfer (analyst-to-
analyst, lab-to-lab, lab-to-counsel); hash the evidence at each transfer and
validate; store in tamper-evident form (sealed bags for physical, signed digital
records for digital); survive cross-examination. Cross-link
`privacy_engineering_expertise.md` (data-subject-rights operationalization during
incident — DSAR requests during incident may interact with privilege and
preservation obligations).

---

## 13. The Detection ↔ DFIR ↔ Intel ↔ Threat-Hunt Loop

### The structural loop

Four disciplines feed each other:

1. **Detection engineering** (`detection_engineering_expertise.md`) writes the rules
   that fire alerts. Output: alerts. Consumer: SOC and IR.
2. **DFIR** (this doc) investigates the alerts, characterizes the intrusion. Output:
   investigation reports, IOC sets, behavior characterizations. Consumer: detection,
   intel.
3. **Threat intel** (`threat_intel_methodology_expertise.md`) contextualizes — actor
   attribution, campaign characterization, sectoral context. Output: intel reports,
   actor profiles, campaign tracking. Consumer: detection, threat hunt, executive.
4. **Threat hunt** proactively searches for adversary presence not surfaced by
   detection. Output: hunt findings (often new IOCs or new TTPs not yet in
   detection). Consumer: detection, IR, intel.

```
Detection rule fires →
  IR investigates →
    Intel characterizes →
      Hunt searches for variants →
        Detection updated with new content →
  (cycle)
```

### Detection rule → IR investigation

A detection alert is the trigger for an IR investigation. The detection-to-
investigation handoff has characteristics the detection-engineering practice
optimizes for (`detection_engineering_expertise.md` §4 — alert schema, analyst-
readable output).

### IR investigation → intel report

IOC sets (IPs, hashes, domains) feed atomic intel feeds. TTP characterizations (the
attacker did X, then Y, then Z) feed campaign tracking. Operator OPSEC failures
(specific identifiers, geo-tied artifacts) feed actor attribution. Capability
characterization (malware family, toolchain) feeds capability tracking. Cross-link
to Diamond Model is direct: each intrusion produces a diamond entry the intel
program ingests.

### Intel report → threat hunt

Intel surfaces hypotheses: "actor X is operating against sector Y with TTP Z." The
hunt translates the hypothesis to a search. Hunting is the proactive complement to
reactive IR. Bianco's pyramid (cross-link `threat_intel_methodology_expertise.md`)
maps the intel-to-hunt translation: low-pyramid IOCs translate to fast hunts (run
the IP against firewall logs); high-pyramid TTPs translate to slow hunts (look for
the behavioral pattern across event-log corpora).

### Threat hunt → detection rule

A successful hunt finds something. The finding produces new detection content —
new Sigma rule, new YARA signature, new behavioral analytic. The detection content
makes future investigations faster; the cycle closes.

### Lessons-from-this-incident pipeline

Disciplined programs operationalize incident-derived lessons: detection-content
lessons (what didn't fire that should have — engineering action item for detection);
intel-content lessons (what didn't we know about this actor / campaign — action
item for intel); preparation lessons (what playbook was missing / wrong — action
item for IR); engineering lessons (what system architecture allowed the intrusion —
action item for engineering / appsec); process lessons (what organizational pattern
slowed the response — action item for leadership). The retro that produces all five
and tracks them to completion is the program at mature state.

---

## 13a. Case Studies — Major IR Incidents 2024-2026

The incidents below are referenced as DFIR teaching cases — what went wrong, what
went right, what the public IR-lessons literature surfaces. None of these
narratives reflects insider-source information; each is sourced from public
post-incident analyses, vendor reports, and (where available) regulatory
disclosures.

### Change Healthcare (UnitedHealth Group) — February 2024

The
[ALPHV/BlackCat ransomware deployment against Change Healthcare](https://www.threatintelreport.com/2024/12/20/incident_reports/change-healthcare-ransomware-attack-unitedhealth-optum-alphv-blackcat-disruption-and-mass-phi-exposure/)
on February 21, 2024 was the largest U.S. healthcare data breach on record at the
time — UnitedHealth disclosed 190 million affected records in 2025, dwarfing the
prior Anthem 2015 (78.8M) maximum. Initial access via a Citrix remote-access
service without MFA enabled; nine-day dwell time before ransomware deployment;
$22M ransom paid by UnitedHealth (CEO Andrew Witty confirmed in Congressional
testimony, May 2024). IR-lessons literature highlights: the missing-MFA
remote-access gateway is the single load-bearing precondition; the nine-day
dwell window indicates inadequate east-west detection (lateral movement, AD
recon, exfiltration prep should all have been visible). Per
[AHA hospital survey](https://www.aha.org/change-healthcare-cyberattack-underscores-urgent-need-strengthen-cyber-preparedness-individual-health-care-organizations-and),
74% of hospitals reported direct patient-care impact; the
[$22M ransom payment was confirmed](https://www.ibm.com/think/news/change-healthcare-22-million-ransomware-payment).
Cross-link `cloud_iam_expertise.md` (MFA enforcement) and
`detection_engineering_expertise.md` §3 (lateral-movement detection content).

### Snowflake / UNC5537 — May-July 2024

The
[Mandiant disclosure on UNC5537](https://cloud.google.com/blog/topics/threat-intelligence/unc5537-snowflake-data-theft-extortion)
(June 2024) characterized a financially-motivated cluster that compromised
roughly 165 of Snowflake's 9000+ customer environments by replaying *infostealer-
captured credentials* against customer Snowflake tenants. Affected organizations
include AT&T, Ticketmaster/Live Nation, Santander, LendingTree, Advance Auto
Parts, Neiman Marcus, Bausch Health. Three load-bearing preconditions per
Mandiant:

1. **MFA was not enabled** on the affected Snowflake customer accounts.
2. **Credentials had not been rotated** despite years of theft-history exposure;
   the credentials in infostealer logs were still valid in some cases years
   after capture.
3. **Network allow-lists were not configured** — the customer tenants accepted
   authentication from arbitrary source IPs.

Mandiant found *no evidence* of compromise to Snowflake's own enterprise
environment; the breach was a shared-responsibility-model gap (customer-side
configuration). The incident reset the SaaS-shared-responsibility conversation —
post-Snowflake, hyperscale SaaS providers (Snowflake, Salesforce, Databricks)
have begun enforcing-by-default MFA and IP allowlists on new tenants, with
deprecation timelines for legacy configurations. DFIR lesson: the
infostealer-credential-shop ecosystem (Lumma, RedLine, Vidar) is a continuous
high-volume credential leak; customer credential rotation cadence and
MFA-enforcement defaults are the most cost-effective compensating controls.
Cross-link `cloud_iam_expertise.md` (federated-identity controls) and
`threat_intel_methodology_expertise.md` (infostealer ecosystem tracking).

### Microsoft Midnight Blizzard — January 2024

Microsoft detected the
[Midnight Blizzard (NOBELIUM, Russia SVR-affiliated)](https://www.microsoft.com/en-us/security/blog/2024/01/25/midnight-blizzard-guidance-for-responders-on-nation-state-attack/)
intrusion on January 12, 2024 — adversary access via password-spray against a
legacy, non-production test tenant account without MFA, followed by abuse of a
legacy test OAuth application with elevated permissions in the Microsoft
corporate environment, granting the actor `full_access_as_app` on Office 365
Exchange Online. Exfiltrated content included emails and attachments of senior
leadership, security, and other employees, with focus on communications about
Midnight Blizzard itself. Per the
[March 2024 Microsoft update](https://www.microsoft.com/en-us/msrc/blog/2024/03/update-on-microsoft-actions-following-attack-by-nation-state-actor-midnight-blizzard),
exfiltrated material was subsequently used to attempt source-code-repository
access and internal-systems access. CISA issued
[Emergency Directive 24-02](https://www.cisa.gov/news-events/directives/ed-24-02-mitigating-significant-risk-nation-state-compromise-microsoft-corporate-email-system-closed)
in April 2024 requiring federal civilian executive branch agencies to assess and
respond to the Microsoft corporate email exposure.

IR-lessons literature highlights: even Microsoft (which both produces the
defensive tools and operates a mature SOC) ran a legacy test tenant without MFA
and a legacy OAuth application with unscoped elevated permissions; legacy
non-production tenants are the most-common forgotten-attack-surface across
mature programs. The OAuth-application-abuse vector (consent-grant phishing,
legacy-application exploitation) has surfaced in multiple 2024-2026 incidents
and is now treated as a first-class detection-engineering target. Cross-link
`cloud_iam_expertise.md` (OAuth-consent monitoring) and
`detection_engineering_expertise.md` §3 (identity-system detection content).

### CDK Global — June 2024

The
[BlackSuit ransomware attack against CDK Global](https://www.techtarget.com/whatis/feature/The-CDK-Global-outage-Explaining-how-it-happened)
on June 18, 2024 disabled dealer-management software at approximately 15,000
auto-dealer locations across North America for two-plus weeks. Anderson Economic
Group estimated dealer-side losses at $1B+. CDK reportedly paid a $25M ransom
([CNN reporting July 2024](https://edition.cnn.com/2024/07/11/business/cdk-hack-ransom-tweny-five-million-dollars)).
Notably, CDK was *re-compromised* after initial restoration — recovery without
full eradication is a recurring postmortem theme. The incident is a teaching
case for *third-party dependency risk* — dealers themselves were not breached
but were unable to operate without the SaaS dependency; the IR question of "who
declares an incident when your SaaS vendor is the victim" is structurally
unresolved across the industry.

### Synnovis (NHS pathology, London) — June 2024

The
[Qilin ransomware attack against Synnovis](https://www.hipaajournal.com/care-disrupted-at-london-hospitals-due-to-ransomware-attack-on-pathology-vendor/)
on June 3, 2024 disabled pathology services to NHS Guy's & St Thomas' and King's
College Hospital Trusts; 10,000+ outpatient appointments and 1,700+ elective
operations cancelled. 400GB of patient data, including 300M patient interactions
and sensitive HIV / STI / cancer test results, were leaked to the Qilin
dark-web leak site after Synnovis (with NHS partnership) declined the reported
$50M ransom demand. King's College Hospital NHS Foundation Trust subsequently
[linked a patient death](https://www.bitdefender.com/en-us/blog/hotforsecurity/patient-death-cyberattack-british-pathology-clinic-synnovis)
to a delay in blood-test results caused by the cyberattack.
Synnovis took 18 months to complete data-reconstruction and breach
notifications, with notifications still arriving in late 2025. Teaching
points: healthcare-sector ransomware can cause loss of life and the
attribution-of-harm methodology is becoming clinical-evidence-grade; data-
reconstruction-after-encryption can take 18+ months; explicit no-ransom
posture coordination with the customer (NHS) is operationally defensible but
forces a long recovery tail.

### CrowdStrike Channel File 291 — July 19, 2024

Not malicious — but the
[CrowdStrike Falcon Channel File 291 incident](https://www.crowdstrike.com/en-us/blog/channel-file-291-rca-available/)
is the largest IT outage in history (~8.5 million Windows hosts crashed and
required manual remediation) and informs IR practice across multiple
dimensions. Per CrowdStrike's published RCA: the Falcon sensor's
Content Interpreter consumed an IPC Template Type expecting 21 input fields
but received only 20 — a missing runtime array-bounds check led to an
unhandled exception in kernel context, BSOD. Channel-file delivery to all
hosts within minutes meant ~8.5M endpoints went down within the deployment
window; recovery required physical or manual Safe Mode boot to delete the bad
channel file. Public-sector and aviation impact was largest (Delta, hospitals,
banks).

DFIR teaching points:

1. **Vendor-pushed content is operationally equivalent to remote code
   execution** when delivered to kernel-resident agents. The forensic question
   "did our EDR vendor crash our fleet" is structurally the same as "did an
   adversary push a malicious update"; recovery posture differs only because
   the vendor is cooperating.
2. **Single-vendor EDR coverage is a single point of failure** at the fleet
   level. Multi-vendor / diversity-engineering for security agents has moved
   from "vendor-management curiosity" to "resilience-engineering hard
   requirement" in some sectors.
3. **Manual-recovery scale matters**. 8.5M endpoints needing physical access
   stresses every restore process; air-gapped systems with no console access
   are worst-case. Recovery runbooks should include "what if every endpoint
   needs Safe Mode" as a tabletop scenario.
4. **The outage forensic timeline must be reconstructible.** Cross-organization
   investigations (CISA, insurers, sectoral regulators) require evidence on
   pre-update detection, response timing, customer-comm cadence, restoration
   posture.

Cross-link `appsec_program_building_expertise.md` (vendor-risk discipline) and
`cicd_supply_chain_expertise.md` (update-channel security model).

### MGM Resorts — September 2023 (retroactive lesson)

The
[MGM Resorts ransomware incident](https://www.cybersecuritydive.com/news/mgm-resorts-cybersecurity-incident-cyber/) (Sep 2023, ALPHV/BlackCat affiliate Scattered Spider) is treated as a 2024-2026
teaching case because the public postmortem and lawsuit-discovery materials
appeared through 2024-2025. Initial access via a vishing call to the MGM IT
service desk. Ten days of operational disruption; estimated $100M financial
impact. Teaching points: help-desk and identity-system social engineering is
the most-effective initial-access vector against mature programs; out-of-band
verification protocols for credential / MFA resets are the structural defense.
Scattered Spider has been linked to subsequent help-desk-vishing intrusions
throughout 2024-2025; the threat-actor pattern is durable. Cross-link
`http_web_security.md` (identity-system controls) and
`threat_intel_methodology_expertise.md` (Scattered Spider actor tracking).

### Cross-incident pattern: identity is the new perimeter

The 2024-2026 case studies converge on a structural observation: **identity-
plane compromise is the primary intrusion modality**, displacing the
network-perimeter model that dominated the 2010-2020 era. Change Healthcare
(Citrix without MFA), Snowflake/UNC5537 (customer SaaS credentials), Microsoft
Midnight Blizzard (legacy tenant + OAuth abuse), MGM (help-desk MFA reset) are
all identity-plane intrusions. The detection-engineering and DFIR investment
center of gravity has shifted accordingly — IAM telemetry, MFA-enforcement
posture, OAuth-application monitoring, identity-anomaly detection, and
help-desk procedural hardening are first-order IR-preparation priorities for
mature programs. Cross-link `cloud_iam_expertise.md` for the identity-control
discipline.

---

## 14. Variant Analysis — Under-Explored DFIR Frontiers

### AI-incident forensics

When an LLM-driven agent does something harmful, what's the forensic process?
Emerging discipline (cross-link `llm_agent_security_expertise.md` §7) treats agent
runtime as three forensically-relevant layers: the model (deployed weights,
version, fine-tuning state); the tool surface (set of tools the agent had access
to; per-tool configuration); the execution trace (sequence of messages, tool
calls, tool responses, final actions per invocation).

The forensic substrate is the execution trace — the agent's "logs." Acquisition
considerations: pre-instrument the agent (every invocation produces a structured
trace, logged immutably; without this, behavior is unrecoverable); hash prompts and
responses (replay depends on integrity); capture the tool-call audit log (every
tool invoked with arguments and result and timestamps); correlate with traditional
logs (agent tool calls touch traditional systems — network log, API audit log,
database log all contain traditional-substrate evidence).

MITRE ATLAS (Adversarial Threat Landscape for AI Systems) is the ATT&CK-equivalent
for AI; mapping incident traces to ATLAS techniques is the emerging practice.
Cross-link `adversarial_ml_model_security_expertise.md`.

Cross-link `agentic_web_capabilities_expertise.md` (web-fetching agents' tool
surface and prompt-injection forensic footprints) — agent-fetched content is
itself evidence, and the chain "URL fetched → content returned → action taken"
needs the same integrity discipline as traditional log forensics.

### AI in IR — the "agent as junior responder" discipline

A second AI-in-DFIR frontier emerged in 2024-2026: using LLM agents as
*investigation assistants* rather than as investigation subjects. Commercial
products in this space (CrowdStrike Charlotte AI, Microsoft Security Copilot,
Google Sec-Gemini, Splunk AI Assistant, SentinelOne Purple AI, Dropzone AI,
Prophet Security) provide agent interfaces over SIEM / EDR / case-management
data, with capabilities ranging from natural-language query translation through
autonomous triage of low-severity alerts. The discipline's operating model:

1. **LLM as analyst force-multiplier, not replacement.** The agent generates
   investigation candidates (queries, IOC pivots, summary narratives, draft
   communications); the human analyst validates, confirms, and decides. The
   junior-analyst metaphor is load-bearing — the agent has the breadth of a
   senior practitioner and the judgment of a first-week hire; it needs
   supervision.
2. **Hallucination risk is operationally severe in IR.** A confidently-
   fabricated IOC, attacker-attribution, or technical-detail claim can mislead
   investigation priorities for hours. Mature programs require citation of
   evidence sources for every agent-emitted claim; outputs without traceable
   substrate are treated as advisory only.
3. **Forensic-trace integrity for the AI itself.** The agent's outputs are part
   of the investigation record. If a decision was made based on an agent
   recommendation, the chat transcript and underlying model version/config are
   evidence. Programs adopting AI-assisted IR are extending chain-of-custody
   documentation to cover model identity (vendor, version, system prompt hash),
   conversation logs, and tool-call audit logs.
4. **The training-data leakage risk.** Customer incident data sent to a vendor
   LLM may end up in the vendor's training pipeline, depending on contract
   terms — counsel must vet the data-handling posture. Air-gapped or
   customer-tenanted models (Azure OpenAI customer-managed deployments,
   on-premises Llama variants) are the higher-assurance configuration.
5. **Adversarial use of the agent.** Prompt injection embedded in attacker
   artifacts (file names, log entries, ticket descriptions) that the agent
   later ingests can subvert investigation. Detection content for "prompt
   injection in evidence stream" is itself an emerging detection-engineering
   target. Cross-link `llm_agent_security_expertise.md` and
   `adversarial_ml_model_security_expertise.md`.

Regulators (SEC,
EU CRA, NIS2) will hold human decision-makers accountable for incident-response
choices, not the AI. Tooling that obscures the decision audit trail is a
liability, not an asset.

### Serverless forensics

Lambda, Cloud Run, Cloud Functions, Azure Functions, Fargate, App Runner — the
serverless / FaaS substrate has limited forensic persistence. The function runs,
emits logs, is destroyed; no host to image, no memory to dump. The forensic
substrate is logs: CloudWatch Logs (AWS Lambda output; retention configurable),
Cloud Logging (GCP function output; route to durable storage), Azure Monitor
(function diagnostic logs), API Gateway / equivalent (edge-level access logs;
sometimes more durable than function logs).

The IR strategy for serverless: pre-establish comprehensive logging, route to
immutable storage, accept that runtime evidence is gone the moment the function
returns. Defense shifts to *preventive* — input validation, output validation,
permission scoping — rather than forensic.

### Ephemeral containers

Kubernetes Job pods, Argo Workflows, CI/CD pipeline containers — same forensic
limitation as serverless. Container ran, produced output, was destroyed. Substrate
is container logs (forwarded to aggregator) and kube-apiserver audit (pod creation,
image used, completion). IR strategy: in-cluster logging that survives the pod;
Falco runtime events for syscall-level visibility; container-image attestation
(cosign / sigstore — cross-link `cicd_supply_chain_expertise.md`) for image
provenance.

### AI-coding-tool compromise

Claude Code, Cursor, Copilot, Aider, and similar AI coding tools have agent-runtime
characteristics relevant to IR: they read source, execute commands, modify files.
A compromised AI coding tool could exfiltrate proprietary code to an attacker-
controlled endpoint, modify code to insert backdoors, or execute arbitrary commands
via the tool-call interface. Forensic substrate is the same as agent-runtime
forensics: tool call log, network log, code-modification log (Git history). Pre-
incident discipline is the same — log everything, route to immutable storage, alert
on anomalies. Cross-link `cicd_supply_chain_expertise.md` (supply-chain frame) and
`llm_agent_security_expertise.md` §7 (agent runtime frame).

### IoT and edge-device forensics

Constrained-device forensics — IoT sensors, edge gateways, industrial controllers,
consumer smart-home — has distinct challenges: no standard forensic substrate
(each device class has its own firmware, log formats, persistence model); limited
or no persistent logging (volatile-only state; reboot loses everything); JTAG /
UART / chip-off acquisition often required for hardware-level access; vendor
cooperation often necessary (firmware extraction may require vendor tooling).
Cross-link `firmware_embedded_security.md`. The discipline: acquire as low as
possible (hardware level when the device allows), parse firmware/storage manually,
treat each device class as a bespoke investigation.

### Web3 / blockchain forensics

Cryptocurrency transactions are pseudonymous, durable, and publicly observable.
Discipline: address-graph analysis (map transactions across addresses; cluster
addresses to entities via common-input ownership, change-address detection,
exchange-deposit patterns); mixer / tumbler tracing (Tornado Cash, Wasabi,
Samourai — trace through mixers via timing, amount, graph-statistics inference);
cross-chain bridge-tracking (funds move across blockchain substrates; bridges
introduce additional evidence); exchange KYC subpoenas (centralized exchanges hold
off-chain KYC data; subpoenable in many jurisdictions). Tools: Chainalysis, TRM
Labs, Elliptic, Crystal Blockchain, Arkham. The discipline is more financial
investigation than traditional digital-forensics; cross-link
`smart_contract_evm_security_expertise.md` for on-chain-attack-vector framing.

---

## 15. References

### Foundational canon

- Carrier, Brian. *File System Forensic Analysis.* Addison-Wesley, 2005.
  [Amazon](https://www.amazon.com/System-Forensic-Analysis-Brian-Carrier/dp/0321268172) —
  [O'Reilly](https://www.oreilly.com/library/view/file-system-forensic/0321268172/).
- Casey, Eoghan. *Digital Evidence and Computer Crime: Forensic Science, Computers,
  and the Internet.* 3rd ed. Academic Press, 2011.
  [Amazon](https://www.amazon.com/Digital-Evidence-Computer-Crime-Computers/dp/0123742684) —
  [ACM DL](https://dl.acm.org/doi/book/10.5555/2021194).
- Hale Ligh, Michael, Andrew Case, Jamie Levy, AAron Walters. *The Art of Memory
  Forensics.* Wiley, 2014.
  [Wiley](https://www.wiley.com/en-us/The+Art+of+Memory+Forensics:+Detecting+Malware+and+Threats+in+Windows,+Linux,+and+Mac+Memory-p-9781118825099) —
  [memoryanalysis.net](https://memoryanalysis.net/amf/).
- Bejtlich, Richard. *The Practice of Network Security Monitoring.* No Starch, 2013.
  [No Starch](https://nostarch.com/nsm).
- Bejtlich, Richard. *The Tao of Network Security Monitoring.* Addison-Wesley, 2004.
- Sanders, Chris, and Jason Smith. *Applied Network Security Monitoring.* Syngress,
  2014. [Elsevier](https://shop.elsevier.com/books/applied-network-security-monitoring/sanders/978-0-12-417208-1) —
  [chrissanders.org / appliednsm](https://chrissanders.org/appliednsm/).
- Mahalik, Heather, Rohit Tamma, Satish Bommisetty. *Practical Mobile Forensics.*
  Packt. [Amazon (2nd ed.)](https://www.amazon.com/Practical-Mobile-Forensics-Heather-Mahalik/dp/1786464209).

### Standards and methodology

- NIST. *SP 800-61 Rev. 2: Computer Security Incident Handling Guide* (Withdrawn).
  [CSRC](https://csrc.nist.gov/pubs/sp/800/61/r2/final) —
  [PDF](https://nvlpubs.nist.gov/nistpubs/specialpublications/nist.sp.800-61r2.pdf).
- NIST. *SP 800-61 Rev. 3: Incident Response Recommendations and Considerations for
  Cybersecurity Risk Management* (April 2025).
  [CSRC](https://csrc.nist.gov/pubs/sp/800/61/r3/final) —
  [PDF](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r3.pdf).
- IETF. RFC 3227, *Guidelines for Evidence Collection and Archiving* (2002).
  [IETF](https://www.ietf.org/rfc/rfc3227.txt) —
  [Datatracker](https://datatracker.ietf.org/doc/html/rfc3227).
- SWGDE — Scientific Working Group on Digital Evidence.
  [swgde.org](https://www.swgde.org/).
- ENFSI Forensic IT Working Group. [enfsi.eu](https://enfsi.eu/).
- DFRWS — Digital Forensics Research Workshop. [dfrws.org](https://dfrws.org/).

### Tooling

- The Sleuth Kit. [sleuthkit.org](https://www.sleuthkit.org/).
- Autopsy. [autopsy.com](https://www.autopsy.com/).
- Volatility 3. [readthedocs](https://volatility3.readthedocs.io/) —
  [GitHub](https://github.com/volatilityfoundation/volatility3) —
  [Volatility Foundation](https://volatilityfoundation.org/).
- Plaso / log2timeline. [readthedocs](https://plaso.readthedocs.io/) —
  [GitHub](https://github.com/log2timeline/plaso) —
  [forensics.wiki](https://forensics.wiki/plaso/).
- Timesketch. [timesketch.org](https://timesketch.org/) —
  [GitHub](https://github.com/google/timesketch).
- WinPmem. [winpmem.velocidex.com](https://winpmem.velocidex.com/).
- AVML. [GitHub](https://github.com/microsoft/avml).
- REMnux. [remnux.org](https://remnux.org/) —
  [Documentation](https://docs.remnux.org/).
- FLARE-VM. [GitHub](https://github.com/mandiant/flare-vm).
- CAPE Sandbox. [GitHub](https://github.com/kevoreilly/CAPEv2).
- Zeek. [zeek.org](https://zeek.org/).
- Suricata. [suricata.io](https://suricata.io/).
- Arkime. [arkime.com](https://arkime.com/).
- Wireshark. [wireshark.org](https://www.wireshark.org/).
- YARA. [virustotal.github.io/yara](https://virustotal.github.io/yara/).
- capa. [GitHub](https://github.com/mandiant/capa).
- MVT. [mvt.re](https://mvt.re/) —
  [GitHub](https://github.com/mvt-project/mvt) —
  [docs](http://mvt-docs.readthedocs.io/).
- Falco. [falco.org](https://falco.org/).
- MITRE CAR. [car.mitre.org](https://car.mitre.org/).
- MITRE ATT&CK. [attack.mitre.org](https://attack.mitre.org/).
- MITRE ATLAS. [atlas.mitre.org](https://atlas.mitre.org/).

### Cloud forensic guidance

- AWS. *Security Incident Response Guide.*
  [docs.aws.amazon.com](https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/welcome.html).
- AWS. *CloudTrail.*
  [docs.aws.amazon.com](https://docs.aws.amazon.com/awscloudtrail/).
- GCP. *Cloud Audit Logs.*
  [cloud.google.com](https://cloud.google.com/logging/docs/audit).
- Azure. *Microsoft Sentinel / Defender for Cloud.*
  [learn.microsoft.com](https://learn.microsoft.com/en-us/azure/sentinel/).

### Pegasus / spyware methodology

- Amnesty International. *Forensic Methodology Report: How to Catch NSO Group's
  Pegasus.* 2021.
  [Amnesty](https://www.amnesty.org/en/latest/research/2021/07/forensic-methodology-report-how-to-catch-nso-groups-pegasus/) —
  [PDF](https://www.amnesty.org/en/wp-content/uploads/2021/08/DOC1044872021ENGLISH.pdf).
- Citizen Lab. [Pegasus archive](https://citizenlab.ca/tag/pegasus/).

### Practitioner writing

- Pomeranz, Hal. [Deer Run / users/hal](https://deer-run.com/users/hal/).
- Edwards, Sarah. [mac4n6.com](http://www.mac4n6.com/) —
  [APOLLO](https://github.com/mac4n6/APOLLO) —
  [SANS FOR518](https://www.sans.org/cyber-security-courses/mac-and-ios-forensic-analysis-and-incident-response).
- Mahalik, Heather. [SANS FOR585](https://www.sans.org/cyber-security-courses/smartphone-forensic-analysis-in-depth/) —
  [Cellebrite blog](https://cellebrite.com/en/blog/celebrating-heather-mahalik-a-trailblazer-in-the-world-of-digital-forensics/).
- Zeltser, Lenny. [zeltser.com](https://zeltser.com/) —
  [SANS FOR610](https://www.sans.org/cyber-security-courses/reverse-engineering-malware-malware-analysis-tools-techniques/).
- Carhart, Lesley. [tisiphone.net](https://tisiphone.net/) —
  [Dragos bio](https://www.dragos.com/lesley-carhart).
- McGeehan, Ryan. [scrty.io](https://scrty.io/about/) —
  [Starting Up Security on Medium](https://medium.com/starting-up-security) —
  [An Incident Response Plan for Startups](https://medium.com/starting-up-security/an-incident-response-plan-for-startups-26549596b914) —
  [Security Breach 101](https://medium.com/starting-up-security/security-breach-101-b0f7897c027c).
- Bejtlich, Richard. [TaoSecurity](https://www.taosecurity.com/).
- Sanders, Chris. [chrissanders.org](https://chrissanders.org/) —
  [Applied Network Defense](https://www.networkdefense.co/).

### Reports

- Mandiant. *M-Trends* annual.
  [Google Cloud blog](https://cloud.google.com/blog/topics/threat-intelligence).
- Verizon. *Data Breach Investigations Report (DBIR)* annual.
  [verizon.com/business/resources/reports/dbir](https://www.verizon.com/business/resources/reports/dbir/).
- IBM. *Cost of a Data Breach* annual.

### 2024-2026 incident case-study references

- Change Healthcare ransomware:
  [ThreatIntelReport writeup](https://www.threatintelreport.com/2024/12/20/incident_reports/change-healthcare-ransomware-attack-unitedhealth-optum-alphv-blackcat-disruption-and-mass-phi-exposure/) —
  [AHA survey](https://www.aha.org/change-healthcare-cyberattack-underscores-urgent-need-strengthen-cyber-preparedness-individual-health-care-organizations-and) —
  [IBM ransom disclosure](https://www.ibm.com/think/news/change-healthcare-22-million-ransomware-payment) —
  [HIPAA Journal](https://www.hipaajournal.com/change-healthcare-responding-to-cyberattack/).
- Snowflake / UNC5537:
  [Mandiant blog](https://cloud.google.com/blog/topics/threat-intelligence/unc5537-snowflake-data-theft-extortion) —
  [Wikipedia summary](https://en.wikipedia.org/wiki/Snowflake_data_breach) —
  [CSA writeup](https://cloudsecurityalliance.org/blog/2025/05/07/unpacking-the-2024-snowflake-data-breach).
- Microsoft Midnight Blizzard:
  [MS initial post (Jan 2024)](https://www.microsoft.com/en-us/security/blog/2024/01/25/midnight-blizzard-guidance-for-responders-on-nation-state-attack/) —
  [MS update (Mar 2024)](https://www.microsoft.com/en-us/msrc/blog/2024/03/update-on-microsoft-actions-following-attack-by-nation-state-actor-midnight-blizzard) —
  [CISA ED 24-02](https://www.cisa.gov/news-events/directives/ed-24-02-mitigating-significant-risk-nation-state-compromise-microsoft-corporate-email-system-closed) —
  [CSA retrospective (Sep 2025)](https://cloudsecurityalliance.org/blog/2025/09/15/reflecting-on-the-2024-microsoft-breach).
- CDK Global ransomware:
  [TechTarget explainer](https://www.techtarget.com/whatis/feature/The-CDK-Global-outage-Explaining-how-it-happened) —
  [CNN ransom-payment reporting](https://edition.cnn.com/2024/07/11/business/cdk-hack-ransom-tweny-five-million-dollars).
- Synnovis / NHS pathology:
  [HIPAA Journal coverage](https://www.hipaajournal.com/care-disrupted-at-london-hospitals-due-to-ransomware-attack-on-pathology-vendor/) —
  [Patient-death link](https://www.bitdefender.com/en-us/blog/hotforsecurity/patient-death-cyberattack-british-pathology-clinic-synnovis) —
  [Investigation closure (Nov 2025)](https://www.theregister.com/2025/11/13/synnovis_qilin_investigation/).
- CrowdStrike Channel File 291:
  [CrowdStrike RCA](https://www.crowdstrike.com/en-us/blog/channel-file-291-rca-available/) —
  [CISA alert](https://www.cisa.gov/news-events/alerts/2024/07/19/widespread-it-outage-due-crowdstrike-update) —
  [Wikipedia summary](https://en.wikipedia.org/wiki/2024_CrowdStrike-related_IT_outages).

### Regulatory / disclosure-rule references (2023-2026)

- SEC Form 8-K Item 1.05 (Dec 2023 effective; Jun 2024 SRC):
  [SEC final rule PDF](https://www.sec.gov/files/rules/final/2023/33-11216.pdf) —
  [Gerding clarification statement (May 2024)](https://www.sec.gov/newsroom/speeches-statements/gerding-cybersecurity-incidents-05212024) —
  [KPMG summary](https://kpmg.com/us/en/frv/reference-library/2024/sec-finalizes-cybersecurity-rules.html).
- EU Cyber Resilience Act Article 14 (effective Sep 11 2026):
  [Commission CRA reporting page](https://digital-strategy.ec.europa.eu/en/policies/cra-reporting) —
  [CRA Article 14 text](https://www.european-cyber-resilience-act.com/Cyber_Resilience_Act_Article_14.html) —
  [White & Case CRA compliance alert](https://www.whitecase.com/insight-alert/cyber-resilience-act-clock-ticking-compliance).

### JA4+ family

- [JA4+ FoxIO repo (canonical reference implementation)](https://github.com/FoxIO-LLC/ja4).
- [JA4+ community database `ja4db.com`](https://ja4db.com/).
- [FoxIO JA4+ overview blog](https://blog.foxio.io/ja4+-network-fingerprinting).
- [Cloudflare integration / inter-request signal analysis](https://blog.cloudflare.com/ja4-signals/).
- [GCTI JA4 deep dive](https://security.googlecloudcommunity.com/community-blog-42/ja4-fingerprinting-in-gti-deep-dive-6043).

### iOS Stolen Device Protection

- [Elcomsoft forensic-implications writeup (Mar 2025)](https://blog.elcomsoft.com/2025/03/forensic-implications-of-apples-stolen-device-protection/).
- [ADF Solutions analysis](https://www.adfsolutions.com/adf-blog/ios-stolen-device-protection-a-game-changer-for-users-and-a-challenge-for-law-enforcement).
- [Cellebrite SDP advisory](https://cellebrite.com/en/blog/ios-stolen-device-protection/).
- [HaystackID forensic deep-dive](https://haystackid.com/a-forensic-deep-dive-into-apples-security-delay-in-ios-17-3/).
- [Kaspersky shutdown.log methodology](https://securelist.com/shutdown-log-lightweight-ios-malware-detection-method/111734/).

### Multi-cloud forensic schema

- [OCSF home (`ocsf.io`)](https://ocsf.io/) — [GitHub org](https://github.com/ocsf) — [schema browser](https://schema.ocsf.io/).
- [AWS Security Lake OCSF integration docs](https://docs.aws.amazon.com/security-lake/latest/userguide/open-cybersecurity-schema-framework.html).

### Worked examples and cross-references

- `threat_intel_methodology_expertise.md` — methodology sibling; intel and DFIR
  feed each other (§1, §10, §13 in this doc).
- `detection_engineering_expertise.md` — detection → IR pipeline (§1, §5, §13).
- `cloud_iam_expertise.md` — cloud forensic logs and IAM-incident response (§7,
  §12, §13a). The 2024-2026 incident pattern — identity-as-perimeter — anchors
  the cross-reference; the cloud-IAM doc covers the federated-identity controls,
  MFA enforcement, OAuth-consent monitoring, and IAM telemetry that the case
  studies in §13a foreground.
- `linux_kernel_exploitation_expertise.md` — offensive side of memory forensics (§3).
- `macos_memory_corruption_investigation.md` — macOS-specific memory considerations
  (§3).
- `macos_apple_security.md` — Apple Silicon platform internals, EndpointSecurity
  framework, and forensic-substrate considerations on managed Apple Silicon
  devices (§3, §9). Cross-link is load-bearing for the Apple Silicon
  memory-forensic gap and Stolen Device Protection discussions.
- `mobile_security_expertise.md` — mobile platform-level context, Pegasus /
  Predator / commercial-spyware literature, MVT operation, and Apple Threat
  Notification methodology (§9).
- `cryptography_expertise.md` — hash integrity, signing, key management (§2, §5,
  §12).
- `privacy_engineering_expertise.md` — data-subject rights during incident (§12).
- `appsec_program_building_expertise.md` — IR as consumer of program outputs (§10).
- `llm_agent_security_expertise.md` — agent-runtime forensics; prompt-injection
  forensic footprints; AI-as-junior-responder discipline (§14). Cross-reference
  bidirectional — agent runtime is both a forensic subject (incident on an
  agent) and a forensic tool (AI as IR-assistant).
- `agentic_web_capabilities_expertise.md` — web-fetching agents' tool surface,
  prompt-injection-via-fetched-content forensic footprint, integrity discipline
  for agent-consumed external content (§14).
- `confidential_computing_expertise.md` — TEE / SGX / SEV / TDX forensic
  substrate, attestation-derived evidence, and the integrity-protected-execution
  variant of memory forensics (§3, §14).
- `firmware_embedded_security.md` — ICS / IoT-device forensics (§10, §14).
- `cicd_supply_chain_expertise.md` — supply-chain incident response and
  attestation-based provenance (§5, §14). The CrowdStrike Channel File 291
  case in §13a sits at the supply-chain / update-channel boundary.
- `container_k8s_security.md` — Kubernetes-runtime forensic substrate (§7).
- `dns_network_infrastructure.md` — DNS forensic substrate (§6).
- `adversarial_ml_model_security_expertise.md` — ATLAS-mapped AI-system incident
  forensics; adversarial-input forensic footprints (§14).
- `steelman_doctrine_expertise.md` — Variant C is structurally identical to
  Casey's investigative process (§1).
- `code_review_expertise.md` — incident post-eradication code-review discipline;
  Carmen-Roundabout-style root-cause-to-codebase tracing of vulnerabilities
  surfaced in IR (§11).
