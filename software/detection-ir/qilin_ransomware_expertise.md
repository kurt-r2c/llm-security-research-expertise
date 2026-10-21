# Qilin (a.k.a. Agenda) Ransomware — Expertise

**First HUNTER-shift target.** Authored 2026-05-22 from urlscan.io-gated primary sources: Group-IB (origin profile + revisited), Cybereason (Linux variant deep-dive), Sophos Counter Threat Unit (ClickFix → StealC → Qilin chain), Trend Micro Research (original 2022 Agenda disclosure via The Hacker News mirror), Huntress / BleepingComputer (RDP-initial-access investigation), The Record (Synnovis NHS impact), The Hacker News (BYOVD 2026-04 + Call Lawyer 2025-06). Trend Micro's October 2025 Linux-on-Windows pivot post and Halcyon's Qilin-B writeup were urlscan-verified clean but returned HTTP 403 to WebFetch — partial detail synthesized from training-data knowledge with `[unverified]` flags.

Audience: detection engineers, IR responders, threat-intel analysts. Output to drive SENTINEL_QUEUE entries.

---

## 1. Identity & aliases

- **Primary name:** Qilin (named after the Chinese mythological creature)
- **Aliases:** Agenda (original 2022 name; rebranded to Qilin in 2023)
- **First seen:** July 2022 (Group-IB) / August 2022 (Trend Micro first public disclosure)
- **RaaS launch:** February 2023 (Group-IB)
- **Operator origin:** Russian-speaking. Affiliate recruitment posts in Russian on RAMP and XSS-style forums; explicit rule "does not work in CIS countries" — the canonical Russian-speaking ransomware-as-a-service tell `[unverified specific forum thread date]`
- **Confidence:** HIGH that the operator core is Russian-speaking; MEDIUM on any specific nation-state-affiliation claim (no public attribution to a specific GRU/FSB-adjacent cluster as of 2026-05)

The Agenda → Qilin rebrand was accompanied by a **Go-to-Rust rewrite**, the most consequential technical decision in the group's history. Both source families exist in the wild; Trend Micro 2022 documented the Go variant, Group-IB's 2023+ work documented the Rust rewrite, and a Qilin-B variant emerged in late 2024 / early 2025 with enhanced EDR-evasion claims (Halcyon `[unverified — Halcyon WebFetch blocked, claim from urlscan title]`).

---

## 2. Timeline & scale

| Date | Event | Source |
|------|-------|--------|
| 2022-07 | Agenda first observed in the wild | Group-IB |
| 2022-08-25 | Trend Micro public disclosure of Agenda (Go variant) | The Hacker News mirror |
| 2023-02 | RaaS launch as "Qilin"; Rust rewrite shipped | Group-IB Revisited |
| 2023-03 | Group-IB infiltrates affiliate panel | Group-IB |
| 2024-06 | Synnovis attack (NHS pathology) — single most-public victim to date; $50M demand `[unverified specific demand figure]` | The Record, Group-IB Revisited |
| 2024-10 | Qilin-B variant emerges | Halcyon `[unverified detail]` |
| 2025-01 | Affiliates conduct ScreenConnect MSP spear-phishing chains | Sophos |
| 2025-06 | "Call Lawyer" feature added to affiliate panel + in-house journalist team + DDoS module + corporate spam tools | The Hacker News |
| 2025-Q4 | Linux variant deployed on Windows hosts (cross-platform pivot) | Trend Micro `[unverified — WebFetch HTTP 403, claim from urlscan title only]` |
| 2026-04 | BYOVD chain via `msimg32.dll` DLL side-loading + `rwdrv.sys`/`hlpdrv.sys` killing 300+ EDR drivers; shared with Akira + Makop | The Hacker News (sourcing Cisco Talos, Trend Micro, CYFIRMA, Cynet) |

**Scale at Group-IB Revisited (2024):** "over 150 organizations compromised across 25 countries." This is the most-current public scale figure verified in this shift; current 2026 cumulative is likely much higher `[unverified — no current cumulative figure in the URLs fetched]`.

---

## 3. RaaS economic model

**Affiliate revenue split** (Group-IB, confirmed via infiltration of admin panel March 2023):
- Payments ≤ $3M USD: affiliate keeps **80%**, operator keeps 20%
- Payments > $3M USD: affiliate keeps **85%**, operator keeps 15%

This is **aggressive even by RaaS standards** — LockBit's contemporary split at the time was 80% flat; BlackCat/ALPHV was 80-90% scaling. The escalating tier above $3M is designed to attract affiliates who can land enterprise-scale victims (the Synnovis-class incidents).

**Affiliate recruitment rules (verbatim quote pattern):**
- "Does not work in CIS countries" — geographic restriction baked in
- Russian-language requirement implied by recruitment-post language

**Affiliate panel structure** (Group-IB observation):
1. **Targets** — victim config + ransom-builder (per-victim binary customization)
2. **Blogs** — leak-site post management
3. **Stuffers** — team account management (multiple operators per affiliate)
4. **News** — operator updates (largely empty at observation time)
5. **Payments** — wallet + transaction tracking
6. **FAQs** — affiliate-facing operator documentation

**2025-06 affiliate-panel additions** (The Hacker News, sourcing Cybereason):
- **"Call Lawyer" button** — affiliate clicks → operator's "legal team" contacts the affiliate to provide "qualified legal support." Verbatim quote: *"The mere appearance of a lawyer in the chat can exert indirect pressure on the company and increase the ransom amount, as companies want to avoid legal proceedings."*
- **In-house journalist team** — for leak-site amplification + press outreach
- **DDoS attack module** — triple-extortion pressure
- **Corporate email + phone spam tools** — multi-channel pressure
- **Safe Mode execution, network spreading, automated negotiation tools**

The Call Lawyer feature is **operationally novel** — most RaaS programs leave legal-coercion to affiliates. Qilin centralizing it suggests the operator has invested in name-pool of cooperating attorneys (or is bluffing — `[unverified whether the lawyers are real or theatrical]`).

---

## 4. Tooling lineage

**Languages:**
- **Go / Golang** — original Agenda variant (2022). Trend Micro: "written in Golang."
- **Rust** — Qilin rewrite (2023+). Group-IB Revisited: *"redeveloped using Rust, reflecting a shift towards more robust and efficient malware construction techniques."* Operationally significant: Rust binaries are harder to analyze (less mature decompiler support in 2023-2024), and the language's lack of widespread RE tooling raised the cost of variant analysis. This is the same defender-cost-asymmetry play seen in BlackCat/ALPHV (also Rust) and more recent Akira variants.

**Platform coverage:**
- Windows (primary)
- ESXi (Linux ELF targeting VMware)
- Linux generic
- **Linux-on-Windows cross-deployment** (Trend Micro Oct 2025 `[unverified WebFetch-blocked detail]`) — operators delivering the Linux ELF encryptor to Windows hosts, via WSL, as an EDR-evasion play (Windows EDR signatures don't fire on ELF execution paths)

**Per-victim binary customization** (Trend Micro 2022, confirmed pattern):
> "options to tailor the binary payloads for each victim, enabling the operators to decide the ransom note, encryption extension, as well as the list of processes and services to terminate"

This means **per-victim hash IOCs are NOT durable**. The encryptor SHA-256 changes per build. Detection MUST anchor on behavior, not on file hashes — see §16.

**Distinctive Rust toolchain fingerprints** (operationally useful for YARA / variant identification): the Rust standard-library symbol table and Cargo-derived compile artifacts have characteristic strings. Specific YARA rules from Cisco Talos / Trend Micro exist `[unverified — not in URLs fetched]`.

---

## 5. Encryption design

From Group-IB Revisited:

- **Symmetric:** AES-256-CTR **or** ChaCha20 (operator-configurable per build)
- **Asymmetric:** RSA-4096 wrapping the symmetric key
- **Modes:** "fast," "per cent," "normal" multi-pass encryption (operator-configurable). The "per cent" mode encrypts a percentage of each file (partial encryption — speed-vs-recoverability trade-off that's now standard across modern RaaS)
- **Password gate:** the encryptor requires `--password <PASS>` at runtime; the supplied password is SHA-256 hashed and compared against a hash embedded in the binary. **This is a deliberate sample-analysis defeat** — researchers who acquire a sample without the password cannot run it to observe behavior. The hash-comparison primitive is itself a useful YARA anchor: look for a hard-coded 32-byte SHA-256 referenced in the password-validation routine.

The RSA-4096 + AES-256-CTR/ChaCha20 design is **functionally unbreakable** without the private key. Synnovis-class victims have no decryption path without operator cooperation or seizure of operator infrastructure.

---

## 6. Command-line interface (load-bearing)

The CLI flag catalog is the **single most-actionable behavioral fingerprint** for Qilin — Rust binaries are hard to reverse, but process-execution telemetry showing `--password` + `--spread` + `--safe` on the same command line is essentially pathognomonic for this family.

**Windows variant flags** (Group-IB Revisited):

| Flag | Effect |
|------|--------|
| `--password <PASS>` | Required runtime password (SHA-256 verified against embedded hash) |
| `--spread` | Self-propagation across SMB shares |
| `--spread-vcenter` | Self-propagation to vCenter/ESXi infrastructure |
| `--safe` | Reboot host into Safe Mode (Networking) before encryption |
| `--no-escalate` | Skip privilege-escalation attempts |
| `--no-local` | Skip local-disk encryption |
| `--no-domain` | Skip encryption of files on domain hosts |
| `--no-network` | Skip network-share encryption |
| `--timer <SECS>` | Delay before encryption starts |
| `--debug` | Verbose / debugging output |

**Linux variant flags** (Cybereason):

| Flag | Effect |
|------|--------|
| `--password <string>` | Required startup password |
| `-p, --path <string>` | Target directory for encryption |
| `-t, --timer <number>` | Delay (seconds) |
| `-d, --debug` | Debug mode |
| `--dry-run` | Scan only; no encryption |
| `--no-proc-kill` | Disable process termination |
| `--no-snap-rm` | Disable snapshot deletion |
| `--no-vm-kill` | Disable VM-process termination |
| `-w, --whitelist` | Use inclusion-list mode instead of blacklist |
| `-y, --yes` | Script mode (skip confirmation prompts) |

**Detection note:** the long-form flags (`--no-escalate`, `--no-local`, `--no-domain`, `--no-network`, `--no-proc-kill`, `--no-snap-rm`, `--no-vm-kill`) and the explicit `--password` requirement are unusual together. A process-creation event-log entry containing two or more of these flags is **near-certainly Qilin** — the flag namespace is distinctive even if the parent binary has been renamed. See SENTINEL entries §16.

---

## 7. Initial-access primitives

Qilin affiliates use a **broad initial-access portfolio** — the operator does not mandate one path. Observed shapes:

1. **Veeam Backup & Replication CVE-2023-27532** (Group-IB Revisited) — internet-facing Veeam B&R; pre-auth credential extraction → lateral access. Patched March 2023; still exploited in unpatched environments through at least 2024.
2. **Fortinet device exploitation** (Group-IB Revisited) — "well-known vulnerabilities" on Fortinet appliances; specific CVE not enumerated in the source `[unverified specific Fortinet CVE]`. Likely candidates: CVE-2022-40684 (FortiOS pre-auth admin bypass), CVE-2023-27997 (FortiOS SSL-VPN heap overflow), CVE-2024-21762 (FortiOS SSL-VPN OOB write).
3. **VPN brute-force** (Group-IB Revisited) — credential-stuffing against exposed VPN portals; *"logs systematically cleared"* post-compromise to obstruct attribution.
4. **RDP** (Huntress via BleepingComputer) — direct RDP login with valid (likely stolen or stuffed) credentials. A number of Huntress's 2025 Qilin engagements started with RDP logins.
5. **Stolen credentials** (The Hacker News 2026-04) — the group "primarily relies on stolen credentials to gain initial access"; the same article's unpatched-SharePoint vector is attributed to Warlock, not Qilin.
6. **ScreenConnect MSP spear-phishing** (Sophos April 2025) — affiliates spear-phish the *administrator* of a managed-service-provider's ScreenConnect deployment, then pivot through the MSP's tenancy to many downstream client environments. This is supply-chain compromise via RMM.
7. **ClickFix → StealC → Qilin** (Sophos) — fake CAPTCHA / "I am not a robot" iframe overlay tricks user into pasting a command (the exact command-paste step is the canonical ClickFix mechanic; Sophos's article does not quote the verbatim PowerShell `[unverified verbatim ClickFix paste-payload]`). Downloads a batch file → NetSupport Manager (RAT) → StealC V2 infostealer (sideloading DLL `rtworkq.dll` SHA-256 `13fe3c1072ce308192994f2d7b329f7c8cbb192d49bdb538872383192d133ebb`) → VPN credential exfiltration → Qilin deployment **approximately one month later** via stolen VPN credentials.

The ~30-day gap between ClickFix infostealer execution and Qilin deployment is operationally significant: **credential-aging detections firing on stale VPN credentials would catch this chain**, and credential-rotation discipline (force re-auth on stolen creds via session-management primitives — see [[reference-session-management]]) would break it.

---

## 8. Defense evasion

This is where Qilin's 2024-2026 evolution has been most aggressive — and where most detection-engineering effort needs to focus.

### 8.1 BYOVD (Bring Your Own Vulnerable Driver) — 2026 primary evasion

From The Hacker News April 2026 (sourcing Cisco Talos, Trend Micro, CYFIRMA, Cynet):

- **DLL side-loading** via a malicious **`msimg32.dll`** to initiate a multi-stage in-memory chain
- **`rwdrv.sys`** renamed to **`ThrottleStop.sys`** (legitimate driver name as a disguise) — used to gain physical-memory access at kernel level
- **`hlpdrv.sys`** — terminates processes associated with **"more than 300 EDR drivers from almost every security vendor in the market"**
- **User-mode hook neutralization** — unhooks ntdll.dll inline hooks installed by EDR
- **ETW (Event Tracing for Windows) suppression** — kills the ETW event source so EDR can't ingest events
- **Control-flow + API-call concealment** — purely in-memory execution

**Shared with Akira and Makop** — the same drivers (`rwdrv.sys`, `hlpdrv.sys`) appear in Akira and Makop intrusions, suggesting either a shared affiliate ecosystem, a common driver-procurement source, or commercial RaaS-adjacent BYOVD-as-a-service tooling.

Cross-link: [[reference-windows-kernel-exploitation]] §6 BYOVD doctrine. Detection: Microsoft Vulnerable Driver Blocklist updates as the structural defense; behavior-anchored detection on the loading of `msimg32.dll` from non-System32 paths.

### 8.2 Safe-Mode reboot for encryption

Group-IB and Trend Micro (2022) confirm the safe-mode reboot mechanism. Standard Windows command for Safe Mode with Networking:

```cmd
BCDEdit.exe /set {current} safeboot network
```

This is the load-bearing technique: Windows Safe Mode disables most EDR agents (which run as user-mode services not started in Safe Mode), so the encryptor runs unhindered post-reboot. The encryptor sets the BCD `safeboot` flag, schedules itself to run on next boot (via a runonce key or service), reboots, encrypts under Safe Mode, then clears the BCD flag and reboots back to normal.

**Detection:** any process invoking `BCDEdit.exe /set {current} safeboot network` is **near-certainly malicious** in production environments — legitimate use is vanishingly rare and always interactive admin-initiated. See SENTINEL entry §16.

### 8.3 Windows Defender disablement (Huntress observation)

The threat actor modifies Defender settings:
- **`SpyNetReporting`** — disabled (kills cloud telemetry to Microsoft)
- **`SubmitSamplesConsent`** — disabled (kills sample-submission)

Registry path: `HKLM\SOFTWARE\Microsoft\Windows Defender\Spynet` (`[unverified exact path — Huntress did not specify in the BleepingComputer excerpt]`).

### 8.4 Volume Shadow Copy / snapshot deletion

- Group-IB documented the malware starting the VSS service and deleting shadow copies with `vssadmin.exe Delete Shadows /all /quiet`

### 8.5 Event-log clearing (Cybereason verbatim)

```powershell
$logs = Get-WinEvent -ListLog * | Where-Object {$_.RecordCount}
ForEach ( $l in $logs | Sort | Get-Unique ) {
  [System.Diagnostics.Eventing.Reader.EventLogSession]::GlobalSession.ClearLog($l)
}
```

This is **detection gold** — the `[System.Diagnostics.Eventing.Reader.EventLogSession]::GlobalSession.ClearLog($l)` invocation is unusual; legitimate admin log-clearing uses `wevtutil cl <Logname>` or `Clear-EventLog`, not the .NET reflection-style invocation. PowerShell Script Block Logging (Event ID 4104) will capture this even though the post-execution event log is cleared. See [[reference-powershell-footguns]] §AMSI/script-block-logging discipline. SENTINEL entry §16.

### 8.6 VPN log cleanup (Group-IB)

After VPN brute-force initial access: *"logs systematically cleared"* on the VPN appliance. Specific commands unspecified in the source `[unverified Fortinet/PaloAlto/etc. log-clear command set used]`.

---

## 9. Lateral movement

**Embedded PsExec 2.43** (Group-IB Revisited) — the encryptor binary embeds Sysinternals PsExec v2.43 (a specific older version, useful as a YARA anchor) for SMB-based propagation. Cross-link: [[reference-active-directory-windows-security]] §lateral-movement.

**fsutil symbolic link manipulation** (Group-IB Revisited) — `fsutil behavior set SymlinkEvaluation R2R:1` and `fsutil behaviour set SymlinkEvaluation R2L:1` to enable symbolic-link evaluation, likely to widen the encryption surface.

**Spread modes via CLI** (§6):
- `--spread` — generic SMB self-propagation
- `--spread-vcenter` — explicit vCenter/ESXi targeting

**Huntress observation:** ransomware "launched from another endpoint, against network shares" — Qilin commonly runs from a single staging host targeting SMB shares fleet-wide rather than running on each victim host. This is a significant detection opportunity: **a single source-host with many concurrent SMB write-fan-out events to encrypted-file extensions** is the canonical Qilin lateral-encryption signature.

---

## 10. Credential access

Public reporting on Qilin's in-network credential harvesting is **thinner than the encryption-mechanic reporting**. This is itself a finding — most vendor blogs focus on the encryptor (sample-analysis output) rather than the affiliate's pre-encryption tradecraft, which is more environment-specific.

Confirmed:
- **`r.ps1` PowerShell script** (Huntress) — enumerates RDP access logs to identify IP addresses, domains, and usernames associated with prior RDP sessions. Used for follow-on lateral access via known-good credential paths.
- **Indirect credential access via StealC handoff** (Sophos) — when the chain begins with ClickFix → StealC, the infostealer obtains credentials, then VPN credentials are used ~30 days later by Qilin affiliates. This means Qilin affiliates frequently *do not* need to run Mimikatz / LSASS-dumping themselves; they buy or trade infostealer output.
- **Mimikatz / LSASS dump** — `[unverified — not confirmed in any URL fetched, but standard ransomware-affiliate tradecraft and likely used in cases where infostealer handoff is not the chain]`

Cross-link: [[reference-active-directory-windows-security]] for Mimikatz / DCSync / Kerberoasting patterns; [[reference-llm-agent-security]] for credential-harvesting via infostealer chains.

---

## 11. Data exfiltration

**Double-extortion is the baseline** — Qilin exfiltrates before encryption.

Observed exfil tooling:
- **`s5cmd`** (Huntress — *"In only one incident did analysts observe the use of s5cmd for data exfiltration"*) — high-performance S3 client; used to push exfiltrated data to attacker-controlled S3-compatible storage
- **FTP** — direct FTP push to operator-controlled servers
- **Rclone** — `[unverified specific to Qilin in the URLs fetched, but standard RaaS exfil tooling and likely used by affiliates who don't use s5cmd]`

**WikiLeaks V2** — Qilin's operator runs a "WikiLeaks V2" project to publish exfiltrated data for publicity / pressure beyond just the standard DLS (Dark Leak Site) Tor hidden-service.

**Triple/quadruple extortion (2025-06+):** the affiliate-panel adds (Call Lawyer + journalist team + DDoS + corporate email/phone spam) extend pressure beyond data publication into reputation + legal-process + service-disruption + harassment.

---

## 12. Impact

**Encryption + filename pattern:**
- Encrypted-file extension: operator-configurable per build (Trend Micro 2022). No fixed extension.
- Ransom-note pattern: **`README-RECOVER-ID-<six-character string>.txt`** (Sophos verbatim) or **`README-RECOVER-<extension>.txt`** (Huntress via BleepingComputer) — the family clearly uses a `README-RECOVER-*.txt` template with per-victim suffixing.
- Cybereason variant: **`_RECOVER.txt`** suffix (likely the Linux variant or an earlier Windows build).

**Recovery posture:** RSA-4096-protected AES-256-CTR / ChaCha20 is unbreakable without operator cooperation. Backup-restore is the only recovery path that does not involve paying.

**Ransom demands:** $50,000 to $800,000 (Trend Micro 2022 baseline); Synnovis was reported at **$50 million** (Group-IB Revisited, claim not independently confirmed in The Record's coverage `[unverified specific $50M figure]`).

---

## 13. Victim corpus (named, verified)

| Date | Victim | Sector | Country | Notes / impact | Source |
|------|--------|--------|---------|----------------|--------|
| 2022-Q3 | Healthcare orgs | Healthcare | Indonesia, Saudi Arabia, South Africa, Thailand | Trend Micro 2022 — original Agenda campaign | The Hacker News mirror |
| 2024-06 | **Synnovis** (NHS pathology JV) | Healthcare / pathology | UK | 814 elective procedures postponed; 97 cancer treatments postponed; 18 organs diverted to other Trusts; 5 planned C-sections rescheduled; **blood testing capacity to ~10% of normal**; emergency call for O-type blood donations; primary affected Trusts: Guy's and St Thomas' NHS Foundation Trust + King's College Hospital NHS Foundation Trust | The Record |
| 2025-01 | MSP customers via ScreenConnect chain | Multiple | Multiple | Spear-phishing MSP admin → cascade to client environments | Sophos |
| 2026-03 | **Die Linke** (German political party) | Political / non-profit | Germany | Data theft confirmed | BleepingComputer (urlscan-verified but not fetched this shift) |
| 2025-10 (~) | Huntress-investigated victim | Unspecified | Unspecified | rogue ScreenConnect; r.ps1 RDP-log enumeration; Defender disablement | BleepingComputer / Huntress |

**Group-IB Revisited total:** "over 150 organizations compromised across 25 countries" as of 2024.

The **Synnovis incident is load-bearing** for any briefing — it is the single most-impactful publicly-reported ransomware-against-critical-infrastructure incident of 2024 in terms of immediate human safety consequences (organs diverted, cancer treatments delayed, blood-supply emergency). It is the canonical "ransomware-as-mass-casualty-event" case study post-Colonial-Pipeline. Cross-link: [[reference-medical-device-security]] (parent-class), [[reference-dfir-methodology]].

---

## 14. Hash IOCs + infrastructure

**Caveat (load-bearing):** Qilin's per-victim binary customization (§4) means **hash IOCs decay fast**. They are useful for forensic confirmation ("yes this was Qilin") but cannot drive ahead-of-time blocking. Behavior is the durable detection surface (§16).

### Huntress-investigation hashes
```
s.exe   SHA-256: af9925161d84ef49e8fbbb08c3d276b49d391fd997d272fe1bf81f8c0b200ba1
ss.exe  SHA-1:   ba79cdbcbd832a0b1c16928c9e8211781bf536cc
```

### StealC V2 sideloading DLL (`rtworkq.dll`) in ClickFix → Qilin chain (Sophos)
```
SHA-256: 13fe3c1072ce308192994f2d7b329f7c8cbb192d49bdb538872383192d133ebb
```

### Infrastructure (Cybereason)
- FTP exfil: `185.208.156.157`, `185.196.10.19`
- WikiLeaks V2 publication: `80.64.16.87` (hosted via OPTIMA LLC)

### Infrastructure (Sophos ClickFix chain)
- Compromised domain: `aquafestonline[.]com`
- Malicious JS host: `islonline[.]org`
- ClickFix delivery: `hxxps://yungask[.]com/work/index.php`
- NetSupport download: `hxxps://2beinflow[.]com/head.php`
- RAT C2: `94.158.245.13`

### Infrastructure (Huntress)
- Rogue ScreenConnect instance ID: `63bbb3bfea4e2eea`
- ScreenConnect C2: `94.156.232.40`

### 2026-04 BYOVD chain (The Hacker News)
- DLL: `msimg32.dll` (DLL side-loading)
- Driver 1: `rwdrv.sys` renamed `ThrottleStop.sys`
- Driver 2: `hlpdrv.sys`
- Specific driver SHA-256s not in source `[unverified — would be in original Cisco Talos / Trend Micro writeups, not fetched this shift]`

### Leak-site / Tor
Specific Qilin DLS .onion URL not enumerated in any URL fetched this shift `[unverified current onion URL]`. Cross-reference with public ransomware-tracker resources (ransomwatch, ransomware.live, Recorded Future Ransomware Tracker) for the current operational onion.

---

## 15. Honest failure modes — where public reporting on Qilin is thin, contradictory, or vendor-marketing-shaped

1. **Per-victim binary customization defeats hash-based detection.** Most vendor blogs publish a handful of SHA-256s as if they are useful long-term IOCs. They are not — they confirm post-hoc that you saw Qilin, but they cannot block. Honest detection engineering anchors on behavior (§16), not hashes. Vendor reports that emphasize hash IOCs over behavioral fingerprints are marketing-shaped.

2. **Affiliate vs operator behavior is conflated in most reporting.** Group-IB's panel-infiltration work cleanly separates operator-developed primitives (the encryptor, the panel, the legal-coercion infrastructure) from affiliate-driven tradecraft (initial access, dwell-time decisions, exfil tooling choices). Most other vendor reports observe an incident and attribute the entire chain to "Qilin," obscuring that the affiliate may have used Mimikatz / Rclone / Cobalt Strike that another Qilin affiliate would not have used. This matters because **detections that key off affiliate-variable tooling are fragile**.

3. **The Synnovis "$50M" demand figure traces to the operator.** Bloomberg reported Qilin's $50 million demand with a 120-hour deadline; Synnovis did not pay, and Qilin published the stolen data on 2024-06-20.

4. **The BYOVD chain (msimg32.dll + rwdrv.sys + hlpdrv.sys) is shared across at least three ransomware families.** Detection rules anchored on these specific files will trigger on Akira and Makop too — high TP for "this is one of three serious ransomware families" but not for "this is Qilin specifically." This is fine for prevention (you want to block all three) but matters for attribution and IR.

5. **The "Call Lawyer" feature may be partly theatrical.** No URL fetched this shift confirms that the lawyers are real, retained attorneys vs. operator-impersonated personas. The forum-post wording (Russian-to-English translation via The Hacker News) is exactly what an operator would write to *appear* credible. Treat the operational sophistication of the legal-coercion vector as `[unverified]`.

6. **Linux-on-Windows pivot (Trend Micro Oct 2025) is reported but not confirmed in this shift.** WebFetch returned HTTP 403; the urlscan title is the only source. The pivot makes operational sense (Windows EDR signatures don't fire on ELF) and BleepingComputer's coverage of the Trend Micro report names the mechanism: the ELF encryptor is transferred with WinSCP, launched via Splashtop's `SRManager.exe`, and run under WSL.

7. **Public victim counts are operator-published.** "150+ orgs / 25 countries" is from Group-IB; some of those count is via the leak-site, which is the operator's publication channel. Victims who paid before publication never appear; victims the operator chose not to publish never appear. The true scale is higher and unknowable without breach-disclosure regulator data.

8. **CIS-exclusion claim is operator-stated but not enforced in observed code.** The "does not work in CIS countries" rule appears in recruitment posts. Whether the binary actually skips encryption on CIS-resolved hosts (e.g., via locale check, keyboard layout check, or IP geolocation) is not documented in any URL fetched this shift. Some ransomware families have this check in code; others rely on affiliate discipline alone. `[unverified — Qilin specifically]`.

9. **The 80%/85% affiliate split was accurate at panel-infiltration time (March 2023).** Three years later, the split may have changed. Group-IB has not published an updated split figure in URLs fetched.

10. **Qilin-B specific differences are vendor-marketing-shaped.** Halcyon's Qilin-B writeup is the primary source for that variant's distinctness; the writeup returned HTTP 403 to WebFetch. Without primary-source confirmation, claims that Qilin-B is meaningfully different from Qilin in detection-relevant ways should be treated as `[unverified]`.

---

## 16. Detection opportunities — high-durability behavioral anchors

These are the behaviors most worth turning into SENTINEL_QUEUE entries. Each is anchored on a structural design choice the operator made (not on per-victim configuration), and each is hard to evade without re-architecting the malware.

### 16.1 BCDedit safeboot tampering
```cmd
BCDEdit.exe /set {current} safeboot network
```
**Why durable:** Safe-Mode-for-encryption is the operator-designed primitive; removing it costs them the EDR-bypass. **Detection shape:** process-creation event for `bcdedit.exe` with `/set` and `safeboot` and (`network` or `minimal`) as args. Sigma rule, EDR query (KQL/Splunk), Sysmon Event ID 1. **FP risk:** vanishingly low in production environments. **Severity:** HIGH (this command is ~1-2 hops from full encryption).

### 16.2 PowerShell event-log clearing via .NET reflection
```powershell
[System.Diagnostics.Eventing.Reader.EventLogSession]::GlobalSession.ClearLog($l)
```
**Why durable:** the operator chose the .NET reflection-style invocation specifically because it bypasses `wevtutil cl` / `Clear-EventLog` cmdlet logging. Switching back to those cmdlets would cost them log-clear stealth. **Detection shape:** PowerShell Script Block Logging (Event ID 4104) pattern-match on the `EventLogSession.ClearLog` invocation. Even though the post-exec event log is cleared, the 4104 entry was already generated before clearing. **FP risk:** very low. **Severity:** HIGH (log-clearing = post-encryption finalization).

### 16.3 CLI flag combinations on Rust binary
```
<any.exe> --password <hash> --spread --safe --no-escalate --timer <n>
```
**Why durable:** the flag namespace is operator-designed; renaming flags would require recompiling the Rust binary and break operator/affiliate workflows. **Detection shape:** EDR command-line parse looking for ≥2 of (`--password`, `--spread`, `--spread-vcenter`, `--safe`, `--no-escalate`, `--no-local`, `--no-domain`, `--no-network`, `--no-proc-kill`, `--no-snap-rm`, `--no-vm-kill`, `--timer`, `--dry-run`) on the same process. **FP risk:** essentially zero — no legitimate software uses this flag combination. **Severity:** CRITICAL.

### 16.4 BYOVD driver-load chain (msimg32.dll + rwdrv.sys + hlpdrv.sys)
**Why durable:** these specific drivers are the operator's chosen BYOVD-as-a-service pair; switching costs them tooling stability. **Detection shape:** Sysmon Event ID 6 (Driver loaded) for `rwdrv.sys` OR `hlpdrv.sys` from non-standard paths; Sysmon Event ID 7 (Image loaded) for `msimg32.dll` loaded from a non-System32 path by a non-system-binary process. Cross-reference: Microsoft Vulnerable Driver Blocklist. **FP risk:** low — `msimg32.dll` is a legitimate system DLL but should only be loaded from System32 by system binaries; load from user paths is anomalous. **Severity:** CRITICAL.

### 16.5 Defender registry tampering
```
HKLM\SOFTWARE\Microsoft\Windows Defender\Spynet\SpyNetReporting = 0
HKLM\SOFTWARE\Microsoft\Windows Defender\Spynet\SubmitSamplesConsent = 0
```
**Why durable:** observed pattern in Huntress's investigation; an affiliate-variable behavior but consistently seen. **Detection shape:** registry-modify event for these two specific values to 0. **FP risk:** low; few legitimate admin workflows touch these. **Severity:** HIGH.

### 16.6 Embedded PsExec v2.43 fingerprint
**Why durable:** the operator embeds a specific older PsExec build (v2.43). Newer or differently-versioned PsExec embedded into a parent binary is a distinguishing artifact. **Detection shape:** YARA rule matching the PsExec v2.43 byte signature inside the Qilin encryptor binary; EDR detection of `psexesvc.exe` (the PsExec service) spawning from a non-Sysinternals path with the v2.43 version string. **FP risk:** medium (legitimate PsExec usage exists); narrow on parent process + version mismatch. **Severity:** MEDIUM.

### 16.7 `--password` SHA-256 password gate anti-analysis
**Why durable:** the operator deliberately requires `--password` to defeat sandbox analysis. The hash-validation routine inside the binary has a characteristic shape (load 32 bytes, compute SHA-256 of CLI arg, compare). **Detection shape:** YARA rule on the password-validation code-block in Rust binaries; absence of the password as a CLI arg means the binary exits before encryption — useful for **safe sample triage** in IR. **FP risk:** N/A (this is sample-triage, not production telemetry). **Severity:** MEDIUM (operational, not detective).

---

## 17. Cross-link cluster

Detection / IR siblings:
- [[reference-detection-engineering]] — Sigma / EDR / KQL rule corpus where Qilin SENTINEL entries become rules
- [[reference-dfir-methodology]] — IR lifecycle; Qilin response maps cleanly to NIST 800-61
- [[reference-threat-intel-methodology]] — Diamond Model + intel-cycle anchors for adding Qilin to a TI program
- [[reference-falco-tetragon-runtime-detection]] — for the Linux variant on Linux hosts (eBPF-based detection of the CLI flag combinations in §16.3)

Technical bug-class siblings:
- [[reference-windows-kernel-exploitation]] §6 — BYOVD doctrine; Microsoft Vulnerable Driver Blocklist as structural defense
- [[reference-powershell-footguns]] — PowerShell Script Block Logging (4104) and AMSI as the durable substrate for catching the .NET reflection log-clear (§16.2)
- [[reference-shell-injection]] — peripheral; ransomware encryptor CLI is operator-controlled but the techniques inform how RaaS operators design CLIs
- [[reference-active-directory-windows-security]] — lateral movement primitives Qilin affiliates use post-domain-foothold

Adversary / actor siblings:
- [[reference-ransomware-akira]] — `[planned but not yet authored]` — shares BYOVD drivers with Qilin per 2026-04 reporting
- [[reference-ransomware-makop]] — `[planned but not yet authored]` — also shares the BYOVD chain

Strategic / regulatory:
- [[reference-medical-device-security]] — Synnovis class incidents intersect medical-device security and clinical-safety regulatory landscape
- [[reference-ai-incident-response-playbook]] — peripheral; AI-tooling adjacent IR procedures
- [[reference-anti-fraud-abuse-engineering]] — ClickFix lure mechanics intersect bot-defense and credential-stuffing economics

---

## 18. Top three load-bearing claims

1. **Qilin's per-victim binary customization makes hash IOCs detection-decorative; behavior is the only durable surface.** Every SHA-256 published by every vendor decays the moment the operator's "Targets" panel rebuilds the binary for the next victim. Detection programs that prioritize hash-feed ingestion over behavioral-rule authoring are spending the detection budget in the wrong place. The CLI flag combinations (§6, §16.3), BCDedit safeboot tampering (§16.1), and .NET-reflection log-clear (§16.2) are durable. Hashes are forensic confirmation only.

2. **The BYOVD chain (msimg32.dll + rwdrv.sys + hlpdrv.sys) is the single most-consequential 2026 Qilin development.** It moves the EDR-bypass from "kill Defender via registry tampering" (Huntress 2025 observation) to "kernel-level termination of 300+ EDR drivers from every major vendor." Detection must shift to driver-load telemetry (Sysmon Event ID 6) and to leveraging Microsoft's Vulnerable Driver Blocklist + HVCI. Operations that have not enabled HVCI on production endpoints have no structural defense against this chain.

3. **The ClickFix → StealC → 30-day-delay → Qilin chain is the load-bearing initial-access shape for 2025-2026, and credential-rotation discipline breaks it.** The 30-day gap between infostealer-execution and Qilin-deployment is operationally significant: any organization that rotates VPN credentials at a 7-30 day cadence forces the chain to fail. This is the most-actionable defensive recommendation for non-technical leadership: short-lived credentials over passwords (passkeys, certificate-based VPN, sender-constrained tokens via DPoP/mTLS — see [[reference-session-management]]) defeat the entire infostealer-to-ransomware pipeline.
